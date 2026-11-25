package net.atlasauth.pca.wallet;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
import net.atlasauth.pca.oauth.JsVal;

/**
 * Agent-initiated clarification. The agent may ask BEFORE acting with {@code {candidates: [at most 8 structured actions], reason}}:
 * there is no free-text field and unknown members are refused. The wallet maps each candidate to its own cell: certain cells are
 * answered at once as a dry run (admitted / denied / outside), and among the uncertain ones it picks the cell of maximal expected
 * information gain under the current asymmetric noise (ties broken by risk weight, then cell index, then candidate position).
 */
public final class WalletClarify {
    private WalletClarify() {}

    public static final int MAX_CANDIDATES = 8;
    private static final int MAX_VALUES = 64;
    private static final int MAX_STRING = 256;
    private static final Pattern PATH_RE = Pattern.compile("[a-z][a-z0-9_]*(\\.[a-z0-9_]+)*", Pattern.CASE_INSENSITIVE);

    private static Map<String, Object> bad(String error) { return Wallet.obj("ok", false, "error", error); }

    /** Strict parse of a clarification body: {ok:true, request:{candidates, reason}} or {ok:false, error}. Never throws. */
    public static Map<String, Object> parseClarifyRequest(Object body) {
        if (!Wallet.isObj(body)) return bad("body must be an object");
        Map<?, ?> b = (Map<?, ?>) body;
        for (Object k : b.keySet()) if (!"candidates".equals(k) && !"reason".equals(k)) return bad("unknown member \"" + k + "\" (clarifications carry no text)");
        Object reason = b.get("reason");
        if (!(reason instanceof String) || !WalletCard.CLARIFY_REASONS.contains(reason)) return bad("reason must be one of " + String.join(", ", WalletCard.CLARIFY_REASONS));
        Object cands = b.get("candidates");
        if (!(cands instanceof List) || ((List<?>) cands).isEmpty() || ((List<?>) cands).size() > MAX_CANDIDATES) return bad("candidates must be 1..8 structured actions");
        List<Object> out = new ArrayList<>();
        int i = 0;
        for (Object cO : (List<?>) cands) {
            if (!Wallet.isObj(cO)) return bad("candidates[" + i + "] must be an object");
            Map<?, ?> c = (Map<?, ?>) cO;
            for (Object k : c.keySet()) if (!"verb".equals(k) && !"values".equals(k)) return bad("candidates[" + i + "] has an unknown member \"" + k + "\"");
            Object verb = c.get("verb");
            if (!(verb instanceof String) || ((String) verb).isEmpty() || ((String) verb).length() > 128) return bad("candidates[" + i + "].verb must be a non-empty string");
            if (!Wallet.isObj(c.get("values"))) return bad("candidates[" + i + "].values must be an object");
            Map<?, ?> vals = (Map<?, ?>) c.get("values");
            if (vals.size() > MAX_VALUES) return bad("candidates[" + i + "] has too many values");
            Map<String, Object> values = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : vals.entrySet()) {
                String p = (String) e.getKey();
                Object v = e.getValue();
                if (!PATH_RE.matcher(p).matches()) return bad("candidates[" + i + "] has a malformed path");
                if (!(p.equals("action.resource") || p.startsWith("action.params."))) return bad("candidates[" + i + "].values may only name action.params.* or action.resource");
                if (JsVal.isNumber(v)) {
                    if (!Wallet.isSafeInteger(v) || JsVal.isNegZero(v)) return bad("candidates[" + i + "].values." + p + " must be a safe integer");
                } else if (!(v instanceof String) || ((String) v).length() > MAX_STRING) return bad("candidates[" + i + "].values." + p + " must be a string (≤ " + MAX_STRING + ") or an integer");
                values.put(p, v);
            }
            out.add(Wallet.obj("verb", verb, "values", values));
            i++;
        }
        return Wallet.obj("ok", true, "request", Wallet.obj("candidates", out, "reason", reason));
    }

    /** Expected information gain (bits) of asking a cell with acceptance p under asymmetric noise. */
    public static double informationGain(double p, double etaPos, double etaNeg) {
        double py = p * (1 - etaNeg) + (1 - p) * etaPos;
        return WalletStats.binEnt(py) - (p * WalletStats.binEnt(etaNeg) + (1 - p) * WalletStats.binEnt(etaPos));
    }

    /** The plan for a clarification: a dry-run verdict per candidate and the one cell to ask (or null). */
    public static final class Plan {
        public final List<Map<String, Object>> verdicts = new ArrayList<>();
        /** {index, verb, idx[], p, ig} or null. */
        public Map<String, Object> ask;
        public int[] askIdx;

        public Map<String, Object> toMap() {
            return Wallet.obj("verdicts", new ArrayList<Object>(verdicts), "ask", ask);
        }
    }

    private static final class Best {
        int index; String verb; int[] idx; double p, ig, weight, flat;
    }

    private static Map<String, Object> verdict(int index, String v) { return Wallet.obj("index", (long) index, "verdict", v); }

    /**
     * Plan a clarification over the parsed candidates (maps {verb, values}). {@code lift} (nullable) lifts a candidate into the
     * lifted outcome space; {@code asked} holds the cells already asked ("verb|i,j,..." keys).
     */
    public static Plan planClarification(Map<String, Object> omega, WalletView view, List<Map<String, Object>> candidates, UnaryOperator<Map<String, Object>> lift,
                                         Set<String> asked, double etaPos, double etaNeg, WalletOmega.HarmModel harm) {
        Plan plan = new Plan();
        Best best = null;
        Set<String> seen = new HashSet<>();
        for (int index = 0; index < candidates.size(); index++) {
            Map<String, Object> cand = candidates.get(index);
            WalletBox.CellAtVs at = WalletBox.cellOfAction(omega, lift != null ? lift.apply(cand) : cand);
            if (at == null) { plan.verdicts.add(verdict(index, "outside")); continue; }
            String verb = (String) at.vs.get("verb");
            int[] idx = at.idx;
            if (view.outsideCeiling(verb, idx) || view.vetoed(verb, idx)) { plan.verdicts.add(verdict(index, "denied")); continue; }
            double p = view.p(verb, idx);
            if (p <= 0) { plan.verdicts.add(verdict(index, "denied")); continue; }
            if (p >= 1) { plan.verdicts.add(verdict(index, "admitted")); continue; }
            String key = WalletNoise.cellKey(verb, idx);
            if (asked.contains(key)) { plan.verdicts.add(verdict(index, "asked")); continue; }
            plan.verdicts.add(verdict(index, "uncertain"));
            if (seen.contains(key)) continue;
            seen.add(key);
            double ig = informationGain(p, etaPos, etaNeg);
            double[] s = WalletOmega.cellStats(at.vs, idx, harm);
            Best c2 = new Best();
            c2.index = index; c2.verb = verb; c2.idx = idx; c2.p = p; c2.ig = ig; c2.weight = s[0] * s[1]; c2.flat = WalletBox.flatIndex(at.vs, idx);
            if (best == null || c2.ig > best.ig + 1e-12
                || (Math.abs(c2.ig - best.ig) <= 1e-12 && (c2.weight > best.weight || (c2.weight == best.weight && c2.flat < best.flat)))) best = c2;
        }
        if (best != null) {
            plan.ask = Wallet.obj("index", (long) best.index, "verb", best.verb, "idx", WalletNoise.idxList(best.idx), "p", best.p, "ig", best.ig);
            plan.askIdx = best.idx;
        }
        return plan;
    }
}
