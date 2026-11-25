package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiPredicate;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.SignersMore;
import net.atlasauth.pca.WalletBridge;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Lazy just-in-time elicitation: the ordered decision for a visited cell (schema violation, ceiling, intent denied, admit, intent required),
 * the cell coordinates of an {@code intent_required} question, the wallet's check of one, and the delta grant minted from an answer.
 */
public final class IntentJit {
    private IntentJit() {}

    public static final String INTENT_ACTION_DOMAIN = "atlas-pca/intent-action/v1";

    private static Map<String, Object> lm() { return new LinkedHashMap<>(); }

    private static VerbSpace verbOf(Omega o, String verb) {
        for (VerbSpace v : o.verbs) if (v.verb.equals(verb)) return v;
        return null;
    }

    private static List<Object> ints(int[] a) {
        List<Object> o = new ArrayList<>();
        for (int x : a) o.add(new net.atlasauth.pca.Json.Num(Integer.toString(x)));
        return o;
    }

    /**
     * The ordered decision of a visit. {@code conform}: {ok, code?, reason?} (the schema conformance of the plaintext action); {@code ceilings}: each must
     * admit the lifted outcome (a deny anywhere wins); {@code inEffective}: is the cell in the effective grant. Returns {kind, ...}.
     */
    public static Map<String, Object> decideVisit(IntentLearner learner, Outcome lifted, Map<String, Object> conform, List<BiPredicate<VerbSpace, Outcome>> ceilings, boolean inEffective) {
        Map<String, Object> r = lm();
        if (!Boolean.TRUE.equals(conform.get("ok"))) {
            r.put("kind", "schema_violation");
            r.put("reason", jsStr(conform.get("code")) + ": " + jsStr(conform.get("reason")));
            return r;
        }
        VerbSpace vs = verbOf(learner.omega, lifted.verb());
        int[] cell = vs == null ? null : IntentOmega.cellOf(vs, lifted);
        if (vs == null || cell == null) {
            r.put("kind", "schema_violation");
            r.put("reason", "the lifted action lies outside Ω̃");
            return r;
        }
        if (ceilings != null) for (BiPredicate<VerbSpace, Outcome> c : ceilings) if (!c.test(vs, lifted)) { r.put("kind", "ceiling"); return r; }
        boolean vetoed = learner.isVetoed(lifted);
        double p = learner.acceptance(lifted);
        if (vetoed || p <= 0) { r.put("kind", "intent_denied"); r.put("vetoed", vetoed); return r; }
        if (inEffective) { r.put("kind", "admit"); r.put("cell", ints(cell)); return r; }
        r.put("kind", "intent_required");
        r.put("cell", ints(cell));
        r.put("p", p);
        return r;
    }

    private static String jsStr(Object o) {
        if (o == null) return "undefined";
        if (IntentOmega.isNumber(o)) return net.atlasauth.pca.AttestCommon.jsNumString(IntentOmega.dbl(o));
        return String.valueOf(o);
    }

    /** The coordinates of one cell (numeric: [i, i]; categorical: the cell's value). */
    public static Map<String, Object> cellCoords(VerbSpace vs, int[] cell) {
        Map<String, Object> out = lm();
        for (int k = 0; k < vs.dims.size(); k++) {
            Dim d = vs.dims.get(k);
            List<Object> c = new ArrayList<>();
            if (d instanceof NumDim) { c.add(new net.atlasauth.pca.Json.Num(Integer.toString(cell[k]))); c.add(new net.atlasauth.pca.Json.Num(Integer.toString(cell[k]))); }
            else c.add(((CatDim) d).values.get(cell[k]).value());
            out.put(d.path, c);
        }
        return out;
    }

    /** Coordinates to per-dimension cell indices (the inverse of {@link #cellCoords} for one cell), or null. */
    public static double[] cellFromCoords(VerbSpace vs, Map<String, Object> coords) {
        if (coords.size() != vs.dims.size()) return null;
        double[] out = new double[vs.dims.size()];
        for (int k = 0; k < out.length; k++) {
            Dim d = vs.dims.get(k);
            if (!coords.containsKey(d.path) || !(coords.get(d.path) instanceof List)) return null;
            List<?> c = (List<?>) coords.get(d.path);
            if (d instanceof NumDim) {
                if (c.isEmpty() || !IntentOmega.isNumber(c.get(0)) || c.size() < 2 || !IntentOmega.isNumber(c.get(1)) || IntentOmega.dbl(c.get(0)) != IntentOmega.dbl(c.get(1))) return null;
                out[k] = IntentOmega.dbl(c.get(0));
            } else {
                if (c.size() != 1 || !(c.get(0) instanceof String)) return null;
                int i = -1;
                List<IntentOmega.CatValue> vals = ((CatDim) d).values;
                for (int j = 0; j < vals.size(); j++) if (vals.get(j).value().equals(c.get(0))) { i = j; break; }
                if (i < 0) return null;
                out[k] = i;
            }
        }
        return out;
    }

    /** {@code intentActionDigest}: the content address of the action an intent_required question is about. */
    public static String intentActionDigest(Object action) {
        Map<?, ?> a = (Map<?, ?>) action;
        Map<String, Object> act = lm();
        for (String k : new String[] {"verb", "resource", "params_digest", "reversibility_class"}) act.put(k, a.get(k));
        Map<String, Object> m = lm();
        m.put("d", INTENT_ACTION_DOMAIN);
        m.put("action", act);
        return Pca.hashCanonical(IntentJs.normalize(m));
    }

    /**
     * The site's {@code pca-intent-required} body for a visited uncertain cell. {@code in}: session, mapDigest, schemaDigest, pcactn (JSON), questionId,
     * friction, deliveredTo, expiresAt; {@code vs} and {@code cell} locate the cell.
     */
    public static Map<String, Object> intentRequiredBody(Map<String, Object> in, VerbSpace vs, int[] cell) {
        Map<String, Object> pcactn = IntentOmega.obj(in.get("pcactn"));
        Map<String, Object> b = lm();
        b.put("v", 1L);
        b.put("kind", "pca-intent-required");
        b.put("session", in.get("session"));
        b.put("map_digest", in.get("mapDigest"));
        b.put("schema", in.get("schemaDigest"));
        b.put("pcactn_digest", Pca.hashCanonical(IntentJs.normalize(pcactn)));
        b.put("action_digest", intentActionDigest(pcactn.get("action")));
        Map<String, Object> c = lm();
        c.put("verb", vs.verb);
        c.put("coords", cellCoords(vs, cell));
        b.put("cell", c);
        b.put("reason", "uncertain");
        b.put("question_id", in.get("questionId"));
        b.put("friction", in.get("friction"));
        b.put("delivered_to", in.get("deliveredTo"));
        b.put("expires_at", in.get("expiresAt"));
        return b;
    }

    public static Map<String, Object> signedIntentRequired(Map<String, Object> in, VerbSpace vs, int[] cell, String kid, Keys.SuiteKey site) {
        return SignersMore.signIntentRequired(intentRequiredBody(in, vs, cell), kid, site);
    }

    private static Map<String, Object> fail(String reason) {
        Map<String, Object> r = lm();
        r.put("ok", false);
        r.put("reason", reason);
        return r;
    }

    /**
     * The wallet's check of an {@code intent_required}: the site signature under its discovery keys, the expiry, the session and map, and the CELL,
     * re-derived from the wallet's own space and the lifted action. Returns {ok: true, vs, cell} or {ok: false, reason}.
     */
    public static Map<String, Object> walletCheckIntentRequired(Object body, List<Object> keys, long now, String session, String mapDigest, Omega omegaTilde, Outcome lifted, Map<String, Object> pcactn) {
        String v = WalletBridge.verifyIntentRequired(body, keys, (Object) Long.valueOf(now));
        if (v != null) return fail(v);
        Map<?, ?> b = (Map<?, ?>) body;
        if (!session.equals(b.get("session")) || !mapDigest.equals(b.get("map_digest"))) return fail("the question is for another session or map");
        if (!Pca.hashCanonical(IntentJs.normalize(pcactn)).equals(b.get("pcactn_digest")) || !intentActionDigest(pcactn.get("action")).equals(b.get("action_digest"))) return fail("the question is about another action");
        VerbSpace vs = verbOf(omegaTilde, lifted.verb());
        int[] mine = vs == null ? null : IntentOmega.cellOf(vs, lifted);
        Map<?, ?> bc = (Map<?, ?>) b.get("cell");
        if (vs == null || mine == null || !vs.verb.equals(bc.get("verb"))) return fail("the wallet cannot place the action in Ω̃");
        @SuppressWarnings("unchecked") double[] theirs = cellFromCoords(vs, (Map<String, Object>) bc.get("coords"));
        if (theirs == null) return fail("the site cell differs from the cell the wallet derives");
        for (int k = 0; k < theirs.length; k++) if (theirs[k] != mine[k]) return fail("the site cell differs from the cell the wallet derives");
        Map<String, Object> r = lm();
        r.put("ok", true);
        r.put("vs", IntentOmega.verbSpaceToJson(vs));
        r.put("cell", ints(mine));
        return r;
    }

    // ---- delta grants ----

    /** Per verb, the cells the next learner's grant adds over the previous one's (both over the same space); verbs with no new cell are absent. */
    public static Map<String, byte[]> deltaCells(IntentLearner prev, IntentLearner next) {
        Map<String, byte[]> out = new LinkedHashMap<>();
        Set<String> prevIn = new LinkedHashSet<>();
        for (IntentLearner.CellView c : prev.cells()) if (c.inGrant) prevIn.add(c.verb + "|" + join(c.cell));
        List<IntentLearner.CellView> nextCells = next.cells();
        for (VerbSpace vs : next.omega.verbs) {
            byte[] a = new byte[(int) IntentOmega.verbCellCount(vs)];
            boolean any = false;
            for (IntentLearner.CellView c : nextCells) {
                if (!c.verb.equals(vs.verb) || !c.inGrant || prevIn.contains(c.verb + "|" + join(c.cell))) continue;
                a[(int) IntentOmega.encodeCell(vs, c.cell)] = 1;
                any = true;
            }
            if (any) out.put(vs.verb, a);
        }
        return out;
    }

    private static String join(int[] a) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < a.length; i++) { if (i > 0) sb.append(','); sb.append(a[i]); }
        return sb.toString();
    }

    /** The predicates of a delta (one maximal box per covered region, per verb). */
    public static List<Map<String, Object>> deltaPredicates(Omega omegaTilde, Map<String, byte[]> delta) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (VerbSpace vs : omegaTilde.verbs) if (delta.containsKey(vs.verb)) out.addAll(IntentLearner.boxesToPredicates(vs, delta.get(vs.verb)));
        return out;
    }

    /**
     * Mint D_k from the k-th answer: null when the answer added no cell. {@code a}: holder, holderPq?, session, seq, prev?, root, mapDigest, mapForm?, caveats?,
     * agentBinding?, riskPolicy?, salt?, and {@code prevGrant} (the previous session grant, JSON). Returns {grant, goalSalt, cells}.
     */
    public static Map<String, Object> mintDelta(IntentLearner prev, IntentLearner next, Map<String, Object> a, Keys.SuiteKey principal) {
        Map<String, byte[]> delta = deltaCells(prev, next);
        long cells = 0;
        for (byte[] v : delta.values()) for (byte x : v) cells += x;
        if (cells == 0) return null;
        Map<String, Object> prevGrant = IntentOmega.obj(a.get("prevGrant"));
        if (a.get("prev") != null && !a.get("prev").equals(prevGrant.get("id"))) throw new IllegalArgumentException("mintDelta: prev must be the id of the previous session grant");
        @SuppressWarnings("unchecked") List<Object> preds = (List<Object>) IntentJs.normalize(new ArrayList<Object>(deltaPredicates(next.omega, delta))); // JS number spelling before the grant is canonicalized
        @SuppressWarnings("unchecked") List<Object> caveats = a.get("caveats") == null ? null : (List<Object>) a.get("caveats");
        @SuppressWarnings("unchecked") Map<String, Object> binding = a.get("agentBinding") == null ? null : (Map<String, Object>) a.get("agentBinding");
        @SuppressWarnings("unchecked") Map<String, Object> risk = a.get("riskPolicy") == null ? null : (Map<String, Object>) a.get("riskPolicy");
        SignersMore.SessionGrant g = SignersMore.mintSessionGrant(principal, (String) a.get("holder"), (String) a.get("session"), (long) IntentOmega.dbl(a.get("seq")), (String) a.get("root"),
            (String) prevGrant.get("id"), (String) a.get("mapDigest"), (String) a.get("mapForm"), preds, caveats, binding, risk, (String) a.get("salt"), (String) a.get("holderPq"));
        Map<String, Object> r = lm();
        r.put("grant", g.grant);
        r.put("goalSalt", g.goalSalt);
        r.put("cells", (double) cells);
        return r;
    }
}
