package net.atlasauth.pca.storeconformance;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.doctor.Js;

/**
 * The pure core of the store conformance kit: the register model both store operations share, the budgeted linearizability search,
 * the per-key checker with minimal counterexamples, the recorder's history parser, and the report formatting.
 *
 * <p>ONE MODEL FOR BOTH OPERATIONS. The register {@code s} starts at -infinity (no record, no counter). A TRUE answer is legal iff
 * {@code s < lo}, and then {@code s := max(s, w)}; a FALSE answer is legal iff {@code s >= lo} and leaves {@code s} unchanged. An
 * UNKNOWN outcome (error, timeout, killed client) may or may not have taken effect. The register never decreases, which the
 * reductions ({@link #prune}, {@link #fastCheck}) rely on. A PASS is evidence, never proof; a FAIL is a recorded history that no
 * sequential order explains.
 */
public final class Kit {
    private Kit() {}

    /** Default number of distinct search states explored per key before giving up (unresolved). */
    public static final double DEFAULT_SEARCH_BUDGET = 200_000;

    // ---- model ----

    /** The register's successor states after {@code op} from {@code s} (empty: the answer is impossible from {@code s}). */
    public static List<Double> step(double s, Op op) {
        boolean fresh = s < op.lo;
        List<Double> out = new ArrayList<>();
        if (op.res.equals("true")) {
            if (fresh) out.add(Math.max(s, op.w));
        } else if (op.res.equals("false")) {
            if (!fresh) out.add(s);
        } else {
            out.add(s);
            if (fresh) out.add(Math.max(s, op.w));
        }
        return out;
    }

    private static int cmp(double a, double b) { return a < b ? -1 : a > b ? 1 : 0; }

    private static List<Op> trues(List<Op> ops) {
        List<Op> ts = new ArrayList<>();
        for (Op o : ops) if (o.res.equals("true")) ts.add(o);
        return ts;
    }

    /** Two definite TRUE answers whose [lo, w] intervals overlap can never both linearize; returns such a pair, or null. */
    public static List<Op> overlappingTrues(List<Op> ops) {
        List<Op> ts = trues(ops);
        ts.sort((a, b) -> cmp(a.lo, b.lo));
        for (int i = 1; i < ts.size(); i++) if (ts.get(i - 1).w >= ts.get(i).lo) return List.of(ts.get(i - 1), ts.get(i));
        return null;
    }

    /** Drop every definite FALSE that a definite TRUE explains (verdict-preserving). */
    public static List<Op> prune(List<Op> ops) {
        List<Op> ts = trues(ops);
        ts.sort((a, b) -> cmp(a.ret, b.ret));
        double[] pm = new double[ts.size()];
        for (int i = 0; i < ts.size(); i++) pm[i] = Math.max(ts.get(i).w, i > 0 ? pm[i - 1] : Double.NEGATIVE_INFINITY);
        List<Op> out = new ArrayList<>();
        for (Op o : ops) {
            if (!o.res.equals("false")) { out.add(o); continue; }
            int n = 0;
            while (n < ts.size() && ts.get(n).ret < o.call) n++;
            if (!(n > 0 && pm[n - 1] >= o.lo)) out.add(o);
        }
        return out;
    }

    /** EXACT decision for a history with no unknown operation (null when one is unknown). */
    public static Boolean fastCheck(List<Op> ops) {
        for (Op o : ops) if (o.res.equals("unknown")) return null;
        List<Op> ts = trues(ops);
        ts.sort((a, b) -> cmp(a.lo, b.lo));
        double[] t = new double[ts.size()];
        double prev = Double.NEGATIVE_INFINITY;
        for (int i = 0; i < ts.size(); i++) {
            Op o = ts.get(i);
            if (i > 0 && ts.get(i - 1).w >= o.lo) return false;
            double ti = Math.max(o.call, prev);
            if (ti > o.ret) return false;
            t[i] = ti;
            prev = ti;
        }
        for (Op f : ops) {
            if (!f.res.equals("false")) continue;
            int j = -1;
            for (int i = 0; i < ts.size(); i++) if (ts.get(i).w >= f.lo) { j = i; break; }
            if (j < 0 || t[j] > f.ret) return false;
        }
        return true;
    }

    // ---- search ----

    /** Linearizability search (Wing-Gong / Lowe) for ONE key: {@code ok}, {@code violation} or {@code unresolved} (over budget, never a pass). */
    public static String searchLinearizable(List<Op> ops, double budget) {
        List<Op> order = new ArrayList<>(ops);
        order.sort((a, b) -> cmp(a.call, b.call));
        int n = order.size();
        BigInteger[] bits = new BigInteger[n];
        for (int i = 0; i < n; i++) bits[i] = BigInteger.ONE.shiftLeft(i);
        BigInteger all = BigInteger.ONE.shiftLeft(n).subtract(BigInteger.ONE);
        Set<String> seen = new HashSet<>();
        List<Object[]> stack = new ArrayList<>();
        stack.add(new Object[] {BigInteger.ZERO, Double.NEGATIVE_INFINITY});
        while (!stack.isEmpty()) {
            Object[] top = stack.remove(stack.size() - 1);
            BigInteger done = (BigInteger) top[0];
            double s = (Double) top[1];
            if (done.equals(all)) return "ok";
            String id = done.toString(36) + "|" + (s == 0 ? 0.0 : s);
            if (seen.contains(id)) continue;
            if (seen.size() >= budget) return "unresolved";
            seen.add(id);
            double minRet = Double.POSITIVE_INFINITY;
            for (int i = 0; i < n; i++) if (done.and(bits[i]).signum() == 0) minRet = Math.min(minRet, order.get(i).ret);
            for (int i = 0; i < n && order.get(i).call <= minRet; i++) {
                if (done.and(bits[i]).signum() != 0) continue;
                for (double s2 : step(s, order.get(i))) stack.add(new Object[] {done.or(bits[i]), s2});
            }
        }
        return "violation";
    }

    public static String searchLinearizable(List<Op> ops) { return searchLinearizable(ops, DEFAULT_SEARCH_BUDGET); }

    // ---- check ----

    /** Options of the per-key checker; null members take the reference defaults. */
    public static final class CheckOptions {
        /** Search states per key before the key is unresolved (default 200,000). */
        public Double budget;
        /** Shrink each violating key's history to a 1-minimal counterexample (default true). */
        public Boolean minimize;
        /** Keys with more operations than this (after pruning) are reported without shrinking (default 200). */
        public Double minimizeLimit;

        @SuppressWarnings("unchecked")
        public static CheckOptions fromJson(Object o) {
            CheckOptions c = new CheckOptions();
            if (!(o instanceof Map)) return c;
            Map<String, Object> m = (Map<String, Object>) o;
            if (m.get("budget") != null) c.budget = Js.toNumber(m.get("budget"));
            if (m.containsKey("minimize")) c.minimize = !Boolean.FALSE.equals(m.get("minimize"));
            if (m.get("minimizeLimit") != null) c.minimizeLimit = Js.toNumber(m.get("minimizeLimit"));
            return c;
        }
    }

    /** One key's decision: the verdict, how it was reached ({@code overlap}, {@code exact}, {@code search}) and the pruned history. */
    public static final class Decision {
        public final String verdict, method;
        public final List<Op> kept;
        Decision(String verdict, String method, List<Op> kept) { this.verdict = verdict; this.method = method; this.kept = kept; }
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("verdict", verdict);
            m.put("method", method);
            m.put("kept", opsJson(kept));
            return m;
        }
    }

    static List<Object> opsJson(List<Op> ops) {
        List<Object> out = new ArrayList<>();
        for (Op o : ops) out.add(o.toJson());
        return out;
    }

    public static List<Op> opsOf(Object o) {
        List<Op> out = new ArrayList<>();
        for (Object x : (List<?>) o) out.add(Op.fromJson(x));
        return out;
    }

    /** Decide one key's history (all operations share kind and key). */
    public static Decision decideKey(List<Op> ops, double budget) {
        if (overlappingTrues(ops) != null) return new Decision("violation", "overlap", new ArrayList<>(ops));
        List<Op> kept = prune(ops);
        Boolean exact = fastCheck(kept);
        if (exact != null) return new Decision(exact ? "ok" : "violation", "exact", kept);
        return new Decision(searchLinearizable(kept, budget), "search", kept);
    }

    /**
     * The SOUND deletion step for {@code op}: deleting a FALSE never helps it; deleting a writer (TRUE or unknown) lowers the register,
     * which can only break FALSEs it may have explained ({@code lo <= w}), so those go with it.
     */
    public static List<Op> deletion(List<Op> ops, Op op) {
        List<Op> out = new ArrayList<>();
        if (op.res.equals("false")) {
            for (Op o : ops) if (o != op) out.add(o);
            return out;
        }
        for (Op o : ops) if (o != op && !(o.res.equals("false") && o.lo <= op.w)) out.add(o);
        return out;
    }

    /** Greedy sound deletion to a 1-minimal violating history. */
    public static List<Op> minimize(List<Op> ops, double budget) {
        List<Op> cur = new ArrayList<>(ops);
        for (boolean changed = true; changed; ) {
            changed = false;
            for (Op op : new ArrayList<>(cur)) {
                List<Op> next = deletion(cur, op);
                if (decideKey(next, budget).verdict.equals("violation")) {
                    cur = next;
                    changed = true;
                    break;
                }
            }
        }
        return cur;
    }

    /** One key's result. */
    public static final class KeyResult {
        public final String key;
        public final Object kind;
        public final int ops, searched;
        public final String verdict, method;
        public List<Op> counterexample;
        public Boolean minimized;

        KeyResult(String key, Object kind, int ops, int searched, String verdict, String method) {
            this.key = key; this.kind = kind; this.ops = ops; this.searched = searched; this.verdict = verdict; this.method = method;
        }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("key", key);
            m.put("kind", kind);
            m.put("ops", ops);
            m.put("searched", searched);
            m.put("verdict", verdict);
            m.put("method", method);
            if (counterexample != null) m.put("counterexample", opsJson(counterexample));
            if (minimized != null) m.put("minimized", minimized);
            return m;
        }
    }

    public static KeyResult checkKey(List<Op> ops, CheckOptions opts) {
        CheckOptions o = opts != null ? opts : new CheckOptions();
        double budget = o.budget != null ? o.budget : DEFAULT_SEARCH_BUDGET;
        Op first = ops.get(0);
        Decision d = decideKey(ops, budget);
        KeyResult r = new KeyResult(first.key, first.kind, ops.size(), d.kept.size(), d.verdict, d.method);
        if (!d.verdict.equals("violation")) return r;
        List<Op> pair = overlappingTrues(ops);
        if (pair != null) {
            List<Op> p = new ArrayList<>(pair);
            p.sort((a, b) -> cmp(a.call, b.call));
            r.counterexample = p;
            r.minimized = true;
        } else if (!Boolean.FALSE.equals(o.minimize) && d.kept.size() <= (o.minimizeLimit != null ? o.minimizeLimit : 200)) {
            r.counterexample = minimize(d.kept, budget);
            r.minimized = true;
        } else {
            r.counterexample = d.kept;
            r.minimized = false;
        }
        return r;
    }

    /** The check of a whole history: counts by outcome, the violating keys and the keys over budget. */
    public static final class HistoryCheck {
        public final int ops, keys;
        public final boolean ok;
        public final int[] outcomes; // true, false, unknown
        public final List<KeyResult> violations, unresolved;

        HistoryCheck(int ops, int keys, boolean ok, int[] outcomes, List<KeyResult> violations, List<KeyResult> unresolved) {
            this.ops = ops; this.keys = keys; this.ok = ok; this.outcomes = outcomes; this.violations = violations; this.unresolved = unresolved;
        }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ops", ops);
            m.put("keys", keys);
            m.put("ok", ok);
            Map<String, Object> oc = new LinkedHashMap<>();
            oc.put("true", outcomes[0]);
            oc.put("false", outcomes[1]);
            oc.put("unknown", outcomes[2]);
            m.put("outcomes", oc);
            m.put("violations", keyResultsJson(violations));
            m.put("unresolved", keyResultsJson(unresolved));
            return m;
        }
    }

    static List<Object> keyResultsJson(List<KeyResult> l) {
        List<Object> out = new ArrayList<>();
        for (KeyResult k : l) out.add(k.toJson());
        return out;
    }

    /** Split a history by (kind, key) and check every key. */
    public static HistoryCheck checkHistory(List<Op> ops, CheckOptions opts) {
        Map<String, List<Op>> byKey = new LinkedHashMap<>();
        int[] outcomes = new int[3];
        for (Op o : ops) {
            outcomes[o.res.equals("true") ? 0 : o.res.equals("false") ? 1 : 2]++;
            byKey.computeIfAbsent(Js.str(o.kind) + "\u0000" + o.key, k -> new ArrayList<>()).add(o);
        }
        List<KeyResult> violations = new ArrayList<>(), unresolved = new ArrayList<>();
        for (List<Op> list : byKey.values()) {
            KeyResult r = checkKey(list, opts);
            if (r.verdict.equals("violation")) violations.add(r);
            else if (r.verdict.equals("unresolved")) unresolved.add(r);
        }
        return new HistoryCheck(ops.size(), byKey.size(), violations.isEmpty() && unresolved.isEmpty(), outcomes, violations, unresolved);
    }

    // ---- formatting ----

    private static String fmtT(double t, double base) { return t == Double.POSITIVE_INFINITY ? "open" : "+" + Js.toFixed(t - base, 3) + "ms"; }

    /** One line per operation, times relative to the first invocation. */
    public static List<String> formatOps(List<Op> ops) {
        double base = Double.POSITIVE_INFINITY;
        for (Op o : ops) base = Math.min(base, o.call);
        List<Op> sorted = new ArrayList<>(ops);
        sorted.sort((a, b) -> cmp(a.call, b.call));
        List<String> out = new ArrayList<>();
        for (Op o : sorted) {
            String what = o.isConsume() ? "consumeOnce(now=" + Js.numStr(o.lo) + ", retainUntil=" + Js.numStr(o.w) + ")" : "advance(" + Js.numStr(o.lo) + ")";
            String res = o.res.equals("true") ? "TRUE" : o.res.equals("false") ? "false" : "unknown";
            out.add(o.client + ": " + what + " [" + fmtT(o.call, base) + " .. " + fmtT(o.ret, base) + "] -> " + res);
        }
        return out;
    }

    // ---- recorder history ----

    /** The operations rebuilt from recorder lines, how many lines were torn, and how many invocations are pending. */
    public static final class ParsedHistory {
        public final List<Op> ops;
        public final int torn, pending;
        ParsedHistory(List<Op> ops, int torn, int pending) { this.ops = ops; this.torn = torn; this.pending = pending; }
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ops", opsJson(ops));
            m.put("torn", torn);
            m.put("pending", pending);
            return m;
        }
    }

    private static Object at(List<?> l, int i) { return i < l.size() ? l.get(i) : Js.UNDEF; }

    /**
     * Rebuild the operations from recorder lines (any number of files concatenated). An invocation without a response is pending
     * (unknown, open-ended); an {@code unknown} response stays open-ended too. Lines that do not parse are counted as torn.
     */
    public static ParsedHistory parseHistory(String text) {
        Map<String, Op> open = new HashMap<>();
        List<Op> ops = new ArrayList<>();
        int torn = 0;
        for (String line : text.split("\n", -1)) {
            if (line.isEmpty()) continue;
            Object e;
            try {
                e = Json.parseLenient(line);
            } catch (RuntimeException ex) {
                torn++;
                continue;
            }
            if (!(e instanceof List)) { torn++; continue; }
            List<?> l = (List<?>) e;
            String id = Js.str(at(l, 1)) + "/" + Js.str(at(l, 2));
            if ("i".equals(at(l, 0)) && l.size() == 9) {
                Op op = new Op(Js.str(at(l, 4)), l.get(5), Js.str(at(l, 6)), jsNumber(l.get(7)), jsNumber(l.get(8)), jsNumber(l.get(3)), Double.POSITIVE_INFINITY, "unknown");
                open.put(id, op);
                ops.add(op);
            } else if ("r".equals(at(l, 0)) && l.size() == 5 && open.containsKey(id)) {
                Op op = open.remove(id);
                if (!"unknown".equals(l.get(4))) {
                    op.ret = jsNumber(l.get(3));
                    op.res = "true".equals(l.get(4)) ? "true" : "false";
                }
            } else {
                torn++;
            }
        }
        return new ParsedHistory(ops, torn, open.size());
    }

    /** {@code Number(v)} for a JSON value, arrays coerced through their string form. */
    private static double jsNumber(Object v) {
        if (v instanceof List) return Js.toNumber(Js.str(v));
        return Js.toNumber(v);
    }

    // ---- PRNG ----

    /** mulberry32, the workload PRNG: {@code rand(n)} is an integer in [0, n) (as a double). */
    public static final class Prng {
        private int a;
        public Prng(double seed) {
            double t = seed < 0 ? Math.ceil(seed) : Math.floor(seed);
            if (Double.isNaN(t) || Double.isInfinite(t)) t = 0;
            double m = t % 4294967296.0;
            if (m < 0) m += 4294967296.0;
            a = (int) (long) m;
        }
        public double rand(double n) {
            a += 0x6d2b79f5;
            int t = a;
            t = (t ^ (t >>> 15)) * (t | 1);
            t ^= t + (t ^ (t >>> 7)) * (t | 61);
            return Math.floor((((t ^ (t >>> 14)) & 0xffffffffL) / 4294967296.0) * n);
        }
    }

    // ---- reports ----

    public static final List<String> ALL_TESTS = List.of("burst", "concurrent", "retention", "durability", "crash");

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static Object decodeNums(Object v) {
        if (v instanceof Map) {
            Map<String, Object> mm = m(v);
            if (mm.size() == 1 && mm.get("$num") instanceof String) return Op.numOf(v);
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : mm.entrySet()) out.put(e.getKey(), decodeNums(e.getValue()));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(decodeNums(x));
            return out;
        }
        return v;
    }

    /** The folded status of a run: any fail is a fail, else any unresolved is unresolved, else pass (a test is a map with a {@code status}). */
    public static String overall(List<?> tests) {
        boolean unresolved = false;
        for (Object t : tests) {
            Object s = m(t).get("status");
            if ("fail".equals(s)) return "fail";
            if ("unresolved".equals(s)) unresolved = true;
        }
        return unresolved ? "unresolved" : "pass";
    }

    /** Human-readable report: one line per test, then each violating key's minimal counterexample (at most {@code maxKeys} per test). */
    public static String formatReport(Object report, double maxKeys) {
        Map<String, Object> r = m(decodeNums(report));
        List<String> out = new ArrayList<>();
        out.add("pca-store-conformance: " + Js.str(r.get("adapter")) + " -> " + Js.str(r.get("status")).toUpperCase(java.util.Locale.ROOT));
        for (Object to : (List<?>) r.get("tests")) {
            Map<String, Object> t = m(to);
            Object kind = t.get("kind");
            String opName = "consume".equals(kind) ? "consumeOnce" : "advance".equals(kind) ? "advance" : "undefined";
            String name = Js.padEnd(Js.str(t.get("test")) + "/" + opName, 24);
            String status = Js.str(t.get("status"));
            String stats = status.equals("skip") ? "" : Js.str(t.get("ops")) + " ops, " + Js.str(t.get("keys")) + " keys, " + Js.str(t.get("errors")) + " errors/timeouts";
            List<?> violations = (List<?>) t.get("violations");
            List<String> extra = new ArrayList<>();
            if (!violations.isEmpty()) extra.add(violations.size() + " NON-LINEARIZABLE key(s)");
            if (Js.truthy(t.get("unresolved"))) extra.add(Js.str(t.get("unresolved")) + " unresolved key(s) (over the search budget)");
            if (Js.truthy(t.get("note"))) extra.add(Js.str(t.get("note")));
            List<String> tail = new ArrayList<>();
            if (!stats.isEmpty()) tail.add(stats);
            if (!extra.isEmpty()) tail.add(String.join("; ", extra));
            out.add("  [" + status.toUpperCase(java.util.Locale.ROOT) + "] " + name + " " + String.join("; ", tail));
            for (int i = 0; i < violations.size() && i < maxKeys; i++) {
                Map<String, Object> v = m(violations.get(i));
                out.add("      key " + Js.str(v.get("key")) + " (" + Js.str(v.get("ops")) + " ops, decided by " + Js.str(v.get("method")) + "): "
                    + (Js.truthy(v.get("minimized")) ? "minimal counterexample" : "violating history (not shrunk)") + ":");
                List<Op> ce = v.get("counterexample") == null ? new ArrayList<>() : opsOf(v.get("counterexample"));
                for (String line : formatOps(ce)) out.add("        " + line);
            }
        }
        return String.join("\n", out);
    }

    public static String formatReport(Object report) { return formatReport(report, 3); }

    /** JSON-safe form of a report (Infinity becomes null), indented by two spaces. */
    public static String reportJson(Object report) { return Js.stringify(decodeNums(report)); }
}
