package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Session histories (Intent Layer v2 section 2.1): the host side of accumulators and monitors. The verifier receives the
 * PRE-STATE of the action's group from its own store; these functions compute it from the session's event history (window,
 * key, selection and counted statuses applied) and fold a monitor over it. They are pure: the store, its lock and the
 * reservation belong to the host. A function that the reference answers with a throw returns null here (store corruption,
 * a missing key, a sum outside the safe-integer range): the caller fails closed.
 */
public final class IntentHistory {
    private IntentHistory() {}

    private static final Pattern DECIMAL = Pattern.compile("[+-]?(?:[0-9]+\\.?[0-9]*|\\.[0-9]+)(?:[eE][+-]?[0-9]+)?");

    /** A reserved or committed event counts toward a cap (a reservation counts as soon as it is made). */
    static boolean isCounted(Object status) { return "reserved".equals(status) || "committed".equals(status); }

    private static double f(Object v) { Double d = IntentJs.num(v); return d == null ? Double.NaN : d; }

    /**
     * Does the counted event stamped ti still count at t? task: always; sliding(ms): (t-ms, t]; period(ms, t0): the period
     * containing t; and every event stamped AFTER t (it has not left any window). A time that is not a safe integer is in no
     * window (fail closed: the caller treats the store as corrupt).
     */
    public static boolean inWindow(Map<String, Object> win, Object ti, Object t) {
        if (!IntentJs.isInt(ti) || !IntentJs.isInt(t)) return false;
        double fi = f(ti), ft = f(t);
        if (fi > ft) return true;
        Object kind = win == null ? null : win.get("kind");
        if ("task".equals(kind)) return true;
        if ("sliding".equals(kind)) return fi > ft - f(win.get("ms"));
        if ("period".equals(kind)) {
            double ms = f(win.get("ms")), t0 = f(win.get("t0"));
            return Math.floor((fi - t0) / ms) == Math.floor((ft - t0) / ms);
        }
        return false;
    }

    /** The canonical key of the grouping parameter, "•" when ungrouped, null when the parameter is missing or not a string / safe integer. */
    public static String accKeyOf(Map<String, Object> a, Map<String, Object> params) {
        Object k = a.get("key");
        if (!(k instanceof String)) return "•";
        String name = ((String) k).substring("action.params.".length());
        if (params == null || !params.containsKey(name)) return null;
        return IntentAcc.distinctKey(params.get(name));
    }

    private static Map<String, Object> emptyPre(Object agg) {
        Map<String, Object> m = new LinkedHashMap<>();
        if ("sum".equals(agg)) m.put("sum", IntentJs.ofLong(0));
        else if ("count".equals(agg)) m.put("count", IntentJs.ofLong(0));
        else if ("max".equals(agg)) m.put("max", IntentJs.ofLong(0));
        else m.put("values", new ArrayList<Object>());
        return m;
    }

    private static Map<String, Object> mapOrEmpty(Object o) { Map<String, Object> m = Ledger.map(o); return m == null ? new LinkedHashMap<>() : m; }

    /** accSelects, with a reference throw reported as a RuntimeException caught by the callers below. */
    private static boolean selects(Map<String, Object> a, Object verb, Object schema) {
        return IntentAcc.accSelects(a, verb instanceof String ? (String) verb : "", schema);
    }

    /**
     * The pre-state of the accumulator for a candidate action, or null where the reference throws: a past event's value or
     * time is unreadable, the candidate's key is missing, or a sum leaves the safe-integer range.
     */
    public static Map<String, Object> accPreState(Map<String, Object> a, List<?> history, Map<String, Object> candParams, Object candT, Object schema) {
        try {
            return preState(a, history, candParams, candT, schema);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Map<String, Object> preState(Map<String, Object> a, List<?> history, Map<String, Object> candParams, Object candT, Object schema) {
        String key = accKeyOf(a, candParams);
        if (key == null || !IntentJs.isInt(candT)) return null;
        Map<String, Object> win = Ledger.map(a.get("win"));
        double sum = 0, count = 0, mx = 0;
        List<String> vals = new ArrayList<>();
        for (Object ev : history) {
            Map<String, Object> e = mapOrEmpty(ev);
            boolean counted = isCounted(e.get("status"));
            if (counted && !IntentJs.isInt(e.get("t"))) return null;
            if (!counted || !inWindow(win, e.get("t"), candT)) continue;
            if (!selects(a, e.get("verb"), schema)) continue;
            Map<String, Object> params = mapOrEmpty(e.get("params"));
            String ek = accKeyOf(a, params);
            if (ek == null || !ek.equals(key)) continue;
            IntentAcc.AccValue v = IntentAcc.accValueOf(a, e.get("verb") instanceof String ? (String) e.get("verb") : "", params, schema);
            if (v.reason != null) return null;
            sum += v.val;
            count += 1;
            mx = Math.max(mx, v.val);
            if (v.key != null) vals.add(v.key);
        }
        Object agg = a.get("agg");
        Map<String, Object> out = new LinkedHashMap<>();
        if ("sum".equals(agg)) {
            if (Math.abs(sum) > IntentJs.MAX_SAFE) return null;
            out.put("sum", IntentJs.ofLong((long) sum));
        } else if ("count".equals(agg)) {
            out.put("count", IntentJs.ofLong((long) count));
        } else if ("max".equals(agg)) {
            out.put("max", IntentJs.ofLong((long) mx));
        } else {
            vals.sort(Json::compareUtf8);
            out.put("values", new ArrayList<Object>(new LinkedHashSet<>(vals)));
        }
        return out;
    }

    /**
     * post(history, action, t): the pre-state combined with the action when it is selected, else the pre-state's value. Null
     * where the reference throws.
     */
    public static Long accPost(Map<String, Object> a, List<?> history, String verb, Map<String, Object> params, Object t, Object schema) {
        try {
            Map<String, Object> pre;
            if (a.get("key") instanceof String && accKeyOf(a, params) == null) pre = emptyPre(a.get("agg"));
            else {
                pre = preState(a, history, params, t, schema);
                if (pre == null) return null;
            }
            if (!selects(a, verb, schema)) return IntentAcc.preValue(a.get("agg"), pre);
            IntentAcc.AccValue v = IntentAcc.accValueOf(a, verb, params, schema);
            if (v.reason != null) return null;
            return IntentAcc.combineAcc(a.get("agg"), pre, v);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** The start state of a monitor. */
    public static String monitorInitialState(Map<String, Object> m) {
        Object k = m.get("kind");
        if ("requires_prior".equals(k) || "precedes".equals(k)) return "unmet";
        if ("never".equals(k)) return "clean";
        if ("always".equals(k)) return "ok";
        return "idle";
    }

    private static boolean match(Object p, Map<String, Object> ctx) { return Predicates.predicateMatches(p, ctx); }

    /** One monitor step on one event; statuses that do not count leave the state unchanged. */
    public static String monitorStep(Map<String, Object> m, String q, Map<String, Object> e) {
        boolean counts = "committed".equals(m.get("status")) ? "committed".equals(e.get("status")) : isCounted(e.get("status"));
        if (!counts) return q;
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("verb", e.get("verb"));
        action.put("resource", e.get("resource"));
        action.put("params", e.get("params"));
        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("action", action);
        Object kind = m.get("kind");
        if ("requires_prior".equals(kind) || "precedes".equals(kind)) return "met".equals(q) || match(m.get("p"), ctx) ? "met" : "unmet";
        if ("never".equals(kind)) return "seen".equals(q) || match(m.get("p"), ctx) ? "seen" : "clean";
        if ("always".equals(kind)) return "broken".equals(q) || !match(m.get("p"), ctx) ? "broken" : "ok";
        if ("responds_within".equals(kind)) {
            if ("missed".equals(q)) return "missed";
            double w = f(m.get("within"));
            double pending = 0;
            boolean has = q.startsWith("pending:");
            if (has) pending = jsNumber(q.substring("pending:".length()));
            if (has) {
                if (match(m.get("q"), ctx)) has = false;
                else if (pending - 1 <= 0) return "missed";
                else pending -= 1;
            }
            if (match(m.get("p"), ctx)) {
                if (!has) { pending = w; has = true; }
                else pending = Math.min(pending, w);
            }
            return has ? "pending:" + jsString(pending) : "idle";
        }
        return q;
    }

    /** JavaScript Number(s) for the decimal tail of a pending state (NaN when it is not a decimal). */
    private static double jsNumber(String s) {
        String t = s.trim();
        if (t.isEmpty()) return 0;
        if (t.equals("Infinity") || t.equals("+Infinity")) return Double.POSITIVE_INFINITY;
        if (t.equals("-Infinity")) return Double.NEGATIVE_INFINITY;
        if (!DECIMAL.matcher(t).matches()) return Double.NaN;
        return Double.parseDouble(t);
    }

    /** JavaScript String(n) for the values a pending counter takes. */
    private static String jsString(double d) {
        if (Double.isNaN(d)) return "NaN";
        if (Double.isInfinite(d)) return d > 0 ? "Infinity" : "-Infinity";
        if (d == 0) return "0";
        if (d == Math.rint(d) && Math.abs(d) < 1e21) return new java.math.BigDecimal(d).toPlainString();
        return IntentJs.shortest(d);
    }

    /** The fold of the monitor over the history (admission order, current statuses). */
    public static String monitorState(Map<String, Object> m, List<?> history) {
        String q = monitorInitialState(m);
        for (Object ev : history) q = monitorStep(m, q, mapOrEmpty(ev));
        return q;
    }
}
