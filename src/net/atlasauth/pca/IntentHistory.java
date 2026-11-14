package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Session histories (Intent Layer v2 section 2.1): the host side of accumulators and monitors. The verifier receives the
 * PRE-STATE of the action's group from its own store; these functions compute it from the session's event history (window,
 * key, selection and counted statuses applied) and fold a monitor over it. They are pure: the store, its lock and the
 * reservation belong to the host. A function that the reference answers with a throw returns null here (store corruption,
 * a missing key, a sum outside the safe-integer range): the caller fails closed.
 */
public final class IntentHistory {
    private IntentHistory() {}

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
        if (win == null) throw new IllegalArgumentException("inWindow: no window"); // the reference throws reading win.kind
        Object kind = win.get("kind");
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

    /** A history entry: null is store corruption (the reference throws reading its status); any other non-object has no members. */
    private static Map<String, Object> event(Object o) {
        if (o == null) throw new IllegalArgumentException("a history event is null");
        return mapOrEmpty(o);
    }

    /** accSelects, with a reference throw reported as a RuntimeException caught by the callers below. A verb that is not a string matches no verb list and no schema entry. */
    private static boolean selects(Map<String, Object> a, Object verb, Object schema) {
        return verb instanceof String && IntentAcc.accSelects(a, (String) verb, schema);
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

    /** Throws where the reference throws. */
    private static Map<String, Object> preState(Map<String, Object> a, List<?> history, Map<String, Object> candParams, Object candT, Object schema) {
        String key = accKeyOf(a, candParams);
        if (key == null) throw new IllegalArgumentException("accPreState: the key parameter " + a.get("key") + " is missing");
        if (!IntentJs.isInt(candT)) throw new IllegalArgumentException("accPreState: the candidate time is not a safe integer");
        Map<String, Object> win = Ledger.map(a.get("win"));
        double sum = 0, count = 0, mx = 0;
        List<String> vals = new ArrayList<>();
        for (Object ev : history) {
            Map<String, Object> e = event(ev);
            boolean counted = isCounted(e.get("status"));
            if (counted && !IntentJs.isInt(e.get("t"))) throw new IllegalArgumentException("accPreState: event " + e.get("id") + ": the time is not a safe integer");
            if (!counted || !inWindow(win, e.get("t"), candT)) continue;
            if (!selects(a, e.get("verb"), schema)) continue;
            Map<String, Object> params = mapOrEmpty(e.get("params"));
            String ek = accKeyOf(a, params);
            if (ek == null || !ek.equals(key)) continue;
            IntentAcc.AccValue v = IntentAcc.accValueOf(a, (String) e.get("verb"), params, schema); // selected: the verb is a string
            if (v.reason != null) throw new IllegalArgumentException("accPreState: event " + e.get("id") + ": " + v.reason);
            sum += v.val;
            count += 1;
            mx = Math.max(mx, v.val);
            if (v.key != null) vals.add(v.key);
        }
        Object agg = a.get("agg");
        Map<String, Object> out = new LinkedHashMap<>();
        if ("sum".equals(agg)) {
            if (sum > IntentJs.MAX_SAFE) throw new IllegalArgumentException("accPreState: sum exceeds 2^53-1"); // values are >= 0
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
            // 'accPost: unknown agg' (intent-history.ts accPost), first: a host-built declaration is not validated otherwise
            // and an unknown agg would read as distinct
            if (!IntentAcc.ACC_AGGS.contains(a.get("agg"))) return null;
            // accKeyOf is null only for a declared key whose parameter is missing
            Map<String, Object> pre = accKeyOf(a, params) == null ? emptyPre(a.get("agg")) : preState(a, history, params, t, schema);
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
            Double pending = q.startsWith("pending:") ? AttestNvidia.jsNumber(q.substring("pending:".length())) : null; // JS Number()
            if (pending != null) {
                if (match(m.get("q"), ctx)) pending = null;
                else if (pending - 1 <= 0) return "missed";
                else pending = pending - 1;
            }
            if (match(m.get("p"), ctx)) pending = pending == null ? f(m.get("within")) : Math.min(pending, f(m.get("within")));
            return pending == null ? "idle" : "pending:" + jsString(pending);
        }
        return null; // an unknown kind has no state (the reference returns undefined)
    }

    /** JavaScript String(n): the shortest round-trip digits, plain from 1e-6 up to 1e21, else in exponent form. */
    static String jsString(double d) {
        if (Double.isNaN(d)) return "NaN";
        if (Double.isInfinite(d)) return d == Double.POSITIVE_INFINITY ? "Infinity" : "-Infinity";
        if (d == 0) return "0";
        double a = Math.abs(d);
        String sign = a != d ? "-" : "";
        java.math.BigDecimal bd = new java.math.BigDecimal(IntentJs.shortest(a)).stripTrailingZeros();
        if (a >= 1e-6 && a < 1e21) return sign + bd.toPlainString();
        String digits = bd.unscaledValue().toString();
        String e = Integer.toString(digits.length() - 1 - bd.scale());
        String mant = digits.length() == 1 ? digits : digits.charAt(0) + "." + digits.substring(1);
        return sign + mant + "e" + (e.charAt(0) == '-' ? e : "+" + e);
    }

    /** The fold of the monitor over the history (admission order, current statuses). */
    public static String monitorState(Map<String, Object> m, List<?> history) {
        String q = monitorInitialState(m);
        for (Object ev : history) q = monitorStep(m, q, event(ev));
        return q;
    }
}
