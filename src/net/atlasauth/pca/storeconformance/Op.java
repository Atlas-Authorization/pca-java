package net.atlasauth.pca.storeconformance;

import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.doctor.Js;

/**
 * One recorded operation on one key of a replay / counter store. Each carries a threshold {@code lo} and a write value {@code w}:
 * {@code consumeOnce(key, retainUntil, now)} has lo = now, w = retainUntil; {@code advance(stream, counter)} has lo = w = counter.
 * {@code call} is recorded BEFORE the request leaves the client; {@code ret} is the response time, infinite when the outcome is
 * unknown (the operation may still take effect at any later time).
 */
public final class Op {
    public final String client;
    /** {@code consume} or {@code advance} (any other value is treated as advance by the formatter, as the reference does). */
    public final Object kind;
    public final String key;
    public final double lo, w, call;
    public double ret;
    /** {@code true}, {@code false} or {@code unknown}. */
    public String res;

    public Op(String client, Object kind, String key, double lo, double w, double call, double ret, String res) {
        this.client = client; this.kind = kind; this.key = key; this.lo = lo; this.w = w; this.call = call; this.ret = ret; this.res = res;
    }

    /** A number as the corpus spells it: a finite value, or {"$num": "Infinity"}. */
    public static Object numJson(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("$num", Double.isNaN(d) ? "NaN" : d > 0 ? "Infinity" : "-Infinity");
            return m;
        }
        return d;
    }

    /** A number from JSON: a plain number, or {"$num": "Infinity" | "-Infinity"}. */
    public static double numOf(Object o) {
        if (o instanceof Map && ((Map<?, ?>) o).get("$num") instanceof String) {
            String s = (String) ((Map<?, ?>) o).get("$num");
            return s.equals("Infinity") ? Double.POSITIVE_INFINITY : s.equals("-Infinity") ? Double.NEGATIVE_INFINITY : Double.NaN;
        }
        return Js.toNumber(o);
    }

    @SuppressWarnings("unchecked")
    public static Op fromJson(Object o) {
        Map<String, Object> m = (Map<String, Object>) o;
        return new Op(Js.str(m.get("client")), m.get("kind"), Js.str(m.get("key")), numOf(m.get("lo")), numOf(m.get("w")), numOf(m.get("call")), numOf(m.get("ret")), (String) m.get("res"));
    }

    public Map<String, Object> toJson() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("client", client);
        m.put("kind", kind);
        m.put("key", key);
        m.put("lo", numJson(lo));
        m.put("w", numJson(w));
        m.put("call", numJson(call));
        m.put("ret", numJson(ret));
        m.put("res", res);
        return m;
    }

    boolean isConsume() { return "consume".equals(kind); }
}
