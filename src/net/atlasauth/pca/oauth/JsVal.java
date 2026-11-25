package net.atlasauth.pca.oauth;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;

/**
 * JavaScript value semantics over parsed JSON (Map, List, String, Boolean, {@link Json.Num}, null), shared by the OAuth-family
 * ports: truthiness, number reads, typeof checks and JSON.stringify (insertion-ordered, unlike the canonical form).
 */
public final class JsVal {
    private JsVal() {}

    /** JavaScript truthiness: null, false, "", 0 and NaN are falsy; everything else is truthy. */
    public static boolean truthy(Object o) {
        if (o == null) return false;
        if (o instanceof Boolean) return (Boolean) o;
        if (o instanceof String) return !((String) o).isEmpty();
        Double d = num(o);
        if (d != null) return d != 0.0 && !Double.isNaN(d);
        return true;
    }

    /** The JavaScript number value of a JSON number or Java number; null when not a number. */
    public static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        if (o instanceof Number) return ((Number) o).doubleValue();
        return null;
    }

    public static boolean isNumber(Object o) { return num(o) != null; }

    /** Number.isInteger plus the safe range check used by the references (finite, integral). */
    public static boolean isInteger(Object o) {
        Double d = num(o);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.floor(d);
    }

    public static boolean isNegZero(Object o) {
        Double d = num(o);
        return d != null && d == 0.0 && Double.doubleToRawLongBits(d) != 0L;
    }

    /** typeof x === 'object' && x !== null (an array counts, as in JavaScript). */
    public static boolean isObjectLike(Object o) { return o instanceof Map || o instanceof List; }

    /** A member read: null for a non-object or an absent key (undefined and null are not told apart). */
    public static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    /** True when the key is present with a value other than null (JavaScript "!== undefined" for JSON-sourced input). */
    public static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).get(k) != null; }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> map(Object o) { return o instanceof Map ? (Map<String, Object>) o : Collections.emptyMap(); }

    @SuppressWarnings("unchecked")
    public static List<Object> list(Object o) { return (List<Object>) o; }

    public static boolean allStrings(Object o) {
        if (!(o instanceof List)) return false;
        for (Object x : (List<?>) o) if (!(x instanceof String)) return false;
        return true;
    }

    public static boolean allNumbers(Object o) {
        if (!(o instanceof List)) return false;
        for (Object x : (List<?>) o) if (!isNumber(x)) return false;
        return true;
    }

    /** A shallow copy of a list ([...xs]). */
    public static List<Object> copy(Object o) { return new ArrayList<>(list(o)); }

    /** JSON.stringify of a parsed value (member order as inserted). */
    public static String stringify(Object v) {
        StringBuilder sb = new StringBuilder();
        ser(sb, v);
        return sb.toString();
    }

    private static void ser(StringBuilder sb, Object v) {
        if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append(Json.canonicalize(String.valueOf(e.getKey()))).append(':');
                ser(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                ser(sb, x);
            }
            sb.append(']');
        } else {
            sb.append(Json.canonicalize(v));
        }
    }

    /** An insertion-ordered result map. */
    public static Map<String, Object> obj() { return new LinkedHashMap<>(); }

    public static Json.Num n(long v) { return new Json.Num(Long.toString(v)); }
}
