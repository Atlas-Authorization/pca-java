package net.atlasauth.pca.ap2;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Json;

/**
 * JavaScript value semantics over parsed JSON (Map, List, String, Boolean, {@link Json.Num}, null) for the AP2 port:
 * number reads by binary64 value, {@code String(v)}, {@code JSON.stringify} (insertion order, integer-like keys first),
 * strict equality, truthiness. {@link #UNDEF} stands for an absent member where JSON null is told apart from it.
 */
final class Js {
    private Js() {}

    static final Object UNDEF = new Object() {
        @Override public String toString() { return "undefined"; }
    };

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Object> arr(Object o) { return (List<Object>) o; }

    static boolean isObj(Object o) { return o instanceof Map; }
    static boolean isArr(Object o) { return o instanceof List; }
    static boolean isStr(Object o) { return o instanceof String; }
    static boolean isNonEmptyStr(Object o) { return o instanceof String && !((String) o).isEmpty(); }

    /** A member read: null for a non-object or an absent key. */
    static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    /** True when the key is present (even with a null value): JavaScript's "!== undefined" for JSON-sourced input. */
    static boolean def(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    /** A member read that tells an absent key ({@link #UNDEF}) from JSON null. */
    static Object getU(Object o, String k) { return def(o, k) ? get(o, k) : UNDEF; }

    static Map<String, Object> m(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    static List<Object> l(Object... xs) { return new ArrayList<>(java.util.Arrays.asList(xs)); }

    // ---- numbers ----
    static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        if (o instanceof Number) return ((Number) o).doubleValue();
        return null;
    }

    static boolean isNumber(Object o) { return num(o) != null; }
    static boolean isNegZero(double d) { return d == 0.0 && Double.doubleToRawLongBits(d) != 0L; }

    static boolean isFinite(Object o) {
        Double d = num(o);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d);
    }

    /** Number.isSafeInteger (accepts -0). */
    static boolean isSafeInteger(Object o) {
        Double d = num(o);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0;
    }

    /** A safe integer that is not -0. */
    static boolean isInt(Object o) { return isSafeInteger(o) && !isNegZero(num(o)); }

    static boolean isNonNegInt(Object o) { return isInt(o) && num(o) >= 0; }

    static Json.Num n(long v) { return new Json.Num(Long.toString(v)); }
    static Json.Num n(double v) { return new Json.Num(AttestCommon.jsNumString(v)); }

    /** Math.round: nearest integer, ties toward +infinity. */
    static double round(double x) {
        if (Double.isNaN(x) || Double.isInfinite(x)) return x;
        double r = Math.floor(x);
        return x - r >= 0.5 ? r + 1 : r;
    }

    // ---- String(v), truthiness, strict equality ----
    static String str(Object v) {
        if (v == UNDEF) return "undefined";
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = num(v);
        if (d != null) return AttestCommon.jsNumString(d);
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                if (x != null && x != UNDEF) sb.append(str(x));
            }
            return sb.toString();
        }
        return "[object Object]";
    }

    static boolean truthy(Object o) {
        if (o == null || o == UNDEF) return false;
        if (o instanceof Boolean) return (Boolean) o;
        if (o instanceof String) return !((String) o).isEmpty();
        Double d = num(o);
        if (d != null) return d != 0.0 && !Double.isNaN(d);
        return true;
    }

    /** The {@code ===} of two parsed values (objects only equal by identity). */
    static boolean sEq(Object a, Object b) {
        if (a == b) return true;
        if (a == null || b == null || a == UNDEF || b == UNDEF) return false;
        if (a instanceof String && b instanceof String) return a.equals(b);
        if (a instanceof Boolean && b instanceof Boolean) return a.equals(b);
        Double x = num(a), y = num(b);
        return x != null && y != null && x.doubleValue() == y.doubleValue();
    }

    // ---- key order and JSON.stringify ----
    private static boolean isIndex(String k) {
        int n = k.length();
        if (n == 0 || n > 10 || (n > 1 && k.charAt(0) == '0')) return false;
        for (int i = 0; i < n; i++) if (k.charAt(i) < '0' || k.charAt(i) > '9') return false;
        return Long.parseLong(k) < 4294967295L;
    }

    /** Own enumerable keys in ECMAScript order: array indices ascending, then the rest in insertion order. */
    static List<String> keyOrder(Map<String, Object> m) {
        List<String> idx = new ArrayList<>(), rest = new ArrayList<>();
        for (String k : m.keySet()) (isIndex(k) ? idx : rest).add(k);
        if (!idx.isEmpty()) idx.sort(Comparator.comparingLong(Long::parseLong));
        idx.addAll(rest);
        return idx;
    }

    /** A deep copy whose objects enumerate their keys in ECMAScript order (what JSON.parse yields). */
    static Object jsOrder(Object v) {
        if (v instanceof Map) {
            Map<String, Object> src = obj(v);
            Map<String, Object> out = new LinkedHashMap<>();
            for (String k : keyOrder(src)) out.put(k, jsOrder(src.get(k)));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(jsOrder(x));
            return out;
        }
        return v;
    }

    /** JSON.stringify; null for undefined. */
    static String stringify(Object v) {
        if (v == UNDEF) return null;
        StringBuilder sb = new StringBuilder();
        ser(sb, v);
        return sb.toString();
    }

    private static void ser(StringBuilder sb, Object v) {
        if (v == null) sb.append("null");
        else if (v instanceof Boolean) sb.append(v.toString());
        else if (v instanceof String) jsString(sb, (String) v);
        else if (isNumber(v)) sb.append(isFinite(v) ? AttestCommon.jsNumString(num(v)) : "null");
        else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                if (x == UNDEF) sb.append("null"); else ser(sb, x);
            }
            sb.append(']');
        } else if (v instanceof Map) {
            Map<String, Object> mm = obj(v);
            sb.append('{');
            boolean first = true;
            for (String k : keyOrder(mm)) {
                Object x = mm.get(k);
                if (x == UNDEF) continue;
                if (!first) sb.append(',');
                first = false;
                jsString(sb, k);
                sb.append(':');
                ser(sb, x);
            }
            sb.append('}');
        } else throw new IllegalArgumentException("not JSON: " + v.getClass());
    }

    private static void jsString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) sb.append(c).append(s.charAt(++i));
                    else if (Character.isSurrogate(c)) sb.append(String.format("\\u%04x", (int) c)); // a lone surrogate is escaped
                    else sb.append(c);
            }
        }
        sb.append('"');
    }

    /** UTF-8 of a JavaScript string: a lone surrogate encodes as U+FFFD (what Buffer.from(s, 'utf8') writes). */
    static byte[] utf8(String s) { return Json.utf8(s); }
}
