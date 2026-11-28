package net.atlasauth.pca.goal;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;

/** Small JSON-shaped value helpers shared by the goal modules (a Goal is a Map of parsed JSON, like the TypeScript objects). */
final class G {
    private G() {}

    static final long MAX_SAFE = 9007199254740991L;

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    static List<Object> l(Object o) { return o instanceof List ? (List<Object>) o : null; }

    /** A required object member (IrError when the value is not an object). */
    static Map<String, Object> obj(Object o, String what) {
        Map<String, Object> r = m(o);
        if (r == null) throw new IrError(what + " expected an object");
        return r;
    }

    static List<Object> arr(Object o, String what) {
        List<Object> r = l(o);
        if (r == null) throw new IrError("array expected" + (what.isEmpty() ? "" : " (" + what + ")"));
        return r;
    }

    static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    /** The string at {@code k}; IrError unless it is a string. */
    static String str(Object o, String k) {
        Object v = get(o, k);
        if (!(v instanceof String)) throw new IrError("string expected");
        return (String) v;
    }

    /** The discriminant {@code k} of a value ("" when absent or not a string). */
    static String kind(Object o) {
        Object v = get(o, "k");
        return v instanceof String ? (String) v : "";
    }

    /** Safe-integer value of a JSON number (Json.Num, Long, Integer), or null. -0 and non-integers are null. */
    static Long safeInt(Object v) {
        if (v instanceof Long) return Math.abs((Long) v) <= MAX_SAFE ? (Long) v : null;
        if (v instanceof Integer) return ((Integer) v).longValue();
        if (v instanceof Json.Num) {
            String raw = ((Json.Num) v).raw;
            try {
                BigDecimal d = new BigDecimal(raw);
                if (d.signum() == 0 && raw.startsWith("-")) return null;
                BigInteger i = d.toBigIntegerExact();
                if (i.abs().compareTo(BigInteger.valueOf(MAX_SAFE)) > 0) return null;
                return i.longValue();
            } catch (ArithmeticException | NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /** The number as a JavaScript double, or null when it is not a number. */
    static Double dbl(Object v) {
        if (v instanceof Json.Num) {
            try { return Double.valueOf(((Json.Num) v).raw); } catch (NumberFormatException e) { return null; }
        }
        if (v instanceof Number) return ((Number) v).doubleValue();
        return null;
    }

    static Json.Num num(long v) { return new Json.Num(Long.toString(v)); }

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }

    static List<Object> list(Object... xs) {
        List<Object> r = new ArrayList<>();
        for (Object x : xs) r.add(x);
        return r;
    }

    /** JSON.stringify of a string (no escaping beyond the short forms and \\u00XX below 0x20; lone surrogates as \\udXXX). */
    static String q(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\t': sb.append("\\t"); break;
                case '\n': sb.append("\\n"); break;
                case '\f': sb.append("\\f"); break;
                case '\r': sb.append("\\r"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { sb.append(c).append(s.charAt(++i)); }
                    else if (Character.isSurrogate(c)) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    /** JSON.stringify of any JSON-shaped value with insertion-order keys (an in-memory comparison key, not a signed form). */
    static String stringify(Object v) {
        StringBuilder sb = new StringBuilder();
        stringify(sb, v, false);
        return sb.toString();
    }

    /** The sorted-key, undefined-dropped stable form (UTF-16 code-unit key order). */
    static String stable(Object v) {
        StringBuilder sb = new StringBuilder();
        stringify(sb, v, true);
        return sb.toString();
    }

    private static void stringify(StringBuilder sb, Object v, boolean sorted) {
        if (v == null) sb.append("null");
        else if (v instanceof String) sb.append(q((String) v));
        else if (v instanceof Boolean) sb.append(v.toString());
        else if (v instanceof Json.Num) sb.append(((Json.Num) v).raw);
        else if (v instanceof Number) sb.append(v.toString());
        else if (v instanceof List) {
            sb.append('[');
            boolean f = true;
            for (Object x : (List<?>) v) { if (!f) sb.append(','); f = false; stringify(sb, x, sorted); }
            sb.append(']');
        } else if (v instanceof Map) {
            List<String> ks = new ArrayList<>();
            for (Object k : ((Map<?, ?>) v).keySet()) ks.add((String) k);
            if (sorted) ks.sort(String::compareTo);
            sb.append('{');
            boolean f = true;
            for (String k : ks) { if (!f) sb.append(','); f = false; sb.append(q(k)).append(':'); stringify(sb, ((Map<?, ?>) v).get(k), sorted); }
            sb.append('}');
        } else throw new IllegalArgumentException("unsupported " + v.getClass().getName());
    }

    /** UTF-16 code-unit comparison (JavaScript {@code <} on strings). */
    static int cmp(String a, String b) { return a.compareTo(b); }

    static List<Object> strs(Object o) {
        List<Object> r = new ArrayList<>();
        List<Object> src = l(o);
        if (src != null) r.addAll(src);
        return r;
    }

    /** JavaScript truthiness of a parsed JSON value. */
    static boolean truthy(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = dbl(v);
        if (d != null) return d != 0.0 && !Double.isNaN(d);
        return true;
    }

    /** JavaScript ToNumber of a parsed JSON value (null 0, "" 0, [] 0, [x] ToNumber(x), objects NaN). */
    static double toNum(Object v) {
        if (v == null) return 0;
        if (v instanceof Boolean) return ((Boolean) v) ? 1 : 0;
        Double d = dbl(v);
        if (d != null) return d;
        if (v instanceof String) {
            String t = ((String) v).strip();
            if (t.isEmpty()) return 0;
            if (!t.matches("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?")) return Double.NaN;
            return Double.parseDouble(t);
        }
        if (v instanceof List) {
            List<?> l = (List<?>) v;
            return l.isEmpty() ? 0 : l.size() == 1 ? toNum(l.get(0)) : Double.NaN;
        }
        return Double.NaN;
    }

    /** JavaScript String(v) of a parsed JSON value (template-literal interpolation). */
    static String jsStr(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Json.Num) {
            String raw = ((Json.Num) v).raw;
            try { if (Double.parseDouble(raw) == 0) return "0"; } catch (NumberFormatException e) { /* keep the text */ } // String(-0) is "0"
            return raw;
        }
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean f = true;
            for (Object x : (List<?>) v) { if (!f) sb.append(','); f = false; if (x != null) sb.append(jsStr(x)); }
            return sb.toString();
        }
        if (v instanceof Map) return "[object Object]";
        return String.valueOf(v);
    }

    /** JSON.stringify of a value used as a quoted label (strings quoted, everything else as its JSON text). */
    static String quote(Object v) { return v instanceof String ? q((String) v) : stringify(v); }

    /** Strict number (the value when it is a number, else null). */
    static Double strictNum(Object v) { return v instanceof Json.Num || v instanceof Number ? dbl(v) : null; }
}
