package net.atlasauth.pca.analyzer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Json;

/** JavaScript-flavoured helpers over JSON trees (Map / List / String / Boolean / Json.Num / null) for the analyzer. */
final class Js {
    private Js() {}

    /** The binary64 value of a JSON number, else null. */
    static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        if (o instanceof Integer || o instanceof Long || o instanceof Double || o instanceof Short) return ((Number) o).doubleValue();
        return null;
    }

    /** {@code typeof v === 'number'}. */
    static boolean isNum(Object o) { return num(o) != null; }

    /** {@code typeof v === 'number' && Number.isFinite(v)}. */
    static boolean isFin(Object o) {
        Double d = num(o);
        return d != null && !d.isNaN() && !d.isInfinite();
    }

    /** A number as a JSON value, spelled the way JavaScript prints it. */
    static Json.Num n(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) return new Json.Num(Double.toString(d));
        return new Json.Num(AttestCommon.jsNumString(d));
    }

    static boolean isMap(Object o) { return o instanceof Map; }
    static boolean isList(Object o) { return o instanceof List; }

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Object> list(Object o) { return (List<Object>) o; }

    static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    /** Insertion-ordered object from alternating key / value arguments. */
    static LinkedHashMap<String, Object> obj(Object... kv) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static List<Object> arr(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    static LinkedHashMap<String, Object> copy(Object m) {
        return m instanceof Map ? new LinkedHashMap<>(map(m)) : new LinkedHashMap<>();
    }

    /** A string member, or null when absent or not a string. */
    static String str(Object o, String k) {
        Object v = get(o, k);
        return v instanceof String ? (String) v : null;
    }

    /** {@code a === b}: numbers by value, strings and booleans by value, null with null, anything else by identity. */
    static boolean strictEq(Object a, Object b) {
        if (a == null || b == null) return a == b;
        Double x = num(a), y = num(b);
        if (x != null || y != null) return x != null && y != null && x.doubleValue() == y.doubleValue();
        if (a instanceof String || a instanceof Boolean) return a.equals(b);
        return a == b;
    }

    /** {@code arr.includes(x)} (SameValueZero; NaN cannot occur in JSON). */
    static boolean includes(List<?> xs, Object x) {
        for (Object e : xs) if (strictEq(e, x)) return true;
        return false;
    }

    /** JavaScript's own-key order: array-index keys ascending first, then the rest in insertion order. */
    static List<String> keys(Map<String, Object> m) {
        List<String> idx = new ArrayList<>(), rest = new ArrayList<>();
        for (String k : m.keySet()) (isIndexKey(k) ? idx : rest).add(k);
        idx.sort((a, b) -> Long.compare(Long.parseLong(a), Long.parseLong(b)));
        idx.addAll(rest);
        return idx;
    }

    private static boolean isIndexKey(String k) {
        if (k.isEmpty() || k.length() > 10 || (k.length() > 1 && k.charAt(0) == '0')) return false;
        for (int i = 0; i < k.length(); i++) if (k.charAt(i) < '0' || k.charAt(i) > '9') return false;
        return Long.parseLong(k) < 4294967295L;
    }

    /** {@code JSON.stringify(v)} for a JSON tree (members of value null are kept; there are no undefined members). */
    static String stringify(Object v) {
        StringBuilder sb = new StringBuilder();
        ser(sb, v);
        return sb.toString();
    }

    private static void ser(StringBuilder sb, Object v) {
        Double d = num(v);
        if (v == null) sb.append("null");
        else if (d != null) sb.append(d.isNaN() || d.isInfinite() ? "null" : AttestCommon.jsNumString(d == 0 ? 0.0 : d));
        else if (v instanceof Boolean) sb.append(v.toString());
        else if (v instanceof String) sb.append(Json.canonicalize(v));
        else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) { if (!first) sb.append(','); first = false; ser(sb, x); }
            sb.append(']');
        } else if (v instanceof Map) {
            Map<String, Object> m = map(v);
            sb.append('{');
            boolean first = true;
            for (String k : keys(m)) { if (!first) sb.append(','); first = false; sb.append(Json.canonicalize(k)).append(':'); ser(sb, m.get(k)); }
            sb.append('}');
        } else sb.append("null");
    }

    /** JavaScript truthiness of a JSON value. */
    static boolean truthy(Object o) {
        if (o == null) return false;
        if (o instanceof Boolean) return (Boolean) o;
        if (o instanceof String) return !((String) o).isEmpty();
        Double d = num(o);
        if (d != null) return d != 0 && !d.isNaN();
        return true;
    }

    private static final java.util.regex.Pattern NUMLIT = java.util.regex.Pattern.compile("[+-]?(?:\\d+\\.?\\d*|\\.\\d+)(?:[eE][+-]?\\d+)?|[+-]?Infinity");

    /** JavaScript {@code Number(x)} for a JSON value (NaN when not numeric). */
    static double toNum(Object o) {
        if (o == null) return 0;
        if (o instanceof Boolean) return (Boolean) o ? 1 : 0;
        Double d = num(o);
        if (d != null) return d;
        if (o instanceof String) {
            String t = ((String) o).strip();
            if (t.isEmpty()) return 0;
            return NUMLIT.matcher(t).matches() ? Double.parseDouble(t) : Double.NaN;
        }
        if (o instanceof List && ((List<?>) o).isEmpty()) return 0;
        return Double.NaN;
    }

    /** {@code to[k] = from[fk]} only when {@code from} has the member (an absent member stays absent). */
    static void putIf(Map<String, Object> to, String k, Object from, String fk) {
        if (has(from, fk)) to.put(k, get(from, fk));
    }

    /** A property read on null / undefined throws in JavaScript; so does this. */
    static <T> T req(T o) {
        if (o == null) throw new IllegalArgumentException("cannot read a member of null");
        return o;
    }

    /** JavaScript {@code String(d)} of a number. */
    static String fmt(double d) {
        if (Double.isNaN(d)) return "NaN";
        if (Double.isInfinite(d)) return d > 0 ? "Infinity" : "-Infinity";
        return AttestCommon.jsNumString(d == 0 ? 0.0 : d);
    }

    /** {@code Number(o[k])}, NaN when the member is absent (undefined). */
    static double numOrNaN(Object o, String k) { return has(o, k) ? toNum(get(o, k)) : Double.NaN; }
}
