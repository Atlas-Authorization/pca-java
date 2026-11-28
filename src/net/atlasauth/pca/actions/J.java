package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import net.atlasauth.pca.Json;

/** Small JSON-tree helpers shared by the action-kit ports (values are Map / List / String / Boolean / Json.Num / null). */
final class J {
    private J() {}

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> a(Object o) { return (List<Object>) o; }
    static boolean isMap(Object o) { return o instanceof Map; }
    static boolean isList(Object o) { return o instanceof List; }
    static boolean isStr(Object o) { return o instanceof String; }
    static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }
    static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        if (o instanceof Integer || o instanceof Long || o instanceof Double || o instanceof Short) return ((Number) o).doubleValue();
        return null;
    }

    /** {@code Number.isSafeInteger(v) && !Object.is(v, -0)}. */
    static boolean isInt(Object o) {
        Double d = num(o);
        if (d == null || d.isNaN() || d.isInfinite() || d != Math.rint(d) || Math.abs(d) > 9007199254740991.0) return false;
        return !(d == 0.0 && 1.0 / d < 0);
    }

    static Json.Num n(long v) { return new Json.Num(Long.toString(v)); }

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(java.util.Arrays.asList(xs)); }

    /** Sorted, de-duplicated strings of a list (non-strings are dropped). */
    static List<String> sortUniq(Object xs) {
        TreeSet<String> out = new TreeSet<>();
        if (xs instanceof List) for (Object x : (List<?>) xs) if (x instanceof String) out.add((String) x);
        return new ArrayList<>(out);
    }

    static List<Object> objs(List<String> xs) { return new ArrayList<Object>(xs); }

    // ---- JSON.stringify (compact): JavaScript key order and number spelling, for sameJson-style comparisons ----

    /** {@code JSON.stringify(v)}; {@code null} stands for JavaScript {@code undefined} at the top level only via {@link #sameJson}. */
    @SuppressWarnings("unchecked")
    static String stringify(Object v) {
        if (v == null) return "null";
        if (v instanceof Boolean) return v.toString();
        if (v instanceof String) return quote((String) v);
        Double d = num(v);
        if (d != null) return d.isNaN() || d.isInfinite() ? "null" : net.atlasauth.pca.AttestCommon.jsNumString(d);
        if (v instanceof List) {
            StringBuilder b = new StringBuilder("[");
            boolean first = true;
            for (Object x : (List<Object>) v) { if (!first) b.append(','); first = false; b.append(stringify(x)); }
            return b.append(']').toString();
        }
        Map<String, Object> m = (Map<String, Object>) v;
        List<String> idx = new ArrayList<>(), rest = new ArrayList<>();
        for (String k : m.keySet()) (isIndexKey(k) ? idx : rest).add(k);
        idx.sort((x, y) -> Long.compare(Long.parseLong(x), Long.parseLong(y)));
        idx.addAll(rest);
        StringBuilder b = new StringBuilder("{");
        boolean first = true;
        for (String k : idx) { if (!first) b.append(','); first = false; b.append(quote(k)).append(':').append(stringify(m.get(k))); }
        return b.append('}').toString();
    }

    private static boolean isIndexKey(String k) {
        if (k.isEmpty() || k.length() > 10 || (k.length() > 1 && k.charAt(0) == '0')) return false;
        for (int i = 0; i < k.length(); i++) if (k.charAt(i) < '0' || k.charAt(i) > '9') return false;
        return Long.parseLong(k) < 4294967295L;
    }

    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    boolean lone = false;
                    if (Character.isHighSurrogate(c)) { if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { b.append(c).append(s.charAt(++i)); continue; } lone = true; }
                    else if (Character.isLowSurrogate(c)) lone = true;
                    if (c < 0x20 || lone) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    /** {@code JSON.stringify(a) === JSON.stringify(b)} where a Java null on BOTH sides stands for {@code undefined} (absent). */
    static boolean sameJson(Object a, boolean aPresent, Object b, boolean bPresent) {
        if (!aPresent || !bPresent) return !aPresent && !bPresent;
        return stringify(sortKeys(a)).equals(stringify(sortKeys(b)));
    }

    /** Object keys sorted recursively (UTF-16 order), list order kept: key order is not meaning (a stored def comes back sorted, a fresh one in author order). */
    @SuppressWarnings("unchecked")
    static Object sortKeys(Object v) {
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<Object>) v) out.add(sortKeys(x)); return out; }
        if (v instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) v;
            Map<String, Object> out = new java.util.LinkedHashMap<>();
            for (String k : new java.util.TreeMap<>(m).keySet()) out.put(k, sortKeys(m.get(k)));
            return out;
        }
        return v;
    }

    static boolean sameJsonMember(Object ma, Object mb, String key) { return sameJson(get(ma, key), has(ma, key), get(mb, key), has(mb, key)); }

    /** JavaScript String(v) for a JSON value. */
    static String jsStr(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = num(v);
        if (d != null) return net.atlasauth.pca.AttestCommon.jsNumString(d);
        if (v instanceof List) {
            StringBuilder b = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) { if (!first) b.append(','); first = false; if (x != null) b.append(jsStr(x)); }
            return b.toString();
        }
        return "[object Object]";
    }

    /** JavaScript white space (WhiteSpace and LineTerminator). */
    static boolean jsSpace(char c) {
        return (c >= 9 && c <= 13) || c == 32 || c == 0xa0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f || c == 0x205f || c == 0x3000 || c == 0xfeff;
    }

    /** {@code s.trim()}. */
    static String jsTrim(String s) {
        int a = 0, b = s.length();
        while (a < b && jsSpace(s.charAt(a))) a++;
        while (b > a && jsSpace(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }
}
