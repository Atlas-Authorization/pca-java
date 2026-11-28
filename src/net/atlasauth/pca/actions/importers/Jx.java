package net.atlasauth.pca.actions.importers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import net.atlasauth.pca.Json;

/** Small JSON-tree helpers shared by the action-kit ports (values are Map / List / String / Boolean / Json.Num / null). */
final class Jx {
    private Jx() {}

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
        return stringify(a).equals(stringify(b));
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

    // ---- additions for the importers ----

    /** {@code Number.isSafeInteger(v)} (so -0 counts). */
    static boolean isSafe(Object o) {
        Double d = num(o);
        return d != null && !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0;
    }

    /** Marks an absent member (JavaScript {@code undefined}) where a present JSON null differs. */
    static final Object UNDEF = new Object();

    static Object getU(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k) ? ((Map<?, ?>) o).get(k) : UNDEF; }

    /** JavaScript truthiness of a JSON value. */
    static boolean truthy(Object v) {
        if (v == null || v == UNDEF) return false;
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = num(v);
        if (d != null) return !(d == 0.0 || d.isNaN());
        return true;
    }

    /** UTF-8 bytes as TextEncoder writes them: a lone surrogate is U+FFFD. */
    static byte[] utf8(String s) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);
            if (Character.isHighSurrogate((char) c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { c = Character.toCodePoint((char) c, s.charAt(++i)); }
            else if (c >= 0xD800 && c <= 0xDFFF) c = 0xFFFD;
            if (c < 0x80) o.write(c);
            else if (c < 0x800) { o.write(0xC0 | (c >> 6)); o.write(0x80 | (c & 63)); }
            else if (c < 0x10000) { o.write(0xE0 | (c >> 12)); o.write(0x80 | ((c >> 6) & 63)); o.write(0x80 | (c & 63)); }
            else { o.write(0xF0 | (c >> 18)); o.write(0x80 | ((c >> 12) & 63)); o.write(0x80 | ((c >> 6) & 63)); o.write(0x80 | (c & 63)); }
        }
        return o.toByteArray();
    }

    static int u8(String s) { return utf8(s).length; }

    static byte[] sha256(byte[] b) {
        try { return java.security.MessageDigest.getInstance("SHA-256").digest(b); } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    /** Object.keys order: integer-like keys ascending, then the rest in insertion order. */
    static List<String> keys(Map<String, Object> m) {
        List<String> idx = new ArrayList<>(), rest = new ArrayList<>();
        for (String k : m.keySet()) (isIndexKey(k) ? idx : rest).add(k);
        idx.sort((x, y) -> Long.compare(Long.parseLong(x), Long.parseLong(y)));
        idx.addAll(rest);
        return idx;
    }

    /** {@code {...src}} into {@code dst}: an object copies its members, a string or array its indexed entries, anything else nothing. */
    @SuppressWarnings("unchecked")
    static void spread(Map<String, Object> dst, Object src) {
        if (src instanceof Map) dst.putAll((Map<String, Object>) src);
        else if (src instanceof String) { String s = (String) src; for (int i = 0; i < s.length(); i++) dst.put(Integer.toString(i), String.valueOf(s.charAt(i))); }
        else if (src instanceof List) { List<Object> l = (List<Object>) src; for (int i = 0; i < l.size(); i++) dst.put(Integer.toString(i), l.get(i)); }
    }

    /** {@code [...x]} of a value that is an array, a string (its code points) or null/absent (caller handles); anything else throws as the engine does. */
    static List<Object> spreadList(Object x) {
        List<Object> out = new ArrayList<>();
        if (x instanceof List) out.addAll(a(x));
        else if (x instanceof String) { String s = (String) x; for (int i = 0; i < s.length(); ) { int cp = s.codePointAt(i); out.add(new String(Character.toChars(cp))); i += Character.charCount(cp); } }
        else throw new IllegalArgumentException("not iterable");
        return out;
    }

    /** decodeURIComponent; null when the engine would throw URIError. */
    static String decodeUriComponent(String s) {
        StringBuilder b = new StringBuilder();
        int n = s.length();
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            if (c != '%') { b.append(c); continue; }
            int b0 = hexByte(s, i);
            if (b0 < 0) return null;
            i += 2;
            if (b0 < 0x80) { b.append((char) b0); continue; }
            int need, cp, min;
            if ((b0 & 0xE0) == 0xC0) { need = 1; cp = b0 & 0x1F; min = 0x80; }
            else if ((b0 & 0xF0) == 0xE0) { need = 2; cp = b0 & 0x0F; min = 0x800; }
            else if ((b0 & 0xF8) == 0xF0) { need = 3; cp = b0 & 0x07; min = 0x10000; }
            else return null;
            for (int k = 0; k < need; k++) {
                if (i + 1 >= n || s.charAt(i + 1) != '%') return null;
                int bx = hexByte(s, i + 1);
                if (bx < 0 || (bx & 0xC0) != 0x80) return null;
                cp = (cp << 6) | (bx & 0x3F);
                i += 3;
            }
            if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return null;
            b.appendCodePoint(cp);
        }
        return b.toString();
    }

    private static int hexByte(String s, int i) {
        if (i + 2 >= s.length()) return -1;
        int h = Character.digit(s.charAt(i + 1), 16), l = Character.digit(s.charAt(i + 2), 16);
        return h < 0 || l < 0 || s.charAt(i + 1) > 0x7f || s.charAt(i + 2) > 0x7f ? -1 : h * 16 + l;
    }
}
