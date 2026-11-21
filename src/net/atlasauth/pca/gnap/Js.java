package net.atlasauth.pca.gnap;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;

/** JavaScript value semantics the reference relies on (truthiness, member reads, String(), JSON.stringify). */
final class Js {
    private Js() {}

    /** Marks an argument or member that is absent (JavaScript {@code undefined}); a Java null is a JSON null. */
    static final Object ABSENT = new Object();

    static boolean truthy(Object v) {
        if (v == null || v == ABSENT) return false;
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = num(v);
        if (d != null) return d != 0.0 && !Double.isNaN(d);
        return true;
    }

    static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        if (o instanceof Number) return ((Number) o).doubleValue();
        return null;
    }

    /** {@code o[k]} for an object; every other value has no such member (null stands for undefined here). */
    static Object member(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    /** {@code o[k]}, or {@link #ABSENT} when the member is not there. */
    static Object get(Object o, String k) { return has(o, k) ? ((Map<?, ?>) o).get(k) : ABSENT; }

    static boolean isObject(Object o) { return o instanceof Map || o instanceof List; }

    /** JavaScript {@code String(v)} for the values a JSON document holds. */
    static String str(Object v) {
        if (v == null) return "null";
        if (v == ABSENT) return "undefined";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        if (v instanceof Json.Num) return ((Json.Num) v).raw;
        if (v instanceof Number) return v instanceof Double ? numText((Double) v) : v.toString();
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                if (x != null) sb.append(str(x));
            }
            return sb.toString();
        }
        return "[object Object]";
    }

    private static String numText(double d) {
        if (d == Math.rint(d) && Math.abs(d) < 1e21) return new java.math.BigDecimal(d).toPlainString();
        return Double.toString(d);
    }

    static byte[] utf8(String s) {
        // TextEncoder writes a lone surrogate as U+FFFD (Java's encoder writes '?')
        StringBuilder sb = null;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean lone = false;
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { if (sb != null) sb.append(c).append(s.charAt(i + 1)); i++; continue; }
                lone = true;
            } else if (Character.isLowSurrogate(c)) lone = true;
            if (lone && sb == null) { sb = new StringBuilder(s.length()); sb.append(s, 0, i); }
            if (sb != null) sb.append(lone ? '\ufffd' : c);
        }
        return Json.utf8((sb == null ? s : sb.toString()));
    }

    static byte[] sha(String alg, byte[] b) {
        try { return MessageDigest.getInstance(alg).digest(b); } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    static byte[] sha256(byte[] b) { return sha("SHA-256", b); }

    /** {@code JSON.stringify} of a JSON value: insertion order of members, numbers as printed, lone surrogates escaped. */
    static String stringify(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object v) {
        if (v == null) sb.append("null");
        else if (v instanceof Boolean) sb.append(v.toString());
        else if (v instanceof Json.Num) sb.append(((Json.Num) v).raw.equals("-0") ? "0" : ((Json.Num) v).raw);
        else if (v instanceof Number) sb.append(str(v));
        else if (v instanceof String) string(sb, (String) v);
        else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                write(sb, x);
            }
            sb.append(']');
        } else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                string(sb, (String) e.getKey());
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
        } else throw new IllegalArgumentException("not a JSON value: " + v.getClass().getName());
    }

    private static void string(StringBuilder sb, String s) {
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
                    else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { sb.append(c).append(s.charAt(++i)); }
                    else if (Character.isSurrogate(c)) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }
}
