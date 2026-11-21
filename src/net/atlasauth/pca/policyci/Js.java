package net.atlasauth.pca.policyci;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Json;

/** JavaScript-flavoured helpers over JSON trees (Map / List / String / Boolean / Json.Num / null) for the policy linter. */
final class Js {
    private Js() {}

    static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }
    static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    /** {@code typeof x === 'object' && x !== null}: an object or an array. */
    static boolean isObject(Object o) { return o instanceof Map || o instanceof List; }
    /** A record: a non-null, non-array object. */
    static boolean isRecord(Object o) { return o instanceof Map; }

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** The binary64 value of a JSON number, else null. */
    static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        if (o instanceof Integer || o instanceof Long || o instanceof Double || o instanceof Short) return ((Number) o).doubleValue();
        return null;
    }

    /** The reference {@code num}: a finite number, else null. */
    static Double finite(Object o) {
        Double d = num(o);
        return d != null && !d.isNaN() && !d.isInfinite() ? d : null;
    }

    static String numStr(double d) { return AttestCommon.jsNumString(d); }

    /** A number as a JSON value, spelled the way JavaScript prints it. */
    static Json.Num n(long v) { return new Json.Num(Long.toString(v)); }

    /** JavaScript {@code String(v)} for a JSON value; {@code present=false} is the {@code undefined} of a missing member. */
    static String str(Object v, boolean present) {
        if (!present) return "undefined";
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = num(v);
        if (d != null) return numStr(d);
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                if (x != null) sb.append(str(x, true));
            }
            return sb.toString();
        }
        return "[object Object]";
    }

    static String str(Object v) { return str(v, true); }

    /** {@code JSON.stringify} of a JSON tree (insertion order, no whitespace). */
    static String stringify(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof String) { quote(sb, (String) v); return; }
        if (v instanceof Boolean) { sb.append(v); return; }
        Double d = num(v);
        if (d != null) { sb.append(d.isNaN() || d.isInfinite() ? "null" : d == 0 ? "0" : numStr(d)); return; }
        if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) { if (!first) sb.append(','); first = false; write(sb, x); }
            sb.append(']');
            return;
        }
        if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                quote(sb, (String) e.getKey());
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
            return;
        }
        throw new IllegalArgumentException("not JSON");
    }

    private static void quote(StringBuilder sb, String s) {
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
                    else if (Character.isSurrogate(c)) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }

    /** {@code Array.prototype.join(" ")}: a missing or null element joins as the empty string. */
    static String joinSpace(List<Object> parts) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.size(); i++) {
            if (i > 0) sb.append(' ');
            Object p = parts.get(i);
            if (p != null) sb.append(str(p, true));
        }
        return sb.toString();
    }

    static List<Object> list() { return new ArrayList<>(); }

    private static boolean isWs(char c) {
        switch (c) {
            case '\t': case '\n': case '\u000B': case '\f': case '\r': case ' ': case '\u00a0': case '\u1680':
            case '\u2028': case '\u2029': case '\u202f': case '\u205f': case '\u3000': case '\ufeff':
                return true;
            default:
                return c >= '\u2000' && c <= '\u200a';
        }
    }

    /** {@code String.prototype.trim}. */
    static String trim(String s) {
        int a = 0, b = s.length();
        while (a < b && isWs(s.charAt(a))) a++;
        while (b > a && isWs(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }
}
