package net.atlasauth.pca.acp;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.oauth.JsVal;

/** JavaScript value semantics over parsed JSON, shared by the ACP / x402 ports. */
final class AcpJs {
    private AcpJs() {}

    static boolean isObj(Object o) { return o instanceof Map; }

    /** JavaScript "!== undefined" on a member of a JSON-sourced object: the key is present (null counts). */
    static boolean def(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    static boolean isString(Object o) { return o instanceof String; }

    static boolean nonEmpty(Object o) { return o instanceof String && !((String) o).isEmpty(); }

    /** Number.isSafeInteger over a JSON number (typeof number). */
    static boolean isSafeInteger(Object o) {
        Double d = JsVal.num(o);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.floor(d) && Math.abs(d) <= 9007199254740991.0;
    }

    /** Safe integer and not -0. */
    static boolean isInt(Object o) { return isSafeInteger(o) && !JsVal.isNegZero(o); }

    /** Positive safe integer (an amount in minor units). */
    static boolean isAmount(Object o) { return isSafeInteger(o) && JsVal.num(o) > 0; }

    /** JavaScript ToNumber over a parsed value (relational comparison coerces; an absent member is NaN, see {@link #dblField}). */
    static double dbl(Object o) {
        Double d = JsVal.num(o);
        if (d != null) return d;
        if (o == null) return 0.0;
        if (o instanceof Boolean) return ((Boolean) o) ? 1.0 : 0.0;
        if (o instanceof List) return fromString(str(o));
        if (o instanceof String) return fromString((String) o);
        return Double.NaN;
    }

    /** ToNumber of a member; undefined (absent) is NaN. */
    static double dblField(Object m, String k) { return def(m, k) ? dbl(get(m, k)) : Double.NaN; }

    private static final Pattern DEC = Pattern.compile("[+-]?(?:[0-9]+\\.?[0-9]*|\\.[0-9]+)(?:[eE][+-]?[0-9]+)?");

    /** StringToNumber. */
    static double fromString(String raw) {
        String s = raw.replaceAll("^[\\s\\u00a0\\ufeff\\u2028\\u2029\\u1680\\u2000-\\u200a\\u202f\\u205f\\u3000]+|[\\s\\u00a0\\ufeff\\u2028\\u2029\\u1680\\u2000-\\u200a\\u202f\\u205f\\u3000]+$", "");
        if (s.isEmpty()) return 0.0;
        if (s.equals("Infinity") || s.equals("+Infinity")) return Double.POSITIVE_INFINITY;
        if (s.equals("-Infinity")) return Double.NEGATIVE_INFINITY;
        try {
            if (s.length() > 2 && s.charAt(0) == '0') {
                char c = s.charAt(1);
                int radix = c == 'x' || c == 'X' ? 16 : c == 'o' || c == 'O' ? 8 : c == 'b' || c == 'B' ? 2 : 0;
                if (radix != 0) return new java.math.BigInteger(s.substring(2), radix).doubleValue();
            }
        } catch (NumberFormatException e) {
            return Double.NaN;
        }
        return DEC.matcher(s).matches() ? Double.parseDouble(s) : Double.NaN;
    }

    /** Object spread ({...v}) of a parsed value into a fresh map: maps copy, strings and lists give index keys, anything else is empty. */
    static Map<String, Object> spread(Object v) {
        Map<String, Object> out = new java.util.LinkedHashMap<>();
        if (v instanceof Map) { for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) out.put((String) e.getKey(), e.getValue()); }
        else if (v instanceof List) { int i = 0; for (Object x : (List<?>) v) out.put(Integer.toString(i++), x); }
        else if (v instanceof String) { String t = (String) v; for (int i = 0; i < t.length(); i++) out.put(Integer.toString(i), String.valueOf(t.charAt(i))); }
        return out;
    }

    static long lng(Object o) { return (long) (double) JsVal.num(o); }

    static Json.Num num(long v) { return new Json.Num(Long.toString(v)); }

    /** String(v) for a parsed JSON value (template-literal interpolation). */
    static String str(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = JsVal.num(v);
        if (d != null) return AttestCommon.jsNumString(d);
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

    /** Whole-string regex match (JavaScript "^...$" without the m flag). */
    static boolean matches(Pattern p, Object s) { return s instanceof String && p.matcher((String) s).matches(); }

    private static final Pattern B64 = Pattern.compile("[A-Za-z0-9+/]+={0,2}");

    static boolean looksBase64(Object v) { return matches(B64, v); }

    /** Node Buffer.from(s, "base64") over a string that passed {@link #looksBase64}: unpadded input and dangling bits are tolerated. */
    static byte[] b64decode(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '=') end--;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int acc = 0, bits = 0;
        for (int i = 0; i < end; i++) {
            char c = s.charAt(i);
            int v = c >= 'A' && c <= 'Z' ? c - 'A' : c >= 'a' && c <= 'z' ? c - 'a' + 26 : c >= '0' && c <= '9' ? c - '0' + 52 : c == '+' ? 62 : 63;
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) { bits -= 8; out.write((acc >> bits) & 0xff); acc &= (1 << bits) - 1; }
        }
        return out.toByteArray();
    }

    static String b64encode(String text) { return Base64.getEncoder().encodeToString(Json.utf8(text)); }

    /** JSON.stringify of a parsed or built value (insertion order). */
    static String stringify(Object v) { return JsVal.stringify(v); }

    /** JSON.parse; throws IllegalArgumentException on bad JSON. */
    static Object parse(String s) { return Json.parseLenient(s); }
}
