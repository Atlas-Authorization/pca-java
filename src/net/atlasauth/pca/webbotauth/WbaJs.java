package net.atlasauth.pca.webbotauth;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import net.atlasauth.pca.AttestCommon;

/** JavaScript string / number / Buffer semantics the Web Bot Auth port needs. */
final class WbaJs {
    private WbaJs() {}

    /** A parse failure the reference raises as WebBotAuthParseError (its message is part of the verify reason). */
    static final class ParseError extends RuntimeException {
        ParseError(String message) { super(message); }
    }

    /** JavaScript's whitespace + line terminator set (String.prototype.trim). */
    static boolean isWs(char c) {
        return c == ' ' || (c >= 0x09 && c <= 0x0d) || c == 0xa0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029
            || c == 0x202f || c == 0x205f || c == 0x3000 || c == 0xfeff;
    }

    static String trim(String s) {
        int a = 0, b = s.length();
        while (a < b && isWs(s.charAt(a))) a++;
        while (b > a && isWs(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }

    /** The number value of a parsed JSON number (NaN when it is not one). */
    static double number(Object o) {
        Double d = net.atlasauth.pca.oauth.JsVal.num(o);
        return d == null ? Double.NaN : d;
    }

    static String lower(String s) { return s.toLowerCase(Locale.ROOT); }

    static boolean def(Object m, String k) { return m instanceof Map && ((Map<?, ?>) m).containsKey(k); }

    static Object get(Object m, String k) { return m instanceof Map ? ((Map<?, ?>) m).get(k) : null; }

    /** Buffer.from(s, "base64"): standard and URL-safe alphabets, other characters skipped, decoding stops at the first "=", dangling bits dropped. */
    static byte[] nodeBase64(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int acc = 0, bits = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '=') break;
            int v = c >= 'A' && c <= 'Z' ? c - 'A' : c >= 'a' && c <= 'z' ? c - 'a' + 26 : c >= '0' && c <= '9' ? c - '0' + 52 : c == '+' || c == '-' ? 62 : c == '/' || c == '_' ? 63 : -1;
            if (v < 0) continue;
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) { bits -= 8; out.write((acc >> bits) & 0xff); acc &= (1 << bits) - 1; }
        }
        return out.toByteArray();
    }

    /** base64 (standard alphabet, padded). */
    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }

    static String numStr(double d) { return AttestCommon.jsNumString(d); }

    /** String(v) of a parameter value (String, Double or Boolean) or of undefined. */
    static String str(Object v) {
        if (v == null) return "undefined";
        if (v instanceof Double) return numStr((Double) v);
        return v.toString();
    }

    /** String(v) of any parsed JSON value. */
    static String anyStr(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = net.atlasauth.pca.oauth.JsVal.num(v);
        if (d != null) return numStr(d);
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                if (x != null) sb.append(anyStr(x));
            }
            return sb.toString();
        }
        return "[object Object]";
    }

    /** An RFC 8941 sf-string: quoted, with backslash and double quote escaped. */
    static String sfString(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }

    /** First element joined as in Array.prototype.join for a list of strings. */
    static String join(List<String> l, String sep) { return String.join(sep, l); }
}
