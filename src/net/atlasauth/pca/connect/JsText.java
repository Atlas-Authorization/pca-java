package net.atlasauth.pca.connect;

import net.atlasauth.pca.Json;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** JavaScript string helpers shared by the connection vault and the connector catalog (URI encoding, trim, regex-style splits, redaction). */
public final class JsText {
    private JsText() {}

    /** encodeURIComponent: everything but A-Za-z0-9 and -_.!~*'() is percent-encoded as UTF-8; a lone surrogate throws (URIError). */
    public static String encodeURIComponent(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            if (cp >= 0xD800 && cp <= 0xDFFF) throw new IllegalArgumentException("URI malformed");
            if ((cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9') || "-_.!~*'()".indexOf(cp) >= 0) {
                sb.append((char) cp);
            } else {
                for (byte b : Json.utf8(new String(Character.toChars(cp)))) sb.append('%').append(String.format("%02X", b & 0xff));
            }
        }
        return sb.toString();
    }

    /** decodeURIComponent: throws IllegalArgumentException (URIError) on a malformed escape or a non-UTF-8 sequence. */
    public static String decodeURIComponent(String s) {
        if (s.indexOf('%') < 0) return s;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < s.length(); ) {
            char c = s.charAt(i);
            if (c == '%') {
                if (i + 2 >= s.length()) throw new IllegalArgumentException("URI malformed");
                int h = hex(s.charAt(i + 1)), l = hex(s.charAt(i + 2));
                if (h < 0 || l < 0) throw new IllegalArgumentException("URI malformed");
                out.write(h * 16 + l);
                i += 3;
            } else {
                int cp = s.codePointAt(i);
                i += Character.charCount(cp);
                byte[] b = Json.utf8(new String(Character.toChars(cp)));
                out.write(b, 0, b.length);
            }
        }
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(out.toByteArray())).toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("URI malformed");
        }
    }

    private static int hex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /** key=value pairs joined with '&amp;', each side through encodeURIComponent, in the map's order. */
    public static String formEncode(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (sb.length() > 0) sb.append('&');
            sb.append(encodeURIComponent(e.getKey())).append('=').append(encodeURIComponent(e.getValue()));
        }
        return sb.toString();
    }

    /** String.prototype.trim (JavaScript whitespace and line terminators). */
    public static String trim(String s) {
        int a = 0, b = s.length();
        while (a < b && net.atlasauth.pca.revoke.JsVal.isSpace(s.charAt(a))) a++;
        while (b > a && net.atlasauth.pca.revoke.JsVal.isSpace(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }

    /** {@code s.split(/[\s]+/)} or {@code s.split(/[\s,]+/)} (JavaScript semantics: leading and trailing empty pieces are kept). */
    public static List<String> splitRuns(String s, boolean commaToo) {
        List<String> out = new ArrayList<>();
        int start = 0, i = 0, n = s.length();
        while (i < n) {
            if (isSep(s.charAt(i), commaToo)) {
                int j = i;
                while (j < n && isSep(s.charAt(j), commaToo)) j++;
                out.add(s.substring(start, i));
                start = j;
                i = j;
            } else i++;
        }
        out.add(s.substring(start));
        return out;
    }

    private static boolean isSep(char c, boolean commaToo) { return net.atlasauth.pca.revoke.JsVal.isSpace(c) || (commaToo && c == ','); }

    /** True when {@code s} contains a JavaScript whitespace character or a comma (the regex /[\s,]/). */
    public static boolean hasSpaceOrComma(String s) {
        for (int i = 0; i < s.length(); i++) if (net.atlasauth.pca.revoke.JsVal.isSpace(s.charAt(i)) || s.charAt(i) == ',') return true;
        return false;
    }

    /** Replace every secret in {@code text} (split/join semantics) so an error message can never carry one. Null and empty secrets are skipped. */
    public static String redact(String text, List<String> secrets) {
        String out = text;
        for (String s : secrets) if (s != null && !s.isEmpty()) out = out.replace(s, "[redacted]");
        return out;
    }

    /** {@code e.message} for an Error; the class name stands in when there is none. */
    public static String errText(Throwable e) { return e.getMessage() == null ? e.toString() : e.getMessage(); }
}
