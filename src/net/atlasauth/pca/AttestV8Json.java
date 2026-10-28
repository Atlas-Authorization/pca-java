package net.atlasauth.pca;

/**
 * The wording of the reference's JSON.parse failures. The token verifiers embed the engine's message for a malformed header
 * or payload segment into the reason they return ({@code malformed JSON segment: <message>}), so a native verifier that
 * answers the same reason text reproduces it: {@link #v8JsonError} validates a document with the grammar of JSON.parse and,
 * when it is not valid, returns the message V8 reports for it ("" for a valid document). Only the reason text depends on
 * this; whether a segment parses never does. Port of the Go attest_v8json.go.
 */
public final class AttestV8Json {
    private final String src;
    private int pos;
    private String err = "";

    private AttestV8Json(String src) { this.src = src; }

    public static String v8JsonError(String text) {
        AttestV8Json p = new AttestV8Json(text);
        p.value();
        if (!p.err.isEmpty()) return p.err;
        p.ws();
        if (p.pos < p.src.length()) p.fail("Unexpected non-whitespace character after JSON at position %d (line %d column %d)", p.pos);
        return p.err;
    }

    /** UTF-16 slice as text; a lone surrogate renders as U+FFFD (the Go utf16.Decode behaviour). */
    private String dec(int a, int b) {
        StringBuilder sb = new StringBuilder();
        for (int i = a; i < b; i++) {
            char c = src.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < b && Character.isLowSurrogate(src.charAt(i + 1))) {
                sb.append(c).append(src.charAt(++i));
            } else if (Character.isSurrogate(c)) sb.append('�');
            else sb.append(c);
        }
        return sb.toString();
    }

    private int[] location(int position) {
        int line = 1;
        int last = -1;
        for (int i = 0; i < position && i < src.length(); i++) {
            char c = src.charAt(i);
            if (c == '\n' || (c == '\r' && !(i + 1 < src.length() && src.charAt(i + 1) == '\n'))) {
                line++;
                last = i;
            }
        }
        return new int[] {line, position - last};
    }

    /** Records the message; its format takes position, line and column. */
    private void fail(String format, int position) {
        if (!err.isEmpty()) return;
        int[] lc = location(position);
        err = String.format(format, position, lc[0], lc[1]);
    }

    private void failExpected(String what, int position) {
        fail(what + " in JSON at position %d (line %d column %d)", position);
    }

    private void unexpectedEnd() {
        if (err.isEmpty()) err = "Unexpected end of JSON input";
    }

    private void unexpectedToken(int position) {
        if (!err.isEmpty()) return;
        String whole = dec(0, src.length());
        switch (whole) {
            case "NaN": case "Infinity": case "undefined": case "[object Object]":
                err = "\"" + whole + "\" is not valid JSON";
                return;
            default:
                break;
        }
        final int ctx = 10;
        String tok = dec(position, position + 1);
        int n = src.length();
        if (n < ctx * 2 + 1) err = "Unexpected token '" + tok + "', \"" + whole + "\" is not valid JSON";
        else if (position < ctx) err = "Unexpected token '" + tok + "', \"" + dec(0, position + ctx) + "\"... is not valid JSON";
        else if (position < n - ctx) err = "Unexpected token '" + tok + "', ...\"" + dec(position - ctx, position + ctx) + "\"... is not valid JSON";
        else err = "Unexpected token '" + tok + "', ...\"" + dec(position - ctx, n) + "\" is not valid JSON";
    }

    private void ws() {
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
            else return;
        }
    }

    private int peek() { return pos >= src.length() ? -1 : src.charAt(pos); }

    private void value() {
        ws();
        if (!err.isEmpty()) return;
        int c = peek();
        if (c < 0) unexpectedEnd();
        else if (c == '"') str();
        else if (c == '{') object();
        else if (c == '[') array();
        else if (c == '-' || (c >= '0' && c <= '9')) number();
        else if (c == 't') literal("true");
        else if (c == 'f') literal("false");
        else if (c == 'n') literal("null");
        else unexpectedToken(pos);
    }

    private void literal(String word) {
        for (int i = 0; i < word.length(); i++) {
            if (pos >= src.length()) {
                unexpectedEnd();
                return;
            }
            if (src.charAt(pos) != word.charAt(i)) {
                unexpectedToken(pos);
                return;
            }
            pos++;
        }
    }

    private static boolean isDigit(int c) { return c >= '0' && c <= '9'; }

    private void number() {
        if (peek() == '-') {
            pos++;
            if (!isDigit(peek())) {
                failExpected("No number after minus sign", pos);
                return;
            }
        }
        if (peek() == '0') {
            pos++;
            if (isDigit(peek())) {
                fail("Unexpected number in JSON at position %d (line %d column %d)", pos);
                return;
            }
        } else {
            while (isDigit(peek())) pos++;
        }
        if (peek() == '.') {
            pos++;
            if (!isDigit(peek())) {
                failExpected("Unterminated fractional number", pos);
                return;
            }
            while (isDigit(peek())) pos++;
        }
        int c = peek();
        if (c == 'e' || c == 'E') {
            pos++;
            int s = peek();
            if (s == '+' || s == '-') pos++;
            if (!isDigit(peek())) {
                failExpected("Exponent part is missing a number", pos);
                return;
            }
            while (isDigit(peek())) pos++;
        }
    }

    private void str() {
        pos++; // opening quote
        while (true) {
            int c = peek();
            if (c < 0) {
                failExpected("Unterminated string", pos);
                return;
            } else if (c == '"') {
                pos++;
                return;
            } else if (c < 0x20) {
                failExpected("Bad control character in string literal", pos);
                return;
            } else if (c == '\\') {
                pos++;
                int e = peek();
                if (e == '"' || e == '\\' || e == '/' || e == 'b' || e == 'f' || e == 'n' || e == 'r' || e == 't') {
                    pos++;
                } else if (e == 'u') {
                    pos++;
                    for (int i = 0; i < 4; i++) {
                        int h = peek();
                        if (!(isDigit(h) || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F'))) {
                            failExpected("Bad Unicode escape", pos);
                            return;
                        }
                        pos++;
                    }
                } else if (e == -1) {
                    failExpected("Unterminated string", pos);
                    return;
                } else {
                    failExpected("Bad escaped character", pos);
                    return;
                }
            } else {
                pos++;
            }
        }
    }

    private void object() {
        pos++; // {
        ws();
        if (peek() == '}') {
            pos++;
            return;
        }
        if (peek() != '"') {
            failExpected("Expected property name or '}'", pos);
            return;
        }
        while (true) {
            str();
            if (!err.isEmpty()) return;
            ws();
            if (peek() != ':') {
                failExpected("Expected ':' after property name", pos);
                return;
            }
            pos++;
            value();
            if (!err.isEmpty()) return;
            ws();
            int c = peek();
            if (c == ',') {
                pos++;
                ws();
                if (peek() != '"') {
                    failExpected("Expected double-quoted property name", pos);
                    return;
                }
            } else if (c == '}') {
                pos++;
                return;
            } else {
                failExpected("Expected ',' or '}' after property value", pos);
                return;
            }
        }
    }

    private void array() {
        pos++; // [
        ws();
        if (peek() == ']') {
            pos++;
            return;
        }
        while (true) {
            value();
            if (!err.isEmpty()) return;
            ws();
            int c = peek();
            if (c == ',') pos++;
            else if (c == ']') {
                pos++;
                return;
            } else {
                failExpected("Expected ',' or ']' after array element", pos);
                return;
            }
        }
    }
}
