package net.atlasauth.pca.policybridge;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.IntentJs;

/**
 * JavaScript string semantics the policy translators depend on: the exact whitespace set of {@code \s} / {@code trim()},
 * ASCII word boundaries, {@code slice}, {@code JSON.stringify} of strings, the top-level splitters, and the key order of
 * {@code Object.entries}. Regex fragments are built so a Java pattern matches what the JavaScript pattern matches.
 */
final class Js {
    private Js() {}

    /** The characters of JavaScript {@code \s} (WhiteSpace and LineTerminator). */
    static final String WS = "\\t\\n\\u000B\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff";
    static final String S = "[" + WS + "]";
    static final String NS = "[^" + WS + "]";
    /** JavaScript {@code .} (no dotAll): everything but the four line terminators. */
    static final String DOT = "[^\\n\\r\\u2028\\u2029]";
    /** JavaScript {@code \b} next to a {@code \w} character ({@code \w} is ASCII only). */
    static final String WB_L = "(?<![A-Za-z0-9_])";
    static final String WB_R = "(?![A-Za-z0-9_])";

    private static final Pattern WS_RUN = Pattern.compile(S + "+");

    static boolean isWs(char c) {
        switch (c) {
            case '\t': case '\n': case '\u000B': case '\f': case '\r': case ' ': case ' ': case ' ':
            case ' ': case ' ': case ' ': case ' ': case '　': case '﻿':
                return true;
            default:
                return c >= ' ' && c <= ' ';
        }
    }

    /** {@code String.prototype.trim}. */
    static String trim(String s) {
        int a = 0, b = s.length();
        while (a < b && isWs(s.charAt(a))) a++;
        while (b > a && isWs(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }

    /** {@code String.prototype.slice(from, to)}. */
    static String slice(String s, int from, int to) {
        int n = s.length();
        int a = from < 0 ? Math.max(n + from, 0) : Math.min(from, n);
        int b = to < 0 ? Math.max(n + to, 0) : Math.min(to, n);
        return a >= b ? "" : s.substring(a, b);
    }

    static String slice(String s, int from) { return slice(s, from, s.length()); }

    static boolean isAsciiLetter(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
    static boolean isIdentStart(char c) { return isAsciiLetter(c) || c == '_'; }
    static boolean isIdentPart(char c) { return isIdentStart(c) || (c >= '0' && c <= '9'); }
    static boolean isDigit(char c) { return c >= '0' && c <= '9'; }

    /** {@code truncate}: whitespace collapsed to one space, at most 80 UTF-16 units. */
    static String truncate(String s) {
        String one = trim(WS_RUN.matcher(s).replaceAll(" "));
        return one.length() > 80 ? slice(one, 0, 77) + "..." : one;
    }

    /** {@code JSON.stringify} of a string (well-formed: a lone surrogate is escaped). */
    static String jsonStr(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
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
        return sb.append('"').toString();
    }

    /** {@code JSON.stringify} of a verb: a string or a list of strings. */
    static String jsonVerb(Object verb) {
        if (verb instanceof String) return jsonStr((String) verb);
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Object o : (List<?>) verb) {
            if (!first) sb.append(',');
            first = false;
            sb.append(jsonStr((String) o));
        }
        return sb.append(']').toString();
    }

    /** A JavaScript number from its decimal text, as the JSON number the reference serializes. */
    static Object number(String text) { return IntentJs.normalize(Double.valueOf(Double.parseDouble(text))); }

    /** A canonical array index ({@code Object.entries} lists these first, ascending). */
    private static boolean isIndexKey(String k) {
        if (k.isEmpty() || k.length() > 10) return false;
        if (k.length() > 1 && k.charAt(0) == '0') return false;
        for (int i = 0; i < k.length(); i++) if (!isDigit(k.charAt(i))) return false;
        return Long.parseLong(k) < 4294967295L;
    }

    /** The own keys of an object in {@code Object.entries} order: array indices ascending, then insertion order. */
    static List<String> entryKeys(Map<String, Object> m) {
        List<String> idx = new ArrayList<>(), rest = new ArrayList<>();
        for (String k : m.keySet()) (isIndexKey(k) ? idx : rest).add(k);
        idx.sort((a, b) -> Long.compare(Long.parseLong(a), Long.parseLong(b)));
        idx.addAll(rest);
        return idx;
    }

    /** {@code Object.entries} of an object or array value (an array's keys are its indices); null for anything else. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> entries(Object o) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (o instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) o;
            for (String k : entryKeys(m)) out.put(k, m.get(k));
            return out;
        }
        if (o instanceof List) {
            List<Object> l = (List<Object>) o;
            for (int i = 0; i < l.size(); i++) out.put(Integer.toString(i), l.get(i));
            return out;
        }
        return null;
    }

    // ---- bracket and quote aware scanning (the structure is shared by the Cedar and Rego readers) ----

    /** Index of {@code token} at bracket/quote depth 0, or -1. */
    static int indexOfTopLevel(String text, String token) {
        int depth = 0;
        boolean inStr = false;
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (inStr) { if (ch == '"') inStr = false; continue; }
            if (ch == '"') { inStr = true; continue; }
            if (ch == '(' || ch == '[' || ch == '{') depth++;
            else if (ch == ')' || ch == ']' || ch == '}') depth--;
            else if (depth == 0 && text.startsWith(token, i)) return i;
        }
        return -1;
    }

    /** Split on a delimiter (one or two characters) at bracket/quote depth 0. */
    static List<String> splitTopLevel(String text, String delim) {
        List<String> out = new ArrayList<>();
        int depth = 0;
        boolean inStr = false;
        int start = 0;
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (inStr) { if (ch == '"') inStr = false; continue; }
            if (ch == '"') { inStr = true; continue; }
            if (ch == '(' || ch == '[' || ch == '{') depth++;
            else if (ch == ')' || ch == ']' || ch == '}') depth--;
            if (depth == 0 && text.startsWith(delim, i)) {
                out.add(text.substring(start, i));
                i += delim.length() - 1;
                start = i + 1;
            }
        }
        out.add(text.substring(Math.min(start, text.length())));
        return out;
    }

    static int matchDelim(String text, int open, char o, char c) {
        int depth = 0;
        boolean inStr = false;
        for (int i = open; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (inStr) { if (ch == '"') inStr = false; continue; }
            if (ch == '"') inStr = true;
            else if (ch == o) depth++;
            else if (ch == c) { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    static List<String> trimmedNonEmpty(List<String> parts) {
        List<String> out = new ArrayList<>();
        for (String p : parts) { String t = trim(p); if (!t.isEmpty()) out.add(t); }
        return out;
    }

    /** A growable JSON object in insertion order: {@code obj("field", f, "op", o, ...)}. */
    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }
}
