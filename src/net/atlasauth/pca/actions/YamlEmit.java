package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Json;

/**
 * A YAML 1.2 emitter for parsed JSON trees (Map, List, String, Boolean, number, null) that writes byte for byte what the {@code yaml} package's
 * default {@code stringify} writes: block collections with two-space indentation (sequences indented under their key), plain scalars unless they
 * would read back as another type (then quoted), literal or folded block scalars for multi-line text, double quotes with YAML escapes, and
 * lines folded at 80 columns. A direct port of that library's string, number, pair and collection stringifiers for the node kinds a JSON tree has.
 *
 * <p>A Map or List that appears more than once in a tree (the same instance) is written once with an anchor ({@code &a1}, numbered in the
 * order the repeats are met) and then as an alias ({@code *a1}), as the reference does; a cycle becomes an alias too. Equal but distinct objects
 * are written in full. A non-finite number or a number that is not a JSON value is refused.
 */
final class YamlEmit {
    private YamlEmit() {}

    private static final int LINE_WIDTH = 80, MIN_CONTENT_WIDTH = 20, DQ_MIN_MULTILINE = 40;
    private static final String FLOW = "flow", BLOCK = "block", QUOTED = "quoted";

    /** The document text of {@code value}: the block-style YAML followed by a newline. */
    static String stringify(Object value) {
        Ctx ctx = new Ctx();
        ctx.anchors = new Anchors(value);
        return stringifyNode(value, ctx) + "\n";
    }

    /** The anchor names of the collections met more than once (numbered at the second sighting, as the reference does) and which are already written. */
    private static final class Anchors {
        final Map<Object, String> names = new IdentityHashMap<>();
        final Set<Object> written = Collections.newSetFromMap(new IdentityHashMap<>());
        private final Set<Object> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        private int count;

        Anchors(Object root) { walk(root); }

        private void walk(Object v) {
            if (!(v instanceof Map) && !(v instanceof List)) return;
            if (!seen.add(v)) {
                names.computeIfAbsent(v, k -> "a" + (++count));
                return;
            }
            if (v instanceof Map) { Map<?, ?> m = (Map<?, ?>) v; for (String k : jsKeys(m)) walk(m.get(k)); }
            else for (Object x : (List<?>) v) walk(x);
        }

        /** True when {@code v} is a repeat of a collection whose anchor is already written (it is emitted as an alias). */
        boolean isAlias(Object v) { return written.contains(v); }
    }

    private static final class Ctx {
        String indent = "";
        String indentStep = "  ";
        Integer indentAtStart;
        boolean implicitKey, actualString, forceBlockIndent;
        Anchors anchors;
        Ctx copy() {
            Ctx c = new Ctx();
            c.indent = indent; c.indentStep = indentStep; c.indentAtStart = indentAtStart;
            c.implicitKey = implicitKey; c.actualString = actualString; c.forceBlockIndent = forceBlockIndent; c.anchors = anchors;
            return c;
        }
    }

    // ---- nodes ---------------------------------------------------------------------------------------------------------------

    private static String stringifyNode(Object v, Ctx ctx) {
        if (v instanceof Map || v instanceof List) {
            String anchor = ctx.anchors.names.get(v);
            if (anchor != null && !ctx.anchors.written.add(v)) return "*" + anchor;
            String props = anchor == null ? null : "&" + anchor;
            if (props != null) ctx.indentAtStart = (ctx.indentAtStart == null ? 0 : ctx.indentAtStart) + props.length() + 1;
            String str = v instanceof Map ? stringifyMap((Map<?, ?>) v, ctx) : stringifySeq((List<?>) v, ctx);
            if (props == null) return str;
            return str.charAt(0) == '{' || str.charAt(0) == '[' ? props + " " + str : props + "\n" + ctx.indent + str;
        }
        if (v instanceof String) { Ctx c = ctx.copy(); c.actualString = true; return stringifyString((String) v, c); }
        if (v == null) return "null";
        if (v instanceof Boolean) return v.toString();
        return stringifyNumber(v);
    }

    private static String stringifyNumber(Object v) {
        Double d = v instanceof Json.Num ? parse((Json.Num) v) : v instanceof Number ? ((Number) v).doubleValue() : null;
        if (d == null || d.isNaN() || d.isInfinite()) throw new IllegalArgumentException("YAML: not a JSON number: " + v);
        if (d == 0 && 1 / d < 0) return "-0";
        return AttestCommon.jsNumString(d);
    }

    private static Double parse(Json.Num n) {
        try { return Double.parseDouble(n.raw); } catch (NumberFormatException e) { return null; }
    }

    private static List<String> jsKeys(Map<?, ?> m) {
        List<String> idx = new ArrayList<>(), rest = new ArrayList<>();
        for (Object o : m.keySet()) {
            String k = (String) o;
            if (k.matches("0|[1-9][0-9]{0,9}") && Long.parseLong(k) < 4294967295L) idx.add(k); else rest.add(k);
        }
        idx.sort((a, b) -> Long.compare(Long.parseLong(a), Long.parseLong(b)));
        idx.addAll(rest);
        return idx;
    }

    private static String stringifyMap(Map<?, ?> m, Ctx ctx) {
        List<String> keys = jsKeys(m);
        Ctx itemCtx = ctx.copy();
        itemCtx.indent = ctx.indent;
        List<String> lines = new ArrayList<>();
        for (String k : keys) lines.add(stringifyPair(k, m.get(k), itemCtx));
        return join(lines, ctx.indent, "{}");
    }

    private static String stringifySeq(List<?> l, Ctx ctx) {
        Ctx itemCtx = ctx.copy();
        itemCtx.indent = ctx.indent + "  ";
        List<String> lines = new ArrayList<>();
        for (Object x : l) lines.add("- " + stringifyNode(x, itemCtx));
        return join(lines, ctx.indent, "[]");
    }

    private static String join(List<String> lines, String indent, String empty) {
        if (lines.isEmpty()) return empty;
        StringBuilder b = new StringBuilder(lines.get(0));
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (!line.isEmpty()) b.append('\n').append(indent).append(line); else b.append('\n');
        }
        return b.toString();
    }

    private static String stringifyPair(String key, Object value, Ctx ctx0) {
        String indent = ctx0.indent;
        Ctx ctx = ctx0.copy();
        ctx.indent = indent + ctx0.indentStep;
        ctx.implicitKey = true;
        String str = stringifyNode(key, ctx);
        boolean explicitKey = str.length() > 1024;
        str = explicitKey ? "? " + str + "\n" + indent + ":" : str + ":";
        ctx.implicitKey = false;
        boolean alias = ctx.anchors.isAlias(value);
        boolean collection = !alias && (value instanceof Map || value instanceof List);
        if (!explicitKey && !collection && !alias) ctx.indentAtStart = str.length() + 1;
        String valueStr = stringifyNode(value, ctx);
        String ws = " ";
        if (!explicitKey && collection) {
            boolean hasNewline = valueStr.indexOf('\n') != -1;
            boolean empty = value instanceof Map ? ((Map<?, ?>) value).isEmpty() : ((List<?>) value).isEmpty();
            if (hasNewline || !empty) {
                int sp0 = valueStr.indexOf(' ');
                boolean propsLine = hasNewline && valueStr.charAt(0) == '&' && (sp0 == -1 || valueStr.indexOf('\n') < sp0); // "&a1" alone on its line
                if (!propsLine) ws = "\n" + ctx.indent;
            }
        } else if (valueStr.isEmpty() || valueStr.charAt(0) == '\n') ws = "";
        return str + ws + valueStr;
    }

    // ---- strings -------------------------------------------------------------------------------------------------------------

    private static final Pattern DOC_MARKER = Pattern.compile("(?:^|[\\n\\r\\u2028\\u2029])(?:%|---|\\.\\.\\.)");
    private static final Pattern PLAIN_FORBIDDEN = Pattern.compile("^[\\n\\t ,\\[\\]{}#&*!|>'\"%@`]|^[?-]\\z|^[?-][ \\t]|[\\n:][ \\t]|[ \\t]\\n|[\\n\\t ]#|[\\n\\t :]\\z");
    // the core schema's default tags that would read a plain scalar back as a non-string
    private static final Pattern[] NON_STRING = {
        Pattern.compile("^(?:~|[Nn]ull|NULL)?\\z"), Pattern.compile("^(?:[Tt]rue|TRUE|[Ff]alse|FALSE)\\z"), Pattern.compile("^0o[0-7]+\\z"), Pattern.compile("^[-+]?[0-9]+\\z"),
        Pattern.compile("^0x[0-9a-fA-F]+\\z"), Pattern.compile("^(?:[-+]?\\.(?:inf|Inf|INF)|\\.nan|\\.NaN|\\.NAN)\\z"), Pattern.compile("^[-+]?(?:\\.[0-9]+|[0-9]+(?:\\.[0-9]*)?)[eE][-+]?[0-9]+\\z"),
        Pattern.compile("^[-+]?(?:\\.[0-9]+|[0-9]+\\.[0-9]*)\\z"),
    };
    private static final Pattern WS_AROUND_NL = Pattern.compile("[ \\t]\\n|\\n[ \\t]");
    private static final Pattern NL_RUN = Pattern.compile("\\n+");

    private static boolean containsDocumentMarker(String s) { return DOC_MARKER.matcher(s).find(); }

    /** {@code s.replace(/\n+/g, '$&' + suffix)}: every newline run followed by {@code suffix}. */
    private static String afterNewlines(String s, String suffix) {
        Matcher m = NL_RUN.matcher(s);
        StringBuilder b = new StringBuilder();
        int last = 0;
        while (m.find()) { b.append(s, last, m.end()).append(suffix); last = m.end(); }
        return b.append(s, last, s.length()).toString();
    }

    private static boolean forcesDoubleQuotes(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c <= 0x08) || (c >= 0x0b && c <= 0x1f) || (c >= 0x7f && c <= 0x9f)) return true;
            if (Character.isHighSurrogate(c)) { if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) i++; else return true; }
            else if (Character.isLowSurrogate(c)) return true;
        }
        return false;
    }

    private static String stringifyString(String value, Ctx ctx) {
        return forcesDoubleQuotes(value) ? doubleQuotedString(value, ctx) : plainString(value, ctx);
    }

    private static String plainString(String value, Ctx ctx) {
        boolean hasNl = value.indexOf('\n') >= 0;
        if (ctx.implicitKey && hasNl) return quotedString(value, ctx);
        if (PLAIN_FORBIDDEN.matcher(value).find()) return ctx.implicitKey || !hasNl ? quotedString(value, ctx) : blockString(value, ctx);
        if (!ctx.implicitKey && hasNl) return blockString(value, ctx);   // the string has no explicit type: block style is preferred where allowed
        if (containsDocumentMarker(value)) {
            if (ctx.indent.isEmpty()) { ctx.forceBlockIndent = true; return blockString(value, ctx); }
            else if (ctx.implicitKey && ctx.indent.equals(ctx.indentStep)) return quotedString(value, ctx);
        }
        String str = afterNewlines(value, "\n" + ctx.indent);
        if (ctx.actualString) for (Pattern p : NON_STRING) if (p.matcher(str).find()) return quotedString(value, ctx);
        return ctx.implicitKey ? str : foldFlowLines(str, ctx.indent, FLOW, ctx.indentAtStart, null);
    }

    private static String quotedString(String value, Ctx ctx) {
        boolean hasDouble = value.indexOf('"') >= 0, hasSingle = value.indexOf('\'') >= 0;
        return hasDouble && !hasSingle ? singleQuotedString(value, ctx) : doubleQuotedString(value, ctx);
    }

    private static String singleQuotedString(String value, Ctx ctx) {
        if ((ctx.implicitKey && value.indexOf('\n') >= 0) || WS_AROUND_NL.matcher(value).find()) return doubleQuotedString(value, ctx);
        String indent = !ctx.indent.isEmpty() ? ctx.indent : containsDocumentMarker(value) ? "  " : "";
        String res = "'" + afterNewlines(value.replace("'", "''"), "\n" + indent) + "'";
        return ctx.implicitKey ? res : foldFlowLines(res, indent, FLOW, ctx.indentAtStart, null);
    }

    private static char at(String s, int i) { return i >= 0 && i < s.length() ? s.charAt(i) : '\0'; }

    private static String doubleQuotedString(String value, Ctx ctx) {
        String json = J.stringify(value);
        String indent = !ctx.indent.isEmpty() ? ctx.indent : containsDocumentMarker(value) ? "  " : "";
        StringBuilder str = new StringBuilder();
        int start = 0;
        for (int i = 0; i < json.length(); i++) {
            char ch = json.charAt(i);
            if (ch == ' ' && at(json, i + 1) == '\\' && at(json, i + 2) == 'n') {
                // a space before a newline is escaped so it is not folded
                str.append(json, start, i).append("\\ ");
                i += 1;
                start = i;
                ch = '\\';
            }
            if (ch == '\\') {
                switch (at(json, i + 1)) {
                    case 'u': {
                        str.append(json, start, i);
                        String code = json.substring(Math.min(i + 2, json.length()), Math.min(i + 6, json.length()));
                        switch (code) {
                            case "0000": str.append("\\0"); break;
                            case "0007": str.append("\\a"); break;
                            case "000b": str.append("\\v"); break;
                            case "001b": str.append("\\e"); break;
                            case "0085": str.append("\\N"); break;
                            case "00a0": str.append("\\_"); break;
                            case "2028": str.append("\\L"); break;
                            case "2029": str.append("\\P"); break;
                            default:
                                if (code.startsWith("00")) str.append("\\x").append(code.substring(2));
                                else str.append(json, i, Math.min(i + 6, json.length()));
                        }
                        i += 5;
                        start = i + 1;
                        break;
                    }
                    case 'n':
                        if (ctx.implicitKey || at(json, i + 2) == '"' || json.length() < DQ_MIN_MULTILINE) {
                            i += 1;
                        } else {
                            // folding eats the first newline
                            str.append(json, start, i).append("\n\n");
                            while (at(json, i + 2) == '\\' && at(json, i + 3) == 'n' && at(json, i + 4) != '"') { str.append('\n'); i += 2; }
                            str.append(indent);
                            // a space after a newline is escaped so it is not folded
                            if (at(json, i + 2) == ' ') str.append('\\');
                            i += 1;
                            start = i + 1;
                        }
                        break;
                    default:
                        i += 1;
                }
            }
        }
        String res = start != 0 ? str.append(json, Math.min(start, json.length()), json.length()).toString() : json;
        return ctx.implicitKey ? res : foldFlowLines(res, indent, QUOTED, ctx.indentAtStart, null);
    }

    private static boolean lineLengthOverLimit(String str, int lineWidth, int indentLength) {
        int limit = lineWidth - indentLength;
        int strLen = str.length();
        if (strLen <= limit) return false;
        for (int i = 0, start = 0; i < strLen; ++i) {
            if (str.charAt(i) == '\n') {
                if (i - start > limit) return true;
                start = i + 1;
                if (strLen - start <= limit) return false;
            }
        }
        return true;
    }

    private static final Pattern BLOCK_END_NL = Pattern.compile("(^|(?<!\\n))\\n+(?!\\n|\\z)");
    private static final Pattern TRAILING_WS_LINE = Pattern.compile("\\n[\\t ]+\\z");
    private static final Pattern MORE_INDENTED = Pattern.compile("(?:^|\\n)([\\t ].*)(?:([\\n\\t ]*)\\n(?![\\n\\t ]))?");

    private static String blockString(String value, Ctx ctx) {
        // a block cannot end in whitespace unless its last line is non-empty
        if (TRAILING_WS_LINE.matcher(value).find()) return quotedString(value, ctx);
        String indent = !ctx.indent.isEmpty() ? ctx.indent : ctx.forceBlockIndent || containsDocumentMarker(value) ? "  " : "";
        boolean literal = !lineLengthOverLimit(value, LINE_WIDTH, indent.length());
        if (value.isEmpty()) return literal ? "|\n" : ">\n";
        // chomping from the whitespace at the value's end
        String chomp;
        int endStart;
        for (endStart = value.length(); endStart > 0; --endStart) {
            char ch = value.charAt(endStart - 1);
            if (ch != '\n' && ch != '\t' && ch != ' ') break;
        }
        String end = value.substring(endStart);
        int endNlPos = end.indexOf('\n');
        if (endNlPos == -1) chomp = "-";
        else if (value.equals(end) || endNlPos != end.length() - 1) chomp = "+";
        else chomp = "";
        if (!end.isEmpty()) {
            value = value.substring(0, value.length() - end.length());
            if (end.charAt(end.length() - 1) == '\n') end = end.substring(0, end.length() - 1);
            end = replaceBlockEnd(end, indent);
        }
        // indent indicator from the whitespace at the value's start
        boolean startWithSpace = false;
        int startEnd, startNlPos = -1;
        for (startEnd = 0; startEnd < value.length(); ++startEnd) {
            char ch = value.charAt(startEnd);
            if (ch == ' ') startWithSpace = true;
            else if (ch == '\n') startNlPos = startEnd;
            else break;
        }
        String start = value.substring(0, startNlPos < startEnd ? startNlPos + 1 : startEnd);
        if (!start.isEmpty()) {
            value = value.substring(start.length());
            start = afterNewlines(start, indent);
        }
        String indentSize = !indent.isEmpty() ? "2" : "1"; // the root is at -1
        String header = (startWithSpace ? indentSize : "") + chomp;
        if (!literal) {
            String foldedValue = afterNewlines(moreIndentedUnfolded(afterNewlinesPrefix(value)), indent);
            boolean[] overflow = {false};
            String body = foldFlowLines(start + foldedValue + end, indent, BLOCK, ctx.indent.length(), overflow);
            if (!overflow[0]) return ">" + header + "\n" + indent + body;
        }
        value = afterNewlines(value, indent);
        return "|" + header + "\n" + indent + start + value + end;
    }

    /** {@code end.replace(blockEndNewlines, '$&' + indent)}. */
    private static String replaceBlockEnd(String end, String indent) {
        Matcher m = BLOCK_END_NL.matcher(end);
        StringBuilder b = new StringBuilder();
        int last = 0;
        while (m.find()) { b.append(end, last, m.end()).append(indent); last = m.end(); }
        return b.append(end, last, end.length()).toString();
    }

    /** {@code value.replace(/\n+/g, '\n$&')}. */
    private static String afterNewlinesPrefix(String s) {
        Matcher m = NL_RUN.matcher(s);
        StringBuilder b = new StringBuilder();
        int last = 0;
        while (m.find()) { b.append(s, last, m.start()).append('\n').append(m.group()); last = m.end(); }
        return b.append(s, last, s.length()).toString();
    }

    /** {@code s.replace(/(?:^|\n)([\t ].*)(?:([\n\t ]*)\n(?![\n\t ]))?/g, '$1$2')}: more-indented lines are not folded. */
    private static String moreIndentedUnfolded(String s) {
        Matcher m = MORE_INDENTED.matcher(s);
        StringBuilder b = new StringBuilder();
        int last = 0;
        while (m.find()) {
            b.append(s, last, m.start()).append(m.group(1));
            if (m.group(2) != null) b.append(m.group(2));
            last = m.end();
        }
        return b.append(s, last, s.length()).toString();
    }

    // ---- folding -------------------------------------------------------------------------------------------------------------

    private static int consumeMoreIndentedLines(String text, int i, int indent) {
        int end = i, start = i + 1;
        char ch = at(text, start);
        while (ch == ' ' || ch == '\t') {
            if (i < start + indent) {
                ch = at(text, ++i);
            } else {
                do { ch = at(text, ++i); } while (ch != '\0' && ch != '\n');
                end = i;
                start = i + 1;
                ch = at(text, start);
            }
        }
        return end;
    }

    /**
     * Keeps text at up to the line width by splitting on spaces not followed by newlines or spaces (anywhere in quoted mode); lines end with a
     * newline and start with {@code indent}. {@code indentAtStart} is where the first line already starts (null = the indent).
     */
    private static String foldFlowLines(String text, String indent, String mode, Integer indentAtStart, boolean[] overflowOut) {
        int lineWidth = LINE_WIDTH, minContentWidth = MIN_CONTENT_WIDTH;
        if (lineWidth < minContentWidth) minContentWidth = 0;
        int endStep = Math.max(1 + minContentWidth, 1 + lineWidth - indent.length());
        if (text.length() <= endStep) return text;
        List<Integer> folds = new ArrayList<>();
        Set<Integer> escapedFolds = new HashSet<>();
        int end = lineWidth - indent.length();
        if (indentAtStart != null) {
            if (indentAtStart > lineWidth - Math.max(2, minContentWidth)) folds.add(0);
            else end = lineWidth - indentAtStart;
        }
        Integer split = null;
        char prev = '\0';
        boolean overflow = false;
        int i = -1, escStart = -1, escEnd = -1;
        if (mode.equals(BLOCK)) {
            i = consumeMoreIndentedLines(text, i, indent.length());
            if (i != -1) end = i + endStep;
        }
        for (char ch; (ch = at(text, i += 1)) != '\0';) {
            if (mode.equals(QUOTED) && ch == '\\') {
                escStart = i;
                switch (at(text, i + 1)) {
                    case 'x': i += 3; break;
                    case 'u': i += 5; break;
                    case 'U': i += 9; break;
                    default: i += 1;
                }
                escEnd = i;
            }
            if (ch == '\n') {
                if (mode.equals(BLOCK)) i = consumeMoreIndentedLines(text, i, indent.length());
                end = i + indent.length() + endStep;
                split = null;
            } else {
                if (ch == ' ' && prev != '\0' && prev != ' ' && prev != '\n' && prev != '\t') {
                    // a space surrounded by non-space can become a newline plus indent
                    char next = at(text, i + 1);
                    if (next != '\0' && next != ' ' && next != '\n' && next != '\t') split = i;
                }
                if (i >= end) {
                    if (split != null) {
                        folds.add(split);
                        end = split + endStep;
                        split = null;
                    } else if (mode.equals(QUOTED)) {
                        // white space collected at the end may stretch past the line width
                        while (prev == ' ' || prev == '\t') {
                            prev = ch;
                            ch = at(text, i += 1);
                            overflow = true;
                        }
                        // account for the newline escape, but do not break a preceding escape
                        int j = i > escEnd + 1 ? i - 2 : escStart - 1;
                        if (escapedFolds.contains(j)) return text;
                        folds.add(j);
                        escapedFolds.add(j);
                        end = j + endStep;
                        split = null;
                    } else {
                        overflow = true;
                    }
                }
            }
            prev = ch;
        }
        if (overflowOut != null && overflow) overflowOut[0] = true;
        if (folds.isEmpty()) return text;
        StringBuilder res = new StringBuilder(text.substring(0, Math.min(folds.get(0), text.length())));
        for (int k = 0; k < folds.size(); ++k) {
            int fold = folds.get(k);
            int e = k + 1 < folds.size() && folds.get(k + 1) != 0 ? folds.get(k + 1) : text.length();
            if (fold == 0) {
                res = new StringBuilder("\n" + indent + text.substring(0, Math.min(e, text.length())));
            } else {
                if (mode.equals(QUOTED) && escapedFolds.contains(fold)) res.append(text.charAt(fold)).append('\\');
                res.append('\n').append(indent).append(text, Math.min(fold + 1, text.length()), Math.min(Math.max(e, fold + 1), text.length()));
            }
        }
        return res.toString();
    }
}
