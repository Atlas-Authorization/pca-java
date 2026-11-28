package net.atlasauth.pca.explain;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.revoke.JsVal;

/** JavaScript value semantics over parsed JSON for the explainer: absent members ({@link #UNDEF}), String(x), JSON.stringify, Number(x). */
final class ExplainJs {
    private ExplainJs() {}

    /** The JavaScript {@code undefined}: a member that is absent (distinct from JSON null). Never stored in an output map. */
    static final Object UNDEF = new Object() { @Override public String toString() { return "undefined"; } };

    static boolean undef(Object o) { return o == UNDEF; }

    static boolean isObject(Object o) { return o instanceof Map || o instanceof List; }

    /** {@code o[k]} (no throw): UNDEF for a missing member or a value without members. A list answers array indices. */
    static Object get(Object o, String k) {
        if (o instanceof Map) { Map<?, ?> m = (Map<?, ?>) o; return m.containsKey(k) ? m.get(k) : UNDEF; }
        if (o instanceof List) {
            if (k.equals("length")) return new Json.Num(Integer.toString(((List<?>) o).size()));
            int i = index(k);
            List<?> l = (List<?>) o;
            return i >= 0 && i < l.size() ? l.get(i) : UNDEF;
        }
        if (o instanceof String) { // a string answers its UTF-16 units and length
            String str = (String) o;
            if (k.equals("length")) return new Json.Num(Integer.toString(str.length()));
            int i = index(k);
            return i >= 0 && i < str.length() ? String.valueOf(str.charAt(i)) : UNDEF;
        }
        return UNDEF;
    }

    /** {@code o[k]} where o must not be null or undefined (a TypeError otherwise). */
    static Object rd(Object o, String k) {
        if (o == null || o == UNDEF) throw new IllegalArgumentException("TypeError: cannot read '" + k + "' of " + o);
        return get(o, k);
    }

    /** {@code o?.[k]}. */
    static Object opt(Object o, String k) { return o == null || o == UNDEF ? UNDEF : get(o, k); }

    private static int index(String k) {
        if (k.isEmpty() || k.length() > 9) return -1;
        for (int i = 0; i < k.length(); i++) if (k.charAt(i) < '0' || k.charAt(i) > '9') return -1;
        if (k.length() > 1 && k.charAt(0) == '0') return -1;
        return Integer.parseInt(k);
    }

    /** {@code a ?? b}. */
    static Object nn(Object a, Object b) { return a == null || a == UNDEF ? b : a; }

    static boolean truthy(Object v) { return v != UNDEF && JsVal.truthy(v); }

    static void put(Map<String, Object> m, String k, Object v) { if (v != UNDEF) m.put(k, v); }

    static Json.Num n(long v) { return new Json.Num(Long.toString(v)); }

    /** {@code Object.keys}: array-index keys ascending first, then the others in insertion order. */
    static List<String> keys(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List) { for (int i = 0; i < ((List<?>) o).size(); i++) out.add(Integer.toString(i)); return out; }
        if (o instanceof String) { for (int i = 0; i < ((String) o).length(); i++) out.add(Integer.toString(i)); return out; }
        if (!(o instanceof Map)) return out;
        List<String> idx = new ArrayList<>();
        for (Object k : ((Map<?, ?>) o).keySet()) {
            String s = (String) k;
            if (isArrayIndex(s)) idx.add(s); else out.add(s);
        }
        Collections.sort(idx, Comparator.comparingLong(Long::parseLong));
        idx.addAll(out);
        return idx;
    }

    private static boolean isArrayIndex(String s) {
        if (s.isEmpty() || s.length() > 10) return false;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) < '0' || s.charAt(i) > '9') return false;
        if (s.length() > 1 && s.charAt(0) == '0') return false;
        return Long.parseLong(s) < 4294967295L;
    }

    // ---- numbers ---------------------------------------------------------------------------------------------------------------

    /** The JavaScript number value of a JSON number (Json.Num / Number), else null. */
    static Double numOf(Object o) { return JsVal.num(o); }

    static boolean isFiniteNumber(Object o) { Double d = JsVal.num(o); return d != null && !d.isNaN() && !d.isInfinite(); }

    static boolean isArray(Object o) { return o instanceof List; }

    /** {@code String(n)} for a number. */
    static String numString(double d) { return AttestCommon.jsNumString(d); }

    private static final Pattern NUMLIT = Pattern.compile("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?");

    /** {@code Number(v)} (scalars; objects are NaN). */
    static double toNum(Object v) {
        if (v == UNDEF) return Double.NaN;
        if (v == null) return 0;
        if (v instanceof Boolean) return (Boolean) v ? 1 : 0;
        Double d = JsVal.num(v);
        if (d != null) return d;
        if (v instanceof String) {
            String s = jsTrim((String) v);
            if (s.isEmpty()) return 0;
            if (s.equals("Infinity") || s.equals("+Infinity")) return Double.POSITIVE_INFINITY;
            if (s.equals("-Infinity")) return Double.NEGATIVE_INFINITY;
            if (NUMLIT.matcher(s).matches()) return Double.parseDouble(s);
            return Double.NaN;
        }
        return Double.NaN;
    }

    /** {@code a > b} (two strings compare as strings, anything else as numbers). */
    static boolean gt(Object a, Object b) {
        if (a instanceof String && b instanceof String) return ((String) a).compareTo((String) b) > 0;
        return toNum(a) > toNum(b);
    }

    /** {@code Math.round}. */
    static double round(double y) {
        double f = Math.floor(y);
        return y - f >= 0.5 ? f + 1 : f;
    }

    // ---- strings ---------------------------------------------------------------------------------------------------------------

    static final String WS = " \\t\\n\\u000B\\f\\r\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF";

    static boolean isWs(char c) {
        return c == ' ' || (c >= '\t' && c <= '\r') || c == ' ' || c == ' ' || (c >= ' ' && c <= ' ')
            || c == ' ' || c == ' ' || c == ' ' || c == ' ' || c == '　' || c == '﻿';
    }

    /** {@code String.prototype.trim}. */
    static String jsTrim(String s) {
        int a = 0, b = s.length();
        while (a < b && isWs(s.charAt(a))) a++;
        while (b > a && isWs(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }

    /** {@code String(v)}. */
    static String str(Object v) {
        if (v == UNDEF) return "undefined";
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        if (v instanceof Double) return numString((Double) v);
        if (v instanceof Integer || v instanceof Long) return numString(((Number) v).doubleValue());
        Double d = JsVal.num(v);
        if (d != null) return numString(d);
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                if (x != null && x != UNDEF) sb.append(str(x));
            }
            return sb.toString();
        }
        return "[object Object]";
    }

    /** {@code `${JSON.stringify(v)}`}: undefined stringifies to the text "undefined". */
    static String jstr(Object v) { return v == UNDEF ? "undefined" : stringify(v); }

    /** JSON.stringify of a parsed value: insertion order (array-index keys first), numbers as JavaScript prints them. */
    static String stringify(Object v) {
        StringBuilder sb = new StringBuilder();
        ser(sb, v);
        return sb.toString();
    }

    private static void ser(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof Boolean) { sb.append(v); return; }
        if (v instanceof String) { quote(sb, (String) v); return; }
        if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (String k : keys(v)) {
                if (!first) sb.append(',');
                first = false;
                quote(sb, k);
                sb.append(':');
                ser(sb, ((Map<?, ?>) v).get(k));
            }
            sb.append('}');
            return;
        }
        if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                ser(sb, x);
            }
            sb.append(']');
            return;
        }
        Double d = v instanceof Double ? (Double) v : JsVal.num(v);
        if (d == null || d.isNaN() || d.isInfinite()) { sb.append("null"); return; }
        sb.append(numString(d));
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
                    boolean lone = Character.isSurrogate(c)
                        && !(Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1)))
                        && !(Character.isLowSurrogate(c) && i > 0 && Character.isHighSurrogate(s.charAt(i - 1)));
                    if (c < 0x20 || lone) sb.append(String.format("\\u%04x", (int) c)); else sb.append(c);
            }
        }
        sb.append('"');
    }

    static Map<String, Object> obj() { return new LinkedHashMap<>(); }
}
