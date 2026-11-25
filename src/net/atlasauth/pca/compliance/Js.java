package net.atlasauth.pca.compliance;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Json;

/** JavaScript value semantics over parsed JSON trees (Map / List / String / Boolean / Json.Num / null), plus {@link #UNDEF}. */
final class Js {
    private Js() {}

    /** The JavaScript {@code undefined} (a missing member). */
    static final Object UNDEF = new Object() { @Override public String toString() { return "undefined"; } };

    static boolean nullish(Object v) { return v == null || v == UNDEF; }

    static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        if (o instanceof Integer || o instanceof Long || o instanceof Double || o instanceof Short) return ((Number) o).doubleValue();
        return null;
    }

    static boolean isNum(Object o) { return num(o) != null; }

    /** {@code Number.isFinite(v)}. */
    static boolean finite(Object o) { Double d = num(o); return d != null && !d.isNaN() && !d.isInfinite(); }

    static boolean truthy(Object v) {
        if (v == null || v == UNDEF || Boolean.FALSE.equals(v) || "".equals(v)) return false;
        Double d = num(v);
        return d == null || !(d == 0 || d.isNaN());
    }

    /** Own-member read: {@link #UNDEF} when absent or {@code o} is not an object. */
    static Object own(Object o, String k) {
        if (o instanceof Map) { Map<?, ?> m = (Map<?, ?>) o; return m.containsKey(k) ? m.get(k) : UNDEF; }
        return UNDEF;
    }

    /** {@code o.k}: throws on null / undefined, like the reference. */
    static Object prop(Object o, String k) {
        if (nullish(o)) throw new IllegalStateException("Cannot read properties of " + (o == null ? "null" : "undefined") + " (reading '" + k + "')");
        return own(o, k);
    }

    /** {@code o?.k}. */
    static Object qprop(Object o, String k) { return nullish(o) ? UNDEF : own(o, k); }

    /** ECMAScript ToNumber. */
    static double toNumber(Object v) {
        if (v == UNDEF) return Double.NaN;
        if (v == null) return 0;
        if (v instanceof Boolean) return (Boolean) v ? 1 : 0;
        Double d = num(v);
        if (d != null) return d;
        if (v instanceof String) return strToNumber((String) v);
        if (v instanceof List) {
            List<?> l = (List<?>) v;
            return l.isEmpty() ? 0 : l.size() == 1 ? toNumber(l.get(0) == null ? "" : l.get(0)) : Double.NaN;
        }
        return Double.NaN;
    }

    private static double strToNumber(String s) {
        String t = s.strip().replace("﻿", "");
        if (t.isEmpty()) return 0;
        if (t.equals("Infinity") || t.equals("+Infinity")) return Double.POSITIVE_INFINITY;
        if (t.equals("-Infinity")) return Double.NEGATIVE_INFINITY;
        try {
            if (t.matches("0[xX][0-9a-fA-F]+")) return Long.parseLong(t.substring(2), 16);
            if (t.matches("0[bB][01]+")) return Long.parseLong(t.substring(2), 2);
            if (t.matches("0[oO][0-7]+")) return Long.parseLong(t.substring(2), 8);
            if (t.matches("[+-]?([0-9]+\\.?[0-9]*|\\.[0-9]+)([eE][+-]?[0-9]+)?")) return Double.parseDouble(t);
        } catch (NumberFormatException e) { /* NaN below */ }
        return Double.NaN;
    }

    /** {@code a > b}: two strings compare by UTF-16 code units, anything else numerically. */
    static boolean gt(Object a, Object b) {
        if (a instanceof String && b instanceof String) return ((String) a).compareTo((String) b) > 0;
        return toNumber(a) > toNumber(b);
    }

    /** Math.round: halves round toward +Infinity. */
    static double round(double v) {
        if (Double.isNaN(v) || Double.isInfinite(v)) return v;
        double r = Math.floor(v);
        return v - r >= 0.5 ? r + 1 : r;
    }

    /** String(n). */
    static String numStr(double d) { return AttestCommon.jsNumString(d); }

    /** A value interpolated into a template literal. */
    static String tpl(Object v) {
        if (v == null) return "null";
        if (v == UNDEF) return "undefined";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = num(v);
        if (d != null) return numStr(d);
        if (v instanceof List) {
            StringBuilder b = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) { if (!first) b.append(','); first = false; if (!nullish(x)) b.append(tpl(x)); }
            return b.toString();
        }
        return "[object Object]";
    }

    /** {@code v.length}: strings (UTF-16 units) and arrays; throws on null / undefined; UNDEF for anything else. */
    static Object length(Object v) {
        if (nullish(v)) throw new IllegalStateException("Cannot read properties of " + (v == null ? "null" : "undefined") + " (reading 'length')");
        if (v instanceof String) return (long) ((String) v).length();
        if (v instanceof List) return (long) ((List<?>) v).size();
        return UNDEF;
    }

    /** Object.keys order: array-index keys ascending, then the rest in insertion order. */
    static List<String> keys(Map<String, Object> m) {
        List<String> idx = new ArrayList<>();
        List<String> rest = new ArrayList<>();
        for (String k : m.keySet()) (isIndex(k) ? idx : rest).add(k);
        idx.sort((a, b) -> Long.compare(Long.parseLong(a), Long.parseLong(b)));
        idx.addAll(rest);
        return idx;
    }

    private static boolean isIndex(String k) {
        if (k.isEmpty() || k.length() > 10 || (k.length() > 1 && k.charAt(0) == '0')) return false;
        for (int i = 0; i < k.length(); i++) if (k.charAt(i) < '0' || k.charAt(i) > '9') return false;
        return Long.parseLong(k) < 4294967295L;
    }

    // ---- JSON.stringify ----
    static String quote(String s) {
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

    /** JSON.stringify(v) (compact) or, with {@code indent}, JSON.stringify(v, null, 2). */
    @SuppressWarnings("unchecked")
    static String stringify(Object v, String base, boolean pretty) {
        if (v == null) return "null";
        if (v instanceof Boolean) return v.toString();
        if (v instanceof String) return quote((String) v);
        Double d = num(v);
        if (d != null) return d.isNaN() || d.isInfinite() ? "null" : numStr(d);
        if (v instanceof List) {
            List<Object> l = (List<Object>) v;
            if (l.isEmpty()) return "[]";
            String ind = base + "  ";
            List<String> parts = new ArrayList<>();
            for (Object x : l) parts.add((pretty ? ind : "") + (x == UNDEF ? "null" : stringify(x, ind, pretty)));
            return pretty ? "[\n" + String.join(",\n", parts) + "\n" + base + "]" : "[" + String.join(",", parts) + "]";
        }
        if (v instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) v;
            String ind = base + "  ";
            List<String> parts = new ArrayList<>();
            for (String k : keys(m)) {
                Object x = m.get(k);
                if (x == UNDEF) continue;
                parts.add((pretty ? ind : "") + quote(k) + (pretty ? ": " : ":") + stringify(x, ind, pretty));
            }
            if (parts.isEmpty()) return "{}";
            return pretty ? "{\n" + String.join(",\n", parts) + "\n" + base + "}" : "{" + String.join(",", parts) + "}";
        }
        throw new IllegalStateException("stringify: unsupported value");
    }

    // ---- Set (SameValueZero) ----
    static final class JsSet {
        private final Set<String> keys = new HashSet<>();
        private int n;
        private final IdentityHashMap<Object, Integer> ids = new IdentityHashMap<>();

        void add(Object v) {
            String k;
            if (v instanceof Boolean) k = "b" + v;
            else if (isNum(v)) { double d = num(v); k = "n" + (d == 0 ? "0" : Double.toString(d)); }
            else if (v instanceof String) k = "s" + v;
            else if (v == null) k = "z";
            else if (v == UNDEF) k = "u";
            else { Integer id = ids.get(v); if (id == null) { id = ++n; ids.put(v, id); } k = "o" + id; }
            keys.add(k);
        }

        int size() { return keys.size(); }
    }

    // ---- dates ----
    /** {@code new Date(ms).toISOString()}; throws for an invalid time. */
    static String isoString(Object msO) {
        Double d = msO == null ? Double.valueOf(0) : num(msO);
        if (d == null || d.isNaN() || d.isInfinite() || Math.abs(d) > 8.64e15) throw new IllegalArgumentException("Invalid time value");
        long t = (long) (double) d;
        long days = Math.floorDiv(t, 86400000L);
        long rem = Math.floorMod(t, 86400000L);
        long z = days + 719468;
        long era = Math.floorDiv(z, 146097L);
        long doe = z - era * 146097L;
        long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        long y = yoe + era * 400;
        long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        long mp = (5 * doy + 2) / 153;
        long day = doy - (153 * mp + 2) / 5 + 1;
        long mo = mp < 10 ? mp + 3 : mp - 9;
        if (mo <= 2) y++;
        String ys = y >= 0 && y <= 9999 ? String.format("%04d", y) : (y > 0 ? "+" : "-") + String.format("%06d", Math.abs(y));
        return String.format("%s-%02d-%02dT%02d:%02d:%02d.%03dZ", ys, mo, day, rem / 3600000, rem / 60000 % 60, rem / 1000 % 60, rem % 1000);
    }

    static String iso(Object ms) {
        if (!finite(ms)) return "(unknown time)";
        try { return isoString(ms); } catch (IllegalArgumentException e) { return "(unrepresentable time)"; }
    }

    static Map<String, Object> ts(Object ms) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("epochMs", ms); // NaN / Infinity stay the number the reference holds; only a serializer drops them
        m.put("iso", iso(ms));
        return m;
    }

    static Object nowMs() { return System.currentTimeMillis(); }

    /** Abbreviate a long key for display (UTF-16 units). */
    static String shortKey(Object key, int n) {
        if (!(key instanceof String) || ((String) key).isEmpty()) return "(none)";
        String s = (String) key;
        return s.length() <= n + 1 ? s : s.substring(0, n) + "…";
    }

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) if (kv[i + 1] != UNDEF) m.put((String) kv[i], kv[i + 1]);
        return m;
    }
}
