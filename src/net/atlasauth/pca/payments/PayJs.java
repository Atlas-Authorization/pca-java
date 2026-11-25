package net.atlasauth.pca.payments;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;

/** JavaScript value semantics over parsed JSON for the payments port (numbers are binary64, member reads of a non-object are undefined). */
final class PayJs {
    private PayJs() {}

    static final double MAX_SAFE = 9007199254740991.0;

    static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        if (o instanceof Number) return ((Number) o).doubleValue();
        return null;
    }

    /** Number.isFinite on a value that is a number. */
    static boolean isFiniteNum(Object o) {
        Double d = num(o);
        return d != null && !d.isNaN() && !d.isInfinite();
    }

    static boolean isSafeInteger(Object o) {
        Double d = num(o);
        return d != null && !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= MAX_SAFE;
    }

    static boolean isNegZero(Object o) {
        Double d = num(o);
        return d != null && d == 0.0 && Double.doubleToRawLongBits(d) != 0L;
    }

    /** A number as a JSON value the canonical form accepts (non-finite becomes null, as JSON.stringify prints it). */
    static Object jn(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) return null;
        if (d == 0.0) return new Json.Num("0");
        return IntentJs.normalize(Double.valueOf(d));
    }

    static double nz(double x) { return !Double.isNaN(x) && !Double.isInfinite(x) && x > 0 ? x : 0; }

    static double clamp01(double x) { return x < 0 ? 0 : x > 1 ? 1 : x; }

    static boolean truthy(Object o) {
        if (o == null) return false;
        if (o instanceof Boolean) return (Boolean) o;
        if (o instanceof String) return !((String) o).isEmpty();
        Double d = num(o);
        if (d != null) return d != 0.0 && !d.isNaN();
        return true;
    }

    static boolean isObj(Object o) { return o instanceof Map || o instanceof List; }

    static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> copy(Object o) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (o instanceof Map) m.putAll((Map<String, Object>) o);
        else if (o instanceof List) { int i = 0; for (Object x : (List<?>) o) m.put(Integer.toString(i++), x); } // `{...array}` keys the elements by index
        else if (o instanceof String) { String t = (String) o; for (int i = 0; i < t.length(); i++) m.put(Integer.toString(i), t.substring(i, i + 1)); }
        return m;
    }

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** JavaScript string conversion as a template literal does it. */
    static String str(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = num(v);
        if (d != null) {
            if (d.isNaN()) return "NaN";
            if (d.isInfinite()) return d > 0 ? "Infinity" : "-Infinity";
            if (d == 0.0) return "0";
            return net.atlasauth.pca.AttestCommon.jsNumString(d); // String(n): exponent form from 1e21
        }
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

    /** A byte array from a Java byte[] or the {"$bytes": b64url} wire form; null otherwise. */
    static byte[] bytes(Object o) {
        if (o instanceof byte[]) return (byte[]) o;
        Object b = get(o, "$bytes");
        return b instanceof String ? Keys.unb64u((String) b) : null;
    }

    static List<Object> list(Object... xs) {
        List<Object> l = new ArrayList<>();
        for (Object x : xs) l.add(x);
        return l;
    }

    private static final java.util.regex.Pattern DEC = java.util.regex.Pattern.compile("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?");

    /** JavaScript ToNumber over JSON-shaped values (undefined must be handled by the caller: it is NaN). */
    static double toNumber(Object o) {
        if (o == null) return 0;
        if (o instanceof Boolean) return (Boolean) o ? 1 : 0;
        Double d = num(o);
        if (d != null) return d;
        if (o instanceof String) {
            String t = jsTrim((String) o);
            if (t.isEmpty()) return 0;
            if (t.equals("Infinity") || t.equals("+Infinity")) return Double.POSITIVE_INFINITY;
            if (t.equals("-Infinity")) return Double.NEGATIVE_INFINITY;
            if (t.matches("0[xX][0-9a-fA-F]+")) return new java.math.BigInteger(t.substring(2), 16).doubleValue();
            if (t.matches("0[bB][01]+")) return new java.math.BigInteger(t.substring(2), 2).doubleValue();
            if (t.matches("0[oO][0-7]+")) return new java.math.BigInteger(t.substring(2), 8).doubleValue();
            if (DEC.matcher(t).matches()) return Double.parseDouble(t);
            return Double.NaN;
        }
        if (o instanceof List) return toNumber(str(o));
        return Double.NaN;
    }

    /** {@code m[k]} as a number: undefined (absent key) is NaN, null is 0. */
    static double numOf(Map<String, Object> m, String k) { return m.containsKey(k) ? toNumber(m.get(k)) : Double.NaN; }

    /** {@code out[k] = m[mk]} unless the member is undefined (absent), as JSON.stringify drops it. */
    static void putTerm(Map<String, Object> out, String k, Map<String, Object> m, String mk) { if (m.containsKey(mk)) out.put(k, m.get(mk)); }

    /** {@code x.length} when it is a number (a string or an array), else NaN (undefined). */
    static double jsLength(Object o) { return o instanceof String ? ((String) o).length() : o instanceof List ? ((List<?>) o).size() : Double.NaN; }

    static String jsTrim(String s) {
        int a = 0, b = s.length();
        while (a < b && ws(s.charAt(a))) a++;
        while (b > a && ws(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }

    private static boolean ws(char c) {
        return c == ' ' || (c >= '\t' && c <= '\r') || c == ' ' || c == ' ' || (c >= ' ' && c <= ' ')
            || c == ' ' || c == ' ' || c == ' ' || c == ' ' || c == '　' || c == '﻿';
    }
}
