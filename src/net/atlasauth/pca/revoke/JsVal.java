package net.atlasauth.pca.revoke;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;

/**
 * JavaScript value semantics over parsed JSON (Map / List / String / Boolean / Json.Num / null), shared by the revocation,
 * rotation, events and signals packages so each port reads the reference's loose checks the same way ({@code ??},
 * {@code typeof}, {@code Number.isFinite}, template literals, member reads that throw on null).
 */
public final class JsVal {
    private JsVal() {}

    /** The reference's TypeError: a refused argument (a subclass of IllegalArgumentException). */
    public static class TypeError extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        public TypeError(String m) { super(m); }
    }

    /** The binary64 value of a JSON number (Json.Num / Integer / Long / Double), else null. */
    public static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        if (o instanceof Integer || o instanceof Long || o instanceof Double || o instanceof Float || o instanceof Short) return ((Number) o).doubleValue();
        return null;
    }

    /** typeof o === 'number' and Number.isFinite(o). */
    public static boolean isFinite(Object o) {
        Double d = num(o);
        return d != null && !d.isNaN() && !d.isInfinite();
    }

    /** typeof o === 'number' (NaN and Infinity included). */
    public static boolean isNumber(Object o) { return num(o) != null; }

    /** Number.isSafeInteger. */
    public static boolean isSafeInteger(Object o) {
        Double d = num(o);
        return d != null && !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0;
    }

    /** True when o is a non-empty String. */
    public static boolean nonEmpty(Object o) { return o instanceof String && !((String) o).isEmpty(); }

    /** {@code o[k]} for a read that throws on null (a TypeError, as JavaScript does); a non-object has no members. */
    public static Object member(Object o, String k) {
        if (o == null) throw new TypeError("cannot read '" + k + "' of null or undefined");
        return o instanceof Map ? ((Map<?, ?>) o).get(k) : null;
    }

    /** {@code o?.[k]}: null when o is not an object. */
    public static Object opt(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    /** True when o is an object that carries the member (JSON null counts as present, as it is not undefined). */
    public static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    /** {@code a ?? b}: the fallback when a is null (absent members read as null). */
    public static Object or(Object a, Object b) { return a == null ? b : a; }

    /** A JSON number carrying a double the way JavaScript prints it (integers without a fraction). */
    public static Json.Num numOf(double d) {
        if (d == Math.rint(d) && Math.abs(d) < 1e21) return new Json.Num(new BigDecimal(d).toPlainString());
        return new Json.Num(Double.toString(d));
    }

    /** A JavaScript template-literal rendering ({@code `${v}`}) of a JSON scalar; arrays join with commas. */
    public static String str(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        if (v instanceof Json.Num || v instanceof Number) {
            Double d = num(v);
            if (d == null || d.isNaN()) return "NaN";
            if (d.isInfinite()) return d > 0 ? "Infinity" : "-Infinity";
            return numOf(d == 0.0 ? 0.0 : d).raw;
        }
        if (v instanceof List) return join((List<?>) v, ",");
        return "[object Object]";
    }

    /** {@code `${o[k]}`}: an absent member prints "undefined". */
    public static String strMember(Object o, String k) { return has(o, k) ? str(((Map<?, ?>) o).get(k)) : "undefined"; }

    /** Array.prototype.join: null elements print as the empty string. */
    public static String join(List<?> xs, String sep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < xs.size(); i++) {
            if (i > 0) sb.append(sep);
            Object x = xs.get(i);
            if (x != null) sb.append(str(x));
        }
        return sb.toString();
    }

    /** Math.round: halves round toward +Infinity. */
    public static double round(double x) {
        if (Double.isNaN(x) || Double.isInfinite(x)) return x;
        double f = Math.floor(x);
        return x - f >= 0.5 ? f + 1 : f;
    }

    /** JavaScript truthiness of a parsed JSON value. */
    public static boolean truthy(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = num(v);
        if (d != null) return d != 0.0 && !d.isNaN();
        return true;
    }

    /** True for a character JavaScript treats as whitespace (String.prototype.trim and the regular expression \\s). */
    public static boolean isSpace(char c) {
        return c == ' ' || (c >= '\t' && c <= '\r') || c == '\u00a0' || c == '\u1680' || (c >= '\u2000' && c <= '\u200a')
            || c == '\u2028' || c == '\u2029' || c == '\u202f' || c == '\u205f' || c == '\u3000' || c == '\ufeff';
    }

    /** A JSON object (not an array, not null). */
    public static boolean isRecord(Object o) { return o instanceof Map; }
}
