package net.atlasauth.pca.siem;

import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import net.atlasauth.pca.revoke.JsVal;

/**
 * JavaScript text formatting over parsed JSON trees (Map / List / String / Boolean / Json.Num / null): the number-to-string
 * conversion, the template-literal rendering and {@code JSON.stringify}, so event lines are byte-identical to the reference.
 */
public final class JsFmt {
    private JsFmt() {}

    /** {@code String(d)} for a number: shortest round-trip digits, plain form for 1e-6 <= |d| < 1e21, else an exponent. */
    public static String num(double d) {
        if (Double.isNaN(d)) return "NaN";
        if (Double.isInfinite(d)) return d > 0 ? "Infinity" : "-Infinity";
        if (d == 0.0) return "0";
        String sign = d < 0 ? "-" : "";
        double a = Math.abs(d);
        BigDecimal exact = new BigDecimal(a);
        BigDecimal r = exact;
        for (int p = 1; p <= 17; p++) {
            BigDecimal c = exact.round(new MathContext(p, RoundingMode.HALF_EVEN));
            if (c.doubleValue() == a) { r = c; break; }
        }
        r = r.stripTrailingZeros();
        String digits = r.unscaledValue().toString();
        int k = digits.length();
        int n = k - r.scale();
        StringBuilder sb = new StringBuilder(sign);
        if (k <= n && n <= 21) {
            sb.append(digits);
            for (int i = 0; i < n - k; i++) sb.append('0');
        } else if (0 < n && n <= 21) {
            sb.append(digits, 0, n).append('.').append(digits, n, k);
        } else if (-6 < n && n <= 0) {
            sb.append("0.");
            for (int i = 0; i < -n; i++) sb.append('0');
            sb.append(digits);
        } else {
            int e = n - 1;
            String es = (e < 0 ? "-" : "+") + Math.abs(e);
            if (k == 1) sb.append(digits).append('e').append(es);
            else sb.append(digits.charAt(0)).append('.').append(digits, 1, k).append('e').append(es);
        }
        return sb.toString();
    }

    /** {@code `${v}`} of a JSON value: arrays join with commas (null elements are empty), objects print as [object Object]. */
    public static String str(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = JsVal.num(v);
        if (d != null) return num(d);
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            List<?> xs = (List<?>) v;
            for (int i = 0; i < xs.size(); i++) {
                if (i > 0) sb.append(',');
                if (xs.get(i) != null) sb.append(str(xs.get(i)));
            }
            return sb.toString();
        }
        return "[object Object]";
    }

    /** {@code JSON.stringify(v)} of a JSON tree: members in map order, numbers as JavaScript prints them (non-finite becomes null). */
    public static String stringify(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof String) { quote(sb, (String) v); return; }
        if (v instanceof Boolean) { sb.append(v.toString()); return; }
        Double d = JsVal.num(v);
        if (d != null) { sb.append(Double.isNaN(d) || Double.isInfinite(d) ? "null" : num(d)); return; }
        if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                write(sb, x);
            }
            sb.append(']');
            return;
        }
        if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                quote(sb, (String) e.getKey());
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
            return;
        }
        throw new IllegalArgumentException("not a JSON value: " + v.getClass().getName());
    }

    /** JSON string quoting as {@code JSON.stringify}: lone surrogates and control characters become lowercase \\u escapes. */
    public static void quote(StringBuilder sb, String s) {
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
                    if (c < 0x20) sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { sb.append(c).append(s.charAt(++i)); }
                    else if (Character.isSurrogate(c)) sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }
}
