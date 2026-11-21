package net.atlasauth.pca.research;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.StoreJs;

/** JavaScript value semantics the research modules lean on (String(), toFixed, number spelling), over parsed JSON values. */
final class Js {
    private Js() {}

    /** The number as a JSON value (printed as JavaScript prints it). */
    static Json.Num n(double d) { return StoreJs.num(d); }

    static Json.Num n(long d) { return StoreJs.num(d); }

    /** True for a JSON number (a finite or infinite binary64, never NaN), like {@code typeof x === 'number' && !Number.isNaN(x)}. */
    static boolean isNum(Object x) { Double d = StoreJs.dbl(x); return d != null && !Double.isNaN(d); }

    /** {@code Number.isFinite(x)}: a number that is finite; a string or null is not. */
    static boolean isFinite(Object x) { return StoreJs.isFinite(x); }

    /** The double of a JSON number; call after {@link #isNum}. */
    static double d(Object x) { return StoreJs.dbl(x); }

    static String jsNum(double d) { return AttestCommon.jsNumString(d); }

    /** JavaScript {@code String(v)} for a JSON value (an absent value is "undefined" via {@link #str(Object, boolean)}). */
    static String str(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = StoreJs.dbl(v);
        if (d != null) return jsNum(d);
        if (v instanceof List) {
            StringBuilder b = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) { if (!first) b.append(','); first = false; if (x != null) b.append(str(x)); }
            return b.toString();
        }
        return "[object Object]";
    }

    static String str(Object v, boolean present) { return present ? str(v) : "undefined"; }

    /** JavaScript {@code x.toFixed(digits)} (exact decimal expansion, ties away from zero on the magnitude). */
    static String toFixed(double x, int digits) {
        if (Double.isNaN(x)) return "NaN";
        if (Double.isInfinite(x)) return x > 0 ? "Infinity" : "-Infinity";
        if (Math.abs(x) >= 1e21) return jsNum(x);
        String s = new BigDecimal(Math.abs(x)).setScale(digits, RoundingMode.HALF_UP).toPlainString();
        return (x < 0 ? "-" : "") + s;   // like JavaScript, a negative value that rounds to zero keeps its sign ("-0.0")
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    static Map<String, Object> obj() { return new LinkedHashMap<>(); }

    /** JavaScript truthiness of a parsed JSON value. */
    static boolean truthy(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = StoreJs.dbl(v);
        return d == null || !(d == 0 || Double.isNaN(d));
    }

    /** {@code Math.round}: ties toward +Infinity. */
    static double round(double x) { return Math.floor(x + 0.5); }
}
