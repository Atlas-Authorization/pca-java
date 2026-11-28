package net.atlasauth.pca.doctor;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;

/** JavaScript value semantics the doctor's checks depend on (Number(), String(), Date.parse, toFixed, JSON.stringify), over parsed JSON values. */
public final class Js {
    private Js() {}

    /** A member that is absent (JavaScript {@code undefined}); distinct from a JSON null. */
    public static final Object UNDEF = new Object() { @Override public String toString() { return "undefined"; } };

    public static boolean isUndef(Object o) { return o == UNDEF; }
    public static boolean nullish(Object o) { return o == null || o == UNDEF; }

    /** {@code o[k]}: UNDEF for an absent member or a non-object. */
    public static Object g(Object o, String k) {
        if (o instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) o;
            return m.containsKey(k) ? m.get(k) : UNDEF;
        }
        return UNDEF;
    }

    /** {@code a?.b} where the member must be present, else the default (the {@code ??} operator). */
    public static Object or(Object v, Object dflt) { return nullish(v) ? dflt : v; }

    public static Double num(Object v) {
        if (v instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) v).raw); } catch (NumberFormatException e) { return null; }
        }
        if (v instanceof Integer || v instanceof Long || v instanceof Double || v instanceof Float || v instanceof Short) return ((Number) v).doubleValue();
        return null;
    }

    public static boolean isNumber(Object v) { return num(v) != null; }

    /** {@code Number.isInteger}. */
    public static boolean isInteger(Object v) {
        Double d = num(v);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.rint(d);
    }

    public static boolean isNegZero(Object v) {
        Double d = num(v);
        return d != null && d == 0.0 && Double.doubleToRawLongBits(d) != 0L;
    }

    public static boolean truthy(Object v) {
        if (v == null || v == UNDEF || Boolean.FALSE.equals(v)) return false;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = num(v);
        return d == null || !(d == 0.0 || Double.isNaN(d));
    }

    // ---- strings and numbers ----

    private static final String WS = new String(new char[] {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF});

    public static String trim(String s) {
        int a = 0, b = s.length();
        while (a < b && WS.indexOf(s.charAt(a)) >= 0) a++;
        while (b > a && WS.indexOf(s.charAt(b - 1)) >= 0) b--;
        return s.substring(a, b);
    }

    private static final Pattern DEC = Pattern.compile("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?");

    /** {@code Number(string)}. */
    public static double toNumber(String s) {
        String t = trim(s);
        if (t.isEmpty()) return 0;
        if (t.matches("0[xX][0-9a-fA-F]+")) return new BigInteger(t.substring(2), 16).doubleValue();
        if (t.matches("0[oO][0-7]+")) return new BigInteger(t.substring(2), 8).doubleValue();
        if (t.matches("0[bB][01]+")) return new BigInteger(t.substring(2), 2).doubleValue();
        if (t.equals("Infinity") || t.equals("+Infinity")) return Double.POSITIVE_INFINITY;
        if (t.equals("-Infinity")) return Double.NEGATIVE_INFINITY;
        if (DEC.matcher(t).matches()) return Double.parseDouble(t);
        return Double.NaN;
    }

    /** {@code Number(v)} for a JSON value (objects and arrays are not coerced: NaN). */
    public static double toNumber(Object v) {
        Double d = num(v);
        if (d != null) return d;
        if (v == null) return 0;
        if (v instanceof Boolean) return ((Boolean) v) ? 1 : 0;
        if (v instanceof String) return toNumber((String) v);
        return Double.NaN;
    }

    /** JavaScript {@code String(number)}. */
    public static String numStr(double d) {
        if (Double.isNaN(d)) return "NaN";
        if (Double.isInfinite(d)) return d > 0 ? "Infinity" : "-Infinity";
        if (d == 0) return "0";
        String sign = d < 0 ? "-" : "";
        BigDecimal bd = new BigDecimal(Double.toString(Math.abs(d))).stripTrailingZeros();
        String digits = bd.unscaledValue().toString();
        int k = digits.length();
        int n = k - bd.scale();
        String body;
        if (k <= n && n <= 21) body = digits + "0".repeat(n - k);
        else if (0 < n && n <= 21) body = digits.substring(0, n) + "." + digits.substring(n);
        else if (-6 < n && n <= 0) body = "0." + "0".repeat(-n) + digits;
        else {
            int e = n - 1;
            String es = (e < 0 ? "-" : "+") + Math.abs(e);
            body = k == 1 ? digits + "e" + es : digits.charAt(0) + "." + digits.substring(1) + "e" + es;
        }
        return sign + body;
    }

    /** JavaScript {@code String(v)} for a JSON value. */
    public static String str(Object v) {
        if (v == null) return "null";
        if (v == UNDEF) return "undefined";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = num(v);
        if (d != null) return numStr(d);
        if (v instanceof List) {
            List<String> parts = new ArrayList<>();
            for (Object x : (List<?>) v) parts.add(nullish(x) ? "" : str(x));
            return String.join(",", parts);
        }
        return "[object Object]";
    }

    /** {@code (x).toFixed(1)} for a finite non-negative double. */
    public static String toFixed1(double x) {
        if (Double.isNaN(x)) return "NaN";
        return new BigDecimal(x).setScale(1, RoundingMode.HALF_UP).toPlainString();
    }

    /** {@code x.toFixed(digits)}. */
    public static String toFixed(double x, int digits) {
        if (Double.isNaN(x)) return "NaN";
        if (Double.isInfinite(x)) return numStr(x);
        boolean neg = x < 0;
        String body = new BigDecimal(Math.abs(x)).setScale(digits, RoundingMode.HALF_UP).toPlainString();
        return (neg ? "-" : "") + body;
    }

    public static String padEnd(String s, int n) { return s.length() >= n ? s : s + " ".repeat(n - s.length()); }

    // ---- Date.parse ----

    private static final String[] MONTHS = {"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"};
    private static final Pattern RFC = Pattern.compile("^(?:[A-Za-z]+,?\\s+)?(\\d{1,2})\\s+([A-Za-z]{3})[A-Za-z]*\\s+(\\d{4})\\s+(\\d{1,2}):(\\d{2})(?::(\\d{2}))?\\s*(GMT|UTC|UT|Z|[+-]\\d{4})$", Pattern.CASE_INSENSITIVE);
    private static final Pattern ISO = Pattern.compile("^(\\d{4})-(\\d{2})-(\\d{2})(?:T(\\d{2}):(\\d{2})(?::(\\d{2})(?:\\.(\\d{1,9}))?)?(Z|[+-]\\d{2}:\\d{2}))?$");

    private static double epoch(int y, int mo, int d, int h, int mi, int s, long ms, int offsetMin) {
        long days = LocalDate.of(y, mo, 1).plusDays(d - 1L).toEpochDay();
        return ((days * 24 + h) * 60 + mi) * 60_000.0 + s * 1000.0 + ms - offsetMin * 60_000.0;
    }

    /**
     * {@code Date.parse}: NaN when unparseable. Covers the HTTP date (RFC 1123 with a zone; a weekday word is ignored, as the reference
     * engine does) and ISO 8601 with a zone or date only (UTC). shortcut: a date without a zone is local time in the reference engine
     * (host-dependent) and is NaN here; other legacy spellings are NaN.
     */
    public static double parseDate(String s) {
        String t = trim(s);
        Matcher m = RFC.matcher(t);
        if (m.matches()) {
            int mo = -1;
            String mn = m.group(2).toLowerCase(Locale.ROOT);
            for (int i = 0; i < 12; i++) if (MONTHS[i].equals(mn)) mo = i + 1;
            if (mo < 0) return Double.NaN;
            int h = Integer.parseInt(m.group(4)), mi = Integer.parseInt(m.group(5)), sec = m.group(6) == null ? 0 : Integer.parseInt(m.group(6));
            if (h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi != 0 || sec != 0))) return Double.NaN;
            String z = m.group(7).toUpperCase(Locale.ROOT);
            int off = z.matches("[+-]\\d{4}") ? (z.charAt(0) == '-' ? -1 : 1) * (Integer.parseInt(z.substring(1, 3)) * 60 + Integer.parseInt(z.substring(3, 5))) : 0;
            int day = Integer.parseInt(m.group(1));
            if (day < 1 || day > 31) return Double.NaN;
            return epoch(Integer.parseInt(m.group(3)), mo, day, h, mi, sec, 0, off);
        }
        m = ISO.matcher(t);
        if (m.matches()) {
            int mo = Integer.parseInt(m.group(2)), d = Integer.parseInt(m.group(3));
            if (mo < 1 || mo > 12 || d < 1 || d > LocalDate.of(Integer.parseInt(m.group(1)), mo, 1).lengthOfMonth()) return Double.NaN;
            int h = m.group(4) == null ? 0 : Integer.parseInt(m.group(4)), mi = m.group(5) == null ? 0 : Integer.parseInt(m.group(5)), sec = m.group(6) == null ? 0 : Integer.parseInt(m.group(6));
            if (h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi != 0 || sec != 0 || m.group(7) != null))) return Double.NaN;
            long ms = m.group(7) == null ? 0 : Long.parseLong((m.group(7) + "00").substring(0, 3));
            String z = m.group(8);
            int off = 0;
            if (z != null && !z.equals("Z")) off = (z.charAt(0) == '-' ? -1 : 1) * (Integer.parseInt(z.substring(1, 3)) * 60 + Integer.parseInt(z.substring(4, 6)));
            return epoch(Integer.parseInt(m.group(1)), mo, d, h, mi, sec, ms, off);
        }
        return Double.NaN;
    }

    // ---- JSON.stringify(v, null, 2) ----

    public static String quote(String s) {
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
                    boolean lone = Character.isHighSurrogate(c) ? !(i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1)))
                        : Character.isLowSurrogate(c) && !(i > 0 && Character.isHighSurrogate(s.charAt(i - 1)));
                    if (c < 0x20 || lone) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    /** {@code JSON.stringify(v, null, 2)}: members that are UNDEF are dropped, an undefined array slot is null. */
    public static String stringify(Object v) {
        StringBuilder b = new StringBuilder();
        write(b, v, "");
        return b.toString();
    }

    private static void write(StringBuilder b, Object v, String ind) {
        if (v == null || v == UNDEF) { b.append("null"); return; }
        if (v instanceof String) { b.append(quote((String) v)); return; }
        if (v instanceof Boolean) { b.append(v); return; }
        Double d = num(v);
        if (d != null) { b.append(Double.isNaN(d) || Double.isInfinite(d) ? "null" : numStr(d)); return; }
        String inner = ind + "  ";
        if (v instanceof List) {
            List<?> l = (List<?>) v;
            if (l.isEmpty()) { b.append("[]"); return; }
            b.append("[\n");
            for (int i = 0; i < l.size(); i++) {
                b.append(inner);
                write(b, l.get(i), inner);
                b.append(i + 1 < l.size() ? ",\n" : "\n");
            }
            b.append(ind).append(']');
            return;
        }
        Map<?, ?> m = (Map<?, ?>) v;
        List<Object> keys = new ArrayList<>();
        for (Map.Entry<?, ?> e : m.entrySet()) if (e.getValue() != UNDEF) keys.add(e.getKey());
        if (keys.isEmpty()) { b.append("{}"); return; }
        b.append("{\n");
        for (int i = 0; i < keys.size(); i++) {
            b.append(inner).append(quote((String) keys.get(i))).append(": ");
            write(b, m.get(keys.get(i)), inner);
            b.append(i + 1 < keys.size() ? ",\n" : "\n");
        }
        b.append(ind).append('}');
    }
}
