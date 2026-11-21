package net.atlasauth.pca.wallet;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.oauth.JsVal;

/**
 * The part of the intent outcome space the wallet reads: cells of a numeric (inclusive integer ranges) or categorical
 * (exact / prefix / other) dimension, the cell of a concrete outcome, its representative outcome, and the cell statistics
 * (mass and expected harm, exact for short cells, closed form or deterministic quadrature for long ones).
 *
 * <p>An outcome space is the parsed-JSON tree {@code {v:1, verbs:[{verb, reversibility, weight, dims:[...]}], approximate}};
 * a dimension is {@code {kind:"num", path, lo, hi, cuts, dist}} or {@code {kind:"cat", path, values:[{kind, value}]}}.
 */
public final class WalletOmega {
    private WalletOmega() {}

    /** The per-dimension harm factors (h_v the verb factor, g_d the dimension factor at a concrete value). */
    public interface HarmModel {
        double verb(Map<String, Object> vs);

        double dim(Map<String, Object> d, Object x);

        /** Closed form of E[g_d | x in [lo, hi]] for a numeric dimension, or null when the model has none. */
        default Double dimMean(Map<String, Object> d, double lo, double hi) { return null; }
    }

    static final int EXACT_SPAN = 4096;
    static final int HARM_QUADRATURE_PIECES = 1024;
    private static final double EULER_GAMMA = 0.5772156649015329;
    private static final Pattern AMOUNT = Pattern.compile("(^|\\.)amount$");

    private static boolean linearAmount(Map<String, Object> d) { return "num".equals(d.get("kind")) && AMOUNT.matcher((String) d.get("path")).find(); }

    /** Default separable harm: irreversible 10, rate-limited 3, reversible 1; amounts scale as 1 + x/100. */
    public static final HarmModel DEFAULT_HARM = new HarmModel() {
        @Override public double verb(Map<String, Object> vs) {
            Object r = vs.get("reversibility");
            return "irreversible".equals(r) ? 10 : "rate_limited".equals(r) ? 3 : 1;
        }

        @Override public double dim(Map<String, Object> d, Object x) {
            return linearAmount(d) && JsVal.isNumber(x) ? 1 + Math.max(0, JsVal.num(x)) / 100 : 1;
        }

        @Override public Double dimMean(Map<String, Object> d, double lo, double hi) {
            return linearAmount(d) ? 1 + Math.max(0, intervalMeanX(d, Math.max(lo, 0), hi, lo)) / 100 : 1.0;
        }
    };

    // ---- accessors ------------------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    public static List<Object> dims(Map<String, Object> vs) { return (List<Object>) vs.get("dims"); }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> dim(Map<String, Object> vs, int k) { return (Map<String, Object>) dims(vs).get(k); }

    @SuppressWarnings("unchecked")
    public static List<Object> values(Map<String, Object> d) { return (List<Object>) d.get("values"); }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> value(Map<String, Object> d, int i) { return (Map<String, Object>) values(d).get(i); }

    public static double dlo(Map<String, Object> d) { return JsVal.num(d.get("lo")); }

    public static double dhi(Map<String, Object> d) { return JsVal.num(d.get("hi")); }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> verbSpace(Map<String, Object> omega, Object verb) {
        for (Object v : (List<Object>) omega.get("verbs")) if (((Map<String, Object>) v).get("verb").equals(verb)) return (Map<String, Object>) v;
        return null;
    }

    // ---- cells ----------------------------------------------------------------------------------------------------------

    /** The ordered cells {lo, hi} of a numeric dimension (inclusive ranges; empty cells dropped). */
    public static List<double[]> numCells(Map<String, Object> d) {
        List<double[]> out = new ArrayList<>();
        double lo = dlo(d), hi = dhi(d);
        double cur = lo;
        for (Object cO : (List<?>) d.get("cuts")) {
            double c = JsVal.num(cO);
            if (c < lo || c > hi) continue;
            if (cur <= c - 1) out.add(new double[] {cur, c - 1});
            out.add(new double[] {c, c});
            cur = c + 1;
        }
        if (cur <= hi) out.add(new double[] {cur, hi});
        return out;
    }

    public static int cellCount(Map<String, Object> d) { return "num".equals(d.get("kind")) ? numCells(d).size() : values(d).size(); }

    /** Number of cells of a verb (the product of per-dimension cell counts). */
    public static double verbCellCount(Map<String, Object> vs) {
        double n = 1;
        for (int k = 0; k < dims(vs).size(); k++) n = n * cellCount(dim(vs, k));
        return n;
    }

    /** Decode a flat cell index into per-dimension cell indices (last dimension varies fastest). */
    public static int[] decodeCell(Map<String, Object> vs, double flat) {
        int nd = dims(vs).size();
        int[] idx = new int[nd];
        for (int i = nd - 1; i >= 0; i--) {
            int n = cellCount(dim(vs, i));
            idx[i] = (int) (flat % n);
            flat = Math.floor(flat / n);
        }
        return idx;
    }

    /** Which cell of a categorical dimension a concrete string falls in (exact, then longest prefix, then other). */
    public static int catCellOf(Map<String, Object> d, String s) {
        int best = -1;
        int bestLen = -1;
        List<Object> vals = values(d);
        for (int i = 0; i < vals.size(); i++) {
            Map<String, Object> v = value(d, i);
            if ("exact".equals(v.get("kind")) && v.get("value").equals(s)) return i;
            String pv = (String) v.get("value");
            if ("prefix".equals(v.get("kind")) && s.startsWith(pv) && pv.length() > bestLen) {
                best = i;
                bestLen = pv.length();
            }
        }
        if (best >= 0) return best;
        for (int i = 0; i < vals.size(); i++) if ("other".equals(value(d, i).get("kind"))) return i;
        return -1;
    }

    /** Which cell a concrete value falls in, or -1 when it is outside the dimension's domain or type. */
    public static int cellOfValue(Map<String, Object> d, Object x) {
        if ("num".equals(d.get("kind"))) {
            if (!JsVal.isNumber(x)) return -1;
            double v = JsVal.num(x);
            if (Double.isNaN(v) || Double.isInfinite(v)) return -1;
            List<double[]> cells = numCells(d);
            for (int i = 0; i < cells.size(); i++) if (v >= cells.get(i)[0] && v <= cells.get(i)[1]) return i;
            return -1;
        }
        if (!(x instanceof String)) return -1;
        return catCellOf(d, (String) x);
    }

    /** Per-dimension cell indices of an outcome {verb, values}, or null if any value lies outside the outcome space. */
    public static int[] cellOf(Map<String, Object> vs, Map<String, Object> o) {
        int nd = dims(vs).size();
        int[] idx = new int[nd];
        Object vals = o.get("values");
        for (int k = 0; k < nd; k++) {
            Map<String, Object> d = dim(vs, k);
            int i = cellOfValue(d, JsVal.get(vals, (String) d.get("path")));
            if (i < 0) return null;
            idx[k] = i;
        }
        return idx;
    }

    /** A concrete string that falls in categorical cell {@code i} (exact: itself; prefix / other: a fresh extension). */
    public static String catRep(Map<String, Object> d, int i) {
        Map<String, Object> v = value(d, i);
        if ("exact".equals(v.get("kind"))) return (String) v.get("value");
        String base = "prefix".equals(v.get("kind")) ? v.get("value") + "x" : "other";
        for (int k = 0; k < 64; k++) {
            String s = base + (k == 0 ? "" : String.valueOf(k));
            if (catCellOf(d, s) == i) return s;
        }
        return base;
    }

    /** The question point of a numeric cell: its lowest value when it has a left neighbour, else its highest. */
    public static double numRep(Map<String, Object> d, int i) {
        double[] c = numCells(d).get(i);
        return i > 0 ? c[0] : c[1];
    }

    public static Object repValue(Map<String, Object> d, int i) { return "num".equals(d.get("kind")) ? (Object) numRep(d, i) : catRep(d, i); }

    /** The representative (question) outcome {verb, values} of a cell. */
    public static Map<String, Object> cellRep(Map<String, Object> vs, int[] idx) {
        Map<String, Object> values = new LinkedHashMap<>();
        for (int k = 0; k < dims(vs).size(); k++) {
            Map<String, Object> d = dim(vs, k);
            values.put((String) d.get("path"), repValue(d, idx[k]));
        }
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("verb", vs.get("verb"));
        o.put("values", values);
        return o;
    }

    // ---- workload mass and harm ---------------------------------------------------------------------------------------

    private static boolean logUniform(Map<String, Object> d) { return "loguniform".equals(d.get("dist")) && dlo(d) >= 0; }

    private static double pointWeight(Map<String, Object> d, double x) { return logUniform(d) ? 1 / (x + 1) : 1; }

    /** H(n) = sum_{k=1}^{n} 1/k. */
    private static double harmonic(double n) {
        if (n <= 0) return 0;
        if (n <= EXACT_SPAN) {
            double s = 0;
            for (double k = n; k >= 1; k--) s += 1 / k;
            return s;
        }
        double n2 = n * n;
        return StrictMath.log(n) + EULER_GAMMA + 1 / (2 * n) - 1 / (12 * n2) + 1 / (120 * n2 * n2) - 1 / (252 * n2 * n2 * n2);
    }

    /** Sum of w(x) over the integers a..b for the dimension's law (0 for an empty interval). */
    public static double intervalWeight(Map<String, Object> d, double a, double b) {
        if (b < a) return 0;
        if (!logUniform(d)) return b - a + 1;
        if (b - a + 1 <= EXACT_SPAN) {
            double s = 0;
            for (double x = b; x >= a; x--) s += 1 / (x + 1);
            return s;
        }
        return harmonic(b + 1) - harmonic(a);
    }

    private static double intervalFirstMoment(Map<String, Object> d, double a, double b) {
        if (b < a) return 0;
        if (!logUniform(d)) return ((a + b) * (b - a + 1)) / 2;
        return b - a + 1 - intervalWeight(d, a, b);
    }

    private static double intervalMeanX(Map<String, Object> d, double a, double b, double cellLo) {
        double whole = intervalWeight(d, cellLo, b);
        return whole > 0 ? intervalFirstMoment(d, a, b) / whole : 0;
    }

    private static double intervalHarm(Map<String, Object> d, double a, double b, HarmModel harm) {
        Double dm = harm.dimMean(d, a, b);
        if (dm != null) return dm;
        double n = b - a + 1;
        double wTot = intervalWeight(d, a, b);
        if (!(wTot > 0)) return harm.dim(d, a);
        if (n <= EXACT_SPAN) {
            double s = 0;
            for (double x = a; x <= b; x++) s += pointWeight(d, x) * harm.dim(d, x);
            return s / wTot;
        }
        double s = 0;
        for (int i = 0; i < HARM_QUADRATURE_PIECES; i++) {
            double pa = a + Math.floor((i * n) / HARM_QUADRATURE_PIECES);
            double pb = a + Math.floor(((i + 1) * n) / HARM_QUADRATURE_PIECES) - 1;
            if (pb < pa) continue;
            double w = intervalWeight(d, pa, pb);
            s += w * harm.dim(d, Math.floor((pa + pb) / 2 + 0.5));
        }
        return s / wTot;
    }

    /** {mass, harm}: mu_d(cell) and E[g_d | cell] for one dimension cell. Categorical values are uniform. */
    public static double[] dimCellStats(Map<String, Object> d, int i, HarmModel harm) {
        if ("cat".equals(d.get("kind"))) return new double[] {1.0 / values(d).size(), harm.dim(d, catRep(d, i))};
        double[] c = numCells(d).get(i);
        double wm = intervalWeight(d, c[0], c[1]);
        double total = intervalWeight(d, dlo(d), dhi(d));
        return new double[] {wm / total, wm > 0 ? intervalHarm(d, c[0], c[1], harm) : harm.dim(d, c[0])};
    }

    /** {mass, harm}: the exact mu(cell) and E[h | cell] of a whole cell (product measure, separable harm). */
    public static double[] cellStats(Map<String, Object> vs, int[] idx, HarmModel harm) {
        double mass = JsVal.num(vs.get("weight"));
        double h = harm.verb(vs);
        for (int k = 0; k < dims(vs).size(); k++) {
            double[] s = dimCellStats(dim(vs, k), idx[k], harm);
            mass *= s[0];
            h *= s[1];
        }
        return new double[] {mass, h};
    }

    /** The label of a dimension path as a card shows it. */
    public static String labelOf(String path) {
        if (path.equals("action.resource")) return "resource";
        String last = path.substring(path.lastIndexOf('.') + 1);
        return last.replace('_', ' ');
    }
}
