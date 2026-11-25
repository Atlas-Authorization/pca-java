package net.atlasauth.pca.intent;

import net.atlasauth.pca.DetMath;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.DoubleSupplier;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;

/**
 * The outcome space (a typed, finite cell grid per verb): numeric dimensions partitioned by cuts, categorical dimensions
 * with an OTHER cell; the product workload measure and the separable harm model. Numbers are binary64 throughout so every
 * figure matches the reference bit for bit (logarithms and exponentials from StrictMath, the fdlibm functions).
 */
public final class IntentOmega {
    private IntentOmega() {}

    /** The categorical "any other value" sentinel. */
    public static final String OTHER = "⊥";
    public static final int EXACT_SPAN = 4096;
    public static final int HARM_QUADRATURE_PIECES = 1024;
    private static final double EULER_GAMMA = 0.5772156649015329;

    public record CatValue(String kind, String value) {}

    public record NumCell(double lo, double hi) {}

    /** A dimension of a verb space: numeric ({@code kind == "num"}) or categorical ({@code "cat"}). */
    public abstract static class Dim {
        public final String kind;
        public final String path;
        Dim(String kind, String path) { this.kind = kind; this.path = path; }
    }

    public static final class NumDim extends Dim {
        public final double lo, hi;
        public final double[] cuts;
        public final String dist;
        private List<NumCell> cells;
        private Double total;
        public NumDim(String path, double lo, double hi, double[] cuts, String dist) {
            super("num", path);
            this.lo = lo; this.hi = hi; this.cuts = cuts; this.dist = dist;
        }
    }

    public static final class CatDim extends Dim {
        public final List<CatValue> values;
        public CatDim(String path, List<CatValue> values) { super("cat", path); this.values = values; }
    }

    public static final class VerbSpace {
        public final String verb;
        public final String reversibility;
        public double weight;
        public final List<Dim> dims;
        public VerbSpace(String verb, String reversibility, double weight, List<Dim> dims) {
            this.verb = verb; this.reversibility = reversibility; this.weight = weight; this.dims = dims;
        }
    }

    public static final class Omega {
        public final List<VerbSpace> verbs;
        public final List<String> approximate;
        public Omega(List<VerbSpace> verbs, List<String> approximate) { this.verbs = verbs; this.approximate = approximate; }
    }

    /** A concrete outcome: the verb and one value (Double or String) per dimension path. */
    public record Outcome(String verb, Map<String, Object> values) {}

    public interface HarmModel {
        double verb(VerbSpace vs);
        double dim(Dim d, Object x);
        /** Optional closed form of the mean of {@link #dim} over an integer interval; null when absent. */
        default Double dimMean(NumDim d, double lo, double hi) { return null; }
    }

    // ---- JSON <-> typed ----

    public static double dbl(Object o) {
        if (o instanceof Json.Num) return Double.parseDouble(((Json.Num) o).raw);
        if (o instanceof Number) return ((Number) o).doubleValue();
        throw new IllegalArgumentException("not a number");
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Object o) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("not an object");
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> arr(Object o) {
        if (!(o instanceof List)) throw new IllegalArgumentException("not an array");
        return (List<Object>) o;
    }

    public static boolean isNumber(Object o) { return o instanceof Json.Num || o instanceof Number; }

    public static Dim dimFromJson(Object o) {
        Map<String, Object> m = obj(o);
        String path = (String) m.get("path");
        if ("num".equals(m.get("kind"))) {
            List<Object> cs = arr(m.get("cuts"));
            double[] cuts = new double[cs.size()];
            for (int i = 0; i < cuts.length; i++) cuts[i] = dbl(cs.get(i));
            return new NumDim(path, dbl(m.get("lo")), dbl(m.get("hi")), cuts, (String) m.get("dist"));
        }
        List<CatValue> vs = new ArrayList<>();
        for (Object x : arr(m.get("values"))) vs.add(new CatValue((String) obj(x).get("kind"), (String) obj(x).get("value")));
        return new CatDim(path, vs);
    }

    public static Map<String, Object> dimToJson(Dim d) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kind", d.kind);
        m.put("path", d.path);
        if (d instanceof NumDim n) {
            m.put("lo", n.lo);
            m.put("hi", n.hi);
            List<Object> cs = new ArrayList<>();
            for (double c : n.cuts) cs.add(c);
            m.put("cuts", cs);
            m.put("dist", n.dist);
        } else {
            List<Object> vs = new ArrayList<>();
            for (CatValue v : ((CatDim) d).values) vs.add(catValueJson(v));
            m.put("values", vs);
        }
        return m;
    }

    static Map<String, Object> catValueJson(CatValue v) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kind", v.kind());
        m.put("value", v.value());
        return m;
    }

    public static VerbSpace verbSpaceFromJson(Object o) {
        Map<String, Object> m = obj(o);
        List<Dim> dims = new ArrayList<>();
        for (Object d : arr(m.get("dims"))) dims.add(dimFromJson(d));
        return new VerbSpace((String) m.get("verb"), (String) m.get("reversibility"), dbl(m.get("weight")), dims);
    }

    public static Map<String, Object> verbSpaceToJson(VerbSpace vs) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("verb", vs.verb);
        m.put("reversibility", vs.reversibility);
        m.put("weight", vs.weight);
        List<Object> ds = new ArrayList<>();
        for (Dim d : vs.dims) ds.add(dimToJson(d));
        m.put("dims", ds);
        return m;
    }

    public static Omega omegaFromJson(Object o) {
        Map<String, Object> m = obj(o);
        List<VerbSpace> vs = new ArrayList<>();
        for (Object v : arr(m.get("verbs"))) vs.add(verbSpaceFromJson(v));
        List<String> ap = new ArrayList<>();
        if (m.get("approximate") instanceof List) for (Object a : arr(m.get("approximate"))) ap.add((String) a);
        return new Omega(vs, ap);
    }

    public static Map<String, Object> omegaToJson(Omega om) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", 1.0);
        List<Object> vs = new ArrayList<>();
        for (VerbSpace v : om.verbs) vs.add(verbSpaceToJson(v));
        m.put("verbs", vs);
        m.put("approximate", new ArrayList<Object>(om.approximate));
        return m;
    }

    public static Outcome outcomeFromJson(Object o) {
        Map<String, Object> m = obj(o);
        Map<String, Object> vals = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : obj(m.get("values")).entrySet()) vals.put(e.getKey(), isNumber(e.getValue()) ? (Object) dbl(e.getValue()) : e.getValue());
        return new Outcome((String) m.get("verb"), vals);
    }

    public static Map<String, Object> outcomeToJson(Outcome o) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("verb", o.verb());
        m.put("values", new LinkedHashMap<>(o.values()));
        return m;
    }

    // ---- cells ----

    public static List<NumCell> numCells(NumDim d) {
        if (d.cells != null) return d.cells;
        List<NumCell> out = new ArrayList<>();
        double cur = d.lo;
        for (double c : d.cuts) {
            if (c < d.lo || c > d.hi) continue;
            if (cur <= c - 1) out.add(new NumCell(cur, c - 1));
            out.add(new NumCell(c, c));
            cur = c + 1;
        }
        if (cur <= d.hi) out.add(new NumCell(cur, d.hi));
        d.cells = out;
        return out;
    }

    public static int cellCount(Dim d) { return d instanceof NumDim n ? numCells(n).size() : ((CatDim) d).values.size(); }

    public static double verbCellCount(VerbSpace vs) {
        double n = 1;
        for (Dim d : vs.dims) n *= cellCount(d);
        return n;
    }

    public static int[] decodeCell(VerbSpace vs, double flat) {
        int[] idx = new int[vs.dims.size()];
        for (int i = vs.dims.size() - 1; i >= 0; i--) {
            int n = cellCount(vs.dims.get(i));
            idx[i] = (int) (flat % n);
            flat = Math.floor(flat / n);
        }
        return idx;
    }

    public static double encodeCell(VerbSpace vs, int[] idx) {
        double flat = 0;
        for (int i = 0; i < vs.dims.size(); i++) flat = flat * cellCount(vs.dims.get(i)) + idx[i];
        return flat;
    }

    /** Which cell a concrete string falls in (exact, then longest prefix, then OTHER). */
    public static int catCellOf(CatDim d, String s) {
        int best = -1;
        int bestLen = -1;
        for (int i = 0; i < d.values.size(); i++) {
            CatValue v = d.values.get(i);
            if (v.kind().equals("exact") && v.value().equals(s)) return i;
            if (v.kind().equals("prefix") && s.startsWith(v.value()) && v.value().length() > bestLen) {
                best = i;
                bestLen = v.value().length();
            }
        }
        if (best >= 0) return best;
        for (int i = 0; i < d.values.size(); i++) if (d.values.get(i).kind().equals("other")) return i;
        return -1;
    }

    /** The cell a value falls in, or -1 outside the dimension's domain or type. */
    public static int cellOfValue(Dim d, Object x) {
        if (d instanceof NumDim n) {
            if (!(x instanceof Double) || !Double.isFinite((Double) x)) return -1;
            double v = (Double) x;
            List<NumCell> cells = numCells(n);
            for (int i = 0; i < cells.size(); i++) if (v >= cells.get(i).lo() && v <= cells.get(i).hi()) return i;
            return -1;
        }
        if (!(x instanceof String)) return -1;
        return catCellOf((CatDim) d, (String) x);
    }

    /** Per-dimension cell indices of an outcome, or null when a value lies outside the space. */
    public static int[] cellOf(VerbSpace vs, Outcome o) {
        int[] idx = new int[vs.dims.size()];
        for (int k = 0; k < idx.length; k++) {
            Dim d = vs.dims.get(k);
            int i = cellOfValue(d, o.values().get(d.path));
            if (i < 0) return null;
            idx[k] = i;
        }
        return idx;
    }

    public static String catRep(CatDim d, int i) {
        CatValue v = d.values.get(i);
        if (v.kind().equals("exact")) return v.value();
        String base = v.kind().equals("prefix") ? v.value() + "x" : "other";
        for (int k = 0; k < 64; k++) {
            String s = base + (k == 0 ? "" : String.valueOf(k));
            if (catCellOf(d, s) == i) return s;
        }
        return base;
    }

    /** The question point of a numeric cell (a boundary witness). */
    public static double numRep(NumDim d, int i) {
        NumCell c = numCells(d).get(i);
        return i > 0 ? c.lo() : c.hi();
    }

    public static Object repValue(Dim d, int i) { return d instanceof NumDim n ? (Object) numRep(n, i) : catRep((CatDim) d, i); }

    public static Outcome cellRep(VerbSpace vs, int[] idx) {
        Map<String, Object> values = new LinkedHashMap<>();
        for (int i = 0; i < vs.dims.size(); i++) values.put(vs.dims.get(i).path, repValue(vs.dims.get(i), idx[i]));
        return new Outcome(vs.verb, values);
    }

    // ---- workload and harm ----

    private static boolean logUniform(NumDim d) { return d.dist.equals("loguniform") && d.lo >= 0; }

    static double pointWeight(NumDim d, double x) { return logUniform(d) ? 1 / (x + 1) : 1; }

    private static final Pattern AMOUNT = Pattern.compile("(^|\\.)amount$");

    private static boolean linearAmount(Dim d) { return d instanceof NumDim && AMOUNT.matcher(d.path).find(); }

    /** Irreversible 10, rate-limited 3, reversible 1; amounts scale as 1 + x/100. */
    public static final HarmModel DEFAULT_HARM = new HarmModel() {
        @Override public double verb(VerbSpace vs) { return vs.reversibility.equals("irreversible") ? 10 : vs.reversibility.equals("rate_limited") ? 3 : 1; }
        @Override public double dim(Dim d, Object x) { return linearAmount(d) && x instanceof Double ? 1 + Math.max(0, (Double) x) / 100 : 1; }
        @Override public Double dimMean(NumDim d, double lo, double hi) {
            return linearAmount(d) ? 1 + Math.max(0, intervalMeanX(d, Math.max(lo, 0), hi, lo)) / 100 : 1.0;
        }
    };

    public static double harmMax(Omega omega) { return harmMax(omega, DEFAULT_HARM); }

    public static double harmMax(Omega omega, HarmModel harm) {
        double m = 0;
        for (VerbSpace vs : omega.verbs) {
            double f = harm.verb(vs);
            for (Dim d : vs.dims) {
                if (d instanceof NumDim n) f *= Math.max(harm.dim(d, n.lo), harm.dim(d, n.hi));
                else {
                    CatDim c = (CatDim) d;
                    double mx = Double.NEGATIVE_INFINITY;
                    for (int i = 0; i < c.values.size(); i++) mx = Math.max(mx, harm.dim(d, catRep(c, i)));
                    f *= mx;
                }
            }
            m = Math.max(m, f);
        }
        return m;
    }

    private static double harmonic(double n) {
        if (n <= 0) return 0;
        if (n <= EXACT_SPAN) {
            double s = 0;
            for (double k = n; k >= 1; k--) s += 1 / k;
            return s;
        }
        double n2 = n * n;
        return DetMath.detLn(n) + EULER_GAMMA + 1 / (2 * n) - 1 / (12 * n2) + 1 / (120 * n2 * n2) - 1 / (252 * n2 * n2 * n2);
    }

    /** The sum of the point weight over the integers a..b (0 for an empty interval). */
    public static double intervalWeight(NumDim d, double a, double b) {
        if (b < a) return 0;
        if (!logUniform(d)) return b - a + 1;
        if (b - a + 1 <= EXACT_SPAN) {
            double s = 0;
            for (double x = b; x >= a; x--) s += 1 / (x + 1);
            return s;
        }
        return harmonic(b + 1) - harmonic(a);
    }

    private static double intervalFirstMoment(NumDim d, double a, double b) {
        if (b < a) return 0;
        if (!logUniform(d)) return ((a + b) * (b - a + 1)) / 2;
        return b - a + 1 - intervalWeight(d, a, b);
    }

    private static double intervalMeanX(NumDim d, double a, double b, double cellLo) {
        double whole = intervalWeight(d, cellLo, b);
        return whole > 0 ? intervalFirstMoment(d, a, b) / whole : 0;
    }

    private static double intervalHarm(NumDim d, double a, double b, HarmModel harm) {
        Double mean = harm.dimMean(d, a, b);
        if (mean != null) return mean;
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
            s += w * harm.dim(d, (double) Math.round((pa + pb) / 2));
        }
        return s / wTot;
    }

    private static double dimTotal(NumDim d) {
        if (d.total == null) d.total = intervalWeight(d, d.lo, d.hi);
        return d.total;
    }

    public record Stats(double mass, double harm) {}

    public static Stats dimCellStats(Dim d, int i) { return dimCellStats(d, i, DEFAULT_HARM); }

    public static Stats dimCellStats(Dim d, int i, HarmModel harm) {
        if (d instanceof CatDim c) return new Stats(1.0 / c.values.size(), harm.dim(d, catRep(c, i)));
        NumDim n = (NumDim) d;
        NumCell c = numCells(n).get(i);
        double wm = intervalWeight(n, c.lo(), c.hi());
        return new Stats(wm / dimTotal(n), wm > 0 ? intervalHarm(n, c.lo(), c.hi(), harm) : harm.dim(n, c.lo()));
    }

    private static double quantileValue(NumDim d, double target) {
        double acc = 0;
        List<NumCell> cells = numCells(d);
        for (NumCell c : cells) {
            double w = intervalWeight(d, c.lo(), c.hi());
            if (target < acc + w || c == cells.get(cells.size() - 1)) {
                double r = target - acc;
                if (c.hi() - c.lo() + 1 <= EXACT_SPAN) {
                    for (double x = c.lo(); x < c.hi(); x++) {
                        r -= pointWeight(d, x);
                        if (r < 0) return x;
                    }
                    return c.hi();
                }
                if (!logUniform(d)) return Math.min(c.hi(), c.lo() + Math.floor(r));
                double x = Math.floor((c.lo() + 1) * DetMath.detExp(r) - 1);
                return Math.max(c.lo(), Math.min(c.hi(), x));
            }
            acc += w;
        }
        return d.hi;
    }

    public static Stats cellStats(VerbSpace vs, int[] idx) { return cellStats(vs, idx, DEFAULT_HARM); }

    public static Stats cellStats(VerbSpace vs, int[] idx, HarmModel harm) {
        double mass = vs.weight;
        double h = harm.verb(vs);
        for (int k = 0; k < vs.dims.size(); k++) {
            Stats s = dimCellStats(vs.dims.get(k), idx[k], harm);
            mass *= s.mass();
            h *= s.harm();
        }
        return new Stats(mass, h);
    }

    public static double harmOf(VerbSpace vs, Outcome o) { return harmOf(vs, o, DEFAULT_HARM); }

    public static double harmOf(VerbSpace vs, Outcome o, HarmModel harm) {
        double h = harm.verb(vs);
        for (Dim d : vs.dims) h *= harm.dim(d, o.values().get(d.path));
        return h;
    }

    /** mulberry32, so every Monte Carlo number is reproducible. */
    public static DoubleSupplier rng(double seed) {
        int[] a = {(int) (long) seed};
        return () -> {
            a[0] += 0x6d2b79f5;
            int t = a[0];
            t = (t ^ (t >>> 15)) * (t | 1);
            t ^= t + (t ^ (t >>> 7)) * (t | 61);
            return ((t ^ (t >>> 14)) & 0xFFFFFFFFL) / 4294967296.0;
        };
    }

    public record Sample(VerbSpace vs, Outcome o) {}

    /** Draw an outcome from the workload. */
    public static Sample sampleOutcome(Omega omega, DoubleSupplier rand) {
        double u = rand.getAsDouble();
        VerbSpace vs = omega.verbs.get(omega.verbs.size() - 1);
        for (VerbSpace v : omega.verbs) {
            if (u < v.weight) { vs = v; break; }
            u -= v.weight;
        }
        Map<String, Object> values = new LinkedHashMap<>();
        for (Dim d : vs.dims) {
            if (d instanceof CatDim c) {
                values.put(d.path, catRep(c, Math.min(c.values.size() - 1, (int) Math.floor(rand.getAsDouble() * c.values.size()))));
                continue;
            }
            NumDim n = (NumDim) d;
            values.put(d.path, quantileValue(n, rand.getAsDouble() * dimTotal(n)));
        }
        return new Sample(vs, new Outcome(vs.verb, values));
    }

    public static VerbSpace verbSpace(Omega omega, String verb) {
        for (VerbSpace v : omega.verbs) if (v.verb.equals(verb)) return v;
        return null;
    }

    static List<Double> sortedNums(java.util.Collection<Double> xs) {
        List<Double> l = new ArrayList<>(xs);
        l.sort(Double::compare);
        return l;
    }

    static double[] toArray(List<Double> l) {
        double[] a = new double[l.size()];
        for (int i = 0; i < a.length; i++) a[i] = l.get(i);
        return a;
    }

    static String show(double[] a) { return Arrays.toString(a); }
}
