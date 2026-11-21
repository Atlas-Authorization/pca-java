package net.atlasauth.pca.intent;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Classifier error folded into the residual risk: a confusion matrix estimated on a labelled calibration set with per-entry Clopper-Pearson upper
 * bounds (union bound), the risk in true coordinates (exact decomposition), the label-sound bound, the classifier-aware residual risk of a learner
 * over the augmented space, and the cells a maximum-error gate sends to just-in-time consent. Calibrations and specs are JSON trees.
 */
public final class IntentClassifierKit {
    private IntentClassifierKit() {}

    private static Map<String, Object> lm() { return new LinkedHashMap<>(); }

    private static Map<String, Object> m(Object o) { return IntentOmega.obj(o); }

    private static List<Object> row(double[] r) {
        List<Object> o = new ArrayList<>();
        for (double x : r) o.add(x);
        return o;
    }

    /** Calibrate a classifier on labelled examples ({truth, predicted}); labels outside the set are refused. {@code deltaGamma} defaults to 0.05. */
    public static Map<String, Object> calibrateConfusion(List<Object> samples, List<Object> labels, Double deltaGamma) {
        double delta = deltaGamma != null ? deltaGamma : 0.05;
        TreeSet<String> set = new TreeSet<>(Json::compareUtf8);
        for (Object l : labels) set.add((String) l);
        List<String> L = new ArrayList<>(set);
        if (L.isEmpty()) throw new IllegalArgumentException("calibrateConfusion: empty label set");
        if (!(delta > 0 && delta < 1)) throw new IllegalArgumentException("calibrateConfusion: delta must be in (0, 1)");
        int n = L.size();
        double[][] counts = new double[n][n];
        for (Object so : samples) {
            Map<String, Object> s = m(so);
            int t = L.indexOf(s.get("truth")), p = L.indexOf(s.get("predicted"));
            if (t < 0 || p < 0) throw new IllegalArgumentException("calibrateConfusion: label outside L (" + s.get("truth") + " / " + s.get("predicted") + ")");
            counts[t][p] = counts[t][p] + 1;
        }
        double alpha = delta / ((double) n * n);
        List<Object> cs = new ArrayList<>(), gs = new ArrayList<>(), bs = new ArrayList<>();
        for (double[] r : counts) {
            double total = 0;
            for (double c : r) total += c;
            double[] g = new double[n], b = new double[n];
            for (int i = 0; i < n; i++) {
                g[i] = total != 0 ? r[i] / total : 0;
                b[i] = IntentStats.clopperPearsonUpper(r[i], total, alpha);
            }
            cs.add(row(r)); gs.add(row(g)); bs.add(row(b));
        }
        Map<String, Object> out = lm();
        out.put("labels", new ArrayList<Object>(L));
        out.put("counts", cs);
        out.put("gamma", gs);
        out.put("gammaBar", bs);
        out.put("delta_ppm", IntentMapKit.jsRound(delta * 1_000_000));
        return out;
    }

    /** The calibration's content address (labels, counts, delta). */
    public static String confusionDigest(Map<String, Object> c) {
        Map<String, Object> body = lm();
        body.put("d", "atlas-pca/intent-classifier-calibration/v1");
        body.put("labels", c.get("labels"));
        body.put("counts", c.get("counts"));
        body.put("delta_ppm", c.get("delta_ppm"));
        return Pca.hashCanonical(IntentJs.normalize(body));
    }

    /** The published error rate shown on cards: the maximum over true labels of the upper bound of any other label, capped at 1. */
    public static double publishedErrorRate(Map<String, Object> c) {
        double worst = 0;
        List<Object> gb = IntentOmega.arr(c.get("gammaBar"));
        for (int t = 0; t < gb.size(); t++) {
            double s = 0;
            List<Object> r = IntentOmega.arr(gb.get(t));
            for (int p = 0; p < r.size(); p++) if (p != t) s = s + IntentOmega.dbl(r.get(p));
            double e = Math.min(1, s);
            if (e > worst) worst = e;
        }
        return worst;
    }

    /** The fixed card note for a classifier dimension. */
    public static String classifierCardNote(String id, Map<String, Object> c) {
        String pct = new BigDecimal(publishedErrorRate(c) * 100).setScale(1, RoundingMode.HALF_UP).toPlainString();
        return "\"" + id + "\" is decided by an attested classifier, not by a person. Published error rate: up to " + pct + "%.";
    }

    // ---- risk on explicit arrays ----

    private static double[][] mat(Object o) {
        List<Object> rows = IntentOmega.arr(o);
        double[][] out = new double[rows.size()][];
        for (int i = 0; i < out.length; i++) {
            List<Object> r = IntentOmega.arr(rows.get(i));
            out[i] = new double[r.size()];
            for (int j = 0; j < r.size(); j++) out[i][j] = IntentOmega.dbl(r.get(j));
        }
        return out;
    }

    private static boolean[][] bmat(Object o) {
        List<Object> rows = IntentOmega.arr(o);
        boolean[][] out = new boolean[rows.size()][];
        for (int i = 0; i < out.length; i++) {
            List<Object> r = IntentOmega.arr(rows.get(i));
            out[i] = new boolean[r.size()];
            for (int j = 0; j < r.size(); j++) out[i][j] = Boolean.TRUE.equals(r.get(j));
        }
        return out;
    }

    private static double gammaOfSet(double[][] g, List<Integer> A, int t) {
        double s = 0;
        for (int p : A) s = s + g[p][t];
        return Math.min(1, s);
    }

    private static List<Integer> members(boolean[] inG) {
        List<Integer> A = new ArrayList<>();
        for (int p = 0; p < inG.length; p++) if (inG[p]) A.add(p);
        return A;
    }

    /** R_kappa(G) over explicit arrays {mu, a, h, inG, g}: sum of mu (1 - a) h Gamma(A_G(x) | l), the set mass capped at 1. */
    public static double classifierRisk(Map<String, Object> arrays) {
        double[][] mu = mat(arrays.get("mu")), a = mat(arrays.get("a")), h = mat(arrays.get("h")), g = mat(arrays.get("g"));
        boolean[][] inG = bmat(arrays.get("inG"));
        double r = 0;
        for (int x = 0; x < mu.length; x++) {
            List<Integer> A = members(inG[x]);
            for (int t = 0; t < mu[x].length; t++) r += mu[x][t] * (1 - a[x][t]) * h[x][t] * gammaOfSet(g, A, t);
        }
        return r;
    }

    /** True iff a(x, l) = 1 for every (x, l) in G. */
    public static boolean labelSound(Map<String, Object> arrays) {
        double[][] a = mat(arrays.get("a"));
        boolean[][] inG = bmat(arrays.get("inG"));
        for (int x = 0; x < inG.length; x++) for (int p = 0; p < inG[x].length; p++) if (inG[x][p] && a[x][p] != 1) return false;
        return true;
    }

    /** The bound for a label-sound grant: hMax times the mass of unacceptable cells weighted by the set error. */
    public static double labelSoundBound(Map<String, Object> arrays, double hMax) {
        double[][] mu = mat(arrays.get("mu")), a = mat(arrays.get("a")), g = mat(arrays.get("g"));
        boolean[][] inG = bmat(arrays.get("inG"));
        double s = 0;
        for (int x = 0; x < mu.length; x++) {
            List<Integer> A = members(inG[x]);
            for (int t = 0; t < mu[x].length; t++) if (a[x][t] == 0) s += mu[x][t] * gammaOfSet(g, A, t);
        }
        return hMax * s;
    }

    // ---- risk from a learner over the augmented space ----

    private record Member(int[] cell, double p, double mass, double harm, boolean inGrant) {}

    private record Groups(CatDim dim, Map<String, Map<Integer, Member>> groups) {}

    private static VerbSpace verbOf(IntentLearner l, String verb) {
        for (VerbSpace v : l.omega.verbs) if (v.verb.equals(verb)) return v;
        return null;
    }

    private static Groups groupsOf(IntentLearner l, Map<String, Object> spec) {
        String verb = (String) spec.get("verb"), path = (String) spec.get("path");
        VerbSpace vs = verbOf(l, verb);
        if (vs == null) throw new IllegalArgumentException("classifier: no verb " + verb + " in Ω");
        int k = -1;
        for (int i = 0; i < vs.dims.size(); i++) if (vs.dims.get(i).path.equals(path)) { k = i; break; }
        Dim dim = k >= 0 ? vs.dims.get(k) : null;
        if (k < 0 || !(dim instanceof CatDim)) throw new IllegalArgumentException("classifier: " + verb + " has no categorical dimension " + path);
        Map<String, Map<Integer, Member>> groups = new LinkedHashMap<>();
        for (IntentLearner.CellView c : l.cells()) {
            if (!c.verb.equals(verb)) continue;
            StringBuilder key = new StringBuilder();
            for (int i = 0; i < c.cell.length; i++) if (i != k) key.append(c.cell[i]).append(',');
            groups.computeIfAbsent(key.toString(), z -> new LinkedHashMap<>()).put(c.cell[k], new Member(c.cell, c.p, c.mass, c.harm, c.inGrant));
        }
        return new Groups((CatDim) dim, groups);
    }

    private static double gbar(Map<String, Object> spec, CatDim dim, int pred, int truth) {
        IntentOmega.CatValue pv = dim.values.get(pred), tv = dim.values.get(truth);
        if (!pv.kind().equals("exact")) return 0;
        Map<String, Object> cal = m(spec.get("cal"));
        List<Object> labels = IntentOmega.arr(cal.get("labels"));
        int pi = labels.indexOf(pv.value());
        if (pi < 0) return 0;
        int ti = tv.kind().equals("exact") ? labels.indexOf(tv.value()) : -1;
        if (ti < 0) return 1;
        return IntentOmega.dbl(IntentOmega.arr(IntentOmega.arr(cal.get("gammaBar")).get(ti)).get(pi));
    }

    private static List<Integer> admitted(Map<Integer, Member> g) {
        List<Integer> A = new ArrayList<>();
        for (Map.Entry<Integer, Member> e : g.entrySet()) if (e.getValue().inGrant()) A.add(e.getKey());
        return A;
    }

    private static double setError(Map<String, Object> spec, CatDim dim, List<Integer> A, int t) {
        double s = 0;
        for (int p : A) s = s + gbar(spec, dim, p, t);
        return Math.min(1, s);
    }

    /** R-hat of the learner's grant with classifier error folded in: {total, perVerb}. {@code specs}: [{verb, path, cal}]. */
    public static Map<String, Object> classifierAwareResidualRisk(IntentLearner l, List<Object> specs) {
        Map<String, Double> perVerb = new LinkedHashMap<>();
        Map<String, Object> specOf = new LinkedHashMap<>();
        for (Object s : specs) specOf.put((String) m(s).get("verb"), s);
        for (IntentLearner.CellView c : l.cells()) {
            if (specOf.containsKey(c.verb)) continue;
            double prev = perVerb.getOrDefault(c.verb, 0.0);
            perVerb.put(c.verb, c.inGrant ? prev + c.mass * (1 - c.p) * c.harm : prev);
        }
        for (Object so : specs) {
            Map<String, Object> spec = m(so);
            Groups gr = groupsOf(l, spec);
            double r = 0;
            for (Map<Integer, Member> g : gr.groups().values()) {
                List<Integer> A = admitted(g);
                for (Map.Entry<Integer, Member> e : g.entrySet()) {
                    Member mem = e.getValue();
                    r += mem.mass() * (1 - mem.p()) * mem.harm() * setError(spec, gr.dim(), A, e.getKey());
                }
            }
            perVerb.put((String) spec.get("verb"), r);
        }
        double total = 0;
        Map<String, Object> pv = lm();
        for (Map.Entry<String, Double> e : perVerb.entrySet()) { total += e.getValue(); pv.put(e.getKey(), e.getValue()); }
        Map<String, Object> out = lm();
        out.put("total", total);
        out.put("perVerb", pv);
        return out;
    }

    /** The maximum-error gate: cells admitted on a classifier label that go to just-in-time consent, as [{verb, cell, flat}] sorted by flat index. */
    public static List<Map<String, Object>> classifierJitCells(IntentLearner l, Map<String, Object> spec, double gammaMax) {
        Groups gr = groupsOf(l, spec);
        VerbSpace vs = verbOf(l, (String) spec.get("verb"));
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<Integer, Member> g : gr.groups().values()) {
            List<Integer> A = admitted(g);
            if (A.isEmpty()) continue;
            double worst = 0;
            for (Map.Entry<Integer, Member> e : g.entrySet()) {
                if (e.getValue().inGrant() || !gr.dim().values.get(e.getKey()).kind().equals("exact")) continue;
                worst = Math.max(worst, setError(spec, gr.dim(), A, e.getKey()));
            }
            if (worst > gammaMax) {
                for (int p : A) {
                    int[] cell = g.get(p).cell();
                    Map<String, Object> o = lm();
                    o.put("verb", spec.get("verb"));
                    List<Object> cl = new ArrayList<>();
                    for (int x : cell) cl.add((double) x);
                    o.put("cell", cl);
                    o.put("flat", IntentOmega.encodeCell(vs, cell));
                    out.add(o);
                }
            }
        }
        out.sort((a, b) -> Double.compare((Double) a.get("flat"), (Double) b.get("flat")));
        return out;
    }
}
