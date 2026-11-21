package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.CatValue;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * The joint-grant rules of multi-principal intent (unanimity, quorum(k), weighted with a threshold, plus vetoers), the exact
 * joint acceptance probability, and the common refinement of several outcome spaces. A rule is a JSON tree
 * {kind, vetoers?, k?, weights?, threshold?}.
 */
public final class IntentMulti {
    private IntentMulti() {}

    /** A rule in normal form: integer weights, an integer threshold, per-principal veto flags. */
    public record NormalRule(double[] weights, double threshold, boolean[] veto) {
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            List<Object> w = new ArrayList<>();
            for (double x : weights) w.add(x);
            m.put("weights", w);
            m.put("threshold", threshold);
            List<Object> v = new ArrayList<>();
            for (boolean x : veto) v.add(x);
            m.put("veto", v);
            return m;
        }

        public static NormalRule fromJson(Object o) {
            Map<String, Object> m = IntentOmega.obj(o);
            List<Object> w = IntentOmega.arr(m.get("weights"));
            List<Object> v = IntentOmega.arr(m.get("veto"));
            double[] ws = new double[w.size()];
            for (int i = 0; i < ws.length; i++) ws[i] = IntentOmega.dbl(w.get(i));
            boolean[] vs = new boolean[v.size()];
            for (int i = 0; i < vs.length; i++) vs[i] = (Boolean) v.get(i);
            return new NormalRule(ws, IntentOmega.dbl(m.get("threshold")), vs);
        }
    }

    private static boolean isInteger(Object o) {
        if (!IntentOmega.isNumber(o)) return false;
        double d = IntentOmega.dbl(o);
        return Double.isFinite(d) && d == Math.rint(d);
    }

    public static NormalRule normalizeRule(Map<String, Object> rule, List<String> refs) {
        Set<String> vetoers = new LinkedHashSet<>();
        if (rule.get("vetoers") instanceof List) for (Object v : (List<?>) rule.get("vetoers")) vetoers.add(String.valueOf(v));
        for (String v : vetoers) if (!refs.contains(v)) throw new IllegalArgumentException("aggregateIntentMaps: vetoer " + v + " is not one of the maps");
        boolean[] veto = new boolean[refs.size()];
        for (int i = 0; i < veto.length; i++) veto[i] = vetoers.contains(refs.get(i));
        double[] ones = new double[refs.size()];
        java.util.Arrays.fill(ones, 1);
        Object kind = rule.get("kind");
        if ("unanimity".equals(kind)) return new NormalRule(ones, refs.size(), veto);
        if ("quorum".equals(kind)) {
            Object k = rule.get("k");
            if (!(isInteger(k) && IntentOmega.dbl(k) >= 1 && IntentOmega.dbl(k) <= refs.size()))
                throw new IllegalArgumentException("aggregateIntentMaps: quorum k must be an integer in [1, " + refs.size() + "]");
            return new NormalRule(ones, IntentOmega.dbl(k), veto);
        }
        Object wm = rule.get("weights");
        if (wm == null && !refs.isEmpty())
            throw new IllegalArgumentException("Cannot read properties of " + (rule.containsKey("weights") ? "null" : "undefined") + " (reading '" + refs.get(0) + "')");
        double[] weights = new double[refs.size()];
        for (int i = 0; i < weights.length; i++) {
            Object w = wm instanceof Map ? ((Map<?, ?>) wm).get(refs.get(i)) : null;
            if (!(isInteger(w) && IntentOmega.dbl(w) >= 0)) throw new IllegalArgumentException("aggregateIntentMaps: every principal needs a non-negative integer weight");
            weights[i] = IntentOmega.dbl(w);
        }
        double W = 0;
        for (double w : weights) W += w;
        Object t = rule.get("threshold");
        if (!(isInteger(t) && IntentOmega.dbl(t) >= 1 && IntentOmega.dbl(t) <= W))
            throw new IllegalArgumentException("aggregateIntentMaps: threshold must be an integer in [1, " + AttestCommon.jsNumString(W) + "]");
        return new NormalRule(weights, IntentOmega.dbl(t), veto);
    }

    /** Principals that bound the joint grant: explicit vetoers plus implicit ones (threshold &gt; W - w_i). */
    public static List<String> effectiveVetoers(Map<String, Object> rule, List<String> refs) {
        NormalRule n = normalizeRule(rule, refs);
        double W = 0;
        for (double w : n.weights()) W += w;
        List<String> out = new ArrayList<>();
        for (int i = 0; i < refs.size(); i++) if (n.veto()[i] || n.threshold() > W - n.weights()[i]) out.add(refs.get(i));
        return out;
    }

    /** Does the rule admit, given which principals admit (vetoers must; the admitting weight must reach the threshold)? */
    public static boolean ruleAdmits(NormalRule n, boolean[] ins) {
        double s = 0;
        for (int i = 0; i < ins.length; i++) {
            if (n.veto()[i] && !ins[i]) return false;
            if (ins[i]) s += n.weights()[i];
        }
        return s >= n.threshold();
    }

    /** P(rule admits) with independent Bernoulli(p_i) acceptances: DP over the capped admitting weight. */
    public static double jointAcceptance(NormalRule n, double[] ps) {
        int T = (int) n.threshold();
        double[] dist = new double[T + 1];
        dist[0] = 1;
        for (int i = 0; i < ps.length; i++) {
            double[] next = new double[T + 1];
            double w = n.weights()[i];
            double p = ps[i];
            for (int s = 0; s <= T; s++) {
                double m = dist[s];
                if (m == 0) continue;
                int to = (int) Math.min(T, s + w);
                next[to] = next[to] + m * p;
                if (!n.veto()[i]) next[s] = next[s] + m * (1 - p);
            }
            dist = next;
        }
        return dist[T];
    }

    // ---- common refinement ----

    private static final List<String> SEV = List.of("reversible", "rate_limited", "irreversible");

    private static Dim mergeDim(Dim a, Dim b) {
        if (!a.kind.equals(b.kind)) throw new IllegalArgumentException("commonRefinement: " + a.path + " is numeric in one Omega and categorical in another");
        if (a instanceof NumDim x && b instanceof NumDim y) {
            if (x.lo != y.lo || x.hi != y.hi)
                throw new IllegalArgumentException("commonRefinement: " + a.path + " has different domains ([" + AttestCommon.jsNumString(x.lo) + ", " + AttestCommon.jsNumString(x.hi)
                    + "] vs [" + AttestCommon.jsNumString(y.lo) + ", " + AttestCommon.jsNumString(y.hi) + "])");
            Set<Double> cuts = new LinkedHashSet<>();
            for (double c : x.cuts) cuts.add(c + 0.0);
            for (double c : y.cuts) cuts.add(c + 0.0);
            return new NumDim(a.path, x.lo, x.hi, IntentOmega.toArray(IntentOmega.sortedNums(cuts)), x.dist);
        }
        TreeSet<String> ex = new TreeSet<>();
        TreeSet<String> pre = new TreeSet<>();
        List<CatValue> all = new ArrayList<>(((CatDim) a).values);
        all.addAll(((CatDim) b).values);
        for (CatValue v : all) {
            if (v.kind().equals("exact")) ex.add(v.value());
            else if (v.kind().equals("prefix")) pre.add(v.value());
        }
        List<CatValue> values = new ArrayList<>();
        for (String v : ex) values.add(new CatValue("exact", v));
        for (String v : pre) values.add(new CatValue("prefix", v));
        values.add(new CatValue("other", IntentOmega.OTHER));
        return new CatDim(a.path, values);
    }

    /** The union of the spaces' verbs, dimensions, cuts and named values (every input cell is a union of result cells). */
    public static Omega commonRefinement(List<Omega> omegas) {
        Map<String, String> revs = new LinkedHashMap<>();
        Map<String, List<Dim>> dimsByVerb = new LinkedHashMap<>();
        Set<String> approx = new TreeSet<>();
        for (Omega o : omegas) {
            approx.addAll(o.approximate);
            for (VerbSpace vs : o.verbs) {
                List<Dim> cur = dimsByVerb.get(vs.verb);
                if (cur == null) {
                    revs.put(vs.verb, vs.reversibility);
                    List<Dim> copy = new ArrayList<>();
                    for (Dim d : vs.dims) copy.add(IntentOmega.dimFromJson(IntentOmega.dimToJson(d)));
                    dimsByVerb.put(vs.verb, copy);
                    continue;
                }
                if (SEV.indexOf(vs.reversibility) > SEV.indexOf(revs.get(vs.verb))) revs.put(vs.verb, vs.reversibility);
                for (Dim d : vs.dims) {
                    int i = -1;
                    for (int k = 0; k < cur.size(); k++) if (cur.get(k).path.equals(d.path)) { i = k; break; }
                    if (i < 0) cur.add(IntentOmega.dimFromJson(IntentOmega.dimToJson(d)));
                    else cur.set(i, mergeDim(cur.get(i), d));
                }
            }
        }
        List<String> names = new ArrayList<>(new TreeSet<>(dimsByVerb.keySet()));
        List<VerbSpace> verbs = new ArrayList<>();
        for (String v : names) {
            List<Dim> dims = dimsByVerb.get(v);
            dims.sort((x, y) -> x.path.compareTo(y.path));
            verbs.add(new VerbSpace(v, revs.get(v), 1.0 / names.size(), dims));
        }
        return new Omega(verbs, new ArrayList<>(approx));
    }
}
