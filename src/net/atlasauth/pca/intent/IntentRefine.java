package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import net.atlasauth.pca.intent.IntentLearner.ElicitOptions;
import net.atlasauth.pca.intent.IntentLearner.Observation;
import net.atlasauth.pca.intent.IntentLearner.Question;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.CatValue;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumCell;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;
import net.atlasauth.pca.intent.IntentRegion.Region;
import net.atlasauth.pca.intent.IntentRegion.RegionDim;

/**
 * Cut refinement and partial answers: a "partly" answer refines the outcome space (inserts cuts, names values or adds a
 * dimension), replays every earlier observation as a value-space region over the refined space, and records one observation
 * per new sub-cell of the questioned cell.
 */
public final class IntentRefine {
    private IntentRefine() {}

    /** One refinement of a verb's space: numeric cuts, categorical values / prefixes, or a whole new dimension. */
    public static final class Refinement {
        public String verb, path;
        public double[] cuts;
        public List<String> values, prefixes;
        public Dim newDim;

        public Refinement(String verb, String path) { this.verb = verb; this.path = path; }

        public static Refinement fromJson(Object o) {
            Map<String, Object> m = IntentOmega.obj(o);
            Refinement r = new Refinement((String) m.get("verb"), (String) m.get("path"));
            if (m.get("cuts") != null) r.cuts = doubles(m.get("cuts"));
            if (m.get("values") != null) r.values = strings(m.get("values"));
            if (m.get("prefixes") != null) r.prefixes = strings(m.get("prefixes"));
            if (m.get("newDim") != null) r.newDim = IntentOmega.dimFromJson(m.get("newDim"));
            return r;
        }
    }

    static double[] doubles(Object o) {
        List<Object> l = IntentOmega.arr(o);
        double[] d = new double[l.size()];
        for (int i = 0; i < d.length; i++) d[i] = IntentOmega.dbl(l.get(i));
        return d;
    }

    static List<String> strings(Object o) {
        List<String> out = new ArrayList<>();
        for (Object x : IntentOmega.arr(o)) out.add((String) x);
        return out;
    }

    private static List<CatValue> sortedCat(List<CatValue> values) {
        TreeSet<String> ex = new TreeSet<>(), pre = new TreeSet<>();
        for (CatValue v : values) {
            if (v.kind().equals("exact")) ex.add(v.value());
            if (v.kind().equals("prefix")) pre.add(v.value());
        }
        List<CatValue> out = new ArrayList<>();
        for (String s : ex) out.add(new CatValue("exact", s));
        for (String s : pre) out.add(new CatValue("prefix", s));
        out.add(new CatValue("other", IntentOmega.OTHER));
        return out;
    }

    private static double[] cutsOf(Iterable<Double> xs, double lo, double hi) {
        TreeSet<Double> set = new TreeSet<>();
        for (double c : xs) if (c >= lo && c <= hi) set.add(c == 0 ? 0.0 : c);
        double[] out = new double[set.size()];
        int i = 0;
        for (double c : set) out[i++] = c;
        return out;
    }

    private static Dim copyDim(Dim d) {
        if (d instanceof NumDim n) return new NumDim(n.path, n.lo, n.hi, n.cuts.clone(), n.dist);
        return new CatDim(d.path, new ArrayList<>(((CatDim) d).values));
    }

    /** The outcome space with one verb's dimension refined (the input is untouched). */
    public static Omega refineOmega(Omega omega, Refinement r) {
        VerbSpace src = null;
        for (VerbSpace v : omega.verbs) if (v.verb.equals(r.verb)) { src = v; break; }
        if (src == null) throw new IllegalArgumentException("refineOmega: no verb " + r.verb + " in Ω");
        List<Dim> dims = new ArrayList<>();
        int i = -1;
        for (int k = 0; k < src.dims.size(); k++) {
            dims.add(copyDim(src.dims.get(k)));
            if (i < 0 && src.dims.get(k).path.equals(r.path)) i = k;
        }
        if (r.newDim != null) {
            if (i >= 0) throw new IllegalArgumentException("refineOmega: " + r.path + " is already a dimension of " + r.verb);
            if (!r.newDim.path.equals(r.path)) throw new IllegalArgumentException("refineOmega: newDim.path must equal path");
            Dim d = copyDim(r.newDim);
            if (d instanceof CatDim c) d = new CatDim(c.path, sortedCat(c.values));
            else {
                NumDim n = (NumDim) d;
                List<Double> cs = new ArrayList<>();
                for (double c : n.cuts) cs.add(c);
                d = new NumDim(n.path, n.lo, n.hi, cutsOf(cs, n.lo, n.hi), n.dist);
            }
            dims.add(d);
            dims.sort((a, b) -> a.path.compareTo(b.path));
        } else {
            if (i < 0) throw new IllegalArgumentException("refineOmega: " + r.verb + " has no dimension " + r.path + " (pass newDim to add it)");
            Dim d = dims.get(i);
            if (d instanceof NumDim n) {
                if ((r.values != null && !r.values.isEmpty()) || (r.prefixes != null && !r.prefixes.isEmpty())) throw new IllegalArgumentException("refineOmega: " + r.path + " is numeric");
                List<Double> all = new ArrayList<>();
                for (double c : n.cuts) all.add(c);
                if (r.cuts != null) for (double c : r.cuts) if (c == Math.floor(c) && !Double.isInfinite(c)) all.add(c);
                dims.set(i, new NumDim(n.path, n.lo, n.hi, cutsOf(all, n.lo, n.hi), n.dist));
            } else {
                CatDim c = (CatDim) d;
                if (r.cuts != null && r.cuts.length > 0) throw new IllegalArgumentException("refineOmega: " + r.path + " is categorical");
                List<CatValue> all = new ArrayList<>(c.values);
                if (r.values != null) for (String s : r.values) all.add(new CatValue("exact", s));
                if (r.prefixes != null) for (String s : r.prefixes) all.add(new CatValue("prefix", s));
                List<CatValue> sorted = sortedCat(all);
                if (sorted.size() > 20) throw new IllegalArgumentException("refineOmega: " + r.path + " would have more than 20 values");
                dims.set(i, new CatDim(c.path, sorted));
            }
        }
        List<VerbSpace> verbs = new ArrayList<>();
        for (VerbSpace v : omega.verbs) {
            if (v == src) verbs.add(new VerbSpace(v.verb, v.reversibility, v.weight, dims));
            else verbs.add(new VerbSpace(v.verb, v.reversibility, v.weight, new ArrayList<>(v.dims)));
        }
        return new Omega(verbs, new ArrayList<>(omega.approximate));
    }

    /** The value-space region an observation was about, in the space it was recorded in. */
    public static Region regionOfObservation(Omega omega, Observation o) {
        if (o.region != null) return o.region;
        for (VerbSpace v : omega.verbs) if (v.verb.equals(o.verb)) return IntentRegion.regionOfCell(v, o.cell);
        throw new IllegalArgumentException("regionOfObservation: no verb " + o.verb);
    }

    /** May rewrite the region of an earlier observation (used when a dimension is added). */
    @FunctionalInterface public interface Rescope { Region apply(Observation o, Region region); }

    public static IntentLearner refineLearner(IntentLearner l, Refinement r, Rescope rescope) {
        Omega omega = refineOmega(l.omega, r);
        IntentLearner next = IntentMapKit.createLearner(omega, IntentMapKit.learnerOptionsOf(l));
        for (Observation o : l.observations) {
            Region region = regionOfObservation(l.omega, o);
            if (rescope != null) region = rescope.apply(o, region);
            VerbSpace vs = null;
            for (VerbSpace v : omega.verbs) if (v.verb.equals(o.verb)) { vs = v; break; }
            Map<String, Object> values = new LinkedHashMap<>(o.values);
            for (Dim d : vs.dims) if (!values.containsKey(d.path)) values.put(d.path, IntentOmega.repValue(d, 0));
            next.observe(new Outcome(o.verb, values), o.y, o.source, region);
        }
        return next;
    }

    /** One labelled part of a partial answer: a numeric range, a set of exact values, or "every other value". */
    public static final class PartialPart {
        public final Double lo, hi;
        public final List<String> values;
        public final int y;
        public final boolean isRange, isValues;

        public PartialPart(Double lo, Double hi, List<String> values, boolean isRange, boolean isValues, int y) {
            this.lo = lo; this.hi = hi; this.values = values; this.isRange = isRange; this.isValues = isValues; this.y = y;
        }

        public static PartialPart fromJson(Object o) {
            Map<String, Object> m = IntentOmega.obj(o);
            int y = (int) IntentOmega.dbl(m.get("y"));
            if (m.containsKey("lo")) return new PartialPart(IntentLearner.numOrNull(m.get("lo")), IntentLearner.numOrNull(m.get("hi")), null, true, false, y);
            if (m.containsKey("values")) return new PartialPart(null, null, strings(m.get("values")), false, true, y);
            return new PartialPart(null, null, null, false, false, y);
        }
    }

    /** "Partly": the refinement the answer implies and the label of every part. */
    public static final class PartialAnswer {
        public String path;
        public double[] cuts;
        public List<String> values;
        public Dim newDim;
        public List<PartialPart> parts = new ArrayList<>();

        public static PartialAnswer fromJson(Object o) {
            Map<String, Object> m = IntentOmega.obj(o);
            PartialAnswer a = new PartialAnswer();
            a.path = (String) m.get("path");
            if (m.get("cuts") != null) a.cuts = doubles(m.get("cuts"));
            if (m.get("values") != null) a.values = strings(m.get("values"));
            if (m.get("newDim") != null) a.newDim = IntentOmega.dimFromJson(m.get("newDim"));
            for (Object p : IntentOmega.arr(m.get("parts"))) a.parts.add(PartialPart.fromJson(p));
            return a;
        }
    }

    private static Integer partLabel(Dim d, int j, List<PartialPart> parts) {
        Object x = IntentOmega.repValue(d, j);
        for (PartialPart p : parts) {
            if (p.isRange) {
                if (!(d instanceof NumDim n)) continue;
                NumCell c = IntentOmega.numCells(n).get(j);
                if (p.lo != null && p.hi != null && c.lo() >= p.lo && c.hi() <= p.hi) return p.y;
            } else if (p.isValues) {
                if (d instanceof CatDim c && c.values.get(j).kind().equals("exact") && p.values.contains(String.valueOf(x))) return p.y;
            } else if (d instanceof CatDim c && !c.values.get(j).kind().equals("exact")) return p.y;
        }
        return null;
    }

    private static List<Integer> subCells(Dim d, Region region) {
        int n = IntentOmega.cellCount(d);
        RegionDim rd = region.dims.get(d.path);
        List<Integer> out = new ArrayList<>();
        for (int j = 0; j < n; j++) {
            if (rd == null) out.add(j);
            else if (d instanceof NumDim nd && rd.kind.equals("num")) {
                NumCell c = IntentOmega.numCells(nd).get(j);
                if (c.lo() >= rd.lo && c.hi() <= rd.hi) out.add(j);
            } else if (d instanceof CatDim && rd.kind.equals("cat")) {
                int cell = IntentOmega.catCellOf(new CatDim(d.path, rd.values), (String) IntentOmega.repValue(d, j));
                if (rd.cells.contains(cell)) out.add(j);
            }
        }
        return out;
    }

    private static Map<String, Object> rangePart(double lo, double hi) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("lo", lo);
        m.put("hi", hi);
        return m;
    }

    private static Map<String, Object> cellsPart(List<Integer> cells) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("cells", new ArrayList<Object>(cells));
        return m;
    }

    private static VerbSpace verbOf(Omega o, String verb) {
        for (VerbSpace v : o.verbs) if (v.verb.equals(verb)) return v;
        return null;
    }

    public static final class PartialResult {
        public final IntentLearner learner;
        public final List<Observation> added;
        PartialResult(IntentLearner learner, List<Observation> added) { this.learner = learner; this.added = added; }
    }

    /** Apply a partial answer to question q: a NEW learner over the refined space and the observations the answer added. */
    public static PartialResult answerPartial(IntentLearner l, Question q, PartialAnswer a) {
        VerbSpace oldVs = verbOf(l.omega, q.verb);
        if (oldVs == null) throw new IllegalArgumentException("answerPartial: no verb " + q.verb);
        Region qRegion = IntentRegion.regionOfCell(oldVs, q.cell);
        Refinement r = new Refinement(q.verb, a.path);
        r.cuts = a.cuts; r.values = a.values; r.newDim = a.newDim;
        Omega refined = refineOmega(l.omega, r);
        VerbSpace nvs = verbOf(refined, q.verb);
        Dim d = null;
        for (Dim x : nvs.dims) if (x.path.equals(a.path)) { d = x; break; }
        final Dim dd = d;
        Rescope rescope = null;
        if (a.newDim != null) {
            List<Integer> yes = new ArrayList<>();
            for (int j = 0; j < IntentOmega.cellCount(dd); j++) if (Integer.valueOf(1).equals(partLabel(dd, j, a.parts))) yes.add(j);
            rescope = (o, region) -> {
                if (!o.verb.equals(q.verb) || o.y != 1) return region;
                if (dd instanceof CatDim) return IntentRegion.restrictRegion(region, dd, cellsPart(yes));
                NumDim nd = (NumDim) dd;
                if (yes.isEmpty()) return IntentRegion.restrictRegion(region, dd, rangePart(nd.hi + 1, nd.hi + 1));
                List<NumCell> cells = IntentOmega.numCells(nd);
                return IntentRegion.restrictRegion(region, dd, rangePart(cells.get(yes.get(0)).lo(), cells.get(yes.get(yes.size() - 1)).hi()));
            };
        }
        IntentLearner next = refineLearner(l, r, rescope);
        List<Observation> added = new ArrayList<>();
        for (int j : subCells(dd, qRegion)) {
            Integer y = partLabel(dd, j, a.parts);
            if (y == null) continue;
            Region region;
            if (dd instanceof NumDim nd) {
                NumCell c = IntentOmega.numCells(nd).get(j);
                region = IntentRegion.restrictRegion(qRegion, dd, rangePart(c.lo(), c.hi()));
            } else region = IntentRegion.restrictRegion(qRegion, dd, cellsPart(List.of(j)));
            Map<String, Object> values = new LinkedHashMap<>(q.outcome.values());
            values.put(dd.path, IntentOmega.repValue(dd, j));
            for (Dim x : nvs.dims) if (!values.containsKey(x.path)) values.put(x.path, IntentOmega.repValue(x, 0));
            Observation ob = next.observe(new Outcome(q.verb, values), y, "elicitation", region);
            if (ob != null) added.add(ob);
        }
        return new PartialResult(next, added);
    }

    /** An adaptive answer is 0, 1 (Integer) or a {@link PartialAnswer}. */
    @FunctionalInterface public interface AdaptiveAnswer { Object answer(Question q, IntentLearner l); }

    public static final class AdaptiveElicitResult {
        public final String stop;
        public final int questions, auditQuestions, seedQuestions, refinements;
        public final List<Question> asked;
        public final IntentLearner learner;

        AdaptiveElicitResult(String stop, int questions, int auditQuestions, int seedQuestions, List<Question> asked, IntentLearner learner, int refinements) {
            this.stop = stop; this.questions = questions; this.auditQuestions = auditQuestions; this.seedQuestions = seedQuestions; this.asked = asked; this.learner = learner; this.refinements = refinements;
        }
    }

    /** Elicitation that accepts yes, no and partly; after maxRefinements (default 8) partial answers further ones count as "no". */
    public static AdaptiveElicitResult elicitAdaptive(IntentLearner learner, AdaptiveAnswer answer, ElicitOptions o, Integer maxRefinements) {
        IntentLearner[] l = {learner};
        List<Question> asked = new ArrayList<>();
        int[] refinements = {0};
        int maxRef = maxRefinements != null ? maxRefinements : 8;
        java.util.function.Consumer<Question> apply = q -> {
            Object a = answer.answer(q, l[0]);
            asked.add(q);
            if (a instanceof PartialAnswer pa) {
                if (refinements[0] < maxRef) {
                    l[0] = answerPartial(l[0], q, pa).learner;
                    refinements[0]++;
                } else l[0].observe(q.outcome, 0, "elicitation", null);
            } else l[0].observe(q.outcome, ((Number) a).intValue(), "elicitation", null);
        };
        int seedQuestions = 0;
        for (Object[] s : o.seed) {
            if (asked.size() >= o.maxQuestions) break;
            VerbSpace vs = verbOf(l[0].omega, (String) s[0]);
            int[] cell = (int[]) s[1];
            if (vs == null || cell.length != vs.dims.size()) continue;
            Map<String, Object> values = new LinkedHashMap<>();
            for (int k = 0; k < vs.dims.size(); k++) values.put(vs.dims.get(k).path, IntentOmega.repValue(vs.dims.get(k), cell[k]));
            Outcome outcome = new Outcome((String) s[0], values);
            double p = l[0].acceptance(outcome);
            if (p <= 1e-9 || p >= 1 - 1e-9 || l[0].isVetoed(outcome)) continue;
            apply.accept(new Question((String) s[0], cell.clone(), outcome, p, 0));
            seedQuestions++;
        }
        String stop = null;
        while (stop == null) {
            IntentLearner.LearnerMetrics m = l[0].metrics();
            if (m.residualRisk <= o.epsRisk && m.burden <= o.epsBurden) stop = "converged";
            else if (asked.size() >= o.maxQuestions) stop = "budget";
            else {
                Question q = l[0].nextQuestion();
                if (q == null) stop = "no-disagreement";
                else apply.accept(q);
            }
        }
        int auditQuestions = 0;
        if (o.audit) {
            for (;;) {
                List<IntentLearner.Unconfirmed> pending = l[0].unconfirmedGrantCells();
                double mass = 0;
                for (IntentLearner.Unconfirmed x : pending) mass += x.weight;
                if (pending.isEmpty() || mass <= o.epsRisk) break;
                if (asked.size() >= o.maxQuestions) { stop = "budget"; break; }
                IntentLearner.Unconfirmed top = pending.get(0);
                VerbSpace vs = verbOf(l[0].omega, top.verb);
                Outcome outcome = IntentOmega.cellRep(vs, top.cell);
                apply.accept(new Question(top.verb, top.cell, outcome, l[0].acceptance(outcome), top.weight));
                auditQuestions++;
            }
        }
        return new AdaptiveElicitResult(stop, asked.size(), auditQuestions, seedQuestions, asked, l[0], refinements[0]);
    }
}
