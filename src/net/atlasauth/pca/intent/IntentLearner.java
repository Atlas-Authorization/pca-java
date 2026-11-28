package net.atlasauth.pca.intent;

import net.atlasauth.pca.DetMath;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.IntPredicate;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.CatValue;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.HarmModel;
import net.atlasauth.pca.intent.IntentOmega.NumCell;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;
import net.atlasauth.pca.intent.IntentPolicy.Admitter;
import net.atlasauth.pca.intent.IntentRegion.Region;

/**
 * Elicitation as learning: the exact Bayesian posterior over a per-verb hypothesis class (boxes, unions of boxes,
 * decision lists), the conservative grant G_tau, the residual-risk / burden / uncertainty metrics, the next-question
 * rule and the synthesis of the grant as predicates. Floating-point evaluation order follows the reference exactly.
 */
public final class IntentLearner {
    // ---- options ----

    /** The hypothesis class. kind is box, union or decision-list; k / maxRules / decay / conditions apply to the richer classes. */
    public static final class HypothesisClassSpec {
        public final String kind;
        public final Double k;
        public final Double maxRules;
        public final Double decay;
        public final String conditions;

        public HypothesisClassSpec(String kind, Double k, Double maxRules, Double decay, String conditions) {
            this.kind = kind; this.k = k; this.maxRules = maxRules; this.decay = decay; this.conditions = conditions;
        }

        public static final HypothesisClassSpec BOX = new HypothesisClassSpec("box", null, null, null, null);

        public static HypothesisClassSpec fromJson(Object o) {
            Map<String, Object> m = IntentOmega.obj(o);
            return new HypothesisClassSpec((String) m.get("kind"), numOrNull(m.get("k")), numOrNull(m.get("maxRules")), numOrNull(m.get("decay")), (String) m.get("conditions"));
        }
    }

    /** The canonical name of a hypothesis class (stored in the Intent Map). */
    public static String hypothesisClassName(HypothesisClassSpec h) {
        if (h.kind.equals("box")) return "per-verb-box/v1";
        if (h.kind.equals("union")) return "per-verb-union/v1";
        return (h.conditions == null ? "box" : h.conditions).equals("atomic") ? "per-verb-decision-list/v1" : "per-verb-decision-list/v2";
    }

    public static final class AnchorSpec {
        public final Object policy;
        public final double lambda;
        public AnchorSpec(Object policy, double lambda) { this.policy = policy; this.lambda = lambda; }
    }

    /** weight(verbSpace, contains) of a hypothesis for the mixture prior; contains tests a flat cell. */
    public interface PriorWeight { double weight(VerbSpace vs, IntPredicate contains); }

    public static final class PriorMix {
        public final double beta;
        public final PriorWeight weight;
        public PriorMix(double beta, PriorWeight weight) { this.beta = beta; this.weight = weight; }
    }

    public static final class Monotone {
        public final List<String> paths;
        public final Double offMass;
        public Monotone(List<String> paths, Double offMass) { this.paths = paths; this.offMass = offMass; }
    }

    /** Learner options; every field is optional (null = the default). */
    public static final class LearnerOptions {
        public Double eta, etaPos, etaNeg, tau;
        public PriorMix priorMix;
        public Double nullMass;
        public Function<VerbSpace, Double> nullMassFn;
        public AnchorSpec anchor;
        public List<AnchorSpec> anchors;
        public HarmModel harm;
        public Integer maxHypotheses, maxEnumeration;
        public String strategy;
        public HypothesisClassSpec hypothesisClass;
        public Integer agnosticSlack;
        public Monotone monotone;

        /** Reads the plain-data options (functions, the harm model and the prior-mixture weight are set by the caller). */
        public static LearnerOptions fromJson(Object o) {
            LearnerOptions p = new LearnerOptions();
            if (o == null) return p;
            Map<String, Object> m = IntentOmega.obj(o);
            p.eta = numOrNull(m.get("eta")); p.etaPos = numOrNull(m.get("etaPos")); p.etaNeg = numOrNull(m.get("etaNeg")); p.tau = numOrNull(m.get("tau"));
            p.nullMass = numOrNull(m.get("nullMass"));
            if (m.get("anchor") != null) p.anchor = anchorOf(m.get("anchor"));
            if (m.get("anchors") != null) {
                p.anchors = new ArrayList<>();
                for (Object a : IntentOmega.arr(m.get("anchors"))) p.anchors.add(anchorOf(a));
            }
            Double mh = numOrNull(m.get("maxHypotheses")), me = numOrNull(m.get("maxEnumeration")), sl = numOrNull(m.get("agnosticSlack"));
            if (mh != null) p.maxHypotheses = (int) Math.min(Integer.MAX_VALUE, mh);
            if (me != null) p.maxEnumeration = (int) Math.min(Integer.MAX_VALUE, me);
            if (sl != null) {
                if (sl != Math.floor(sl) || sl < 0 || sl > Integer.MAX_VALUE) throw new IllegalArgumentException("pca-intent: agnosticSlack must be a non-negative integer");
                p.agnosticSlack = (int) (double) sl;
            }
            p.strategy = (String) m.get("strategy");
            if (m.get("hypothesisClass") != null) p.hypothesisClass = HypothesisClassSpec.fromJson(m.get("hypothesisClass"));
            if (m.get("monotone") != null) {
                Map<String, Object> mo = IntentOmega.obj(m.get("monotone"));
                List<String> paths = new ArrayList<>();
                for (Object x : IntentOmega.arr(mo.get("paths"))) paths.add((String) x);
                p.monotone = new Monotone(paths, numOrNull(mo.get("offMass")));
            }
            return p;
        }

        private static AnchorSpec anchorOf(Object o) {
            Map<String, Object> m = IntentOmega.obj(o);
            return new AnchorSpec(m.get("policy"), IntentOmega.dbl(m.get("lambda")));
        }
    }

    static Double numOrNull(Object o) { return o == null ? null : IntentOmega.dbl(o); }

    /** One recorded answer. */
    public static final class Observation {
        public final String verb;
        public final Map<String, Object> values;
        public final int[] cell;
        public final int y;
        public final String source;
        public final Region region;
        public boolean conflict;

        public Observation(String verb, Map<String, Object> values, int[] cell, int y, String source, Region region) {
            this.verb = verb; this.values = values; this.cell = cell; this.y = y; this.source = source; this.region = region;
        }

        public Map<String, Object> toJson() {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("verb", verb);
            o.put("values", values);
            List<Object> c = new ArrayList<>();
            for (int x : cell) c.add((double) x);
            o.put("cell", c);
            o.put("y", (double) y);
            o.put("source", source);
            if (region != null) o.put("region", region.toJson());
            if (conflict) o.put("conflict", true);
            return o;
        }
    }

    public static final class Question {
        public final String verb;
        public final int[] cell;
        public final Outcome outcome;
        public final double p;
        public final double score;

        public Question(String verb, int[] cell, Outcome outcome, double p, double score) {
            this.verb = verb; this.cell = cell; this.outcome = outcome; this.p = p; this.score = score;
        }
    }

    public static final class LearnerMetrics {
        public double residualRisk, burden, uncertainty, entropyBits, disagreementMass, meanHarm;
        public Double log2VersionSpace;
        public int questions, conflicts;
    }

    public static final class CellView {
        public final String verb;
        public final int[] cell;
        public final double p, mass, harm;
        public final boolean inGrant, vetoed;

        CellView(String verb, int[] cell, double p, double mass, double harm, boolean inGrant, boolean vetoed) {
            this.verb = verb; this.cell = cell; this.p = p; this.mass = mass; this.harm = harm; this.inGrant = inGrant; this.vetoed = vetoed;
        }
    }

    public static final class Unconfirmed {
        public final String verb;
        public final int[] cell;
        public final double weight;
        Unconfirmed(String verb, int[] cell, double weight) { this.verb = verb; this.cell = cell; this.weight = weight; }
    }

    public static final class Synthesis {
        public final List<Map<String, Object>> predicates;
        public final List<Map<String, Object>> caveats;
        Synthesis(List<Map<String, Object>> p, List<Map<String, Object>> c) { predicates = p; caveats = c; }
    }

    // ---- verb model ----

    private static final class VerbModel {
        VerbSpace vs;
        int[] nChoice;
        byte[][] contains;
        int[] nCellsD;
        int nh;
        int[] choice;
        byte[] member;
        int[] complexity;
        double[] prior, w;
        int[] err;
        int nCells;
        int[] cellIdx;
        double[] mass, harm, p;
        byte[] veto, seen;
        boolean dirty;
    }

    // the binary entropy feeds the next-question argmax and recurs for every cell of a model: memoized (bounded, cleared when it passes 4096 entries)
    private static final java.util.Map<Double, Double> BIN_ENT_MEMO = new java.util.HashMap<>();

    static synchronized double binEnt(double p) {
        if (p <= 0 || p >= 1) return 0;
        Double hit = BIN_ENT_MEMO.get(p);
        if (hit != null) return hit;
        double v = -(p * DetMath.detLog2(p) + (1 - p) * DetMath.detLog2(1 - p));
        if (BIN_ENT_MEMO.size() >= 4096) BIN_ENT_MEMO.clear();
        BIN_ENT_MEMO.put(p, v);
        return v;
    }

    private static List<int[]> rangeChoices(int n) {
        List<int[]> out = new ArrayList<>();
        for (int i = 0; i < n; i++) for (int j = i; j < n; j++) out.add(new int[] {i, j});
        return out;
    }

    private static final class FullOpts {
        final int maxHypotheses, maxEnumeration;
        final HypothesisClassSpec hypothesisClass;
        FullOpts(LearnerOptions o) {
            maxHypotheses = o.maxHypotheses != null ? o.maxHypotheses : 400_000;
            maxEnumeration = o.maxEnumeration != null ? o.maxEnumeration : 4_000_000;
            hypothesisClass = o.hypothesisClass != null ? o.hypothesisClass : HypothesisClassSpec.BOX;
        }
    }

    private static void buildBoxTables(VerbSpace vs, int[] nCellsD, List<byte[]> contains, int[] nChoice) {
        for (int k = 0; k < vs.dims.size(); k++) {
            Dim d = vs.dims.get(k);
            int n = nCellsD[k];
            if (d.kind.equals("num")) {
                List<int[]> ch = rangeChoices(n);
                byte[] t = new byte[ch.size() * n];
                for (int c = 0; c < ch.size(); c++) for (int x = ch.get(c)[0]; x <= ch.get(c)[1]; x++) t[c * n + x] = 1;
                contains.add(t);
                nChoice[k] = ch.size();
            } else {
                if (n > 20) throw new IllegalStateException("pca-intent: categorical dimension " + d.path + " has " + n + " values (max 20 for exact enumeration)");
                int m = (1 << n) - 1;
                byte[] t = new byte[m * n];
                for (int mask = 1; mask <= m; mask++) for (int x = 0; x < n; x++) if ((mask & (1 << x)) != 0) t[(mask - 1) * n + x] = 1;
                contains.add(t);
                nChoice[k] = m;
            }
        }
    }

    private static String keyOf(byte[] m) {
        char[] c = new char[m.length];
        for (int i = 0; i < m.length; i++) c[i] = (char) (48 + m[i]);
        return new String(c);
    }

    private static List<byte[]> boxMasks(VerbSpace vs, int nCells, int[] cellIdx, int[] nCellsD, byte[][] contains, int[] nChoice, int cap) {
        int D = vs.dims.size();
        double boxes = 1;
        for (int c : nChoice) boxes *= c;
        if (boxes > cap) throw new IllegalStateException("pca-intent: " + jsNum(boxes) + " boxes for " + vs.verb + " exceed the enumeration cap; coarsen the cuts");
        List<byte[]> out = new ArrayList<>();
        int[] cur = new int[D];
        for (long b = 0; b < (long) boxes; b++) {
            byte[] mask = new byte[nCells];
            for (int c = 0; c < nCells; c++) {
                boolean inside = true;
                for (int d = 0; d < D && inside; d++) if (contains[d][cur[d] * nCellsD[d] + cellIdx[c * D + d]] == 0) inside = false;
                if (inside) mask[c] = 1;
            }
            out.add(mask);
            for (int d = D - 1; d >= 0; d--) {
                cur[d]++;
                if (cur[d] < nChoice[d]) break;
                cur[d] = 0;
            }
        }
        return out;
    }

    private static String jsNum(double x) { return x == Math.rint(x) && Math.abs(x) < 1e21 ? Long.toString((long) x) : Double.toString(x); }

    private static final class SetsOut {
        final List<byte[]> sets = new ArrayList<>();
        final List<Integer> complexity = new ArrayList<>();
    }

    private static SetsOut enumerateUnions(List<byte[]> boxes, int k, int cap, String verb) {
        Map<String, Integer> seen = new LinkedHashMap<>();
        SetsOut out = new SetsOut();
        List<byte[]> frontier = new ArrayList<>();
        for (byte[] b : boxes) {
            String key = keyOf(b);
            if (seen.containsKey(key)) continue;
            seen.put(key, out.sets.size());
            out.sets.add(b);
            out.complexity.add(1);
            frontier.add(b);
        }
        long work = 0;
        for (int level = 2; level <= k; level++) {
            List<byte[]> next = new ArrayList<>();
            for (byte[] s : frontier) {
                for (byte[] b : boxes) {
                    work += 1;
                    if (work > cap) throw new IllegalStateException("pca-intent: the union-of-" + k + "-boxes class for " + verb + " exceeds the enumeration cap; coarsen the cuts or lower k");
                    byte[] u = new byte[s.length];
                    for (int i = 0; i < s.length; i++) u[i] = (byte) (s[i] | b[i]);
                    String key = keyOf(u);
                    if (seen.containsKey(key)) continue;
                    seen.put(key, out.sets.size());
                    out.sets.add(u);
                    out.complexity.add(level);
                    next.add(u);
                }
            }
            frontier = next;
        }
        return out;
    }

    private static List<byte[]> atomicTests(VerbSpace vs, int nCells, int[] cellIdx, int[] nCellsD) {
        int D = vs.dims.size();
        List<byte[]> tests = new ArrayList<>();
        for (int k = 0; k < D; k++) {
            Dim d = vs.dims.get(k);
            int n = nCellsD[k];
            if (d.kind.equals("num")) {
                for (int i = 0; i < n - 1; i++) { final int ii = i; addAtomic(tests, nCells, cellIdx, D, k, x -> x <= ii); }
                for (int i = 1; i < n; i++) { final int ii = i; addAtomic(tests, nCells, cellIdx, D, k, x -> x >= ii); }
                if (n > 2) for (int i = 1; i < n - 1; i++) { final int ii = i; addAtomic(tests, nCells, cellIdx, D, k, x -> x == ii); }
            } else for (int i = 0; i < n; i++) { final int ii = i; addAtomic(tests, nCells, cellIdx, D, k, x -> x == ii); }
        }
        return dedupMasks(tests);
    }

    private static void addAtomic(List<byte[]> tests, int nCells, int[] cellIdx, int D, int k, IntPredicate pred) {
        byte[] m = new byte[nCells];
        boolean any = false, all = true;
        for (int c = 0; c < nCells; c++) {
            if (pred.test(cellIdx[c * D + k])) { m[c] = 1; any = true; } else all = false;
        }
        if (any && !all) tests.add(m);
    }

    private static List<byte[]> dedupMasks(List<byte[]> masks) {
        Set<String> seen = new LinkedHashSet<>();
        List<byte[]> out = new ArrayList<>();
        for (byte[] t : masks) if (seen.add(keyOf(t))) out.add(t);
        return out;
    }

    private static void emitList(SetsOut out, Map<String, Integer> seen, byte[] acc, byte[] decided, int rules, int nCells) {
        for (int def = 0; def <= 1; def++) {
            byte[] s = new byte[nCells];
            boolean any = false;
            for (int c = 0; c < nCells; c++) {
                s[c] = decided[c] != 0 ? acc[c] : (byte) def;
                if (s[c] != 0) any = true;
            }
            if (!any) continue;
            String key = keyOf(s);
            if (seen.containsKey(key)) continue;
            seen.put(key, out.sets.size());
            out.sets.add(s);
            out.complexity.add(Math.max(1, rules));
        }
    }

    private static SetsOut enumerateDecisionLists(List<byte[]> tests, int nCells, int L, int cap, String verb) {
        Map<String, Integer> seen = new LinkedHashMap<>();
        SetsOut out = new SetsOut();
        List<byte[][]> frontier = new ArrayList<>();
        frontier.add(new byte[][] {new byte[nCells], new byte[nCells]}); // {decided, acc}
        emitList(out, seen, frontier.get(0)[1], frontier.get(0)[0], 0, nCells);
        long work = 0;
        for (int depth = 1; depth <= L; depth++) {
            Map<String, byte[][]> states = new LinkedHashMap<>();
            for (byte[][] st : frontier) {
                for (byte[] t : tests) {
                    for (int label = 0; label <= 1; label++) {
                        work += 1;
                        if (work > cap) throw new IllegalStateException("pca-intent: the decision-list class (≤ " + L + " rules) for " + verb + " exceeds the enumeration cap");
                        byte[] decided = new byte[nCells];
                        byte[] acc = new byte[nCells];
                        boolean fresh = false;
                        for (int c = 0; c < nCells; c++) {
                            if (st[0][c] != 0) { decided[c] = 1; acc[c] = st[1][c]; }
                            else if (t[c] != 0) { decided[c] = 1; acc[c] = (byte) label; fresh = true; }
                        }
                        if (!fresh) continue;
                        String key = keyOf(decided) + "|" + keyOf(acc);
                        if (states.containsKey(key)) continue;
                        states.put(key, new byte[][] {decided, acc});
                    }
                }
            }
            frontier = new ArrayList<>(states.values());
            for (byte[][] st : frontier) emitList(out, seen, st[1], st[0], depth, nCells);
        }
        return out;
    }

    private static boolean isInt(Double x) { return x != null && !x.isNaN() && !x.isInfinite() && x == Math.floor(x); }

    private static VerbModel buildVerbModel(VerbSpace vs, FullOpts opts, HarmModel harm) {
        int D = vs.dims.size();
        int[] nCellsD = new int[D];
        for (int k = 0; k < D; k++) nCellsD[k] = IntentOmega.cellCount(vs.dims.get(k));
        int[] nChoice = new int[D];
        List<byte[]> containsL = new ArrayList<>();
        buildBoxTables(vs, nCellsD, containsL, nChoice);
        byte[][] contains = containsL.toArray(new byte[0][]);
        double ncd = IntentOmega.verbCellCount(vs);
        if (ncd > Integer.MAX_VALUE) throw new IllegalStateException("pca-intent: too many cells for " + vs.verb);
        int nCells = (int) ncd;
        int[] cellIdx = new int[nCells * D];
        double[] mass = new double[nCells];
        double[] hm = new double[nCells];
        for (int c = 0; c < nCells; c++) {
            int[] idx = IntentOmega.decodeCell(vs, c);
            for (int d = 0; d < D; d++) cellIdx[c * D + d] = idx[d];
            IntentOmega.Stats s = IntentOmega.cellStats(vs, idx, harm);
            mass[c] = s.mass();
            hm[c] = s.harm();
        }
        HypothesisClassSpec hc = opts.hypothesisClass;
        int nh;
        int[] choice = new int[1];
        byte[] member = null;
        int[] complexity = null;
        if (hc.kind.equals("box")) {
            double boxes = 1;
            for (int c : nChoice) boxes *= c;
            if (boxes + 1 > opts.maxHypotheses) {
                throw new IllegalStateException("pca-intent: |Θ_" + vs.verb + "| = " + jsNum(boxes + 1) + " exceeds maxHypotheses " + opts.maxHypotheses + "; coarsen the cuts");
            }
            nh = (int) boxes + 1;
            choice = new int[Math.max(1, (int) boxes * D)];
            int[] cur = new int[D];
            for (int h = 0; h < (int) boxes; h++) {
                for (int d = 0; d < D; d++) choice[h * D + d] = cur[d];
                for (int d = D - 1; d >= 0; d--) {
                    cur[d]++;
                    if (cur[d] < nChoice[d]) break;
                    cur[d] = 0;
                }
            }
        } else {
            SetsOut so;
            if (hc.kind.equals("union")) {
                if (!(isInt(hc.k) && hc.k >= 1)) throw new IllegalArgumentException("pca-intent: union class needs an integer k ≥ 1");
                List<byte[]> boxes = boxMasks(vs, nCells, cellIdx, nCellsD, contains, nChoice, opts.maxEnumeration);
                so = enumerateUnions(boxes, (int) (double) hc.k, opts.maxEnumeration, vs.verb);
            } else {
                if (!(isInt(hc.maxRules) && hc.maxRules >= 1)) throw new IllegalArgumentException("pca-intent: decision-list class needs an integer maxRules ≥ 1");
                String cond = hc.conditions == null ? "box" : hc.conditions;
                if (!cond.equals("box") && !cond.equals("atomic")) throw new IllegalArgumentException("pca-intent: decision-list conditions must be 'box' or 'atomic'");
                List<byte[]> tests = cond.equals("atomic") ? atomicTests(vs, nCells, cellIdx, nCellsD) : dedupMasks(boxMasks(vs, nCells, cellIdx, nCellsD, contains, nChoice, opts.maxEnumeration));
                so = enumerateDecisionLists(tests, nCells, (int) (double) hc.maxRules, opts.maxEnumeration, vs.verb);
            }
            if (so.sets.size() + 1 > opts.maxHypotheses) {
                throw new IllegalStateException("pca-intent: |Θ_" + vs.verb + "| = " + (so.sets.size() + 1) + " exceeds maxHypotheses " + opts.maxHypotheses + "; coarsen the cuts");
            }
            nh = so.sets.size() + 1;
            if ((long) nh * nCells > Integer.MAX_VALUE) throw new IllegalStateException("pca-intent: hypothesis table too large for " + vs.verb);
            member = new byte[nh * nCells];
            complexity = new int[nh];
            for (int i = 0; i < so.sets.size(); i++) {
                System.arraycopy(so.sets.get(i), 0, member, (i + 1) * nCells, nCells);
                complexity[i + 1] = so.complexity.get(i);
            }
        }
        VerbModel m = new VerbModel();
        m.vs = vs; m.nChoice = nChoice; m.contains = contains; m.nCellsD = nCellsD; m.nh = nh; m.choice = choice; m.member = member;
        m.complexity = complexity; m.prior = new double[nh]; m.w = new double[nh]; m.err = new int[nh]; m.nCells = nCells; m.cellIdx = cellIdx;
        m.mass = mass; m.harm = hm; m.p = new double[nCells]; m.veto = new byte[nCells]; m.seen = new byte[nCells]; m.dirty = true;
        return m;
    }

    private static boolean holds(VerbModel m, int h, int c) {
        if (m.member != null) return m.member[h * m.nCells + c] == 1;
        int D = m.vs.dims.size();
        int base = (h - 1) * D;
        for (int d = 0; d < D; d++) {
            int n = m.nCellsD[d];
            if (m.contains[d][m.choice[base + d] * n + m.cellIdx[c * D + d]] == 0) return false;
        }
        return true;
    }

    /** The non-empty hypotheses of a verb's class as cell masks (index 0 = the empty hypothesis omitted), with their Occam complexity. */
    public static SetsResult hypothesisCellSets(VerbSpace vs, HypothesisClassSpec hc, Integer maxHypotheses, Integer maxEnumeration) {
        LearnerOptions o = new LearnerOptions();
        o.maxHypotheses = maxHypotheses; o.maxEnumeration = maxEnumeration; o.hypothesisClass = hc == null ? HypothesisClassSpec.BOX : hc;
        VerbModel m = buildVerbModel(vs, new FullOpts(o), IntentOmega.DEFAULT_HARM);
        SetsResult r = new SetsResult();
        for (int h = 1; h < m.nh; h++) {
            byte[] s = new byte[m.nCells];
            for (int c = 0; c < m.nCells; c++) if (holds(m, h, c)) s[c] = 1;
            r.sets.add(s);
            r.complexity.add(m.complexity != null ? m.complexity[h] : 1);
        }
        return r;
    }

    public static final class SetsResult {
        public final List<byte[]> sets = new ArrayList<>();
        public final List<Integer> complexity = new ArrayList<>();
    }

    private static void applyMonotonePrior(VerbModel m, Monotone mono) {
        double off = mono.offMass == null ? 0 : mono.offMass;
        if (!(off >= 0 && off <= 1)) throw new IllegalArgumentException("pca-intent: monotone.offMass must be in [0, 1]");
        int D = m.vs.dims.size();
        List<Integer> ks = new ArrayList<>();
        for (int k = 0; k < D; k++) if (m.vs.dims.get(k).kind.equals("num") && mono.paths.contains(m.vs.dims.get(k).path)) ks.add(k);
        if (ks.isEmpty()) return;
        int[] stride = new int[ks.size()];
        for (int i = 0; i < ks.size(); i++) {
            int s = 1;
            for (int j = ks.get(i) + 1; j < D; j++) s *= m.nCellsD[j];
            stride[i] = s;
        }
        for (int h = 1; h < m.nh; h++) {
            boolean isMono = true;
            for (int c = 0; c < m.nCells && isMono; c++) {
                if (!holds(m, h, c)) continue;
                for (int i = 0; i < ks.size(); i++) {
                    if (m.cellIdx[c * D + ks.get(i)] > 0 && !holds(m, h, c - stride[i])) { isMono = false; break; }
                }
            }
            if (!isMono) m.w[h] = m.w[h] * off;
        }
    }

    private static boolean holdsAll(VerbModel m, int h, int[] cells) {
        if (h == 0) return false;
        for (int c : cells) if (!holds(m, h, c)) return false;
        return true;
    }

    // ---- learner ----

    public final Omega omega;
    public final double eta, etaPos, etaNeg;
    private final boolean noisy;
    public final double tau;
    public final String strategy;
    public final HarmModel harm;
    public final HypothesisClassSpec hypothesisClass;
    public final Integer agnosticSlack;
    public final List<Observation> observations = new ArrayList<>();
    private final List<VerbModel> models = new ArrayList<>();
    private final LearnerOptions opts;

    public IntentLearner(Omega omega) { this(omega, new LearnerOptions()); }

    public IntentLearner(Omega omega, LearnerOptions opts) {
        this.omega = omega;
        this.opts = opts;
        this.eta = opts.eta != null ? opts.eta : 0;
        if (!(eta >= 0 && eta < 0.5)) throw new IllegalArgumentException("pca-intent: eta must be in [0, 0.5)");
        this.etaPos = opts.etaPos != null ? opts.etaPos : eta;
        this.etaNeg = opts.etaNeg != null ? opts.etaNeg : eta;
        if (!(etaPos >= 0 && etaPos < 0.5 && etaNeg >= 0 && etaNeg < 0.5)) throw new IllegalArgumentException("pca-intent: etaPos and etaNeg must be in [0, 0.5)");
        this.noisy = etaPos != 0 || etaNeg != 0;
        this.tau = opts.tau != null ? opts.tau : (noisy ? 0.95 : 1);
        this.strategy = opts.strategy != null ? opts.strategy : "disagreement";
        this.harm = opts.harm != null ? opts.harm : IntentOmega.DEFAULT_HARM;
        this.hypothesisClass = opts.hypothesisClass != null ? opts.hypothesisClass : HypothesisClassSpec.BOX;
        this.agnosticSlack = opts.agnosticSlack;
        if (agnosticSlack != null) {
            if (agnosticSlack < 0) throw new IllegalArgumentException("pca-intent: agnosticSlack must be a non-negative integer");
            if (noisy) throw new IllegalArgumentException("pca-intent: agnostic selection replaces the noise model; use eta = 0");
        }
        FullOpts full = new FullOpts(opts);
        for (VerbSpace vs : omega.verbs) models.add(buildVerbModel(vs, full, harm));
        initPrior();
    }

    private void initPrior() {
        List<AnchorSpec> anchors = new ArrayList<>();
        if (opts.anchor != null) anchors.add(opts.anchor);
        if (opts.anchors != null) anchors.addAll(opts.anchors);
        anchors.removeIf(a -> !(a.lambda > 0));
        List<Admitter> admitters = new ArrayList<>();
        List<Double> lambdas = new ArrayList<>();
        for (AnchorSpec a : anchors) { admitters.add(IntentPolicy.admitter(a.policy)); lambdas.add(a.lambda); }
        double decay = hypothesisClass.kind.equals("box") ? 1 : (hypothesisClass.decay != null ? hypothesisClass.decay : 0.25);
        if (!(decay > 0 && decay <= 1)) throw new IllegalArgumentException("pca-intent: decay must be in (0, 1]");
        for (VerbModel m : models) {
            double nm = opts.nullMassFn != null ? opts.nullMassFn.apply(m.vs) : (opts.nullMass != null ? opts.nullMass : 0.2);
            if (!(nm >= 0 && nm <= 1)) throw new IllegalArgumentException("pca-intent: nullMass must be in [0, 1]");
            m.w[0] = nm;
            double z = 0;
            for (int h = 1; h < m.nh; h++) {
                double raw = m.complexity != null ? DetMath.detPowInt(decay, m.complexity[h] - 1) : 1;
                m.w[h] = raw;
                z += raw;
            }
            for (int h = 1; h < m.nh; h++) m.w[h] = ((1 - nm) * m.w[h]) / (z == 0 ? 1 : z);
            if (opts.monotone != null) applyMonotonePrior(m, opts.monotone);
            if (!admitters.isEmpty()) {
                double tot = 0;
                for (int c = 0; c < m.nCells; c++) tot += m.mass[c];
                List<byte[]> accs = new ArrayList<>();
                for (Admitter adm : admitters) {
                    byte[] acc = new byte[m.nCells];
                    for (int c = 0; c < m.nCells; c++) acc[c] = (byte) (adm.admits(m.vs, IntentOmega.cellRep(m.vs, IntentOmega.decodeCell(m.vs, c))) ? 1 : 0);
                    accs.add(acc);
                }
                for (int h = 0; h < m.nh; h++) {
                    double mix = 0;
                    for (int i = 0; i < accs.size(); i++) {
                        byte[] acc = accs.get(i);
                        double dist = 0;
                        for (int c = 0; c < m.nCells; c++) {
                            int inH = h == 0 ? 0 : holds(m, h, c) ? 1 : 0;
                            if (inH != acc[c]) dist += m.mass[c];
                        }
                        mix += DetMath.detExp((-lambdas.get(i) * dist) / (tot == 0 ? 1 : tot));
                    }
                    m.w[h] = m.w[h] * (mix / accs.size());
                }
            }
            normalize(m.w);
            if (opts.priorMix != null) mixPrior(m, opts.priorMix);
            System.arraycopy(m.w, 0, m.prior, 0, m.nh);
            m.dirty = true;
        }
    }

    private boolean inGrant(VerbModel m, int c) { return m.veto[c] == 0 && m.p[c] >= tau - 1e-12; }

    private VerbModel model(String verb) {
        for (VerbModel m : models) if (m.vs.verb.equals(verb)) return m;
        return null;
    }

    private void refresh(VerbModel m) {
        if (!m.dirty) return;
        Arrays.fill(m.p, 0);
        byte[] anyIn = new byte[m.nCells];
        byte[] anyOut = new byte[m.nCells];
        boolean live = false;
        for (int h = 0; h < m.nh; h++) {
            double w = m.w[h];
            if (w == 0) continue;
            live = true;
            for (int c = 0; c < m.nCells; c++) {
                if (h > 0 && holds(m, h, c)) { m.p[c] = m.p[c] + w; anyIn[c] = 1; } else anyOut[c] = 1;
            }
        }
        for (int c = 0; c < m.nCells; c++) m.p[c] = !live || anyIn[c] == 0 ? 0 : anyOut[c] == 0 ? 1 : Math.min(1, Math.max(0, m.p[c]));
        m.dirty = false;
    }

    private static int flat(VerbModel m, int[] idx) {
        int f = 0;
        for (int d = 0; d < idx.length; d++) f = f * m.nCellsD[d] + idx[d];
        return f;
    }

    /** p_n(outcome); 0 outside the space (the conservative reading). */
    public double acceptance(Outcome o) {
        VerbModel m = model(o.verb());
        if (m == null) return 0;
        int[] idx = IntentOmega.cellOf(m.vs, o);
        if (idx == null) return 0;
        refresh(m);
        return m.p[flat(m, idx)];
    }

    /** Is the outcome inside the current conservative grant (p_n &ge; tau and not vetoed)? */
    public boolean admitsOutcome(Outcome o) {
        VerbModel m = model(o.verb());
        if (m == null) return false;
        int[] idx = IntentOmega.cellOf(m.vs, o);
        if (idx == null) return false;
        refresh(m);
        return inGrant(m, flat(m, idx));
    }

    public boolean isVetoed(Outcome o) {
        VerbModel m = model(o.verb());
        int[] idx = m != null ? IntentOmega.cellOf(m.vs, o) : null;
        return m != null && idx != null && m.veto[flat(m, idx)] == 1;
    }

    /** Every vetoed cell as "verb|flat" keys. */
    public List<String> vetoedCells() {
        List<String> out = new ArrayList<>();
        for (VerbModel m : models) for (int c = 0; c < m.nCells; c++) if (m.veto[c] != 0) out.add(m.vs.verb + "|" + c);
        return out;
    }

    public Observation observe(Outcome o, int y) { return observe(o, y, "elicitation", null); }

    /** Record the answer y to "should the outcome (or every outcome of the region) be allowed?"; null outside the space or on an empty region. */
    public Observation observe(Outcome o, int y, String source, Region region) {
        VerbModel m = model(o.verb());
        if (m == null) return null;
        int[] idx = IntentOmega.cellOf(m.vs, o);
        if (idx == null) return null;
        int[] cells;
        if (region != null) {
            List<Long> rc = IntentRegion.regionCells(m.vs, region, y == 1);
            cells = new int[rc.size()];
            for (int i = 0; i < cells.length; i++) cells[i] = (int) (long) rc.get(i);
        } else cells = new int[] {flat(m, idx)};
        if (cells.length == 0) return null;
        refresh(m);
        Observation obs = new Observation(o.verb(), new LinkedHashMap<>(o.values()), idx, y, source, region);
        double regionP = 0;
        for (int h = 1; h < m.nh; h++) if (m.w[h] > 0 && holdsAll(m, h, cells)) regionP += m.w[h];
        boolean contradictsAll = y == 0 ? regionP >= 1 - 1e-12 : regionP <= 1e-12;
        if (source.equals("runtime") && y == 0) for (int c : cells) m.veto[c] = 1;
        for (int c : cells) m.seen[c] = 1;
        if (agnosticSlack != null) {
            for (int h = 0; h < m.nh; h++) if ((holdsAll(m, h, cells) ? 1 : 0) != y) m.err[h] = m.err[h] + 1;
            double minErr = Double.POSITIVE_INFINITY;
            for (int h = 0; h < m.nh; h++) if (m.prior[h] > 0) minErr = Math.min(minErr, m.err[h]);
            for (int h = 0; h < m.nh; h++) m.w[h] = m.err[h] <= minErr + agnosticSlack ? m.prior[h] : 0;
            normalize(m.w);
            if (contradictsAll) {
                obs.conflict = true;
                if (y == 0) for (int c : cells) m.veto[c] = 1;
            }
        } else {
            double[] prev = etaPos == 0 || etaNeg == 0 ? m.w.clone() : null;
            double sum = 0;
            for (int h = 0; h < m.nh; h++) {
                int inH = holdsAll(m, h, cells) ? 1 : 0;
                double lik = inH == 1 ? (y == 1 ? 1 - etaNeg : etaNeg) : y == 1 ? etaPos : 1 - etaPos;
                m.w[h] = m.w[h] * lik;
                sum += m.w[h];
            }
            if (sum == 0 && prev != null) {
                System.arraycopy(prev, 0, m.w, 0, m.nh);
                obs.conflict = true;
                if (y == 0) for (int c : cells) m.veto[c] = 1;
            } else normalize(m.w);
        }
        m.dirty = true;
        observations.add(obs);
        return obs;
    }

    public List<CellView> cells() {
        List<CellView> out = new ArrayList<>();
        for (VerbModel m : models) {
            refresh(m);
            for (int c = 0; c < m.nCells; c++) out.add(new CellView(m.vs.verb, IntentOmega.decodeCell(m.vs, c), m.p[c], m.mass[c], m.harm[c], inGrant(m, c), m.veto[c] == 1));
        }
        return out;
    }

    public LearnerMetrics metrics() {
        double R = 0, B = 0, U = 0, H = 0, vs = 0, dis = 0, meanHarm = 0;
        for (VerbModel m : models) {
            refresh(m);
            for (int c = 0; c < m.nCells; c++) {
                double p = m.p[c];
                double mu = m.mass[c];
                meanHarm += mu * m.harm[c];
                if (inGrant(m, c)) R += mu * (1 - p) * m.harm[c];
                else B += mu * p;
                U += mu * Math.min(p, 1 - p);
                if (p > 1e-12 && p < 1 - 1e-12) dis += mu;
            }
            int alive = 0;
            for (int h = 0; h < m.nh; h++) {
                double w = m.w[h];
                if (w > 0) { alive++; H -= w * DetMath.detLog2(w); }
            }
            vs += DetMath.detLog2(Math.max(1, alive));
        }
        LearnerMetrics r = new LearnerMetrics();
        r.residualRisk = R; r.burden = B; r.uncertainty = U; r.entropyBits = H;
        r.log2VersionSpace = noisy ? null : vs;
        r.disagreementMass = dis; r.meanHarm = meanHarm;
        for (Observation o : observations) {
            if (o.source.equals("elicitation")) r.questions++;
            if (o.conflict) r.conflicts++;
        }
        return r;
    }

    /** The next question: argmax expected information (times mass and harm for the risk strategy); null when nothing is uncertain. */
    public Question nextQuestion() {
        Question best = null;
        double hPos = binEnt(etaPos);
        double hNeg = binEnt(etaNeg);
        for (VerbModel m : models) {
            refresh(m);
            for (int c = 0; c < m.nCells; c++) {
                if (m.veto[c] != 0) continue;
                double p = m.p[c];
                if (p <= 1e-9 || p >= 1 - 1e-9) continue;
                double pe = p * (1 - etaNeg) + (1 - p) * etaPos;
                double score = binEnt(pe) - (etaPos == etaNeg ? hPos : p * hNeg + (1 - p) * hPos);
                if (strategy.equals("risk")) score *= m.mass[c] * m.harm[c];
                if (score <= 1e-15) continue;
                if (best == null || score > best.score + 1e-12) {
                    int[] cell = IntentOmega.decodeCell(m.vs, c);
                    best = new Question(m.vs.verb, cell, IntentOmega.cellRep(m.vs, cell), p, score);
                }
            }
        }
        return best;
    }

    /** Grant cells inferred but never directly observed, most consequential first. */
    public List<Unconfirmed> unconfirmedGrantCells() {
        List<Unconfirmed> out = new ArrayList<>();
        for (VerbModel m : models) {
            refresh(m);
            for (int c = 0; c < m.nCells; c++) {
                if (m.seen[c] != 0 || !inGrant(m, c)) continue;
                out.add(new Unconfirmed(m.vs.verb, IntentOmega.decodeCell(m.vs, c), m.mass[c] * m.harm[c]));
            }
        }
        out.sort((a, b) -> Double.compare(b.weight, a.weight));
        return out;
    }

    /** The conservative grant as predicates plus the reversibility caveat. */
    public Synthesis synthesize() {
        List<Map<String, Object>> predicates = new ArrayList<>();
        List<String> order = List.of("reversible", "rate_limited", "irreversible");
        int worst = -1;
        for (VerbModel m : models) {
            refresh(m);
            byte[] allowed = new byte[m.nCells];
            boolean any = false;
            for (int c = 0; c < m.nCells; c++) if (inGrant(m, c)) { allowed[c] = 1; any = true; }
            if (!any) continue;
            worst = Math.max(worst, order.indexOf(m.vs.reversibility));
            predicates.addAll(boxesToPredicates(m.vs, allowed));
        }
        List<Map<String, Object>> caveats = new ArrayList<>();
        if (worst >= 0) {
            Map<String, Object> cv = new LinkedHashMap<>();
            cv.put("type", "reversibility_max");
            cv.put("class", order.get(worst));
            caveats.add(cv);
        }
        return new Synthesis(predicates, caveats);
    }

    /** Replay observations onto a fresh learner. */
    public static IntentLearner replay(Omega omega, LearnerOptions opts, Collection<Observation> observations) {
        IntentLearner l = new IntentLearner(omega, opts);
        for (Observation o : observations) l.observe(new Outcome(o.verb, o.values), o.y, o.source, o.region);
        return l;
    }

    private static void normalize(double[] w) {
        double s = 0;
        for (double x : w) s += x;
        if (s > 0) for (int i = 0; i < w.length; i++) w[i] = w[i] / s;
    }

    private static void mixPrior(VerbModel m, PriorMix mix) {
        if (!(mix.beta >= 0 && mix.beta < 1)) throw new IllegalArgumentException("pca-intent: priorMix.beta must be in [0, 1)");
        double[] pop = new double[m.nh];
        double z = 0;
        for (int h = 0; h < m.nh; h++) {
            final int hh = h;
            double x = mix.weight.weight(m.vs, c -> hh != 0 && c >= 0 && c < m.nCells && holds(m, hh, c));
            if (!(Double.isFinite(x) && x >= 0)) throw new IllegalArgumentException("pca-intent: priorMix.weight must be finite and >= 0");
            pop[h] = x;
            z += x;
        }
        if (!(z > 0)) return;
        for (int h = 0; h < m.nh; h++) m.w[h] = (1 - mix.beta) * m.w[h] + (mix.beta * pop[h]) / z;
    }

    // ---- synthesis: allowed cells -> union of boxes -> predicates ----

    private static final class Box {
        /** numeric: {lo, hi}; categorical: null here and a value set at the same index in sets. */
        final int[][] ranges;
        final Set<Integer>[] sets;
        @SuppressWarnings("unchecked")
        Box(int n) { ranges = new int[n][]; sets = (Set<Integer>[]) new Set[n]; }
    }

    private static List<int[]> boxCells(Box box) {
        List<int[]> acc = new ArrayList<>();
        acc.add(new int[0]);
        for (int k = 0; k < box.ranges.length; k++) {
            List<Integer> vals = new ArrayList<>();
            if (box.ranges[k] != null) for (int i = box.ranges[k][0]; i <= box.ranges[k][1]; i++) vals.add(i);
            else { vals.addAll(box.sets[k]); java.util.Collections.sort(vals); }
            List<int[]> next = new ArrayList<>();
            for (int[] pre : acc) for (int v : vals) {
                int[] n = Arrays.copyOf(pre, pre.length + 1);
                n[pre.length] = v;
                next.add(n);
            }
            acc = next;
        }
        return acc;
    }

    private static int encode(int[] nCellsD, int[] idx) {
        int f = 0;
        for (int i = 0; i < nCellsD.length; i++) f = f * nCellsD[i] + idx[i];
        return f;
    }

    private static Map<String, Object> cond(String field, String op, Object value) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("field", field);
        c.put("op", op);
        c.put("value", value);
        return c;
    }

    private static Map<String, Object> single(String k, Object v) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put(k, v);
        return c;
    }

    private static Map<String, Object> catCondition(CatDim d, Set<Integer> S) {
        if (S.size() == d.values.size()) return null;
        List<String> exacts = new ArrayList<>();
        List<String> prefixes = new ArrayList<>();
        for (CatValue v : d.values) {
            if (v.kind().equals("exact")) exacts.add(v.value());
            if (v.kind().equals("prefix")) prefixes.add(v.value());
        }
        List<Map<String, Object>> alts = new ArrayList<>();
        List<Object> allowedExacts = new ArrayList<>();
        for (int i : S) if (d.values.get(i).kind().equals("exact")) allowedExacts.add(d.values.get(i).value());
        if (allowedExacts.size() == 1) alts.add(cond(d.path, "eq", allowedExacts.get(0)));
        else if (allowedExacts.size() > 1) alts.add(cond(d.path, "in", allowedExacts));
        List<Integer> sorted = new ArrayList<>(S);
        java.util.Collections.sort(sorted);
        for (int i : sorted) {
            CatValue v = d.values.get(i);
            if (v.kind().equals("exact")) continue;
            List<Map<String, Object>> parts = new ArrayList<>();
            if (v.kind().equals("prefix")) {
                parts.add(cond(d.path, "prefix", v.value()));
                List<Object> under = new ArrayList<>();
                for (String e : exacts) if (e.startsWith(v.value())) under.add(e);
                if (!under.isEmpty()) parts.add(cond(d.path, "nin", under));
                for (String q : prefixes) if (!q.equals(v.value()) && q.startsWith(v.value())) parts.add(single("not", cond(d.path, "prefix", q)));
            } else {
                if (!exacts.isEmpty()) parts.add(cond(d.path, "nin", new ArrayList<Object>(exacts)));
                for (String q : prefixes) parts.add(single("not", cond(d.path, "prefix", q)));
            }
            if (parts.size() == 1) alts.add(parts.get(0));
            else if (parts.size() > 1) alts.add(single("all_of", new ArrayList<Object>(parts)));
        }
        if (alts.isEmpty()) return null;
        return alts.size() == 1 ? alts.get(0) : single("any_of", new ArrayList<Object>(alts));
    }

    private static Map<String, Object> boxToPredicate(VerbSpace vs, Box box) {
        List<Object> where = new ArrayList<>();
        for (int k = 0; k < vs.dims.size(); k++) {
            Dim d = vs.dims.get(k);
            if (d instanceof NumDim nd && box.ranges[k] != null) {
                List<NumCell> cells = IntentOmega.numCells(nd);
                where.add(cond(d.path, "gte", cells.get(box.ranges[k][0]).lo()));
                where.add(cond(d.path, "lte", cells.get(box.ranges[k][1]).hi()));
            } else if (d instanceof CatDim cd && box.sets[k] != null) {
                Map<String, Object> c = catCondition(cd, box.sets[k]);
                if (c != null) where.add(c);
            }
        }
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("verb", vs.verb);
        p.put("resource", "*");
        if (!where.isEmpty()) p.put("where", where);
        return p;
    }

    /** Cover the allowed cell set exactly with greedily grown maximal boxes; one predicate per box. */
    public static List<Map<String, Object>> boxesToPredicates(VerbSpace vs, byte[] allowed) {
        int D = vs.dims.size();
        int[] nCellsD = new int[D];
        for (int k = 0; k < D; k++) nCellsD[k] = IntentOmega.cellCount(vs.dims.get(k));
        byte[] covered = new byte[allowed.length];
        List<Map<String, Object>> out = new ArrayList<>();
        for (int c = 0; c < allowed.length; c++) {
            if (allowed[c] == 0 || covered[c] != 0) continue;
            int[] idx = IntentOmega.decodeCell(vs, c);
            Box box = new Box(D);
            for (int k = 0; k < D; k++) {
                if (vs.dims.get(k).kind.equals("num")) box.ranges[k] = new int[] {idx[k], idx[k]};
                else { box.sets[k] = new LinkedHashSet<>(); box.sets[k].add(idx[k]); }
            }
            for (int k = 0; k < D; k++) {
                Dim d = vs.dims.get(k);
                if (d.kind.equals("num")) {
                    int n = nCellsD[k];
                    int[] r = box.ranges[k];
                    while (r[1] + 1 < n) {
                        r[1]++;
                        if (!allIn(box, allowed, nCellsD)) { r[1]--; break; }
                    }
                    while (r[0] > 0) {
                        r[0]--;
                        if (!allIn(box, allowed, nCellsD)) { r[0]++; break; }
                    }
                } else {
                    Set<Integer> s = box.sets[k];
                    for (int v = 0; v < ((CatDim) d).values.size(); v++) {
                        if (s.contains(v)) continue;
                        s.add(v);
                        if (!allIn(box, allowed, nCellsD)) s.remove(v);
                    }
                }
            }
            for (int[] bi : boxCells(box)) covered[encode(nCellsD, bi)] = 1;
            out.add(boxToPredicate(vs, box));
        }
        return out;
    }

    private static boolean allIn(Box b, byte[] allowed, int[] nCellsD) {
        for (int[] idx : boxCells(b)) if (allowed[encode(nCellsD, idx)] != 1) return false;
        return true;
    }

    // ---- elicitation loop ----

    @FunctionalInterface public interface Answer { int answer(Question q); }

    public static final class ElicitOptions {
        public double epsRisk, epsBurden;
        public int maxQuestions;
        public boolean audit;
        public List<Object[]> seed = new ArrayList<>(); // {verb, int[] cell}

        public ElicitOptions(double epsRisk, double epsBurden, int maxQuestions, boolean audit) {
            this.epsRisk = epsRisk; this.epsBurden = epsBurden; this.maxQuestions = maxQuestions; this.audit = audit;
        }
    }

    public static final class ElicitResult {
        public final String stop;
        public final int questions, auditQuestions, seedQuestions;
        public final List<Question> asked;
        ElicitResult(String stop, int questions, int auditQuestions, int seedQuestions, List<Question> asked) {
            this.stop = stop; this.questions = questions; this.auditQuestions = auditQuestions; this.seedQuestions = seedQuestions; this.asked = asked;
        }
    }

    private static Question seedQuestion(IntentLearner learner, String verb, int[] cell) {
        VerbSpace vs = null;
        for (VerbSpace v : learner.omega.verbs) if (v.verb.equals(verb)) { vs = v; break; }
        if (vs == null || cell.length != vs.dims.size()) return null;
        Outcome outcome = IntentOmega.cellRep(vs, cell);
        double p = learner.acceptance(outcome);
        if (p <= 1e-9 || p >= 1 - 1e-9 || learner.isVetoed(outcome)) return null;
        return new Question(verb, cell.clone(), outcome, p, 0);
    }

    public static ElicitResult elicit(IntentLearner learner, Answer answer, ElicitOptions o) {
        List<Question> asked = new ArrayList<>();
        int seedQuestions = 0;
        for (Object[] s : o.seed) {
            if (asked.size() >= o.maxQuestions) break;
            LearnerMetrics m = learner.metrics();
            if (m.residualRisk <= o.epsRisk && m.burden <= o.epsBurden) break;
            Question q = seedQuestion(learner, (String) s[0], (int[]) s[1]);
            if (q == null) continue;
            learner.observe(q.outcome, answer.answer(q), "elicitation", null);
            asked.add(q);
            seedQuestions++;
        }
        String stop = null;
        while (stop == null) {
            LearnerMetrics m = learner.metrics();
            if (m.residualRisk <= o.epsRisk && m.burden <= o.epsBurden) stop = "converged";
            else if (asked.size() >= o.maxQuestions) stop = "budget";
            else {
                Question q = learner.nextQuestion();
                if (q == null) stop = "no-disagreement";
                else {
                    learner.observe(q.outcome, answer.answer(q), "elicitation", null);
                    asked.add(q);
                }
            }
        }
        int[] audit = auditRound(learner, answer, o.epsRisk, o.maxQuestions, o.audit, asked);
        if (audit[1] == 1) stop = "budget";
        return new ElicitResult(stop, asked.size(), audit[0], seedQuestions, asked);
    }

    /** The audit round on its own: {questions asked, 1 when the budget ran out before the unconfirmed weight fell to epsRisk}. Appends to asked. */
    public static int[] auditRound(IntentLearner learner, Answer answer, double epsRisk, int maxQuestions, boolean audit, List<Question> asked) {
        int n = 0;
        if (!audit) return new int[] {0, 0};
        for (;;) {
            List<Unconfirmed> pending = learner.unconfirmedGrantCells();
            double mass = 0;
            for (Unconfirmed x : pending) mass += x.weight;
            if (pending.isEmpty() || mass <= epsRisk) return new int[] {n, 0};
            if (asked.size() >= maxQuestions) return new int[] {n, 1};
            Unconfirmed top = pending.get(0);
            VerbSpace vs = null;
            for (VerbSpace v : learner.omega.verbs) if (v.verb.equals(top.verb)) { vs = v; break; }
            Outcome oc = IntentOmega.cellRep(vs, top.cell);
            Question q = new Question(top.verb, top.cell, oc, learner.acceptance(oc), top.weight);
            learner.observe(q.outcome, answer.answer(q), "elicitation", null);
            asked.add(q);
            n++;
        }
    }
}
