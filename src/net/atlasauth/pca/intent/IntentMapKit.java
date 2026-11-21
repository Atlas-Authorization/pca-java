package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.intent.IntentLearner.AnchorSpec;
import net.atlasauth.pca.intent.IntentLearner.HypothesisClassSpec;
import net.atlasauth.pca.intent.IntentLearner.LearnerOptions;
import net.atlasauth.pca.intent.IntentOmega.CatValue;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * The Intent Map (spec 2, 6): a content-addressed JSON artifact holding the outcome space, the prior, every answer, the learned
 * acceptance per cell, the conservative grant and the quantified fidelity. Every probability and metric is an integer in parts
 * per million, so the digest is language-portable. {@link #verifyIntentMap} replays the map and re-derives every number.
 * Maps are plain JSON trees (Map / List / String / Boolean / Json.Num or Number / null).
 */
public final class IntentMapKit {
    private IntentMapKit() {}

    public static final String INTENT_MAP_DOMAIN = "atlas-pca/intent-map/v1";
    private static final double PPM = 1_000_000;

    /** JavaScript Math.round for the finite values the map arithmetic produces. */
    static double jsRound(double x) { return Double.isNaN(x) || Double.isInfinite(x) || Math.abs(x) >= 4503599627370496.0 ? x : Math.floor(x + 0.5); }

    private static double ppm(double x) { return jsRound(x * PPM); }

    private static double qz(double x) { return jsRound(x * PPM) / PPM; }

    private static Object num(double d) { return IntentJs.normalize(d); }

    private static Map<String, Object> lm() { return new LinkedHashMap<>(); }

    // ---- options carried by a map ----

    public static final class PolicyData {
        public final Object predicates;
        public final Object caveats;
        public PolicyData(Object predicates, Object caveats) { this.predicates = predicates; this.caveats = caveats; }
        Map<String, Object> toJson() {
            Map<String, Object> m = lm();
            m.put("predicates", predicates);
            m.put("caveats", caveats == null ? new ArrayList<>() : caveats);
            return m;
        }
    }

    public static final class AnchorIn {
        public final PolicyData policy;
        public final double lambda;
        public AnchorIn(PolicyData policy, double lambda) { this.policy = policy; this.lambda = lambda; }
        static AnchorIn fromJson(Object o) {
            Map<String, Object> m = IntentOmega.obj(o);
            Map<String, Object> p = IntentOmega.obj(m.get("policy"));
            return new AnchorIn(new PolicyData(p.get("predicates"), p.get("caveats")), IntentOmega.dbl(m.get("lambda")));
        }
        Map<String, Object> toJson() {
            Map<String, Object> m = lm();
            m.put("policy", policy.toJson());
            m.put("lambda", num(lambda));
            return m;
        }
    }

    public static final class PriorMixCell {
        public final String verb;
        public final double cell, q;
        public PriorMixCell(String verb, double cell, double q) { this.verb = verb; this.cell = cell; this.q = q; }
    }

    /** The serialisable learner parameters (every field optional; null = the default). */
    public static final class MapLearnerOptions {
        public Double eta, tau, defaultNullMass, etaPos, etaNeg;
        public String strategy;
        public Double nullMassNumber;
        public Map<String, Double> nullMassByVerb;
        public AnchorIn anchor;
        public List<AnchorIn> anchors;
        public HypothesisClassSpec hypothesisClass;
        public Double agnosticSlack;
        public List<String> monotonePaths;
        public Double monotoneOffMass;
        public Double priorMixBeta;
        public List<PriorMixCell> priorMixCells;

        public static MapLearnerOptions fromJson(Object o) {
            MapLearnerOptions r = new MapLearnerOptions();
            if (o == null) return r;
            Map<String, Object> m = IntentOmega.obj(o);
            r.eta = IntentLearner.numOrNull(m.get("eta")); r.tau = IntentLearner.numOrNull(m.get("tau"));
            r.defaultNullMass = IntentLearner.numOrNull(m.get("defaultNullMass"));
            r.etaPos = IntentLearner.numOrNull(m.get("etaPos")); r.etaNeg = IntentLearner.numOrNull(m.get("etaNeg"));
            r.strategy = (String) m.get("strategy");
            Object nm = m.get("nullMass");
            if (nm != null) {
                if (IntentOmega.isNumber(nm)) r.nullMassNumber = IntentOmega.dbl(nm);
                else {
                    r.nullMassByVerb = new LinkedHashMap<>();
                    for (Map.Entry<String, Object> e : IntentOmega.obj(nm).entrySet()) r.nullMassByVerb.put(e.getKey(), IntentOmega.dbl(e.getValue()));
                }
            }
            if (m.get("anchor") != null) r.anchor = AnchorIn.fromJson(m.get("anchor"));
            if (m.get("anchors") != null) {
                r.anchors = new ArrayList<>();
                for (Object a : IntentOmega.arr(m.get("anchors"))) r.anchors.add(AnchorIn.fromJson(a));
            }
            if (m.get("hypothesisClass") != null) r.hypothesisClass = HypothesisClassSpec.fromJson(m.get("hypothesisClass"));
            r.agnosticSlack = IntentLearner.numOrNull(m.get("agnosticSlack"));
            if (m.get("monotone") != null) {
                Map<String, Object> mo = IntentOmega.obj(m.get("monotone"));
                r.monotonePaths = new ArrayList<>();
                for (Object x : IntentOmega.arr(mo.get("paths"))) r.monotonePaths.add((String) x);
                r.monotoneOffMass = IntentLearner.numOrNull(mo.get("offMass"));
            }
            if (m.get("priorMix") != null) {
                Map<String, Object> pm = IntentOmega.obj(m.get("priorMix"));
                r.priorMixBeta = IntentOmega.dbl(pm.get("beta"));
                r.priorMixCells = new ArrayList<>();
                for (Object c : IntentOmega.arr(pm.get("cells"))) {
                    Map<String, Object> cm = IntentOmega.obj(c);
                    r.priorMixCells.add(new PriorMixCell((String) cm.get("verb"), IntentOmega.dbl(cm.get("cell")), IntentOmega.dbl(cm.get("q"))));
                }
            }
            return r;
        }

        /** The JSON form of these options (absent fields omitted). */
        public Map<String, Object> toJson() {
            Map<String, Object> m = lm();
            if (eta != null) m.put("eta", num(eta));
            if (tau != null) m.put("tau", num(tau));
            if (strategy != null) m.put("strategy", strategy);
            if (nullMassNumber != null) m.put("nullMass", num(nullMassNumber));
            if (nullMassByVerb != null) {
                Map<String, Object> nm = lm();
                for (Map.Entry<String, Double> e : nullMassByVerb.entrySet()) nm.put(e.getKey(), num(e.getValue()));
                m.put("nullMass", nm);
            }
            if (anchor != null) m.put("anchor", anchor.toJson());
            if (anchors != null) {
                List<Object> as = new ArrayList<>();
                for (AnchorIn a : anchors) as.add(a.toJson());
                m.put("anchors", as);
            }
            if (hypothesisClass != null) {
                HypothesisClassSpec h = hypothesisClass;
                Map<String, Object> hm = lm();
                hm.put("kind", h.kind);
                if (h.k != null) hm.put("k", num(h.k));
                if (h.maxRules != null) hm.put("maxRules", num(h.maxRules));
                if (h.decay != null) hm.put("decay", num(h.decay));
                if (h.conditions != null) hm.put("conditions", h.conditions);
                m.put("hypothesisClass", hm);
            }
            if (agnosticSlack != null) m.put("agnosticSlack", num(agnosticSlack));
            if (monotonePaths != null) {
                Map<String, Object> mo = lm();
                mo.put("paths", new ArrayList<Object>(monotonePaths));
                if (monotoneOffMass != null) mo.put("offMass", num(monotoneOffMass));
                m.put("monotone", mo);
            }
            if (etaPos != null) m.put("etaPos", num(etaPos));
            if (etaNeg != null) m.put("etaNeg", num(etaNeg));
            if (priorMixBeta != null) {
                Map<String, Object> pm = lm();
                pm.put("beta", num(priorMixBeta));
                List<Object> cs = new ArrayList<>();
                for (PriorMixCell c : priorMixCells) {
                    Map<String, Object> cm = lm();
                    cm.put("verb", c.verb); cm.put("cell", num(c.cell)); cm.put("q", num(c.q));
                    cs.add(cm);
                }
                pm.put("cells", cs);
                m.put("priorMix", pm);
            }
            return m;
        }
    }

    // ---- omega <-> JSON ----

    public static Map<String, Object> omegaToJSON(Omega o) {
        boolean equal = true;
        for (VerbSpace v : o.verbs) if (!(Math.abs(v.weight - o.verbs.get(0).weight) < 1e-15)) equal = false;
        List<Object> verbs = new ArrayList<>();
        for (VerbSpace v : o.verbs) {
            Map<String, Object> m = lm();
            m.put("verb", v.verb);
            m.put("reversibility", v.reversibility);
            m.put("w", equal ? (Object) 1L : num(Math.max(1, jsRound(v.weight * PPM))));
            List<Object> dims = new ArrayList<>();
            for (Dim d : v.dims) dims.add(IntentOmega.dimToJson(d));
            m.put("dims", dims);
            verbs.add(m);
        }
        Map<String, Object> out = lm();
        out.put("verbs", verbs);
        out.put("approximate", new ArrayList<Object>(o.approximate));
        return out;
    }

    public static Omega omegaFromJSON(Object j) {
        Map<String, Object> jm = IntentOmega.obj(j);
        List<Object> vs = IntentOmega.arr(jm.get("verbs"));
        double tot = 0;
        for (Object v : vs) tot += IntentOmega.dbl(IntentOmega.obj(v).get("w"));
        List<VerbSpace> verbs = new ArrayList<>();
        for (Object v : vs) {
            Map<String, Object> vm = IntentOmega.obj(v);
            List<Dim> dims = new ArrayList<>();
            for (Object d : IntentOmega.arr(vm.get("dims"))) {
                Map<String, Object> dm = IntentOmega.obj(d);
                if ("num".equals(dm.get("kind"))) {
                    List<Object> cs = dm.get("cuts") == null ? new ArrayList<>() : IntentOmega.arr(dm.get("cuts"));
                    double[] cuts = new double[cs.size()];
                    for (int i = 0; i < cuts.length; i++) cuts[i] = IntentOmega.dbl(cs.get(i));
                    dims.add(new NumDim((String) dm.get("path"), IntentOmega.dbl(dm.get("lo")), IntentOmega.dbl(dm.get("hi")), cuts, dm.get("dist") == null ? "uniform" : (String) dm.get("dist")));
                } else {
                    List<CatValue> cv = new ArrayList<>();
                    if (dm.get("values") != null) for (Object x : IntentOmega.arr(dm.get("values"))) cv.add(new CatValue((String) IntentOmega.obj(x).get("kind"), (String) IntentOmega.obj(x).get("value")));
                    dims.add(new IntentOmega.CatDim((String) dm.get("path"), cv));
                }
            }
            verbs.add(new VerbSpace((String) vm.get("verb"), (String) vm.get("reversibility"), IntentOmega.dbl(vm.get("w")) / tot, dims));
        }
        List<String> approx = new ArrayList<>();
        for (Object x : IntentOmega.arr(jm.get("approximate"))) approx.add((String) x);
        return new Omega(verbs, approx);
    }

    // ---- digests ----

    /** Content address of a grant ({predicates, caveats}). */
    public static String grantDigest(Object g) {
        Map<String, Object> gm = IntentOmega.obj(g);
        Map<String, Object> body = lm();
        body.put("predicates", gm.get("predicates"));
        body.put("caveats", gm.containsKey("caveats") ? gm.get("caveats") : new ArrayList<>());
        Map<String, Object> top = lm();
        top.put("d", "atlas-pca/intent-grant/v1");
        top.put("g", body);
        return Pca.hashCanonical(IntentJs.normalize(top));
    }

    /** Content address of an Intent Map. */
    public static String intentMapDigest(Object m) {
        Map<String, Object> top = lm();
        top.put("d", INTENT_MAP_DOMAIN);
        top.put("m", m);
        return Pca.hashCanonical(IntentJs.normalize(top));
    }

    private static Map<String, Object> metricsOf(IntentLearner l) {
        IntentLearner.LearnerMetrics m = l.metrics();
        double rmax = 0;
        for (IntentLearner.CellView c : l.cells()) rmax += c.mass * (1 - c.p) * c.harm;
        Map<String, Object> o = lm();
        o.put("residual_risk_ppm", num(ppm(m.residualRisk)));
        o.put("burden_ppm", num(ppm(m.burden)));
        o.put("uncertainty_ppm", num(ppm(m.uncertainty)));
        o.put("disagreement_ppm", num(ppm(m.disagreementMass)));
        o.put("mean_harm_ppm", num(ppm(m.meanHarm)));
        o.put("fidelity_est_ppm", num(ppm(rmax > 0 ? 1 - m.residualRisk / rmax : 1)));
        o.put("entropy_mbits", num(jsRound(m.entropyBits * 1000)));
        o.put("log2_vs_mbits", m.log2VersionSpace == null ? null : num(jsRound(m.log2VersionSpace * 1000)));
        o.put("questions", (long) m.questions);
        o.put("conflicts", (long) m.conflicts);
        return o;
    }

    // ---- learner construction ----

    private static final Map<IntentLearner, MapLearnerOptions> PARAMS = Collections.synchronizedMap(new WeakHashMap<>());

    private static double nullMassOf(MapLearnerOptions o, String verb) {
        if (o.nullMassNumber != null) return o.nullMassNumber;
        Double own = o.nullMassByVerb != null ? o.nullMassByVerb.get(verb) : null;
        if (own != null) return own;
        return o.defaultNullMass != null ? o.defaultNullMass : 0.2;
    }

    private static AnchorSpec anchorOpt(AnchorIn a) {
        return new AnchorSpec(a.policy.toJson(), jsRound(a.lambda * 1000) / 1000);
    }

    private static HypothesisClassSpec quantizeClass(HypothesisClassSpec h) {
        if (h == null || h.kind.equals("box")) return HypothesisClassSpec.BOX;
        double decay = qz(h.decay != null ? h.decay : 0.25);
        return h.kind.equals("union") ? new HypothesisClassSpec("union", h.k, null, decay, null)
            : new HypothesisClassSpec("decision-list", null, h.maxRules, decay, h.conditions != null ? h.conditions : "box");
    }

    private static IntentLearner.PriorMix priorMixOf(MapLearnerOptions o) {
        Map<String, List<double[]>> byVerb = new LinkedHashMap<>();
        for (PriorMixCell c : o.priorMixCells) {
            double q = qz(c.q);
            if (!(q >= 0 && q <= 1) || !(c.cell == Math.floor(c.cell) && Math.abs(c.cell) <= 9007199254740991.0) || c.cell < 0) {
                throw new IllegalArgumentException("pca-intent: priorMix cells need q in [0, 1] and a cell index >= 0");
            }
            byVerb.computeIfAbsent(c.verb, k -> new ArrayList<>()).add(new double[] {c.cell, StrictMath.log(q), StrictMath.log(1 - q)});
        }
        return new IntentLearner.PriorMix(qz(o.priorMixBeta), (vs, contains) -> {
            double lw = 0;
            List<double[]> ts = byVerb.get(vs.verb);
            if (ts != null) for (double[] t : ts) lw += t[0] <= Integer.MAX_VALUE && contains.test((int) t[0]) ? t[1] : t[2];
            return StrictMath.exp(lw);
        });
    }

    /** Build a learner whose parameters are exactly representable in an Intent Map (ppm-quantised). */
    public static IntentLearner createLearner(Omega omega, MapLearnerOptions o) {
        LearnerOptions opts = new LearnerOptions();
        opts.eta = qz(o.eta != null ? o.eta : 0);
        opts.tau = qz(o.tau != null ? o.tau : ((o.eta != null ? o.eta : 0) == 0 ? 1 : 0.95));
        opts.strategy = o.strategy != null ? o.strategy : "disagreement";
        opts.nullMassFn = vs -> qz(nullMassOf(o, vs.verb));
        opts.hypothesisClass = quantizeClass(o.hypothesisClass);
        if (o.agnosticSlack != null) {
            double s = o.agnosticSlack;
            if (!(s == Math.floor(s) && s >= 0 && s <= Integer.MAX_VALUE)) throw new IllegalArgumentException("pca-intent: agnosticSlack must be a non-negative integer");
            opts.agnosticSlack = (int) s;
        }
        if (o.anchor != null) opts.anchor = anchorOpt(o.anchor);
        if (o.anchors != null && !o.anchors.isEmpty()) {
            opts.anchors = new ArrayList<>();
            for (AnchorIn a : o.anchors) opts.anchors.add(anchorOpt(a));
        }
        if (o.monotonePaths != null) opts.monotone = new IntentLearner.Monotone(new ArrayList<>(o.monotonePaths), qz(o.monotoneOffMass != null ? o.monotoneOffMass : 0));
        if (o.etaPos != null) opts.etaPos = qz(o.etaPos);
        if (o.etaNeg != null) opts.etaNeg = qz(o.etaNeg);
        if (o.priorMixBeta != null) opts.priorMix = priorMixOf(o);
        IntentLearner l = new IntentLearner(omega, opts);
        PARAMS.put(l, o);
        return l;
    }

    /** The serialisable parameters a learner was built with (createLearner only). */
    public static MapLearnerOptions learnerOptionsOf(IntentLearner l) {
        MapLearnerOptions o = PARAMS.get(l);
        if (o == null) throw new IllegalStateException("pca-intent: build the learner with createLearner() so its parameters are serialisable");
        return o;
    }

    private static Map<String, Object> anchorJson(AnchorIn a) {
        Map<String, Object> m = lm();
        m.put("policy", a.policy.toJson());
        m.put("lambda_milli", num(jsRound(a.lambda * 1000)));
        return m;
    }

    public static Map<String, Object> emitIntentMap(IntentLearner l) { return emitIntentMap(l, null); }

    public static Map<String, Object> emitIntentMap(IntentLearner l, String intentRef) {
        MapLearnerOptions o = learnerOptionsOf(l);
        Map<String, Object> nullMass = lm();
        for (VerbSpace vs : l.omega.verbs) nullMass.put(vs.verb, num(ppm(nullMassOf(o, vs.verb))));
        IntentLearner.Synthesis syn = l.synthesize();
        Map<String, Object> grant = lm();
        grant.put("predicates", syn.predicates);
        grant.put("caveats", syn.caveats);
        HypothesisClassSpec hc = l.hypothesisClass;
        Map<String, Object> learner = lm();
        learner.put("hypothesis_class", IntentLearner.hypothesisClassName(hc));
        if (hc.kind.equals("union")) {
            Map<String, Object> cp = lm();
            cp.put("k", num(hc.k));
            cp.put("decay_ppm", num(ppm(hc.decay != null ? hc.decay : 0.25)));
            learner.put("class_params", cp);
        }
        if (hc.kind.equals("decision-list")) {
            Map<String, Object> cp = lm();
            cp.put("max_rules", num(hc.maxRules));
            cp.put("decay_ppm", num(ppm(hc.decay != null ? hc.decay : 0.25)));
            learner.put("class_params", cp);
        }
        if (l.agnosticSlack != null) learner.put("agnostic_slack", (long) (int) l.agnosticSlack);
        learner.put("eta_ppm", num(ppm(l.eta)));
        learner.put("tau_ppm", num(ppm(l.tau)));
        learner.put("strategy", l.strategy);
        learner.put("null_mass_ppm", nullMass);
        if (o.anchor != null) learner.put("anchor", anchorJson(o.anchor));
        if (o.anchors != null && !o.anchors.isEmpty()) {
            List<Object> as = new ArrayList<>();
            for (AnchorIn a : o.anchors) as.add(anchorJson(a));
            learner.put("anchors", as);
        }
        if (o.monotonePaths != null) {
            Map<String, Object> mo = lm();
            mo.put("paths", new ArrayList<Object>(o.monotonePaths));
            mo.put("off_ppm", num(ppm(o.monotoneOffMass != null ? o.monotoneOffMass : 0)));
            learner.put("monotone", mo);
        }
        if (o.etaPos != null || o.etaNeg != null) {
            Map<String, Object> nz = lm();
            nz.put("eta_pos_ppm", num(ppm(l.etaPos)));
            nz.put("eta_neg_ppm", num(ppm(l.etaNeg)));
            learner.put("noise", nz);
        }
        if (o.priorMixBeta != null) {
            Map<String, Object> pm = lm();
            pm.put("beta_ppm", num(ppm(o.priorMixBeta)));
            List<Object> cs = new ArrayList<>();
            for (PriorMixCell c : o.priorMixCells) {
                Map<String, Object> cm = lm();
                cm.put("verb", c.verb); cm.put("cell", num(c.cell)); cm.put("q_ppm", num(ppm(c.q)));
                cs.add(cm);
            }
            pm.put("cells", cs);
            learner.put("prior_mix", pm);
        }
        List<Object> obs = new ArrayList<>();
        for (IntentLearner.Observation x : l.observations) {
            Map<String, Object> m = lm();
            m.put("verb", x.verb);
            m.put("values", new LinkedHashMap<>(x.values));
            m.put("y", (long) x.y);
            m.put("source", x.source);
            if (x.region != null) m.put("region", x.region.toJson());
            obs.add(m);
        }
        List<Object> cells = new ArrayList<>();
        for (IntentLearner.CellView c : l.cells()) {
            Map<String, Object> m = lm();
            m.put("verb", c.verb);
            List<Object> idx = new ArrayList<>();
            for (int i : c.cell) idx.add((long) i);
            m.put("cell", idx);
            m.put("p_ppm", num(ppm(c.p)));
            m.put("in_grant", c.inGrant);
            cells.add(m);
        }
        Map<String, Object> map = lm();
        map.put("v", 1L);
        map.put("kind", "pca-intent-map");
        map.put("intent_ref", intentRef);
        List<Object> principals = new ArrayList<>();
        if (intentRef != null && !intentRef.isEmpty()) principals.add(intentRef);
        map.put("principals", principals);
        map.put("omega", omegaToJSON(l.omega));
        map.put("learner", learner);
        map.put("observations", obs);
        map.put("cells", cells);
        map.put("grant", grant);
        map.put("grant_digest", grantDigest(grant));
        map.put("metrics", metricsOf(l));
        return map;
    }

    /** The learner parameters a map records (inverse of what emitIntentMap writes). */
    public static MapLearnerOptions mapLearnerOptions(Object mapO) {
        Map<String, Object> m = IntentOmega.obj(mapO);
        Map<String, Object> ln = IntentOmega.obj(m.get("learner"));
        MapLearnerOptions r = new MapLearnerOptions();
        r.nullMassByVerb = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : IntentOmega.obj(ln.get("null_mass_ppm")).entrySet()) r.nullMassByVerb.put(e.getKey(), IntentOmega.dbl(e.getValue()) / PPM);
        Map<String, Object> cp = ln.get("class_params") == null ? null : IntentOmega.obj(ln.get("class_params"));
        String hcn = (String) ln.get("hypothesis_class");
        double decay = (cp != null && cp.get("decay_ppm") != null ? IntentOmega.dbl(cp.get("decay_ppm")) : 250_000) / PPM;
        if ("per-verb-union/v1".equals(hcn)) {
            r.hypothesisClass = new HypothesisClassSpec("union", cp != null && cp.get("k") != null ? IntentOmega.dbl(cp.get("k")) : 2.0, null, decay, null);
        } else if ("per-verb-decision-list/v1".equals(hcn) || "per-verb-decision-list/v2".equals(hcn)) {
            r.hypothesisClass = new HypothesisClassSpec("decision-list", null, cp != null && cp.get("max_rules") != null ? IntentOmega.dbl(cp.get("max_rules")) : 2.0, decay,
                "per-verb-decision-list/v1".equals(hcn) ? "atomic" : "box");
        } else r.hypothesisClass = HypothesisClassSpec.BOX;
        r.eta = IntentOmega.dbl(ln.get("eta_ppm")) / PPM;
        r.tau = IntentOmega.dbl(ln.get("tau_ppm")) / PPM;
        r.strategy = (String) ln.get("strategy");
        if (ln.get("agnostic_slack") != null) r.agnosticSlack = IntentOmega.dbl(ln.get("agnostic_slack"));
        if (ln.get("anchor") != null) r.anchor = anchorBack(ln.get("anchor"));
        if (ln.get("anchors") != null && !IntentOmega.arr(ln.get("anchors")).isEmpty()) {
            r.anchors = new ArrayList<>();
            for (Object a : IntentOmega.arr(ln.get("anchors"))) r.anchors.add(anchorBack(a));
        }
        if (ln.get("monotone") != null) {
            Map<String, Object> mo = IntentOmega.obj(ln.get("monotone"));
            r.monotonePaths = new ArrayList<>();
            for (Object x : IntentOmega.arr(mo.get("paths"))) r.monotonePaths.add((String) x);
            r.monotoneOffMass = IntentOmega.dbl(mo.get("off_ppm")) / PPM;
        }
        if (ln.get("noise") != null) {
            Map<String, Object> nz = IntentOmega.obj(ln.get("noise"));
            r.etaPos = IntentOmega.dbl(nz.get("eta_pos_ppm")) / PPM;
            r.etaNeg = IntentOmega.dbl(nz.get("eta_neg_ppm")) / PPM;
        }
        if (ln.get("prior_mix") != null) {
            Map<String, Object> pm = IntentOmega.obj(ln.get("prior_mix"));
            r.priorMixBeta = IntentOmega.dbl(pm.get("beta_ppm")) / PPM;
            r.priorMixCells = new ArrayList<>();
            for (Object c : IntentOmega.arr(pm.get("cells"))) {
                Map<String, Object> cm = IntentOmega.obj(c);
                r.priorMixCells.add(new PriorMixCell((String) cm.get("verb"), IntentOmega.dbl(cm.get("cell")), IntentOmega.dbl(cm.get("q_ppm")) / PPM));
            }
        }
        return r;
    }

    private static AnchorIn anchorBack(Object o) {
        Map<String, Object> a = IntentOmega.obj(o);
        Map<String, Object> p = IntentOmega.obj(a.get("policy"));
        return new AnchorIn(new PolicyData(p.get("predicates"), p.get("caveats")), IntentOmega.dbl(a.get("lambda_milli")) / 1000);
    }

    /** Rebuild the learner a map describes (outcome space + prior + observations). */
    public static IntentLearner learnerFromMap(Object mapO) {
        Map<String, Object> m = IntentOmega.obj(mapO);
        IntentLearner l = createLearner(omegaFromJSON(m.get("omega")), mapLearnerOptions(mapO));
        for (Object oo : IntentOmega.arr(m.get("observations"))) {
            Map<String, Object> o = IntentOmega.obj(oo);
            Map<String, Object> vals = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : IntentOmega.obj(o.get("values")).entrySet()) vals.put(e.getKey(), IntentOmega.isNumber(e.getValue()) ? (Object) IntentOmega.dbl(e.getValue()) : e.getValue());
            l.observe(new Outcome((String) o.get("verb"), vals), (int) IntentOmega.dbl(o.get("y")), (String) o.get("source"), o.get("region") == null ? null : IntentRegion.Region.fromJson(o.get("region")));
        }
        return l;
    }

    private static String jsStr(Object v) {
        if (v == null) return "null";
        if (IntentOmega.isNumber(v)) return ((Json.Num) IntentJs.normalize(IntentOmega.dbl(v))).raw;
        return String.valueOf(v);
    }

    /** Replay a single-principal map and check every number, every cell and the grant. */
    public static Map<String, Object> verifyIntentMap(Object mapO) {
        List<Object> problems = new ArrayList<>();
        try {
            if (!(mapO instanceof Map)) return result(false, List.of("not an intent map v1"));
            Map<String, Object> m = IntentOmega.obj(mapO);
            if (!(IntentOmega.isNumber(m.get("v")) && IntentOmega.dbl(m.get("v")) == 1) || !"pca-intent-map".equals(m.get("kind"))) return result(false, List.of("not an intent map v1"));
            if (IntentOmega.arr(m.get("principals")).size() > 1 || m.get("aggregation") != null) {
                return result(false, List.of("combined map: verify each principal map and recombine with verifyAggregate"));
            }
            Object ir = m.get("intent_ref");
            Map<String, Object> r = emitIntentMap(learnerFromMap(m), ir == null ? null : (String) ir);
            Object gd = m.get("grant_digest");
            if (!r.get("grant_digest").equals(gd) || !grantDigest(m.get("grant")).equals(gd)) problems.add("grant does not match the replayed posterior");
            List<Object> rc = IntentOmega.arr(r.get("cells"));
            List<Object> mc = IntentOmega.arr(m.get("cells"));
            if (rc.size() != mc.size()) problems.add("cell count differs");
            else {
                for (int i = 0; i < rc.size(); i++) {
                    Map<String, Object> c = IntentOmega.obj(rc.get(i));
                    Map<String, Object> x = IntentOmega.obj(mc.get(i));
                    if (!c.get("verb").equals(x.get("verb")) || !c.get("in_grant").equals(x.get("in_grant")) || Math.abs(IntentOmega.dbl(c.get("p_ppm")) - IntentOmega.dbl(x.get("p_ppm"))) > 2) problems.add("cell " + i + " differs");
                }
            }
            Map<String, Object> rm = IntentOmega.obj(r.get("metrics"));
            Map<String, Object> mm = IntentOmega.obj(m.get("metrics"));
            for (String k : rm.keySet()) {
                Object a = rm.get(k);
                Object b = mm.get(k);
                boolean differs;
                if (a == null || mm.containsKey(k) && b == null) differs = !(a == null && mm.containsKey(k) && b == null);
                else if (!mm.containsKey(k) || !IntentOmega.isNumber(b)) differs = false;
                else differs = Math.abs(IntentOmega.dbl(a) - IntentOmega.dbl(b)) > 2;
                if (differs) problems.add("metric " + k + " differs (" + (mm.containsKey(k) ? jsStr(b) : "undefined") + " claimed, " + jsStr(a) + " replayed)");
            }
        } catch (RuntimeException e) {
            problems.add("replay failed");
        }
        return result(problems.isEmpty(), problems);
    }

    private static Map<String, Object> result(boolean ok, List<?> problems) {
        Map<String, Object> r = lm();
        r.put("ok", ok);
        r.put("problems", new ArrayList<Object>(problems));
        return r;
    }

    /** A runtime divergence is one more labelled observation; a negative one also vetoes the cell. Returns {before, after, grant}. */
    public static Map<String, Object> applyDivergence(IntentLearner l, Outcome outcome, int y) {
        long before = 0;
        for (IntentLearner.CellView c : l.cells()) if (c.inGrant) before++;
        l.observe(outcome, y, "runtime", null);
        long after = 0;
        for (IntentLearner.CellView c : l.cells()) if (c.inGrant) after++;
        IntentLearner.Synthesis s = l.synthesize();
        Map<String, Object> grant = lm();
        grant.put("predicates", s.predicates);
        grant.put("caveats", s.caveats);
        Map<String, Object> r = lm();
        r.put("before", before);
        r.put("after", after);
        r.put("grant", grant);
        return r;
    }

    // ---- committed (Merkle) form ----

    private static long numCellCount(double lo, double hi, List<Object> cuts) {
        long n = 0;
        double cur = lo;
        for (Object co : cuts) {
            double c = IntentOmega.dbl(co);
            if (c < lo || c > hi) continue;
            if (cur <= c - 1) n++;
            n++;
            cur = c + 1;
        }
        return cur <= hi ? n + 1 : n;
    }

    /** The committed form of an Intent Map; {@code secret} (32 bytes) derives every leaf salt. */
    public static net.atlasauth.pca.IntentMapCommit.CommittedMap commitIntentMap(Object mapO, byte[] secret) {
        Map<String, Object> m = IntentOmega.obj(mapO);
        List<Object> verbs = IntentOmega.arr(IntentOmega.obj(m.get("omega")).get("verbs"));
        List<Map<String, Object>> headers = new ArrayList<>();
        for (Object vo : verbs) {
            Map<String, Object> v = IntentOmega.obj(vo);
            List<Object> dims = new ArrayList<>();
            for (Object d : IntentOmega.arr(v.get("dims"))) {
                Map<String, Object> dm = IntentOmega.obj(d);
                Map<String, Object> o = lm();
                if ("num".equals(dm.get("kind"))) {
                    double lo = IntentOmega.dbl(dm.get("lo")), hi = IntentOmega.dbl(dm.get("hi"));
                    List<Object> cuts = new ArrayList<>();
                    if (dm.get("cuts") != null) for (Object c : IntentOmega.arr(dm.get("cuts"))) if (IntentOmega.dbl(c) >= lo && IntentOmega.dbl(c) <= hi) cuts.add(c);
                    o.put("kind", "num"); o.put("path", dm.get("path")); o.put("lo", dm.get("lo")); o.put("hi", dm.get("hi")); o.put("cuts", cuts);
                } else {
                    List<Object> vals = new ArrayList<>();
                    if (dm.get("values") != null) for (Object x : IntentOmega.arr(dm.get("values"))) {
                        Map<String, Object> xm = IntentOmega.obj(x);
                        Map<String, Object> y = lm();
                        y.put("kind", xm.get("kind")); y.put("value", xm.get("value"));
                        vals.add(y);
                    }
                    o.put("kind", "cat"); o.put("path", dm.get("path")); o.put("values", vals);
                }
                dims.add(o);
            }
            Map<String, Object> h = lm();
            h.put("verb", v.get("verb"));
            h.put("dims", dims);
            headers.add(h);
        }
        Map<String, List<Map<String, Object>>> cells = new LinkedHashMap<>();
        for (Object vo : verbs) {
            Map<String, Object> v = IntentOmega.obj(vo);
            List<Object> dims = IntentOmega.arr(v.get("dims"));
            long[] counts = new long[dims.size()];
            long total = 1;
            for (int j = 0; j < counts.length; j++) {
                Map<String, Object> dm = IntentOmega.obj(dims.get(j));
                counts[j] = "num".equals(dm.get("kind")) ? numCellCount(IntentOmega.dbl(dm.get("lo")), IntentOmega.dbl(dm.get("hi")), dm.get("cuts") == null ? new ArrayList<>() : IntentOmega.arr(dm.get("cuts")))
                    : dm.get("values") == null ? 0 : IntentOmega.arr(dm.get("values")).size();
                total *= counts[j];
            }
            if (total > MAX_CELLS) throw new IllegalArgumentException("commitIntentMap: too many cells for " + v.get("verb"));
            List<Map<String, Object>> slots = new ArrayList<>();
            for (long i = 0; i < total; i++) slots.add(null);
            for (Object co : IntentOmega.arr(m.get("cells"))) {
                Map<String, Object> c = IntentOmega.obj(co);
                if (!v.get("verb").equals(c.get("verb"))) continue;
                List<Object> cell = IntentOmega.arr(c.get("cell"));
                if (cell.size() != counts.length) throw new IllegalArgumentException("commitIntentMap: cell of " + v.get("verb") + " has the wrong arity");
                long flat = 0;
                for (int j = 0; j < cell.size(); j++) {
                    Object io = cell.get(j);
                    double i = IntentOmega.isNumber(io) ? IntentOmega.dbl(io) : Double.NaN;
                    if (!(i == Math.floor(i) && Math.abs(i) <= 9007199254740991.0 && i >= 0 && i < counts[j])) throw new IllegalArgumentException("commitIntentMap: cell index out of range for " + v.get("verb"));
                    flat = flat * counts[j] + (long) i;
                }
                Map<String, Object> s = lm();
                s.put("cell", new ArrayList<Object>(cell));
                s.put("p_ppm", c.get("p_ppm"));
                s.put("in_grant", c.get("in_grant"));
                slots.set((int) flat, s);
            }
            for (Map<String, Object> s : slots) if (s == null) throw new IllegalArgumentException("commitIntentMap: the map does not list every cell of " + v.get("verb"));
            cells.put((String) v.get("verb"), slots);
        }
        Map<String, Object> metrics = lm();
        Map<String, Object> mm = IntentOmega.obj(m.get("metrics"));
        for (Map.Entry<String, Object> e : mm.entrySet()) if (!e.getKey().equals("log2_vs_mbits")) metrics.put(e.getKey(), e.getValue());
        if (mm.get("log2_vs_mbits") != null) metrics.put("log2_vs_mbits", mm.get("log2_vs_mbits"));
        return net.atlasauth.pca.IntentMapCommit.commitMap(headers, cells, metrics, Pca.hashCanonical(IntentJs.normalize(m.get("learner"))), secret);
    }

    private static final long MAX_CELLS = 1L << 20;
}
