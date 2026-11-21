package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.intent.IntentMulti.NormalRule;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Multi-principal aggregation over replay-verified Intent Maps: the joint grant of a rule (unanimity, quorum, weighted, vetoers) per
 * cell, its recomputation check, and the cross-organisation form that lifts maps over different outcome spaces onto their common
 * refinement first. Maps are plain JSON trees.
 */
public final class IntentMultiAgg {
    private IntentMultiAgg() {}

    private static final double PPM = 1_000_000;

    private static double ppm(double x) { return IntentMapKit.jsRound(x * PPM); }

    private static Object num(double d) { return IntentJs.normalize(d); }

    private static Map<String, Object> lm() { return new LinkedHashMap<>(); }

    private static boolean truthy(Object o) { return o != null && !Boolean.FALSE.equals(o) && !(o instanceof String s && s.isEmpty()); }

    /** The error text of an own (reference-defined) failure, else a generic marker for engine-specific faults. */
    static String ownMessage(RuntimeException e) {
        String m = e.getMessage();
        if (m != null && (m.startsWith("aggregateIntentMaps") || m.startsWith("ruleOf") || m.startsWith("liftIntentMap") || m.startsWith("crossOrgAggregate")
            || m.startsWith("commonRefinement") || m.startsWith("pca-intent") || m.startsWith("refineOmega"))) return m;
        return "error";
    }

    /** {@code JSON.stringify} of a JSON tree (insertion order). */
    static String stringify(Object v) {
        StringBuilder sb = new StringBuilder();
        str(sb, v);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void str(StringBuilder sb, Object v) {
        if (v == null) sb.append("null");
        else if (v instanceof Boolean) sb.append(v);
        else if (v instanceof String s) {
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
                        boolean lone = Character.isSurrogate(c) && !(Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1)))
                            && !(Character.isLowSurrogate(c) && i > 0 && Character.isHighSurrogate(s.charAt(i - 1)));
                        if (c < 0x20 || lone) sb.append(String.format("\\u%04x", (int) c));
                        else sb.append(c);
                }
            }
            sb.append('"');
        } else if (IntentOmega.isNumber(v)) sb.append(((Json.Num) IntentJs.normalize(IntentOmega.dbl(v))).raw);
        else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<Object>) v) {
                if (!first) sb.append(',');
                first = false;
                str(sb, x);
            }
            sb.append(']');
        } else {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                str(sb, e.getKey());
                sb.append(':');
                str(sb, e.getValue());
            }
            sb.append('}');
        }
    }

    private static Map<String, Object> mp(Object o) { return IntentOmega.obj(o); }

    private static boolean nullKey(Map<String, Object> m, String k) { return m.containsKey(k) && m.get(k) == null; }

    private static double metric(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v == null ? 0 : IntentOmega.dbl(v);
    }

    /** Aggregate single-principal maps over a shared outcome space under a rule ({@code orgs}: intent_ref to organisation label, optional). */
    public static Map<String, Object> aggregateIntentMaps(List<Object> maps, Map<String, Object> rule, Map<String, Object> orgs) {
        if (maps.isEmpty()) throw new IllegalArgumentException("aggregateIntentMaps: no maps");
        String om = stringify(mp(maps.get(0)).get("omega"));
        for (Object m : maps) if (!stringify(mp(m).get("omega")).equals(om)) throw new IllegalArgumentException("aggregateIntentMaps: maps must share Ω (lift them with crossOrgAggregate)");
        for (Object mo : maps) {
            Map<String, Object> m = mp(mo);
            if (truthy(m.get("aggregation")) || IntentOmega.arr(m.get("principals")).size() != 1 || !(m.get("intent_ref") instanceof String)) {
                throw new IllegalArgumentException("aggregateIntentMaps: every input must be a single-principal map with an intent_ref");
            }
        }
        List<String> refs = new ArrayList<>();
        for (Object m : maps) refs.add((String) mp(m).get("intent_ref"));
        if (new LinkedHashSet<>(refs).size() != refs.size()) throw new IllegalArgumentException("aggregateIntentMaps: duplicate principal");
        NormalRule n = IntentMulti.normalizeRule(rule, refs);
        Omega omega = IntentMapKit.omegaFromJSON(mp(maps.get(0)).get("omega"));
        List<double[]> stats = new ArrayList<>();
        for (VerbSpace vs : omega.verbs) {
            double nc = IntentOmega.verbCellCount(vs);
            for (int c = 0; c < nc; c++) {
                IntentOmega.Stats s = IntentOmega.cellStats(vs, IntentOmega.decodeCell(vs, c), IntentOmega.DEFAULT_HARM);
                stats.add(new double[] {s.mass(), s.harm()});
            }
        }
        List<Object> c0 = IntentOmega.arr(mp(maps.get(0)).get("cells"));
        List<Object> cells = new ArrayList<>();
        for (int i = 0; i < c0.size(); i++) {
            Map<String, Object> c = mp(c0.get(i));
            double[] ps = new double[maps.size()];
            boolean[] ins = new boolean[maps.size()];
            for (int k = 0; k < maps.size(); k++) {
                Map<String, Object> ck = mp(IntentOmega.arr(mp(maps.get(k)).get("cells")).get(i));
                ps[k] = IntentOmega.dbl(ck.get("p_ppm")) / PPM;
                ins[k] = Boolean.TRUE.equals(ck.get("in_grant"));
            }
            Map<String, Object> o = lm();
            o.put("verb", c.get("verb"));
            o.put("cell", c.get("cell"));
            o.put("p_ppm", num(ppm(IntentMulti.jointAcceptance(n, ps))));
            o.put("in_grant", IntentMulti.ruleAdmits(n, ins));
            cells.add(o);
        }
        List<Map<String, Object>> predicates = new ArrayList<>();
        List<String> order = List.of("reversible", "rate_limited", "irreversible");
        int worst = -1;
        int off = 0;
        for (VerbSpace vs : omega.verbs) {
            int nc = (int) IntentOmega.verbCellCount(vs);
            byte[] allowed = new byte[nc];
            boolean any = false;
            for (int c = 0; c < nc; c++) if (Boolean.TRUE.equals(mp(cells.get(off + c)).get("in_grant"))) { allowed[c] = 1; any = true; }
            off += nc;
            if (!any) continue;
            worst = Math.max(worst, order.indexOf(vs.reversibility));
            predicates.addAll(IntentLearner.boxesToPredicates(vs, allowed));
        }
        List<Map<String, Object>> caveats = new ArrayList<>();
        if (worst >= 0) {
            Map<String, Object> cv = lm();
            cv.put("type", "reversibility_max");
            cv.put("class", order.get(worst));
            caveats.add(cv);
        }
        Map<String, Object> grant = lm();
        grant.put("predicates", predicates);
        grant.put("caveats", caveats);
        double[] pR = new double[maps.size()], pB = new double[maps.size()], pF = new double[maps.size()];
        for (int i = 0; i < maps.size(); i++) {
            double R = 0, B = 0, Rmax = 0;
            List<Object> mc = IntentOmega.arr(mp(maps.get(i)).get("cells"));
            for (int j = 0; j < mc.size(); j++) {
                double p = IntentOmega.dbl(mp(mc.get(j)).get("p_ppm")) / PPM;
                double[] st = stats.get(j);
                Rmax += st[0] * (1 - p) * st[1];
                if (Boolean.TRUE.equals(mp(cells.get(j)).get("in_grant"))) R += st[0] * (1 - p) * st[1];
                else B += st[0] * p;
            }
            pR[i] = R; pB[i] = B; pF[i] = Rmax > 0 ? 1 - R / Rmax : 1;
        }
        Object kind = rule.get("kind");
        Map<String, Object> agg = lm();
        agg.put("rule", kind);
        if ("quorum".equals(kind)) agg.put("k", rule.get("k"));
        if ("weighted".equals(kind)) {
            Map<String, Object> w = lm();
            for (int i = 0; i < refs.size(); i++) w.put(refs.get(i), num(n.weights()[i]));
            agg.put("weights", w);
            agg.put("threshold", rule.get("threshold"));
        }
        List<Object> vetoers = new ArrayList<>();
        for (int i = 0; i < refs.size(); i++) if (n.veto()[i]) vetoers.add(refs.get(i));
        agg.put("vetoers", vetoers);
        List<Object> per = new ArrayList<>();
        double maxR = Double.NEGATIVE_INFINITY, maxB = Double.NEGATIVE_INFINITY, minF = Double.POSITIVE_INFINITY;
        for (int i = 0; i < refs.size(); i++) {
            Map<String, Object> x = lm();
            x.put("intent_ref", refs.get(i));
            Object org = orgs == null ? null : orgs.get(refs.get(i));
            if (truthy(org)) x.put("org", org);
            double r = ppm(pR[i]), b = ppm(pB[i]);
            x.put("residual_risk_ppm", num(r));
            x.put("burden_ppm", num(b));
            per.add(x);
            maxR = Math.max(maxR, r); maxB = Math.max(maxB, b); minF = Math.min(minF, pF[i]);
        }
        agg.put("per_principal", per);
        boolean anyNull = false;
        for (Object m : maps) if (nullKey(mp(mp(m).get("metrics")), "log2_vs_mbits")) anyNull = true;
        Map<String, Object> metrics = lm();
        metrics.put("residual_risk_ppm", num(maxR));
        metrics.put("burden_ppm", num(maxB));
        metrics.put("uncertainty_ppm", num(worst(maps, "uncertainty_ppm", false)));
        metrics.put("disagreement_ppm", num(worst(maps, "disagreement_ppm", false)));
        metrics.put("mean_harm_ppm", mp(mp(maps.get(0)).get("metrics")).get("mean_harm_ppm"));
        metrics.put("fidelity_est_ppm", num(ppm(minF)));
        metrics.put("entropy_mbits", num(worst(maps, "entropy_mbits", true)));
        metrics.put("log2_vs_mbits", anyNull ? null : num(worst(maps, "log2_vs_mbits", true)));
        metrics.put("questions", num(worst(maps, "questions", true)));
        metrics.put("conflicts", num(worst(maps, "conflicts", true)));
        List<Object> obs = new ArrayList<>();
        for (Object m : maps) obs.addAll(IntentOmega.arr(mp(m).get("observations")));
        Map<String, Object> out = lm();
        out.put("v", 1L);
        out.put("kind", "pca-intent-map");
        out.put("intent_ref", null);
        out.put("principals", new ArrayList<Object>(refs));
        out.put("omega", mp(maps.get(0)).get("omega"));
        out.put("learner", mp(maps.get(0)).get("learner"));
        out.put("observations", obs);
        out.put("cells", cells);
        out.put("grant", grant);
        out.put("grant_digest", IntentMapKit.grantDigest(grant));
        out.put("metrics", metrics);
        out.put("aggregation", agg);
        return out;
    }

    private static double worst(List<Object> maps, String k, boolean sum) {
        double acc = sum ? 0 : Double.NEGATIVE_INFINITY;
        for (Object m : maps) {
            double v = metric(mp(mp(m).get("metrics")), k);
            acc = sum ? acc + v : Math.max(acc, v);
        }
        return acc;
    }

    /** The unanimity rule: the joint grant is the intersection of the principals' conservative grants. */
    public static Map<String, Object> combineIntentMaps(List<Object> maps, Map<String, Object> orgs) {
        Map<String, Object> rule = lm();
        rule.put("kind", "unanimity");
        return aggregateIntentMaps(maps, rule, orgs);
    }

    /** The rule an aggregated map records. */
    public static Map<String, Object> ruleOf(Object aggMap) {
        Object ao = mp(aggMap).get("aggregation");
        if (!truthy(ao)) throw new IllegalArgumentException("ruleOf: not an aggregated map");
        Map<String, Object> a = mp(ao);
        Map<String, Object> r = lm();
        Object kind = a.get("rule");
        if ("unanimity".equals(kind)) { r.put("kind", "unanimity"); r.put("vetoers", a.get("vetoers")); }
        else if ("quorum".equals(kind)) { r.put("kind", "quorum"); r.put("k", a.get("k")); r.put("vetoers", a.get("vetoers")); }
        else { r.put("kind", "weighted"); r.put("weights", a.get("weights")); r.put("threshold", a.get("threshold")); r.put("vetoers", a.get("vetoers")); }
        return r;
    }

    private static Map<String, Object> result(boolean ok, List<String> problems) {
        Map<String, Object> r = lm();
        r.put("ok", ok);
        r.put("problems", new ArrayList<Object>(problems));
        return r;
    }

    /** Verify an aggregated map against its inputs: replay-verify each input, recompute the aggregate and compare digests. */
    public static Map<String, Object> verifyAggregate(Object agg, List<Object> inputs, Map<String, Object> orgs) {
        List<String> problems = new ArrayList<>();
        try {
            for (int i = 0; i < inputs.size(); i++) {
                Map<String, Object> r = IntentMapKit.verifyIntentMap(inputs.get(i));
                if (!Boolean.TRUE.equals(r.get("ok"))) {
                    List<String> ps = new ArrayList<>();
                    for (Object p : IntentOmega.arr(r.get("problems"))) ps.add((String) p);
                    problems.add("input " + i + ": " + String.join("; ", ps));
                }
            }
            if (!problems.isEmpty()) return result(false, problems);
            Map<String, Object> again = aggregateIntentMaps(inputs, ruleOf(agg), orgs);
            if (!IntentMapKit.intentMapDigest(again).equals(IntentMapKit.intentMapDigest(agg))) problems.add("aggregate does not match its recomputation");
        } catch (RuntimeException e) {
            problems.add("recompute failed: " + ownMessage(e));
        }
        return result(problems.isEmpty(), problems);
    }

    /** Lift a replay-verified single-principal map onto a refinement of its outcome space (unseen verbs are denied: null mass 1). */
    public static Map<String, Object> liftIntentMap(Object mapO, Omega target) {
        Map<String, Object> m = mp(mapO);
        if (truthy(m.get("aggregation")) || IntentOmega.arr(m.get("principals")).size() > 1) throw new IllegalArgumentException("liftIntentMap: lift single-principal maps, then aggregate");
        Omega src = IntentMapKit.omegaFromJSON(m.get("omega"));
        IntentMapKit.MapLearnerOptions o = IntentMapKit.mapLearnerOptions(m);
        Set<String> known = new LinkedHashSet<>();
        for (VerbSpace v : src.verbs) known.add(v.verb);
        Map<String, Double> nullMass = new LinkedHashMap<>();
        for (VerbSpace vs : target.verbs) {
            Double own = o.nullMassByVerb != null ? o.nullMassByVerb.get(vs.verb) : null;
            nullMass.put(vs.verb, known.contains(vs.verb) ? (own != null ? own : 0.2) : 1.0);
        }
        IntentMapKit.MapLearnerOptions o2 = new IntentMapKit.MapLearnerOptions();
        o2.eta = o.eta; o2.tau = o.tau; o2.defaultNullMass = o.defaultNullMass; o2.etaPos = o.etaPos; o2.etaNeg = o.etaNeg; o2.strategy = o.strategy;
        o2.nullMassByVerb = nullMass;
        o2.anchor = o.anchor; o2.anchors = o.anchors; o2.hypothesisClass = o.hypothesisClass; o2.agnosticSlack = o.agnosticSlack;
        o2.monotonePaths = o.monotonePaths; o2.monotoneOffMass = o.monotoneOffMass; o2.priorMixBeta = o.priorMixBeta; o2.priorMixCells = o.priorMixCells;
        IntentLearner l = IntentMapKit.createLearner(target, o2);
        for (Object obo : IntentOmega.arr(m.get("observations"))) {
            Map<String, Object> ob = mp(obo);
            String verb = (String) ob.get("verb");
            VerbSpace svs = null, tvs = null;
            for (VerbSpace v : src.verbs) if (v.verb.equals(verb)) { svs = v; break; }
            for (VerbSpace v : target.verbs) if (v.verb.equals(verb)) { tvs = v; break; }
            if (svs == null || tvs == null) throw new IllegalArgumentException("liftIntentMap: verb " + verb + " missing from Ω");
            Map<String, Object> own = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : mp(ob.get("values")).entrySet()) own.put(e.getKey(), IntentOmega.isNumber(e.getValue()) ? (Object) IntentOmega.dbl(e.getValue()) : e.getValue());
            Map<String, Object> values = new LinkedHashMap<>(own);
            for (Dim d : tvs.dims) if (!values.containsKey(d.path)) values.put(d.path, IntentOmega.repValue(d, 0));
            int[] cell = IntentOmega.cellOf(svs, new Outcome(verb, own));
            if (cell == null) throw new IllegalArgumentException("liftIntentMap: an observation of " + verb + " lies outside the map's own Ω");
            IntentRegion.Region region = ob.get("region") != null ? IntentRegion.Region.fromJson(ob.get("region")) : IntentRegion.regionOfCell(svs, cell);
            l.observe(new Outcome(verb, values), (int) IntentOmega.dbl(ob.get("y")), (String) ob.get("source"), region);
        }
        Object ir = m.get("intent_ref");
        return IntentMapKit.emitIntentMap(l, ir == null ? null : (String) ir);
    }

    /** The aggregate, the lifted maps and the common refinement of a cross-organisation aggregation. */
    public static final class CrossOrg {
        public final Map<String, Object> aggregate;
        public final List<Object> lifted;
        public final Omega omega;
        CrossOrg(Map<String, Object> aggregate, List<Object> lifted, Omega omega) { this.aggregate = aggregate; this.lifted = lifted; this.omega = omega; }
    }

    /** Replay-verify every map, lift them all onto the common refinement of their spaces, then aggregate. */
    public static CrossOrg crossOrgAggregate(List<Object> maps, Map<String, Object> rule, Map<String, Object> orgs) {
        for (int i = 0; i < maps.size(); i++) {
            Map<String, Object> r = IntentMapKit.verifyIntentMap(maps.get(i));
            if (!Boolean.TRUE.equals(r.get("ok"))) {
                List<String> ps = new ArrayList<>();
                for (Object p : IntentOmega.arr(r.get("problems"))) ps.add((String) p);
                throw new IllegalArgumentException("crossOrgAggregate: map " + i + " does not verify: " + String.join("; ", ps));
            }
        }
        List<Omega> omegas = new ArrayList<>();
        for (Object m : maps) omegas.add(IntentMapKit.omegaFromJSON(mp(m).get("omega")));
        Omega omega = IntentMulti.commonRefinement(omegas);
        List<Object> lifted = new ArrayList<>();
        for (Object m : maps) lifted.add(liftIntentMap(m, omega));
        return new CrossOrg(aggregateIntentMaps(lifted, rule, orgs), lifted, omega);
    }

    /** Verify a cross-org aggregate by recomputing it from the original maps. */
    public static Map<String, Object> verifyCrossOrgAggregate(Object agg, List<Object> maps, Map<String, Object> orgs) {
        try {
            Map<String, Object> again = crossOrgAggregate(maps, ruleOf(agg), orgs).aggregate;
            return IntentMapKit.intentMapDigest(again).equals(IntentMapKit.intentMapDigest(agg)) ? result(true, List.of()) : result(false, List.of("aggregate does not match its recomputation"));
        } catch (RuntimeException e) {
            return result(false, List.of(ownMessage(e)));
        }
    }

    /** The outcome space as canonical-order JSON text (for callers that compare maps). */
    public static String omegaKey(Omega o) { return stringify(IntentMapKit.omegaToJSON(o)); }
}
