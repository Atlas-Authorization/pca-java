package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import net.atlasauth.pca.intent.IntentBond;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentMapKit;
import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentRouting;
import net.atlasauth.pca.intent.IntentRuntime;
import net.atlasauth.pca.intent.IntentSemantic;
import org.junit.jupiter.api.Test;

class IntentRoutingDiffTest {
    private static final String M = "ref-intent-routing";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> ls(Object o) { return (List<Object>) o; }

    private static Object inf(double x) { return Double.isFinite(x) ? (Object) x : "inf"; }

    private static IntentLearner make(Object omega, Object mapOpts, Object obs) {
        IntentLearner l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(omega), MapLearnerOptions.fromJson(mapOpts));
        for (Object xo : ls(obs)) {
            Map<String, Object> x = mp(xo);
            l.observe(IntentOmega.outcomeFromJson(x), (int) IntentOmega.dbl(x.get("y")), (String) x.get("source"), null);
        }
        return l;
    }

    private static Map<String, Object> metrics(IntentLearner.LearnerMetrics r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("residualRisk", r.residualRisk); m.put("burden", r.burden); m.put("uncertainty", r.uncertainty); m.put("entropyBits", r.entropyBits);
        m.put("log2VersionSpace", r.log2VersionSpace); m.put("disagreementMass", r.disagreementMass); m.put("meanHarm", r.meanHarm);
        m.put("questions", (double) r.questions); m.put("conflicts", (double) r.conflicts);
        return m;
    }

    @Test void bondAmount() throws Exception {
        OracleCases.each(M, "bondAmount", a -> IntentBond.bondAmount(IntentBond.BondPolicy.fromJson(a.get(0)), IntentOmega.dbl(a.get(1))));
    }

    @Test void quantizeScore() throws Exception { OracleCases.each(M, "quantizeScore", a -> IntentSemantic.quantizeScore(IntentOmega.dbl(a.get(0)))); }

    @Test void verifyJudgeVerdict() throws Exception {
        OracleCases.each(M, "verifyJudgeVerdict", a -> {
            Map<String, Object> e = mp(a.get(1));
            Map<String, Object> pins = a.get(2) == null || mp(a.get(2)).get("pqPins") == null ? null : mp(mp(a.get(2)).get("pqPins"));
            return IntentSemantic.verifyJudgeVerdict(a.get(0), (String) e.get("actionDigest"), (String) e.get("goalCommitment"), pins);
        });
    }

    @Test void conformalThreshold() throws Exception { OracleCases.each(M, "conformalThreshold", a -> inf(IntentSemantic.conformalThreshold(a.get(0)))); }

    @Test void empiricalFalseAllowRate() throws Exception {
        OracleCases.each(M, "empiricalFalseAllowRate", a -> IntentSemantic.empiricalFalseAllowRate(a.get(0), IntentOmega.dbl(a.get(1))));
    }

    @Test void verifySemanticThreshold() throws Exception {
        OracleCases.each(M, "verifySemanticThreshold", a -> {
            Map<String, Object> r = IntentSemantic.verifySemanticThreshold(a.get(0), mp(a.get(1)), null);
            if (r.get("cutoff") != null) r.put("cutoff", inf((Double) r.get("cutoff")));
            return r;
        });
    }

    private static Object route(List<?> a, boolean veto) {
        IntentLearner l = make(a.get(0), a.get(1), a.get(2));
        IntentRouting.RouteOptions ro = IntentRouting.RouteOptions.fromJson(a.get(4));
        List<Object> outs = new ArrayList<>();
        if (veto) for (Object x : ls(a.get(3))) l.observe(IntentOmega.outcomeFromJson(x), 0, "runtime", null);
        for (Object x : ls(a.get(3))) outs.add(IntentRouting.routeAction(l, IntentOmega.outcomeFromJson(x), ro));
        return outs;
    }

    @Test void routeScenario() throws Exception { OracleCases.each(M, "routeScenario", a -> route(a, false)); }

    @Test void routeVetoScenario() throws Exception { OracleCases.each(M, "routeVetoScenario", a -> route(a, true)); }

    private static void add(Map<String, Object> m, String key, double d) { m.put(key, new Json.Num(Long.toString((long) (IntentOmega.dbl(m.get(key)) + d)))); }

    private static final List<Consumer<Map<String, Object>>> MUTS = List.of(
        m -> { },
        m -> m.put("ok", !((Boolean) m.get("ok"))),
        m -> add(m, "aggregate_score_ppm", 1),
        m -> { List<Object> d = ls(m.get("verdict_digests")); if (!d.isEmpty()) d.remove(d.size() - 1); },
        m -> add(m, "k", 1),
        m -> m.put("reason", "x"));

    @Test void conformanceScenario() throws Exception {
        OracleCases.each(M, "conformanceScenario", a -> {
            IntentLearner l = make(a.get(0), a.get(1), a.get(2));
            Map<String, Object> input = IntentRouting.judgeInputOf(l, IntentOmega.outcomeFromJson(a.get(3)), mp(a.get(4)));
            List<Object> verdicts = ls(a.get(5));
            Map<String, Object> copts = mp(a.get(6));
            Map<String, Object> att = IntentRouting.intentConformanceAttestation(input, verdicts, copts, null);
            List<Object> tampered = new ArrayList<>();
            for (Consumer<Map<String, Object>> f : MUTS) {
                Map<String, Object> copy = mp(IntentJs.normalize(att));
                f.accept(copy);
                tampered.add(IntentRouting.verifyICAtt(copy, input, verdicts, copts, null));
            }
            tampered.add(IntentRouting.verifyICAtt(att, input, new ArrayList<>(verdicts.subList(Math.min(1, verdicts.size()), verdicts.size())), copts, null));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("input", input);
            out.put("att", att);
            out.put("digest", IntentRuntime.icAttDigest(att));
            out.put("verify", IntentRouting.verifyICAtt(att, input, verdicts, copts, null));
            out.put("tampered", tampered);
            out.put("check", IntentRouting.checkIntentConformance(in -> verdicts, input, copts, null));
            return out;
        });
    }

    @Test void jitScenario() throws Exception {
        OracleCases.each(M, "jitScenario", a -> {
            IntentLearner l = make(a.get(0), a.get(1), a.get(2));
            Outcome oc = IntentOmega.outcomeFromJson(a.get(3));
            Map<String, Object> c = mp(a.get(5));
            Map<String, Object> req = IntentRouting.jitConsentRequest(l, oc, (String) c.get("intentRef"), (String) c.get("mapDigest"));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("req", req);
            out.put("digest", IntentRuntime.jitConsentDigest(req));
            out.put("result", IntentRouting.recordJitDecision(l, req, (String) a.get(4)));
            out.put("metrics", metrics(l.metrics()));
            out.put("route", IntentRouting.routeAction(l, oc, new IntentRouting.RouteOptions()));
            return out;
        });
    }
}
