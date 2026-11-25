package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentMapKit;
import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions;
import net.atlasauth.pca.intent.IntentObservation;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentTrustRamp;
import org.junit.jupiter.api.Test;

class IntentRampDiffTest {
    private static final String M = "ref-intent-ramp";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> ls(Object o) { return (List<Object>) o; }

    private static IntentLearner make(Object omega, Object mapOpts, Object obs) {
        IntentLearner l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(omega), MapLearnerOptions.fromJson(mapOpts));
        for (Object xo : ls(obs)) {
            Map<String, Object> x = mp(xo);
            l.observe(IntentOmega.outcomeFromJson(x), (int) IntentOmega.dbl(x.get("y")), (String) x.get("source"), null);
        }
        return l;
    }

    @Test void signObservation() throws Exception {
        OracleCases.each(M, "signObservation", a -> IntentObservation.signIntentObservation(mp(a.get(0)), Keys.unb64u((String) a.get(1))));
    }

    @Test void verifyObservation() throws Exception {
        OracleCases.each(M, "verifyObservation", a -> {
            Map<String, Object> opts = mp(a.get(1));
            Map<String, Object> pins = opts.get("pqPins") == null ? null : mp(opts.get("pqPins"));
            return IntentObservation.verifyIntentObservation(a.get(0), (String) opts.get("expectedSigner"), pins);
        });
    }

    private static Double dnum(Map<String, Object> m, String k) { return m.get(k) == null ? null : IntentOmega.dbl(m.get(k)); }

    @Test void rampScenario() throws Exception {
        OracleCases.each(M, "rampScenario", a -> {
            Map<String, Object> d = mp(a.get(3));
            IntentTrustRamp ramp = new IntentTrustRamp(make(a.get(0), a.get(1), a.get(2)), dnum(d, "rho0"), dnum(d, "rho1"), dnum(d, "h"));
            List<Object> out = new ArrayList<>();
            for (Object oo : ls(a.get(4))) {
                Map<String, Object> op = mp(oo);
                switch ((String) op.get("op")) {
                    case "record": out.add(ramp.record(IntentOmega.outcomeFromJson(op.get("outcome")), (String) op.get("signal")).toJson()); break;
                    case "observe": {
                        Map<String, Object> c = mp(op.get("ctx"));
                        List<String> trusted = new ArrayList<>();
                        for (Object t : ls(c.get("trustedSigners"))) trusted.add((String) t);
                        Map<String, Object> ver = c.get("verify") == null ? new LinkedHashMap<>() : mp(c.get("verify"));
                        Map<String, Object> pins = ver.get("pqPins") == null ? null : mp(ver.get("pqPins"));
                        out.add(ramp.recordObservation(op.get("obs"), (String) c.get("mapDigest"), trusted, (String) ver.get("expectedSigner"), pins));
                        break;
                    }
                    case "rebase": {
                        ramp.rebase(make(op.get("omega"), op.get("mapOpts"), op.get("observations")));
                        Map<String, Object> m = new LinkedHashMap<>();
                        m.put("frozen", ramp.frozen());
                        m.put("pending", (double) ramp.pending().size());
                        out.add(m);
                        break;
                    }
                    default: {
                        Map<String, Object> m = new LinkedHashMap<>();
                        m.put("frozen", ramp.frozen());
                        m.put("pending", ramp.pendingView()); // the reference hands out its live queue array
                        m.put("drift", ramp.drift.state().toJson());
                        out.add(m);
                    }
                }
            }
            List<Object> log = new ArrayList<>();
            for (IntentTrustRamp.RampRecord r : ramp.log) log.add(r.toJson());
            IntentLearner.LearnerMetrics lm = ramp.learner().metrics();
            Map<String, Object> metrics = new LinkedHashMap<>();
            metrics.put("residualRisk", lm.residualRisk); metrics.put("burden", lm.burden); metrics.put("uncertainty", lm.uncertainty); metrics.put("entropyBits", lm.entropyBits);
            metrics.put("log2VersionSpace", lm.log2VersionSpace); metrics.put("disagreementMass", lm.disagreementMass); metrics.put("meanHarm", lm.meanHarm);
            metrics.put("questions", (double) lm.questions); metrics.put("conflicts", (double) lm.conflicts);
            Map<String, Object> end = new LinkedHashMap<>();
            end.put("log", log);
            end.put("frozen", ramp.frozen());
            end.put("pending", ramp.pending());
            end.put("metrics", metrics);
            List<Object> res = new ArrayList<>();
            res.add(out);
            res.add(end);
            return res;
        });
    }
}
