package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentMapKit;
import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOutcome;
import org.junit.jupiter.api.Test;

class IntentOutcomeDiffTest {
    private static final String M = "ref-intent-outcome";

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

    @Test void verifyScenario() throws Exception {
        OracleCases.each(M, "verifyScenario", a -> {
            IntentLearner l = make(a.get(0), a.get(1), a.get(2));
            Map<String, Object> result = IntentOutcome.verifyOutcome(l, IntentOmega.outcomeFromJson(a.get(3)), mp(a.get(4)), a.size() > 5 ? ls(a.get(5)) : null);
            IntentLearner.LearnerMetrics r = l.metrics();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("residualRisk", r.residualRisk); m.put("burden", r.burden); m.put("uncertainty", r.uncertainty); m.put("entropyBits", r.entropyBits);
            m.put("log2VersionSpace", r.log2VersionSpace); m.put("disagreementMass", r.disagreementMass); m.put("meanHarm", r.meanHarm);
            m.put("questions", (double) r.questions); m.put("conflicts", (double) r.conflicts);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("result", result);
            out.put("metrics", m);
            return out;
        });
    }

    @Test void mcScenario() throws Exception {
        OracleCases.each(M, "mcScenario", a -> IntentOutcome.estimateResidualRiskMC(make(a.get(0), a.get(1), a.get(2)), (int) IntentOmega.dbl(a.get(3)), IntentOmega.dbl(a.get(4))));
    }
}
