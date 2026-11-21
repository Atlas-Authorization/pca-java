package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentClassifierKit;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentMapKit;
import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions;
import net.atlasauth.pca.intent.IntentOmega;
import org.junit.jupiter.api.Test;

class IntentClassifierKitDiffTest {
    private static final String M = "ref-intent-classifier";

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

    @Test void calibrate() throws Exception {
        OracleCases.each(M, "calibrate", a -> IntentClassifierKit.calibrateConfusion(ls(a.get(0)), ls(a.get(1)), a.size() > 2 ? IntentOmega.dbl(a.get(2)) : null));
    }

    @Test void confusionDigest() throws Exception { OracleCases.each(M, "confusionDigest", a -> IntentClassifierKit.confusionDigest(mp(a.get(0)))); }

    @Test void publishedErrorRate() throws Exception { OracleCases.each(M, "publishedErrorRate", a -> IntentClassifierKit.publishedErrorRate(mp(a.get(0)))); }

    @Test void classifierCardNote() throws Exception { OracleCases.each(M, "classifierCardNote", a -> IntentClassifierKit.classifierCardNote((String) a.get(0), mp(a.get(1)))); }

    @Test void riskArrays() throws Exception {
        OracleCases.each(M, "riskArrays", a -> {
            String op = (String) a.get(0);
            Map<String, Object> arr = mp(a.get(1));
            if (op.equals("risk")) return IntentClassifierKit.classifierRisk(arr);
            if (op.equals("sound")) return IntentClassifierKit.labelSound(arr);
            return IntentClassifierKit.labelSoundBound(arr, IntentOmega.dbl(a.get(2)));
        });
    }

    @Test void awareScenario() throws Exception {
        OracleCases.each(M, "awareScenario", a -> IntentClassifierKit.classifierAwareResidualRisk(make(a.get(0), a.get(1), a.get(2)), ls(a.get(3))));
    }

    @Test void jitScenario() throws Exception {
        OracleCases.each(M, "jitScenario", a -> IntentClassifierKit.classifierJitCells(make(a.get(0), a.get(1), a.get(2)), mp(a.get(3)), IntentOmega.dbl(a.get(4))));
    }
}
