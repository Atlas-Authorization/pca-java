package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentFrames;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentMapKit;
import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions;
import net.atlasauth.pca.intent.IntentOmega;
import org.junit.jupiter.api.Test;

class IntentFramesDiffTest {
    private static final String M = "ref-intent-frames";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> ls(Object o) { return (List<Object>) o; }

    @Test void stateDigest() throws Exception { OracleCases.each(M, "stateDigest", a -> IntentFrames.stateDigest(a.get(0))); }

    @Test void snapshotState() throws Exception {
        OracleCases.each(M, "snapshotState", a -> IntentFrames.snapshotState(mp(a.get(0)), a.size() < 2 || !Boolean.FALSE.equals(a.get(1))));
    }

    @Test void checkFrame() throws Exception {
        OracleCases.each(M, "checkFrame", a -> IntentFrames.checkFrame(a.get(0), a.get(1), a.get(2), a.get(3), mp(a.get(4))));
    }

    @Test void applyScenario() throws Exception {
        OracleCases.each(M, "applyScenario", a -> {
            IntentLearner l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(a.get(0)), MapLearnerOptions.fromJson(a.get(1)));
            for (Object xo : ls(a.get(2))) {
                Map<String, Object> x = mp(xo);
                l.observe(IntentOmega.outcomeFromJson(x), (int) IntentOmega.dbl(x.get("y")), (String) x.get("source"), null);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("result", IntentFrames.applyFrameReport(l, IntentOmega.outcomeFromJson(a.get(3)), a.get(4)));
            IntentLearner.LearnerMetrics r = l.metrics();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("residualRisk", r.residualRisk); m.put("burden", r.burden); m.put("uncertainty", r.uncertainty); m.put("entropyBits", r.entropyBits);
            m.put("log2VersionSpace", r.log2VersionSpace); m.put("disagreementMass", r.disagreementMass); m.put("meanHarm", r.meanHarm);
            m.put("questions", (double) r.questions); m.put("conflicts", (double) r.conflicts);
            out.put("metrics", m);
            return out;
        });
    }
}
