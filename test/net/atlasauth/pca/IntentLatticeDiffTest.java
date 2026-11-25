package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentLattice;
import net.atlasauth.pca.intent.IntentLayers;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentMapKit;
import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions;
import net.atlasauth.pca.intent.IntentOmega;
import org.junit.jupiter.api.Test;

class IntentLatticeDiffTest {
    private static final String M = "ref-intent-lattice";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> ls(Object o) { return (List<Object>) o; }

    @Test void latticeScenario() throws Exception {
        OracleCases.each(M, "latticeScenario", a -> {
            IntentLearner l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(a.get(0)), MapLearnerOptions.fromJson(a.get(1)));
            for (Object xo : ls(a.get(2))) {
                Map<String, Object> x = mp(xo);
                l.observe(IntentOmega.outcomeFromJson(x), (int) IntentOmega.dbl(x.get("y")), (String) x.get("source"), null);
            }
            IntentLayers.CeilingAdmitters c = IntentLayers.ceilingAdmitters(mp(a.get(3)));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("view", IntentLattice.latticeView(l, c));
            List<Object> decisions = new ArrayList<>();
            for (Object o : ls(a.get(4))) decisions.add(IntentLattice.decideOutcomeLayers(l, c, IntentOmega.outcomeFromJson(o)));
            out.put("decisions", decisions);
            return out;
        });
    }

    @Test void orgScenario() throws Exception { OracleCases.each(M, "orgScenario", a -> IntentLattice.orgLayerFromMaps(ls(a.get(0)), mp(a.get(1)))); }
}
