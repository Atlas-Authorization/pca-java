package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentWorld;
import org.junit.jupiter.api.Test;

class IntentWorldDiffTest {
    private static final String M = "ref-intent-world";

    private static Map<String, Object> map(Object o) { return IntentOmega.obj(o); }

    private static List<Double> nums(Object o) {
        if (o == null) return null;
        List<Double> out = new ArrayList<>();
        for (Object x : IntentOmega.arr(o)) out.add(IntentOmega.dbl(x));
        return out;
    }

    private static List<String> strs(Object o) {
        List<String> out = new ArrayList<>();
        for (Object x : IntentOmega.arr(o)) out.add((String) x);
        return out;
    }

    @Test void worldDim() throws Exception {
        OracleCases.each(M, "worldDim", a -> {
            Map<String, Object> s = map(a.get(1));
            return IntentOmega.dimToJson(IntentWorld.worldDim((String) a.get(0), IntentOmega.dbl(s.get("lo")), IntentOmega.dbl(s.get("hi")), nums(s.get("cuts")), (String) s.get("dist")));
        });
    }

    @Test void excessDim() throws Exception {
        OracleCases.each(M, "excessDim", a -> IntentOmega.dimToJson(IntentWorld.excessDim((String) a.get(0), IntentOmega.dbl(a.get(1)), nums(a.get(2)))));
    }

    @Test void optimalityCondition() throws Exception {
        OracleCases.each(M, "optimalityCondition", a -> IntentWorld.optimalityCondition((String) a.get(0), a.size() > 1 ? IntentOmega.dbl(a.get(1)) : 0));
    }

    @Test void provenanceDim() throws Exception { OracleCases.each(M, "provenanceDim", a -> IntentOmega.dimToJson(IntentWorld.provenanceDim((String) a.get(0)))); }

    @Test void classifierDim() throws Exception {
        OracleCases.each(M, "classifierDim", a -> IntentOmega.dimToJson(IntentWorld.classifierDim((String) a.get(0), strs(a.get(1)))));
    }

    @Test void withDims() throws Exception {
        OracleCases.each(M, "withDims", a -> {
            List<IntentOmega.Dim> ds = new ArrayList<>();
            for (Object d : IntentOmega.arr(a.get(2))) ds.add(IntentOmega.dimFromJson(d));
            return IntentOmega.omegaToJson(IntentWorld.withDims(IntentOmega.omegaFromJson(a.get(0)), (String) a.get(1), ds));
        });
    }

    @Test void liftOutcome() throws Exception {
        OracleCases.each(M, "liftOutcome", a -> IntentOmega.outcomeToJson(IntentWorld.liftOutcome(IntentOmega.outcomeFromJson(a.get(0)), map(a.get(1)), strs(a.get(2)))));
    }
}
