package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.function.Function;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentTrajectory;
import org.junit.jupiter.api.Test;

class IntentTrajectoryDiffTest {
    private static final String M = "ref-intent-trajectory";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> ls(Object o) { return (List<Object>) o; }

    private static List<Object> ints(int[] a) {
        List<Object> o = new ArrayList<>();
        for (int x : a) o.add((double) x);
        return o;
    }

    @Test void dimKindOf() throws Exception { OracleCases.each(M, "dimKindOf", a -> IntentTrajectory.dimKindOf((String) a.get(0))); }

    @Test void accDimPath() throws Exception { OracleCases.each(M, "accDimPath", a -> IntentTrajectory.accDimPath((String) a.get(0))); }

    @Test void monDimPath() throws Exception { OracleCases.each(M, "monDimPath", a -> IntentTrajectory.monDimPath((String) a.get(0))); }

    @Test void trajectoryHarmRange() throws Exception {
        OracleCases.each(M, "trajectoryHarmRange", a -> IntentTrajectory.trajectoryHarmRange(IntentOmega.dbl(a.get(0)), IntentOmega.dbl(a.get(1))));
    }

    @Test void augment() throws Exception {
        OracleCases.each(M, "augment", a -> IntentOmega.omegaToJson(IntentTrajectory.augmentOmega(IntentOmega.omegaFromJson(a.get(0)), mp(a.get(1)), a.size() > 2 ? mp(a.get(2)) : null)));
    }

    private static Object schemaOf(List<?> a, int i) { return a.size() > i ? a.get(i) : null; }

    @Test void liftScenario() throws Exception {
        OracleCases.each(M, "liftScenario", a -> {
            Omega tilde = IntentTrajectory.augmentOmega(IntentOmega.omegaFromJson(a.get(0)), mp(a.get(1)), mp(a.get(2)));
            Outcome lifted = IntentTrajectory.liftAction(tilde, mp(a.get(1)), ls(a.get(3)), mp(a.get(4)), schemaOf(a, 5));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("lifted", lifted == null ? null : IntentOmega.outcomeToJson(lifted));
            IntentTrajectory.LiftedCell c = lifted == null ? null : IntentTrajectory.liftedCell(tilde, lifted);
            if (c == null) out.put("cell", null);
            else {
                Map<String, Object> cm = new LinkedHashMap<>();
                cm.put("verb", c.vs().verb);
                cm.put("cell", ints(c.cell()));
                out.put("cell", cm);
            }
            return out;
        });
    }

    private static BiPredicate<String, int[]> grant(String g) {
        switch (g) {
            case "all": return (v, c) -> true;
            case "none": return (v, c) -> false;
            case "cell0": return (v, c) -> { for (int x : c) if (x != 0) return false; return true; };
            default: return (v, c) -> c[0] <= 1;
        }
    }

    @Test void stepScenario() throws Exception {
        OracleCases.each(M, "stepScenario", a -> {
            Omega tilde = IntentTrajectory.augmentOmega(IntentOmega.omegaFromJson(a.get(0)), mp(a.get(1)), mp(a.get(2)));
            IntentTrajectory.Step s = IntentTrajectory.stepTrajectory(tilde, mp(a.get(1)), ls(a.get(3)), mp(a.get(4)), grant((String) a.get(5)), schemaOf(a, 6));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("admitted", s.admitted());
            out.put("history", s.history());
            out.put("lifted", s.lifted() == null ? null : IntentOmega.outcomeToJson(s.lifted()));
            return out;
        });
    }

    @Test void defaultAccumulators() throws Exception {
        OracleCases.each(M, "defaultAccumulators", a -> {
            Map<String, Object> o = mp(a.get(1));
            return IntentTrajectory.defaultAccumulators(a.get(0), IntentOmega.dbl(o.get("spendDomainMax")), o.get("questionCap") == null ? null : IntentOmega.dbl(o.get("questionCap")), o.get("holder") == null ? null : mp(o.get("holder")));
        });
    }

    @Test void describeAccCell() throws Exception {
        OracleCases.each(M, "describeAccCell", a -> {
            Function<Double, String> fmt = "bracket".equals(a.get(4)) ? x -> "[" + net.atlasauth.pca.AttestCommon.jsNumString(x) + "]" : null;
            return IntentTrajectory.describeAccCell((IntentOmega.NumDim) IntentOmega.dimFromJson(a.get(0)), (int) IntentOmega.dbl(a.get(1)), (String) a.get(2), a.get(3) == null ? null : IntentOmega.dbl(a.get(3)), fmt);
        });
    }
}
