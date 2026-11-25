package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentLayers;
import net.atlasauth.pca.intent.IntentMetrics;
import net.atlasauth.pca.intent.IntentMulti;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentPolicy;
import org.junit.jupiter.api.Test;

class IntentLayersDiffTest {
    private static final String M = "ref-intent-layers";

    private static Map<String, Object> map(Object o) { return IntentOmega.obj(o); }

    private static List<String> strs(Object o) {
        List<String> out = new ArrayList<>();
        for (Object x : IntentOmega.arr(o)) out.add((String) x);
        return out;
    }

    private static boolean[] bools(Object o) {
        List<Object> l = IntentOmega.arr(o);
        boolean[] b = new boolean[l.size()];
        for (int i = 0; i < b.length; i++) b[i] = (Boolean) l.get(i);
        return b;
    }

    private static double[] dbls(Object o) {
        List<Object> l = IntentOmega.arr(o);
        double[] b = new double[l.size()];
        for (int i = 0; i < b.length; i++) b[i] = IntentOmega.dbl(l.get(i));
        return b;
    }

    @Test void normalizeRule() throws Exception { OracleCases.each(M, "normalizeRule", a -> IntentMulti.normalizeRule(map(a.get(0)), strs(a.get(1))).toJson()); }

    @Test void effectiveVetoers() throws Exception { OracleCases.each(M, "effectiveVetoers", a -> IntentMulti.effectiveVetoers(map(a.get(0)), strs(a.get(1)))); }

    @Test void ruleAdmits() throws Exception { OracleCases.each(M, "ruleAdmits", a -> IntentMulti.ruleAdmits(IntentMulti.NormalRule.fromJson(a.get(0)), bools(a.get(1)))); }

    @Test void jointAcceptance() throws Exception { OracleCases.each(M, "jointAcceptance", a -> IntentMulti.jointAcceptance(IntentMulti.NormalRule.fromJson(a.get(0)), dbls(a.get(1)))); }

    @Test void commonRefinement() throws Exception {
        OracleCases.each(M, "commonRefinement", a -> {
            List<IntentOmega.Omega> oms = new ArrayList<>();
            for (Object o : IntentOmega.arr(a.get(0))) oms.add(IntentOmega.omegaFromJson(o));
            return IntentOmega.omegaToJson(IntentMulti.commonRefinement(oms));
        });
    }

    @Test void ceilingOf() throws Exception {
        OracleCases.each(M, "ceilingOf", a -> IntentLayers.ceilingOf(IntentLayers.ceilingAdmitters(map(a.get(0))), IntentOmega.verbSpaceFromJson(a.get(1)), IntentOmega.outcomeFromJson(a.get(2))));
    }

    @Test void assertAskable() throws Exception {
        OracleCases.each(M, "assertAskable", a -> {
            IntentLayers.assertAskable(map(a.get(0)), map(a.get(1)));
            return null;
        });
    }

    @Test void layerCells() throws Exception { OracleCases.each(M, "layerCells", a -> IntentLayers.layerCells(IntentOmega.omegaFromJson(a.get(0)), IntentPolicy.admitter(a.get(1)))); }

    @SuppressWarnings("unchecked")
    @Test void ownerRisk() throws Exception {
        OracleCases.each(M, "ownerRisk", a -> IntentLayers.ownerRisk(IntentOmega.omegaFromJson(a.get(0)), (List<Map<String, Object>>) a.get(1), IntentMetrics.acceptabilityOf(a.get(2)), IntentOmega.DEFAULT_HARM));
    }

    @Test void cellKeyOf() throws Exception { OracleCases.each(M, "cellKeyOf", a -> IntentLayers.cellKeyOf(IntentOmega.omegaFromJson(a.get(0)), map(a.get(1)))); }

    @Test void signLayerApproval() throws Exception { OracleCases.each(M, "signLayerApproval", a -> IntentLayers.signLayerApproval(map(a.get(0)), Keys.unb64u((String) a.get(1)))); }

    @Test void verifyQuorumApprovals() throws Exception {
        OracleCases.each(M, "verifyQuorumApprovals", a -> IntentLayers.verifyQuorumApprovals(a.get(0), a.get(1), map(a.get(2)), a.get(3)));
    }

    @Test void measureGrantExact() throws Exception {
        OracleCases.each(M, "measureGrantExact", a -> IntentMetrics.measureGrantExact(IntentOmega.omegaFromJson(a.get(0)), a.get(1), IntentMetrics.acceptabilityOf(a.get(2))).toJson());
    }

    @Test void measureGrant() throws Exception {
        OracleCases.each(M, "measureGrant", a -> {
            Map<String, Object> opts = map(a.get(3));
            double samples = opts.containsKey("samples") ? IntentOmega.dbl(opts.get("samples")) : 20000;
            double seed = opts.containsKey("seed") ? IntentOmega.dbl(opts.get("seed")) : 1;
            Double hMax = opts.containsKey("hMax") ? IntentOmega.dbl(opts.get("hMax")) : null;
            return IntentMetrics.measureGrant(IntentOmega.omegaFromJson(a.get(0)), a.get(1), IntentMetrics.acceptabilityOf(a.get(2)), samples, seed, IntentOmega.DEFAULT_HARM, hMax).toJson();
        });
    }
}
