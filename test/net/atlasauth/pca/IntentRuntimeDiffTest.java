package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentEffects;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;
import net.atlasauth.pca.intent.IntentRamp;
import net.atlasauth.pca.intent.IntentRuntime;
import net.atlasauth.pca.intent.IntentUx;
import org.junit.jupiter.api.Test;

class IntentRuntimeDiffTest {
    private static final String M = "ref-intent-runtime";

    private static Map<String, Object> map(Object o) { return IntentOmega.obj(o); }

    private static double d(Object o) { return IntentOmega.dbl(o); }

    private static VerbSpace vs(Object o) { return IntentOmega.verbSpaceFromJson(o); }

    private static Outcome out(Object o) { return IntentOmega.outcomeFromJson(o); }

    private static int[] idx(Object o) {
        List<?> l = (List<?>) o;
        int[] a = new int[l.size()];
        for (int k = 0; k < a.length; k++) a[k] = (int) d(l.get(k));
        return a;
    }

    private static VerbSpace verbOf(Object omega, Outcome o) { return IntentOmega.verbSpace(IntentOmega.omegaFromJson(omega), o.verb()); }

    @Test void pcactnActionOf() throws Exception { OracleCases.each(M, "pcactnActionOf", a -> IntentRuntime.pcactnActionOf(vs(a.get(0)), out(a.get(1)))); }

    @Test void judgeInputOf() throws Exception {
        OracleCases.each(M, "judgeInputOf", a -> {
            Outcome o = out(a.get(1));
            return IntentRuntime.judgeInputOf(verbOf(a.get(0), o), o, d(a.get(2)), map(a.get(3)));
        });
    }

    @Test void jitConsentRequest() throws Exception {
        OracleCases.each(M, "jitConsentRequest", a -> {
            Outcome o = out(a.get(1));
            Map<String, Object> c = map(a.get(3));
            return IntentRuntime.jitConsentRequest(verbOf(a.get(0), o), o, d(a.get(2)), (String) c.get("intentRef"), (String) c.get("mapDigest"));
        });
    }

    @Test void jitConsentDigest() throws Exception { OracleCases.each(M, "jitConsentDigest", a -> IntentRuntime.jitConsentDigest(a.get(0))); }

    @Test void calibrationDigest() throws Exception { OracleCases.each(M, "calibrationDigest", a -> IntentRuntime.calibrationDigest(map(a.get(0)))); }

    @Test void icAttDigest() throws Exception { OracleCases.each(M, "icAttDigest", a -> IntentRuntime.icAttDigest(a.get(0))); }

    @Test void foldSemanticRisk() throws Exception { OracleCases.each(M, "foldSemanticRisk", a -> IntentRuntime.foldSemanticRisk(d(a.get(0)), map(a.get(1)))); }

    @Test void defaultPostconditions() throws Exception { OracleCases.each(M, "defaultPostconditions", a -> IntentEffects.DEFAULT_POSTCONDITIONS); }

    @Test void effectContext() throws Exception { OracleCases.each(M, "effectContext", a -> IntentEffects.effectContext(vs(a.get(0)), out(a.get(1)), map(a.get(2)))); }

    @Test void checkPostconditions() throws Exception {
        OracleCases.each(M, "checkPostconditions", a -> a.size() > 3
            ? IntentEffects.checkPostconditions(vs(a.get(0)), out(a.get(1)), map(a.get(2)), (List<?>) a.get(3))
            : IntentEffects.checkPostconditions(vs(a.get(0)), out(a.get(1)), map(a.get(2))));
    }

    @Test void signalLabel() throws Exception { OracleCases.each(M, "signalLabel", a -> IntentRamp.signalLabel((String) a.get(0))); }

    @Test void narrowStart() throws Exception {
        OracleCases.each(M, "narrowStart", a -> {
            Map<String, Object> o = map(a.get(2));
            return IntentRamp.narrowStart(IntentOmega.omegaFromJson(a.get(0)), a.get(1), o.containsKey("slotNullMass") ? d(o.get("slotNullMass")) : null,
                o.containsKey("otherNullMass") ? d(o.get("otherNullMass")) : null);
        });
    }

    @Test void driftRun() throws Exception {
        OracleCases.each(M, "driftRun", a -> {
            Map<String, Object> o = map(a.get(0));
            IntentRamp.DriftDetector dd = new IntentRamp.DriftDetector(o.containsKey("rho0") ? d(o.get("rho0")) : null, o.containsKey("rho1") ? d(o.get("rho1")) : null,
                o.containsKey("h") ? d(o.get("h")) : null);
            List<Object> states = new ArrayList<>();
            for (Object x : (List<?>) a.get(1)) states.add(dd.update((Boolean) x).toJson());
            states.add(dd.state().toJson());
            dd.reset();
            states.add(dd.state().toJson());
            return states;
        });
    }

    @Test void questionCard() throws Exception {
        OracleCases.each(M, "questionCard", a -> {
            Map<String, Object> q = map(a.get(1));
            return IntentUx.questionCard(IntentOmega.omegaFromJson(a.get(0)), (String) q.get("verb"), idx(q.get("cell")));
        });
    }

    @Test void parseCardAnswer() throws Exception { OracleCases.each(M, "parseCardAnswer", a -> IntentUx.parseCardAnswer(a.get(0), a.get(1))); }
}
