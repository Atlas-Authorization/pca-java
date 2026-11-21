package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentObservation;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentProfile;
import net.atlasauth.pca.intent.IntentStatement;
import org.junit.jupiter.api.Test;

/** Suite signing of the intent artifacts: shape of the signed artifact plus the verdict under the matching pin. */
class IntentSuiteSignDiffTest {
    private static final String M = "ref-intent-suite-sign-java";

    private static Keys.SuiteKey key(List<?> a) {
        String alg = (String) a.get(2);
        Keys.EdKey ed = Keys.edFromSeed(Keys.unb64u((String) a.get(1)));
        if ("ed25519".equals(alg)) return Keys.ed25519(ed);
        Pq.Prim p = alg.endsWith("ml-dsa-87") ? Pq.Prim.ML_DSA_87 : Pq.Prim.ML_DSA_65;
        return Keys.suite(alg, ed, Keys.pqFromSeed(p, Keys.unb64u((String) a.get(3))));
    }

    private static Object len(Object v) { return v instanceof String ? (Object) Integer.valueOf(Keys.unb64u((String) v).length) : null; }

    private static Map<String, Object> shape(Map<String, Object> a, boolean ok) {
        Map<String, Object> rest = new LinkedHashMap<>(a);
        for (String k : new String[] {"sig", "pq_sig", "alg", "pq_pk"}) rest.remove(k);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("alg", a.get("alg"));
        out.put("pq_pk", a.get("pq_pk"));
        out.put("rest", rest);
        out.put("sig_len", len(a.get("sig")));
        out.put("pq_sig_len", len(a.get("pq_sig")));
        out.put("ok", ok);
        return out;
    }

    private static Map<String, Object> pins(Map<String, Object> a, String who) {
        Map<String, Object> p = new LinkedHashMap<>();
        if (a.get("pq_pk") != null) p.put(who, a.get("pq_pk"));
        return p;
    }

    private static boolean ok(Map<String, Object> v) { return Boolean.TRUE.equals(v.get("ok")); }

    @Test void signStatement() throws Exception {
        OracleCases.each(M, "signStatement", a -> {
            Map<String, Object> s = IntentStatement.signIntent(IntentOmega.obj(a.get(0)), key(a));
            return shape(s, ok(IntentStatement.verifyIntent(s, null, pins(s, (String) s.get("principal")))));
        });
    }

    @Test void signObservation() throws Exception {
        OracleCases.each(M, "signObservation", a -> {
            Map<String, Object> s = IntentObservation.signIntentObservation(IntentOmega.obj(a.get(0)), key(a));
            return shape(s, ok(IntentObservation.verifyIntentObservation(s, null, pins(s, (String) s.get("signer")))));
        });
    }

    @Test void signProfile() throws Exception {
        OracleCases.each(M, "signProfile", a -> {
            Map<String, Object> s = IntentProfile.signIntentProfile(IntentOmega.obj(a.get(0)), key(a));
            return shape(s, ok(IntentProfile.verifyIntentProfile(s, pins(s, (String) s.get("owner")))));
        });
    }
}
