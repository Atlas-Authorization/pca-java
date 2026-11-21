package net.atlasauth.pca.intent;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.IntentBridge;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * A signed runtime observation against an Intent Map: y = 0 says the outcome should NOT have been allowed (a divergence), y = 1 confirms it.
 * Signed by whoever observed it (Ed25519; a PQ-suite artifact verifies only under a PQ key the verifier pins).
 */
public final class IntentObservation {
    private IntentObservation() {}

    public static final String INTENT_OBS_SIG_DOMAIN = "atlas-pca/intent-obs/v1\0";
    public static final List<String> INTENT_OBSERVATION_SOURCES = List.of("runtime", "witness", "elicitation", "import");
    private static final String[] BODY_KEYS = {"v", "map_digest", "verb", "values", "y", "source", "observed_at", "pcactn_digest", "signer"};

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obsBody(Map<?, ?> o) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : BODY_KEYS) if (o.containsKey(k)) b.put(k, o.get(k));
        return (Map<String, Object>) IntentJs.normalize(b);
    }

    private static boolean isNum(Object o, double v) { Double d = IntentBridge.num(o); return d != null && d == v; }

    /** The first shape problem of an observation, or null. */
    static String obsShapeError(Object oo) {
        if (!(oo instanceof Map) || !isNum(((Map<?, ?>) oo).get("v"), 1)) return "not an intent observation v1";
        Map<?, ?> o = (Map<?, ?>) oo;
        if (Pca.decodeB64uStrict(o.get("map_digest"), 32) == null) return "map_digest is not canonical base64url (32 bytes)";
        if (!(o.get("verb") instanceof String) || ((String) o.get("verb")).isEmpty()) return "verb must be a non-empty string";
        boolean ok = o.get("values") instanceof Map;
        if (ok) {
            for (Object x : ((Map<?, ?>) o.get("values")).values()) {
                Double d = IntentBridge.num(x);
                if (!(x instanceof String) && !(d != null && Double.isFinite(d))) ok = false;
            }
        }
        if (!ok) return "values must map paths to numbers or strings";
        if (!isNum(o.get("y"), 0) && !isNum(o.get("y"), 1)) return "y must be 0 or 1";
        if (!(o.get("source") instanceof String) || !INTENT_OBSERVATION_SOURCES.contains(o.get("source"))) return "unknown observation source";
        if (!IntentBridge.isInt(o.get("observed_at")) || IntentBridge.num(o.get("observed_at")) < 0) return "observed_at must be a non-negative safe integer";
        if (o.containsKey("pcactn_digest") && Pca.decodeB64uStrict(o.get("pcactn_digest"), 32) == null) return "pcactn_digest is not canonical base64url (32 bytes)";
        if (Pca.decodeB64uStrict(o.get("signer"), 32) == null) return "signer is not canonical base64url (32 bytes)";
        return null;
    }

    /** Sign an observation ({map_digest, verb, values, y, source, observed_at, pcactn_digest?}) as the holder of an Ed25519 seed. */
    public static Map<String, Object> signIntentObservation(Map<String, Object> o, byte[] signerSeed) {
        return signIntentObservation(o, Keys.ed25519(Keys.edFromSeed(signerSeed)));
    }

    /** Sign under any registry suite (ML-DSA, hybrid, ...): {@code alg} and {@code pq_pk} are signed into the observation. */
    public static Map<String, Object> signIntentObservation(Map<String, Object> o, Keys.SuiteKey key) {
        if (key.ed == null) throw new IllegalArgumentException("signIntentObservation: signer needs an Ed25519 identity key");
        Map<String, Object> in = new LinkedHashMap<>(o);
        in.put("v", 1L);
        in.put("signer", key.ed.id());
        Map<String, Object> body = obsBody(in);
        String bad = obsShapeError(body);
        if (bad != null) throw new IllegalArgumentException("signIntentObservation: " + bad);
        return IntentBridge.signSuite(body, key, b -> IntentBridge.message(INTENT_OBS_SIG_DOMAIN, b));
    }

    private static Map<String, Object> verdict(String reason) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("ok", reason == null);
        if (reason != null) r.put("reason", reason);
        return r;
    }

    public static Map<String, Object> verifyIntentObservation(Object o) { return verifyIntentObservation(o, null, null); }

    /** {ok: true} or {ok: false, reason}. Never throws. */
    public static Map<String, Object> verifyIntentObservation(Object oo, String expectedSigner, Map<String, Object> pqPins) {
        try {
            String bad = obsShapeError(oo);
            if (bad != null) return verdict(bad);
            Map<?, ?> ob = (Map<?, ?>) oo;
            if (expectedSigner != null && !expectedSigner.equals(ob.get("signer"))) return verdict("signer mismatch");
            boolean algPresent = ob.containsKey("alg");
            String suite = IntentBridge.suiteName(ob.get("alg"), algPresent);
            if (suite == null) return verdict("unknown signature suite");
            if (suite.equals("ed25519") && (ob.containsKey("pq_pk") || ob.containsKey("pq_sig"))) return verdict("an ed25519 artifact must not carry pq_pk / pq_sig");
            Map<String, Object> body = IntentBridge.bindSuiteFields(obsBody(ob), ob.get("alg"), algPresent, ob.get("pq_pk"), ob.containsKey("pq_pk"));
            byte[] msg = IntentBridge.message(INTENT_OBS_SIG_DOMAIN, body);
            if (!IntentBridge.verifyPinnedSuite(ob.get("alg"), algPresent, (String) ob.get("signer"), ob.get("pq_pk"), msg, ob.get("sig"), ob.get("pq_sig"), pqPins)) return verdict("bad signature");
            return verdict(null);
        } catch (RuntimeException e) {
            return verdict("malformed intent observation: " + e.getMessage());
        }
    }
}
