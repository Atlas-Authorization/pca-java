package net.atlasauth.pca.intent;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import net.atlasauth.pca.IntentBridge;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * A detached signature over an Intent Map's digest (who vouches for the map: the synthesiser, the principal, ...). Signed under any
 * registry suite; a PQ-suite attestation verifies only under a PQ key the verifier pins.
 */
public final class IntentMapAttestation {
    private IntentMapAttestation() {}

    public static final String INTENT_MAP_SIG_DOMAIN = "atlas-pca/intent-map-sig/v1\0";
    private static final String[] BODY_KEYS = {"v", "map_digest", "intent_ref", "signer", "signed_at"};

    @SuppressWarnings("unchecked")
    private static Map<String, Object> attBody(Map<?, ?> a) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : BODY_KEYS) if (a.containsKey(k)) b.put(k, a.get(k));
        return (Map<String, Object>) IntentJs.normalize(b);
    }

    private static boolean isOne(Object o) { Double d = IntentBridge.num(o); return d != null && d == 1; }

    /** Structural check of an Intent Map (it does not replay the map): the first problem, or null. */
    public static String intentMapShapeError(Object mo) {
        if (!(mo instanceof Map)) return "not an intent map v1";
        Map<?, ?> m = (Map<?, ?>) mo;
        if (!isOne(m.get("v")) || !"pca-intent-map".equals(m.get("kind"))) return "not an intent map v1";
        // an absent intent_ref is neither null nor a digest: refused like any other non-digest
        if (!m.containsKey("intent_ref") || (m.get("intent_ref") != null && Pca.decodeB64uStrict(m.get("intent_ref"), 32) == null))
            return "intent_ref must be null or canonical base64url (32 bytes)";
        if (!(m.get("metrics") instanceof Map)) return "metrics must be an object";
        Map<?, ?> mt = (Map<?, ?>) m.get("metrics");
        Object f = mt.get("fidelity_est_ppm");
        if (!IntentBridge.isInt(f) || IntentBridge.num(f) < 0 || IntentBridge.num(f) > 1_000_000) return "metrics.fidelity_est_ppm must be an integer in [0, 1e6]";
        Object r = mt.get("residual_risk_ppm");
        if (!IntentBridge.isInt(r) || IntentBridge.num(r) < 0) return "metrics.residual_risk_ppm must be a non-negative integer";
        return null;
    }

    /** Signs {@code map}'s digest as the holder of an Ed25519 seed. */
    public static Map<String, Object> signIntentMapAttestation(Map<String, Object> map, byte[] signerSeed, long signedAt) {
        return signIntentMapAttestation(map, Keys.ed25519(Keys.edFromSeed(signerSeed)), signedAt);
    }

    /** Signs under any registry suite (ML-DSA, hybrid, ...): {@code alg} and {@code pq_pk} are signed into the attestation. Throws on a malformed map or timestamp. */
    public static Map<String, Object> signIntentMapAttestation(Map<String, Object> map, Keys.SuiteKey key, long signedAt) {
        String bad = intentMapShapeError(map);
        if (bad != null) throw new IllegalArgumentException("signIntentMapAttestation: " + bad);
        if (signedAt < 0 || signedAt > 9007199254740991L) throw new IllegalArgumentException("signIntentMapAttestation: signedAt must be a non-negative safe integer");
        if (key.ed == null) throw new IllegalArgumentException("signIntentMapAttestation: signer needs an Ed25519 identity key");
        Map<String, Object> in = new LinkedHashMap<>();
        in.put("v", 1L);
        in.put("map_digest", IntentMapKit.intentMapDigest(map));
        in.put("intent_ref", map.get("intent_ref"));
        in.put("signer", key.ed.id());
        in.put("signed_at", signedAt);
        Map<String, Object> body = attBody(in);
        return IntentBridge.signSuite(body, key, b -> IntentBridge.message(INTENT_MAP_SIG_DOMAIN, b));
    }

    private static Map<String, Object> verdict(String reason) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("ok", reason == null);
        if (reason != null) r.put("reason", reason);
        return r;
    }

    public static Map<String, Object> verifyIntentMapAttestation(Object a) { return verifyIntentMapAttestation(a, false, null, null, null); }

    /**
     * {ok: true} or {ok: false, reason}: well formed, signature valid and, when {@code checkMap}, the digest and intent_ref of {@code map} match.
     * {@code expectedSigner} (nullable) pins the signer; {@code pqPins} maps a signer to the PQ key the verifier pins for it. Never throws.
     */
    public static Map<String, Object> verifyIntentMapAttestation(Object ao, boolean checkMap, Object map, String expectedSigner, Map<String, Object> pqPins) {
        try {
            if (!(ao instanceof Map) || !isOne(((Map<?, ?>) ao).get("v"))) return verdict("not an intent map attestation v1");
            Map<?, ?> at = (Map<?, ?>) ao;
            if (Pca.decodeB64uStrict(at.get("map_digest"), 32) == null) return verdict("map_digest is not canonical base64url (32 bytes)");
            if (!at.containsKey("intent_ref") || (at.get("intent_ref") != null && Pca.decodeB64uStrict(at.get("intent_ref"), 32) == null)) return verdict("intent_ref must be null or canonical base64url (32 bytes)");
            if (Pca.decodeB64uStrict(at.get("signer"), 32) == null) return verdict("signer is not canonical base64url (32 bytes)");
            if (!IntentBridge.isInt(at.get("signed_at")) || IntentBridge.num(at.get("signed_at")) < 0) return verdict("signed_at must be a non-negative safe integer");
            if (expectedSigner != null && !expectedSigner.equals(at.get("signer"))) return verdict("signer mismatch");
            boolean algPresent = at.containsKey("alg");
            String suite = IntentBridge.suiteName(at.get("alg"), algPresent);
            if (suite == null) return verdict("unknown signature suite");
            if (suite.equals("ed25519") && (at.containsKey("pq_pk") || at.containsKey("pq_sig"))) return verdict("an ed25519 artifact must not carry pq_pk / pq_sig");
            if (checkMap) {
                String bad = intentMapShapeError(map);
                if (bad != null) return verdict(bad);
                if (!IntentMapKit.intentMapDigest(map).equals(at.get("map_digest"))) return verdict("map digest mismatch");
                if (!Objects.equals(((Map<?, ?>) map).get("intent_ref"), at.get("intent_ref"))) return verdict("intent_ref mismatch");
            }
            Map<String, Object> body = IntentBridge.bindSuiteFields(attBody(at), at.get("alg"), algPresent, at.get("pq_pk"), at.containsKey("pq_pk"));
            byte[] msg = IntentBridge.message(INTENT_MAP_SIG_DOMAIN, body);
            if (!IntentBridge.verifyPinnedSuite(at.get("alg"), algPresent, (String) at.get("signer"), at.get("pq_pk"), msg, at.get("sig"), at.get("pq_sig"), pqPins)) return verdict("bad signature");
            return verdict(null);
        } catch (RuntimeException e) {
            return verdict("malformed intent map attestation: " + e.getMessage());
        }
    }
}
