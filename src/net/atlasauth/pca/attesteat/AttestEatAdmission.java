package net.atlasauth.pca.attesteat;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * EAT evidence for blueprint admission (port of {@code admission.ts}): turns an EAT (RFC 9711) into admission evidence for ONE instance key.
 * The token's signature, issuer, freshness (the server-issued nonce) and RATS appraisal must all pass and its {@code cnf.jkt} must be the
 * RFC 7638 thumbprint of the instance key, so evidence for one instance cannot admit another. The identity returned is the measured identity
 * the verifier established, never a field the instance supplies separately.
 */
public final class AttestEatAdmission {
    private AttestEatAdmission() {}

    /** RFC 7638 thumbprint (base64url SHA-256) of an Ed25519 public key given as unpadded base64url. */
    public static String ed25519Jkt(String holderPubB64u) {
        String canonical = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + holderPubB64u + "\"}";
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(Json.utf8(canonical)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static int rank(Object tier) {
        if ("rejected".equals(tier) || "contraindicated".equals(tier)) return 0;
        if ("warning".equals(tier)) return 1;
        if ("affirming".equals(tier)) return 2;
        if ("affirming-hw-rooted".equals(tier)) return 3;
        return -1;
    }

    private static Map<String, Object> result(boolean ok, boolean bound, String reason, Map<String, Object> identity) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        m.put("bound", bound);
        if (identity != null) m.put("identity", identity);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    /**
     * {@code o}: the {@link AttestEat#verifyFreshAttestedEAT} options (verifyKey, amd?, now?, maxAgeMs?, ...) plus nonce, instanceKey, policy and
     * {@code minTier} ({@code affirming} default, or {@code affirming-hw-rooted}). Result {ok, bound, identity?, reason?}; anything
     * unverifiable is {@code ok: false}. (Any unexpected failure reports the reason {@code TypeError}, the reference's error name.)
     */
    public static Map<String, Object> eatAdmissionEvidence(Object eat, Map<String, Object> o) {
        try {
            // An unknown tier has no rank: refuse it before verification instead of admitting any tier.
            if (o.containsKey("minTier") && !"affirming".equals(o.get("minTier")) && !"affirming-hw-rooted".equals(o.get("minTier"))) return result(false, false, "invalid minTier", null);
            Map<String, Object> rest = new LinkedHashMap<>(o);
            rest.remove("instanceKey");
            rest.remove("minTier");
            Object ik = o.get("instanceKey");
            Map<String, Object> cb = new LinkedHashMap<>();
            cb.put("jkt", ed25519Jkt(ik instanceof String ? (String) ik : String.valueOf(ik)));
            rest.put("channelBinding", cb);
            Map<String, Object> v = AttestEat.verifyFreshAttestedEAT(eat, rest);
            if (!Boolean.TRUE.equals(v.get("ok")) || v.get("tier") == null) {
                List<?> rs = (List<?>) v.get("reasons");
                return result(false, false, rs.isEmpty() ? "EAT rejected" : String.valueOf(rs.get(rs.size() - 1)), null);
            }
            Object minTier = o.containsKey("minTier") ? o.get("minTier") : "affirming";
            if (!(rank(v.get("tier")) >= rank(minTier))) return result(false, true, "appraisal tier " + v.get("tier") + " is below the minimum", null);
            Object claims = v.get("claims");
            Map<String, Object> m = claims instanceof Map ? AttestEat.rec(((Map<?, ?>) claims).get("measured")) : null;
            if (m == null) return result(true, true, null, null);
            Map<String, Object> id = new LinkedHashMap<>();
            for (String k : new String[] {"runtime_measurement", "model_id", "weights_digest", "operator"}) id.put(k, m.get(k));
            return result(true, true, null, id);
        } catch (RuntimeException e) {
            return result(false, false, "TypeError", null);
        }
    }
}
