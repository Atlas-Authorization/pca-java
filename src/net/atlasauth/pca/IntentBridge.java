package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/** Public entry points to the package-private suite and number helpers of the intent artifacts, for the intent package port. */
public final class IntentBridge {
    private IntentBridge() {}

    /** The suite an {@code alg} resolves to ("ed25519" when absent), or null when this SDK does not implement it. */
    public static String suiteName(Object alg, boolean algPresent) {
        Pq.Suite s = Pq.resolveSigAlg(alg, algPresent);
        return s == null ? null : s.alg;
    }

    public static boolean verifyPinnedSuite(Object alg, boolean algPresent, String identity, Object artifactPqPk, byte[] msg, Object sig, Object pqSig, Map<String, Object> pqPins) {
        return IntentJs.verifyPinnedSuite(alg, algPresent, identity, artifactPqPk, msg, sig, pqSig, pqPins);
    }

    public static Map<String, Object> bindSuiteFields(Map<String, Object> base, Object alg, boolean algPresent, Object pqPk, boolean pqPresent) {
        return IntentJs.bindSuiteFields(base, alg, algPresent, pqPk, pqPresent);
    }

    /** {@code Number.isSafeInteger(v) && !Object.is(v, -0)} for a JSON number. */
    public static boolean isInt(Object v) { return IntentJs.isInt(v); }

    /** The binary64 value of a JSON number, else null. */
    public static Double num(Object v) { return IntentJs.num(v); }

    /** {@code utf8(domain) || strictCanonical(body)}. */
    public static byte[] message(String domain, Object body) { return IntentJs.message(domain, body); }

    /** Strict Ed25519 under a b64u key; a malformed key or signature is a failed signature. */
    public static boolean verifyEd(Object pub, byte[] msg, Object sig) { return IntentJs.verifyEd(pub, msg, sig); }

    /**
     * Sign {@code body} under {@code key}'s suite: the message is {@code msg(bound)} where a non-ed25519 suite binds {@code alg} and
     * {@code pq_pk} into the signed body; the result is {@code body} plus {@code sig} (and {@code alg}, {@code pq_pk}, {@code pq_sig}
     * when the suite has them). The key must carry an Ed25519 identity (the artifact's principal).
     */
    public static Map<String, Object> signSuite(Map<String, Object> body, Keys.SuiteKey key, Function<Map<String, Object>, byte[]> msg) {
        if (key.ed == null) throw new IllegalArgumentException("signer needs an Ed25519 identity key");
        Map<String, Object> bound = new LinkedHashMap<>(body);
        boolean plain = "ed25519".equals(key.alg);
        if (!plain) {
            bound.put("alg", key.alg);
            bound.put("pq_pk", key.pqPk());
        }
        String[] sg = key.sign(msg.apply(bound));
        Map<String, Object> out = new LinkedHashMap<>(bound);
        out.put("sig", sg[0]);
        if (sg[1] != null) out.put("pq_sig", sg[1]);
        return out;
    }
}
