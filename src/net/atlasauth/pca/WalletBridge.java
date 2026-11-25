package net.atlasauth.pca;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Public entry points to core rules that the wallet package (net.atlasauth.pca.wallet) needs and that are package-private in
 * the core: strict Ed25519 over base64url, the strict domain message, the coordinate shape rule and the verification of a
 * site-signed {@code pca-intent-required} body (intent-required.ts {@code verifyIntentRequired}).
 */
public final class WalletBridge {
    private WalletBridge() {}

    /** Strict Ed25519 over a base64url public key and signature; false on any malformed input. */
    public static boolean verifyEd(String pub, byte[] msg, String sig) { return Pca.verifyB64u(pub, msg, sig); }

    /** {@code utf8(domain) || strictCanonical(body)}. */
    public static byte[] message(String domain, Object body) { return IntentJs.message(domain, body); }

    /** {@code cellCoordsError}: null when the coordinates are well formed. */
    public static String cellCoordsError(Object coords) { return SignersMore.cellCoordsError(coords); }

    private static final List<String> BODY_KEYS = Arrays.asList("v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest",
        "cell", "reason", "question_id", "friction", "delivered_to", "expires_at", "sig");
    private static final Pattern QID = Pattern.compile("[A-Za-z0-9_-]{1,64}");

    /** The signed-body shape check of the reference's {@code intentRequiredShapeError}; null when well formed. */
    static String signedShapeError(Object bO) {
        if (!(bO instanceof Map)) return "not an object";
        Map<?, ?> b = (Map<?, ?>) bO;
        for (Object k : b.keySet()) if (!BODY_KEYS.contains(k)) return "unknown member '" + k + "'";
        if (!OracleFacts.isOne(b.get("v")) || !"pca-intent-required".equals(b.get("kind"))) return "not a pca-intent-required v1";
        for (String k : new String[] {"session", "map_digest", "schema", "pcactn_digest", "action_digest"})
            if (!IntentJs.b32(b.get(k))) return k + " must be canonical base64url (32 bytes)";
        Object cell = b.get("cell");
        if (!(cell instanceof Map) || ((Map<?, ?>) cell).size() != 2 || !((Map<?, ?>) cell).containsKey("coords") || !(((Map<?, ?>) cell).get("verb") instanceof String)
            || ((String) ((Map<?, ?>) cell).get("verb")).isEmpty()) return "cell must be {verb, coords}";
        String ce = SignersMore.cellCoordsError(((Map<?, ?>) cell).get("coords"));
        if (ce != null) return ce;
        if (!"uncertain".equals(b.get("reason"))) return "reason must be 'uncertain'";
        if (!(b.get("question_id") instanceof String) || !QID.matcher((String) b.get("question_id")).matches()) return "question_id must match [A-Za-z0-9_-]{1,64}";
        if (!Arrays.asList("tap", "hold", "typed", "device").contains(b.get("friction"))) return "unknown friction tier";
        if (!"wallet".equals(b.get("delivered_to")) && !"agent".equals(b.get("delivered_to"))) return "delivered_to must be 'wallet' or 'agent'";
        if (!IntentJs.isNonNeg(b.get("expires_at"))) return "expires_at must be a non-negative safe integer";
        Object s = b.get("sig");
        if (s instanceof Map) {
            Map<?, ?> sm = (Map<?, ?>) s;
            String se = IntentJs.suiteError(sm.get("alg"), sm.containsKey("alg"));
            if (se != null) return "sig.alg: " + se;
            if (sm.containsKey("pq_value") && sm.get("pq_value") != null && !(sm.get("pq_value") instanceof String)) return "sig.pq_value must be a string";
        }
        boolean okSig = s instanceof Map;
        if (okSig) {
            Map<?, ?> sm = (Map<?, ?>) s;
            for (Object k : sm.keySet()) if (!Arrays.asList("alg", "kid", "value", "pq_value").contains(k)) okSig = false;
            if (Pq.resolveSigAlg(sm.get("alg"), sm.containsKey("alg")) == null || !(sm.get("kid") instanceof String) || !(sm.get("value") instanceof String)) okSig = false;
        }
        if (!okSig) return "sig must be {alg, kid, value, pq_value?}";
        return null;
    }

    /**
     * Verify a site-signed intent_required body against the site's discovery keys at {@code now}: null when valid, else the
     * reason. The clock must be a safe integer (fail closed).
     */
    @SuppressWarnings("unchecked")
    public static String verifyIntentRequired(Object b, Object keys, Object now) {
        try {
            if (!IntentJs.isSafeInteger(now)) return "the verifier clock is not a safe integer (fail closed)";
            String e = signedShapeError(b);
            if (e != null) return e;
            Map<String, Object> s = (Map<String, Object>) b;
            Map<String, Object> sig = (Map<String, Object>) s.get("sig");
            if (!(keys instanceof List)) return "the site keys must be an array";
            Map<String, Object> key = null;
            for (Object k : (List<?>) keys) if (k instanceof Map && sig.get("kid").equals(((Map<?, ?>) k).get("kid"))) { key = (Map<String, Object>) k; break; }
            if (key == null) return "no site key with kid '" + sig.get("kid") + "'";
            String kse = IntentJs.suiteError(key.get("alg"), key.containsKey("alg"));
            if (kse != null) return "site key: " + kse;
            String ka = IntentJs.suiteOf(key);
            String sa = IntentJs.suiteOf(sig);
            if (ka == null || !ka.equals(sa)) return "sig.alg does not match the pinned key suite";
            Object pk = key.get("pk");
            Map<String, Object> pin = key.containsKey("pq_pk") && key.get("pq_pk") != null ? IntentJs.pin((String) pk, key.get("pq_pk")) : null;
            Map<String, Object> body = new java.util.LinkedHashMap<>(s);
            body.remove("sig");
            byte[] msg = IntentJs.message(SignersMore.INTENT_REQUIRED_DOMAIN, body);
            if (!IntentJs.verifyPinnedSuite(ka, true, (String) pk, key.get("pq_pk"), msg, sig.get("value"), sig.get("pq_value"), pin)) return "site signature invalid";
            if (!(IntentJs.num(now) <= IntentJs.num(s.get("expires_at")))) return "the question has expired";
            return null;
        } catch (RuntimeException err) {
            return "malformed intent_required: " + err.getMessage();
        }
    }
}
