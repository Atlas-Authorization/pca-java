package net.atlasauth.pca.goal;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.IntentBridge;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Keys;

/**
 * The one signer of the goal-to-decision flow: approvals, test sets, policy pins and precedents are artifacts signed with the
 * suite-agile artifact signer under a per-kind domain, over strict canonical bytes.
 */
public final class GoalSign {
    private GoalSign() {}

    /** Domain separation: an artifact of one kind never verifies as another kind. */
    public static String goalDomain(String kind) { return "atlas-pca/goal/" + kind + "/v1\0"; }

    /** The pinned public identity (b64u Ed25519) of a signing key. */
    public static String signerId(Keys.EdKey key) { return key.id(); }

    /** The pinned public identity of a 32-byte Ed25519 seed. */
    public static String signerId(byte[] seed) { return Keys.edFromSeed(seed).id(); }

    /** Sign a flat artifact body (it must already carry its signer identity member). Throws on a non-canonical body. */
    public static Map<String, Object> signGoalArtifact(String kind, Map<String, Object> body, Keys.SuiteKey signer) {
        return Issue.signArtifact(goalDomain(kind), body, signer);
    }

    public static Map<String, Object> signGoalArtifact(String kind, Map<String, Object> body, byte[] seed) {
        return signGoalArtifact(kind, body, Keys.ed25519(Keys.edFromSeed(seed)));
    }

    /** Suite capability and shape of an artifact's suite members; null = usable. */
    static String artifactSuiteError(Map<String, Object> a) {
        String suite = IntentBridge.suiteName(a.get("alg"), a.containsKey("alg"));
        if (suite == null) return "unsupported_suite";
        for (String k : new String[] {"pq_pk", "pq_sig"}) if (a.containsKey(k) && !(a.get(k) instanceof String)) return k + " must be a string";
        if (suite.equals("ed25519") && (a.containsKey("pq_pk") || a.containsKey("pq_sig"))) return "an ed25519 artifact must not carry pq_pk / pq_sig";
        return null;
    }

    /**
     * Verify a signed artifact against the caller's PINNED signers (each a b64u key String or a Map {pk, pq_pk}): the pin whose
     * {@code pk} equals the artifact's own {@code signerField} member must verify. Total: false on anything malformed.
     */
    public static boolean verifyGoalArtifact(String kind, Object artifact, String signerField, List<?> pins) {
        try {
            Map<String, Object> a = G.m(artifact);
            if (a == null) return false;
            if (artifactSuiteError(a) != null) return false;
            Object who = a.get(signerField);
            if (!(who instanceof String)) return false;
            Object pin = null;
            boolean found = false;
            for (Object p : pins) {
                Object pk = p instanceof String ? p : G.get(p, "pk");
                if (who.equals(pk)) { pin = p; found = true; break; }
            }
            if (!found) return false;
            return verifyArtifactSig(goalDomain(kind), a, pin);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * The artifact's signature under a PINNED signer (a b64u key String or a Map {pk, pq_pk?}); the caller has checked the
     * suite members. Ed25519 under {@code pk}; any other suite only when the artifact's {@code pq_pk} equals the pin's. Total.
     */
    public static boolean verifyArtifactSig(String domain, Map<String, Object> a, Object pin) {
        try {
            Object pk = pin instanceof String ? pin : G.get(pin, "pk");
            if (!(a.get("sig") instanceof String) || !(pk instanceof String)) return false;
            Object pinPq = pin instanceof Map ? ((Map<?, ?>) pin).get("pq_pk") : null;
            Map<String, Object> body = new LinkedHashMap<>(a);
            body.remove("sig");
            body.remove("pq_sig");
            Map<String, Object> pqPins = pinPq instanceof String ? G.map((String) pk, pinPq) : null;
            return IntentBridge.verifyPinnedSuite(a.get("alg"), a.containsKey("alg"), (String) pk, a.get("pq_pk"),
                IntentBridge.message(domain, body), a.get("sig"), a.get("pq_sig"), pqPins);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** A payload wrapped with its kind and signer: the envelope used by tests, pins and precedents. */
    public static Map<String, Object> signPayload(String kind, Object payload, Keys.EdKey key, Keys.SuiteKey suite) {
        return signGoalArtifact(kind, G.map("v", G.num(1), "kind", kind, "signer", key.id(), "payload", payload), suite);
    }

    public static Map<String, Object> signPayload(String kind, Object payload, byte[] seed) {
        Keys.EdKey key = Keys.edFromSeed(seed);
        return signPayload(kind, payload, key, Keys.ed25519(key));
    }

    public static boolean verifyPayload(Map<String, Object> s, String kind, List<?> pins) {
        return s != null && Long.valueOf(1).equals(G.safeInt(s.get("v"))) && kind.equals(s.get("kind")) && verifyGoalArtifact(kind, s, "signer", pins);
    }
}
