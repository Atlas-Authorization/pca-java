package net.atlasauth.pca.intent;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.IntentBridge;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * Intent capture and commitment: the principal's own words plus their structured reading, with provenance pointers, signed by the
 * principal (Ed25519; a PQ-suite artifact verifies only under a PQ key the verifier pins). {@code intentRef} is the content address a
 * grant binds to through the intent goal string.
 */
public final class IntentStatement {
    private IntentStatement() {}

    public static final String INTENT_SIG_DOMAIN = "atlas-pca/intent/v1\0";
    public static final String INTENT_REF_DOMAIN = "atlas-pca/intent-ref/v1";
    public static final String INTENT_GOAL_PREFIX = "pca-intent:v1:";
    public static final List<String> INTENT_SOURCE_KINDS = List.of("conversation", "ticket", "document", "form", "other");

    private static final String[] BODY_KEYS = {"v", "principal", "text", "slots", "sources", "created_at", "nonce"};

    private static Map<String, Object> statementBody(Map<?, ?> s) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : BODY_KEYS) if (s.containsKey(k)) b.put(k, s.get(k));
        @SuppressWarnings("unchecked")
        Map<String, Object> n = (Map<String, Object>) IntentJs.normalize(b);
        return n;
    }

    /** Content address of a statement: suite fields and signatures excluded. */
    public static String intentRef(Object s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", INTENT_REF_DOMAIN);
        m.put("s", statementBody((Map<?, ?>) s));
        return Pca.hashCanonical(m);
    }

    private static boolean isObj(Object o) { return o instanceof Map; }

    /** The first shape problem of a statement, or null. */
    static String statementShapeError(Object so) {
        if (!isObj(so)) return "intent statement is not an object";
        Map<?, ?> s = (Map<?, ?>) so;
        Double v = IntentBridge.num(s.get("v"));
        if (v == null || v != 1) return "unsupported intent statement version";
        if (Pca.decodeB64uStrict(s.get("principal"), 32) == null) return "principal is not canonical base64url (32 bytes)";
        if (!(s.get("text") instanceof String) || ((String) s.get("text")).isEmpty()) return "text must be a non-empty string";
        if (!isObj(s.get("slots"))) return "slots must be an object";
        if (!(s.get("sources") instanceof List)) return "sources must be an array";
        List<?> sources = (List<?>) s.get("sources");
        for (int i = 0; i < sources.size(); i++) {
            Object src = sources.get(i);
            if (!isObj(src) || !(((Map<?, ?>) src).get("kind") instanceof String) || !INTENT_SOURCE_KINDS.contains(((Map<?, ?>) src).get("kind"))) return "sources[" + i + "] has an unknown kind";
            Map<?, ?> sm = (Map<?, ?>) src;
            if (sm.containsKey("uri") && !(sm.get("uri") instanceof String)) return "sources[" + i + "].uri must be a string";
            if (Pca.decodeB64uStrict(sm.get("digest"), 32) == null) return "sources[" + i + "].digest is not canonical base64url (32 bytes)";
        }
        Object ca = s.get("created_at");
        if (!IntentBridge.isInt(ca) || IntentBridge.num(ca) < 0) return "created_at must be a non-negative safe integer (epoch ms)";
        if (!(s.get("nonce") instanceof String) || ((String) s.get("nonce")).isEmpty()) return "nonce must be a non-empty string";
        return null;
    }

    /** Sign a statement as its principal with the principal's Ed25519 seed ({@code principal} defaults to the key's identity; must match when given). */
    public static Map<String, Object> signIntent(Map<String, Object> s, byte[] principalSeed) {
        return signIntent(s, Keys.ed25519(Keys.edFromSeed(principalSeed)));
    }

    /** Sign under any registry suite (ML-DSA, hybrid, ...): {@code alg} and {@code pq_pk} are signed into the statement. */
    public static Map<String, Object> signIntent(Map<String, Object> s, Keys.SuiteKey suiteKey) {
        String principal = suiteKey.ed == null ? null : suiteKey.ed.id();
        if (principal == null) throw new IllegalArgumentException("signIntentStatement: signer needs an Ed25519 identity key");
        if (s.containsKey("principal") && !principal.equals(s.get("principal"))) throw new IllegalArgumentException("signIntentStatement: principal key mismatch");
        Map<String, Object> withP = new LinkedHashMap<>(s);
        withP.put("principal", principal);
        Map<String, Object> body = statementBody(withP);
        String bad = statementShapeError(body);
        if (bad != null) throw new IllegalArgumentException("signIntentStatement: " + bad);
        return IntentBridge.signSuite(body, suiteKey, b -> IntentBridge.message(INTENT_SIG_DOMAIN, b));
    }

    private static Map<String, Object> verdict(String reason) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("ok", reason == null);
        if (reason != null) r.put("reason", reason);
        return r;
    }

    public static Map<String, Object> verifyIntent(Object s) { return verifyIntent(s, null, null); }

    /** {ok: true} or {ok: false, reason}. {@code pqPins} maps a principal to the PQ key the verifier pins for it. Never throws. */
    public static Map<String, Object> verifyIntent(Object so, String expectedSigner, Map<String, Object> pqPins) {
        try {
            String bad = statementShapeError(so);
            if (bad != null) return verdict(bad);
            Map<?, ?> st = (Map<?, ?>) so;
            if (expectedSigner != null && !expectedSigner.equals(st.get("principal"))) return verdict("principal mismatch");
            boolean algPresent = st.containsKey("alg");
            String suite = IntentBridge.suiteName(st.get("alg"), algPresent);
            if (suite == null) return verdict("unknown signature suite");
            if (suite.equals("ed25519") && (st.containsKey("pq_pk") || st.containsKey("pq_sig"))) return verdict("an ed25519 artifact must not carry pq_pk / pq_sig");
            Map<String, Object> body = IntentBridge.bindSuiteFields(statementBody(st), st.get("alg"), algPresent, st.get("pq_pk"), st.containsKey("pq_pk"));
            byte[] msg = IntentBridge.message(INTENT_SIG_DOMAIN, body);
            if (!IntentBridge.verifyPinnedSuite(st.get("alg"), algPresent, (String) st.get("principal"), st.get("pq_pk"), msg, st.get("sig"), st.get("pq_sig"), pqPins)) return verdict("bad signature");
            return verdict(null);
        } catch (RuntimeException e) {
            return verdict("malformed intent statement: " + e.getMessage());
        }
    }

    /** The goal string that binds a grant to an intent statement (and optionally an Intent Map). */
    public static String intentGoal(String ref, String mapDigest) { return INTENT_GOAL_PREFIX + ref + (mapDigest != null && !mapDigest.isEmpty() ? ":" + mapDigest : ""); }

    /** Parse an intent goal string: {intentRef, mapDigest?}, or null when it is not one. */
    public static Map<String, Object> parseIntentGoal(Object goal) {
        if (!(goal instanceof String) || !((String) goal).startsWith(INTENT_GOAL_PREFIX)) return null;
        String[] parts = ((String) goal).substring(INTENT_GOAL_PREFIX.length()).split(":", -1);
        String ref = parts[0];
        String map = parts.length > 1 ? parts[1] : null;
        if (ref.isEmpty() || parts.length > 2) return null;
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("intentRef", ref);
        if (map != null && !map.isEmpty()) r.put("mapDigest", map);
        return r;
    }
}
