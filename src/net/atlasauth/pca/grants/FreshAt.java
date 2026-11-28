package net.atlasauth.pca.grants;

import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.K3;
import net.atlasauth.pca.Keys;

/**
 * Consistency tokens for the operational plane. Verification (verifyFreshAt, freshAtDigest, checkFreshAt, decideFreshAt,
 * validateFreshAtWire) is {@link K3}; signing is {@link Issue#signFreshAt}. This class adds the state fold, the gate and the issuer.
 */
public final class FreshAt {
    private FreshAt() {}

    private static final String[] NUMERIC = {"revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision"};

    /** The JavaScript number value of a JSON number; a non-number is refused (the reference would compute NaN and sign nothing). */
    private static double dbl(Map<String, Object> s, String k) {
        Object v = s.get(k);
        if (v instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) v).raw); } catch (NumberFormatException e) { throw new IllegalArgumentException("fresh_at state: " + k + " is not a number"); }
        }
        if (v instanceof Number) return ((Number) v).doubleValue();
        throw new IllegalArgumentException("fresh_at state: " + k + " is not a number");
    }

    /** Whichever of the two values is larger (the first when equal): Math.max without losing the value's own representation. */
    private static Object max(Map<String, Object> a, Map<String, Object> b, String k) { return dbl(b, k) > dbl(a, k) ? b.get(k) : a.get(k); }

    /** Sign a token for {@code state}; throws on a malformed state (the reference's RangeError). */
    public static Map<String, Object> signFreshAt(Keys.EdKey secret, String scope, Map<String, Object> state, long issuedAt) {
        boolean ok = Sig.isStr(scope, 256) && Sig.isStr(state.get("policy_digest"), 128) && issuedAt >= 0;
        for (String k : NUMERIC) ok = ok && Sig.isSafeInt(state.get(k));
        if (!ok) throw new IllegalArgumentException("signFreshAt: a malformed state");
        return Issue.signFreshAt(secret, scope, state, issuedAt);
    }

    /** Field-wise maximum of two states (the client-side fold); equal revisions with different digests keep a's digest. */
    public static Map<String, Object> mergeFreshAt(Map<String, Object> a, Map<String, Object> b) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (String k : NUMERIC) m.put(k, max(a, b, k));
        m.put("policy_digest", dbl(b, "policy_revision") > dbl(a, "policy_revision") ? b.get("policy_digest") : a.get("policy_digest"));
        return m;
    }

    /** Compose a freshness verdict into a decision: it can only tighten (allow to escalate/deny), never loosen. */
    public static String gateDecision(String decision, K3.FreshVerdict v) {
        if ("deny".equals(decision)) return "deny";
        if ("deny".equals(v.decision)) return "deny";
        if ("escalate".equals(v.decision)) return "escalate";
        return decision;
    }

    /** Verifier-side state holder: advance on every write, mint the token for the write, check incoming tokens. */
    public static final class Issuer {
        private Map<String, Object> state;
        private final Keys.EdKey secret;
        public final String scope;

        public Issuer(Keys.EdKey secret, String scope, Map<String, Object> initial) {
            this.secret = secret;
            this.scope = scope;
            this.state = new LinkedHashMap<>(initial);
        }

        public synchronized Map<String, Object> current() { return new LinkedHashMap<>(state); }

        /** Apply a write (any subset of counters; each only moves forward) and return its token. */
        public synchronized Map<String, Object> advance(Map<String, Object> patch, long now) {
            Map<String, Object> next = new LinkedHashMap<>(state);
            next.putAll(patch);
            state = mergeFreshAt(state, next);
            return signFreshAt(secret, scope, state, now);
        }

        public synchronized K3.FreshVerdict check(Object token, long now, Double maxTokenAgeMs) {
            return K3.checkFreshAt(token, state, Sig.signerOf(secret), scope, now, maxTokenAgeMs);
        }
    }
}
