package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Signing side of the operational-plane artifacts (lease, lease revocation, agent blueprint, break-glass, review) and the
 * domain-separated body signature they share. Lives beside the verifiers because it reuses their package-private shape checks,
 * so a record is signed only when the verifier would take its shape. The {@code net.atlasauth.pca.grants} classes delegate here.
 */
public final class GrantSigning {
    private GrantSigning() {}

    private static final String[] LEASE_KEYS = {"v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at", "renewed_at", "expires_at", "max_ttl", "authority"};
    private static final String[] REVOKE_KEYS = {"v", "target", "value", "revoked_at", "authority"};
    private static final String[] BLUEPRINT_KEYS = {"v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator"};
    private static final String[] BG_KEYS = {"v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority"};
    private static final String[] REVIEW_KEYS = {"v", "id", "outcome", "notes_digest", "at", "reviewer"};

    public static String signerOf(Keys.EdKey secret) { return secret.id(); }

    /** b64u Ed25519 signature over {@code domain || strictCanonicalJSON(body)}. */
    public static String signBody(String domain, Object body, Keys.EdKey secret) { return Issue.signBody(secret, domain, body); }

    /** True iff {@code sig} is a canonical 64-byte b64u signature by {@code signer} over exactly {@code body}. Never throws. */
    public static boolean verifyBody(String domain, Object body, String signer, Object sig) { return K3.verifyBody(domain, body, signer, sig); }

    private static Map<String, Object> base(Map<String, Object> rec, String authorityKey, Keys.EdKey secret) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("v", 1L);
        b.putAll(rec);
        b.put(authorityKey, secret.id());
        return b;
    }

    private static Map<String, Object> pick(Map<String, Object> o, String[] keys, boolean onlyPresent) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : keys) if (!onlyPresent || o.containsKey(k)) b.put(k, o.get(k));
        return b;
    }

    private static Map<String, Object> signed(Map<String, Object> base, String domain, String[] keys, boolean onlyPresent, Keys.EdKey secret) {
        base.put("sig", signBody(domain, pick(base, keys, onlyPresent), secret));
        return base;
    }

    public static Map<String, Object> signLease(Keys.EdKey secret, Map<String, Object> l) {
        Map<String, Object> b = base(l, "authority", secret);
        if (!Lease.wellFormed(b) || Json.asLong(b.get("expires_at")) > Lease.cap(b)) throw new IllegalArgumentException("signLease: a malformed lease, or one past issued_at + max_ttl");
        return signed(b, Lease.DOMAIN, LEASE_KEYS, false, secret);
    }

    /** Conformance-vector builder only: signs a record that outlives its cap, to prove verifiers refuse it. */
    public static Map<String, Object> signLeaseUnsafeOverCap(Keys.EdKey secret, Map<String, Object> l) {
        Map<String, Object> b = base(l, "authority", secret);
        if (!Lease.wellFormed(b)) throw new IllegalArgumentException("signLeaseUnsafeOverCap: malformed");
        return signed(b, Lease.DOMAIN, LEASE_KEYS, false, secret);
    }

    public static Map<String, Object> signLeaseRevocation(Keys.EdKey secret, Map<String, Object> r) {
        Map<String, Object> b = base(r, "authority", secret);
        if (!Lease.revocationWellFormed(b)) throw new IllegalArgumentException("signLeaseRevocation: malformed");
        return signed(b, Lease.REVOKE_DOMAIN, REVOKE_KEYS, false, secret);
    }

    public static Map<String, Object> signBlueprint(Keys.EdKey secret, Map<String, Object> bp) {
        Map<String, Object> b = base(bp, "operator", secret);
        if (!Blueprint.wellFormed(b)) throw new IllegalArgumentException("signBlueprint: a malformed blueprint");
        return signed(b, Blueprint.DOMAIN, BLUEPRINT_KEYS, true, secret);
    }

    public static Map<String, Object> signBreakGlass(Keys.EdKey secret, Map<String, Object> bg) {
        Map<String, Object> b = base(bg, "authority", secret);
        if (!BreakGlass.wellFormed(b)) throw new IllegalArgumentException("signBreakGlass: malformed, or the window is longer than 24 hours, or the budget is outside 1..16");
        return signed(b, BreakGlass.DOMAIN, BG_KEYS, false, secret);
    }

    public static Map<String, Object> signBreakGlassReview(Keys.EdKey secret, Map<String, Object> r) {
        Map<String, Object> b = base(r, "reviewer", secret);
        if (!BreakGlass.reviewWellFormed(b)) throw new IllegalArgumentException("signBreakGlassReview: malformed");
        return signed(b, BreakGlass.REVIEW_DOMAIN, REVIEW_KEYS, false, secret);
    }

    /** RFC 6962 inclusion proof {index, size, path:[{side, hash}]} (leaf to root) for leaf {@code index}; throws when out of range. */
    public static Map<String, Object> merkleProof(List<Object> leaves, int index) {
        if (index < 0 || index >= leaves.size()) throw new IllegalArgumentException("merkleProof: index out of range");
        List<byte[]> hs = new ArrayList<>();
        for (Object l : leaves) hs.add(Pca.leafHash(l));
        List<Object> path = new ArrayList<>();
        prove(hs, index, path);
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("index", (long) index);
        p.put("size", (long) leaves.size());
        p.put("path", path);
        return p;
    }

    private static void prove(List<byte[]> hs, int idx, List<Object> out) {
        if (hs.size() == 1) return;
        int k = Pca.split(hs.size());
        Map<String, Object> step = new LinkedHashMap<>();
        if (idx < k) {
            prove(hs.subList(0, k), idx, out);
            step.put("side", "R");
            step.put("hash", Pca.b64(Pca.build(hs.subList(k, hs.size()))));
        } else {
            prove(hs.subList(k, hs.size()), idx - k, out);
            step.put("side", "L");
            step.put("hash", Pca.b64(Pca.build(hs.subList(0, k))));
        }
        out.add(step);
    }

    /** The newest record held for a blueprint key, or null. */
    public static Map<String, Object> blueprintGet(Blueprint.Registry registry, String key) { return registry.get(key); }

    /** The shard a lease id lives in. */
    public static int shardOf(String id, int shards) { return Lease.shardOf(id, shards); }

    static byte[] utf8(String s) { return Json.utf8(s); }
}
