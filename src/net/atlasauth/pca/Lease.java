package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Leases (verification side): a time-boxed, renewable record with a hard max_ttl, separation of duties and revoke by id, path prefix
 * or grant. {@link Registry} keeps the newest record per lease_id (in memory). Total. Replays packages/pca/conformance/lease-vectors.json.
 */
public final class Lease {
    private Lease() {}

    public static final String DOMAIN = "atlas-pca/lease/v1\u0000";
    public static final String REVOKE_DOMAIN = "atlas-pca/lease-revoke/v1\u0000";
    private static final String[] BODY_KEYS = {"v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at", "renewed_at", "expires_at", "max_ttl", "authority"};
    private static final String[] REVOKE_KEYS = {"v", "target", "value", "revoked_at", "authority"};
    private static final Pattern PATH_RE = Pattern.compile("[a-z0-9_.-]{1,64}(/[a-z0-9_.-]{1,64}){0,7}");

    private static boolean str(Object o, int max) { return o instanceof String && !((String) o).isEmpty() && ((String) o).length() <= max; }
    private static boolean nat(Object o) { return Json.isSafeInt(o) && Json.asLong(o) >= 0; }

    @SuppressWarnings("unchecked")
    static boolean wellFormed(Object v) {
        if (!(v instanceof Map)) return false;
        Map<String, Object> l = (Map<String, Object>) v;
        if (!Json.isSafeInt(l.get("v")) || Json.asLong(l.get("v")) != 1) return false;
        if (!str(l.get("lease_id"), 128) || !str(l.get("grant_ref"), 256) || !str(l.get("holder"), 128) || !str(l.get("requester"), 128)) return false;
        if (!str(l.get("authority"), 128) || !str(l.get("justification_digest"), 128)) return false;
        if (!(l.get("path") instanceof String) || !PATH_RE.matcher((String) l.get("path")).matches()) return false;
        for (String k : new String[] {"seq", "issued_at", "renewed_at", "expires_at", "max_ttl"}) if (!nat(l.get(k))) return false;
        if (Json.asLong(l.get("seq")) < 1 || Json.asLong(l.get("max_ttl")) < 1) return false;
        long issued = Json.asLong(l.get("issued_at")), renewed = Json.asLong(l.get("renewed_at")), expires = Json.asLong(l.get("expires_at"));
        if (renewed < issued || expires <= renewed || (Json.asLong(l.get("seq")) == 1 && renewed != issued)) return false;
        if (!(l.get("approvers") instanceof List) || ((List<Object>) l.get("approvers")).size() > 16) return false;
        for (Object a : (List<Object>) l.get("approvers")) if (!str(a, 128)) return false;
        return true;
    }

    @SuppressWarnings("unchecked")
    static long cap(Map<String, Object> l) { return Json.asLong(l.get("issued_at")) + Json.asLong(l.get("max_ttl")); }

    private static Map<String, Object> body(Map<String, Object> o, String[] keys) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : keys) b.put(k, o.get(k));
        return b;
    }

    /** Well formed and signed by its authority over exactly its content. Does NOT check the cap. */
    @SuppressWarnings("unchecked")
    public static boolean verify(Object v) {
        if (!wellFormed(v)) return false;
        Map<String, Object> l = (Map<String, Object>) v;
        return K3.verifyBody(DOMAIN, body(l, BODY_KEYS), (String) l.get("authority"), l.get("sig"));
    }

    @SuppressWarnings("unchecked")
    static boolean revocationWellFormed(Object v) {
        if (!(v instanceof Map)) return false;
        Map<String, Object> r = (Map<String, Object>) v;
        if (!Json.isSafeInt(r.get("v")) || Json.asLong(r.get("v")) != 1 || !str(r.get("value"), 256) || !str(r.get("authority"), 128) || !nat(r.get("revoked_at"))) return false;
        Object t = r.get("target");
        if (!"lease".equals(t) && !"prefix".equals(t) && !"grant".equals(t)) return false;
        return !"prefix".equals(t) || PATH_RE.matcher((String) r.get("value")).matches();
    }

    @SuppressWarnings("unchecked")
    public static boolean verifyRevocation(Object v) {
        if (!revocationWellFormed(v)) return false;
        Map<String, Object> r = (Map<String, Object>) v;
        return K3.verifyBody(REVOKE_DOMAIN, body(r, REVOKE_KEYS), (String) r.get("authority"), r.get("sig"));
    }

    /** {@code prefix} covers {@code path} iff equal or {@code path} continues it at a segment boundary. */
    public static boolean pathUnder(String path, String prefix) { return path.equals(prefix) || path.startsWith(prefix + "/"); }

    static boolean covers(Map<String, Object> r, Map<String, Object> l) {
        if (Json.asLong(l.get("issued_at")) > Json.asLong(r.get("revoked_at"))) return false;
        Object t = r.get("target");
        if ("lease".equals(t)) return l.get("lease_id").equals(r.get("value"));
        if ("grant".equals(t)) return l.get("grant_ref").equals(r.get("value"));
        return pathUnder((String) l.get("path"), (String) r.get("value"));
    }

    /** The verifier's policy. {@code minApprovals} null means 1, {@code eligibleApprovers} null means anyone, {@code freshJustification} null means true. */
    public static final class Policy {
        public final List<String> authorities;
        public Long minApprovals;
        public List<String> eligibleApprovers;
        public Boolean freshJustification;
        public Policy(List<String> authorities) { this.authorities = authorities; }
    }

    /** Separation of duties over one record (parsed JSON). A reason or null. */
    @SuppressWarnings("unchecked")
    public static String sodError(Map<String, Object> l, Policy p, List<String> chain) {
        long k = p.minApprovals == null ? 1 : p.minApprovals;
        if (k < 1 || k > 9007199254740991L) return "minApprovals must be a positive integer";
        Set<String> seen = new HashSet<>();
        List<Object> approvers = (List<Object>) l.get("approvers");
        for (Object o : approvers) {
            String a = (String) o;
            if (!seen.add(a)) return "an approver is listed twice";
            if (a.equals(l.get("requester"))) return "the requester may not approve their own request";
            if (a.equals(l.get("holder"))) return "the holder may not approve its own lease";
            if (chain.contains(a)) return "an approver appears in the holder's delegation chain";
            if (p.eligibleApprovers != null && !p.eligibleApprovers.contains(a)) return "an approver is not eligible";
        }
        return approvers.size() < k ? approvers.size() + " approver(s), need " + k : null;
    }

    /** Outcome of {@link Registry#accept}: {@code code} is null when taken. */
    public static final class Accept {
        public final String code;
        public final boolean replaced;
        public final long seq;
        Accept(String code, boolean replaced, long seq) { this.code = code; this.replaced = replaced; this.seq = seq; }
    }

    /** Outcome of {@link Registry#revoke}: {@code code} is null when taken. */
    public static final class Revoke {
        public final String code;
        public final int revoked;
        Revoke(String code, int revoked) { this.code = code; this.revoked = revoked; }
    }

    /** {@code decision} is "allow" or "deny"; {@code code}, {@code leaseId} and {@code expiresAt} as in the vectors (null when absent). */
    public static final class Decision {
        public final String decision, code, leaseId;
        public final Long expiresAt;
        Decision(String decision, String code, String leaseId, Long expiresAt) { this.decision = decision; this.code = code; this.leaseId = leaseId; this.expiresAt = expiresAt; }
    }

    /** The newest record per lease_id, the revocation list and the renewal ledger, in memory. */
    public static final class Registry {
        private final Policy policy;
        private final Map<String, Map<String, Object>> leases = new HashMap<>();
        private final Map<String, List<long[]>> history = new HashMap<>();
        private final List<Map<String, Object>> revocations = new ArrayList<>();

        public Registry(Policy policy) { this.policy = policy; }

        private static Accept no(String code) { return new Accept(code, false, 0); }

        /** Take an issue (seq 1) or a renewal (seq = current + 1). {@code chain}: the keys in the holder's delegation chain. */
        @SuppressWarnings("unchecked")
        public Accept accept(Object rec, List<String> chain) {
            try {
                if (!verify(rec)) return no("bad_record");
                Map<String, Object> l = (Map<String, Object>) rec;
                if (!policy.authorities.contains(l.get("authority"))) return no("unknown_authority");
                if (sodError(l, policy, chain) != null) return no("sod");
                if (Json.asLong(l.get("expires_at")) > cap(l)) return no("over_max_ttl");
                for (Map<String, Object> r : revocations) if (covers(r, l)) return no("revoked");
                Map<String, Object> cur = leases.get(l.get("lease_id"));
                long seq = Json.asLong(l.get("seq"));
                if (cur == null) {
                    if (seq != 1) return no("bad_seq");
                } else {
                    long cs = Json.asLong(cur.get("seq"));
                    if (seq < cs) return no("stale_seq");
                    if (seq == cs) return cur.get("sig").equals(l.get("sig")) ? new Accept(null, false, seq) : no("lease_fork");
                    if (seq != cs + 1) return no("bad_seq");
                    for (String k : new String[] {"authority", "path", "grant_ref", "holder", "requester"}) if (!l.get(k).equals(cur.get(k))) return no("renewal_mismatch");
                    for (String k : new String[] {"max_ttl", "issued_at"}) if (Json.asLong(l.get(k)) != Json.asLong(cur.get(k))) return no("renewal_mismatch");
                    if (Json.asLong(l.get("renewed_at")) >= Json.asLong(cur.get("expires_at"))) return no("expired_lease");
                    if (Json.asLong(l.get("renewed_at")) < Json.asLong(cur.get("renewed_at")) || Json.asLong(l.get("expires_at")) <= Json.asLong(cur.get("expires_at"))) return no("not_extending");
                    if ((policy.freshJustification == null || policy.freshJustification) && l.get("justification_digest").equals(cur.get("justification_digest"))) return no("stale_justification");
                }
                String id = (String) l.get("lease_id");
                leases.put(id, l);
                history.computeIfAbsent(id, x -> new ArrayList<>()).add(new long[] {seq, Json.asLong(l.get("renewed_at")), Json.asLong(l.get("expires_at"))});
                return new Accept(null, true, seq);
            } catch (RuntimeException e) {
                return no("store_unreachable");
            }
        }

        /** Take a signed revocation. Idempotent. */
        @SuppressWarnings("unchecked")
        public Revoke revoke(Object rec) {
            try {
                if (!verifyRevocation(rec)) return new Revoke("bad_record", 0);
                Map<String, Object> r = (Map<String, Object>) rec;
                if (!policy.authorities.contains(r.get("authority"))) return new Revoke("unknown_authority", 0);
                boolean known = false;
                for (Map<String, Object> x : revocations) known |= x.get("sig").equals(r.get("sig"));
                if (!known) revocations.add(r);
                int n = 0;
                for (Map<String, Object> l : leases.values()) if (covers(r, l)) n++;
                return new Revoke(null, n);
            } catch (RuntimeException e) {
                return new Revoke("store_unreachable", 0);
            }
        }

        /** Is {@code presented} a live lease? It must verify, be the newest record held, be inside its window and cap, and not be revoked. Fails closed. */
        @SuppressWarnings("unchecked")
        public Decision check(Object presented, Object now) {
            if (!nat(now)) return new Decision("deny", "bad_input", null, null);
            if (!verify(presented)) return new Decision("deny", "bad_record", null, null);
            try {
                Map<String, Object> p = (Map<String, Object>) presented;
                String id = (String) p.get("lease_id");
                long t = Json.asLong(now);
                Map<String, Object> cur = leases.get(id);
                if (cur == null) return deny("unknown_lease", id);
                if (!cur.get("sig").equals(p.get("sig"))) return deny("superseded", id);
                for (Map<String, Object> r : revocations) if (covers(r, cur)) return deny("revoked", id);
                if (t < Json.asLong(cur.get("renewed_at"))) return deny("not_yet_valid", id);
                if (t >= cap(cur)) return deny("past_max_ttl", id);
                if (t >= Json.asLong(cur.get("expires_at"))) return deny("expired", id);
                return new Decision("allow", null, id, Json.asLong(cur.get("expires_at")));
            } catch (RuntimeException e) {
                return new Decision("deny", "store_unreachable", null, null);
            }
        }

        private static Decision deny(String code, String id) { return new Decision("deny", code, id, null); }
    }
}
