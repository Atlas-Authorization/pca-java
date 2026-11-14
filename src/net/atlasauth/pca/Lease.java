package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Leases (verification side): a time-boxed, renewable record with a hard max_ttl, separation of duties and revoke by id, path prefix
 * or grant. {@link Registry} keeps the newest record per lease_id and the revocation list in a durable {@link AtomicKv}. Total. Replays packages/pca/conformance/lease-vectors.json.
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
        /** The longest max_ttl (ms) a registry accepts ({@code ttl_ceiling}); null means no ceiling. */
        public Long maxTtlCeiling;
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

    public static final int DEFAULT_SHARDS = 16;
    public static final int MAX_SHARDS = 4096;

    /** The shard a key lives in: the first four bytes of SHA-256 of it, modulo the shard count. Stable across processes (the reference's {@code shardOf}). */
    static int shardOf(String id, int shards) {
        byte[] h = AttestCommon.sha256Sum(id.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        long v = ((h[0] & 0xffL) << 24) | ((h[1] & 0xffL) << 16) | ((h[2] & 0xffL) << 8) | (h[3] & 0xffL);
        return (int) (v % shards);
    }

    /** Pins the shard count in the store on first use; a different count would hide existing records, so it is refused (false). */
    static boolean pinShards(AtomicKv kv, String metaKey, int shards) {
        Object m = kv.update(metaKey, prev -> {
            if (prev != null) return null;
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("v", IntentJs.ofLong(1));
            meta.put("shards", IntentJs.ofLong(shards));
            return meta;
        });
        return m instanceof Map && Json.isSafeInt(((Map<?, ?>) m).get("shards")) && Json.asLong(((Map<?, ?>) m).get("shards")) == shards;
    }

    /** The registry's durable state: one document per shard {@code {leases: {id: {current, history}}, revocations: [...]}}; a prefix or grant revocation is written to EVERY shard. */
    public static final class Registry {
        private final Policy policy;
        private final AtomicKv kv;
        private final int shards;
        private final java.util.function.LongSupplier clock;
        private boolean metaOk;

        /** @param kv the durable store (required: a process-local default would forget revocations on restart; {@link MemoryAtomicKv} is for tests and one process). */
        public Registry(Policy policy, AtomicKv kv) { this(policy, kv, DEFAULT_SHARDS, System::currentTimeMillis); }

        public Registry(Policy policy, AtomicKv kv, int shards, java.util.function.LongSupplier clock) {
            if (kv == null) throw new IllegalArgumentException("LeaseRegistry: a durable key-value store is required (MemoryAtomicKv is for tests and single-process use)");
            if (shards < 1 || shards > MAX_SHARDS) throw new IllegalArgumentException("LeaseRegistry: shards must be an integer from 1 to 4096");
            if (policy.maxTtlCeiling != null && (policy.maxTtlCeiling < 1 || policy.maxTtlCeiling > 9007199254740991L)) {
                throw new IllegalArgumentException("LeaseRegistry: maxTtlCeiling must be a positive integer");
            }
            this.policy = policy;
            this.kv = kv;
            this.shards = shards;
            this.clock = clock;
        }

        public int shardCount() { return shards; }

        private static Accept no(String code) { return new Accept(code, false, 0); }

        private String shardKey(int i) { return "lease/" + shards + "/" + i; }

        private synchronized boolean ready() {
            if (!metaOk) metaOk = pinShards(kv, "lease/meta", shards);
            return metaOk;
        }

        /** A private copy of a shard document (the store's value is never mutated in place). */
        @SuppressWarnings("unchecked")
        private static Map<String, Object> load(Object prev) {
            Map<String, Object> st = new LinkedHashMap<>();
            Map<String, Object> leases = new LinkedHashMap<>();
            List<Object> revocations = new ArrayList<>();
            if (prev instanceof Map && ((Map<?, ?>) prev).get("leases") instanceof Map && ((Map<?, ?>) prev).get("revocations") instanceof List) {
                for (Map.Entry<String, Object> e : ((Map<String, Object>) ((Map<?, ?>) prev).get("leases")).entrySet()) {
                    Map<String, Object> entry = new LinkedHashMap<>((Map<String, Object>) e.getValue());
                    entry.put("history", new ArrayList<>((List<Object>) entry.get("history")));
                    leases.put(e.getKey(), entry);
                }
                revocations.addAll((List<Object>) ((Map<?, ?>) prev).get("revocations"));
            }
            st.put("leases", leases);
            st.put("revocations", revocations);
            return st;
        }

        /** Drops a revocation once {@code revoked_at + ceiling} is past (every lease it could cover is then beyond its own cap); with no ceiling nothing is pruned. */
        @SuppressWarnings("unchecked")
        private void prune(Map<String, Object> st) {
            if (policy.maxTtlCeiling == null) return;
            long now = clock.getAsLong();
            ((List<Object>) st.get("revocations")).removeIf(r -> Json.asLong(((Map<String, Object>) r).get("revoked_at")) + policy.maxTtlCeiling < now);
        }

        @SuppressWarnings("unchecked")
        private static boolean anyCovers(Map<String, Object> st, Map<String, Object> l) {
            for (Object r : (List<Object>) st.get("revocations")) if (covers((Map<String, Object>) r, l)) return true;
            return false;
        }

        /** Take an issue (seq 1) or a renewal (seq = current + 1). {@code chain}: the keys in the holder's delegation chain. */
        @SuppressWarnings("unchecked")
        public Accept accept(Object rec, List<String> chain) {
            try {
                if (!verify(rec)) return no("bad_record");
                Map<String, Object> l = (Map<String, Object>) rec;
                if (!policy.authorities.contains(l.get("authority"))) return no("unknown_authority");
                if (sodError(l, policy, chain) != null) return no("sod");
                if (Json.asLong(l.get("expires_at")) > cap(l)) return no("over_max_ttl");
                if (policy.maxTtlCeiling != null && Json.asLong(l.get("max_ttl")) > policy.maxTtlCeiling) return no("ttl_ceiling");
                Accept[] out = {no("store_unreachable")};
                if (!ready()) return out[0];
                String id = (String) l.get("lease_id");
                kv.update(shardKey(shardOf(id, shards)), prev -> {
                    Map<String, Object> st = load(prev);
                    Map<String, Object> leases = (Map<String, Object>) st.get("leases");
                    Map<String, Object> entry = (Map<String, Object>) leases.get(id);
                    Map<String, Object> cur = entry == null ? null : (Map<String, Object>) entry.get("current");
                    if (anyCovers(st, l)) { out[0] = no("revoked"); return null; }
                    long seq = Json.asLong(l.get("seq"));
                    if (cur == null) {
                        if (seq != 1) { out[0] = no("bad_seq"); return null; }
                    } else {
                        long cs = Json.asLong(cur.get("seq"));
                        if (seq < cs) { out[0] = no("stale_seq"); return null; }
                        if (seq == cs) { out[0] = cur.get("sig").equals(l.get("sig")) ? new Accept(null, false, seq) : no("lease_fork"); return null; }
                        if (seq != cs + 1) { out[0] = no("bad_seq"); return null; }
                        for (String k : new String[] {"authority", "path", "grant_ref", "holder", "requester"}) if (!l.get(k).equals(cur.get(k))) { out[0] = no("renewal_mismatch"); return null; }
                        for (String k : new String[] {"max_ttl", "issued_at"}) if (Json.asLong(l.get(k)) != Json.asLong(cur.get(k))) { out[0] = no("renewal_mismatch"); return null; }
                        if (Json.asLong(l.get("renewed_at")) >= Json.asLong(cur.get("expires_at"))) { out[0] = no("expired_lease"); return null; }
                        if (Json.asLong(l.get("renewed_at")) < Json.asLong(cur.get("renewed_at")) || Json.asLong(l.get("expires_at")) <= Json.asLong(cur.get("expires_at"))) { out[0] = no("not_extending"); return null; }
                        if ((policy.freshJustification == null || policy.freshJustification) && l.get("justification_digest").equals(cur.get("justification_digest"))) { out[0] = no("stale_justification"); return null; }
                    }
                    Map<String, Object> line = new LinkedHashMap<>();
                    line.put("seq", l.get("seq"));
                    line.put("renewed_at", l.get("renewed_at"));
                    line.put("expires_at", l.get("expires_at"));
                    line.put("justification_digest", l.get("justification_digest"));
                    List<Object> history = entry == null ? new ArrayList<>() : (List<Object>) entry.get("history");
                    history.add(line);
                    Map<String, Object> ne = new LinkedHashMap<>();
                    ne.put("current", l);
                    ne.put("history", history);
                    leases.put(id, ne);
                    prune(st);
                    out[0] = new Accept(null, true, seq);
                    return st;
                });
                return out[0];
            } catch (RuntimeException e) {
                return no("store_unreachable");
            }
        }

        /** Take a signed revocation. Idempotent. A prefix or grant revocation is written to every shard; the count is the leases covered across all of them. */
        @SuppressWarnings("unchecked")
        public Revoke revoke(Object rec) {
            try {
                if (!verifyRevocation(rec)) return new Revoke("bad_record", 0);
                Map<String, Object> r = (Map<String, Object>) rec;
                if (!policy.authorities.contains(r.get("authority"))) return new Revoke("unknown_authority", 0);
                List<Integer> targets = new ArrayList<>();
                if ("lease".equals(r.get("target"))) targets.add(shardOf((String) r.get("value"), shards));
                else for (int i = 0; i < shards; i++) targets.add(i);
                if (!ready()) return new Revoke("store_unreachable", 0);
                int[] n = {0};
                for (int i : targets) {
                    kv.update(shardKey(i), prev -> {
                        Map<String, Object> st = load(prev);
                        List<Object> revs = (List<Object>) st.get("revocations");
                        boolean known = false;
                        for (Object x : revs) if (((Map<String, Object>) x).get("sig").equals(r.get("sig"))) known = true;
                        if (!known) revs.add(r);
                        for (Object e : ((Map<String, Object>) st.get("leases")).values()) if (covers(r, (Map<String, Object>) ((Map<String, Object>) e).get("current"))) n[0]++;
                        prune(st);
                        return st;
                    });
                }
                return new Revoke(null, n[0]);
            } catch (RuntimeException e) {
                return new Revoke("store_unreachable", 0);
            }
        }

        /** The newest record held for a lease id and whether a stored revocation covers it; null when unknown. Throws when the store cannot answer. */
        @SuppressWarnings("unchecked")
        Map.Entry<Map<String, Object>, Boolean> lookup(String id) {
            if (!ready()) throw new IllegalStateException("shard count mismatch");
            Map<String, Object> st = load(kv.get(shardKey(shardOf(id, shards))));
            Map<String, Object> entry = (Map<String, Object>) ((Map<String, Object>) st.get("leases")).get(id);
            if (entry == null) return null;
            Map<String, Object> cur = (Map<String, Object>) entry.get("current");
            return new java.util.AbstractMap.SimpleEntry<>(cur, anyCovers(st, cur));
        }

        /** The newest record of a lease, or null. */
        @SuppressWarnings("unchecked")
        public Map<String, Object> get(String id) {
            Map.Entry<Map<String, Object>, Boolean> f = lookup(id);
            return f == null ? null : f.getKey();
        }

        /** The renewal ledger of a lease, oldest first (one line per accepted record). */
        @SuppressWarnings("unchecked")
        public List<Object> history(String id) {
            if (!ready()) throw new IllegalStateException("shard count mismatch");
            Map<String, Object> st = load(kv.get(shardKey(shardOf(id, shards))));
            Map<String, Object> entry = (Map<String, Object>) ((Map<String, Object>) st.get("leases")).get(id);
            return entry == null ? new ArrayList<>() : (List<Object>) entry.get("history");
        }

        /** The revocations one shard holds (for operators and the conformance kit). */
        @SuppressWarnings("unchecked")
        public List<Object> shardRevocations(int i) {
            if (i < 0 || i >= shards) throw new IllegalArgumentException("no such shard");
            return (List<Object>) load(kv.get(shardKey(i))).get("revocations");
        }

        /** Is {@code presented} a live lease? It must verify, be the newest record held, be inside its window and cap, and not be revoked. Fails closed. */
        @SuppressWarnings("unchecked")
        public Decision check(Object presented, Object now) {
            if (!nat(now)) return new Decision("deny", "bad_input", null, null);
            if (!verify(presented)) return new Decision("deny", "bad_record", null, null);
            Map<String, Object> p = (Map<String, Object>) presented;
            String id = (String) p.get("lease_id");
            try {
                long t = Json.asLong(now);
                Map.Entry<Map<String, Object>, Boolean> found = lookup(id);
                if (found == null) return deny("unknown_lease", id);
                Map<String, Object> cur = found.getKey();
                if (!cur.get("sig").equals(p.get("sig"))) return deny("superseded", id);
                if (found.getValue()) return deny("revoked", id);
                if (t < Json.asLong(cur.get("renewed_at"))) return deny("not_yet_valid", id);
                if (t >= cap(cur)) return deny("past_max_ttl", id);
                if (t >= Json.asLong(cur.get("expires_at"))) return deny("expired", id);
                return new Decision("allow", null, id, Json.asLong(cur.get("expires_at")));
            } catch (RuntimeException e) {
                return deny("store_unreachable", id);
            }
        }

        private static Decision deny(String code, String id) { return new Decision("deny", code, id, null); }
    }
}
