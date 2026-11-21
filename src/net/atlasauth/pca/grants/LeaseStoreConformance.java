package net.atlasauth.pca.grants;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;
import net.atlasauth.pca.AtomicKv;
import net.atlasauth.pca.GrantSigning;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Lease;

/**
 * Conformance kit for lease storage. Run it against any {@link AtomicKv} (the in-memory one, an opened durable state, or your own database
 * adapter) before trusting that store with leases. It throws {@code IllegalStateException("lease store conformance: <check>: <detail>")} on the
 * first failure and returns the list of checks passed. It proves: leases spread over the shards; an update is atomic (of many concurrent
 * renewals of one lease exactly one wins and the rest are forks); different leases do not interfere; a prefix revocation lands in every shard and a
 * lease revocation only in its own; a store opened with another shard count is refused rather than silently empty; state survives a reopen
 * (give {@code reopen}); a later-issued lease under a revoked prefix is a new lease; with a TTL ceiling, old revocations are pruned from every
 * shard and a longer {@code max_ttl} is refused.
 */
public final class LeaseStoreConformance {
    private LeaseStoreConformance() {}

    private static final Keys.EdKey SK = Keys.edFromSeed(filled((byte) 61));
    private static final String AUTH = SK.id();
    private static final long T0 = 1_800_000_000_000L;
    private static final long DAY = 86_400_000L;

    private static byte[] filled(byte v) {
        byte[] b = new byte[32];
        Arrays.fill(b, v);
        return b;
    }

    /** The store under test. */
    public interface Kit {
        /** A fresh, empty store. */
        AtomicKv open() throws Exception;

        /** The same store opened again as a restarted process would (state kept); null skips the restart check. */
        default AtomicKv reopen(AtomicKv kv) throws Exception { return null; }

        default boolean supportsReopen() { return false; }

        /** Shard count; 16 by default. */
        default int shards() { return 16; }
    }

    private static Map<String, Object> mk(String id, Object... over) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("lease_id", id);
        m.put("path", "svc/" + (id.length() % 3) + "/" + id);
        m.put("grant_ref", "g-" + id);
        m.put("holder", "agent");
        m.put("requester", "alice");
        m.put("approvers", new ArrayList<Object>(Arrays.asList("bob")));
        m.put("justification_digest", "j1");
        m.put("seq", 1L);
        m.put("issued_at", T0);
        m.put("renewed_at", T0);
        m.put("expires_at", T0 + 600_000L);
        m.put("max_ttl", 3_600_000L);
        for (int i = 0; i < over.length; i += 2) m.put((String) over[i], over[i + 1]);
        return m;
    }

    private static Map<String, Object> lease(String id, Object... over) { return GrantSigning.signLease(SK, mk(id, over)); }

    private static Map<String, Object> revocation(String target, String value, long at) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("target", target);
        r.put("value", value);
        r.put("revoked_at", at);
        return GrantSigning.signLeaseRevocation(SK, r);
    }

    private static IllegalStateException fail(String check, String detail) { return new IllegalStateException("lease store conformance: " + check + ": " + detail); }

    private static void expectEq(String check, Object got, Object want) {
        String g = Json.canonicalize(got), w = Json.canonicalize(want);
        if (!g.equals(w)) throw fail(check, "got " + g + ", want " + w);
    }

    private static Map<String, Object> acc(Lease.Accept a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", a.code == null);
        if (a.code != null) m.put("code", a.code);
        return m;
    }

    private static Map<String, Object> rev(Lease.Revoke r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", r.code == null);
        if (r.code == null) m.put("revoked", (long) r.revoked);
        return m;
    }

    private static List<Object> seqs(List<Object> history) {
        List<Object> out = new ArrayList<>();
        for (Object h : history) out.add(Json.asLong(Sig.map(h).get("seq")));
        return out;
    }

    private static boolean okAccept(Lease.Registry reg, Map<String, Object> rec) { return reg.accept(rec, new ArrayList<String>()).code == null; }

    public static List<String> runLeaseStoreConformance(Kit kit) throws Exception {
        List<String> passed = new ArrayList<>();
        int shards = kit.shards();
        Lease.Policy policy = new Lease.Policy(Arrays.asList(AUTH));

        // 1. spread
        {
            Lease.Registry reg = new Lease.Registry(policy, kit.open(), shards, System::currentTimeMillis);
            List<String> ids = new ArrayList<>();
            for (int i = 0; i < 256; i++) ids.add("lease-" + i);
            for (String id : ids) expectEq("spread: issue " + id, okAccept(reg, lease(id)), true);
            int[] per = new int[shards];
            for (String id : ids) per[shardOf(id, shards)]++;
            int max = 0, used = 0;
            for (int n : per) { max = Math.max(max, n); if (n > 0) used++; }
            if (max > ids.size() / 4.0 || used < shards / 2.0) throw fail("spread", "256 leases landed " + Arrays.toString(per));
            for (String id : ids) { Map<String, Object> g = reg.get(id); if (g == null || !id.equals(g.get("lease_id"))) throw fail("spread", id + " not found after issue"); }
            passed.add("spread");
        }

        // 2. atomic update
        {
            Lease.Registry reg = new Lease.Registry(policy, kit.open(), shards, System::currentTimeMillis);
            reg.accept(lease("hot"), new ArrayList<String>());
            List<Callable<Lease.Accept>> jobs = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                Map<String, Object> r = lease("hot", "seq", 2L, "renewed_at", T0 + 1000, "expires_at", T0 + 700_000L + i, "justification_digest", "r" + i);
                jobs.add(() -> reg.accept(r, new ArrayList<String>()));
            }
            ExecutorService ex = Executors.newFixedThreadPool(8);
            long wins = 0, forks = 0;
            try {
                for (Future<Lease.Accept> f : ex.invokeAll(jobs)) {
                    Lease.Accept a = f.get();
                    if (a.code == null) wins++; else if ("lease_fork".equals(a.code)) forks++;
                }
            } finally {
                ex.shutdown();
            }
            expectEq("atomic: one winner", wins, 1L);
            expectEq("atomic: the rest are forks", forks, 7L);
            expectEq("atomic: ledger length", seqs(reg.history("hot")), Arrays.asList(1L, 2L));
            passed.add("atomic update");
        }

        // 3. independence
        {
            Lease.Registry reg = new Lease.Registry(policy, kit.open(), shards, System::currentTimeMillis);
            List<String> ids = new ArrayList<>();
            for (int i = 0; i < 32; i++) ids.add("ind-" + i);
            for (String id : ids) reg.accept(lease(id), new ArrayList<String>());
            boolean all = true;
            for (String id : ids) all = okAccept(reg, lease(id, "seq", 2L, "renewed_at", T0 + 10, "expires_at", T0 + 900_000L, "justification_digest", "j2")) && all;
            expectEq("independence", all, true);
            passed.add("independent leases");
        }

        // 4 + 5. revocation placement
        {
            Lease.Registry reg = new Lease.Registry(policy, kit.open(), shards, System::currentTimeMillis);
            List<String> ids = new ArrayList<>();
            for (int i = 0; i < 64; i++) ids.add("rv-" + i);
            for (String id : ids) reg.accept(lease(id, "path", "db/prod/ro"), new ArrayList<String>());
            Map<String, Object> lone = lease("lone", "path", "other/x");
            reg.accept(lone, new ArrayList<String>());
            Map<String, Object> byLease = revocation("lease", "lone", T0 + 5);
            expectEq("revoke by lease", rev(reg.revoke(byLease)), okRevoked(1));
            int holders = 0;
            for (int i = 0; i < shards; i++) if (!reg.shardRevocations(i).isEmpty()) holders++;
            expectEq("lease revocation lands in exactly one shard", (long) holders, 1L);
            expectEq("revoked lease is dead", reg.check(lone, T0 + 6).decision, "deny");
            Map<String, Object> byPrefix = revocation("prefix", "db/prod", T0 + 10);
            expectEq("revoke by prefix covers every lease in every shard", rev(reg.revoke(byPrefix)), okRevoked(64));
            expectEq("revoke twice is idempotent", rev(reg.revoke(byPrefix)), okRevoked(64));
            for (int i = 0; i < shards; i++) {
                long n = 0;
                for (Object r : reg.shardRevocations(i)) if (byPrefix.get("sig").equals(Sig.map(r).get("sig"))) n++;
                if (n == 0) throw fail("prefix revocation in every shard", "shard " + i + " lacks it");
                expectEq("no duplicate in shard " + i, n, 1L);
            }
            for (String id : ids) {
                Map<String, Object> cur = reg.get(id);
                expectEq("check " + id, reg.check(cur, T0 + 11).decision, "deny");
                expectEq("renewal of " + id + " refused", okAccept(reg, lease(id, "path", "db/prod/ro", "seq", 2L, "renewed_at", T0 + 20, "expires_at", T0 + 700_000L, "justification_digest", "x")), false);
            }
            Map<String, Object> fresh = lease("after", "path", "db/prod/ro", "issued_at", T0 + 100, "renewed_at", T0 + 100, "expires_at", T0 + 900_000L);
            expectEq("a lease issued after the revocation is new", okAccept(reg, fresh), true);
            passed.add("revocation placement");
        }

        // 6. shard-count mismatch
        {
            AtomicKv kv = kit.open();
            new Lease.Registry(policy, kv, shards, System::currentTimeMillis).accept(lease("m1"), new ArrayList<String>());
            Lease.Registry other = new Lease.Registry(policy, kv, shards * 2, System::currentTimeMillis);
            expectEq("shard mismatch accept", acc(other.accept(lease("m2"), new ArrayList<String>())), storeUnreachable());
            expectEq("shard mismatch check", other.check(lease("m1"), T0 + 1).decision, "deny");
            passed.add("shard count is pinned");
        }

        // 7. restart
        if (kit.supportsReopen()) {
            AtomicKv kv = kit.open();
            Lease.Registry reg = new Lease.Registry(policy, kv, shards, System::currentTimeMillis);
            Map<String, Object> l = lease("persist");
            reg.accept(l, new ArrayList<String>());
            reg.accept(lease("persist", "seq", 2L, "renewed_at", T0 + 5, "expires_at", T0 + 800_000L, "justification_digest", "j2"), new ArrayList<String>());
            reg.revoke(revocation("prefix", "gone", T0 + 50));
            Lease.Registry again = new Lease.Registry(policy, kit.reopen(kv), shards, System::currentTimeMillis);
            expectEq("restart: renewal ledger", seqs(again.history("persist")), Arrays.asList(1L, 2L));
            expectEq("restart: revocation kept", (long) again.shardRevocations(0).size(), 1L);
            expectEq("restart: old record still superseded", again.check(l, T0 + 6).decision, "deny");
            passed.add("state survives a restart");
        }

        // 8. ceiling and pruning
        {
            AtomicLong now = new AtomicLong(T0);
            Lease.Policy capped = new Lease.Policy(Arrays.asList(AUTH));
            capped.maxTtlCeiling = DAY;
            Lease.Registry reg = new Lease.Registry(capped, kit.open(), shards, now::get);
            expectEq("ceiling refuses a longer max_ttl", acc(reg.accept(lease("big", "max_ttl", DAY + 1, "expires_at", T0 + 1000), new ArrayList<String>())), ceiling());
            reg.accept(lease("small", "max_ttl", DAY), new ArrayList<String>());
            reg.revoke(revocation("prefix", "svc", T0));
            for (int i = 0; i < shards; i++) expectEq("kept before the ceiling passes (shard " + i + ")", (long) reg.shardRevocations(i).size(), 1L);
            now.set(T0 + DAY + 1);
            long t = now.get();
            reg.accept(lease("trigger", "issued_at", t, "renewed_at", t, "expires_at", t + 1000, "max_ttl", 5000L), new ArrayList<String>());
            reg.revoke(revocation("prefix", "zzz", t));
            for (int i = 0; i < shards; i++) {
                boolean hasSvc = false, hasZzz = false;
                for (Object r : reg.shardRevocations(i)) {
                    Object v = Sig.map(r).get("value");
                    hasSvc = hasSvc || "svc".equals(v);
                    hasZzz = hasZzz || "zzz".equals(v);
                }
                if (hasSvc) throw fail("pruning", "shard " + i + " still holds the expired revocation");
                if (!hasZzz) throw fail("pruning", "shard " + i + " lost the fresh revocation");
            }
            passed.add("pruning bounds revocations");
        }
        return passed;
    }

    private static int shardOf(String id, int shards) { return GrantSigning.shardOf(id, shards); }

    private static Map<String, Object> okRevoked(long n) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("revoked", n);
        return m;
    }

    private static Map<String, Object> storeUnreachable() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("code", "store_unreachable");
        return m;
    }

    private static Map<String, Object> ceiling() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("code", "ttl_ceiling");
        return m;
    }
}
