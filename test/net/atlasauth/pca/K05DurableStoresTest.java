package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

/** PCA 0.5 H15 / F4 / F5: lease, break-glass and blueprint registries need a durable kv; their state survives a new registry over the same kv. */
class K05DurableStoresTest {
    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static final Map<String, Object> LEASES = Track3Vectors.load("lease-vectors.json");
    static final Map<String, Object> BG = Track3Vectors.load("break-glass-vectors.json");
    static final Map<String, Object> BP = Track3Vectors.load("blueprint-vectors.json");

    static Lease.Policy leasePolicy() { return new Lease.Policy(List.of((String) LEASES.get("authority"))); }
    static Object lease(int i) { return l(LEASES.get("records")).get(i); }
    static Object leaseRevocation(int i) { return l(LEASES.get("revocations")).get(i); }

    /** An AtomicKv that fails every call. */
    static final class ThrowingKv implements AtomicKv {
        @Override public Object get(String key) { throw new IllegalStateException("down"); }
        @Override public void set(String key, Object value) { throw new IllegalStateException("down"); }
        @Override public Object update(String key, UnaryOperator<Object> fn) { throw new IllegalStateException("down"); }
    }

    @Test void constructorsRequireAKv() {
        assertEquals("LeaseRegistry: a durable key-value store is required (MemoryAtomicKv is for tests and single-process use)",
            assertThrows(IllegalArgumentException.class, () -> new Lease.Registry(leasePolicy(), null)).getMessage());
        assertEquals("BreakGlassRegistry: a durable key-value store is required (MemoryAtomicKv is for tests and single-process use)",
            assertThrows(IllegalArgumentException.class, () -> new BreakGlass.Registry(List.of(), List.of(), null)).getMessage());
        assertEquals("BlueprintRegistry: a durable BlueprintStore is required (MemoryAtomicKv is for tests and single-process use)",
            assertThrows(IllegalArgumentException.class, () -> new Blueprint.Registry(List.of(), null)).getMessage());
        for (int bad : new int[] {0, -1, 4097}) {
            assertEquals("LeaseRegistry: shards must be an integer from 1 to 4096",
                assertThrows(IllegalArgumentException.class, () -> new Lease.Registry(leasePolicy(), new MemoryAtomicKv(), bad, () -> 0L)).getMessage());
            assertEquals("BreakGlassRegistry: shards must be an integer from 1 to 4096",
                assertThrows(IllegalArgumentException.class, () -> new BreakGlass.Registry(List.of(), List.of(), new MemoryAtomicKv(), bad)).getMessage());
        }
        assertEquals(1, new Lease.Registry(leasePolicy(), new MemoryAtomicKv(), 1, () -> 0L).shardCount());
        assertEquals(4096, new Lease.Registry(leasePolicy(), new MemoryAtomicKv(), 4096, () -> 0L).shardCount());
        assertEquals(16, new Lease.Registry(leasePolicy(), new MemoryAtomicKv()).shardCount());
    }

    @Test void aRevokedLeaseStaysRevokedInANewRegistryOverTheSameKv() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        Lease.Registry a = new Lease.Registry(leasePolicy(), kv);
        assertNull(a.accept(lease(0), List.of()).code);
        Lease.Revoke r = a.revoke(leaseRevocation(0)); // target lease L1
        assertNull(r.code);
        assertEquals(1, r.revoked);
        Lease.Registry b = new Lease.Registry(leasePolicy(), kv);
        assertEquals("revoked", b.check(lease(0), 1800000050000L).code);
        assertEquals("revoked", b.accept(lease(1), List.of()).code); // the renewal is covered by the stored revocation
        assertEquals(1, b.history("L1").size());
        assertEquals("L1", b.get("L1").get("lease_id"));
        // the shard count is pinned in the store: another count is refused
        Lease.Registry other = new Lease.Registry(leasePolicy(), kv, 8, () -> 0L);
        assertEquals("store_unreachable", other.accept(lease(0), List.of()).code);
        assertEquals("store_unreachable", other.revoke(leaseRevocation(0)).code);
        assertEquals("store_unreachable", other.check(lease(0), 1800000050000L).code);
    }

    @Test void aPrefixRevocationIsWrittenToEveryShard() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        Lease.Registry a = new Lease.Registry(leasePolicy(), kv, 4, () -> 0L);
        assertNull(a.accept(lease(0), List.of()).code);
        Lease.Revoke r = a.revoke(leaseRevocation(1)); // prefix db/prod
        assertNull(r.code);
        assertEquals(1, r.revoked);
        for (int i = 0; i < 4; i++) assertEquals(1, a.shardRevocations(i).size(), "shard " + i);
        assertEquals(null, a.revoke(leaseRevocation(1)).code); // idempotent
        for (int i = 0; i < 4; i++) assertEquals(1, a.shardRevocations(i).size(), "shard " + i);
        assertThrows(IllegalArgumentException.class, () -> a.shardRevocations(4));
        assertThrows(IllegalArgumentException.class, () -> a.shardRevocations(-1));
        // a lease revocation is written to its own shard only
        Lease.Registry b = new Lease.Registry(leasePolicy(), new MemoryAtomicKv(), 4, () -> 0L);
        assertNull(b.revoke(leaseRevocation(0)).code);
        int with = 0;
        for (int i = 0; i < 4; i++) with += b.shardRevocations(i).size();
        assertEquals(1, with);
    }

    @Test void revocationsArePrunedOnlyWithACeiling() {
        long revokedAt = 1800000100000L;
        long ceiling = 3600000L;
        long[] now = {revokedAt + ceiling};
        Lease.Policy p = leasePolicy();
        p.maxTtlCeiling = ceiling;
        MemoryAtomicKv kv = new MemoryAtomicKv();
        Lease.Registry reg = new Lease.Registry(p, kv, 2, () -> now[0]);
        assertNull(reg.revoke(leaseRevocation(3)).code); // grant g1, revoked_at = revokedAt; now = revoked_at + ceiling: kept
        assertEquals(1, reg.shardRevocations(0).size());
        now[0] = revokedAt + ceiling + 1; // past the ceiling: the next write to a shard drops it (it could only cover leases already beyond their cap)
        assertEquals("revoked", reg.accept(lease(0), List.of()).code); // still covered at decision time: pruning happens after the checks
        assertNull(reg.revoke(leaseRevocation(0)).code); // a revocation of lease L1 is written to L1's shard only: that shard is pruned, the other is not
        int l1 = Lease.shardOf("L1", 2);
        assertEquals(0, reg.shardRevocations(l1).size());
        assertEquals(1, reg.shardRevocations(1 - l1).size());
        // with no ceiling nothing is ever pruned
        Lease.Registry keep = new Lease.Registry(leasePolicy(), new MemoryAtomicKv(), 2, () -> Long.MAX_VALUE / 2);
        assertNull(keep.revoke(leaseRevocation(3)).code);
        assertNull(keep.revoke(leaseRevocation(0)).code);
        assertEquals(3, keep.shardRevocations(0).size() + keep.shardRevocations(1).size()); // the grant revocation in both shards, L1 in one
        assertEquals("revoked", keep.accept(lease(0), List.of()).code);
    }

    @Test void breakGlassBudgetAndFreezeSurviveANewRegistry() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        List<String> auth = List.of((String) BG.get("authority")), revs = List.of((String) BG.get("reviewer"));
        Object bg2 = l(BG.get("grants")).get(1); // bg2: max_uses 1, holder agent
        BreakGlass.Registry a = new BreakGlass.Registry(auth, revs, kv);
        assertEquals(Boolean.TRUE, a.accept(bg2, 1800000000000L).get("ok"));
        assertEquals("allow", a.use("bg2", "agent", "act-1", 1800000000000L, true).get("decision"));
        BreakGlass.Registry b = new BreakGlass.Registry(auth, revs, kv);
        Map<String, Object> second = b.use("bg2", "agent", "act-2", 1800000000001L, true);
        assertEquals("deny", second.get("decision"));
        assertEquals("budget_exhausted", second.get("code"));
        assertEquals(1, b.uses("agent", "bg2").size());
        assertEquals("act-1", m(b.uses("agent", "bg2").get(0)).get("action_digest"));
        assertTrue(b.uses("agent", "nope").isEmpty());
        // the unreviewed use freezes the holder once the review clock has run out, in the new registry too
        long late = 1800000000000L + 1800000L;
        assertTrue(b.frozen("agent", late));
        assertFalse(b.frozen("agent", late - 1));
        // a store that cannot answer fails closed
        BreakGlass.Registry down = new BreakGlass.Registry(auth, revs, new ThrowingKv());
        assertEquals("store_unreachable", down.accept(bg2, 1800000000000L).get("code"));
        assertEquals("store_unreachable", down.use("bg2", "agent", "act", 1800000000000L, true).get("code"));
        assertEquals("store_unreachable", down.review(l(BG.get("reviews")).get(0), "agent", 1800000000000L).get("code"));
        assertTrue(down.frozen("agent", 1800000000000L));
    }

    @Test void aThrowingKvIsStoreUnreachable() {
        Lease.Registry lease = new Lease.Registry(leasePolicy(), new ThrowingKv());
        assertEquals("store_unreachable", lease.accept(lease(0), List.of()).code);
        assertEquals("store_unreachable", lease.revoke(leaseRevocation(0)).code);
        assertEquals("store_unreachable", lease.check(lease(0), 1800000000000L).code);
        Blueprint.Registry bp = new Blueprint.Registry(List.of((String) BP.get("operator")), new ThrowingKv());
        assertEquals("store_unreachable", bp.accept(l(BP.get("records")).get(0)).code);
    }

    @Test void aDisabledBlueprintStaysDisabledAcrossARestart() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        List<String> ops = List.of((String) BP.get("operator"));
        List<Object> recs = l(BP.get("records"));
        Blueprint.Registry a = new Blueprint.Registry(ops, kv);
        assertNull(a.accept(recs.get(2)).code); // active, epoch 3
        assertEquals(3L, a.epoch());
        Blueprint.Registry b = new Blueprint.Registry(ops, kv);
        assertEquals(3L, b.epoch());
        assertEquals("stale_epoch", b.accept(recs.get(0)).code); // epoch 1 cannot replace epoch 3
        assertEquals("stale_epoch", b.accept(recs.get(3)).code); // epoch 2
        assertNull(b.accept(recs.get(2)).code); // the identical record again is a no-op
        assertEquals(3L, b.epoch());
        Blueprint.Registry fresh = new Blueprint.Registry(ops, new MemoryAtomicKv());
        assertEquals(0L, fresh.epoch());
    }

    @Test void theAdmissionHook() {
        List<String> ops = List.of((String) BP.get("operator"));
        List<Object> recs = l(BP.get("records"));
        Blueprint.Registry reg = new Blueprint.Registry(ops, new MemoryAtomicKv());
        assertNull(reg.accept(recs.get(9)).code); // active, epoch 1, runtime_pins
        Map<String, Object> bp = reg.get(m(recs.get(9)).get("key").toString());
        String key = (String) bp.get("key");
        List<Object> chain = List.of(Map.of("issuer", "principal", "holder", key), Map.of("issuer", key, "holder", "inst1"));
        long now = 1800000000000L;
        assertEquals("admission_required", Blueprint.check(chain, reg, now, "require", null).code);
        assertEquals("not_admitted", Blueprint.check(chain, reg, now, "require", null, (h, b) -> false).code);
        Blueprint.Decision ok = Blueprint.check(chain, reg, now, "require", null, (h, b) -> h.equals("inst1") && b.get("id").equals("support-bot"));
        assertEquals("allow", ok.decision);
        assertEquals(List.of("support-bot"), ok.governed);
        assertEquals("store_unreachable", Blueprint.check(chain, reg, now, "require", null, (h, b) -> { throw new IllegalStateException("x"); }).code);
    }
}
