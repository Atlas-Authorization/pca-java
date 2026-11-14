package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

/** Lease and break-glass registries: shard placement, the pinned shard count, history, pruning, private copies, store failures. */
class GrantsPitKillTest {
    static byte[] fill(int b) {
        byte[] x = new byte[32];
        Arrays.fill(x, (byte) b);
        return x;
    }

    static final Keys.EdKey AUTH = Keys.edFromSeed(fill(41));
    static final Keys.EdKey REV = Keys.edFromSeed(fill(42));

    static Json.Num n(long v) { return IntentJs.ofLong(v); }

    static String sign(Keys.EdKey k, String domain, Map<String, Object> body) {
        return Keys.b64u(k.sign(Pca.concat(domain.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body))));
    }

    static Map<String, Object> signed(Keys.EdKey k, String domain, Map<String, Object> all, String... bodyKeys) {
        Map<String, Object> body = new LinkedHashMap<>();
        for (String key : bodyKeys) body.put(key, all.get(key));
        Map<String, Object> out = new LinkedHashMap<>(all);
        out.put("sig", sign(k, domain, body));
        return out;
    }

    /** Counts nothing and decides nothing: update never runs its function (except for the shard-count pin). */
    static final class DeadKv implements AtomicKv {
        final MemoryAtomicKv in = new MemoryAtomicKv();
        @Override public Object get(String key) { return in.get(key); }
        @Override public void set(String key, Object value) { in.set(key, value); }
        @Override public Object update(String key, UnaryOperator<Object> fn) { return key.endsWith("/meta") ? in.update(key, fn) : null; }
    }

    static Map<String, Object> meta(long shards) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", n(1));
        m.put("shards", n(shards));
        return m;
    }

    @SuppressWarnings("unchecked") static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> list(Object o) { return (List<Object>) o; }

    // ---- shardOf and pinShards ----------------------------------------------------------------------------------------

    @Test void shardOfIsTheBigEndianFirstFourBytesOfSha256ModuloTheShardCount() throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < 400; i++) {
            String id = "holder-" + i;
            byte[] h = sha.digest(id.getBytes(StandardCharsets.UTF_8));
            BigInteger first4 = new BigInteger(1, Arrays.copyOfRange(h, 0, 4));
            for (int shards : new int[] {1, 2, 3, 7, 16, 255, 256, 4096}) {
                assertEquals(first4.mod(BigInteger.valueOf(shards)).intValue(), Lease.shardOf(id, shards), id + "/" + shards);
            }
        }
    }

    @Test void pinShardsWritesTheMetaOnceAndRefusesAnyOtherCount() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        assertTrue(Lease.pinShards(kv, "m", 16));
        Map<String, Object> m = map(kv.get("m"));
        assertEquals(new ArrayList<>(List.of("v", "shards")), new ArrayList<>(m.keySet()));
        assertEquals("1", m.get("v").toString());
        assertEquals("16", m.get("shards").toString());
        assertTrue(Lease.pinShards(kv, "m", 16));
        assertFalse(Lease.pinShards(kv, "m", 8));
        kv.set("s", "garbage");
        assertFalse(Lease.pinShards(kv, "s", 16), "a non-object meta is not a pin");
        Map<String, Object> bad = new LinkedHashMap<>();
        for (Object shards : new Object[] {"16", new Json.Num("16.5"), new Json.Num("1e3"), Boolean.TRUE}) {
            bad.put("shards", shards);
            kv.set("b", new LinkedHashMap<>(bad));
            assertFalse(Lease.pinShards(kv, "b", 16), String.valueOf(shards));
        }
        kv.set("n", new LinkedHashMap<String, Object>());
        assertFalse(Lease.pinShards(kv, "n", 16));
    }

    // ---- Lease ---------------------------------------------------------------------------------------------------------

    static final String[] LEASE_BODY = {"v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at", "renewed_at", "expires_at", "max_ttl", "authority"};

    static Map<String, Object> lease(String id, String path, long seq, long issued, long renewed, long expires, String digest) {
        Map<String, Object> l = new LinkedHashMap<>();
        l.put("v", n(1));
        l.put("lease_id", id);
        l.put("path", path);
        l.put("grant_ref", "g");
        l.put("holder", "h");
        l.put("requester", "r");
        l.put("approvers", new ArrayList<Object>(List.of("ap")));
        l.put("justification_digest", digest);
        l.put("seq", n(seq));
        l.put("issued_at", n(issued));
        l.put("renewed_at", n(renewed));
        l.put("expires_at", n(expires));
        l.put("max_ttl", n(100_000));
        l.put("authority", AUTH.id());
        return signed(AUTH, Lease.DOMAIN, l, LEASE_BODY);
    }

    static Map<String, Object> revocation(String target, String value, long at) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("v", n(1));
        r.put("target", target);
        r.put("value", value);
        r.put("revoked_at", n(at));
        r.put("authority", AUTH.id());
        return signed(AUTH, Lease.REVOKE_DOMAIN, r, "v", "target", "value", "revoked_at", "authority");
    }

    static Lease.Policy policy() { return new Lease.Policy(List.of(AUTH.id())); }

    static String leaseKey(String id, int shards) { return "lease/" + shards + "/" + Lease.shardOf(id, shards); }

    @Test void theRenewalLedgerHoldsOneExactLinePerAcceptedRecordAndNeverMutatesTheStoredValue() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        Lease.Registry reg = new Lease.Registry(policy(), kv);
        assertNull(reg.accept(lease("l", "db/prod", 1, 1000, 1000, 2000, "j1"), List.of()).code);
        Object before = kv.get(leaseKey("l", 16));
        List<Object> storedHistory = list(map(map(map(before).get("leases")).get("l")).get("history"));
        assertEquals(1, storedHistory.size());
        Lease.Accept second = reg.accept(lease("l", "db/prod", 2, 1000, 1500, 3000, "j2"), List.of());
        assertNull(second.code);
        assertTrue(second.replaced);
        assertEquals(2L, second.seq);
        assertEquals(1, storedHistory.size(), "the previous stored document keeps its own history");
        List<Object> h = reg.history("l");
        assertEquals(2, h.size());
        String[][] want = {{"1", "1000", "2000", "j1"}, {"2", "1500", "3000", "j2"}};
        for (int i = 0; i < 2; i++) {
            Map<String, Object> line = map(h.get(i));
            assertEquals(new ArrayList<>(List.of("seq", "renewed_at", "expires_at", "justification_digest")), new ArrayList<>(line.keySet()));
            assertEquals(want[i][0], line.get("seq").toString());
            assertEquals(want[i][1], line.get("renewed_at").toString());
            assertEquals(want[i][2], line.get("expires_at").toString());
            assertEquals(want[i][3], line.get("justification_digest"));
        }
        assertEquals(new ArrayList<>(), reg.history("unknown"));
        assertNotNull(reg.history("unknown"));
        assertNull(reg.get("unknown"));
        assertEquals("2", reg.get("l").get("seq").toString());
    }

    @Test void aShardDocumentThatIsNotTheExpectedShapeReadsAsEmpty() {
        Object[] docs = {"garbage", new LinkedHashMap<String, Object>(Map.of("leases", "x", "revocations", new ArrayList<>())), new LinkedHashMap<String, Object>(Map.of("leases", new LinkedHashMap<>(), "revocations", "x"))};
        for (Object doc : docs) {
            MemoryAtomicKv kv = new MemoryAtomicKv();
            kv.set(leaseKey("l", 16), doc);
            Lease.Registry reg = new Lease.Registry(policy(), kv);
            Lease.Accept a = reg.accept(lease("l", "db/prod", 1, 1000, 1000, 2000, "j1"), List.of());
            assertNull(a.code, String.valueOf(doc));
            assertTrue(a.replaced);
        }
    }

    @Test void aStoreWhoseShardCountDisagreesRefusesEverything() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        kv.set("lease/meta", meta(8));
        Lease.Registry reg = new Lease.Registry(policy(), kv);
        assertEquals("store_unreachable", reg.accept(lease("l", "db/prod", 1, 1000, 1000, 2000, "j1"), List.of()).code);
        Lease.Revoke r = reg.revoke(revocation("prefix", "db", 5));
        assertEquals("store_unreachable", r.code);
        assertEquals(0, r.revoked);
        assertEquals("shard count mismatch", assertThrows(IllegalStateException.class, () -> reg.get("l")).getMessage());
        assertEquals("shard count mismatch", assertThrows(IllegalStateException.class, () -> reg.history("l")).getMessage());
        assertEquals("store_unreachable", reg.check(lease("l", "db/prod", 1, 1000, 1000, 2000, "j1"), n(1500)).code);
    }

    @Test void theShardCountIsCheckedOnceAndRememberedWhileItHolds() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        Lease.Registry reg = new Lease.Registry(policy(), kv);
        assertNull(reg.accept(lease("l", "db/prod", 1, 1000, 1000, 2000, "j1"), List.of()).code);
        kv.set("lease/meta", meta(8));
        assertNotNull(reg.get("l"), "the pin was verified once; later calls do not re-read it");
        assertEquals(1, reg.history("l").size());
    }

    @Test void aPrefixRevocationWritesEveryShardAndNoMore() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        Lease.Registry reg = new Lease.Registry(policy(), kv, 3, () -> 0L);
        Lease.Revoke r = reg.revoke(revocation("prefix", "other", 100));
        assertNull(r.code);
        for (int i = 0; i < 3; i++) assertEquals(1, reg.shardRevocations(i).size(), "shard " + i);
        assertNull(kv.get("lease/3/3"), "no fourth shard document");
        assertThrows(IllegalArgumentException.class, () -> reg.shardRevocations(3));
        assertThrows(IllegalArgumentException.class, () -> reg.shardRevocations(-1));
    }

    @Test void aRevocationIsPrunedOnTheNextWriteOnceItsCeilingHasPassed() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        Lease.Policy p = policy();
        p.maxTtlCeiling = 100_000L;
        AtomicLong clock = new AtomicLong(500);
        Lease.Registry reg = new Lease.Registry(p, kv, 16, clock::get);
        assertNull(reg.revoke(revocation("prefix", "other", 100)).code);
        for (int i = 0; i < 16; i++) assertEquals(1, reg.shardRevocations(i).size());
        clock.set(1_000_000L);
        assertNull(reg.accept(lease("l", "db/prod", 1, 1000, 1000, 2000, "j1"), List.of()).code);
        int shard = Lease.shardOf("l", 16);
        for (int i = 0; i < 16; i++) assertEquals(i == shard ? 0 : 1, reg.shardRevocations(i).size(), "shard " + i);
        // a revocation inside its ceiling is kept by a revoke write
        clock.set(500);
        assertNull(reg.revoke(revocation("prefix", "another", 100)).code);
        assertEquals(1, reg.shardRevocations(shard).size());
    }

    // ---- BreakGlass ----------------------------------------------------------------------------------------------------

    static final String[] BG_BODY = {"v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority"};
    static final String[] REVIEW_BODY = {"v", "id", "outcome", "notes_digest", "at", "reviewer"};

    static Map<String, Object> grant(String id, String holder, long issued, long expires, long maxUses, long reviewWithin) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("v", n(1));
        b.put("id", id);
        b.put("holder", holder);
        b.put("grant_ref", "gr");
        b.put("reason_digest", "rd");
        b.put("max_uses", n(maxUses));
        b.put("issued_at", n(issued));
        b.put("expires_at", n(expires));
        b.put("review_within", n(reviewWithin));
        b.put("notify_to", "ops");
        b.put("authority", AUTH.id());
        return signed(AUTH, BreakGlass.DOMAIN, b, BG_BODY);
    }

    static Map<String, Object> review(String id, String outcome, long at) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("v", n(1));
        r.put("id", id);
        r.put("outcome", outcome);
        r.put("notes_digest", "nd");
        r.put("at", n(at));
        r.put("reviewer", REV.id());
        return signed(REV, BreakGlass.REVIEW_DOMAIN, r, REVIEW_BODY);
    }

    static BreakGlass.Registry bg(AtomicKv kv, int shards) { return new BreakGlass.Registry(List.of(AUTH.id()), List.of(REV.id()), kv, shards); }

    static String bgKey(String holder, int shards) { return "breakglass/" + shards + "/" + Lease.shardOf(holder, shards); }

    @Test void theShardCountOfABreakGlassRegistryIsBounded() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        for (int bad : new int[] {0, -1, 4097}) {
            assertEquals("BreakGlassRegistry: shards must be an integer from 1 to 4096", assertThrows(IllegalArgumentException.class, () -> bg(kv, bad)).getMessage(), String.valueOf(bad));
        }
        assertNotNull(bg(kv, 1));
        assertNotNull(bg(kv, 4096));
        assertNotNull(new BreakGlass.Registry(List.of(), List.of(), kv, 1));
    }

    @Test void theDefaultShardCountIsSixteen() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        BreakGlass.Registry reg = new BreakGlass.Registry(List.of(AUTH.id()), List.of(REV.id()), kv);
        assertEquals(true, reg.accept(grant("g1", "ha", 1000, 5000, 3, 100), n(1000)).get("ok"));
        assertEquals("16", map(kv.get("breakglass/meta")).get("shards").toString());
        assertEquals("1", map(kv.get("breakglass/meta")).get("v").toString());
        assertNotNull(kv.get(bgKey("ha", 16)));
    }

    @Test void usesAreNumberedExactlyAndTheStoredDocumentIsNeverMutatedInPlace() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        BreakGlass.Registry reg = bg(kv, 1);
        assertEquals(true, reg.accept(grant("g1", "ha", 1000, 5000, 3, 100), n(1000)).get("ok"));
        Map<String, Object> u1 = reg.use("g1", "ha", "d1", n(1000), true);
        assertEquals("allow", u1.get("decision"));
        assertEquals("g1", u1.get("id"));
        assertEquals(1L, u1.get("use"));
        assertEquals(2L, u1.get("remaining"));
        assertEquals(1100L, u1.get("review_due"));
        Object before = kv.get(bgKey("ha", 1));
        List<Object> storedUses = list(map(map(map(before).get("grants")).get("g1")).get("uses"));
        assertEquals(1, storedUses.size());
        Map<String, Object> u2 = reg.use("g1", "ha", "d2", n(1010), true);
        assertEquals(2L, u2.get("use"));
        assertEquals(1L, u2.get("remaining"));
        assertEquals(1100L, u2.get("review_due"));
        assertEquals(1, storedUses.size(), "the earlier stored document keeps its own use log");
        List<Object> uses = reg.uses("ha", "g1");
        assertEquals(2, uses.size());
        String[][] want = {{"1", "d1", "1000"}, {"2", "d2", "1010"}};
        for (int i = 0; i < 2; i++) {
            Map<String, Object> u = map(uses.get(i));
            assertEquals(new ArrayList<>(List.of("n", "action_digest", "at")), new ArrayList<>(u.keySet()));
            assertEquals(want[i][0], u.get("n").toString());
            assertEquals(want[i][1], u.get("action_digest"));
            assertEquals(want[i][2], u.get("at").toString());
        }
        assertEquals(new ArrayList<>(), reg.uses("ha", "unknown"));
        assertNotNull(reg.uses("ha", "unknown"));
    }

    @Test void holdersSharingAShardDoNotShareAFreezeOrAGrant() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        BreakGlass.Registry reg = bg(kv, 1);
        assertEquals(true, reg.accept(grant("g1", "ha", 1000, 5000, 3, 100), n(1000)).get("ok"));
        assertEquals("allow", reg.use("g1", "ha", "d1", n(1000), true).get("decision"));
        // ha's review clock has run out: ha is frozen, hb (same shard) is not
        assertTrue(reg.frozen("ha", n(1200)));
        assertFalse(reg.frozen("hb", n(1200)));
        Map<String, Object> accepted = reg.accept(grant("g2", "hb", 1000, 5000, 3, 100), n(1200));
        assertEquals(true, accepted.get("ok"), String.valueOf(accepted));
        assertEquals(true, accepted.get("replaced"));
        assertEquals("allow", reg.use("g2", "hb", "d9", n(1200), true).get("decision"));
        assertEquals("holder_frozen", reg.accept(grant("g3", "ha", 1000, 5000, 3, 100), n(1200)).get("code"));
        // a grant id that belongs to another holder
        assertEquals("wrong_holder", reg.use("g1", "hb", "d", n(1200), true).get("code"));
        assertEquals("g1", reg.use("g1", "hb", "d", n(1200), true).get("id"));
        // a review submitted under the wrong holder does not find the grant
        Map<String, Object> wrong = reg.review(review("g1", "justified", 1050), "hb", n(1200));
        assertEquals(false, wrong.get("ok"));
        assertEquals("unknown_break_glass", wrong.get("code"));
        Map<String, Object> right = reg.review(review("g1", "justified", 1050), "ha", n(1200));
        assertEquals(true, right.get("ok"), String.valueOf(right));
        assertFalse(reg.frozen("ha", n(1200)));
    }

    @Test void aShardDocumentThatIsNotTheExpectedShapeReadsAsEmptyForBreakGlass() {
        Object[] docs = {"garbage", new LinkedHashMap<String, Object>(Map.of("grants", "x"))};
        for (Object doc : docs) {
            MemoryAtomicKv kv = new MemoryAtomicKv();
            kv.set(bgKey("ha", 16), doc);
            BreakGlass.Registry reg = bg(kv, 16);
            Map<String, Object> a = reg.accept(grant("g1", "ha", 1000, 5000, 3, 100), n(1000));
            assertEquals(true, a.get("ok"), String.valueOf(doc));
            assertEquals(true, a.get("replaced"));
        }
    }

    @Test void aStoreThatNeverRunsTheUpdateReportsTheStoreAsUnreachable() {
        DeadKv kv = new DeadKv();
        BreakGlass.Registry reg = bg(kv, 16);
        Map<String, Object> a = reg.accept(grant("g1", "ha", 1000, 5000, 3, 100), n(1000));
        assertEquals(false, a.get("ok"));
        assertEquals("store_unreachable", a.get("code"));
        Map<String, Object> u = reg.use("g1", "ha", "d1", n(1000), true);
        assertEquals("deny", u.get("decision"));
        assertEquals("store_unreachable", u.get("code"));
        assertEquals("g1", u.get("id"));
        Map<String, Object> r = reg.review(review("g1", "justified", 1050), "ha", n(1200));
        assertEquals(false, r.get("ok"));
        assertEquals("store_unreachable", r.get("code"));
    }

    @Test void aStoreWhoseShardCountDisagreesRefusesEveryBreakGlassCall() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        BreakGlass.Registry good = bg(kv, 16);
        assertEquals(true, good.accept(grant("g1", "ha", 1000, 5000, 3, 100), n(1000)).get("ok"));
        assertEquals("allow", good.use("g1", "ha", "d1", n(1000), true).get("decision"));
        kv.set("breakglass/meta", meta(8));
        BreakGlass.Registry reg = bg(kv, 16);
        Map<String, Object> a = reg.accept(grant("g2", "hb", 1000, 5000, 3, 100), n(1000));
        assertEquals(false, a.get("ok"));
        assertEquals("store_unreachable", a.get("code"));
        Map<String, Object> u = reg.use("g1", "ha", "d2", n(1001), true);
        assertEquals("deny", u.get("decision"));
        assertEquals("store_unreachable", u.get("code"));
        assertEquals("g1", u.get("id"));
        Map<String, Object> r = reg.review(review("g1", "justified", 1050), "ha", n(1060));
        assertEquals(false, r.get("ok"));
        assertEquals("store_unreachable", r.get("code"));
        assertTrue(reg.frozen("ha", n(1001)), "an unreachable store reads as frozen");
        assertEquals(new ArrayList<>(), reg.uses("ha", "g1"));
        // the good registry saw nothing change
        assertEquals(1, good.uses("ha", "g1").size());
    }

    @Test void theShardCountPinOfABreakGlassRegistryIsRememberedOnceVerified() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        BreakGlass.Registry reg = bg(kv, 16);
        assertEquals(true, reg.accept(grant("g1", "ha", 1000, 5000, 3, 100), n(1000)).get("ok"));
        kv.set("breakglass/meta", meta(8));
        assertEquals("allow", reg.use("g1", "ha", "d1", n(1000), true).get("decision"));
        assertEquals(1, reg.uses("ha", "g1").size());
    }
}
