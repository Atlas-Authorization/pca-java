package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

/**
 * Exact-output kills for {@link ContractEnforcer}: construction guards, the durable document shape, every admit / deny / latch path of {@code check},
 * the read-only {@code peek}, {@code state}, and the signed {@code reset}, with a recording clock and failing stores.
 */
public class ContractEnforcerPitKill1Test {
    static Object j(String s) { return Json.parseLenient(s.replace('\'', '"')); }

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static void eq(String want, Object got) { assertEquals(Json.canonicalize(j(want)), Json.canonicalize(got)); }

    static byte[] seed(int fill) {
        byte[] s = new byte[32];
        Arrays.fill(s, (byte) fill);
        return s;
    }

    static final byte[] SEED = seed(7);
    static final String CLAUSES = "[{'id':'no-send','kind':'never','p':{'verb':'send'}},{'id':'order','kind':'precedes','p':{'verb':'review'},'q':{'verb':'deploy'}}]";
    static final String CORRUPT = "<state>: stored state is corrupt or belongs to another contract";
    static final double T0 = 1_800_000_000_000.0;

    static String principal() { return Keys.edFromSeed(SEED).id(); }

    static Map<String, Object> signed() {
        return Contracts.signContract(m(j("{'version':1,'principal':'" + principal() + "','clauses':" + CLAUSES + "}")), SEED);
    }

    static Object act(String verb) { return j("{'action':{'verb':'" + verb + "','resource':'/r'}}"); }

    /** A store whose calls can be made to fail or to answer without doing anything. */
    static final class FaultKv implements AtomicKv {
        final MemoryAtomicKv inner = new MemoryAtomicKv();
        boolean getThrows, updateThrows, updateSkips;

        @Override public Object get(String key) {
            if (getThrows) throw new IllegalStateException("get down");
            return inner.get(key);
        }
        @Override public void set(String key, Object value) { inner.set(key, value); }
        @Override public Object update(String key, UnaryOperator<Object> fn) {
            if (updateThrows) throw new IllegalStateException("update down");
            if (updateSkips) return null;
            return inner.update(key, fn);
        }
    }

    static final class Fx {
        final MemoryAtomicKv kv = new MemoryAtomicKv();
        final double[] wall = {T0};
        final int[] calls = {0};
        final Map<String, Object> contract = signed();
        final ContractEnforcer en;

        Fx(boolean latch) {
            en = ContractEnforcer.open(kv, contract, principal(), "k", () -> { calls[0]++; return wall[0]; }, latch);
        }

        String id() { return (String) contract.get("id"); }

        Map<String, Object> doc() { return m(kv.get("k")); }
    }

    static void expect(ContractEnforcer.Result r, boolean allow, String reason, List<Object> violated, List<Object> reasons, long seq) {
        assertEquals(allow, r.allow, "allow");
        assertEquals(reason, r.reason, "reason");
        assertEquals(violated, r.violated, "violated");
        assertEquals(reasons, r.reasons, "reasons");
        assertEquals(seq, r.seq, "seq");
    }

    static List<Object> l(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    // ---- open / signReset -----------------------------------------------------------------------------------------------

    @Test void openRefusesWhatItCannotPin() {
        Map<String, Object> c = signed();
        IllegalArgumentException a = assertThrows(IllegalArgumentException.class, () -> ContractEnforcer.open(null, c, principal(), "k", () -> 1, true));
        assertEquals("ContractEnforcer: a durable key-value store is required", a.getMessage());
        for (String p : new String[] {null, ""}) {
            IllegalArgumentException b = assertThrows(IllegalArgumentException.class, () -> ContractEnforcer.open(new MemoryAtomicKv(), c, p, "k", () -> 1, true));
            assertEquals("ContractEnforcer: a pinned principal is required", b.getMessage());
        }
        IllegalArgumentException d = assertThrows(IllegalArgumentException.class, () -> ContractEnforcer.open(new MemoryAtomicKv(), c, "someone-else", "k", () -> 1, true));
        assertEquals("ContractEnforcer: contract refused: principal mismatch", d.getMessage());
        Map<String, Object> unsigned = new LinkedHashMap<>(c);
        unsigned.remove("id");
        unsigned.remove("sig");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ContractEnforcer.open(new MemoryAtomicKv(), unsigned, principal(), "k", () -> 1, true));
        assertEquals("ContractEnforcer: contract refused: id does not match content", e.getMessage());
        assertTrue(ContractEnforcer.open(new MemoryAtomicKv(), c, principal(), "k", () -> 1, true) != null);
    }

    @Test void theKeyDefaultsToTheContractIdAndTheClockToTheWallClock() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        Map<String, Object> c = signed();
        ContractEnforcer en = ContractEnforcer.open(kv, c, principal(), null, null, true);
        long before = System.currentTimeMillis();
        ContractEnforcer.Result r = en.check(act("read"), true);
        long after = System.currentTimeMillis();
        assertTrue(r.allow);
        assertNull(kv.get("k"));
        Map<String, Object> doc = m(kv.get("contract/" + Contracts.contractId(c)));
        assertEquals(c.get("id"), doc.get("contract_id"));
        double now = Prohibitions.dv(m(doc.get("state")).get("now"));
        assertTrue(now >= before && now <= after, "now " + now + " not in [" + before + ", " + after + "]");
        // peek also reads the default clock
        assertTrue(en.peek(act("read")).allow);
    }

    @Test void signResetIsTheSignatureOverTheDomainedHashOfIdAndSeq() {
        String sig = ContractEnforcer.signReset(SEED, "id1", 1);
        assertEquals(86, sig.length());
        assertEquals(sig, ContractEnforcer.signReset(SEED, "id1", 1));
        assertNotEquals(sig, ContractEnforcer.signReset(SEED, "id1", 2));
        assertNotEquals(sig, ContractEnforcer.signReset(SEED, "id2", 1));
        assertNotEquals(sig, ContractEnforcer.signReset(seed(8), "id1", 1));
        byte[] msg = Pca.concat(ContractEnforcer.RESET_DOMAIN.getBytes(StandardCharsets.UTF_8), AttestCommon.sha256Sum("id1:1".getBytes(StandardCharsets.UTF_8)));
        assertTrue(Pca.verifyB64u(principal(), msg, sig));
        byte[] other = Pca.concat(ContractEnforcer.RESET_DOMAIN.getBytes(StandardCharsets.UTF_8), AttestCommon.sha256Sum("id1:2".getBytes(StandardCharsets.UTF_8)));
        assertFalse(Pca.verifyB64u(principal(), other, sig));
    }

    // ---- check ----------------------------------------------------------------------------------------------------------

    @Test void anAdmittedActionCreatesAndThenAdvancesTheDocument() {
        Fx fx = new Fx(true);
        assertNull(fx.kv.get("k"));
        assertNull(fx.en.state());
        expect(fx.en.check(act("read"), true), true, "ok", l(), l(), 1);
        Map<String, Object> doc = fx.doc();
        assertEquals(new HashSet<>(Arrays.asList("v", "contract_id", "state")), doc.keySet());
        eq("1", doc.get("v"));
        assertEquals(fx.id(), doc.get("contract_id"));
        eq("1", m(doc.get("state")).get("seq"));
        eq("1800000000000", m(doc.get("state")).get("now"));
        eq("{}", m(doc.get("state")).get("latched"));
        assertEquals(1, fx.calls[0]);
        expect(fx.en.check(act("review"), true), true, "ok", l(), l(), 2);
        eq("{'order':1800000000000}", m(fx.doc().get("state")).get("latched"));
        assertEquals(2, fx.calls[0]);
        expect(fx.en.check(act("deploy"), true), true, "ok", l(), l(), 3);
        Map<String, Object> st = fx.en.state();
        assertEquals(new HashSet<>(Arrays.asList("state", "latched")), st.keySet());
        assertEquals(Boolean.FALSE, st.get("latched"));
        eq("3", m(st.get("state")).get("seq"));
        assertNull(Prohibitions.stateProblem(st.get("state")));
    }

    @Test void theStoredClockNeverMovesBackwardsAndFollowsAForwardWallClock() {
        Fx fx = new Fx(true);
        fx.wall[0] = 2000;
        expect(fx.en.check(act("read"), true), true, "ok", l(), l(), 1);
        eq("2000", m(fx.doc().get("state")).get("now"));
        fx.wall[0] = 1500;
        expect(fx.en.check(act("read"), true), true, "ok", l(), l(), 2);
        eq("2000", m(fx.doc().get("state")).get("now"));
        fx.wall[0] = 3000;
        expect(fx.en.check(act("read"), true), true, "ok", l(), l(), 3);
        eq("3000", m(fx.doc().get("state")).get("now"));
    }

    @Test void aClockThatIsNotFiniteIsAStateErrorOnAStoredDocument() {
        for (double bad : new double[] {Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY}) {
            Fx fx = new Fx(true);
            expect(fx.en.check(act("read"), true), true, "ok", l(), l(), 1);
            Object before = fx.kv.get("k");
            fx.wall[0] = bad;
            expect(fx.en.check(act("read"), true), false, "state-error", l(), l("<state>: clock is not finite"), 1);
            assertSame(before, fx.kv.get("k"));
        }
    }

    @Test void aClockThatIsNotFiniteOnTheFirstCallStoresNothing() {
        for (double bad : new double[] {Double.NaN, Double.POSITIVE_INFINITY}) {
            Fx fx = new Fx(true);
            fx.wall[0] = bad;
            expect(fx.en.check(act("read"), true), false, "state-error", l(), l("<state>: advance failed: clock regression"), 0);
            assertNull(fx.kv.get("k"));
        }
        // minus infinity falls back to the genesis clock 0 and the first action is admitted at 0
        Fx neg = new Fx(true);
        neg.wall[0] = Double.NEGATIVE_INFINITY;
        expect(neg.en.check(act("read"), true), true, "ok", l(), l(), 1);
        eq("0", m(neg.doc().get("state")).get("now"));
    }

    @Test void notPermittedDeniesWithoutLatchingOrStoring() {
        Fx fx = new Fx(true);
        expect(fx.en.check(act("read"), false), false, "permission", l(), l("<permission>: not permitted"), 0);
        assertNull(fx.kv.get("k"));
        expect(fx.en.check(act("read"), true), true, "ok", l(), l(), 1);
        Object before = fx.kv.get("k");
        expect(fx.en.check(act("read"), false), false, "permission", l(), l("<permission>: not permitted"), 1);
        assertSame(before, fx.kv.get("k"));
        assertEquals(Boolean.FALSE, fx.en.state().get("latched"));
    }

    @Test void aRealViolationLatchesAndEverythingAfterItIsDeniedUntilAReset() {
        Fx fx = new Fx(true);
        expect(fx.en.check(act("read"), true), true, "ok", l(), l(), 1);
        expect(fx.en.check(act("read"), true), true, "ok", l(), l(), 2);
        ContractEnforcer.Result v = fx.en.check(act("send"), true);
        expect(v, false, "violated", l("no-send"), l("no-send: never-invariant violated (forbidden action)"), 2);
        Map<String, Object> doc = fx.doc();
        assertEquals(new HashSet<>(Arrays.asList("v", "contract_id", "state", "latched")), doc.keySet());
        eq("{'seq':2,'violated':['no-send']}", doc.get("latched"));
        eq("2", m(doc.get("state")).get("seq"));
        assertEquals(Boolean.TRUE, fx.en.state().get("latched"));
        // latched: every action is denied, whatever it is and whatever the permission, and nothing is written
        for (boolean permitted : new boolean[] {true, false}) {
            ContractEnforcer.Result r = fx.en.check(act("read"), permitted);
            expect(r, false, "latched", l("no-send"), l("<latched>: contract violated at seq 2"), 2);
            assertSame(doc, fx.kv.get("k"));
        }
        expect(fx.en.peek(act("read")), false, "latched", l("no-send"), l("<latched>: contract violated at seq 2"), 2);
        // a wrong or foreign reset does not clear it
        String id = fx.id();
        assertFalse(fx.en.reset(null));
        assertFalse(fx.en.reset("garbage"));
        assertFalse(fx.en.reset(ContractEnforcer.signReset(SEED, id, 1)));
        assertFalse(fx.en.reset(ContractEnforcer.signReset(SEED, id, 3)));
        assertFalse(fx.en.reset(ContractEnforcer.signReset(SEED, "other-contract", 2)));
        assertFalse(fx.en.reset(ContractEnforcer.signReset(seed(8), id, 2)));
        assertSame(doc, fx.kv.get("k"));
        assertEquals(Boolean.TRUE, fx.en.state().get("latched"));
        // the principal's reset at the latched sequence clears it and the chain goes on
        assertTrue(fx.en.reset(ContractEnforcer.signReset(SEED, id, 2)));
        assertEquals(new HashSet<>(Arrays.asList("v", "contract_id", "state")), fx.doc().keySet());
        assertEquals(Boolean.FALSE, fx.en.state().get("latched"));
        expect(fx.en.check(act("read"), true), true, "ok", l(), l(), 3);
        // and a second reset has nothing to clear
        assertFalse(fx.en.reset(ContractEnforcer.signReset(SEED, id, 3)));
    }

    @Test void theFirstEverViolationLatchesAtSequenceZero() {
        Fx fx = new Fx(true);
        expect(fx.en.check(act("deploy"), true), false, "violated", l("order"), l("order: precedence violated (prerequisite p not yet admitted before q)"), 0);
        eq("{'seq':0,'violated':['order']}", fx.doc().get("latched"));
        expect(fx.en.check(act("review"), true), false, "latched", l("order"), l("<latched>: contract violated at seq 0"), 0);
        assertTrue(fx.en.reset(ContractEnforcer.signReset(SEED, fx.id(), 0)));
        expect(fx.en.check(act("review"), true), true, "ok", l(), l(), 1);
        expect(fx.en.check(act("deploy"), true), true, "ok", l(), l(), 2);
    }

    @Test void aViolationWithoutLatchingLeavesTheStateAlone() {
        Fx fx = new Fx(false);
        expect(fx.en.check(act("send"), true), false, "violated", l("no-send"), l("no-send: never-invariant violated (forbidden action)"), 0);
        assertNull(fx.kv.get("k"));
        expect(fx.en.check(act("read"), true), true, "ok", l(), l(), 1);
        Object before = fx.kv.get("k");
        expect(fx.en.check(act("send"), true), false, "violated", l("no-send"), l("no-send: never-invariant violated (forbidden action)"), 1);
        assertSame(before, fx.kv.get("k"));
        assertEquals(Boolean.FALSE, fx.en.state().get("latched"));
        expect(fx.en.check(act("read"), true), true, "ok", l(), l(), 2);
    }

    @Test void aViolationIsAViolationEvenWhenThePermissionAlsoDenies() {
        Fx fx = new Fx(true);
        expect(fx.en.check(act("send"), false), false, "violated", l("no-send"), l("no-send: never-invariant violated (forbidden action)"), 0);
        assertTrue(fx.doc().containsKey("latched"));
    }

    // ---- stores that fail -----------------------------------------------------------------------------------------------

    @Test void aStoreThatFailsOrDoesNothingIsAStoreErrorNeverAnAdmission() {
        FaultKv down = new FaultKv();
        ContractEnforcer en = ContractEnforcer.open(down, signed(), principal(), "k", () -> T0, true);
        down.updateThrows = true;
        expect(en.check(act("read"), true), false, "store-error", l(), l("store error (fail closed)"), 0);
        down.updateThrows = false;
        down.updateSkips = true;
        expect(en.check(act("read"), true), false, "store-error", l(), l("store unavailable"), 0);
        down.updateSkips = false;
        down.getThrows = true;
        expect(en.peek(act("read")), false, "store-error", l(), l("store error (fail closed)"), 0);
        // the clock failing is the same refusal
        ContractEnforcer broken = ContractEnforcer.open(new MemoryAtomicKv(), signed(), principal(), "k", () -> { throw new IllegalStateException("clock"); }, true);
        expect(broken.check(act("read"), true), false, "store-error", l(), l("store error (fail closed)"), 0);
        expect(broken.peek(act("read")), false, "store-error", l(), l("store error (fail closed)"), 0);
        // an update that raises an assertion error is contained too
        AtomicKv bad = new AtomicKv() {
            @Override public Object get(String key) { return null; }
            @Override public void set(String key, Object value) {}
            @Override public Object update(String key, UnaryOperator<Object> fn) { throw new AssertionError("bad store"); }
        };
        expect(ContractEnforcer.open(bad, signed(), principal(), "k", () -> T0, true).check(act("read"), true), false, "store-error", l(), l("store error (fail closed)"), 0);
        // reset on a failing store is a refusal
        FaultKv rk = new FaultKv();
        Fx fx = new Fx(true);
        ContractEnforcer en2 = ContractEnforcer.open(rk, fx.contract, principal(), "k", () -> T0, true);
        en2.check(act("send"), true);
        rk.updateThrows = true;
        assertFalse(en2.reset(ContractEnforcer.signReset(SEED, fx.id(), 0)));
        rk.updateThrows = false;
        assertTrue(en2.reset(ContractEnforcer.signReset(SEED, fx.id(), 0)));
    }

    // ---- corrupt documents ----------------------------------------------------------------------------------------------

    static Map<String, Object> goodDoc(Fx fx) {
        assertTrue(fx.en.check(act("read"), true).allow);
        return new LinkedHashMap<>(fx.doc());
    }

    static void corrupt(Fx fx, Object stored) {
        fx.kv.set("k", stored);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> fx.en.state());
        assertEquals("ContractEnforcer: stored state is corrupt or belongs to another contract", e.getMessage());
        expect(fx.en.peek(act("read")), false, "state-error", l(), l(CORRUPT), 0);
        Object before = fx.kv.get("k");
        expect(fx.en.check(act("read"), true), false, "state-error", l(), l(CORRUPT), 0);
        assertSame(before, fx.kv.get("k"));
        assertFalse(fx.en.reset(ContractEnforcer.signReset(SEED, fx.id(), 1)));
        assertSame(before, fx.kv.get("k"));
    }

    @Test void everyMalformedDocumentIsCorruptNotAdmitted() {
        Fx fx = new Fx(true);
        Map<String, Object> good = goodDoc(fx);
        corrupt(fx, "x");
        corrupt(fx, new ArrayList<Object>());
        Map<String, Object> d = new LinkedHashMap<>(good);
        d.put("v", j("2"));
        corrupt(fx, d);
        d = new LinkedHashMap<>(good);
        d.put("v", j("1.5"));
        corrupt(fx, d);
        d = new LinkedHashMap<>(good);
        d.put("v", "1");
        corrupt(fx, d);
        d = new LinkedHashMap<>(good);
        d.remove("v");
        corrupt(fx, d);
        d = new LinkedHashMap<>(good);
        d.put("contract_id", "another");
        corrupt(fx, d);
        d = new LinkedHashMap<>(good);
        d.remove("contract_id");
        corrupt(fx, d);
        d = new LinkedHashMap<>(good);
        d.put("state", j("{'now':1}"));
        corrupt(fx, d);
        d = new LinkedHashMap<>(good);
        d.remove("state");
        corrupt(fx, d);
        String[] badLatched = {
            "'x'", "5", "null", "[]", "{'violated':[]}", "{'seq':1}", "{'seq':1.5,'violated':[]}", "{'seq':'1','violated':[]}", "{'seq':-0,'violated':[]}",
            "{'seq':1,'violated':'a'}", "{'seq':1,'violated':[5]}", "{'seq':1,'violated':['a',null]}"};
        for (String bad : badLatched) {
            d = new LinkedHashMap<>(good);
            d.put("latched", j(bad));
            corrupt(fx, d);
        }
    }

    @Test void wellFormedLatchesAreServedBack() {
        Fx fx = new Fx(true);
        Map<String, Object> good = goodDoc(fx);
        Map<String, Object> d = new LinkedHashMap<>(good);
        d.put("latched", j("{'seq':0,'violated':[]}"));
        fx.kv.set("k", d);
        assertEquals(Boolean.TRUE, fx.en.state().get("latched"));
        expect(fx.en.peek(act("read")), false, "latched", l(), l("<latched>: contract violated at seq 0"), 1);
        d = new LinkedHashMap<>(good);
        d.put("latched", j("{'seq':7,'violated':['a','b']}"));
        fx.kv.set("k", d);
        expect(fx.en.peek(act("read")), false, "latched", l("a", "b"), l("<latched>: contract violated at seq 7"), 1);
        expect(fx.en.check(act("read"), true), false, "latched", l("a", "b"), l("<latched>: contract violated at seq 7"), 1);
        assertTrue(fx.en.reset(ContractEnforcer.signReset(SEED, fx.id(), 7)));
        assertFalse(fx.doc().containsKey("latched"));
    }

    // ---- peek -----------------------------------------------------------------------------------------------------------

    @Test void peekEvaluatesWithoutAdvancingAndReadsTheClockOnce() {
        Fx fx = new Fx(true);
        expect(fx.en.peek(act("read")), true, "ok", l(), l(), 0);
        assertEquals(1, fx.calls[0]);
        assertNull(fx.kv.get("k"));
        expect(fx.en.peek(act("send")), false, "violated", l("no-send"), l("no-send: never-invariant violated (forbidden action)"), 0);
        assertNull(fx.kv.get("k"));
        expect(fx.en.check(act("read"), true), true, "ok", l(), l(), 1);
        expect(fx.en.check(act("review"), true), true, "ok", l(), l(), 2);
        Object before = fx.kv.get("k");
        fx.calls[0] = 0;
        expect(fx.en.peek(act("deploy")), true, "ok", l(), l(), 2);
        assertEquals(1, fx.calls[0]);
        expect(fx.en.peek(act("send")), false, "violated", l("no-send"), l("no-send: never-invariant violated (forbidden action)"), 2);
        assertSame(before, fx.kv.get("k"));
        // a corrupt or latched document answers before the clock is read
        fx.calls[0] = 0;
        fx.kv.set("k", "x");
        expect(fx.en.peek(act("read")), false, "state-error", l(), l(CORRUPT), 0);
        assertEquals(0, fx.calls[0]);
    }

    @Test void peekToleratesANonFiniteClockOnAnEmptyStore() {
        for (double bad : new double[] {Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY}) {
            Fx fx = new Fx(true);
            fx.wall[0] = bad;
            expect(fx.en.peek(act("read")), true, "ok", l(), l(), 0);
            expect(fx.en.peek(act("send")), false, "violated", l("no-send"), l("no-send: never-invariant violated (forbidden action)"), 0);
        }
    }

    @Test void peekOnAViolatingPrerequisiteReportsTheContractsOwnViolations() {
        Fx fx = new Fx(true);
        expect(fx.en.peek(act("deploy")), false, "violated", l("order"), l("order: precedence violated (prerequisite p not yet admitted before q)"), 0);
        // the reasons are a copy: a second peek is the same
        expect(fx.en.peek(act("deploy")), false, "violated", l("order"), l("order: precedence violated (prerequisite p not yet admitted before q)"), 0);
    }
}
