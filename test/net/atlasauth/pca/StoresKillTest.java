package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.junit.jupiter.api.Test;

/**
 * The in-process stores and their value types, member by member: StateStore's default consumeOnce, ClaimResult's value
 * semantics, MemoryStateStore, MemoryAtomicKv, the OperationStore defaults, AtomicKvOperationStore and OperationRecord.
 */
public class StoresKillTest {
    static final String BAD = "consumeOnce: invalid key or retention horizon";

    // ---- StateStore.consumeOnce (the default) ----------------------------------------------------------------------------

    @Test void theDefaultConsumeOnceValidatesThenClaimsCounterOne() {
        List<String> calls = new ArrayList<>();
        StateStore.ClaimResult[] answer = {StateStore.ClaimResult.claimed()};
        StateStore s = (k, c) -> { calls.add(k + "#" + c); return answer[0]; };
        assertEquals(BAD, assertThrows(IllegalArgumentException.class, () -> s.consumeOnce(null, 10, 1)).getMessage());
        assertEquals(BAD, assertThrows(IllegalArgumentException.class, () -> s.consumeOnce("", 10, 1)).getMessage());
        assertEquals(BAD, assertThrows(IllegalArgumentException.class, () -> s.consumeOnce("k", 9, 10)).getMessage());
        assertEquals(List.of(), calls, "an invalid call never reaches the store");
        assertTrue(s.consumeOnce("k", 10, 10), "retainUntil == now is still live");
        assertEquals(List.of("k#1"), calls);
        answer[0] = StateStore.ClaimResult.replay(1L);
        assertFalse(s.consumeOnce("k", 20, 10));
        answer[0] = new StateStore.ClaimResult(true, 3L);
        assertTrue(s.consumeOnce("j", 20, 10));
        answer[0] = null;
        assertEquals("consumeOnce: the store answered null (fail closed)",
            assertThrows(IllegalStateException.class, () -> s.consumeOnce("k", 20, 10)).getMessage());
        assertEquals(List.of("k#1", "k#1", "j#1", "k#1"), calls);
    }

    @Test void claimResultValueSemantics() {
        StateStore.ClaimResult a = new StateStore.ClaimResult(true, 5L);
        assertTrue(a.equals(new StateStore.ClaimResult(true, 5L)));
        assertFalse(a.equals(new StateStore.ClaimResult(false, 5L)));
        assertFalse(a.equals(new StateStore.ClaimResult(true, 6L)));
        assertFalse(a.equals(new StateStore.ClaimResult(true, null)));
        assertFalse(new StateStore.ClaimResult(true, null).equals(a));
        assertFalse(a.equals("ClaimResult{ok=true, lastCounter=5}"));
        assertFalse(a.equals(null));
        assertTrue(StateStore.ClaimResult.replay(null).equals(new StateStore.ClaimResult(false, null)));
        assertTrue(StateStore.ClaimResult.claimed().equals(new StateStore.ClaimResult(true, null)));
        assertEquals(Objects.hash(true, 5L), a.hashCode());
        assertEquals(Objects.hash(false, null), StateStore.ClaimResult.replay(null).hashCode());
        assertEquals("ClaimResult{ok=true, lastCounter=5}", a.toString());
        assertEquals("ClaimResult{ok=false, lastCounter=null}", StateStore.ClaimResult.replay(null).toString());
    }

    // ---- MemoryStateStore ----------------------------------------------------------------------------------------------

    @Test void memoryStateStore() {
        MemoryStateStore s = new MemoryStateStore();
        StateStore.ClaimResult nul = s.claim(null, 5);
        assertFalse(nul.ok);
        assertNull(nul.lastCounter);
        assertNull(s.last(null));
        assertNull(s.last("k"));
        assertTrue(s.claim("k", 3).ok);
        assertEquals(Long.valueOf(3L), s.last("k"));
        assertEquals(StateStore.ClaimResult.replay(3L), s.claim("k", 3));
        assertEquals(BAD, assertThrows(IllegalArgumentException.class, () -> s.consumeOnce(null, 10, 1)).getMessage());
        assertEquals(BAD, assertThrows(IllegalArgumentException.class, () -> s.consumeOnce("", 10, 1)).getMessage());
        assertEquals(BAD, assertThrows(IllegalArgumentException.class, () -> s.consumeOnce("x", 0, 1)).getMessage());
        // a horizon of 0 at time 0 is pruned at time 1: the slot is free again
        assertTrue(s.consumeOnce("z", 0, 0));
        assertFalse(s.consumeOnce("z", 0, 0));
        assertTrue(s.consumeOnce("z", 1, 1));
        assertFalse(s.consumeOnce("z", 1, 1));
    }

    // ---- MemoryAtomicKv ------------------------------------------------------------------------------------------------

    @Test void memoryAtomicKv() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        kv.set("a", "v");
        kv.set("b", "w");
        assertEquals("v", kv.get("a"));
        kv.set("a", null);
        assertNull(kv.get("a"));
        assertEquals("w", kv.get("b"));
        assertEquals("w1", kv.update("b", p -> p + "1"));
        assertEquals("w1", kv.get("b"));
        assertEquals("w1", kv.update("b", p -> null), "fn null: unchanged, the current value is returned");
        assertNull(kv.update("none", p -> null));
        List<Object> seen = new ArrayList<>();
        assertEquals("n", kv.update("new", p -> { seen.add(p); return "n"; }));
        assertEquals(java.util.Collections.singletonList(null), seen);
    }

    // ---- OperationStore defaults and AtomicKvOperationStore --------------------------------------------------------------

    @Test void operationStoreDefaults() {
        OperationStore bare = new OperationStore() {
            @Override public OperationRecord create(OperationRecord record) { return null; }
            @Override public OperationRecord get(String id) { return null; }
            @Override public boolean transition(String id, String from, OperationRecord next) { return false; }
        };
        assertFalse(bare.supportsListOpen());
        assertFalse(bare.processLocal());
        assertEquals("this store has no listOpen", assertThrows(UnsupportedOperationException.class, bare::listOpen).getMessage());
    }

    static OperationRecord rec(String id) { return OperationRecord.pending(id, "v", "/r", "pd", "reversible", 7L); }

    @Test void atomicKvOperationStore() {
        assertEquals("kv", assertThrows(IllegalArgumentException.class, () -> new AtomicKvOperationStore(null)).getMessage());
        MemoryAtomicKv kv = new MemoryAtomicKv();
        AtomicKvOperationStore def = new AtomicKvOperationStore(kv);
        assertFalse(def.processLocal());
        assertFalse(def.supportsListOpen());
        assertNull(def.create(rec("x")));
        assertEquals("x", ((Map<?, ?>) kv.get("pca-op:x")).get("id"));

        AtomicKvOperationStore nullPrefix = new AtomicKvOperationStore(kv, null, true);
        assertTrue(nullPrefix.processLocal());
        assertNull(nullPrefix.create(rec("y")));
        assertEquals("y", ((Map<?, ?>) kv.get("pca-op:y")).get("id"));
        assertNull(kv.get("nully"));

        AtomicKvOperationStore custom = new AtomicKvOperationStore(kv, "p/", false);
        assertFalse(custom.processLocal());
        assertNull(custom.create(rec("z")));
        assertEquals("z", ((Map<?, ?>) kv.get("p/z")).get("id"));
        assertNull(kv.get("pca-op:z"));
        assertEquals("pending", custom.create(rec("z")).state());

        // the stored record always keeps the store's id, whatever id the next record carries
        assertTrue(custom.transition("z", "pending", rec("other").moved("executing", 9L, null, null)));
        OperationRecord got = custom.get("z");
        assertEquals("z", got.id());
        assertEquals("executing", got.state());
        assertEquals(Long.valueOf(9L), got.executingAt());
        assertNull(custom.get("other"));
        assertFalse(custom.transition("z", "pending", rec("z")));
        assertFalse(custom.transition("missing", "pending", rec("missing")));
        assertNull(kv.get("p/missing"));
    }

    // ---- OperationRecord -----------------------------------------------------------------------------------------------

    static Map<String, Object> tree(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    @Test void operationRecordOf() {
        assertNull(OperationRecord.of("x"));
        assertNull(OperationRecord.of(null));
        assertNull(OperationRecord.of(tree("id", IntentJs.ofLong(1), "state", "s")));
        assertNull(OperationRecord.of(tree("id", "a", "state", IntentJs.ofLong(1))));
        assertNull(OperationRecord.of(tree("id", "a")));
        assertNull(OperationRecord.of(tree("state", "s")));
        OperationRecord r = OperationRecord.of(tree("id", "a", "state", "s"));
        assertEquals("a", r.id());
        assertEquals("s", r.state());
        assertEquals("OperationRecord{id=a, state=s}", r.toString());
        // the record is a copy: changing the source does not change it
        Map<String, Object> src = tree("id", "a", "state", "s");
        OperationRecord c = OperationRecord.of(src);
        src.put("state", "t");
        assertEquals("s", c.state());
        Map<String, Object> out = c.toMap();
        out.put("state", "u");
        assertEquals("s", c.state());
    }

    @Test void operationRecordMembers() {
        OperationRecord p = rec("a");
        assertEquals("reversible", p.reversibility());
        assertEquals("v", p.verb());
        assertEquals("/r", p.resource());
        assertEquals("pd", p.paramsDigest());
        assertNull(p.error());
        assertFalse(p.hasResult());
        assertTrue(p.with("result", null).hasResult());
        assertEquals(7L, p.startedAt());
        assertNull(p.executingAt());
        assertNull(p.finishedAt());
        OperationRecord f = p.moved("failed", null, 11L, "boom");
        assertEquals(Long.valueOf(11L), f.finishedAt());
        assertEquals("boom", f.error());
        assertNull(f.executingAt());

        OperationRecord odd = OperationRecord.of(tree("id", "a", "state", "s", "verb", IntentJs.ofLong(1), "reversibility", true,
            "error", IntentJs.ofLong(2), "startedAt", "x"));
        assertNull(odd.verb());
        assertNull(odd.reversibility());
        assertNull(odd.error());
        assertEquals(0L, odd.startedAt());
        assertEquals(0L, OperationRecord.of(tree("id", "a", "state", "s")).startedAt());
        assertEquals(0L, OperationRecord.of(tree("id", "a", "state", "s", "startedAt", Double.NaN)).startedAt());

        assertNull(OperationRecord.of(tree("id", "a", "state", "s", "finishedAt", Double.NaN)).finishedAt());
        assertNull(OperationRecord.of(tree("id", "a", "state", "s", "finishedAt", Double.POSITIVE_INFINITY)).finishedAt());
        assertNull(OperationRecord.of(tree("id", "a", "state", "s", "finishedAt", Double.NEGATIVE_INFINITY)).finishedAt());
        assertNull(OperationRecord.of(tree("id", "a", "state", "s", "finishedAt", new Json.Num("x"))).finishedAt());
        assertEquals(Long.valueOf(1500L), OperationRecord.of(tree("id", "a", "state", "s", "finishedAt", 1500.9)).finishedAt());
        assertEquals(Long.valueOf(12L), OperationRecord.of(tree("id", "a", "state", "s", "executingAt", new Json.Num("12"))).executingAt());
    }
}
