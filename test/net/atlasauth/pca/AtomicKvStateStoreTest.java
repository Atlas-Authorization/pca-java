package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

/** The AtomicKv-backed state store behaves exactly like the in-process reference store (claims, budgets, one-time slots). */
public class AtomicKvStateStoreTest {
    private static Map<String, Object> budget(double b, double tau, double asOf) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("B", StoreJs.num(b));
        m.put("tau", StoreJs.num(tau));
        m.put("asOf", StoreJs.num(asOf));
        return m;
    }

    @Test void claimsAreStrictlyIncreasing() {
        AtomicKvStateStore s = new AtomicKvStateStore(new MemoryAtomicKv());
        assertTrue(s.claim("k", 1).ok);
        StateStore.ClaimResult again = s.claim("k", 1);
        assertFalse(again.ok);
        assertEquals(Long.valueOf(1), again.lastCounter);
        assertTrue(s.claim("k", 5).ok);
        assertFalse(s.claim("k", 3).ok);
        assertEquals(Long.valueOf(5), s.last("k"));
        assertNull(s.last("other"));
        assertFalse(s.claim(null, 1).ok);
    }

    @Test void budgetMovesWithTheCounterAndConflictsConsumeNothing() {
        AtomicKvStateStore s = new AtomicKvStateStore(new MemoryAtomicKv());
        assertTrue(s.holdsBudgets());
        assertNull(s.budget("k"));
        assertTrue(s.claim("k", 1, null, budget(5, 0, 0)).ok);
        assertEquals(Double.valueOf(5), Caveats.fin(s.budget("k").get("B")));
        StateStore.ClaimResult stale = s.claim("k", 2, budget(4, 0, 0), budget(3, 0, 0));
        assertTrue(stale.conflict);
        assertEquals(Long.valueOf(1), s.last("k"), "a conflict consumed nothing");
        assertTrue(s.claim("k", 2, budget(5, 0, 0), budget(3, 0, 0)).ok);
        assertEquals(Double.valueOf(3), Caveats.fin(s.budget("k").get("B")));
        assertTrue(s.claim("k", 3).ok, "a plain claim keeps the stored budget");
        assertEquals(Double.valueOf(3), Caveats.fin(s.budget("k").get("B")));
    }

    @Test void differentialAgainstTheReferenceStore() {
        Random rnd = new Random(7);
        MemoryStateStore ref = new MemoryStateStore();
        AtomicKvStateStore kv = new AtomicKvStateStore(new MemoryAtomicKv());
        for (int i = 0; i < 400; i++) {
            String key = "k" + rnd.nextInt(3);
            long counter = rnd.nextInt(12);
            Map<String, Object> before = rnd.nextInt(3) == 0 ? budget(rnd.nextInt(3), 0, 0) : ref.budget(key);
            Map<String, Object> after = rnd.nextBoolean() ? budget(rnd.nextInt(4), 0, 0) : null;
            StateStore.ClaimResult a = ref.claim(key, counter, before, after), b = kv.claim(key, counter, before, after);
            assertEquals(a, b, "step " + i);
            assertEquals(ref.last(key), kv.last(key));
        }
    }

    @Test void oneTimeSlotsLiveUntilTheirHorizon() {
        AtomicKvStateStore s = new AtomicKvStateStore(new MemoryAtomicKv());
        assertTrue(s.consumeOnce("n", 100, 10));
        assertFalse(s.consumeOnce("n", 100, 99));
        assertFalse(s.consumeOnce("n", 150, 100), "still live at its horizon");
        assertFalse(s.consumeOnce("n", 160, 149), "the longer horizon is kept");
        assertTrue(s.consumeOnce("n", 400, 161), "free again once past the horizon");
        assertThrows(IllegalArgumentException.class, () -> s.consumeOnce("", 10, 1));
        assertThrows(IllegalArgumentException.class, () -> s.consumeOnce("x", 5, 10));
    }

    @Test void pinsOnlyRise() {
        AtomicKvStateStore s = new AtomicKvStateStore(new MemoryAtomicKv());
        s.raisePin("k", "lastEpoch", 5);
        s.raisePin("k", "lastEpoch", 3);
        assertEquals(Long.valueOf(5), s.pin("k", "lastEpoch"));
        s.raisePin("k", "lastEpoch", 9);
        assertEquals(Long.valueOf(9), s.pin("k", "lastEpoch"));
        assertNull(s.pin("k", "lastBeaconSeq"));
        assertThrows(IllegalArgumentException.class, () -> s.raisePin("k", "other", 1));
        assertTrue(s.claim("k", 1).ok, "a claim keeps the pins");
        assertEquals(Long.valueOf(9), s.pin("k", "lastEpoch"));
    }

    @Test void scopeFollowsTheBackend() {
        assertFalse(new AtomicKvStateStore(new MemoryAtomicKv()).processScoped());
        assertTrue(new AtomicKvStateStore(new MemoryAtomicKv(), "x:", false).processScoped());
    }
}
