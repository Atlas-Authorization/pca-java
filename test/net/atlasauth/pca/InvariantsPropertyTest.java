package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.invariants.InvariantProperties;
import net.atlasauth.pca.invariants.Invariants;
import net.atlasauth.pca.invariants.Rng;
import org.junit.jupiter.api.Test;

/** Runs the seeded safety-invariant property suite over the real core at the default seed and run count. */
class InvariantsPropertyTest {
    @Test void everyInvariantHoldsAtTheDefaultSeed() {
        List<Map<String, Object>> results = InvariantProperties.checkInvariants(null, null, false);
        assertEquals(Invariants.INVARIANT_NAMES.size(), results.size());
        for (int i = 0; i < results.size(); i++) {
            Map<String, Object> res = results.get(i);
            assertEquals(Invariants.INVARIANT_NAMES.get(i), res.get("name"));
            assertEquals(Boolean.TRUE, res.get("ok"), res.get("name") + ": " + res.get("error"));
            assertEquals((long) Invariants.DEFAULT_NUM_RUNS, res.get("numRuns"));
            assertEquals(Invariants.DEFAULT_SEED, res.get("seed"));
        }
    }

    @Test void theRegistryMatchesTheNameList() {
        assertEquals(Invariants.INVARIANT_NAMES, List.copyOf(InvariantProperties.INVARIANTS.keySet()));
    }

    @Test void theSameSeedGeneratesTheSameCases() {
        Rng a = new Rng(Invariants.DEFAULT_SEED), b = new Rng(Invariants.DEFAULT_SEED);
        for (int i = 0; i < 100; i++) assertEquals(a.next(), b.next(), 0.0);
        assertEquals(new Rng(1).string(0, 10), new Rng(1).string(0, 10));
        assertTrue(java.util.Arrays.equals(new Rng(7).bytes(32), new Rng(7).bytes(32)));
    }

    @Test void aViolatedPropertyFailsTheRunWithItsIndex() {
        AssertionError e = assertThrows(AssertionError.class, () -> InvariantProperties.run(r -> r.next() < 0.5, 1000, 1));
        assertTrue(e.getMessage().contains("Property failed after"));
        InvariantProperties.run(r -> true, 10, 1);
    }

    @Test void aPropertyThatThrowsFails() {
        assertThrows(AssertionError.class, () -> InvariantProperties.run(r -> { throw new IllegalStateException("boom"); }, 5, 1));
    }

    @Test void aCheckOfZeroCasesIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> InvariantProperties.checkInvariants(0L, null, false));
        assertThrows(IllegalArgumentException.class, () -> InvariantProperties.checkInvariants(-3L, null, false));
        assertThrows(IllegalArgumentException.class, () -> InvariantProperties.checkInvariants(5L, 9007199254740992L, false));
    }

    @Test void bailStopsAtTheFirstFailure() {
        List<Map<String, Object>> all = InvariantProperties.checkInvariants(5L, 3L, true);
        assertFalse(all.isEmpty());
        assertTrue(all.size() <= Invariants.INVARIANT_NAMES.size());
    }
}
