package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Mutation kills for the replay / budget store seams: {@link StateStore} defaults and {@code ClaimResult} identity, {@link MemoryStateStore} and
 * {@link PcaJdbcStateStore} budget comparison, null keys, column order and transaction handling, and {@link SafeRegex#refusals()}.
 */
public class StorePathsPitKill1Test {
    static StateStore.ClaimResult claimed() { return StateStore.ClaimResult.claimed(); }

    static StateStore.ClaimResult replay(Long l) { return StateStore.ClaimResult.replay(l); }

    static StateStore.ClaimResult conflict() { return StateStore.ClaimResult.conflict(); }

    static Map<String, Object> b(double bb, double tau, double asOf) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("B", bb);
        m.put("tau", tau);
        m.put("asOf", asOf);
        return m;
    }

    // ---- StateStore -----------------------------------------------------------------------------------------------------

    @Test void aStoreThatKeepsNoBudgetsSaysSoAndHoldsNone() {
        StateStore s = (k, c) -> StateStore.ClaimResult.claimed();
        assertFalse(s.holdsBudgets());
        assertNull(s.budget("k"));
        assertFalse(s.processScoped());
        assertEquals(claimed(), s.claim("k", 1, null, Map.of("B", 1.0)));
        StateStore replayOnly = (k, c) -> StateStore.ClaimResult.replay(7L);
        assertEquals(replay(7L), replayOnly.claim("k", 1, null, null));
    }

    @Test void claimResultEqualityCoversEveryField() {
        assertEquals(claimed(), claimed());
        assertEquals(replay(5L), replay(5L));
        assertEquals(replay(null), replay(null));
        assertEquals(conflict(), conflict());
        assertEquals(new StateStore.ClaimResult(true, 3L), new StateStore.ClaimResult(true, 3L));
        assertFalse(claimed().equals(replay(null)));
        assertFalse(replay(1L).equals(replay(2L)));
        assertFalse(replay(1L).equals(replay(null)));
        assertFalse(replay(null).equals(replay(1L)));
        assertFalse(conflict().equals(replay(null)));
        assertFalse(replay(null).equals(conflict()));
        assertFalse(claimed().equals(null));
        assertFalse(claimed().equals("claimed"));
        assertFalse(new StateStore.ClaimResult(true, 3L).equals(new StateStore.ClaimResult(false, 3L)));
    }

    @Test void claimResultHashCodeIsTheHashOfItsFields() {
        assertEquals(39122, claimed().hashCode());
        assertEquals(39313, replay(5L).hashCode());
        assertEquals(1219779, conflict().hashCode());
        assertEquals(claimed().hashCode(), claimed().hashCode());
        assertFalse(conflict().hashCode() == replay(null).hashCode());
        assertEquals("ClaimResult{ok=false, lastCounter=5}", replay(5L).toString());
    }

    // ---- MemoryStateStore -----------------------------------------------------------------------------------------------

    @Test void aNullKeyIsAReplayNeverAClaim() {
        MemoryStateStore m = new MemoryStateStore();
        assertEquals(replay(null), m.claim(null, 1));
        assertEquals(replay(null), m.claim(null, 2));
        assertEquals(replay(null), m.claim(null, 1, null, null));
        assertEquals(replay(null), m.claim(null, 1, null, b(1, 1, 1)));
        assertNull(m.budget(null));
        assertEquals(claimed(), m.claim("k", 1));
    }

    @Test void theBudgetComparisonReadsEveryNamedFieldAndAbsenceOnlyEqualsAbsence() {
        MemoryStateStore m = new MemoryStateStore();
        // both absent is equal
        assertEquals(claimed(), m.claim("y", 1, null, null));
        // a stored budget against an absent one, and the reverse, is a conflict that consumes nothing
        assertEquals(conflict(), m.claim("z", 1, Map.of("B", 1.0), null));
        assertEquals(claimed(), m.claim("z", 1, null, Map.of("B", 5.0)));
        assertEquals(conflict(), m.claim("z", 2, null, null));
        // a stored budget with only B: an immutable before with the same B is equal (no field is read under a null name)
        assertEquals(claimed(), m.claim("z", 2, Map.of("B", 5.0), null));
        // a missing field only equals a missing field
        assertEquals(conflict(), m.claim("z", 3, Map.of("B", 5.0, "tau", 1.0), null));
        assertEquals(conflict(), m.claim("z", 3, Map.of("B", 6.0), null));
        assertEquals(claimed(), m.claim("z", 3, Map.of("B", 5.0), Map.of("B", 5.0, "tau", 2.0, "asOf", 3.0)));
        // each field decides on its own
        assertEquals(conflict(), m.claim("z", 4, b(5, 2, 4), null));
        assertEquals(conflict(), m.claim("z", 4, b(5, 3, 3), null));
        assertEquals(conflict(), m.claim("z", 4, b(6, 2, 3), null));
        assertEquals(claimed(), m.claim("z", 4, b(5, 2, 3), null));
        // a stored field the before lacks is a conflict
        assertEquals(conflict(), m.claim("z", 5, Map.of("B", 5.0, "tau", 2.0), null));
        assertEquals(b(5, 2, 3), m.budget("z"));
    }

    // ---- SafeRegex.refusals ---------------------------------------------------------------------------------------------

    @Test void refusalsCountTheOpenBudgetOnly() {
        assertEquals(0, SafeRegex.refusals());
        int inside = SafeRegex.withBudget(() -> {
            assertEquals(0, SafeRegex.refusals());
            assertFalse(SafeRegex.charge("(", 1));
            assertEquals(1, SafeRegex.refusals());
            assertFalse(SafeRegex.charge("[", 1));
            return SafeRegex.refusals();
        });
        assertEquals(2, inside);
        assertEquals(0, SafeRegex.refusals());
        // a charge outside any budget leaves nothing behind
        assertFalse(SafeRegex.charge("(", 1));
        assertEquals(0, SafeRegex.refusals());
    }

    // ---- PcaJdbcStateStore ----------------------------------------------------------------------------------------------

    static Connection recording(Connection real, List<String> calls) {
        InvocationHandler h = (p, m, a) -> {
            calls.add(m.getName());
            try {
                return m.invoke(real, a);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        };
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[] {Connection.class}, h);
    }

    interface Body { void run(PcaJdbcStateStore s, Path f, List<String> calls) throws Exception; }

    static void withStore(Body body) throws Exception {
        Path f = Files.createTempFile("pca-store-kill", ".db");
        try {
            AuthorizeFixtures.sqlite(f);
            List<String> calls = new ArrayList<>();
            body.run(new PcaJdbcStateStore(() -> recording(AuthorizeFixtures.sqliteConnection(f), calls)), f, calls);
        } finally {
            Files.deleteIfExists(f);
        }
    }

    @Test void theSqliteBudgetKeepsTauAndAsOfInTheirOwnColumns() throws Exception {
        withStore((s, f, calls) -> {
            assertNull(s.budget(null));
            assertTrue(calls.isEmpty(), "no connection is opened for a null key: " + calls);
            assertNull(s.budget("absent"));
            assertEquals(claimed(), s.claim("k", 1, null, b(10, 500, 1000)));
            assertEquals(b(10, 500, 1000), s.budget("k"));
            assertTrue(s.holdsBudgets());
        });
    }

    @Test void aNullKeyIsAReplayInTheDatabaseToo() throws Exception {
        withStore((s, f, calls) -> {
            assertEquals(replay(null), s.claim(null, 1, null, null));
            assertEquals(replay(null), s.claim(null, 1, null, b(1, 1, 1)));
            assertEquals(replay(null), s.claim(null, 2, null, null));
            assertTrue(calls.isEmpty(), "no connection is opened for a null key: " + calls);
        });
    }

    @Test void theSqliteBudgetComparisonMatchesTheMemoryOne() throws Exception {
        withStore((s, f, calls) -> {
            assertEquals(claimed(), s.claim("y", 1, null, null));
            assertEquals(conflict(), s.claim("z", 1, Map.of("B", 1.0), null));
            assertEquals(claimed(), s.claim("z", 1, null, b(5, 2, 3)));
            assertEquals(conflict(), s.claim("z", 2, null, null));
            // an immutable before map with the same values is equal (no field is read under a null name)
            assertEquals(claimed(), s.claim("z", 2, Map.of("B", 5.0, "tau", 2.0, "asOf", 3.0), null));
            assertEquals(conflict(), s.claim("z", 3, b(6, 2, 3), null));
            assertEquals(conflict(), s.claim("z", 3, b(5, 3, 3), null));
            assertEquals(conflict(), s.claim("z", 3, b(5, 2, 4), null));
            assertEquals(conflict(), s.claim("z", 3, Map.of("B", 5.0), null));
            assertEquals(claimed(), s.claim("z", 3, b(5, 2, 3), null));
            assertEquals(replay(3L), s.claim("z", 3, b(5, 2, 3), null));
            assertEquals(b(5, 2, 3), s.budget("z"));
        });
    }

    @Test void aFailedBudgetClaimIsRolledBackAndNeverCommitted() throws Exception {
        withStore((s, f, calls) -> {
            Map<String, Object> bad = b(1, 1, 1);
            bad.put("B", Double.NaN);
            assertThrows(IllegalArgumentException.class, () -> s.claim("k", 1, null, bad));
            assertEquals(1, calls.stream().filter("rollback"::equals).count(), calls.toString());
            assertFalse(calls.contains("commit"), calls.toString());
            // the counter was not consumed
            calls.clear();
            assertEquals(claimed(), s.claim("k", 1, null, b(2, 2, 2)));
            assertTrue(calls.contains("commit"));
            assertFalse(calls.contains("rollback"), calls.toString());
            // a refused claim rolls back exactly once
            calls.clear();
            assertEquals(replay(1L), s.claim("k", 1, null, b(2, 2, 2)));
            assertEquals(1, calls.stream().filter("rollback"::equals).count(), calls.toString());
            calls.clear();
            assertEquals(conflict(), s.claim("k", 2, b(9, 9, 9), null));
            assertEquals(1, calls.stream().filter("rollback"::equals).count(), calls.toString());
            assertFalse(calls.contains("commit"));
        });
    }

    @Test void aDatabaseErrorIsAnUncheckedStoreError() throws Exception {
        Path f = Files.createTempFile("pca-store-kill-empty", ".db");
        try {
            PcaJdbcStateStore bare = new PcaJdbcStateStore(() -> AuthorizeFixtures.sqliteConnection(f)); // no tables
            IllegalStateException a = assertThrows(IllegalStateException.class, () -> bare.budget("k"));
            assertTrue(a.getMessage().startsWith("replay store: "), a.getMessage());
            assertTrue(a.getMessage().contains("no such table"), a.getMessage());
            assertNotNull(a.getCause());
            IllegalStateException c = assertThrows(IllegalStateException.class, () -> bare.claim("k", 1, null, null));
            assertTrue(c.getMessage().startsWith("replay store: "), c.getMessage());
            assertTrue(c.getMessage().contains("no such table"), c.getMessage());
            assertNotNull(c.getCause());
            assertNotSame(a, c);
        } finally {
            Files.deleteIfExists(f);
        }
    }
}
