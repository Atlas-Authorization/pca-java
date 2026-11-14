package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.junit.jupiter.api.Test;

/**
 * The store-conformance helper against the shipped stores (it must pass them) and against deliberately broken ones (it must
 * fail them, naming the test): the helper is only worth anything if it can fail.
 */
public class StoreConformanceTest {
    static void pause() {
        try {
            Thread.sleep(15);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** A replay store whose claim is read, wait, write: two callers both see the counter unconsumed. */
    static final class RacyStateStore implements StateStore {
        final Map<String, Long> last = new ConcurrentHashMap<>();

        @Override public ClaimResult claim(String key, long counter) {
            Long prev = last.get(key);
            pause();
            if (prev != null && counter <= prev) return ClaimResult.replay(prev);
            last.put(key, counter);
            return ClaimResult.claimed();
        }
    }

    /** An operation store whose create is check, wait, put. */
    static final class RacyOperationStore implements OperationStore {
        final Map<String, OperationRecord> m = new ConcurrentHashMap<>();

        @Override public OperationRecord create(OperationRecord record) {
            OperationRecord cur = m.get(record.id());
            pause();
            if (cur != null) return cur;
            m.put(record.id(), record);
            return null;
        }
        @Override public OperationRecord get(String id) { return m.get(id); }
        @Override public boolean transition(String id, String from, OperationRecord next) {
            OperationRecord cur = m.get(id);
            pause();
            if (cur == null || !from.equals(cur.state())) return false;
            m.put(id, next);
            return true;
        }
    }

    static List<String> failed(StoreConformance.Report r) {
        return r.failures().stream().map(t -> t.test).collect(java.util.stream.Collectors.toList());
    }

    @Test void theInProcessStoresPassWhenDeclaredProcessLocal() {
        StoreConformance.Report state = StoreConformance.runStateStoreConformance(MemoryStateStore::new, new StoreConformance.Options().durable(false).shared(false));
        assertTrue(state.ok(), state.render());
        assertEquals("skip", state.results.get(2).status);
        StoreConformance.Report ops = StoreConformance.runOperationStoreConformance(MemoryOperationStore::new, new StoreConformance.Options().durable(false).shared(false));
        assertTrue(ops.ok(), ops.render());
    }

    @Test void theSqliteStoresPassTheFullProfile() throws Exception {
        Path f = Files.createTempFile("pca-conformance", ".db");
        try {
            PcaJdbcStateStore.ConnectionFactory conn = () -> AuthorizeFixtures.sqliteConnection(f);
            AuthorizeFixtures.sqlite(f); // the table
            StoreConformance.Report state = StoreConformance.runStateStoreConformance(() -> new PcaJdbcStateStore(conn), new StoreConformance.Options());
            assertTrue(state.ok(), state.render());
            assertTrue(state.results.stream().noneMatch(t -> t.status.equals("skip")), state.render());
            new PcaJdbcAtomicKv(conn).createTable();
            StoreConformance.Report ops = StoreConformance.runOperationStoreConformance(() -> new AtomicKvOperationStore(new PcaJdbcAtomicKv(conn)), new StoreConformance.Options());
            assertTrue(ops.ok(), ops.render());
            assertTrue(ops.results.stream().noneMatch(t -> t.status.equals("skip")), ops.render());
        } finally {
            Files.deleteIfExists(f);
        }
    }

    @Test void theSqliteStoreHoldsBudgetsAtomicallyWithTheCounter() throws Exception {
        Path f = Files.createTempFile("pca-budget-conformance", ".db");
        try {
            PcaJdbcStateStore.ConnectionFactory conn = () -> AuthorizeFixtures.sqliteConnection(f);
            AuthorizeFixtures.sqlite(f); // the tables
            assertTrue(new PcaJdbcStateStore(conn).holdsBudgets());
            StoreConformance.Report budget = StoreConformance.runBudgetStoreConformance(() -> new PcaJdbcStateStore(conn), new StoreConformance.Options());
            assertTrue(budget.ok(), budget.render());
            assertTrue(budget.results.stream().allMatch(t -> t.status.equals("pass")), budget.render());
            new PcaJdbcAtomicKv(conn).createTable();
            StoreConformance.Report kvs = StoreConformance.runKvRegistryConformance(() -> new PcaJdbcAtomicKv(conn), new StoreConformance.Options(),
                Track3Vectors.load("lease-vectors.json"), Track3Vectors.load("break-glass-vectors.json"), Track3Vectors.load("blueprint-vectors.json"));
            assertTrue(kvs.ok(), kvs.render());
            assertTrue(kvs.results.stream().allMatch(t -> t.status.equals("pass")), kvs.render());
        } finally {
            Files.deleteIfExists(f);
        }
    }

    @Test void aRacyReplayStoreFails() {
        StoreConformance.Report r = StoreConformance.runStateStoreConformance(RacyStateStore::new, new StoreConformance.Options().durable(false).shared(false).rounds(2));
        assertFalse(r.ok(), r.render());
        assertTrue(failed(r).contains("claim-burst"), r.render());
    }

    @Test void aStorePerHandleFailsTheSharedAndDurableTests() {
        // every handle is its own island: no cross-handle exclusion, nothing survives closing the handles
        StoreConformance.Report r = StoreConformance.runStateStoreConformance(MemoryStateStore::new, new StoreConformance.Options().rounds(2));
        assertFalse(r.ok(), r.render());
        assertTrue(failed(r).contains("claim-concurrent"), r.render());
        assertTrue(failed(r).contains("claim-durability"), r.render());
        assertTrue(failed(r).contains("crash-after-claim"), r.render());
        assertFalse(failed(r).contains("claim-burst"), r.render());
    }

    @Test void aRacyOperationStoreFails() {
        StoreConformance.Report r = StoreConformance.runOperationStoreConformance(RacyOperationStore::new, new StoreConformance.Options().durable(false).shared(false).rounds(2));
        assertFalse(r.ok(), r.render());
        assertTrue(failed(r).contains("create-race"), r.render());
        assertTrue(failed(r).contains("transition-race"), r.render());
    }

    /** A store that loses the first claim of each key: what re-admitting a claim whose answer was lost looks like. */
    static final class ForgetsFirstClaim implements StateStore {
        final Map<String, Long> last = new ConcurrentHashMap<>();
        final java.util.Set<String> seen = ConcurrentHashMap.newKeySet();

        @Override public synchronized ClaimResult claim(String key, long counter) {
            if (!seen.add(key)) {
                Long prev = last.get(key);
                if (prev != null && counter <= prev) return ClaimResult.replay(prev);
                last.put(key, counter);
            }
            return ClaimResult.claimed();
        }
    }

    @Test void aStoreThatReadmitsALostClaimFails() {
        ForgetsFirstClaim s = new ForgetsFirstClaim();
        StoreConformance.Report r = StoreConformance.runStateStoreConformance(() -> s, new StoreConformance.Options().durable(false));
        assertTrue(failed(r).contains("retry-after-timeout"), r.render());
    }

    @Test void aFactoryThatThrowsIsAFailureNotACrash() {
        StoreConformance.Report r = StoreConformance.runStateStoreConformance(() -> { throw new IllegalStateException("no backend"); }, new StoreConformance.Options());
        assertFalse(r.ok());
        assertTrue(r.render().contains("no backend"), r.render());
    }

    /** The race helper releases every thread through ONE timed gate (60 s), and a broken gate is reported per thread. */
    @Test void raceReleasesEveryThreadThroughOneTimedGate() throws Exception {
        List<String> awaits = Collections.synchronizedList(new ArrayList<>());
        CyclicBarrier gate = new CyclicBarrier(3) {
            @Override public int await(long t, TimeUnit u) throws InterruptedException, BrokenBarrierException, TimeoutException {
                awaits.add(t + " " + u);
                return super.await(t, u);
            }
        };
        // every worker runs only after all three passed the gate
        Object[] out = StoreConformance.race(gate, 3, i -> awaits.size() == 3 ? i : -1);
        assertEquals(List.of(0, 1, 2), Arrays.asList(out));
        assertEquals(List.of("60 SECONDS", "60 SECONDS", "60 SECONDS"), awaits);
        CyclicBarrier broken = new CyclicBarrier(2) {
            @Override public int await(long t, TimeUnit u) throws BrokenBarrierException { throw new BrokenBarrierException("gate broke"); }
        };
        Object[] bad = StoreConformance.race(broken, 2, i -> i);
        for (Object o : bad) assertEquals("gate broke", ((BrokenBarrierException) o).getMessage());
    }

    // ---- the trust-budget and kv-registry profiles (F11)

    @Test void theBudgetProfilePassesOnTheMemoryStore() {
        StoreConformance.Report r = StoreConformance.runBudgetStoreConformance(MemoryStateStore::new, new StoreConformance.Options().durable(false).shared(false));
        assertTrue(r.ok(), r.render());
        assertEquals(6, r.results.size());
        assertEquals(5L, r.results.stream().filter(t -> t.status.equals("pass")).count(), r.render());
    }

    /** A store that holds budgets but spends them without checking the stored one: the conflict and burst checks must catch it. */
    static final class BlindBudgetStore implements StateStore {
        private final MemoryStateStore inner = new MemoryStateStore();
        @Override public ClaimResult claim(String key, long counter) { return inner.claim(key, counter); }
        @Override public boolean holdsBudgets() { return true; }
        @Override public java.util.Map<String, Object> budget(String key) { return inner.budget(key); }
        @Override public synchronized ClaimResult claim(String key, long counter, java.util.Map<String, Object> before, java.util.Map<String, Object> after) {
            ClaimResult r = inner.claim(key, counter);
            if (r.ok && after != null) inner.putBudget(key, after); // never compares budgetBefore
            return r;
        }
    }

    @Test void theBudgetProfileFailsAStoreThatIgnoresBudgetBefore() {
        BlindBudgetStore shared = new BlindBudgetStore();
        StoreConformance.Report r = StoreConformance.runBudgetStoreConformance(() -> shared, new StoreConformance.Options().durable(false).rounds(2));
        assertFalse(r.ok(), r.render());
        assertTrue(r.failures().stream().anyMatch(t -> t.test.equals("budget-conflict-consumes-nothing")), r.render());
    }

    @Test void theBudgetProfileFailsAStoreThatHoldsNone() {
        StoreConformance.Report r = StoreConformance.runBudgetStoreConformance(() -> (key, counter) -> StateStore.ClaimResult.claimed(), new StoreConformance.Options().durable(false));
        assertFalse(r.ok(), r.render());
    }

    @Test void theKvRegistryProfilePassesOnTheMemoryKv() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        StoreConformance.Report r = StoreConformance.runKvRegistryConformance(() -> kv, new StoreConformance.Options().durable(false).rounds(2),
            Track3Vectors.load("lease-vectors.json"), Track3Vectors.load("break-glass-vectors.json"), Track3Vectors.load("blueprint-vectors.json"));
        assertTrue(r.ok(), r.render());
        assertTrue(r.results.stream().allMatch(t -> t.status.equals("pass")), r.render());
    }
}
