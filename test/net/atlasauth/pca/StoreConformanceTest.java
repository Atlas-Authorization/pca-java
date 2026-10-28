package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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

    @Test void aFactoryThatThrowsIsAFailureNotACrash() {
        StoreConformance.Report r = StoreConformance.runStateStoreConformance(() -> { throw new IllegalStateException("no backend"); }, new StoreConformance.Options());
        assertFalse(r.ok());
        assertTrue(r.render().contains("no backend"), r.render());
    }
}
