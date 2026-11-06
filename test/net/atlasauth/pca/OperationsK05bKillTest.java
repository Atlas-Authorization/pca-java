package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.LongSupplier;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 0.5 mutation survivors of Operations (settle, resolve, the replay answer, the executor) and PcaJdbcAtomicKv.set (shard 9). */
public class OperationsK05bKillTest {
    static final long T0 = OperationsKillTest.T0;
    static final double TO = OperationsKillTest.TO;

    @TempDir Path dir;

    @Test void anExecutingRecordWithoutAStartTimeIsAgedFromItsClaim() {
        MemoryOperationStore st = new MemoryOperationStore();
        OperationsKillTest.seed(st, OperationsKillTest.rec("e", "executing")); // startedAt T0, no executingAt
        assertEquals("executing", Operations.recoverOperation(st, "e", TO, () -> T0 + 1000).state());
        assertEquals("uncertain", Operations.recoverOperation(st, "e", TO, () -> T0 + 1001).state());
    }

    @Test void onlyAnUncertainRecordIsResolvedAndNothingElseReadsTheClock() {
        MemoryOperationStore st = new MemoryOperationStore();
        OperationsKillTest.seed(st, OperationsKillTest.rec("c", "committed"));
        LongSupplier boom = () -> { throw new AssertionError("the clock is read only to resolve an uncertain record"); };
        assertFalse(Operations.resolveCommitted(st, "c", "R", boom));
        assertFalse(Operations.resolveCommitted(st, "c", boom));
        assertFalse(Operations.resolveFailed(st, "c", "x", boom));
        assertFalse(Operations.resolveCommitted(st, "missing", "R", boom));
        assertEquals("committed", st.get("c").state());
    }

    @Test void noPcactnOrNoOperationNeverReadsTheStore() {
        OperationStore untouched = new OperationStore() {
            @Override public OperationRecord create(OperationRecord r) { throw new AssertionError("create"); }
            @Override public OperationRecord get(String i) { throw new AssertionError("get"); }
            @Override public boolean transition(String i, String f, OperationRecord n) { throw new AssertionError("transition"); }
        };
        Authorize.Operation op = Authorize.Operation.of("v", "/r", new LinkedHashMap<>());
        assertNull(Operations.answerReplay(untouched, null, op, T0, TO));
        assertNull(Operations.answerReplay(untouched, "not json", op, T0, TO));
        assertNull(Operations.answerReplay(untouched, OperationsKillTest.handlePcactn("g1", null), null, T0, TO));
    }

    @Test void theExecutorAnswersAReplayFromTheRecordSettledAtItsClock() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Map<String, Object> grant = AuthorizeFixtures.grant(c);
        Object pcactn = AuthorizeFixtures.pcactn(c, 0);
        Authorize.Operation op = AuthorizeFixtures.operation(c, 0);
        long now = AuthorizeFixtures.now();
        boolean[] revoked = {false};
        Authorize.Options az = new Authorize.Options(new MemoryStateStore(), (p, g) -> revoked[0]).withProvenance(ProvHarness.options());
        // the proof is consumed by a plain authorize; the record of its operation was claimed 10 ms ago and never started
        assertTrue(az.run(pcactn, op, AuthorizeFixtures.audience(), ref -> grant, now).allow);
        MemoryOperationStore records = new MemoryOperationStore();
        String id = Pca.hashCanonical(Authorize.coerce(pcactn, new String[1]));
        assertNull(records.create(OperationRecord.pending(id, op.verb, op.resource, Pca.paramsDigest(Authorize.copyParams(op.params)), "reversible", now - 10)));
        Operations.Executor ex = Operations.createExecutor(new Operations.ExecutorOptions().operations(records).authorize(az)
            .audience(AuthorizeFixtures.audience()).resolveGrant(ref -> grant).pendingTimeoutMs(1).now(() -> now));

        // the replay is the only failure: the record answers, settled at the executor's clock (stale: aborted)
        Operations.ExecuteOutcome out = ex.execute(pcactn, op, OperationsKillTest.NEVER);
        assertEquals("aborted", out.status, out.toString());
        assertTrue(out.replayed);
        assertEquals("not started within 1 ms of the claim: the side effect never ran", out.reason);
        assertEquals(OperationRecord.ABORTED, records.get(id).state());

        // a replay that also fails revocation now is a denial, never the record
        revoked[0] = true;
        Operations.ExecuteOutcome denied = ex.execute(pcactn, op, OperationsKillTest.NEVER);
        assertEquals("denied", denied.status, denied.toString());
        assertFalse(denied.authorization.allow);
    }

    // ---- PcaJdbcAtomicKv.set ------------------------------------------------------------------------------------------

    static int rows(Path f, String k) throws SQLException {
        try (Connection c = AuthorizeFixtures.sqliteConnection(f);
             PreparedStatement st = c.prepareStatement("SELECT COUNT(*) FROM " + PcaJdbcAtomicKv.TABLE + " WHERE k = ?")) {
            st.setString(1, k);
            try (ResultSet rs = st.executeQuery()) {
                assertTrue(rs.next());
                return rs.getInt(1);
            }
        }
    }

    @Test void settingNullDeletesTheRow() throws Exception {
        Path f = dir.resolve("kv.db");
        PcaJdbcAtomicKv kv = new PcaJdbcAtomicKv(() -> AuthorizeFixtures.sqliteConnection(f)).createTable();
        kv.set("a", "x");
        assertEquals(1, rows(f, "a"));
        kv.set("a", null);
        assertNull(kv.get("a"));
        assertEquals(0, rows(f, "a"), "a null value removes the row, it never stores JSON null");
        kv.set("b", null);
        assertEquals(0, rows(f, "b"));
    }
}
