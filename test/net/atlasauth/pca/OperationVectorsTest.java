package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * Operation records (T3): the shared operation vectors scenario by scenario (the step shapes are in the file's description),
 * the concurrency guarantee (N parallel executions of one id run the function exactly once) over the in-memory store and over a
 * durable SQLite store, and the executor. A missing vector file or a table of the wrong size FAILS.
 */
public class OperationVectorsTest {
    static final long T0 = 1_800_000_000_000L;

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked")
    static List<Object> l(Object o) { return (List<Object>) o; }

    static Authorize.AuthorizeResult allowed(String id, String verb, String resource, String digest, Map<String, Object> pcactn) {
        Pca.Verdict v = new Pca.Verdict();
        v.allow = true;
        return new Authorize.AuthorizeResult(true, 200, new LinkedHashMap<>(), new ArrayList<>(), null,
            new Authorize.AuthorizedOperation(verb, resource, digest, id), pcactn, v, null);
    }

    static Authorize.AuthorizeResult notAllowed() {
        Pca.Verdict v = new Pca.Verdict();
        v.allow = false;
        return new Authorize.AuthorizeResult(false, 403, new LinkedHashMap<>(), new ArrayList<>(), "no", null, new LinkedHashMap<>(), v, null);
    }

    static Authorize.AuthorizeResult authorizationOf(Map<String, Object> s) {
        String sc = (String) s.get("signed_class");
        Map<String, Object> action = new LinkedHashMap<>();
        if (sc != null) action.put("reversibility_class", sc);
        Map<String, Object> pcactn = new LinkedHashMap<>();
        if (s.containsKey("exp")) pcactn.put("exp", s.get("exp"));
        pcactn.put("action", action);
        return allowed((String) s.get("id"), s.containsKey("verb") ? (String) s.get("verb") : "payments.refund",
            s.containsKey("resource") ? (String) s.get("resource") : "/orders/1",
            s.containsKey("params_digest") ? (String) s.get("params_digest") : Pca.paramsDigest(null), pcactn);
    }

    /** A PCActn whose signed class is reversible: a missing class is irreversible and then needs a recheck (fail closed). */
    static Map<String, Object> reversiblePcactn() {
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("reversibility_class", "reversible");
        Map<String, Object> pcactn = new LinkedHashMap<>();
        pcactn.put("action", action);
        return pcactn;
    }

    static Object canon(Object v) { return Json.canonicalize(v); }

    /** Runs one execute step and returns {outcome, fn_calls, record}. */
    static Map<String, Object> execute(Map<String, Object> s, OperationStore store) {
        AtomicInteger calls = new AtomicInteger();
        boolean noStore = Boolean.TRUE.equals(s.get("no_store"));
        boolean notAllowed = Boolean.TRUE.equals(s.get("not_allowed"));
        Authorize.AuthorizeResult az = notAllowed ? notAllowed() : authorizationOf(s);
        long at = Json.asLong(s.get("at"));
        Operations.ExecuteOptions opts = new Operations.ExecuteOptions().store(noStore ? null : store).now(() -> at);
        Object rc = s.get("recheck");
        if (rc instanceof String) opts.recheck(h -> Operations.RecheckResult.ok());
        else if (rc instanceof Map && ((Map<?, ?>) rc).containsKey("refuse")) {
            String why = (String) ((Map<?, ?>) rc).get("refuse");
            opts.recheck(h -> Operations.RecheckResult.refuse(why));
        } else if (rc instanceof Map) {
            String msg = (String) ((Map<?, ?>) rc).get("throw");
            opts.recheck(h -> { throw new IllegalStateException(msg); });
        }
        if (s.containsKey("recheck_for")) opts.recheckFor((String) s.get("recheck_for"));
        if (s.containsKey("server_class")) opts.reversibilityClass((String) s.get("server_class"));
        if (s.containsKey("timeout_ms")) opts.pendingTimeoutMs((double) Json.asLong(s.get("timeout_ms")));
        Map<String, Object> fnSpec = m(s.get("fn"));
        Operations.OperationFn fn = h -> {
            calls.incrementAndGet();
            String kind = (String) fnSpec.get("kind");
            if ("throw".equals(kind)) throw new IllegalStateException((String) fnSpec.get("message"));
            if ("reenter".equals(kind)) {
                return Operations.executeAuthorized(az, hh -> { throw new IllegalStateException("inner must not run"); }, opts).status;
            }
            return fnSpec.containsKey("result") ? fnSpec.get("result") : h.idempotencyKey;
        };
        Operations.ExecuteOutcome out = Operations.executeAuthorized(az, fn, opts);
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("outcome", out.toMap());
        r.put("fn_calls", (long) calls.get());
        OperationRecord rec = noStore || notAllowed ? null : store.get((String) s.get("id"));
        r.put("record", rec == null ? null : rec.toMap());
        return r;
    }

    @Test void scenarios() {
        Map<String, Object> doc = Track3Vectors.load("operation-vectors.json");
        assertEquals(Operations.OPERATION_PENDING_TIMEOUT_MS, Json.asLong(m(doc.get("constants")).get("pending_timeout_ms")));
        List<Object> scenarios = l(doc.get("scenarios"));
        assertEquals(19, scenarios.size());
        for (Object so : scenarios) {
            Map<String, Object> sc = m(so);
            String name = (String) sc.get("name");
            OperationStore store = new MemoryOperationStore();
            List<Object> steps = l(sc.get("steps")), expect = l(sc.get("expect"));
            assertEquals(steps.size(), expect.size(), name);
            for (int i = 0; i < steps.size(); i++) {
                Map<String, Object> s = m(steps.get(i));
                Object got;
                switch ((String) s.get("op")) {
                    case "seed":
                        assertNull(store.create(OperationRecord.of(s.get("record"))), name);
                        got = null;
                        break;
                    case "get": {
                        OperationRecord r = store.get((String) s.get("id"));
                        got = r == null ? null : r.toMap();
                        break;
                    }
                    case "recover": {
                        long at = Json.asLong(s.get("at"));
                        double older = s.containsKey("older_than_ms") ? (double) Json.asLong(s.get("older_than_ms")) : Operations.OPERATION_PENDING_TIMEOUT_MS;
                        List<Map<String, Object>> rows = new ArrayList<>();
                        for (OperationRecord r : Operations.recoverOperations(store, older, () -> at)) {
                            Map<String, Object> row = new LinkedHashMap<>();
                            row.put("id", r.id());
                            row.put("state", r.state());
                            rows.add(row);
                        }
                        rows.sort((a, b) -> ((String) a.get("id")).compareTo((String) b.get("id")));
                        got = rows;
                        break;
                    }
                    case "recover_one": {
                        long at = Json.asLong(s.get("at"));
                        double older = s.containsKey("older_than_ms") ? (double) Json.asLong(s.get("older_than_ms")) : Operations.OPERATION_PENDING_TIMEOUT_MS;
                        OperationRecord r = Operations.recoverOperation(store, (String) s.get("id"), older, () -> at);
                        got = r == null ? null : r.toMap();
                        break;
                    }
                    case "resolve": {
                        long at = Json.asLong(s.get("at"));
                        Map<String, Object> o = m(s.get("outcome"));
                        if ("committed".equals(o.get("state")))
                            got = o.containsKey("result") ? Operations.resolveCommitted(store, (String) s.get("id"), o.get("result"), () -> at)
                                : Operations.resolveCommitted(store, (String) s.get("id"), () -> at);
                        else got = Operations.resolveFailed(store, (String) s.get("id"), (String) o.get("error"), () -> at);
                        break;
                    }
                    case "execute":
                        got = execute(s, store);
                        break;
                    default:
                        throw new AssertionError(name + ": unknown step " + s.get("op"));
                }
                assertEquals(canon(expect.get(i)), canon(got), name + " step " + i);
            }
        }
    }

    // ---- concurrency ---------------------------------------------------------------------------------------------------

    static void parallelExecutionsRunOnce(OperationStore store) throws Exception {
        Authorize.AuthorizeResult az = allowed("op-parallel", "payments.refund", "/orders/1", Pca.paramsDigest(null), reversiblePcactn());
        int n = 16;
        AtomicInteger runs = new AtomicInteger();
        List<Operations.ExecuteOutcome> outcomes = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch start = new CountDownLatch(1);
        List<Thread> ts = new ArrayList<>();
        Operations.ExecuteOptions opts = new Operations.ExecuteOptions().store(store).now(() -> T0);
        for (int i = 0; i < n; i++) {
            Thread t = new Thread(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    return;
                }
                outcomes.add(Operations.executeAuthorized(az, h -> { runs.incrementAndGet(); Thread.sleep(20); return "done"; }, opts));
            });
            ts.add(t);
            t.start();
        }
        start.countDown();
        for (Thread t : ts) t.join();
        assertEquals(1, runs.get(), "the function ran exactly once");
        assertEquals(n, outcomes.size());
        int fresh = 0;
        for (Operations.ExecuteOutcome o : outcomes) if (!o.replayed) fresh++;
        assertEquals(1, fresh, "exactly one execution is not a replay");
        assertEquals(OperationRecord.COMMITTED, store.get("op-parallel").state());
        // once committed, every further execution is answered from the record
        Operations.ExecuteOutcome again = Operations.executeAuthorized(az, h -> { runs.incrementAndGet(); return "again"; }, opts);
        assertEquals(1, runs.get());
        assertTrue(again.replayed);
        assertEquals("done", again.result);
    }

    @Test void parallelExecutionsRunOnceInMemory() throws Exception { parallelExecutionsRunOnce(new MemoryOperationStore()); }

    @Test void parallelExecutionsRunOnceOnSqlite() throws Exception {
        Path f = Files.createTempFile("pca-ops", ".db");
        try {
            parallelExecutionsRunOnce(new AtomicKvOperationStore(new PcaJdbcAtomicKv(() -> AuthorizeFixtures.sqliteConnection(f)).createTable()));
        } finally {
            Files.deleteIfExists(f);
        }
    }

    @Test void kvStoreHonoursTheStoreContract() throws Exception {
        Path f = Files.createTempFile("pca-ops-contract", ".db");
        try {
            for (OperationStore store : List.of(new MemoryOperationStore(), new AtomicKvOperationStore(new MemoryAtomicKv()),
                    new AtomicKvOperationStore(new PcaJdbcAtomicKv(() -> AuthorizeFixtures.sqliteConnection(f)).createTable()))) {
                OperationRecord rec = OperationRecord.pending("c1", "v", "/r", Pca.paramsDigest(null), "reversible", T0);
                assertNull(store.create(rec));
                assertEquals("pending", store.create(rec.with("verb", "other")).state(), "create-once returns the existing record");
                assertEquals("v", store.get("c1").verb());
                assertFalse(store.transition("c1", "executing", rec.moved("committed", null, T0, null)), "a transition from the wrong state is refused");
                assertTrue(store.transition("c1", "pending", rec.moved("executing", T0, null, null)));
                assertFalse(store.transition("c1", "pending", rec.moved("aborted", null, T0, "x")), "the old state no longer matches");
                assertEquals("executing", store.get("c1").state());
                assertEquals(Long.valueOf(T0), store.get("c1").executingAt());
                assertNull(store.get("nope"));
                assertFalse(store.transition("nope", "pending", rec));
            }
        } finally {
            Files.deleteIfExists(f);
        }
    }

    @Test void durableStoreSurvivesANewHandle() throws Exception {
        Path f = Files.createTempFile("pca-ops-durable", ".db");
        try {
            OperationStore a = new AtomicKvOperationStore(new PcaJdbcAtomicKv(() -> AuthorizeFixtures.sqliteConnection(f)).createTable());
            Authorize.AuthorizeResult az = allowed("op-dur", "payments.refund", "/orders/1", Pca.paramsDigest(null), reversiblePcactn());
            Operations.ExecuteOptions oa = new Operations.ExecuteOptions().store(a).now(() -> T0);
            AtomicInteger runs = new AtomicInteger();
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("n", IntentJs.ofLong(7));
            assertEquals("committed", Operations.executeAuthorized(az, h -> { runs.incrementAndGet(); return result; }, oa).status);
            // a new process: a new store on the same file answers from the record
            OperationStore b = new AtomicKvOperationStore(new PcaJdbcAtomicKv(() -> AuthorizeFixtures.sqliteConnection(f)));
            Operations.ExecuteOutcome o = Operations.executeAuthorized(az, h -> { runs.incrementAndGet(); return "x"; }, new Operations.ExecuteOptions().store(b).now(() -> T0));
            assertEquals(1, runs.get());
            assertTrue(o.replayed);
            assertEquals(canon(result), canon(o.result));
        } finally {
            Files.deleteIfExists(f);
        }
    }

    @Test void refusalsRecordNothing() {
        OperationStore store = new MemoryOperationStore();
        Authorize.AuthorizeResult az = allowed("op-r", "payments.refund", "/orders/1", Pca.paramsDigest(null), new LinkedHashMap<>());
        Operations.ExecuteOptions opts = new Operations.ExecuteOptions().store(store).now(() -> T0);
        // the authorization is for another operation
        Map<String, Object> p = new LinkedHashMap<>();
        Operations.ExecuteOutcome wrong = Operations.executeAuthorized(az, h -> "x",
            new Operations.ExecuteOptions().store(store).now(() -> T0).operation(Authorize.Operation.of("payments.refund", "/orders/2", p)));
        assertEquals("refused", wrong.status);
        assertNull(store.get("op-r"));
        // a null function, and a null authorization
        assertEquals("refused", Operations.executeAuthorized(az, null, opts).status);
        assertEquals("refused", Operations.executeAuthorized(null, h -> "x", opts).status);
        assertNull(store.get("op-r"));
        // recover needs listOpen
        assertThrows(UnsupportedOperationException.class, () -> Operations.recoverOperations(new AtomicKvOperationStore(new MemoryAtomicKv())));
    }

    // ---- the executor --------------------------------------------------------------------------------------------------

    @Test void executorAnswersARetryFromTheRecord() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Map<String, Object> grant = AuthorizeFixtures.grant(c);
        Object pcactn = AuthorizeFixtures.pcactn(c, 0);
        Authorize.Operation op = AuthorizeFixtures.operation(c, 0);
        long now = AuthorizeFixtures.now();
        StateStore replay = new MemoryStateStore();
        OperationStore records = new MemoryOperationStore();
        boolean[] revoked = {false};
        Operations.Executor ex = Operations.createExecutor(new Operations.ExecutorOptions().operations(records)
            .authorize(new Authorize.Options(replay, (p, g) -> revoked[0]).withProvenance(ProvHarness.options())).audience(AuthorizeFixtures.audience())
            .resolveGrant(ref -> grant).now(() -> now));
        AtomicInteger runs = new AtomicInteger();

        Operations.ExecuteOutcome first = ex.execute(pcactn, op, h -> { runs.incrementAndGet(); return h.idempotencyKey; });
        assertEquals("committed", first.status, first.toString());
        assertFalse(first.replayed);
        assertTrue(first.recorded);
        assertEquals(first.operationId, first.result);
        assertEquals(OperationRecord.COMMITTED, records.get(first.operationId).state());

        // the same proof again: authorize refuses it as a replay, the executor answers from the record
        Operations.ExecuteOutcome retry = ex.execute(pcactn, op, h -> { runs.incrementAndGet(); return "again"; });
        assertEquals("committed", retry.status);
        assertTrue(retry.replayed);
        assertEquals(first.result, retry.result);
        assertEquals(1, runs.get());

        // another operation under the same proof is a denial, not the record
        Authorize.Operation other = Authorize.Operation.of(op.verb, op.resource + "/other", op.params);
        assertEquals("denied", ex.execute(pcactn, other, h -> "x").status);
        assertEquals(1, runs.get());
    }

    @Test void executorDeniesAReplayWithNoRecordAndARevokedGrant() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Map<String, Object> grant = AuthorizeFixtures.grant(c);
        Object pcactn = AuthorizeFixtures.pcactn(c, 0);
        Authorize.Operation op = AuthorizeFixtures.operation(c, 0);
        long now = AuthorizeFixtures.now();
        StateStore replay = new MemoryStateStore();
        Authorize.Options az = new Authorize.Options(replay, (p, g) -> false).withProvenance(ProvHarness.options());
        // the proof was consumed by a plain authorize and never reached execution: there is no record, the denial stands
        assertTrue(az.run(pcactn, op, AuthorizeFixtures.audience(), ref -> grant, now).allow);
        Operations.Executor ex = Operations.createExecutor(new Operations.ExecutorOptions().operations(new MemoryOperationStore())
            .authorize(az).audience(AuthorizeFixtures.audience()).resolveGrant(ref -> grant).now(() -> now));
        Operations.ExecuteOutcome out = ex.execute(pcactn, op, h -> "x");
        assertEquals("denied", out.status);
        assertNotNull(out.authorization);
        assertFalse(out.authorization.allow);

        // a revoked grant is denied before anything runs
        Operations.Executor revoked = Operations.createExecutor(new Operations.ExecutorOptions().operations(new MemoryOperationStore())
            .authorize(new Authorize.Options(new MemoryStateStore(), (p, g) -> true).withProvenance(ProvHarness.options())).audience(AuthorizeFixtures.audience()).resolveGrant(ref -> grant).now(() -> now));
        assertEquals("denied", revoked.execute(pcactn, op, h -> "x").status);
        assertThrows(IllegalArgumentException.class, () -> Operations.createExecutor(new Operations.ExecutorOptions()));
        assertEquals("refused", Operations.createExecutor(new Operations.ExecutorOptions().authorize(az).audience("a").resolveGrant(ref -> grant))
            .execute(pcactn, op, h -> "x").status);
    }

    @Test void executorRechecksAnIrreversibleOperationBeforeItRuns() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Map<String, Object> grant = AuthorizeFixtures.grant(c);
        Object pcactn = AuthorizeFixtures.pcactn(c, 0);
        Authorize.Operation op = AuthorizeFixtures.operation(c, 0);
        long now = AuthorizeFixtures.now();
        AtomicInteger runs = new AtomicInteger();
        // the signed class of this fixture is irreversible: the extra recheck refuses, the function never runs, the record is aborted
        OperationStore records = new MemoryOperationStore();
        Operations.Executor ex = Operations.createExecutor(new Operations.ExecutorOptions().operations(records)
            .authorize(new Authorize.Options(new MemoryStateStore(), (p, g) -> false).withProvenance(ProvHarness.options())).audience(AuthorizeFixtures.audience())
            .resolveGrant(ref -> grant).recheck(h -> Operations.RecheckResult.refuse("approval withdrawn")).now(() -> now));
        Operations.ExecuteOutcome out = ex.execute(pcactn, op, h -> { runs.incrementAndGet(); return "x"; });
        assertEquals("aborted", out.status);
        assertEquals("recheck: approval withdrawn", out.reason);
        assertEquals(0, runs.get());
        assertEquals(OperationRecord.ABORTED, records.get(out.operationId).state());
    }
}
