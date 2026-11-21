package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.IntPredicate;
import java.util.function.LongSupplier;

import org.junit.jupiter.api.Test;

/**
 * Operation records (T3) outcome by outcome: every refusal reason, the exact outcome and record of each path (commit, failure,
 * abort, the record answers, stale settling), the races a store can lose (a recovery or a second worker moving the record
 * between two steps), recovery and reconciliation, and the executor's re-check, options and replay answer.
 */
public class OperationsKillTest {
    static final long T0 = 1_800_000_000_000L;
    static final double TO = 1000;
    static final String PD = Pca.paramsDigest(null);

    /** An operation store that can lose (or fail) chosen transitions and forget a record on chosen reads. */
    static final class Scripted implements OperationStore {
        final MemoryOperationStore m = new MemoryOperationStore();
        final List<String> log = new ArrayList<>();
        Function<String, Boolean> onTransition = k -> null;
        IntPredicate nullGet = i -> false;
        int gets;

        @Override public OperationRecord create(OperationRecord r) { log.add("create " + r.id()); return m.create(r); }
        @Override public OperationRecord get(String id) {
            int i = gets++;
            log.add("get " + id);
            return nullGet.test(i) ? null : m.get(id);
        }
        @Override public boolean transition(String id, String from, OperationRecord next) {
            String k = from + ">" + next.state();
            log.add("transition " + id + " " + k);
            Boolean forced = onTransition.apply(k);
            return forced != null ? forced : m.transition(id, from, next);
        }
        @Override public boolean supportsListOpen() { return true; }
        @Override public List<OperationRecord> listOpen() { return m.listOpen(); }
    }

    static Map<String, Object> pc(String cls, Object exp) {
        Map<String, Object> action = new LinkedHashMap<>();
        if (cls != null) action.put("reversibility_class", cls);
        Map<String, Object> p = new LinkedHashMap<>();
        if (exp != null) p.put("exp", exp);
        p.put("action", action);
        return p;
    }

    static Authorize.AuthorizeResult az(String id, Map<String, Object> pcactn) {
        return OperationVectorsTest.allowed(id, "v", "/r", PD, pcactn);
    }

    static Authorize.AuthorizeResult result(boolean allow, Boolean verdictAllow, Map<String, Object> pcactn, Authorize.AuthorizedOperation op) {
        Pca.Verdict v = null;
        if (verdictAllow != null) {
            v = new Pca.Verdict();
            v.allow = verdictAllow;
        }
        return new Authorize.AuthorizeResult(allow, 200, new LinkedHashMap<>(), new ArrayList<>(), null, op, pcactn, v, null);
    }

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static Operations.ExecuteOptions opts(OperationStore s, long now) {
        return new Operations.ExecuteOptions().store(s).now(() -> now).pendingTimeoutMs(TO);
    }

    static final Operations.OperationFn NEVER = h -> { throw new AssertionError("the function must not run"); };

    static void assertOutcome(Map<String, Object> want, Operations.ExecuteOutcome out) {
        assertEquals(want, out.toMap());
        assertEquals("ExecuteOutcome" + want, out.toString());
    }

    static void assertRefused(String reason, Operations.ExecuteOutcome out) {
        assertOutcome(map("status", "refused", "reason", reason), out);
        assertNull(out.operationId);
        assertFalse(out.replayed);
        assertFalse(out.recorded);
        assertFalse(out.hasResult);
        assertNull(out.error);
        assertNull(out.result);
        assertNull(out.authorization);
    }

    static OperationRecord seed(OperationStore s, Object... kv) {
        OperationRecord r = OperationRecord.of(map(kv));
        assertNull(s.create(r));
        return r;
    }

    // ---- refusals --------------------------------------------------------------------------------------------------

    @Test void refusalsNameTheMissingPartAndRecordNothing() {
        MemoryOperationStore st = new MemoryOperationStore();
        Authorize.AuthorizeResult ok = az("op", pc("reversible", null));
        Operations.OperationFn fn = h -> "r";
        String noStore = "executeAuthorized: missing required component: store (fail closed)";
        assertRefused(noStore, Operations.executeAuthorized(ok, fn, (Operations.ExecuteOptions) null));
        assertRefused(noStore, Operations.executeAuthorized(ok, fn, new Operations.ExecuteOptions()));
        assertRefused(noStore, Operations.executeAuthorized(ok, fn, (OperationStore) null));
        assertRefused("executeAuthorized: missing required component: fn (fail closed)", Operations.executeAuthorized(ok, null, opts(st, T0)));

        Map<String, Object> p = pc("reversible", null);
        Authorize.AuthorizedOperation op = new Authorize.AuthorizedOperation("v", "/r", PD, "op");
        String notAllowed = "executeAuthorized: the authorization did not allow an operation";
        for (Authorize.AuthorizeResult bad : new Authorize.AuthorizeResult[] {
            null,
            result(false, true, p, op),
            result(true, null, p, op),
            result(true, false, p, op),
            result(true, true, null, op),
            result(true, true, p, null),
            result(true, true, p, new Authorize.AuthorizedOperation("v", "/r", PD, null)),
            result(true, true, p, new Authorize.AuthorizedOperation("v", "/r", PD, "")),
        }) assertRefused(notAllowed, Operations.executeAuthorized(bad, NEVER, opts(st, T0)));
        // the same parts, complete, run
        assertEquals("committed", Operations.executeAuthorized(result(true, true, p, op), h -> "r", opts(st, T0)).status);

        MemoryOperationStore st2 = new MemoryOperationStore();
        assertRefused("executeAuthorized: the authorization is not for this operation (verb, resource or params differ)",
            Operations.executeAuthorized(ok, NEVER, opts(st2, T0).operation(Authorize.Operation.of("v", "/other", new LinkedHashMap<>()))));
        assertRefused("executeAuthorized: a irreversible operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)",
            Operations.executeAuthorized(az("op", map("action", "not an object")), NEVER, opts(st2, T0)));
        assertRefused("executeAuthorized: a irreversible operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)",
            Operations.executeAuthorized(ok, NEVER, opts(st2, T0).reversibilityClass("irreversible").now(() -> T0)));
        assertRefused("executeAuthorized: a rate_limited operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)",
            Operations.executeAuthorized(az("op", pc("costly", null)), NEVER, opts(st2, T0).recheckFor("always")));
        assertNull(st2.get("op"), "a refusal records nothing");
        // the operation it IS for runs; a costly one needs no recheck by default
        assertEquals("committed", Operations.executeAuthorized(ok, h -> "r", opts(st2, T0).operation(Authorize.Operation.of("v", "/r", new LinkedHashMap<>()))).status);
        assertEquals("committed", Operations.executeAuthorized(az("c", pc("costly", null)), h -> "r", opts(st2, T0)).status);
        assertEquals("committed", Operations.executeAuthorized(az("s", pc("reversible", null)), h -> "r", st2).status);
        assertEquals("committed", st2.get("s").state());

        Operations.ExecuteOutcome d = Operations.ExecuteOutcome.denied(new Authorize.AuthorizeResult(false, 403, new LinkedHashMap<>(), new ArrayList<>(), "nope", null, p, null, null));
        assertOutcome(map("status", "denied", "reason", "nope"), d);
        assertFalse(d.replayed);
        assertFalse(d.recorded);
        assertFalse(d.hasResult);
        assertNotNull(d.authorization);
    }

    // ---- the fresh paths -------------------------------------------------------------------------------------------

    @Test void aCommitSeesTheHandleAndRecordsTheResult() {
        MemoryOperationStore st = new MemoryOperationStore();
        Map<String, Object> p = pc("reversible", null);
        Authorize.AuthorizeResult a = az("op", p);
        Operations.ExecuteOutcome out = Operations.executeAuthorized(a, h -> {
            assertEquals("op", h.idempotencyKey);
            assertSame(a.operation, h.operation);
            assertSame(p, h.pcactn);
            return "done";
        }, opts(st, T0));
        assertOutcome(map("status", "committed", "operationId", "op", "result", "done", "replayed", false, "recorded", true), out);
        assertTrue(out.hasResult);
        assertEquals("{\"executingAt\":1800000000000,\"finishedAt\":1800000000000,\"id\":\"op\",\"params_digest\":\"" + PD
            + "\",\"resource\":\"/r\",\"result\":\"done\",\"reversibility\":\"reversible\",\"startedAt\":1800000000000,\"state\":\"committed\",\"verb\":\"v\"}",
            Json.canonicalize(st.get("op").toMap()));

        Operations.ExecuteOutcome nul = Operations.executeAuthorized(az("n", p), h -> null, opts(st, T0));
        assertOutcome(map("status", "committed", "operationId", "n", "result", null, "replayed", false, "recorded", true), nul);
        assertTrue(st.get("n").hasResult());
    }

    @Test void aThrowIsRecordedAsFailed() {
        MemoryOperationStore st = new MemoryOperationStore();
        Operations.ExecuteOutcome boom = Operations.executeAuthorized(az("b", pc("reversible", null)), h -> { throw new IllegalStateException("boom"); }, opts(st, T0));
        assertOutcome(map("status", "failed", "operationId", "b", "error", "boom", "replayed", false), boom);
        assertFalse(boom.recorded);
        assertFalse(boom.hasResult);
        assertNull(boom.reason);
        assertEquals("failed", st.get("b").state());
        assertEquals("boom", st.get("b").error());
        Operations.ExecuteOutcome anon = Operations.executeAuthorized(az("a", pc("reversible", null)), h -> { throw new IllegalStateException(); }, opts(st, T0));
        assertEquals("IllegalStateException", anon.error);
        assertEquals("IllegalStateException", st.get("a").error());
        // a store that cannot record the failure: the failure is still returned
        Scripted sc = new Scripted();
        sc.onTransition = k -> { if (k.equals("executing>failed")) throw new IllegalStateException("store down"); return null; };
        Operations.ExecuteOutcome f = Operations.executeAuthorized(az("x", pc("reversible", null)), h -> { throw new IllegalArgumentException("bad"); }, opts(sc, T0));
        assertOutcome(map("status", "failed", "operationId", "x", "error", "bad", "replayed", false), f);
        assertEquals("executing", sc.m.get("x").state());
    }

    @Test void recheckRefusalsAbortWithTheirReason() {
        Object[][] cases = {
            {null, (Operations.Recheck) h -> null, "recheck: refused"},
            {null, (Operations.Recheck) h -> Operations.RecheckResult.refuse(null), "recheck: refused"},
            {null, (Operations.Recheck) h -> Operations.RecheckResult.refuse(""), "recheck: refused"},
            {null, (Operations.Recheck) h -> Operations.RecheckResult.refuse("why"), "recheck: why"},
            {null, (Operations.Recheck) h -> { throw new IllegalStateException("down"); }, "recheck: recheck error (fail closed): down"},
            {null, (Operations.Recheck) h -> { throw new IllegalStateException(); }, "recheck: recheck error (fail closed): IllegalStateException"},
            {IntentJs.ofLong(T0 - 1), (Operations.Recheck) h -> { throw new AssertionError("an expired PCActn is not re-checked"); }, "recheck: the PCActn expired at 1799999999999"},
        };
        int i = 0;
        for (Object[] c : cases) {
            MemoryOperationStore st = new MemoryOperationStore();
            String id = "r" + i++;
            Operations.ExecuteOutcome out = Operations.executeAuthorized(az(id, pc("irreversible", c[0])), NEVER, opts(st, T0).recheck((Operations.Recheck) c[1]));
            assertOutcome(map("status", "aborted", "operationId", id, "reason", c[2], "replayed", false), out);
            assertFalse(out.recorded);
            assertFalse(out.hasResult);
            OperationRecord r = st.get(id);
            assertEquals("aborted", r.state());
            assertEquals(c[2], r.error());
            assertEquals(Long.valueOf(T0), r.finishedAt());
            assertNull(r.executingAt());
        }
        // not expired: exactly at exp, a NaN exp, no exp, a future exp
        for (Object exp : new Object[] {IntentJs.ofLong(T0), Double.NaN, null, IntentJs.ofLong(T0 + 1)}) {
            AtomicInteger checks = new AtomicInteger();
            Operations.ExecuteOutcome out = Operations.executeAuthorized(az("e", pc("irreversible", exp)), h -> "ran",
                opts(new MemoryOperationStore(), T0).recheck(h -> { checks.incrementAndGet(); return Operations.RecheckResult.ok(); }));
            assertEquals("committed", out.status, String.valueOf(exp));
            assertEquals(1, checks.get());
        }
        // "always" re-checks a reversible operation too
        assertEquals("aborted", Operations.executeAuthorized(az("al", pc("reversible", null)), NEVER,
            opts(new MemoryOperationStore(), T0).recheckFor("always").recheck(h -> Operations.RecheckResult.refuse("no"))).status);
        // no clock given: the wall clock (far past and far future expiries)
        Operations.ExecuteOptions wall = new Operations.ExecuteOptions().store(new MemoryOperationStore()).recheck(h -> Operations.RecheckResult.ok());
        assertEquals("recheck: the PCActn expired at 1", Operations.executeAuthorized(az("w1", pc("irreversible", IntentJs.ofLong(1))), NEVER, wall).reason);
        assertEquals("committed", Operations.executeAuthorized(az("w2", pc("irreversible", IntentJs.ofLong(4_000_000_000_000L))), h -> "x", wall).status);
    }

    // ---- answers from the record -------------------------------------------------------------------------------------

    static Object[] rec(String id, String state, Object... extra) {
        List<Object> kv = new ArrayList<>(List.of("id", id, "state", state, "verb", "v", "resource", "/r", "params_digest", PD,
            "reversibility", "reversible", "startedAt", IntentJs.ofLong(T0)));
        kv.addAll(List.of(extra));
        return kv.toArray();
    }

    @Test void everyRecordStateHasItsAnswer() {
        Object[][] cases = {
            {rec("c", "committed"), map("status", "committed", "operationId", "c", "replayed", true, "recorded", true), false},
            {rec("c2", "committed", "result", "R"), map("status", "committed", "operationId", "c2", "result", "R", "replayed", true, "recorded", true), true},
            {rec("f", "failed"), map("status", "failed", "operationId", "f", "error", "failed", "replayed", true), false},
            {rec("f2", "failed", "error", "e1"), map("status", "failed", "operationId", "f2", "error", "e1", "replayed", true), false},
            {rec("a", "aborted"), map("status", "aborted", "operationId", "a", "reason", "aborted", "replayed", true), false},
            {rec("a2", "aborted", "error", "e2"), map("status", "aborted", "operationId", "a2", "reason", "e2", "replayed", true), false},
            {rec("u", "uncertain"), map("status", "uncertain", "operationId", "u", "reason", "outcome unknown", "replayed", true), false},
            {rec("u2", "uncertain", "error", "e3"), map("status", "uncertain", "operationId", "u2", "reason", "e3", "replayed", true), false},
            {rec("p", "pending"), map("status", "pending", "operationId", "p", "replayed", true), false},
            {rec("x", "executing", "executingAt", IntentJs.ofLong(T0)), map("status", "pending", "operationId", "x", "replayed", true), false},
            {rec("w", "weird"), map("status", "uncertain", "operationId", "w", "reason", "unknown record state 'weird'", "replayed", true), false},
        };
        for (Object[] c : cases) {
            MemoryOperationStore st = new MemoryOperationStore();
            OperationRecord r = seed(st, (Object[]) c[0]);
            Operations.ExecuteOutcome out = Operations.executeAuthorized(az(r.id(), pc("reversible", null)), NEVER, opts(st, T0));
            assertOutcome(m(c[1]), out);
            assertTrue(out.replayed);
            assertEquals(c[2], out.hasResult, r.id());
            assertEquals("committed".equals(r.state()), out.recorded, r.id());
            assertEquals(r.toMap(), st.get(r.id()).toMap(), "answering never changes a settled or fresh record");
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @Test void openRecordsAreSettledByTheirOwnClock() {
        // executing: aged from executingAt; exactly the timeout is not stale
        MemoryOperationStore st = new MemoryOperationStore();
        seed(st, rec("x", "executing", "executingAt", IntentJs.ofLong(T0 + 500)));
        assertEquals("pending", Operations.executeAuthorized(az("x", pc("reversible", null)), NEVER, opts(st, T0 + 1500)).status);
        Operations.ExecuteOutcome late = Operations.executeAuthorized(az("x", pc("reversible", null)), NEVER, opts(st, T0 + 1501));
        String unc = "no outcome recorded within 1000 ms of the start: the side effect may or may not have happened";
        assertOutcome(map("status", "uncertain", "operationId", "x", "reason", unc, "replayed", true), late);
        assertEquals(unc, st.get("x").error());
        assertEquals(Long.valueOf(T0 + 1501), st.get("x").finishedAt());
        // executing without executingAt: aged from startedAt
        seed(st, rec("y", "executing"));
        assertEquals("uncertain", Operations.executeAuthorized(az("y", pc("reversible", null)), NEVER, opts(st, T0 + 1001)).status);
        // pending: aged from startedAt even when an executingAt is present
        seed(st, rec("p", "pending", "executingAt", IntentJs.ofLong(T0 + 900)));
        assertEquals("pending", Operations.executeAuthorized(az("p", pc("reversible", null)), NEVER, opts(st, T0 + 1000)).status);
        Operations.ExecuteOutcome ab = Operations.executeAuthorized(az("p", pc("reversible", null)), NEVER, opts(st, T0 + 1001));
        assertOutcome(map("status", "aborted", "operationId", "p", "reason", "not started within 1000 ms of the claim: the side effect never ran", "replayed", true), ab);
    }

    @Test void aSettleThatLosesAnswersWhatIsStored() {
        Scripted s = new Scripted();
        seed(s, rec("x", "executing", "executingAt", IntentJs.ofLong(T0)));
        s.onTransition = k -> k.equals("executing>uncertain") ? Boolean.FALSE : null;
        assertEquals("executing", Operations.recoverOperation(s, "x", TO, () -> T0 + 1001).state());
        // ... and when the record is gone afterwards, the settled one is returned
        s.gets = 0;
        s.nullGet = i -> i == 1;
        OperationRecord gone = Operations.recoverOperation(s, "x", TO, () -> T0 + 1001);
        assertEquals("uncertain", gone.state());
        assertEquals("no outcome recorded within 1000 ms of the start: the side effect may or may not have happened", gone.error());
        assertNull(Operations.recoverOperation(new MemoryOperationStore(), "none", TO, () -> T0));
    }

    // ---- races with a recovery -------------------------------------------------------------------------------------

    @Test void aCommitAfterARecoveryMadeItUncertainIsStillRecorded() {
        MemoryOperationStore st = new MemoryOperationStore();
        Operations.ExecuteOutcome out = Operations.executeAuthorized(az("op", pc("reversible", null)), h -> {
            assertEquals("uncertain", Operations.recoverOperation(st, "op", 0, () -> T0 + 1).state());
            return "done";
        }, opts(st, T0));
        assertOutcome(map("status", "committed", "operationId", "op", "result", "done", "replayed", false, "recorded", true), out);
        assertEquals("committed", st.get("op").state());
        assertEquals("done", st.get("op").result());

        // the uncertain record was reconciled as failed meanwhile: the commit is not recorded, the reconciliation stands
        MemoryOperationStore st2 = new MemoryOperationStore();
        Operations.ExecuteOutcome lost = Operations.executeAuthorized(az("op", pc("reversible", null)), h -> {
            Operations.recoverOperation(st2, "op", 0, () -> T0 + 1);
            assertTrue(Operations.resolveFailed(st2, "op", "gone", () -> T0 + 2));
            return "done";
        }, opts(st2, T0));
        assertOutcome(map("status", "committed", "operationId", "op", "result", "done", "replayed", false, "recorded", false), lost);
        assertEquals("failed", st2.get("op").state());

        // a store error while recording the commit
        Scripted sc = new Scripted();
        sc.onTransition = k -> { if (k.equals("executing>committed")) throw new IllegalStateException("store down"); return null; };
        Operations.ExecuteOutcome err = Operations.executeAuthorized(az("op", pc("reversible", null)), h -> "done", opts(sc, T0));
        assertOutcome(map("status", "committed", "operationId", "op", "result", "done", "replayed", false, "recorded", false), err);
    }

    @Test void anAbortThatLosesNeverOverwritesAnotherState() {
        // the re-check itself sees the claim settled as uncertain: the abort is not forced over it
        MemoryOperationStore st = new MemoryOperationStore();
        Operations.ExecuteOutcome out = Operations.executeAuthorized(az("op", pc("irreversible", null)), NEVER, opts(st, T0).recheck(h -> {
            assertTrue(st.transition("op", "pending", OperationRecord.pending("op", "v", "/r", PD, "irreversible", T0).moved("uncertain", null, T0, "moved")));
            return Operations.RecheckResult.refuse("no");
        }));
        assertOutcome(map("status", "uncertain", "operationId", "op", "reason", "moved", "replayed", true), out);
        assertEquals("uncertain", st.get("op").state());

        // the abort loses and the record is gone
        Scripted gone = new Scripted();
        gone.onTransition = k -> k.equals("pending>aborted") ? Boolean.FALSE : null;
        gone.nullGet = i -> i == 0;
        Operations.ExecuteOutcome g = Operations.executeAuthorized(az("op", pc("irreversible", null)), NEVER, opts(gone, T0).recheck(h -> Operations.RecheckResult.refuse("no")));
        assertOutcome(map("status", "uncertain", "operationId", "op", "reason", "the operation record disappeared", "replayed", true), g);
        assertFalse(g.recorded);
        assertFalse(g.hasResult);

        // the abort loses once, then the answer is read at the current time (the claim is long stale by then)
        Scripted late = new Scripted();
        int[] n = {0};
        late.onTransition = k -> k.equals("pending>aborted") && n[0]++ == 0 ? Boolean.FALSE : null;
        AtomicInteger clock = new AtomicInteger();
        LongSupplier ticking = () -> clock.getAndIncrement() == 0 ? T0 : T0 + 5000;
        Operations.ExecuteOutcome l = Operations.executeAuthorized(az("op", pc("irreversible", null)), NEVER,
            new Operations.ExecuteOptions().store(late).now(ticking).pendingTimeoutMs(TO).recheck(h -> Operations.RecheckResult.refuse("no")));
        assertOutcome(map("status", "aborted", "operationId", "op", "reason", "not started within 1000 ms of the claim: the side effect never ran", "replayed", true), l);
    }

    @Test void aClaimMovedBeforeTheStartIsAnsweredAtTheCurrentTime() {
        Scripted s = new Scripted();
        int[] n = {0};
        s.onTransition = k -> k.equals("pending>executing") && n[0]++ == 0 ? Boolean.FALSE : null;
        AtomicInteger clock = new AtomicInteger();
        LongSupplier ticking = () -> clock.getAndIncrement() == 0 ? T0 : T0 + 5000;
        Operations.ExecuteOutcome out = Operations.executeAuthorized(az("op", pc("reversible", null)), NEVER,
            new Operations.ExecuteOptions().store(s).now(ticking).pendingTimeoutMs(TO));
        assertOutcome(map("status", "aborted", "operationId", "op", "reason", "not started within 1000 ms of the claim: the side effect never ran", "replayed", true), out);

        Scripted g = new Scripted();
        g.onTransition = k -> k.equals("pending>executing") ? Boolean.FALSE : null;
        g.nullGet = i -> i == 0;
        assertEquals("the operation record disappeared", Operations.executeAuthorized(az("op", pc("reversible", null)), NEVER, opts(g, T0)).reason);
    }

    // ---- recovery and reconciliation ---------------------------------------------------------------------------------

    @Test void recovery() {
        String noList = "recoverOperations: the store has no listOpen (recover by id with recoverOperation)";
        assertEquals(noList, assertThrows(UnsupportedOperationException.class, () -> Operations.recoverOperations(null, TO, () -> T0)).getMessage());
        assertEquals(noList, assertThrows(UnsupportedOperationException.class,
            () -> Operations.recoverOperations(new AtomicKvOperationStore(new MemoryAtomicKv()), TO, () -> T0)).getMessage());

        MemoryOperationStore st = new MemoryOperationStore();
        seed(st, rec("a", "pending"));
        seed(st, rec("b", "pending", "startedAt", IntentJs.ofLong(T0 + 900)));
        seed(st, rec("c", "executing", "executingAt", IntentJs.ofLong(T0)));
        seed(st, rec("d", "committed"));
        List<OperationRecord> got = new ArrayList<>(Operations.recoverOperations(st, TO, () -> T0 + 1001));
        got.sort((x, y) -> x.id().compareTo(y.id()));
        assertEquals(2, got.size());
        assertEquals("a", got.get(0).id());
        assertEquals("aborted", got.get(0).state());
        assertEquals("c", got.get(1).id());
        assertEquals("uncertain", got.get(1).state());
        assertEquals("pending", st.get("b").state());

        // a record that disappears between the listing and its recovery is skipped
        Scripted s = new Scripted();
        seed(s, rec("z", "pending"));
        s.nullGet = i -> i == 0;
        assertEquals(List.of(), Operations.recoverOperations(s, TO, () -> T0 + 5000));

        // the defaults: 5 minutes, the wall clock
        long now = System.currentTimeMillis();
        MemoryOperationStore w = new MemoryOperationStore();
        seed(w, "id", "fresh", "state", "pending", "startedAt", IntentJs.ofLong(now - 60_000));
        assertEquals(List.of(), Operations.recoverOperations(w));
        assertEquals("pending", Operations.recoverOperation(w, "fresh").state());
        seed(w, "id", "old", "state", "pending", "startedAt", IntentJs.ofLong(now - 600_000));
        List<OperationRecord> old = Operations.recoverOperations(w);
        assertEquals(1, old.size());
        assertEquals("old", old.get(0).id());
        assertEquals("aborted", old.get(0).state());
        seed(w, "id", "ancient", "state", "pending", "startedAt", IntentJs.ofLong(0));
        assertEquals("aborted", Operations.recoverOperation(w, "ancient", TO, null).state());
        assertNull(Operations.recoverOperation(w, "missing"));
    }

    @Test void reconciliation() {
        Object[] unc = rec("u", "uncertain", "executingAt", IntentJs.ofLong(T0), "finishedAt", IntentJs.ofLong(T0 + 5), "error", "why");
        String base = "\"executingAt\":1800000000000,\"finishedAt\":1800000000009,\"id\":\"u\",\"params_digest\":\"" + PD + "\",\"resource\":\"/r\"";

        MemoryOperationStore st = new MemoryOperationStore();
        seed(st, unc);
        assertTrue(Operations.resolveCommitted(st, "u", "R", () -> T0 + 9));
        assertEquals("{\"error\":\"why\"," + base + ",\"result\":\"R\",\"reversibility\":\"reversible\",\"startedAt\":1800000000000,\"state\":\"committed\",\"verb\":\"v\"}",
            Json.canonicalize(st.get("u").toMap()));
        assertFalse(Operations.resolveCommitted(st, "u", "R2", () -> T0 + 10), "only an uncertain record is settled");
        assertFalse(Operations.resolveCommitted(st, "u", () -> T0 + 10));
        assertFalse(Operations.resolveFailed(st, "u", "x", () -> T0 + 10));
        assertEquals("R", st.get("u").result());
        assertFalse(Operations.resolveCommitted(st, "missing", "R", () -> T0));

        MemoryOperationStore st2 = new MemoryOperationStore();
        seed(st2, unc);
        assertTrue(Operations.resolveCommitted(st2, "u", () -> T0 + 9));
        assertEquals("{\"error\":\"why\"," + base + ",\"reversibility\":\"reversible\",\"startedAt\":1800000000000,\"state\":\"committed\",\"verb\":\"v\"}",
            Json.canonicalize(st2.get("u").toMap()));

        MemoryOperationStore st3 = new MemoryOperationStore();
        seed(st3, unc);
        assertTrue(Operations.resolveCommitted(st3, "u", null, () -> T0 + 9));
        assertTrue(st3.get("u").hasResult());

        MemoryOperationStore st4 = new MemoryOperationStore();
        seed(st4, unc);
        assertTrue(Operations.resolveFailed(st4, "u", null, () -> T0 + 9));
        assertEquals("{\"error\":\"\"," + base + ",\"reversibility\":\"reversible\",\"startedAt\":1800000000000,\"state\":\"failed\",\"verb\":\"v\"}",
            Json.canonicalize(st4.get("u").toMap()));

        MemoryOperationStore st5 = new MemoryOperationStore();
        seed(st5, unc);
        long before = System.currentTimeMillis();
        assertTrue(Operations.resolveFailed(st5, "u", "e", null));
        long at = st5.get("u").finishedAt();
        assertTrue(at >= before && at <= System.currentTimeMillis());
        assertEquals("e", st5.get("u").error());

        // the store loses the transition: not settled
        Scripted s = new Scripted();
        seed(s, unc);
        s.onTransition = k -> Boolean.FALSE;
        assertFalse(Operations.resolveCommitted(s, "u", "R", () -> T0));
        assertFalse(Operations.resolveCommitted(s, "u", () -> T0));
        assertFalse(Operations.resolveFailed(s, "u", "e", () -> T0));
    }

    // ---- the executor ----------------------------------------------------------------------------------------------

    static Map<String, Object> handlePcactn(Object grantRef, Object plan) {
        Map<String, Object> p = new LinkedHashMap<>();
        if (grantRef != null) p.put("grant_ref", grantRef);
        if (plan != null) p.put("plan", plan);
        return p;
    }

    static Operations.Executor executor(Authorize.RevocationCheck revoked, PlanRegistry plans, Operations.Recheck extra, long now) {
        Authorize.Options az = new Authorize.Options(new MemoryStateStore(), revoked, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO);
        if (plans != null) az = az.withPlans(plans);
        Map<String, Object> grant = map("g", "rant");
        Operations.ExecutorOptions o = new Operations.ExecutorOptions().operations(new MemoryOperationStore()).authorize(az).audience("aud")
            .resolveGrant(ref -> "g1".equals(ref) ? grant : null).now(() -> now);
        if (extra != null) o.recheck(extra);
        return Operations.createExecutor(o);
    }

    static Operations.ExecutionHandle handle(Map<String, Object> p) { return new Operations.ExecutionHandle("id", null, p); }

    static void assertRecheck(String reason, Operations.RecheckResult r) {
        if (reason == null) {
            assertTrue(r.ok);
            assertNull(r.reason);
        } else {
            assertFalse(r.ok);
            assertEquals(reason, r.reason);
        }
    }

    @Test void theExecutorRecheck() throws Exception {
        Operations.Executor ok = executor((p, g) -> false, null, null, T0);
        assertRecheck("the grant is no longer known", ok.recheck(handle(handlePcactn(null, null))));
        assertRecheck("the grant is no longer known", ok.recheck(handle(handlePcactn(IntentJs.ofLong(1), null))));
        assertRecheck("the grant is no longer known", ok.recheck(handle(handlePcactn("g2", null))));
        assertRecheck(null, ok.recheck(handle(handlePcactn("g1", null))));
        assertRecheck("the grant has been revoked", executor((p, g) -> true, null, null, T0).recheck(handle(handlePcactn("g1", null))));
        assertRecheck("revocation could not be checked", executor((p, g) -> null, null, null, T0).recheck(handle(handlePcactn("g1", null))));
        assertRecheck("revocation could not be checked", executor((p, g) -> { throw new IllegalStateException("down"); }, null, null, T0).recheck(handle(handlePcactn("g1", null))));
        // the revocation check sees the presented PCActn and the resolved grant
        List<Object> seen = new ArrayList<>();
        Map<String, Object> hp = handlePcactn("g1", null);
        executor((p, g) -> { seen.add(p); seen.add(g); return false; }, null, null, T0).recheck(handle(hp));
        assertSame(hp, seen.get(0));
        assertEquals(map("g", "rant"), seen.get(1));
        // the extra re-check runs last
        assertRecheck("approval withdrawn", executor((p, g) -> false, null, h -> Operations.RecheckResult.refuse("approval withdrawn"), T0).recheck(handle(handlePcactn("g1", null))));
        assertRecheck("the grant has been revoked", executor((p, g) -> true, null, h -> { throw new AssertionError("not reached"); }, T0).recheck(handle(handlePcactn("g1", null))));
    }

    @Test void theExecutorRechecksARegisteredPlan() throws Exception {
        long now = T0;
        PlanRegistry reg = new PlanRegistry(new MemoryAtomicKv(), null, () -> now, null);
        String root = reg.draft("g1", PlanVectorsTest.nodes()).record.root();
        assertTrue(reg.validate("g1", root).ok);
        assertTrue(reg.commit("g1", root).ok);
        Operations.Executor ex = executor((p, g) -> false, reg, null, now);
        assertRecheck("plan " + root + " is committed but not authorized by the principal", ex.recheck(handle(handlePcactn("g1", map("root", root)))));
        // not a registered plan, or no usable root: nothing to check
        assertRecheck(null, ex.recheck(handle(handlePcactn("g1", map("root", "unknown-root")))));
        assertRecheck(null, ex.recheck(handle(handlePcactn("g1", map("root", IntentJs.ofLong(1))))));
        assertRecheck(null, ex.recheck(handle(handlePcactn("g1", "not an object"))));
        assertRecheck(null, executor((p, g) -> false, null, null, now).recheck(handle(handlePcactn("g1", map("root", root)))));

        assertTrue(reg.authorize("g1", root, "alice", now + 100).ok);
        assertRecheck(null, ex.recheck(handle(handlePcactn("g1", map("root", root)))));
        assertRecheck(null, ex.recheck(handle(handlePcactn("g1", map("root", root, "node_id", "n1")))));
        assertRecheck(null, ex.recheck(handle(handlePcactn("g1", map("root", root, "node_id", IntentJs.ofLong(1))))));
        assertRecheck("plan " + root + " has no node 'nX'", ex.recheck(handle(handlePcactn("g1", map("root", root, "node_id", "nX")))));
        // the approval is judged at the executor's clock
        assertRecheck("plan " + root + ": the principal's approval expired at " + (now + 100),
            executor((p, g) -> false, reg, null, now + 100).recheck(handle(handlePcactn("g1", map("root", root)))));
        // a revoked grant is refused before the plan is looked at
        assertRecheck("the grant has been revoked", executor((p, g) -> true, reg, null, now).recheck(handle(handlePcactn("g1", map("root", root)))));
    }

    @Test void theExecutorOptionsCarryEverySetting() throws Exception {
        assertEquals("createExecutor: authorize options, audience and resolveGrant are required",
            assertThrows(IllegalArgumentException.class, () -> Operations.createExecutor(null)).getMessage());
        Authorize.Options az = new Authorize.Options(new MemoryStateStore(), (p, g) -> false, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO);
        Function<String, Map<String, Object>> rg = ref -> null;
        for (Operations.ExecutorOptions bad : new Operations.ExecutorOptions[] {
            new Operations.ExecutorOptions().audience("a").resolveGrant(rg),
            new Operations.ExecutorOptions().authorize(az).resolveGrant(rg),
            new Operations.ExecutorOptions().authorize(az).audience("").resolveGrant(rg),
            new Operations.ExecutorOptions().authorize(az).audience("a"),
        }) assertThrows(IllegalArgumentException.class, () -> Operations.createExecutor(bad));

        MemoryOperationStore records = new MemoryOperationStore();
        LongSupplier clock = () -> T0;
        Operations.Executor plain = Operations.createExecutor(new Operations.ExecutorOptions().operations(records).authorize(az).audience("a").resolveGrant(rg).now(clock));
        Authorize.Operation op = Authorize.Operation.of("v", "/r", new LinkedHashMap<>());
        Operations.ExecuteOptions eo = plain.executeOptions(op);
        assertSame(records, eo.store);
        assertSame(op, eo.operation);
        assertSame(clock, eo.now);
        assertNull(eo.recheckFor);
        assertNull(eo.reversibilityClass);
        assertEquals(300_000.0, eo.pendingTimeoutMs);
        assertRecheck("the grant is no longer known", eo.recheck.check(handle(handlePcactn("g1", null))));

        Operations.Executor tuned = Operations.createExecutor(new Operations.ExecutorOptions().operations(records).authorize(az).audience("a").resolveGrant(rg)
            .recheckFor("always").pendingTimeoutMs(7).reversibilityClassOf(o -> o.verb + "!").now(clock));
        Operations.ExecuteOptions t = tuned.executeOptions(op);
        assertEquals("always", t.recheckFor);
        assertEquals(7.0, t.pendingTimeoutMs);
        assertEquals("v!", t.reversibilityClass);
        assertNull(tuned.executeOptions(null).reversibilityClass, "no operation: the catalog is not asked");

        // the default clock is the wall clock
        Operations.Executor wall = Operations.createExecutor(new Operations.ExecutorOptions().operations(records).authorize(az).audience("a").resolveGrant(rg));
        long before = System.currentTimeMillis();
        long got = wall.executeOptions(op).now.getAsLong();
        assertTrue(got >= before && got <= System.currentTimeMillis());
        assertEquals("denied", wall.execute(null, op, NEVER).status);
    }

    @Test void theReplayAnswer() {
        MemoryOperationStore st = new MemoryOperationStore();
        Map<String, Object> p = map("grant_ref", "g1", "counter", IntentJs.ofLong(1));
        String id = Pca.hashCanonical(p);
        Map<String, Object> params = map("n", (short) 5);
        String digest = Pca.paramsDigest(Authorize.copyParams(params));
        seed(st, "id", id, "state", "committed", "verb", "v", "resource", "/r", "params_digest", digest, "result", "R", "startedAt", IntentJs.ofLong(T0));
        Authorize.Operation op = Authorize.Operation.of("v", "/r", params);
        Operations.ExecuteOutcome a = Operations.answerReplay(st, p, op, T0, TO);
        assertOutcome(map("status", "committed", "operationId", id, "result", "R", "replayed", true, "recorded", true), a);
        assertEquals("committed", Operations.answerReplay(st, Json.canonicalize(p), op, T0, TO).status, "the PCActn as JSON text");

        assertNull(Operations.answerReplay(st, null, op, T0, TO));
        assertNull(Operations.answerReplay(st, "not json", op, T0, TO));
        assertNull(Operations.answerReplay(st, p, null, T0, TO));
        assertNull(Operations.answerReplay(st, p, Authorize.Operation.of("w", "/r", params), T0, TO));
        assertNull(Operations.answerReplay(st, p, Authorize.Operation.of("v", "/s", params), T0, TO));
        assertNull(Operations.answerReplay(st, p, Authorize.Operation.of("v", "/r", map("n", (short) 6)), T0, TO));
        assertNull(Operations.answerReplay(st, p, Authorize.Operation.of("v", "/r", map("n", new Object())), T0, TO), "unhashable params");
        assertNull(Operations.answerReplay(st, map("grant_ref", "g2"), op, T0, TO), "no record");
        OperationStore broken = new OperationStore() {
            @Override public OperationRecord create(OperationRecord r) { throw new IllegalStateException(); }
            @Override public OperationRecord get(String i) { throw new IllegalStateException("down"); }
            @Override public boolean transition(String i, String f, OperationRecord n) { throw new IllegalStateException(); }
        };
        assertNull(Operations.answerReplay(broken, p, op, T0, TO));

        // null params hash as the empty object; an open record is settled at the given time
        MemoryOperationStore st2 = new MemoryOperationStore();
        seed(st2, "id", id, "state", "pending", "verb", "v", "resource", "/r", "params_digest", PD, "startedAt", IntentJs.ofLong(T0));
        Authorize.Operation noParams = new Authorize.Operation("v", "/r", null);
        assertEquals("pending", Operations.answerReplay(st2, p, noParams, T0 + 1000, TO).status);
        assertEquals("aborted", Operations.answerReplay(st2, p, noParams, T0 + 1001, TO).status);
    }

    @Test void theExecutorEndToEnd() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Map<String, Object> grant = AuthorizeFixtures.grant(c);
        Object pcactn = AuthorizeFixtures.pcactn(c, 0);
        Authorize.Operation fixtureOp = AuthorizeFixtures.operation(c, 0);
        long now = AuthorizeFixtures.now();
        MemoryOperationStore records = new MemoryOperationStore();
        boolean[] revoked = {false};
        Operations.Executor ex = Operations.createExecutor(new Operations.ExecutorOptions().operations(records)
            .authorize(new Authorize.Options(new MemoryStateStore(), (p, g) -> revoked[0], Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO).withProvenance(ProvHarness.options()))
            .audience(AuthorizeFixtures.audience()).resolveGrant(ref -> grant).now(() -> now));
        assertEquals("committed", ex.execute(pcactn, fixtureOp, h -> "done").status);
        // a replay that is also revoked now is a denial, never the record
        revoked[0] = true;
        assertEquals("denied", ex.execute(pcactn, fixtureOp, NEVER).status);

        // a fresh replay store, the grant revoked: the only failure is revocation, so the record does not answer
        Operations.Executor fresh = Operations.createExecutor(new Operations.ExecutorOptions().operations(records)
            .authorize(new Authorize.Options(new MemoryStateStore(), (p, g) -> true, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO).withProvenance(ProvHarness.options()))
            .audience(AuthorizeFixtures.audience()).resolveGrant(ref -> grant).now(() -> now));
        Operations.ExecuteOutcome d = fresh.execute(pcactn, fixtureOp, NEVER);
        assertEquals("denied", d.status);
        assertEquals(List.of("revocation"), d.authorization.failed());

        // the params change after the decision (a callback mutates the handler's map): the execution is refused
        Map<String, Object> params = new LinkedHashMap<>(AuthorizeFixtures.params(c, 0));
        Authorize.Operation op = Authorize.Operation.of(fixtureOp.verb, fixtureOp.resource, params);
        Operations.Executor toctou = Operations.createExecutor(new Operations.ExecutorOptions().operations(new MemoryOperationStore())
            .authorize(new Authorize.Options(new MemoryStateStore(), (p, g) -> { params.put("injected", "x"); return false; }, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO).withProvenance(ProvHarness.options()))
            .audience(AuthorizeFixtures.audience()).resolveGrant(ref -> grant).now(() -> now));
        assertEquals("executeAuthorized: the authorization is not for this operation (verb, resource or params differ)", toctou.execute(pcactn, op, NEVER).reason);
    }
}
