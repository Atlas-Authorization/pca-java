package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.LongSupplier;

/**
 * Operation records (T3): execute an authorized operation at most once, with a durable record of what happened.
 *
 * <p>{@link Authorize#authorize} decides and consumes the PCActn's replay counter. Between that decision and the end of the
 * side effect the process can crash, the client can time out and retry, or two workers can pick up the same authorization.
 * This class closes that gap with a record per operation id ({@code AuthorizedOperation.id}, the digest of the presented
 * PCActn):
 * <ol>
 *   <li>{@link #executeAuthorized} creates the record in state {@code pending} BEFORE anything runs (one atomic
 *       create-if-absent: of N concurrent executions of one authorization exactly one gets to run the function);</li>
 *   <li>for an irreversible operation it re-checks revocation, expiry and approval immediately before the function
 *       ({@link Recheck}; required, fail closed); a failed re-check records {@code aborted} and the function never runs;</li>
 *   <li>it moves the record to {@code executing} and only then calls the function, with the operation id as the idempotency
 *       key for the downstream call;</li>
 *   <li>the record becomes {@code committed} (with the function's result) or {@code failed} (with its error) afterwards.</li>
 * </ol>
 *
 * <p>A second execution of the same id never runs the function again: it is answered from the record. Nothing is re-run after
 * a crash either. Once the pending timeout has passed, a record still {@code pending} is settled as {@code aborted} (the side
 * effect never started: the agent may sign a fresh PCActn), and one still {@code executing} as {@code uncertain} (the side
 * effect may or may not have happened: an operator or a reconciliation job settles it with {@link #resolveCommitted} or
 * {@link #resolveFailed}, asking the downstream system by the idempotency key). {@link #createExecutor} combines
 * {@code authorize} and {@code executeAuthorized} so that a retry of the same PCActn (which {@code authorize} refuses as a
 * replay) is answered from the record instead of a bare replay denial.
 */
public final class Operations {
    private Operations() {}

    /** An open record older than this (ms) is settled by default: {@code pending} as {@code aborted}, {@code executing} as {@code uncertain}. */
    public static final long OPERATION_PENDING_TIMEOUT_MS = 5 * 60_000L;

    /** What the executed function receives. */
    public static final class ExecutionHandle {
        /** The operation id: pass it as the idempotency key of the downstream call (for example an {@code Idempotency-Key} header). */
        public final String idempotencyKey;
        public final Authorize.AuthorizedOperation operation;
        /** The presented PCActn. */
        public final Map<String, Object> pcactn;

        ExecutionHandle(String idempotencyKey, Authorize.AuthorizedOperation operation, Map<String, Object> pcactn) {
            this.idempotencyKey = idempotencyKey;
            this.operation = operation;
            this.pcactn = pcactn;
        }
    }

    /** The side effect. Its result should be a JSON value (Map, List, String, Boolean, number) so a durable store can keep it. */
    @FunctionalInterface
    public interface OperationFn {
        Object run(ExecutionHandle handle) throws Exception;
    }

    /** What a pre-execution re-check answered. */
    public static final class RecheckResult {
        public final boolean ok;
        public final String reason;

        private RecheckResult(boolean ok, String reason) { this.ok = ok; this.reason = reason; }

        public static RecheckResult ok() { return new RecheckResult(true, null); }
        public static RecheckResult refuse(String reason) { return new RecheckResult(false, reason); }
    }

    /** Re-check, immediately before the function, that the authorization still stands. A throw counts as a refusal. */
    @FunctionalInterface
    public interface Recheck {
        RecheckResult check(ExecutionHandle handle) throws Exception;
    }

    /** The options of {@link #executeAuthorized} (fluent). */
    public static final class ExecuteOptions {
        OperationStore store;
        Authorize.Operation operation;
        Recheck recheck;
        String recheckFor = "irreversible";
        String reversibilityClass;
        double pendingTimeoutMs = OPERATION_PENDING_TIMEOUT_MS;
        LongSupplier now = System::currentTimeMillis;

        /** REQUIRED: the operation record store (shared and durable in production). */
        public ExecuteOptions store(OperationStore store) { this.store = store; return this; }
        /**
         * The operation about to execute, as the handler will run it. When given, the authorization must be for exactly it
         * ({@link Authorize#isAuthorizedFor}), else the call is refused before anything is recorded.
         */
        public ExecuteOptions operation(Authorize.Operation operation) { this.operation = operation; return this; }
        /**
         * Re-check immediately before the function that the grant is not revoked and the approval (plan, step-up) has not
         * expired or been withdrawn. REQUIRED for an irreversible operation (fail closed). The PCActn's own {@code exp} is
         * always checked with it.
         */
        public ExecuteOptions recheck(Recheck recheck) { this.recheck = recheck; return this; }
        /** Which operations are re-checked: {@code "irreversible"} (default) or {@code "always"}. */
        public ExecuteOptions recheckFor(String recheckFor) { this.recheckFor = recheckFor; return this; }
        /** The server's authoritative reversibility class; the stricter of it and the signed class applies (missing = irreversible). */
        public ExecuteOptions reversibilityClass(String reversibilityClass) { this.reversibilityClass = reversibilityClass; return this; }
        /** An open record older than this (ms) is settled. Default 5 minutes. */
        public ExecuteOptions pendingTimeoutMs(double ms) { this.pendingTimeoutMs = ms; return this; }
        /** Clock (epoch ms). Default the wall clock. */
        public ExecuteOptions now(LongSupplier now) { this.now = now; return this; }
    }

    /** The outcome of an execution attempt. {@link #replayed} means it was answered from an existing record. */
    public static final class ExecuteOutcome {
        public static final String COMMITTED = "committed";
        public static final String FAILED = "failed";
        public static final String ABORTED = "aborted";
        /** Another execution of this id is in flight (or crashed less than the timeout ago). The function did not run here. */
        public static final String PENDING = "pending";
        /** The outcome of an earlier execution is unknown. The function did not run here. */
        public static final String UNCERTAIN = "uncertain";
        /** Not executed and nothing recorded: the authorization does not allow this operation, or the configuration is incomplete. */
        public static final String REFUSED = "refused";
        /** {@link Executor} only: the authorization was denied; {@link #authorization} says why. */
        public static final String DENIED = "denied";

        public final String status;
        public final String operationId;
        /** {@code committed}: the function's result. */
        public final Object result;
        private final boolean hasResult;
        /** {@code failed}: the error message. */
        public final String error;
        /** {@code aborted}, {@code uncertain}, {@code refused}, {@code denied}: why. */
        public final String reason;
        public final boolean replayed;
        /** {@code committed}: false when the function ran but the record could not be written (it stays executing, then uncertain). */
        public final boolean recorded;
        /** {@code denied}: the authorization result. */
        public final Authorize.AuthorizeResult authorization;

        ExecuteOutcome(String status, String operationId, Object result, boolean hasResult, String error, String reason, boolean replayed,
                       boolean recorded, Authorize.AuthorizeResult authorization) {
            this.status = status;
            this.operationId = operationId;
            this.result = result;
            this.hasResult = hasResult;
            this.error = error;
            this.reason = reason;
            this.replayed = replayed;
            this.recorded = recorded;
            this.authorization = authorization;
        }

        /** A refusal: nothing ran and nothing was recorded. */
        public static ExecuteOutcome refused(String reason) { return new ExecuteOutcome(REFUSED, null, null, false, null, reason, false, false, null); }
        static ExecuteOutcome denied(Authorize.AuthorizeResult r) { return new ExecuteOutcome(DENIED, null, null, false, null, r.reason, false, false, r); }

        /** The reference's JSON shape of the outcome (the members that are set). */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("status", status);
            if (operationId != null) m.put("operationId", operationId);
            if (COMMITTED.equals(status)) {
                if (hasResult) m.put("result", result);
                m.put("replayed", replayed);
                m.put("recorded", recorded);
            } else if (FAILED.equals(status)) {
                m.put("error", error);
                m.put("replayed", replayed);
            } else if (PENDING.equals(status)) {
                m.put("replayed", replayed);
            } else {
                m.put("reason", reason);
                if (ABORTED.equals(status) || UNCERTAIN.equals(status)) m.put("replayed", replayed);
            }
            return m;
        }

        @Override public String toString() { return "ExecuteOutcome" + toMap(); }
    }

    private static String message(Throwable e) { return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName(); }

    /** Settle an open record that is older than {@code timeoutMs}: {@code pending} -> {@code aborted}, {@code executing} -> {@code uncertain}. */
    private static OperationRecord settleStale(OperationStore store, OperationRecord rec, long now, double timeoutMs) {
        String state = rec.state();
        boolean executing = OperationRecord.EXECUTING.equals(state);
        if (!OperationRecord.PENDING.equals(state) && !executing) return rec;
        // executing is aged from the moment the function was started (a slow re-check does not count against it)
        long since = executing ? (rec.executingAt() != null ? rec.executingAt() : rec.startedAt()) : rec.startedAt();
        if (!((double) (now - since) > timeoutMs)) return rec;
        String t = RevocationStaleness.jsNum(timeoutMs);
        OperationRecord next = executing
            ? rec.moved(OperationRecord.UNCERTAIN, null, now, "no outcome recorded within " + t + " ms of the start: the side effect may or may not have happened")
            : rec.moved(OperationRecord.ABORTED, null, now, "not started within " + t + " ms of the claim: the side effect never ran");
        store.transition(rec.id(), state, next);
        // whatever is stored now (the original execution may have finished in between)
        OperationRecord cur = store.get(rec.id());
        return cur != null ? cur : next;
    }

    /** Answer an execution attempt from an existing record (never runs anything). */
    private static ExecuteOutcome fromRecord(OperationStore store, OperationRecord rec0, long now, double timeoutMs) {
        OperationRecord rec = settleStale(store, rec0, now, timeoutMs);
        String id = rec.id();
        switch (rec.state()) {
            case OperationRecord.COMMITTED:
                return new ExecuteOutcome(ExecuteOutcome.COMMITTED, id, rec.result(), rec.hasResult(), null, null, true, true, null);
            case OperationRecord.FAILED:
                return new ExecuteOutcome(ExecuteOutcome.FAILED, id, null, false, rec.error() != null ? rec.error() : "failed", null, true, false, null);
            case OperationRecord.ABORTED:
                return new ExecuteOutcome(ExecuteOutcome.ABORTED, id, null, false, null, rec.error() != null ? rec.error() : "aborted", true, false, null);
            case OperationRecord.UNCERTAIN:
                return new ExecuteOutcome(ExecuteOutcome.UNCERTAIN, id, null, false, null, rec.error() != null ? rec.error() : "outcome unknown", true, false, null);
            case OperationRecord.PENDING:
            case OperationRecord.EXECUTING:
                return new ExecuteOutcome(ExecuteOutcome.PENDING, id, null, false, null, null, true, false, null);
            default:
                return new ExecuteOutcome(ExecuteOutcome.UNCERTAIN, id, null, false, null, "unknown record state '" + rec.state() + "'", true, false, null);
        }
    }

    /** Leave {@code executing} (or {@code uncertain}, when recovery settled a slow execution) for the final state. */
    private static boolean finish(OperationStore store, OperationRecord rec, OperationRecord next) {
        if (store.transition(rec.id(), rec.state(), next)) return true;
        return OperationRecord.EXECUTING.equals(rec.state()) && store.transition(rec.id(), OperationRecord.UNCERTAIN, next);
    }

    /** Answer from the record as it is stored now (a concurrent recovery or execution changed it). */
    private static ExecuteOutcome answerCurrent(OperationStore store, String id, long now, double timeoutMs) {
        OperationRecord cur = store.get(id);
        return cur != null ? fromRecord(store, cur, now, timeoutMs)
            : new ExecuteOutcome(ExecuteOutcome.UNCERTAIN, id, null, false, null, "the operation record disappeared", true, false, null);
    }

    /**
     * Execute an allowed {@link Authorize#authorize} result at most once, with a durable record (see the class doc). The
     * function runs only if this call created the {@code pending} record and the re-check (when required) passed; every other
     * outcome is answered from the record. A throw from the function is recorded as {@code failed} and returned, not re-thrown
     * (an {@link Error} is not caught: the record stays {@code executing}, then {@code uncertain}). A store error is thrown.
     */
    public static ExecuteOutcome executeAuthorized(Authorize.AuthorizeResult authorization, OperationFn fn, ExecuteOptions opts) {
        OperationStore store = opts == null ? null : opts.store;
        if (store == null) return ExecuteOutcome.refused("executeAuthorized: missing required component: store (fail closed)");
        if (fn == null) return ExecuteOutcome.refused("executeAuthorized: missing required component: fn (fail closed)");
        if (authorization == null || !authorization.allow || authorization.verdict == null || !authorization.verdict.allow
                || authorization.pcactn == null || authorization.operation == null
                || authorization.operation.id == null || authorization.operation.id.isEmpty())
            return ExecuteOutcome.refused("executeAuthorized: the authorization did not allow an operation");
        if (opts.operation != null && !Authorize.isAuthorizedFor(authorization, opts.operation))
            return ExecuteOutcome.refused("executeAuthorized: the authorization is not for this operation (verb, resource or params differ)");
        LongSupplier clock = opts.now != null ? opts.now : System::currentTimeMillis;
        double timeoutMs = opts.pendingTimeoutMs;
        Map<String, Object> pcactn = authorization.pcactn;
        Authorize.AuthorizedOperation operation = authorization.operation;
        Object action = pcactn.get("action");
        String reversibility = RevocationStaleness.effectiveReversibility(opts.reversibilityClass,
            action instanceof Map ? ((Map<?, ?>) action).get("reversibility_class") : null);
        boolean mustRecheck = "irreversible".equals(reversibility) || "always".equals(opts.recheckFor);
        if (mustRecheck && opts.recheck == null)
            return ExecuteOutcome.refused("executeAuthorized: a " + reversibility + " operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)");

        ExecutionHandle handle = new ExecutionHandle(operation.id, operation, pcactn);
        OperationRecord rec = OperationRecord.pending(operation.id, operation.verb, operation.resource, operation.paramsDigest, reversibility, clock.getAsLong());
        OperationRecord existing = store.create(rec);
        if (existing != null) return fromRecord(store, existing, clock.getAsLong(), timeoutMs);

        if (mustRecheck) {
            RecheckResult rc;
            try {
                long t = clock.getAsLong();
                Double exp = IntentJs.num(pcactn.get("exp"));
                if (exp != null && !Double.isNaN(exp) && (double) t > exp) rc = RecheckResult.refuse("the PCActn expired at " + RevocationStaleness.jsNum(exp));
                else rc = opts.recheck.check(handle);
            } catch (Exception e) {
                rc = RecheckResult.refuse("recheck error (fail closed): " + message(e));
            }
            if (rc == null || !rc.ok) {
                String reason = "recheck: " + (rc != null && rc.reason != null && !rc.reason.isEmpty() ? rc.reason : "refused");
                if (finish(store, rec, rec.moved(OperationRecord.ABORTED, null, clock.getAsLong(), reason)))
                    return new ExecuteOutcome(ExecuteOutcome.ABORTED, rec.id(), null, false, null, reason, false, false, null);
                return answerCurrent(store, rec.id(), clock.getAsLong(), timeoutMs);
            }
        }

        // the marker that separates "never started" from "maybe happened"; a recovery that settled the claim meanwhile wins
        OperationRecord running = rec.moved(OperationRecord.EXECUTING, clock.getAsLong(), null, null);
        if (!store.transition(rec.id(), OperationRecord.PENDING, running)) return answerCurrent(store, rec.id(), clock.getAsLong(), timeoutMs);

        Object result;
        try {
            result = fn.run(handle);
        } catch (Exception e) {
            String error = message(e);
            try {
                finish(store, running, running.moved(OperationRecord.FAILED, null, clock.getAsLong(), error));
            } catch (RuntimeException ignored) {
                // the failure is still returned; the record stays executing and becomes uncertain
            }
            return new ExecuteOutcome(ExecuteOutcome.FAILED, rec.id(), null, false, error, null, false, false, null);
        }
        boolean recorded;
        try {
            recorded = finish(store, running, running.moved(OperationRecord.COMMITTED, null, clock.getAsLong(), null).with("result", result));
        } catch (RuntimeException e) {
            recorded = false;
        }
        return new ExecuteOutcome(ExecuteOutcome.COMMITTED, rec.id(), result, true, null, null, false, recorded, null);
    }

    /** {@link #executeAuthorized} for a guard result such as {@code PcaResult.authorization()}. */
    public static ExecuteOutcome executeAuthorized(Authorize.AuthorizeResult authorization, OperationFn fn, OperationStore store) {
        return executeAuthorized(authorization, fn, new ExecuteOptions().store(store));
    }

    /**
     * Settle every open record older than {@code olderThanMs} (run it at startup and periodically): {@code pending} ->
     * {@code aborted} (the side effect never started), {@code executing} -> {@code uncertain}. Returns the records it settled.
     * Needs {@link OperationStore#supportsListOpen}. Nothing is re-run: reconcile each {@code uncertain} one with
     * {@link #resolveCommitted} or {@link #resolveFailed}.
     */
    public static List<OperationRecord> recoverOperations(OperationStore store, double olderThanMs, LongSupplier now) {
        if (store == null || !store.supportsListOpen())
            throw new UnsupportedOperationException("recoverOperations: the store has no listOpen (recover by id with recoverOperation)");
        List<OperationRecord> out = new ArrayList<>();
        for (OperationRecord r : store.listOpen()) {
            OperationRecord u = recoverOperation(store, r.id(), olderThanMs, now);
            if (u != null && !u.state().equals(r.state())) out.add(u);
        }
        return out;
    }

    /** {@link #recoverOperations} with the default timeout and the wall clock. */
    public static List<OperationRecord> recoverOperations(OperationStore store) {
        return recoverOperations(store, OPERATION_PENDING_TIMEOUT_MS, null);
    }

    /** {@link #recoverOperations} for one id. Returns the record as it now stands (null: no record, the operation never started). */
    public static OperationRecord recoverOperation(OperationStore store, String id, double olderThanMs, LongSupplier now) {
        OperationRecord r = store.get(id);
        if (r == null) return null;
        LongSupplier clock = now != null ? now : System::currentTimeMillis;
        return settleStale(store, r, clock.getAsLong(), olderThanMs);
    }

    /** {@link #recoverOperation} with the default timeout and the wall clock. */
    public static OperationRecord recoverOperation(OperationStore store, String id) {
        return recoverOperation(store, id, OPERATION_PENDING_TIMEOUT_MS, null);
    }

    private static boolean resolve(OperationStore store, String id, boolean committed, boolean hasResult, Object result, String error, LongSupplier now) {
        OperationRecord r = store.get(id);
        if (r == null || !OperationRecord.UNCERTAIN.equals(r.state())) return false;
        LongSupplier clock = now != null ? now : System::currentTimeMillis;
        long t = clock.getAsLong();
        OperationRecord next = committed
            ? (hasResult ? r.moved(OperationRecord.COMMITTED, null, t, null).with("result", result) : r.moved(OperationRecord.COMMITTED, null, t, null))
            : r.moved(OperationRecord.FAILED, null, t, error == null ? "" : error);
        return store.transition(id, OperationRecord.UNCERTAIN, next);
    }

    /**
     * Settle an {@code uncertain} record after reconciling with the downstream system (look the idempotency key up there):
     * {@code committed} with the result it reports. Returns false if the record is not {@code uncertain}.
     */
    public static boolean resolveCommitted(OperationStore store, String id, Object result, LongSupplier now) {
        return resolve(store, id, true, true, result, null, now);
    }

    /** {@link #resolveCommitted} without a result. */
    public static boolean resolveCommitted(OperationStore store, String id, LongSupplier now) {
        return resolve(store, id, true, false, null, null, now);
    }

    /** Settle an {@code uncertain} record as {@code failed} (the downstream never applied it). Returns false if it is not {@code uncertain}. */
    public static boolean resolveFailed(OperationStore store, String id, String error, LongSupplier now) {
        return resolve(store, id, false, false, null, error, now);
    }

    // ---- the executor -----------------------------------------------------------------------------------------------

    /** The options of {@link #createExecutor}: the {@code authorize} options of the guard plus the operation store and the re-check policy. */
    public static final class ExecutorOptions {
        OperationStore operations;
        Authorize.Options authorize;
        String audience;
        Function<String, Map<String, Object>> resolveGrant;
        Recheck recheck;
        String recheckFor = "irreversible";
        Function<Authorize.Operation, String> reversibilityClassOf;
        double pendingTimeoutMs = OPERATION_PENDING_TIMEOUT_MS;
        LongSupplier now = System::currentTimeMillis;

        /** REQUIRED: the operation record store. */
        public ExecutorOptions operations(OperationStore operations) { this.operations = operations; return this; }
        /** REQUIRED: the authorize options (replay store, revocation check, plan registry, ...). */
        public ExecutorOptions authorize(Authorize.Options authorize) { this.authorize = authorize; return this; }
        /** REQUIRED: this resource server's id. */
        public ExecutorOptions audience(String audience) { this.audience = audience; return this; }
        /** REQUIRED: {@code grant_ref -> grant | null}. */
        public ExecutorOptions resolveGrant(Function<String, Map<String, Object>> resolveGrant) { this.resolveGrant = resolveGrant; return this; }
        /** Extra re-check before an irreversible operation (for example a step-up approval still stands); it adds to the built-in ones. */
        public ExecutorOptions recheck(Recheck recheck) { this.recheck = recheck; return this; }
        public ExecutorOptions recheckFor(String recheckFor) { this.recheckFor = recheckFor; return this; }
        /** The server's reversibility class for an operation (catalog). Absent: the signed class. */
        public ExecutorOptions reversibilityClassOf(Function<Authorize.Operation, String> f) { this.reversibilityClassOf = f; return this; }
        public ExecutorOptions pendingTimeoutMs(double ms) { this.pendingTimeoutMs = ms; return this; }
        public ExecutorOptions now(LongSupplier now) { this.now = now; return this; }
    }

    /**
     * {@code authorize} + {@code executeAuthorized} in one call, with retries answered from the record: a second presentation of
     * the same PCActn is refused by {@code authorize} as a replay, and if that replay is the ONLY failing check (the proof,
     * binding, policy and revocation all still pass now) and a record exists for its operation id and this operation, the
     * record's outcome is returned ({@code replayed}) instead of the denial. No record means the first attempt never reached
     * execution: the denial stands (the authorization was consumed; the agent signs a fresh PCActn).
     *
     * <p>The executor always re-runs {@code isRevoked} against the grant from {@code resolveGrant}, checks the PCActn's expiry
     * and, with a plan registry in the authorize options, that a registered plan is still executable.
     */
    public static final class Executor {
        private final ExecutorOptions o;

        private Executor(ExecutorOptions o) { this.o = o; }

        private RecheckResult recheck(ExecutionHandle h) throws Exception {
            Object gr = h.pcactn.get("grant_ref");
            Map<String, Object> grant = gr instanceof String ? o.resolveGrant.apply((String) gr) : null;
            if (grant == null) return RecheckResult.refuse("the grant is no longer known");
            Boolean revoked;
            try {
                revoked = o.authorize.isRevoked.isRevoked(h.pcactn, grant);
            } catch (RuntimeException e) {
                revoked = null;
            }
            if (!Boolean.FALSE.equals(revoked))
                return RecheckResult.refuse(Boolean.TRUE.equals(revoked) ? "the grant has been revoked" : "revocation could not be checked");
            // a registered plan must still be executable: not revoked, the principal's approval not expired
            Object pl = h.pcactn.get("plan");
            Object root = pl instanceof Map ? ((Map<?, ?>) pl).get("root") : null;
            PlanRegistry plans = o.authorize.plans;
            if (plans != null && root instanceof String && plans.get((String) gr, (String) root) != null) {
                Object nodeId = ((Map<?, ?>) pl).get("node_id");
                PlanRegistry.PlanStatus ps = plans.check((String) gr, (String) root, nodeId instanceof String ? (String) nodeId : null, null, o.now.getAsLong());
                if (!ps.executable) return RecheckResult.refuse(ps.reason != null ? ps.reason : "plan is " + ps.state);
            }
            return o.recheck != null ? o.recheck.check(h) : RecheckResult.ok();
        }

        /** Authorize {@code pcactn} (a parsed object, or its JSON text / UTF-8 bytes) for {@code operation} and execute {@code fn} at most once. */
        public ExecuteOutcome execute(Object pcactn, Authorize.Operation operation, OperationFn fn) {
            return execute(pcactn, operation, fn, null);
        }

        /** As above, with the principal's escalation answer for this request (null: none). */
        public ExecuteOutcome execute(Object pcactn, Authorize.Operation operation, OperationFn fn, Object escalationAnswer) {
            return execute(pcactn, operation, fn, escalationAnswer, null);
        }

        /**
         * As above, with the provenance bundle the agent presented for this call ({@code ArgProvenance.Presented.bundle}; null: the
         * authorize options' gate {@code bundle} function, else none, which escalates a sensitive action).
         */
        public ExecuteOutcome execute(Object pcactn, Authorize.Operation operation, OperationFn fn, Object escalationAnswer, ArgProvenance.Presented provenance) {
            if (o.operations == null) return ExecuteOutcome.refused("createExecutor: missing required component: operations (fail closed)");
            long now = o.now.getAsLong();
            Authorize.AuthorizeResult r = o.authorize.run(pcactn, operation, o.audience, o.resolveGrant, now, escalationAnswer, null, null, null, provenance);
            if (r.allow) {
                ExecuteOptions eo = new ExecuteOptions().store(o.operations).operation(operation).recheck(this::recheck)
                    .recheckFor(o.recheckFor).pendingTimeoutMs(o.pendingTimeoutMs).now(o.now);
                if (o.reversibilityClassOf != null && operation != null) eo.reversibilityClass(o.reversibilityClassOf.apply(operation));
                return executeAuthorized(r, fn, eo);
            }
            List<String> failed = r.failed();
            if (r.status != 403 || failed.size() != 1 || !"replay".equals(failed.get(0))) return ExecuteOutcome.denied(r);
            // a replay of a proof that is otherwise still valid now: answer from the record, if the first attempt made one
            Map<String, Object> p = Authorize.coerce(pcactn, new String[1]);
            if (p == null || operation == null) return ExecuteOutcome.denied(r);
            OperationRecord rec;
            String want;
            try {
                rec = o.operations.get(Pca.hashCanonical(p));
                want = Pca.paramsDigest(operation.params == null ? null : Authorize.copyParams(operation.params));
            } catch (RuntimeException e) {
                return ExecuteOutcome.denied(r);
            }
            if (rec == null || !operation.verb.equals(rec.verb()) || !operation.resource.equals(rec.resource()) || !want.equals(rec.paramsDigest()))
                return ExecuteOutcome.denied(r);
            return fromRecord(o.operations, rec, o.now.getAsLong(), o.pendingTimeoutMs);
        }
    }

    /** Build an {@link Executor}. A missing component other than the store is a configuration error and throws {@link IllegalArgumentException}. */
    public static Executor createExecutor(ExecutorOptions options) {
        if (options == null || options.authorize == null || options.audience == null || options.audience.isEmpty() || options.resolveGrant == null)
            throw new IllegalArgumentException("createExecutor: authorize options, audience and resolveGrant are required");
        return new Executor(options);
    }
}
