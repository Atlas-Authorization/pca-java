package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.IntFunction;
import java.util.function.Supplier;

/**
 * A reusable conformance helper for the stores behind {@code authorize}: run the replay / counter and operation-record
 * contracts against YOUR store. Pass a factory that opens a handle on the backend (one handle is one verifier instance's
 * connection to the shared backend) and read the report.
 *
 * <pre>{@code
 * StoreConformance.Report report = StoreConformance.runStateStoreConformance(() -> new MyStateStore(dsn), new StoreConformance.Options());
 * assert report.ok() : report.render();
 * }</pre>
 *
 * <p>The state-store profile runs the store's {@code claim(key, counter)} as the replay invariant "a counter goes from
 * unconsumed to consumed at most once, however many copies arrive":
 * <ul>
 *   <li>{@code claim-sequence}: strict increase on one key; replays and older counters refused (with {@code lastCounter}); keys independent;</li>
 *   <li>{@code claim-burst}: N threads race one (key, counter) on ONE handle, every round, then the next counter: exactly one wins;</li>
 *   <li>{@code claim-concurrent}: the same race spread over K handles (a store only an in-process lock can serialise fails here);</li>
 *   <li>{@code claim-durability}: a claim survives closing every handle and {@link Options#restart};</li>
 *   <li>{@code crash-after-claim}: the instance dies after the admission ({@link Options#crash}): the same counter stays consumed and the next one is admitted.</li>
 * </ul>
 *
 * <p>The operation-store profile checks {@code create} (atomic create-if-absent), {@code transition} (a compare-and-set on the
 * state), {@code get} and durability. A declared {@code durable(false)} / {@code shared(false)} (a process-local store) skips
 * the tests that need them; everything else is a failure, never a skip. Tests run with real threads on this machine's
 * scheduler: a racy store is caught with overwhelming probability per round, so run it more than once for a store you wrote.
 * A handle that implements {@link AutoCloseable} is closed by the durability tests.
 */
public final class StoreConformance {
    private StoreConformance() {}

    /** One test's outcome: {@code status} is {@code pass}, {@code fail} or {@code skip}. */
    public static final class TestResult {
        public final String test;
        public final String status;
        public final String note;

        TestResult(String test, String status, String note) { this.test = test; this.status = status; this.note = note; }

        @Override public String toString() { return status + " " + test + (note.isEmpty() ? "" : ": " + note); }
    }

    /** The result of a profile. */
    public static final class Report {
        public final String name;
        public final List<TestResult> results = new ArrayList<>();

        Report(String name) { this.name = name; }

        /** True when nothing failed and at least one test passed. */
        public boolean ok() {
            boolean pass = false;
            for (TestResult r : results) {
                if (r.status.equals("fail")) return false;
                if (r.status.equals("pass")) pass = true;
            }
            return pass;
        }

        public List<TestResult> failures() {
            List<TestResult> out = new ArrayList<>();
            for (TestResult r : results) if (r.status.equals("fail")) out.add(r);
            return out;
        }

        public String render() {
            StringBuilder b = new StringBuilder();
            for (TestResult r : results) b.append(r).append('\n');
            return b.toString();
        }
    }

    /** What the store under test is and how to disturb it. */
    public static final class Options {
        boolean durable = true, shared = true;
        Runnable crash, restart, teardown;
        int threads = 16, rounds = 5, handles = 4;
        String name;

        /** False: the store is process-local and its state dies with the process (the durability tests are skipped). */
        public Options durable(boolean durable) { this.durable = durable; return this; }
        /** False: handles do not share a backend (the cross-handle tests are skipped). */
        public Options shared(boolean shared) { this.shared = shared; return this; }
        /** Kill the backend or instance abruptly (optional). */
        public Options crash(Runnable crash) { this.crash = crash; return this; }
        /** Bring the backend back after a crash or after every handle was closed (optional). */
        public Options restart(Runnable restart) { this.restart = restart; return this; }
        /** Runs last (optional). */
        public Options teardown(Runnable teardown) { this.teardown = teardown; return this; }
        public Options threads(int threads) { this.threads = threads; return this; }
        public Options rounds(int rounds) { this.rounds = rounds; return this; }
        public Options handles(int handles) { this.handles = handles; return this; }
        public Options name(String name) { this.name = name; return this; }
    }

    private static final class Skip extends RuntimeException {
        private static final long serialVersionUID = 1L;
        Skip(String why) { super(why); }
    }

    @FunctionalInterface
    private interface Step {
        /** Returns a note (or null); throws {@link AssertionError} to fail. */
        String run() throws Exception;
    }

    private static void check(boolean cond, String message) {
        if (!cond) throw new AssertionError(message);
    }

    /** Run {@code fn(i)} in {@code n} threads released together; the results in order (an exception is returned as a value). */
    private static Object[] race(int n, IntFunction<Object> fn) throws InterruptedException {
        CyclicBarrier gate = new CyclicBarrier(n);
        Object[] out = new Object[n];
        List<Thread> ts = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            final int idx = i;
            Thread t = new Thread(() -> {
                try {
                    gate.await(60, TimeUnit.SECONDS);
                    out[idx] = fn.apply(idx);
                } catch (BrokenBarrierException | TimeoutException e) {
                    out[idx] = e;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    out[idx] = e;
                } catch (Throwable e) { // a store that raises under load is reported, not hidden
                    out[idx] = e;
                }
            });
            ts.add(t);
            t.start();
        }
        for (Thread t : ts) t.join();
        return out;
    }

    private static void noErrors(Object[] rs) {
        int errs = 0;
        Object first = null;
        for (Object r : rs) if (r instanceof Throwable) { errs++; if (first == null) first = r; }
        check(errs == 0, errs + " of " + rs.length + " concurrent calls raised: " + first);
    }

    private static void close(Object h) {
        if (h instanceof AutoCloseable) {
            try {
                ((AutoCloseable) h).close();
            } catch (Exception e) {
                // closing is best effort
            }
        }
    }

    private static void run(Report report, String name, Step step) {
        try {
            String note = step.run();
            report.results.add(new TestResult(name, "pass", note == null ? "" : note));
        } catch (Skip s) {
            report.results.add(new TestResult(name, "skip", s.getMessage()));
        } catch (AssertionError e) {
            report.results.add(new TestResult(name, "fail", String.valueOf(e.getMessage())));
        } catch (Exception e) {
            report.results.add(new TestResult(name, "fail", e.getClass().getSimpleName() + ": " + e.getMessage()));
        }
    }

    private static String runId() { return UUID.randomUUID().toString().replace("-", "").substring(0, 12); }

    // ---- replay / counter store -------------------------------------------------------------------------------------

    private static boolean claimed(StateStore.ClaimResult r) { return r != null && r.ok; }

    /** Run the replay-store contract (see the class doc). {@code open} returns a handle with {@code claim(key, counter)}. */
    public static Report runStateStoreConformance(Supplier<StateStore> open, Options options) {
        Options o = options == null ? new Options() : options;
        Report report = new Report(o.name != null ? o.name : "state store");
        String id = runId();
        List<Object> opened = new ArrayList<>();
        Supplier<StateStore> handle = () -> {
            StateStore h = open.get();
            check(h != null, "the factory returned no store");
            opened.add(h);
            return h;
        };
        try {
            run(report, "claim-sequence", () -> {
                StateStore s = handle.get();
                String k = "seq:" + id, other = "seq-other:" + id;
                check(claimed(s.claim(k, 1)), "first claim of counter 1 refused");
                StateStore.ClaimResult r = s.claim(k, 1);
                check(!claimed(r), "counter 1 claimed twice");
                check(r != null && r.lastCounter != null && r.lastCounter == 1L, "a refused claim must report lastCounter=1, got " + r);
                check(claimed(s.claim(k, 5)), "a larger counter (a gap) must be admitted");
                check(!claimed(s.claim(k, 3)), "an older counter was admitted after 5");
                check(!claimed(s.claim(k, 5)), "counter 5 claimed twice");
                check(claimed(s.claim(other, 1)), "another key must be independent");
                return null;
            });
            run(report, "claim-burst", () -> {
                StateStore s = handle.get();
                String k = "burst:" + id;
                for (int c = 1; c <= o.rounds; c++) {
                    final long counter = c;
                    Object[] rs = race(o.threads, i -> s.claim(k, counter));
                    noErrors(rs);
                    int wins = 0;
                    for (Object r : rs) if (claimed((StateStore.ClaimResult) r)) wins++;
                    check(wins == 1, "round " + c + ": " + wins + " of " + o.threads + " concurrent claims of counter " + c + " were admitted (want exactly 1)");
                }
                return o.rounds + " rounds x " + o.threads + " threads";
            });
            run(report, "claim-concurrent", () -> {
                if (!o.shared) throw new Skip("the adapter declares shared(false) (a process-local store)");
                List<StateStore> hs = new ArrayList<>();
                for (int i = 0; i < o.handles; i++) hs.add(handle.get());
                String k = "conc:" + id;
                for (int c = 1; c <= o.rounds; c++) {
                    final long counter = c;
                    Object[] rs = race(o.threads, i -> hs.get(i % o.handles).claim(k, counter));
                    noErrors(rs);
                    int wins = 0;
                    for (Object r : rs) if (claimed((StateStore.ClaimResult) r)) wins++;
                    check(wins == 1, "round " + c + ": " + wins + " of " + o.threads + " claims over " + o.handles + " handles were admitted (want exactly 1)");
                }
                return o.rounds + " rounds x " + o.threads + " threads over " + o.handles + " handles";
            });
            run(report, "claim-durability", () -> {
                if (!o.durable) throw new Skip("the adapter declares durable(false) (state dies with the process)");
                String k = "dur:" + id;
                check(claimed(handle.get().claim(k, 7)), "claim refused");
                for (Object h : new ArrayList<>(opened)) close(h);
                if (o.restart != null) o.restart.run();
                check(!claimed(handle.get().claim(k, 7)), "counter 7 was admitted again after the handles were closed (the claim was not durable)");
                check(claimed(handle.get().claim(k, 8)), "the next counter must be admitted after a restart");
                return null;
            });
            run(report, "crash-after-claim", () -> {
                if (!o.durable) throw new Skip("the adapter declares durable(false) (state dies with the process)");
                String k = "crash:" + id;
                StateStore first = handle.get();
                check(claimed(first.claim(k, 1)), "claim refused");
                // the instance dies right after the admission, before its handler ran: no close, no cleanup
                if (o.crash != null) o.crash.run();
                if (o.restart != null) o.restart.run();
                StateStore again = handle.get();
                check(!claimed(again.claim(k, 1)), "the proof admitted before the crash was admitted again");
                check(claimed(again.claim(k, 2)), "the next counter must be admitted after the crash");
                return null;
            });
        } finally {
            for (Object h : opened) close(h);
            if (o.teardown != null) o.teardown.run();
        }
        return report;
    }

    // ---- operation-record store -------------------------------------------------------------------------------------

    private static OperationRecord record(String id) { return OperationRecord.pending(id, "v", "/r", "d", "reversible", 1L); }

    private static OperationRecord executing(String id, long at) { return record(id).moved(OperationRecord.EXECUTING, at, null, null); }

    /**
     * Run the operation-store contract: {@code create(record)} returns null or the existing record, {@code get(id)},
     * {@code transition(id, from, next)} (see {@link OperationStore}).
     */
    public static Report runOperationStoreConformance(Supplier<OperationStore> open, Options options) {
        Options o = options == null ? new Options() : options;
        Report report = new Report(o.name != null ? o.name : "operation store");
        String id = runId();
        List<Object> opened = new ArrayList<>();
        Supplier<OperationStore> handle = () -> {
            OperationStore h = open.get();
            check(h != null, "the factory returned no store");
            opened.add(h);
            return h;
        };
        try {
            run(report, "semantics", () -> {
                OperationStore s = handle.get();
                String i = "op-sem:" + id;
                check(s.get(i) == null, "get of an unknown id must be null");
                check(s.create(record(i)) == null, "create of a new id must return null");
                OperationRecord again = s.create(record(i).with("verb", "other"));
                check(again != null && "v".equals(again.verb()), "create of an existing id must return the existing record unchanged");
                check(!s.transition("nope:" + id, "pending", record("nope")), "transition of an unknown id must be false");
                check(!s.transition(i, "executing", executing(i, 2)), "transition from the wrong state must be false");
                check("pending".equals(s.get(i).state()), "a refused transition changed the record");
                check(s.transition(i, "pending", executing(i, 2)), "transition pending -> executing refused");
                check("executing".equals(s.get(i).state()) && Long.valueOf(2).equals(s.get(i).executingAt()), "the transition was not stored");
                check(!s.transition(i, "pending", record(i).moved("aborted", null, 3L, "x")), "the old state must no longer match");
                return null;
            });
            run(report, "create-race", () -> {
                OperationStore s = handle.get();
                for (int r = 0; r < o.rounds; r++) {
                    final String i = "op-create:" + id + ":" + r;
                    Object[] rs = race(o.threads, n -> s.create(record(i)) == null ? Boolean.TRUE : Boolean.FALSE);
                    noErrors(rs);
                    int wins = 0;
                    for (Object x : rs) if (Boolean.TRUE.equals(x)) wins++;
                    check(wins == 1, "round " + r + ": " + wins + " of " + o.threads + " concurrent creates reported 'created' (want exactly 1)");
                }
                return o.rounds + " rounds x " + o.threads + " threads";
            });
            run(report, "transition-race", () -> {
                OperationStore s = handle.get();
                for (int r = 0; r < o.rounds; r++) {
                    final String i = "op-cas:" + id + ":" + r;
                    s.create(record(i));
                    Object[] rs = race(o.threads, n -> s.transition(i, "pending", executing(i, n)) ? Boolean.TRUE : Boolean.FALSE);
                    noErrors(rs);
                    int wins = 0;
                    for (Object x : rs) if (Boolean.TRUE.equals(x)) wins++;
                    check(wins == 1, "round " + r + ": " + wins + " of " + o.threads + " concurrent pending -> executing transitions succeeded (want exactly 1)");
                }
                return o.rounds + " rounds x " + o.threads + " threads";
            });
            run(report, "cross-handle", () -> {
                if (!o.shared) throw new Skip("the adapter declares shared(false) (a process-local store)");
                List<OperationStore> hs = new ArrayList<>();
                for (int n = 0; n < o.handles; n++) hs.add(handle.get());
                final String i = "op-shared:" + id;
                Object[] rs = race(o.threads, n -> hs.get(n % o.handles).create(record(i)) == null ? Boolean.TRUE : Boolean.FALSE);
                noErrors(rs);
                int created = 0;
                for (Object x : rs) if (Boolean.TRUE.equals(x)) created++;
                check(created == 1, "creates over " + o.handles + " handles: not exactly one 'created'");
                rs = race(o.threads, n -> hs.get(n % o.handles).transition(i, "pending", executing(i, n)) ? Boolean.TRUE : Boolean.FALSE);
                noErrors(rs);
                int won = 0;
                for (Object x : rs) if (Boolean.TRUE.equals(x)) won++;
                check(won == 1, "transitions over " + o.handles + " handles: not exactly one success");
                return "over " + o.handles + " handles";
            });
            run(report, "durability", () -> {
                if (!o.durable) throw new Skip("the adapter declares durable(false) (state dies with the process)");
                final String i = "op-dur:" + id;
                OperationStore h = handle.get();
                h.create(record(i));
                h.transition(i, "pending", executing(i, 3));
                for (Object x : new ArrayList<>(opened)) close(x);
                if (o.restart != null) o.restart.run();
                OperationRecord got = handle.get().get(i);
                check(got != null && "executing".equals(got.state()) && Long.valueOf(3).equals(got.executingAt()), "the record did not survive closing every handle");
                return null;
            });
        } finally {
            for (Object h : opened) close(h);
            if (o.teardown != null) o.teardown.run();
        }
        return report;
    }
}
