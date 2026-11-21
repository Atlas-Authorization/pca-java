package net.atlasauth.pca;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Semaphore;
import java.util.function.Function;
import net.atlasauth.pca.doctor.Js;
import net.atlasauth.pca.servlet.PcaCore;
import net.atlasauth.pca.servlet.PcaResult;

/**
 * The pca-state conformance profile: run your replay store behind the REAL request guard ({@link PcaCore#authorize}, the full authorize path) with real
 * signed PCActns, and check the replay-state invariant: one action id (grant, leaf holder, counter) goes from unconsumed to consumed at most once, however
 * many copies arrive, on however many instances or processes, across crashes after the claim and retries after a timeout.
 *
 * <pre>{@code
 * StoreConformance.Report r = PcaStateConformance.run(adapter, new PcaStateConformance.Options());
 * assertTrue(r.ok(), r.render());
 * }</pre>
 *
 * Checks: claim-* (the store's claim on its own, as {@link StoreConformance#runStateStoreConformance} runs them), one-instance (N concurrent copies of one
 * proof to one guard: exactly one admitted, every round), instances (the copies spread over K guards on separate handles, built multi-instance: a store only
 * an in-process lock can serialise is refused there and fails), processes (the same race across K child processes), crash-after-claim (admitted, then the
 * instance dies before its handler runs: the same proof is denied afterwards, the next counter admitted; with a worker the instance is a child process that is
 * killed right after the admission) and retry-after-timeout (the commit lands but its answer is lost: the guard fails closed and the retry is denied; and a
 * retry on another instance while the first commit is still in flight: exactly one admitted). A check the store declares it cannot meet is skipped, never
 * passed. The process checks need a worker: a main of yours that calls {@link #workerMain} with a way to open your store.
 */
public final class PcaStateConformance {
    private PcaStateConformance() {}

    /** The store under test: {@link #open} returns a NEW handle onto the SAME backend each call (one handle = one verifier instance's connection). */
    public interface Adapter {
        String name();
        StateStore open() throws Exception;
        /** State survives closing every handle (and {@link #restart}). False skips the durability and crash checks. */
        default boolean durable() { return false; }
        /** Several handles can share the backend. False skips the instance and process checks. */
        default boolean shared() { return false; }
        /** Crashes and restarts the backend; it runs between closing the handles and reopening. */
        default void restart() throws Exception {}
        default void teardown() throws Exception {}
    }

    /** How to start one worker process: the command that comes before the configuration text, and the options its {@code open} receives. */
    public static final class Worker {
        public final List<String> command;
        public final Map<String, String> options;
        public Worker(List<String> command, Map<String, String> options) { this.command = command; this.options = options; }
    }

    public static final class Options {
        public int rounds = 10, copies = 16, instances = 4, processes = 3;
        /** The process checks and the process half of crash-after-claim; without it they are skipped. */
        public Worker worker;
    }

    static final String AUD = "pca-state-conformance";
    private static final Authorize.Operation OPERATION = new Authorize.Operation("read", "doc:1", new LinkedHashMap<String, Object>());
    private static final SecureRandom RNG = new SecureRandom();

    private enum Outcome { ADMITTED, REPLAY, ERROR }

    private static Json.Num n(String raw) { return new Json.Num(raw); }

    /** Pre-signed PCActns (counters 1..n) from one agent under one grant, with the request headers and body each is sent with. */
    static final class Fixture {
        final Map<String, Object> grant, pin;
        final List<Map<String, String>> headers;
        final List<String> bodies;

        Fixture(Map<String, Object> grant, Map<String, Object> pin, List<Map<String, String>> headers, List<String> bodies) {
            this.grant = grant; this.pin = pin; this.headers = headers; this.bodies = bodies;
        }

        static Fixture make(int count) {
            Keys.SuiteKey principal = Keys.ed25519(Keys.edGenerate()), holder = Keys.ed25519(Keys.edGenerate());
            Map<String, Object> weights = Issue.obj("alpha", n("0"), "beta", n("0"), "gamma", n("0"), "delta", n("0"), "epsilon", n("0"), "zeta", n("0"));
            Map<String, Object> risk = Issue.obj("weights", weights, "theta1", n("0.5"), "theta2", n("0.8"), "kappa", n("1"), "lambda", n("0"), "rho", n("0"), "bMax", n("1000"));
            List<Object> predicates = new ArrayList<>();
            predicates.add(Issue.obj("verb", "read", "resource", "doc:*"));
            Map<String, Object> envelope = Issue.obj("predicates", predicates, "caveats", new ArrayList<Object>(), "agent_binding", new LinkedHashMap<String, Object>(), "risk_policy", risk);
            Map<String, Object> grant = Issue.mintGrant(principal, holder.ed.id(), null, envelope, "store conformance", null).grant;
            Map<String, Object> node = Issue.obj("id", "n1", "verb", "read", "resource", "doc:1", "params_digest", Pca.paramsDigest(new LinkedHashMap<String, Object>()),
                "reversibility_class", "irreversible");
            List<Map<String, Object>> nodes = new ArrayList<>();
            nodes.add(node);
            Issue.Plan plan = Issue.commitPlan(nodes);
            ArgProvenance.Recorder recorder = ArgProvenance.Recorder.create("pca-state-conformance", "k1");
            long now = System.currentTimeMillis();
            List<Map<String, String>> headers = new ArrayList<>();
            List<String> bodies = new ArrayList<>();
            for (int i = 1; i <= Math.max(1, count); i++) {
                Issue.ActSpec s = new Issue.ActSpec();
                s.grant = grant;
                List<Object> chain = new ArrayList<>();
                chain.add(grant);
                s.chain = chain;
                s.plan = plan;
                s.nodeId = "n1";
                s.params = new LinkedHashMap<>();
                s.counter = i;
                s.signer = holder;
                s.aud = AUD;
                s.iat = now;
                byte[] nonce = new byte[16];
                RNG.nextBytes(nonce);
                s.nonce = Keys.b64u(nonce);
                s.riskClaim = Issue.obj("r", n("0"), "inputs", new LinkedHashMap<String, Object>());
                Map<String, Object> pcactn = Issue.buildPCActn(s);
                Map<String, Object> bundle = ArgProvenance.principalDirect(recorder, OPERATION);
                headers.add(Issue.headers(pcactn, null, null, null, null, bundle));
                bodies.add(Json.canonicalize(Issue.obj("pca_provenance", bundle)));
            }
            return new Fixture(grant, recorder.pin(), headers, bodies);
        }

        Map<String, Object> json() {
            List<Object> hs = new ArrayList<>(), bs = new ArrayList<>();
            for (Map<String, String> h : headers) hs.add(new LinkedHashMap<String, Object>(h));
            bs.addAll(bodies);
            return Issue.obj("grant", grant, "pin", pin, "headers", hs, "bodies", bs);
        }

        @SuppressWarnings("unchecked")
        static Fixture from(Object v) {
            Map<String, Object> m = (Map<String, Object>) v;
            List<Map<String, String>> hs = new ArrayList<>();
            for (Object h : (List<Object>) m.get("headers")) {
                Map<String, String> one = new LinkedHashMap<>();
                for (Map.Entry<String, Object> e : ((Map<String, Object>) h).entrySet()) one.put(e.getKey(), (String) e.getValue());
                hs.add(one);
            }
            List<String> bs = new ArrayList<>();
            for (Object b : (List<Object>) m.get("bodies")) bs.add((String) b);
            return new Fixture((Map<String, Object>) m.get("grant"), (Map<String, Object>) m.get("pin"), hs, bs);
        }

        /** The guard under test: the real request guard, full authorize path, the store as the replay store. */
        Guard guardFor(StateStore store, boolean multiInstance) {
            Authorize.Options az = new Authorize.Options(store, (p, g) -> Boolean.FALSE, Authorize.SINGLE_STEP, null, null)
                .withProvenance(new ArgProvenance.Options().mediators(List.of(pin)))
                .withRisk((op, g, p) -> Issue.obj("semanticDistance", n("0"), "reversibility", n("1"), "blastRadius", n("0"), "taint", n("0"), "confidence", n("1"), "age", n("0")))
                .withMultiInstance(multiInstance); // refuses a process-scoped store when multiInstance
            return new Guard(this, az);
        }
    }

    static final class Guard {
        private final Fixture fx;
        private final Authorize.Options options;

        Guard(Fixture fx, Authorize.Options options) { this.fx = fx; this.options = options; }

        Outcome handle(int counter) {
            Map<String, String> h = fx.headers.get(counter - 1);
            PcaResult r = PcaCore.authorize(h.get(Agent.HEADER), fx.bodies.get(counter - 1).getBytes(StandardCharsets.UTF_8), AUD, System.currentTimeMillis(),
                ref -> ref != null && ref.equals(fx.grant.get("id")) ? fx.grant : null, options, OPERATION, null, null, null, null, null, null, h.get(ArgProvenance.HEADER));
            Authorize.AuthorizeResult a = r.authorization();
            if (a == null) return Outcome.ERROR;
            if (a.allow) return Outcome.ADMITTED;
            // a store that threw is a guard error (fail closed), not a replay, though this guard reports it on the replay check too
            if (a.reasons != null && a.reasons.contains("replay: the replay store failed (fail closed)")) return Outcome.ERROR;
            return "fail".equals(a.checks.get("replay")) ? Outcome.REPLAY : Outcome.ERROR;
        }
    }

    /** A store whose claim lands but whose answer is lost. */
    private static final class LossyStore implements StateStore {
        private final StateStore inner;
        LossyStore(StateStore inner) { this.inner = inner; }
        @Override public ClaimResult claim(String key, long counter) { inner.claim(key, counter); throw new IllegalStateException("the answer was lost (timeout)"); }
        @Override public ClaimResult claim(String key, long counter, Map<String, Object> before, Map<String, Object> after) { inner.claim(key, counter, before, after); throw new IllegalStateException("the answer was lost (timeout)"); }
        @Override public boolean holdsBudgets() { return inner.holdsBudgets(); }
        @Override public Map<String, Object> budget(String key) { return inner.budget(key); }
        @Override public boolean processScoped() { return inner.processScoped(); }
    }

    /** A store whose claim blocks until released, to hold a commit in flight. */
    private static final class GatedStore implements StateStore {
        private final StateStore inner;
        final Semaphore entered = new Semaphore(0), gate = new Semaphore(0);
        GatedStore(StateStore inner) { this.inner = inner; }
        private void hold() {
            entered.release();
            gate.acquireUninterruptibly();
        }
        @Override public ClaimResult claim(String key, long counter) { hold(); return inner.claim(key, counter); }
        @Override public ClaimResult claim(String key, long counter, Map<String, Object> before, Map<String, Object> after) { hold(); return inner.claim(key, counter, before, after); }
        @Override public boolean holdsBudgets() { return inner.holdsBudgets(); }
        @Override public Map<String, Object> budget(String key) { return inner.budget(key); }
        @Override public boolean processScoped() { return inner.processScoped(); }
    }

    private static void close(Object h) {
        if (h instanceof AutoCloseable) {
            try { ((AutoCloseable) h).close(); } catch (Exception e) { /* best effort */ }
        }
    }

    private static String err(Throwable e) { return e.getClass().getSimpleName() + ": " + e.getMessage(); }

    /** Runs every check. */
    public static StoreConformance.Report run(Adapter adapter, Options options) {
        Options o = options == null ? new Options() : options;
        StoreConformance.Report rep = new StoreConformance.Report(adapter.name());
        StoreConformance.Options base = new StoreConformance.Options().name(adapter.name()).durable(adapter.durable()).shared(adapter.shared())
            .threads(Math.max(1, o.copies)).rounds(Math.max(1, o.rounds)).handles(Math.max(1, o.instances)).restart(() -> {
                try { adapter.restart(); } catch (Exception e) { throw new IllegalStateException(e); }
            });
        StoreConformance.Report claims = StoreConformance.runStateStoreConformance(() -> {
            try { return adapter.open(); } catch (Exception e) { throw new IllegalStateException(e); }
        }, base);
        for (StoreConformance.TestResult t : claims.results) if (t.test.startsWith("claim-")) rep.results.add(t);
        int rounds = Math.max(1, o.rounds), copies = Math.max(1, o.copies);
        add(rep, "one-instance", raceCheck(adapter, 1, false, rounds, copies));
        if (adapter.shared()) add(rep, "instances", raceCheck(adapter, Math.max(1, o.instances), true, rounds, copies));
        else skip(rep, "instances", "shared is false (one instance only)");
        if (!adapter.shared()) skip(rep, "processes", "shared is false (one instance only)");
        else if (o.worker == null) skip(rep, "processes", "needs a worker command (the guards run in child processes)");
        else add(rep, "processes", processRace(o.worker, rounds, copies, Math.max(1, o.processes)));
        if (adapter.durable()) add(rep, "crash-after-claim", crashAfterClaim(adapter, o));
        else skip(rep, "crash-after-claim", "durable is false (state dies with the process)");
        add(rep, "retry-after-timeout", retryAfterTimeout(adapter));
        return rep;
    }

    private static void add(StoreConformance.Report rep, String name, String failure) {
        rep.results.add(new StoreConformance.TestResult(name, failure == null ? "pass" : "fail", failure == null ? "" : failure));
    }

    private static void skip(StoreConformance.Report rep, String name, String why) { rep.results.add(new StoreConformance.TestResult(name, "skip", why)); }

    private static int race(Fixture fx, List<Guard> guards, int counter, int copies) throws InterruptedException {
        Object[] rs = StoreConformance.race(new CyclicBarrier(copies), copies, i -> guards.get(i % guards.size()).handle(counter));
        int wins = 0;
        for (Object r : rs) if (r == Outcome.ADMITTED) wins++;
        return wins;
    }

    private static String raceCheck(Adapter adapter, int handles, boolean multiInstance, int rounds, int copies) {
        List<StateStore> hs = new ArrayList<>();
        try {
            for (int i = 0; i < handles; i++) hs.add(adapter.open());
            Fixture fx = Fixture.make(rounds);
            List<Guard> guards = new ArrayList<>();
            try {
                for (StateStore s : hs) guards.add(fx.guardFor(s, multiInstance));
            } catch (RuntimeException e) { return "refused in multi-instance mode: " + err(e); }
            for (int r = 1; r <= rounds; r++) {
                int wins = race(fx, guards, r, copies);
                if (wins != 1) return "round " + r + ": " + wins + " of " + copies + " copies of one proof were admitted (want exactly 1)";
            }
            return null;
        } catch (Exception e) { return err(e); }
        finally { for (StateStore s : hs) close(s); }
    }

    private static String crashAfterClaim(Adapter adapter, Options o) {
        List<StateStore> opened = new ArrayList<>();
        try {
            StateStore h1 = adapter.open();
            opened.add(h1);
            Fixture fx = Fixture.make(Math.max(4, o.rounds));
            // in process: admitted on handle 1, which is then abandoned (never closed); the backend restarts when it can
            Outcome first = fx.guardFor(h1, adapter.shared()).handle(1);
            adapter.restart();
            StateStore h2 = adapter.open();
            opened.add(h2);
            Guard g = fx.guardFor(h2, adapter.shared());
            Outcome again = g.handle(1), next = g.handle(2);
            if (first != Outcome.ADMITTED || again != Outcome.REPLAY || next != Outcome.ADMITTED)
                return "in process: admitted=" + first + ", same proof after the instance died=" + again + ", next counter=" + next;
            return o.worker != null ? processCrash(adapter, o.worker, fx) : null;
        } catch (Exception e) { return err(e); }
        finally { for (StateStore s : opened) close(s); }
    }

    private static String retryAfterTimeout(Adapter adapter) {
        List<StateStore> hs = new ArrayList<>();
        try {
            for (int i = 0; i < (adapter.shared() ? 2 : 1); i++) hs.add(adapter.open());
            Fixture fx = Fixture.make(4);
            StateStore other = hs.get(hs.size() - 1);
            // 1. the commit lands, its answer is lost: the guard fails closed, the retry (another instance when shared) is a replay
            Outcome first = fx.guardFor(new LossyStore(hs.get(0)), adapter.shared()).handle(1);
            Guard og = fx.guardFor(other, adapter.shared());
            Outcome retry = og.handle(1), next = og.handle(2);
            if (first != Outcome.ERROR || retry != Outcome.REPLAY || next != Outcome.ADMITTED)
                return "lost answer: first=" + first + ", retry=" + retry + ", next counter=" + next;
            // 2. the first commit is still in flight when the caller retries elsewhere: exactly one of the two is admitted
            GatedStore slow = new GatedStore(hs.get(0));
            Guard sg = fx.guardFor(slow, adapter.shared());
            Outcome[] res = new Outcome[2];
            Thread t1 = new Thread(() -> res[0] = sg.handle(3));
            t1.start();
            slow.entered.acquire();
            Thread t2 = new Thread(() -> res[1] = og.handle(3));
            t2.start();
            slow.gate.release();
            t1.join();
            t2.join();
            int admitted = (res[0] == Outcome.ADMITTED ? 1 : 0) + (res[1] == Outcome.ADMITTED ? 1 : 0);
            return admitted == 1 ? null : "in-flight retry: " + admitted + " admitted of 2 (want exactly 1)";
        } catch (Exception e) { return err(e); }
        finally { for (StateStore s : hs) close(s); }
    }

    // ---- child processes ----

    private static final class WorkerRun {
        boolean killed;
        int admitted, replays;
        final List<long[]> lines = new ArrayList<>(); // counter, admitted, replays, errors
    }

    @SuppressWarnings("unchecked")
    private static Process start(Worker w, Fixture fx, Map<String, Object> cfg, String out) throws Exception {
        Map<String, Object> c = new LinkedHashMap<>(cfg);
        c.put("fixture", fx.json());
        c.put("out", out);
        c.put("options", new LinkedHashMap<String, Object>(w.options));
        List<String> cmd = new ArrayList<>(w.command);
        cmd.add(Json.canonicalize(c));
        return new ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
    }

    @SuppressWarnings("unchecked")
    private static WorkerRun finish(Process p, String out) throws Exception {
        int code = p.waitFor();
        WorkerRun run = new WorkerRun();
        run.killed = code == 137 || code == -9; // SIGKILL
        File f = new File(out);
        if (f.exists()) {
            for (String l : Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)) {
                if (l.isBlank()) continue;
                Map<String, Object> m = (Map<String, Object>) Json.parseLenient(l);
                long counter = (long) Js.toNumber(m.get("counter")), a = (long) Js.toNumber(m.get("admitted")), rp = (long) Js.toNumber(m.get("replays")), er = (long) Js.toNumber(m.get("errors"));
                run.lines.add(new long[] {counter, a, rp, er});
                run.admitted += a;
                run.replays += rp;
            }
        }
        return run;
    }

    private static File tempDir() throws Exception { return Files.createTempDirectory("pcasc-pstate-").toFile(); }

    private static void rm(File d) {
        File[] fs = d.listFiles();
        if (fs != null) for (File f : fs) f.delete();
        d.delete();
    }

    private static String processRace(Worker w, int rounds, int copies, int processes) {
        File dir = null;
        try {
            Fixture fx = Fixture.make(rounds);
            dir = tempDir();
            long origin = System.currentTimeMillis() + 3000; // time for every process to start and open its handles
            List<Process> ps = new ArrayList<>();
            List<String> outs = new ArrayList<>();
            for (int i = 0; i < processes; i++) {
                String out = new File(dir, "p" + i + ".jsonl").getPath();
                outs.add(out);
                ps.add(start(w, fx, Issue.obj("mode", "race", "rounds", (long) rounds, "origin", origin, "roundMs", 150L, "copies", (long) copies, "instances", 2L), out));
            }
            List<WorkerRun> runs = new ArrayList<>();
            for (int i = 0; i < ps.size(); i++) runs.add(finish(ps.get(i), outs.get(i)));
            for (int r = 1; r <= rounds; r++) {
                long admitted = 0;
                for (WorkerRun run : runs) for (long[] l : run.lines) if (l[0] == r) admitted += l[1];
                if (admitted != 1) return "round " + r + ": " + admitted + " presentations admitted across " + runs.size() + " processes (want exactly 1)";
            }
            for (WorkerRun run : runs) if (run.killed || run.lines.size() != rounds) return "a worker did not finish (" + run.lines.size() + " of " + rounds + " rounds recorded)";
            return null;
        } catch (Exception e) { return err(e); }
        finally { if (dir != null) rm(dir); }
    }

    /** A child process admits counter 3 and is killed before its handler; a new process retries it; the next counter is admitted. */
    private static String processCrash(Adapter adapter, Worker w, Fixture fx) {
        File dir = null;
        try {
            dir = tempDir();
            String a = new File(dir, "a.jsonl").getPath(), b = new File(dir, "b.jsonl").getPath(), c = new File(dir, "c.jsonl").getPath();
            WorkerRun killed = finish(start(w, fx, Issue.obj("mode", "admit-then-die", "counter", 3L, "copies", 1L, "instances", 1L), a), a);
            adapter.restart();
            WorkerRun retried = finish(start(w, fx, Issue.obj("mode", "race", "counter", 3L, "copies", 1L, "instances", 1L, "rounds", 1L), b), b);
            WorkerRun fresh = finish(start(w, fx, Issue.obj("mode", "race", "counter", 4L, "copies", 1L, "instances", 1L, "rounds", 1L), c), c);
            if (!(killed.killed && killed.admitted == 1 && retried.admitted == 0 && retried.replays == 1 && fresh.admitted == 1))
                return "child process: killed after admission=" + (killed.killed && killed.admitted == 1) + ", retry in a new process admitted " + retried.admitted + ", next counter admitted " + fresh.admitted;
            return null;
        } catch (Exception e) { return err(e); }
        finally { if (dir != null) rm(dir); }
    }

    // ---- the worker side ----

    private static void record(String out, long counter, List<Outcome> rs) throws Exception {
        long a = 0, rp = 0, er = 0;
        for (Outcome r : rs) { if (r == Outcome.ADMITTED) a++; else if (r == Outcome.REPLAY) rp++; else er++; }
        String line = Json.canonicalize(Issue.obj("counter", counter, "admitted", a, "replays", rp, "errors", er)) + "\n";
        Files.write(new File(out).toPath(), line.getBytes(StandardCharsets.UTF_8), java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
    }

    /**
     * The entry of one worker process: {@code configText} is the last argument the parent passed; {@code open} opens a handle onto the shared backend from
     * the parent's {@code options}. Returns the process exit status. Mode {@code admit-then-die} records the admission and kills the process (SIGKILL) before
     * any handler.
     */
    @SuppressWarnings("unchecked")
    public static int workerMain(String configText, Function<Map<String, String>, StateStore> open) {
        try {
            Map<String, Object> cfg = (Map<String, Object>) Json.parseLenient(configText);
            Fixture fx = Fixture.from(cfg.get("fixture"));
            String out = (String) cfg.get("out");
            Map<String, String> options = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) cfg.get("options")).entrySet()) options.put(e.getKey(), (String) e.getValue());
            int nInstances = cfg.get("instances") == null ? 1 : (int) Js.toNumber(cfg.get("instances"));
            int copies = cfg.get("copies") == null ? 1 : (int) Js.toNumber(cfg.get("copies"));
            String mode = cfg.get("mode") == null ? "race" : (String) cfg.get("mode");
            List<Guard> guards = new ArrayList<>();
            for (int i = 0; i < Math.max(1, nInstances); i++) guards.add(fx.guardFor(open.apply(options), true));
            if (mode.equals("admit-then-die")) {
                int counter = (int) Js.toNumber(cfg.get("counter"));
                record(out, counter, presentations(guards, counter, copies));
                ProcessHandle.current().destroyForcibly(); // SIGKILL: no shutdown hooks, nothing is flushed
                return 3;
            }
            int rounds = cfg.get("rounds") == null ? 1 : (int) Js.toNumber(cfg.get("rounds"));
            for (int r = 0; r < rounds; r++) {
                int counter = cfg.get("counter") != null ? (int) Js.toNumber(cfg.get("counter")) : r + 1;
                long origin = cfg.get("origin") == null ? System.currentTimeMillis() : (long) Js.toNumber(cfg.get("origin"));
                long at = origin + r * (cfg.get("roundMs") == null ? 0L : (long) Js.toNumber(cfg.get("roundMs")));
                while (System.currentTimeMillis() < at) Thread.sleep(2);
                record(out, counter, presentations(guards, counter, copies));
            }
            return 0;
        } catch (Exception e) { return 1; }
    }

    private static List<Outcome> presentations(List<Guard> guards, int counter, int copies) throws InterruptedException {
        int n = Math.max(1, copies);
        Object[] rs = StoreConformance.race(new CyclicBarrier(n), n, i -> guards.get(i % guards.size()).handle(counter));
        List<Outcome> out = new ArrayList<>();
        for (Object r : rs) out.add(r instanceof Outcome ? (Outcome) r : Outcome.ERROR);
        return out;
    }
}
