package net.atlasauth.pca.storeconformance;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.function.Supplier;
import java.util.stream.Stream;
import net.atlasauth.pca.storeconformance.Workloads.WorkloadOptions;
import net.atlasauth.pca.storeconformance.Workloads.WorkloadResult;

/**
 * Crash harness. Several client "processes" (each a group of client threads with its own history file) run the windowed workload
 * against the same backend; every {@code killEveryMs} one of them is KILLED (its recorder stops writing, so its in-flight operations
 * stay PENDING, exactly like a SIGKILLed process) and a replacement starts under a new identity. When the adapter has {@code crash()},
 * the backend is crashed and restarted once mid-run. Every writer is joined before the histories are read (a partial history can
 * make a FALSE look unexplained). shortcut: a JVM cannot SIGKILL a thread, so a "killed process" stops recording and issuing
 * operations while the call it is inside runs to its end unrecorded; upgrade by forking JVMs if real process death matters.
 */
public final class Crash {
    private Crash() {}

    public static class CrashOptions extends WorkloadOptions {
        /** Opens an adapter over the SHARED backend; called once per client process (and once for the control that crashes the backend). */
        public Supplier<StoreAdapter> adapters;
        /** Client processes alive at once (default 3); {@code clients} is per process (default 4). */
        public Integer processes;
        /** Kill one client process this often (default 400 ms; 0 = never). */
        public Integer killEveryMs;
        /** Crash + restart the backend once mid-run when the adapter has {@code crash()} (default true). */
        public Boolean backendCrash;
        /** History directory (default: a fresh temp dir). */
        public Path dir;
    }

    public static final class CrashResult extends WorkloadResult {
        public final int kills, backendCrashes, torn, pending, processes;
        CrashResult(List<Op> ops, int errors, int kills, int backendCrashes, int torn, int pending, int processes) {
            super(ops, errors, null);
            this.kills = kills; this.backendCrashes = backendCrashes; this.torn = torn; this.pending = pending; this.processes = processes;
        }
    }

    private static final class Proc {
        final Thread thread;
        final Recorder.FileRecorder rec;
        volatile boolean killed;
        Proc(Thread thread, Recorder.FileRecorder rec) { this.thread = thread; this.rec = rec; }
    }

    public static CrashResult runCrash(String kind, CrashOptions o) throws Exception {
        if (o.adapters == null) throw new IllegalArgumentException("runCrash needs an adapter supplier (CrashOptions.adapters)");
        Path dir = o.dir != null ? o.dir : net.atlasauth.pca.PrivateFiles.createTempDirectory("pcasc-hist-");
        double durationMs = o.durationMs != null ? o.durationMs : 3000;
        int killEveryMs = o.killEveryMs != null ? o.killEveryMs : 400;
        long seed = o.seed != null ? o.seed : (long) Math.floor(Math.random() * Math.pow(2, 31));
        Kit.Prng rand = new Kit.Prng(seed);
        double origin = Recorder.clock();
        double deadline = origin + durationMs;
        int clients = o.clients != null ? o.clients : 4;
        String namespace = o.namespace != null ? o.namespace : Workloads.randomNamespace();
        double windowMs = o.windowMs != null ? o.windowMs : 5;
        int spread = o.spread != null ? o.spread : 3;
        int values = o.values != null ? o.values : 20;
        double retentionMs = o.retentionMs != null ? o.retentionMs : 600_000;
        long opTimeoutMs = o.opTimeoutMs != null ? o.opTimeoutMs : 5000;

        List<Proc> live = new ArrayList<>();
        List<Proc> all = new ArrayList<>();
        int[] n = {0};
        Runnable spawn = () -> {
            String proc = "p" + n[0];
            Path file = dir.resolve("h-" + proc + ".jsonl");
            long procSeed = seed + 7919L * n[0];
            n[0]++;
            try {
                Recorder.FileRecorder rec = new Recorder.FileRecorder(file, proc);
                Proc[] self = new Proc[1];
                Thread t = new Thread(() -> worker(self[0], o, kind, proc, clients, namespace, windowMs, spread, values, retentionMs, opTimeoutMs, origin, deadline, procSeed), "pcasc-" + proc);
                self[0] = new Proc(t, rec);
                t.setDaemon(true);
                live.add(self[0]);
                all.add(self[0]);
                t.start();
            } catch (IOException e) {
                throw new IllegalStateException("cannot start a client process: " + e.getMessage(), e);
            }
        };
        for (int i = 0; i < (o.processes != null ? o.processes : 3); i++) spawn.run();
        StoreAdapter control = !Boolean.FALSE.equals(o.backendCrash) ? o.adapters.get() : null;
        int kills = 0, backendCrashes = 0;
        double half = origin + durationMs / 2;
        while (killEveryMs > 0 && Recorder.clock() + killEveryMs < deadline) {
            Thread.sleep(killEveryMs);
            List<Proc> victims = new ArrayList<>(live);
            if (!victims.isEmpty()) {
                Proc v = victims.get((int) rand.rand(victims.size()));
                v.killed = true;
                v.rec.kill();
                live.remove(v);
                kills++;
                spawn.run();
            }
            if (control != null && control.hasCrash() && backendCrashes == 0 && Recorder.clock() >= half) {
                control.crash();
                if (control.hasRestart()) control.restart();
                backendCrashes++;
            }
        }
        for (Proc p : all) p.thread.join();
        if (control != null) control.teardown();
        StringBuilder text = new StringBuilder();
        try (Stream<Path> files = Files.list(dir)) {
            List<Path> hs = new ArrayList<>();
            files.filter(f -> f.getFileName().toString().startsWith("h-") && f.getFileName().toString().endsWith(".jsonl")).forEach(hs::add);
            hs.sort(null);
            for (Path f : hs) text.append(Files.readString(f, StandardCharsets.UTF_8)).append('\n');
        }
        Kit.ParsedHistory h = Kit.parseHistory(text.toString());
        int unknown = 0;
        for (Op x : h.ops) if (x.res.equals("unknown")) unknown++;
        return new CrashResult(h.ops, unknown, kills, backendCrashes, h.torn, h.pending, n[0]);
    }

    /** One client process: open an adapter, run the windowed workload on {@code clients} threads, record to the process's file. */
    private static void worker(Proc self, CrashOptions o, String kind, String proc, int clients, String namespace, double windowMs, int spread, int values,
                               double retentionMs, long opTimeoutMs, double origin, double deadline, long seed) {
        ExecutorService pool = Workloads.newPool();
        List<StoreClient> cs = new ArrayList<>();
        try {
            StoreAdapter adapter = o.adapters.get(); // the adapter's owner tears the backend down, never a client process
            Workloads.OpContext ctx = new Workloads.OpContext(self.rec, retentionMs, opTimeoutMs, pool);
            cs = Workloads.openClients(adapter, clients);
            List<Thread> ts = new ArrayList<>();
            for (int i = 0; i < cs.size(); i++) {
                StoreClient c = cs.get(i);
                String name = proc + "c" + i;
                Workloads.Window w = new Workloads.Window();
                w.namespace = namespace; w.windowMs = windowMs; w.spread = spread; w.values = values; w.origin = origin; w.deadline = deadline;
                w.rand = new Kit.Prng(seed + i);
                w.stop = () -> self.killed;
                Thread t = new Thread(() -> Workloads.driveWindowed(c, name, kind, ctx, w), "pcasc-" + name);
                t.setDaemon(true);
                ts.add(t);
                t.start();
            }
            for (Thread t : ts) t.join();
        } catch (Exception e) {
            // a worker that cannot run records nothing; the parent sees fewer operations
        } finally {
            try { Workloads.closeClients(cs); } catch (Exception ignored) { /* best effort */ }
            try { self.rec.close(); } catch (IOException ignored) { /* best effort */ }
            pool.shutdownNow();
        }
    }
}
