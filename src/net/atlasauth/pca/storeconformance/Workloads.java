package net.atlasauth.pca.storeconformance;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;
import net.atlasauth.pca.storeconformance.Recorder.MemoryRecorder;

/**
 * Workloads that drive a store adapter and record the history: same-key bursts, a windowed concurrent run in which every client
 * contends on the same few keys at once, a retention run (many keys, then every key revisited while still live), and a durability
 * run (write, close every client, restart the backend, read back). Clients are threads.
 */
public final class Workloads {
    private Workloads() {}

    /** Workload settings; null members take the reference defaults. */
    public static class WorkloadOptions {
        /** Concurrent clients (each {@code adapter.open()}), default 16. */
        public Integer clients;
        /** Concurrent run length, default 2000 ms. */
        public Double durationMs;
        /** Contention window: every client targets the same {@code spread} keys within one window (default 5 ms, 3 keys). */
        public Double windowMs;
        public Integer spread;
        /** Counter values are drawn from [0, values) so duplicates and reorderings occur (default 20). */
        public Integer values;
        /** consumeOnce horizon: retainUntil = now + retentionMs (default 10 minutes, longer than any run). */
        public Double retentionMs;
        /** A call that has not settled after this long is recorded as unknown (open-ended), default 5000 ms. */
        public Long opTimeoutMs;
        /** Same-key burst rounds, default 20. */
        public Integer rounds;
        /** Retention run: distinct keys written then revisited, default 500. */
        public Integer revisitKeys;
        /** Key prefix. Default: random per run, so runs never collide with each other or with real data. */
        public String namespace;
        /** PRNG seed (default random). */
        public Long seed;
    }

    /** The recorded history of a run, how many calls failed or timed out, and a note. */
    public static class WorkloadResult {
        public final List<Op> ops;
        public final int errors;
        public final String note;
        public WorkloadResult(List<Op> ops, int errors, String note) { this.ops = ops; this.errors = errors; this.note = note; }
    }

    static final class Resolved {
        int clients, spread, values, rounds, revisitKeys;
        double durationMs, windowMs, retentionMs;
        long opTimeoutMs, seed;
        String namespace;
    }

    static Resolved defaults(WorkloadOptions o) {
        Resolved r = new Resolved();
        r.clients = o.clients != null ? o.clients : 16;
        r.durationMs = o.durationMs != null ? o.durationMs : 2000;
        r.windowMs = o.windowMs != null ? o.windowMs : 5;
        r.spread = o.spread != null ? o.spread : 3;
        r.values = o.values != null ? o.values : 20;
        r.retentionMs = o.retentionMs != null ? o.retentionMs : 600_000;
        r.opTimeoutMs = o.opTimeoutMs != null ? o.opTimeoutMs : 5000;
        r.rounds = o.rounds != null ? o.rounds : 20;
        r.revisitKeys = o.revisitKeys != null ? o.revisitKeys : 500;
        r.namespace = o.namespace != null ? o.namespace : randomNamespace();
        r.seed = o.seed != null ? o.seed : (long) Math.floor(Math.random() * Math.pow(2, 31));
        return r;
    }

    public static String randomNamespace() { return "pcasc-" + Long.toString(System.currentTimeMillis(), 36) + "-" + Long.toString((long) (Math.random() * 2176782336L), 36); }

    /** What every operation needs: where to record, the retention horizon, the per-call timeout and the threads calls run on. */
    public static final class OpContext {
        final Recorder rec;
        final double retentionMs;
        final long opTimeoutMs;
        final ExecutorService pool;
        public OpContext(Recorder rec, double retentionMs, long opTimeoutMs, ExecutorService pool) { this.rec = rec; this.retentionMs = retentionMs; this.opTimeoutMs = opTimeoutMs; this.pool = pool; }
    }

    static ExecutorService newPool() {
        return Executors.newCachedThreadPool(r -> { Thread t = new Thread(r, "pcasc"); t.setDaemon(true); return t; });
    }

    /** Settle {@code fn} as a definite boolean, or null (unknown) on a throw or a timeout. */
    public static Boolean settle(Callable<Boolean> fn, long timeoutMs, ExecutorService pool) {
        Future<Boolean> f = pool.submit(fn);
        try {
            return f.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            f.cancel(true);
            return null;
        } catch (InterruptedException e) {
            f.cancel(true);
            Thread.currentThread().interrupt();
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /** Record and perform one operation. For {@code advance}, {@code value} is the counter; for {@code consume} it is ignored. */
    public static Boolean perform(StoreClient c, String client, String kind, String key, double value, OpContext ctx) {
        double now = System.currentTimeMillis();
        boolean consume = kind.equals("consume");
        double lo = consume ? now : value;
        double w = consume ? now + ctx.retentionMs : value;
        Op op = ctx.rec.invoke(client, kind, key, lo, w);
        if (ctx.rec.dead()) return null; // killed before the invocation was written: issuing the call would leave an effect no history explains
        Boolean r = settle(() -> consume ? c.consumeOnce(key, w, now) : c.advance(key, value), ctx.opTimeoutMs, ctx.pool);
        ctx.rec.complete(op, r);
        return r;
    }

    public static List<StoreClient> openClients(StoreAdapter adapter, int n) throws Exception {
        List<StoreClient> out = new ArrayList<>();
        try {
            for (int i = 0; i < n; i++) out.add(adapter.open());
        } catch (Exception e) {
            closeClients(out);
            throw e;
        }
        return out;
    }

    public static void closeClients(List<StoreClient> clients) throws Exception {
        Exception first = null;
        for (StoreClient c : clients) {
            try { c.close(); } catch (Exception e) { if (first == null) first = e; }
        }
        if (first != null) throw first;
    }

    private static int countUnknown(List<Op> ops) {
        int n = 0;
        for (Op o : ops) if (o.res.equals("unknown")) n++;
        return n;
    }

    /** Where a windowed client's keys and values come from (shared by every client and process). */
    public static final class Window {
        public String namespace;
        public double windowMs;
        public int spread;
        public int values;
        public double origin, deadline;
        public Kit.Prng rand;
        public BooleanSupplier stop = () -> false;
    }

    /**
     * The client loop of the concurrent run, shared with the crash harness: until {@code deadline}, pick one of the {@code spread}
     * keys of the current window (all clients compute the same window from {@code origin}) and operate on it.
     */
    public static void driveWindowed(StoreClient c, String client, String kind, OpContext ctx, Window o) {
        while (Recorder.clock() < o.deadline && !o.stop.getAsBoolean()) {
            long win = (long) Math.floor((Recorder.clock() - o.origin) / o.windowMs);
            String key = o.namespace + ":" + kind + ":" + win + ":" + (long) o.rand.rand(o.spread);
            perform(c, client, kind, key, o.rand.rand(o.values), ctx);
        }
    }

    /** {@code rounds} times: every client fires one operation at the SAME fresh key at once. */
    public static WorkloadResult runBurst(StoreAdapter adapter, String kind, WorkloadOptions opts) throws Exception {
        Resolved o = defaults(opts);
        Kit.Prng rand = new Kit.Prng(o.seed);
        MemoryRecorder rec = new MemoryRecorder();
        ExecutorService pool = newPool();
        OpContext ctx = new OpContext(rec, o.retentionMs, o.opTimeoutMs, pool);
        List<StoreClient> clients = openClients(adapter, o.clients);
        try {
            for (int r = 0; r < o.rounds; r++) {
                String key = o.namespace + ":" + kind + ":burst:" + r;
                List<Future<?>> fs = new ArrayList<>();
                for (int i = 0; i < clients.size(); i++) {
                    StoreClient c = clients.get(i);
                    String name = "c" + i;
                    double v = rand.rand(o.values);
                    fs.add(pool.submit(() -> perform(c, name, kind, key, v, ctx)));
                }
                for (Future<?> f : fs) f.get();
            }
        } finally {
            closeQuietly(clients);
            pool.shutdownNow();
        }
        List<Op> ops = rec.ops();
        return new WorkloadResult(ops, countUnknown(ops), null);
    }

    private static void closeQuietly(List<StoreClient> clients) {
        try { closeClients(clients); } catch (Exception ignored) { /* the run's result stands */ }
    }

    /** Every client loops on the windowed keys for {@code durationMs}. */
    public static WorkloadResult runConcurrent(StoreAdapter adapter, String kind, WorkloadOptions opts) throws Exception {
        Resolved o = defaults(opts);
        MemoryRecorder rec = new MemoryRecorder();
        ExecutorService pool = newPool();
        OpContext ctx = new OpContext(rec, o.retentionMs, o.opTimeoutMs, pool);
        List<StoreClient> clients = openClients(adapter, o.clients);
        double origin = Recorder.clock();
        try {
            List<Future<?>> fs = new ArrayList<>();
            for (int i = 0; i < clients.size(); i++) {
                StoreClient c = clients.get(i);
                String name = "c" + i;
                Window w = new Window();
                w.namespace = o.namespace; w.windowMs = o.windowMs; w.spread = o.spread; w.values = o.values;
                w.origin = origin; w.deadline = origin + o.durationMs; w.rand = new Kit.Prng(o.seed + i);
                fs.add(pool.submit(() -> driveWindowed(c, name, kind, ctx, w)));
            }
            for (Future<?> f : fs) f.get();
        } finally {
            closeQuietly(clients);
            pool.shutdownNow();
        }
        List<Op> ops = rec.ops();
        return new WorkloadResult(ops, countUnknown(ops), null);
    }

    /**
     * Retention: write {@code revisitKeys} distinct keys (consume once / advance to 1), then revisit every one while it is still
     * live (same counter): each revisit must answer false. Catches early pruning and capacity eviction of live records.
     */
    public static WorkloadResult runRetention(StoreAdapter adapter, String kind, WorkloadOptions opts) throws Exception {
        Resolved o = defaults(opts);
        MemoryRecorder rec = new MemoryRecorder();
        ExecutorService pool = newPool();
        OpContext ctx = new OpContext(rec, o.retentionMs, o.opTimeoutMs, pool);
        List<StoreClient> clients = openClients(adapter, o.clients);
        List<String> keys = new ArrayList<>();
        for (int i = 0; i < o.revisitKeys; i++) keys.add(o.namespace + ":" + kind + ":keep:" + i);
        try {
            for (String pass : new String[] {"write", "revisit"}) {
                for (int i = 0; i < keys.size(); i += clients.size()) {
                    List<Future<?>> fs = new ArrayList<>();
                    for (int j = 0; j < clients.size(); j++) {
                        if (i + j >= keys.size()) continue;
                        StoreClient c = clients.get(j);
                        String name = pass + "-c" + j;
                        String key = keys.get(i + j);
                        fs.add(pool.submit(() -> perform(c, name, kind, key, 1, ctx)));
                    }
                    for (Future<?> f : fs) f.get();
                }
            }
        } finally {
            closeQuietly(clients);
            pool.shutdownNow();
        }
        List<Op> ops = rec.ops();
        return new WorkloadResult(ops, countUnknown(ops), null);
    }

    /**
     * Durability: consume a key / advance a stream to 7, close the client, {@code restart()} the backend when the adapter can, open
     * a new client and read back: the key must stay consumed and the counter must not go backwards (7 refused, 8 accepted).
     */
    public static WorkloadResult runDurability(StoreAdapter adapter, String kind, WorkloadOptions opts) throws Exception {
        Resolved o = defaults(opts);
        MemoryRecorder rec = new MemoryRecorder();
        ExecutorService pool = newPool();
        OpContext ctx = new OpContext(rec, o.retentionMs, o.opTimeoutMs, pool);
        String key = o.namespace + ":" + kind + ":durable";
        try {
            StoreClient before = adapter.open();
            try {
                perform(before, "before-restart", kind, key, 7, ctx);
            } finally {
                before.close();
            }
            if (adapter.hasRestart()) adapter.restart();
            StoreClient after = adapter.open();
            try {
                perform(after, "after-restart", kind, key, 7, ctx);
                if (kind.equals("advance")) perform(after, "after-restart", kind, key, 8, ctx);
            } finally {
                after.close();
            }
        } finally {
            pool.shutdownNow();
        }
        List<Op> ops = rec.ops();
        return new WorkloadResult(ops, countUnknown(ops), adapter.hasRestart() ? "backend restarted between write and read" : "no restart() hook: clients closed and re-opened only");
    }
}
