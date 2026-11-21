package net.atlasauth.pca.storeconformance;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.StoreJs;

/**
 * The shared frame of the per-store conformance suites (bond store, ledger store, budget ledger, mesh witness store): a named check with a
 * claim, a run that reports pass / fail / skip per check, and the assertion helpers the checks use. A check passes by returning and
 * fails by throwing; the report carries the first line of the failure.
 */
public final class Suite {
    private Suite() {}

    /** What a check runs against: one isolated backend plus the means to reconnect to it. */
    public interface Handle {
        /** True when {@code crash()} is implemented (a check that needs a crash is skipped otherwise). */
        default boolean canCrash() { return false; }

        /** Release the backend (never drop shared data of another handle). */
        default void close() throws Exception {}
    }

    /** A check body. */
    public interface Body<H> { void run(H h) throws Exception; }

    /** One claim about a store, driven through an adapter's handle. {@code needs} is null, {@code "durable"} or {@code "crash"}. */
    public static final class Check<H> {
        public final String name, claim, needs;
        public final Body<H> body;

        public Check(String name, String claim, String needs, Body<H> body) { this.name = name; this.claim = claim; this.needs = needs; this.body = body; }

        public Check(String name, String claim, Body<H> body) { this(name, claim, null, body); }
    }

    /** One check's outcome: {@code pass}, {@code fail} or {@code skip}. */
    public static final class Result {
        public final String name, status, detail;

        Result(String name, String status, String detail) { this.name = name; this.status = status; this.detail = detail; }
    }

    /** A run's report. */
    public static final class Report {
        public final String adapter, status, suite;
        public final List<Result> checks;

        Report(String suite, String adapter, List<Result> checks) {
            this.suite = suite;
            this.adapter = adapter;
            this.checks = checks;
            boolean failed = false;
            for (Result r : checks) failed |= r.status.equals("fail");
            this.status = failed ? "fail" : "pass";
        }

        public Result check(String name) {
            for (Result r : checks) if (r.name.equals(name)) return r;
            throw new IllegalArgumentException("no check " + name);
        }

        public int count(String status) {
            int n = 0;
            for (Result r : checks) if (r.status.equals(status)) n++;
            return n;
        }

        /** The text report. */
        public String format() {
            StringBuilder sb = new StringBuilder("pca-store-conformance (" + suite + "): " + adapter + " -> " + status.toUpperCase());
            for (Result c : checks) {
                sb.append("\n  [").append(c.status.toUpperCase()).append("] ").append(c.name);
                if (c.detail != null) sb.append(": ").append(c.detail.split("\n")[0]);
            }
            return sb.toString();
        }
    }

    /** Opens one isolated backend. */
    public interface Maker<H extends Handle> { H create() throws Exception; }

    /**
     * Run {@code checks} (only those named in {@code only} when non-null) against fresh handles from {@code make}. A check that needs
     * durability is skipped when {@code durable} is false; one that needs a crash is skipped when the handle cannot crash.
     */
    public static <H extends Handle> Report run(String suite, String adapter, boolean durable, Maker<H> make, List<Check<H>> checks, Collection<String> only) {
        List<Result> out = new ArrayList<>();
        for (Check<H> c : checks) {
            if (only != null && !only.contains(c.name)) continue;
            if ("durable".equals(c.needs) && !durable) {
                out.add(new Result(c.name, "skip", "the adapter declares durable: false"));
                continue;
            }
            H h = null;
            try {
                h = make.create();
                if ("crash".equals(c.needs) && !h.canCrash()) {
                    out.add(new Result(c.name, "skip", "the adapter has no crash()"));
                    continue;
                }
                c.body.run(h);
                out.add(new Result(c.name, "pass", null));
            } catch (Throwable e) {
                out.add(new Result(c.name, "fail", String.valueOf(e.getMessage() == null ? e.toString() : e.getMessage())));
            } finally {
                if (h != null) try { h.close(); } catch (Exception ignored) { /* closing is best effort */ }
            }
        }
        return new Report(suite, adapter, out);
    }

    // ---- assertions ----

    /** Numbers print as JavaScript prints them; everything else is kept. */
    @SuppressWarnings("unchecked")
    public static Object norm(Object v) {
        if (v instanceof Json.Num) { Double d = StoreJs.dbl(v); return d == null ? v : StoreJs.num(d.doubleValue()); }
        if (v instanceof Number) return StoreJs.num(((Number) v).doubleValue());
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), norm(e.getValue()));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(norm(x));
            return out;
        }
        return v;
    }

    /** Deep JSON equality (numbers by value, objects by member). */
    public static void eq(Object want, Object got, String what) {
        String a = Json.canonicalize(norm(want)), b = Json.canonicalize(norm(got));
        if (!a.equals(b)) throw new AssertionError((what == null ? "" : what + ": ") + "expected " + a + " but got " + b);
    }

    public static void eq(Object want, Object got) { eq(want, got, null); }

    public static void ok(boolean cond, String what) { if (!cond) throw new AssertionError(what); }

    /** The call must throw {@code type}; anything else (including no throw) fails. */
    public static void rejects(Class<? extends Throwable> type, Callable<?> f, String what) {
        try {
            f.call();
        } catch (Throwable t) {
            if (type.isInstance(t)) return;
            throw new AssertionError(what + ": expected " + type.getSimpleName() + " but got " + t);
        }
        throw new AssertionError(what + ": expected " + type.getSimpleName() + " but nothing was thrown");
    }

    /** The call must throw (any exception). */
    public static void rejects(Callable<?> f, String what) { rejects(Throwable.class, f, what); }

    /** Run the tasks concurrently (the reference's Promise.all) and return their results in order; a failure rethrows. */
    public static <T> List<T> parallel(List<Callable<T>> tasks) throws Exception {
        ExecutorService ex = Executors.newFixedThreadPool(Math.max(1, Math.min(tasks.size(), 16)));
        try {
            List<Future<T>> fs = new ArrayList<>();
            for (Callable<T> t : tasks) fs.add(ex.submit(t));
            List<T> out = new ArrayList<>();
            for (Future<T> f : fs) {
                try {
                    out.add(f.get());
                } catch (ExecutionException e) {
                    if (e.getCause() instanceof Exception) throw (Exception) e.getCause();
                    throw e;
                }
            }
            return out;
        } finally {
            ex.shutdownNow();
        }
    }
}
