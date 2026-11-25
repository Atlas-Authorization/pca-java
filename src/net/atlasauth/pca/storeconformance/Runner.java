package net.atlasauth.pca.storeconformance;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.storeconformance.Crash.CrashOptions;
import net.atlasauth.pca.storeconformance.Kit.CheckOptions;
import net.atlasauth.pca.storeconformance.Workloads.WorkloadOptions;
import net.atlasauth.pca.storeconformance.Workloads.WorkloadResult;

/**
 * The conformance run: every test for every operation the adapter implements, each history checked for linearizability, with a
 * report (text or JSON). A PASS is evidence, not proof: the kit checks the histories it observed. A FAIL is a proof of a contract
 * violation (the counterexample is a recorded history that no sequential order explains), unless the adapter itself is mis-wired.
 */
public final class Runner {
    private Runner() {}

    /** Workload, checker and crash settings of a run. */
    public static class ConformanceOptions extends WorkloadOptions {
        /** Which tests to run (default all). */
        public List<String> tests;
        public CheckOptions check = new CheckOptions();
        /** The crash test needs an adapter supplier over the shared backend (each "process" opens its own). Without it: skipped. */
        public CrashOptions crash;
    }

    /** One test's report: {@code status} is pass, fail, skip or unresolved. */
    public static final class TestReport {
        public final String test, kind, status;
        public final int ops, keys, errors, unresolved;
        public final List<Kit.KeyResult> violations;
        public final String note;

        TestReport(String test, String kind, String status, int ops, int keys, int errors, List<Kit.KeyResult> violations, int unresolved, String note) {
            this.test = test; this.kind = kind; this.status = status; this.ops = ops; this.keys = keys; this.errors = errors; this.violations = violations; this.unresolved = unresolved; this.note = note;
        }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("test", test);
            m.put("kind", kind);
            m.put("status", status);
            m.put("ops", ops);
            m.put("keys", keys);
            m.put("errors", errors);
            m.put("violations", Kit.keyResultsJson(violations));
            m.put("unresolved", unresolved);
            if (note != null) m.put("note", note);
            return m;
        }
    }

    public static final class ConformanceReport {
        public final String adapter, status;
        public final List<TestReport> tests;
        ConformanceReport(String adapter, String status, List<TestReport> tests) { this.adapter = adapter; this.status = status; this.tests = tests; }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("adapter", adapter);
            m.put("status", status);
            List<Object> ts = new ArrayList<>();
            for (TestReport t : tests) ts.add(t.toJson());
            m.put("tests", ts);
            return m;
        }

        public String format() { return Kit.formatReport(toJson(), 3); }
        public String json() { return Kit.reportJson(toJson()); }
        public boolean ok() { return status.equals("pass"); }
    }

    /** Which operations the adapter implements: declared capabilities win, else what its first client exposes. */
    public static List<String> detectKinds(StoreAdapter adapter) throws Exception {
        StoreAdapter.Capabilities caps = adapter.capabilities() != null ? adapter.capabilities() : new StoreAdapter.Capabilities();
        StoreClient c = adapter.open();
        try {
            List<String> kinds = new ArrayList<>();
            if (caps.consumeOnce != null ? caps.consumeOnce : c.hasConsumeOnce()) kinds.add("consume");
            if (caps.advance != null ? caps.advance : c.hasAdvance()) kinds.add("advance");
            return kinds;
        } finally {
            c.close();
        }
    }

    private static TestReport judge(String test, String kind, WorkloadResult w, CheckOptions opts) {
        Kit.HistoryCheck h = Kit.checkHistory(w.ops, opts);
        int definite = h.outcomes[0] + h.outcomes[1];
        String status = !h.violations.isEmpty() ? "fail" : !h.unresolved.isEmpty() || definite == 0 ? "unresolved" : "pass";
        List<String> notes = new ArrayList<>();
        if (w.note != null && !w.note.isEmpty()) notes.add(w.note);
        if (definite == 0) notes.add("no definite answer was observed (every call failed or timed out)");
        return new TestReport(test, kind, status, h.ops, h.keys, w.errors, h.violations, h.unresolved.size(), notes.isEmpty() ? null : String.join("; ", notes));
    }

    private static TestReport skip(String test, String kind, String note) { return new TestReport(test, kind, "skip", 0, 0, 0, new ArrayList<>(), 0, note); }

    public static TestReport runTest(StoreAdapter adapter, String test, String kind, ConformanceOptions opts) throws Exception {
        if (test.equals("durability") && adapter.capabilities() != null && Boolean.FALSE.equals(adapter.capabilities().durable)) {
            return skip(test, kind, "the adapter declares durable: false (only correct for one process whose lifetime covers the action lifetime)");
        }
        if (test.equals("crash") && (opts.crash == null || opts.crash.adapters == null)) {
            return skip(test, kind, "needs an adapter supplier over the shared backend (the crash test runs the adapter in several client processes)");
        }
        WorkloadResult w;
        switch (test) {
            case "burst": w = Workloads.runBurst(adapter, kind, opts); break;
            case "concurrent": w = Workloads.runConcurrent(adapter, kind, opts); break;
            case "retention": w = Workloads.runRetention(adapter, kind, opts); break;
            case "durability": w = Workloads.runDurability(adapter, kind, opts); break;
            case "crash": {
                CrashOptions c = opts.crash;
                c.clients = c.clients != null ? c.clients : opts.clients;
                c.durationMs = c.durationMs != null ? c.durationMs : opts.durationMs;
                c.windowMs = c.windowMs != null ? c.windowMs : opts.windowMs;
                c.spread = c.spread != null ? c.spread : opts.spread;
                c.values = c.values != null ? c.values : opts.values;
                c.retentionMs = c.retentionMs != null ? c.retentionMs : opts.retentionMs;
                c.opTimeoutMs = c.opTimeoutMs != null ? c.opTimeoutMs : opts.opTimeoutMs;
                c.namespace = c.namespace != null ? c.namespace : opts.namespace;
                c.seed = c.seed != null ? c.seed : opts.seed;
                w = Crash.runCrash(kind, c);
                break;
            }
            default: throw new IllegalArgumentException("unknown test " + test);
        }
        return judge(test, kind, w, opts.check);
    }

    public static ConformanceReport runConformance(StoreAdapter adapter, ConformanceOptions opts) throws Exception {
        ConformanceOptions o = opts != null ? opts : new ConformanceOptions();
        List<String> kinds = detectKinds(adapter);
        if (kinds.isEmpty()) throw new IllegalArgumentException(adapter.name() + ": the client implements neither consumeOnce nor advance");
        List<TestReport> tests = new ArrayList<>();
        for (String test : o.tests != null ? o.tests : Kit.ALL_TESTS) for (String kind : kinds) tests.add(runTest(adapter, test, kind, o));
        return new ConformanceReport(adapter.name(), overall(tests), tests);
    }

    public static String overall(List<TestReport> tests) {
        boolean unresolved = false;
        for (TestReport t : tests) {
            if (t.status.equals("fail")) return "fail";
            if (t.status.equals("unresolved")) unresolved = true;
        }
        return unresolved ? "unresolved" : "pass";
    }

    /** Run the kit and fail with the formatted report (counterexamples included) when the store does not pass: the test-runner binding. */
    public static ConformanceReport assertConformance(StoreAdapter adapter, ConformanceOptions opts) throws Exception {
        ConformanceReport r = runConformance(adapter, opts);
        if (!r.ok()) throw new AssertionError(r.format());
        return r;
    }
}
