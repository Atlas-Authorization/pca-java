package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import net.atlasauth.pca.storeconformance.Crash;
import net.atlasauth.pca.storeconformance.Kit;
import net.atlasauth.pca.storeconformance.Recorder;
import net.atlasauth.pca.storeconformance.Reference;
import net.atlasauth.pca.storeconformance.Runner;
import net.atlasauth.pca.storeconformance.StoreAdapter;
import org.junit.jupiter.api.Test;

/** The kit against its own reference adapters: the good one passes, every bad one is flagged (a checker that passes everything is worthless). */
class StoreConformanceRunTest {
    private static Runner.ConformanceOptions small(String... tests) {
        Runner.ConformanceOptions o = new Runner.ConformanceOptions();
        o.clients = 8;
        o.rounds = 10;
        o.durationMs = 300.0;
        o.revisitKeys = 100;
        o.tests = List.of(tests);
        return o;
    }

    @Test void goodAdapterPasses() throws Exception {
        Runner.ConformanceReport r = Runner.runConformance(Reference.inMemoryAdapter(), small("burst", "concurrent", "retention", "durability"));
        assertEquals("pass", r.status, r.format());
        // the adapter declares durable: false, so the durability test is skipped and said so
        assertTrue(r.tests.stream().anyMatch(t -> t.test.equals("durability") && t.status.equals("skip")));
    }

    @Test void readThenWriteIsFlagged() throws Exception {
        assertEquals("fail", Runner.runConformance(Reference.readThenWriteAdapter(), small("burst")).status);
    }

    @Test void nonStrictCounterIsFlagged() throws Exception {
        assertEquals("fail", Runner.runConformance(Reference.nonStrictCounterAdapter(), small("burst")).status);
    }

    @Test void volatileStateIsFlaggedByDurability() throws Exception {
        assertEquals("fail", Runner.runConformance(Reference.volatileAdapter(), small("durability")).status);
    }

    @Test void evictionOfLiveRecordsIsFlaggedByRetention() throws Exception {
        assertEquals("fail", Runner.runConformance(Reference.evictingAdapter(16), small("retention")).status);
    }

    @Test void crashHarnessLeavesPendingOperationsAndStaysLinearizable() throws Exception {
        StoreAdapter shared = Reference.inMemoryAdapter();
        Runner.ConformanceOptions o = small("crash");
        o.durationMs = 600.0;
        Crash.CrashOptions c = new Crash.CrashOptions();
        c.adapters = () -> shared;
        c.processes = 2;
        c.killEveryMs = 100;
        c.backendCrash = false;
        o.crash = c;
        Runner.ConformanceReport r = Runner.runConformance(shared, o);
        assertTrue(!r.status.equals("fail"), r.format()); // unresolved is possible when many operations stay pending; a violation never is
    }

    @Test void doctorExercisesAStoreAdapterThroughTheKit() {
        java.util.Map<String, Object> store = new java.util.LinkedHashMap<>();
        store.put("adapter", "builtin:in-memory");
        store.put("concurrency", 8);
        store.put("rounds", 5);
        java.util.Map<String, Object> cfg = new java.util.LinkedHashMap<>();
        cfg.put("store", store);
        List<net.atlasauth.pca.doctor.Doctor.CheckResult> good = net.atlasauth.pca.doctor.Doctor.runDoctor(cfg, List.of("store"), null);
        assertEquals("pass", good.get(0).status(), good.get(0).detail());
        assertEquals("warn", good.get(1).status()); // the in-memory adapter declares itself non-durable
        store.put("adapter", "builtin:bad-read-then-write");
        List<net.atlasauth.pca.doctor.Doctor.CheckResult> bad = net.atlasauth.pca.doctor.Doctor.runDoctor(cfg, List.of("store"), null);
        assertEquals("fail", bad.get(0).status(), bad.get(0).detail());
        store.put("adapter", "builtin:nope");
        assertEquals("fail", net.atlasauth.pca.doctor.Doctor.runDoctor(cfg, List.of("store"), null).get(0).status());
    }

    @Test void fileRecorderRoundTripsThroughTheParser() throws Exception {
        Path f = Files.createTempFile("hist", ".jsonl");
        try (Recorder.FileRecorder rec = new Recorder.FileRecorder(f, "p0")) {
            net.atlasauth.pca.storeconformance.Op a = rec.invoke("c0", "advance", "k", 3, 3);
            rec.complete(a, Boolean.TRUE);
            rec.invoke("c1", "consume", "k2", 5, 9); // never completes: pending
        }
        Kit.ParsedHistory h = Kit.parseHistory(Files.readString(f));
        assertEquals(2, h.ops.size());
        assertEquals(1, h.pending);
        assertEquals("true", h.ops.get(0).res);
        assertEquals("unknown", h.ops.get(1).res);
        assertEquals(0, h.torn);
    }
}
