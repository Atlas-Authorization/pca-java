package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;

import org.junit.jupiter.api.Test;

/** Pins reasons / rejection messages / canonical forms over the whole corpus (see {@link ReasonSnapshot}). */
public class SnapshotTest {
    static final int CHUNKS = 16;
    static Map<String, Object> core, adv;

    static synchronized void init() throws Exception {
        if (core == null) { core = ReasonSnapshot.loadJson("vectors.json"); adv = ReasonSnapshot.loadJson("vectors-adversarial.json.gz"); }
    }

    static void run(Map<String, Object> doc, String tag, int k, int step) throws Exception {
        init();
        Map<String, String> exp = ReasonSnapshot.load();
        for (Map.Entry<String, String> e : ReasonSnapshot.onBigStack(() -> ReasonSnapshot.compute(doc, tag, k, step)).entrySet()) {
            String key = ReasonSnapshot.esc(e.getKey());
            String want = exp.get(key);
            if (want == null) continue; // vector added after the snapshot was taken: not pinned
            assertEquals(want, e.getValue(), key);
        }
    }

    static void runInputs(int k) throws Exception {
        Map<String, String> exp = ReasonSnapshot.load();
        for (Map.Entry<String, String> e : ReasonSnapshot.onBigStack(() -> ReasonSnapshot.computeInputs(k, CHUNKS)).entrySet()) {
            String want = exp.get(e.getKey());
            if (want == null) continue;
            assertEquals(want, e.getValue(), e.getKey());
        }
    }
    @Test void i00() throws Exception { runInputs(0); }
    @Test void i01() throws Exception { runInputs(1); }
    @Test void i02() throws Exception { runInputs(2); }
    @Test void i03() throws Exception { runInputs(3); }
    @Test void i04() throws Exception { runInputs(4); }
    @Test void i05() throws Exception { runInputs(5); }
    @Test void i06() throws Exception { runInputs(6); }
    @Test void i07() throws Exception { runInputs(7); }
    @Test void i08() throws Exception { runInputs(8); }
    @Test void i09() throws Exception { runInputs(9); }
    @Test void i10() throws Exception { runInputs(10); }
    @Test void i11() throws Exception { runInputs(11); }
    @Test void i12() throws Exception { runInputs(12); }
    @Test void i13() throws Exception { runInputs(13); }
    @Test void i14() throws Exception { runInputs(14); }
    @Test void i15() throws Exception { runInputs(15); }

    @Test void coreVectors() throws Exception { run(core(), "core", 0, 1); }
    static Map<String, Object> core() throws Exception { init(); return core; }
    static Map<String, Object> adv() throws Exception { init(); return adv; }

    @Test void a00() throws Exception { run(adv(), "adv", 0, CHUNKS); }
    @Test void a01() throws Exception { run(adv(), "adv", 1, CHUNKS); }
    @Test void a02() throws Exception { run(adv(), "adv", 2, CHUNKS); }
    @Test void a03() throws Exception { run(adv(), "adv", 3, CHUNKS); }
    @Test void a04() throws Exception { run(adv(), "adv", 4, CHUNKS); }
    @Test void a05() throws Exception { run(adv(), "adv", 5, CHUNKS); }
    @Test void a06() throws Exception { run(adv(), "adv", 6, CHUNKS); }
    @Test void a07() throws Exception { run(adv(), "adv", 7, CHUNKS); }
    @Test void a08() throws Exception { run(adv(), "adv", 8, CHUNKS); }
    @Test void a09() throws Exception { run(adv(), "adv", 9, CHUNKS); }
    @Test void a10() throws Exception { run(adv(), "adv", 10, CHUNKS); }
    @Test void a11() throws Exception { run(adv(), "adv", 11, CHUNKS); }
    @Test void a12() throws Exception { run(adv(), "adv", 12, CHUNKS); }
    @Test void a13() throws Exception { run(adv(), "adv", 13, CHUNKS); }
    @Test void a14() throws Exception { run(adv(), "adv", 14, CHUNKS); }
    @Test void a15() throws Exception { run(adv(), "adv", 15, CHUNKS); }
}
