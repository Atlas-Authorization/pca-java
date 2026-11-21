package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.storeconformance.Cli;
import org.junit.jupiter.api.Test;

/** The pca-state profile: the in-memory reference store passes, a check-then-act store is caught, and the CLI runs the profile. */
class PcaStateConformanceTest {
    private static PcaStateConformance.Adapter adapter(String name, StateStore store) {
        return new PcaStateConformance.Adapter() {
            @Override public String name() { return name; }
            @Override public StateStore open() { return store; }
        };
    }

    private static String status(StoreConformance.Report r, String test) {
        for (StoreConformance.TestResult t : r.results) if (t.test.equals(test)) return t.status;
        return null;
    }

    @Test void theReferenceStorePasses() {
        StoreConformance.Report r = PcaStateConformance.run(adapter("memory", new MemoryStateStore()), new PcaStateConformance.Options());
        assertTrue(r.ok(), r.render());
        assertEquals("pass", status(r, "one-instance"), r.render());
        assertEquals("pass", status(r, "retry-after-timeout"), r.render());
        assertEquals("skip", status(r, "instances"), r.render());
        assertEquals("skip", status(r, "processes"), r.render());
        assertEquals("skip", status(r, "crash-after-claim"), r.render());
    }

    /** A claim that reads, pauses and then writes: two copies of one proof are both admitted. */
    private static final class RacyStore implements StateStore {
        private final Map<String, Long> last = new HashMap<>();
        @Override public ClaimResult claim(String key, long counter) {
            Long prev;
            synchronized (last) { prev = last.get(key); }
            if (prev != null && counter <= prev) return ClaimResult.replay(prev);
            try { Thread.sleep(5); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            synchronized (last) { last.put(key, counter); }
            return ClaimResult.claimed();
        }
        @Override public boolean processScoped() { return false; }
    }

    @Test void aCheckThenActStoreIsCaught() {
        PcaStateConformance.Options o = new PcaStateConformance.Options();
        o.rounds = 3;
        StoreConformance.Report r = PcaStateConformance.run(adapter("racy", new RacyStore()), o);
        assertEquals("fail", status(r, "one-instance"), r.render());
        assertTrue(!r.ok(), r.render());
    }

    @Test void theCliRunsTheProfile() {
        List<String> out = new ArrayList<>(), err = new ArrayList<>();
        int code = Cli.main(List.of("--adapter", "builtin:in-memory", "--profile", "pca-state", "--rounds", "3"), out::add, err::add);
        assertEquals(0, code, String.join("\n", out) + String.join("\n", err));
        assertTrue(String.join("\n", out).contains("one-instance"));
    }
}
