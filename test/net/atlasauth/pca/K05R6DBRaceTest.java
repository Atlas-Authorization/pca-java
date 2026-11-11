package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * 0.5 dead-minion kill (round 6, tag DB): {@link StoreConformance#race} starts exactly one thread per slot, all released together by
 * the gate. A loop that starts one thread too many or too few leaves the gate un-tripped (each parked thread waits up to 60 s), so
 * the race call does not return within a few seconds; the check runs the call on a daemon thread and fails fast on the join.
 */
public class K05R6DBRaceTest {

    @Test void raceStartsExactlyOneThreadPerSlotAndTripsTheGate() throws Exception {
        for (int n : new int[] {1, 2, 3}) {
            CyclicBarrier gate = new CyclicBarrier(n);
            AtomicInteger calls = new AtomicInteger();
            Object[][] res = new Object[1][];
            Thread t = new Thread(() -> {
                try {
                    res[0] = StoreConformance.race(gate, n, i -> {
                        calls.incrementAndGet();
                        return i * 10;
                    });
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            t.setDaemon(true);
            t.start();
            t.join(5000);
            assertFalse(t.isAlive(), "race must return once its n threads passed the gate (n=" + n + ")");
            assertEquals(n, calls.get(), "one call per slot (n=" + n + ")");
            assertEquals(0, gate.getNumberWaiting(), "no thread left parked at the gate (n=" + n + ")");
            assertEquals(n, res[0].length);
            for (int i = 0; i < n; i++) assertEquals(Integer.valueOf(i * 10), res[0][i]);
        }
    }
}
