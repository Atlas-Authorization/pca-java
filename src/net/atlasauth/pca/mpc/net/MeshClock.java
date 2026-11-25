package net.atlasauth.pca.mpc.net;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Time source for every DECISION the mesh makes by time (receive deadlines, connect deadline, dial retry window). The default
 * is the real clock; tests inject a virtual clock so an outcome never depends on how loaded the machine is.
 */
public interface MeshClock {
    /** Current time in milliseconds (monotonic; only differences matter). */
    long now();

    /** Run {@code fn} after {@code ms} of clock time; returns a handle for {@link #clearTimer}. */
    Object setTimer(Runnable fn, long ms);

    void clearTimer(Object handle);

    /** Real time (monotonic). */
    MeshClock WALL = new MeshClock() {
        private final ScheduledExecutorService sch = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "mesh-clock");
            t.setDaemon(true);
            return t;
        });

        @Override public long now() { return System.nanoTime() / 1_000_000L; }

        @Override public Object setTimer(Runnable fn, long ms) { return sch.schedule(fn, Math.max(0, ms), TimeUnit.MILLISECONDS); }

        @Override public void clearTimer(Object h) {
            if (h instanceof ScheduledFuture<?> f) f.cancel(false);
        }
    };
}
