package net.atlasauth.pca;

import java.util.Map;
import java.util.TreeMap;
import net.atlasauth.pca.mpc.net.MeshClock;

/** A virtual clock: time moves only when the test says so. Timers fire in order of due time (then creation) during {@link #advance}. */
final class ManualClock implements MeshClock {
    private record Timer(long due, Runnable fn) {}

    private long t;
    private long seq;
    private final Map<Long, Timer> timers = new TreeMap<>();

    @Override public synchronized long now() { return t; }

    @Override public synchronized Object setTimer(Runnable fn, long ms) {
        long id = ++seq;
        timers.put(id, new Timer(t + ms, fn));
        return id;
    }

    @Override public synchronized void clearTimer(Object h) { timers.remove(h); }

    synchronized int pending() { return timers.size(); }

    /** Advance by {@code ms}, firing every timer that falls due (earliest first). Timers run outside the monitor. */
    void advance(long ms) {
        long target;
        synchronized (this) { target = t + ms; }
        for (;;) {
            Runnable fn;
            synchronized (this) {
                Map.Entry<Long, Timer> best = null;
                for (Map.Entry<Long, Timer> e : timers.entrySet()) {
                    if (e.getValue().due() <= target && (best == null || e.getValue().due() < best.getValue().due())) best = e;
                }
                if (best == null) {
                    t = target;
                    return;
                }
                timers.remove(best.getKey());
                t = Math.max(t, best.getValue().due());
                fn = best.getValue().fn();
            }
            fn.run();
        }
    }
}
