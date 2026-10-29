package net.atlasauth.pca;

import java.util.HashMap;
import java.util.Map;

/**
 * In-process reference {@link StateStore} (one lock). Correct for ONE process only: several workers need
 * {@link PcaJdbcStateStore} or your own database.
 */
public final class MemoryStateStore implements StateStore, LastStore {
    private final Map<String, Long> last = new HashMap<>();
    private final Map<String, Long> retain = new HashMap<>();

    @Override
    public synchronized ClaimResult claim(String key, long counter) {
        if (key == null) return ClaimResult.replay(null);
        Long prev = last.get(key);
        if (prev != null && !(counter > prev)) return ClaimResult.replay(prev);
        last.put(key, counter);
        return ClaimResult.claimed();
    }

    @Override
    public synchronized boolean consumeOnce(String key, long retainUntilMs, long nowMs) {
        if (key == null || key.isEmpty() || retainUntilMs < nowMs) throw new IllegalArgumentException("consumeOnce: invalid key or retention horizon");
        retain.values().removeIf(u -> u < nowMs); // prune what is no longer live
        Long until = retain.get(key);
        retain.put(key, Math.max(retainUntilMs, until == null ? 0L : until));
        return until == null;
    }

    @Override
    public synchronized Long last(String key) { return key == null ? null : last.get(key); }
}
