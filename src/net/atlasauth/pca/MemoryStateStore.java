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
    private final Map<String, Map<String, Object>> budgets = new HashMap<>();

    @Override
    public synchronized Map<String, Object> budget(String key) {
        Map<String, Object> b = budgets.get(key);
        return b == null ? null : new java.util.LinkedHashMap<>(b);
    }

    private static boolean sameBudget(Map<String, Object> a, Map<String, Object> b) {
        if (a == null || b == null) return a == b;
        for (String k : new String[] {"B", "tau", "asOf"}) {
            Double x = Caveats.fin(a.get(k)), y = Caveats.fin(b.get(k));
            if (x == null ? y != null : !x.equals(y)) return false;
        }
        return true;
    }

    @Override
    public synchronized ClaimResult claim(String key, long counter, Map<String, Object> budgetBefore, Map<String, Object> budgetAfter) {
        if (key == null) return ClaimResult.replay(null);
        Long prev = last.get(key);
        if (prev != null && !(counter > prev)) return ClaimResult.replay(prev);
        if (!sameBudget(budgets.get(key), budgetBefore)) return ClaimResult.conflict();
        last.put(key, counter);
        if (budgetAfter != null) budgets.put(key, new java.util.LinkedHashMap<>(budgetAfter));
        return ClaimResult.claimed();
    }

    /** Seeds the trust budget of a stream (the resource server's own budget store, before any action). */
    public synchronized void putBudget(String key, Map<String, Object> budget) { budgets.put(key, new java.util.LinkedHashMap<>(budget)); }

    @Override
    public boolean processScoped() { return true; }

    @Override
    public boolean holdsBudgets() { return true; }

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
    public synchronized Long last(String key) { return last.get(key); } // claim never stores a null key
}
