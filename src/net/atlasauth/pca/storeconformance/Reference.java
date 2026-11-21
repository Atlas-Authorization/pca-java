package net.atlasauth.pca.storeconformance;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;
import net.atlasauth.pca.MemoryStateStore;

/**
 * Reference adapters. The GOOD one must pass the kit; the BAD ones are positive controls the kit MUST flag (a checker that passes
 * everything is worthless). Each bad adapter reproduces one real mistake from the replay-store verification work.
 */
public final class Reference {
    private Reference() {}

    private static void requireFiniteHorizon(double retainUntilMs, double nowMs) {
        if (!(Double.isFinite(nowMs) && Double.isFinite(retainUntilMs) && retainUntilMs >= nowMs)) throw new IllegalArgumentException("consumeOnce: retainUntilMs is before nowMs");
    }

    /** GOOD for ONE process: the library's in-memory state store. Not durable (declared), not shared between processes. */
    public static StoreAdapter inMemoryAdapter() {
        MemoryStateStore store = new MemoryStateStore();
        return new StoreAdapter() {
            @Override public String name() { return "in-memory (MemoryStateStore)"; }
            @Override public Capabilities capabilities() { return new Capabilities().durable(false); }
            @Override public StoreClient open() {
                return new StoreClient() {
                    @Override public boolean hasConsumeOnce() { return true; }
                    @Override public boolean hasAdvance() { return true; }
                    @Override public boolean consumeOnce(String key, double retainUntilMs, double nowMs) { requireFiniteHorizon(retainUntilMs, nowMs); return store.consumeOnce(key, (long) retainUntilMs, (long) nowMs); }
                    @Override public boolean advance(String streamKey, double counter) { return store.claim(streamKey, (long) counter).ok; }
                };
            }
        };
    }

    private static void yieldTurn() {
        Thread.yield();
        try { Thread.sleep(1); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    /** BAD: read, then write after a pause (no transaction / no compare-and-set). Two clients both read "absent". */
    public static StoreAdapter readThenWriteAdapter() {
        Map<String, Double> seen = new java.util.concurrent.ConcurrentHashMap<>();
        Map<String, Double> counters = new java.util.concurrent.ConcurrentHashMap<>();
        return new StoreAdapter() {
            @Override public String name() { return "BAD read-then-write (pause between check and set)"; }
            @Override public Capabilities capabilities() { return new Capabilities().durable(false); }
            @Override public StoreClient open() {
                return new StoreClient() {
                    @Override public boolean hasConsumeOnce() { return true; }
                    @Override public boolean hasAdvance() { return true; }
                    @Override public boolean consumeOnce(String k, double r, double now) {
                        Double until = seen.get(k);
                        yieldTurn();
                        if (until != null && !(Double.isFinite(now) && until < now)) return false;
                        seen.put(k, r);
                        return true;
                    }
                    @Override public boolean advance(String k, double c) {
                        Double last = counters.get(k);
                        yieldTurn();
                        if (last != null && !(c > last)) return false;
                        counters.put(k, c);
                        return true;
                    }
                };
            }
        };
    }

    /** BAD: claims durability but keeps state in process memory, so a restart forgets every consumed key and counter. */
    public static StoreAdapter volatileAdapter() {
        MemoryStateStore[] store = {new MemoryStateStore()};
        return new StoreAdapter() {
            @Override public String name() { return "BAD volatile (state lost on restart)"; }
            @Override public Capabilities capabilities() { return new Capabilities().durable(true); }
            @Override public boolean hasRestart() { return true; }
            @Override public void restart() { store[0] = new MemoryStateStore(); }
            @Override public StoreClient open() {
                return new StoreClient() {
                    @Override public boolean hasConsumeOnce() { return true; }
                    @Override public boolean hasAdvance() { return true; }
                    @Override public boolean consumeOnce(String key, double r, double n) { requireFiniteHorizon(r, n); return store[0].consumeOnce(key, (long) r, (long) n); }
                    @Override public boolean advance(String key, double c) { return store[0].claim(key, (long) c).ok; }
                };
            }
        };
    }

    /** BAD: a bounded cache that evicts the oldest record when full, LIVE or not (capacity eviction / early prune). */
    public static StoreAdapter evictingAdapter(int capacity) {
        Map<String, Double> seen = new LinkedHashMap<>();
        Map<String, Double> counters = new LinkedHashMap<>();
        return new StoreAdapter() {
            private void evict(Map<String, Double> m) {
                while (m.size() > capacity) { Iterator<String> it = m.keySet().iterator(); it.next(); it.remove(); }
            }
            @Override public String name() { return "BAD evicting cache (capacity " + capacity + ", evicts live records)"; }
            @Override public Capabilities capabilities() { return new Capabilities().durable(false); }
            @Override public StoreClient open() {
                return new StoreClient() {
                    @Override public boolean hasConsumeOnce() { return true; }
                    @Override public boolean hasAdvance() { return true; }
                    @Override public boolean consumeOnce(String k, double r, double now) {
                        synchronized (seen) {
                            Double until = seen.get(k);
                            if (until != null && !(Double.isFinite(now) && until < now)) return false;
                            seen.put(k, r);
                            evict(seen);
                            return true;
                        }
                    }
                    @Override public boolean advance(String k, double c) {
                        synchronized (counters) {
                            Double last = counters.get(k);
                            if (last != null && !(c > last)) return false;
                            counters.put(k, c);
                            evict(counters);
                            return true;
                        }
                    }
                };
            }
        };
    }

    /** BAD: a counter that accepts a value EQUAL to the last one ({@code >=} instead of {@code >}), so one counter is accepted twice. */
    public static StoreAdapter nonStrictCounterAdapter() {
        Map<String, Double> counters = new HashMap<>();
        return new StoreAdapter() {
            @Override public String name() { return "BAD non-strict counter (accepts an equal value)"; }
            @Override public Capabilities capabilities() { return new Capabilities().durable(false).consumeOnce(false); }
            @Override public StoreClient open() {
                return new StoreClient() {
                    @Override public boolean hasAdvance() { return true; }
                    @Override public boolean advance(String k, double c) {
                        synchronized (counters) {
                            Double last = counters.get(k);
                            if (last != null && c < last) return false;
                            counters.put(k, c);
                            return true;
                        }
                    }
                };
            }
        };
    }

    /**
     * Built-in adapters by name ({@code --adapter builtin:<name>}); each takes the {@code --option k=v} pairs. shortcut: the reference's
     * {@code durable-file} adapter (a crash-safe multi-process file store) is not here, upgrade by writing one over java.nio file locks.
     */
    public static final Map<String, Function<Map<String, String>, StoreAdapter>> REFERENCE_ADAPTERS;
    static {
        Map<String, Function<Map<String, String>, StoreAdapter>> m = new LinkedHashMap<>();
        m.put("in-memory", o -> inMemoryAdapter());
        m.put("bad-read-then-write", o -> readThenWriteAdapter());
        m.put("bad-volatile", o -> volatileAdapter());
        m.put("bad-evicting", o -> evictingAdapter(o.get("capacity") == null ? 64 : (int) Double.parseDouble(o.get("capacity"))));
        m.put("bad-non-strict-counter", o -> nonStrictCounterAdapter());
        REFERENCE_ADAPTERS = java.util.Collections.unmodifiableMap(m);
    }

    /**
     * Load a store adapter from a built-in name ({@code builtin:<name>}) or a class name: a {@link StoreAdapter} with a public no-argument
     * constructor, or a {@code Function<Map<String,String>, StoreAdapter>} factory.
     */
    @SuppressWarnings("unchecked")
    public static StoreAdapter loadAdapter(String spec, Map<String, String> options) throws Exception {
        Object made;
        if (spec.startsWith("builtin:")) {
            String name = spec.substring("builtin:".length());
            Function<Map<String, String>, StoreAdapter> f = REFERENCE_ADAPTERS.get(name);
            if (f == null) throw new IllegalArgumentException("unknown built-in adapter '" + name + "' (known: " + String.join(", ", REFERENCE_ADAPTERS.keySet()) + ")");
            made = f.apply(options);
        } else {
            Object inst = Class.forName(spec).getDeclaredConstructor().newInstance();
            made = inst instanceof Function ? ((Function<Map<String, String>, Object>) inst).apply(options) : inst;
        }
        if (!(made instanceof StoreAdapter) || ((StoreAdapter) made).name() == null) {
            throw new IllegalArgumentException(spec + ": does not name a store adapter (a StoreAdapter with a name and an open() method, or a factory returning one)");
        }
        return (StoreAdapter) made;
    }
}
