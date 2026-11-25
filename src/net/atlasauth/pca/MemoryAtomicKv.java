package net.atlasauth.pca;

import java.util.HashMap;
import java.util.Map;
import java.util.function.UnaryOperator;

/** In-process {@link AtomicKv} (one lock). Correct for ONE process only; its values die with the process. */
public final class MemoryAtomicKv implements AtomicKv {
    private final Map<String, Object> map = new HashMap<>();

    @Override
    public synchronized Object get(String key) { return map.get(key); }

    @Override
    public synchronized void set(String key, Object value) {
        map.compute(key, (k, v) -> value); // a null value removes the key
    }

    @Override
    public synchronized Object update(String key, UnaryOperator<Object> fn) {
        Object next = fn.apply(map.get(key));
        if (next != null) map.put(key, next);
        return map.get(key);
    }
}
