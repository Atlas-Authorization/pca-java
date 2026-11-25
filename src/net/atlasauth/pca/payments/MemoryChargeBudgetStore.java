package net.atlasauth.pca.payments;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/** Single-process reference store; production needs a durable store with a conditional write. */
public final class MemoryChargeBudgetStore implements ChargeBudgetStore {
    private final Map<String, Record> m = new HashMap<>();

    @Override public synchronized Record get(String key) { return m.get(key); }

    @Override public synchronized boolean compareAndSet(String key, Object expected, Map<String, Object> budget) {
        Record cur = m.get(key);
        Object have = cur == null ? null : cur.version;
        if (!Objects.equals(have == null ? null : PayJs.num(have), expected == null ? null : PayJs.num(expected))) return false;
        m.put(key, new Record(budget, PayJs.jn((expected == null ? 0 : PayJs.num(expected)) + 1)));
        return true;
    }
}
