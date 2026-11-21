package net.atlasauth.pca.payments;

import java.util.Map;

/**
 * Durable cumulative-budget state with an atomic compare-and-set. {@code version} is opaque to the caller: {@code compareAndSet}
 * succeeds only when the stored version still equals {@code expected} (null = no record yet) and returns false otherwise.
 */
public interface ChargeBudgetStore {
    /** A stored budget and its version. */
    final class Record {
        public final Object budget;
        public final Object version;

        public Record(Object budget, Object version) {
            this.budget = budget;
            this.version = version;
        }
    }

    /** The record under {@code key}, or null when there is none. */
    Record get(String key);

    boolean compareAndSet(String key, Object expected, Map<String, Object> budget);
}
