package net.atlasauth.pca.storeconformance;

/**
 * One connection / verifier instance talking to the shared backend. Implement whichever of the two operations you ship (and
 * override the matching {@code has...} method). Both are atomic across every client of the same backend, durable, and FAIL CLOSED
 * (throw when they cannot decide).
 */
public interface StoreClient {
    default boolean hasConsumeOnce() { return false; }
    default boolean hasAdvance() { return false; }

    /** True iff there is no live record for {@code key} (live = its stored horizon is &gt;= {@code nowMs}); then records {@code retainUntilMs}. */
    default boolean consumeOnce(String key, double retainUntilMs, double nowMs) throws Exception { throw new UnsupportedOperationException("consumeOnce"); }

    /** True iff {@code counter} is strictly greater than the stored value; then stores it. */
    default boolean advance(String streamKey, double counter) throws Exception { throw new UnsupportedOperationException("advance"); }

    /** Release the connection. The backend's state must survive it. */
    default void close() throws Exception {}
}
