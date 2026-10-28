package net.atlasauth.pca;

/**
 * The replay store {@link Authorize#authorize} consumes counters through (0.5): ONE atomic operation of your backend.
 *
 * <p>{@code claim(key, counter)}: if a counter is stored for {@code key} and {@code counter} is not strictly greater,
 * return {@code ClaimResult.replay(stored)}; otherwise store {@code counter} and return {@code ClaimResult.claimed()}.
 * A claim that cannot decide must return a non-ok result, null, or throw: {@code authorize} then denies (fail closed).
 * {@link MemoryStateStore} is the in-process reference, {@link PcaJdbcStateStore} the durable one.
 */
@FunctionalInterface
public interface StateStore {
    ClaimResult claim(String key, long counter);

    /**
     * Consume {@code key} once, remembered at least until {@code retainUntilMs} (inclusive: a record is live while
     * {@code retainUntilMs >= nowMs}). True iff this call is the first with no live record; the horizon kept is the maximum
     * seen. Throws {@link IllegalArgumentException} (never returns true) when the key is empty or {@code retainUntilMs <
     * nowMs}, leaving nothing behind. The default falls back to a permanent {@code claim(key, 1)}: override it so slots expire.
     */
    default boolean consumeOnce(String key, long retainUntilMs, long nowMs) {
        if (key == null || key.isEmpty() || retainUntilMs < nowMs) throw new IllegalArgumentException("consumeOnce: invalid key or retention horizon");
        ClaimResult r = claim(key, 1L);
        if (r == null) throw new IllegalStateException("consumeOnce: the store answered null (fail closed)");
        return r.ok;
    }

    /** What {@link StateStore#claim} returns. {@code ok} is true only when THIS call consumed the counter. */
    final class ClaimResult {
        public final boolean ok;
        /** The counter already stored for the key when the claim was refused (null when unknown or ok). */
        public final Long lastCounter;

        public ClaimResult(boolean ok, Long lastCounter) {
            this.ok = ok;
            this.lastCounter = lastCounter;
        }

        /** This call consumed the counter. */
        public static ClaimResult claimed() { return new ClaimResult(true, null); }

        /** Refused: {@code last} (nullable) is the counter already stored for the key. */
        public static ClaimResult replay(Long last) { return new ClaimResult(false, last); }

        @Override public boolean equals(Object o) {
            return o instanceof ClaimResult && ((ClaimResult) o).ok == ok && java.util.Objects.equals(((ClaimResult) o).lastCounter, lastCounter);
        }
        @Override public int hashCode() { return java.util.Objects.hash(ok, lastCounter); }
        @Override public String toString() { return "ClaimResult{ok=" + ok + ", lastCounter=" + lastCounter + "}"; }
    }
}
