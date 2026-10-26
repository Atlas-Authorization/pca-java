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
