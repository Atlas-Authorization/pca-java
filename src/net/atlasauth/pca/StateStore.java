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
     * True when this store keeps trust budgets ({@link #budget}, and {@link #claim(String, long, java.util.Map, java.util.Map)} moves them atomically with
     * the counter). Only such a store may seed a fresh stream with the grant's bMax: seeding where the debit cannot be kept would hand every request a
     * full budget (fail-open), so a store that holds none leaves the stream deny-metered unless the host supplies a budget in the context.
     */
    default boolean holdsBudgets() { return false; }

    /**
     * The trust budget {@code {B, tau, asOf}} stored for {@code key} (the same key as the counter), or null. The default holds none: a
     * store that cannot keep budgets leaves the guard deny-metered (B = 0) unless the host supplies a budget in the context.
     */
    default java.util.Map<String, Object> budget(String key) { return null; }

    /**
     * {@link #claim(String, long)} that also moves the trust budget in the same atomic step: when the stored budget differs from
     * {@code budgetBefore} (both absent counts as equal) nothing is consumed and {@link ClaimResult#conflict()} is returned; else the
     * counter is stored together with {@code budgetAfter} (null keeps the stored budget). The default consumes the counter alone.
     */
    default ClaimResult claim(String key, long counter, java.util.Map<String, Object> budgetBefore, java.util.Map<String, Object> budgetAfter) {
        return claim(key, counter);
    }

    /**
     * True when the state lives in this process only ({@link MemoryStateStore}): one PCActn would then replay once per instance, so a guard
     * declared {@code multiInstance} refuses it. Default false (a shared store: a database or a cache all instances use).
     */
    default boolean processScoped() { return false; }

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
        /** True when the claim was refused because the stored trust budget moved since it was read (nothing consumed; retry). */
        public final boolean conflict;

        public ClaimResult(boolean ok, Long lastCounter) {
            this(ok, lastCounter, false);
        }

        private ClaimResult(boolean ok, Long lastCounter, boolean conflict) {
            this.ok = ok;
            this.lastCounter = lastCounter;
            this.conflict = conflict;
        }

        /** Refused: the stored trust budget is not the one the caller read. */
        public static ClaimResult conflict() { return new ClaimResult(false, null, true); }

        /** This call consumed the counter. */
        public static ClaimResult claimed() { return new ClaimResult(true, null); }

        /** Refused: {@code last} (nullable) is the counter already stored for the key. */
        public static ClaimResult replay(Long last) { return new ClaimResult(false, last); }

        @Override public boolean equals(Object o) {
            return o instanceof ClaimResult && ((ClaimResult) o).ok == ok && ((ClaimResult) o).conflict == conflict
                && java.util.Objects.equals(((ClaimResult) o).lastCounter, lastCounter);
        }
        @Override public int hashCode() { return conflict ? java.util.Objects.hash(ok, lastCounter, true) : java.util.Objects.hash(ok, lastCounter); }
        @Override public String toString() { return "ClaimResult{ok=" + ok + ", lastCounter=" + lastCounter + "}"; }
    }
}
