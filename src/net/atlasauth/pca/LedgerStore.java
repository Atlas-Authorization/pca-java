package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The persistence contract of a transparency log (the durable side of {@link StoredLedger}). Implement it over a database (an
 * append-only table with a unique index on the position gives {@code append} for free) or use {@link KvLedgerStore}.
 *
 * <p>{@code append} and {@code appendCheckpoint} are compare-and-swap on the current length: they succeed only at the exact position
 * the caller saw, all entries of a batch or none, so two writers can never assign one index twice and a log never has holes.
 * Committing the same batch again at the same position is a replay (idempotent, nothing written). Acknowledged writes survive a
 * crash or restart; a write in flight at the crash is applied entirely or not at all.
 */
public interface LedgerStore {
    /** The result of {@link #append}: {@code appended}, {@code replayed} (the same batch was already there) or {@code conflict}; {@code size} is the log length after. */
    final class AppendOutcome {
        public final String outcome;
        public final long size;
        public AppendOutcome(String outcome, long size) { this.outcome = outcome; this.size = size; }
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("outcome", outcome);
            m.put("size", StoreJs.num(size));
            return m;
        }
    }

    /** The result of {@link #appendCheckpoint}; {@code reason} only on a conflict. */
    final class CheckpointOutcome {
        public final String outcome;
        public final long count;
        public final String reason;
        public CheckpointOutcome(String outcome, long count, String reason) { this.outcome = outcome; this.count = count; this.reason = reason; }
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("outcome", outcome);
            m.put("count", StoreJs.num(count));
            if (reason != null) m.put("reason", reason);
            return m;
        }
    }

    /** Current number of entries. */
    long size();

    /** Commits {@code [from, to)}. Throws IllegalArgumentException (the reference's RangeError) when the range is not inside the log. */
    List<String> read(long from, long to);

    /**
     * Atomically append {@code commits} iff the log has exactly {@code expectedSize} entries (all or none). A batch that is already stored
     * at {@code expectedSize} is {@code replayed}. Every commit must be a non-empty string (IllegalArgumentException otherwise).
     */
    AppendOutcome append(long expectedSize, List<String> commits);

    /** Number of checkpoints. */
    long checkpointCount();

    /** Checkpoints {@code [from, count)} in order (copies). */
    List<Map<String, Object>> checkpoints(long from);

    /**
     * Atomically append a checkpoint {@code {sth, proof?}} iff exactly {@code expectedCount} exist. A store also enforces what needs no
     * cryptography: the checkpoint's size is within the log and not below the previous checkpoint's (equal only with the same root).
     * The same checkpoint at the same position is {@code replayed}.
     */
    CheckpointOutcome appendCheckpoint(long expectedCount, Map<String, Object> cp);
}
