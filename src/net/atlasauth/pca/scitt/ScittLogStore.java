package net.atlasauth.pca.scitt;

import java.util.List;

/**
 * Durable, append-only storage for a transparency log. {@link #append} is atomic: it succeeds only when the log still has exactly
 * {@code expectedSize} entries (a compare-and-set, so two writers cannot both take the same index) and stores the entry and the new
 * subtree hashes together, or none of them. Entries and nodes are immutable once written.
 */
public interface ScittLogStore {
    /** The hash of the complete subtree at {@code level} covering leaves [index * 2^level, (index + 1) * 2^level). */
    final class StoredNode {
        public final long level;
        public final long index;
        public final byte[] hash;

        public StoredNode(long level, long index, byte[] hash) {
            this.level = level;
            this.index = index;
            this.hash = hash;
        }
    }

    long size();

    /** The entry at {@code index}, or null when absent. Returns a copy. */
    byte[] getEntry(long index);

    /** The subtree hash, or null when absent. Returns a copy. */
    byte[] getNode(long level, long index);

    boolean append(long expectedSize, byte[] entry, List<StoredNode> nodes);
}
