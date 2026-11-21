package net.atlasauth.pca.revoke;

import java.util.List;

/**
 * The pluggable backing store for a {@link RevocationRegistry}. Point kinds (cap / holder / issuer) are addressed by
 * (kind, value); prefix entries are scanned via {@link #all()}. Implementations must be thread-safe: after add returns, every
 * reader sees the entry.
 */
public interface RevocationStore {
    /** Insert or replace the entry at its (kind, value) key. */
    void add(RevocationEntry entry);

    /** Remove the entry at (kind, value); true when something was removed. */
    boolean remove(String kind, String value);

    /** The entry at (kind, value), or null. */
    RevocationEntry get(String kind, String value);

    /** Every stored entry (a snapshot copy). */
    List<RevocationEntry> all();

    /** Drop every entry. */
    void clear();
}
