package net.atlasauth.pca;

/**
 * The optional read side of a {@link StateStore}: the last admitted counter of a stream. It binds an escalation answer to
 * the holder's history; a store without it cannot admit an answered escalation (the decision stays {@code escalate}).
 * {@link MemoryStateStore} and {@link PcaJdbcStateStore} implement it.
 */
public interface LastStore {
    /** The highest counter admitted for {@code key}, or null when none yet. Throws an unchecked exception when it cannot tell. */
    Long last(String key);
}
