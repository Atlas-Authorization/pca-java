package net.atlasauth.pca;

import java.util.Map;

/**
 * Where a mesh log witness keeps what it has cosigned. {@code save} MUST be durable and atomic: when it returns, a restarted witness
 * loads exactly this state. A witness that forgets across a restart can be walked back to cosign a fork. Synchronous on purpose:
 * {@code cosign} must not return a signature before the state behind it is on disk.
 *
 * <p>The state is the JSON object {@code {seen: [{head, rev_ids}]}}.
 */
public interface MeshWitnessStore {
    /** The last saved state (a copy), or null for a store that has never been written. Throws on corrupt data (never returns a partial state). */
    Map<String, Object> load();

    void save(Map<String, Object> state);
}
