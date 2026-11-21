package net.atlasauth.pca;

import java.util.Map;

/** In-process {@link MeshWitnessStore}: a test double, and the default when no store is given. It does not survive a restart. */
public final class MemoryMeshWitnessStore implements MeshWitnessStore {
    private String state;

    @Override public synchronized Map<String, Object> load() {
        return state == null ? null : StoreJs.map(Json.parseLenient(state));
    }

    @Override public synchronized void save(Map<String, Object> st) { this.state = Json.canonicalize(st); }
}
