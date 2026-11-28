package net.atlasauth.pca;

import java.util.Map;

/**
 * A durable {@link MeshWitnessStore} over an {@link AtomicKv} (for example {@link PcaJdbcAtomicKv}): the state is one document with a digest.
 * {@code save} returns only after the kv acknowledged the write; {@code load} refuses damaged or edited content (it throws, so a witness
 * never starts empty over it).
 */
public final class KvMeshWitnessStore implements MeshWitnessStore {
    public static final String DOC_KEY = "pca-mesh-witness/v1";
    private final AtomicKv kv;
    private final String key;

    public KvMeshWitnessStore(AtomicKv kv) { this(kv, DOC_KEY); }

    public KvMeshWitnessStore(AtomicKv kv, String key) {
        if (kv == null) throw new IllegalArgumentException("KvMeshWitnessStore needs an AtomicKv");
        this.kv = kv;
        this.key = key;
    }

    @Override public Map<String, Object> load() {
        Object doc = kv.get(key);
        return doc == null ? null : MeshWitnessDoc.state(doc, "KvMeshWitnessStore: the stored state");
    }

    @Override public void save(Map<String, Object> state) { kv.set(key, MeshWitnessDoc.wrap(state)); }
}
