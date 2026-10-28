package net.atlasauth.pca;

/**
 * {@link OperationStore} over any {@link AtomicKv} (for example {@link PcaJdbcAtomicKv}: crash-safe and multi-process-safe).
 * {@code prefix} namespaces the keys. It has no {@code listOpen}; recover a known id with {@code Operations.recoverOperation}.
 */
public final class AtomicKvOperationStore implements OperationStore {
    private final AtomicKv kv;
    private final String prefix;
    private final boolean local;

    public AtomicKvOperationStore(AtomicKv kv) { this(kv, "pca-op:", false); }

    /** {@code processLocal}: true when the kv lives in this process only (for example {@link MemoryAtomicKv}). */
    public AtomicKvOperationStore(AtomicKv kv, String prefix, boolean processLocal) {
        if (kv == null) throw new IllegalArgumentException("kv");
        this.kv = kv;
        this.prefix = prefix == null ? "pca-op:" : prefix;
        this.local = processLocal;
    }

    @Override
    public OperationRecord create(OperationRecord record) {
        OperationRecord[] existing = new OperationRecord[1];
        kv.update(prefix + record.id(), prev -> {
            existing[0] = OperationRecord.of(prev);
            return existing[0] != null ? null : record.toMap();
        });
        return existing[0];
    }

    @Override
    public OperationRecord get(String id) { return OperationRecord.of(kv.get(prefix + id)); }

    @Override
    public boolean transition(String id, String from, OperationRecord next) {
        boolean[] done = new boolean[1];
        kv.update(prefix + id, prev -> {
            OperationRecord cur = OperationRecord.of(prev);
            done[0] = cur != null && from.equals(cur.state());
            return done[0] ? next.with("id", id).toMap() : null;
        });
        return done[0];
    }

    @Override public boolean processLocal() { return local; }
}
