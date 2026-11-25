package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The reference {@link LedgerStore}: the whole log is one document in an {@link AtomicKv}, so every write is one atomic
 * read-modify-write. Over {@link PcaJdbcAtomicKv} it is durable and safe across processes; over {@link MemoryAtomicKv} it is the
 * in-process variant (tests only).
 *
 * <p>LIMIT: the document is rewritten on every write; a production log lives in a database with a unique index on the position.
 */
public final class KvLedgerStore implements LedgerStore {
    public static final String DOC_KEY = "pca-ledger-store/v1";
    private final AtomicKv kv;
    private final String key;

    public KvLedgerStore(AtomicKv kv) { this(kv, DOC_KEY); }

    public KvLedgerStore(AtomicKv kv, String key) {
        if (kv == null) throw new LedgerStoreError("store_missing", "KvLedgerStore needs an AtomicKv");
        this.kv = kv;
        this.key = key;
    }

    private LedgerDoc doc() { return LedgerDoc.decode(kv.get(key)); }

    @Override public long size() { return doc().commits.size(); }

    @Override public List<String> read(long from, long to) {
        LedgerDoc d = doc();
        if (from < 0 || from > to || to > d.commits.size()) throw new IllegalArgumentException("read: range is not inside the log");
        return new ArrayList<>(d.commits.subList((int) from, (int) to));
    }

    @Override public AppendOutcome append(long expectedSize, List<String> commits) {
        AppendOutcome[] out = new AppendOutcome[1];
        kv.update(key, prev -> {
            LedgerDoc d = LedgerDoc.decode(prev);
            out[0] = LedgerDoc.appendToLedgerDoc(d, expectedSize, commits);
            return "appended".equals(out[0].outcome) ? d.toJson() : null;
        });
        return out[0];
    }

    @Override public long checkpointCount() { return doc().checkpoints.size(); }

    @Override public List<Map<String, Object>> checkpoints(long from) {
        LedgerDoc d = doc();
        if (from < 0 || from > d.checkpoints.size()) throw new IllegalArgumentException("checkpoints: from is not inside the list");
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> c : d.checkpoints.subList((int) from, d.checkpoints.size())) out.add(StoreJs.map(StoreJs.deepCopy(c)));
        return out;
    }

    @Override public CheckpointOutcome appendCheckpoint(long expectedCount, Map<String, Object> cp) {
        CheckpointOutcome[] out = new CheckpointOutcome[1];
        kv.update(key, prev -> {
            LedgerDoc d = LedgerDoc.decode(prev);
            out[0] = LedgerDoc.checkpointToLedgerDoc(d, expectedCount, cp);
            return "appended".equals(out[0].outcome) ? d.toJson() : null;
        });
        return out[0];
    }
}
