package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The reference {@link UndoStore} over any {@link AtomicKv} (one document per record under {@code pca-undo/v1/<id>}, every write one atomic
 * read-modify-write). {@code durable} is declared by the caller because a kv cannot tell: true only over a persistent kv (for example
 * {@link PcaJdbcAtomicKv}), false over an in-memory one. {@link #list} scans every key (fine for one host's backlog); a database store indexes
 * (state, window_end). The kv must be able to list its keys ({@link AtomicKv#keys}).
 */
public final class KvUndoStore implements UndoStore {
    private static final String PREFIX = "pca-undo/v1/";
    private final AtomicKv kv;
    private final boolean durable;

    public KvUndoStore(AtomicKv kv, boolean durable) {
        if (kv == null) throw new Undo.UndoError("store_missing", "KvUndoStore needs an AtomicKv");
        this.kv = kv;
        this.durable = durable;
    }

    @Override public boolean durable() { return durable; }

    private static String key(Object id) {
        if (!Undo.idOk(id)) throw new Undo.UndoError("invalid", "an undo record id is a non-empty string without control characters");
        return PREFIX + id;
    }

    @Override
    public Map<String, Object> get(String id) {
        Map<String, Object> r = UndoStore.decodeRecord(kv.get(key(id)));
        return r == null ? null : UndoStore.copy(r);
    }

    @Override
    public CreateResult create(Map<String, Object> rec) {
        AtomicReference<Map<String, Object>> existing = new AtomicReference<>();
        kv.update(key(rec == null ? null : rec.get("id")), prev -> {
            Map<String, Object> cur = UndoStore.decodeRecord(prev);
            existing.set(cur);
            return cur != null ? null : UndoStore.copy(rec);
        });
        return existing.get() != null ? new CreateResult(false, UndoStore.copy(existing.get())) : new CreateResult(true, null);
    }

    @Override
    public boolean replace(String id, long expectedVer, Map<String, Object> next) {
        if (!id.equals(next.get("id"))) throw new Undo.UndoError("invalid", "replace: the record id cannot change");
        AtomicReference<Boolean> done = new AtomicReference<>(Boolean.FALSE);
        kv.update(key(id), prev -> {
            Map<String, Object> cur = UndoStore.decodeRecord(prev);
            boolean ok = cur != null && IntentJs.lng(cur.get("ver")) == expectedVer;
            done.set(ok);
            return ok ? UndoStore.copy(next) : null;
        });
        return done.get();
    }

    @Override
    public List<Map<String, Object>> list(Query q) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (String k : kv.keys()) {
            if (!k.startsWith(PREFIX)) continue;
            Map<String, Object> r = UndoStore.decodeRecord(kv.get(k));
            if (r != null && UndoStore.matches(r, q)) out.add(UndoStore.copy(r));
            if (q.limit != null && out.size() >= q.limit) break;
        }
        return out;
    }
}
