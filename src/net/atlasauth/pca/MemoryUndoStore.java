package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A process-memory {@link UndoStore}: {@link #durable} is false, so a coordinator refuses it unless the caller says, for a test, that it accepts
 * losing every open window on restart. Never use it in production.
 */
public final class MemoryUndoStore implements UndoStore {
    private final Map<String, Map<String, Object>> m = new LinkedHashMap<>();

    @Override public boolean durable() { return false; }

    @Override
    public synchronized Map<String, Object> get(String id) {
        Map<String, Object> r = m.get(id);
        return r == null ? null : UndoStore.copy(r);
    }

    @Override
    public synchronized CreateResult create(Map<String, Object> rec) {
        if (rec == null || !Undo.idOk(rec.get("id"))) throw new Undo.UndoError("invalid", "an undo record id is a non-empty string without control characters");
        Map<String, Object> cur = m.get((String) rec.get("id"));
        if (cur != null) return new CreateResult(false, UndoStore.copy(cur));
        m.put((String) rec.get("id"), UndoStore.copy(rec));
        return new CreateResult(true, null);
    }

    @Override
    public synchronized boolean replace(String id, long expectedVer, Map<String, Object> next) {
        if (!id.equals(next.get("id"))) throw new Undo.UndoError("invalid", "replace: the record id cannot change");
        Map<String, Object> cur = m.get(id);
        if (cur == null || IntentJs.lng(cur.get("ver")) != expectedVer) return false;
        m.put(id, UndoStore.copy(next));
        return true;
    }

    @Override
    public synchronized List<Map<String, Object>> list(Query q) {
        List<Map<String, Object>> hits = new ArrayList<>();
        for (Map<String, Object> r : m.values()) if (UndoStore.matches(r, q)) hits.add(UndoStore.copy(r));
        return UndoStore.sortedCopies(hits, q.limit);
    }
}
