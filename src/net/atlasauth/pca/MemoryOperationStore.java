package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** In-memory {@link OperationStore} for ONE process (tests, a single worker). Its records die with the process. */
public final class MemoryOperationStore implements OperationStore {
    private final Map<String, OperationRecord> records = new HashMap<>();

    @Override
    public synchronized OperationRecord create(OperationRecord record) {
        OperationRecord cur = records.get(record.id());
        if (cur != null) return cur;
        records.put(record.id(), record);
        return null;
    }

    @Override
    public synchronized OperationRecord get(String id) { return records.get(id); }

    @Override
    public synchronized boolean transition(String id, String from, OperationRecord next) {
        OperationRecord cur = records.get(id);
        if (cur == null || !from.equals(cur.state())) return false;
        records.put(id, next.with("id", id));
        return true;
    }

    @Override public boolean supportsListOpen() { return true; }

    @Override
    public synchronized List<OperationRecord> listOpen() {
        List<OperationRecord> out = new ArrayList<>();
        for (OperationRecord r : records.values())
            if (OperationRecord.PENDING.equals(r.state()) || OperationRecord.EXECUTING.equals(r.state())) out.add(r);
        return out;
    }

    @Override public boolean processLocal() { return true; }
}
