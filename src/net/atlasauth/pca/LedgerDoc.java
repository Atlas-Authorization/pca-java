package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The pure transition functions of a ledger store: every reference store is these plus a lock. A document is the commits and the
 * checkpoints; {@link #appendToLedgerDoc} and {@link #checkpointToLedgerDoc} mutate it ONLY when they report {@code appended}.
 */
public final class LedgerDoc {
    public final List<String> commits = new ArrayList<>();
    public final List<Map<String, Object>> checkpoints = new ArrayList<>();

    public static LedgerDoc empty() { return new LedgerDoc(); }

    private static boolean isCommit(Object c) { return c instanceof String && !((String) c).isEmpty(); }

    /** The JSON form {@code {v:1, commits, checkpoints}}. */
    public Map<String, Object> toJson() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", StoreJs.num(1));
        m.put("commits", new ArrayList<Object>(commits));
        List<Object> cps = new ArrayList<>();
        for (Map<String, Object> c : checkpoints) cps.add(StoreJs.deepCopy(c));
        m.put("checkpoints", cps);
        return m;
    }

    /** Decode a stored document (null = empty). Fails closed with {@code store_corrupt}; the result shares nothing with {@code raw}. */
    public static LedgerDoc decode(Object raw) {
        if (raw == null) return empty();
        Map<String, Object> m = StoreJs.map(raw);
        if (m == null || !(m.get("v") instanceof Json.Num || m.get("v") instanceof Number) || !StoreJs.isInt(m.get("v")) || StoreJs.lng(m.get("v")) != 1
            || !(m.get("commits") instanceof List) || !(m.get("checkpoints") instanceof List)) throw new LedgerStoreError("store_corrupt", "ledger document has the wrong shape");
        LedgerDoc d = new LedgerDoc();
        for (Object c : (List<?>) m.get("commits")) {
            if (!isCommit(c)) throw new LedgerStoreError("store_corrupt", "ledger document has the wrong shape");
            d.commits.add((String) c);
        }
        for (Object c : (List<?>) m.get("checkpoints")) {
            Map<String, Object> cm = StoreJs.map(c);
            if (cm == null || StoreJs.map(cm.get("sth")) == null) throw new LedgerStoreError("store_corrupt", "malformed checkpoint entry");
            d.checkpoints.add(StoreJs.map(StoreJs.deepCopy(cm)));
        }
        return d;
    }

    private static void checkSafe(long v, String what) {
        if (v < 0 || v > 9007199254740991L) throw new IllegalArgumentException(what);
    }

    public static LedgerStore.AppendOutcome appendToLedgerDoc(LedgerDoc doc, long expectedSize, List<String> commits) {
        checkSafe(expectedSize, "append: expectedSize must be a non-negative safe integer");
        if (commits == null || commits.isEmpty()) throw new IllegalArgumentException("append: commits must be a non-empty array of non-empty strings");
        for (Object c : commits) if (!isCommit(c)) throw new IllegalArgumentException("append: commits must be a non-empty array of non-empty strings");
        long size = doc.commits.size();
        if (expectedSize < size) {
            boolean same = true;
            for (int i = 0; i < commits.size(); i++) {
                long at = expectedSize + i;
                if (at >= size || !doc.commits.get((int) at).equals(commits.get(i))) { same = false; break; }
            }
            return new LedgerStore.AppendOutcome(same ? "replayed" : "conflict", size);
        }
        if (expectedSize > size) return new LedgerStore.AppendOutcome("conflict", size);
        doc.commits.addAll(commits);
        return new LedgerStore.AppendOutcome("appended", doc.commits.size());
    }

    public static LedgerStore.CheckpointOutcome checkpointToLedgerDoc(LedgerDoc doc, long expectedCount, Map<String, Object> cp) {
        checkSafe(expectedCount, "appendCheckpoint: expectedCount must be a non-negative safe integer");
        long count = doc.checkpoints.size();
        if (expectedCount < count) {
            return StoreJs.jsonEq(doc.checkpoints.get((int) expectedCount), cp) ? new LedgerStore.CheckpointOutcome("replayed", count, null)
                : new LedgerStore.CheckpointOutcome("conflict", count, "another checkpoint holds that position");
        }
        if (expectedCount > count) return new LedgerStore.CheckpointOutcome("conflict", count, "the checkpoint position is ahead of the log");
        Map<String, Object> sth = cp == null ? null : StoreJs.map(cp.get("sth"));
        if (sth == null || !StoreJs.isInt(sth.get("size")) || StoreJs.lng(sth.get("size")) < 0 || !(sth.get("root") instanceof String)) {
            return new LedgerStore.CheckpointOutcome("conflict", count, "malformed checkpoint");
        }
        long size = StoreJs.lng(sth.get("size"));
        if (size > doc.commits.size()) return new LedgerStore.CheckpointOutcome("conflict", count, "the checkpoint is beyond the end of the log");
        Map<String, Object> last = count == 0 ? null : StoreJs.map(doc.checkpoints.get((int) count - 1).get("sth"));
        if (last != null) {
            Double ls = StoreJs.dbl(last.get("size")); // a stored size that is no number compares false both ways, as in the reference
            if (ls != null && (size < ls || (size == ls && !sth.get("root").equals(last.get("root"))))) {
                return new LedgerStore.CheckpointOutcome("conflict", count, "the checkpoint does not extend the previous one");
            }
        }
        doc.checkpoints.add(StoreJs.map(StoreJs.deepCopy(cp)));
        return new LedgerStore.CheckpointOutcome("appended", doc.checkpoints.size(), null);
    }
}
