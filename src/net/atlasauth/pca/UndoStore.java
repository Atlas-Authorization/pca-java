package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The persistence contract of the undo ledger: one record per action (a map with {@code id}, {@code v}, {@code state}, {@code ver},
 * {@code window_end}, {@code receipts}, optional {@code grant_ref} / {@code bond_ref}, as {@link Undo#transition} reads them). Implement it over
 * a database (a row per record with a unique id and a version column: {@code UPDATE ... WHERE id = ? AND ver = ?}) or use {@link KvUndoStore}.
 * Every method either answers or throws; a store that cannot decide must throw (the coordinator then reports the outcome as unknown).
 */
public interface UndoStore {
    /** True ONLY when acknowledged writes survive a restart or crash. A coordinator refuses a store that does not say so. */
    boolean durable();

    /** The record, or null. The result is a copy. */
    Map<String, Object> get(String id);

    /** Atomically insert the record if none with this id exists; otherwise the stored one comes back unchanged. */
    CreateResult create(Map<String, Object> record);

    /** Atomically replace the record iff its stored {@code ver} is {@code expectedVer}. */
    boolean replace(String id, long expectedVer, Map<String, Object> next);

    /** The records matching the query, in id order. */
    List<Map<String, Object>> list(Query q);

    /** The answer of {@link #create}: {@code created}, else the {@code record} already stored. */
    final class CreateResult {
        public final boolean created;
        public final Map<String, Object> record;
        public CreateResult(boolean created, Map<String, Object> record) { this.created = created; this.record = record; }
    }

    /** A record query: the state is required; the rest narrow it. */
    final class Query {
        public final String state;
        /** Only records whose window ended at or before this time (the finalize sweep); null: any. */
        public Long windowEndedBy;
        public String grantRef, bondRef;
        /** At most this many records; null: all. */
        public Integer limit;
        public Query(String state) { this.state = state; }
    }

    /** True iff {@code r} matches {@code q}. */
    static boolean matches(Map<String, Object> r, Query q) {
        if (!q.state.equals(r.get("state"))) return false;
        if (q.windowEndedBy != null && !(IntentJs.lng(r.get("window_end")) <= q.windowEndedBy)) return false;
        if (q.grantRef != null && !q.grantRef.equals(r.get("grant_ref"))) return false;
        return q.bondRef == null || q.bondRef.equals(r.get("bond_ref"));
    }

    /** A deep copy (numbers normalised), so a caller can never reach into a store's state. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> copy(Map<String, Object> r) { return (Map<String, Object>) IntentJs.normalize(r); }

    /** True iff {@code s} is a usable store. */
    static boolean isUndoStore(Object s) { return s instanceof UndoStore; }

    /** A well-formed stored record: version 1, a good id, a known state, a safe-integer {@code ver} and a receipt list. */
    static Map<String, Object> decodeRecord(Object raw) {
        if (raw == null) return null;
        if (!(raw instanceof Map)) throw new Undo.UndoError("store_corrupt", "an undo record has the wrong shape");
        @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) raw;
        if (!IntentJs.isInt(m.get("v")) || IntentJs.lng(m.get("v")) != 1 || !Undo.idOk(m.get("id")) || !Undo.STATES.contains(m.get("state"))
            || !IntentJs.isInt(m.get("ver")) || !(m.get("receipts") instanceof List)) throw new Undo.UndoError("store_corrupt", "an undo record has the wrong shape");
        return m;
    }

    static List<Map<String, Object>> sortedCopies(List<Map<String, Object>> in, Integer limit) {
        List<Map<String, Object>> out = new ArrayList<>(in);
        out.sort((a, b) -> ((String) a.get("id")).compareTo((String) b.get("id")));
        if (limit != null && out.size() > limit) out = new ArrayList<>(out.subList(0, limit));
        return out;
    }
}
