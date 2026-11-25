package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * The reference {@link BudgetLedger}: one document per key in an {@link AtomicKv}, so every operation is one atomic read-modify-write.
 * {@code durable} is declared by the caller because a kv cannot tell: pass true only for a persistent one ({@link PcaJdbcAtomicKv}); over
 * {@link MemoryAtomicKv} it must be false. LIMIT: one document per key, rewritten per write; a production ledger is a database
 * row-per-event with a unique index on (key, id) and a version column (reuse {@link BudgetDoc} inside its transaction).
 */
public final class KvBudgetLedger implements BudgetLedger {
    static final String PREFIX = "pca-budget-ledger/v1/";
    private final AtomicKv kv;
    private final boolean durable;

    public KvBudgetLedger(AtomicKv kv, boolean durable) {
        if (kv == null) throw new BudgetLedgerError("store_missing", "KvBudgetLedger needs an AtomicKv");
        this.kv = kv;
        this.durable = durable;
    }

    @Override public boolean durable() { return durable; }

    private String k(String key) {
        if (!BudgetDoc.idOk(key)) throw new IllegalArgumentException("a ledger key is a non-empty string without control characters");
        return PREFIX + key;
    }

    private <T> T txn(String key, Function<BudgetDoc, T> fn, Predicate<T> writes) {
        Object[] out = new Object[1];
        kv.update(k(key), prev -> {
            BudgetDoc d = BudgetDoc.decode(prev);
            @SuppressWarnings("unchecked") T r = fn.apply(d);
            out[0] = r;
            return writes.test(r) ? d.encode() : null;
        });
        @SuppressWarnings("unchecked") T r = (T) out[0];
        return r;
    }

    @Override public Snapshot snapshot(String key) {
        BudgetDoc d = BudgetDoc.decode(kv.get(k(key)));
        List<Map<String, Object>> evs = new ArrayList<>();
        for (Map<String, Object> e : d.events) evs.add(StoreJs.map(StoreJs.deepCopy(e)));
        return new Snapshot(d.ver, evs);
    }

    @Override public ReserveOutcome reserve(String key, ReserveRequest req) { return txn(key, d -> d.reserveInDoc(req), r -> "reserved".equals(r.outcome)); }

    @Override public SettleOutcome start(String key, String id) { return txn(key, d -> d.startInDoc(id), r -> "settled".equals(r.outcome)); }

    @Override public SettleOutcome commit(String key, String id) { return txn(key, d -> d.commitInDoc(id), r -> "settled".equals(r.outcome)); }

    @Override public SettleOutcome release(String key, String id, Map<String, Object> evidence) { return txn(key, d -> d.releaseInDoc(key, id, evidence), r -> "settled".equals(r.outcome)); }

    @Override public Expired expire(String key, long now) { return txn(key, d -> d.expireInDoc(now), r -> !r.released.isEmpty()); }
}
