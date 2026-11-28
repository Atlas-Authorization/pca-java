package net.atlasauth.pca;

import java.util.Map;

/**
 * The reference {@link BondStore}: the whole book is one document in an {@link AtomicKv}, so every transition is a single atomic
 * read-modify-write. Over {@link PcaJdbcAtomicKv} it is durable and multi-process safe; over {@link MemoryAtomicKv} it is the in-process
 * variant (tests only). LIMIT: one document rewritten on every commit; a production deployment implements {@link BondStore} over a
 * database transaction.
 */
public final class KvBondStore implements BondStore {
    public static final String DOC_KEY = "pca-bond-store/v1";
    private final AtomicKv kv;
    private final String key;

    public KvBondStore(AtomicKv kv) { this(kv, DOC_KEY); }

    public KvBondStore(AtomicKv kv, String key) {
        if (kv == null) throw new BondStoreError("store_missing", "KvBondStore needs an AtomicKv");
        this.kv = kv;
        this.key = key;
    }

    @Override public Snapshot read(String claimId, String depositor) { return BondDoc.decode(kv.get(key)).snapshot(claimId, depositor); }

    @Override public CommitOutcome commit(Map<String, Object> plan, double observedAt) {
        CommitOutcome[] out = new CommitOutcome[1];
        kv.update(key, prev -> {
            BondDoc doc = BondDoc.decode(prev);
            out[0] = BondDoc.commitBondPlan(doc, plan, observedAt);
            return "committed".equals(out[0].outcome) ? doc.encode() : null; // null: leave the key untouched
        });
        return out[0];
    }

    @Override public double deposit(String account, double amount) {
        if (account == null || account.isEmpty()) throw new IllegalArgumentException("deposit: account is required");
        if (Double.isNaN(amount) || Double.isInfinite(amount) || amount <= 0) throw new IllegalArgumentException("deposit: amount must be a positive finite number");
        double[] balance = new double[1];
        kv.update(key, prev -> {
            BondDoc doc = BondDoc.decode(prev);
            java.util.List<Object> mv = new java.util.ArrayList<>();
            Map<String, Object> m = new java.util.LinkedHashMap<>();
            m.put("account", account);
            m.put("op", "credit");
            m.put("amount", StoreJs.num(amount));
            mv.add(m);
            balance[0] = BondDoc.applyBondMoves(a -> doc.balances.containsKey(a) ? doc.balances.get(a) : 0.0, mv).get(account);
            doc.balances.put(account, balance[0]);
            return doc.encode();
        });
        return balance[0];
    }
}
