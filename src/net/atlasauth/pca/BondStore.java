package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The persistence contract for bond settlement. INTERNAL ACCOUNTING ONLY: nothing here moves money; balances are numbers a store
 * keeps for the deployment's own books. {@link #commit} applies a plan ALL OR NOTHING: the compare-and-swap on the bond's phase,
 * every balance movement, the new phase and the signed record become visible together; committing the same transition twice is
 * idempotent (the stored record, nothing moved).
 *
 * <p>A plan is the JSON object {@code {claimId, expect, next, open?: {amount, depositor, maxOpenClaims, maxOpenAmount, window?},
 * moves: [{account, op, amount}], record}}; a bond row is {@code {claimId, amount, depositor, status, window?, records}}.
 */
public interface BondStore {
    /** What a planner may read: the bond, the depositor's balance and open totals, and the store's time high-water mark. */
    final class Snapshot {
        /** The bond row (a copy), or null. */
        public final Map<String, Object> bond;
        /** {@code account -> balance} for the accounts asked for. */
        public final Map<String, Double> balances;
        public final long openCount;
        public final double openSum;
        public final double highWater;

        public Snapshot(Map<String, Object> bond, Map<String, Double> balances, long openCount, double openSum, double highWater) {
            this.bond = bond;
            this.balances = balances;
            this.openCount = openCount;
            this.openSum = openSum;
            this.highWater = highWater;
        }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            if (bond != null) m.put("bond", bond);
            List<Object> bal = new ArrayList<>();
            for (Map.Entry<String, Double> e : balances.entrySet()) {
                List<Object> pair = new ArrayList<>();
                pair.add(e.getKey());
                pair.add(StoreJs.num(e.getValue()));
                bal.add(pair);
            }
            m.put("balances", bal);
            Map<String, Object> t = new LinkedHashMap<>();
            t.put("count", StoreJs.num(openCount));
            t.put("sum", StoreJs.num(openSum));
            m.put("openTotals", t);
            m.put("highWater", StoreJs.num(highWater));
            return m;
        }
    }

    /** {@code committed} / {@code replayed} (with {@code record}) or {@code conflict} (with {@code reason} and {@code current}, the bond's phase). */
    final class CommitOutcome {
        public final String outcome;
        public final Map<String, Object> record;
        public final String reason;
        public final String current;

        public CommitOutcome(String outcome, Map<String, Object> record, String reason, String current) {
            this.outcome = outcome;
            this.record = record;
            this.reason = reason;
            this.current = current;
        }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("outcome", outcome);
            if (record != null) m.put("record", record);
            if (reason != null) m.put("reason", reason);
            if (current != null) m.put("current", current);
            return m;
        }
    }

    /** A consistent snapshot for planning ({@code depositor} may be null). May be stale by commit time; commit re-checks everything. */
    Snapshot read(String claimId, String depositor);

    /**
     * Apply {@code plan} atomically and record {@code observedAt} in the time high-water mark. An open plan on an absent bond checks the
     * caps and the balance and creates it; the same bond again is {@code replayed}, anything else {@code conflict}. Any other plan
     * needs the bond in phase {@code expect}; if it is already in {@code next} via the same settlement it is {@code replayed}, else
     * {@code conflict}; an overdraft is a {@code conflict}. Never throws for a refused plan, only when the store itself fails.
     */
    CommitOutcome commit(Map<String, Object> plan, double observedAt);

    /** Atomically credit {@code account} with {@code amount} (a positive finite number). Returns the new balance. */
    double deposit(String account, double amount);
}
