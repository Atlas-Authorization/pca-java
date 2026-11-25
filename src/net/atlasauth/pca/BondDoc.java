package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The state a reference bond store keeps, and the pure transition over it ({@link #commitBondPlan}); every reference store is this plus a lock. */
public final class BondDoc {
    public final Map<String, Double> balances = new LinkedHashMap<>();
    public final Map<String, Map<String, Object>> bonds = new LinkedHashMap<>();
    public double highWater = 0;

    public static BondDoc empty() { return new BondDoc(); }

    private static final double MAX_SAFE_MICROS = 1e15;

    /** Integer micro-units of {@code x} when it is a micro-grid amount below 1e15 micros, else null. */
    static Long toMicros(double x) {
        if (Double.isNaN(x) || Double.isInfinite(x) || x < 0) return null;
        double scaled = x * 1_000_000;
        if (scaled > MAX_SAFE_MICROS) return null;
        double r = Math.floor(scaled + 0.5); // JavaScript Math.round
        if (r / 1_000_000 != x && Math.abs(scaled - r) > 1e-3) return null;
        return (long) r;
    }

    /** a + sign*b in exact micro-unit integers when both are micro-grid amounts; plain float otherwise. */
    public static double exactAdd(double a, double b, int sign) {
        Long ma = toMicros(a), mb = toMicros(b);
        if (ma == null || mb == null) return a + sign * b;
        return (double) (sign == 1 ? ma + mb : ma - mb) / 1_000_000;
    }

    /** Apply moves in order over a balance reader; throws IllegalStateException (the reference's Error) on an invalid amount or an overdraft. */
    public static Map<String, Double> applyBondMoves(java.util.function.ToDoubleFunction<String> balanceOf, List<?> moves) {
        Map<String, Double> out = new LinkedHashMap<>();
        java.util.function.ToDoubleFunction<String> bal = a -> out.containsKey(a) ? out.get(a) : balanceOf.applyAsDouble(a);
        for (Object mo : moves) {
            Map<String, Object> m = StoreJs.map(mo);
            Double amount = StoreJs.dbl(m.get("amount"));
            Object op = m.get("op");
            if (amount == null || Double.isNaN(amount) || Double.isInfinite(amount) || amount < 0) throw new IllegalStateException(op + ": invalid amount");
            String account = (String) m.get("account");
            boolean debit = "debit".equals(op);
            if (!Double.isFinite(bal.applyAsDouble(account))) throw new IllegalStateException(op + ": balance of " + account + " is not finite");
            if (debit && !(bal.applyAsDouble(account) >= amount)) throw new IllegalStateException("debit: insufficient balance for " + account);
            out.put(account, exactAdd(bal.applyAsDouble(account), amount, debit ? -1 : 1));
        }
        return out;
    }

    /** Same settlement: action, bond, amount, parties, evidence and split (time and signature bytes ignored). */
    public static boolean sameSettlement(Map<String, Object> a, Map<String, Object> b) {
        return java.util.Objects.equals(a.get("claimId"), b.get("claimId")) && java.util.Objects.equals(a.get("action"), b.get("action"))
            && sameNum(a.get("amount"), b.get("amount")) && java.util.Objects.equals(a.get("from"), b.get("from")) && java.util.Objects.equals(a.get("to"), b.get("to"))
            && java.util.Objects.equals(a.get("evidenceDigest"), b.get("evidenceDigest"))
            && StoreJs.hashLenient(a.get("split")).equals(StoreJs.hashLenient(b.get("split")));
    }

    private static boolean sameNum(Object a, Object b) {
        Double x = StoreJs.dbl(a), y = StoreJs.dbl(b);
        return x == null || y == null ? a == null && b == null : x.doubleValue() == y.doubleValue();
    }

    private static boolean sameWindow(Map<String, Object> a, Map<String, Object> b) {
        if (a == null || b == null) return a == b;
        return sameNum(a.get("windowMs"), b.get("windowMs")) && java.util.Objects.equals(a.get("claimDigest"), b.get("claimDigest")); // registeredAt is the first call's
    }

    private static String status(Map<String, Object> bond) { return bond == null ? "none" : (String) bond.get("status"); }

    @SuppressWarnings("unchecked")
    private static List<Object> records(Map<String, Object> bond) { return (List<Object>) bond.get("records"); }

    /**
     * Apply {@code plan} to {@code doc} following the {@link BondStore#commit} rules. Mutates {@code doc} ONLY on {@code committed}
     * (the moves are checked on an overlay first).
     */
    public static BondStore.CommitOutcome commitBondPlan(BondDoc doc, Map<String, Object> plan, double observedAt) {
        String claimId = (String) plan.get("claimId");
        Map<String, Object> bond = doc.bonds.get(claimId);
        Map<String, Object> open = StoreJs.map(plan.get("open"));
        Map<String, Object> record = StoreJs.map(plan.get("record"));
        if ("none".equals(plan.get("expect"))) {
            if (open == null || !"open".equals(plan.get("next"))) return new BondStore.CommitOutcome("conflict", null, "malformed open plan", status(bond));
            if (bond != null) {
                List<Object> recs = records(bond);
                boolean same = java.util.Objects.equals(bond.get("depositor"), open.get("depositor")) && sameNum(bond.get("amount"), open.get("amount"))
                    && sameWindow(StoreJs.map(bond.get("window")), StoreJs.map(open.get("window"))) && !recs.isEmpty() && sameSettlement(StoreJs.map(recs.get(0)), record);
                return same ? new BondStore.CommitOutcome("replayed", StoreJs.map(recs.get(0)), null, null)
                    : new BondStore.CommitOutcome("conflict", null, "bond " + claimId + " already exists", status(bond));
            }
            long count = 0;
            double sum = 0;
            for (Map<String, Object> b : doc.bonds.values()) {
                if ("open".equals(b.get("status")) && java.util.Objects.equals(b.get("depositor"), open.get("depositor"))) {
                    count += 1;
                    sum += StoreJs.dbl(b.get("amount"));
                }
            }
            if (!(Double.isFinite(count) && count + 1 <= StoreJs.dbl(open.get("maxOpenClaims")))) return new BondStore.CommitOutcome("conflict", null, "depositor open-claim cap reached", "none");
            if (!(Double.isFinite(sum + StoreJs.dbl(open.get("amount"))) && sum + StoreJs.dbl(open.get("amount")) <= StoreJs.dbl(open.get("maxOpenAmount")))) return new BondStore.CommitOutcome("conflict", null, "depositor aggregate open-bond cap exceeded", "none");
        } else if (bond == null) {
            return new BondStore.CommitOutcome("conflict", null, "no bond for " + claimId, "none");
        } else if (!java.util.Objects.equals(bond.get("status"), plan.get("expect"))) {
            List<Object> recs = records(bond);
            Map<String, Object> last = recs.isEmpty() ? null : StoreJs.map(recs.get(recs.size() - 1));
            return java.util.Objects.equals(bond.get("status"), plan.get("next")) && last != null && sameSettlement(last, record)
                ? new BondStore.CommitOutcome("replayed", last, null, null)
                : new BondStore.CommitOutcome("conflict", null, "bond " + claimId + " is already " + bond.get("status"), status(bond));
        }
        Map<String, Double> next;
        try {
            next = applyBondMoves(a -> doc.balances.containsKey(a) ? doc.balances.get(a) : 0.0, (List<?>) plan.get("moves"));
        } catch (IllegalStateException e) {
            return new BondStore.CommitOutcome("conflict", null, e.getMessage(), status(bond));
        }
        doc.balances.putAll(next);
        if (open != null) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("claimId", claimId);
            row.put("amount", open.get("amount"));
            row.put("depositor", open.get("depositor"));
            row.put("status", "open");
            if (StoreJs.map(open.get("window")) != null) row.put("window", StoreJs.deepCopy(open.get("window")));
            List<Object> recs = new ArrayList<>();
            recs.add(StoreJs.deepCopy(record));
            row.put("records", recs);
            doc.bonds.put(claimId, row);
        } else {
            bond.put("status", plan.get("next"));
            records(bond).add(StoreJs.deepCopy(record));
        }
        double obs = Double.isNaN(observedAt) || Double.isInfinite(observedAt) ? 0 : observedAt;
        doc.highWater = Math.max(doc.highWater, obs);
        return new BondStore.CommitOutcome("committed", record, null, null);
    }

    /** The snapshot a scope reads from a document. */
    @SuppressWarnings("unchecked")
    public BondStore.Snapshot snapshot(String claimId, String depositor) {
        Map<String, Object> bond = bonds.get(claimId);
        long count = 0;
        double sum = 0;
        Map<String, Double> bal = new LinkedHashMap<>();
        if (depositor != null) {
            for (Map<String, Object> b : bonds.values()) {
                if ("open".equals(b.get("status")) && depositor.equals(b.get("depositor"))) {
                    count += 1;
                    sum += StoreJs.dbl(b.get("amount"));
                }
            }
            bal.put(depositor, balances.containsKey(depositor) ? balances.get(depositor) : 0.0);
        }
        return new BondStore.Snapshot(bond == null ? null : (Map<String, Object>) StoreJs.deepCopy(bond), bal, count, sum, highWater);
    }

    /** The stored form {@code {v:1, balances:[[a,n]..], bonds:[..], highWater}}. */
    public Map<String, Object> encode() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", StoreJs.num(1));
        List<Object> bal = new ArrayList<>();
        for (Map.Entry<String, Double> e : balances.entrySet()) {
            List<Object> pair = new ArrayList<>();
            pair.add(e.getKey());
            pair.add(StoreJs.num(e.getValue()));
            bal.add(pair);
        }
        m.put("balances", bal);
        List<Object> bs = new ArrayList<>();
        for (Map<String, Object> b : bonds.values()) bs.add(StoreJs.deepCopy(b));
        m.put("bonds", bs);
        m.put("highWater", StoreJs.num(highWater));
        return m;
    }

    private static BondStoreError bad(String why) { return new BondStoreError("store_corrupt", why); }

    /** Decode a stored document (null = empty); fails closed with {@code store_corrupt}. The result shares nothing with {@code raw}. */
    public static BondDoc decode(Object raw) {
        if (raw == null) return empty();
        Map<String, Object> m = StoreJs.map(raw);
        if (m == null || !StoreJs.isInt(m.get("v")) || StoreJs.lng(m.get("v")) != 1 || !(m.get("balances") instanceof List) || !(m.get("bonds") instanceof List) || StoreJs.dbl(m.get("highWater")) == null) {
            throw bad("bond document has the wrong shape");
        }
        BondDoc d = empty();
        double hw = StoreJs.dbl(m.get("highWater"));
        if (Double.isNaN(hw) || Double.isInfinite(hw) || hw < 0) throw bad("highWater is not a non-negative number");
        d.highWater = hw;
        for (Object e : (List<?>) m.get("balances")) {
            if (!(e instanceof List) || ((List<?>) e).size() != 2 || !(((List<?>) e).get(0) instanceof String)) throw bad("malformed balance entry");
            Double v = StoreJs.dbl(((List<?>) e).get(1));
            if (v == null || Double.isNaN(v) || Double.isInfinite(v) || v < 0) throw bad("malformed balance entry");
            d.balances.put((String) ((List<?>) e).get(0), v);
        }
        for (Object bo : (List<?>) m.get("bonds")) {
            Map<String, Object> b = StoreJs.map(bo);
            if (b == null || !(b.get("claimId") instanceof String) || !(b.get("depositor") instanceof String) || StoreJs.dbl(b.get("amount")) == null || !StoreJs.isFinite(b.get("amount"))
                || !("open".equals(b.get("status")) || "released".equals(b.get("status")) || "slashed".equals(b.get("status")))
                || !(b.get("records") instanceof List) || ((List<?>) b.get("records")).isEmpty()) throw bad("malformed bond row");
            if (d.bonds.containsKey(b.get("claimId"))) throw bad("duplicate bond row");
            d.bonds.put((String) b.get("claimId"), StoreJs.map(StoreJs.deepCopy(b)));
        }
        return d;
    }
}
