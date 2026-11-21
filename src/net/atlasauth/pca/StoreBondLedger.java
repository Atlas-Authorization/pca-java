package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.BiConsumer;
import java.util.function.DoubleSupplier;
import java.util.function.Supplier;

/**
 * Durable, restart-safe bond settlement over a {@link BondStore}. INTERNAL ACCOUNTING ONLY: nothing here moves money.
 *
 * <p>Each transition is planned by the same {@link BondSettlementPlanner} a deployment's in-memory ledger would use (so a slash is authorised
 * by a verdict the ledger recomputes, never by the challenger), stamped from a clock the claimant cannot touch, and committed atomically and
 * idempotently. It FAILS CLOSED: no store ({@code store_missing}), no guardian key ({@code guardian_key_missing}), a non-finite clock
 * ({@code clock_invalid}), a store that throws ({@code store_unavailable}), malformed stored state ({@code store_corrupt}), a claim that fails
 * verification or the window floor ({@code invalid_claim}), a release inside the challenge window ({@code window_open}), a fraud or dispute slash
 * after it ({@code window_closed}), a release or slash of an unregistered bond ({@code unregistered}), a claim differing from the registered one
 * ({@code claim_mismatch}) and a conflicting concurrent transition ({@code conflict}) are each a {@link BondStoreError} with that code.
 *
 * <p>The challenge window opens at the ledger's own {@code registeredAt}, lasts the claim's {@code challenge_window_ms}, and is never derived
 * from the claim's {@code issued_at}. "Now" is {@code max(clock(), highest time the store ever recorded)}, so a clock that steps backwards cannot
 * reopen a closed window or release early. Records, bond rows and statuses are JSON objects.
 */
public final class StoreBondLedger {
    /** {@link BondSettlementPlanner.Options} plus the store, clock and window policy. */
    public static final class Options extends BondSettlementPlanner.Options {
        /** REQUIRED. There is deliberately no default store. */
        public BondStore store;
        /** Epoch-ms clock (default the system clock). A non-finite reading fails the operation. */
        public DoubleSupplier clock;
        /** Window bounds applied by {@link #openClaim} (default {@link Optimistic#DEFAULT_POLICY}); a window is never below the 30 s realistic floor. */
        public Optimistic.ChallengeWindowPolicy windowPolicy;
    }

    private final BondSettlementPlanner planner;
    private final BondStore store;
    private final DoubleSupplier clock;
    private final Optimistic.ChallengeWindowPolicy windowPolicy;

    public StoreBondLedger(Options opts) {
        if (opts == null || opts.store == null) throw new BondStoreError("store_missing", "a BondStore is required (there is no in-memory default)");
        if (opts.guardianKey == null || opts.guardianKey.isDestroyed()) throw new BondStoreError("guardian_key_missing", "a guardian secret key is required");
        this.store = opts.store;
        this.planner = new BondSettlementPlanner(opts);
        this.clock = opts.clock != null ? opts.clock : () -> (double) System.currentTimeMillis();
        this.windowPolicy = opts.windowPolicy != null ? opts.windowPolicy : Optimistic.DEFAULT_POLICY;
    }

    /** The guardian/settlement public key (b64u) the records verify under. */
    public String guardianPublicKey() { return planner.guardianPublicKey(); }

    private static <T> T guard(Supplier<T> fn) {
        try {
            return fn.get();
        } catch (BondStoreError e) {
            throw e;
        } catch (RuntimeException e) {
            throw new BondStoreError("store_unavailable", e.getMessage() == null ? "store failed" : e.getMessage(), e);
        }
    }

    private static final class Loaded {
        final BondStore.Snapshot snap;
        final BondSettlementPlanner.View view;
        final double now;

        Loaded(BondStore.Snapshot snap, BondSettlementPlanner.View view, double now) {
            this.snap = snap;
            this.view = view;
            this.now = now;
        }
    }

    private static BondSettlementPlanner.View viewOf(Map<String, Object> bond, Map<String, Double> balances, double[] totals) {
        return new BondSettlementPlanner.View() {
            @Override public Map<String, Object> bond(String id) { return bond != null && id != null && id.equals(bond.get("claimId")) ? bond : null; }
            @Override public double balanceOf(String a) { Double d = balances.get(a); return d == null ? 0 : d; }
            @Override public double[] openTotals(String depositor) { return totals; }
        };
    }

    private Loaded load(String claimId, String depositor) {
        BondStore.Snapshot snap = guard(() -> store.read(claimId, depositor));
        double t = clock.getAsDouble();
        if (Double.isNaN(t) || Double.isInfinite(t)) throw new BondStoreError("clock_invalid", "the clock returned a non-finite time");
        return new Loaded(snap, viewOf(snap.bond, snap.balances, new double[] {snap.openCount, snap.openSum}), Math.max(t, snap.highWater));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> lastRecord(Map<String, Object> bond) {
        List<Object> recs = (List<Object>) bond.get("records");
        return recs.isEmpty() ? null : StoreJs.map(recs.get(recs.size() - 1));
    }

    private Map<String, Object> submit(Map<String, Object> plan, double now) {
        BondStore.CommitOutcome out = guard(() -> store.commit(plan, now));
        if ("conflict".equals(out.outcome)) throw new BondStoreError("conflict", out.reason);
        return out.record;
    }

    /** Settle: plan against the true view; if the bond is already settled, a retry that would have produced the same settlement returns the stored record. */
    private Map<String, Object> settle(String claimId, BiFunction<BondSettlementPlanner.View, Double, Map<String, Object>> plan, BiConsumer<Map<String, Object>, Double> gate) {
        Loaded l = load(claimId, null);
        Map<String, Object> bond = l.snap.bond;
        if (bond != null && !"open".equals(bond.get("status"))) {
            Map<String, Object> last = lastRecord(bond);
            Map<String, Object> reopened = new LinkedHashMap<>(bond);
            reopened.put("status", "open");
            Map<String, Object> again = plan.apply(viewOf(reopened, l.snap.balances, new double[] {l.snap.openCount, l.snap.openSum}), l.now); // throws if the evidence no longer holds
            if (last != null && BondDoc.sameSettlement(last, StoreJs.map(again.get("record")))) return last;
            return StoreJs.map(plan.apply(l.view, l.now).get("record")); // throws the standard double-settle refusal
        }
        if (bond != null && gate != null) gate.accept(bond, l.now);
        return submit(plan.apply(l.view, l.now), l.now);
    }

    /** Top up an account of the internal books (a positive finite amount). */
    public double deposit(String account, double amount) { return guard(() -> store.deposit(account, amount)); }

    public double balanceOf(String account) {
        BondStore.Snapshot snap = guard(() -> store.read("", account));
        Double d = snap.balances.get(account);
        return d == null ? 0 : d;
    }

    /** {@code none}, {@code open}, {@code released} or {@code slashed}. */
    public String bondStatus(String claimId) {
        BondStore.Snapshot s = guard(() -> store.read(claimId, null));
        return s.bond == null ? "none" : (String) s.bond.get("status");
    }

    /** The bond row {@code {claimId, amount, depositor, status, window?, records}}, or null. */
    public Map<String, Object> getBond(String claimId) { return guard(() -> store.read(claimId, null)).bond; }

    /** {@code {phase: open|finalized, endsAt, now}} on the ledger's clock; throws {@code unregistered} for a bond with no claim. */
    public Map<String, Object> challengeStatus(String claimId) {
        Loaded l = load(claimId, null);
        Map<String, Object> w = l.snap.bond == null ? null : StoreJs.map(l.snap.bond.get("window"));
        if (w == null) throw new BondStoreError("unregistered", "bond " + claimId + " has no registered claim");
        double endsAt = StoreJs.dbl(w.get("registeredAt")) + StoreJs.dbl(w.get("windowMs"));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("phase", Double.isFinite(l.now) && Double.isFinite(endsAt) && l.now > endsAt ? "finalized" : "open");
        m.put("endsAt", StoreJs.num(endsAt));
        m.put("now", StoreJs.num(l.now));
        return m;
    }

    /**
     * Register an optimistic claim and lock its bond in one atomic commit. The claim must pass {@link OptimisticAdjudication#verifyClaim} against
     * the ledger's clock and its window must be at least the realistic floor; the window then runs from the ledger's own {@code registeredAt}.
     * Retrying the same call returns the original {@code open} record. {@code exposure} may be null.
     */
    public Map<String, Object> openClaim(Map<String, Object> claim, Map<String, Object> pcactn, String signerPublic, double amount, String depositor, Double exposure) {
        Object bondRef = claim == null ? null : claim.get("bond_ref");
        Loaded l = load(String.valueOf(bondRef), depositor);
        Map<String, Object> verdict = OptimisticAdjudication.verifyClaim(claim, pcactn, signerPublic, l.now, windowPolicy);
        if (!Boolean.TRUE.equals(verdict.get("ok"))) throw new BondStoreError("invalid_claim", String.valueOf(verdict.get("reason")));
        double floor = Math.max(windowPolicy.minWindowMs, OptimisticAdjudication.DEFAULT_MIN_CHALLENGE_WINDOW_MS);
        double windowMs = StoreJs.dbl(claim.get("challenge_window_ms"));
        if (windowMs < floor) throw new BondStoreError("invalid_claim", "challenge window " + AttestCommon.jsNumString(windowMs) + " ms is below the " + AttestCommon.jsNumString(floor) + " ms floor");
        if (!(bondRef instanceof String) || ((String) bondRef).isEmpty()) throw new BondStoreError("invalid_claim", "claim has no bond_ref");
        Map<String, Object> window = new LinkedHashMap<>();
        window.put("registeredAt", StoreJs.num(l.now));
        window.put("windowMs", StoreJs.num(windowMs));
        window.put("claimDigest", StoreJs.hashLenient(claim));
        if (l.snap.bond != null) return replayOpen(l.snap.bond, depositor, amount, window);
        return submit(planner.planOpen(l.view, (String) bondRef, amount, depositor, exposure, l.now, window), l.now);
    }

    /** A retried open: the same terms return the original {@code open} record; anything else is the standard double-open refusal. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> replayOpen(Map<String, Object> prior, String depositor, double amount, Map<String, Object> window) {
        Map<String, Object> pw = StoreJs.map(prior.get("window"));
        boolean sameWindow = pw == null ? window == null : window != null && java.util.Objects.equals(pw.get("claimDigest"), window.get("claimDigest"));
        boolean same = java.util.Objects.equals(prior.get("depositor"), depositor) && StoreJs.dbl(prior.get("amount")) == amount && sameWindow;
        List<Object> recs = (List<Object>) prior.get("records");
        if (same && !recs.isEmpty()) return StoreJs.map(recs.get(0));
        throw new BondStoreError("conflict", "openBond: bond " + prior.get("claimId") + " already exists (double-open refused)");
    }

    /** Open a bond that backs no claim (a challenger's counter-bond). It has no window; settle it with {@link #slashCounterBond} or {@link #releaseUnregistered}. */
    public Map<String, Object> openBond(String claimId, double amount, String depositor, Double exposure) {
        Loaded l = load(claimId, depositor);
        if (l.snap.bond != null) return replayOpen(l.snap.bond, depositor, amount, null);
        return submit(planner.planOpen(l.view, claimId, amount, depositor, exposure, l.now, null), l.now);
    }

    /** Release a registered claim's bond once its challenge window has closed on the ledger's clock. */
    public Map<String, Object> release(String claimId) {
        return settle(claimId, (view, now) -> planner.planRelease(view, claimId, now), (bond, now) -> {
            Map<String, Object> w = StoreJs.map(bond.get("window"));
            if (w == null) throw new BondStoreError("unregistered", "bond " + claimId + " has no registered claim; use releaseUnregistered for a counter-bond");
            double end = StoreJs.dbl(w.get("registeredAt")) + StoreJs.dbl(w.get("windowMs"));
            if (!(Double.isFinite(now) && Double.isFinite(end) && now > end)) throw new BondStoreError("window_open", "the challenge window of " + claimId + " closes at " + AttestCommon.jsNumString(end));
        });
    }

    /** Release a bond that backs no claim (a counter-bond). */
    public Map<String, Object> releaseUnregistered(String claimId) {
        return settle(claimId, (view, now) -> planner.planRelease(view, claimId, now), (bond, now) -> {
            if (StoreJs.map(bond.get("window")) != null) throw new BondStoreError("conflict", "bond " + claimId + " backs a registered claim; use release");
        });
    }

    private static BiConsumer<Map<String, Object>, Double> challengeGate(Map<String, Object> claim) {
        return (bond, now) -> {
            Map<String, Object> w = StoreJs.map(bond.get("window"));
            if (w == null) throw new BondStoreError("unregistered", "bond " + bond.get("claimId") + " has no registered claim");
            if (!java.util.Objects.equals(w.get("claimDigest"), StoreJs.hashLenient(claim))) throw new BondStoreError("claim_mismatch", "the claim is not the one registered for " + bond.get("claimId"));
            double end = StoreJs.dbl(w.get("registeredAt")) + StoreJs.dbl(w.get("windowMs"));
            if (!(Double.isFinite(now) && Double.isFinite(end) && now <= end)) throw new BondStoreError("window_closed", "the challenge window of " + bond.get("claimId") + " closed at " + AttestCommon.jsNumString(end));
        };
    }

    private static String idOf(Map<String, Object> p, String k) { return p.get(k) instanceof String ? (String) p.get(k) : String.valueOf(p.get(k)); }

    /** Slash on a fraud proof the ledger re-verifies itself, inside the challenge window. {@code params}: see {@link BondSettlementPlanner#planSlash}. */
    public Map<String, Object> slashBond(Map<String, Object> params) {
        return settle(idOf(params, "claimId"), (view, now) -> planner.planSlash(view, params, now), challengeGate(StoreJs.map(params.get("claim"))));
    }

    /** Slash on a dispute the ledger re-adjudicates itself, inside the challenge window. */
    public Map<String, Object> slashBondOnDispute(Map<String, Object> params) {
        return settle(idOf(params, "claimId"), (view, now) -> planner.planSlashOnDispute(view, params, now), challengeGate(StoreJs.map(params.get("claim"))));
    }

    /** Slash because a capability in the claim's chain was revoked (server-derived evidence; not window-gated). */
    public Map<String, Object> slashBondOnRevocation(Map<String, Object> params) {
        Map<String, Object> claim = StoreJs.map(params.get("claim"));
        return settle(idOf(params, "claimId"), (view, now) -> planner.planSlashOnRevocation(view, params, now), (bond, now) -> {
            Map<String, Object> w = StoreJs.map(bond.get("window"));
            if (w != null && !java.util.Objects.equals(w.get("claimDigest"), StoreJs.hashLenient(claim))) throw new BondStoreError("claim_mismatch", "the claim is not the one registered for " + bond.get("claimId"));
        });
    }

    /** Slash a challenger's counter-bond after a frivolous dispute. */
    public Map<String, Object> slashCounterBond(Map<String, Object> params) {
        return settle(idOf(params, "counterBondId"), (view, now) -> planner.planSlashCounterBond(view, params, now), null);
    }
}
