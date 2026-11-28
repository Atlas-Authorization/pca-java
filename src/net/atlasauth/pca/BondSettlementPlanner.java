package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The pure half of bond settlement: validates a transition against a read {@link View}, re-derives every slash verdict itself (a slash is
 * never authorised by challenger assertion), computes the balance movements and signs the record. It holds no state and touches no store.
 * A {@link StoreBondLedger} commits the plans it returns to a {@link BondStore} atomically.
 *
 * <p>A plan is {@code {claimId, expect, next, open?: {amount, depositor, maxOpenClaims, maxOpenAmount, window?}, moves: [{account, op, amount}], record}}
 * (see {@link BondStore}); a window is {@code {registeredAt, windowMs, claimDigest}}.
 */
public final class BondSettlementPlanner {
    /** What deciding a transition needs to read. */
    public interface View {
        /** The bond head {@code {claimId, amount, depositor, status, ...}}, or null. */
        Map<String, Object> bond(String claimId);

        double balanceOf(String account);

        /** {@code {count, sum}} of the depositor's currently open bonds. */
        double[] openTotals(String depositor);
    }

    /** Planner configuration. Only {@code guardianKey} is required. */
    public static class Options {
        /** The guardian/settlement key that signs every record. */
        public Keys.EdKey guardianKey;
        /** Bound into every signed record when non-null (a non-negative safe integer). */
        public Long guardianEpoch;
        /** Signature suite (null: ed25519). A PQ or hybrid suite binds its public key into the signed body. */
        public Keys.SuiteKey suite;
        public String escrowAccount;
        /** {@code {floor, k, maxOpenClaims, maxOpenAmount, curve?}} (null: {@link BondSettlement#defaultBondPolicy}). */
        public Map<String, Object> bondPolicy;
        /** {@code {challengerBps, victimBps}} (null: {@link BondSettlement#defaultSlashSplitPolicy}). */
        public Map<String, Object> slashSplitPolicy;
    }

    private final String guardianPublicKey;
    private final String escrow;
    private final Map<String, Object> bondPolicy;
    private final Map<String, Object> slashSplitPolicy;
    private final Keys.SuiteKey suite;
    private final Long guardianEpoch;

    public BondSettlementPlanner(Options opts) {
        if (opts == null || opts.guardianKey == null) throw new IllegalArgumentException("BondLedger: guardianSecret must be a Uint8Array");
        this.guardianPublicKey = opts.guardianKey.id();
        if (opts.guardianEpoch != null && (opts.guardianEpoch < 0 || opts.guardianEpoch > 9007199254740991L)) {
            throw new IllegalArgumentException("BondLedger: guardianEpoch must be a non-negative safe integer");
        }
        this.guardianEpoch = opts.guardianEpoch;
        if (opts.suite != null && opts.suite.ed != null && !opts.suite.ed.id().equals(guardianPublicKey)) {
            throw new IllegalArgumentException("BondLedger: the suite's Ed25519 key is not the guardian key");
        }
        this.suite = opts.suite != null ? opts.suite : Keys.ed25519(opts.guardianKey);
        this.escrow = opts.escrowAccount != null ? opts.escrowAccount : BondSettlement.ESCROW_ACCOUNT;
        this.bondPolicy = opts.bondPolicy != null ? opts.bondPolicy : BondSettlement.defaultBondPolicy();
        this.slashSplitPolicy = opts.slashSplitPolicy != null ? opts.slashSplitPolicy : BondSettlement.defaultSlashSplitPolicy();
    }

    /** The guardian/settlement public key (b64u) the signed records verify under. */
    public String guardianPublicKey() { return guardianPublicKey; }

    public String escrow() { return escrow; }

    public Map<String, Object> bondPolicy() { return bondPolicy; }

    public Map<String, Object> slashSplitPolicy() { return slashSplitPolicy; }

    private Map<String, Object> signRecord(Map<String, Object> base) {
        Map<String, Object> withEpoch = new LinkedHashMap<>(base);
        if (guardianEpoch != null) withEpoch.put("guardian_epoch", StoreJs.num(guardianEpoch));
        Map<String, Object> body = IntentJs.bindSuiteFields(withEpoch, suite.alg, true, suite.pqPk(), true);
        String[] sigs = suite.sign(BondSettlement.settlementMessage(body));
        Map<String, Object> rec = new LinkedHashMap<>(body);
        rec.put("sig", sigs[0]);
        if (sigs[1] != null) rec.put("pq_sig", sigs[1]);
        return rec;
    }

    private static Map<String, Object> mv(String account, String op, double amount) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("account", account);
        m.put("op", op);
        m.put("amount", StoreJs.num(amount));
        return m;
    }

    private static Map<String, Object> base(String claimId, String action, double amount, String from, String to, double at, String evidenceDigest) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("claimId", claimId);
        m.put("action", action);
        m.put("amount", StoreJs.num(amount));
        m.put("from", from);
        m.put("to", to);
        m.put("at", StoreJs.num(at));
        m.put("evidenceDigest", evidenceDigest);
        return m;
    }

    private static Map<String, Object> plan(String claimId, String expect, String next, List<Object> moves, Map<String, Object> record) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("claimId", claimId);
        p.put("expect", expect);
        p.put("next", next);
        p.put("moves", moves);
        p.put("record", record);
        return p;
    }

    private static double amountOf(Map<String, Object> bond) { return StoreJs.dbl(bond.get("amount")); }

    private Map<String, Object> openBondOrThrow(View view, String who, String claimId) {
        Map<String, Object> bond = view.bond(claimId);
        if (bond == null) throw new IllegalStateException(who + ": no bond for " + claimId);
        if (!"open".equals(bond.get("status"))) throw new IllegalStateException(who + ": bond " + claimId + " is already " + bond.get("status") + " (double-settle refused)");
        return bond;
    }

    private static String stringParam(Map<String, Object> p, String k) { return p.get(k) instanceof String ? (String) p.get(k) : null; }

    private static void needTreasury(Map<String, Object> p, String who) {
        String t = stringParam(p, "treasury");
        if (t == null || t.isEmpty()) throw new IllegalStateException(who + ": treasury is required");
    }

    /** The balance movements of a slash: the full bond leaves escrow and is divided per {@link BondSettlement#computeSlashSplit}. */
    private Map<String, Object> slashPlan(Map<String, Object> bond, String claimId, double now, String evidenceDigest, Map<String, Object> p) {
        String treasury = (String) p.get("treasury");
        double amount = amountOf(bond);
        Map<String, Object> policy = StoreJs.map(p.get("splitPolicy")) != null ? StoreJs.map(p.get("splitPolicy")) : slashSplitPolicy;
        Map<String, Object> dest = new LinkedHashMap<>();
        dest.put("challengerAccount", p.get("challengerAccount"));
        dest.put("victimAccount", p.get("compensationAccount") != null ? p.get("compensationAccount") : BondSettlement.COMPENSATION_POOL_ACCOUNT);
        dest.put("treasuryAccount", treasury);
        BondSettlement.SlashSplit split = BondSettlement.computeSlashSplit(amount, policy, dest);
        List<Object> moves = new ArrayList<>();
        moves.add(mv(escrow, "debit", amount)); // the full bond leaves escrow
        if (split.challengerAccount != null && !split.challengerAccount.isEmpty() && split.challengerReward > 0) moves.add(mv(split.challengerAccount, "credit", split.challengerReward));
        if (split.victimCompensation > 0) moves.add(mv(split.victimAccount, "credit", split.victimCompensation));
        if (split.treasuryRemainder > 0) moves.add(mv(split.treasuryAccount, "credit", split.treasuryRemainder));
        Map<String, Object> b = base(claimId, "slash", amount, escrow, treasury, now, evidenceDigest);
        b.put("split", split.toJson());
        return plan(claimId, "open", "slashed", moves, signRecord(b));
    }

    /**
     * Open (lock) a bond: refuses an unaffordable bond, one below {@code bondAmount(policy, exposure)}, one that breaches the depositor's
     * caps and a double-open. {@code exposure} and {@code window} may be null. The bond moves from the depositor into escrow.
     */
    public Map<String, Object> planOpen(View view, String claimId, double amount, String depositor, Double exposure, double now, Map<String, Object> window) {
        if (claimId == null || claimId.isEmpty()) throw new IllegalStateException("openBond: claimId is required");
        if (Double.isNaN(amount) || Double.isInfinite(amount) || amount <= 0) throw new IllegalStateException("openBond: amount must be a positive finite number");
        if (depositor == null || depositor.isEmpty()) throw new IllegalStateException("openBond: depositor is required");
        if (view.bond(claimId) != null) throw new IllegalStateException("openBond: bond " + claimId + " already exists (double-open refused)");

        double required = BondSettlement.bondAmount(bondPolicy, exposure == null ? 0 : exposure);
        if (!(amount >= required)) throw new IllegalStateException("openBond: amount " + AttestCommon.jsNumString(amount) + " is below the required bond " + AttestCommon.jsNumString(required));
        double[] totals = view.openTotals(depositor);
        double maxClaims = StoreJs.dbl(bondPolicy.get("maxOpenClaims")), maxAmount = StoreJs.dbl(bondPolicy.get("maxOpenAmount"));
        if (!(Double.isFinite(totals[0]) && totals[0] + 1 <= maxClaims)) throw new IllegalStateException("openBond: depositor open-claim cap reached");
        if (!(Double.isFinite(totals[1] + amount) && totals[1] + amount <= maxAmount)) throw new IllegalStateException("openBond: depositor aggregate open-bond cap exceeded");
        if (!(Double.isFinite(view.balanceOf(depositor)) && view.balanceOf(depositor) >= amount)) throw new IllegalStateException("openBond: insufficient balance for the bond");

        Map<String, Object> record = signRecord(base(claimId, "open", amount, depositor, escrow, now, ""));
        Map<String, Object> open = new LinkedHashMap<>();
        open.put("amount", StoreJs.num(amount));
        open.put("depositor", depositor);
        open.put("maxOpenClaims", bondPolicy.get("maxOpenClaims"));
        open.put("maxOpenAmount", bondPolicy.get("maxOpenAmount"));
        if (window != null) open.put("window", window);
        List<Object> moves = new ArrayList<>();
        moves.add(mv(depositor, "debit", amount)); // collateral is really taken
        moves.add(mv(escrow, "credit", amount));
        Map<String, Object> p = plan(claimId, "none", "open", moves, record);
        p.put("open", open);
        return p;
    }

    /** Release a bond back to its depositor after an unchallenged window; refuses a missing or already settled bond. */
    public Map<String, Object> planRelease(View view, String claimId, double now) {
        Map<String, Object> bond = view.bond(claimId);
        if (bond == null) throw new IllegalStateException("releaseBond: no bond for " + claimId);
        if (!"open".equals(bond.get("status"))) throw new IllegalStateException("releaseBond: bond " + claimId + " is already " + bond.get("status") + " (double-settle refused)");
        double amount = amountOf(bond);
        String depositor = (String) bond.get("depositor");
        List<Object> moves = new ArrayList<>();
        moves.add(mv(escrow, "debit", amount));
        moves.add(mv(depositor, "credit", amount));
        return plan(claimId, "open", "released", moves, signRecord(base(claimId, "release", amount, escrow, depositor, now, "")));
    }

    /**
     * Slash against a VERIFIED fraud verdict; re-runs the Policy VM itself. {@code params}: claimId, claim, fraudProof, grant, openSnapshot,
     * treasury, and optionally challengerAccount, compensationAccount, splitPolicy.
     */
    public Map<String, Object> planSlash(View view, Map<String, Object> params, double now) {
        String claimId = stringParam(params, "claimId");
        Map<String, Object> claim = StoreJs.map(params.get("claim"));
        Map<String, Object> bond = openBondOrThrow(view, "slashBond", claimId);
        needTreasury(params, "slashBond");
        if (!java.util.Objects.equals(claim.get("bond_ref"), claimId)) throw new IllegalStateException("slashBond: claim.bond_ref does not match claimId");
        Map<String, Object> verdict = OptimisticAdjudication.verifyFraudProof(claim, params.get("fraudProof"), StoreJs.map(params.get("grant")), params.get("openSnapshot"));
        if (!Boolean.TRUE.equals(verdict.get("fraudulent")) || !java.util.Objects.equals(verdict.get("slashBondRef"), claimId)) {
            throw new IllegalStateException("slashBond: refused — no verified fraud verdict slashing " + claimId + " (" + verdict.get("reason") + ")");
        }
        return slashPlan(bond, claimId, now, BondSettlement.settlementEvidenceDigest(claim, verdict), params);
    }

    /** Slash because a capability in the claim's chain was revoked after the bond opened (server-derived evidence). {@code params} adds revokedCapId. */
    public Map<String, Object> planSlashOnRevocation(View view, Map<String, Object> params, double now) {
        String claimId = stringParam(params, "claimId");
        Map<String, Object> claim = StoreJs.map(params.get("claim"));
        Map<String, Object> bond = openBondOrThrow(view, "slashBondOnRevocation", claimId);
        needTreasury(params, "slashBondOnRevocation");
        if (!java.util.Objects.equals(claim.get("bond_ref"), claimId)) throw new IllegalStateException("slashBondOnRevocation: claim.bond_ref does not match claimId");
        String revoked = stringParam(params, "revokedCapId");
        if (revoked == null || revoked.isEmpty()) throw new IllegalStateException("slashBondOnRevocation: revokedCapId is required");
        return slashPlan(bond, claimId, now, BondSettlement.revocationEvidenceDigest(claim, revoked), params);
    }

    private static OptimisticAdjudication.ObjectiveOracle oracleOf(Map<String, Object> params) {
        Object o = params.get("oracle");
        return o instanceof OptimisticAdjudication.ObjectiveOracle ? (OptimisticAdjudication.ObjectiveOracle) o : null;
    }

    private static Double rMargin(Map<String, Object> params) { return StoreJs.dbl(params.get("rMargin")); }

    /** Slash the AGENT's bond because a dispute proved it understated a risk input; re-runs the adjudication itself. {@code params} adds dispute, oracle, rMargin?. */
    public Map<String, Object> planSlashOnDispute(View view, Map<String, Object> params, double now) {
        String claimId = stringParam(params, "claimId");
        Map<String, Object> claim = StoreJs.map(params.get("claim"));
        Map<String, Object> bond = openBondOrThrow(view, "slashBondOnDispute", claimId);
        needTreasury(params, "slashBondOnDispute");
        if (!java.util.Objects.equals(claim.get("bond_ref"), claimId)) throw new IllegalStateException("slashBondOnDispute: claim.bond_ref does not match claimId");
        Map<String, Object> verdict = OptimisticAdjudication.adjudicateDispute(claim, params.get("dispute"), StoreJs.map(params.get("grant")), params.get("openSnapshot"), oracleOf(params), rMargin(params));
        if (!"agent-fraud".equals(verdict.get("outcome")) || !Boolean.TRUE.equals(verdict.get("fraudulent")) || !java.util.Objects.equals(verdict.get("slashBondRef"), claimId)) {
            throw new IllegalStateException("slashBondOnDispute: refused — no verified agent-fraud verdict slashing " + claimId + " (" + verdict.get("outcome") + ": " + verdict.get("reason") + ")");
        }
        return slashPlan(bond, claimId, now, BondSettlement.disputeEvidenceDigest(claim, verdict), params);
    }

    /** Slash the CHALLENGER's counter-bond because the dispute was frivolous (anti-griefing); an anonymous slash, 100% to the treasury. {@code params}: counterBondId, claim, dispute, grant, openSnapshot, oracle, treasury. */
    public Map<String, Object> planSlashCounterBond(View view, Map<String, Object> params, double now) {
        String counterBondId = stringParam(params, "counterBondId");
        Map<String, Object> claim = StoreJs.map(params.get("claim"));
        Map<String, Object> bond = view.bond(counterBondId);
        if (bond == null) throw new IllegalStateException("slashCounterBond: no counter-bond for " + counterBondId);
        if (!"open".equals(bond.get("status"))) throw new IllegalStateException("slashCounterBond: counter-bond " + counterBondId + " is already " + bond.get("status") + " (double-settle refused)");
        needTreasury(params, "slashCounterBond");
        Map<String, Object> verdict = OptimisticAdjudication.adjudicateDispute(claim, params.get("dispute"), StoreJs.map(params.get("grant")), params.get("openSnapshot"), oracleOf(params), rMargin(params));
        if (!"claim-upheld".equals(verdict.get("outcome")) || !Boolean.TRUE.equals(verdict.get("slashCounterBond"))) {
            throw new IllegalStateException("slashCounterBond: refused — the dispute is not frivolous (" + verdict.get("outcome") + ": " + verdict.get("reason") + ")");
        }
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("treasury", params.get("treasury"));
        p.put("challengerAccount", null);
        p.put("compensationAccount", params.get("compensationAccount"));
        p.put("splitPolicy", params.get("splitPolicy"));
        return slashPlan(bond, counterBondId, now, BondSettlement.disputeEvidenceDigest(claim, verdict), p);
    }
}
