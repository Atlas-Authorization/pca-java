package net.atlasauth.pca;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.ToLongFunction;

/**
 * The pure accounting of bond settlement: exact micro-unit money arithmetic, the slash split, bond sizing, the evidence digests a signed
 * settlement record commits to, and record verification and anchoring. INTERNAL ACCOUNTING ONLY; no money moves. Policies and records
 * are JSON objects ({@link Map}); amounts are doubles on the micro grid. See {@link BondSettlementPlanner} for the signing half.
 */
public final class BondSettlement {
    private BondSettlement() {}

    /** The default escrow account label. */
    public static final String ESCROW_ACCOUNT = "escrow";
    /** The default victim-compensation pool account (contains ':', so it can never be a challenger payout account). */
    public static final String COMPENSATION_POOL_ACCOUNT = "pca:pool:compensation";
    /** Micro-units per whole unit. */
    public static final long MICROS_PER_UNIT = 1_000_000;
    /** Domain-separated tag of the settlement transparency leaf. */
    public static final String SETTLEMENT_LEAF_DOMAIN = "atlas-pca/settlement-leaf/v1";

    private static final double MAX_SAFE_MICROS = 1e15;
    private static final double MIN_SHARE_QUANTUM = Math.pow(2, -30);

    /** The conservative reference split: challenger 50%, victim pool 40%, treasury the remainder. Tunable, not a product decision. */
    public static Map<String, Object> defaultSlashSplitPolicy() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("challengerBps", StoreJs.num(5000L));
        m.put("victimBps", StoreJs.num(4000L));
        return m;
    }

    /** {@code {floor:1, k:1, maxOpenClaims:100, maxOpenAmount:Infinity}} (no curve: linear). */
    public static Map<String, Object> defaultBondPolicy() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("floor", StoreJs.num(1L));
        m.put("k", StoreJs.num(1L));
        m.put("maxOpenClaims", StoreJs.num(100L));
        m.put("maxOpenAmount", StoreJs.num(Double.POSITIVE_INFINITY));
        return m;
    }

    // ---- exact money ----

    /** Integer micro-units of {@code x} when it is a micro-grid amount below 1e15 micros, else null. */
    public static Long toMicros(double x) { return BondDoc.toMicros(x); }

    /** The number for an integer micro-unit amount (round-trips through {@link #toMicros}). */
    public static double fromMicros(long m) { return (double) m / MICROS_PER_UNIT; }

    /** Snap a computed amount UP onto the micro grid (a bond is never rounded down); float noise below 1e-3 micro-units is absorbed. */
    public static double quantizeUp(double x) {
        if (Double.isNaN(x) || Double.isInfinite(x) || x <= 0) return x;
        double scaled = x * MICROS_PER_UNIT;
        if (scaled > MAX_SAFE_MICROS) return x;
        double r = Math.floor(scaled + 0.5); // JavaScript Math.round
        double m = r / MICROS_PER_UNIT == x || Math.abs(scaled - r) <= 1e-3 ? r : Math.ceil(scaled);
        return m / MICROS_PER_UNIT;
    }

    /** a + sign*b in exact micro-unit integers when both are micro-grid amounts; plain float otherwise. */
    public static double exactAdd(double a, double b, int sign) { return BondDoc.exactAdd(a, b, sign); }

    // ---- slash split ----

    /** The exact division of one slashed bond. The three payouts sum exactly to {@code amount}. */
    public static final class SlashSplit {
        public final double amount, challengerReward, victimCompensation, treasuryRemainder;
        /** The identified challenger's payout account, or null for an anonymous challenge. */
        public final String challengerAccount;
        public final boolean hasChallengerAccount;
        public final String victimAccount, treasuryAccount;

        SlashSplit(double amount, double c, double v, double t, String challengerAccount, boolean has, String victimAccount, String treasuryAccount) {
            this.amount = amount;
            this.challengerReward = c;
            this.victimCompensation = v;
            this.treasuryRemainder = t;
            this.challengerAccount = challengerAccount;
            this.hasChallengerAccount = has;
            this.victimAccount = victimAccount;
            this.treasuryAccount = treasuryAccount;
        }

        /** The JSON form (the record's {@code split}). */
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("amount", StoreJs.num(amount));
            m.put("challengerReward", StoreJs.num(challengerReward));
            m.put("victimCompensation", StoreJs.num(victimCompensation));
            m.put("treasuryRemainder", StoreJs.num(treasuryRemainder));
            if (hasChallengerAccount) m.put("challengerAccount", challengerAccount);
            m.put("victimAccount", victimAccount);
            m.put("treasuryAccount", treasuryAccount);
            return m;
        }
    }

    private static boolean isInteger(Double v) { return v != null && !v.isNaN() && !v.isInfinite() && v == Math.floor(v); }

    static void assertSplitPolicy(Map<String, Object> p) {
        double sum = 0;
        for (String k : new String[] {"challengerBps", "victimBps"}) {
            Double v = p == null ? null : StoreJs.dbl(p.get(k));
            if (!isInteger(v) || v < 0 || v > 10_000) throw new IllegalStateException("slash split: " + k + " must be an integer in [0,10000]");
            sum += v;
        }
        if (sum > 10_000) throw new IllegalStateException("slash split: challengerBps + victimBps must not exceed 10000");
    }

    private static long shareMicros(long micros, double bps) {
        return BigInteger.valueOf(micros).multiply(BigInteger.valueOf((long) bps)).divide(BigInteger.valueOf(10_000)).longValue();
    }

    private static double shareQuantum(double amount) {
        double u = Math.ulp(amount); // the exact power-of-two unit in the last place
        if (amount == Math.floor(amount)) return Math.max(1, u);
        return Math.max(MIN_SHARE_QUANTUM, u);
    }

    private static double shareOf(double amount, double bps, double quantum) {
        double raw = (amount * bps) / 10_000;
        return Math.floor(raw / quantum) * quantum;
    }

    /**
     * The challenger / victim / treasury division of a slashed {@code amount}. Exact (treasury = amount - challenger - victim) and
     * integer-safe. {@code dest} carries {@code challengerAccount} (a string, or an explicit null for an anonymous challenge, which pays the
     * whole bond to the treasury), {@code victimAccount} and {@code treasuryAccount}.
     */
    public static SlashSplit computeSlashSplit(double amount, Map<String, Object> policy, Map<String, Object> dest) {
        if (Double.isNaN(amount) || Double.isInfinite(amount) || amount <= 0) throw new IllegalStateException("computeSlashSplit: amount must be a positive finite number");
        assertSplitPolicy(policy);
        Object victim = dest.get("victimAccount"), treasury = dest.get("treasuryAccount");
        if (!(victim instanceof String) || ((String) victim).isEmpty()) throw new IllegalStateException("computeSlashSplit: victimAccount is required");
        if (!(treasury instanceof String) || ((String) treasury).isEmpty()) throw new IllegalStateException("computeSlashSplit: treasuryAccount is required");
        boolean has = dest.containsKey("challengerAccount");
        Object ch = dest.get("challengerAccount");
        String chAcct = ch instanceof String ? (String) ch : null;
        if (has && ch == null) return new SlashSplit(amount, 0, 0, amount, null, true, (String) victim, (String) treasury); // anonymous
        Long micros = amount == Math.floor(amount) ? null : toMicros(amount); // integer bonds keep whole-unit shares
        double cbps = StoreJs.dbl(policy.get("challengerBps")), vbps = StoreJs.dbl(policy.get("victimBps"));
        if (micros != null) {
            long c = shareMicros(micros, cbps), v = shareMicros(micros, vbps);
            long t = micros - c - v;
            return new SlashSplit(fromMicros(micros), fromMicros(c), fromMicros(v), fromMicros(t), chAcct, has, (String) victim, (String) treasury);
        }
        double q = shareQuantum(amount);
        double challengerReward = Math.min(shareOf(amount, cbps, q), amount);
        double victimCompensation = Math.min(shareOf(amount, vbps, q), amount - challengerReward);
        double treasuryRemainder = amount - challengerReward - victimCompensation;
        return new SlashSplit(amount, challengerReward, victimCompensation, treasuryRemainder, chAcct, has, (String) victim, (String) treasury);
    }

    // ---- bond sizing ----

    private static double dnum(Object o) { Double d = StoreJs.dbl(o); return d == null ? Double.NaN : d; }

    private static double curveComponent(Map<String, Object> curve, double k, double e) {
        Object kind = curve == null ? null : curve.get("kind");
        if (curve == null || "linear".equals(kind)) return k * e;
        if ("power".equals(kind)) {
            double gamma = dnum(curve.get("gamma"));
            if (!(!Double.isNaN(gamma) && !Double.isInfinite(gamma) && gamma >= 1)) throw new IllegalStateException("bondAmount: power curve requires finite gamma >= 1");
            return k * StrictMath.pow(e, gamma);
        }
        Object tiersO = curve.get("tiers");
        if (!(tiersO instanceof List) || ((List<?>) tiersO).isEmpty()) throw new IllegalStateException("bondAmount: piecewise curve requires at least one tier");
        double acc = 0, prevUpTo = 0, prevMarginal = 0;
        for (Object to : (List<?>) tiersO) {
            Map<String, Object> tier = StoreJs.map(to);
            if (tier == null) throw new IllegalStateException("bondAmount: malformed tier");
            double upTo = dnum(tier.get("upTo")), mk = dnum(tier.get("marginalK"));
            if (!(!Double.isNaN(upTo) && !Double.isInfinite(upTo) && upTo > prevUpTo) && upTo != Double.POSITIVE_INFINITY) {
                throw new IllegalStateException("bondAmount: piecewise tier `upTo` must be strictly increasing");
            }
            if (!(!Double.isNaN(mk) && !Double.isInfinite(mk) && mk >= 0)) throw new IllegalStateException("bondAmount: piecewise `marginalK` must be a finite number >= 0");
            if (mk < prevMarginal) throw new IllegalStateException("bondAmount: piecewise marginal rates must be non-decreasing (convex)");
            double width = Math.min(e, upTo) - prevUpTo;
            if (width > 0) acc += width * mk;
            prevUpTo = upTo;
            prevMarginal = mk;
            if (e <= upTo) break;
        }
        if (e > prevUpTo) acc += (e - prevUpTo) * prevMarginal;
        return k * acc;
    }

    /** {@code max(floor, curve(k, exposure))} snapped up onto the micro grid; no curve = linear. Non-finite or non-positive exposure gives the floor. */
    public static double bondAmount(Map<String, Object> policy, double exposure) {
        double e = !Double.isNaN(exposure) && !Double.isInfinite(exposure) && exposure > 0 ? exposure : 0;
        Object curve = policy.get("curve");
        return quantizeUp(Math.max(dnum(policy.get("floor")), curveComponent(StoreJs.map(curve), dnum(policy.get("k")), e)));
    }

    // ---- evidence digests ----

    private static Map<String, Object> claimIdentity(Map<String, Object> claim) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("claimDigest", claim.get("pcactn_digest"));
        m.put("bond_ref", claim.get("bond_ref"));
        return m;
    }

    /** Binds a slash to the server-derived fraud verdict ({@code fraudulent}, {@code slashBondRef}, {@code reason}). */
    public static String settlementEvidenceDigest(Map<String, Object> claim, Map<String, Object> fraudVerdict) {
        Map<String, Object> m = claimIdentity(claim);
        m.put("fraudulent", fraudVerdict.get("fraudulent"));
        m.put("slashBondRef", fraudVerdict.get("slashBondRef"));
        m.put("reason", fraudVerdict.get("reason"));
        return StoreJs.hashLenient(m);
    }

    /** Evidence digest of a revocation slash (a capability in the claim's chain was revoked after the bond opened). */
    public static String revocationEvidenceDigest(Map<String, Object> claim, String revokedCapId) {
        Map<String, Object> m = claimIdentity(claim);
        m.put("kind", "revocation");
        m.put("revokedCapId", revokedCapId);
        return StoreJs.hashLenient(m);
    }

    /** Evidence digest of a dispute-game slash: the adjudicator's own verdict, never a challenger assertion. */
    public static String disputeEvidenceDigest(Map<String, Object> claim, Map<String, Object> verdict) {
        Map<String, Object> m = claimIdentity(claim);
        m.put("kind", "dispute");
        m.put("outcome", verdict.get("outcome"));
        m.put("input", verdict.get("input"));
        m.put("agentValue", verdict.get("agentValue"));
        m.put("oracleValue", verdict.get("oracleValue"));
        m.put("slashBondRef", verdict.get("slashBondRef"));
        m.put("reason", verdict.get("reason"));
        return StoreJs.hashLenient(m);
    }

    // ---- verification and anchoring ----

    static byte[] settlementMessage(Map<String, Object> body) {
        return Pca.concat(Json.utf8(Optimistic.SETTLEMENT_DOMAIN), Json.canonicalize(body).getBytes(StandardCharsets.UTF_8));
    }

    /** Verify a settlement record's signature under the guardian public key; suite-agile (a PQ half needs a pin in {@code pins}). Never throws. */
    public static boolean verifySettlement(Object recordO, String guardianPublicKey, Map<String, Object> pins) {
        try {
            Map<String, Object> r = StoreJs.map(recordO);
            if (r == null) return false;
            Map<String, Object> body = new LinkedHashMap<>(r);
            body.remove("sig");
            body.remove("pq_sig");
            if (!(r.get("sig") instanceof String) || Pq.resolveSigAlg(r.get("alg"), r.containsKey("alg")) == null) return false;
            return IntentJs.verifyPinnedSuite(r.get("alg"), r.containsKey("alg"), guardianPublicKey, r.get("pq_pk"), settlementMessage(body), r.get("sig"), r.get("pq_sig"), pins);
        } catch (RuntimeException e) {
            return false;
        }
    }

    public static boolean verifySettlement(Object record, String guardianPublicKey) { return verifySettlement(record, guardianPublicKey, null); }

    /** Canonical digest of a signed settlement record (the whole record, signature included). */
    public static String settlementRecordDigest(Map<String, Object> record) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("t", SETTLEMENT_LEAF_DOMAIN);
        m.put("record", record);
        return StoreJs.hashLenient(m);
    }

    /** The salted commitment of a settlement record (the opaque transparency-log leaf). */
    public static String settlementCommit(String salt, Map<String, Object> record) {
        if (salt == null || salt.isEmpty()) throw new IllegalStateException("settlementCommit: salt must be a non-empty string");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("salt", salt);
        m.put("settlement_digest", settlementRecordDigest(record));
        return StoreJs.hashLenient(m);
    }

    /** True iff {@code salt} + {@code record} reproduce the anchored {@code commit}. Never throws. */
    public static boolean verifySettlementCommit(String commit, String salt, Map<String, Object> record) {
        try {
            return settlementCommit(salt, record).equals(commit);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Append a settlement record as a salted commitment through {@code append} (for example {@code log::appendCommitment} of a
     * {@link MerkleLog}, or {@code storedLedger::append}); returns {@code {index, commit, salt}}. A null {@code salt} draws 16 random bytes.
     */
    public static Map<String, Object> appendSettlement(ToLongFunction<String> append, Map<String, Object> record, String salt) {
        String s = salt;
        if (s == null) {
            byte[] b = new byte[16];
            new SecureRandom().nextBytes(b);
            s = Keys.b64u(b);
        }
        String commit = settlementCommit(s, record);
        long index = append.applyAsLong(commit);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("index", StoreJs.num(index));
        m.put("commit", commit);
        m.put("salt", s);
        return m;
    }
}
