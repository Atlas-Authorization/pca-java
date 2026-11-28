package net.atlasauth.pca.ratchet;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Map;
import net.atlasauth.pca.Json;

/**
 * Thin adapters that bind the two mechanisms to the PCA bookkeeping they replace: the ratchet leaf index is the PCActn spend-once counter,
 * and the accumulator's integer units are the core risk budget (RiskPolicy.bMax / kappa). They map values only.
 */
public final class Adapters {
    private Adapters() {}

    /** Fixed-point scale for quantizing risk scores (r in [0, 1]) into accumulator units: 1000 = millirisk resolution. */
    public static final int RISK_SCALE = 1000;

    private static final BigInteger NANO = BigInteger.valueOf(1_000_000L);

    private static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        return o instanceof Number ? Double.valueOf(((Number) o).doubleValue()) : null;
    }

    private static boolean isSafeInteger(Double d) {
        return d != null && !d.isNaN() && !d.isInfinite() && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0;
    }

    private static boolean isNegZero(Double d) { return d == 0.0 && Double.doubleToRawLongBits(d) != 0L; }

    /**
     * Map a PCActn's spend-once counter to a ratchet leaf index: spending counter c signs (and punctures) leaf c, so a counter can never be
     * re-used. Throws {@link RatchetError} (invalid_depth, leaf_out_of_range).
     */
    public static long counterToLeafIndex(Object counter, Object depth) {
        Double dp = num(depth);
        if (dp == null || dp.isNaN() || dp.isInfinite() || dp != Math.rint(dp) || dp < 1 || dp > Ratchet.MAX_RATCHET_DEPTH)
            throw new RatchetError("invalid_depth", "depth must be an integer in [1, " + Ratchet.MAX_RATCHET_DEPTH + "]");
        Double c = num(counter);
        if (!isSafeInteger(c) || c < 0 || isNegZero(c)) throw new RatchetError("leaf_out_of_range", "counter must be a non-negative safe integer");
        if (c >= Math.pow(2, dp)) throw new RatchetError("leaf_out_of_range", "counter " + c.longValue() + " exceeds the ratchet capacity 2^" + dp.intValue());
        return c.longValue();
    }

    /** Inverse of {@link #counterToLeafIndex}: a leaf index is the spend-once counter it realizes. */
    public static long leafIndexToCounter(Object leafIndex) {
        Double d = num(leafIndex);
        if (!isSafeInteger(d) || d < 0 || isNegZero(d)) throw new RatchetError("leaf_out_of_range", "leafIndex must be a non-negative safe integer");
        return d.longValue();
    }

    /** The ratchet leaf index for a PCActn, read straight off its {@code counter} field. */
    public static long leafIndexForAction(Map<String, Object> actn, Object depth) { return counterToLeafIndex(actn.get("counter"), depth); }

    /** Math.round of JavaScript: floor(x + 0.5) without the precision loss, NaN and the infinities unchanged. */
    private static double jsRound(double x) {
        if (Double.isNaN(x) || Double.isInfinite(x)) return x;
        double f = Math.floor(x);
        return x - f >= 0.5 ? f + 1 : f;
    }

    private static BigInteger bigInt(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) throw new IllegalArgumentException("cannot convert a non-finite number to a BigInt");
        return new BigDecimal(d).toBigInteger();
    }

    /**
     * Quantize a core risk score (any finite r >= 0) to non-negative integer accumulator units, ROUNDING UP (a nonzero risk is never 0 units; a sum
     * of quantized risks never under-counts the true sum). A value within float noise of an exact unit keeps that unit.
     */
    public static BigInteger riskToUnits(Object r) {
        Double d = num(r);
        if (d == null || d.isNaN() || d.isInfinite() || d < 0) throw new AccumulatorError("invalid_value", "risk must be a finite number >= 0");
        double v = d * RISK_SCALE;
        double nearest = jsRound(v);
        if (Math.abs(v - nearest) <= 1e-9 * Math.max(1, v)) return bigInt(nearest);
        return bigInt(Math.ceil(v));
    }

    /**
     * Carry-forward quantizer: emits per-action integer units such that the running total of emitted units is ALWAYS
     * {@code ceil(sum of true risk * SCALE)} (never below the true cumulative sum). Stateful; one instance per budget stream.
     */
    public static final class RiskQuantizer {
        private BigInteger nano = BigInteger.ZERO;
        private BigInteger emitted = BigInteger.ZERO;

        public BigInteger next(Object r) {
            Double d = num(r);
            if (d == null || d.isNaN() || d.isInfinite() || d < 0) throw new AccumulatorError("invalid_value", "risk must be a finite number >= 0");
            // r * SCALE in millionths of a unit, rounded UP so the total can only over-approximate
            BigInteger add = bigInt(Math.ceil(d * RISK_SCALE * 1e6 - 1e-3));
            nano = nano.add(add);
            BigInteger total = nano.add(NANO).subtract(BigInteger.ONE).divide(NANO);
            BigInteger out = total.subtract(emitted);
            emitted = total;
            return out;
        }

        public BigInteger totalUnits() { return emitted; }
    }

    /** JavaScript ToNumber of a policy member: an absent member is NaN, null is 0, a number is itself, anything else is NaN. */
    private static double member(Map<String, Object> m, String k) {
        if (!m.containsKey(k)) return Double.NaN;
        Object o = m.get(k);
        if (o == null) return 0;
        Double d = num(o);
        return d == null ? Double.NaN : d;
    }

    /**
     * The accumulator's budget ceiling in integer units from a RiskPolicy: the core cumulative-risk safety bound {@code sum(risk) <= bMax / kappa},
     * quantized, so the zero-knowledge verifyBudget proves the SAME inequality the control plane enforces.
     */
    public static BigInteger budgetCeilingUnits(Map<String, Object> policy) {
        double kappa = member(policy, "kappa");
        double bMax = member(policy, "bMax");
        double bound = kappa > 0 ? Math.max(0, bMax) / kappa : 0;
        if (Double.isNaN(bound) || Double.isInfinite(bound) || bound < 0)
            throw new AccumulatorError("invalid_value", "safety bound (bMax/kappa) must be finite and >= 0");
        return bigInt(Math.floor(bound * RISK_SCALE));
    }
}
