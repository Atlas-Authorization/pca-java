package net.atlasauth.pca.intent;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.function.Predicate;

/**
 * Exact Clopper-Pearson upper bounds (integer arithmetic on the 2^-52 grid), the floating-point binomial CDF used for starting
 * guesses, Hoeffding half-widths and Wilson intervals. Mirrors the reference numerics bit for bit: logarithms and exponentials
 * come from StrictMath (fdlibm, as the reference engine's), square roots are exact.
 */
public final class IntentStats {
    private IntentStats() {}

    public static final int CP_GRID_BITS = 52;
    public static final double CP_TOLERANCE = Math.scalb(1.0, -44);

    private static final BigInteger A = BigInteger.ONE.shiftLeft(CP_GRID_BITS);
    private static final BigInteger TOL_UNITS = BigInteger.ONE.shiftLeft(CP_GRID_BITS - 44);

    /** The exact binary fraction num / 2^exp of a double in (0, 1). */
    public record Dyadic(BigInteger num, int exp) {}

    /** A bound on the 2^-52 grid with its certified bracket. */
    public record CPCertificate(double upper, BigInteger upperUnits, BigInteger lowerUnits) {}

    /** The bracket of {@link #certifyBracket}. */
    public record Bracket(BigInteger hi, BigInteger lo) {}

    public record Wilson(double p, double lo, double hi) {}

    public static double[] logFactorials(int n) {
        double[] lf = new double[n + 1];
        for (int i = 1; i <= n; i++) lf[i] = lf[i - 1] + StrictMath.log(i);
        return lf;
    }

    /** P(X &lt;= k), X ~ Binomial(n, p), in floating point (guesses and diagnostics only). */
    public static double binomialCdf(int k, int n, double p) { return binomialCdf(k, n, p, null); }

    public static double binomialCdf(int k, int n, double p, double[] lf) {
        if (k >= n) return 1;
        if (k < 0) return 0;
        if (p <= 0) return 1;
        if (p >= 1) return 0;
        if (lf == null) lf = logFactorials(n);
        double lp = StrictMath.log(p);
        double lq = StrictMath.log1p(-p);
        double s = 0;
        for (int i = 0; i <= k; i++) s += StrictMath.exp(lf[n] - lf[i] - lf[n - i] + i * lp + (n - i) * lq);
        return Math.min(1, s);
    }

    public static Dyadic doubleToDyadic(double x) {
        if (!(Double.isFinite(x) && x > 0 && x < 1)) throw new IllegalArgumentException("doubleToDyadic: need 0 < x < 1");
        int e = 0;
        double y = x;
        while (y != Math.rint(y)) {
            y *= 2;
            e++;
            if (e > 1100) throw new IllegalArgumentException("doubleToDyadic: not reached");
        }
        return new Dyadic(new BigDecimal(y).toBigIntegerExact(), e);
    }

    /** N with cdfRec(a / 2^52, n, k) = N / 2^(52 n), by the recursion of the definition. */
    public static BigInteger cdfRecNumerator(int n, int k, BigInteger a) {
        if (a.signum() < 0 || a.compareTo(A) > 0) throw new IllegalArgumentException("cdfRecNumerator: a must be in [0, 2^52]");
        BigInteger b = A.subtract(a);
        int kk = Math.min(k, n);
        if (kk < 0) throw new IllegalArgumentException("cdfRecNumerator: bad k");
        BigInteger[] row = new BigInteger[kk + 1];
        java.util.Arrays.fill(row, BigInteger.ONE);
        BigInteger pow = BigInteger.ONE;
        for (int m = 0; m < n; m++) {
            BigInteger[] next = new BigInteger[kk + 1];
            BigInteger powNext = pow.multiply(A);
            for (int j = 0; j <= kk; j++) {
                if (j >= m + 1) next[j] = powNext;
                else {
                    BigInteger left = j == 0 ? BigInteger.ZERO : row[j - 1];
                    next[j] = a.multiply(left).add(b.multiply(row[j]));
                }
            }
            row = next;
            pow = powNext;
        }
        return row[kk];
    }

    /** Exactly decides alpha &lt; cdfRec(a / 2^52, n, k). */
    public static boolean cdfExceeds(int n, int k, BigInteger a, Dyadic alpha) {
        BigInteger N = cdfRecNumerator(n, k, a);
        return N.shiftLeft(alpha.exp()).compareTo(alpha.num().multiply(A.pow(n))) > 0;
    }

    private static double floatGuess(int k, int n, double alpha) {
        double[] lf = logFactorials(n);
        double lo = (double) k / n;
        double hi = 1;
        for (int it = 0; it < 200 && hi - lo > 1e-13; it++) {
            double mid = (lo + hi) / 2;
            if (binomialCdf(k, n, mid, lf) > alpha) lo = mid;
            else hi = mid;
        }
        return hi;
    }

    private static BigInteger clamp(BigInteger a) { return a.signum() < 0 ? BigInteger.ZERO : a.compareTo(A) > 0 ? A : a; }

    public static CPCertificate clopperPearsonCertified(double kD, double nD, double alpha) {
        if (!(isInt(kD) && isInt(nD) && kD >= 0 && nD >= 0 && kD <= nD)) throw new IllegalArgumentException("clopperPearsonUpper: need integers 0 <= k <= n");
        if (!(alpha > 0 && alpha < 1)) throw new IllegalArgumentException("clopperPearsonUpper: alpha must be in (0, 1)");
        int k = (int) kD;
        int n = (int) nD;
        if (n == 0 || k == n) return new CPCertificate(1, A, A);
        Dyadic al = doubleToDyadic(alpha);
        BigInteger start = clamp(BigInteger.valueOf((long) Math.ceil(floatGuess(k, n, alpha) * Math.scalb(1.0, CP_GRID_BITS))).add(TOL_UNITS));
        Bracket br = certifyBracket(start, a -> cdfExceeds(n, k, a, al));
        return new CPCertificate(br.hi().doubleValue() / Math.scalb(1.0, CP_GRID_BITS), br.hi(), br.lo());
    }

    private static boolean isInt(double d) { return Double.isFinite(d) && d == Math.rint(d); }

    /** Certifies a bracket of at most TOL_UNITS around the flip point of the antitone {@code exceeds}. */
    public static Bracket certifyBracket(BigInteger start, Predicate<BigInteger> exceeds) {
        BigInteger hi = start;
        BigInteger step = TOL_UNITS;
        while (exceeds.test(hi)) {
            hi = clamp(hi.add(step));
            step = step.shiftLeft(1);
        }
        BigInteger lo = clamp(hi.subtract(TOL_UNITS));
        step = TOL_UNITS;
        while (lo.signum() > 0 && !exceeds.test(lo)) {
            hi = lo;
            lo = clamp(lo.subtract(step));
            step = step.shiftLeft(1);
        }
        if (lo.signum() == 0 && !exceeds.test(BigInteger.ZERO)) throw new IllegalStateException("clopperPearsonUpper: unreachable (cdfRec(0) = 1)");
        while (hi.subtract(lo).compareTo(TOL_UNITS) > 0) {
            BigInteger mid = lo.add(hi).shiftRight(1);
            if (exceeds.test(mid)) lo = mid;
            else hi = mid;
        }
        return new Bracket(hi, lo);
    }

    public static double clopperPearsonUpper(double k, double n, double alpha) { return clopperPearsonCertified(k, n, alpha).upper(); }

    public static double hoeffdingHalfWidth(double range, double samples) { return hoeffdingHalfWidth(range, samples, 0.05); }

    public static double hoeffdingHalfWidth(double range, double samples, double deltaPrime) {
        return range * Math.sqrt(StrictMath.log(2 / deltaPrime) / (2 * samples));
    }

    public static Wilson wilsonInterval(double k, double n) { return wilsonInterval(k, n, 1.959963984540054); }

    public static Wilson wilsonInterval(double k, double n, double z) {
        if (!(n > 0)) return new Wilson(Double.NaN, 0, 1);
        double p = k / n;
        double z2 = z * z;
        double den = 1 + z2 / n;
        double centre = (p + z2 / (2 * n)) / den;
        double half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / den;
        return new Wilson(p, Math.max(0, centre - half), Math.min(1, centre + half));
    }
}
