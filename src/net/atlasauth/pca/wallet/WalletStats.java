package net.atlasauth.pca.wallet;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.function.Predicate;

/**
 * Small numerics for the noise estimates: log-gamma (Lanczos), the regularized incomplete beta function (continued fraction,
 * modified Lentz) and its quantile by bisection, the exact Clopper-Pearson upper bound (binomial-tail inversion in integer
 * arithmetic) and the binary entropy. Deterministic. The transcendental functions are the fdlibm ones (StrictMath), which is
 * what the reference's runtime computes, so results agree to the last bit; operation order follows the reference exactly.
 */
public final class WalletStats {
    private WalletStats() {}

    private static final double[] LANCZOS = {676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905,
        -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7};

    public static double lnGamma(double x) {
        if (x < 0.5) return StrictMath.log(Math.PI / StrictMath.sin(Math.PI * x)) - lnGamma(1 - x);
        double z = x - 1;
        double a = 0.99999999999980993;
        double t = z + 7.5;
        for (int i = 0; i < LANCZOS.length; i++) a += LANCZOS[i] / (z + i + 1);
        return 0.5 * StrictMath.log(2 * Math.PI) + (z + 0.5) * StrictMath.log(t) - t + StrictMath.log(a);
    }

    /** The continued fraction of I_x(a, b) (modified Lentz; a zero denominator is replaced by 1e-300, never divided by). */
    public static double betacf(double a, double b, double x) {
        final double TINY = 1e-300;
        double qab = a + b;
        double qap = a + 1;
        double qam = a - 1;
        double c = 1;
        double d = 1 - (qab * x) / qap;
        if (Math.abs(d) < TINY) d = TINY;
        d = 1 / d;
        double h = d;
        for (int m = 1; m <= 300; m++) {
            int m2 = 2 * m;
            double aa = (m * (b - m) * x) / ((qam + m2) * (a + m2));
            d = 1 + aa * d;
            if (Math.abs(d) < TINY) d = TINY;
            c = 1 + aa / c;
            if (Math.abs(c) < TINY) c = TINY;
            d = 1 / d;
            h *= d * c;
            aa = (-(a + m) * (qab + m) * x) / ((a + m2) * (qap + m2));
            d = 1 + aa * d;
            if (Math.abs(d) < TINY) d = TINY;
            c = 1 + aa / c;
            if (Math.abs(c) < TINY) c = TINY;
            d = 1 / d;
            double del = d * c;
            h *= del;
            if (Math.abs(del - 1) < 1e-15) break;
        }
        return h;
    }

    /** Regularized incomplete beta I_x(a, b), a, b &gt; 0, x in [0, 1]. */
    public static double betaInc(double x, double a, double b) {
        if (!(a > 0 && b > 0)) throw new IllegalArgumentException("betaInc: a and b must be > 0");
        if (x <= 0) return 0;
        if (x >= 1) return 1;
        double lbt = lnGamma(a + b) - lnGamma(a) - lnGamma(b) + a * StrictMath.log(x) + b * StrictMath.log(1 - x);
        double bt = StrictMath.exp(lbt);
        if (x < (a + 1) / (a + b + 2)) return (bt * betacf(a, b, x)) / a;
        return 1 - (bt * betacf(b, a, 1 - x)) / b;
    }

    /** The q-quantile of Beta(a, b): the x with I_x(a, b) = q (bisection, 200 steps). */
    public static double betaQuantile(double q, double a, double b) {
        if (!(q >= 0 && q <= 1)) throw new IllegalArgumentException("betaQuantile: q must be in [0, 1]");
        if (q == 0) return 0;
        if (q == 1) return 1;
        double lo = 0;
        double hi = 1;
        for (int i = 0; i < 200; i++) {
            double mid = (lo + hi) / 2;
            if (betaInc(mid, a, b) < q) lo = mid;
            else hi = mid;
        }
        return hi;
    }

    // ---- exact Clopper-Pearson --------------------------------------------------------------------------------------------

    private static final int CP_GRID_BITS = 52;
    private static final BigInteger A = BigInteger.ONE.shiftLeft(CP_GRID_BITS);
    private static final BigInteger TOL_UNITS = BigInteger.ONE.shiftLeft(CP_GRID_BITS - 44);

    private static double[] logFactorials(int n) {
        double[] lf = new double[n + 1];
        for (int i = 1; i <= n; i++) lf[i] = lf[i - 1] + StrictMath.log(i);
        return lf;
    }

    /** P(X &lt;= k) for X ~ Binomial(n, p) in floating point (a starting guess only; never decides a result). */
    static double binomialCdf(int k, int n, double p, double[] lf) {
        if (k >= n) return 1;
        if (k < 0) return 0;
        if (p <= 0) return 1;
        if (p >= 1) return 0;
        double lp = StrictMath.log(p);
        double lq = StrictMath.log1p(-p);
        double s = 0;
        for (int i = 0; i <= k; i++) s += StrictMath.exp(lf[n] - lf[i] - lf[n - i] + i * lp + (n - i) * lq);
        return Math.min(1, s);
    }

    private static BigInteger[] doubleToDyadic(double x) {
        if (!(x > 0 && x < 1)) throw new IllegalArgumentException("doubleToDyadic: need 0 < x < 1");
        int e = 0;
        double y = x;
        while (y != Math.rint(y)) {
            y *= 2;
            e++;
            if (e > 1100) throw new IllegalStateException("doubleToDyadic: not reached");
        }
        return new BigInteger[] {new BigDecimal(y).toBigInteger(), BigInteger.valueOf(e)};
    }

    /** The numerator N with cdfRec(a / 2^52, n, k) = N / 2^(52 n), by the recursion of the Lean definition. */
    static BigInteger cdfRecNumerator(int n, int k, BigInteger a) {
        if (a.signum() < 0 || a.compareTo(A) > 0) throw new IllegalArgumentException("cdfRecNumerator: a must be in [0, 2^52]");
        BigInteger b = A.subtract(a);
        int K = Math.min(k, n);
        BigInteger[] row = new BigInteger[K + 1];
        java.util.Arrays.fill(row, BigInteger.ONE);
        BigInteger pow = BigInteger.ONE;
        for (int m = 0; m < n; m++) {
            BigInteger[] next = new BigInteger[K + 1];
            BigInteger powNext = pow.multiply(A);
            for (int j = 0; j <= K; j++) {
                if (j >= m + 1) next[j] = powNext;
                else {
                    BigInteger left = j == 0 ? BigInteger.ZERO : row[j - 1];
                    next[j] = a.multiply(left).add(b.multiply(row[j]));
                }
            }
            row = next;
            pow = powNext;
        }
        return row[K];
    }

    private static boolean cdfExceeds(int n, int k, BigInteger a, BigInteger[] alpha) {
        BigInteger N = cdfRecNumerator(n, k, a);
        return N.shiftLeft(alpha[1].intValueExact()).compareTo(alpha[0].multiply(A.pow(n))) > 0;
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

    /** A bracket [lo, hi] of at most TOL_UNITS around the point where {@code exceeds} (antitone) flips, from any start. */
    private static BigInteger[] certifyBracket(BigInteger start, Predicate<BigInteger> exceeds) {
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
        return new BigInteger[] {hi, lo};
    }

    /**
     * One-sided exact Clopper-Pearson upper bound on a binomial rate (k successes in n trials, level 1 - alpha): a multiple of
     * 2^-52 within 2^-44 above the exact bound. Throws unless 0 &lt;= k &lt;= n are integers and alpha is in (0, 1).
     */
    public static double clopperPearsonUpper(double kD, double nD, double alpha) {
        if (!(kD == Math.rint(kD) && nD == Math.rint(nD) && !Double.isInfinite(kD) && !Double.isInfinite(nD) && kD >= 0 && nD >= 0 && kD <= nD))
            throw new IllegalArgumentException("clopperPearsonUpper: need integers 0 <= k <= n");
        if (!(alpha > 0 && alpha < 1)) throw new IllegalArgumentException("clopperPearsonUpper: alpha must be in (0, 1)");
        if (nD > 100_000) throw new IllegalArgumentException("clopperPearsonUpper: n too large");
        final int k = (int) kD, n = (int) nD;
        if (n == 0 || k == n) return 1;
        final BigInteger[] al = doubleToDyadic(alpha);
        double g = floatGuess(k, n, alpha);
        BigInteger start = clamp(new BigDecimal(Math.ceil(g * 4503599627370496.0)).toBigInteger().add(TOL_UNITS));
        BigInteger[] r = certifyBracket(start, a -> cdfExceeds(n, k, a, al));
        return r[0].doubleValue() / 4503599627370496.0;
    }

    /**
     * The upper bound q such that the Beta(a, b) posterior puts mass delta above it, for POSITIVE INTEGER a and b, exactly: I_x(a, b) =
     * P[Bin(a + b - 1, x) >= a], so the quantile at level 1 - delta is the Clopper-Pearson inversion with k = a - 1 successes in
     * n = a + b - 1 trials (integer arithmetic, rounded outward to 2^-44). The freeze and admission decisions compare this value, so it
     * must not depend on a platform's libm.
     */
    public static double betaUpperExact(double delta, double a, double b) {
        if (!(a == Math.rint(a) && a >= 1 && !Double.isInfinite(a) && b == Math.rint(b) && b >= 1 && !Double.isInfinite(b))) throw new IllegalArgumentException("betaUpperExact: a and b must be positive integers");
        return clopperPearsonUpper(a - 1, a + b - 1, delta);
    }

    // ---- entropy ------------------------------------------------------------------------------------------------------

    /** Binary entropy in bits. */
    public static double binEnt(double p) {
        if (p <= 0 || p >= 1) return 0;
        return -(p * log2(p) + (1 - p) * log2(1 - p));
    }

    private static final double TWO54 = 1.80143985094819840000e+16;
    private static final double IVLN2HI = 1.44269504072144627571e+00;
    private static final double IVLN2LO = 1.67517131648865118353e-10;
    private static final double LG1 = 6.666666666666735130e-01, LG2 = 3.999999999940941908e-01, LG3 = 2.857142874366239149e-01,
        LG4 = 2.222219843214978396e-01, LG5 = 1.818357216161805012e-01, LG6 = 1.531383769920937332e-01, LG7 = 1.479819860511658591e-01;

    private static double kLog1p(double f) {
        double s = f / (2.0 + f);
        double z = s * s;
        double w = z * z;
        double t1 = w * (LG2 + w * (LG4 + w * LG6));
        double t2 = z * (LG1 + w * (LG3 + w * (LG5 + w * LG7)));
        double r = t2 + t1;
        double hfsq = 0.5 * f * f;
        return s * (hfsq + r);
    }

    private static int hiWord(double x) { return (int) (Double.doubleToRawLongBits(x) >> 32); }

    private static int loWord(double x) { return (int) Double.doubleToRawLongBits(x); }

    private static double withHi(double x, int hi) { return Double.longBitsToDouble(((long) hi << 32) | (Double.doubleToRawLongBits(x) & 0xffffffffL)); }

    private static double withLoZero(double x) { return Double.longBitsToDouble(Double.doubleToRawLongBits(x) & 0xffffffff00000000L); }

    /** log2 as the reference's runtime computes it (the fdlibm / FreeBSD algorithm; StrictMath has no log2). */
    public static double log2(double x) {
        int hx = hiWord(x);
        int lx = loWord(x);
        int k = 0;
        if (hx < 0x00100000) {
            if (((hx & 0x7fffffff) | lx) == 0) return Double.NEGATIVE_INFINITY;
            if (hx < 0) return Double.NaN;
            k -= 54;
            x *= TWO54;
            hx = hiWord(x);
        }
        if (hx >= 0x7ff00000) return x + x;
        if (hx == 0x3ff00000 && lx == 0) return 0;
        k += (hx >> 20) - 1023;
        hx &= 0x000fffff;
        int i = (hx + 0x95f64) & 0x100000;
        x = withHi(x, hx | (i ^ 0x3ff00000));
        k += (i >> 20);
        double y = k;
        double f = x - 1.0;
        double hfsq = 0.5 * f * f;
        double r = kLog1p(f);
        double hi = withLoZero(f - hfsq);
        double lo = (f - hi) - hfsq + r;
        double valHi = hi * IVLN2HI;
        double valLo = (lo + hi) * IVLN2LO + lo * IVLN2HI;
        double w = y + valHi;
        valLo += (y - w) + valHi;
        valHi = w;
        return valLo + valHi;
    }
}
