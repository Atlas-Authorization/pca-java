package net.atlasauth.pca;

import java.math.BigInteger;

/**
 * Deterministic math: the same bit pattern on every platform and in every language. libm's log, exp, log2 and pow are not correctly rounded
 * and differ in the last digit between implementations, which moves a decision that sits on a boundary (the drift threshold, the next
 * question, a map weight, an integer cut point). These functions use only integer arithmetic: fixed point with 96 fractional bits (a value
 * is an integer scaled by 2^96), TRUNCATING division (toward zero), and one final conversion of the integer to a double with
 * round-to-nearest-even followed by an exact power-of-two scaling.
 * <ul>
 * <li>{@link #detLn}: x = m 2^E, m = M / 2^52 in [1, 2) (M the 53-bit significand); ln x = E LN2 + 2 atanh((M - 2^52) / (M + 2^52)), atanh summed as
 *     z + z^3/3 + z^5/5 + ... (z fixed point, z2 = (z z) / 2^96 truncated) until a term is 0; LN2 = 2 atanh(1/3).</li>
 * <li>{@link #detLog2}: the same fixed value divided by LN2 in fixed point ((fixed 2^96) / LN2, truncating): an exact power of two gives its
 *     integer exponent exactly.</li>
 * <li>{@link #detExp}: X = trunc(x 2^96); k = floor((X + LN2/2) / LN2); r = X - k LN2; e^r = sum of r^n / n! with term_0 = 2^96,
 *     term_n = trunc(trunc(term_{n-1} r / 2^96) / n), until a term is 0; result = double(sum) 2^(k - 96), the scaling split into two exact
 *     powers of two. x above 709.782712893384 gives +Infinity, x below -745.2 gives 0, NaN gives NaN.</li>
 * <li>{@link #detPowInt}: b^n for an integer n >= 0, 1 multiplied by b, n times, in sequence.</li>
 * </ul>
 */
public final class DetMath {
    private DetMath() {}

    private static final int FRAC = 96;
    private static final BigInteger ONE = BigInteger.ONE.shiftLeft(FRAC);
    private static final BigInteger TWO52 = BigInteger.ONE.shiftLeft(52);
    private static final BigInteger LN2 = atanh2(BigInteger.ONE, BigInteger.valueOf(3)); // ln 2 = 2 atanh(1/3)
    private static final double ONE_D = ONE.doubleValue(); // 2^96, exact

    /** 2 atanh(num / den) in fixed point. */
    private static BigInteger atanh2(BigInteger num, BigInteger den) {
        BigInteger z = num.shiftLeft(FRAC).divide(den);
        BigInteger z2 = z.multiply(z).shiftRight(FRAC);
        BigInteger term = z, sum = BigInteger.ZERO;
        for (long i = 1; term.signum() != 0; i += 2) {
            sum = sum.add(term.divide(BigInteger.valueOf(i)));
            term = term.multiply(z2).shiftRight(FRAC);
        }
        return sum.shiftLeft(1);
    }

    /** Fixed-point ln(x) (an integer scaled by 2^96) of a positive finite double. */
    private static BigInteger lnFixed(double x) {
        long scale = 0;
        double y = x;
        if (y < Double.MIN_NORMAL) {
            y *= Math.scalb(1.0, 64);
            scale = 64;
        }
        long bits = Double.doubleToRawLongBits(y);
        long e = ((bits >>> 52) & 0x7ffL) - 1023 - scale;
        BigInteger m = BigInteger.valueOf(bits & ((1L << 52) - 1)).or(TWO52);
        return LN2.multiply(BigInteger.valueOf(e)).add(atanh2(m.subtract(TWO52), m.add(TWO52)));
    }

    /** ln x: -Infinity for zero (either sign), NaN for x below zero or NaN, +Infinity for +Infinity, exactly 0 for 1. */
    public static double detLn(double x) {
        if (x == 0) return Double.NEGATIVE_INFINITY; // as Math.log (either sign of zero): a probability of 0 is a weight of 0 after detExp, never NaN
        if (!(x > 0)) return Double.NaN;
        if (x == Double.POSITIVE_INFINITY) return x;
        if (x == 1) return 0;
        return lnFixed(x).doubleValue() / ONE_D;
    }

    /** log2 x (an exact power of two gives its exponent exactly). */
    public static double detLog2(double x) {
        if (x == 0) return Double.NEGATIVE_INFINITY;
        if (!(x > 0)) return Double.NaN;
        if (x == Double.POSITIVE_INFINITY) return x;
        if (x == 1) return 0;
        return lnFixed(x).shiftLeft(FRAC).divide(LN2).doubleValue() / ONE_D;
    }

    private static BigInteger floorDiv(BigInteger a, BigInteger b) {
        BigInteger[] qr = a.divideAndRemainder(b);
        return qr[1].signum() != 0 && (a.signum() < 0) != (b.signum() < 0) ? qr[0].subtract(BigInteger.ONE) : qr[0];
    }

    /** e^x. */
    public static double detExp(double x) {
        if (Double.isNaN(x)) return x;
        if (x > 709.782712893384) return Double.POSITIVE_INFINITY;
        if (x < -745.2) return 0;
        if (x == 0) return 1;
        long bits = Double.doubleToRawLongBits(Math.abs(x));
        int be = (int) ((bits >>> 52) & 0x7ffL);
        long frac = bits & ((1L << 52) - 1);
        BigInteger m = BigInteger.valueOf(be == 0 ? frac : frac | (1L << 52));
        int sh = (be == 0 ? 1 : be) - 1075 + FRAC; // |x| 2^96 = m 2^sh
        BigInteger xx = sh >= 0 ? m.shiftLeft(sh) : m.shiftRight(-sh);
        if (x < 0) xx = xx.negate();
        BigInteger k = floorDiv(xx.add(LN2.divide(BigInteger.TWO)), LN2);
        BigInteger r = xx.subtract(k.multiply(LN2));
        BigInteger term = ONE, sum = ONE;
        for (long n = 1; term.signum() != 0; n++) {
            term = term.multiply(r).divide(ONE).divide(BigInteger.valueOf(n));
            sum = sum.add(term);
        }
        long e = k.longValue() - FRAC;
        long half = e / 2; // truncates toward zero
        return sum.doubleValue() * Math.scalb(1.0, (int) half) * Math.scalb(1.0, (int) (e - half));
    }

    /** b^n for an integer n >= 0 by sequential multiplication (1 * b * b ..., n times). */
    public static double detPowInt(double b, double n) {
        double r = 1;
        for (double i = 0; i < n; i++) r *= b;
        return r;
    }
}
