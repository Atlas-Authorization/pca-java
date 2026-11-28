package net.atlasauth.pca.intent;

/** Base-2 logarithm with the exact bit pattern of ECMAScript's Math.log2 (the fdlibm algorithm); the JDK has no log2. */
public final class IntentMath {
    private IntentMath() {}

    private static double kLog1p(double f) {
        final double lg1 = 6.666666666666735130e-01, lg2 = 3.999999999940941908e-01, lg3 = 2.857142874366239149e-01,
            lg4 = 2.222219843214978396e-01, lg5 = 1.818357216161805012e-01, lg6 = 1.531383769920937332e-01,
            lg7 = 1.479819860511658591e-01;
        double s = f / (2.0 + f);
        double z = s * s;
        double w = z * z;
        double t1 = w * (lg2 + w * (lg4 + w * lg6));
        double t2 = z * (lg1 + w * (lg3 + w * (lg5 + w * lg7)));
        double r = t2 + t1;
        double hfsq = 0.5 * f * f;
        return s * (hfsq + r);
    }

    public static double log2(double x) {
        final double two54 = 1.80143985094819840000e+16, ivln2hi = 1.44269504072144627571e+00, ivln2lo = 1.67517131648865118353e-10;
        long bits = Double.doubleToRawLongBits(x);
        int hx = (int) (bits >> 32);
        int lx = (int) bits;
        int k = 0;
        if (hx < 0x00100000) {
            if (((hx & 0x7fffffff) | lx) == 0) return Double.NEGATIVE_INFINITY;
            if (hx < 0) return Double.NaN;
            k -= 54;
            x *= two54;
            hx = (int) (Double.doubleToRawLongBits(x) >> 32);
        }
        if (hx >= 0x7ff00000) return x + x;
        if (hx == 0x3ff00000 && lx == 0) return 0.0;
        k += (hx >> 20) - 1023;
        hx &= 0x000fffff;
        int i = (hx + 0x95f64) & 0x100000;
        long xb = Double.doubleToRawLongBits(x);
        x = Double.longBitsToDouble(((long) (hx | (i ^ 0x3ff00000)) << 32) | (xb & 0xffffffffL));
        k += i >> 20;
        double y = k;
        double f = x - 1.0;
        double hfsq = 0.5 * f * f;
        double r = kLog1p(f);
        double hi = Double.longBitsToDouble(Double.doubleToRawLongBits(f - hfsq) & 0xffffffff00000000L);
        double lo = (f - hi) - hfsq + r;
        double valHi = hi * ivln2hi;
        double valLo = (lo + hi) * ivln2lo + lo * ivln2hi;
        double w = y + valHi;
        valLo += (y - w) + valHi;
        valHi = w;
        return valLo + valHi;
    }
}
