package net.atlasauth.pca.mpc;

import java.math.BigInteger;

/** Thermometer (unary) encoding of a bounded integer: ge[k] = [v >= k] for k = 1..M, so MAX is a position-wise OR. */
public final class Thermometer {
    private Thermometer() {}

    /** Encodes v in {0..M}; v is clamped into range (fail-safe). v is a JS number (non-finite clamps like Math.trunc). */
    public static int[] thermometerEncode(double v, int M) {
        if (M < 0) throw new IllegalArgumentException("thermometerEncode: M must be a non-negative integer");
        double tr = Double.isNaN(v) ? Double.NaN : (v < 0 ? Math.ceil(v) : Math.floor(v));
        double clamped = Double.isNaN(tr) ? Double.NaN : Math.max(0, Math.min(M, tr));
        int[] bits = new int[M];
        for (int k = 1; k <= M; k++) bits[k - 1] = clamped >= k ? 1 : 0; // NaN compares false: all zero (Math.max(0,NaN) is NaN in JS too)
        return bits;
    }

    /** Number of 1s (robust to non-monotone input). */
    public static int thermometerDecode(int[] bits) {
        int c = 0;
        for (int b : bits) if (b == 1) c++;
        return c;
    }

    public static int thermometerDecode(BigInteger[] bits) {
        int c = 0;
        for (BigInteger b : bits) if (b.equals(BigInteger.ONE)) c++;
        return c;
    }
}
