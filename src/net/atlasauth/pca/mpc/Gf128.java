package net.atlasauth.pca.mpc;

import java.math.BigInteger;

/**
 * GF(2^128) arithmetic with the reduction polynomial x^128 + x^7 + x^2 + x + 1: the field of the KOS correlation check.
 * Elements are 128-bit non-negative BigIntegers (bit i = coefficient of x^i); addition is XOR. Not constant-time.
 */
public final class Gf128 {
    private Gf128() {}

    private static final BigInteger MASK = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
    private static final BigInteger RED = BigInteger.valueOf(0x87);

    public static BigInteger add(BigInteger a, BigInteger b) { return a.xor(b).and(MASK); }

    public static BigInteger mulX(BigInteger v) {
        boolean carry = v.testBit(127);
        BigInteger r = v.shiftLeft(1).and(MASK);
        return carry ? r.xor(RED) : r;
    }

    public static BigInteger mulByXi(BigInteger v, int i) {
        BigInteger r = v.and(MASK);
        for (int k = 0; k < i; k++) r = mulX(r);
        return r;
    }

    public static BigInteger mul(BigInteger a, BigInteger b) {
        BigInteger res = BigInteger.ZERO;
        BigInteger v = a.and(MASK);
        for (int i = 0; i < 128; i++) {
            if (b.testBit(i)) res = res.xor(v);
            v = mulX(v);
        }
        return res.and(MASK);
    }
}
