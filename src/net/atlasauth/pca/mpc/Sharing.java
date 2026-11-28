package net.atlasauth.pca.mpc;

import static net.atlasauth.pca.mpc.Field.fadd;
import static net.atlasauth.pca.mpc.Field.fmul;
import static net.atlasauth.pca.mpc.Field.fneg;
import static net.atlasauth.pca.mpc.Field.mod;

import java.math.BigInteger;
import net.atlasauth.pca.mpc.Field.FieldSource;

/**
 * Additive secret sharing over F_p for N parties: shares sum to the secret; reconstruction is all-or-nothing and fails
 * closed on an absent share. A shared value is a {@code BigInteger[]} with {@code x[i]} held by party i.
 */
public final class Sharing {
    private Sharing() {}

    /** Largest party count accepted (bounds allocation). */
    public static final int MAX_PARTIES = 1024;

    public static BigInteger[] share(BigInteger secret, int n, FieldSource rng) {
        if (n < 1 || n > MAX_PARTIES) throw new IllegalArgumentException("share: n must be an integer in [1, " + MAX_PARTIES + "]");
        BigInteger[] out = new BigInteger[n];
        BigInteger acc = BigInteger.ZERO;
        for (int i = 0; i < n - 1; i++) {
            BigInteger s = rng.next();
            out[i] = s;
            acc = fadd(acc, s);
        }
        out[n - 1] = fadd(mod(secret), fneg(acc));
        return out;
    }

    public static BigInteger reconstruct(BigInteger[] shares) {
        if (shares.length == 0) throw new IllegalArgumentException("reconstruct: no shares (fail closed)");
        BigInteger acc = BigInteger.ZERO;
        for (BigInteger s : shares) {
            if (s == null) throw new IllegalArgumentException("reconstruct: missing share (fail closed)");
            acc = fadd(acc, s);
        }
        return acc;
    }

    public static BigInteger[] shareConstant(BigInteger c, int n) {
        if (n < 1 || n > MAX_PARTIES) throw new IllegalArgumentException("shareConstant: n must be an integer in [1, " + MAX_PARTIES + "]");
        BigInteger[] out = new BigInteger[n];
        java.util.Arrays.fill(out, BigInteger.ZERO);
        out[0] = mod(c);
        return out;
    }

    public static BigInteger[] addSV(BigInteger[] x, BigInteger[] y) {
        same(x, y);
        BigInteger[] o = new BigInteger[x.length];
        for (int i = 0; i < x.length; i++) o[i] = fadd(x[i], y[i]);
        return o;
    }

    public static BigInteger[] subSV(BigInteger[] x, BigInteger[] y) {
        same(x, y);
        BigInteger[] o = new BigInteger[x.length];
        for (int i = 0; i < x.length; i++) o[i] = fadd(x[i], fneg(y[i]));
        return o;
    }

    public static BigInteger[] negSV(BigInteger[] x) {
        BigInteger[] o = new BigInteger[x.length];
        for (int i = 0; i < x.length; i++) o[i] = fneg(x[i]);
        return o;
    }

    public static BigInteger[] scaleSV(BigInteger[] x, BigInteger c) {
        BigInteger[] o = new BigInteger[x.length];
        for (int i = 0; i < x.length; i++) o[i] = fmul(x[i], c);
        return o;
    }

    public static BigInteger[] addPublicSV(BigInteger[] x, BigInteger c) {
        BigInteger[] o = x.clone();
        o[0] = fadd(o[0], mod(c));
        return o;
    }

    public static BigInteger[] notBitSV(BigInteger[] b) { return addPublicSV(negSV(b), BigInteger.ONE); }

    private static void same(BigInteger[] x, BigInteger[] y) {
        if (x.length != y.length) throw new IllegalArgumentException("shared values must have the same party count");
    }
}
