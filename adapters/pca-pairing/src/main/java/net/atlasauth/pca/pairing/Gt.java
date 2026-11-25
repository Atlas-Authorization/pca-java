package net.atlasauth.pca.pairing;

import java.math.BigInteger;
import java.util.List;
import supranational.blst.P1;
import supranational.blst.P2;

/**
 * The pairing target group GT of BLS12-381, through a small JNI shim over blst (src/main/c/pca_gt.c): canonical
 * 576-byte parsing, multiplication, constant-time exponentiation (a Montgomery ladder over blst's Fp12 multiply and
 * square) and multi-pairing with one final exponentiation. jblst's {@code PT} offers neither parsing nor exponentiation.
 *
 * <p>An element is its 576-byte encoding (the 12 Fp coordinates in tower order, 48 bytes big-endian each), the same
 * bytes as the TypeScript reference. The native library is {@code -Dpca.gt.lib=/path/to/libpcagt.so} when set, else the one packaged in this module's jar, or {@code pcagt}
 * on {@code java.library.path}; a missing library is a {@link LinkageError}, never a "bad input" result.
 */
public final class Gt {
    private Gt() {}

    /** Byte length of an encoded GT element. */
    public static final int BYTES = 576;

    static {
        String lib = net.atlasauth.pca.NativeLibs.resolve(Gt.class, "pcagt", System.getProperty("pca.gt.lib"));
        if (lib != null && !lib.isEmpty()) System.load(lib);
        else System.loadLibrary("pcagt");
    }

    private static native byte[] mul0(byte[] a, byte[] b);

    private static native byte[] pow0(byte[] a, byte[] k);

    private static native boolean isElement0(byte[] a);

    private static native byte[] pairing0(byte[] g1s, byte[] g2s, int n);

    /** a * b; throws on a non-canonical operand. */
    public static byte[] mul(byte[] a, byte[] b) {
        byte[] r = mul0(a, b);
        if (r == null) throw new IllegalArgumentException("not a canonical GT encoding");
        return r;
    }

    /** a^(k mod r); throws on a non-canonical operand. */
    public static byte[] pow(byte[] a, BigInteger k) {
        byte[] r = pow0(a, Bls12.i2osp(Bls12.mod(k), 32));
        if (r == null) throw new IllegalArgumentException("not a canonical GT encoding");
        return r;
    }

    /** True iff the bytes canonically encode an element of the order-r subgroup other than the identity. */
    public static boolean isElement(byte[] a) { return a != null && a.length == BYTES && isElement0(a); }

    /** e(p, q). Throws on an identity point. */
    public static byte[] pairing(P1 p, P2 q) { return pairingProduct(List.of(p), List.of(q)); }

    /** prod e(g1[i], g2[i]) with one shared final exponentiation. Throws on an identity point. */
    public static byte[] pairingProduct(List<P1> g1, List<P2> g2) {
        int n = g1.size();
        if (n == 0 || n != g2.size()) throw new IllegalArgumentException("pairing product needs equal, non-empty point lists");
        byte[] a = new byte[48 * n], b = new byte[96 * n];
        for (int i = 0; i < n; i++) {
            if (g1.get(i).is_inf() || g2.get(i).is_inf()) throw new IllegalArgumentException("pairing is not defined for the identity");
            System.arraycopy(g1.get(i).compress(), 0, a, 48 * i, 48);
            System.arraycopy(g2.get(i).compress(), 0, b, 96 * i, 96);
        }
        byte[] r = pairing0(a, b, n);
        if (r == null) throw new IllegalArgumentException("invalid pairing input");
        return r;
    }
}
