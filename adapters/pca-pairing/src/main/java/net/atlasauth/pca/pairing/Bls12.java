package net.atlasauth.pca.pairing;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import supranational.blst.P1;
import supranational.blst.P1_Affine;
import supranational.blst.P2;
import supranational.blst.P2_Affine;
import supranational.blst.PT;
import supranational.blst.Scalar;

/**
 * Thin helpers over blst (via jblst) shared by the pairing-based packages: scalar-field arithmetic mod r on BigInteger,
 * point multiplication by a scalar through blst's own scalar type, RFC 9380 expand_message_xmd (SHA-256), and the
 * canonical decoders. No pairing, field or curve arithmetic is implemented here.
 *
 * <p>shortcut: scalar-field arithmetic (add/mul/inverse) is BigInteger, which is not constant-time. Point
 * multiplication (the expensive, key-dependent part) is blst's constant-time implementation. Upgrade to blst's Scalar
 * arithmetic if a deployment needs the scalar steps constant-time too.
 */
public final class Bls12 {
    private Bls12() {}

    /** The prime order r of the BLS12-381 groups. */
    public static final BigInteger R = new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    public static BigInteger mod(BigInteger x) { return x.mod(R); }

    public static BigInteger add(BigInteger a, BigInteger b) { return a.add(b).mod(R); }

    public static BigInteger sub(BigInteger a, BigInteger b) { return a.subtract(b).mod(R); }

    public static BigInteger mul(BigInteger a, BigInteger b) { return a.multiply(b).mod(R); }

    /** Fermat inverse x^(r-2) mod r (fixed public exponent). Throws on zero. */
    public static BigInteger inv(BigInteger x) {
        BigInteger v = mod(x);
        if (v.signum() == 0) throw new ArithmeticException("inverse of zero");
        return v.modPow(R.subtract(BigInteger.TWO), R);
    }

    /** I2OSP: non-negative integer to fixed-length big-endian octets; throws when it does not fit. */
    public static byte[] i2osp(BigInteger n, int len) {
        if (n.signum() < 0 || n.bitLength() > 8 * len) throw new IllegalArgumentException("integer does not fit " + len + " octets");
        byte[] be = n.toByteArray();
        byte[] out = new byte[len];
        int copy = Math.min(len, be.length);
        System.arraycopy(be, be.length - copy, out, len - copy, copy);
        return out;
    }

    /** OS2IP: big-endian octets to a non-negative integer. */
    public static BigInteger os2ip(byte[] b) { return new BigInteger(1, b); }

    /** A blst scalar from a value in [0, r): the 32-byte big-endian form. */
    public static Scalar scalar(BigInteger s) { return new Scalar().from_bendian(i2osp(mod(s), 32)); }

    /** s * P as a new point (P is not modified); the identity when s is zero mod r. */
    public static P1 mul(P1 p, BigInteger s) {
        BigInteger v = mod(s);
        return v.signum() == 0 ? new P1() : p.dup().mult(scalar(v));
    }

    public static P2 mul(P2 p, BigInteger s) {
        BigInteger v = mod(s);
        return v.signum() == 0 ? new P2() : p.dup().mult(scalar(v));
    }

    public static P1 add(P1 a, P1 b) { return a.dup().add(b); }

    public static P2 add(P2 a, P2 b) { return a.dup().add(b); }

    public static P1 sub(P1 a, P1 b) { return a.dup().add(b.dup().neg()); }

    /** Strict compressed-G1 decoding: compression flag set, canonical, on curve, in the prime-order subgroup. Identity is allowed (check it separately). */
    public static P1 decodeG1(byte[] b) {
        if (b == null || b.length != 48 || (b[0] & 0x80) == 0) throw new IllegalArgumentException("not a 48-byte compressed G1 point");
        try {
            P1_Affine a = new P1_Affine(b);
            if (!Arrays.equals(a.compress(), b) || !a.on_curve() || !a.in_group()) throw new IllegalArgumentException("non-canonical or invalid G1 encoding");
            return a.to_jacobian();
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Throwable t) {
            fatal(t);
            throw new IllegalArgumentException("invalid G1 encoding", t);
        }
    }

    public static P2 decodeG2(byte[] b) {
        if (b == null || b.length != 96 || (b[0] & 0x80) == 0) throw new IllegalArgumentException("not a 96-byte compressed G2 point");
        try {
            P2_Affine a = new P2_Affine(b);
            if (!Arrays.equals(a.compress(), b) || !a.on_curve() || !a.in_group()) throw new IllegalArgumentException("non-canonical or invalid G2 encoding");
            return a.to_jacobian();
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Throwable t) {
            fatal(t);
            throw new IllegalArgumentException("invalid G2 encoding", t);
        }
    }

    /** e(a, x) == e(b, y), by blst's pairing. */
    public static boolean pairingEq(P1 a, P2 x, P1 b, P2 y) {
        PT l = new PT(x.to_affine(), a.to_affine());
        PT r = new PT(y.to_affine(), b.to_affine());
        return PT.finalverify(l, r);
    }

    /** A native-library failure must surface, never be read as "bad input". */
    public static void fatal(Throwable t) {
        if (t instanceof Error && (t instanceof LinkageError || t instanceof VirtualMachineError)) throw (Error) t;
    }

    /** expand_message_xmd with SHA-256 (RFC 9380 5.3.1); the DST must be at most 255 octets. */
    public static byte[] expandMessageXmd(byte[] msg, byte[] dst, int len) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            int ell = (len + 31) / 32;
            if (ell > 255 || len > 65535 || dst.length > 255 || len < 0) throw new IllegalArgumentException("expand_message_xmd: invalid length or DST");
            byte[] dstPrime = Arrays.copyOf(dst, dst.length + 1);
            dstPrime[dst.length] = (byte) dst.length;
            h.update(new byte[64]);
            h.update(msg);
            h.update(new byte[] {(byte) (len >> 8), (byte) len, 0});
            h.update(dstPrime);
            byte[] b0 = h.digest();
            h.update(b0);
            h.update((byte) 1);
            h.update(dstPrime);
            byte[] bi = h.digest();
            byte[] out = new byte[len];
            System.arraycopy(bi, 0, out, 0, Math.min(32, len));
            for (int i = 2; i <= ell; i++) {
                byte[] x = new byte[32];
                for (int k = 0; k < 32; k++) x[k] = (byte) (b0[k] ^ bi[k]);
                h.update(x);
                h.update((byte) i);
                h.update(dstPrime);
                bi = h.digest();
                int off = (i - 1) * 32;
                System.arraycopy(bi, 0, out, off, Math.min(32, len - off));
            }
            return out;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
