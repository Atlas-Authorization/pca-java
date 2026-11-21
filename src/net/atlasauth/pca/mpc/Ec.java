package net.atlasauth.pca.mpc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.function.Supplier;
import net.atlasauth.pca.Libsodium;

/**
 * A small prime-order group for the base oblivious transfer: Ed25519 (twisted Edwards, q = 2^255 - 19), used in its prime-order
 * subgroup (order L). The group law (add, subtract, scalar multiplication, subgroup test) is libsodium's constant-time Ed25519 core,
 * called through net.atlasauth.pca.Libsodium on the compressed encoding; nothing of it is written out here. What remains in
 * BigInteger is only the public coordinate codec (affine normalisation, RFC 8032 x-recovery) and the on-curve predicate, which
 * touch no secret. Every point received across the OT trust boundary is validated (on curve, non-identity, [L]P = O).
 */
public final class Ec {
    private Ec() {}

    public static final BigInteger Q = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    public static final BigInteger L = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger TWO = BigInteger.TWO;
    private static final BigInteger D = modFq(BigInteger.valueOf(-121665).multiply(invFq(BigInteger.valueOf(121666))));
    private static final BigInteger SQRT_M1 = powFq(TWO, Q.subtract(BigInteger.ONE).shiftRight(2));

    /** A curve point in extended coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, T = XY/Z. */
    public record Point(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) {}

    public static final Point IDENTITY = new Point(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO);
    public static final Point BASE = fromAffine(
        new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
        new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));

    public static BigInteger modFq(BigInteger x) { return x.mod(Q); }

    private static BigInteger invFq(BigInteger a) { return powFq(modFq(a), Q.subtract(TWO)); }

    private static BigInteger powFq(BigInteger b, BigInteger e) { return modFq(b).modPow(e, Q); }

    public static Point fromAffine(BigInteger x, BigInteger y) {
        BigInteger X = modFq(x), Y = modFq(y);
        return new Point(X, Y, BigInteger.ONE, modFq(X.multiply(Y)));
    }

    private static BigInteger mm(BigInteger a, BigInteger b) { return a.multiply(b).mod(Q); }

    private static Point fromEnc(byte[] enc) { return decompressPoint(enc); }

    private static Point binary(boolean sub, Point p1, Point p2) {
        byte[] r = new byte[32];
        int rc = sub ? Libsodium.Ed.crypto_core_ed25519_sub(r, compressPoint(p1), compressPoint(p2))
                     : Libsodium.Ed.crypto_core_ed25519_add(r, compressPoint(p1), compressPoint(p2));
        if (rc != 0) throw new PointValidationError("point is not on the curve");
        return fromEnc(r);
    }

    private static Point add(Point p1, Point p2) { return binary(false, p1, p2); }

    /** Public group addition P + Q (complete on the subgroup). */
    public static Point addPoints(Point p1, Point p2) { return add(p1, p2); }

    public static Point dbl(Point p) { return add(p, p); }

    /** [k]P with k reduced mod L (k = 0 or P = identity is the identity). P must lie in the prime-order subgroup (libsodium refuses torsion). */
    public static Point mul(BigInteger k, Point p) {
        BigInteger s = k.mod(L);
        if (s.signum() == 0 || isIdentity(p)) return IDENTITY;
        byte[] r = new byte[32];
        if (Libsodium.Ed.crypto_scalarmult_ed25519_noclamp(r, Libsodium.le32(s), compressPoint(p)) != 0) throw new PointValidationError("scalar multiplication refused: point not in the prime-order subgroup");
        return fromEnc(r);
    }

    public static Point mulBase(BigInteger k) {
        BigInteger s = k.mod(L);
        if (s.signum() == 0) return IDENTITY;
        byte[] r = new byte[32];
        if (Libsodium.Ed.crypto_scalarmult_ed25519_base_noclamp(r, Libsodium.le32(s)) != 0) throw new IllegalStateException("ed25519 base multiplication failed");
        return fromEnc(r);
    }

    public static Point neg(Point p) { return sub(IDENTITY, p); }

    public static Point sub(Point p1, Point p2) { return binary(true, p1, p2); }

    /** Affine {x, y} of a point (identity is (0, 1)). */
    public static BigInteger[] toAffine(Point p) {
        BigInteger zinv = invFq(p.Z());
        return new BigInteger[] {modFq(p.X().multiply(zinv)), modFq(p.Y().multiply(zinv))};
    }

    public static boolean equal(Point a, Point b) {
        return modFq(a.X().multiply(b.Z())).equals(modFq(b.X().multiply(a.Z()))) && modFq(a.Y().multiply(b.Z())).equals(modFq(b.Y().multiply(a.Z())));
    }

    private static byte[] feBytes(BigInteger a) {
        byte[] out = new byte[32];
        BigInteger v = modFq(a);
        for (int i = 0; i < 32; i++) {
            out[i] = (byte) v.and(BigInteger.valueOf(0xff)).intValue();
            v = v.shiftRight(8);
        }
        return out;
    }

    /** Canonical 64-byte affine encoding x || y (little-endian field elements), the OT key-derivation input. */
    public static byte[] encodePoint(Point p) {
        BigInteger[] xy = toAffine(p);
        byte[] out = new byte[64];
        System.arraycopy(feBytes(xy[0]), 0, out, 0, 32);
        System.arraycopy(feBytes(xy[1]), 0, out, 32, 32);
        return out;
    }

    /** Canonical 32-byte compressed encoding (little-endian y, sign of x in bit 255). */
    public static byte[] compressPoint(Point p) {
        BigInteger[] xy = toAffine(p);
        byte[] out = feBytes(xy[1]);
        out[31] = (byte) ((out[31] & 0xff) | ((xy[0].testBit(0) ? 1 : 0) << 7));
        return out;
    }

    /** Raised when a received point fails on-curve / subgroup / identity validation. */
    public static final class PointValidationError extends RuntimeException {
        public PointValidationError(String message) { super(message); }
    }

    /** Decodes a canonical compressed encoding (RFC 8032 5.1.3 x-recovery). */
    public static Point decompressPoint(byte[] bytes) {
        if (bytes.length != 32) throw new PointValidationError("decompressPoint: expected 32 bytes");
        int sign = (bytes[31] >> 7) & 1;
        BigInteger y = BigInteger.ZERO;
        for (int i = 0; i < 32; i++) y = y.or(BigInteger.valueOf(bytes[i] & 0xffL).shiftLeft(8 * i));
        y = y.clearBit(255);
        if (y.compareTo(Q) >= 0) throw new PointValidationError("decompressPoint: non-canonical y (≥ q)");
        BigInteger y2 = mm(y, y);
        BigInteger u = modFq(y2.subtract(BigInteger.ONE));
        BigInteger v = modFq(D.multiply(y2).add(BigInteger.ONE));
        BigInteger v3 = mm(mm(v, v), v);
        BigInteger v7 = mm(mm(v3, v3), v);
        BigInteger x = mm(mm(u, v3), powFq(mm(u, v7), Q.subtract(BigInteger.valueOf(5)).shiftRight(3)));
        BigInteger vx2 = mm(v, mm(x, x));
        if (vx2.equals(modFq(u))) {
            // x is correct as-is
        } else if (vx2.equals(modFq(u.negate()))) {
            x = mm(x, SQRT_M1);
        } else {
            throw new PointValidationError("decompressPoint: not on curve");
        }
        if (x.signum() == 0 && sign == 1) throw new PointValidationError("decompressPoint: non-canonical sign");
        if ((x.testBit(0) ? 1 : 0) != sign) x = modFq(Q.subtract(x));
        return fromAffine(x, y);
    }

    /** Whether the extended coordinates lie on the curve (projectively, no inversion). */
    public static boolean isOnCurve(Point p) {
        if (modFq(p.Z()).signum() == 0) return false;
        if (!modFq(p.T().multiply(p.Z())).equals(modFq(p.X().multiply(p.Y())))) return false;
        BigInteger X2 = mm(p.X(), p.X()), Y2 = mm(p.Y(), p.Y()), Z2 = mm(p.Z(), p.Z());
        BigInteger lhs = modFq(Y2.subtract(X2).multiply(Z2));
        BigInteger Z4 = mm(Z2, Z2);
        BigInteger dxy = mm(mm(D, X2), Y2);
        return lhs.equals(modFq(Z4.add(dxy)));
    }

    public static boolean isIdentity(Point p) { return equal(p, IDENTITY); }

    /** The cofactor check [L]P = O (true for the identity too). */
    public static boolean hasPrimeOrder(Point p) {
        if (!isOnCurve(p)) return false;
        if (isIdentity(p)) return true;
        byte[] b = compressPoint(p);
        // the group law decides: libsodium 1.0.20 and older accept a mixed-order point through is_valid_point (its subgroup test reads only X of L*P)
        return net.atlasauth.pca.ratchet.EdwardsPoint.fromBytes(b).isTorsionFree() && Libsodium.Ed.crypto_core_ed25519_is_valid_point(b) == 1;
    }

    /** A valid non-identity point of the prime-order subgroup. */
    public static boolean isInSubgroup(Point p) { return isOnCurve(p) && !isIdentity(p) && hasPrimeOrder(p); }

    public static void assertInSubgroup(Point p, String label) {
        if (!isOnCurve(p)) throw new PointValidationError(label + ": not on curve");
        if (isIdentity(p)) throw new PointValidationError(label + ": identity element (forbidden here)");
        if (!hasPrimeOrder(p)) throw new PointValidationError(label + ": not in the prime-order subgroup (small-order/cofactor)");
    }

    public static void assertInSubgroup(Point p) { assertInSubgroup(p, "point"); }

    /** Fiat-Shamir Schnorr proof of knowledge of y with S = y*B: commitment U = r*B and z = r + e*y. */
    public record SchnorrProof(Point U, BigInteger z) {}

    private static final byte[] TAG_SCHNORR = "atlas-pca-mpc/schnorr-dlog".getBytes(StandardCharsets.UTF_8);

    private static BigInteger schnorrChallenge(Point S, Point U, byte[] ctx) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(TAG_SCHNORR);
            md.update(new byte[] {(byte) (ctx.length >>> 24), (byte) (ctx.length >>> 16), (byte) (ctx.length >>> 8), (byte) ctx.length});
            md.update(ctx);
            md.update(encodePoint(BASE));
            md.update(encodePoint(S));
            md.update(encodePoint(U));
            return new BigInteger(1, md.digest()).mod(L);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static SchnorrProof schnorrProve(BigInteger y, Point S, Supplier<BigInteger> rnd, byte[] ctx) {
        if (ctx == null || ctx.length == 0) throw new IllegalArgumentException("schnorrProve: a non-empty session binding is required");
        BigInteger r = rnd.get().mod(L);
        if (r.signum() == 0) throw new IllegalStateException("schnorrProve: nonce source returned 0 (RNG failure); refusing to produce a proof");
        Point U = mulBase(r);
        BigInteger e = schnorrChallenge(S, U, ctx);
        BigInteger z = r.add(e.multiply(y.mod(L))).mod(L);
        return new SchnorrProof(U, z);
    }

    public static boolean schnorrVerify(Point S, SchnorrProof proof, byte[] ctx) {
        if (ctx == null || ctx.length == 0) return false;
        if (proof.z().signum() < 0 || proof.z().compareTo(L) >= 0) return false;
        if (!isInSubgroup(proof.U())) return false;
        BigInteger e = schnorrChallenge(S, proof.U(), ctx);
        try {
            return equal(mulBase(proof.z()), add(proof.U(), mul(e, S)));
        } catch (PointValidationError err) {
            return false;
        }
    }
}
