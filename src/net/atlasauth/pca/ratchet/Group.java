package net.atlasauth.pca.ratchet;

import net.atlasauth.pca.Json;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.ratchet.Ristretto.Point;

/**
 * Prime-order group layer for the homomorphic risk accumulator: ristretto255 (order L, the Ed25519 subgroup order), the two Pedersen
 * generators and the scalar arithmetic mod L. {@code H} is hash-to-group of a constant label: nobody knows its discrete log to {@code G}.
 */
final class Group {
    private Group() {}

    static final BigInteger L = Ristretto.L;
    static final Point G = Ristretto.BASE;
    static final Point ZERO = Ristretto.ZERO;
    private static final String H_LABEL = "atlas-pca-ratchet/pedersen-generator-H/v1";
    static final Point H = Ristretto.hashToCurve(sha512(utf8(H_LABEL)));
    private static final SecureRandom RNG = new SecureRandom();

    static byte[] utf8(String s) { return Json.utf8(s); }

    static byte[] sha512(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(b);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static BigInteger mod(BigInteger x) { return x.mod(L); }
    static BigInteger scalarAdd(BigInteger a, BigInteger b) { return Ristretto.scalarAdd(a, b); }
    static BigInteger scalarSub(BigInteger a, BigInteger b) { return Ristretto.scalarSub(a, b); }
    static BigInteger scalarMul(BigInteger a, BigInteger b) { return Ristretto.scalarMul(a, b); }

    /** k*P with k reduced mod L; k = 0 gives the identity, with no branch on the scalar. */
    static Point mul(Point p, BigInteger k) { return p.multiply(mod(k)); }

    static Point add(Point a, Point b) { return a.add(b); }
    static Point sub(Point a, Point b) { return a.subtract(b); }

    /** A uniformly random non-zero scalar in [1, L). */
    static BigInteger randScalar() {
        for (;;) {
            byte[] b = new byte[64];
            RNG.nextBytes(b);
            BigInteger s = mod(Ristretto.fromLe(b, false));
            if (s.signum() != 0) return s;
        }
    }

    /** Little-endian bytes of a non-negative integer; throws when it does not fit. */
    static byte[] numberToBytesLE(BigInteger n, int len) {
        if (n.signum() < 0) throw new IllegalArgumentException("numberToBytesLE: negative");
        if (n.bitLength() > 8 * len) throw new IllegalArgumentException("numberToBytesLE: overflow");
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) out[i] = (byte) n.shiftRight(8 * i).intValue();
        return out;
    }

    static String encodePoint(Point p) { return Keys.b64u(p.toRawBytes()); }

    /** Decode a wire point; throws on non-canonical base64url, a length other than 32 bytes, or a non-canonical / invalid ristretto encoding. */
    static Point decodePoint(Object s) {
        byte[] b = Pca.decodeB64uStrict(s, 32);
        if (b == null) throw new IllegalArgumentException("decodePoint: not a canonical 32-byte base64url string");
        return Ristretto.decode(b);
    }

    static String encodeScalar(BigInteger k) { return Keys.b64u(numberToBytesLE(mod(k), 32)); }

    /** Decode a wire scalar. Strict: canonical base64url, exactly 32 bytes, value below L (reducing would make every proof malleable). */
    static BigInteger decodeScalar(Object s) {
        byte[] b = Pca.decodeB64uStrict(s, 32);
        if (b == null) throw new IllegalArgumentException("decodeScalar: not a canonical 32-byte base64url string");
        BigInteger v = Ristretto.fromLe(b, false);
        if (v.compareTo(L) >= 0) throw new IllegalArgumentException("decodeScalar: non-canonical scalar (>= L)");
        return v;
    }

    /** SHA-512 of the length-prefixed (4-byte big-endian) concatenation of the parts, reduced mod L. */
    static BigInteger hashToScalar(byte[]... parts) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            buf.write((p.length >>> 24) & 0xff);
            buf.write((p.length >>> 16) & 0xff);
            buf.write((p.length >>> 8) & 0xff);
            buf.write(p.length & 0xff);
            buf.write(p, 0, p.length);
        }
        return mod(Ristretto.fromLe(sha512(buf.toByteArray()), false));
    }
}
