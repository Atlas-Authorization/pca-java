package net.atlasauth.pca.ratchet;

import java.math.BigInteger;
import java.util.Arrays;
import net.atlasauth.pca.Libsodium;

/**
 * The ristretto255 prime-order group (RFC 9496), a thin typed wrapper over libsodium (net.atlasauth.pca.Libsodium): the group law,
 * encode / decode and the one-way map are libsodium's constant-time implementation, none of it is written out here. A {@link Point}
 * is its canonical 32-byte encoding, so group equality is byte equality.
 */
final class Ristretto {
    private Ristretto() {}

    /** Order of the prime-order group (the Ed25519 subgroup order). */
    static final BigInteger L = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));

    static final class Point {
        private final byte[] e;
        private Point(byte[] e) { this.e = e; }

        Point add(Point o) {
            byte[] r = new byte[32];
            if (Libsodium.S.crypto_core_ristretto255_add(r, e, o.e) != 0) throw new IllegalStateException("ristretto255 add failed");
            return new Point(r);
        }

        Point subtract(Point o) {
            byte[] r = new byte[32];
            if (Libsodium.S.crypto_core_ristretto255_sub(r, e, o.e) != 0) throw new IllegalStateException("ristretto255 sub failed");
            return new Point(r);
        }

        Point negate() { return ZERO.subtract(this); }

        /** k * this for any 0 <= k < 2^256 (reduced mod L first); a zero scalar or the identity gives the identity, which libsodium itself refuses. */
        Point multiply(BigInteger k) {
            BigInteger s = k.mod(L);
            if (s.signum() == 0 || equalsPoint(ZERO)) return ZERO;
            byte[] r = new byte[32];
            if (Libsodium.S.crypto_scalarmult_ristretto255(r, Libsodium.le32(s), e) != 0) throw new IllegalStateException("ristretto255 scalarmult failed");
            return new Point(r);
        }

        boolean equalsPoint(Point o) { return java.security.MessageDigest.isEqual(e, o.e); }

        byte[] toRawBytes() { return e.clone(); }
    }

    static final Point ZERO = new Point(new byte[32]);

    /** The standard generator (the encoding of the Ed25519 base point). */
    static final Point BASE = base();

    private static Point base() {
        byte[] r = new byte[32];
        if (Libsodium.S.crypto_scalarmult_ristretto255_base(r, Libsodium.le32(BigInteger.ONE)) != 0) throw new IllegalStateException("ristretto255 base failed");
        return new Point(r);
    }

    private static BigInteger scalar3(int op, BigInteger a, BigInteger b) {
        byte[] r = new byte[32], x = Libsodium.le32(a.mod(L)), y = Libsodium.le32(b.mod(L));
        if (op == 0) Libsodium.S.crypto_core_ristretto255_scalar_add(r, x, y);
        else if (op == 1) Libsodium.S.crypto_core_ristretto255_scalar_sub(r, x, y);
        else Libsodium.S.crypto_core_ristretto255_scalar_mul(r, x, y);
        return Libsodium.fromLe(r);
    }

    static BigInteger scalarAdd(BigInteger a, BigInteger b) { return scalar3(0, a, b); }
    static BigInteger scalarSub(BigInteger a, BigInteger b) { return scalar3(1, a, b); }
    static BigInteger scalarMul(BigInteger a, BigInteger b) { return scalar3(2, a, b); }

    /** Inverse mod L; throws on zero. */
    static BigInteger scalarInvert(BigInteger s) {
        byte[] r = new byte[32];
        if (Libsodium.S.crypto_core_ristretto255_scalar_invert(r, Libsodium.le32(s.mod(L))) != 0) throw new IllegalArgumentException("scalarInvert: inverse of zero");
        return Libsodium.fromLe(r);
    }

    static byte[] le32(BigInteger n) { return Libsodium.le32(n); }

    static BigInteger fromLe(byte[] b, boolean maskTop) {
        byte[] c = b.clone();
        if (maskTop) c[c.length - 1] &= 0x7f;
        return Libsodium.fromLe(c);
    }


    /** Decode a canonical 32-byte ristretto255 encoding (RFC 9496 section 4.3.1); throws on anything non-canonical or invalid. */
    static Point decode(byte[] b) {
        if (b.length != 32) throw new IllegalArgumentException("ristretto255: not 32 bytes");
        if (Libsodium.S.crypto_core_ristretto255_is_valid_point(b) != 1) throw new IllegalArgumentException("ristretto255: invalid encoding");
        // RFC 9496 4.3.1: the top bit is clear and the encoding is the one the decoded point re-encodes to (adding the identity re-encodes it)
        if ((b[31] & 0x80) != 0) throw new IllegalArgumentException("ristretto255: non-canonical encoding");
        byte[] re = new byte[32];
        if (Libsodium.S.crypto_core_ristretto255_add(re, b, new byte[32]) != 0 || !java.security.MessageDigest.isEqual(re, b)) throw new IllegalArgumentException("ristretto255: non-canonical encoding");
        return new Point(Arrays.copyOf(b, 32));
    }

    /** The one-way map from 64 uniform bytes (RFC 9496 section 4.3.4). */
    static Point hashToCurve(byte[] b64) {
        if (b64.length != 64) throw new IllegalArgumentException("ristretto255: 64 bytes required");
        byte[] r = new byte[32];
        if (Libsodium.S.crypto_core_ristretto255_from_hash(r, b64) != 0) throw new IllegalStateException("ristretto255 from_hash failed");
        return new Point(r);
    }
}
