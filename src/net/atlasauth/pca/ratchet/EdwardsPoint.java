package net.atlasauth.pca.ratchet;

import java.math.BigInteger;
import java.util.Arrays;
import net.atlasauth.pca.Libsodium;

/**
 * Public handle on an Edwards25519 point (the Ed25519 group, RFC 8032 encoding) over libsodium's constant-time Ed25519 core
 * (net.atlasauth.pca.Libsodium), so other packages (FROST) share one vetted curve implementation. A point is its canonical 32-byte
 * encoding. Immutable. Unlike {@link RistrettoElement}, equality here is true point equality and decoding is the strict Ed25519 one.
 */
public final class EdwardsPoint {
    /** The prime order L of the Ed25519 base-point subgroup. */
    public static final BigInteger ORDER = Ristretto.L;
    private static final byte[] ID = identityEncoding();
    public static final EdwardsPoint ZERO = new EdwardsPoint(ID);
    public static final EdwardsPoint BASE = base();

    private final byte[] e;

    private EdwardsPoint(byte[] e) { this.e = e; }

    private static byte[] identityEncoding() { byte[] b = new byte[32]; b[0] = 1; return b; }

    private static EdwardsPoint base() {
        byte[] r = new byte[32];
        if (Libsodium.Ed.crypto_scalarmult_ed25519_base_noclamp(r, Libsodium.le32(BigInteger.ONE)) != 0) throw new IllegalStateException("ed25519 base failed");
        return new EdwardsPoint(r);
    }

    /**
     * Decode a canonical 32-byte Ed25519 point encoding (RFC 8032 section 5.1.3): throws on a wrong length, a point off the curve, or any
     * non-canonical encoding (y >= p, x = 0 with the sign bit set), checked by round-tripping through libsodium's decode/encode. Torsion
     * (small / mixed order) is NOT checked here; see {@link #isSmallOrder} and {@link #isTorsionFree}.
     */
    public static EdwardsPoint fromBytes(byte[] b) {
        if (b == null || b.length != 32) throw new IllegalArgumentException("ed25519: point must be 32 bytes");
        byte[] r = new byte[32];
        if (Libsodium.Ed.crypto_core_ed25519_add(r, b, ID) != 0) throw new IllegalArgumentException("ed25519: point is not on the curve");
        if (!Arrays.equals(r, b)) throw new IllegalArgumentException("ed25519: non-canonical point encoding");
        return new EdwardsPoint(r);
    }

    public EdwardsPoint add(EdwardsPoint o) {
        byte[] r = new byte[32];
        if (Libsodium.Ed.crypto_core_ed25519_add(r, e, o.e) != 0) throw new IllegalStateException("ed25519 add failed");
        return new EdwardsPoint(r);
    }

    /**
     * {@code k * this} for 0 <= k < 2^256, reduced mod L (zero or the identity gives the identity). Valid for a torsion-free point (libsodium
     * refuses any other); every caller multiplies the base point or a point already checked with {@link #isTorsionFree}.
     */
    public EdwardsPoint multiply(BigInteger k) {
        if (k.signum() < 0 || k.bitLength() > 256) throw new IllegalArgumentException("scalar out of range");
        BigInteger s = k.mod(ORDER);
        if (s.signum() == 0 || isIdentity()) return ZERO;
        byte[] r = new byte[32];
        if (Libsodium.Ed.crypto_scalarmult_ed25519_noclamp(r, Libsodium.le32(s), e) != 0) throw new IllegalArgumentException("ed25519: scalar multiplication refused (point has a torsion component)");
        return new EdwardsPoint(r);
    }

    /** True point equality (not the ristretto coset equality): encodings are canonical. */
    public boolean sameAs(EdwardsPoint o) { return java.security.MessageDigest.isEqual(e, o.e); }

    public boolean isIdentity() { return sameAs(ZERO); }

    /** 8 * P is the identity (three doublings through libsodium's add, which accepts torsion points). */
    public boolean isSmallOrder() {
        EdwardsPoint q = this;
        for (int i = 0; i < 3; i++) q = q.add(q);
        return q.isIdentity();
    }

    /**
     * L * P is the identity, computed by double-and-add over libsodium's add (which accepts torsion points). The public order and the public point
     * are all it touches; libsodium's is_valid_point is not used so the answer cannot depend on which libsodium build a platform ships.
     */
    public boolean isTorsionFree() {
        EdwardsPoint acc = ZERO;
        for (int i = ORDER.bitLength() - 1; i >= 0; i--) {
            acc = acc.add(acc);
            if (ORDER.testBit(i)) acc = acc.add(this);
        }
        return acc.isIdentity();
    }

    /** The canonical 32-byte Ed25519 encoding. */
    public byte[] toBytes() { return e.clone(); }
}
