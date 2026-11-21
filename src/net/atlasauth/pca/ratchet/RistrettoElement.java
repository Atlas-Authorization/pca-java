package net.atlasauth.pca.ratchet;

import java.math.BigInteger;

/**
 * Public handle on a ristretto255 group element (RFC 9496), backed by the ratchet package's group implementation, so that other
 * packages (the OPRF) share one audited group instead of carrying a second copy. Immutable.
 */
public final class RistrettoElement {
    /** The prime group order L. */
    public static final BigInteger ORDER = Ristretto.L;
    public static final RistrettoElement ZERO = new RistrettoElement(Ristretto.ZERO);
    public static final RistrettoElement BASE = new RistrettoElement(Ristretto.BASE);

    private final Ristretto.Point p;

    private RistrettoElement(Ristretto.Point p) { this.p = p; }

    /** Decode a canonical 32-byte encoding (RFC 9496 section 4.3.1); throws on a wrong length, non-canonical or invalid encoding. The identity is a valid element here. */
    public static RistrettoElement fromBytes(byte[] b) { return new RistrettoElement(Ristretto.decode(b)); }

    /** The one-way map of 64 uniform bytes (RFC 9496 section 4.3.4). */
    public static RistrettoElement fromUniformBytes(byte[] b64) { return new RistrettoElement(Ristretto.hashToCurve(b64)); }

    public RistrettoElement add(RistrettoElement o) { return new RistrettoElement(p.add(o.p)); }

    /** {@code k * this} for a SECRET-capable scalar: refuses 0 and anything >= the group order (a fixed-iteration ladder, no scalar-dependent branch). */
    public RistrettoElement multiply(BigInteger k) {
        if (k.signum() <= 0 || k.compareTo(ORDER) >= 0) throw new IllegalArgumentException("expected valid scalar: 1 <= n < order");
        return new RistrettoElement(p.multiply(k));
    }

    /** {@code k * this} for a PUBLIC scalar in [0, order). Same ladder; zero is allowed (gives the identity). */
    public RistrettoElement multiplyPublic(BigInteger k) {
        if (k.signum() < 0 || k.compareTo(ORDER) >= 0) throw new IllegalArgumentException("expected valid scalar: 0 <= n < order");
        return new RistrettoElement(p.multiply(k));
    }

    /** Inverse mod the group order via libsodium; throws on zero. */
    public static BigInteger scalarInvert(BigInteger s) { return Ristretto.scalarInvert(s); }

    public byte[] toRawBytes() { return p.toRawBytes(); }

    public boolean isIdentity() { return p.equalsPoint(Ristretto.ZERO); }

    public boolean sameAs(RistrettoElement o) { return p.equalsPoint(o.p); }
}
