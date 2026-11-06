package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.function.Predicate;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

/** AttestCommon EC helpers on deterministic points (multiples of the generator): fixed-width SEC1 output, strict point length, unsupported curves. */
public class AttestCommonK05bKillTest {
    static final X9ECParameters P256 = ECNamedCurveTable.getByName("P-256");

    static BigInteger x(ECPoint q) { return q.getAffineXCoord().toBigInteger(); }

    static BigInteger y(ECPoint q) { return q.getAffineYCoord().toBigInteger(); }

    /** The first multiple k*G (k = 1, 2, ...) that satisfies p. */
    static ECPoint find(X9ECParameters c, Predicate<ECPoint> p) {
        for (int k = 1; k < 100_000; k++) {
            ECPoint q = c.getG().multiply(BigInteger.valueOf(k)).normalize();
            if (p.test(q)) return q;
        }
        throw new IllegalStateException("no such multiple");
    }

    @Test
    void ecPointOfKeyIsFixedWidth() {
        ECPoint high = find(P256, q -> x(q).bitLength() == 256 && y(q).bitLength() == 256); // toByteArray has a sign byte
        ECPoint shortX = find(P256, q -> x(q).bitLength() <= 248); // needs left padding
        ECPoint shortY = find(P256, q -> y(q).bitLength() <= 248);
        for (ECPoint q : new ECPoint[] {high, shortX, shortY}) {
            ECPublicKey pub = AttestCommon.ecKeyOf("P-256", x(q), y(q));
            assertNotNull(pub);
            assertArrayEquals(q.getEncoded(false), AttestCommon.ecPointOfKey(CertKey.of(pub, pub.getEncoded()), "P-256"));
        }
    }

    @Test
    void pointToKeyNeedsTheExactLength() {
        ECPoint q = find(P256, p -> true);
        byte[] enc = q.getEncoded(false);
        assertNotNull(AttestCommon.pointToKey("P-256", enc));
        // 04 || X || 00 || Y: the same coordinates, one byte too long
        byte[] padded = new byte[enc.length + 1];
        System.arraycopy(enc, 0, padded, 0, 33);
        System.arraycopy(enc, 33, padded, 34, 32);
        assertNull(AttestCommon.pointToKey("P-256", padded));
        assertNull(AttestCommon.pointToKey("P-256", Arrays.copyOf(enc, enc.length - 1)));
    }

    @Test
    void ecKeyOfRefusesOffCurveAndJdkUnknownCurves() {
        ECPoint q = find(P256, p -> true);
        assertNull(AttestCommon.ecKeyOf("P-256", x(q), y(q).add(BigInteger.ONE)));
        assertNull(AttestCommon.ecKeyOf("P-999", x(q), y(q)));
        // a curve BouncyCastle knows but this JDK may not: without the JDK parameters there is no key (never an exception)
        X9ECParameters p224 = ECNamedCurveTable.getByName("P-224");
        ECPoint g = p224.getG().normalize();
        if (AttestCommon.jdkSpec("P-224") == null) assertNull(AttestCommon.ecKeyOf("P-224", x(g), y(g)));
    }
}
