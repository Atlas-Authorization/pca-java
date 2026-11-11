package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

/** Exact outcomes of the compact-JWS plumbing: segment errors, JWK key builders, key type names and the ES256 curve rule. */
public class AttestJwsKillTest {
    private static String reason(Runnable r) {
        try {
            r.run();
        } catch (AttestException e) {
            return e.getMessage();
        }
        return "no error";
    }

    private static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    private static String seg(String json) { return b64u(json.getBytes(StandardCharsets.UTF_8)); }

    private static byte[] unsigned(BigInteger v, int len) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[len];
        int skip = b.length > len ? b.length - len : 0;
        System.arraycopy(b, skip, out, len - (b.length - skip), b.length - skip);
        return out;
    }

    private static KeyPair gen(String alg, String curve) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance(alg);
        if (curve != null) g.initialize(new ECGenParameterSpec(curve));
        return g.generateKeyPair();
    }

    // ---- segment errors

    @Test
    void segmentErrorsNameTheFailingSegment() {
        String h = seg("{\"alg\":\"ES256\"}");
        String p = seg("{\"x\":1}");
        String s = b64u(new byte[] {1});
        // the header gate fails before the payload is looked at
        assertEquals("P: malformed JSON segment: non-canonical compact JWS: bad-character", reason(() -> AttestJws.parseJwt("a+b." + p + "." + s, "P")));
        assertEquals("P: malformed JSON segment: non-canonical compact JWS: non-canonical-base64url (impossible length)",
            reason(() -> AttestJws.parseJwt("abcde." + seg("[") + "." + s, "P")));
        assertEquals("P: malformed JSON segment: non-canonical compact JWS: non-canonical-base64url", reason(() -> AttestJws.parseJwt("AR." + seg("[") + "." + s, "P")));
        // header parses, payload gate / JSON fails
        assertEquals("P: malformed JSON segment: non-canonical compact JWS: non-canonical-base64url", reason(() -> AttestJws.parseJwt(h + ".AR." + s, "P")));
        assertEquals("P: malformed JSON segment: Unexpected end of JSON input", reason(() -> AttestJws.parseJwt(h + "." + seg("{\"a\":") + "." + s, "P")));
        assertEquals("Q: malformed JSON segment: Unexpected token 'x', \"x\" is not valid JSON", reason(() -> AttestJws.parseJwt(seg("x") + "." + p + "." + s, "Q")));
        // a header that is invalid JSON wins over a payload that does not decode
        assertEquals("P: malformed JSON segment: Unexpected token 'x', \"x\" is not valid JSON", reason(() -> AttestJws.parseJwt(seg("x") + ".AR." + s, "P")));
        // a signature segment is only decoded after both JSON segments parse
        assertEquals("P: malformed signature segment: non-canonical compact JWS: bad-character", reason(() -> AttestJws.parseJwt(h + "." + p + ".a+", "P")));
        assertEquals("P: malformed signature segment: non-canonical compact JWS: non-canonical-base64url (impossible length)",
            reason(() -> AttestJws.parseJwt(h + "." + p + ".abcde", "P")));
        assertEquals("no error", reason(() -> AttestJws.parseJwt(h + "." + p + "." + s, "P")));
    }

    @Test
    void canonicalGateDecodesEveryLegalLength() {
        assertArrayEquals(new byte[0], AttestJws.decodeCanonicalBase64url(""));
        assertArrayEquals(new byte[] {(byte) 0xfb}, AttestJws.decodeCanonicalBase64url("-w"));
        assertArrayEquals(new byte[] {(byte) 0xff, (byte) 0xe0}, AttestJws.decodeCanonicalBase64url("_-A"));
        assertArrayEquals(new byte[] {1, 2, 3}, AttestJws.decodeCanonicalBase64url("AQID"));
        assertEquals("non-canonical compact JWS: non-canonical-base64url", reason(() -> AttestJws.decodeCanonicalBase64url("_-B")));
        assertEquals("non-canonical compact JWS: bad-character", reason(() -> AttestJws.decodeCanonicalBase64url("AQ==")));
    }

    @Test
    void nestingDeeperThanTheParserIsRefusedWithItsOwnMessage() {
        int depth = 2_000_000;
        StringBuilder sb = new StringBuilder(2 * depth);
        for (int i = 0; i < depth; i++) sb.append('[');
        for (int i = 0; i < depth; i++) sb.append(']');
        String deep = sb.toString();
        // the engine accepts any depth, so no JSON.parse wording is claimed for it
        assertEquals("", AttestV8Json.v8JsonError(deep));
        String p = seg("{\"x\":1}");
        assertEquals("P: malformed JSON segment: JSON nesting too deep", reason(() -> AttestJws.parseJwt(seg(deep) + "." + p + ".AQ", "P")));
    }

    // ---- JWK keys

    @Test
    void ecJwkCurves() throws Exception {
        ECPublicKey p521 = (ECPublicKey) gen("EC", "secp521r1").getPublic();
        CertKey k = AttestJws.jwkEcKey("P-521", b64u(unsigned(p521.getW().getAffineX(), 66)), b64u(unsigned(p521.getW().getAffineY(), 66)));
        assertEquals("ec", k.typ);
        assertEquals("secp521r1", k.curve);
        assertArrayEquals(p521.getEncoded(), k.spki);
        assertArrayEquals(new String[] {"EC", "P-521"}, AttestJws.jwkKtyCrv(k));
        ECPublicKey p256 = (ECPublicKey) gen("EC", "secp256r1").getPublic();
        assertEquals("prime256v1", AttestJws.jwkEcKey("P-256", b64u(unsigned(p256.getW().getAffineX(), 32)), b64u(unsigned(p256.getW().getAffineY(), 32))).curve);
        // a real P-224 point (the generator) is still not a JWK curve
        X9ECParameters c224 = ECNamedCurveTable.getByName("P-224");
        ECPoint g = c224.getG().normalize();
        String gx = b64u(unsigned(g.getAffineXCoord().toBigInteger(), 28));
        String gy = b64u(unsigned(g.getAffineYCoord().toBigInteger(), 28));
        assertTrue(AttestCommon.isOnCurve("P-224", g.getAffineXCoord().toBigInteger(), g.getAffineYCoord().toBigInteger()));
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkEcKey("P-224", gx, gy)));
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkEcKey("", gx, gy)));
    }

    @Test
    void rsaJwkExponentBounds() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        RSAPublicKey pub = (RSAPublicKey) g.generateKeyPair().getPublic();
        String n = b64u(unsigned(pub.getModulus(), 256));
        // e = 3 is the smallest accepted exponent, 2^30 + 1 (31 bits) the widest
        CertKey k3 = AttestJws.jwkRsaKey(n, b64u(new byte[] {3}));
        assertEquals("rsa", k3.typ);
        assertEquals(BigInteger.valueOf(3), ((RSAPublicKey) k3.pub).getPublicExponent());
        CertKey k31 = AttestJws.jwkRsaKey(n, b64u(new byte[] {0x40, 0, 0, 1}));
        assertEquals(BigInteger.valueOf(0x40000001L), ((RSAPublicKey) k31.pub).getPublicExponent());
        assertEquals(pub.getModulus(), ((RSAPublicKey) k31.pub).getModulus());
        assertArrayEquals(new String[] {"RSA", "undefined"}, AttestJws.jwkKtyCrv(k31));
        // 2^31 + 1 is 32 bits and odd: inside the rule (at most 32 bits); 2^32 + 1 is 33 bits and refused
        assertEquals("rsa", AttestJws.jwkRsaKey(n, b64u(new byte[] {(byte) 0x80, 0, 0, 1})).typ);
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkRsaKey(n, b64u(new byte[] {1, 0, 0, 0, 1}))));
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkRsaKey(n, "")));
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkRsaKey(n, "AA")));
        // a modulus the key factory refuses (one byte) is the same refusal, never a raw exception
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkRsaKey("AQ", "AQAB")));
        assertEquals(AttestCert.OSSL_UNSUPPORTED, reason(() -> AttestJws.jwkRsaKey("", "AQAB")));
    }

    @Test
    void ktyCrvOfOtherKeyTypes() throws Exception {
        CertKey ed = CertKey.of(gen("Ed25519", null).getPublic(), new byte[0]);
        assertEquals("ed25519", ed.typ);
        assertArrayEquals(new String[] {"OKP", "Ed25519"}, AttestJws.jwkKtyCrv(ed));
        CertKey x = CertKey.of(gen("X25519", null).getPublic(), new byte[0]);
        assertEquals("unknown", x.typ);
        assertArrayEquals(new String[] {"unknown", "undefined"}, AttestJws.jwkKtyCrv(x));
        // the RSA rule reads the key, not its type tag
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        CertKey pss = CertKey.of(g.generateKeyPair().getPublic(), new byte[0]).withType("rsa-pss");
        assertArrayEquals(new String[] {"RSA", "undefined"}, AttestJws.jwkKtyCrv(pss));
        assertArrayEquals(new String[] {"OKP", "Ed25519"}, AttestJws.jwkKtyCrv(x.withType("ed25519")));
        assertFalse(AttestJws.jwsRs256Ok(new byte[256], "a.b".getBytes(StandardCharsets.UTF_8), ed));
        assertFalse(AttestJws.jwsEs256Ok(new byte[64], "a.b".getBytes(StandardCharsets.UTF_8), ed));
    }

    /**
     * A P-384 key under which a 64-byte r||s DOES verify over SHA-256 of the input (public key solved for a chosen R with a
     * small x and s = 1): ES256 still refuses it, because ES256 is P-256 only.
     */
    @Test
    void es256IsP256Only() {
        byte[] input = "header.payload".getBytes(StandardCharsets.UTF_8);
        X9ECParameters c = ECNamedCurveTable.getByName("P-384");
        BigInteger order = c.getN();
        ECPoint r = null;
        BigInteger rx = null;
        for (int x = 1; r == null; x++) {
            byte[] enc = new byte[49];
            enc[0] = 0x02;
            enc[48] = (byte) x;
            try {
                r = c.getCurve().decodePoint(enc);
                rx = BigInteger.valueOf(x);
            } catch (RuntimeException e) { // x is not the abscissa of a point
                r = null;
            }
        }
        BigInteger e = new BigInteger(1, AttestCommon.sha256Sum(input));
        ECPoint q = r.subtract(c.getG().multiply(e)).multiply(rx.modInverse(order)).normalize();
        ECPublicKey pub = AttestCommon.ecKeyOf("P-384", q.getAffineXCoord().toBigInteger(), q.getAffineYCoord().toBigInteger());
        assertNotNull(pub);
        byte[] sig = new byte[64];
        System.arraycopy(unsigned(rx, 32), 0, sig, 0, 32);
        sig[63] = 1;
        assertTrue(AttestCommon.verifyRawECDSA(pub, AttestCommon.sha256Sum(input), sig));
        CertKey k = CertKey.of(pub, pub.getEncoded());
        assertEquals("secp384r1", k.curve);
        assertFalse(AttestJws.jwsEs256Ok(sig, input, k));
    }
}
