package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.bits;
import static net.atlasauth.pca.AttestTestDer.ext;
import static net.atlasauth.pca.AttestTestDer.seq;
import static net.atlasauth.pca.AttestTestDer.withTag;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Round 4 attestation kill tests. Extension rows were read from Node 26 X509Certificate.checkIssued, on subject and issuer alike. */
class K05R4AttestKillTest {
    static String t(int tag, String... parts) {
        String body = String.join("", parts);
        int n = body.length() / 2;
        if (n >= 128) throw new IllegalArgumentException("row too long");
        return String.format("%02x%02x", tag, n) + body;
    }

    static final String U = "68747470733a2f2f61";
    static final String NAMES = t(0xa0, t(0xa0, "8609" + U)); // distributionPoint [0] fullName
    static final String CRLI = t(0xa2, "8609" + U);
    static final String REASONS = "81020180";
    static final String GN = "820161";

    static String nc(String... bounds) { return t(0x30, t(0xa0, t(0x30, GN + String.join("", bounds)))); }

    static String cdp(String... parts) { return t(0x30, t(0x30, parts)); }

    @Test void repeatedOrMisorderedMembersOfNameConstraintsAndDistributionPointsAreRefused() {
        Object[][] rows = {
            {"30", t(0x30, t(0xa0, t(0x30, GN)), t(0xa0, t(0x30, GN))), false},
            {"30", t(0x30, t(0xa0, t(0x30, GN)), t(0xa1, t(0x30, GN))), true},
            {"30", t(0x30, t(0xa1, t(0x30, GN)), t(0xa1, t(0x30, GN))), false},
            {"30", t(0x30, t(0xa1, t(0x30, GN)), t(0xa0, t(0x30, GN))), false},
            {"30", nc("800100", "800100"), false},
            {"30", nc("810101", "810101"), false},
            {"30", nc("800100", "810101"), true},
            {"30", nc("810101", "800100"), false},
            {"30", nc("800100"), true},
            {"30", nc("8000"), false},
            {"30", nc("80020080"), true},
            {"30", nc("80020000"), false},
            {"31", cdp(REASONS, NAMES), false},
            {"31", cdp(NAMES, CRLI), true},
            {"31", cdp(NAMES, NAMES), false},
            {"31", cdp(NAMES, REASONS, CRLI), true},
            {"31", cdp(NAMES, CRLI, REASONS), false},
            {"31", cdp(CRLI, REASONS), false},
            {"31", cdp(NAMES, CRLI, CRLI), false},
            {"31", cdp(NAMES, NAMES, REASONS), false},
            {"31", cdp(NAMES, "81020780"), true},
            {"31", cdp(NAMES, "81020880"), false},
            {"31", cdp(t(0xa0, t(0xa2, "8600"))), false},
            {"17", t(0x30, t(0xa4, "30000500")), false},
            {"17", t(0x30, t(0xa4, "0500")), false},
            {"17", t(0x30, t(0xa4, "3000")), true},
            {"17", t(0x30, t(0xa4, "3000"), t(0xa4, "3000")), true},
            {"37", "30000500", true},
        };
        for (Object[] r : rows) {
            byte[] e = ext("2.5.29." + r[0], false, HexFormat.of().parseHex((String) r[1]));
            boolean want = (Boolean) r[2];
            assertEquals(want, K05IssuerLinkTableTest.issued(K05IssuerLinkTableTest.child(e), K05IssuerLinkTableTest.ca()), "subject " + r[0] + " " + r[1]);
            assertEquals(want, K05IssuerLinkTableTest.issued(K05IssuerLinkTableTest.child(), K05IssuerLinkTableTest.ca(e)), "issuer " + r[0] + " " + r[1]);
        }
    }

    /** x509-strict.ts:276: the message of the read failure is carried (the second, strict read refuses a duplicate extension the role read ignores). */
    @Test void aStrictExtensionReadFailureCarriesItsMessage() {
        KeyPair k = AttestTestDer.ecKey("secp256r1");
        byte[] dup = ext("2.5.29.99", false, new byte[] {5, 0});
        assertEquals("certificate extension parse failed: duplicate extension 2.5.29.99",
            AttestDer.strictChainError(List.of(AttestTestDer.cert("x", "x", k, k, dup, dup))));
    }

    /** attest-azure-maa.ts:395: the profile slice runs through the anchor itself (certs.slice(0, anchorIdx + 1)). */
    @Test void theInChainAnchorIsHeldToTheChainProfile() {
        KeyPair root = AttestTestDer.ecKey("secp256r1");
        KeyPair leaf = AttestTestDer.ecKey("secp256r1");
        byte[] rootDer = AttestTestDer.cert("root", "root", root, root, AttestTestDer.basicConstraints(true, -1), K05StrictChainTest.unknownCritical());
        byte[] leafDer = AttestTestDer.cert("leaf", "root", leaf, root);
        Map<String, Object> pinned = AttestMaaKillTest.config("{\"rootSpkiSha256\":[\"" + AttestCommon.toHexLower(AttestCommon.sha256Sum(root.getPublic().getEncoded())) + "\"]}", AttestMaaKillTest.TDX);
        String tok = AttestMaaKillTest.x5cTok(leaf, null, AttestMaaKillTest.b64(leafDer), AttestMaaKillTest.b64(rootDer));
        AttestMaaTest.assertDenied("anchor with an unrecognised critical extension",
            AttestMaaTest.run(AttestMaaKillTest.V, pinned, AttestMaaTest.obj("token", tok), AttestMaaTest.BINDING, AttestMaaTest.NOW),
            "MAA signing chain invalid: x5c chain profile: certificate at depth 1 has an unrecognised critical extension 1.2.3.4");
    }

    /** x509.ParsePKCS1PublicKey: a redundant leading 0x00 on the modulus or exponent is not DER. */
    @Test void aNonMinimalPkcs1IntegerIsRefused() {
        RSAPublicKey k = (RSAPublicKey) K05IssuerRsaPssTest.RSA.getPublic();
        byte[] n = k.getModulus().toByteArray();
        byte[] e = k.getPublicExponent().toByteArray();
        byte[] n0 = new byte[n.length + 1];
        System.arraycopy(n, 0, n0, 1, n.length);
        byte[] e0 = new byte[e.length + 1];
        System.arraycopy(e, 0, e0, 1, e.length);
        AttestCert.keyOfCert(AttestCert.parseCertDer(K05IssuerRsaPssTest.rsaSigned(new byte[] {5}, "Sub", "Int", pkcs1Spki(n, e)))); // control
        for (byte[][] bad : new byte[][][] {{n0, e}, {n, e0}}) {
            AttestException x = org.junit.jupiter.api.Assertions.assertThrows(AttestException.class, () -> AttestCert.keyOfCert(AttestCert.parseCertDer(
                K05IssuerRsaPssTest.rsaSigned(new byte[] {5}, "Sub", "Int", pkcs1Spki(bad[0], bad[1])))));
            assertEquals(AttestCert.OSSL_UNSUPPORTED, x.getMessage());
        }
    }

    static byte[] pkcs1Spki(byte[] n, byte[] e) {
        return seq(K05IssuerRsaPssTest.RSA_SPKI_ALG, bits((byte) 0, seq(withTag(0x02, n), withTag(0x02, e))));
    }
}
