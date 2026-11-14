package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.integer;
import static net.atlasauth.pca.AttestTestDer.oid;
import static net.atlasauth.pca.AttestTestDer.seq;
import static net.atlasauth.pca.AttestTestDer.utf8;
import static net.atlasauth.pca.AttestTestDer.withTag;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for the attestation readers (reference packages/pca-attest-eat/src): the X.509 extension shapes the OCSP
 * issuer check decodes (name constraints, CRL distribution points, authority key identifier), RIM input limits, and two Sigstore
 * checkpoint / EKU edges. Keys are generated at class load.
 */
public class K05R5G4Test {
    static final KeyPair K = AttestTestDer.ecKey("secp256r1");

    static byte[] ext(String oid, byte[] value) { return AttestTestDer.ext(oid, false, value); }

    /** True when a certificate issued by "Int" (carrying the given extensions) is accepted as the issuer of a plain subject. */
    static boolean issuerWith(byte[]... exts) {
        AttCert issuer = AttestCert.parseCertDer(AttestTestDer.cert("Int", "Top", K, K, exts));
        AttCert cand = AttestCert.parseCertDer(AttestTestDer.cert("Sub", "Int", K, K));
        return AttestNvidiaOcsp.checkIssued(cand, issuer);
    }

    static final byte[] DNS = withTag(0x82, "x".getBytes(StandardCharsets.US_ASCII));
    static final byte[] ATV = seq(oid("2.5.4.3"), utf8("x"));

    // ---- nameConstraints (2.5.29.30) ----

    static boolean nc(byte[]... parts) { return issuerWith(ext("2.5.29.30", seq(parts))); }

    @Test void nameConstraintsShape() {
        assertTrue(issuerWith());
        assertTrue(nc(withTag(0xa0, seq(DNS))));
        assertTrue(nc(withTag(0xa0, seq(DNS, withTag(0x80, new byte[] {0}), withTag(0x81, new byte[] {5}))), withTag(0xa1, seq(DNS))));
        assertTrue(nc());
        // only [0] and [1], in that order, nothing else (a child with tag 0 is not a subtree list)
        assertFalse(nc(withTag(0xa0, seq(DNS)), withTag(0x00)));
        assertFalse(nc(withTag(0xa1, seq(DNS)), withTag(0xa0, seq(DNS))));
        assertFalse(nc(withTag(0xa0, seq(DNS)), withTag(0xa0, seq(DNS))));
        // each subtree is a SEQUENCE
        assertFalse(nc(withTag(0xa0, withTag(0x31, DNS))));
        assertFalse(nc(withTag(0xa0, withTag(0x04, DNS))));
        assertFalse(nc(withTag(0xa0, seq())));
        // its base must be a decodable GeneralName
        assertFalse(nc(withTag(0xa0, seq(withTag(0x83, new byte[] {1})))));
        // minimum [0] then maximum [1], each at most once, each a positive minimal INTEGER
        assertFalse(nc(withTag(0xa0, seq(DNS, withTag(0x00, new byte[] {1})))));
        assertFalse(nc(withTag(0xa0, seq(DNS, withTag(0x81, new byte[] {5}), withTag(0x80, new byte[] {0})))));
        assertFalse(nc(withTag(0xa0, seq(DNS, withTag(0x80, new byte[] {0}), withTag(0x80, new byte[] {0})))));
        assertFalse(nc(withTag(0xa0, seq(DNS, withTag(0x80, new byte[] {(byte) 0x80})))));
        assertFalse(nc(withTag(0xa0, seq(DNS, withTag(0x80, new byte[] {0, 1})))));
        assertFalse(nc(withTag(0xa0, seq(DNS, withTag(0x80)))));
    }

    // ---- cRLDistributionPoints (2.5.29.31) ----

    static boolean dp(byte[]... dps) { return issuerWith(ext("2.5.29.31", seq(dps))); }

    @Test void distributionPointsShape() {
        assertTrue(dp(seq(withTag(0xa2, DNS))));
        assertTrue(dp(seq(withTag(0xa0, withTag(0xa0, DNS)))));
        assertTrue(dp(seq(withTag(0xa0, withTag(0xa1, ATV)))));
        assertTrue(dp(seq(withTag(0xa0, withTag(0xa1, ATV)), withTag(0x81, new byte[] {7}), withTag(0xa2, DNS))));
        // each distribution point is a SEQUENCE
        assertFalse(dp(withTag(0x31, withTag(0xa2, DNS))));
        assertFalse(dp(withTag(0x04, withTag(0xa2, DNS))));
        // members are [0], [1] (reasons), [2], once each, in that order; a child with tag 0 is none of them
        assertFalse(dp(seq(withTag(0x00, withTag(0xa0)))));
        assertFalse(dp(seq(withTag(0xa2, DNS), withTag(0xa0, withTag(0xa0, DNS)))));
        // reasons alone do not decode; the unused-bits octet is at most 7
        assertFalse(dp(seq(withTag(0x81, new byte[] {1}))));
        assertFalse(dp(seq(withTag(0xa0, withTag(0xa0, DNS)), withTag(0x81, new byte[] {8}))));
        assertFalse(dp(seq(withTag(0xa0, withTag(0xa0, DNS)), withTag(0x81))));
        // the [0] name is a fullName [0] or a relative name [1], nothing else
        assertFalse(dp(seq(withTag(0xa0, withTag(0xa5, ATV)))));
        assertFalse(dp(seq(withTag(0xa0, withTag(0xa0, DNS), withTag(0xa0, DNS)))));
        assertFalse(dp(seq(withTag(0xa0))));
        // a relative name: each attribute is a SEQUENCE of exactly an OID and a text value
        assertFalse(dp(seq(withTag(0xa0, withTag(0xa1, withTag(0x31, oid("2.5.4.3"), utf8("x")))))));
        assertFalse(dp(seq(withTag(0xa0, withTag(0xa1, seq(oid("2.5.4.3")))))));
        assertFalse(dp(seq(withTag(0xa0, withTag(0xa1, seq(oid("2.5.4.3"), withTag(0x02, new byte[] {1})))))));
        assertFalse(dp(seq(withTag(0xa0, withTag(0xa1, seq(oid("2.5.4.3"), withTag(0x0c, new byte[] {(byte) 0xff})))))));
    }

    // ---- authorityKeyIdentifier (2.5.29.35) on the issuer ----

    static boolean aki(byte[]... parts) { return issuerWith(ext("2.5.29.35", seq(parts))); }

    @Test void issuerAuthorityKeyIdentifierShape() {
        assertTrue(aki());
        assertTrue(aki(withTag(0x80, new byte[] {1}), withTag(0xa1, DNS), withTag(0x82, new byte[] {1})));
        assertTrue(aki(withTag(0x82, new byte[] {0x7f})));
        assertTrue(aki(withTag(0x82, new byte[] {0, (byte) 0x80})));
        // the key identifier is any octets, empty or not: only the serial is read as an INTEGER
        assertTrue(aki(withTag(0x80, new byte[] {0, 1})));
        assertTrue(aki(withTag(0x80)));
        assertFalse(aki(withTag(0x00)));
        assertFalse(aki(withTag(0x82, new byte[] {1}), withTag(0x80, new byte[] {1})));
        // the serial is a minimal, non-empty INTEGER
        assertFalse(aki(withTag(0x82)));
        assertFalse(aki(withTag(0x82, new byte[] {0, 1})));
        assertFalse(aki(withTag(0x82, new byte[] {(byte) 0xff, (byte) 0x80})));
        assertFalse(aki(withTag(0xa1, withTag(0x83, new byte[] {1}))));
    }

    // ---- RIM ----

    @Test void rimInputLimits() {
        for (String bad : new String[] {null, ""}) assertEquals("RIM: empty or oversized document", AttestNvidiaRim.verifyRim(bad, List.of("p"), 0L).reason);
        assertEquals("RIM: empty or oversized document", AttestNvidiaRim.verifyRim("x".repeat(4_000_001), List.of("p"), 0L).reason);
        assertEquals("RIM: no pinned RIM root configured", AttestNvidiaRim.verifyRim("x".repeat(4_000_000), List.of(), 0L).reason);
    }

    @Test void aFreshCollateralBundleCarriesNoRims() {
        AttestNvidiaRim.Bundle b = new AttestNvidiaRim.Bundle();
        assertEquals("", b.driverRim);
        assertEquals("", b.vbiosRim);
        assertTrue(b.crls.isEmpty());
        assertTrue(b.ocsp.isEmpty());
    }

    // ---- Sigstore ----

    @Test void anEcKeyNeverVerifiesAV2CheckpointNote() throws Exception {
        byte[] root = new byte[32];
        byte[] keyId = new byte[32];
        Arrays.fill(keyId, (byte) 7);
        String body = "o\n1\n" + SigstoreK05KillTest.b64(root) + "\n";
        byte[] sig = SigstoreK05KillTest.sign("SHA256withECDSA", SigstoreK05KillTest.TLOG.getPrivate(), K05R3SigstoreKillTest.utf(body));
        String text = body + "\n" + K05R3SigstoreKillTest.DASH + " rekor.example " + SigstoreK05KillTest.b64(AttestTestDer.cat(Arrays.copyOf(keyId, 4), sig)) + "\n";
        Class<?>[] types = {String.class, Sigstore.PinnedLog.class, long.class, byte[].class};
        long[] always = {0, Long.MAX_VALUE};
        Sigstore.PinnedLog v2 = new Sigstore.PinnedLog(keyId, SigstoreK05KillTest.TLOG.getPublic(), always, "rekor.example");
        assertEquals("no checkpoint signature by the pinned log key", K05R3SigstoreKillTest.call("verifyCheckpoint", types, text, v2, 1L, root));
        // the same signature under a v1 (ECDSA / SHA-256) log verifies
        Sigstore.PinnedLog v1 = new Sigstore.PinnedLog(keyId, SigstoreK05KillTest.TLOG.getPublic(), always, null);
        assertNull(K05R3SigstoreKillTest.call("verifyCheckpoint", types, text, v1, 1L, root));
    }

    @Test void extendedKeyUsageIsReadStrictly() throws Exception {
        String codeSigning = "1.3.6.1.5.5.7.3.3";
        Class<?>[] types = {X509Certificate.class, String.class};
        X509Certificate none = new K05R3SigstoreKillTest.ExtCert("2.5.29.19", AttestTestDer.octets(seq()));
        X509Certificate has = new K05R3SigstoreKillTest.ExtCert("2.5.29.37", AttestTestDer.octets(seq(oid(codeSigning))));
        X509Certificate bad = new K05R3SigstoreKillTest.ExtCert("2.5.29.37", AttestTestDer.octets(integer(5)));
        assertEquals(false, K05R3SigstoreKillTest.call("hasEku", types, none, codeSigning));
        assertEquals(true, K05R3SigstoreKillTest.call("hasEku", types, has, codeSigning));
        assertEquals(false, K05R3SigstoreKillTest.call("hasEku", types, has, "1.3.6.1.5.5.7.3.9"));
        assertEquals(false, K05R3SigstoreKillTest.call("hasEku", types, bad, codeSigning));
    }
}
