package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.octets;
import static net.atlasauth.pca.AttestTestDer.oid;
import static net.atlasauth.pca.AttestTestDer.seq;
import static net.atlasauth.pca.AttestTestDer.withTag;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * AttestNvidiaOcsp: responseBytes wrapped in exactly one SEQUENCE, an empty ResponseData, an ECDSA signature under an RSA
 * algorithm, and a delegated responder whose notAfter the strict reader cannot parse (checked at a clock where its zero
 * instant would otherwise fall inside the window).
 */
public class AttestNvidiaOcspK05bKillTest {
    static final String REJ = AttestNvidiaOcspKillTest.REJ;

    static String v(byte[] der) { return AttestNvidiaOcspKillTest.v(der); }

    @Test
    void responseBytesIsExactlyOneSequence() {
        byte[] basic = AttestNvidiaOcspKillTest.resp().basic();
        byte[] en0 = withTag(0x0a, new byte[] {0});
        byte[] rb = seq(oid(AttestNvidiaOcsp.OID_OCSP_BASIC), octets(basic));
        assertEquals("OK good", v(seq(en0, withTag(0xa0, rb))));
        assertEquals(REJ + "malformed responseBytes", v(seq(en0, withTag(0xa0, rb, seq()))));
        assertEquals(REJ + "malformed responseBytes", v(seq(en0, withTag(0xa0, withTag(0x31, oid(AttestNvidiaOcsp.OID_OCSP_BASIC), octets(basic))))));
    }

    @Test
    void emptyResponseData() {
        assertEquals(REJ + "malformed ResponseData", v(AttestNvidiaOcspKillTest.wrap(AttestNvidiaOcspKillTest.rawBasic(seq()))));
    }

    @Test
    void ecdsaSignatureUnderAnRsaAlgorithm() {
        byte[] tbs = "tbs".getBytes(StandardCharsets.US_ASCII);
        CertKey ec = CertKey.of(AttestNvidiaOcspKillTest.K_INT.getPublic(), AttestNvidiaOcspKillTest.K_INT.getPublic().getEncoded());
        byte[] es256 = AttestNvidiaOcspKillTest.signWith(AttestNvidiaOcspKillTest.K_INT.getPrivate(), "SHA256withECDSA", tbs);
        assertTrue(AttestNvidiaOcsp.sigOk(AttestNvidiaOcspKillTest.EC256, tbs, es256, ec));
        assertFalse(AttestNvidiaOcsp.sigOk(AttestNvidiaOcspKillTest.RSA256, tbs, es256, ec));
    }

    @Test
    void unparseableNotAfterIsOutsideAtAnyClock() {
        // notBefore 1969-01-01, notAfter a fractional GeneralizedTime (well-formed for the response, not for the certificate reader)
        AttestNvidiaOcspKillTest.Party d = AttestNvidiaOcspKillTest.delegate("Responder", "Int", AttestNvidiaOcspKillTest.K_DEL, AttestNvidiaOcspKillTest.K_INT,
            AttestNvidiaOcspKillTest.utEl("690101000000Z"), AttestNvidiaOcspKillTest.gtEl("20350101000000.5Z"), true);
        byte[] der = AttestNvidiaOcspKillTest.delegated(d).der();
        assertEquals(AttestNvidiaOcspKillTest.OUTSIDE, AttestNvidiaOcspKillTest.v(der, -1000L));
    }

    // attest-nvidia-ocsp.ts:196
    @Test
    void pkcs1UnderAnRsaPssKeyIsRefused() throws Exception {
        java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        java.security.KeyPair rsa = g.generateKeyPair();
        byte[] tbs = "tbs".getBytes(StandardCharsets.US_ASCII);
        byte[] sig = AttestNvidiaOcspKillTest.signWith(rsa.getPrivate(), "SHA256withRSA", tbs);
        CertKey key = CertKey.of(rsa.getPublic(), rsa.getPublic().getEncoded());
        assertTrue(AttestNvidiaOcsp.sigOk(AttestNvidiaOcspKillTest.RSA256, tbs, sig, key));
        assertFalse(AttestNvidiaOcsp.sigOk(AttestNvidiaOcspKillTest.RSA256, tbs, sig, key.withType("rsa-pss")));
    }

    // attest-nvidia-ocsp.ts:297: cand.checkIssued(s)
    private static AttCert parsed(byte[] der) { return AttestCert.parseCertDer(der); }

    private static byte[] aki(byte[]... members) { return AttestTestDer.ext("2.5.29.35", false, AttestTestDer.seq(members)); }

    private static byte[] ski(byte[] id) { return AttestTestDer.ext("2.5.29.14", false, AttestTestDer.octets(id)); }

    @Test
    void checkIssuedIsOpenSslChecks() {
        java.security.KeyPair k = AttestTestDer.ecKey("secp256r1");
        byte[] id = {1, 2, 3}, other = {9};
        byte[] issuerName = AttestTestDer.name("Top");
        AttCert issuer = parsed(AttestTestDer.cert("Int", "Top", k, k, ski(id)));
        AttCert plainIssuer = parsed(AttestTestDer.cert("Int", "Top", k, k));
        java.util.function.Function<byte[][], AttCert> subject = exts -> parsed(AttestTestDer.cert("Sub", "Int", k, k, exts));
        assertTrue(AttestNvidiaOcsp.checkIssued(subject.apply(new byte[0][]), issuer), "no AKID");
        assertFalse(AttestNvidiaOcsp.checkIssued(parsed(AttestTestDer.cert("Sub", "Else", k, k)), issuer), "another issuer name");
        // keyUsage
        assertFalse(AttestNvidiaOcsp.checkIssued(subject.apply(new byte[0][]), parsed(AttestTestDer.cert("Int", "Top", k, k, AttestTestDer.keyUsageDigitalSignature()))));
        assertTrue(AttestNvidiaOcsp.checkIssued(subject.apply(new byte[0][]), parsed(AttestTestDer.cert("Int", "Top", k, k, AttestTestDer.keyUsageCertSign()))));
        // key id: compared only when the issuer has a SKI
        AttCert withId = subject.apply(new byte[][] {aki(AttestTestDer.withTag(0x80, id))});
        AttCert otherId = subject.apply(new byte[][] {aki(AttestTestDer.withTag(0x80, other))});
        assertTrue(AttestNvidiaOcsp.checkIssued(withId, issuer));
        assertFalse(AttestNvidiaOcsp.checkIssued(otherId, issuer));
        assertTrue(AttestNvidiaOcsp.checkIssued(otherId, plainIssuer));
        // serial
        AttCert rightSerial = subject.apply(new byte[][] {aki(AttestTestDer.withTag(0x82, issuer.serial))});
        AttCert wrongSerial = subject.apply(new byte[][] {aki(AttestTestDer.withTag(0x82, other))});
        assertTrue(AttestNvidiaOcsp.checkIssued(rightSerial, issuer));
        assertFalse(AttestNvidiaOcsp.checkIssued(wrongSerial, issuer));
        // the first directoryName in the AKID issuer, after any other name form
        byte[] dns = AttestTestDer.withTag(0x82, "x".getBytes(StandardCharsets.US_ASCII));
        byte[] right = AttestTestDer.withTag(0xa4, issuerName), wrong = AttestTestDer.withTag(0xa4, AttestTestDer.name("Nope"));
        assertTrue(AttestNvidiaOcsp.checkIssued(subject.apply(new byte[][] {aki(AttestTestDer.withTag(0xa1, dns, right))}), issuer));
        assertFalse(AttestNvidiaOcsp.checkIssued(subject.apply(new byte[][] {aki(AttestTestDer.withTag(0xa1, dns, wrong))}), issuer));
        assertTrue(AttestNvidiaOcsp.checkIssued(subject.apply(new byte[][] {aki(AttestTestDer.withTag(0xa1, right, wrong))}), issuer), "only the first");
        assertTrue(AttestNvidiaOcsp.checkIssued(subject.apply(new byte[][] {aki(AttestTestDer.withTag(0xa1, dns))}), issuer), "no directoryName");
        // members after the first are read, and an unreadable extension is not an issuer match
        assertFalse(AttestNvidiaOcsp.checkIssued(subject.apply(new byte[][] {aki(AttestTestDer.withTag(0x80, id), AttestTestDer.withTag(0x82, other))}), issuer));
        assertFalse(AttestNvidiaOcsp.checkIssued(subject.apply(new byte[][] {AttestTestDer.ext("2.5.29.35", false, AttestTestDer.octets(id))}), issuer), "AKID not a SEQUENCE");
        AttCert badSki = parsed(AttestTestDer.cert("Int", "Top", k, k, AttestTestDer.ext("2.5.29.14", false, AttestTestDer.seq())));
        assertFalse(AttestNvidiaOcsp.checkIssued(withId, badSki), "SKI not an OCTET STRING");
    }
}
