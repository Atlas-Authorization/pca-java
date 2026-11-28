package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.oid;
import static net.atlasauth.pca.AttestTestDer.seq;
import static net.atlasauth.pca.AttestTestDer.withTag;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** AttestCert: the OID arc-start rule after an odd byte, and an MGF that is not MGF1 under a matching hash. */
public class AttestCertBasebKillTest {
    @Test
    void oidArcStartIsTheHighBitOfThePreviousByte() {
        // 0x2b has its low bit set: only its high bit (clear) says the next byte starts an arc, so 0x80 there is refused
        assertFalse(AttestCertBaseKillTest.vo(0x06, 2, 5, 0x06, 0x03, 0x2b, 0x80, 0x01));
        // 0x81 at an arc start is a legal continuation
        assertTrue(AttestCertBaseKillTest.vo(0x06, 2, 5, 0x06, 0x03, 0x2b, 0x81, 0x01));
    }

    @Test
    void maskGenerationMustBeMgf1EvenWhenItsHashMatches() {
        String sha256 = AttestCertBaseKillTest.SHA256;
        byte[] notMgf1 = withTag(0xa1, seq(oid("1.2.3"), AttestCertBaseKillTest.hashAlg(sha256)));
        assertEquals("SHA-1/20/false", AttestCertBaseKillTest.pp(seq(withTag(0xa0, AttestCertBaseKillTest.hashAlg(sha256)), notMgf1)));
        // the same parameters with MGF1: accepted
        assertEquals("SHA-256/20/true", AttestCertBaseKillTest.pp(seq(withTag(0xa0, AttestCertBaseKillTest.hashAlg(sha256)), AttestCertBaseKillTest.mgf(sha256))));
    }
}
