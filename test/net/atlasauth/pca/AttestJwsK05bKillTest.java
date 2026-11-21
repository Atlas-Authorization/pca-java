package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

import org.junit.jupiter.api.Test;

/** ES256 takes exactly 64 signature bytes, even when a longer r || s (zero-padded halves) would verify. */
public class AttestJwsK05bKillTest {
    @Test
    void es256SignatureMustBe64Bytes() throws Exception {
        KeyPair kp = AttestTestDer.ecKey("secp256r1");
        byte[] input = "a.b".getBytes(StandardCharsets.UTF_8);
        Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
        s.initSign(kp.getPrivate());
        s.update(input);
        byte[] sig = s.sign();
        assertEquals(64, sig.length);
        CertKey k = CertKey.of(kp.getPublic(), kp.getPublic().getEncoded());
        assertTrue(AttestJws.jwsEs256Ok(sig, input, k));
        byte[] padded = new byte[66]; // 00 || r || 00 || s: the same r and s
        System.arraycopy(sig, 0, padded, 1, 32);
        System.arraycopy(sig, 32, padded, 34, 32);
        assertTrue(AttestCommon.verifyRawECDSA((ECPublicKey) kp.getPublic(), AttestCommon.sha256Sum(input), padded));
        assertFalse(AttestJws.jwsEs256Ok(padded, input, k));
    }
}
