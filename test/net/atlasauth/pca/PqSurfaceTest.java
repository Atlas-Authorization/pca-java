package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** The public PQ surface of pq.ts: keygen / sign / verify per primitive, the suite seam, composite, key checks. */
public class PqSurfaceTest {
    private static final byte[] MSG = "pca pq surface".getBytes(StandardCharsets.UTF_8);

    private static byte[] seed(int n, int v) {
        byte[] b = new byte[n];
        java.util.Arrays.fill(b, (byte) v);
        return b;
    }

    @Test void sizesMatchTheReference() {
        assertEquals(1952 + 3309, Pq.ML_DSA_65_PUBLIC_KEY_BYTES + Pq.ML_DSA_65_SIGNATURE_BYTES);
        assertEquals(3373, Pq.COMPOSITE_SIGNATURE_BYTES);
        assertEquals(2592, Pq.ML_DSA_87_PUBLIC_KEY_BYTES);
        assertEquals(4627, Pq.ML_DSA_87_SIGNATURE_BYTES);
        assertEquals(97484, Pq.LESS_CAT1_PUBLIC_KEY_BYTES);
        assertEquals(1345, Pq.FN_DSA_512_SECRET_KEY_BYTES);
        assertEquals(2369, Pq.FN_DSA_1024_SECRET_KEY_BYTES);
    }

    @Test void mlDsaRoundTripAndTamper() {
        for (int v = 0; v < 2; v++) {
            Pq.KeyPair k = v == 0 ? Pq.mlDsa65Keygen(seed(32, 7)) : Pq.mlDsa87Keygen(seed(32, 7));
            byte[] sig = v == 0 ? Pq.mlDsa65Sign(k.secretKey, MSG) : Pq.mlDsa87Sign(k.secretKey, MSG);
            String pk = Pca.b64(k.publicKey), sg = Pca.b64(sig);
            assertTrue(v == 0 ? Pq.mlDsa65VerifyB64u(pk, MSG, sg) : Pq.mlDsa87VerifyB64u(pk, MSG, sg));
            byte[] other = "other".getBytes(StandardCharsets.UTF_8);
            assertFalse(v == 0 ? Pq.mlDsa65Verify(k.publicKey, other, sig) : Pq.mlDsa87Verify(k.publicKey, other, sig));
        }
        assertArrayEquals(Pq.mlDsa65Keygen(seed(32, 1)).publicKey, Pq.mlDsa65Keygen(seed(32, 1)).publicKey);
        assertThrows(IllegalArgumentException.class, () -> Pq.mlDsa65Keygen(seed(31, 1)));
    }

    @Test void slhDsaRoundTrip() {
        Pq.KeyPair k = Pq.slhDsa128fKeygen(seed(48, 3));
        assertEquals(Pq.SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, k.publicKey.length);
        assertEquals(Pq.SLH_DSA_SHA2_128F_SECRET_KEY_BYTES, k.secretKey.length);
        byte[] sig = Pq.slhDsa128fSign(k.secretKey, MSG);
        assertEquals(Pq.SLH_DSA_SHA2_128F_SIGNATURE_BYTES, sig.length);
        assertTrue(Pq.slhDsa128fVerifyB64u(Pca.b64(k.publicKey), MSG, Pca.b64(sig)));
        assertFalse(Pq.slhDsa128fVerify(k.publicKey, new byte[] {1}, sig));
    }

    @Test void suiteSeamSignsAndVerifiesEveryImplementedSuite() {
        byte[] ed = seed(32, 9);
        String edPub = Keys.edFromSeed(ed).id();
        Pq.SuiteSecretKeys keys = new Pq.SuiteSecretKeys();
        keys.edSecret = ed;
        keys.mlDsa = Pq.mlDsa65Keygen(seed(32, 2));
        keys.mlDsa87 = Pq.mlDsa87Keygen(seed(32, 2));
        for (String alg : new String[] {"ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65", "ml-dsa-87", "hybrid-ed25519-ml-dsa-87"}) {
            Pq.SuiteArtifactFields f = Pq.signSuiteArtifact(alg, keys, MSG);
            Pq.PinnedPq pin = f.pqPk == null ? null : Pq.resolvePqVerifyKey("id", f.pqPk, null, null, f.pqPk);
            assertTrue(Pq.verifyWithSuite(alg, edPub, pin, MSG, f.sig, f.pqSig), alg);
            assertFalse(Pq.verifyWithSuite(alg, edPub, pin, "x".getBytes(StandardCharsets.UTF_8), f.sig, f.pqSig), alg);
            assertEquals("ed25519".equals(alg) ? null : alg, f.alg);
        }
        // the default suite carries no suite fields and equals the plain Ed25519 signature
        assertEquals(Pca.b64(Keys.edFromSeed(ed).sign(MSG)), Pq.signWithSuite(null, keys, MSG).sig);
        assertNull(Pq.suitePqPublicKey("ed25519", keys));
        assertNotNull(Pq.suitePqPublicKey("ml-dsa-65", keys));
        assertNull(Pq.suitePqPublicKey("ml-dsa-65", new Pq.SuiteSecretKeys()));
    }

    @Test void signingFailsClosed() {
        Pq.SuiteSecretKeys none = new Pq.SuiteSecretKeys();
        assertThrows(IllegalArgumentException.class, () -> Pq.signWithSuite("no-such-alg", none, MSG));
        assertThrows(IllegalArgumentException.class, () -> Pq.signWithSuite("ml-dsa-65", none, MSG));
        assertThrows(IllegalArgumentException.class, () -> Pq.signWithSuite("hybrid-ed25519-ml-dsa-65", none, MSG));
        assertTrue(Pq.isKnownSigAlg("fn-dsa-512"));
        assertFalse(Pq.isKnownSigAlg("nope"));
        assertFalse(Pq.isKnownSigAlg(null));
    }

    @Test void hybridNeedsBothHalves() {
        byte[] ed = seed(32, 4);
        Pq.SuiteSecretKeys keys = new Pq.SuiteSecretKeys();
        keys.edSecret = ed;
        keys.mlDsa = Pq.mlDsa65Keygen(seed(32, 4));
        Pq.SuiteArtifactFields f = Pq.signSuiteArtifact("hybrid-ed25519-ml-dsa-65", keys, MSG);
        Pq.PinnedPq pin = Pq.resolvePqVerifyKey("id", f.pqPk, null, null, f.pqPk);
        String edPub = Keys.edFromSeed(ed).id();
        assertFalse(Pq.verifyWithSuite(f.alg, edPub, pin, MSG, f.sig, null));
        assertFalse(Pq.verifyWithSuite(f.alg, edPub, null, MSG, f.sig, f.pqSig));
        assertTrue(Pq.isPinnedPqKey(pin));
        assertFalse(Pq.isPinnedPqKey(f.pqPk));
    }

    @Test void wellFormedPqPublicKey() {
        assertTrue(Pq.isWellFormedPqPublicKey(Pca.b64(Pq.mlDsa65Keygen(seed(32, 5)).publicKey)));
        assertTrue(Pq.isWellFormedPqPublicKey(Pca.b64(new byte[32])));
        assertFalse(Pq.isWellFormedPqPublicKey(Pca.b64(new byte[33])));
        assertFalse(Pq.isWellFormedPqPublicKey("not base64url!"));
        assertFalse(Pq.isWellFormedPqPublicKey(null));
    }

    @Test void compositeBindsBothHalvesAndTheContext() {
        byte[] ed = seed(32, 6);
        byte[] edPub = Keys.edFromSeed(ed).pub;
        Pq.KeyPair ml = Pq.mlDsa65Keygen(seed(32, 6));
        byte[] ctx = "ctx".getBytes(StandardCharsets.UTF_8);
        byte[] sig = Pq.compositeSign(ed, ml, MSG, ctx);
        assertEquals(Pq.COMPOSITE_SIGNATURE_BYTES, sig.length);
        assertTrue(Pq.compositeVerify(edPub, ml.publicKey, MSG, sig, ctx));
        assertFalse(Pq.compositeVerify(edPub, ml.publicKey, MSG, sig, null));
        assertFalse(Pq.compositeVerify(edPub, ml.publicKey, MSG, java.util.Arrays.copyOf(sig, sig.length - 1), ctx));
        byte[] bad = sig.clone();
        bad[sig.length - 1] ^= 1;
        assertFalse(Pq.compositeVerify(edPub, ml.publicKey, MSG, bad, ctx));
        assertFalse(Pq.compositeVerify(edPub, ml.publicKey, MSG, sig, new byte[256]));
        assertThrows(IllegalArgumentException.class, () -> Pq.compositeRepresentative(MSG, new byte[256]));
        byte[] r = Pq.compositeRepresentative(MSG, "ctx");
        assertEquals(32 + 30 + 1 + 3 + 64, r.length);
    }

    @Test void lessIsOptional() {
        assertEquals(LessNative.available(), Pq.isLessBackendActive());
        assertEquals(Pq.isLessBackendActive(), Pq.lessBackendStatus().available);
        if (!Pq.isLessBackendActive()) {
            assertNotNull(Pq.lessBackendStatus().reason);
            assertThrows(IllegalStateException.class, () -> Pq.lessCat1Keygen(seed(32, 1)));
        }
    }
}
