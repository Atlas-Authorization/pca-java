package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import org.bouncycastle.crypto.CryptoException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * 0.5 mutation kills for {@link Keys}: every suite signs a message the verifier accepts, the key generators and loaders produce
 * the documented sizes and copies, and every refusal is the exact exception and message.
 */
public class KeysK05KillTest {
    static byte[] fill(int n, int v) { byte[] b = new byte[n]; Arrays.fill(b, (byte) v); return b; }
    static final byte[] MSG = "keys kill test".getBytes(StandardCharsets.UTF_8);

    static void refuses(Class<? extends Throwable> type, String message, Executable e) {
        assertEquals(message, assertThrows(type, e).getMessage());
    }

    @Test void base64url() {
        assertArrayEquals(new byte[] {0, 0, 0}, Keys.unb64u("AAAA"));
        assertArrayEquals(new byte[] {(byte) 0xfb, (byte) 0xff}, Keys.unb64u("-_8"));
        assertEquals("AAAA", Keys.b64u(new byte[3]));
        for (String bad : new String[] {"A", "AB", "AA==", "A+AA", null}) refuses(IllegalArgumentException.class, "not canonical base64url", () -> Keys.unb64u(bad));
    }

    @Test void ed25519Keys() {
        Keys.EdKey k = Keys.edFromSeed(fill(32, 1));
        assertEquals(32, k.pub.length);
        assertEquals(Keys.b64u(k.pub), k.id());
        byte[] seed = fill(32, 1);
        Keys.EdKey k2 = Keys.edFromSeed(seed);
        seed[0] = 9;
        assertArrayEquals(fill(32, 1), k2.seed); // copied
        assertArrayEquals(k.pub, k2.pub);
        refuses(IllegalArgumentException.class, "an Ed25519 seed is 32 bytes", () -> Keys.edFromSeed(null));
        refuses(IllegalArgumentException.class, "an Ed25519 seed is 32 bytes", () -> Keys.edFromSeed(new byte[31]));
        Keys.EdKey g1 = Keys.edGenerate(), g2 = Keys.edGenerate();
        assertFalse(Arrays.equals(g1.seed, g2.seed));
        assertFalse(Arrays.equals(new byte[32], g1.seed)); // drawn from the RNG, not left zero
        assertTrue(Pca.verifyB64u(g1.id(), MSG, Keys.b64u(g1.sign(MSG))));
    }

    @Test void seedRandomReplaysAndRunsOut() {
        Keys.SeedRandom r = new Keys.SeedRandom(new byte[] {1, 2, 3});
        byte[] a = new byte[2];
        r.nextBytes(a);
        assertArrayEquals(new byte[] {1, 2}, a);
        byte[] b = new byte[1];
        r.nextBytes(b);
        assertArrayEquals(new byte[] {3}, b);
        refuses(IllegalStateException.class, "seed exhausted", () -> r.nextBytes(new byte[1]));
        Keys.SeedRandom r2 = new Keys.SeedRandom(new byte[] {7});
        refuses(IllegalStateException.class, "seed exhausted", () -> r2.nextBytes(new byte[2]));
        r2.nextBytes(new byte[0]);
    }

    @Test void checkedSignerFailureIsIllegalState() {
        CryptoException cause = new CryptoException("boom");
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> Keys.bc(() -> { throw cause; }));
        assertSame(cause, e.getCause());
        byte[] out = {4};
        assertSame(out, Keys.bc(() -> out));
    }

    @Test void pqFromSeedSizes() {
        assertEquals(1952, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(32, 2)).pk.length);
        assertEquals(2592, Keys.pqFromSeed(Pq.Prim.ML_DSA_87, fill(32, 2)).pk.length);
        assertEquals(32, Keys.pqFromSeed(Pq.Prim.SLH_DSA_SHA2_128F, fill(48, 2)).pk.length);
        assertEquals(64, Keys.pqFromSeed(Pq.Prim.SLH_DSA_SHA2_256S, fill(96, 2)).pk.length);
        assertArrayEquals(Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(32, 2)).pk, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(32, 2)).pk);
        assertFalse(Arrays.equals(Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(32, 2)).pk, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(32, 3)).pk));
        refuses(IllegalArgumentException.class, "SLH_DSA_SHA2_128F needs a 48-byte seed", () -> Keys.pqFromSeed(Pq.Prim.SLH_DSA_SHA2_128F, fill(49, 2)));
        refuses(IllegalArgumentException.class, "SLH_DSA_SHA2_128F needs a 48-byte seed", () -> Keys.pqFromSeed(Pq.Prim.SLH_DSA_SHA2_128F, fill(32, 2)));
        refuses(IllegalArgumentException.class, "SLH_DSA_SHA2_256S needs a 96-byte seed", () -> Keys.pqFromSeed(Pq.Prim.SLH_DSA_SHA2_256S, fill(97, 2)));
        refuses(IllegalArgumentException.class, "SLH_DSA_SHA2_256S needs a 96-byte seed", () -> Keys.pqFromSeed(Pq.Prim.SLH_DSA_SHA2_256S, fill(48, 2)));
        refuses(IllegalArgumentException.class, "ML_DSA_65 needs a 32-byte seed", () -> Keys.pqFromSeed(Pq.Prim.ML_DSA_65, null));
        refuses(IllegalArgumentException.class, "ML_DSA_87 needs a 32-byte seed", () -> Keys.pqFromSeed(Pq.Prim.ML_DSA_87, fill(48, 2)));
        refuses(IllegalArgumentException.class, "cannot generate LESS_CAT1 keys in this SDK", () -> Keys.pqFromSeed(Pq.Prim.LESS_CAT1, fill(32, 2)));
    }

    @Test void pqGenerateIsRandom() {
        Keys.PqKey a = Keys.pqGenerate(Pq.Prim.ML_DSA_65), b = Keys.pqGenerate(Pq.Prim.ML_DSA_65);
        assertEquals(1952, a.pk.length);
        assertFalse(Arrays.equals(a.pk, b.pk));
        assertEquals(Pq.Prim.ML_DSA_65, a.prim);
    }

    @Test void pqLoadCopies() {
        Keys.PqKey k = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(32, 4));
        byte[] pk = k.pk.clone(), sk = k.sk.clone();
        Keys.PqKey l = Keys.pqLoad(Pq.Prim.ML_DSA_65, pk, sk);
        assertNotNull(l);
        assertEquals(Pq.Prim.ML_DSA_65, l.prim);
        assertNotSame(pk, l.pk);
        assertNotSame(sk, l.sk);
        pk[0] ^= 1;
        sk[0] ^= 1;
        assertArrayEquals(k.pk, l.pk);
        assertArrayEquals(k.sk, l.sk);
        assertEquals(k.pkB64u(), l.pkB64u());
        Keys.SuiteKey s = Keys.suite("ml-dsa-65", null, l);
        String[] sig = s.sign(MSG);
        assertTrue(Pq.verifyArtifactSignature("ml-dsa-65", null, k.pkB64u(), MSG, sig[0], sig[1]));
        refuses(IllegalArgumentException.class, "wrong public key length for ML_DSA_65", () -> Keys.pqLoad(Pq.Prim.ML_DSA_65, null, k.sk));
        refuses(IllegalArgumentException.class, "wrong public key length for ML_DSA_65", () -> Keys.pqLoad(Pq.Prim.ML_DSA_65, new byte[1951], k.sk));
        refuses(IllegalArgumentException.class, "wrong public key length for ML_DSA_87", () -> Keys.pqLoad(Pq.Prim.ML_DSA_87, k.pk, k.sk));
        Keys.PqKey less = Keys.pqLoad(Pq.Prim.LESS_CAT1, new byte[LessNative.PUBLIC_KEY_BYTES], new byte[1]);
        refuses(IllegalArgumentException.class, "cannot sign with LESS_CAT1 in this SDK", () -> less.sign(MSG));
    }

    @Test void everySuiteSignsWhatTheVerifierAccepts() {
        Keys.EdKey ed = Keys.edFromSeed(fill(32, 5));
        Keys.PqKey m65 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(32, 6)), m87 = Keys.pqFromSeed(Pq.Prim.ML_DSA_87, fill(32, 7));
        Keys.PqKey s128 = Keys.pqFromSeed(Pq.Prim.SLH_DSA_SHA2_128F, fill(48, 8)), s256 = Keys.pqFromSeed(Pq.Prim.SLH_DSA_SHA2_256S, fill(96, 9));
        Object[][] rows = {
            {"ed25519", ed, null}, {"ml-dsa-65", null, m65}, {"ml-dsa-87", null, m87}, {"hybrid-ed25519-ml-dsa-65", ed, m65},
            {"hybrid-nested-ed25519-ml-dsa-65", ed, m65}, {"hybrid-ed25519-ml-dsa-87", ed, m87}, {"slh-dsa-sha2-128f", null, s128},
            {"hybrid-ed25519-slh-dsa-sha2-256s", ed, s256},
        };
        for (Object[] r : rows) {
            String alg = (String) r[0];
            Keys.EdKey e = (Keys.EdKey) r[1];
            Keys.PqKey q = (Keys.PqKey) r[2];
            Keys.SuiteKey k = alg.equals("ed25519") ? Keys.ed25519(e) : Keys.suite(alg, e, q);
            String[] sig = k.sign(MSG);
            assertEquals(2, sig.length, alg);
            assertEquals(alg.startsWith("hybrid"), sig[1] != null, alg);
            assertEquals(q == null ? null : q.pkB64u(), k.pqPk(), alg);
            assertEquals(e == null ? null : e.id(), k.id(), alg);
            assertEquals(alg, k.alg);
            assertTrue(Pq.verifyArtifactSignature(alg, e == null ? null : e.id(), k.pqPk(), MSG, sig[0], sig[1]), alg);
            assertFalse(Pq.verifyArtifactSignature(alg, e == null ? null : e.id(), k.pqPk(), "other".getBytes(StandardCharsets.UTF_8), sig[0], sig[1]), alg);
        }
    }

    @Test void suiteRefusals() {
        Keys.EdKey ed = Keys.edFromSeed(fill(32, 5));
        Keys.PqKey m65 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(32, 6)), m87 = Keys.pqFromSeed(Pq.Prim.ML_DSA_87, fill(32, 7));
        refuses(IllegalArgumentException.class, "unknown signature alg 'bogus'", () -> Keys.suite("bogus", ed, null));
        refuses(IllegalArgumentException.class, "unsupported_suite: fn-dsa-512", () -> Keys.suite("fn-dsa-512", ed, null));
        refuses(IllegalArgumentException.class, "'ed25519' requires an Ed25519 key", () -> Keys.ed25519(null));
        refuses(IllegalArgumentException.class, "'hybrid-ed25519-ml-dsa-65' requires an Ed25519 key", () -> Keys.suite("hybrid-ed25519-ml-dsa-65", null, m65));
        refuses(IllegalArgumentException.class, "'ml-dsa-65' requires a ML_DSA_65 key", () -> Keys.suite("ml-dsa-65", ed, null));
        refuses(IllegalArgumentException.class, "'hybrid-ed25519-ml-dsa-87' requires a ML_DSA_87 key", () -> Keys.suite("hybrid-ed25519-ml-dsa-87", ed, null));
        refuses(IllegalArgumentException.class, "'ml-dsa-65' needs a ML_DSA_65 key, got ML_DSA_87", () -> Keys.suite("ml-dsa-65", null, m87));
        Keys.PqKey less = Keys.pqLoad(Pq.Prim.LESS_CAT1, new byte[LessNative.PUBLIC_KEY_BYTES], new byte[1]);
        if (LessNative.available()) {
            refuses(IllegalArgumentException.class, "unsupported_suite: less-cat1", () -> Keys.suite("less-cat1", null, less));
            refuses(IllegalArgumentException.class, "unsupported_suite: hybrid-ed25519-less-cat1", () -> Keys.suite("hybrid-ed25519-less-cat1", ed, less));
        } else {
            refuses(IllegalArgumentException.class, "unsupported_suite: less-cat1", () -> Keys.suite("less-cat1", null, less));
        }
        // a pure PQ suite may carry an Ed25519 key it does not use
        assertEquals(ed.id(), Keys.suite("ml-dsa-65", ed, m65).id());
        assertNull(Keys.suite("ml-dsa-65", null, m65).id());
    }

    @Test void pqPins() {
        Keys.EdKey ed = Keys.edFromSeed(fill(32, 5));
        Keys.PqKey m65 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(32, 6));
        assertEquals(Map.of(ed.id(), m65.pkB64u()), Keys.pqPin(Keys.suite("hybrid-ed25519-ml-dsa-65", ed, m65)));
        assertEquals(Map.of(ed.id(), m65.pkB64u()), Keys.pqPin(Keys.suite("ml-dsa-65", ed, m65)));
        assertEquals(Map.of(), Keys.pqPin(Keys.suite("ml-dsa-65", null, m65)));
        assertEquals(Map.of(), Keys.pqPin(Keys.ed25519(ed)));
        Map<String, Object> pin = Keys.pqPin(Keys.suite("hybrid-ed25519-ml-dsa-65", ed, m65));
        pin.put("x", "y"); // a fresh, mutable map
        assertEquals(2, pin.size());
    }
}
