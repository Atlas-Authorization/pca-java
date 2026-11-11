package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Key zeroisation: a destroyed key holds no secret bytes and signs nothing; its public key is kept. */
class KeyDestroyTest {
    @Test void anEd25519KeyIsZeroedAndRefusesToSign() {
        Keys.EdKey k = Keys.edGenerate();
        String id = k.id();
        assertFalse(k.isDestroyed());
        assertEquals(64, k.sign(new byte[] {1}).length);
        k.destroy();
        k.destroy(); // idempotent
        assertTrue(k.isDestroyed());
        assertArrayEquals(new byte[32], k.seed);
        assertEquals(id, k.id());
        assertEquals("the key was destroyed", assertThrows(IllegalStateException.class, () -> k.sign(new byte[] {1})).getMessage());
    }

    @Test void aPostQuantumKeyIsZeroedAndRefusesToSign() {
        Keys.PqKey k = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, new byte[32]);
        assertFalse(k.isDestroyed());
        assertTrue(k.sign(new byte[] {1}).length > 0);
        int n = k.sk.length;
        k.destroy();
        assertTrue(k.isDestroyed());
        assertArrayEquals(new byte[n], k.sk);
        assertEquals("the key was destroyed", assertThrows(IllegalStateException.class, () -> k.sign(new byte[] {1})).getMessage());
    }
}
