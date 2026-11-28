package net.atlasauth.pca.connect;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A key ring held in process memory. Rotation: add the new key under a new id and make it active; records written under old ids still open
 * until you remove the old key. For production keys implement {@link KeyWrapper} over a KMS. {@link #destroy} overwrites the key bytes.
 */
public final class LocalKeyWrapper implements KeyWrapper {
    private static final SecureRandom RNG = new SecureRandom();
    private final Map<String, byte[]> keys = new HashMap<>();
    private String active;

    public LocalKeyWrapper(Map<String, byte[]> ring, String activeId) {
        for (Map.Entry<String, byte[]> e : ring.entrySet()) addKey(e.getKey(), e.getValue());
        if (!keys.containsKey(activeId)) throw new IllegalArgumentException("LocalKeyWrapper: the active key id is not in the key ring");
        this.active = activeId;
    }

    public synchronized void addKey(String id, byte[] key) {
        if (id.isEmpty()) throw new IllegalArgumentException("LocalKeyWrapper: key id must not be empty");
        if (key == null || key.length != 32) throw new IllegalArgumentException("LocalKeyWrapper: keys must be 32 bytes");
        keys.put(id, key.clone());
    }

    public synchronized void setActive(String id) {
        if (!keys.containsKey(id)) throw new IllegalArgumentException("LocalKeyWrapper: the active key id is not in the key ring");
        active = id;
    }

    public synchronized void removeKey(String id) {
        if (id.equals(active)) throw new IllegalArgumentException("LocalKeyWrapper: cannot remove the active key");
        byte[] k = keys.remove(id);
        if (k != null) Arrays.fill(k, (byte) 0);
    }

    public synchronized void destroy() {
        for (byte[] k : keys.values()) Arrays.fill(k, (byte) 0);
        keys.clear();
    }

    @Override public synchronized Wrapped wrap(byte[] dek, byte[] aad) {
        byte[] k = keys.get(active);
        if (k == null) throw new IllegalStateException("no active key");
        return new Wrapped(active, seal(k, aad, dek));
    }

    @Override public synchronized byte[] unwrap(String keyId, byte[] wrapped, byte[] aad) {
        byte[] k = keys.get(keyId);
        if (k == null) throw new IllegalStateException("unknown key id");
        return open(k, aad, wrapped);
    }

    /** AES-256-GCM: iv(12) || ciphertext || tag(16), the aad authenticated. */
    static byte[] seal(byte[] key, byte[] aad, byte[] plain) {
        try {
            byte[] iv = new byte[12];
            RNG.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            c.updateAAD(aad);
            byte[] ct = c.doFinal(plain);
            byte[] out = new byte[12 + ct.length];
            System.arraycopy(iv, 0, out, 0, 12);
            System.arraycopy(ct, 0, out, 12, ct.length);
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("seal failed", e);
        }
    }

    static byte[] open(byte[] key, byte[] aad, byte[] sealed) {
        if (sealed.length < 12 + 16) throw new IllegalArgumentException("short ciphertext");
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, sealed, 0, 12));
            c.updateAAD(aad);
            return c.doFinal(sealed, 12, sealed.length - 12);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("open failed", e);
        }
    }
}
