package net.atlasauth.pca.stepup;

import java.security.SecureRandom;
import java.util.Base64;

import net.atlasauth.pca.Pca;

import org.bouncycastle.math.ec.rfc8032.Ed25519;

/**
 * The principal's Ed25519 device key, held in a {@link SecretStore}.
 *
 * <p>The PCA principal key MUST be Ed25519, which most platform keystores do not offer, so this is a SOFTWARE key: the 32-byte
 * seed lives in the store you give it. Back it with the platform keystore and gate approvals behind user presence.
 */
public final class PrincipalDeviceKey {
    private final SecretStore store;

    public PrincipalDeviceKey(SecretStore store) {
        if (store == null) throw new IllegalArgumentException("store");
        this.store = store;
    }

    private static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    /** True when a key is stored. */
    public boolean exists() {
        try {
            return store.load() != null;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Generate a fresh key (replacing any existing one). Returns the public key (base64url) to register as the grant's principal. */
    public String generate() {
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        store.save(seed);
        return publicOf(seed);
    }

    /** Import an existing principal secret (a base64url 32-byte seed). It MUST match the grant's principal. Returns the public key. */
    public String importSecret(String secretB64u) {
        byte[] raw = Pca.decodeB64uStrict(secretB64u, 32);
        if (raw == null) throw new StepUpException.InvalidSecret("The secret must be a base64url 32-byte Ed25519 seed.");
        store.save(raw);
        return publicOf(raw);
    }

    /** The secret (base64url seed) for backup or migration. Treat it like a password. */
    public String exportSecret() { return b64(seed()); }

    /** The public key (base64url), as registered on the grant. */
    public String publicKey() { return publicOf(seed()); }

    /** Ed25519-sign {@code message}; returns the signature as base64url. */
    public String sign(byte[] message) {
        byte[] sig = new byte[Ed25519.SIGNATURE_SIZE];
        Ed25519.sign(seed(), 0, message, 0, message.length, sig, 0);
        return b64(sig);
    }

    /** Remove the key from storage. */
    public void delete() { store.delete(); }

    private byte[] seed() {
        byte[] seed = store.load();
        if (seed == null) throw new StepUpException.NoDeviceKey();
        if (seed.length != 32) throw new StepUpException.InvalidSecret("The stored secret is not a 32-byte seed.");
        return seed;
    }

    private static String publicOf(byte[] seed) {
        byte[] pk = new byte[Ed25519.PUBLIC_KEY_SIZE];
        Ed25519.generatePublicKey(seed, 0, pk, 0);
        return b64(pk);
    }
}
