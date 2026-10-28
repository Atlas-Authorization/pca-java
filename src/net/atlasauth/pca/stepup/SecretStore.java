package net.atlasauth.pca.stepup;

/** Where the 32-byte Ed25519 seed of the {@link PrincipalDeviceKey} is persisted. Implementations throw unchecked exceptions on failure. */
public interface SecretStore {
    /** The stored seed, or null when none. */
    byte[] load();

    void save(byte[] secret);

    void delete();
}
