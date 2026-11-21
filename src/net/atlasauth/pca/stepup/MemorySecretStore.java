package net.atlasauth.pca.stepup;

/** In-memory {@link SecretStore}, for tests and demos only. */
public final class MemorySecretStore implements SecretStore {
    private volatile byte[] value;

    @Override public byte[] load() { byte[] v = value; return v == null ? null : v.clone(); }
    @Override public void save(byte[] secret) { value = secret.clone(); }
    @Override public void delete() { value = null; }
}
