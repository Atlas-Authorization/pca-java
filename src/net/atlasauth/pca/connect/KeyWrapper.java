package net.atlasauth.pca.connect;

/**
 * Wraps and unwraps the per-secret data keys of {@link EncryptedConnectionStore}: a local key ring ({@link LocalKeyWrapper}) or your KMS
 * behind the same two methods. {@code aad} binds the wrapped key to the exact connection and field, so a ciphertext copied to another
 * connection or field fails to open.
 */
public interface KeyWrapper {
    final class Wrapped {
        public final String keyId;
        public final byte[] wrapped;
        public Wrapped(String keyId, byte[] wrapped) { this.keyId = keyId; this.wrapped = wrapped; }
    }

    Wrapped wrap(byte[] dek, byte[] aad) throws Exception;

    byte[] unwrap(String keyId, byte[] wrapped, byte[] aad) throws Exception;
}
