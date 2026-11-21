package net.atlasauth.pca.aggsig;

/**
 * A public key whose proof of possession has been verified. The constructor is package-private and the class is final, so the
 * only producers are {@link Aggsig#registerKey} and {@link KeyRegistry#register}, and both run the proof-of-possession check first.
 */
public final class RegisteredKey {
    private final byte[] bytes;

    RegisteredKey(byte[] bytes) { this.bytes = bytes.clone(); }

    /** A copy of the 48-byte compressed G1 public key. */
    public byte[] bytes() { return bytes.clone(); }
}
