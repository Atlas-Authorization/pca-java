package net.atlasauth.pca;

/** Public entry to the strict Ed25519 verify (non-canonical S / y and small-order or mixed-order keys and R refused) for the subpackage ports. */
public final class EdStrict {
    private EdStrict() {}

    /** Never throws; false on any malformed input. */
    public static boolean verify(byte[] publicKey, byte[] msg, byte[] sig) { return Pca.ed25519Strict(publicKey, msg, sig); }
}
