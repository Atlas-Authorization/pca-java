package net.atlasauth.pca.txntokens;

/** Thrown when a verifier is configured without a required security component. {@link #code()}: replay_store_required. */
public class TxnTokenError extends RuntimeException {
    private final String code;

    public TxnTokenError(String code, String message) {
        super(message);
        this.code = code;
    }

    public String code() { return code; }
}
