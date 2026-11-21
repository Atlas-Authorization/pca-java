package net.atlasauth.pca.ratchet;

/** A refused accumulator input. {@link #code}: invalid_value, length_mismatch or invalid_proof_shape. */
public final class AccumulatorError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public final String code;

    public AccumulatorError(String code, String message) {
        super(message);
        this.code = code;
    }
}
