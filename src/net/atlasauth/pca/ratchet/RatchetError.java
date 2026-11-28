package net.atlasauth.pca.ratchet;

/** A refused ratchet operation. {@link #code}: invalid_depth, invalid_seed, leaf_out_of_range or leaf_punctured. */
public final class RatchetError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public final String code;

    public RatchetError(String code, String message) {
        super(message);
        this.code = code;
    }
}
