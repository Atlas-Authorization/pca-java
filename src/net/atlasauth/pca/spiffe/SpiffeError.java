package net.atlasauth.pca.spiffe;

/** A SPIFFE validation / parse failure with a stable {@link #code()} (the reference's error codes, e.g. {@code malformed_spiffe_id}). */
public final class SpiffeError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public SpiffeError(String code, String message) {
        super(message);
        this.code = code;
    }

    /** The stable error code. */
    public String code() { return code; }
}
