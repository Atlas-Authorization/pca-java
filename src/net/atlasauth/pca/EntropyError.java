package net.atlasauth.pca;

/** Typed entropy failure: only thrown where a caller demanded quantum entropy or the transport is unsafe. Codes: quantum_required, health_test_failed, insecure_transport. */
public final class EntropyError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public EntropyError(String code, String message) {
        super(message);
        this.code = code;
    }

    /** The stable failure code. */
    public String code() { return code; }
}
