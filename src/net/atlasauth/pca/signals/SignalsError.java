package net.atlasauth.pca.signals;

/** A misconfiguration or malformed input to the signals package. {@link #code} names the check (misconfigured, bad_snapshot, unmapped_subject). */
public final class SignalsError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public final String code;

    public SignalsError(String code, String message) {
        super(message);
        this.code = code;
    }
}
