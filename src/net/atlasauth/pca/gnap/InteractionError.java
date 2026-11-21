package net.atlasauth.pca.gnap;

/** A GNAP interaction failure carrying its stable code (invalid_interaction, unknown_interaction, too_many_attempts, invalid_request, expired, wrong_state, unsupported_hash). */
public final class InteractionError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public InteractionError(String code, String message) {
        super(message);
        this.code = code;
    }

    public String code() { return code; }
}
