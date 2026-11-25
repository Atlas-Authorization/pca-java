package net.atlasauth.pca;

/** A refusal of the durable state store. {@code code}: invalid | corrupt | rollback | key-mismatch | too-large | lock-timeout | lock-lost | link-unsupported. */
public final class DurableStateError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public DurableStateError(String code, String detail) {
        super(code + ": " + detail);
        this.code = code;
    }

    public String code() { return code; }
}
