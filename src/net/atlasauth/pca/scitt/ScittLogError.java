package net.atlasauth.pca.scitt;

/** A transparency-log failure with a stable code: store_required, store_corrupt, append_contention, out_of_range, bad_statement. */
public final class ScittLogError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final String code;

    public ScittLogError(String code, String message) {
        super(message);
        this.code = code;
    }

    public String code() { return code; }
}
