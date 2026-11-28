package net.atlasauth.pca.goal;

/** A value that is not exactly a Goal IR value, or a malformed compiler tape. */
public final class IrError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public IrError(String m) { super("pca-goal: " + m); }
}
