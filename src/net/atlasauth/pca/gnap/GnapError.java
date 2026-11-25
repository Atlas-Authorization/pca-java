package net.atlasauth.pca.gnap;

/** Thrown by the issuance paths on a malformed request (the verify paths fail closed instead). */
public final class GnapError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public GnapError(String message) { super(message); }
}
