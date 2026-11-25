package net.atlasauth.pca;

/** The typed failure of every store-backed bond operation. {@link #code()} is stable; the message is for humans. */
public final class BondStoreError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public BondStoreError(String code, String message) { super(code + ": " + message); this.code = code; }

    public BondStoreError(String code, String message, Throwable cause) { super(code + ": " + message, cause); this.code = code; }

    public String code() { return code; }
}
