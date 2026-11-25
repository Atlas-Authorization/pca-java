package net.atlasauth.pca;

/** The typed failure of every store-backed ledger operation. {@link #code()} is stable ({@code store_missing}, {@code rollback}, ...); the message is for humans. */
public final class LedgerStoreError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public LedgerStoreError(String code, String message) { super(code + ": " + message); this.code = code; }

    public LedgerStoreError(String code, String message, Throwable cause) { super(code + ": " + message, cause); this.code = code; }

    public String code() { return code; }
}
