package net.atlasauth.pca;

/** The typed failure of the aggregate budget ledger: {@code not_durable}, {@code scope_unbound}, {@code store_missing}, {@code store_corrupt}, {@code invalid}, {@code conflict_exhausted}. */
public final class BudgetLedgerError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public BudgetLedgerError(String code, String message) { super(code + ": " + message); this.code = code; }

    public String code() { return code; }
}
