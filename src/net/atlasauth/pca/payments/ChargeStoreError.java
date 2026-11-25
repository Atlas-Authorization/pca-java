package net.atlasauth.pca.payments;

/** The cumulative-budget store is missing, malformed or kept changing. */
public final class ChargeStoreError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public ChargeStoreError(String message) { super(message); }
}
