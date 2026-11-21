package net.atlasauth.pca.payments;

/** Why a mandate was refused before any decision: verified_grant_required, mandate_grant_mismatch or mandate_terms_mismatch. */
public final class MandateGrantError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public final String code;

    public MandateGrantError(String code, String message) {
        super(message);
        this.code = code;
    }
}
