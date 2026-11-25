package net.atlasauth.pca.idjag;

/** The error of ID-JAG verification. {@link #code()}: the OIDC codes (config, invalid_token, signature, issuer, audience, expired, issued_at, not_before, nonce, azp, at_hash, c_hash, keys, claims) plus actor, scope and grant. */
public class IdJagVerificationError extends RuntimeException {
    private final String code;

    public IdJagVerificationError(String code, String message) { this(code, message, null); }

    public IdJagVerificationError(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String code() { return code; }
}
