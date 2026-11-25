package net.atlasauth.pca.oidc;

/** The error of ID-token verification. {@link #code()} is one of: config, invalid_token, signature, issuer, audience, expired, issued_at, not_before, nonce, azp, at_hash, c_hash, keys, claims. */
public class OidcVerificationError extends RuntimeException {
    private final String code;

    public OidcVerificationError(String code, String message) { this(code, message, null); }

    public OidcVerificationError(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String code() { return code; }
}
