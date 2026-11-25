package net.atlasauth.pca.oidc;

/** The error of any OIDC discovery failure (network, non-2xx, bad JSON, issuer mismatch). */
public class OidcDiscoveryError extends RuntimeException {
    public OidcDiscoveryError(String message) { super(message); }

    public OidcDiscoveryError(String message, Throwable cause) { super(message, cause); }
}
