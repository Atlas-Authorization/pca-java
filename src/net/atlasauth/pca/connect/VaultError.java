package net.atlasauth.pca.connect;

import java.util.List;
import java.util.Map;

/** Base class for every typed refusal the outbound token vault raises. Branch on {@link #code()}; the codes are stable. */
public class VaultError extends RuntimeException {
    private final String code;
    private final String name;

    public VaultError(String code, String message) { this(code, "VaultError", message); }

    VaultError(String code, String name, String message) {
        super(message);
        this.code = code;
        this.name = name;
    }

    /** One of not_authorized, scope_exceeded, expired_no_refresh, refresh_failed, unknown_connection, store_error, unknown_action, unconfirmed_action, request_mismatch, bearer_release_disabled, proxy_failed. */
    public String code() { return code; }

    /** The reference's error class name (e.g. NotAuthorizedError). */
    public String errorName() { return name; }

    /** The PCActn is not a valid, provider-bound authorization for this connection. */
    public static final class NotAuthorizedError extends VaultError {
        /** The verifier's per-check verdict map, when the refusal came from PCActn verification (else null). */
        public final Map<String, Boolean> checks;
        public NotAuthorizedError(String message) { this(message, null); }
        public NotAuthorizedError(String message, Map<String, Boolean> checks) {
            super("not_authorized", "NotAuthorizedError", message);
            this.checks = checks;
        }
    }

    /** The requested scopes are not a subset of what the capability chain grants. */
    public static final class ScopeExceededError extends VaultError {
        public final String provider;
        public final List<String> requested, granted, missing;
        public ScopeExceededError(String provider, List<String> requested, List<String> granted, List<String> missing) {
            super("scope_exceeded", "ScopeExceededError",
                "requested scopes exceed the capability's grant for '" + provider + "': not granted [" + String.join(", ", missing) + "]");
            this.provider = provider;
            this.requested = requested;
            this.granted = granted;
            this.missing = missing;
        }
    }

    /** The access token is stale and there is no refresh token. */
    public static final class ExpiredNoRefreshError extends VaultError {
        public final String provider, connectionId;
        public ExpiredNoRefreshError(String provider, String connectionId) {
            super("expired_no_refresh", "ExpiredNoRefreshError", "connection '" + provider + "/" + connectionId + "' token is expired and has no refresh token");
            this.provider = provider;
            this.connectionId = connectionId;
        }
    }

    /** A refresh was attempted but the provider token endpoint call did not yield a usable token. */
    public static final class RefreshFailedError extends VaultError {
        public final String provider;
        /** HTTP status when the failure was a non-2xx response, else null. */
        public final Integer status;
        public RefreshFailedError(String provider, String detail) { this(provider, detail, null); }
        public RefreshFailedError(String provider, String detail, Integer status) {
            super("refresh_failed", "RefreshFailedError", "refresh for '" + provider + "' failed: " + detail);
            this.provider = provider;
            this.status = status;
        }
    }

    /** No stored connection for this agent + provider + connectionId. */
    public static final class UnknownConnectionError extends VaultError {
        public final String agentId, provider, connectionId;
        public UnknownConnectionError(String agentId, String provider, String connectionId) {
            super("unknown_connection", "UnknownConnectionError", "no connection for agent '" + agentId + "' provider '" + provider + "' id '" + connectionId + "'");
            this.agentId = agentId;
            this.provider = provider;
            this.connectionId = connectionId;
        }
    }

    /** The connection store or its encryption failed. The message never carries the underlying error text. */
    public static final class StoreError extends VaultError {
        public StoreError() { this("the connection store failed"); }
        public StoreError(String message) { super("store_error", "StoreError", message); }
    }

    /** The action definition for the PCActn's verb is unknown, so no scope can be derived. */
    public static final class UnknownActionError extends VaultError {
        public UnknownActionError(String verb) {
            super("unknown_action", "UnknownActionError", "no pinned action definition for verb '" + verb + "': refusing to release a credential");
        }
    }

    /** The action definition has no valid signed confirmation: unconfirmed means maximally dangerous. */
    public static final class UnconfirmedActionError extends VaultError {
        public UnconfirmedActionError(String verb) {
            super("unconfirmed_action", "UnconfirmedActionError", "the definition of '" + verb + "' has no valid signed confirmation: refusing to release a credential");
        }
    }

    /** The outbound request does not re-derive the signed params digest. */
    public static final class RequestMismatchError extends VaultError {
        public RequestMismatchError(String message) { super("request_mismatch", "RequestMismatchError", message); }
    }

    /** A bare bearer token was requested without the explicit insecure opt-in. */
    public static final class BearerReleaseDisabledError extends VaultError {
        public BearerReleaseDisabledError() {
            super("bearer_release_disabled", "BearerReleaseDisabledError",
                "this vault does not release bearer tokens to callers; use proxyCall(), or construct it with insecureBearerRelease: true (insecure: the caller can use the token for anything inside its scopes until it expires)");
        }
    }

    /** The proxied call failed after the action was spent. */
    public static final class ProxyFailedError extends VaultError {
        public ProxyFailedError(String message) { super("proxy_failed", "ProxyFailedError", message); }
    }
}
