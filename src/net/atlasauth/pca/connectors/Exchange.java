package net.atlasauth.pca.connectors;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.connect.JsText;
import net.atlasauth.pca.connect.Refresh;
import net.atlasauth.pca.connect.Refresh.ProviderConfig;
import net.atlasauth.pca.connect.Refresh.VaultFetch;
import net.atlasauth.pca.connect.Refresh.VaultHttpRequest;
import net.atlasauth.pca.connect.Refresh.VaultHttpResponse;
import net.atlasauth.pca.connect.StoredConnection;
import net.atlasauth.pca.connect.TokenVault;
import net.atlasauth.pca.oauth.JsVal;

/**
 * The token side of a connector: exchange an authorization code (or a refresh token) at a provider's token endpoint and FEED the connection vault,
 * so every stored connection is bound to a PCA capability. A connection minted here is unusable until a verified Proof-Carrying Action proves
 * authority over the provider and that the requested scopes are inside what the capability grants. The vault's own auto-refresh is wired from the
 * same manifests via {@link #manifestToProviderConfig} / {@link #buildVaultProviders}. Calls are synchronous.
 */
public final class Exchange {
    private Exchange() {}

    /** Default access-token lifetime assumed when the provider returns no expires_in. */
    private static final double DEFAULT_TOKEN_LIFETIME_MS = 3_600_000;

    /** How a minted connection is stored and bound to a PCA capability in the vault. */
    public static final class ConnectionBinding {
        public TokenVault vault;
        /** b64u public key of the agent: the capability chain's LEAF holder this connection belongs to. */
        public String agentId;
        /** Null = the vault's default connection id. */
        public String connectionId;
        /** b64u public key the capability chain must be rooted at. */
        public String principal;
        /** Scopes the capability must cover (null = the requested scopes: least privilege). */
        public List<String> authorityScopes;
        /** When set, the PCActn's signed aud must equal it. */
        public String audience;
    }

    public static final class ExchangeCodeArgs {
        public String providerId, clientId;
        /** Null for a public client. */
        public String clientSecret;
        /** The authorization code returned to the redirect URI. */
        public String code;
        public String redirectUri;
        /** The PKCE code_verifier used for the authorize request (required when the provider uses PKCE). */
        public String codeVerifier;
        /** Scopes requested (null = the manifest's defaultScopes). */
        public List<String> scopes;
        public VaultFetch fetch;
        public ConnectionBinding bind;
        /** Clock, epoch ms (null = now). */
        public Double now;
        /** Null = the default registry. */
        public ProviderRegistry registry;
        public Map<String, Object> vars;
        public Map<String, String> extraParams;
    }

    public static final class RefreshArgs {
        public String providerId, clientId, clientSecret;
        /** The refresh token to present (the vault does not expose stored refresh tokens without a PCActn). */
        public String refreshToken;
        public List<String> scopes;
        public VaultFetch fetch;
        public ConnectionBinding bind;
        public Double now;
        public ProviderRegistry registry;
        public Map<String, Object> vars;
        public Map<String, String> extraParams;
    }

    /** Per-provider client credentials used to derive a vault {@link ProviderConfig}. */
    public static final class ProviderCredentials {
        public String clientId;
        public String clientSecret;
        /** {var} substitutions for the refresh token endpoint. */
        public Map<String, Object> vars;
        public ProviderCredentials() {}
        public ProviderCredentials(String clientId, String clientSecret, Map<String, Object> vars) { this.clientId = clientId; this.clientSecret = clientSecret; this.vars = vars; }
    }

    /** The fields of a token-endpoint success response this package consumes. */
    private static final class ParsedToken {
        String accessToken;
        Double expiresInSecs;
        String refreshToken;
        List<String> scopes;
    }

    private static void checkExtraParams(Map<String, String> extra, String what) {
        if (extra != null) for (String k : extra.keySet()) if (Manifest.RESERVED_TOKEN_PARAMS.contains(k)) throw new ConnectorError(what + ": extraParams may not set '" + k + "'");
    }

    /** Standard base64 (padded) of clientId:clientSecret, for HTTP Basic client authentication (RFC 6749 section 2.3.1). */
    static String basicAuthHeader(String clientId, String clientSecret) {
        return "Basic " + Base64.getEncoder().encodeToString(Json.utf8((clientId + ":" + clientSecret)));
    }

    /** Parse an OAuth token-endpoint JSON body. Fails closed: a missing or empty access_token is a hard error. */
    private static ParsedToken parseTokenResponse(Object body, String provider) {
        if (!(body instanceof Map)) throw new ConnectorError("[" + provider + "] token endpoint returned a non-object body");
        Map<?, ?> m = (Map<?, ?>) body;
        Object at = m.get("access_token");
        if (!(at instanceof String) || ((String) at).isEmpty()) throw new ConnectorError("[" + provider + "] token endpoint response has no access_token");
        ParsedToken out = new ParsedToken();
        out.accessToken = (String) at;
        Double ei = JsVal.num(m.get("expires_in"));
        if (ei != null && !ei.isNaN() && !ei.isInfinite() && ei > 0) out.expiresInSecs = ei;
        Object rt = m.get("refresh_token");
        if (rt instanceof String && !((String) rt).isEmpty()) out.refreshToken = (String) rt;
        Object scope = m.get("scope");
        if (scope instanceof String && !JsText.trim((String) scope).isEmpty()) out.scopes = JsText.splitRuns(JsText.trim((String) scope), true);
        return out;
    }

    /** POST a form to a token endpoint via the injectable transport and parse the response (fail-closed). */
    private static ParsedToken postToken(ProviderManifest manifest, String tokenEndpoint, Map<String, String> params, String clientSecret, VaultFetch fetchImpl) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("content-type", "application/x-www-form-urlencoded");
        headers.put("accept", "application/json");
        Map<String, String> body = new LinkedHashMap<>(params);
        if ("basic".equals(manifest.clientAuth)) {
            // Client credentials move to the Authorization header; they must not also appear in the body.
            if (clientSecret == null) throw new ConnectorError("[" + manifest.id + "] clientAuth 'basic' requires a clientSecret");
            String clientId = body.get("client_id");
            if (clientId == null) throw new ConnectorError("[" + manifest.id + "] missing client_id for basic auth");
            headers.put("authorization", basicAuthHeader(clientId, clientSecret));
            body.remove("client_id");
            body.remove("client_secret");
        }

        if (fetchImpl == null) throw new ConnectorError("[" + manifest.id + "] no fetch transport configured");
        List<String> secrets = Arrays.asList(clientSecret, params.get("code"), params.get("code_verifier"), params.get("refresh_token"), headers.get("authorization"));
        VaultHttpResponse res;
        try {
            res = fetchImpl.call(tokenEndpoint, new VaultHttpRequest("POST", headers, JsText.formEncode(body)));
        } catch (Exception e) {
            throw new ConnectorError("[" + manifest.id + "] token transport error: " + JsText.redact(JsText.errText(e), secrets));
        }
        if (!res.ok()) {
            String detail;
            try {
                String t = res.text();
                detail = JsText.redact(t.length() > 256 ? t.substring(0, 256) : t, secrets);
            } catch (Exception e) {
                detail = "<unreadable body>";
            }
            throw new ConnectorError("[" + manifest.id + "] token endpoint " + res.status() + ": " + detail);
        }
        Object json;
        try {
            json = res.json();
        } catch (Exception e) {
            // the parser's message quotes the start of the body, which may hold a token
            throw new ConnectorError("[" + manifest.id + "] unparseable token JSON");
        }
        return parseTokenResponse(json, manifest.id);
    }

    /** Store the token result in the vault, bound to the PCA capability authority. */
    private static StoredConnection storeConnection(ProviderManifest manifest, ParsedToken parsed, List<String> requested, ConnectionBinding bind, double now, String priorRefreshToken) {
        double expiresAt = parsed.expiresInSecs != null ? now + parsed.expiresInSecs * 1000 : now + DEFAULT_TOKEN_LIFETIME_MS;
        // Scopes the stored token actually carries: the provider's echo wins; else the requested set.
        List<String> granted = parsed.scopes != null ? parsed.scopes : requested;
        // Token rotation: keep the prior refresh token unless the provider issued a new one.
        String refreshToken = parsed.refreshToken != null ? parsed.refreshToken : priorRefreshToken;
        TokenVault.PutConnectionArgs a = new TokenVault.PutConnectionArgs();
        a.agentId = bind.agentId;
        a.provider = manifest.id;
        a.accessToken = parsed.accessToken;
        a.expiresAt = expiresAt;
        a.scopes = granted;
        a.principal = bind.principal;
        a.authorityScopes = bind.authorityScopes != null ? bind.authorityScopes : requested;
        a.audience = bind.audience;
        a.connectionId = bind.connectionId;
        a.refreshToken = refreshToken;
        return bind.vault.putConnection(a);
    }

    private static String orUndefined(String s) { return s == null ? "undefined" : s; }

    /**
     * Exchange an authorization code for tokens and store a capability-bound connection in the vault. The requested scopes become the connection's
     * least-privilege authority; the connection is unusable until a verified PCActn proves a capability covering them.
     */
    public static StoredConnection exchangeCode(ExchangeCodeArgs args) {
        ProviderRegistry registry = args.registry != null ? args.registry : ProviderRegistry.defaultRegistry();
        ProviderManifest manifest = registry.require(args.providerId);
        double now = args.now != null ? args.now : (double) System.currentTimeMillis();
        List<String> requested = args.scopes != null ? args.scopes : manifest.defaultScopes;

        if (args.code == null || args.code.isEmpty()) throw new ConnectorError("[" + manifest.id + "] an authorization code is required");
        checkExtraParams(args.extraParams, "[" + manifest.id + "] exchangeCode");
        if (Boolean.TRUE.equals(manifest.pkce) && args.codeVerifier == null) {
            throw new ConnectorError("[" + manifest.id + "] provider uses PKCE; a codeVerifier is required to exchange the code");
        }

        Map<String, String> params = new LinkedHashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("code", args.code);
        params.put("redirect_uri", orUndefined(args.redirectUri));
        params.put("client_id", orUndefined(args.clientId));
        if (args.clientSecret != null) params.put("client_secret", args.clientSecret);
        if (args.codeVerifier != null) params.put("code_verifier", args.codeVerifier);
        if (args.extraParams != null) params.putAll(args.extraParams);
        String tokenEndpoint = Authorize.substituteVars(manifest.tokenUrl, args.vars);
        ParsedToken parsed = postToken(manifest, tokenEndpoint, params, args.clientSecret, args.fetch);
        return storeConnection(manifest, parsed, requested, args.bind, now, null);
    }

    /**
     * Refresh an access token at the provider's refresh endpoint and re-store the capability-bound connection. Throws when the manifest declares
     * {@code refresh.mode == "none"}. Scope narrowing is sent only when the manifest opts in. The authority binding is preserved from {@code bind}.
     */
    public static StoredConnection refresh(RefreshArgs args) {
        ProviderRegistry registry = args.registry != null ? args.registry : ProviderRegistry.defaultRegistry();
        ProviderManifest manifest = registry.require(args.providerId);
        if ("none".equals(manifest.refresh.mode)) throw new ConnectorError("[" + manifest.id + "] provider does not support token refresh");
        double now = args.now != null ? args.now : (double) System.currentTimeMillis();
        List<String> requested = args.scopes != null ? args.scopes : manifest.defaultScopes;
        if (args.refreshToken == null || args.refreshToken.isEmpty()) throw new ConnectorError("[" + manifest.id + "] a refresh token is required");
        checkExtraParams(args.extraParams, "[" + manifest.id + "] refresh");

        Map<String, String> params = new LinkedHashMap<>();
        params.put("grant_type", "refresh_token");
        params.put("refresh_token", args.refreshToken);
        params.put("client_id", orUndefined(args.clientId));
        if (args.clientSecret != null) params.put("client_secret", args.clientSecret);
        if (manifest.refresh.extraParams != null) params.putAll(manifest.refresh.extraParams);
        if (args.extraParams != null) params.putAll(args.extraParams);
        if (Boolean.TRUE.equals(manifest.refresh.supportsScopeNarrowing) && !requested.isEmpty()) {
            params.put("scope", String.join(manifest.scopeSeparator != null ? manifest.scopeSeparator : " ", requested));
        }
        String tokenEndpoint = Authorize.substituteVars(manifest.refresh.tokenEndpoint != null ? manifest.refresh.tokenEndpoint : manifest.tokenUrl, args.vars);
        ParsedToken parsed = postToken(manifest, tokenEndpoint, params, args.clientSecret, args.fetch);
        return storeConnection(manifest, parsed, requested, args.bind, now, args.refreshToken);
    }

    /**
     * Derive the connection vault's {@link ProviderConfig} (used for its OWN auto-refresh) from a manifest + credentials: the manifest's token
     * endpoint, scope-narrowing flag and extra params flow straight into the vault. Throws when the manifest does not support refresh.
     */
    public static ProviderConfig manifestToProviderConfig(ProviderManifest manifest, ProviderCredentials creds) {
        if ("none".equals(manifest.refresh.mode)) {
            throw new ConnectorError("[" + manifest.id + "] provider does not support token refresh; no ProviderConfig");
        }
        ProviderConfig config = new ProviderConfig(
            Authorize.substituteVars(manifest.refresh.tokenEndpoint != null ? manifest.refresh.tokenEndpoint : manifest.tokenUrl, creds.vars), orUndefined(creds.clientId));
        if (creds.clientSecret != null) config.clientSecret = creds.clientSecret;
        if (manifest.refresh.supportsScopeNarrowing != null) config.supportsScopeNarrowing = manifest.refresh.supportsScopeNarrowing;
        if (manifest.refresh.extraParams != null) config.extraParams = new LinkedHashMap<>(manifest.refresh.extraParams);
        return config;
    }

    /**
     * Build the vault's {@code providers} map (provider id to {@link ProviderConfig}) from a set of configured providers, skipping any whose manifest
     * cannot refresh. {@code registry} null means the default registry.
     */
    public static Map<String, ProviderConfig> buildVaultProviders(Map<String, ProviderCredentials> credsById, ProviderRegistry registry) {
        ProviderRegistry reg = registry != null ? registry : ProviderRegistry.defaultRegistry();
        Map<String, ProviderConfig> out = new LinkedHashMap<>();
        for (Map.Entry<String, ProviderCredentials> e : credsById.entrySet()) {
            ProviderManifest manifest = reg.require(e.getKey());
            if ("none".equals(manifest.refresh.mode)) continue;
            out.put(e.getKey(), manifestToProviderConfig(manifest, e.getValue()));
        }
        return out;
    }
}
