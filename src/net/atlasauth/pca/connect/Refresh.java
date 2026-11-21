package net.atlasauth.pca.connect;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.connect.VaultError.RefreshFailedError;
import net.atlasauth.pca.oauth.JsVal;

/** The token-refresh side of the outbound vault: one refresh-token grant against a provider's token endpoint. */
public final class Refresh {
    private Refresh() {}

    /** Per-provider OAuth token-endpoint configuration used to refresh an access token. */
    public static final class ProviderConfig {
        public String tokenEndpoint;
        public String clientId;
        /** Null for public clients / PKCE. */
        public String clientSecret;
        /** Null = unset. When true a narrowed {@code scope} is sent on refresh. */
        public Boolean supportsScopeNarrowing;
        /** Extra static form parameters (null = none). */
        public Map<String, String> extraParams;

        public ProviderConfig() {}
        public ProviderConfig(String tokenEndpoint, String clientId) { this.tokenEndpoint = tokenEndpoint; this.clientId = clientId; }

        /** The config as the reference's plain object. */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("tokenEndpoint", tokenEndpoint);
            m.put("clientId", clientId);
            if (clientSecret != null) m.put("clientSecret", clientSecret);
            if (supportsScopeNarrowing != null) m.put("supportsScopeNarrowing", supportsScopeNarrowing);
            if (extraParams != null) m.put("extraParams", new LinkedHashMap<String, Object>(extraParams));
            return m;
        }
    }

    /** A minimal structural view of an HTTP response. */
    public interface VaultHttpResponse {
        boolean ok();
        int status();
        /** The parsed JSON body (Map, List, String, Boolean, Json.Num, null); throws when it does not parse. */
        Object json() throws Exception;
        String text() throws Exception;
    }

    public static final class VaultHttpRequest {
        public final String method;
        public final Map<String, String> headers;
        public final String body;
        public VaultHttpRequest(String method, Map<String, String> headers, String body) { this.method = method; this.headers = headers; this.body = body; }
    }

    /** The injectable transport. In production wrap java.net.http; in tests pass a scripted one. */
    @FunctionalInterface
    public interface VaultFetch {
        VaultHttpResponse call(String url, VaultHttpRequest init) throws Exception;
    }

    /** The fields {@link #refreshConnection} hands back for the vault to apply. */
    public static final class Refreshed {
        public String accessToken;
        public String refreshToken;
        public double expiresAt;
        public List<String> scopes;
    }

    /** What {@link #refreshConnection} needs. */
    public static final class Args {
        public StoredConnection connection;
        /** Null when the provider has no configuration. */
        public ProviderConfig config;
        public String refreshToken;
        public List<String> requested = new ArrayList<>();
        /** Null when no transport is configured. */
        public VaultFetch fetch;
        public double now;
        public double defaultTokenLifetimeMs;
    }

    /** The fields of an OAuth token-endpoint success response the vault consumes. */
    private static final class TokenResponse {
        String accessToken;
        Double expiresInSecs;
        String refreshToken;
        List<String> scopes;
    }

    private static TokenResponse parseTokenResponse(Object body, String provider) {
        if (!(body instanceof Map)) throw new RefreshFailedError(provider, "token endpoint returned a non-object body");
        Map<?, ?> m = (Map<?, ?>) body;
        Object at = m.get("access_token");
        if (!(at instanceof String) || ((String) at).isEmpty()) throw new RefreshFailedError(provider, "token endpoint response has no access_token");
        TokenResponse out = new TokenResponse();
        out.accessToken = (String) at;
        Double ei = JsVal.num(m.get("expires_in"));
        if (ei != null && !ei.isNaN() && !ei.isInfinite() && ei > 0) out.expiresInSecs = ei;
        Object rt = m.get("refresh_token");
        if (rt instanceof String && !((String) rt).isEmpty()) out.refreshToken = (String) rt;
        Object scope = m.get("scope");
        if (scope instanceof String && !JsText.trim((String) scope).isEmpty()) out.scopes = JsText.splitRuns(JsText.trim((String) scope), false);
        return out;
    }

    /**
     * Epoch-ms expiry claimed by a JWT access token (decodeJwt semantics: three dot-separated parts, a non-empty payload that is a JSON
     * object); null for an opaque token or a non-finite / non-number {@code exp}.
     */
    public static Double jwtExpiryMs(String accessToken) {
        try {
            String[] parts = accessToken.split("\\.", -1);
            if (parts.length != 3 || parts[1].isEmpty()) return null;
            byte[] raw = Base64.getUrlDecoder().decode(parts[1]);
            Object payload = Json.parseLenient(new String(raw, StandardCharsets.UTF_8));
            if (!(payload instanceof Map)) return null;
            Double exp = JsVal.num(((Map<?, ?>) payload).get("exp"));
            return exp != null && !exp.isNaN() && !exp.isInfinite() ? exp * 1000 : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Refresh {@code connection}'s access token at its provider's token endpoint with the stored refresh token. When the provider supports
     * scope narrowing the requested scopes are sent so the new token is no wider. Returns the fields to apply; throws
     * {@link RefreshFailedError} on any transport or parse failure.
     */
    public static Refreshed refreshConnection(Args args) {
        String provider = args.connection.provider;
        List<String> secrets = new ArrayList<>();
        secrets.add(args.refreshToken);
        secrets.add(args.connection.accessToken);
        if (args.config != null) {
            secrets.add(args.config.clientSecret);
            if (args.config.extraParams != null) secrets.addAll(args.config.extraParams.values());
        }
        if (args.config == null) throw new RefreshFailedError(provider, "no provider token-endpoint config");
        if (args.fetch == null) throw new RefreshFailedError(provider, "no fetch transport configured");

        Map<String, String> params = new LinkedHashMap<>();
        params.put("grant_type", "refresh_token");
        params.put("refresh_token", args.refreshToken);
        params.put("client_id", args.config.clientId);
        if (args.config.clientSecret != null) params.put("client_secret", args.config.clientSecret);
        if (args.config.extraParams != null) params.putAll(args.config.extraParams);
        boolean narrow = Boolean.TRUE.equals(args.config.supportsScopeNarrowing) && !args.requested.isEmpty();
        if (narrow) params.put("scope", String.join(" ", args.requested));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("content-type", "application/x-www-form-urlencoded");
        headers.put("accept", "application/json");
        VaultHttpResponse res;
        try {
            res = args.fetch.call(args.config.tokenEndpoint, new VaultHttpRequest("POST", headers, JsText.formEncode(params)));
        } catch (Exception e) {
            throw new RefreshFailedError(provider, "transport error: " + JsText.redact(JsText.errText(e), secrets));
        }
        if (!res.ok()) {
            String detail;
            try {
                String t = res.text();
                detail = JsText.redact(t.length() > 256 ? t.substring(0, 256) : t, secrets);
            } catch (Exception e) {
                detail = "<unreadable body>";
            }
            throw new RefreshFailedError(provider, "token endpoint " + res.status() + ": " + detail, res.status());
        }
        Object json;
        try {
            json = res.json();
        } catch (Exception e) {
            // the parser's message quotes the start of the body, which may hold a token: say nothing of it
            throw new RefreshFailedError(provider, "unparseable JSON body");
        }
        TokenResponse parsed = parseTokenResponse(json, provider);

        Refreshed out = new Refreshed();
        out.accessToken = parsed.accessToken;
        if (parsed.expiresInSecs != null) out.expiresAt = args.now + parsed.expiresInSecs * 1000;
        else {
            Double jwt = jwtExpiryMs(parsed.accessToken);
            out.expiresAt = jwt != null ? jwt : args.now + args.defaultTokenLifetimeMs;
        }
        out.scopes = parsed.scopes != null ? parsed.scopes : narrow ? new ArrayList<>(args.requested) : new ArrayList<>(args.connection.scopes);
        out.refreshToken = parsed.refreshToken != null ? parsed.refreshToken : args.refreshToken;
        return out;
    }
}
