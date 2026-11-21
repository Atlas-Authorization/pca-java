package net.atlasauth.pca.connectors;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.connect.JsText;
import net.atlasauth.pca.connect.UrlBits;
import net.atlasauth.pca.oauth.WhatwgUrl;

/**
 * The authorization-request side of a connector: turn a declarative {@link ProviderManifest} into a correct OAuth 2.0 authorize URL (with PKCE
 * when the provider wants it), and describe how the resulting access token is presented on an outbound API call. Options arrive as a parsed-JSON
 * map with the reference's camelCase member names; a null member counts as unset.
 */
public final class Authorize {
    private Authorize() {}

    private static final Pattern PKCE_VERIFIER = Pattern.compile("[A-Za-z0-9._~-]{43,128}");
    private static final Pattern VAR = Pattern.compile("\\{(\\w+)\\}");
    private static final Pattern DNS_LABEL = Pattern.compile("[A-Za-z0-9][A-Za-z0-9-]{0,62}");
    private static final int MIN_STATE_CHARS = 16;
    private static final SecureRandom RNG = new SecureRandom();

    /** The PKCE values used for an authorize request; keep {@code verifier} to complete the code exchange. */
    public static final class PkceResult {
        public final String verifier, challenge, method;
        PkceResult(String verifier, String challenge, String method) { this.verifier = verifier; this.challenge = challenge; this.method = method; }
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("verifier", verifier);
            m.put("challenge", challenge);
            m.put("method", method);
            return m;
        }
    }

    /** A built authorize URL plus the state and (if used) PKCE values the caller must retain for the exchange. */
    public static final class AuthorizeUrl {
        public final String url, state;
        /** Null when PKCE is not in effect. */
        public final PkceResult pkce;
        AuthorizeUrl(String url, String state, PkceResult pkce) { this.url = url; this.state = state; this.pkce = pkce; }
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("url", url);
            m.put("state", state);
            if (pkce != null) m.put("pkce", pkce.toMap());
            return m;
        }
    }

    private static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    /** 32 bytes of CSPRNG entropy, base64url (unpadded). */
    static String randomToken() {
        byte[] b = new byte[32];
        RNG.nextBytes(b);
        return b64u(b);
    }

    /** The S256 code challenge for a verifier: base64url(SHA-256(ASCII(verifier))), unpadded (RFC 7636 section 4.2); "plain" returns the verifier. */
    public static String pkceChallenge(String verifier, String method) {
        if ("plain".equals(method)) return verifier;
        try {
            return b64u(MessageDigest.getInstance("SHA-256").digest(Json.utf8(verifier)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String pkceChallenge(String verifier) { return pkceChallenge(verifier, "S256"); }

    /** Substitute {var} placeholders in {@code url}. Throws {@link ConnectorError} when a used var is not supplied, or is not a single DNS label. */
    public static String substituteVars(String url, Map<String, Object> vars) {
        Matcher m = VAR.matcher(url);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String name = m.group(1);
            if (vars == null || !vars.containsKey(name)) throw new ConnectorError("missing URL variable '{" + name + "}'");
            Object v = vars.get(name);
            // A variable is a DNS label (a shop, an account). Anything else could move the request to another host or path:
            // `evil.com/x?` in `https://{shop}.myshopify.com/...` sends the authorization code to evil.com.
            if (!(v instanceof String) || !DNS_LABEL.matcher((String) v).matches()) {
                throw new ConnectorError("URL variable '{" + name + "}' must be a single DNS label (letters, digits and hyphens)");
            }
            m.appendReplacement(sb, Matcher.quoteReplacement((String) v));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static String str(Object v) { return v instanceof String ? (String) v : net.atlasauth.pca.revoke.JsVal.str(v); }

    private static String encodeForm(List<String[]> params) {
        StringBuilder sb = new StringBuilder();
        for (String[] kv : params) {
            if (sb.length() > 0) sb.append('&');
            sb.append(JsText.encodeURIComponent(kv[0])).append('=').append(JsText.encodeURIComponent(kv[1]));
        }
        return sb.toString();
    }

    public static AuthorizeUrl buildAuthorizeUrl(String providerId, Map<String, Object> options) { return buildAuthorizeUrl(providerId, options, null); }

    /**
     * Build the OAuth 2.0 authorization-request URL for {@code providerId}. Always emits response_type=code, client_id, redirect_uri, scope, and
     * state; adds code_challenge + code_challenge_method when PKCE is in effect, and merges the manifest's authParams then the caller's extraParams.
     * Scopes are joined with the manifest's scopeSeparator (default space). {@code registry} null means the default registry. Options:
     * clientId, redirectUri, scopes, state, pkce (true | false | {verifier, method}), vars, extraParams, allowUnlistedScopes, allowPlainPkce.
     */
    public static AuthorizeUrl buildAuthorizeUrl(String providerId, Map<String, Object> options, ProviderRegistry registry) {
        ProviderRegistry reg = registry != null ? registry : ProviderRegistry.defaultRegistry();
        ProviderManifest manifest = reg.require(providerId);

        Object scopes = options.get("scopes") != null ? options.get("scopes") : new ArrayList<Object>(manifest.defaultScopes);
        String separator = manifest.scopeSeparator != null ? manifest.scopeSeparator : " ";
        Object state = options.get("state") != null ? options.get("state") : randomToken();

        Object clientId = options.get("clientId");
        if (!(clientId instanceof String) || ((String) clientId).isEmpty()) throw new ConnectorError("buildAuthorizeUrl: clientId must be a non-empty string");
        checkRedirectUri(options.get("redirectUri"));
        if (!(state instanceof String) || ((String) state).length() < MIN_STATE_CHARS) {
            throw new ConnectorError("buildAuthorizeUrl: state must be at least " + MIN_STATE_CHARS + " characters (omit it to get a random one)");
        }
        checkScopes(manifest, scopes, Boolean.TRUE.equals(options.get("allowUnlistedScopes")));
        List<Object[]> extra = entriesOf(options.get("extraParams"));
        for (Object[] kv : extra) if (Manifest.RESERVED_AUTHORIZE_PARAMS.contains(kv[0])) throw new ConnectorError("buildAuthorizeUrl: extraParams may not set '" + kv[0] + "'");

        List<String> scopeList = new ArrayList<>();
        for (Object s : (List<?>) scopes) scopeList.add((String) s);
        List<String[]> params = new ArrayList<>();
        params.add(new String[] {"response_type", "code"});
        params.add(new String[] {"client_id", (String) clientId});
        params.add(new String[] {"redirect_uri", str(options.get("redirectUri"))});
        if (!scopeList.isEmpty()) params.add(new String[] {"scope", String.join(separator, scopeList)});
        params.add(new String[] {"state", (String) state});

        // PKCE: on when explicitly requested, when a verifier object is passed, or (unless disabled) when the manifest declares it.
        Object pk = options.get("pkce");
        boolean wantPkce = Boolean.FALSE.equals(pk) ? false : pk != null ? true : Boolean.TRUE.equals(manifest.pkce);
        PkceResult pkce = null;
        if (wantPkce) {
            Object verifier = pk instanceof Map ? ((Map<?, ?>) pk).get("verifier") : randomToken();
            Object method = pk instanceof Map ? (((Map<?, ?>) pk).get("method") != null ? ((Map<?, ?>) pk).get("method") : "S256") : "S256";
            if (!(verifier instanceof String) || !PKCE_VERIFIER.matcher((String) verifier).matches()) {
                throw new ConnectorError("buildAuthorizeUrl: the PKCE verifier must be 43 to 128 unreserved characters (RFC 7636)");
            }
            if (!"S256".equals(method) && !("plain".equals(method) && Boolean.TRUE.equals(options.get("allowPlainPkce")))) {
                throw new ConnectorError("buildAuthorizeUrl: PKCE method must be 'S256' (pass allowPlainPkce to use 'plain')");
            }
            String challenge = pkceChallenge((String) verifier, (String) method);
            params.add(new String[] {"code_challenge", challenge});
            params.add(new String[] {"code_challenge_method", (String) method});
            pkce = new PkceResult((String) verifier, challenge, (String) method);
        }

        if (manifest.authParams != null) for (Map.Entry<String, String> e : manifest.authParams.entrySet()) params.add(new String[] {e.getKey(), e.getValue()});
        for (Object[] kv : extra) params.add(new String[] {(String) kv[0], str(kv[1])});

        Object varsO = options.get("vars");
        String base = substituteVars(manifest.authorizeUrl, varsO instanceof Map ? castVars(varsO) : null);
        String url = base + (base.contains("?") ? "&" : "?") + encodeForm(params);
        return new AuthorizeUrl(url, (String) state, pkce);
    }

    /** {@code Object.entries(v)} of a parsed-JSON value: an object's members, an array's indexed items, a string's characters; nothing for a scalar. */
    private static List<Object[]> entriesOf(Object v) {
        List<Object[]> out = new ArrayList<>();
        if (v instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) out.add(new Object[] {e.getKey(), e.getValue()});
        } else if (v instanceof List) {
            List<?> l = (List<?>) v;
            for (int i = 0; i < l.size(); i++) out.add(new Object[] {Integer.toString(i), l.get(i)});
        } else if (v instanceof String) {
            String t = (String) v;
            for (int i = 0; i < t.length(); i++) out.add(new Object[] {Integer.toString(i), String.valueOf(t.charAt(i))});
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castVars(Object o) { return (Map<String, Object>) o; }

    private static void checkRedirectUri(Object uriO) {
        String uri = str(uriO);
        WhatwgUrl u = WhatwgUrl.parse(uri);
        if (u == null) throw new ConnectorError("buildAuthorizeUrl: redirectUri must be an absolute URL");
        if (UrlBits.hasFragment(uri)) throw new ConnectorError("buildAuthorizeUrl: redirectUri must not have a fragment (RFC 6749 3.1.2)");
        if (UrlBits.hasCredentials(uri)) throw new ConnectorError("buildAuthorizeUrl: redirectUri must not carry credentials");
        boolean local = u.host.equals("localhost") || u.host.equals("127.0.0.1") || u.host.equals("[::1]");
        if (!u.protocol.equals("https:") && !(u.protocol.equals("http:") && local)) throw new ConnectorError("buildAuthorizeUrl: redirectUri must be https (http only for localhost)");
    }

    /** Every scope must be one token the manifest lists: a scope containing the separator would smuggle in another one. */
    private static void checkScopes(ProviderManifest manifest, Object scopes, boolean allowUnlisted) {
        if (!(scopes instanceof List)) throw new ConnectorError("buildAuthorizeUrl: scopes must be a list");
        String sep = manifest.scopeSeparator != null ? manifest.scopeSeparator : " ";
        Set<String> seen = new HashSet<>();
        for (Object o : (List<?>) scopes) {
            if (!(o instanceof String) || ((String) o).isEmpty() || JsText.hasSpaceOrComma((String) o) || ((String) o).contains(sep)) {
                throw new ConnectorError("buildAuthorizeUrl: every scope must be a non-empty string without whitespace, commas or the separator");
            }
            String s = (String) o;
            if (!seen.add(s)) throw new ConnectorError("buildAuthorizeUrl: scope '" + s + "' is listed twice");
            if (!allowUnlisted && !manifest.scopesAvailable.isEmpty() && !manifest.scopesAvailable.contains(s)) {
                throw new ConnectorError("buildAuthorizeUrl: scope '" + s + "' is not offered by provider '" + manifest.id + "'");
            }
        }
    }

    /** Describe how {@code accessToken} is attached to a provider API call, per the manifest's tokenPlacement: {@code {kind, name, value}}. */
    public static Map<String, Object> applyAccessToken(ProviderManifest manifest, Object accessToken) {
        // A control character or space in a token would end the header value (response splitting) or add a header.
        if (!(accessToken instanceof String) || ((String) accessToken).isEmpty() || hasNonPrintable((String) accessToken)) {
            throw new ConnectorError("applyAccessToken: the access token must be a non-empty string of printable ASCII without spaces");
        }
        String token = (String) accessToken;
        Map<String, Object> out = new LinkedHashMap<>();
        switch (manifest.tokenPlacement) {
            case "bearer":
                out.put("kind", "header");
                out.put("name", "Authorization");
                out.put("value", "Bearer " + token);
                return out;
            case "header":
                if (manifest.headerName == null) throw new ConnectorError("manifest '" + manifest.id + "' is header-placed but has no headerName");
                out.put("kind", "header");
                out.put("name", manifest.headerName);
                out.put("value", token);
                return out;
            case "query":
                if (manifest.queryParam == null) throw new ConnectorError("manifest '" + manifest.id + "' is query-placed but has no queryParam");
                out.put("kind", "query");
                out.put("name", manifest.queryParam);
                out.put("value", token);
                return out;
            default:
                throw new ConnectorError("manifest '" + manifest.id + "' has an unknown tokenPlacement");
        }
    }

    private static boolean hasNonPrintable(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x21 || c > 0x7e) return true;
        }
        return false;
    }
}
