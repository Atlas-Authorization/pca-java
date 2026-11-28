package net.atlasauth.pca.oauth;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Pattern;
import net.atlasauth.pca.A2a;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.PcaGrant;

/**
 * OAuth 2.1 / MCP-authorization interop bridge for Proof-Carrying Authority: RFC 9728 protected resource metadata, the MCP 401
 * challenge (RFC 6750 + RFC 7235), RFC 8707 resource indicators, the {@code pca_grant} authorization-details type (RFC 9396) and the
 * OAuth scopes derived from a confirmed action. Pure: no I/O. Documents are {@code Map<String,Object>} (member names as on the wire),
 * options use the reference's camelCase names. A refusal throws IllegalArgumentException.
 */
public final class Oauth {
    private Oauth() {}

    public static final String WELL_KNOWN_OAUTH_PRM = "/.well-known/oauth-protected-resource";
    public static final String WELL_KNOWN_PCA_PATH = "/.well-known/pca-configuration";
    private static final String DEFAULT_PCA_HINT = "send PCA-Action: <base64url PCActn> or JSON body {pcactn}";
    private static final int PCA_NEED_MAX_ENCODED = 2048;

    // ---- RFC 9728 ----

    /** RFC 9728 section 1.2: the reason {@code resource} is not an https URL without a fragment; null when valid. */
    public static String resourceIdentifierProblem(Object resource) {
        if (!(resource instanceof String) || ((String) resource).isEmpty()) return "resource identifier must be a non-empty string";
        String r = (String) resource;
        WhatwgUrl u = WhatwgUrl.parse(r);
        if (u == null) return "resource identifier is not an absolute URL";
        if (!u.protocol.equals("https:")) return "resource identifier must use the https scheme";
        if (r.indexOf('#') >= 0) return "resource identifier must not contain a fragment";
        return null;
    }

    /** RFC 9728 section 3.1: the well-known path for a resource identifier. Throws on an invalid identifier. */
    public static String prmPathForResource(String resource) {
        String problem = resourceIdentifierProblem(resource);
        if (problem != null) throw new IllegalArgumentException("prmPathForResource: " + problem);
        WhatwgUrl u = WhatwgUrl.parse(resource);
        String path = u.pathname.equals("/") ? "" : u.pathname;
        return WELL_KNOWN_OAUTH_PRM + path + u.search;
    }

    /** The absolute metadata URL for a resource identifier. */
    public static String prmUrlForResource(String resource) {
        WhatwgUrl u = WhatwgUrl.parse(resource);
        if (u == null) throw new IllegalArgumentException("prmUrlForResource: not an absolute URL");
        return u.origin() + prmPathForResource(resource);
    }

    private static Object orDefault(Map<String, Object> opts, String k, Object dflt) {
        Object v = opts.get(k);
        return v == null ? dflt : v;
    }

    private static List<Object> strs(String... xs) {
        List<Object> l = new ArrayList<>();
        for (String x : xs) l.add(x);
        return l;
    }

    /** The PCA discovery document the PRM embeds (audience, suites, versions, header, checks, endpoints, roots, metadata). */
    private static Map<String, Object> buildDiscoveryDocument(Map<String, Object> o) {
        Object aud = o.get("audience");
        if (!(aud instanceof String) || ((String) aud).isEmpty()) throw new IllegalArgumentException("buildDiscoveryDocument: audience is required");
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("audience", aud);
        d.put("pca_versions", orDefault(o, "pcaVersions", new ArrayList<Object>(List.of(JsVal.n(2)))));
        d.put("signature_suites", orDefault(o, "signatureSuites", strs("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65")));
        d.put("action_header", orDefault(o, "actionHeader", "PCA-Action"));
        d.put("required_checks", orDefault(o, "requiredChecks",
                strs("counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound")));
        if (JsVal.truthy(o.get("endpoints"))) d.put("endpoints", o.get("endpoints"));
        if (JsVal.truthy(o.get("trustedRoots"))) d.put("trusted_roots", o.get("trustedRoots"));
        if (JsVal.truthy(o.get("metadata"))) d.put("metadata", o.get("metadata"));
        return d;
    }

    /** RFC 9728: the Protected Resource Metadata document with the PCA extension block. Throws on an empty or (strict) invalid resource. */
    public static Map<String, Object> protectedResourceMetadata(Map<String, Object> opts) {
        Object res = opts.get("resource");
        if (!(res instanceof String) || ((String) res).isEmpty()) throw new IllegalArgumentException("protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required");
        String resource = (String) res;
        if (!Boolean.FALSE.equals(opts.get("strict"))) {
            String problem = resourceIdentifierProblem(resource);
            if (problem != null) throw new IllegalArgumentException("protectedResourceMetadata: " + problem);
        }
        Map<String, Object> dopts = new LinkedHashMap<>();
        dopts.put("audience", resource);
        for (String k : new String[] {"signatureSuites", "pcaVersions", "actionHeader", "requiredChecks", "endpoints", "trustedRoots", "metadata"}) dopts.put(k, opts.get(k));
        Map<String, Object> discovery = buildDiscoveryDocument(dopts);
        Object endpoint = opts.get("pcaConfigurationEndpoint");
        if (endpoint == null) {
            int q = resource.indexOf('?');
            String base = q >= 0 ? resource.substring(0, q) : resource;
            int end = base.length();
            while (end > 0 && base.charAt(end - 1) == '/') end--;
            endpoint = base.substring(0, end) + WELL_KNOWN_PCA_PATH;
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("resource", resource);
        doc.put("bearer_methods_supported", orDefault(opts, "bearerMethodsSupported", strs("header")));
        doc.put("pca_action_header", discovery.get("action_header"));
        doc.put("pca_signature_suites", JsVal.copy(discovery.get("signature_suites")));
        doc.put("pca_versions", JsVal.copy(discovery.get("pca_versions")));
        doc.put("pca_configuration_endpoint", endpoint);
        doc.put("pca", discovery);
        if (JsVal.truthy(opts.get("authorizationServers"))) doc.put("authorization_servers", JsVal.copy(opts.get("authorizationServers")));
        if (JsVal.truthy(opts.get("resourceDocumentation"))) doc.put("resource_documentation", opts.get("resourceDocumentation"));
        if (JsVal.truthy(opts.get("scopesSupported"))) doc.put("scopes_supported", JsVal.copy(opts.get("scopesSupported")));
        if (JsVal.truthy(opts.get("resourceName"))) doc.put("resource_name", opts.get("resourceName"));
        if (JsVal.truthy(opts.get("resourceSigningAlgValuesSupported"))) doc.put("resource_signing_alg_values_supported", JsVal.copy(opts.get("resourceSigningAlgValuesSupported")));
        if (JsVal.truthy(opts.get("authorizationDetailsTypesSupported"))) doc.put("authorization_details_types_supported", JsVal.copy(opts.get("authorizationDetailsTypesSupported")));
        return doc;
    }

    public static Map<String, Object> parseProtectedResourceMetadata(Object value) { return parseProtectedResourceMetadata(value, null); }

    /** Validate and narrow an untrusted value into a protected-resource-metadata document. Throws on anything malformed. */
    public static Map<String, Object> parseProtectedResourceMetadata(Object value, Map<String, Object> parseOpts) {
        final String p = "parseProtectedResourceMetadata: ";
        Map<String, Object> po = parseOpts == null ? new LinkedHashMap<>() : parseOpts;
        if (!JsVal.isObjectLike(value)) throw new IllegalArgumentException(p + "not an object");
        Object resource = JsVal.get(value, "resource");
        if (!(resource instanceof String) || ((String) resource).isEmpty()) throw new IllegalArgumentException(p + "missing `resource`");
        Object bearer = JsVal.get(value, "bearer_methods_supported");
        if (!JsVal.allStrings(bearer)) throw new IllegalArgumentException(p + "bearer_methods_supported must be a string[]");
        Object header = JsVal.get(value, "pca_action_header");
        if (!(header instanceof String) || ((String) header).isEmpty()) throw new IllegalArgumentException(p + "missing pca_action_header");
        Object suites = JsVal.get(value, "pca_signature_suites");
        if (!JsVal.allStrings(suites)) throw new IllegalArgumentException(p + "pca_signature_suites must be a string[]");
        Object versions = JsVal.get(value, "pca_versions");
        if (!JsVal.allNumbers(versions)) throw new IllegalArgumentException(p + "pca_versions must be a number[]");
        Object pca = JsVal.get(value, "pca");
        if (!JsVal.isObjectLike(pca)) throw new IllegalArgumentException(p + "missing embedded `pca` discovery document");
        Object audience = JsVal.get(pca, "audience");
        if (!(audience instanceof String) || ((String) audience).isEmpty()) throw new IllegalArgumentException(p + "embedded pca.audience is required");
        Object expected = po.get("expectedResource");
        if (expected != null) {
            if (!resource.equals(expected)) throw new IllegalArgumentException(p + "`resource` does not match the expected resource identifier");
            if (!audience.equals(expected)) throw new IllegalArgumentException(p + "embedded pca.audience does not match the expected resource identifier");
        }
        if (!Boolean.FALSE.equals(po.get("strict"))) {
            if (expected == null) throw new IllegalArgumentException(p + "expectedResource is required (RFC 9728 section 3.3); pass strict: false to skip");
            String problem = resourceIdentifierProblem(resource);
            if (problem != null) throw new IllegalArgumentException(p + problem);
            for (Object m : JsVal.list(bearer)) {
                if (!"header".equals(m) && !"body".equals(m) && !"query".equals(m)) throw new IllegalArgumentException(p + "bearer_methods_supported has a value outside header/body/query");
            }
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("resource", resource);
        doc.put("bearer_methods_supported", bearer);
        doc.put("pca_action_header", header);
        doc.put("pca_signature_suites", suites);
        doc.put("pca_versions", versions);
        doc.put("pca", pca);
        if (JsVal.get(value, "pca_configuration_endpoint") instanceof String) doc.put("pca_configuration_endpoint", JsVal.get(value, "pca_configuration_endpoint"));
        if (JsVal.allStrings(JsVal.get(value, "authorization_servers"))) doc.put("authorization_servers", JsVal.get(value, "authorization_servers"));
        if (JsVal.get(value, "resource_documentation") instanceof String) doc.put("resource_documentation", JsVal.get(value, "resource_documentation"));
        if (JsVal.allStrings(JsVal.get(value, "scopes_supported"))) doc.put("scopes_supported", JsVal.get(value, "scopes_supported"));
        if (JsVal.get(value, "resource_name") instanceof String) doc.put("resource_name", JsVal.get(value, "resource_name"));
        if (JsVal.allStrings(JsVal.get(value, "resource_signing_alg_values_supported"))) doc.put("resource_signing_alg_values_supported", JsVal.get(value, "resource_signing_alg_values_supported"));
        return doc;
    }

    // ---- RFC 6750 / MCP challenge ----

    /** A value for a quoted auth-param: a quote, backslash or control character would allow header injection. */
    private static String quotedParam(String v) {
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '"' || c == '\\' || c <= 0x1f || c == 0x7f) throw new IllegalArgumentException("pca-oauth: WWW-Authenticate parameter value may not contain a quote or newline");
        }
        return v;
    }

    private static String str(Object o) {
        if (o instanceof String) return (String) o;
        throw new IllegalArgumentException("pca-oauth: option must be a string");
    }

    /** Encode a need as the unpadded base64url of its strict-canonical JSON. Throws on a malformed need or an over-long value. */
    public static String encodePcaNeed(Object need) {
        String code = A2a.needError(need);
        if (code != null) throw new IllegalArgumentException("encodePcaNeed: malformed need (" + code + ")");
        String enc = Keys.b64u(Json.canonicalizeStrict(need).getBytes(StandardCharsets.UTF_8));
        if (enc.length() > PCA_NEED_MAX_ENCODED) throw new IllegalArgumentException("encodePcaNeed: the need is too large for a header");
        return enc;
    }

    public static String wwwAuthenticate(String prmUrl) { return wwwAuthenticate(prmUrl, null); }

    /** The WWW-Authenticate value of an MCP 401: Bearer resource_metadata (+ error, scope, pca_need) and by default a PCA challenge. */
    public static String wwwAuthenticate(String prmUrl, Map<String, Object> opts) {
        if (prmUrl == null || prmUrl.isEmpty()) throw new IllegalArgumentException("wwwAuthenticate: prmUrl is required");
        Map<String, Object> o = opts == null ? new LinkedHashMap<>() : opts;
        List<String> bearer = new ArrayList<>();
        bearer.add("resource_metadata=\"" + quotedParam(prmUrl) + "\"");
        if (JsVal.truthy(o.get("error"))) bearer.add("error=\"" + quotedParam(str(o.get("error"))) + "\"");
        if (JsVal.truthy(o.get("errorDescription"))) bearer.add("error_description=\"" + quotedParam(str(o.get("errorDescription"))) + "\"");
        if (JsVal.truthy(o.get("scope"))) bearer.add("scope=\"" + quotedParam(str(o.get("scope"))) + "\"");
        if (JsVal.truthy(o.get("pcaNeed"))) bearer.add("pca_need=\"" + quotedParam(encodePcaNeed(o.get("pcaNeed"))) + "\"");
        List<String> challenges = new ArrayList<>();
        challenges.add("Bearer " + String.join(", ", bearer));
        boolean includePca = JsVal.truthy(orDefault(o, "includePca", Boolean.TRUE));
        if (JsVal.truthy(o.get("pcaChallenge"))) {
            String c = str(o.get("pcaChallenge"));
            for (int i = 0; i < c.length(); i++) {
                char ch = c.charAt(i);
                if ((ch <= 0x08) || (ch >= 0x0a && ch <= 0x1f) || ch == 0x7f) throw new IllegalArgumentException("pca-oauth: pcaChallenge may not contain control characters or newlines");
            }
            challenges.add(c);
        } else if (includePca) {
            String realm = str(orDefault(o, "realm", "pca"));
            Object hint = orDefault(o, "hint", DEFAULT_PCA_HINT);
            String pca = "PCA realm=\"" + quotedParam(realm) + "\"";
            if (JsVal.truthy(hint)) pca += ", hint=\"" + quotedParam(str(hint)) + "\"";
            challenges.add(pca);
        }
        return String.join(", ", challenges);
    }

    // ---- RFC 8707 ----

    private static Map<String, Object> ok(String matched) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", Boolean.TRUE);
        m.put("matched", matched);
        return m;
    }

    private static Map<String, Object> fail(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", Boolean.FALSE);
        m.put("reason", reason);
        return m;
    }

    private static List<Object> valuesOf(Object v) {
        if (v instanceof List) return JsVal.list(v);
        List<Object> l = new ArrayList<>();
        l.add(v);
        return l;
    }

    /** RFC 8707: does an incoming resource indicator (one value or several) include this RS's audience? */
    public static Map<String, Object> checkResourceIndicator(Object resourceParam, String expectedAudience) {
        if (expectedAudience == null || expectedAudience.isEmpty()) throw new IllegalArgumentException("checkResourceIndicator: expectedAudience is required");
        if (resourceParam == null) return fail("no resource indicator presented");
        List<Object> values = valuesOf(resourceParam);
        if (values.isEmpty()) return fail("empty resource indicator");
        for (Object r : values) {
            if (!(r instanceof String) || ((String) r).isEmpty()) continue;
            if (r.equals(expectedAudience)) return ok((String) r);
        }
        return fail("resource indicator " + JsVal.stringify(values) + " does not match audience " + JsVal.stringify(expectedAudience));
    }

    /** A token's aud must be, or contain, exactly this resource identifier (exact string equality; fail closed). */
    public static Map<String, Object> checkTokenAudience(Object aud, String expectedResource) {
        if (expectedResource == null || expectedResource.isEmpty()) throw new IllegalArgumentException("checkTokenAudience: expectedResource is required");
        if (aud == null) return fail("token has no audience");
        List<Object> values = valuesOf(aud);
        if (values.isEmpty()) return fail("token has an empty audience");
        for (Object a : values) if (expectedResource.equals(a)) return ok(expectedResource);
        return fail("token audience " + JsVal.stringify(aud) + " does not include resource " + JsVal.stringify(expectedResource));
    }

    // ---- glue ----

    /** The path and body to serve the PRM document: {path, body, rfcPath}. */
    public static Map<String, Object> oauthDiscoveryHandler(Map<String, Object> opts) {
        Map<String, Object> body = protectedResourceMetadata(opts);
        String resource = (String) opts.get("resource");
        String path = resourceIdentifierProblem(resource) == null ? prmPathForResource(resource) : WELL_KNOWN_OAUTH_PRM;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("path", path);
        out.put("body", body);
        out.put("rfcPath", path);
        return out;
    }

    public static Map<String, Object> mcpUnauthorized(String prmUrl) { return mcpUnauthorized(prmUrl, null); }

    /** The complete MCP/OAuth 401: status, the WWW-Authenticate header and a small JSON body. */
    public static Map<String, Object> mcpUnauthorized(String prmUrl, Map<String, Object> opts) {
        Map<String, Object> o = opts == null ? new LinkedHashMap<>() : opts;
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", orDefault(o, "error", "invalid_request"));
        body.put("resource_metadata", prmUrl);
        if (JsVal.truthy(o.get("errorDescription"))) body.put("error_description", o.get("errorDescription"));
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("WWW-Authenticate", wwwAuthenticate(prmUrl, o));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", JsVal.n(401));
        out.put("headers", headers);
        out.put("body", body);
        return out;
    }

    /** Upgrade a deny result's challenge so it also carries the MCP resource_metadata pointer; other fields are kept. */
    public static Map<String, Object> upgradeUnauthorizedChallenge(Map<String, Object> result, String prmUrl, Map<String, Object> opts) {
        Object existing = result.get("wwwAuthenticate");
        Map<String, Object> o = new LinkedHashMap<>();
        if (opts != null) o.putAll(opts);
        if (JsVal.truthy(existing)) o.put("pcaChallenge", existing);
        String header = wwwAuthenticate(prmUrl, o);
        Map<String, Object> out = new LinkedHashMap<>(result);
        out.put("wwwAuthenticate", header);
        return out;
    }

    // ---- pca_grant (RFC 9396) ----

    private static List<String> idList(Object o) {
        List<String> ids = new ArrayList<>();
        for (Object x : JsVal.list(o)) {
            if (!(x instanceof String)) throw new IllegalArgumentException("chainIds must be strings");
            ids.add((String) x);
        }
        return ids;
    }

    /** A validated pca_grant detail for the chain. Throws on anything the profile would refuse. */
    public static Map<String, Object> buildPcaGrantDetail(Map<String, Object> o) {
        List<String> ids = idList(o.get("chainIds"));
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("type", PcaGrant.TYPE);
        d.put("chain_digest", PcaGrant.chainDigest(ids));
        d.put("chain_len", JsVal.n(ids.size()));
        if (o.get("chainRef") != null) d.put("chain_ref", o.get("chainRef"));
        if (o.get("bundleRevision") != null) d.put("bundle_revision", o.get("bundleRevision"));
        if (o.get("locations") != null) d.put("locations", JsVal.copy(o.get("locations")));
        String code = PcaGrant.validate(d);
        if (code != null) throw new IllegalArgumentException("buildPcaGrantDetail: refused (" + code + ")");
        return d;
    }

    /** The form-encoded value of the authorization_details request parameter (encodeURIComponent of the JSON). */
    public static String pcaGrantRequestParam(List<Object> details) {
        String json = JsVal.stringify(details);
        if (Json.hasLoneSurrogate(json)) throw new IllegalArgumentException("pcaGrantRequestParam: URI malformed");
        StringBuilder sb = new StringBuilder();
        for (byte b : Json.utf8(json)) {
            int c = b & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "-_.!~*'()".indexOf(c) >= 0) sb.append((char) c);
            else sb.append('%').append(String.format("%02X", c));
        }
        return sb.toString();
    }

    /**
     * Gate an OAuth access token carrying pca_grant details: allow only for well-formed details naming a prefix of the presented chain
     * and this resource, with a verified per-action proof. Returns {allow:true, detail} or {allow:false, status, error, code}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> authorizePcaGrantToken(Map<String, Object> o) {
        PcaGrant.Result parsed = PcaGrant.parse(o.get("authorizationDetails"));
        if (parsed.code != null) return denied(401, "invalid_token", parsed.code);
        Object res = o.get("resource");
        PcaGrant.Result r = PcaGrant.check(parsed.details, res instanceof String ? (String) res : "\u0000no-resource", idList(o.get("chainIds")), Boolean.TRUE.equals(o.get("proofVerified")));
        if (r.code == null) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("allow", Boolean.TRUE);
            m.put("detail", parsed.details.get(r.index));
            return m;
        }
        boolean loc = r.code.equals("wrong_location");
        return denied(loc ? 403 : 401, loc ? "insufficient_scope" : "invalid_token", r.code);
    }

    private static Map<String, Object> denied(int status, String error, String code) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("allow", Boolean.FALSE);
        m.put("status", JsVal.n(status));
        m.put("error", error);
        m.put("code", code);
        return m;
    }

    // ---- scopes derived from the confirmed action ----

    private static final Pattern SCOPE_TOKEN = Pattern.compile("^[\\x21\\x23-\\x5b\\x5d-\\x7e]+$");

    /** The refusal code, or null with {@code out[0]} set to the sorted scopes. */
    private static String deriveActionScopes(Object action, String provider, Object granted, List<String>[] out) {
        if (action == null || !JsVal.isObjectLike(action)) return "unknown_action";
        if (!Boolean.TRUE.equals(JsVal.get(action, "confirmed"))) return "unconfirmed";
        Object up = JsVal.get(action, "upstream");
        if (provider != null && !provider.equals(JsVal.get(up, "provider"))) return "provider_mismatch";
        Object min = JsVal.get(up, "scopes_min");
        if (!(min instanceof List) || ((List<?>) min).isEmpty()) return "no_scopes";
        for (Object s : (List<?>) min) {
            if (!(s instanceof String) || ((String) s).length() > 256 || !SCOPE_TOKEN.matcher((String) s).matches()) return "bad_scope";
        }
        TreeSet<String> sorted = new TreeSet<>();
        for (Object s : (List<?>) min) sorted.add((String) s);
        if (granted != null) {
            List<?> g = (List<?>) granted;
            for (String s : sorted) if (!g.contains(s)) return "exceeds_grant";
        }
        out[0] = new ArrayList<>(sorted);
        return null;
    }

    /** The scope (and RFC 8707 resource) an OAuth client should request for one action; an unconfirmed or mismatched action yields a refusal. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> oauthScopeForAction(Object action, Map<String, Object> o) {
        List<String>[] out = new List[1];
        Object provider = o.get("provider");
        String code = deriveActionScopes(action, provider instanceof String ? (String) provider : null, o.get("granted"), out);
        Map<String, Object> m = new LinkedHashMap<>();
        if (code != null) {
            m.put("ok", Boolean.FALSE);
            m.put("code", code);
            return m;
        }
        m.put("ok", Boolean.TRUE);
        m.put("scope", String.join(" ", out[0]));
        m.put("scopes", new ArrayList<Object>(out[0]));
        if (o.get("resource") != null) m.put("resource", o.get("resource"));
        return m;
    }
}
