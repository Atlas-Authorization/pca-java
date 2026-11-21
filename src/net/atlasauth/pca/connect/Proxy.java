package net.atlasauth.pca.connect;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.ConnectBridge;
import net.atlasauth.pca.Escalation;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.connect.VaultError.RequestMismatchError;
import net.atlasauth.pca.oauth.WhatwgUrl;

/**
 * Vault proxy mode: re-derive the params digest of the OUTBOUND request, and the signed release receipt. The agent never holds the
 * credential: it hands the vault the request it wants made; the vault maps that request back to the action's parameters with a pinned
 * extractor and only then attaches the token. Anything the request carries that the extractor does not map is a mismatch.
 */
public final class Proxy {
    private Proxy() {}

    public static final class ProxyRequest {
        public String method;
        /** Absolute https URL. */
        public String url;
        /** Null when none. */
        public Map<String, String> headers;
        /** The body as text; null when none. */
        public String body;
        public ProxyRequest() {}
        public ProxyRequest(String method, String url, Map<String, String> headers, String body) { this.method = method; this.url = url; this.headers = headers; this.body = body; }
    }

    public static final class ProxyResponse {
        public int status;
        public Map<String, String> headers = new LinkedHashMap<>();
        public String body;
        public ProxyResponse() {}
        public ProxyResponse(int status, Map<String, String> headers, String body) { this.status = status; this.headers = headers; this.body = body; }
    }

    /** The injected outbound transport. It MUST NOT follow redirects (a redirect would send the credential to a host the extractor never saw). */
    @FunctionalInterface
    public interface ProxyFetch {
        ProxyResponse call(String method, String url, Map<String, String> headers, String body) throws Exception;
    }

    public static final class HttpRequestSpec {
        /** Exact method, upper case. */
        public String method;
        /** {@code https://host/path/{param}/more}: literal text matches exactly; each {@code {name}} is one path segment. No query, no fragment. */
        public String url;
        /** Query keys that may appear (null = none). */
        public List<String> query;
        /** "json", "form", or null for no body. */
        public String body;
        /** Body members the request always carries with exactly these values (null = none). */
        public Map<String, Object> fixed;
    }

    private static RequestMismatchError mismatch(String m) { return new RequestMismatchError("outbound request refused: " + m); }

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{([A-Za-z0-9_]+)\\}");

    /** Build the extractor for one operation. Throws on a malformed spec (at configuration time, not at call time). */
    public static Function<ProxyRequest, Map<String, Object>> httpExtractor(HttpRequestSpec spec) {
        String probe = PLACEHOLDER.matcher(spec.url).replaceAll("x");
        WhatwgUrl u = WhatwgUrl.parse(probe);
        if (u == null) throw new IllegalArgumentException("Invalid URL");
        if (!u.protocol.equals("https:") || !u.search.isEmpty() || UrlBits.hasFragment(probe) || UrlBits.hasCredentials(probe))
            throw new IllegalArgumentException("httpExtractor: url must be https without query, fragment or userinfo");
        if (!spec.method.equals(spec.method.toUpperCase(Locale.ROOT))) throw new IllegalArgumentException("httpExtractor: method must be upper case");
        List<String> names = new ArrayList<>();
        String origin = u.origin();
        String pathTemplate = spec.url.substring(Math.min(origin.length(), spec.url.length()));
        StringBuilder re = new StringBuilder();
        Matcher pm = PLACEHOLDER.matcher(pathTemplate);
        int last = 0;
        while (pm.find()) {
            if (pm.start() > last) re.append(Pattern.quote(pathTemplate.substring(last, pm.start())));
            names.add(pm.group(1));
            re.append("([A-Za-z0-9._~%-]+)");
            last = pm.end();
        }
        if (last < pathTemplate.length()) re.append(Pattern.quote(pathTemplate.substring(last)));
        Pattern pathRe = Pattern.compile(re.toString());
        Set<String> allowedQuery = new HashSet<>(spec.query == null ? List.of() : spec.query);
        String ctype = "json".equals(spec.body) ? "application/json" : "form".equals(spec.body) ? "application/x-www-form-urlencoded" : null;
        final String specBody = spec.body, specMethod = spec.method;
        final Map<String, Object> specFixed = spec.fixed == null ? new LinkedHashMap<>() : spec.fixed;
        return req -> {
            if (!specMethod.equals(req.method)) throw mismatch("method " + req.method + " is not " + specMethod);
            WhatwgUrl r = req.url == null ? null : WhatwgUrl.parse(req.url);
            if (r == null) throw mismatch("the url does not parse");
            if (!r.origin().equals(origin) || UrlBits.hasCredentials(req.url) || UrlBits.hasFragment(req.url)) throw mismatch("the url is not on the pinned origin");
            Matcher m = pathRe.matcher(r.pathname);
            if (!m.matches()) throw mismatch("the path does not match the pinned template");
            Map<String, Object> params = new LinkedHashMap<>();
            for (int i = 0; i < names.size(); i++) {
                String dec;
                try {
                    dec = JsText.decodeURIComponent(m.group(i + 1));
                } catch (IllegalArgumentException e) {
                    throw mismatch("a path segment is not valid percent-encoding");
                }
                put(params, names.get(i), dec);
            }
            Set<String> seen = new HashSet<>();
            String search = r.search.isEmpty() ? "" : r.search.substring(1);
            for (String[] kv : formParse(search)) {
                if (!allowedQuery.contains(kv[0])) throw mismatch("query key '" + kv[0] + "' is not allowed");
                if (!seen.add(kv[0])) throw mismatch("query key '" + kv[0] + "' is repeated");
                put(params, kv[0], kv[1]);
            }
            String ct = null;
            if (req.headers != null) for (Map.Entry<String, String> h : req.headers.entrySet()) if (h.getKey().toLowerCase(Locale.ROOT).equals("content-type")) { ct = h.getValue(); break; }
            if (specBody == null) {
                if (req.body != null && !req.body.isEmpty()) throw mismatch("this operation carries no body");
            } else {
                if (req.body == null || req.body.isEmpty()) throw mismatch("the body is missing");
                if (ct == null || !JsText.trim(ct.split(";", -1)[0]).toLowerCase(Locale.ROOT).equals(ctype)) throw mismatch("content-type must be " + ctype);
                Map<String, Object> fixed = new LinkedHashMap<>(specFixed);
                if (specBody.equals("json")) {
                    Object b;
                    try { b = Json.parse(req.body); } catch (RuntimeException e) { throw mismatch("the body is not strict JSON"); }
                    if (!(b instanceof Map)) throw mismatch("the body must be a JSON object");
                    for (Map.Entry<?, ?> e : ((Map<?, ?>) b).entrySet()) {
                        String k = (String) e.getKey();
                        if (fixed.containsKey(k)) {
                            if (!Pca.hashCanonical(e.getValue()).equals(Pca.hashCanonical(fixed.get(k)))) throw mismatch("fixed member '" + k + "' has another value");
                            fixed.remove(k);
                        } else put(params, k, e.getValue());
                    }
                } else {
                    Set<String> keys = new HashSet<>();
                    for (String[] kv : formParse(req.body)) {
                        if (!keys.add(kv[0])) throw mismatch("form key '" + kv[0] + "' is repeated");
                        if (fixed.containsKey(kv[0])) {
                            if (!kv[1].equals(fixed.get(kv[0]))) throw mismatch("fixed member '" + kv[0] + "' has another value");
                            fixed.remove(kv[0]);
                        } else put(params, kv[0], kv[1]);
                    }
                }
                if (!fixed.isEmpty()) throw mismatch("fixed member(s) " + String.join(", ", fixed.keySet()) + " missing");
            }
            return params;
        };
    }

    private static void put(Map<String, Object> params, String k, Object v) {
        if (params.containsKey(k)) throw mismatch("parameter '" + k + "' is carried twice");
        params.put(k, v);
    }

    /** The application/x-www-form-urlencoded parser behind URLSearchParams: '+' is a space, invalid percent escapes stay literal, UTF-8 decoded leniently. */
    static List<String[]> formParse(String input) {
        String s = input.startsWith("?") ? input.substring(1) : input;
        List<String[]> out = new ArrayList<>();
        if (s.isEmpty()) return out;
        for (String part : s.split("&", -1)) {
            if (part.isEmpty()) continue;
            int eq = part.indexOf('=');
            String k = eq < 0 ? part : part.substring(0, eq), v = eq < 0 ? "" : part.substring(eq + 1);
            out.add(new String[] {pctLenient(k.replace('+', ' ')), pctLenient(v.replace('+', ' '))});
        }
        return out;
    }

    private static String pctLenient(String s) {
        if (s.indexOf('%') < 0) return s;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] in = Json.utf8(s);
        for (int i = 0; i < in.length; i++) {
            if (in[i] == '%' && i + 2 < in.length && hexv(in[i + 1]) >= 0 && hexv(in[i + 2]) >= 0) {
                out.write(hexv(in[i + 1]) * 16 + hexv(in[i + 2]));
                i += 2;
            } else out.write(in[i]);
        }
        return new String(out.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
    }

    private static int hexv(int c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /** Request headers the agent may set; the vault sets Authorization itself. Anything else is refused (Host, Cookie, X-HTTP-Method-Override, ...). */
    public static final List<String> DEFAULT_PROXY_HEADERS = List.of("content-type", "accept", "idempotency-key");

    public static Map<String, String> checkProxyHeaders(Map<String, String> headers, List<String> allow) {
        Map<String, String> out = new LinkedHashMap<>();
        if (headers == null) return out;
        for (Map.Entry<String, String> e : headers.entrySet()) {
            String k = e.getKey(), v = e.getValue(), n = k.toLowerCase(Locale.ROOT);
            if (!allow.contains(n)) throw mismatch("header '" + k + "' is not allowed");
            if (out.containsKey(n)) throw mismatch("header '" + k + "' is repeated");
            if (v == null || v.indexOf('\r') >= 0 || v.indexOf('\n') >= 0 || v.indexOf('\0') >= 0) throw mismatch("header '" + k + "' has an invalid value");
            out.put(n, v);
        }
        return out;
    }

    // ---- release receipt ----

    public static final String RELEASE_RECEIPT_DOMAIN = "atlas-pca/connect-release-receipt/v1\0";

    /** Digest of the outbound request as made (method, url, headers sent, body). */
    public static String outboundRequestDigest(String method, String url, Map<String, String> headers, String body) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", "atlas-pca/connect-request/v1");
        m.put("method", method);
        m.put("url", url);
        m.put("headers", new LinkedHashMap<String, Object>(headers));
        m.put("body", body);
        return Pca.hashCanonical(m);
    }

    /** Sign a receipt body ({@code v, kind, action_digest, provider, connection_id, mode, scopes_released, request_digest, http_status, outcome, ts}) under the vault key. */
    public static Map<String, Object> signReleaseReceipt(Map<String, Object> body, Keys.EdKey vaultKey) {
        return Issue.signArtifact(RELEASE_RECEIPT_DOMAIN, body, Keys.ed25519(vaultKey));
    }

    /** True iff the receipt is signed by the pinned vault key. */
    public static boolean verifyReleaseReceipt(Map<String, Object> receipt, String vaultPk) {
        return ConnectBridge.verifyArtifactSig(RELEASE_RECEIPT_DOMAIN, receipt, vaultPk);
    }

    /** Digest of the exact PCActn that authorized a release. */
    public static String receiptActionDigest(Map<String, Object> pcActn) { return Escalation.actionDigest(pcActn); }
}
