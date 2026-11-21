package net.atlasauth.pca.webbotauth;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.oauth.WhatwgUrl;

/**
 * Fetch and strictly parse a Web Bot Auth key directory. FAIL-CLOSED: throws on a non-https URL, a redirect, a non-200 status, a wrong content type,
 * an oversize body, invalid JSON, or any key that is not a well-formed Ed25519 OKP JWK with a string {@code kid} and 32-byte {@code x}. Never returns a
 * partial directory.
 *
 * <p>shortcut: a directory URL that carries credentials is refused (the reference would pass them on) and a fragment is dropped, as fetch does;
 * only http(s) URLs are accepted. Upgrade if a credentialed directory URL is ever needed.
 */
public final class DirectoryFetch {
    private DirectoryFetch() {}

    /** The part of an HTTP response the directory fetch reads. */
    public interface Response {
        int status();
        /** The first value of a response header (case-insensitive), or null. */
        String header(String name);
        String text() throws Exception;
    }

    /** The HTTP client: inject your own for SSRF-safe egress. It must NOT follow redirects (a redirect is a failure). */
    @FunctionalInterface
    public interface Fetcher { Response fetch(String url, Map<String, String> headers, long timeoutMs) throws Exception; }

    /** The default {@link Fetcher}: java.net.http with redirects disabled. */
    public static Response httpFetch(String url, Map<String, String> headers, long timeoutMs) throws Exception {
        HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofMillis(timeoutMs)).build();
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofMillis(timeoutMs)).GET();
        for (Map.Entry<String, String> e : headers.entrySet()) b.header(e.getKey(), e.getValue());
        HttpResponse<byte[]> res = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
        return new Response() {
            @Override public int status() { return res.statusCode(); }
            @Override public String header(String name) { return res.headers().firstValue(name).orElse(null); }
            @Override public String text() { return new String(res.body(), StandardCharsets.UTF_8); }
        };
    }

    /**
     * {@code options}: fetch ({@link Fetcher}, default {@link #httpFetch}), maxBytes (characters, default 65536), timeoutMs (default 5000),
     * allowInsecureHttp (tests only), requireSignature (require the signed directory response and return only the keys with a valid signature;
     * throws when none does), now (epoch seconds for the signature check).
     */
    public static Map<String, Object> fetchKeyDirectory(String url, Map<String, Object> options) throws Exception {
        WhatwgUrl u = WhatwgUrl.parse(url);
        if (u == null) throw new IllegalArgumentException("Invalid URL");
        if (u.origin().equals("null")) throw new IllegalArgumentException("directory URL must be an http(s) URL");
        if (!u.protocol.equals("https:") && !(Boolean.TRUE.equals(options.get("allowInsecureHttp")) && u.protocol.equals("http:"))) throw new IllegalArgumentException("directory URL must be https");
        String hostport = u.host + (u.port.isEmpty() ? "" : ":" + u.port);
        String raw = url;
        int hash = raw.indexOf('#');
        String noFrag = hash >= 0 ? raw.substring(0, hash) : raw;
        int slashes = noFrag.indexOf("//");
        int authEnd = noFrag.length();
        for (int k = slashes + 2; k < noFrag.length(); k++) { char c = noFrag.charAt(k); if (c == '/' || c == '\\' || c == '?') { authEnd = k; break; } }
        if (slashes >= 0 && noFrag.substring(slashes + 2, authEnd).indexOf('@') >= 0) throw new IllegalArgumentException("directory URL must not carry credentials");
        String href = u.protocol + "//" + hostport + u.pathname + u.search + (u.search.isEmpty() && noFrag.indexOf('?') >= 0 ? "?" : "");
        Fetcher fetcher = options.get("fetch") instanceof Fetcher ? (Fetcher) options.get("fetch") : DirectoryFetch::httpFetch;
        long timeout = options.get("timeoutMs") != null ? (long) WbaJs.number(options.get("timeoutMs")) : 5000L;
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("accept", "application/http-message-signatures-directory+json");
        Response res = fetcher.fetch(href, headers, timeout);
        if (res.status() != 200) throw new IllegalStateException("directory fetch returned status " + res.status());
        String ctRaw = res.header("content-type");
        String ct = WbaJs.lower(WbaJs.trim((ctRaw == null ? "" : ctRaw).split(";", -1)[0]));
        if (!ct.equals("application/http-message-signatures-directory+json")) throw new IllegalStateException("directory has the wrong content type");
        String text = res.text();
        double max = options.get("maxBytes") != null ? WbaJs.number(options.get("maxBytes")) : 65536;
        if (text.length() > max) throw new IllegalStateException("directory response is too large");
        Map<String, Object> directory = SignedDirectory.parseKeyDirectory(text);
        if (Boolean.TRUE.equals(options.get("requireSignature"))) {
            Map<String, Object> in = new LinkedHashMap<>();
            in.put("authority", WbaJs.lower(hostport));
            Map<String, Object> hs = new LinkedHashMap<>();
            String si = res.header("signature-input"), sg = res.header("signature");
            hs.put("signature-input", si == null ? "" : si);
            hs.put("signature", sg == null ? "" : sg);
            in.put("headers", hs);
            in.put("body", text);
            if (options.get("now") != null) in.put("now", options.get("now"));
            Map<String, Object> v = SignedDirectory.verifyDirectoryResponse(in);
            if (!Boolean.TRUE.equals(v.get("valid"))) throw new IllegalStateException("directory signature: " + v.get("reason"));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("keys", v.get("keys"));
            return out;
        }
        return directory;
    }

    public static Map<String, Object> fetchKeyDirectory(String url) throws Exception { return fetchKeyDirectory(url, new LinkedHashMap<>()); }

}
