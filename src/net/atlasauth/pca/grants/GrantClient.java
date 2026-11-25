package net.atlasauth.pca.grants;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.K3;

/**
 * Thin java.net.http client for the grant management resource. It also carries the newest {@code pca-fresh-at} token it has seen: a token
 * that does not verify under {@code freshSigner} (when set) is ignored, and a token never replaces a fresher one.
 */
public final class GrantClient {
    public static final class ApiError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final int status;
        public final String code;

        public ApiError(int status, String code, String message) { super(message); this.status = status; this.code = code; }
    }

    private static final String[] COUNTERS = {"revocation_epoch", "policy_revision", "ledger_tree_size", "budget_version"};

    private final String baseUrl;
    private final HttpClient http;
    private final String freshSigner;
    private final Supplier<Map<String, String>> headers;
    private Map<String, Object> latest;

    public GrantClient(String baseUrl, HttpClient http, String freshSigner, Supplier<Map<String, String>> headers) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.http = http != null ? http : HttpClient.newHttpClient();
        this.freshSigner = freshSigner;
        this.headers = headers;
    }

    public GrantClient(String baseUrl) { this(baseUrl, null, null, null); }

    /** The newest consistency token seen on any response (attach it to later requests for read-your-writes), or null. */
    public synchronized Map<String, Object> freshAt() { return latest; }

    /** Fold the newest token into a local state; null when none was seen. */
    public synchronized Map<String, Object> foldFreshAt(Map<String, Object> state) { return latest == null ? null : FreshAt.mergeFreshAt(latest, state); }

    /** JavaScript encodeURIComponent. */
    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20").replace("%21", "!").replace("%27", "'").replace("%28", "(").replace("%29", ")").replace("%7E", "~");
    }

    private Map<String, Object> call(String method, String path, Object body) throws IOException, InterruptedException {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path)).header("content-type", "application/json");
        synchronized (this) { if (latest != null) b.header("pca-fresh-at", Json.canonicalize(latest)); }
        if (headers != null) for (Map.Entry<String, String> e : headers.get().entrySet()) b.header(e.getKey(), e.getValue());
        b.method(method, body != null ? HttpRequest.BodyPublishers.ofString(Json.canonicalize(body)) : HttpRequest.BodyPublishers.noBody());
        HttpResponse<String> res = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        res.headers().firstValue("pca-fresh-at").ifPresent(this::fold);
        Map<String, Object> json;
        try {
            json = Sig.map(Json.parseLenient(res.body()));
        } catch (RuntimeException e) {
            json = null;
        }
        if (json == null) json = new LinkedHashMap<>();
        if (res.statusCode() < 200 || res.statusCode() > 299) {
            Object code = json.get("error"), msg = json.get("message");
            throw new ApiError(res.statusCode(), code instanceof String ? (String) code : "error", msg instanceof String ? (String) msg : "HTTP " + res.statusCode());
        }
        return json;
    }

    private synchronized void fold(String tok) {
        try { // a malformed header is ignored: freshness is only ever tightened by a valid token
            Map<String, Object> t = Sig.map(Json.parseLenient(tok));
            if (t == null) return;
            if (freshSigner != null && !K3.verifyFreshAt(t, freshSigner)) return;
            for (String k : COUNTERS) if (!Sig.isSafeInt(t.get(k))) return;
            boolean newer = latest == null;
            if (!newer) {
                newer = true;
                for (String k : COUNTERS) newer = newer && Json.asLong(t.get(k)) >= Json.asLong(latest.get(k));
            }
            if (newer) latest = t; // monotone fold: never replace a fresher token with an older one
        } catch (RuntimeException e) {
            // ignored
        }
    }

    public Map<String, Object> list(Map<String, String> q) throws IOException, InterruptedException {
        StringBuilder sb = new StringBuilder();
        if (q != null) for (Map.Entry<String, String> e : q.entrySet()) {
            if (e.getValue() == null) continue;
            sb.append(sb.length() == 0 ? "?" : "&").append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)).append('=').append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        return call("GET", GrantHttp.GRANTS_PATH + sb, null);
    }

    public Map<String, Object> inspect(String id) throws IOException, InterruptedException { return call("GET", GrantHttp.GRANTS_PATH + "/" + enc(id), null); }

    public Map<String, Object> amend(String id, Map<String, Object> req) throws IOException, InterruptedException { return call("POST", GrantHttp.GRANTS_PATH + "/" + enc(id) + "/amend", req); }

    /** {@code scope} null means grant; {@code sig} null sends no body (an admin revoke). */
    public Map<String, Object> revoke(String id, String scope, String sig) throws IOException, InterruptedException {
        Map<String, Object> body = null;
        if (sig != null && !sig.isEmpty()) { body = new LinkedHashMap<>(); body.put("sig", sig); }
        return call("DELETE", GrantHttp.GRANTS_PATH + "/" + enc(id) + "?scope=" + (scope != null ? scope : "grant"), body);
    }

    public Map<String, Object> requestNeeds(String id, List<Object> needs) throws IOException, InterruptedException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("needs", needs);
        return call("POST", GrantHttp.GRANTS_PATH + "/" + enc(id) + "/needs", body);
    }

    public Map<String, Object> approveNeeds(String needId, List<Object> approved, String sig, String stepUpRef) throws IOException, InterruptedException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("approved", approved);
        body.put("sig", sig);
        if (stepUpRef != null && !stepUpRef.isEmpty()) body.put("step_up_ref", stepUpRef);
        return call("POST", GrantHttp.NEEDS_PATH + "/" + enc(needId) + "/approve", body);
    }

    public Map<String, Object> denyNeeds(String needId) throws IOException, InterruptedException { return call("POST", GrantHttp.NEEDS_PATH + "/" + enc(needId) + "/deny", null); }
}
