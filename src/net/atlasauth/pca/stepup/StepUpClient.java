package net.atlasauth.pca.stepup;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;

/**
 * Lists, approves and denies PCA step-ups from the principal's device.
 *
 * <ul>
 *   <li>{@code dashboardUrl} plus a dashboard bearer token (a service key or a console session token) serve
 *       {@code GET/POST .../pca/stepups} (list, deny). Deny needs an owner or admin role.</li>
 *   <li>{@code instanceUrl} (the Atlas instance the agent talks to) serves the public, self-authenticating
 *       {@code POST /v1/pca/stepups/<id>/cosign}; the device signature is the credential and the dashboard token is never sent to it.</li>
 * </ul>
 *
 * <p>The default transport is {@code java.net.http}; it never follows a redirect, so a bearer token cannot be sent to another host.
 * All errors are unchecked {@link StepUpException}s.
 */
public final class StepUpClient {
    /** The answer of a request: the status and the body text. */
    public static final class Response {
        public final int status;
        public final String body;
        public Response(int status, String body) { this.status = status; this.body = body; }
    }

    /** Sends one request. A network failure is an {@link IOException}. */
    @FunctionalInterface
    public interface Transport {
        Response send(String method, String url, Map<String, String> headers, byte[] body) throws IOException;
    }

    /** A pending step-up. */
    public static final class PendingStepUp {
        public final String id;
        public final String grantRef;
        public final String actionVerb;
        public final String actionResource;
        public final int requiredT;
        /** base64url bytes the device signs. */
        public final String thresholdMessage;
        /** epoch ms. */
        public final long expiresAt;

        public PendingStepUp(String id, String grantRef, String actionVerb, String actionResource, int requiredT, String thresholdMessage, long expiresAt) {
            this.id = id;
            this.grantRef = grantRef;
            this.actionVerb = actionVerb;
            this.actionResource = actionResource;
            this.requiredT = requiredT;
            this.thresholdMessage = thresholdMessage;
            this.expiresAt = expiresAt;
        }
    }

    /** The answer to an approval. */
    public static final class ApproveResult {
        /** The server's status text (for example {@code anchored} or {@code pending}). */
        public final String status;
        /** True when the action is now anchored (200 and {@code allow}); false on 202: more roles are still required. */
        public final boolean anchored;
        public final int httpStatus;

        public ApproveResult(String status, boolean anchored, int httpStatus) {
            this.status = status;
            this.anchored = anchored;
            this.httpStatus = httpStatus;
        }
    }

    private static final Pattern ISO = Pattern.compile("^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d(?:\\.(\\d+))?Z$");

    private final String dashboard;
    private final String instance;
    private final String accountId;
    private final String instanceId;
    private final PrincipalDeviceKey key;
    private final Supplier<String> token;
    private final Transport transport;
    private final LongSupplier now;

    /**
     * @param token returns the dashboard bearer token (called per request)
     * @param transport replaces the built-in HTTP client (tests, proxies); null: {@code java.net.http}
     * @param now the clock in epoch ms; null: the wall clock
     */
    public StepUpClient(String dashboardUrl, String instanceUrl, String accountId, String instanceId, PrincipalDeviceKey key,
                        Supplier<String> token, Transport transport, LongSupplier now) {
        this.dashboard = base(dashboardUrl);
        this.instance = base(instanceUrl);
        if (accountId == null || instanceId == null || key == null || token == null) throw new IllegalArgumentException("accountId, instanceId, key and token are required");
        this.accountId = accountId;
        this.instanceId = instanceId;
        this.key = key;
        this.token = token;
        this.transport = transport != null ? transport : defaultTransport(Duration.ofSeconds(30));
        this.now = now != null ? now : System::currentTimeMillis;
    }

    public StepUpClient(String dashboardUrl, String instanceUrl, String accountId, String instanceId, PrincipalDeviceKey key, Supplier<String> token) {
        this(dashboardUrl, instanceUrl, accountId, instanceId, key, token, null, null);
    }

    public PrincipalDeviceKey key() { return key; }

    private static String base(String url) {
        URI u;
        try {
            u = URI.create(url == null ? "" : url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("a step-up URL must be an http(s) URL: " + url);
        }
        String scheme = u.getScheme();
        if (!("http".equals(scheme) || "https".equals(scheme)) || u.getHost() == null) throw new IllegalArgumentException("a step-up URL must be an http(s) URL: " + url);
        String s = url;
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s;
    }

    /** The default transport: {@code java.net.http}, no redirects. */
    public static Transport defaultTransport(Duration timeout) {
        HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(timeout).build();
        return (method, url, headers, body) -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(timeout)
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
            for (Map.Entry<String, String> h : headers.entrySet()) b.header(h.getKey(), h.getValue());
            try {
                HttpResponse<String> r = client.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                return new Response(r.statusCode(), r.body());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted", e);
            }
        };
    }

    private static String q(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20").replace("*", "%2A").replace("%7E", "~"); }

    private String stepupsUrl() { return dashboard + "/v1/dashboard/accounts/" + q(accountId) + "/instances/" + q(instanceId) + "/pca/stepups"; }

    private Response call(String method, String url, Map<String, String> headers, byte[] body) {
        Response r;
        try {
            r = transport.send(method, url, headers, body);
        } catch (IOException e) {
            throw new StepUpException.TransportError(e.getMessage() != null ? e.getMessage() : "Network error.", e);
        }
        if (r == null) throw new StepUpException.TransportError("No answer.");
        if (r.status < 200 || r.status >= 300) {
            String msg = "The request failed.";
            try {
                Object errors = ((Map<?, ?>) Json.parseLenient(r.body)).get("errors");
                Object message = ((Map<?, ?>) ((List<?>) errors).get(0)).get("message");
                if (message instanceof String) msg = (String) message;
            } catch (RuntimeException e) {
                // keep the generic message
            }
            if (r.status == 403) throw new StepUpException.PrincipalMismatch(msg);
            throw new StepUpException.ApiError(r.status, msg);
        }
        return r;
    }

    private Map<String, String> auth() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Authorization", "Bearer " + token.get());
        h.put("Accept", "application/json");
        return h;
    }

    private static String str(Object v) {
        if (!(v instanceof String)) throw new IllegalArgumentException("expected a string");
        return (String) v;
    }

    /** {@code 2026-10-06T18:00:00.123Z} (fraction optional, always UTC from the API) as epoch ms; the fraction is cut to milliseconds. */
    static long parseIso(String s) {
        java.util.regex.Matcher m = ISO.matcher(s);
        if (!m.matches()) throw new IllegalArgumentException("bad timestamp");
        String frac = m.group(1);
        String whole = frac == null ? s : s.substring(0, s.indexOf('.')) + "Z";
        long ms = frac == null ? 0L : Long.parseLong((frac + "000").substring(0, 3));
        return Instant.parse(whole).toEpochMilli() + ms;
    }

    /** Pending, not-yet-expired step-ups. */
    public List<PendingStepUp> pending() {
        Response r = call("GET", stepupsUrl() + "?status=pending", auth(), null);
        List<?> items;
        try {
            items = (List<?>) ((Map<?, ?>) Json.parseLenient(r.body)).get("stepups");
            if (items == null) throw new IllegalArgumentException("no stepups");
        } catch (RuntimeException e) {
            throw new StepUpException.TransportError("Unreadable step-up list.", e);
        }
        long t = now.getAsLong();
        List<PendingStepUp> out = new ArrayList<>();
        for (Object it : items) {
            try {
                Map<?, ?> o = (Map<?, ?>) it;
                long exp = parseIso(str(o.get("expires_at")));
                if (exp <= t) continue;
                Map<?, ?> a = (Map<?, ?>) o.get("action");
                Object rt = o.get("required_t");
                if (!(rt instanceof Json.Num) || !Json.isSafeInt(rt)) throw new IllegalArgumentException("required_t");
                out.add(new PendingStepUp(str(o.get("id")), str(o.get("grant_ref")), str(a.get("verb")), str(a.get("resource")),
                    (int) Json.asLong(rt), str(o.get("threshold_message")), exp));
            } catch (RuntimeException e) {
                throw new StepUpException.TransportError("Unreadable step-up entry.", e);
            }
        }
        return out;
    }

    /**
     * Sign the step-up's threshold message with the device key and submit it. Throws {@link StepUpException.PrincipalMismatch}
     * (server 403) when this key is not the grant's principal. The dashboard token is never sent.
     */
    public ApproveResult approve(PendingStepUp stepUp) {
        byte[] message = Pca.decodeB64uStrict(stepUp.thresholdMessage, -1);
        if (message == null) throw new StepUpException.InvalidThresholdMessage();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("role", "principal");
        payload.put("publicKey", key.publicKey());
        payload.put("sig", key.sign(message));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Accept", "application/json");
        Response r = call("POST", instance + "/v1/pca/stepups/" + q(stepUp.id) + "/cosign", headers, Json.canonicalize(payload).getBytes(StandardCharsets.UTF_8));
        Map<?, ?> obj = Map.of();
        try {
            Object parsed = Json.parseLenient(r.body);
            if (parsed instanceof Map) obj = (Map<?, ?>) parsed;
        } catch (RuntimeException e) {
            // an unreadable answer on success: report what the status says
        }
        Object st = obj.get("status");
        // 200 + allow:true = anchored; 202 = more roles still required
        return new ApproveResult(st instanceof String ? (String) st : "", Boolean.TRUE.equals(obj.get("allow")), r.status);
    }

    /** {@link #deny(PendingStepUp, String)} without a reason. */
    public void deny(PendingStepUp stepUp) { deny(stepUp, null); }

    /** Deny a pending step-up (dashboard endpoint; audited; owner or admin). {@code reason} may be null. */
    public void deny(PendingStepUp stepUp, String reason) {
        Map<String, String> headers = auth();
        headers.put("Content-Type", "application/json");
        Map<String, Object> payload = new LinkedHashMap<>();
        if (reason != null) payload.put("reason", reason);
        call("POST", stepupsUrl() + "/" + q(stepUp.id) + "/deny", headers, Json.canonicalize(payload).getBytes(StandardCharsets.UTF_8));
    }
}
