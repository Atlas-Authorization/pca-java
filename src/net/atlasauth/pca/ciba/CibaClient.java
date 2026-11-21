package net.atlasauth.pca.ciba;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;

/**
 * A network client for a real OpenID Provider's CIBA endpoints (OpenID CIBA Core 1.0): start a backchannel authentication request and wait
 * for the human's decision by POLL or PING. It is the relying-party side that the in-memory broker models.
 *
 * <p>Poll discipline follows CIBA Core 7.3 / 11: the client never polls faster than the {@code interval} the OP returned, adds at least 5
 * seconds to it on every {@code slow_down}, and stops at {@code expires_in}. A terminal answer (approved / denied / expired) is cached, so a
 * settled flow is never re-sent to the token endpoint (an approved {@code auth_req_id} is single-use at real providers). The client
 * authenticates with {@code client_secret_basic}. The returned tokens are the OP's response, not verified here.
 *
 * <p>The transport is injectable ({@link Transport}); the default uses {@code java.net.http}. Calls block. A poller serializes its callers
 * (concurrent callers wait for the in-flight request and then see its cached result when it settled); {@code notify()} wakes a poller that is
 * sleeping on its own timer but cannot shorten a custom {@link Sleeper}.
 */
public final class CibaClient {
    private CibaClient() {}

    private static final String CIBA_GRANT = "urn:openid:params:grant-type:ciba";
    private static final int SLOW_DOWN_STEP_SEC = 5;
    private static final int MIN_NOTIFICATION_TOKEN_CHARS = 22;
    private static final int MAX_NOTIFICATION_TOKEN_CHARS = 1024;
    private static final long DEFAULT_TIMEOUT_MS = 30_000;
    private static final long MAX_BACKOFF_MS = 60_000;
    private static final int MAX_CONSECUTIVE_TRANSIENT = 5;
    private static final SecureRandom RNG = new SecureRandom();

    /** An error response from the OP (RFC 6749 5.2 / CIBA Core 13), or a malformed reply. */
    public static final class CibaProviderError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final String error;
        public final String errorDescription;
        public final int status;
        /** True for failures worth retrying (network error, timeout, 5xx, non-JSON reply); not for a definitive OP answer. */
        public final boolean retryable;

        public CibaProviderError(int status, String error, String errorDescription, boolean retryable) {
            super("ciba: provider returned " + status + " " + error + (errorDescription != null ? " (" + errorDescription + ")" : ""));
            this.status = status;
            this.error = error;
            this.errorDescription = errorDescription;
            this.retryable = retryable;
        }
    }

    /** One HTTP answer: the status code and the body text. */
    public static final class Response {
        public final int status;
        public final String text;
        public Response(int status, String text) { this.status = status; this.text = text; }
        public boolean ok() { return status >= 200 && status < 300; }
    }

    /** POST {@code body} (form-encoded) to {@code url} with {@code headers}; throws on a network failure or a timeout. */
    public interface Transport { Response post(String url, Map<String, String> headers, String body, long timeoutMs) throws IOException; }

    /** Sleeps {@code ms} milliseconds (injectable for tests). */
    public interface Sleeper { void sleep(long ms) throws InterruptedException; }

    /** Client configuration. {@code transport}, {@code sleep} and {@code now} default to {@code java.net.http}, {@code Thread.sleep} and the system clock. */
    public static final class Config {
        public String backchannelAuthenticationEndpoint;
        public String tokenEndpoint;
        public String clientId;
        public String clientSecret;
        public Transport transport;
        public Sleeper sleep;
        public java.util.function.LongSupplier now = System::currentTimeMillis;
        public double timeoutMs = DEFAULT_TIMEOUT_MS;
        /** Permit {@code http://} endpoints (local test providers only). */
        public boolean allowInsecureHttp;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    // ---- helpers ------------------------------------------------------------------------------------------------------------------

    /** {@code encodeURIComponent}. */
    static String encodeURIComponent(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            if (cp >= 0xd800 && cp <= 0xdfff) throw new IllegalArgumentException("URI malformed");
            i += Character.charCount(cp);
            if ((cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z') || (cp >= '0' && cp <= '9') || "-_.!~*'()".indexOf(cp) >= 0) sb.appendCodePoint(cp);
            else for (byte b : Json.utf8(new String(Character.toChars(cp)))) sb.append('%').append(String.format("%02X", b & 0xff));
        }
        return sb.toString();
    }

    /** {@code application/x-www-form-urlencoded} serialization of one parameter name or value. */
    static String formEncode(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte bb : CibaJs.utf8(s)) {
            int b = bb & 0xff;
            if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '*' || b == '-' || b == '.' || b == '_') sb.append((char) b);
            else if (b == ' ') sb.append('+');
            else sb.append('%').append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private static String formBody(List<String[]> params) {
        StringBuilder sb = new StringBuilder();
        for (String[] kv : params) { if (sb.length() > 0) sb.append('&'); sb.append(formEncode(kv[0])).append('=').append(formEncode(kv[1])); }
        return sb.toString();
    }

    /** {@code URLSearchParams.set}: replace the first parameter of that name and drop the others, else append. */
    private static void setParam(List<String[]> params, String k, String v) {
        boolean set = false;
        for (int i = 0; i < params.size(); i++) {
            if (!params.get(i)[0].equals(k)) continue;
            if (!set) { params.get(i)[1] = v; set = true; } else params.remove(i--);
        }
        if (!set) params.add(new String[] {k, v});
    }

    private static void checkEndpoint(String name, String value, boolean allowInsecure) {
        String scheme = null;
        if (value != null) {
            Matcher m = Pattern.compile("^\\s*([A-Za-z][A-Za-z0-9+.\\-]*):").matcher(value);
            if (m.find()) scheme = m.group(1).toLowerCase(java.util.Locale.ROOT);
        }
        boolean parses = false;
        if (scheme != null) {
            try { URI u = URI.create(value.trim()); parses = u.getHost() != null || !"https".equals(scheme) && !"http".equals(scheme); } catch (IllegalArgumentException e) { parses = false; }
        }
        if (!parses) throw new IllegalArgumentException("ciba: " + name + " is not a valid URL");
        if (scheme.equals("https")) return;
        if (scheme.equals("http") && allowInsecure) return;
        throw new IllegalArgumentException("ciba: " + name + " must be an https:// URL (set allowInsecureHttp only for a local test provider)");
    }

    /** A fresh {@code client_notification_token} (CIBA Core 7.1: at least 128 bits of entropy, at most 1024 chars): 256 random bits, base64url. */
    public static String newClientNotificationToken() {
        byte[] b = new byte[32];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static Map<String, Object> readJson(Response res) {
        Object parsed;
        try {
            parsed = Json.parseLenient(res.text);
        } catch (RuntimeException | StackOverflowError e) {
            throw new CibaProviderError(res.status, "invalid_response", "the provider reply was not JSON", true);
        }
        if (!(parsed instanceof Map)) throw new CibaProviderError(res.status, "invalid_response", "the provider reply was not a JSON object", false);
        return map(parsed);
    }

    private static CibaProviderError providerError(int status, Map<String, Object> body) {
        String error = body.get("error") instanceof String ? (String) body.get("error") : "invalid_response";
        String desc = body.get("error_description") instanceof String ? (String) body.get("error_description") : null;
        return new CibaProviderError(status, error, desc, false);
    }

    private static long positiveInt(Object value, String name, int status) {
        if (!CibaJs.isSafeInteger(value) || value instanceof Boolean || CibaJs.num(value) <= 0)
            throw new CibaProviderError(status, "invalid_response", name + " must be a positive integer", false);
        return (long) (double) CibaJs.num(value);
    }

    private static Transport defaultTransport() {
        HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        return (url, headers, body, timeoutMs) -> {
            HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofMillis(timeoutMs)).POST(HttpRequest.BodyPublishers.ofString(body));
            for (Map.Entry<String, String> h : headers.entrySet()) rb.header(h.getKey(), h.getValue());
            try {
                HttpResponse<String> r = http.send(rb.build(), HttpResponse.BodyHandlers.ofString());
                return new Response(r.statusCode(), r.body());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted", e);
            }
        };
    }

    // ---- the client ---------------------------------------------------------------------------------------------------------------

    /** The CIBA client over one OP: {@link #initiate} starts a flow and {@link #poller} follows it. */
    public static final class Client {
        private final Config cfg;
        private final Transport transport;
        private final String basic;

        Client(Config cfg) {
            this.cfg = cfg;
            this.transport = cfg.transport != null ? cfg.transport : defaultTransport();
            this.basic = "Basic " + Base64.getEncoder().encodeToString(Json.utf8((encodeURIComponent(cfg.clientId) + ":" + encodeURIComponent(cfg.clientSecret))));
        }

        private Response post(String url, List<String[]> form, AtomicBoolean signal) {
            if (signal != null && signal.get()) throw new IllegalStateException("ciba: wait aborted");
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("authorization", basic);
            headers.put("content-type", "application/x-www-form-urlencoded");
            headers.put("accept", "application/json");
            try {
                return transport.post(url, headers, formBody(form), (long) Math.ceil(cfg.timeoutMs));
            } catch (IOException | RuntimeException e) {
                if (signal != null && signal.get()) throw new IllegalStateException("ciba: wait aborted");
                throw new CibaProviderError(0, "network_error", e.getMessage() != null ? e.getMessage() : "request failed", true);
            }
        }

        /**
         * Start a backchannel flow for a step-up. {@code opts}: the request options of {@link Ciba#toCibaAuthRequest} plus {@code loginHintToken},
         * {@code idTokenHint}, {@code delivery} ({@code poll} default or {@code ping}), {@code clientNotificationToken}, {@code acrValues},
         * {@code userCode}. Exactly one identifying hint is required (CIBA Core 7.1). Returns the flow
         * {@code {authReqId, expiresInSec, intervalSec, startedAt, delivery, [clientNotificationToken,] request}}.
         */
        public Map<String, Object> initiate(Map<String, Object> stepUp, Map<String, Object> opts) {
            Map<String, Object> o = opts == null ? new LinkedHashMap<>() : opts;
            int hints = 0;
            for (String k : new String[] {"loginHint", "loginHintToken", "idTokenHint"}) if (o.containsKey(k)) hints++;
            if (hints != 1) throw new IllegalArgumentException("ciba: exactly one of loginHint, loginHintToken, idTokenHint is required (CIBA Core 7.1)");
            Object deliveryO = o.get("delivery");
            String delivery = deliveryO != null ? (String) deliveryO : "poll";
            Object cnt = o.get("clientNotificationToken");
            String notificationToken = delivery.equals("ping") ? (cnt != null ? (String) cnt : newClientNotificationToken()) : null;
            if (o.containsKey("clientNotificationToken")) {
                String t = (String) o.get("clientNotificationToken");
                boolean printable = !t.isEmpty();
                for (int i = 0; i < t.length(); i++) { char c = t.charAt(i); if (c < 0x21 || c > 0x7e) { printable = false; break; } }
                if (t.length() < MIN_NOTIFICATION_TOKEN_CHARS || t.length() > MAX_NOTIFICATION_TOKEN_CHARS || !printable)
                    throw new IllegalArgumentException("ciba: clientNotificationToken must be " + MIN_NOTIFICATION_TOKEN_CHARS + ".." + MAX_NOTIFICATION_TOKEN_CHARS
                        + " printable characters (>= 128 bits, CIBA Core 7.1)");
            }
            Map<String, Object> request = Ciba.toCibaAuthRequest(stepUp, o);
            List<String[]> form = new ArrayList<>();
            form.add(new String[] {"scope", (String) request.get("scope")});
            form.add(new String[] {"binding_message", (String) request.get("binding_message")});
            form.add(new String[] {"requested_expiry", CibaJs.str(request.get("requested_expiry"))});
            if (o.containsKey("loginHint")) setParam(form, "login_hint", CibaJs.str(o.get("loginHint")));
            if (o.containsKey("loginHintToken")) setParam(form, "login_hint_token", CibaJs.str(o.get("loginHintToken")));
            if (o.containsKey("idTokenHint")) setParam(form, "id_token_hint", CibaJs.str(o.get("idTokenHint")));
            if (o.containsKey("acrValues")) setParam(form, "acr_values", CibaJs.str(o.get("acrValues")));
            if (o.containsKey("userCode")) setParam(form, "user_code", CibaJs.str(o.get("userCode")));
            if (notificationToken != null) setParam(form, "client_notification_token", notificationToken);
            Response res = post(cfg.backchannelAuthenticationEndpoint, form, null);
            Map<String, Object> body = readJson(res);
            if (!res.ok()) throw providerError(res.status, body);
            Object authReqId = body.get("auth_req_id");
            if (!(authReqId instanceof String) || ((String) authReqId).isEmpty()) throw new CibaProviderError(res.status, "invalid_response", "auth_req_id missing", false);
            long expiresInSec = positiveInt(body.get("expires_in"), "expires_in", res.status);
            // CIBA Core 7.3: `interval` is optional and defaults to 5 seconds.
            long intervalSec = body.containsKey("interval") ? positiveInt(body.get("interval"), "interval", res.status) : 5;
            Map<String, Object> flow = Issue.obj("authReqId", authReqId, "expiresInSec", expiresInSec, "intervalSec", intervalSec, "startedAt", cfg.now.getAsLong(), "delivery", delivery);
            if (notificationToken != null) flow.put("clientNotificationToken", notificationToken);
            flow.put("request", request);
            return flow;
        }

        /** The poller for a flow returned by {@link #initiate}. */
        public Poller poller(Map<String, Object> flow) { return new Poller(this, flow); }
    }

    /** Follows one flow: sleeps until the interval allows it, asks the token endpoint once per {@link #poll}, and caches a settled answer. */
    public static final class Poller {
        private final Client c;
        private final Config cfg;
        private final Map<String, Object> flow;
        private double intervalMs;
        private volatile double nextAt;
        private final double deadline;
        private Map<String, Object> settled;
        private int failures;
        private final Object lock = new Object();
        private boolean woken;

        Poller(Client c, Map<String, Object> flow) {
            this.c = c;
            this.cfg = c.cfg;
            this.flow = flow;
            this.intervalMs = CibaJs.num(flow.get("intervalSec")) * 1000;
            this.nextAt = CibaJs.num(flow.get("startedAt")) + intervalMs;
            this.deadline = CibaJs.num(flow.get("startedAt")) + CibaJs.num(flow.get("expiresInSec")) * 1000;
        }

        /** Current poll interval in seconds (grows on {@code slow_down}). */
        public synchronized double intervalSec() { return intervalMs / 1000; }

        /** A PING arrived: the next {@link #poll} may go out immediately, and a poll that is sleeping on its own timer wakes now. */
        public void notifyPing() {
            synchronized (lock) {
                nextAt = cfg.now.getAsLong();
                woken = true;
                lock.notifyAll();
            }
        }

        private void pause(double ms, AtomicBoolean signal) {
            try {
                if (cfg.sleep != null) cfg.sleep.sleep((long) Math.ceil(ms));
                else {
                    long end = System.currentTimeMillis() + (long) Math.ceil(ms);
                    synchronized (lock) {
                        woken = false;
                        while (!woken && (signal == null || !signal.get())) {
                            long left = end - System.currentTimeMillis();
                            if (left <= 0) break;
                            lock.wait(left);
                        }
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("ciba: wait aborted");
            }
            if (signal != null && signal.get()) throw new IllegalStateException("ciba: wait aborted");
        }

        private void backoff() {
            failures += 1;
            double delay = Math.min(MAX_BACKOFF_MS, intervalMs * Math.pow(2, Math.min(failures, 6)));
            nextAt = cfg.now.getAsLong() + delay;
        }

        private Map<String, Object> doPoll(AtomicBoolean signal) {
            if (settled != null) return settled;
            double wait = nextAt - cfg.now.getAsLong();
            if (wait > 0) pause(wait, signal);
            if (settled != null) return settled;
            if (!(cfg.now.getAsLong() < deadline)) {
                settled = Issue.obj("status", "expired");
                return settled;
            }
            Response res;
            Map<String, Object> body;
            try {
                List<String[]> form = new ArrayList<>();
                form.add(new String[] {"grant_type", CIBA_GRANT});
                form.add(new String[] {"auth_req_id", (String) flow.get("authReqId")});
                res = c.post(cfg.tokenEndpoint, form, signal);
                if (res.status >= 500) throw new CibaProviderError(res.status, "server_error", "the provider answered with a server error", true);
                body = readJson(res);
            } catch (CibaProviderError e) {
                if (e.retryable) backoff();
                throw e;
            }
            failures = 0;
            nextAt = cfg.now.getAsLong() + intervalMs;
            if (res.ok()) {
                Object at = body.get("access_token"), tt = body.get("token_type");
                if (!(at instanceof String) || !(tt instanceof String)) throw new CibaProviderError(res.status, "invalid_response", "token response lacks access_token / token_type", false);
                settled = Issue.obj("status", "approved", "tokens", body);
                return settled;
            }
            CibaProviderError err = providerError(res.status, body);
            switch (err.error) {
                case "authorization_pending":
                    return Issue.obj("status", "pending", "intervalSec", intervalMs / 1000);
                case "slow_down":
                    intervalMs += SLOW_DOWN_STEP_SEC * 1000;
                    nextAt = cfg.now.getAsLong() + intervalMs;
                    return Issue.obj("status", "pending", "intervalSec", intervalMs / 1000);
                case "access_denied":
                    settled = Issue.obj("status", "denied", "error", err.error);
                    return settled;
                case "expired_token":
                    settled = Issue.obj("status", "expired");
                    return settled;
                default:
                    throw err;
            }
        }

        /** Sleep until the interval allows it, then ask the token endpoint once: {@code {status: pending, intervalSec}}, {@code {approved, tokens}}, {@code {denied, error}} or {@code {expired}}. */
        public Map<String, Object> poll() { return poll(null); }

        public synchronized Map<String, Object> poll(AtomicBoolean signal) { return doPoll(signal); }

        /** Poll until the flow settles; honours {@code signal}. Transient failures are retried (up to 5 in a row); a definitive OP error throws. */
        public Map<String, Object> await(AtomicBoolean signal) {
            int transientFailures = 0;
            for (;;) {
                if (signal != null && signal.get()) throw new IllegalStateException("ciba: wait aborted");
                try {
                    Map<String, Object> r = poll(signal);
                    transientFailures = 0;
                    if (!"pending".equals(r.get("status"))) return r;
                } catch (CibaProviderError e) {
                    if (!e.retryable || ++transientFailures >= MAX_CONSECUTIVE_TRANSIENT) throw e;
                }
            }
        }
    }

    /** The CIBA client for {@code cfg}; endpoints must be https:// unless {@code allowInsecureHttp}. */
    public static Client createCibaClient(Config cfg) {
        if (Double.isNaN(cfg.timeoutMs) || Double.isInfinite(cfg.timeoutMs) || cfg.timeoutMs <= 0) throw new IllegalArgumentException("ciba: timeoutMs must be a positive number");
        checkEndpoint("backchannelAuthenticationEndpoint", cfg.backchannelAuthenticationEndpoint, cfg.allowInsecureHttp);
        checkEndpoint("tokenEndpoint", cfg.tokenEndpoint, cfg.allowInsecureHttp);
        return new Client(cfg);
    }

    // ---- PING callback ------------------------------------------------------------------------------------------------------------

    private static final Pattern BEARER = Pattern.compile("^bearer +(\\S+)$", Pattern.CASE_INSENSITIVE);

    /**
     * Validate a PING callback (CIBA Core 10.2): {@code Authorization: Bearer <client_notification_token>} and a JSON body
     * {@code {"auth_req_id": ...}}. Returns the {@code auth_req_id} only when the bearer matches the token sent for that flow (constant-time
     * comparison); throws otherwise. The callback carries no decision: call {@code poller.notifyPing()} and then {@code poll()}.
     */
    public static String verifyPingCallback(String authorization, Object body, Map<String, Object> flow) {
        if (flow.get("clientNotificationToken") == null) throw new IllegalStateException("ciba: flow was not started in ping mode");
        Matcher m = BEARER.matcher(authorization == null ? "" : authorization);
        if (!m.matches()) throw new IllegalStateException("ciba: ping callback lacks a bearer token");
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] a = sha.digest(Json.utf8(m.group(1)));
            byte[] b = MessageDigest.getInstance("SHA-256").digest(Json.utf8(((String) flow.get("clientNotificationToken"))));
            if (!MessageDigest.isEqual(a, b)) throw new IllegalStateException("ciba: ping callback bearer does not match the client_notification_token");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        Object id = body instanceof Map ? map(body).get("auth_req_id") : null;
        if (!(id instanceof String) || !id.equals(flow.get("authReqId"))) throw new IllegalStateException("ciba: ping callback auth_req_id does not match this flow");
        return (String) id;
    }
}
