package net.atlasauth.pca;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Approval-notification channels for step-ups (the channel layer over {@link Approvals}): each channel FORMATS a human-readable
 * notification of a pending step-up request (the action summary, the "because you asked to ..." goal lineage, the canonical
 * render with its match words, an approve / deny affordance or an inbox link) and DISPATCHES it over an injected transport.
 *
 * <p>A channel is gated by its configuration (an unconfigured one reports {@code enabled() == false} and never dispatches), its
 * transport is injected (default: the JDK HTTP client), and what it returns never carries the webhook URL, a token or a signing
 * secret. A channel only reports a step-up the verifier already produced; it authorizes nothing.
 *
 * <p>A step-up request is the plain map {@link Approvals} produces ({@code id, verb, resource, tier, reason, lineage, r, render?,
 * renderDigest?, ...}).
 */
public final class ApprovalChannels {
    private ApprovalChannels() {}

    /** The HTTP surface a channel needs: POST {@code body} with {@code headers} to {@code url}. */
    public interface FetchLike {
        Response post(String url, Map<String, String> headers, String body) throws Exception;
    }

    public static final class Response {
        public final boolean ok;
        public final int status;
        public Response(boolean ok, int status) { this.ok = ok; this.status = status; }
    }

    /** Deliver a formatted text body; returns a channel-native message id (or null). A failure throws. */
    public interface TextSender {
        String send(String subject, String text) throws Exception;
    }

    /** Context of a notification: where the human approves. */
    public static final class NotifyContext {
        public String inboxUrl;
        public Long now;
        public NotifyContext() {}
        public NotifyContext(String inboxUrl) { this.inboxUrl = inboxUrl; }
    }

    /** The outcome of one delivery attempt. {@code payload} is the formatted, secret-free message. */
    public static final class Delivery {
        public final String kind, requestId, reason;
        public final boolean delivered;
        public final Object payload;
        public final Integer status;
        Delivery(String kind, String requestId, boolean delivered, Object payload, Integer status, String reason) {
            this.kind = kind; this.requestId = requestId; this.delivered = delivered; this.payload = payload; this.status = status; this.reason = reason;
        }
    }

    /** The common channel contract. */
    public interface Channel {
        /** {@code slack}, {@code webhook}, {@code email}, {@code push} or {@code sms}. */
        String kind();
        /** True iff the channel is configured enough to deliver. */
        boolean enabled();
        /** Format the step-up for this channel and dispatch it. Never throws: a failure is a not-delivered outcome. */
        Delivery notify(Map<String, Object> request, NotifyContext ctx);
    }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return o instanceof Map ? (Map<String, Object>) o : new LinkedHashMap<>(); }

    private static String str(Object o) { return AttestNvidia.jsString(o); }

    private static String id(Map<String, Object> request) { return str(request.get("id")); }

    /** The default transport: a JSON POST over the JDK HTTP client. */
    public static FetchLike defaultFetch() {
        HttpClient client = HttpClient.newHttpClient();
        return (url, headers, body) -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
            for (Map.Entry<String, String> h : headers.entrySet()) b.header(h.getKey(), h.getValue());
            HttpResponse<Void> r = client.send(b.build(), HttpResponse.BodyHandlers.discarding());
            return new Response(r.statusCode() >= 200 && r.statusCode() < 300, r.statusCode());
        };
    }

    // ---- human-readable formatting (shared by every channel) ----

    /** One-line action summary: {@code verb on resource (tier N, risk R)}. */
    public static String actionSummary(Map<String, Object> request) {
        Double r = StoreJs.dbl(request.get("r"));
        String risk = r == null || r.isNaN() ? "NaN" : r.isInfinite() ? (r > 0 ? "Infinity" : "-Infinity")
            : new BigDecimal(r).setScale(2, RoundingMode.HALF_UP).toPlainString();
        return str(request.get("verb")) + " on " + str(request.get("resource")) + " (tier " + str(request.get("tier")) + ", risk " + risk + ")";
    }

    /** The lines a human reads to understand why: the "because" sentence, the goal chain, then the canonical render. */
    public static List<String> lineageLines(Map<String, Object> request) {
        if (!(request.get("lineage") instanceof Map)) throw new IllegalArgumentException("lineageLines: the request has no lineage");
        Map<String, Object> lineage = map(request.get("lineage"));
        List<String> out = new ArrayList<>();
        out.add(str(lineage.get("because")));
        for (Object l : Approvals.describeGoalLineage(lineage)) out.add(str(l));
        out.addAll(renderLines(request));
        return out;
    }

    /**
     * The canonical render, one line per field (nothing omitted), the banner for an unreviewed action and the speakable match words
     * of the render digest. Empty when the request carries no render.
     */
    public static List<String> renderLines(Map<String, Object> request) {
        Object r = request.get("render");
        if (!(r instanceof Map) || request.get("renderDigest") == null) return new ArrayList<>();
        Map<String, Object> render = map(r);
        List<String> out = new ArrayList<>();
        if (Boolean.TRUE.equals(render.get("unreviewed")))
            out.add("UNREVIEWED ACTION: its definition has not been confirmed, so every value is shown raw and one-tap approval is disabled.");
        Object fields = render.get("fields");
        if (fields instanceof List) for (Object fo : (List<?>) fields) {
            Map<String, Object> f = map(fo);
            Map<String, Object> unit = map(f.get("unit"));
            String u = "money".equals(unit.get("kind")) ? " " + str(unit.get("ccy")) + " (minor units, exponent " + str(unit.get("exp")) + ")" : "";
            out.add(str(f.get("id")) + " [" + str(f.get("class")) + "]: " + escapeControl(Json.stringify(f.get("value"))) + u);
        }
        out.add("Match code: " + Approval.bindingWords(request.get("renderDigest")));
        return out;
    }

    /** Replace control and format characters and U+2028/2029 with {@code \}{@code u{hex}}, as the reference prints a value. */
    private static String escapeControl(String s) {
        StringBuilder sb = new StringBuilder();
        s.codePoints().forEach(cp -> {
            int t = Character.getType(cp);
            if (t == Character.CONTROL || t == Character.FORMAT || cp == 0x2028 || cp == 0x2029) sb.append("\\u{").append(Integer.toHexString(cp)).append('}');
            else sb.appendCodePoint(cp);
        });
        return sb.toString();
    }

    /** Add query parameters before any {@code #fragment} (an approval link may carry its token there, which must stay last). */
    static String appendQuery(String url, String... kv) {
        StringBuilder q = new StringBuilder();
        for (int i = 0; i < kv.length; i += 2) {
            if (i > 0) q.append('&');
            q.append(enc(kv[i])).append('=').append(enc(kv[i + 1]));
        }
        int hash = url.indexOf('#');
        String base = hash == -1 ? url : url.substring(0, hash);
        String fragment = hash == -1 ? "" : url.substring(hash);
        return base + (base.contains("?") ? "&" : "?") + q + fragment;
    }

    /** {@code encodeURIComponent}: everything but {@code A-Za-z0-9 - _ . ! ~ * ' ( )} is percent-encoded. */
    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20").replace("%21", "!").replace("%27", "'").replace("%28", "(")
            .replace("%29", ")").replace("%7E", "~");
    }

    private static boolean hasInbox(NotifyContext ctx) { return ctx != null && ctx.inboxUrl != null && !ctx.inboxUrl.isEmpty(); }

    // ---- Slack (Block Kit over an incoming webhook) ----

    /** The Block Kit message for a step-up: action summary, goal lineage, approve / deny affordance. */
    public static Map<String, Object> buildSlackMessage(Map<String, Object> request, NotifyContext ctx) {
        List<Object> blocks = new ArrayList<>();
        blocks.add(obj("type", "header", "text", obj("type", "plain_text", "text", "Approval needed · tier " + str(request.get("tier")), "emoji", true)));
        blocks.add(obj("type", "section", "text", obj("type", "mrkdwn", "text", "*" + str(request.get("verb")) + "* on `" + str(request.get("resource")) + "`\n_" + str(request.get("reason")) + "_")));
        StringBuilder why = new StringBuilder("*Why this is requested*\n");
        boolean first = true;
        for (String l : lineageLines(request)) {
            if (!first) why.append('\n');
            first = false;
            why.append("• ").append(l);
        }
        blocks.add(obj("type", "section", "text", obj("type", "mrkdwn", "text", why.toString())));
        if (hasInbox(ctx)) {
            String rid = str(request.get("id"));
            List<Object> els = new ArrayList<>();
            els.add(obj("type", "button", "text", obj("type", "plain_text", "text", "Approve", "emoji", true), "url", appendQuery(ctx.inboxUrl, "stepup", rid, "decision", "approve"), "style", "primary", "action_id", "pca_approve"));
            els.add(obj("type", "button", "text", obj("type", "plain_text", "text", "Deny", "emoji", true), "url", appendQuery(ctx.inboxUrl, "stepup", rid, "decision", "deny"), "style", "danger", "action_id", "pca_deny"));
            blocks.add(obj("type", "actions", "elements", els));
        } else {
            List<Object> els = new ArrayList<>();
            els.add(obj("type", "mrkdwn", "text", "Approve or deny step-up `" + str(request.get("id")) + "` in your Atlas inbox."));
            blocks.add(obj("type", "context", "elements", els));
        }
        return obj("text", "Approval needed: " + actionSummary(request), "blocks", blocks);
    }

    private static Delivery post(String kind, FetchLike transport, String url, Map<String, String> headers, Map<String, Object> request, Object payload, String name) {
        String rid = id(request);
        try {
            Response res = transport.post(url, headers, Json.stringify(payload));
            return res.ok ? new Delivery(kind, rid, true, payload, res.status, null)
                : new Delivery(kind, rid, false, payload, res.status, name + " returned " + res.status);
        } catch (Exception err) {
            return new Delivery(kind, rid, false, payload, null, err.getMessage() != null ? err.getMessage() : name + " transport error");
        }
    }

    /** Slack approval channel. Disabled (and a no-op) unless a webhook URL is configured; {@code fetch} null = the JDK client. */
    public static Channel slackApprovalChannel(String webhookUrl, FetchLike fetch) {
        final boolean enabled = webhookUrl != null && !webhookUrl.isEmpty();
        final FetchLike transport = fetch != null ? fetch : defaultFetch();
        return new Channel() {
            @Override public String kind() { return "slack"; }
            @Override public boolean enabled() { return enabled; }
            @Override public Delivery notify(Map<String, Object> request, NotifyContext ctx) {
                Map<String, Object> message = buildSlackMessage(request, ctx);
                if (!enabled) return new Delivery("slack", id(request), false, message, null, "slack channel not configured");
                Map<String, String> h = new LinkedHashMap<>();
                h.put("content-type", "application/json");
                return post("slack", transport, webhookUrl, h, request, message, "slack webhook");
            }
        };
    }

    // ---- generic webhook ----

    /** The webhook body: the step-up plus its pre-formatted human summary and lineage. */
    public static Map<String, Object> buildWebhookBody(Map<String, Object> request, NotifyContext ctx) {
        Map<String, Object> m = obj("type", "pca.step_up.created", "stepup", request, "summary", actionSummary(request), "lineage", new ArrayList<Object>(lineageLines(request)));
        if (hasInbox(ctx)) m.put("inbox_url", ctx.inboxUrl);
        return m;
    }

    /** Generic webhook approval channel. {@code headers} are extra request headers (never logged); disabled without a URL. */
    public static Channel webhookApprovalChannel(String url, FetchLike fetch, Map<String, String> headers) {
        final boolean enabled = url != null && !url.isEmpty();
        final FetchLike transport = fetch != null ? fetch : defaultFetch();
        final Map<String, String> hs = new LinkedHashMap<>();
        hs.put("content-type", "application/json");
        if (headers != null) hs.putAll(headers);
        return new Channel() {
            @Override public String kind() { return "webhook"; }
            @Override public boolean enabled() { return enabled; }
            @Override public Delivery notify(Map<String, Object> request, NotifyContext ctx) {
                Map<String, Object> body = buildWebhookBody(request, ctx);
                if (!enabled) return new Delivery("webhook", id(request), false, body, null, "webhook channel not configured");
                return post("webhook", transport, url, hs, request, body, "webhook");
            }
        };
    }

    // ---- text channels (email / sms / push) over an injected sender ----

    /** The plain-text body ({@code subject}, {@code text}) shared by the email, sms and push surfaces. */
    public static Map<String, Object> buildTextBody(Map<String, Object> request, NotifyContext ctx) {
        List<String> lines = new ArrayList<>();
        lines.add(actionSummary(request));
        lines.add("");
        lines.addAll(lineageLines(request));
        if (hasInbox(ctx)) {
            lines.add("");
            lines.add("Approve or deny: " + appendQuery(ctx.inboxUrl, "stepup", str(request.get("id"))));
        }
        return obj("subject", "Approval needed: " + str(request.get("verb")) + " on " + str(request.get("resource")), "text", String.join("\n", lines));
    }

    /** A text-formatter channel ({@code email}, {@code sms} or {@code push}) over an injected sender; disabled without one. */
    public static Channel textApprovalChannel(String kind, TextSender send) {
        if (!"email".equals(kind) && !"sms".equals(kind) && !"push".equals(kind)) throw new IllegalArgumentException("textApprovalChannel: kind must be email, sms or push");
        final boolean enabled = send != null;
        return new Channel() {
            @Override public String kind() { return kind; }
            @Override public boolean enabled() { return enabled; }
            @Override public Delivery notify(Map<String, Object> request, NotifyContext ctx) {
                Map<String, Object> body = buildTextBody(request, ctx);
                if (!enabled) return new Delivery(kind, id(request), false, body, null, kind + " channel not configured");
                try {
                    send.send((String) body.get("subject"), (String) body.get("text"));
                    return new Delivery(kind, id(request), true, body, null, null);
                } catch (Exception err) {
                    return new Delivery(kind, id(request), false, body, null, err.getMessage() != null ? err.getMessage() : kind + " send error");
                }
            }
        };
    }

    // ---- registry / dispatcher ----

    /** One dispatcher over a set of channels; a disabled channel is skipped at {@link #notifyAll}. */
    public static final class Dispatcher {
        private final List<Channel> channels;
        Dispatcher(List<Channel> channels) { this.channels = Collections.unmodifiableList(new ArrayList<>(channels)); }
        public List<Channel> channels() { return channels; }
        /** Fan a step-up out to every enabled channel; one delivery per channel. */
        public List<Delivery> notifyAll(Map<String, Object> request, NotifyContext ctx) {
            List<Delivery> out = new ArrayList<>();
            for (Channel c : channels) if (c.enabled()) out.add(c.notify(request, ctx));
            return out;
        }
    }

    public static Dispatcher createApprovalDispatcher(List<Channel> channels) {
        return new Dispatcher(Objects.requireNonNull(channels, "channels"));
    }
}
