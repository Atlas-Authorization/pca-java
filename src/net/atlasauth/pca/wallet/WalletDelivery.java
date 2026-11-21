package net.atlasauth.pca.wallet;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.WalletBridge;
import net.atlasauth.pca.oauth.JsVal;

/**
 * Question delivery over approval-channel transports. A delivery only tells the principal's device that a question is waiting and
 * hands it the SIGNED question. It never carries a rendered card, agent text, the map, or p. A site question carries the
 * site-signed intent_required body exactly as received (the device re-verifies it and renders the card itself); a
 * wallet-originated question (an agent clarification) carries only its session and question id; text surfaces (email, SMS, push)
 * use one fixed template. Notices and deliveries are maps; a delivery is {kind, questionId, payload, delivered, status?, reason?}.
 */
public final class WalletDelivery {
    private WalletDelivery() {}

    private static boolean truthyString(Object o) { return o instanceof String && !((String) o).isEmpty(); }

    /**
     * A notice for a site-signed question. {@code keys} are the site's discovery keys, {@code site} the verified origin, {@code now}
     * the clock; {@code inboxUrl} may be null. Throws when the signature or expiry does not verify (nothing unsigned leaves).
     */
    public static Map<String, Object> siteQuestionNotice(Map<String, Object> ir, Object keys, Object site, Object now, Object inboxUrl) {
        String bad = WalletBridge.verifyIntentRequired(ir, keys, now);
        if (bad != null) throw new IllegalArgumentException("siteQuestionNotice: " + bad);
        Map<String, Object> n = Wallet.obj("type", "pca.intent.question", "session", ir.get("session"), "question_id", ir.get("question_id"), "site", site,
            "friction", ir.get("friction"), "expires_at", ir.get("expires_at"), "intent_required", ir);
        if (truthyString(inboxUrl)) n.put("inbox_url", inboxUrl);
        return n;
    }

    /** A notice for a wallet-originated question (clarification): ids only. */
    public static Map<String, Object> clarificationNotice(Object session, Object questionId, Object inboxUrl) {
        Map<String, Object> n = Wallet.obj("type", "pca.intent.clarification", "session", session, "question_id", questionId);
        if (truthyString(inboxUrl)) n.put("inbox_url", inboxUrl);
        return n;
    }

    /** A channel that delivers a notice: its kind, whether it is configured, and the delivery attempt. */
    public interface QuestionChannel {
        String kind();

        boolean enabled();

        Map<String, Object> notify(Map<String, Object> notice);
    }

    /** The result of the webhook transport: whether the response was 2xx and its status. */
    public static final class TransportResult {
        public final boolean ok;
        public final int status;

        public TransportResult(boolean ok, int status) { this.ok = ok; this.status = status; }
    }

    /** The webhook transport: POST {@code body} with {@code headers} to {@code url}. */
    public interface Transport {
        TransportResult post(String url, Map<String, String> headers, String body) throws Exception;
    }

    /** The default transport over {@code java.net.http.HttpClient}. */
    public static Transport defaultTransport() {
        HttpClient client = HttpClient.newHttpClient();
        return (url, headers, body) -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
            for (Map.Entry<String, String> h : headers.entrySet()) b.header(h.getKey(), h.getValue());
            HttpResponse<Void> r = client.send(b.build(), HttpResponse.BodyHandlers.discarding());
            return new TransportResult(r.statusCode() >= 200 && r.statusCode() < 300, r.statusCode());
        };
    }

    private static Map<String, Object> delivery(String kind, Object questionId, Object payload) {
        return Wallet.obj("kind", kind, "questionId", questionId, "payload", payload);
    }

    /** Webhook delivery (the principal's own wallet push endpoint): the JSON notice, signed question included. */
    public static QuestionChannel questionWebhookChannel(String url, Map<String, String> extraHeaders, Transport transport) {
        final boolean enabled = url != null && !url.isEmpty();
        final Transport tr = transport != null ? transport : defaultTransport();
        final Map<String, String> headers = new LinkedHashMap<>();
        headers.put("content-type", "application/json");
        if (extraHeaders != null) headers.putAll(extraHeaders);
        return new QuestionChannel() {
            @Override public String kind() { return "webhook"; }

            @Override public boolean enabled() { return enabled; }

            @Override public Map<String, Object> notify(Map<String, Object> notice) {
                Map<String, Object> d = delivery("webhook", notice.get("question_id"), notice);
                if (!enabled) { d.put("delivered", false); d.put("reason", "webhook channel not configured"); return d; }
                try {
                    TransportResult res = tr.post(url, headers, jsonStringify(notice));
                    d.put("delivered", res.ok);
                    d.put("status", (long) res.status);
                    if (!res.ok) d.put("reason", "webhook returned " + res.status);
                    return d;
                } catch (Exception err) {
                    d.put("delivered", false);
                    d.put("reason", err.getMessage() == null ? "" : err.getMessage());
                    return d;
                }
            }
        };
    }

    /** {@code encodeURIComponent}. */
    public static String encodeUriComponent(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "-_.!~*'()".indexOf(c) >= 0) { sb.append(c); continue; }
            int cp;
            if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { cp = Character.toCodePoint(c, s.charAt(i + 1)); i++; }
            else if (Character.isSurrogate(c)) throw new IllegalArgumentException("URI malformed");
            else cp = c;
            for (byte x : Json.utf8(new String(Character.toChars(cp)))) sb.append('%').append(String.format("%02X", x & 0xff));
        }
        return sb.toString();
    }

    /** The fixed text of a text-surface notice: {subject, text}. */
    public static Map<String, Object> questionText(Map<String, Object> notice, String siteName) {
        boolean question = "pca.intent.question".equals(notice.get("type"));
        String clean = WalletCard.cleanText(siteName, 64);
        String who = question ? (clean.isEmpty() ? "A site" : clean) : "Your agent";
        String subject = question ? who + " has a question about your request" : who + " needs a decision about your request";
        Object inbox = notice.get("inbox_url");
        String link = null;
        if (truthyString(inbox)) link = inbox + (((String) inbox).contains("?") ? "&" : "?") + "question=" + encodeUriComponent(String.valueOf(notice.get("question_id")));
        return Wallet.obj("subject", subject, "text", subject + "\n\n" + (link != null ? "Open your wallet to answer: " + link : "Open your wallet to answer."));
    }

    /** The email / SMS / push sender port: gets {subject, text}. */
    public interface TextSender {
        void send(Map<String, Object> body) throws Exception;
    }

    /** Email / SMS / push delivery through a sender port (fixed text only); {@code send} may be null (disabled). */
    public static QuestionChannel questionTextChannel(String kind, TextSender send, String siteName) {
        final boolean enabled = send != null;
        return new QuestionChannel() {
            @Override public String kind() { return kind; }

            @Override public boolean enabled() { return enabled; }

            @Override public Map<String, Object> notify(Map<String, Object> notice) {
                Map<String, Object> body = questionText(notice, siteName);
                Map<String, Object> d = delivery(kind, notice.get("question_id"), body);
                if (!enabled) { d.put("delivered", false); d.put("reason", kind + " channel not configured"); return d; }
                try {
                    send.send(body);
                    d.put("delivered", true);
                    return d;
                } catch (Exception err) {
                    d.put("delivered", false);
                    d.put("reason", err.getMessage() == null ? "" : err.getMessage());
                    return d;
                }
            }
        };
    }

    /** Fan a notice out to every enabled channel (disabled channels are skipped). */
    public static List<Map<String, Object>> notifyAll(List<QuestionChannel> channels, Map<String, Object> notice) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (QuestionChannel c : channels) if (c.enabled()) out.add(c.notify(notice));
        return out;
    }

    // ---- JSON.stringify ---------------------------------------------------------------------------------------------------

    /** {@code JSON.stringify} of a parsed value: insertion-ordered members, numbers as JavaScript prints them ({@code -0} as 0). */
    public static String jsonStringify(Object v) {
        StringBuilder sb = new StringBuilder();
        ser(sb, v);
        return sb.toString();
    }

    private static void ser(StringBuilder sb, Object v) {
        if (v == null) sb.append("null");
        else if (v instanceof String) sb.append(WalletBox.jsonString((String) v));
        else if (v instanceof Boolean) sb.append(v);
        else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append(WalletBox.jsonString((String) e.getKey())).append(':');
                ser(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                ser(sb, x);
            }
            sb.append(']');
        } else if (JsVal.isNumber(v)) {
            Double d = JsVal.num(v);
            if (Double.isNaN(d) || Double.isInfinite(d)) sb.append("null");
            else if (d == 0) sb.append('0');
            else sb.append(((Json.Num) IntentJs.normalize(v instanceof Json.Num ? v : new Json.Num(String.valueOf(v)))).raw);
        } else sb.append("null");
    }
}
