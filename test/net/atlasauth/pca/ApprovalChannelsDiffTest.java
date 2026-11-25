package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The approval-channel layer against the reference corpus (payload builders, every channel kind, the dispatcher). */
public class ApprovalChannelsDiffTest {
    private static final String MOD = "ref-core-approval-channels";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static ApprovalChannels.NotifyContext ctx(Object c) {
        ApprovalChannels.NotifyContext n = new ApprovalChannels.NotifyContext();
        if (c instanceof Map && m(c).get("inboxUrl") instanceof String) n.inboxUrl = (String) m(c).get("inboxUrl");
        return n;
    }

    private static ApprovalChannels.FetchLike transport(String mode) {
        return (url, headers, body) -> {
            switch (mode) {
                case "ok": return new ApprovalChannels.Response(true, 200);
                case "http500": return new ApprovalChannels.Response(false, 500);
                case "throw": throw new IllegalStateException("boom");
                default: throw new IllegalStateException("");
            }
        };
    }

    private static ApprovalChannels.Channel channel(String kind, Map<String, Object> cfg) {
        boolean configured = Boolean.TRUE.equals(cfg.get("configured"));
        String t = (String) cfg.get("transport");
        ApprovalChannels.FetchLike f = transport(t);
        if (kind.equals("slack")) return ApprovalChannels.slackApprovalChannel(configured ? "https://hooks.example/secret" : null, f);
        if (kind.equals("webhook")) {
            Map<String, String> h = new LinkedHashMap<>();
            if (cfg.get("headers") instanceof Map) for (Map.Entry<String, Object> e : m(cfg.get("headers")).entrySet()) h.put(e.getKey(), (String) e.getValue());
            return ApprovalChannels.webhookApprovalChannel(configured ? "https://hooks.example/secret" : null, f, h);
        }
        ApprovalChannels.TextSender sender = (subject, text) -> {
            if (t.equals("ok")) return "m1";
            throw new IllegalStateException(t.equals("throw-empty") ? "" : "boom");
        };
        return ApprovalChannels.textApprovalChannel(kind, configured ? sender : null);
    }

    private static Map<String, Object> out(ApprovalChannels.Delivery d) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("kind", d.kind);
        r.put("requestId", d.requestId);
        r.put("delivered", d.delivered);
        r.put("payload", d.payload);
        if (d.status != null) r.put("status", d.status);
        if (d.reason != null) r.put("reason", d.reason);
        return r;
    }

    @Test void actionSummary() throws Exception { OracleCases.each(MOD, "actionSummary", a -> ApprovalChannels.actionSummary(m(a.get(0)))); }
    @Test void lineageLines() throws Exception { OracleCases.each(MOD, "lineageLines", a -> ApprovalChannels.lineageLines(m(a.get(0)))); }
    @Test void renderLines() throws Exception { OracleCases.each(MOD, "renderLines", a -> ApprovalChannels.renderLines(m(a.get(0)))); }
    @Test void buildSlackMessage() throws Exception { OracleCases.each(MOD, "buildSlackMessage", a -> ApprovalChannels.buildSlackMessage(m(a.get(0)), ctx(a.get(1)))); }
    @Test void buildWebhookBody() throws Exception { OracleCases.each(MOD, "buildWebhookBody", a -> ApprovalChannels.buildWebhookBody(m(a.get(0)), ctx(a.get(1)))); }
    @Test void buildTextBody() throws Exception { OracleCases.each(MOD, "buildTextBody", a -> ApprovalChannels.buildTextBody(m(a.get(0)), ctx(a.get(1)))); }

    @Test void notifyChannel() throws Exception {
        OracleCases.each(MOD, "notify", a -> out(channel((String) a.get(0), m(a.get(3))).notify(m(a.get(1)), ctx(a.get(2)))));
    }

    @Test void dispatcherNotifyAll() throws Exception {
        OracleCases.each(MOD, "notifyAll", a -> {
            List<ApprovalChannels.Channel> chans = new ArrayList<>();
            for (Object c : (List<?>) a.get(2)) chans.add(channel((String) m(c).get("kind"), m(c)));
            List<Object> res = new ArrayList<>();
            for (ApprovalChannels.Delivery d : ApprovalChannels.createApprovalDispatcher(chans).notifyAll(m(a.get(0)), ctx(a.get(1)))) res.add(out(d));
            return res;
        });
    }
}
