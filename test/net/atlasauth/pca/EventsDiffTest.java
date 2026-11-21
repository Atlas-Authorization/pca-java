package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.events.Events;
import org.junit.jupiter.api.Test;

class EventsDiffTest {
    private static final String M = "ref-events";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    /** A secret: a JSON string, {"$bytes": b64u} for a byte secret, any other value as is. */
    private static Object secret(Object o) {
        if (o instanceof Map && ((Map<?, ?>) o).get("$bytes") instanceof String) return Keys.unb64u((String) ((Map<?, ?>) o).get("$bytes"));
        return o;
    }

    private static String str(Object o) { return (String) o; }

    @Test void buildStepUpEvent() throws Exception { OracleCases.each(M, "buildStepUpEvent", a -> Events.buildStepUpEvent(a.get(0), a.get(1))); }

    @Test void serializeEvent() throws Exception { OracleCases.each(M, "serializeEvent", a -> Events.serializeEvent(a.get(0))); }

    @Test void parseEvent() throws Exception {
        OracleCases.each(M, "parseEvent", a -> {
            if (!(a.get(0) instanceof String)) throw new IllegalArgumentException("not a string");
            return Events.parseEvent(str(a.get(0)));
        });
    }

    @Test void signWebhook() throws Exception { OracleCases.each(M, "signWebhook", a -> Events.signWebhook(secret(a.get(0)), str(a.get(1)), map(a.get(2)))); }

    @Test void verifyWebhook() throws Exception { OracleCases.each(M, "verifyWebhook", a -> Events.verifyWebhook(secret(a.get(0)), str(a.get(1)), a.get(2), map(a.get(3)))); }

    @Test void webhookHeaders() throws Exception { OracleCases.each(M, "webhookHeaders", a -> Events.webhookHeaders(secret(a.get(0)), str(a.get(1)), map(a.get(2)))); }

    @Test void minSecretBytes() throws Exception { OracleCases.each(M, "minSecretBytes", a -> Events.MIN_SECRET_BYTES); }

    @Test void deliveries() throws Exception {
        OracleCases.each(M, "deliveryScenario", a -> {
            Map<String, Object> spec = map(a.get(0));
            Object st = spec.get("store");
            StateStore store = "throws".equals(st) ? new StateStore() {
                @Override public ClaimResult claim(String key, long counter) { throw new IllegalStateException("down"); }
                @Override public boolean consumeOnce(String key, long retainUntilMs, long nowMs) { throw new IllegalStateException("down"); }
            } : "refuses".equals(st) ? new StateStore() {
                @Override public ClaimResult claim(String key, long counter) { throw new IllegalStateException("unused"); }
                @Override public boolean consumeOnce(String key, long retainUntilMs, long nowMs) { return false; }
            } : new MemoryStateStore();
            boolean noReplay = Boolean.TRUE.equals(spec.get("noReplay")), noOpts = Boolean.TRUE.equals(spec.get("noOpts"));
            List<Object> out = new ArrayList<>();
            for (Object dO : (List<?>) spec.get("deliveries")) {
                Map<String, Object> d = map(dO);
                Map<String, Object> opts = new LinkedHashMap<>();
                if (d.get("opts") != null) opts.putAll(map(d.get("opts")));
                boolean replayNulled = opts.containsKey("replay");
                opts.remove("replay");
                Object sec = secret(d.containsKey("secret") ? d.get("secret") : "whsec_0123456789abcdef0123456789");
                Events.DeliveryVerdict v = Events.verifyDelivery(sec, str(d.get("payload")), d.get("header"), noReplay || replayNulled ? null : store, noOpts ? null : opts);
                Map<String, Object> m = v.toMap();
                if (!v.ok && v.reason != null) {
                    if (v.reason.startsWith("canonicalize:")) m.put("reason", "<canonicalize>");
                    else if (v.reason.startsWith(Events.SYNTAX_PREFIX)) m.put("reason", "<json>");
                }
                out.add(m);
            }
            return out;
        });
    }

    @Test void signAndVerifyWithTheClock() {
        String secret = "whsec_0123456789abcdef0123456789";
        String sig = Events.signWebhook(secret, "body", null);
        assertTrue(Events.verifyWebhook(secret, "body", sig, null));
        assertFalse(Events.verifyWebhook(secret, "other", sig, null));
        Map<String, Object> e = Events.buildStepUpEvent("step_up.created", map(Json.parseLenient("{\"grant_ref\":\"g\",\"action\":{\"verb\":\"v\",\"resource\":\"r\"},\"tier\":2}")));
        assertNotNull(e.get("at"));
        assertEquals(e.get("id"), Events.parseEvent(Events.serializeEvent(e)).get("id"));
        assertEquals(Events.MIN_SECRET_BYTES, 16);
    }
}
