package net.atlasauth.pca.wallet;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.oauth.JsVal;

/**
 * Framework-neutral handlers for the two wallet endpoints named in the session root: the question endpoint (a site delivers, or an
 * agent relays unchanged, a site-signed intent_required with the attempted action) and the clarification endpoint. The HTTP
 * routes live with the session store; these functions are what such a route calls, so the wire behaviour is fixed and tested here.
 * Neither response carries p or any map content: the caller learns a question id, a dry-run verdict, or a refusal code, exactly
 * what an attempt would teach it. A response is {status, body}.
 */
public final class WalletHandlers {
    private WalletHandlers() {}

    /** Finds the channel of a session, or null. */
    public interface ChannelResolver { TrustedChannel resolve(String sessionId); }

    private static final Map<String, Integer> STATUS_OF_REFUSAL = Map.ofEntries(
        Map.entry("bad_site_signature", 401), Map.entry("wrong_session", 409), Map.entry("stale_map", 409), Map.entry("action_mismatch", 422),
        Map.entry("cell_mismatch", 422), Map.entry("not_uncertain", 409), Map.entry("already_asked", 409), Map.entry("frozen", 429),
        Map.entry("cap_session", 429), Map.entry("cap_hour", 429), Map.entry("cell_too_large", 422), Map.entry("bad_request", 400), Map.entry("render_failed", 422));

    private static Map<String, Object> resp(int status, Map<String, Object> body) { return Wallet.obj("status", JsVal.n(status), "body", body); }

    private static Map<String, Object> actionOf(Object v) {
        if (!Wallet.isObj(v)) return null;
        Map<?, ?> m = (Map<?, ?>) v;
        if (!(m.get("verb") instanceof String) || !(m.get("resource") instanceof String) || !(m.get("reversibility_class") instanceof String) || !Wallet.isObj(m.get("params"))) return null;
        for (Object k : m.keySet()) if (!List.of("verb", "resource", "params", "reversibility_class").contains(k)) return null;
        return Wallet.obj("verb", m.get("verb"), "resource", m.get("resource"), "params", m.get("params"), "reversibility_class", m.get("reversibility_class"));
    }

    /** The question endpoint: POST {intent_required, action} to a session. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> question(ChannelResolver resolve, String sessionId, Object body) {
        TrustedChannel ch = resolve.resolve(sessionId);
        if (ch == null) return resp(404, Wallet.obj("error", "unknown_session"));
        if (!Wallet.isObj(body)) return resp(400, Wallet.obj("error", "bad_request"));
        for (Object k : ((Map<?, ?>) body).keySet())
            if (!"intent_required".equals(k) && !"action".equals(k)) return resp(400, Wallet.obj("error", "bad_request", "detail", "unknown member \"" + k + "\""));
        Map<String, Object> action = actionOf(((Map<?, ?>) body).get("action"));
        Object ir = ((Map<?, ?>) body).get("intent_required");
        if (action == null || !Wallet.isObj(ir)) return resp(400, Wallet.obj("error", "bad_request"));
        Map<String, Object> r = ch.receive((Map<String, Object>) ir, action);
        if (Boolean.TRUE.equals(r.get("ok"))) return resp(202, Wallet.obj("question_id", r.get("questionId"), "friction", r.get("friction")));
        Integer st = STATUS_OF_REFUSAL.get(r.get("code"));
        return resp(st != null ? st : 400, Wallet.obj("error", r.get("code")));
    }

    /** The clarification endpoint: POST {candidates, reason} to a session. */
    public static Map<String, Object> clarify(ChannelResolver resolve, String sessionId, Object body) {
        TrustedChannel ch = resolve.resolve(sessionId);
        if (ch == null) return resp(404, Wallet.obj("error", "unknown_session"));
        Map<String, Object> r = ch.clarify(body);
        if (r.containsKey("error")) return resp(400, Wallet.obj("error", "bad_request", "detail", r.get("error")));
        Map<String, Object> b = Wallet.obj("verdicts", r.get("verdicts"));
        if (r.containsKey("questionId")) b.put("question_id", r.get("questionId"));
        if (r.containsKey("refused")) b.put("refused", r.get("refused"));
        return Wallet.obj("status", r.get("status"), "body", b);
    }
}
