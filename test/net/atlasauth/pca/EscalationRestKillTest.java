package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** 0.5 mutation kills for {@link Escalation}: exact shape reasons, request fields, wire escaping, verify edges. */
public class EscalationRestKillTest {
    static final long MAX_SAFE = 9007199254740991L;

    static String canon(Object v) { return Json.canonicalize(IntentJs.normalize(v)); }

    static String shape(String k, Object v) throws Exception {
        Map<String, Object> over = new LinkedHashMap<>();
        over.put(k, v);
        return Escalation.answerShapeError(EscalationTest.answer(null, over));
    }

    @Test void answerShapeReasons() throws Exception {
        assertNull(Escalation.answerShapeError(EscalationTest.answer(null, null)));
        assertEquals("not a pca-escalation-answer v1", shape("v", IntentJs.ofLong(2)));
        assertEquals("not a pca-escalation-answer v1", shape("v", "1"));
        assertEquals("not a pca-escalation-answer v1", shape("kind", "pca-escalation-request"));
        assertEquals("principal must be canonical base64url (32 bytes)", shape("principal", IntentJs.ofLong(7)));
        assertEquals("principal must be canonical base64url (32 bytes)", shape("principal", "A".repeat(65)));
        assertEquals("iat and expires_at must be non-negative safe integers", shape("iat", IntentJs.ofLong(-1)));
        assertEquals("iat and expires_at must be non-negative safe integers", shape("expires_at", IntentJs.ofLong(-1)));
        assertEquals("nonce must be canonical base64url of at least 16 bytes", shape("nonce", IntentJs.ofLong(5)));
        assertEquals("nonce must be canonical base64url of at least 16 bytes", shape("nonce", "AAAA"));
    }

    @Test void requestCarriesEveryField() {
        Map<String, Object> g = EscalationTest.grant(), p = EscalationTest.pcactn();
        Map<?, ?> act = (Map<?, ?>) p.get("action");
        Map<String, Object> r = Escalation.buildRequest("aud1", g, p, 7L, List.of("x".repeat(513), "y".repeat(512)), 1000L, "RD");
        Map<String, Object> w = new LinkedHashMap<>();
        w.put("v", IntentJs.ofLong(1));
        w.put("kind", "pca-escalation-request");
        w.put("aud", "aud1");
        w.put("policy_digest", Escalation.policyDigest(g));
        w.put("action_digest", Escalation.actionDigest(p));
        w.put("history_head", Escalation.historyHead(7L));
        w.put("verb", act.get("verb"));
        w.put("resource", act.get("resource"));
        w.put("reasons", List.of("x".repeat(512), "y".repeat(512)));
        w.put("expires_at", IntentJs.ofLong(3_601_000L));
        w.put("render_digest", "RD");
        assertEquals(canon(w), canon(r));
        w.remove("render_digest");
        w.put("history_head", Escalation.historyHead(null));
        assertEquals(canon(w), canon(Escalation.buildRequest("aud1", g, p, null, List.of("x".repeat(513), "y".repeat(512)), 1000L)));
    }

    @Test void historyHeadUsesTheCounterValue() {
        assertNotEquals(Escalation.historyHead(0L), Escalation.historyHead(5L));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", Escalation.HISTORY_DOMAIN);
        m.put("last_counter", IntentJs.ofLong(5));
        assertEquals(Pca.hashCanonical(m), Escalation.historyHead(5L));
    }

    @Test void reasonsWireSurrogates() {
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("reasons", List.of("a\uDE00", "\uD83Dx", "\uD83D\uDE00", "q\"\\\n"));
        assertEquals("[\"a\\ude00\",\"\\ud83dx\",\"\uD83D\uDE00\",\"q\\\"\\\\\\n\"]", Escalation.reasonsWire(req));
    }

    @Test void verifyEdges() throws Exception {
        Escalation.Binding b = new Escalation.Binding("p", "a", "h");
        assertEquals("malformed escalation answer: not an object", Escalation.verify(null, List.of(), b, MAX_SAFE).reason);
        assertEquals("malformed escalation answer: not an object", Escalation.verify(null, List.of(), b, -MAX_SAFE).reason);
        assertEquals("the verifier clock is not a safe integer (fail closed)", Escalation.verify(null, List.of(), b, MAX_SAFE + 1).reason);
        assertEquals("the verifier clock is not a safe integer (fail closed)", Escalation.verify(null, List.of(), b, -MAX_SAFE - 1).reason);
        Map<String, Object> ans = EscalationTest.answer(null, null);
        long now = AuthorizeFixtures.now();
        Map<String, Object> other = new LinkedHashMap<>();
        other.put("pk", EscalationTest.ZERO);
        assertEquals("the answering principal is not pinned by this verifier", Escalation.verify(ans, List.of(other), b, now).reason);
        assertEquals("the answering principal is not pinned by this verifier", Escalation.verify(ans, List.of(7), b, now).reason);
        Escalation.Result e = Escalation.verify(ans, List.of(EscalationTest.pub()), null, now);
        assertFalse(e.ok);
        assertEquals("escalation answer error (fail closed): NullPointerException", e.reason);
        assertEquals("Result{escalation answer error (fail closed): NullPointerException}", e.toString());
        Escalation.Binding good = new Escalation.Binding(Escalation.policyDigest(EscalationTest.grant()),
            Escalation.actionDigest(EscalationTest.pcactn()), Escalation.historyHead(null));
        Escalation.Result ok = Escalation.verify(ans, List.of(EscalationTest.pub()), good, now);
        assertTrue(ok.ok, ok.reason);
        assertEquals("Result{ok, " + EscalationTest.pub() + ", allow}", ok.toString());
    }
}
