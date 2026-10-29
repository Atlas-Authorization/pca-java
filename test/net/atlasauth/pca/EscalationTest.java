package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import net.atlasauth.pca.servlet.PcaFilter;

/**
 * Escalation answers through authorize and the carriers: escalate is surfaced distinctly, refused without an answer, admitted
 * only by a bound principal answer spent by the replay counter, and never upgraded from a deny.
 */
public class EscalationTest {
    static final Map<String, Object> C = AuthorizeFixtures.kase("envelope-predicate-within");
    static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(AuthorizeFixtures.now()), ZoneOffset.UTC);
    static final String ZERO = Pca.b64(new byte[32]);

    @AfterEach void clearHook() { Authorize.coreHook = null; }

    /** Make the core verdict fail exactly these checks, the first with an escalate-class reason. */
    static void escalateHook(String... checks) {
        Authorize.coreHook = core -> {
            for (String c : checks) core.checks.put(c, false);
            core.allow = false;
            core.reason = "provenance: intent_required: a question is required";
        };
    }

    static byte[] seed() throws Exception {
        return Pca.decodeB64uStrict(((Map<?, ?>) ReasonSnapshot.loadJson("keys.json").get("principal")).get("seed"), 32);
    }

    static String pub() {
        try { return (String) ((Map<?, ?>) ReasonSnapshot.loadJson("keys.json").get("principal")).get("public"); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    static Map<String, Object> pcactn() { return AuthorizeFixtures.pcactn(C, 0); }
    static Map<String, Object> grant() { return AuthorizeFixtures.grant(C); }

    @SuppressWarnings("unchecked")
    static String key() {
        List<Object> chain = (List<Object>) pcactn().get("cap_chain");
        return Authorize.stateKey((String) grant().get("id"), (String) ((Map<String, Object>) chain.get(chain.size() - 1)).get("holder"));
    }

    static Map<String, Object> answer(Long last, Map<String, Object> over) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", IntentJs.ofLong(1));
        body.put("kind", "pca-escalation-answer");
        body.put("principal", pub());
        body.put("policy_digest", Escalation.policyDigest(grant()));
        body.put("action_digest", Escalation.actionDigest(pcactn()));
        body.put("history_head", Escalation.historyHead(last));
        body.put("decision", "allow");
        body.put("iat", IntentJs.ofLong(AuthorizeFixtures.now() - 1000));
        body.put("expires_at", IntentJs.ofLong(AuthorizeFixtures.now() + 600_000));
        body.put("nonce", "CQkJCQkJCQkJCQkJCQkJCQ");
        if (over != null) body.putAll(over);
        byte[] msg = Pca.concat(Escalation.ANSWER_DOMAIN.getBytes(StandardCharsets.UTF_8), Json.canonicalizeStrict(body).getBytes(StandardCharsets.UTF_8));
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(seed(), 0, msg, 0, msg.length, sig, 0);
        body.put("sig", Pca.b64(sig));
        return body;
    }

    static Authorize.Input in(StateStore store, Object answer, List<?> principals) {
        return AuthorizeFixtures.input(C, 0).stateStore(store).escalationAnswer(answer).escalationPrincipals(principals).insecureUnboundApproval(true);
    }

    @Test void escalateIsSurfacedAndRefusedWithoutAnAnswer() {
        escalateHook("provenance");
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), in(new MemoryStateStore(), null, List.of()));
        assertFalse(r.allow);
        assertEquals("escalate", r.decision);
        assertEquals(403, r.status);
        assertEquals("pca-escalation-request", r.escalation.get("kind"));
        assertEquals(List.of("provenance"), r.failed());
        assertEquals(Escalation.policyDigest(grant()), r.escalation.get("policy_digest"));
        assertEquals(Escalation.actionDigest(pcactn()), r.escalation.get("action_digest"));
        assertEquals(Escalation.historyHead(null), r.escalation.get("history_head"));
        assertEquals(AuthorizeFixtures.audience(), r.escalation.get("aud"));
        assertEquals(IntentJs.ofLong(AuthorizeFixtures.now() + 3_600_000L).raw, r.escalation.get("expires_at").toString());
    }

    @Test void aHardFailureIsDenyNotEscalate() {
        escalateHook("provenance", "leaf_signature");
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), in(new MemoryStateStore(), null, List.of()));
        assertFalse(r.allow);
        assertEquals("deny", r.decision);
        assertNull(r.escalation);
    }

    @Test void aPlainAllowAndAPlainDenyCarryTheirDecision() {
        Authorize.AuthorizeResult ok = Authorize.authorize(pcactn(), in(new MemoryStateStore(), null, List.of()));
        assertTrue(ok.allow);
        assertEquals("allow", ok.decision);
        assertNull(ok.escalation);
        Authorize.AuthorizeResult no = Authorize.authorize(pcactn(), in(new MemoryStateStore(), null, List.of()).isRevoked((p, g) -> true));
        assertFalse(no.allow);
        assertEquals("deny", no.decision);
    }

    @Test void aValidAnswerAdmitsOnceAndTheCounterSpendsIt() throws Exception {
        escalateHook("provenance");
        MemoryStateStore store = new MemoryStateStore();
        List<String> pins = List.of(pub());
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), in(store, answer(null, null), pins));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("allow", r.decision);
        assertEquals(pub(), r.escalation.get("answered_by"));
        assertEquals("pass", r.checks.get("escalation"));
        assertEquals("pass", r.checks.get("provenance"));
        assertTrue(r.reasons.stream().anyMatch(s -> s.equals("escalation: answered allow by principal " + pub().substring(0, 8))), r.reasons.toString());
        assertEquals(Long.valueOf(Json.asLong(pcactn().get("counter"))), store.last(key()));
        Authorize.AuthorizeResult again = Authorize.authorize(pcactn(), in(store, answer(store.last(key()), null), pins));
        assertFalse(again.allow);
        assertEquals("deny", again.decision);
        assertEquals("fail", again.checks.get("replay"));
    }

    @Test void unboundApprovalIsRefusedByDefault() throws Exception {
        escalateHook("provenance");
        List<String> pins = List.of(pub());
        Authorize.AuthorizeResult secure = Authorize.authorize(pcactn(), in(new MemoryStateStore(), answer(null, null), pins).insecureUnboundApproval(false));
        assertFalse(secure.allow);
        assertTrue(secure.reasons.stream().anyMatch(x -> x.contains("approval render is required")), secure.reasons.toString());
        assertTrue(Authorize.authorize(pcactn(), in(new MemoryStateStore(), answer(null, null), pins)).allow);
    }

    @Test void aPinObjectIsAccepted() throws Exception {
        escalateHook("provenance");
        Map<String, Object> pin = new LinkedHashMap<>();
        pin.put("pk", pub());
        assertTrue(Authorize.authorize(pcactn(), in(new MemoryStateStore(), answer(null, null), List.of(pin))).allow);
    }

    @Test void badAnswersStayEscalate() throws Exception {
        escalateHook("provenance");
        Map<String, Object> junk = new LinkedHashMap<>();
        junk.put("junk", IntentJs.ofLong(1));
        Map<String, Object> deny = new LinkedHashMap<>();
        deny.put("decision", "deny");
        Map<String, Object> pol = new LinkedHashMap<>();
        pol.put("policy_digest", ZERO);
        Map<String, Object> act = new LinkedHashMap<>();
        act.put("action_digest", ZERO);
        Map<String, Object> old = new LinkedHashMap<>();
        old.put("iat", IntentJs.ofLong(1));
        old.put("expires_at", IntentJs.ofLong(2));
        Map<String, Map<String, Object>> cases = new LinkedHashMap<>();
        cases.put("deny", answer(null, deny));
        cases.put("policy", answer(null, pol));
        cases.put("action", answer(null, act));
        cases.put("history", answer(99L, null));
        cases.put("expired", answer(null, old));
        cases.put("unsigned", junk);
        for (Map.Entry<String, Map<String, Object>> e : cases.entrySet()) {
            Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), in(new MemoryStateStore(), e.getValue(), List.of(pub())));
            assertFalse(r.allow, e.getKey());
            assertEquals("escalate", r.decision, e.getKey());
            assertNotNull(r.escalation, e.getKey());
            assertTrue(r.reasons.stream().anyMatch(s -> s.startsWith("escalation: ")), e.getKey() + " " + r.reasons);
        }
        assertTrue(Authorize.authorize(pcactn(), in(new MemoryStateStore(), answer(null, null), List.of(pub()))).allow, "the control answer admits");
        assertFalse(Authorize.authorize(pcactn(), in(new MemoryStateStore(), answer(null, null), List.of())).allow, "no pinned principal");
        assertFalse(Authorize.authorize(pcactn(), in(new MemoryStateStore(), answer(null, null), List.of(ZERO))).allow, "another principal pinned");
    }

    @Test void theDenyAnswerReasonIsNamed() throws Exception {
        escalateHook("provenance");
        Map<String, Object> deny = new LinkedHashMap<>();
        deny.put("decision", "deny");
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), in(new MemoryStateStore(), answer(null, deny), List.of(pub())));
        assertTrue(r.reasons.contains("escalation: the principal answered deny"), r.reasons.toString());
    }

    @Test void anAnswerNeverUpgradesADeny() throws Exception {
        escalateHook("provenance", "leaf_signature");
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), in(new MemoryStateStore(), answer(null, null), List.of(pub())));
        assertFalse(r.allow);
        assertEquals("deny", r.decision);
    }

    @Test void aStoreWithoutLastCannotBindTheHistory() throws Exception {
        escalateHook("provenance");
        MemoryStateStore mem = new MemoryStateStore();
        StateStore bare = mem::claim;
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), in(bare, answer(null, null), List.of(pub())));
        assertFalse(r.allow);
        assertEquals("escalate", r.decision);
        assertThrows(IllegalArgumentException.class,
            () -> new Authorize.Options(bare, (p, g) -> false, Authorize.SINGLE_STEP, null, List.of(), List.of(pub())));
        assertNotNull(new Authorize.Options(mem, (p, g) -> false, Authorize.SINGLE_STEP, null, List.of(), List.of(pub())));
    }

    // ---- the carriers ----

    static PcaFilter filter(MemoryStateStore store) {
        return new PcaFilter(AuthorizeFixtures.audience(), ref -> grant(), CLOCK,
            new Authorize.Options(store, (p, g) -> false, Authorize.SINGLE_STEP, null, List.of(), List.of(pub())).insecureUnboundApproval(true).withProvenance(ProvHarness.options()),
            (req, body) -> AuthorizeFixtures.operation(C, 0));
    }

    static String b64json(Object o) { return Pca.b64(Json.canonicalizeStrict(o).getBytes(StandardCharsets.UTF_8)); }

    @Test void theHeaderCarrierRefusesThenAdmits() throws Exception {
        escalateHook("provenance");
        MemoryStateStore store = new MemoryStateStore();
        PcaFilter f = filter(store);
        AtomicInteger calls = new AtomicInteger();
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
        req.addHeader("PCA-Action", AuthorizeTest.hdr(pcactn()));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        f.doFilter(req, resp, (a, b) -> calls.incrementAndGet());
        assertEquals(0, calls.get());
        assertEquals(403, resp.getStatus());
        String body = resp.getContentAsString();
        assertTrue(body.contains("\"decision\":\"escalate\""), body);
        assertTrue(body.contains("\"escalation\":{") && body.contains("\"kind\":\"pca-escalation-request\""), body);

        MockHttpServletRequest req2 = new MockHttpServletRequest("POST", "/pay");
        req2.addHeader("PCA-Action", AuthorizeTest.hdr(pcactn()));
        req2.addHeader("PCA-Escalation-Answer", b64json(answer(null, null)));
        MockHttpServletResponse resp2 = new MockHttpServletResponse();
        f.doFilter(req2, resp2, (a, b) -> calls.incrementAndGet());
        assertEquals(1, calls.get());
        assertEquals(200, resp2.getStatus());
    }

    @Test void anUnreadableHeaderAnswerIsNoAnswer() throws Exception {
        escalateHook("provenance");
        PcaFilter f = filter(new MemoryStateStore());
        AtomicInteger calls = new AtomicInteger();
        for (String bad : new String[] {"not base64url!", Pca.b64("{".getBytes(StandardCharsets.UTF_8)), Pca.b64("[]".getBytes(StandardCharsets.UTF_8))}) {
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
            req.addHeader("PCA-Action", AuthorizeTest.hdr(pcactn()));
            req.addHeader("PCA-Escalation-Answer", bad);
            MockHttpServletResponse resp = new MockHttpServletResponse();
            f.doFilter(req, resp, (a, b) -> calls.incrementAndGet());
            assertEquals(403, resp.getStatus(), bad);
            assertTrue(resp.getContentAsString().contains("\"decision\":\"escalate\""), bad);
        }
        assertEquals(0, calls.get());
    }

    @Test void theBodyCarrierAdmitsWithTheAnswerMember() throws Exception {
        escalateHook("provenance");
        PcaFilter f = filter(new MemoryStateStore());
        AtomicInteger calls = new AtomicInteger();
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("pcactn", pcactn());
        env.put("escalation_answer", answer(null, null));
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
        req.setContent(Json.canonicalizeStrict(env).getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        f.doFilter(req, resp, (a, b) -> calls.incrementAndGet());
        assertEquals(1, calls.get(), resp.getContentAsString());
        assertEquals(200, resp.getStatus());
    }
}
