package net.atlasauth.pca.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.RiskCtx;
import net.atlasauth.pca.AuthorizeFixtures;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.K3;
import net.atlasauth.pca.MemoryStateStore;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.ProvHarness;

/** PcaCore's authorize-mode overloads and request readers, and the PcaResult accessors of an authorize decision. */
public class PcaCoreKillTest {
    static final Map<String, Object> C = AuthorizeFixtures.kase("envelope-predicate-within");
    static final String AUD = AuthorizeFixtures.audience();
    static final long NOW = AuthorizeFixtures.now();
    static final Map<String, Object> GRANT = AuthorizeFixtures.grant(C);
    static final GrantResolver RES = ref -> GRANT;

    static String hdr(String text) { return ServletKillTest.hdr(text); }
    static String action() { return hdr(Json.canonicalizeStrict(AuthorizeFixtures.pcactn(C, 0))); }
    static Authorize.Operation op() { return AuthorizeFixtures.operation(C, 0); }
    /** Fresh options (a new replay store) that admit the fixture step. */
    static Authorize.Options opts() { return new Authorize.Options(new MemoryStateStore(), (p, g) -> false, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO).withProvenance(ProvHarness.options()); }

    static void allowedByAuthorize(PcaResult r) {
        assertTrue(r.allowed(), r.detail());
        assertNotNull(r.authorization());
        assertTrue(r.authorization().allow);
        assertEquals("allow", r.decision());
        assertNull(r.escalation());
    }

    @Test void everyAuthorizeOverloadRunsThePipeline() {
        String h = action();
        allowedByAuthorize(PcaCore.authorize(h, null, AUD, NOW, RES, opts(), op()));
        allowedByAuthorize(PcaCore.authorize(h, null, AUD, NOW, RES, opts(), op(), null));
        allowedByAuthorize(PcaCore.authorize(h, null, AUD, NOW, RES, opts(), op(), null, (String) null, null));
        allowedByAuthorize(PcaCore.authorize(h, null, AUD, NOW, RES, opts(), op(), null, (K3.FreshAtPolicy) null, null));
        allowedByAuthorize(PcaCore.authorize(h, null, AUD, NOW, RES, opts(), op(), null, null, null, null, null));
        allowedByAuthorize(PcaCore.authorize(h, null, AUD, NOW, RES, opts(), op(), null, null, null, null, null, null));
        allowedByAuthorize(PcaCore.authorize(h, null, AUD, NOW, RES, opts(), op(), null, null, null, null, null, null, null));
        // the same store: the second presentation is a replay, a 403 denial with the decision's own status
        Authorize.Options once = opts();
        allowedByAuthorize(PcaCore.authorize(h, null, AUD, NOW, RES, once, op()));
        PcaResult replay = PcaCore.authorize(h, null, AUD, NOW, RES, once, op());
        assertEquals(PcaResult.Outcome.DENIED, replay.outcome());
        assertEquals(403, replay.status());
        assertEquals("insufficient_authority", replay.error());
        assertEquals("deny", replay.decision());
        assertNull(replay.escalation());
    }

    @Test void anUndecodablePcactnIsTheDecisions401() {
        PcaResult r = PcaCore.authorize(null, "{\"pcactn\":\"x\"}".getBytes(StandardCharsets.UTF_8), AUD, NOW, RES, opts(), op());
        assertEquals(PcaResult.Outcome.DENIED, r.outcome());
        assertEquals(401, r.status());
        assertEquals("invalid_pcactn", r.error());
        assertEquals("PCA realm=\"pca\", error=\"invalid_pcactn\"", r.wwwAuthenticate());
        assertEquals("deny", r.decision());
        assertEquals("{\"error\":\"invalid_pcactn\",\"error_description\":\"undecodable PCActn: could not be decoded\",\"decision\":\"deny\"}", r.jsonBody());
    }

    @Test void signatureOnlyDecisionAndEscalation() throws Exception {
        PcaResult ok = PcaCore.authorize(action(), null, AUD, NOW, RES);
        assertTrue(ok.allowed(), ok.detail());
        assertNull(ok.authorization());
        assertEquals("allow", ok.decision());
        assertNull(ok.escalation());
        PcaResult no = PcaCore.authorize(action(), null, "other", NOW, RES);
        assertEquals("deny", no.decision());
        assertNull(no.escalation());
        assertEquals("deny", PcaResult.of(PcaResult.Outcome.ABSENT, "x").decision());
    }

    @Test void allowedSuitesAppliesToSignatureOnlyAndAuthorizePaths() {
        String h = action();
        String denied = "signature suite is not allowed by this verifier's suite policy";
        // signature-only: null = unrestricted, a listed suite passes, an unlisted suite and an empty list refuse
        assertTrue(PcaCore.authorizeSignatureOnly(h, null, AUD, NOW, RES, null, null, null).allowed());
        assertTrue(PcaCore.authorizeSignatureOnly(h, null, AUD, NOW, RES, null, null, List.of("ed25519")).allowed());
        for (List<String> pol : List.of(List.of("ml-dsa-65"), List.<String>of())) {
            PcaResult r = PcaCore.authorizeSignatureOnly(h, null, AUD, NOW, RES, null, null, pol);
            assertFalse(r.allowed(), pol.toString());
            assertTrue(r.detail().contains(denied), r.detail());
        }
        // the authorize pipeline forwards the suite policy of its options
        allowedByAuthorize(PcaCore.authorize(h, null, AUD, NOW, RES, opts().withAllowedSuites(List.of("ed25519")), op()));
        PcaResult r = PcaCore.authorize(h, null, AUD, NOW, RES, opts().withAllowedSuites(List.of("ml-dsa-65")), op());
        assertFalse(r.allowed());
        assertTrue(r.detail().contains(denied), r.detail());
        assertFalse(PcaCore.authorize(h, null, AUD, NOW, RES, opts().withAllowedSuites(List.of()), op()).allowed());
    }

    @Test void aNullResolverOrNullOptionsNeverThrow() {
        // no options: the bare pipeline has no replay store / revocation check and fails closed on its configuration
        PcaResult r = PcaCore.authorize(action(), null, AUD, NOW, null, null, op());
        assertEquals(PcaResult.Outcome.DENIED, r.outcome());
        assertTrue(r.detail().startsWith("authorize_config: missing required component(s): "), r.detail());
        r = PcaCore.authorize(action(), null, AUD, NOW, RES, null, op(), null, null, null, null, null, null, null);
        assertTrue(r.detail().startsWith("authorize_config: "), r.detail());
        // options but no resolver: refused on the configuration, never a NullPointerException
        r = PcaCore.authorize(action(), null, AUD, NOW, null, opts(), op());
        assertEquals(PcaResult.Outcome.DENIED, r.outcome());
        assertTrue(r.detail().startsWith("authorize_config: missing required component(s): "), r.detail());
        assertTrue(r.authorization().missing.contains("resolveGrant"), r.authorization().missing.toString());
    }

    @Test void aRequiredWorkflowWithNoStepIsRefusedBeforeThePcactn() {
        Authorize.Options wf = opts().withWorkflow(new Authorize.WorkflowPin("p", "s", true));
        // no PCActn at all: the workflow refusal comes first (it needs no PCActn)
        PcaResult r = PcaCore.authorize(null, null, AUD, NOW, RES, wf, op());
        assertEquals(PcaResult.Outcome.DENIED, r.outcome());
        assertEquals("workflow: this call carries no workflow step (fail closed)", r.detail());
        assertEquals("fail", r.authorization().checks.get("workflow"));
        // ... also with no resolver (the refusal does not need one)
        r = PcaCore.authorize(null, null, AUD, NOW, null, wf, op());
        assertEquals(PcaResult.Outcome.DENIED, r.outcome());
        assertNotNull(r.authorization());
        // a step in the body: the PCActn's own refusal stands
        r = PcaCore.authorize(null, "{\"workflow\":{\"step\":\"s1\"}}".getBytes(StandardCharsets.UTF_8), AUD, NOW, RES, wf, op());
        assertEquals(PcaResult.Outcome.ABSENT, r.outcome());
        // a step from the callback: the same
        r = PcaCore.authorize(null, null, AUD, NOW, RES, wf, op(), null, null, null, null, null,
            new Authorize.WorkflowStep(null, null, "s1", null, null));
        assertEquals(PcaResult.Outcome.ABSENT, r.outcome());
        // a pin that does not require a step, or no pin, or no options: the absent PCActn is the refusal
        assertEquals(PcaResult.Outcome.ABSENT, PcaCore.authorize(null, null, AUD, NOW, RES,
            opts().withWorkflow(new Authorize.WorkflowPin("p", "s", false)), op()).outcome());
        assertEquals(PcaResult.Outcome.ABSENT, PcaCore.authorize(null, null, AUD, NOW, RES, opts(), op()).outcome());
        assertEquals(PcaResult.Outcome.ABSENT, PcaCore.authorize(null, null, AUD, NOW, RES, null, op()).outcome());
    }

    // ------------------------------------------------------------------ presentedK1 / header map

    @Test void presentedK1Readings() {
        PcaCore.PresentedK1 p = PcaCore.presentedK1("!!", null);
        assertFalse(p.ok);
        assertNull(p.value);
        assertEquals("not canonical base64url: PCA-Discharges", p.error);
        p = PcaCore.presentedK1(null, "!!");
        assertFalse(p.ok);
        assertEquals("not canonical base64url: PCA-Narrow", p.error);
        p = PcaCore.presentedK1(hdr("{"), null);
        assertFalse(p.ok);
        assertEquals("unreadable discharge header: expected key at 1", p.error);
        p = PcaCore.presentedK1(hdr("{}"), null);
        assertEquals("PCA-Discharges must be a JSON array", p.error);
        p = PcaCore.presentedK1(null, hdr("{"));
        assertEquals("unreadable discharge header: expected key at 1", p.error);
        p = PcaCore.presentedK1(hdr("[\"d\"]"), hdr("{\"a\":\"b\"}"));
        assertTrue(p.ok);
        assertNull(p.error);
        assertEquals(List.of("d"), p.value.get("discharges"));
        assertEquals(Map.of("a", "b"), p.value.get("narrow"));
        p = PcaCore.presentedK1("", "");
        assertTrue(p.ok);
        assertTrue(p.value.isEmpty());
    }

    @Test void presentedK1FromAHeaderMap() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put(null, "ignored");
        h.put("pca-discharges", hdr("[\"d\"]"));
        h.put("PCA-NARROW", hdr("1"));
        PcaCore.PresentedK1 p = PcaCore.presentedK1(h);
        assertTrue(p.ok, p.error);
        assertEquals(List.of("d"), p.value.get("discharges"));
        assertTrue(p.value.containsKey("narrow"));
        // the same value under two spellings is that value; two different values are absent
        h = new LinkedHashMap<>();
        h.put("PCA-Discharges", hdr("[\"d\"]"));
        h.put("pca-discharges", hdr("[\"d\"]"));
        assertEquals(List.of("d"), PcaCore.presentedK1(h).value.get("discharges"));
        h.put("Pca-Discharges", hdr("[\"e\"]"));
        p = PcaCore.presentedK1(h);
        assertTrue(p.ok);
        assertFalse(p.value.containsKey("discharges"));
        assertTrue(PcaCore.presentedK1((Map<String, String>) null).value.isEmpty());
    }

    // ------------------------------------------------------------------ fresh_at side carriage

    @Test void sideCarriedFreshAt() {
        K3.FreshAtPolicy pol = new K3.FreshAtPolicy("signer", "scope", Map.of("k", "v"), 5.0, true, false, null);
        assertNull(PcaCore.withSideCarried(null, Map.of(), "{}"));
        K3.FreshAtPolicy carried = new K3.FreshAtPolicy("signer", "scope", null, null, true, true, "t");
        assertSame(carried, PcaCore.withSideCarried(carried, Map.of(), "{\"a\":1}"));
        assertSame(pol, PcaCore.withSideCarried(pol, Map.of(), null));
        assertSame(pol, PcaCore.withSideCarried(pol, Map.of(), ""));
        assertSame(pol, PcaCore.withSideCarried(pol, Map.of("fresh_at", Map.of()), "{\"a\":1}"));
        for (Object pcactn : new Object[] {Map.of("x", 1), "not a map", null}) {
            K3.FreshAtPolicy s = PcaCore.withSideCarried(pol, pcactn, "{\"a\":\"b\"}");
            assertTrue(s.hasSideCarried, String.valueOf(pcactn));
            assertEquals(Map.of("a", "b"), s.sideCarried);
            assertEquals("signer", s.signer);
            assertEquals("scope", s.scope);
            assertEquals(Map.of("k", "v"), s.local);
            assertEquals(5.0, s.maxTokenAgeMs);
            assertTrue(s.require);
        }
        K3.FreshAtPolicy bad = PcaCore.withSideCarried(pol, Map.of(), "{not json");
        assertTrue(bad.hasSideCarried);
        assertNull(bad.sideCarried);
    }

    // ------------------------------------------------------------------ workflow body member

    static Authorize.WorkflowStep wf(String body) { return PcaCore.workflowFromBody(body == null ? null : body.getBytes(StandardCharsets.UTF_8)); }

    static void empty(Authorize.WorkflowStep s, String why) {
        assertNotNull(s, why);
        assertNull(s.step, why);
        assertNull(s.commitment, why);
        assertNull(s.receipts, why);
        assertNull(s.units, why);
        assertNull(s.goalDigest, why);
    }

    @Test void workflowFromTheBody() {
        assertNull(wf(null));
        assertNull(wf(""));
        assertNull(wf("{"));
        assertNull(wf("[1]"));
        assertNull(wf("{\"x\":1}"));
        assertNull(wf("{\"workflow\":null}"));
        assertNull(PcaCore.workflowFromBody(new byte[] {'{', (byte) 0xC0, (byte) 0xAF, '}'}));
        empty(wf("{\"workflow\":5}"), "non-object");
        empty(wf("{\"workflow\":[]}"), "array");
        empty(wf("{\"workflow\":{}}"), "no step");
        empty(wf("{\"workflow\":{\"step\":1}}"), "non-string step");
        empty(wf("{\"workflow\":{\"step\":\"s\",\"units\":[]}}"), "non-object units");
        empty(wf("{\"workflow\":{\"step\":\"s\",\"goal_digest\":1}}"), "non-string goal");
        Authorize.WorkflowStep s = wf("{\"workflow\":{\"step\":\"s\",\"commitment\":{\"c\":\"1\"},\"receipts\":[\"r\"],\"units\":{\"u\":\"1\"},\"goal_digest\":\"g\"}}");
        assertEquals("s", s.step);
        assertEquals(Map.of("c", "1"), s.commitment);
        assertEquals(List.of("r"), s.receipts);
        assertEquals(Map.of("u", "1"), s.units);
        assertEquals("g", s.goalDigest);
        s = wf("{\"workflow\":{\"step\":\"s\",\"units\":null,\"goal_digest\":null}}");
        assertEquals("s", s.step);
        assertNull(s.units);
        assertNull(s.goalDigest);
    }

    // ------------------------------------------------------------------ escalation answer

    @Test void escalationAnswerCarriers() {
        Map<String, Object> ans = Map.of("kind", "a");
        byte[] body = "{\"escalation_answer\":{\"kind\":\"b\"}}".getBytes(StandardCharsets.UTF_8);
        assertEquals(ans, PcaCore.escalationAnswer(hdr("{\"kind\":\"a\"}"), body));
        assertNull(PcaCore.escalationAnswer("!!", body)); // an unreadable header is no answer (the body is not consulted)
        assertNull(PcaCore.escalationAnswer(hdr("{"), body));
        assertEquals(Map.of("kind", "b"), PcaCore.escalationAnswer("", body));
        assertEquals(Map.of("kind", "b"), PcaCore.escalationAnswer(null, body));
        assertNull(PcaCore.escalationAnswer(null, null));
        assertNull(PcaCore.escalationAnswer(null, new byte[0]));
        assertNull(PcaCore.escalationAnswer(null, "[1]".getBytes(StandardCharsets.UTF_8)));
        assertNull(PcaCore.escalationAnswer(null, "{\"x\":1}".getBytes(StandardCharsets.UTF_8)));
        assertNull(PcaCore.escalationAnswer(null, new byte[] {'{', (byte) 0xED, (byte) 0xA0, (byte) 0x80, '}'}));
    }

    // ------------------------------------------------------------------ PcaResult

    @Test void aDeniedVerdictWithANullReasonDescribesByDetail() {
        Pca.Verdict v = net.atlasauth.pca.VerdictFactory.empty();
        v.reason = null;
        assertEquals("{\"error\":\"insufficient_authority\",\"error_description\":\"dd\"}", new PcaResult(PcaResult.Outcome.DENIED, v, null, "dd").jsonBody());
    }

    // ------------------------------------------------------------------ filter / interceptor construction and workflow callback

    static final java.time.Clock CLOCK = java.time.Clock.fixed(java.time.Instant.ofEpochMilli(NOW), java.time.ZoneOffset.UTC);
    static final PcaFilter.OperationMapper MAP = (r, b) -> op();

    @Test void carrierConstructors() {
        assertNotNull(new PcaFilter(AUD, RES));
        assertNotNull(new net.atlasauth.pca.spring.PcaInterceptor(AUD, RES));
        assertEquals("authorize", org.junit.jupiter.api.Assertions.assertThrows(NullPointerException.class, () -> new PcaFilter(AUD, RES, CLOCK, null, MAP)).getMessage());
        assertEquals("operation", org.junit.jupiter.api.Assertions.assertThrows(NullPointerException.class, () -> new PcaFilter(AUD, RES, CLOCK, opts(), null)).getMessage());
        assertEquals("authorize", org.junit.jupiter.api.Assertions.assertThrows(NullPointerException.class,
            () -> new net.atlasauth.pca.spring.PcaInterceptor(AUD, RES, CLOCK, null, MAP)).getMessage());
        assertEquals("operation", org.junit.jupiter.api.Assertions.assertThrows(NullPointerException.class,
            () -> new net.atlasauth.pca.spring.PcaInterceptor(AUD, RES, CLOCK, opts(), null)).getMessage());
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> new net.atlasauth.pca.spring.PcaInterceptor(AUD, RES, CLOCK, null, MAP, true));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> new net.atlasauth.pca.spring.PcaInterceptor(AUD, RES, CLOCK, opts(), null, true));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> new PcaFilter(AUD, RES, CLOCK, null, MAP, true));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> new PcaFilter(AUD, RES, CLOCK, opts(), null, true));
    }

    static Authorize.Options required() { return opts().withWorkflow(new Authorize.WorkflowPin("p", "s", true)); }

    @Test void aThrowingWorkflowCallbackIsAStepThatIsRefused() throws Exception {
        // no PCActn: with a step (even a refused one) the PCActn's absence is the 401; with no step it is the workflow refusal
        PcaFilter f = new PcaFilter(AUD, RES, CLOCK, required(), MAP);
        assertSame(f, f.withWorkflowStep(r -> { throw new IllegalStateException("x"); }));
        org.springframework.mock.web.MockHttpServletResponse resp = new org.springframework.mock.web.MockHttpServletResponse();
        f.doFilter(new org.springframework.mock.web.MockHttpServletRequest("POST", "/x"), resp, (a, b) -> { throw new AssertionError("chain"); });
        assertEquals(401, resp.getStatus());
        net.atlasauth.pca.spring.PcaInterceptor it = new net.atlasauth.pca.spring.PcaInterceptor(AUD, RES, CLOCK, required(), MAP);
        assertSame(it, it.withWorkflowStep(r -> { throw new IllegalStateException("x"); }));
        resp = new org.springframework.mock.web.MockHttpServletResponse();
        assertFalse(it.preHandle(new org.springframework.mock.web.MockHttpServletRequest("POST", "/x"), resp, new Object()));
        assertEquals(401, resp.getStatus());
        // the interceptor with no callback: no step, the workflow refusal (403)
        resp = new org.springframework.mock.web.MockHttpServletResponse();
        assertFalse(new net.atlasauth.pca.spring.PcaInterceptor(AUD, RES, CLOCK, required(), MAP)
            .preHandle(new org.springframework.mock.web.MockHttpServletRequest("POST", "/x"), resp, new Object()));
        assertEquals(403, resp.getStatus());
        assertTrue(resp.getContentAsString().contains("workflow: this call carries no workflow step"), resp.getContentAsString());
    }

    @Test void theInterceptorsMapperGetsAnEmptyBody() throws Exception {
        int[] len = {-1};
        net.atlasauth.pca.spring.PcaInterceptor it = new net.atlasauth.pca.spring.PcaInterceptor(AUD, RES, CLOCK, opts(), (r, b) -> { len[0] = b.length; return op(); });
        org.springframework.mock.web.MockHttpServletRequest req = new org.springframework.mock.web.MockHttpServletRequest("POST", "/x");
        req.addHeader("PCA-Action", action());
        req.setContent("{\"a\":1}".getBytes(StandardCharsets.UTF_8));
        assertTrue(it.preHandle(req, new org.springframework.mock.web.MockHttpServletResponse(), new Object()));
        assertEquals(0, len[0]);
    }

    @Test void writeOperationAnswers() throws Exception {
        org.springframework.mock.web.MockHttpServletResponse resp = new org.springframework.mock.web.MockHttpServletResponse();
        PcaFilter.writeOperation(resp, null);
        assertEquals(403, resp.getStatus());
        assertEquals("application/json;charset=UTF-8", resp.getContentType());
        assertEquals("{\"status\":\"refused\"}", resp.getContentAsString());
        assertEquals(20, resp.getContentLength());
    }
}
