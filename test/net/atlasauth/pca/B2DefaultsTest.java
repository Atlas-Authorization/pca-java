package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.servlet.PcaResult;
import net.atlasauth.pca.spring.PcaInterceptor;

/** 0.5 B3 (middleware defaults to the full authorize path) and B6 (check names `counter_format` / `replay`). */
public class B2DefaultsTest {
    static final Map<String, Object> C = AuthorizeFixtures.kase("envelope-predicate-within");
    static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(AuthorizeFixtures.now()), ZoneOffset.UTC);

    static MockHttpServletRequest request() {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
        req.addHeader("PCA-Action", AuthorizeTest.hdr(AuthorizeFixtures.pcactn(C, 0)));
        return req;
    }

    // ---- B6: names ----

    @Test void coreVerifierReportsCounterFormatNotCounter() {
        Map<String, Object> p = AuthorizeFixtures.pcactn(C, 0);
        Pca.Verdict v = Pca.verifyPcactn(p, AuthorizeFixtures.grant(C), AuthorizeFixtures.now(), AuthorizeFixtures.audience());
        assertTrue(v.allow);
        assertEquals(Boolean.TRUE, v.checks.get("counter_format"));
        assertFalse(v.checks.containsKey("counter"));
    }

    /** The re-signed negative-counter conformance vector: the first failing check is counter_format, with its reason. */
    @SuppressWarnings("unchecked")
    @Test void malformedCounterFailsCounterFormatWithItsReason() throws Exception {
        Map<String, Object> doc = (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(AuthorizeFixtures.VECTORS)));
        Map<String, Object> v = null;
        for (Object o : (List<Object>) doc.get("vectors")) if ("invalid-counter".equals(((Map<String, Object>) o).get("name"))) v = (Map<String, Object>) o;
        Map<String, Object> ctx = (Map<String, Object>) v.get("context");
        Pca.Verdict r = Pca.verifyPcactn(v.get("pcactn"), (Map<String, Object>) v.get("grant"), Json.asLong(ctx.get("now")), (String) ctx.get("aud"));
        assertFalse(r.allow);
        assertEquals(Boolean.FALSE, r.checks.get("counter_format"));
        assertEquals(Boolean.TRUE, r.checks.get("leaf_signature"));
        assertFalse(r.checks.containsKey("counter"));
        assertEquals("counter_format: missing or not a non-negative safe integer", r.reason);
    }

    @Test void authorizeRequiredListNamesCounterFormatAndReplay() {
        assertEquals(List.of("counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity",
            "grant_ref_bound", "operation", "params_digest", "policy"), Authorize.DEFAULT_REQUIRED_CHECKS);
    }

    @Test void authorizeReportsReplayAndNeverCounter() {
        StateStore store = new MemoryStateStore();
        Authorize.AuthorizeResult first = Authorize.authorize(AuthorizeFixtures.pcactn(C, 0), AuthorizeFixtures.input(C, 0).stateStore(store));
        assertTrue(first.allow);
        assertEquals("pass", first.checks.get("replay"));
        assertEquals("pass", first.checks.get("counter_format"));
        assertFalse(first.checks.containsKey("counter"));
        Authorize.AuthorizeResult again = Authorize.authorize(AuthorizeFixtures.pcactn(C, 0), AuthorizeFixtures.input(C, 0).stateStore(store));
        assertFalse(again.allow);
        assertEquals(List.of("replay"), again.failed());
        assertTrue(again.reasons.contains("replay: 1 is not greater than last seen 1 (replay)"), again.reasons.toString());
    }

    @Test void storeFailureAndAlreadyClaimedReasons() {
        StateStore down = (key, counter) -> { throw new RuntimeException("down"); };
        Authorize.AuthorizeResult r = Authorize.authorize(AuthorizeFixtures.pcactn(C, 0), AuthorizeFixtures.input(C, 0).stateStore(down));
        assertEquals(List.of("replay"), r.failed());
        assertTrue(r.reasons.contains("replay: the replay store failed (fail closed)"), r.reasons.toString());
        StateStore claimed = (key, counter) -> StateStore.ClaimResult.replay(null);
        r = Authorize.authorize(AuthorizeFixtures.pcactn(C, 0), AuthorizeFixtures.input(C, 0).stateStore(claimed));
        assertTrue(r.reasons.contains("replay: 1 was already claimed (replay)"), r.reasons.toString());
    }

    @Test void requireCounterIsAnAliasOfReplay() {
        Authorize.AuthorizeResult r = Authorize.authorize(AuthorizeFixtures.pcactn(C, 0), AuthorizeFixtures.input(C, 0).require(List.of("counter")));
        assertTrue(r.allow, r.reasons.toString());
        assertFalse(r.checks.containsKey("counter"));
    }

    // ---- B3: defaults ----

    @Test void filterDefaultWithoutAuthorizeOptionsRefusesWithAuthorizeConfig() throws Exception {
        PcaFilter f = new PcaFilter(AuthorizeFixtures.audience(), ref -> AuthorizeFixtures.grant(C), CLOCK);
        MockHttpServletResponse resp = new MockHttpServletResponse();
        AtomicInteger calls = new AtomicInteger();
        f.doFilter(request(), resp, (a, b) -> calls.incrementAndGet());
        assertEquals(403, resp.getStatus());
        assertEquals(0, calls.get());
        assertTrue(resp.getContentAsString().contains("authorize_config: missing required component(s): stateStore, isRevoked"), resp.getContentAsString());
    }

    @Test void interceptorDefaultWithoutAuthorizeOptionsRefusesWithAuthorizeConfig() throws Exception {
        PcaInterceptor it = new PcaInterceptor(AuthorizeFixtures.audience(), ref -> AuthorizeFixtures.grant(C), CLOCK);
        MockHttpServletRequest req = request();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        assertFalse(it.preHandle(req, resp, new Object()));
        assertEquals(403, resp.getStatus());
        assertNull(req.getAttribute("pca"));
        assertTrue(resp.getContentAsString().contains("authorize_config: missing required component(s): stateStore, isRevoked"), resp.getContentAsString());
    }

    @Test void signatureOnlyFilterVerifiesTheSignatureAndRunsTheHandler() throws Exception {
        PcaFilter f = PcaFilter.signatureOnly(AuthorizeFixtures.audience(), ref -> AuthorizeFixtures.grant(C), CLOCK);
        MockHttpServletRequest req = request();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        f.doFilter(req, resp, chain);
        assertEquals(200, resp.getStatus());
        assertNotNull(chain.getRequest());
        PcaResult r = (PcaResult) req.getAttribute("pca");
        assertTrue(r.allowed());
        assertNull(r.authorization());
    }

    @Test void signatureOnlyInterceptorVerifiesTheSignature() throws Exception {
        PcaInterceptor it = PcaInterceptor.signatureOnly(AuthorizeFixtures.audience(), ref -> AuthorizeFixtures.grant(C), CLOCK);
        MockHttpServletRequest req = request();
        assertTrue(it.preHandle(req, new MockHttpServletResponse(), new Object()));
        assertNull(((PcaResult) req.getAttribute("pca")).authorization());
    }

    @Test void signatureOnlyTogetherWithAuthorizeOptionsIsAConfigurationError() {
        Authorize.Options o = new Authorize.Options(new MemoryStateStore(), (p, g) -> false);
        PcaFilter.OperationMapper m = (req, body) -> null;
        assertThrows(IllegalArgumentException.class, () -> new PcaFilter("a", ref -> null, CLOCK, o, m, true));
        assertThrows(IllegalArgumentException.class, () -> new PcaFilter("a", ref -> null, CLOCK, o, null, true));
        assertThrows(IllegalArgumentException.class, () -> new PcaFilter("a", ref -> null, CLOCK, null, m, true));
        assertThrows(IllegalArgumentException.class, () -> new PcaInterceptor("a", ref -> null, CLOCK, o, m, true));
        assertThrows(IllegalArgumentException.class, () -> new PcaInterceptor("a", ref -> null, CLOCK, null, m, true));
    }

    /** The shared acceptance cases through the filter built with the authorize options (the previous opt-in construction). */
    @Test void acceptanceThroughTheFilter() throws Exception {
        Authorize.Operation signed = AuthorizeFixtures.operation(C, 0);
        Authorize.Operation[] executed = {signed};
        StateStore store = new MemoryStateStore();
        PcaFilter f = new PcaFilter(AuthorizeFixtures.audience(), ref -> AuthorizeFixtures.grant(C), CLOCK,
            new Authorize.Options(store, (p, g) -> false), (req, body) -> executed[0]);
        List<String> bodies = new ArrayList<>();
        int[] codes = new int[4];
        AtomicInteger calls = new AtomicInteger();
        for (int i = 0; i < 4; i++) {
            if (i == 2) executed[0] = Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 400L, "currency", "usd"));
            if (i == 3) { executed[0] = null; }
            MockHttpServletResponse resp = new MockHttpServletResponse();
            f.doFilter(request(), resp, (a, b) -> calls.incrementAndGet());
            codes[i] = resp.getStatus();
            bodies.add(resp.getContentAsString());
        }
        assertEquals(1, calls.get());
        assertEquals(List.of(200, 403, 403, 403), List.of(codes[0], codes[1], codes[2], codes[3]));
        assertTrue(bodies.get(1).contains("replay: 1 is not greater than last seen 1"), bodies.get(1));
        assertEquals("{\"error\":\"insufficient_authority\",\"error_description\":\"operation: the proof's params_digest does not match the params of this payments.send operation\"}", bodies.get(2));
        assertEquals("{\"error\":\"insufficient_authority\",\"error_description\":\"operation: authorize needs the operation to execute (verb, resource, params) (fail closed)\"}", bodies.get(3));
    }

    @Test void revokedIsRefusedThroughTheFilter() throws Exception {
        PcaFilter f = new PcaFilter(AuthorizeFixtures.audience(), ref -> AuthorizeFixtures.grant(C), CLOCK,
            new Authorize.Options(new MemoryStateStore(), (p, g) -> true), (req, body) -> AuthorizeFixtures.operation(C, 0));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        AtomicInteger calls = new AtomicInteger();
        f.doFilter(request(), resp, (a, b) -> calls.incrementAndGet());
        assertEquals(403, resp.getStatus());
        assertEquals(0, calls.get());
        assertEquals("{\"error\":\"insufficient_authority\",\"error_description\":\"revocation: the grant is revoked\"}", resp.getContentAsString());
    }
}
