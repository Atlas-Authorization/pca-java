package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.spring.Protect;

/** Protect.protect: secure defaults in one call, and the refusal bodies carry a `doc` link. */
public class ProtectTest {
    static final Map<String, Object> C = AuthorizeFixtures.kase("envelope-predicate-within");
    static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(AuthorizeFixtures.now()), ZoneOffset.UTC);
    static final String DOCS = "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md";

    static Protect.Config config() {
        return new Protect.Config(AuthorizeFixtures.audience(), (req, body) -> AuthorizeFixtures.operation(C, 0))
            .grants(List.of(AuthorizeFixtures.grant(C))).clock(CLOCK).provenance(ProvHarness.options());
    }

    static MockHttpServletRequest request() {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
        req.addHeader("PCA-Action", AuthorizeTest.hdr(AuthorizeFixtures.pcactn(C, 0)));
        return req;
    }

    static MockHttpServletResponse run(PcaFilter f, AtomicInteger calls) throws Exception {
        MockHttpServletResponse resp = new MockHttpServletResponse();
        f.doFilter(request(), resp, (a, b) -> calls.incrementAndGet());
        return resp;
    }

    @Test void allowsOnceThenRefusesReplayWithDocLink() throws Exception {
        PcaFilter f = Protect.protect(config()).filter();
        AtomicInteger calls = new AtomicInteger();
        assertEquals(200, run(f, calls).getStatus());
        MockHttpServletResponse again = run(f, calls);
        assertEquals(403, again.getStatus());
        assertEquals(1, calls.get());
        assertTrue(again.getContentAsString().contains("replay: 1 is not greater than last seen 1"), again.getContentAsString());
        assertTrue(again.getContentAsString().endsWith(",\"doc\":\"" + DOCS + "#replay\"}"), again.getContentAsString());
    }

    @Test void revokeHandleRefusesTheGrant() throws Exception {
        Protect.Protected p = Protect.protect(config());
        p.revoke((String) AuthorizeFixtures.grant(C).get("id"));
        AtomicInteger calls = new AtomicInteger();
        MockHttpServletResponse resp = run(p.filter(), calls);
        assertEquals(403, resp.getStatus());
        assertEquals(0, calls.get());
        assertTrue(resp.getContentAsString().contains("revocation: the grant is revoked"), resp.getContentAsString());
        assertTrue(resp.getContentAsString().endsWith("\"doc\":\"" + DOCS + "#revocation\"}"), resp.getContentAsString());
    }

    @Test void yourOwnRevocationSourceIsConsultedToo() throws Exception {
        PcaFilter f = Protect.protect(config().isRevoked((pcactn, grant) -> true)).filter();
        assertEquals(403, run(f, new AtomicInteger()).getStatus());
    }

    @Test void yourOwnStateStoreWins() throws Exception {
        int[] claims = {0};
        MemoryStateStore inner = new MemoryStateStore();
        StateStore mine = (key, counter) -> { claims[0]++; return inner.claim(key, counter); };
        assertEquals(200, run(Protect.protect(config().stateStore(mine)).filter(), new AtomicInteger()).getStatus());
        assertEquals(1, claims[0]);
    }

    @Test void interceptorRefusesWithoutAProof() throws Exception {
        MockHttpServletResponse resp = new MockHttpServletResponse();
        assertEquals(false, Protect.protect(config()).interceptor().preHandle(new MockHttpServletRequest("POST", "/pay"), resp, new Object()));
        assertEquals(401, resp.getStatus());
        assertTrue(resp.getContentAsString().contains("\"doc\":\"" + DOCS + "\"}"), resp.getContentAsString());
    }

    @Test void noGrantsIsAConfigurationError() {
        assertThrows(IllegalArgumentException.class, () -> Protect.protect(new Protect.Config("a", (r, b) -> null)));
    }

    @Test void configArgumentsAndFluentSetters() {
        assertEquals("audience", assertThrows(NullPointerException.class, () -> new Protect.Config(null, (r, b) -> null)).getMessage());
        assertEquals("operation", assertThrows(NullPointerException.class, () -> new Protect.Config("a", null)).getMessage());
        Protect.Config c = new Protect.Config("a", (r, b) -> null);
        assertEquals("resolver", assertThrows(NullPointerException.class, () -> c.grants((net.atlasauth.pca.servlet.GrantResolver) null)).getMessage());
        assertEquals("clock", assertThrows(NullPointerException.class, () -> c.clock(null)).getMessage());
        assertEquals("plan", assertThrows(NullPointerException.class, () -> c.plan(null)).getMessage());
        assertSame(c, c.grants(ref -> null));
        assertSame(c, c.plan(Authorize.SINGLE_STEP));
    }

    @Test void aLookupFunctionAndTheDefaultClockWork() throws Exception {
        Map<String, Object> g = AuthorizeFixtures.grant(C);
        Protect.Config c = new Protect.Config(AuthorizeFixtures.audience(), (req, body) -> AuthorizeFixtures.operation(C, 0))
            .grants(ref -> g).clock(CLOCK).provenance(ProvHarness.options());
        assertEquals(200, run(Protect.protect(c).filter(), new AtomicInteger()).getStatus());
        // no clock set: the system clock (the fixture's validity window is not now, so validity refuses it: 401, not a NullPointerException)
        Protect.Config sys = new Protect.Config(AuthorizeFixtures.audience(), (req, body) -> AuthorizeFixtures.operation(C, 0)).grants(ref -> g);
        assertEquals(401, run(Protect.protect(sys).filter(), new AtomicInteger()).getStatus());
    }

    @Test void thePlanModeReachesTheOptions() throws Exception {
        Protect.Protected p = Protect.protect(config().plan("multi-step"));
        assertEquals("multi-step", p.options().plan);
        MockHttpServletResponse resp = run(p.filter(), new AtomicInteger());
        assertEquals(403, resp.getStatus());
        assertTrue(resp.getContentAsString().contains("authorize_config"), resp.getContentAsString());
        assertEquals(Authorize.SINGLE_STEP, Protect.protect(config()).options().plan);
    }

    @Test void theRevocationCheck() {
        Map<String, Object> g = AuthorizeFixtures.grant(C);
        Authorize.RevocationCheck mine = Protect.protect(config()).options().isRevoked;
        assertEquals(Boolean.FALSE, mine.isRevoked(Map.of(), g));
        assertEquals(Boolean.TRUE, mine.isRevoked(Map.of(), null));
        assertEquals(Boolean.TRUE, mine.isRevoked(Map.of(), Map.<String, Object>of("x", 1)));
        assertEquals(Boolean.FALSE, Protect.protect(config().isRevoked((p, gr) -> false)).options().isRevoked.isRevoked(Map.of(), g));
        assertEquals(Boolean.TRUE, Protect.protect(config().isRevoked((p, gr) -> true)).options().isRevoked.isRevoked(Map.of(), g));
        assertNull(Protect.protect(config().isRevoked((p, gr) -> null)).options().isRevoked.isRevoked(Map.of(), g));
        Protect.Protected p = Protect.protect(config());
        p.revoke((String) g.get("id"));
        assertEquals(Boolean.TRUE, p.options().isRevoked.isRevoked(Map.of(), g));
    }
}
