package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;
import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.servlet.PcaResult;
import net.atlasauth.pca.testing.AdapterAcceptance;
import net.atlasauth.pca.testing.AdapterAcceptance.Observation;
import net.atlasauth.pca.testing.AdapterAcceptance.Request;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/** Runs the shared adapter acceptance matrix through the servlet filter, and proves the matrix has teeth with an adapter that skips the guard. */
class AdapterAcceptanceTest {
    /** The servlet filter in authorize mode, driven by Spring's mock request / response. */
    private static Function<Request, Observation> servlet(AdapterAcceptance.Setup s) {
        PcaFilter filter = new PcaFilter(s.audience, s.resolveGrant::apply, Clock.systemUTC(), s.options(), (req, body) -> {
            try {
                return s.operation(req.getMethod(), req.getRequestURI(), Json.parse(new String(body, StandardCharsets.UTF_8)));
            } catch (RuntimeException e) {
                return null;
            }
        });
        return r -> {
            try {
                MockHttpServletRequest q = new MockHttpServletRequest(r.method, r.path);
                for (Map.Entry<String, String> h : r.headers.entrySet()) q.addHeader(h.getKey(), h.getValue());
                q.setContent(Json.canonicalize(r.body).getBytes(StandardCharsets.UTF_8));
                MockHttpServletResponse resp = new MockHttpServletResponse();
                MockFilterChain chain = new MockFilterChain();
                filter.doFilter(q, resp, chain);
                boolean ran = chain.getRequest() != null;
                Object res = ran ? chain.getRequest().getAttribute(PcaFilter.ATTRIBUTE) : null;
                return new Observation(resp.getStatus(), ran, res instanceof PcaResult ? ((PcaResult) res).authorization() : null);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        };
    }

    @Test void theServletFilterPassesTheMatrix() {
        assertEquals(AdapterAcceptance.EXPECTED, AdapterAcceptance.run(AdapterAcceptanceTest::servlet));
    }

    @Test void anAdapterThatSkipsTheGuardFailsTheMatrix() {
        Map<String, AdapterAcceptance.Outcome> got = AdapterAcceptance.run(s -> r -> new Observation(200, true, null));
        assertNotEquals(AdapterAcceptance.EXPECTED, got);
        assertEquals(new AdapterAcceptance.Outcome(200, true, false), got.get("over_limit_predicate"));
    }

    @Test void theRouteMapping() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("amount", 5L);
        assertEquals("payments.send", AdapterAcceptance.acceptanceOperation("POST", "/payments", body).verb);
        assertEquals("payments.refund", AdapterAcceptance.acceptanceOperation("post", "/refunds", body).verb);
        assertEquals("payments", AdapterAcceptance.acceptanceOperation("POST", "/refunds", body).resource);
        assertNull(AdapterAcceptance.acceptanceOperation("GET", "/payments", body));
        assertNull(AdapterAcceptance.acceptanceOperation("POST", "/other", body));
        assertNull(AdapterAcceptance.acceptanceOperation("POST", "/payments", null));
        assertNull(AdapterAcceptance.acceptanceOperation("POST", "/payments", java.util.List.of()));
        assertNotNull(AdapterAcceptance.EXPECTED.get("valid_first"));
    }
}
