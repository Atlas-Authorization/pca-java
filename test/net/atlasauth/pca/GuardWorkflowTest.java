package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.spring.PcaInterceptor;

/**
 * The workflow option through the servlet filter and the Spring interceptor ({@code Options.withWorkflow}): the step comes from
 * the per-request callback, else (filter only) the JSON body member {@code workflow}. Steps and expectations come from the shared
 * authorize-workflow-fixtures.json; a refusal never reaches the chain.
 */
public class GuardWorkflowTest {
    static final Map<String, Object> F = AuthorizeWorkflowTest.F;
    static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(Json.asLong(F.get("now"))), ZoneOffset.UTC);

    static Map<String, Object> m(Object o) { return AuthorizeWorkflowTest.m(o); }
    static List<Object> l(Object o) { return AuthorizeWorkflowTest.l(o); }

    static Authorize.Options options(boolean required, StateStore store) {
        Authorize.Options o = new Authorize.Options(store, (p, g) -> false, null, pc -> Map.of("plan", l(F.get("plan")), "plan_authorized", Boolean.TRUE), List.of());
        return o.withWorkflow(new Authorize.WorkflowPin((String) F.get("principal"), (String) F.get("rs_signer"), required));
    }

    static Authorize.Operation op(Map<String, Object> s) {
        Map<String, Object> op = m(s.get("operation"));
        return Authorize.Operation.of((String) op.get("verb"), (String) op.get("resource"), m(op.get("params")));
    }

    static Authorize.WorkflowStep step(Map<String, Object> s) {
        if (s.get("workflow") == null) return null;
        Map<String, Object> w = m(s.get("workflow"));
        return new Authorize.WorkflowStep(w.get("commitment"), w.get("receipts"), (String) w.get("step"), w.get("units") == null ? null : m(w.get("units")), (String) w.get("goal_digest"));
    }

    static String header(Map<String, Object> s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Json.canonicalizeStrict(s.get("pcactn")).getBytes(StandardCharsets.UTF_8));
    }

    /** body: how the step travels. 0 = filter + JSON body member, 1 = filter + callback, 2 = interceptor + callback. */
    static void replay(String name, int mode, boolean required) throws Exception {
        Map<String, Object> grant = m(F.get("grant"));
        Map<String, Object> c = AuthorizeWorkflowTest.kase(name);
        StateStore store = new MemoryStateStore();
        AtomicInteger chain = new AtomicInteger(), allowed = new AtomicInteger();
        int i = 0;
        for (Object so : l(c.get("steps"))) {
            Map<String, Object> s = m(so), want = m(s.get("expect"));
            String where = name + " mode " + mode + " step " + i++;
            Authorize.WorkflowStep ws = step(s);
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
            req.addHeader("PCA-Action", header(s));
            MockHttpServletResponse resp = new MockHttpServletResponse();
            boolean passed;
            if (mode == 2) {
                PcaInterceptor it = new PcaInterceptor((String) F.get("audience"), ref -> ref.equals(grant.get("id")) ? grant : null, CLOCK, options(required, store), (r, b) -> op(s))
                    .withWorkflowStep(r -> ws);
                passed = it.preHandle(req, resp, new Object());
            } else {
                PcaFilter f = new PcaFilter((String) F.get("audience"), ref -> ref.equals(grant.get("id")) ? grant : null, CLOCK, options(required, store), (r, b) -> op(s));
                if (mode == 0) {
                    Map<String, Object> body = new LinkedHashMap<>();
                    if (s.get("workflow") != null) body.put("workflow", s.get("workflow"));
                    req.setContent(Json.canonicalize(body).getBytes(StandardCharsets.UTF_8));
                } else f.withWorkflowStep(r -> ws);
                f.doFilter(req, resp, (a, b) -> chain.incrementAndGet());
                passed = chain.get() > allowed.get();
                if (passed) allowed.incrementAndGet();
            }
            assertEquals(Boolean.TRUE.equals(want.get("allow")), passed, where + " allow");
            if (!passed) {
                assertEquals(Json.asLong(want.get("status")), (long) resp.getStatus(), where + " status");
                if (want.get("reason") != null) assertTrue(resp.getContentAsString().contains((String) want.get("reason")), where + " reason: " + resp.getContentAsString());
            }
        }
    }

    @Test void aValidStepPassesAndAViolatingOneIsRefusedOnEveryTransport() throws Exception {
        for (int mode = 0; mode < 3; mode++) {
            replay("pay-after-quote", mode, false);
            replay("amount-over-the-quote", mode, false); // 403 workflow: edge_relation (step pay)
            replay("workflow-required-but-absent", mode, true);
            replay("workflow-optional-and-absent", mode, false);
        }
    }

    @Test void aRequiredStepIsRefusedBeforeAnUndecodableHeader() throws Exception {
        Map<String, Object> grant = m(F.get("grant"));
        Authorize.Operation anyOp = op(m(l(AuthorizeWorkflowTest.kase("workflow-required-but-absent").get("steps")).get(0)));
        for (boolean required : new boolean[] {true, false}) {
            PcaFilter f = new PcaFilter((String) F.get("audience"), ref -> grant, CLOCK, options(required, new MemoryStateStore()), (r, b) -> anyOp);
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
            req.addHeader("PCA-Action", "!!not base64url!!");
            MockHttpServletResponse resp = new MockHttpServletResponse();
            AtomicInteger chain = new AtomicInteger();
            f.doFilter(req, resp, (a, b) -> chain.incrementAndGet());
            assertEquals(required ? 403 : 401, resp.getStatus());
            if (required) assertTrue(resp.getContentAsString().contains("workflow: this call carries no workflow step (fail closed)"), resp.getContentAsString());
            assertEquals(0, chain.get());
        }
    }

    @Test void noWorkflowOptionIgnoresAWorkflowBodyMember() throws Exception {
        Map<String, Object> grant = m(F.get("grant"));
        Map<String, Object> s = m(l(AuthorizeWorkflowTest.kase("amount-over-the-quote").get("steps")).get(0));
        Authorize.Options plain = new Authorize.Options(new MemoryStateStore(), (p, g) -> false, null, pc -> Map.of("plan", l(F.get("plan")), "plan_authorized", Boolean.TRUE), List.of());
        PcaFilter f = new PcaFilter((String) F.get("audience"), ref -> ref.equals(grant.get("id")) ? grant : null, CLOCK, plain, (r, b) -> op(s));
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
        req.addHeader("PCA-Action", header(s));
        req.setContent(Json.canonicalize(Map.of("workflow", s.get("workflow"))).getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        AtomicInteger chain = new AtomicInteger();
        f.doFilter(req, resp, (a, b) -> chain.incrementAndGet());
        assertEquals(1, chain.get()); // the violating step is not judged: no workflow gate is configured
        assertFalse(resp.getContentAsString().contains("workflow"));
    }
}
