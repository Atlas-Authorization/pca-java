package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import net.atlasauth.pca.servlet.PcaCore;
import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.servlet.PcaResult;
import net.atlasauth.pca.spring.PcaInterceptor;

/**
 * The caveat-language headers reach the authorize pipeline through every carrier: a root {@code needs_discharge} caveat is
 * satisfied only by the {@code PCA-Discharges} header, and a {@code PCA-Narrow} header that does not verify refuses.
 */
public class K1CarrierTest {
    static final long NOW = 1_800_000_000_000L;
    static final String AUD = "https://rs.example";
    static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC);
    static final Authorize.Operation OP = Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 50L));

    static Keys.SuiteKey key(int b) {
        byte[] x = new byte[32];
        Arrays.fill(x, (byte) b);
        return Keys.ed25519(Keys.edFromSeed(x));
    }

    static final Keys.SuiteKey PRINCIPAL = key(21), AGENT = key(22), RISK = key(23);
    static final Map<String, Object> GRANT;
    static final Map<String, Object> PCACTN;
    static final String DISCHARGES;

    static {
        List<Object> preds = new ArrayList<>();
        preds.add(Issue.obj("verb", "*"));
        Map<String, Object> env = Issue.obj("predicates", preds, "caveats", new ArrayList<Object>(), "risk_policy", Issue.defaultRiskPolicy());
        Map<String, Object> enveloped = Issue.mintGrant(PRINCIPAL, AGENT.id(), null, env, "pay invoices", Pca.b64(new byte[16])).grant;
        List<Object> caveats = new ArrayList<>((List<?>) enveloped.get("caveats"));
        List<Object> require = new ArrayList<>();
        require.add(Issue.obj("claim", "kyc_level", "op", "gte", "value", 2L));
        caveats.add(Issue.obj("type", "needs_discharge", "id", "kyc", "issuer", "risk-team", "issuer_class", "human", "bind", "chain_hop",
            "ttl_ms", 600_000L, "require", require));
        GRANT = Issue.mintRoot(PRINCIPAL, AGENT.id(), null, caveats);
        PCACTN = Agent.create(AGENT, AUD, GRANT, null).clock(() -> NOW).act(OP.verb, OP.resource, Issue.obj("amount", 50L));
        Map<String, Object> d = Issue.discharge(RISK, "kyc", "risk-team", GRANT, "chain_hop", null, Issue.obj("kyc_level", 3L), NOW - 1000, NOW + 300_000);
        List<Object> ds = new ArrayList<>();
        ds.add(d);
        DISCHARGES = b64(ds);
    }

    static String b64(Object o) { return Pca.b64(Json.canonicalizeStrict(o).getBytes(StandardCharsets.UTF_8)); }

    static Authorize.Options opts() {
        List<Object> pins = new ArrayList<>();
        pins.add(Issue.obj("label", "risk-team", "class", "human", "pk", RISK.id()));
        return new Authorize.Options(new MemoryStateStore(), (p, g) -> false, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO).withProvenance(ProvHarness.options()).k1(Issue.obj("pins", pins));
    }

    static PcaResult core(String discharges, String narrow) {
        return PcaCore.authorize(Issue.header(PCACTN), null, AUD, NOW, ref -> GRANT, opts(), OP, null, discharges, narrow, null, null);
    }

    @Test void pcaCoreReadsTheDischargesAndTheNarrow() {
        PcaResult ok = core(DISCHARGES, null);
        assertTrue(ok.allowed(), ok.authorization().reasons.toString());
        assertEquals("pass", ok.authorization().checks.get("delegated_caveats"));
        PcaResult none = core(null, null);
        assertFalse(none.allowed());
        assertEquals("fail", none.authorization().checks.get("delegated_caveats"), none.authorization().reasons.toString());
        // an unreadable discharges header is no discharges
        assertEquals("fail", core("!!", null).authorization().checks.get("delegated_caveats"));
        // a narrow block that does not verify refuses, even with the discharge
        PcaResult narrowed = core(DISCHARGES, b64(1L));
        assertFalse(narrowed.allowed());
        assertEquals("fail", narrowed.authorization().checks.get("delegated_caveats"));
    }

    static MockHttpServletRequest request(String discharges, String narrow) {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
        req.addHeader("PCA-Action", Issue.header(PCACTN));
        if (discharges != null) req.addHeader("PCA-Discharges", discharges);
        if (narrow != null) req.addHeader("PCA-Narrow", narrow);
        return req;
    }

    static int filter(String discharges, String narrow) throws Exception {
        PcaFilter f = new PcaFilter(AUD, ref -> GRANT, CLOCK, opts(), (r, b) -> OP);
        MockHttpServletResponse resp = new MockHttpServletResponse();
        AtomicInteger calls = new AtomicInteger();
        f.doFilter(request(discharges, narrow), resp, (a, b) -> calls.incrementAndGet());
        return calls.get() == 1 ? 200 : resp.getStatus();
    }

    static boolean interceptor(String discharges, String narrow) throws Exception {
        PcaInterceptor it = new PcaInterceptor(AUD, ref -> GRANT, CLOCK, opts(), (r, b) -> OP);
        return it.preHandle(request(discharges, narrow), new MockHttpServletResponse(), new Object());
    }

    @Test void theFilterAndTheInterceptorForwardTheHeaders() throws Exception {
        assertEquals(200, filter(DISCHARGES, null));
        assertEquals(403, filter(null, null));
        assertEquals(403, filter(DISCHARGES, b64(1L)));
        assertTrue(interceptor(DISCHARGES, null));
        assertFalse(interceptor(null, null));
        assertFalse(interceptor(DISCHARGES, b64(1L)));
    }
}
