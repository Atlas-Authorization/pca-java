package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import net.atlasauth.pca.servlet.PcaFilter;

public class AuthorizeTest {
    /** Every shared fixture case: steps in order against ONE fresh store; exact {allow, status, failing checks}. */
    @Test void sharedFixtures() {
        assertEquals(31, AuthorizeFixtures.cases().size());
        for (Map<String, Object> c : AuthorizeFixtures.cases()) {
            StateStore store = new MemoryStateStore();
            int n = ((List<?>) c.get("steps")).size();
            for (int i = 0; i < n; i++) {
                boolean revoked = Boolean.TRUE.equals(AuthorizeFixtures.step(c, i).get("revoked"));
                Authorize.Input in = AuthorizeFixtures.input(c, i).stateStore(store).isRevoked((p, g) -> revoked);
                Authorize.AuthorizeResult r = Authorize.authorize(AuthorizeFixtures.pcactn(c, i), in);
                assertEquals(AuthorizeFixtures.want(AuthorizeFixtures.step(c, i).get("expect"), true), AuthorizeFixtures.settle(r), c.get("name") + " step " + i);
                Object why = ((Map<?, ?>) AuthorizeFixtures.step(c, i).get("expect")).get("reason");
                if (why != null) assertTrue(String.join("\n", r.reasons).contains((String) why), c.get("name") + " step " + i + " reasons " + r.reasons);
            }
        }
    }

    @Test void missingComponentsDeny() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Object p = AuthorizeFixtures.pcactn(c, 0);
        assertTrue(Authorize.authorize(p, AuthorizeFixtures.input(c, 0)).allow);
        List<Authorize.Input> bad = List.of(
            AuthorizeFixtures.input(c, 0).stateStore(null), AuthorizeFixtures.input(c, 0).isRevoked(null),
            AuthorizeFixtures.input(c, 0).resolveGrant(null), AuthorizeFixtures.input(c, 0).audience(""),
            AuthorizeFixtures.input(c, 0).operation(null), AuthorizeFixtures.input(c, 0).plan("anything"),
            AuthorizeFixtures.input(c, 0).isRevoked((x, g) -> { throw new RuntimeException("boom"); }));
        for (int i = 0; i < bad.size(); i++) {
            Authorize.AuthorizeResult r = Authorize.authorize(p, bad.get(i));
            assertFalse(r.allow, "case " + i);
            assertEquals(403, r.status, "case " + i);
        }
    }

    /** K5: no configured plan is a failure, never "not-enforced"; authorize() has no opt-out; a configured plan passes. */
    @Test void planRootIsDefaultDenied() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Object p = AuthorizeFixtures.pcactn(c, 0);
        Authorize.AuthorizeResult none = Authorize.authorize(p, AuthorizeFixtures.input(c, 0).plan(null));
        assertFalse(none.allow);
        assertEquals("fail", none.checks.get("plan_root_authorized"));
        assertTrue(none.reasons.contains("plan_root_authorized: default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)"), none.reasons.toString());
        // dropping the check from `require` does not bring back the old not-enforced report
        Authorize.AuthorizeResult relaxed = Authorize.authorize(p, AuthorizeFixtures.input(c, 0).plan(null).require(List.of("replay")));
        assertFalse(relaxed.allow);
        assertEquals("fail", relaxed.checks.get("plan_root_authorized"));
        Authorize.AuthorizeResult ok = Authorize.authorize(p, AuthorizeFixtures.input(c, 0));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("plan_root_authorized"));
    }

    static void exercise(StateStore s) throws Exception {
        long[] counters = {5, 5, 4, 6};
        boolean[] ok = {true, false, false, true};
        for (int i = 0; i < counters.length; i++) assertEquals(ok[i], s.claim("k", counters[i]).ok, "claim " + counters[i]);
        assertEquals(Long.valueOf(6), s.claim("k", 1).lastCounter);
        AtomicInteger wins = new AtomicInteger();
        List<Thread> ts = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            Thread t = new Thread(() -> { if (s.claim("c", 1).ok) wins.incrementAndGet(); });
            ts.add(t); t.start();
        }
        for (Thread t : ts) t.join();
        assertEquals(1, wins.get(), "exactly one concurrent claim wins");
    }

    @Test void memoryStoreIsMonotoneAndAtomic() throws Exception { exercise(new MemoryStateStore()); }

    @Test void sqliteStoreIsMonotoneAtomicAndDurable() throws Exception {
        java.nio.file.Path f = Files.createTempFile("pca-replay", ".db");
        try {
            exercise(AuthorizeFixtures.sqlite(f));
            PcaJdbcStateStore again = AuthorizeFixtures.sqlite(f); // a restart sees the committed counters
            assertFalse(again.claim("k", 6).ok);
            assertTrue(again.claim("k", 7).ok);
        } finally { Files.deleteIfExists(f); }
    }

    static String hdr(Object pcactn) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Json.canonicalizeStrict(pcactn).getBytes(StandardCharsets.UTF_8));
    }

    /** PcaFilter in authorize mode: the chain never runs for a refused request; replay and a different executed amount are refused. */
    @Test void filterAuthorizeMode() throws Exception {
        Map<String, Object> c = AuthorizeFixtures.kase("envelope-predicate-within");
        Map<String, Object> grant = AuthorizeFixtures.grant(c);
        Clock clock = Clock.fixed(Instant.ofEpochMilli(AuthorizeFixtures.now()), ZoneOffset.UTC);
        Authorize.Operation signed = AuthorizeFixtures.operation(c, 0);
        Authorize.Operation[] executed = {signed};
        PcaFilter f = new PcaFilter(AuthorizeFixtures.audience(), ref -> grant, clock,
            new Authorize.Options(new MemoryStateStore(), (p, g) -> false), (req, body) -> executed[0]);
        String h = hdr(AuthorizeFixtures.pcactn(c, 0));
        int[] codes = new int[3];
        int[] calls = {0};
        for (int i = 0; i < 3; i++) {
            if (i == 2) executed[0] = Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 400L, "currency", "usd"));
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
            req.addHeader("PCA-Action", h);
            req.setContent("{\"amount\":50}".getBytes(StandardCharsets.UTF_8));
            MockHttpServletResponse resp = new MockHttpServletResponse();
            f.doFilter(req, resp, (a, b) -> { calls[0]++; });
            codes[i] = resp.getStatus();
        }
        assertEquals(1, calls[0]);
        assertEquals(200, codes[0]);
        assertEquals(403, codes[1]);
        assertEquals(403, codes[2]);
    }
}
