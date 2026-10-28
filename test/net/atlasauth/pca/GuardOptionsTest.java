package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import net.atlasauth.pca.servlet.PcaCore;
import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.servlet.PcaResult;
import net.atlasauth.pca.spring.PcaInterceptor;

/**
 * The 0.5 options of the servlet filter, the Spring interceptor and {@code PcaCore}: goal binding v3, revocation staleness,
 * the high-assurance policy, plans and the operation executor. Same guard semantics as {@code Authorize}: a refusal never
 * reaches the chain and consumes nothing.
 */
public class GuardOptionsTest {
    static String hdr(Object pcactn) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Json.canonicalizeStrict(pcactn).getBytes(StandardCharsets.UTF_8));
    }

    static final class Rig {
        final Map<String, Object> c = AuthorizeFixtures.kase("envelope-predicate-within");
        final Map<String, Object> grant = AuthorizeFixtures.grant(c);
        final Clock clock = Clock.fixed(Instant.ofEpochMilli(AuthorizeFixtures.now()), ZoneOffset.UTC);
        final Authorize.Operation op = AuthorizeFixtures.operation(c, 0);
        final String header = hdr(AuthorizeFixtures.pcactn(c, 0));
        final StateStore store = new MemoryStateStore();
        final AtomicInteger chain = new AtomicInteger();

        Authorize.Options options() { return new Authorize.Options(store, (p, g) -> false); }

        PcaFilter filter(Authorize.Options o) {
            return new PcaFilter(AuthorizeFixtures.audience(), ref -> grant, clock, o, (req, body) -> op);
        }

        MockHttpServletResponse call(PcaFilter f) throws Exception {
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
            req.addHeader("PCA-Action", header);
            req.setContent("{\"amount\":50}".getBytes(StandardCharsets.UTF_8));
            MockHttpServletResponse resp = new MockHttpServletResponse();
            f.doFilter(req, resp, (a, b) -> chain.incrementAndGet());
            return resp;
        }
    }

    @Test void approvedGoalIsEnforcedAndAMisconfigurationFailsClosed() throws Exception {
        Rig r = new Rig();
        String digest = Pca.b64(new byte[32]); // a canonical 32-byte digest, built at run time
        // the proof carries no intent: a required binding is missing
        MockHttpServletResponse missing = r.call(r.filter(r.options().withApprovedGoal(digest, digest)));
        assertEquals(403, missing.getStatus());
        assertTrue(missing.getContentAsString().contains("intent"), missing.getContentAsString());
        // a malformed digest is a misconfiguration: refused on every request
        MockHttpServletResponse bad = r.call(r.filter(r.options().withApprovedGoal("AAAA", digest)));
        assertEquals(403, bad.getStatus());
        assertTrue(bad.getContentAsString().contains("approved_goal"), bad.getContentAsString());
        assertEquals(0, r.chain.get());
        // nothing was consumed by the refusals
        assertEquals(200, r.call(r.filter(r.options())).getStatus());
        assertEquals(1, r.chain.get());
    }

    @Test void highAssuranceIsEnforcedBeforeTheCounterIsSpent() throws Exception {
        Rig r = new Rig();
        MockHttpServletResponse weak = r.call(r.filter(r.options().withRequireAssurance(Assurance.Requirement.pq())));
        assertEquals(403, weak.getStatus());
        assertTrue(weak.getContentAsString().contains("post-quantum signatures required but leaf_signature is ed25519"), weak.getContentAsString());
        assertEquals(0, r.chain.get());
        assertEquals(200, r.call(r.filter(r.options().withRequireAssurance(new Assurance.Requirement()))).getStatus());
    }

    @Test void revocationStalenessNeedsVerifiableStateForAnIrreversibleAction() throws Exception {
        Rig r = new Rig();
        String grantRef = (String) AuthorizeFixtures.pcactn(r.c, 0).get("grant_ref");
        long now = AuthorizeFixtures.now();
        RevocationStaleness policy = new RevocationStaleness().maxRevocationAgeMs(300_000).guardianPublic(StalenessVectorsTest.pub())
            .ids(pc -> java.util.List.of());
        // no state: refused
        MockHttpServletResponse none = r.call(r.filter(r.options().withRevocationStaleness(policy)));
        assertEquals(403, none.getStatus());
        assertTrue(none.getContentAsString().contains("no verifiable (guardian-signed) revocation state"), none.getContentAsString());
        // a stale epoch: refused
        MockHttpServletResponse stale = r.call(r.filter(r.options().withRevocationStaleness(policy)
            .withRevocationState(p -> RevocationStaleness.State.epoch(StalenessVectorsTest.epoch(grantRef, now, 200_000), null, null))));
        assertEquals(403, stale.getStatus());
        assertEquals(0, r.chain.get());
        // a fresh one: allowed, with the same counter (nothing was spent)
        MockHttpServletResponse ok = r.call(r.filter(r.options().withRevocationStaleness(policy)
            .withRevocationState(p -> RevocationStaleness.State.epoch(StalenessVectorsTest.epoch(grantRef, now, 1_000), null, null))));
        assertEquals(200, ok.getStatus());
        assertEquals(1, r.chain.get());
    }

    @Test void theInterceptorSharesTheOptions() throws Exception {
        Rig r = new Rig();
        PcaInterceptor it = new PcaInterceptor(AuthorizeFixtures.audience(), ref -> r.grant, r.clock,
            r.options().withRequireAssurance(Assurance.Requirement.pq()), (req, body) -> r.op);
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
        req.addHeader("PCA-Action", r.header);
        MockHttpServletResponse resp = new MockHttpServletResponse();
        assertFalse(it.preHandle(req, resp, new Object()));
        assertEquals(403, resp.getStatus());
        PcaInterceptor ok = new PcaInterceptor(AuthorizeFixtures.audience(), ref -> r.grant, r.clock, r.options(), (rq, body) -> r.op);
        MockHttpServletRequest req2 = new MockHttpServletRequest("POST", "/pay");
        req2.addHeader("PCA-Action", r.header);
        assertTrue(ok.preHandle(req2, new MockHttpServletResponse(), new Object()));
    }

    @Test void anAllowedRequestExecutesAtMostOnceAndIsAnsweredFromTheRecord() throws Exception {
        Rig r = new Rig();
        OperationStore records = new MemoryOperationStore();
        AtomicInteger runs = new AtomicInteger();
        AtomicReference<PcaResult> seen = new AtomicReference<>();
        PcaFilter f = r.filter(r.options());
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
        req.addHeader("PCA-Action", r.header);
        req.setContent("{\"amount\":50}".getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        f.doFilter(req, resp, (a, b) -> seen.set((PcaResult) a.getAttribute(PcaCore.ATTRIBUTE)));
        PcaResult res = seen.get();
        assertNotNull(res);
        // the signed class of this fixture is irreversible: the execution needs its recheck
        Operations.ExecuteOptions eo = new Operations.ExecuteOptions().store(records).now(() -> AuthorizeFixtures.now())
            .recheck(h -> Operations.RecheckResult.ok());
        Operations.ExecuteOutcome first = res.execute(h -> { runs.incrementAndGet(); return h.idempotencyKey; }, eo);
        assertEquals("committed", first.status, first.toString());
        assertEquals(200, PcaCore.operationStatus(first));
        MockHttpServletResponse out = new MockHttpServletResponse();
        PcaFilter.writeOperation(out, first);
        assertEquals(200, out.getStatus());
        assertTrue(out.getContentAsString().contains("\"status\":\"committed\""), out.getContentAsString());
        Operations.ExecuteOutcome again = res.execute(h -> { runs.incrementAndGet(); return "x"; }, eo);
        assertTrue(again.replayed);
        assertEquals(1, runs.get());
        // a refusal is a 403; an unknown state is a 409; a failed function is a 500
        assertEquals(403, PcaCore.operationStatus(Operations.ExecuteOutcome.refused("no")));
        assertEquals(403, PcaCore.operationStatus(null));
        Operations.ExecuteOutcome failed = res.execute(h -> { throw new IllegalStateException("x"); },
            new Operations.ExecuteOptions().store(new MemoryOperationStore()).now(() -> AuthorizeFixtures.now()).recheck(h -> Operations.RecheckResult.ok()));
        assertEquals("failed", failed.status);
        assertEquals(500, PcaCore.operationStatus(failed));
        // a request that was not authorized through the authorize pipeline never executes
        PcaFilter plain = PcaFilter.signatureOnly(AuthorizeFixtures.audience(), ref -> r.grant, r.clock);
        AtomicReference<PcaResult> sig = new AtomicReference<>();
        MockHttpServletRequest req3 = new MockHttpServletRequest("POST", "/pay");
        req3.addHeader("PCA-Action", r.header);
        plain.doFilter(req3, new MockHttpServletResponse(), (a, b) -> sig.set((PcaResult) a.getAttribute(PcaCore.ATTRIBUTE)));
        if (sig.get() != null) assertEquals("refused", sig.get().execute(h -> "x", eo).status);
    }

    @Test void maturityIsStableInTheCodeAndTheBuildMetadata() throws Exception {
        assertEquals("stable", Pca.MATURITY);
        String pom = Files.readString(Path.of("pom.xml"));
        assertTrue(pom.contains("<pca.maturity>" + Pca.MATURITY + "</pca.maturity>"), "pom.xml states the same maturity");
    }
}
