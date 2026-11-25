package net.atlasauth.pca.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.agent.PcaAgent.ActResult;
import net.atlasauth.pca.agent.PcaAgent.AgentClient;
import net.atlasauth.pca.agent.PcaAgent.CreateAgentOptions;
import net.atlasauth.pca.agent.PcaAgent.FetchResponse;
import org.junit.jupiter.api.Test;

/** The HTTP agent client against a scripted resource server. */
public class PcaAgentTest {
    private static final Keys.SuiteKey PRINCIPAL = Keys.ed25519(Keys.edFromSeed(new byte[32]));
    private static final Keys.EdKey AGENT_ED = Keys.edFromSeed(filled(1));
    private static final Keys.SuiteKey AGENT = Keys.ed25519(AGENT_ED);
    private static final Map<String, Object> GRANT = Issue.mintGrant(PRINCIPAL, AGENT_ED.id(), null,
        Issue.obj("predicates", new ArrayList<Object>(List.of(Issue.obj("verb", "*"))), "caveats", new ArrayList<Object>(), "risk_policy", Issue.defaultRiskPolicy()), "g", "s").grant;
    private static final Map<String, Object> NODE = Issue.obj("id", "n1", "verb", "read", "resource", "doc/1", "params_digest", Pca.paramsDigest(null));

    private static byte[] filled(int v) {
        byte[] b = new byte[32];
        Arrays.fill(b, (byte) v);
        return b;
    }

    @FunctionalInterface
    private interface Answer { FetchResponse answer(String method, String url, String body); }

    private static AgentClient client(Answer a, boolean verify, Keys.SuiteKey key) {
        CreateAgentOptions o = new CreateAgentOptions(GRANT, "https://rs.example/", "ins_1");
        o.agentKey = key;
        o.now = () -> 1_800_000_000_000L;
        o.fetch = (m, u, h, b) -> a.answer(m, u, b);
        o.verifyReceipts = verify;
        return PcaAgent.createAgent(o);
    }

    private static AgentClient client(Answer a) { return client(a, false, AGENT); }

    private static Answer planOk() {
        return (m, u, b) -> new FetchResponse(200, "{\"plan_root\":\"" + Issue.commitPlan(List.of(NODE)).root + "\"}");
    }

    @Test void createAgentRefusesAnEmptyAudienceAndARelativeUrl() {
        for (CreateAgentOptions o : List.of(new CreateAgentOptions(GRANT, "https://x", ""), new CreateAgentOptions(GRANT, "/x", "a"), new CreateAgentOptions(GRANT, "ftp://x", "a"))) {
            assertEquals("build_failed", assertThrows(PcaAgentError.class, () -> PcaAgent.createAgent(o)).code());
        }
    }

    @Test void actBeforeCommitPlanIsNoPlan() {
        assertEquals("no_plan", ((ActResult.Error) client(planOk()).act("n1")).error.code());
    }

    @Test void commitPlanNeedsTheServerToEchoTheRoot() {
        AgentClient c = client((m, u, b) -> new FetchResponse(200, "{\"plan_root\":\"other\"}"));
        assertEquals("bad_response", assertThrows(PcaAgentError.class, () -> c.commitPlan(List.of(NODE))).code());
        AgentClient c2 = client((m, u, b) -> new FetchResponse(200, "not json"));
        assertEquals("bad_response", assertThrows(PcaAgentError.class, () -> c2.commitPlan(List.of(NODE))).code());
    }

    @Test void allowNeedsAnExplicitTrueAndAReceipt() {
        String[] reply = {"{\"verdict\":{\"allow\":true},\"receipt\":{\"root\":\"r\",\"commit\":\"c\",\"index\":0,\"inclusion_proof\":{}}}"};
        AgentClient c = client((m, u, b) -> u.endsWith("/plans") ? planOk().answer(m, u, b) : new FetchResponse(200, reply[0]));
        assertEquals(Issue.commitPlan(List.of(NODE)).root, c.commitPlan(List.of(NODE)));
        ActResult.Allowed ok = (ActResult.Allowed) c.act("n1");
        assertTrue(ok.verdict.allow);
        assertEquals(1L, c.counter());
        reply[0] = "{\"verdict\":{\"allow\":true}}";
        assertEquals("bad_response", ((ActResult.Error) c.act("n1")).error.code());
        reply[0] = "{\"verdict\":{\"allow\":true},\"allow\":false,\"receipt\":{}}";
        assertTrue(c.act("n1") instanceof ActResult.Denied);
        reply[0] = "{\"verdict\":{\"allow\":\"true\"},\"receipt\":{}}";
        assertTrue(c.act("n1") instanceof ActResult.Denied);
        assertEquals(4L, c.counter()); // a counter is never reused
        assertEquals("unknown_node", ((ActResult.Error) c.act("zz")).error.code());
    }

    @Test void anAllowWhoseInclusionProofFailsIsAnError() {
        AgentClient c = client((m, u, b) -> u.endsWith("/plans") ? planOk().answer(m, u, b)
            : new FetchResponse(200, "{\"verdict\":{\"allow\":true},\"receipt\":{\"root\":\"r\",\"commit\":\"c\",\"inclusion_proof\":{}}}"), true, AGENT);
        c.commitPlan(List.of(NODE));
        assertEquals("bad_response", ((ActResult.Error) c.act("n1")).error.code());
    }

    @Test void theActionBodyCarriesASignedPCActnForTheAudience() {
        String[] seen = new String[1];
        AgentClient c = client((m, u, b) -> {
            if (u.endsWith("/plans")) return planOk().answer(m, u, b);
            seen[0] = b;
            return new FetchResponse(200, "{\"verdict\":{\"allow\":false}}");
        });
        c.commitPlan(List.of(NODE));
        ActResult r = c.act("n1");
        assertEquals("denied", r.status());
        Object body = net.atlasauth.pca.Json.parseLenient(seen[0]);
        @SuppressWarnings("unchecked") Map<String, Object> pc = (Map<String, Object>) ((Map<String, Object>) body).get("pcactn");
        assertEquals("ins_1", pc.get("aud"));
        assertNotNull(pc.get("sig"));
    }

    @Test void aStepUpIsReportedAndPolledUntilDecided() {
        AtomicInteger polls = new AtomicInteger();
        AgentClient c = client((m, u, b) -> {
            if (u.endsWith("/plans")) return planOk().answer(m, u, b);
            if (u.endsWith("/actions")) return new FetchResponse(202, "{\"stepup_id\":\"s/1\",\"required_t\":3}");
            return new FetchResponse(200, polls.incrementAndGet() < 2 ? "{\"status\":\"pending\"}" : "{\"status\":\"approved\"}");
        });
        c.commitPlan(List.of(NODE));
        ActResult.StepUp s = (ActResult.StepUp) c.act("n1");
        assertEquals("s/1", s.stepupId);
        assertEquals(3.0, s.requiredT, 0.0);
        assertEquals("approved", c.awaitStepUp("s/1", 1L, 10_000L).status);
        assertEquals(2, polls.get());
    }

    @Test void aStepUpPollEncodesTheIdAndAsksForALongPoll() {
        String[] url = new String[1];
        AgentClient c = client((m, u, b) -> { url[0] = u; return new FetchResponse(200, "{\"status\":\"denied\"}"); });
        assertEquals("denied", c.awaitStepUp("a b/c", 1L, 60_000L).status);
        assertTrue(url[0].startsWith("https://rs.example/v1/pca/stepups/a%20b%2Fc?wait="), url[0]);
    }

    @Test void aClientErrorOnPollIsFinalAndNeverApproves() {
        AgentClient c = client((m, u, b) -> new FetchResponse(404, "{\"status\":\"approved\"}"));
        PcaAgent.StepUpOutcome o = c.awaitStepUp("x", 1L, 1000L);
        assertEquals("denied", o.status);
        assertEquals(404, o.httpStatus);
        assertFalse(o.status.equals("approved"));
    }

    @Test void aPollThatNeverDecidesTimesOut() {
        AgentClient c = client((m, u, b) -> new FetchResponse(200, "{\"status\":\"pending\"}"));
        assertEquals("timeout", c.awaitStepUp("x", 5L, 30L).status);
    }

    @Test void delegateExtendsTheChainAndNeedsAKey() {
        AgentClient c = client(planOk());
        AgentClient sub = c.delegate(Keys.edFromSeed(filled(2)).id(), new ArrayList<>(), null);
        assertEquals(2, sub.chain.size());
        assertNotNull(sub.agentPublic);
        assertEquals("no_secret", assertThrows(PcaAgentError.class, () -> client(planOk(), false, null).delegate("x", null, null)).code());
    }
}
