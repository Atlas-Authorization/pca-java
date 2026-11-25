package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The attestation and zk hooks through the whole {@link Authorize#authorize} pipeline, end to end on grants and PCActns signed in the test:
 * a grant that binds the agent (agent_binding) is allowed only with an ENFORCED, passing attestation; a carried zk_compliance proof is allowed
 * only with an enforced, passing zk hook and refused with none (the fail-closed default); a PCActn that carries no proof never calls the zk hook.
 * Complements {@link VerifierHooksTest}, which drives the core verifier.
 */
class AuthorizeHooksEndToEndTest {
    static final long NOW = AuthorizeBaseKillTest.NOW;
    static final Keys.SuiteKey PRINCIPAL = AuthorizeBaseKillTest.PRINCIPAL, AGENT = AuthorizeBaseKillTest.AGENT;
    static final Map<String, Object> PARAMS = Map.of("amount", 50L);
    static Object zkMember;

    @SuppressWarnings("unchecked")
    @BeforeAll static void load() throws Exception {
        for (Map<String, Object> c : OracleCases.of("ref-zk", "createZkVerifier")) {
            if (!"createZkVerifier/ok".equals(c.get("name"))) continue;
            Map<String, Object> ctx = (Map<String, Object>) ((List<?>) c.get("args")).get(1);
            zkMember = ((Map<String, Object>) ctx.get("pcactn")).get("zk_compliance");
        }
    }

    /** A root grant whose envelope binds the agent to {@code binding}. */
    static Map<String, Object> grant(Map<String, Object> binding) {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("type", "envelope");
        env.put("goal_commit", Issue.goalCommit("pay invoices", AuthorizeRunBasebKillTest.SALT));
        env.put("predicates", AuthorizeRunBasebKillTest.star());
        env.put("caveats", new ArrayList<Object>());
        env.put("risk_policy", Issue.defaultRiskPolicy());
        env.put("agent_binding", binding);
        List<Object> cavs = new ArrayList<>();
        cavs.add(env);
        return Issue.mintRoot(PRINCIPAL, AGENT.id(), null, cavs);
    }

    static final Map<String, Object> BOUND = Issue.obj("operator", "acme");
    static final Map<String, Object> UNBOUND = new LinkedHashMap<>();

    static Map<String, Object> act(Map<String, Object> g, boolean withProof) {
        Map<String, Object> pc = AuthorizeRunBasebKillTest.act(g);
        if (!withProof) return pc;
        Map<String, Object> body = new LinkedHashMap<>(pc);
        body.remove("sig");
        body.put("zk_compliance", zkMember);
        return Issue.signPCActn(body, AGENT);
    }

    static Authorize.AuthorizeResult run(Map<String, Object> g, Map<String, Object> pc, PcaCore.Hook att, PcaCore.Hook zk) {
        Authorize.Input in = AuthorizeRunBasebKillTest.in(g);
        if (att != null) in.attestationHook(att);
        if (zk != null) in.zkHook(zk);
        return Authorize.authorize(pc, in);
    }

    static final PcaCore.Hook OK = ctx -> PcaCore.HookResult.enforced(true);
    static final PcaCore.Hook NOT_ENFORCED = ctx -> PcaCore.HookResult.notEnforced();

    @SuppressWarnings("unchecked")
    static Map<String, Object> entry(Authorize.AuthorizeResult r, String check) { return (Map<String, Object>) r.assurance().get(check); }

    // ---- attestation -----------------------------------------------------------------------------------------------------

    @Test void aBoundGrantWithoutAnAttestationVerifierIsRefusedAndReportedUnsupported() {
        Map<String, Object> g = grant(BOUND);
        Authorize.AuthorizeResult r = run(g, act(g, false), null, null);
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("fail", r.checks.get("attestation"));
        assertTrue(r.reasons.stream().anyMatch(x -> x.contains("a valid, bound attestation is REQUIRED") && x.contains("no attestation verifier in this SDK")), r.reasons.toString());
        assertEquals("unsupported", entry(r, "attestation").get("outcome"));
    }

    @Test void aBoundGrantIsAllowedOnlyWithAnEnforcedPassingAttestation() {
        Map<String, Object> g = grant(BOUND);
        List<PcaCore.Ctx> seen = new ArrayList<>();
        Authorize.AuthorizeResult ok = run(g, act(g, false), ctx -> { seen.add(ctx); return PcaCore.HookResult.enforced(true); }, null);
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("attestation"));
        assertEquals("pass", entry(ok, "attestation").get("outcome"));
        assertEquals("unknown", entry(ok, "attestation").get("level")); // an unlabelled hook proves nothing about the evidence
        assertEquals(1, seen.size());
        assertEquals(NOW, seen.get(0).nowEpoch);
        assertEquals(g.get("id"), seen.get(0).grant.get("id"));
        assertEquals(g.get("id"), seen.get(0).pcactn.get("grant_ref"));

        Authorize.AuthorizeResult rejected = run(g, act(g, false), ctx -> PcaCore.HookResult.enforced(false, "measurement not allowlisted", null), null);
        assertFalse(rejected.allow);
        assertEquals("fail", rejected.checks.get("attestation"));
        assertTrue(rejected.reasons.stream().anyMatch(x -> x.contains("measurement not allowlisted")), rejected.reasons.toString());

        // a hook that did not enforce is not an attestation: the bound grant is still refused (and the refusal does not blame a missing verifier)
        Authorize.AuthorizeResult silent = run(g, act(g, false), NOT_ENFORCED, null);
        assertFalse(silent.allow);
        assertEquals("fail", silent.checks.get("attestation"));
        assertFalse(silent.reasons.stream().anyMatch(x -> x.contains("no attestation verifier in this SDK")), silent.reasons.toString());
    }

    @Test void aThrowingAttestationHookDeniesAndNeverAllows() {
        Map<String, Object> g = grant(BOUND);
        Authorize.AuthorizeResult r = run(g, act(g, false), ctx -> { throw new IllegalStateException("verifier down"); }, null);
        assertFalse(r.allow);
        assertFalse("pass".equals(r.checks.get("attestation")));
    }

    @Test void aGrantThatDoesNotBindTheAgentNeedsNoAttestationButUsesOneWhenGiven() {
        Map<String, Object> g = grant(UNBOUND);
        Authorize.AuthorizeResult none = run(g, act(g, false), null, null);
        assertTrue(none.allow, none.reasons.toString());
        assertFalse(none.checks.containsKey("attestation"));
        Authorize.AuthorizeResult with = run(g, act(g, false), OK, null);
        assertTrue(with.allow, with.reasons.toString());
        assertEquals("pass", with.checks.get("attestation"));
        Authorize.AuthorizeResult bad = run(g, act(g, false), ctx -> PcaCore.HookResult.enforced(false, "no", null), null);
        assertFalse(bad.allow);
        assertEquals("fail", bad.checks.get("attestation"));
    }

    @Test void aLabelledHookReportsItsLevelInTheAssuranceReport() {
        Map<String, Object> g = grant(BOUND);
        PcaCore.Hook hw = Assurance.setLabel(ctx -> PcaCore.HookResult.enforced(true), Assurance.Label.of("hardware"));
        Authorize.AuthorizeResult r = run(g, act(g, false), hw, null);
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("hardware", entry(r, "attestation").get("level"));
    }

    // ---- zk_compliance ---------------------------------------------------------------------------------------------------

    @Test void aCarriedProofWithNoZkHookIsRefusedByAuthorize() {
        Map<String, Object> g = grant(UNBOUND);
        Authorize.AuthorizeResult r = run(g, act(g, true), null, null);
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("fail", r.checks.get("zk_compliance"));
        assertTrue(r.reasons.stream().anyMatch(x -> x.contains("no zk verifier enforced it")), r.reasons.toString());
        assertEquals("unsupported", entry(r, "zk_compliance").get("outcome"));
        Authorize.AuthorizeResult silent = run(g, act(g, true), null, NOT_ENFORCED);
        assertFalse(silent.allow);
        assertEquals("fail", silent.checks.get("zk_compliance"));
    }

    @Test void aCarriedProofIsAllowedOnlyWithAnEnforcedPassingZkHook() {
        Map<String, Object> g = grant(UNBOUND);
        List<PcaCore.Ctx> seen = new ArrayList<>();
        Authorize.AuthorizeResult ok = run(g, act(g, true), null, ctx -> { seen.add(ctx); return PcaCore.HookResult.enforced(true); });
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("zk_compliance"));
        assertEquals("pass", entry(ok, "zk_compliance").get("outcome"));
        assertEquals(1, seen.size());
        assertTrue(seen.get(0).pcactn.containsKey("zk_compliance"));
        assertEquals(NOW, seen.get(0).nowEpoch);

        Authorize.AuthorizeResult rejected = run(g, act(g, true), null, ctx -> PcaCore.HookResult.enforced(false, "statement rejected", null));
        assertFalse(rejected.allow);
        assertEquals("fail", rejected.checks.get("zk_compliance"));
        assertTrue(rejected.reasons.stream().anyMatch(x -> x.contains("statement rejected")), rejected.reasons.toString());

        Authorize.AuthorizeResult threw = run(g, act(g, true), null, ctx -> { throw new IllegalStateException("verifier down"); });
        assertFalse(threw.allow);
        assertFalse("pass".equals(threw.checks.get("zk_compliance")));
    }

    @Test void aPcactnWithoutAProofNeverCallsTheZkHook() {
        Map<String, Object> g = grant(UNBOUND);
        List<PcaCore.Ctx> called = new ArrayList<>();
        Authorize.AuthorizeResult r = run(g, act(g, false), null, ctx -> { called.add(ctx); return PcaCore.HookResult.enforced(true); });
        assertTrue(r.allow, r.reasons.toString());
        assertTrue(called.isEmpty());
        assertFalse(r.checks.containsKey("zk_compliance"));
    }

    // ---- both together ---------------------------------------------------------------------------------------------------

    @Test void aBoundGrantWithAProofNeedsBothHooksToPass() {
        Map<String, Object> g = grant(BOUND);
        Authorize.AuthorizeResult both = run(g, act(g, true), OK, OK);
        assertTrue(both.allow, both.reasons.toString());
        assertEquals("pass", both.checks.get("attestation"));
        assertEquals("pass", both.checks.get("zk_compliance"));
        Authorize.AuthorizeResult noZk = run(g, act(g, true), OK, null);
        assertFalse(noZk.allow);
        assertEquals("pass", noZk.checks.get("attestation"));
        assertEquals("fail", noZk.checks.get("zk_compliance"));
        Authorize.AuthorizeResult noAtt = run(g, act(g, true), null, OK);
        assertFalse(noAtt.allow);
        assertEquals("fail", noAtt.checks.get("attestation"));
        assertEquals("pass", noAtt.checks.get("zk_compliance"));
    }

    @Test void theGuardOptionsCarryTheHooksIntoTheSameDecision() {
        Map<String, Object> g = grant(BOUND);
        Authorize.Options o = new Authorize.Options(new MemoryStateStore(), (p, gr) -> false).withAttestationHook(OK);
        assertTrue(o.attestationHook == OK);
        assertNull(new Authorize.Options(new MemoryStateStore(), (p, gr) -> false).attestationHook);
        assertEquals("pass", run(g, act(g, false), OK, null).checks.get("attestation"));
    }
}
