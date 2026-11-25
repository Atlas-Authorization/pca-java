package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills: {@code Authorize.Options.run} forwards usesStore, require, escalationRender and plans to the Input (each
 * option's effect observed through the guard-facing API), the (escalationAnswer, freshAt) overload returns the long form's
 * result, and the workflow request carries {@code units} as given ({} when the step has none).
 */
public class AuthorizeOptionsK05cKillTest {
    static final long NOW = AuthorizeK05KillTest.NOW;
    static final String AUD = AuthorizeK05KillTest.AUD;
    static final Authorize.Operation OP = Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 50L));
    static final Function<String, Map<String, Object>> RESOLVE =
        ref -> ref.equals(AuthorizeK05KillTest.GRANT.get("id")) ? AuthorizeK05KillTest.GRANT : null;

    @AfterEach void clearHook() { Authorize.coreHook = null; }

    /** The guard options equivalent of {@code AuthorizeK05KillTest.input}: single-step, never revoked, the provenance harness. */
    static Authorize.Options base() {
        return new Authorize.Options(new MemoryStateStore(), (p, g) -> false, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO).withProvenance(ProvHarness.options());
    }

    // ---- Options.run forwarding ---------------------------------------------------------------------------------------------

    @Test void theUsesStoreReachesTheMaxUsesCaveat() {
        Map<String, Object> g = AuthorizeRunK05bKillTest.usesGrant();
        Function<String, Map<String, Object>> resolve = ref -> ref.equals(g.get("id")) ? g : null;
        Authorize.AuthorizeResult none = base().k1(new LinkedHashMap<>()).run(AuthorizeRunK05bKillTest.act(g), OP, AUD, resolve, NOW);
        AuthorizeRunK05bKillTest.denied(none, "max_uses: the chain carries a max_uses caveat and this authorize call has no usesStore (fail closed)");
        Authorize.AuthorizeResult r = base().k1(new LinkedHashMap<>()).usesStore(new MemoryStateStore())
            .run(AuthorizeRunK05bKillTest.act(g), OP, AUD, resolve, NOW);
        AuthorizeRunK05bKillTest.allowed(r);
    }

    @Test void aRequiredCheckReachesTheDecision() {
        Authorize.Options o = new Authorize.Options(new MemoryStateStore(), (p, g) -> false, Authorize.SINGLE_STEP, null, List.of("unknown_check")).withRisk(RiskCtx.ZERO)
            .withProvenance(ProvHarness.options());
        Authorize.AuthorizeResult r = o.run(AuthorizeK05KillTest.pcactn(), OP, AUD, RESOLVE, NOW);
        AuthorizeRunK05bKillTest.denied(r, "unknown_check: required check is absent (default-deny: not enforced by this resource server)");
        assertEquals("fail", r.checks.get("unknown_check"));
        AuthorizeRunK05bKillTest.allowed(base().run(AuthorizeK05KillTest.pcactn(), OP, AUD, RESOLVE, NOW));
    }

    @Test void theEscalationRenderDigestIsInTheRequest() {
        AuthorizeRunK05bKillTest.escalate();
        String rd = Pca.b64(new byte[32]);
        Authorize.AuthorizeResult r = base().escalationRender(p -> rd).run(AuthorizeK05KillTest.pcactn(), OP, AUD, RESOLVE, NOW);
        assertEquals("escalate", r.decision, r.reasons.toString());
        assertEquals(rd, r.escalation.get("render_digest"));
        Authorize.AuthorizeResult bare = base().run(AuthorizeK05KillTest.pcactn(), OP, AUD, RESOLVE, NOW);
        assertEquals("escalate", bare.decision, bare.reasons.toString());
        assertFalse(bare.escalation.containsKey("render_digest"));
    }

    @SuppressWarnings("unchecked")
    @Test void thePlanRegistryJudgesThePlan() {
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        String root = (String) ((Map<String, Object>) pc.get("plan")).get("root");
        Authorize.Options noStep = new Authorize.Options(new MemoryStateStore(), (p, g) -> false, null, null, null).withRisk(RiskCtx.ZERO).withProvenance(ProvHarness.options());
        Authorize.AuthorizeResult r = noStep.withPlans(new PlanRegistry()).run(pc, OP, AUD, RESOLVE, NOW);
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("plan_state"));
        assertTrue(r.reasons.contains("plan_state: plan " + root + " is unknown to the plan registry"), r.reasons.toString());
        // without the registry the plan state is never judged
        Authorize.AuthorizeResult without = noStep.run(AuthorizeK05KillTest.pcactn(), OP, AUD, RESOLVE, NOW);
        assertFalse(without.checks.containsKey("plan_state"), without.checks.toString());
    }

    // ---- the (escalationAnswer, freshAt) overload ---------------------------------------------------------------------------

    @Test void theFreshAtOverloadIsTheLongForm() {
        Authorize.AuthorizeResult shortForm = base().run(AuthorizeK05KillTest.pcactn(), OP, AUD, RESOLVE, NOW, null, (K3.FreshAtPolicy) null);
        Authorize.AuthorizeResult longForm = base().run(AuthorizeK05KillTest.pcactn(), OP, AUD, RESOLVE, NOW, null, (Map<String, Object>) null, (K3.FreshAtPolicy) null);
        AuthorizeRunK05bKillTest.allowed(shortForm);
        assertEquals(longForm.allow, shortForm.allow);
        assertEquals(longForm.status, shortForm.status);
        assertEquals(longForm.decision, shortForm.decision);
        assertEquals(longForm.checks, shortForm.checks);
        assertEquals(longForm.reasons, shortForm.reasons);
    }

    // ---- the workflow request's units ---------------------------------------------------------------------------------------

    static Map<String, Object> m(Object o) { return AuthorizeWorkflowTest.m(o); }

    /** Step {@code i} of the fixture case, as AuthorizeWorkflowTest runs it, with {@code units} in place of the fixture's. */
    static Authorize.AuthorizeResult step(String kase, int i, Map<String, ?> units, MemoryStateStore store) {
        Map<String, Object> F = AuthorizeWorkflowTest.F, grant = m(F.get("grant"));
        Map<String, Object> s = m(AuthorizeWorkflowTest.l(AuthorizeWorkflowTest.kase(kase).get("steps")).get(i));
        Map<String, Object> op = m(s.get("operation")), w = m(s.get("workflow"));
        assertEquals(Map.of(), w.get("units"), "fixture premise: the step carries empty units");
        List<Object> plan = AuthorizeWorkflowTest.l(F.get("plan"));
        Authorize.Input in = new Authorize.Input().risk(RiskCtx.ZERO)
            .operation(Authorize.Operation.of((String) op.get("verb"), (String) op.get("resource"), m(op.get("params"))))
            .audience((String) F.get("audience")).resolveGrant(ref -> ref.equals(grant.get("id")) ? grant : null)
            .stateStore(store).isRevoked((p, g) -> false).now(Json.asLong(F.get("now"))).plan(null)
            .context(p -> Map.of("plan", plan, "plan_authorized", Boolean.TRUE))
            .workflow(new Authorize.WorkflowPin((String) F.get("principal"), (String) F.get("rs_signer"), false))
            .workflowStep(new Authorize.WorkflowStep(w.get("commitment"), w.get("receipts"), (String) w.get("step"), units, (String) w.get("goal_digest")))
            .provenanceGate(ProvHarness.options());
        return Authorize.authorize(s.get("pcactn"), in);
    }

    @Test void aStepWithoutUnitsIsAdmittedAsEmptyUnits() {
        // null units are sent as {} (Workflow refuses a request whose units are not an object: bad_workflow)
        MemoryStateStore store = new MemoryStateStore();
        Authorize.AuthorizeResult quote = step("pay-after-quote", 0, null, store);
        assertTrue(quote.allow, quote.reasons.toString());
        Authorize.AuthorizeResult pay = step("pay-after-quote", 1, null, store);
        assertTrue(pay.allow, pay.reasons.toString());
    }

    @Test void theStepsUnitsReachTheEdgeCheck() {
        // the quote->pay edge and the quote's total output are unit-less: a unit on `amount` is an edge_unit refusal
        Authorize.AuthorizeResult r = step("pay-after-quote", 1, Map.of("amount", "usd"), new MemoryStateStore());
        AuthorizeRunK05bKillTestFlowsTest.refused(r, 403, "workflow", "workflow: edge_unit (step pay)");
        // control: the same step with the fixture's {} units is admitted (the quote step first, on the same replay store)
        MemoryStateStore store = new MemoryStateStore();
        assertTrue(step("pay-after-quote", 0, Map.of(), store).allow);
        Authorize.AuthorizeResult empty = step("pay-after-quote", 1, Map.of(), store);
        assertTrue(empty.allow, empty.reasons.toString());
    }
}
