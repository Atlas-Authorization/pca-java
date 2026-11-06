package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.UnaryOperator;

import org.junit.jupiter.api.Test;

/** Authorize.run, the gates before the core checks: workflow admission, the plan registry, the intent v2 state, required checks. */
public class AuthorizeRunK05bKillTestFlowsTest {
    static Authorize.Input input() { return AuthorizeK05KillTest.input(Map.of("amount", 50L)); }

    static Map<String, Object> pcactn() { return AuthorizeK05KillTest.pcactn(); }

    static void refused(Authorize.AuthorizeResult r, int status, String check, String reason) {
        assertFalse(r.allow);
        assertEquals(status, r.status);
        assertEquals(Map.of(check, "fail"), r.checks);
        assertEquals(List.of(reason), r.reasons);
        assertEquals(reason, r.reason);
    }

    // ---- workflow ----------------------------------------------------------------------------------------------------------

    static final Authorize.WorkflowPin PIN = new Authorize.WorkflowPin((String) AuthorizeWorkflowTest.F.get("principal"),
        (String) AuthorizeWorkflowTest.F.get("rs_signer"), false);

    @Test void aRequiredWorkflowWithoutAStepIsRefused() {
        Authorize.WorkflowPin req = new Authorize.WorkflowPin(PIN.principal, PIN.rsSigner, true);
        refused(Authorize.authorize(pcactn(), input().workflow(req)), 403, "workflow", "workflow: this call carries no workflow step (fail closed)");
    }

    @Test void aStepThatIsNoWorkflowNamesNoStep() {
        Authorize.WorkflowStep step = new Authorize.WorkflowStep("not a commitment", List.of(), "quote", null, "g");
        refused(Authorize.authorize(pcactn(), input().workflow(PIN).workflowStep(step)), 403, "workflow", "workflow: bad_workflow");
    }

    @Test void aRefusedStepNamesTheStep() {
        // the first fixture step that carries a workflow and is admitted; its PCActn's plan root replaced by a non-string
        for (Object co : AuthorizeWorkflowTest.l(AuthorizeWorkflowTest.F.get("cases"))) {
            for (Object so : AuthorizeWorkflowTest.l(AuthorizeWorkflowTest.m(co).get("steps"))) {
                Map<String, Object> s = AuthorizeWorkflowTest.m(so);
                if (s.get("workflow") == null || !Boolean.TRUE.equals(AuthorizeWorkflowTest.m(s.get("expect")).get("allow"))) continue;
                Map<String, Object> w = AuthorizeWorkflowTest.m(s.get("workflow"));
                Map<String, Object> body = AuthorizeWorkflowTest.m(AuthorizeWorkflowTest.m(w.get("commitment")).get("body"));
                assertTrue(body.get("plan_root") instanceof String, "fixture premise: the workflow pins a plan root");
                Map<String, Object> pc = new LinkedHashMap<>(AuthorizeWorkflowTest.m(s.get("pcactn")));
                Map<String, Object> plan = new LinkedHashMap<>(AuthorizeWorkflowTest.m(pc.get("plan")));
                plan.put("root", 5L);
                pc.put("plan", plan);
                Map<String, Object> op = AuthorizeWorkflowTest.m(s.get("operation"));
                Authorize.Input in = new Authorize.Input()
                    .operation(Authorize.Operation.of((String) op.get("verb"), (String) op.get("resource"), AuthorizeWorkflowTest.m(op.get("params"))))
                    .audience((String) AuthorizeWorkflowTest.F.get("audience")).resolveGrant(ref -> AuthorizeWorkflowTest.m(AuthorizeWorkflowTest.F.get("grant")))
                    .stateStore(new MemoryStateStore()).isRevoked((p, g) -> false).now(Json.asLong(AuthorizeWorkflowTest.F.get("now"))).plan(null)
                    .workflow(PIN).workflowStep(new Authorize.WorkflowStep(w.get("commitment"), w.get("receipts"), (String) w.get("step"),
                        w.get("units") == null ? null : AuthorizeWorkflowTest.m(w.get("units")), (String) w.get("goal_digest")));
                refused(Authorize.authorize(pc, in), 403, "workflow", "workflow: plan_root_mismatch (step " + w.get("step") + ")");
                return;
            }
        }
        throw new AssertionError("fixture premise: no admitted workflow step");
    }

    // ---- the plan registry ---------------------------------------------------------------------------------------------------

    static final class DownKv implements AtomicKv {
        @Override public Object get(String key) { throw new IllegalStateException("down"); }
        @Override public void set(String key, Object value) { throw new IllegalStateException("down"); }
        @Override public Object update(String key, UnaryOperator<Object> fn) { throw new IllegalStateException("down"); }
    }

    @Test void aFailingRegistryIsRefused() {
        PlanRegistry reg = new PlanRegistry(new DownKv(), "pca-plan:", () -> AuthorizeK05KillTest.NOW, null);
        refused(Authorize.authorize(pcactn(), input().plans(reg)), 403, "plans", "plans: the plan registry failed (fail closed)");
    }

    @SuppressWarnings("unchecked")
    @Test void aPlanUnknownToTheRegistryIsNamedUnlessTheCallIsSingleStep() {
        Authorize.AuthorizeResult single = Authorize.authorize(pcactn(), input().plans(new PlanRegistry()));
        assertTrue(single.allow, single.reasons.toString());
        assertFalse(single.checks.containsKey("plan_state"));
        Map<String, Object> pc = pcactn();
        String root = (String) ((Map<String, Object>) pc.get("plan")).get("root");
        Authorize.AuthorizeResult r = Authorize.authorize(pc, input().plans(new PlanRegistry()).plan(null));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("plan_state"));
        assertTrue(r.reasons.contains("plan_state: plan " + root + " is unknown to the plan registry"), r.reasons.toString());
    }

    // ---- intent v2, required checks ------------------------------------------------------------------------------------------

    @Test void unavailableIntentV2StateIsRefused() {
        Function<Map<String, Object>, IntentV2.Context> down = p -> { throw new IllegalStateException("down"); };
        refused(Authorize.authorize(pcactn(), input().intentV2(down)), 403, "intent_v2", "intent_v2: verifier state unavailable (fail closed)");
    }

    @Test void aRequiredCheckNoGateRanIsAbsent() {
        Authorize.AuthorizeResult r = Authorize.authorize(pcactn(), input().require("unknown_check"));
        assertFalse(r.allow);
        assertEquals("deny", r.decision);
        assertEquals("fail", r.checks.get("unknown_check"));
        assertEquals(List.of("unknown_check: required check is absent (default-deny: not enforced by this resource server)"), r.reasons);
    }
}
