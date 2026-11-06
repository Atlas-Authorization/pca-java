package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Workflow admission inside {@code Authorize.authorize} (K5, C-308): the shared fixtures pca-authorize-workflow-fixtures/1, each case
 * threading its steps through ONE replay store. A missing file FAILS (Track3Vectors.load).
 */
public class AuthorizeWorkflowTest {
    static final Map<String, Object> F = Track3Vectors.load("authorize-workflow-fixtures.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static Map<String, Object> kase(String name) {
        for (Object co : l(F.get("cases"))) if (name.equals(m(co).get("name"))) return m(co);
        throw new AssertionError("no fixture case " + name);
    }

    @Test void replaysTheSharedFixtures() {
        assertEquals("pca-authorize-workflow-fixtures/1", F.get("format"));
        assertTrue(l(F.get("cases")).size() >= 17);
        Map<String, Object> grant = m(F.get("grant"));
        long now = Json.asLong(F.get("now"));
        for (Object co : l(F.get("cases"))) {
            Map<String, Object> c = m(co);
            MemoryStateStore store = new MemoryStateStore();
            Authorize.WorkflowPin pin = new Authorize.WorkflowPin((String) F.get("principal"), (String) F.get("rs_signer"), Boolean.TRUE.equals(c.get("required")));
            List<Object> plan = l(F.get("plan"));
            int i = 0;
            for (Object so : l(c.get("steps"))) {
                Map<String, Object> s = m(so), op = m(s.get("operation")), want = m(s.get("expect"));
                String where = c.get("name") + " step " + i++;
                Authorize.Input in = new Authorize.Input()
                    .operation(Authorize.Operation.of((String) op.get("verb"), (String) op.get("resource"), m(op.get("params"))))
                    .audience((String) F.get("audience")).resolveGrant(ref -> ref.equals(grant.get("id")) ? grant : null)
                    .stateStore(store).isRevoked((p, g) -> false).now(now).plan(null)
                    .context(p -> Map.of("plan", plan, "plan_authorized", Boolean.TRUE)).workflow(pin)
                    .provenanceGate(ProvHarness.options()); // the reference harness presents a principal-direct bundle
                if (s.get("workflow") != null) {
                    Map<String, Object> w = m(s.get("workflow"));
                    in.workflowStep(new Authorize.WorkflowStep(w.get("commitment"), w.get("receipts"), (String) w.get("step"), w.get("units") == null ? null : m(w.get("units")), (String) w.get("goal_digest")));
                }
                Authorize.AuthorizeResult r = Authorize.authorize(s.get("pcactn"), in);
                List<String> failed = new ArrayList<>(r.failed());
                Collections.sort(failed);
                List<String> wantFailed = new ArrayList<>();
                for (Object f : l(want.get("failed"))) wantFailed.add((String) f);
                Collections.sort(wantFailed);
                assertEquals(want.get("allow"), r.allow, where + " allow");
                assertEquals(want.get("decision"), r.decision, where + " decision");
                assertEquals(Json.asLong(want.get("status")), (long) r.status, where + " status");
                assertEquals(wantFailed, failed, where + " failed");
                if (want.get("reason") != null) assertTrue(r.reason != null && r.reason.contains((String) want.get("reason")), where + " reason: " + r.reason);
            }
        }
    }

    @Test void noWorkflowOptionChangesNothing() {
        Map<String, Object> c = kase("workflow-optional-and-absent");
        Map<String, Object> s = m(l(c.get("steps")).get(0)), op = m(s.get("operation"));
        Map<String, Object> grant = m(F.get("grant"));
        Authorize.Input in = new Authorize.Input()
            .operation(Authorize.Operation.of((String) op.get("verb"), (String) op.get("resource"), m(op.get("params"))))
            .audience((String) F.get("audience")).resolveGrant(ref -> ref.equals(grant.get("id")) ? grant : null)
            .stateStore(new MemoryStateStore()).isRevoked((p, g) -> false).now(Json.asLong(F.get("now"))).plan(null)
            .context(p -> Map.of("plan", l(F.get("plan")), "plan_authorized", Boolean.TRUE)).provenanceGate(ProvHarness.options());
        assertTrue(Authorize.authorize(s.get("pcactn"), in).allow);
    }
}
