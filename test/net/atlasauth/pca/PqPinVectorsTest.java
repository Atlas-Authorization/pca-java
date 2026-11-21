package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Server-side PQ pins at the authorize pipeline (pq-pin-vectors.json, F3 pqPins): the {@code pq_pin} check status and its exact reason. */
public class PqPinVectorsTest {
    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static String sub(Object v, Map<String, Object> grant) {
        String s = (String) v;
        String pk = (String) grant.get("pq_pk");
        if (s.equals("$grant.issuer")) return (String) grant.get("issuer");
        if (s.equals("$grant.pq_pk")) return pk;
        if (s.equals("$grant.pq_pk[0:20]")) return pk.substring(0, 20);
        return s;
    }

    @SuppressWarnings("unchecked")
    @Test void everyCaseReproducesTheReference() {
        Map<String, Object> doc = Track3Vectors.load("pq-pin-vectors.json");
        List<Object> cases = (List<Object>) doc.get("pq_pin");
        assertTrue(cases.size() >= 8, "pq_pin cases: " + cases.size());
        for (Object x : cases) {
            Map<String, Object> c = m(x);
            String name = (String) c.get("name");
            Map<String, Object> v = PlanRootVectorsTest.vector((String) c.get("vector"));
            Map<String, Object> grant = m(v.get("grant"));
            Map<String, Object> ctx = m(v.get("context"));
            Map<String, Object> pcactn = m(v.get("pcactn"));
            Map<String, Object> action = m(pcactn.get("action"));
            Map<String, Object> pins = null;
            if (c.get("pq_pins") != null) {
                pins = new LinkedHashMap<>();
                for (Map.Entry<String, Object> e : m(c.get("pq_pins")).entrySet()) pins.put(sub(e.getKey(), grant), e.getValue() instanceof String ? sub(e.getValue(), grant) : e.getValue());
            }
            Authorize.Input in = new Authorize.Input().risk(RiskCtx.ZERO).operation(Authorize.Operation.of((String) action.get("verb"), (String) action.get("resource"), Map.of()))
                .audience((String) ctx.get("aud")).resolveGrant(ref -> grant).stateStore(new MemoryStateStore()).isRevoked((p, g) -> false)
                .plan(Authorize.SINGLE_STEP).now(Json.asLong(ctx.get("now"))).provenanceGate(ProvHarness.options()).pqPins(pins);
            Authorize.AuthorizeResult r = Authorize.authorize(pcactn, in);
            Map<String, Object> exp = m(c.get("expect"));
            String check = (String) exp.get("check");
            if (check.equals("absent")) assertFalse(r.checks.containsKey("pq_pin"), name);
            else assertEquals(check, r.checks.get("pq_pin"), name);
            if (exp.get("reason") instanceof String) assertTrue(r.reasons.contains(exp.get("reason")), name + ": " + r.reasons);
        }
    }
}
