package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** authorize-pq-pin-fixtures.json end to end: the pq_pin check, status, decision and exact reason of every case, including a classical grant from a pinned issuer. */
public class AuthorizePqPinFixturesTest {
    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    @Test void everyCaseReproducesTheReference() {
        Map<String, Object> doc = Track3Vectors.load("authorize-pq-pin-fixtures.json");
        assertEquals("pca-authorize-pq-pin-fixtures/1", doc.get("format"));
        List<Object> cases = (List<Object>) doc.get("cases");
        assertTrue(cases.size() >= 9, "cases: " + cases.size());
        Map<String, Object> op = m(doc.get("operation"));
        for (Object x : cases) {
            Map<String, Object> c = m(x);
            String name = (String) c.get("name");
            Map<String, Object> grant = m(c.get("grant"));
            Authorize.Input in = new Authorize.Input().risk(RiskCtx.ZERO)
                .operation(Authorize.Operation.of((String) op.get("verb"), (String) op.get("resource"), m(op.get("params"))))
                .audience((String) doc.get("audience")).resolveGrant(ref -> grant).stateStore(new MemoryStateStore()).isRevoked((p, g) -> false)
                .plan(Authorize.SINGLE_STEP).now(Json.asLong(doc.get("now"))).provenanceGate(ProvHarness.options())
                .pqPins(c.get("pq_pins") == null ? null : m(c.get("pq_pins")));
            Authorize.AuthorizeResult r = Authorize.authorize(c.get("pcactn"), in);
            Map<String, Object> exp = m(c.get("expect"));
            assertEquals(exp.get("allow"), r.allow, name + ": " + r.reasons);
            assertEquals(((String) exp.get("decision")).toLowerCase(), String.valueOf(r.decision).toLowerCase(), name + ": decision");
            assertEquals((int) Json.asLong(exp.get("status")), r.status, name + ": status");
            for (Object f : (List<Object>) exp.get("failed_includes")) assertTrue(r.failed().contains(f), name + ": failed " + r.failed());
            String check = (String) m(exp.get("checks")).get("pq_pin");
            if (check.equals("absent")) assertFalse(r.checks.containsKey("pq_pin"), name);
            else assertEquals(check, r.checks.get("pq_pin"), name);
            if (exp.get("reason") instanceof String) assertTrue(r.reasons.stream().anyMatch(s -> s.contains((String) exp.get("reason"))), name + ": " + r.reasons);
        }
    }
}
