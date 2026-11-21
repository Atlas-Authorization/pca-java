package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.policybridge.Cedar;
import net.atlasauth.pca.policybridge.Cel;
import net.atlasauth.pca.policybridge.OpenFga;
import net.atlasauth.pca.policybridge.PolicyBridge;
import net.atlasauth.pca.policybridge.Rego;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle for the policy bridge (see the oracle header for the case shapes). */
class PolicyBridgeDiffTest {
    private static final String MODULE = "ref-policy-bridge";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Map<String, Object>> items(Object o) { return (List<Map<String, Object>>) o; }

    @Test void cedarToPca() throws Exception { OracleCases.each(MODULE, "cedarToPca", a -> Cedar.cedarToPca((String) a.get(0))); }
    @Test void translateCedar() throws Exception { OracleCases.each(MODULE, "translateCedar", a -> Cedar.translateCedar((String) a.get(0), (Boolean) a.get(1))); }
    @Test void regoToPca() throws Exception { OracleCases.each(MODULE, "regoToPca", a -> Rego.regoToPca((String) a.get(0))); }
    @Test void openfgaToPca() throws Exception { OracleCases.each(MODULE, "openfgaToPca", a -> OpenFga.openfgaToPca(a.get(0), a.get(1))); }
    @Test void decide() throws Exception { OracleCases.each(MODULE, "decide", a -> PolicyBridge.decide(m(a.get(0)), m(a.get(1)))); }
    @Test void celToCondition() throws Exception { OracleCases.each(MODULE, "celToCondition", a -> Cel.celToCondition((String) a.get(0), a.get(1))); }
    @Test void parseCel() throws Exception { OracleCases.each(MODULE, "parseCel", a -> Cel.parseCel((String) a.get(0))); }

    @Test void celToPredicate() throws Exception {
        OracleCases.each(MODULE, "celToPredicate", a -> {
            Map<String, Object> scope = m(a.get(2));
            return Cel.celToPredicate((String) a.get(0), a.get(1), scope.get("verb"), (String) scope.get("resource"));
        });
    }

    @Test void celConditionsToPca() throws Exception { OracleCases.each(MODULE, "celConditionsToPca", a -> Cel.celConditionsToPca(items(a.get(0)), a.get(1))); }

    /** A forbid that matches overrides a matching permit; an incomplete translation denies everything. */
    @Test void denyOverridesPermit() {
        Map<String, Object> r = Cedar.cedarToPca("permit (principal, action, resource); forbid (principal, action == Action::\"delete\", resource);");
        Map<String, Object> read = Map.of("subject", Map.of("id", "u"), "action", Map.of("verb", "read", "resource", "r"));
        Map<String, Object> del = Map.of("subject", Map.of("id", "u"), "action", Map.of("verb", "delete", "resource", "r"));
        assertEquals(Boolean.TRUE, PolicyBridge.decide(r, read).get("allowed"));
        assertEquals("forbidden by deny policy", PolicyBridge.decide(r, del).get("reason"));
        Map<String, Object> bad = Cedar.cedarToPca("forbid (principal, action, resource) when { resource.a + 1 < 2 };");
        assertTrue(!((List<?>) m(bad.get("report")).get("errors")).isEmpty());
        assertEquals("translation incomplete (fail closed)", PolicyBridge.decide(bad, read).get("reason"));
    }
}
