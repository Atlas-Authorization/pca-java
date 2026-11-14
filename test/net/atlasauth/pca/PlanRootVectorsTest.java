package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The core {@code plan_root_authorized} check (plan-root-vectors.json, F1): authorizedPlanRoots / insecureSkipPlanRootCheck on the core
 * verifier. A missing file or a short corpus FAILS.
 */
public class PlanRootVectorsTest {
    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static Map<String, Object> vector(String name) {
        for (Object x : (List<Object>) Track3Vectors.load("vectors.json").get("vectors")) if (name.equals(m(x).get("name"))) return m(x);
        throw new AssertionError("no vector " + name);
    }

    @SuppressWarnings("unchecked")
    @Test void everyCaseReproducesTheReference() {
        Map<String, Object> doc = Track3Vectors.load("plan-root-vectors.json");
        List<Object> cases = (List<Object>) doc.get("plan_root_authorized");
        assertTrue(cases.size() >= 9, "plan_root_authorized cases: " + cases.size());
        for (Object x : cases) {
            Map<String, Object> c = m(x);
            String name = (String) c.get("name");
            Map<String, Object> v = vector((String) c.get("vector"));
            Map<String, Object> ctx = m(v.get("context"));
            String root = (String) m(m(v.get("pcactn")).get("plan")).get("root");
            Map<String, Object> o = m(c.get("options"));
            List<String> roots = null;
            if (o.get("authorizedPlanRoots") instanceof List) {
                roots = new ArrayList<>();
                for (Object r : (List<Object>) o.get("authorizedPlanRoots")) roots.add("$plan_root".equals(r) ? root : (String) r);
            }
            boolean skip = Boolean.TRUE.equals(o.get("insecureSkipPlanRootCheck"));
            Pca.Verdict got = Pca.verifyPcactn(v.get("pcactn"), m(v.get("grant")), Json.asLong(ctx.get("now")), (String) ctx.get("aud"), null, null, null, null,
                Pca.PlanRoots.of(roots, skip));
            Map<String, Object> exp = m(c.get("expect"));
            assertEquals(exp.get("allow"), got.allow, name + ": allow (" + got.reason + ")");
            String check = (String) exp.get("check");
            if (check.equals("pass")) assertEquals(Boolean.TRUE, got.checks.get("plan_root_authorized"), name);
            else if (check.equals("fail")) assertEquals(Boolean.FALSE, got.checks.get("plan_root_authorized"), name);
            else assertFalse(got.checks.containsKey("plan_root_authorized"), name + ": not enforced is unreported");
            if (exp.get("reason") instanceof String) assertEquals(exp.get("reason"), got.reason, name + ": reason");
            else assertEquals("", got.reason, name + ": no reason");
        }
        assertNotNull(doc);
    }

    @Test void theLegacyOverloadsRefuseWithNothingConfigured() {
        Map<String, Object> v = vector("valid-in-plan-action");
        Map<String, Object> ctx = m(v.get("context"));
        Pca.Verdict got = Pca.verifyPcactn(v.get("pcactn"), m(v.get("grant")), Json.asLong(ctx.get("now")), (String) ctx.get("aud"));
        assertFalse(got.allow);
        assertEquals("plan_root_authorized: no authorized plan is configured for this verifier (set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)", got.reason);
        assertEquals(Boolean.FALSE, got.checks.get("plan_root_authorized"));
    }
}
