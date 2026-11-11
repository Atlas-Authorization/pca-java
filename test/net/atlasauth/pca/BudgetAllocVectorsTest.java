package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** budget_alloc monotonicity over the flattened caveat list (budget-alloc-vectors.json): exact reasons. A missing file or a short corpus FAILS. */
public class BudgetAllocVectorsTest {
    @SuppressWarnings("unchecked")
    @Test void everyCaseReproducesTheReference() {
        Map<String, Object> doc = Track3Vectors.load("budget-alloc-vectors.json");
        List<Object> cases = (List<Object>) doc.get("budget_alloc");
        assertTrue(cases.size() >= 24, "cases: " + cases.size());
        for (Object x : cases) {
            Map<String, Object> c = (Map<String, Object>) x;
            String name = (String) c.get("name");
            Map<String, Object> exp = (Map<String, Object>) c.get("expect");
            String got = Pca.allocationsError(c.get("caveats"));
            if (Boolean.TRUE.equals(exp.get("ok"))) assertNull(got, name);
            else assertEquals(exp.get("reason"), got, name);
        }
    }
}
