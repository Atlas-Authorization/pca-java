package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The {@code fresh_at} PCActn member corpus (fresh-at-vectors.json): allow, the per-check booleans, the fresh_at outcome (pass / fail /
 * absent), the ternary decision (escalate-class failures) and the reason. A missing file or an unexpected vector count FAILS.
 * The reason is compared exactly for wire and fresh_at failures; for the pre-existing checks only the check name before ": " (their
 * wording is the shared corpus' business, the vectors.json runner pins it).
 */
public class FreshAtVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("fresh-at-vectors.json");

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    @Test void everyVectorReproducesTheReference() {
        assertEquals(1L, Json.asLong(DOC.get("format")));
        List<Object> vs = (List<Object>) DOC.get("vectors");
        assertEquals(28, vs.size());
        for (Object x : vs) {
            Map<String, Object> v = m(x);
            String name = (String) v.get("name");
            Map<String, Object> ctx = m(v.get("context"));
            K3.FreshAtPolicy policy = K3.FreshAtPolicy.fromJson(ctx.get("fresh_at"));
            Pca.Verdict got = Pca.verifyPcactn(v.get("pcactn"), m(v.get("grant")), Json.asLong(ctx.get("now")), (String) ctx.get("aud"), null, null, null, policy);
            Map<String, Object> exp = m(v.get("expect"));

            assertEquals(exp.get("allow"), got.allow, name + ": allow");
            Map<String, Boolean> checks = new LinkedHashMap<>(got.checks);
            checks.remove("fresh_at");
            assertEquals(m(exp.get("checks")), checks, name + ": checks");
            assertEquals(new ArrayList<>(m(exp.get("checks")).keySet()), new ArrayList<>(checks.keySet()), name + ": check order");
            String fresh = !got.checks.containsKey("fresh_at") ? "absent" : got.checks.get("fresh_at") ? "pass" : "fail";
            assertEquals(exp.get("fresh_at"), fresh, name + ": fresh_at");

            Map<String, String> status = new LinkedHashMap<>();
            for (Map.Entry<String, Boolean> en : got.checks.entrySet()) status.put(en.getKey(), en.getValue() ? "pass" : "fail");
            List<String> reasons = got.reason.isEmpty() ? new ArrayList<String>() : List.of(got.reason);
            assertEquals(exp.get("decision"), Decision.decisionOf(got.allow, status, reasons), name + ": decision (" + got.reason + ")");

            if (exp.get("reason") instanceof String) {
                String want = (String) exp.get("reason");
                if (want.startsWith("wire:") || want.startsWith("fresh_at:")) assertEquals(want, got.reason, name + ": reason");
                else assertTrue(got.reason.startsWith(want.substring(0, want.indexOf(':') + 1)), name + ": reason " + got.reason);
            } else assertEquals("", got.reason, name + ": no reason");
        }
    }

    /** No member and no policy: the verdict has no fresh_at entry at all (byte-identical to before). */
    @SuppressWarnings("unchecked")
    @Test void noMemberNoPolicyIsUnchanged() {
        for (Object x : (List<Object>) DOC.get("vectors")) {
            Map<String, Object> v = m(x);
            if (!"no-member-no-policy".equals(v.get("name"))) continue;
            Map<String, Object> ctx = m(v.get("context"));
            Pca.Verdict got = Pca.verifyPcactn(v.get("pcactn"), m(v.get("grant")), Json.asLong(ctx.get("now")), (String) ctx.get("aud"));
            assertTrue(got.allow);
            assertFalse(got.checks.containsKey("fresh_at"));
        }
    }
}
