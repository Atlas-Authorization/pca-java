package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Rules 20 (units) and 21 (tighten-only) END TO END through {@link Authorize#authorize}: the signed cases of
 * model-rules-vectors.json, decided by the TypeScript reference. A missing file fails the test, it is never skipped.
 */
public class ModelRulesVectorsTest {
    static final String FILE = "conformance/model-rules-vectors.json";
    private static final Pattern MODEL = Pattern.compile("^(units|tighten|schema|intent_session): .*", Pattern.DOTALL);

    @SuppressWarnings("unchecked")
    static Map<String, Object> doc() throws Exception { return (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(FILE))); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static Authorize.AuthorizeResult run(Map<String, Object> doc, Map<String, Object> c) {
        Map<String, Object> grant = m(c.get("grant"));
        Map<String, Object> op = m(c.get("operation"));
        Authorize.Input in = new Authorize.Input()
            .operation(Authorize.Operation.of((String) op.get("verb"), (String) op.get("resource"), m(op.get("params"))))
            .audience((String) doc.get("audience"))
            .resolveGrant(ref -> ref.equals(grant.get("id")) ? grant : null)
            .stateStore(new MemoryStateStore())
            .isRevoked((p, g) -> false)
            .now(Json.asLong(doc.get("now")))
            .plan(Authorize.SINGLE_STEP)
            .provenanceGate(ProvHarness.options()); // the reference harness presents a principal-direct bundle
        if (c.containsKey("intent_v2")) in.intentV2(IntentV2.Context.fromJson(c.get("intent_v2")));
        if (c.containsKey("context") && m(c.get("context")).containsKey("env")) {
            Map<String, Object> ctx = new LinkedHashMap<>();
            ctx.put("env", m(c.get("context")).get("env"));
            in.context(p -> ctx);
        }
        return Authorize.authorize(c.get("pcactn"), in);
    }

    @Test void everyCaseDecidesLikeTheReference() throws Exception {
        Map<String, Object> d = doc();
        List<?> cases = (List<?>) d.get("cases");
        assertEquals(32, cases.size());
        for (Object o : cases) {
            Map<String, Object> c = m(o);
            String name = (String) c.get("name");
            Map<String, Object> e = m(c.get("expect"));
            Authorize.AuthorizeResult r = run(d, c);
            assertEquals(e.get("allow"), r.allow, name + " allow: " + r.reasons);
            assertEquals(e.get("decision"), r.decision, name + " decision: " + r.reasons);
            assertEquals(Json.asLong(e.get("status")), (long) r.status, name + " status");
            List<String> failed = new ArrayList<>(r.failed());
            Collections.sort(failed);
            assertEquals(e.get("failed"), failed, name + " failed");
            List<String> model = new ArrayList<>();
            for (String x : r.reasons) if (MODEL.matcher(x).matches()) model.add(x);
            assertEquals(e.get("reasons"), model, name + " reasons");
            if (e.containsKey("degraded")) assertEquals(e.get("degraded"), r.degraded, name + " degraded");
            else assertNull(r.degraded, name + " is not degraded");
            for (String k : new String[] {"units", "tighten"}) {
                if (e.containsKey(k)) assertEquals(e.get(k), r.checks.get(k), name + " check " + k);
                else assertFalse(r.checks.containsKey(k), name + " reports no " + k + " check");
            }
            assertEquals("allow".equals(r.decision), r.allow, name + ": allow is exactly decision == allow");
        }
    }

    @Test void theCorpusExercisesAllowEscalateAndDeny() throws Exception {
        Set<Object> seen = new HashSet<>();
        for (Object o : (List<?>) doc().get("cases")) seen.add(m(m(o).get("expect")).get("decision"));
        assertEquals(Set.of("allow", "escalate", "deny"), seen);
    }

    /** An escalation request is built for an escalating model rule, and carries the tighten reason. */
    @Test void anEscalatingRuleSurfacesTheRequest() throws Exception {
        Map<String, Object> d = doc();
        for (Object o : (List<?>) d.get("cases")) {
            Map<String, Object> c = m(o);
            if (!"tighten-escalate".equals(c.get("name"))) continue;
            Authorize.AuthorizeResult r = run(d, c);
            assertEquals("escalate", r.decision);
            assertTrue(r.escalation != null && "pca-escalation-request".equals(r.escalation.get("kind")));
            assertTrue(((List<?>) r.escalation.get("reasons")).contains("tighten: escalate: asked by tighten rule 'big'"));
        }
    }
}
