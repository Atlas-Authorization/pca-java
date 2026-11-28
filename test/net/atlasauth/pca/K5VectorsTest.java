package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The K5 corpus: workflow admission (workflow-vectors.json) and read-side authorization (readside-vectors.json). A missing file FAILS. */
public class K5VectorsTest {
    static final Map<String, Object> W = Track3Vectors.load("workflow-vectors.json");
    static final Map<String, Object> R = Track3Vectors.load("readside-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    /** Integer lexemes become Long (so the vectors compare with the results by value); everything else is kept. */
    static Object norm(Object o) {
        if (o instanceof Json.Num) return Json.isSafeInt(o) ? (Object) Json.asLong(o) : ((Json.Num) o).raw;
        if (o instanceof Map) { Map<String, Object> out = new LinkedHashMap<>(); for (Map.Entry<String, Object> e : m(o).entrySet()) out.put(e.getKey(), norm(e.getValue())); return out; }
        if (o instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : l(o)) out.add(norm(x)); return out; }
        return o;
    }

    static Workflow.Result run(boolean bind, Map<String, Object> c) {
        Object wf = m(W.get("workflows")).get(c.get("workflow"));
        return bind ? Workflow.bindPromises(wf, c.get("principal"), c.get("rs_signer"), c.get("receipts"), c.get("now"), c.get("request"))
            : Workflow.admitStep(wf, c.get("principal"), c.get("rs_signer"), c.get("receipts"), c.get("now"), c.get("request"));
    }

    @Test void workflowDigests() {
        Map<String, Object> d = m(W.get("digests"));
        assertEquals(d.get("workflow"), Workflow.workflowDigest(m(m(W.get("workflows")).get("main")).get("body")));
        for (Object x : l(d.get("values"))) assertEquals(m(x).get("digest"), Workflow.valueDigest(m(x).get("value")), "value digest");
        assertEquals(4, l(d.get("receipt_refs")).size());
    }

    @Test void admit() {
        assertEquals(62, l(W.get("admit")).size());
        for (Object x : l(W.get("admit"))) { Map<String, Object> c = m(x); assertEquals(norm(c.get("expect")), run(false, c).toMap(), "admit: " + c.get("name")); }
    }

    @Test void bind() {
        assertEquals(5, l(W.get("bind")).size());
        for (Object x : l(W.get("bind"))) { Map<String, Object> c = m(x); assertEquals(norm(c.get("expect")), run(true, c).toMap(), "bind: " + c.get("name")); }
    }

    @Test void planRoot() {
        assertTrue(l(W.get("plan_root")).size() >= 2);
        for (Object x : l(W.get("plan_root"))) {
            Map<String, Object> c = m(x);
            assertEquals(c.get("expect"), Workflow.planRootAuthorized(m(W.get("workflows")).get(c.get("workflow")), c.get("principal"), c.get("now"), c.get("root")), "plan_root: " + c.get("name"));
        }
    }

    @Test void everyDenialCodeIsExercised() {
        Set<String> seen = new HashSet<>();
        for (String k : new String[] {"admit", "bind"}) for (Object x : l(W.get(k))) { Object code = m(m(x).get("expect")).get("code"); if (code != null) seen.add((String) code); }
        for (String code : new String[] {"bad_workflow", "bad_dag", "bad_signature", "not_yet", "expired", "goal_mismatch", "plan_root_mismatch", "bad_receipt", "unplanned_step", "step_mismatch", "params_mismatch", "already_done", "budget_exceeded", "deps_unmet", "dep_failed", "stale_dep", "edge_missing", "edge_unit", "edge_digest", "edge_value", "edge_relation", "taint_flow", "pipeline_unconstrained", "taint_escalate"})
            assertTrue(seen.contains(code), code);
    }

    @Test void neverThrowsOnHostileInput() {
        Map<String, Object> keys = m(W.get("keys"));
        Map<String, Object> bodyNull = new LinkedHashMap<>(); bodyNull.put("body", null);
        Map<String, Object> bodyEmpty = new LinkedHashMap<>(); bodyEmpty.put("body", new LinkedHashMap<String, Object>()); bodyEmpty.put("sig", 1L);
        Object[] hostile = {null, 1L, "x", new ArrayList<>(), new LinkedHashMap<String, Object>(), bodyNull, bodyEmpty};
        for (Object x : hostile) assertEquals("deny", Workflow.admitStep(x, keys.get("principal"), keys.get("rs"), new ArrayList<>(), 1L, x).decision);
        assertEquals("deny", Workflow.admitStep(m(W.get("workflows")).get("main"), keys.get("principal"), keys.get("rs"), "x", 1L, new LinkedHashMap<String, Object>()).decision);
    }

    @Test void redact() {
        assertEquals(31, l(R.get("redact")).size());
        for (Object x : l(R.get("redact"))) {
            Map<String, Object> c = m(x), in = m(c.get("input"));
            ReadSide.Read got = ReadSide.redactRead(m(R.get("grants")).get(c.get("grant")), in.get("principal"), in.get("now"), in.get("verb"), in.get("resource"), in.get("purpose"), in.get("schema"), in.get("record"), in.get("tighten"), in.get("salt"), in.get("counts"));
            assertEquals(norm(c.get("expect")), got.toMap(), "redact: " + c.get("name"));
        }
    }

    @Test void sinks() {
        assertEquals(18, l(R.get("sinks")).size());
        for (Object x : l(R.get("sinks"))) {
            Map<String, Object> c = m(x);
            ReadSide.Sink got = ReadSide.checkSink(m(R.get("grants")).get(c.get("grant")), c.get("principal"), c.get("rs_signer"), c.get("now"), c.get("sink"), c.get("receipts"));
            assertEquals(norm(c.get("expect")), got.toMap(), "sink: " + c.get("name"));
        }
    }

    @Test void readDigestsAndChainLabels() {
        Map<String, Object> d = m(R.get("digests"));
        assertEquals(d.get("grant"), ReadSide.readGrantDigest(m(m(R.get("grants")).get("main")).get("body")));
        Object receipts = null;
        for (Object x : l(R.get("sinks"))) if ("chain-of-two-public-reads".equals(m(x).get("name"))) receipts = m(x).get("receipts");
        assertTrue(receipts != null, "chain-of-two-public-reads present");
        assertEquals(norm(d.get("chain_labels")), ReadSide.readChainLabels(receipts, m(R.get("keys")).get("rs"), (String) d.get("grant"), new Json.Num("1800000000000")).toMap());
    }

    @Test void maskedViewNeverContainsADroppedValue() {
        Map<String, Object> c = null;
        for (Object x : l(R.get("redact"))) if ("support-view".equals(m(x).get("name"))) c = m(x);
        assertTrue(c != null, "support-view present");
        String text = String.valueOf(norm(m(c.get("expect")).get("view")));
        for (String secret : new String[] {"sk_live_x", "123-45-6789", "dev-1", "c_77", "not in the schema"}) assertTrue(!text.contains(secret), secret);
    }
}
