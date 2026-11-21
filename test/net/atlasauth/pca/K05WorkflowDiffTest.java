package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for {@link Workflow}: a differential test against the TS reference (shared oracle
 * test-data/k05-workflow.json.gz, written by tools/pca-audit/k05-oracles/workflow-oracle.mts). Every body member deleted /
 * retyped / at its limit and RE-SIGNED, every receipt member (re-signed and not), every request member, the clock and the pinned
 * keys at their boundaries, budgets, freshness, edge operators and labels, promise binding, random DAGs, plan-root authorization
 * and the digests. Admission results are compared in full (decision, code, step, at, pending).
 */
public class K05WorkflowDiffTest {
    static final String MODULE = "k05-workflow";

    static List<Map<String, Object>> cases(String fn) throws Exception {
        List<Map<String, Object>> cs = K05Oracle.of(MODULE, fn);
        assertFalse(cs.isEmpty(), "no " + fn + " cases");
        return cs;
    }

    @SuppressWarnings("unchecked")
    static List<Object> args(Map<String, Object> c) { return (List<Object>) c.get("args"); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object o) { return (Map<String, Object>) o; }

    static boolean refThrows(Object out) { return out instanceof Map && ((Map<?, ?>) out).containsKey("$throws"); }

    static void report(String fn, List<String> bad, int n) {
        if (!bad.isEmpty()) fail(fn + ": " + bad.size() + "/" + n + " mismatches:\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 60))));
    }

    interface Fn { Object apply(List<Object> a); }

    /** Compare canonical JSON of Java's answer with the reference output; a reference throw must be a Java throw. */
    static void diff(String fn, Fn f) throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases(fn);
        for (Map<String, Object> c : cs) {
            Object out = c.get("out");
            String got;
            try {
                got = Json.canonicalize(f.apply(args(c)));
            } catch (RuntimeException e) {
                got = "threw " + e;
            }
            if (refThrows(out)) {
                if (!got.startsWith("threw ")) bad.add(c.get("name") + ": reference threw, got " + got);
                continue;
            }
            String want = Json.canonicalize(out);
            if (!Objects.equals(want, got)) bad.add(c.get("name") + ": want " + want + " got " + got);
        }
        report(fn, bad, cs.size());
    }

    @Test void admit() throws Exception { diff("admit", a -> Workflow.admitStep(a.get(0), a.get(1), a.get(2), a.get(3), a.get(4), a.get(5)).toMap()); }

    @Test void bind() throws Exception { diff("bind", a -> Workflow.bindPromises(a.get(0), a.get(1), a.get(2), a.get(3), a.get(4), a.get(5)).toMap()); }

    @Test void validBody() throws Exception { diff("validBody", a -> Workflow.validWorkflowBody(a.get(0))); }

    @Test void dag() throws Exception { diff("dag", a -> Workflow.dagError(obj(a.get(0)))); }

    @Test
    void ancestors() throws Exception {
        diff("ancestors", a -> {
            Map<String, Set<String>> m = Workflow.ancestors(obj(a.get(0)));
            if (m == null) return null;
            Map<String, Object> out = new TreeMap<>();
            for (Map.Entry<String, Set<String>> e : m.entrySet()) {
                List<String> v = new ArrayList<>(e.getValue());
                v.sort(null);
                out.put(e.getKey(), v);
            }
            return out;
        });
    }

    @Test void planRoot() throws Exception { diff("planRoot", a -> Workflow.planRootAuthorized(a.get(0), a.get(1), a.get(2), a.get(3))); }

    @Test void valueDigest() throws Exception { diff("valueDigest", a -> Workflow.valueDigest(a.get(0))); }

    @Test void workflowDigest() throws Exception { diff("workflowDigest", a -> Workflow.workflowDigest(a.get(0))); }

    @Test void receiptRef() throws Exception { diff("receiptRef", a -> Workflow.receiptRef(a.get(0))); }
}
