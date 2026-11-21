package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for {@link Workflow} (reference packages/pca/src/workflow.ts): the shape validators at and just past
 * every limit, each member of a step / edge / body / receipt / request refused in isolation, the DAG checks, the memoised
 * ancestor walk, plan-root authorization, the receipt-chain rules (order, duplicates, signatures, pipelined dependencies) and the
 * edge constraints (relational operators, taint labels, promise binding). Workflows and receipts are signed here with fixed seeds.
 */
public class K05R5G1WorkflowTest {
    static byte[] fill(int b) { byte[] s = new byte[32]; Arrays.fill(s, (byte) b); return s; }

    static final Keys.EdKey WK = Keys.edFromSeed(fill(0x31));
    static final Keys.EdKey RK = Keys.edFromSeed(fill(0x32));
    static final Keys.EdKey OTHER = Keys.edFromSeed(fill(0x33));
    static final String P = WK.id();
    static final String R = RK.id();
    static final long NOW = 500L;
    static final String D = Keys.b64u(fill(9));
    static final String PD = Pca.hashCanonical(map());

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    static Map<String, Object> m(Object o) { return Workflow.m(o); }

    static List<Object> l(Object o) { return Workflow.l(o); }

    // ---- builders ----

    static Map<String, Object> step(String id, String... deps) {
        return map("id", id, "verb", "do", "resource", "res", "params_digest", null, "deps", list((Object[]) deps), "sink", null,
            "deny_labels", list(), "escalate_labels", list(), "fresh_ms", null, "cost", map());
    }

    static Map<String, Object> edge(String from, String field, String to, String param, String op, Object unit, List<Object> deny, Object promise) {
        return map("from", map("step", from, "field", field), "to", map("step", to, "param", param), "op", op, "unit", unit, "deny_labels", deny, "promise", promise);
    }

    static Map<String, Object> body(List<Object> steps, List<Object> edges) {
        return map("v", 1L, "id", "wf", "principal", P, "goal_digest", null, "plan_root", null, "issued_at", 100L, "expires_at", 1000L,
            "steps", steps, "edges", edges, "budget", map("max_steps", 10L, "caps", map()));
    }

    static Map<String, Object> baseBody() {
        return body(list(step("a"), step("b", "a")), list(edge("a", "f", "b", "p", "eq", null, list(), null)));
    }

    static Map<String, Object> st(Map<String, Object> b, int i) { return m(l(b.get("steps")).get(i)); }

    static Map<String, Object> ed(Map<String, Object> b, int i) { return m(l(b.get("edges")).get(i)); }

    static boolean valid(Map<String, Object> b) { return Workflow.validWorkflowBody(b); }

    static byte[] msg(String domain, Object b) { return Pca.concat(domain.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(b)); }

    static Map<String, Object> signed(Map<String, Object> b) {
        return map("body", b, "sig", Keys.b64u(WK.sign(msg(Workflow.WORKFLOW_DOMAIN, b))));
    }

    static Map<String, Object> resign(Map<String, Object> r) {
        r.remove("sig");
        r.put("sig", Keys.b64u(RK.sign(msg(Workflow.WF_RECEIPT_DOMAIN, r))));
        return r;
    }

    static Map<String, Object> rc(Map<String, Object> b, String step, long seq, Map<String, Object> prev, String outcome, Map<String, Object> outputs, long issued) {
        Map<String, Object> r = map("v", 1L, "wf", Workflow.workflowDigest(b), "step", step, "seq", seq, "prev", prev == null ? null : Workflow.receiptRef(prev),
            "outcome", outcome, "params_digest", PD, "outputs", outputs, "issued_at", issued, "signer", R);
        return resign(r);
    }

    static Map<String, Object> out(String digest, Object num, Object unit, List<Object> labels) {
        return map("digest", digest, "num", num, "unit", unit, "labels", labels);
    }

    static Map<String, Object> req(String step, Map<String, Object> params) {
        return map("step", step, "verb", "do", "resource", "res", "params", params, "units", map(), "goal_digest", null, "plan_root", null);
    }

    static Workflow.Result admit(Map<String, Object> b, List<Object> receipts, String step, Map<String, Object> params) {
        return Workflow.admitStep(signed(b), P, R, receipts, NOW, req(step, params));
    }

    static Workflow.Result bind(Map<String, Object> b, List<Object> receipts, String step, Map<String, Object> params) {
        return Workflow.bindPromises(signed(b), P, R, receipts, NOW, req(step, params));
    }

    static void is(Workflow.Result r, String decision, String code, String step, Integer at) {
        assertNotNull(r);
        assertEquals(decision, r.decision);
        assertEquals(code, r.code);
        assertEquals(step, r.step);
        assertEquals(at, r.at);
    }

    static List<Object> ids(String prefix, int n) {
        List<Object> xs = new ArrayList<>();
        for (int i = 0; i < n; i++) xs.add(prefix + String.format("%02d", i));
        return xs;
    }

    // ---- shared helpers ----

    @Test void onlyKeysIsTotalAndExact() {
        assertFalse(Workflow.onlyKeys("x", List.of("a")));
        assertFalse(Workflow.onlyKeys(null, List.of("a")));
        assertFalse(Workflow.onlyKeys(list("a"), List.of("a")));
        assertFalse(Workflow.onlyKeys(map("b", 1L), List.of("a")));
        assertFalse(Workflow.onlyKeys(map("a", 1L, "b", 2L), List.of("a", "c")));
        assertFalse(Workflow.onlyKeys(map("a", 1L, "b", 2L), List.of("a")));
        assertTrue(Workflow.onlyKeys(map("a", 1L), List.of("a")));
        assertTrue(Workflow.onlyKeys(map("b", null, "a", 1L), List.of("a", "b")));
    }

    @Test void scalarMapIsBoundedAndTyped() {
        assertFalse(Workflow.isScalarMap("x"));
        assertFalse(Workflow.isScalarMap(null));
        assertTrue(Workflow.isScalarMap(map()));
        assertTrue(Workflow.isScalarMap(map("a", "s", "b", true, "c", 5L)));
        assertFalse(Workflow.isScalarMap(map("a b", 1L)));
        assertFalse(Workflow.isScalarMap(map("a", map())));
        assertFalse(Workflow.isScalarMap(map("a", null)));
        Map<String, Object> m32 = map();
        for (int i = 0; i < 32; i++) m32.put("k" + i, (long) i);
        assertTrue(Workflow.isScalarMap(m32));
        m32.put("k32", 32L);
        assertFalse(Workflow.isScalarMap(m32));
    }

    @Test void verifyBodyRefusesAForeignSignerType() {
        Map<String, Object> b = map("a", 1L);
        String sig = Keys.b64u(WK.sign(msg(Workflow.WORKFLOW_DOMAIN, b)));
        assertTrue(Workflow.verifyBody(Workflow.WORKFLOW_DOMAIN, b, P, sig));
        assertFalse(Workflow.verifyBody(Workflow.WORKFLOW_DOMAIN, b, 5L, sig));
        assertFalse(Workflow.verifyBody(Workflow.WORKFLOW_DOMAIN, b, null, sig));
        assertFalse(Workflow.verifyBody(Workflow.WORKFLOW_DOMAIN, b, map(), sig));
        assertFalse(Workflow.verifyBody(Workflow.WORKFLOW_DOMAIN, b, OTHER.id(), sig));
        assertFalse(Workflow.verifyBody(Workflow.WF_RECEIPT_DOMAIN, b, P, sig));
    }

    // ---- validWorkflowBody ----

    @Test void aBaseBodyIsValid() {
        assertTrue(valid(baseBody()));
        assertFalse(valid(null));
        assertFalse(Workflow.validWorkflowBody("x"));
    }

    @Test void bodyMembersAreExactAndTyped() {
        Map<String, Object> b = baseBody();
        b.put("x", 1L);
        assertFalse(valid(b));
        b = baseBody();
        b.remove("plan_root");
        assertFalse(valid(b));
        b = baseBody();
        b.put("v", 2L);
        assertFalse(valid(b));
        b = baseBody();
        b.put("id", "a b");
        assertFalse(valid(b));
        b = baseBody();
        b.put("principal", "x");
        assertFalse(valid(b));
        b = baseBody();
        b.put("goal_digest", "x");
        assertFalse(valid(b));
        b = baseBody();
        b.put("plan_root", "x");
        assertFalse(valid(b));
        b = baseBody();
        b.put("issued_at", -1L);
        assertFalse(valid(b));
        b = baseBody();
        b.put("expires_at", "x");
        assertFalse(valid(b));
        b = baseBody();
        b.put("goal_digest", D);
        b.put("plan_root", D);
        assertTrue(valid(b));
    }

    @Test void stepCountIsBoundedAtSixtyFour() {
        for (int n : new int[] {0, 1, 63, 64, 65}) {
            List<Object> steps = new ArrayList<>();
            for (Object id : ids("s", n)) steps.add(step((String) id));
            assertEquals(n >= 1 && n <= 64, valid(body(steps, list())), n + " steps");
        }
        Map<String, Object> b = baseBody();
        b.put("steps", "x");
        assertFalse(valid(b));
    }

    @Test void edgeCountIsBoundedAtTwoHundredFiftySix() {
        for (int n : new int[] {0, 255, 256, 257}) {
            List<Object> edges = new ArrayList<>();
            for (int i = 0; i < n; i++) edges.add(edge("a", "f", "b", "p", "eq", null, list(), null));
            assertEquals(n <= 256, valid(body(list(step("a"), step("b", "a")), edges)), n + " edges");
        }
        Map<String, Object> b = baseBody();
        b.put("edges", "x");
        assertFalse(valid(b));
    }

    @Test void budgetMembersAndCaps() {
        Map<String, Object> b = baseBody();
        b.put("budget", map("max_steps", 3L, "caps", map(), "x", 1L));
        assertFalse(valid(b));
        b = baseBody();
        b.put("budget", map("max_steps", 3L));
        assertFalse(valid(b));
        b = baseBody();
        b.put("budget", map("max_steps", -1L, "caps", map()));
        assertFalse(valid(b));
        b = baseBody();
        b.put("budget", map("max_steps", "x", "caps", map()));
        assertFalse(valid(b));
        b = baseBody();
        b.put("budget", "x");
        assertFalse(valid(b));
        b = baseBody();
        b.put("budget", map("max_steps", 3L, "caps", "x"));
        assertFalse(valid(b));
        b = baseBody();
        b.put("budget", map("max_steps", 3L, "caps", map("bad name", 1L)));
        assertFalse(valid(b));
        b = baseBody();
        b.put("budget", map("max_steps", 3L, "caps", map("c0", -1L)));
        assertFalse(valid(b));
        b = baseBody();
        b.put("budget", map("max_steps", 3L, "caps", map("c0", "x")));
        assertFalse(valid(b));
        b = baseBody();
        b.put("budget", map("max_steps", 0L, "caps", map("c0", 0L)));
        assertTrue(valid(b));
        for (int n : new int[] {7, 8, 9}) {
            Map<String, Object> caps = map();
            for (int i = 0; i < n; i++) caps.put("c" + i, 1L);
            b = baseBody();
            b.put("budget", map("max_steps", 3L, "caps", caps));
            assertEquals(n <= 8, valid(b), n + " caps");
        }
    }

    @Test void costNamesMustBeCappedAndBounded() {
        Map<String, Object> caps = map();
        Map<String, Object> cost = map();
        for (int i = 0; i < 8; i++) { caps.put("c" + i, 5L); cost.put("c" + i, 1L); }
        Map<String, Object> b = baseBody();
        b.put("budget", map("max_steps", 3L, "caps", caps));
        st(b, 0).put("cost", cost);
        assertTrue(valid(b));
        b = baseBody();
        st(b, 0).put("cost", map("zz", 1L));
        assertFalse(valid(b));
        b = baseBody();
        b.put("budget", map("max_steps", 3L, "caps", map("c0", 5L)));
        st(b, 0).put("cost", map("c0", -1L));
        assertFalse(valid(b));
        b = baseBody();
        b.put("budget", map("max_steps", 3L, "caps", map("c0", 5L)));
        st(b, 0).put("cost", map("bad name", 1L));
        assertFalse(valid(b));
        b = baseBody();
        st(b, 0).put("cost", "x");
        assertFalse(valid(b));
    }

    @Test void stepMembersAreExactAndTyped() {
        Map<String, Object> b = baseBody();
        st(b, 0).put("x", 1L);
        assertFalse(valid(b));
        b = baseBody();
        st(b, 0).remove("sink");
        st(b, 0).put("zz", null);
        assertFalse(valid(b));
        b = baseBody();
        l(b.get("steps")).set(0, "x");
        assertFalse(valid(b));
        b = baseBody();
        st(b, 0).put("id", "a b");
        assertFalse(valid(b));
        b = baseBody();
        st(b, 0).put("verb", "");
        assertFalse(valid(b));
        b = baseBody();
        st(b, 0).put("verb", "v".repeat(129));
        assertFalse(valid(b));
        b = baseBody();
        st(b, 0).put("verb", "v".repeat(128));
        assertTrue(valid(b));
        b = baseBody();
        st(b, 0).put("resource", "r".repeat(513));
        assertFalse(valid(b));
        b = baseBody();
        st(b, 0).put("resource", "r".repeat(512));
        assertTrue(valid(b));
        b = baseBody();
        st(b, 0).put("params_digest", "x");
        assertFalse(valid(b));
        b = baseBody();
        st(b, 0).put("params_digest", D);
        assertTrue(valid(b));
        b = baseBody();
        st(b, 0).put("sink", "a b");
        assertFalse(valid(b));
        b = baseBody();
        st(b, 0).put("sink", "out");
        assertTrue(valid(b));
        b = baseBody();
        st(b, 0).put("fresh_ms", -1L);
        assertFalse(valid(b));
        b = baseBody();
        st(b, 0).put("fresh_ms", 0L);
        assertTrue(valid(b));
    }

    @Test void stepListsAreSortedDistinctAndBoundedAtSixteen() {
        for (String member : new String[] {"deps", "deny_labels", "escalate_labels"}) {
            String pfx = member.equals("deps") ? "d" : "l";
            for (int n : new int[] {15, 16, 17}) {
                Map<String, Object> b = baseBody();
                st(b, 0).put(member, ids(pfx, n));
                assertEquals(n <= 16, valid(b), member + " x" + n);
            }
            Map<String, Object> b = baseBody();
            st(b, 0).put(member, list(pfx + "b", pfx + "a"));
            assertFalse(valid(b), member + " unsorted");
            b = baseBody();
            st(b, 0).put(member, list(pfx + "a", pfx + "a"));
            assertFalse(valid(b), member + " duplicate");
            b = baseBody();
            st(b, 0).put(member, "x");
            assertFalse(valid(b), member + " not a list");
            b = baseBody();
            st(b, 0).put(member, list(5L));
            assertFalse(valid(b), member + " not strings");
        }
        Map<String, Object> b = baseBody();
        st(b, 0).put("deny_labels", list("A"));
        assertFalse(valid(b));
        b = baseBody();
        st(b, 0).put("deps", list("A"));
        assertTrue(valid(b));
    }

    @Test void edgeMembersAreExactAndTyped() {
        Map<String, Object> b = baseBody();
        ed(b, 0).put("x", 1L);
        assertFalse(valid(b));
        b = baseBody();
        l(b.get("edges")).set(0, "x");
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("from", "x");
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("from", map("step", "a", "field", "f", "x", 1L));
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("from", map("step", "a b", "field", "f"));
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("from", map("step", "a", "field", "f g"));
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("to", "x");
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("to", map("step", "b", "param", "p", "x", 1L));
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("to", map("step", "b b", "param", "p"));
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("to", map("step", "b", "param", "p q"));
        assertFalse(valid(b));
        for (String op : new String[] {"eq", "le", "ge", "lt", "gt"}) {
            b = baseBody();
            ed(b, 0).put("op", op);
            assertTrue(valid(b), op);
        }
        b = baseBody();
        ed(b, 0).put("op", "zz");
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("op", 5L);
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("op", null);
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("unit", "a b");
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("unit", "u".repeat(17));
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("unit", "u".repeat(16));
        assertTrue(valid(b));
        b = baseBody();
        ed(b, 0).put("unit", 5L);
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("promise", "a b");
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("promise", 5L);
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("promise", "pr");
        assertTrue(valid(b));
    }

    @Test void edgeLabelsAreSortedDistinctAndBoundedAtSixteen() {
        for (int n : new int[] {15, 16, 17}) {
            Map<String, Object> b = baseBody();
            ed(b, 0).put("deny_labels", ids("l", n));
            assertEquals(n <= 16, valid(b), n + " labels");
        }
        Map<String, Object> b = baseBody();
        ed(b, 0).put("deny_labels", list("lb", "la"));
        assertFalse(valid(b));
        b = baseBody();
        ed(b, 0).put("deny_labels", "x");
        assertFalse(valid(b));
    }

    // ---- DAG ----

    @Test void dagErrors() {
        assertNull(Workflow.dagError(baseBody()));
        assertEquals("duplicate step id", Workflow.dagError(body(list(step("a"), step("a")), list())));
        assertEquals("bad dependency", Workflow.dagError(body(list(step("a", "zz")), list())));
        assertEquals("bad dependency", Workflow.dagError(body(list(step("a", "a")), list())));
        assertEquals("cycle", Workflow.dagError(body(list(step("a", "b"), step("b", "a")), list())));
        assertEquals("edge does not follow a dependency",
            Workflow.dagError(body(list(step("a"), step("b")), list(edge("a", "f", "b", "p", "eq", null, list(), null)))));
        assertEquals("edge does not follow a dependency",
            Workflow.dagError(body(list(step("a"), step("b", "a")), list(edge("a", "f", "zz", "p", "eq", null, list(), null)))));
        assertEquals("edge does not follow a dependency",
            Workflow.dagError(body(list(step("a"), step("b", "a")), list(edge("zz", "f", "b", "p", "eq", null, list(), null)))));
        assertEquals("edge does not follow a dependency",
            Workflow.dagError(body(list(step("a"), step("b", "a")), list(edge("b", "f", "a", "p", "eq", null, list(), null)))));
        assertNull(Workflow.dagError(body(list(step("a"), step("b", "a"), step("c", "b")), list(edge("a", "f", "c", "p", "eq", null, list(), null)))));
    }

    /** A step map that counts how often its dependencies are read. */
    static final class Counting extends LinkedHashMap<String, Object> {
        int depsReads;
        Counting(Map<String, Object> m) { super(m); }
        @Override public Object get(Object k) {
            if ("deps".equals(k)) depsReads++;
            return super.get(k);
        }
    }

    @Test void ancestorsAreMemoised() {
        Counting a = new Counting(step("a")), b = new Counting(step("b", "a")), c = new Counting(step("c", "a")), d = new Counting(step("d", "b", "c"));
        Map<String, Set<String>> anc = Workflow.ancestors(map("steps", list(a, b, c, d)));
        assertEquals(Set.of(), anc.get("a"));
        assertEquals(Set.of("a"), anc.get("b"));
        assertEquals(Set.of("a"), anc.get("c"));
        assertEquals(Set.of("a", "b", "c"), anc.get("d"));
        assertEquals(1, a.depsReads);
        assertEquals(1, b.depsReads);
        assertEquals(1, c.depsReads);
        assertEquals(1, d.depsReads);
        assertNull(Workflow.ancestors(map("steps", list(step("a", "b"), step("b", "a")))));
        assertNull(Workflow.ancestors(map("steps", list(step("a", "b"), step("b", "c"), step("c", "a")))));
        assertNull(Workflow.ancestors(map("steps", list(step("a", "a")))));
    }

    // ---- plan-root authorization ----

    @Test void planRootAuthorizationChecksEveryCondition() {
        Map<String, Object> b = baseBody();
        b.put("plan_root", D);
        Map<String, Object> wf = signed(b);
        assertTrue(Workflow.planRootAuthorized(wf, P, NOW, D));
        assertTrue(Workflow.planRootAuthorized(wf, P, 100L, D));
        assertTrue(Workflow.planRootAuthorized(wf, P, 999L, D));
        assertFalse(Workflow.planRootAuthorized(wf, P, 99L, D));
        assertFalse(Workflow.planRootAuthorized(wf, P, 1000L, D));
        assertFalse(Workflow.planRootAuthorized(wf, P, -1L, D));
        assertFalse(Workflow.planRootAuthorized(wf, P, 500.5, D));
        assertFalse(Workflow.planRootAuthorized(wf, P, "500", D));
        assertFalse(Workflow.planRootAuthorized(wf, P, null, D));
        assertFalse(Workflow.planRootAuthorized(wf, P, NOW, Keys.b64u(fill(8))));
        assertFalse(Workflow.planRootAuthorized(wf, P, NOW, null));
        assertFalse(Workflow.planRootAuthorized(wf, OTHER.id(), NOW, D));
        assertFalse(Workflow.planRootAuthorized(wf, 5L, NOW, D));
        assertFalse(Workflow.planRootAuthorized(wf, null, NOW, D));
        assertFalse(Workflow.planRootAuthorized("x", P, NOW, D));
        assertFalse(Workflow.planRootAuthorized(null, P, NOW, D));
        assertFalse(Workflow.planRootAuthorized(map("body", b), P, NOW, D));
        assertFalse(Workflow.planRootAuthorized(map("body", b, "sig", Keys.b64u(new byte[64])), P, NOW, D));
        assertFalse(Workflow.planRootAuthorized(map("body", b, "sig", 5L), P, NOW, D));
        // a signed body whose shape is invalid (unsorted labels)
        Map<String, Object> bad = baseBody();
        bad.put("plan_root", D);
        st(bad, 0).put("deny_labels", list("lb", "la"));
        assertFalse(Workflow.planRootAuthorized(signed(bad), P, NOW, D));
        // a signed body that is not a DAG (a step depending on itself)
        Map<String, Object> cyc = body(list(step("a", "a")), list());
        cyc.put("plan_root", D);
        assertFalse(Workflow.planRootAuthorized(signed(cyc), P, NOW, D));
        // a signed body that names another principal
        Map<String, Object> other = baseBody();
        other.put("plan_root", D);
        other.put("principal", OTHER.id());
        assertFalse(Workflow.planRootAuthorized(signed(other), P, NOW, D));
        assertFalse(Workflow.planRootAuthorized(signed(other), OTHER.id(), NOW, D), "signed by the wrong key");
    }

    @Test void planRootAuthorizationFailsClosedOnAHostileMap() {
        Map<String, Object> boom = new HashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("boom"); }
        };
        assertFalse(Workflow.planRootAuthorized(boom, P, NOW, D));
    }

    // ---- admission: request / workflow shape ----

    static void badWorkflow(Workflow.Result r) {
        is(r, "deny", "bad_workflow", null, null);
        assertTrue(r.pending.isEmpty());
    }

    @Test void aBaseAdmissionIsAllowed() {
        Map<String, Object> b = baseBody();
        Map<String, Object> ra = rc(b, "a", 0, null, "ok", map("f", out(Workflow.valueDigest(5L), null, null, list())), 200L);
        Workflow.Result r = admit(b, list(ra), "b", map("p", 5L));
        is(r, "allow", null, "b", null);
        assertTrue(r.pending.isEmpty());
        is(admit(b, list(), "a", map()), "allow", null, "a", null);
    }

    @Test void evaluateWorkflowArgument() {
        Map<String, Object> b = baseBody();
        Map<String, Object> rq = req("a", map());
        badWorkflow(Workflow.admitStep("x", P, R, list(), NOW, rq));
        badWorkflow(Workflow.admitStep(null, P, R, list(), NOW, rq));
        Map<String, Object> extra = signed(b);
        extra.put("x", 1L);
        badWorkflow(Workflow.admitStep(extra, P, R, list(), NOW, rq));
        badWorkflow(Workflow.admitStep(map("body", b), P, R, list(), NOW, rq));
        Map<String, Object> badShape = baseBody();
        st(badShape, 0).put("deny_labels", list("lb", "la"));
        badWorkflow(Workflow.admitStep(signed(badShape), P, R, list(), NOW, rq));
        Map<String, Object> badBudget = baseBody();
        badBudget.put("budget", map("max_steps", 3L, "caps", map(), "x", 1L));
        badWorkflow(Workflow.admitStep(signed(badBudget), P, R, list(), NOW, rq));
    }

    @Test void evaluateRequestArgument() {
        Map<String, Object> wf = signed(baseBody());
        Map<String, Object> extra = req("a", map());
        extra.put("x", 1L);
        badWorkflow(Workflow.admitStep(wf, P, R, list(), NOW, extra));
        badWorkflow(Workflow.admitStep(wf, P, R, list(), NOW, req("a", map("p", map()))));
        badWorkflow(Workflow.admitStep(wf, P, R, list(), NOW, req("a b", map())));
        Map<String, Object> unitsBad = req("a", map());
        unitsBad.put("units", map("bad key", "usd"));
        badWorkflow(Workflow.admitStep(wf, P, R, list(), NOW, unitsBad));
        Map<String, Object> unitsBad2 = req("a", map());
        unitsBad2.put("units", map("p", "a b"));
        badWorkflow(Workflow.admitStep(wf, P, R, list(), NOW, unitsBad2));
        Map<String, Object> unitsNotMap = req("a", map());
        unitsNotMap.put("units", "x");
        badWorkflow(Workflow.admitStep(wf, P, R, list(), NOW, unitsNotMap));
        Map<String, Object> verbEmpty = req("a", map());
        verbEmpty.put("verb", "");
        badWorkflow(Workflow.admitStep(wf, P, R, list(), NOW, verbEmpty));
        Map<String, Object> goalBad = req("a", map());
        goalBad.put("goal_digest", "x");
        badWorkflow(Workflow.admitStep(wf, P, R, list(), NOW, goalBad));
        Map<String, Object> rootBad = req("a", map());
        rootBad.put("plan_root", "x");
        badWorkflow(Workflow.admitStep(wf, P, R, list(), NOW, rootBad));
        badWorkflow(Workflow.admitStep(wf, P, R, list(), NOW, "x"));
        Map<String, Object> missing = req("a", map());
        missing.remove("resource");
        badWorkflow(Workflow.admitStep(wf, P, R, list(), NOW, missing));
        Map<String, Object> ok = req("a", map("p", "s", "q", true, "r", 7L));
        is(Workflow.admitStep(wf, P, R, list(), NOW, ok), "allow", null, "a", null);
    }

    @Test void evaluatePinnedArguments() {
        Map<String, Object> wf = signed(baseBody());
        Map<String, Object> rq = req("a", map());
        badWorkflow(Workflow.admitStep(wf, "x", R, list(), NOW, rq));
        badWorkflow(Workflow.admitStep(wf, 5L, R, list(), NOW, rq));
        badWorkflow(Workflow.admitStep(wf, P, "x", list(), NOW, rq));
        badWorkflow(Workflow.admitStep(wf, P, R, list(), 500.5, rq));
        badWorkflow(Workflow.admitStep(wf, P, R, list(), -1L, rq));
        badWorkflow(Workflow.admitStep(wf, P, R, list(), "500", rq));
        // a missing receipt list is malformed, whatever else is wrong with the workflow
        Map<String, Object> expired = baseBody();
        expired.put("expires_at", 400L);
        badWorkflow(Workflow.admitStep(signed(expired), P, R, null, NOW, rq));
        is(Workflow.admitStep(signed(expired), P, R, list(), NOW, rq), "deny", "expired", "a", null);
        badWorkflow(Workflow.admitStep(signed(expired), P, R, "x", NOW, rq));
        // a principal that is not 32 bytes is malformed, not a signature failure
        badWorkflow(Workflow.admitStep(wf, OTHER.id().substring(1), R, list(), NOW, rq));
        is(Workflow.admitStep(wf, OTHER.id(), R, list(), NOW, rq), "deny", "bad_signature", "a", null);
        // an unpinned receipt signer that is not 32 bytes
        badWorkflow(Workflow.admitStep(wf, P, R.substring(1), list(), NOW, rq));
    }

    @Test void evaluateTimeAndBindingDenials() {
        Map<String, Object> b = baseBody();
        Workflow.Result r = Workflow.admitStep(signed(b), P, R, list(), 99L, req("a", map()));
        is(r, "deny", "not_yet", "a", null);
        is(Workflow.admitStep(signed(b), P, R, list(), 1000L, req("a", map())), "deny", "expired", "a", null);
        is(Workflow.admitStep(signed(b), P, R, list(), 100L, req("a", map())), "allow", null, "a", null);
        is(Workflow.admitStep(signed(b), P, R, list(), 999L, req("a", map())), "allow", null, "a", null);
        Map<String, Object> tampered = signed(b);
        tampered.put("sig", Keys.b64u(new byte[64]));
        is(Workflow.admitStep(tampered, P, R, list(), NOW, req("a", map())), "deny", "bad_signature", "a", null);
        Map<String, Object> cyc = body(list(step("a", "b"), step("b", "a")), list());
        is(Workflow.admitStep(signed(cyc), P, R, list(), NOW, req("a", map())), "deny", "bad_dag", "a", null);
        is(admit(b, list(), "zz", map()), "deny", "unplanned_step", "zz", null);
    }

    // ---- receipts ----

    static Map<String, Object> rcBody() {
        return body(list(step("a"), step("b", "a"), step("c")), list(edge("a", "f", "b", "p", "eq", null, list(), null)));
    }

    static Map<String, Object> goodOutputs() { return map("f", out(Workflow.valueDigest(5L), null, null, list())); }

    static Map<String, Object> ra(Map<String, Object> b) { return rc(b, "a", 0, null, "ok", goodOutputs(), 200L); }

    static void badReceipt(Map<String, Object> b, List<Object> receipts, int at) {
        is(admit(b, receipts, "b", map("p", 5L)), "deny", "bad_receipt", "b", at);
    }

    static void goodReceipts(Map<String, Object> b, List<Object> receipts) {
        is(admit(b, receipts, "b", map("p", 5L)), "allow", null, "b", null);
    }

    @Test void aChainOfReceiptsIsAdmitted() {
        Map<String, Object> b = rcBody();
        Map<String, Object> r0 = ra(b);
        Map<String, Object> r1 = rc(b, "c", 1, r0, "ok", map(), 210L);
        goodReceipts(b, list(r0));
        goodReceipts(b, list(r0, r1));
        goodReceipts(b, list(rc(b, "a", 0, null, "ok", goodOutputs(), 500L)));
    }

    @Test void receiptsAreBoundToTheWorkflowSignerAndPosition() {
        Map<String, Object> b = rcBody();
        Map<String, Object> r0 = ra(b);
        Map<String, Object> r1 = rc(b, "c", 1, r0, "ok", map(), 210L);
        badReceipt(b, list(rc(b, "zz", 0, null, "ok", goodOutputs(), 200L)), 0);
        Map<String, Object> wrongSigner = ra(b);
        wrongSigner.put("signer", OTHER.id());
        badReceipt(b, list(resign(wrongSigner)), 0);
        Map<String, Object> wrongWf = ra(b);
        wrongWf.put("wf", D);
        badReceipt(b, list(resign(wrongWf)), 0);
        badReceipt(b, list(rc(b, "a", 1, rc(b, "c", 0, null, "ok", map(), 1L), "ok", goodOutputs(), 200L)), 0);
        badReceipt(b, list(rc(b, "a", 0, null, "ok", goodOutputs(), 501L)), 0);
        Map<String, Object> tampered = ra(b);
        tampered.put("sig", Keys.b64u(RK.sign(new byte[] {1})));
        badReceipt(b, list(tampered), 0);
        Map<String, Object> flipped = ra(b);
        flipped.put("outcome", "failed");
        badReceipt(b, list(flipped), 0);
        // the second receipt
        Map<String, Object> wrongPrev = rc(b, "c", 1, r0, "ok", map(), 210L);
        wrongPrev.put("prev", D);
        badReceipt(b, list(r0, resign(wrongPrev)), 1);
        Map<String, Object> tampered1 = rc(b, "c", 1, r0, "ok", map(), 210L);
        tampered1.put("sig", Keys.b64u(RK.sign(new byte[] {2})));
        badReceipt(b, list(r0, tampered1), 1);
        badReceipt(b, list(r0, rc(b, "a", 1, r0, "ok", goodOutputs(), 210L)), 1);
        badReceipt(b, list(r0, rc(b, "zz", 1, r0, "ok", map(), 210L)), 1);
        badReceipt(b, list(r0, rc(b, "c", 1, r1, "ok", map(), 210L)), 1);
        badReceipt(b, list(r0, rc(b, "c", 2, r0, "ok", map(), 210L)), 1);
        badReceipt(b, list(r0, rc(b, "c", 0, null, "ok", map(), 210L)), 1);
    }

    @Test void receiptMembersAreExactAndTyped() {
        Map<String, Object> b = rcBody();
        for (String[] kv : new String[][] {{"v", "2"}, {"wf", "x"}, {"params_digest", "x"}, {"signer", "x"}, {"outcome", "bogus"}}) {
            Map<String, Object> r = ra(b);
            r.put(kv[0], kv[0].equals("v") ? (Object) 2L : kv[1]);
            badReceipt(b, list(resign(r)), 0);
        }
        for (String k : new String[] {"step", "seq", "params_digest", "signer", "wf"}) {
            Map<String, Object> r = ra(b);
            r.put(k, 5L);
            badReceipt(b, list(resign(r)), 0);
        }
        Map<String, Object> r = ra(b);
        r.put("seq", "x");
        badReceipt(b, list(resign(r)), 0);
        r = ra(b);
        r.put("seq", -1L);
        badReceipt(b, list(resign(r)), 0);
        r = ra(b);
        r.put("issued_at", -1L);
        badReceipt(b, list(resign(r)), 0);
        r = ra(b);
        r.put("issued_at", "x");
        badReceipt(b, list(resign(r)), 0);
        r = ra(b);
        r.put("sig", 5L);
        badReceipt(b, list(r), 0);
        r = ra(b);
        r.put("prev", D);
        badReceipt(b, list(resign(r)), 0);
        r = ra(b);
        r.put("x", 1L);
        badReceipt(b, list(resign(r)), 0);
        r = ra(b);
        r.remove("outputs");
        badReceipt(b, list(resign(r)), 0);
        badReceipt(b, list("x"), 0);
        badReceipt(b, list((Object) null), 0);
        // the params digest of a receipt that is not the one asked about must still be a digest
        Map<String, Object> r0 = ra(b);
        Map<String, Object> r1 = rc(b, "c", 1, r0, "ok", map(), 210L);
        r1.put("params_digest", "x");
        badReceipt(b, list(r0, resign(r1)), 1);
        r1 = rc(b, "c", 1, r0, "ok", map(), 210L);
        r1.put("issued_at", -5L);
        badReceipt(b, list(r0, resign(r1)), 1);
    }

    @Test void receiptOutputsAreBoundedAndTyped() {
        Map<String, Object> b = rcBody();
        Map<String, Object> fill31 = goodOutputs();
        for (int i = 0; i < 31; i++) fill31.put("o" + String.format("%02d", i), out(D, null, null, list()));
        goodReceipts(b, list(rc(b, "a", 0, null, "ok", fill31, 200L)));
        Map<String, Object> fill32 = new LinkedHashMap<>(fill31);
        fill32.put("o31", out(D, null, null, list()));
        badReceipt(b, list(rc(b, "a", 0, null, "ok", fill32, 200L)), 0);
        Map<String, Object> r = ra(b);
        r.put("outputs", "x");
        badReceipt(b, list(resign(r)), 0);
        for (Object bad : new Object[] {"x", null, map("digest", D), map("digest", D, "num", null, "unit", null, "labels", list(), "x", 1L)}) {
            Map<String, Object> outs = goodOutputs();
            outs.put("g", bad);
            badReceipt(b, list(rc(b, "a", 0, null, "ok", outs, 200L)), 0);
        }
        Map<String, Object> badName = goodOutputs();
        badName.put("bad name", out(D, null, null, list()));
        badReceipt(b, list(rc(b, "a", 0, null, "ok", badName, 200L)), 0);
        for (Map<String, Object> v : List.of(out("x", null, null, list()), out(D, -1L, null, list()), out(D, "x", null, list()), out(D, null, "a b", list()),
                out(D, null, null, list("lb", "la")), out(D, null, null, list("A")), map("digest", D, "num", null, "unit", null, "labels", "x"), out(D, null, null, ids("l", 17)))) {
            Map<String, Object> outs = goodOutputs();
            outs.put("g", v);
            badReceipt(b, list(rc(b, "a", 0, null, "ok", outs, 200L)), 0);
        }
        for (Map<String, Object> v : List.of(out(D, 0L, null, list()), out(D, 3L, "usd", list()), out(D, null, "u".repeat(16), list()), out(D, null, null, ids("l", 16)))) {
            Map<String, Object> outs = goodOutputs();
            outs.put("g", v);
            goodReceipts(b, list(rc(b, "a", 0, null, "ok", outs, 200L)));
        }
    }

    // ---- pipelined receipts (a receipt before its dependency's) ----

    static Map<String, Object> pipeBody(Object promise, boolean withEdge) {
        return body(list(step("a"), step("b", "a"), step("c")), withEdge ? list(edge("a", "f", "b", "p", "eq", null, list(), promise)) : list());
    }

    @Test void aPromisedDependencyMayBeReceiptedLater() {
        Map<String, Object> b = pipeBody("pr", true);
        Map<String, Object> rb = rc(b, "b", 0, null, "ok", map(), 200L);
        is(admit(b, list(rb), "c", map()), "allow", null, "c", null);
        // an unpromised edge does not allow it
        Map<String, Object> bu = pipeBody(null, true);
        is(admit(bu, list(rc(bu, "b", 0, null, "ok", map(), 200L)), "c", map()), "deny", "bad_receipt", "c", 0);
        // neither does the absence of any edge
        Map<String, Object> bn = pipeBody(null, false);
        is(admit(bn, list(rc(bn, "b", 0, null, "ok", map(), 200L)), "c", map()), "deny", "bad_receipt", "c", 0);
        // the offending receipt is reported at its own index
        Map<String, Object> rcc = rc(bn, "c", 0, null, "ok", map(), 200L);
        Map<String, Object> rbn = rc(bn, "b", 1, rcc, "ok", map(), 210L);
        is(admit(bn, list(rcc, rbn), "a", map()), "deny", "bad_receipt", "a", 1);
    }

    @Test void onlyEdgesFromTheMissingDependencyIntoTheStepCount() {
        // an unpromised edge from the missing dependency into ANOTHER step does not count against this one
        Map<String, Object> b1 = body(list(step("a"), step("b", "a"), step("y", "a")),
            list(edge("a", "f", "b", "p", "eq", null, list(), "pr"), edge("a", "f", "y", "p", "eq", null, list(), null)));
        Map<String, Object> rb = rc(b1, "b", 0, null, "ok", map(), 200L);
        Workflow.Result r = admit(b1, list(rb), "y", map());
        is(r, "escalate", "pipeline_unconstrained", "y", null);
        assertTrue(r.pending.isEmpty());
        // an unpromised edge from ANOTHER (already receipted) dependency into the step does not count against the missing one
        Map<String, Object> b2 = body(list(step("a"), step("x"), step("b", "a", "x")),
            list(edge("x", "f", "b", "q", "eq", null, list(), null), edge("a", "f", "b", "p", "eq", null, list(), "pr")));
        Map<String, Object> rx = rc(b2, "x", 0, null, "ok", map(), 200L);
        Map<String, Object> rb2 = rc(b2, "b", 1, rx, "ok", map(), 210L);
        is(admit(b2, list(rx, rb2), "a", map()), "allow", null, "a", null);
    }

    // ---- dependencies ----

    @Test void dependencyOutcomeAndFreshness() {
        Map<String, Object> b = baseBody();
        Map<String, Object> failed = rc(b, "a", 0, null, "failed", goodOutputs(), 200L);
        is(admit(b, list(failed), "b", map("p", 5L)), "deny", "dep_failed", "b", null);
        Map<String, Object> fresh = baseBody();
        st(fresh, 1).put("fresh_ms", 300L);
        is(admit(fresh, list(rc(fresh, "a", 0, null, "ok", goodOutputs(), 200L)), "b", map("p", 5L)), "allow", null, "b", null);
        is(admit(fresh, list(rc(fresh, "a", 0, null, "ok", goodOutputs(), 199L)), "b", map("p", 5L)), "deny", "stale_dep", "b", null);
        // an unpromised edge from the missing dependency lets an admission through as unconstrained, no edge at all does not
        is(admit(b, list(), "b", map("p", 5L)), "escalate", "pipeline_unconstrained", "b", null);
        Map<String, Object> noEdge = body(list(step("a"), step("b", "a")), list());
        is(admit(noEdge, list(), "b", map()), "deny", "deps_unmet", "b", null);
    }

    @Test void bindingDeniesAMissingDependencyAtOnceNotALaterFailure() {
        Map<String, Object> b = body(list(step("A"), step("C"), step("B", "A", "C")), list(edge("A", "f", "B", "p", "eq", null, list(), "pr")));
        Map<String, Object> rC = rc(b, "C", 0, null, "failed", map(), 200L);
        Map<String, Object> rB = rc(b, "B", 1, rC, "ok", map(), 210L);
        Workflow.Result r = bind(b, list(rC, rB), "B", map());
        is(r, "deny", "deps_unmet", "B", null);
        // admitted (not bound), the same missing promised dependency is only noted and the failed one is reported
        is(admit(b, list(rC), "B", map()), "deny", "dep_failed", "B", null);
    }

    @Test void bindingDeniesAPendingEdgeFromADistantAncestor() {
        Map<String, Object> b = body(list(step("X"), step("A", "X"), step("B", "A")),
            list(edge("X", "f", "A", "p", "eq", null, list(), "pr"), edge("X", "f", "B", "q", "eq", null, list(), null)));
        Map<String, Object> rA = rc(b, "A", 0, null, "ok", map(), 200L);
        Map<String, Object> rB = rc(b, "B", 1, rA, "ok", map(), 210L);
        Workflow.Result r = bind(b, list(rA, rB), "B", map());
        is(r, "deny", "deps_unmet", "B", null);
        assertTrue(r.pending.isEmpty());
        assertNotNull(r.toMap());
        // a bound step whose parameter is absent fails its edge
        Map<String, Object> bb = baseBody();
        Map<String, Object> ra = rc(bb, "a", 0, null, "ok", goodOutputs(), 200L);
        Map<String, Object> rb = rc(bb, "b", 1, ra, "ok", map(), 210L);
        is(bind(bb, list(ra, rb), "b", map()), "deny", "edge_missing", "b", 0);
    }

    // ---- edge constraints ----

    static Workflow.Result relation(String op, long v) {
        Map<String, Object> b = body(list(step("A"), step("C", "A")), list(edge("A", "f", "C", "p", op, null, list(), null)));
        Map<String, Object> rA = rc(b, "A", 0, null, "ok", map("f", out(D, 10L, null, list())), 200L);
        return admit(b, list(rA), "C", map("p", v));
    }

    @Test void relationalOperatorsCompareTheParameterWithTheOutput() {
        String[] ops = {"le", "ge", "lt", "gt"};
        boolean[][] allowed = {{true, true, false}, {false, true, true}, {true, false, false}, {false, false, true}};
        long[] vs = {9L, 10L, 11L};
        for (int o = 0; o < 4; o++) {
            for (int i = 0; i < 3; i++) {
                Workflow.Result r = relation(ops[o], vs[i]);
                if (allowed[o][i]) is(r, "allow", null, "C", null);
                else is(r, "deny", "edge_relation", "C", 0);
            }
        }
    }

    @Test void edgeValueAndDigestAndUnitChecks() {
        Map<String, Object> b = body(list(step("A"), step("C", "A")), list(edge("A", "f", "C", "p", "le", null, list(), null)));
        Map<String, Object> rA = rc(b, "A", 0, null, "ok", map("f", out(D, 10L, null, list())), 200L);
        is(admit(b, list(rA), "C", map("p", "s")), "deny", "edge_value", "C", 0);
        is(admit(b, list(rA), "C", map()), "deny", "edge_missing", "C", 0);
        Map<String, Object> rNoNum = rc(b, "A", 0, null, "ok", map("f", out(D, null, null, list())), 200L);
        is(admit(b, list(rNoNum), "C", map("p", 1L)), "deny", "edge_value", "C", 0);
        Map<String, Object> be = body(list(step("A"), step("C", "A")), list(edge("A", "f", "C", "p", "eq", null, list(), null)));
        Map<String, Object> rE = rc(be, "A", 0, null, "ok", map("f", out(Workflow.valueDigest(5L), null, null, list())), 200L);
        is(admit(be, list(rE), "C", map("p", 5L)), "allow", null, "C", null);
        is(admit(be, list(rE), "C", map("p", 6L)), "deny", "edge_digest", "C", 0);
    }

    @Test void edgeDenyLabelsStopTaintedValues() {
        Map<String, Object> b = body(list(step("A"), step("C", "A")), list(edge("A", "f", "C", "p", "eq", null, list("x"), null)));
        Map<String, Object> tainted = rc(b, "A", 0, null, "ok", map("f", out(Workflow.valueDigest(5L), null, null, list("x"))), 200L);
        is(admit(b, list(tainted), "C", map("p", 5L)), "deny", "taint_flow", "C", 0);
        Map<String, Object> clean = rc(b, "A", 0, null, "ok", map("f", out(Workflow.valueDigest(5L), null, null, list("y"))), 200L);
        is(admit(b, list(clean), "C", map("p", 5L)), "allow", null, "C", null);
        Map<String, Object> two = rc(b, "A", 0, null, "ok", map("f", out(Workflow.valueDigest(5L), null, null, list("w", "x"))), 200L);
        is(admit(b, list(two), "C", map("p", 5L)), "deny", "taint_flow", "C", 0);
    }

    @Test void pendingEdgesAreListedWhenAdmitting() {
        Map<String, Object> b = body(list(step("X"), step("A", "X"), step("B", "A")),
            list(edge("X", "f", "A", "p", "eq", null, list(), "pr"), edge("X", "f", "B", "q", "eq", null, list(), null)));
        Map<String, Object> rA = rc(b, "A", 0, null, "ok", map(), 200L);
        Workflow.Result r = admit(b, list(rA), "A", map());
        is(r, "deny", "already_done", "A", null);
        Workflow.Result r2 = admit(body(list(step("X"), step("A", "X")), list(edge("X", "f", "A", "p", "eq", null, list(), "pr"))), list(), "A", map("p", 1L));
        is(r2, "allow", null, "A", null);
        assertEquals(List.of(0), r2.pending);
    }
}
