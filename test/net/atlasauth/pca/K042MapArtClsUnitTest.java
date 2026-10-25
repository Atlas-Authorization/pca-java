package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.4.2 mutation kills (hand cases) for {@link IntentMap}, {@link IntentClassifier} and {@link IntentArtifacts} that
 * the TS oracle (K042MapArtClsDiffTest) cannot express: Java-only entry points and totality (fail-closed reasons of
 * thrown exceptions, non-normalized numbers, values with no strict canonical form), the RFC 9162 path edges, the byte
 * layout of u64be, and the IntentArtifacts helpers (packages/pca/src/intent-artifacts.ts semantics).
 */
public class K042MapArtClsUnitTest {
    static Map<String, Object> map(Object... kv) { return IntentMapKillTest.map(kv); }
    @SafeVarargs static <T> List<Object> list(T... xs) { return IntentMapKillTest.list(xs); }
    static <T> T deep(T o) { return IntentMapKillTest.deep(o); }
    static Map<String, Object> m(Object o) { return IntentMapKillTest.m(o); }

    // ================================================================ IntentMap
    @Test void hashingEdges() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> IntentMap.tagOf("node"));
        assertEquals("unknown leaf kind", e.getMessage());
        assertEquals(IntentMap.MAP_TAG_LEARNER, IntentMap.tagOf("learner"));
        assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6, 7, 8}, IntentMap.u64be(0x0102030405060708L));
        assertArrayEquals(new byte[] {(byte) 0xff, 0, 0, 0, 0, 0, 0, 1}, IntentMap.u64be(0xff00000000000001L));
        IllegalArgumentException n = assertThrows(IllegalArgumentException.class, () -> IntentMap.leafHash("cell", null, map()));
        assertEquals("mapLeafHash: the salt is 32 bytes", n.getMessage());
        assertThrows(IllegalArgumentException.class, () -> IntentMap.leafHash("cell", new byte[33], map()));
        assertEquals(32, IntentMap.leafHash("cell", new byte[32], map()).length);
    }

    @Test void commitLeavesEdges() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> IntentMap.commitLeaves(list()));
        assertEquals("mapTree: empty", e.getMessage());
        // the entry point normalizes: 3.0 is the number 3 (strictly canonical "3")
        String salt = Pca.b64(new byte[32]);
        String want = IntentMap.commitLeaves(list(map("kind", "header", "salt", salt, "leaf", map("verb", "v", "first", 3L, "cells", 1L, "dims", list()))));
        String got = IntentMap.commitLeaves(list(map("kind", "header", "salt", salt, "leaf", map("verb", "v", "first", new Json.Num("3.0"), "cells", 1L, "dims", list()))));
        assertEquals(want, got);
        assertEquals(IntentMap.commitOf(1, IntentMap.leafHash("header", new byte[32], map("cells", 1L, "dims", list(), "first", 3L, "verb", "v"))), want);
    }

    // RFC 9162 tree helpers (the reference shape, as in packages/pca/src/intent-map-commit.ts)
    static long split(long n) { long k = 1; while (k * 2 < n) k *= 2; return k; }
    static byte[] root(List<byte[]> hs) {
        if (hs.size() == 1) return hs.get(0);
        int k = (int) split(hs.size());
        return IntentMap.nodeHash(root(hs.subList(0, k)), root(hs.subList(k, hs.size())));
    }
    static void path(List<byte[]> hs, int idx, List<byte[]> out) {
        if (hs.size() == 1) return;
        int k = (int) split(hs.size());
        if (idx < k) { path(hs.subList(0, k), idx, out); out.add(root(hs.subList(k, hs.size()))); }
        else { path(hs.subList(k, hs.size()), idx - k, out); out.add(root(hs.subList(0, k))); }
    }
    static byte[] leaf(int i) { byte[] b = new byte[32]; b[0] = (byte) i; b[31] = (byte) (i * 7 + 1); return b; }

    @Test void rootFromPathEveryShape() {
        for (int size = 1; size <= 23; size++) {
            List<byte[]> hs = new ArrayList<>();
            for (int i = 0; i < size; i++) hs.add(leaf(i));
            byte[] r = root(hs);
            for (int i = 0; i < size; i++) {
                List<byte[]> p = new ArrayList<>();
                path(hs, i, p);
                assertArrayEquals(r, IntentMap.rootFromPath(i, size, hs.get(i), p), "size " + size + " index " + i);
                List<byte[]> longer = new ArrayList<>(p);
                longer.add(leaf(99));
                assertNull(IntentMap.rootFromPath(i, size, hs.get(i), longer), "longer " + size + "/" + i);
                if (!p.isEmpty()) assertNull(IntentMap.rootFromPath(i, size, hs.get(i), p.subList(0, p.size() - 1)), "shorter " + size + "/" + i);
                // the leaf at a neighbouring index does not recompute the root with this path
                if (size > 1) assertFalse(java.util.Arrays.equals(r, IntentMap.rootFromPath(i, size, hs.get((i + 1) % size), p)));
            }
            // out-of-range indices never recompute anything, whatever the path
            List<byte[]> p0 = new ArrayList<>();
            path(hs, 0, p0);
            assertNull(IntentMap.rootFromPath(size, size, hs.get(0), p0), "index = size " + size);
            assertNull(IntentMap.rootFromPath(-1, size, hs.get(0), p0), "index -1 " + size);
            assertNull(IntentMap.rootFromPath(size, size, hs.get(0), List.of(leaf(5))), "index = size, one step " + size);
        }
        assertArrayEquals(leaf(3), IntentMap.rootFromPath(0, 1, leaf(3), List.of()));
        assertNull(IntentMap.rootFromPath(1, 1, leaf(3), List.of()));
        assertNull(IntentMap.rootFromPath(-1, 1, leaf(3), List.of()));
        assertNull(IntentMap.rootFromPath(0, 1, leaf(3), List.of(leaf(4))));
        assertNull(IntentMap.rootFromPath(2, 2, leaf(3), List.of(leaf(4))));
    }

    static IntentMap.Decision decideRaw(Object disclosure, boolean paramsPresent, Object params, Map<String, Object> digestOf) {
        Map<String, Object> action = map("verb", "air.book", "resource", "r", "params_digest", Pca.paramsDigest(deep(digestOf)));
        return IntentMap.decide(IntentMapKillTest.COMMIT, deep(action), paramsPresent, params, disclosure, null);
    }
    static void bad(String reason, IntentMap.Decision d) {
        assertFalse(d.ok);
        assertEquals(reason, d.reason);
        assertNull(d.cell);
        assertEquals(0L, d.pPpm);
        assertEquals(0L, d.residualRiskPpm);
    }

    @Test void decideTotality() {
        Map<String, Object> p = IntentMapKillTest.params(38_900L, "economy");
        IntentMap.Decision ok = decideRaw(deep(IntentMapKillTest.disclosure(2)), true, deep(p), p);
        assertTrue(ok.ok, ok.reason);
        assertEquals(List.of(0L, 0L), ok.cell);
        assertEquals(1000L, ok.pPpm);
        assertEquals(1200L, ok.residualRiskPpm);
        // a disclosed leaf without a strict canonical form (a Java Double) is a leaf that does not open
        Map<String, Object> d = deep(IntentMapKillTest.disclosure(2));
        m(m(d.get("cell")).get("leaf")).put("p_ppm", 1000.0d);
        bad("the cell leaf does not open the map commitment", decideRaw(d, true, deep(p), p));
        Map<String, Object> dh = deep(IntentMapKillTest.disclosure(2));
        m(m(dh.get("header")).get("leaf")).put("first", 2.0d);
        bad("the header leaf does not open the map commitment", decideRaw(dh, true, deep(p), p));
        // params that cannot be hashed: fail closed with the exception's class
        Map<String, Object> pd = deep(p);
        pd.put("total", 38_900.0d);
        bad("map error (fail closed): IllegalArgumentException", decideRaw(deep(IntentMapKillTest.disclosure(2)), true, pd, p));
        // params ABSENT: the verifier uses {} (whatever the params argument holds)
        bad(K042MapArtClsDiffTest.OUTSIDE, decideRaw(deep(IntentMapKillTest.disclosure(2)), false, deep(p), map()));
        bad("the params do not hash to action.params_digest", decideRaw(deep(IntentMapKillTest.disclosure(2)), false, deep(p), p));
        bad(K042MapArtClsDiffTest.OUTSIDE, decideRaw(deep(IntentMapKillTest.disclosure(2)), false, null, map()));
    }

    @Test void primitiveEntryTotality() {
        bad("map error (fail closed): ClassCastException", IntentMap.decidePrimitive("x"));
        bad("map error (fail closed): ClassCastException", IntentMap.decidePrimitive(list()));
        Map<String, Object> p = IntentMapKillTest.params(38_900L, "economy");
        Map<String, Object> in = map("map_commit", IntentMapKillTest.COMMIT, "action", map("verb", "air.book", "resource", "r", "params_digest", Pca.paramsDigest(deep(p))),
            "params", p, "disclosure", IntentMapKillTest.disclosure(2));
        IntentMap.Decision ok = IntentMap.decidePrimitive(in);
        assertTrue(ok.ok, ok.reason);
        for (Object eps : new Object[] {"1200", null, true, list()}) {
            Map<String, Object> x = new LinkedHashMap<>(in);
            x.put("max_residual_risk_ppm", eps);
            bad("max_residual_risk_ppm must be a number", IntentMap.decidePrimitive(x));
        }
        Map<String, Object> e = new LinkedHashMap<>(in);
        e.put("max_residual_risk_ppm", 1200L);
        assertTrue(IntentMap.decidePrimitive(e).ok);
        e.put("max_residual_risk_ppm", new Json.Num("1199"));
        bad("the committed residual risk 1200 ppm exceeds ε = 1199", IntentMap.decidePrimitive(e));
        // the primitive normalizes its input: 2.0 is the number 2 in the disclosed header leaf
        Map<String, Object> n = deep(in);
        m(m(m(n.get("disclosure")).get("header")).get("leaf")).put("first", new Json.Num("2.0"));
        m(m(m(n.get("disclosure")).get("cell")).get("leaf")).put("p_ppm", new Json.Num("1000.0"));
        IntentMap.Decision nd = IntentMap.decidePrimitive(n);
        assertTrue(nd.ok, nd.reason);
        assertEquals(1000L, nd.pPpm);
        // action absent: no params_digest
        Map<String, Object> na = new LinkedHashMap<>(in);
        na.remove("action");
        bad("the params do not hash to action.params_digest", IntentMap.decidePrimitive(na));
    }

    @Test void cellOfArrayShape() {
        long[][] w = IntentMap.cellOf(deep(IntentMapKillTest.BOOK), "r", deep(IntentMapKillTest.params(40_000L, "first")));
        assertEquals(2, w.length);
        assertArrayEquals(new long[] {1, 2}, w[0]);
        assertArrayEquals(new long[] {5}, w[1]);
        // an absent numeric value is outside its dimension (never an exception)
        assertNull(IntentMap.cellOf(deep(IntentMapKillTest.BOOK), "r", deep(map("cabin", "economy"))));
        assertNull(IntentMap.cellOf(deep(IntentMapKillTest.BOOK), "r", null));
        assertNull(IntentMap.cellOf(deep(IntentMapKillTest.BOOK), "r", "total"));
    }

    // ================================================================ IntentClassifier
    @Test void classifierTotality() {
        IntentClassifier.ClassResult r = IntentClassifier.decide((Object) "x");
        assertFalse(r.ok);
        assertEquals("classes: evaluation error (fail closed): ClassCastException", r.reason);
        assertNull(r.classes);
        IntentClassifier.ClassResult l = IntentClassifier.decide((Object) list());
        assertEquals("classes: evaluation error (fail closed): ClassCastException", l.reason);
        IntentClassifier.ClassResult ok = IntentClassifier.decide((Object) map("action", map(), "policy", map("classifiers", list())));
        assertTrue(ok.ok);
        assertNull(ok.reason);
        assertEquals(Map.of(), ok.classes);
        assertTrue(IntentClassifier.classifierCheckActive(list("d"), null));
        assertTrue(IntentClassifier.classifierCheckActive(null, map("classifiers", list(map()))));
        assertFalse(IntentClassifier.classifierCheckActive(list(), map("classifiers", list())));
    }

    // ================================================================ IntentArtifacts
    @Test void pathSegments() {
        for (String s : new String[] {"a", "A-b_9", "x".repeat(64), "-", "_", "proto", "__proto", "Constructor"}) assertTrue(IntentArtifacts.isPathSegment(s), s);
        for (String s : new String[] {"", "x".repeat(65), "__proto__", "constructor", "prototype", "a.b", "a b", "é"}) assertFalse(IntentArtifacts.isPathSegment(s), s);
        assertTrue(IntentArtifacts.isName("a"));
        assertTrue(IntentArtifacts.isName("a" + "b".repeat(63)));
        for (Object v : new Object[] {"A", "1a", "", "a".repeat(65), "a-b", 5L, null, list("a")}) assertFalse(IntentArtifacts.isName(v), String.valueOf(v));
    }

    @Test void boundedStrings() {
        assertTrue(IntentArtifacts.isBoundedString("ab", 2));
        assertTrue(IntentArtifacts.isBoundedString("é", 2));
        assertFalse(IntentArtifacts.isBoundedString("abc", 2));
        assertFalse(IntentArtifacts.isBoundedString("é", 1));
        assertFalse(IntentArtifacts.isBoundedString("", 2));
        assertFalse(IntentArtifacts.isBoundedString(5L, 2));
        assertFalse(IntentArtifacts.isBoundedString(null, 2));
    }

    @Test void scalarEquality() {
        assertTrue(IntentArtifacts.scalarEq("a", "a"));
        assertFalse(IntentArtifacts.scalarEq("a", "b"));
        assertFalse(IntentArtifacts.scalarEq("1", 1L));
        assertFalse(IntentArtifacts.scalarEq(1L, "1"));
        assertFalse(IntentArtifacts.scalarEq("true", true));
        assertTrue(IntentArtifacts.scalarEq(true, true));
        assertTrue(IntentArtifacts.scalarEq(false, false));
        assertFalse(IntentArtifacts.scalarEq(true, false));
        assertFalse(IntentArtifacts.scalarEq(true, 1L));
        assertFalse(IntentArtifacts.scalarEq(1L, true));
        assertTrue(IntentArtifacts.scalarEq(2L, new Json.Num("2")));
        assertTrue(IntentArtifacts.scalarEq(new Json.Num("2"), 2L));
        assertTrue(IntentArtifacts.scalarEq(7L, 7L));
        assertFalse(IntentArtifacts.scalarEq(2L, 3L));
        assertFalse(IntentArtifacts.scalarEq(3L, 2L));
        assertFalse(IntentArtifacts.scalarEq(0L, 1L));
        assertTrue(IntentArtifacts.scalarEq(0L, 0L));
        assertTrue(IntentArtifacts.scalarEq(null, null));
        assertFalse(IntentArtifacts.scalarEq(null, 1L));
        assertFalse(IntentArtifacts.scalarEq(1L, null));
        assertFalse(IntentArtifacts.scalarEq(0L, null));
        assertFalse(IntentArtifacts.scalarEq(null, 0L));
        assertFalse(IntentArtifacts.scalarEq(map(), null));
        assertFalse(IntentArtifacts.scalarEq(null, map()));
        assertFalse(IntentArtifacts.scalarEq(list(), map()));
        assertFalse(IntentArtifacts.scalarEq(map(), 1L));
        assertFalse(IntentArtifacts.scalarEq(1L, list()));
        assertFalse(IntentArtifacts.scalarEq(null, "a"));
        assertFalse(IntentArtifacts.scalarEq(null, false));
    }

    @Test void closedMemberSets() {
        Map<String, Object> o = map("a", 1L, "b", 2L);
        assertNull(IntentArtifacts.closedMembers(o, List.of("a"), List.of("b", "c"), "w"));
        assertEquals("unknown member 'w.b'", IntentArtifacts.closedMembers(o, List.of("a"), List.of(), "w"));
        assertEquals("missing member 'w.c'", IntentArtifacts.closedMembers(o, List.of("a", "c"), List.of("b"), "w"));
        assertEquals("missing member 'w.a'", IntentArtifacts.closedMembers(map(), List.of("a", "c"), List.of(), "w"));
    }

    @Test void pinPq() {
        assertTrue(IntentArtifacts.pinPqOk(map("pk", "k")));
        assertTrue(IntentArtifacts.pinPqOk(map("pq_pk", "x")));
        assertFalse(IntentArtifacts.pinPqOk(map("pq_pk", "")));
        assertFalse(IntentArtifacts.pinPqOk(map("pq_pk", null)));
        assertFalse(IntentArtifacts.pinPqOk(map("pq_pk", 5L)));
        assertTrue(IntentArtifacts.pinPqOk(null));
    }

    @Test void artifactSuites() {
        assertNull(IntentArtifacts.artifactSuiteError(map()));
        assertNull(IntentArtifacts.artifactSuiteError(map("alg", "ed25519")));
        assertNull(IntentArtifacts.artifactSuiteError(Map.of("alg", "ed25519", "sig", "s")));
        assertNull(IntentArtifacts.artifactSuiteError(map("alg", "ml-dsa-65", "pq_pk", "k", "pq_sig", "s")));
        assertNull(IntentArtifacts.artifactSuiteError(map("alg", "hybrid-ed25519-ml-dsa-65", "pq_pk", "k")));
        assertEquals("alg must be a string", IntentArtifacts.artifactSuiteError(map("alg", 5L)));
        assertEquals("unsupported_suite: 'x'", IntentArtifacts.artifactSuiteError(map("alg", "x")));
        assertEquals("pq_pk must be a string", IntentArtifacts.artifactSuiteError(map("alg", "ml-dsa-65", "pq_pk", 5L)));
        assertEquals("pq_sig must be a string", IntentArtifacts.artifactSuiteError(map("alg", "ml-dsa-65", "pq_sig", 5L)));
        assertEquals("pq_sig must be a string", IntentArtifacts.artifactSuiteError(map("alg", "ml-dsa-65", "pq_sig", null)));
        assertEquals("pq_pk must be a string", IntentArtifacts.artifactSuiteError(map("pq_pk", 5L, "pq_sig", 5L)));
        assertEquals("an ed25519 artifact must not carry pq_pk / pq_sig", IntentArtifacts.artifactSuiteError(map("pq_pk", "k")));
        assertEquals("an ed25519 artifact must not carry pq_pk / pq_sig", IntentArtifacts.artifactSuiteError(map("pq_sig", "s")));
        assertEquals("an ed25519 artifact must not carry pq_pk / pq_sig", IntentArtifacts.artifactSuiteError(map("alg", "ed25519", "pq_sig", "s")));
    }

    @Test void paramPaths() {
        Map<String, Object> params = deep(map("a", map("b", "x", "n", null, "__proto__", 1L), "s", "str", "k-1", 2L));
        Predicates.Resolved r = IntentArtifacts.resolveParamPath(params, "action.params.a.b");
        assertTrue(r.found);
        assertEquals("x", r.value);
        Predicates.Resolved n = IntentArtifacts.resolveParamPath(params, "action.params.a.n");
        assertTrue(n.found);
        assertNull(n.value);
        assertEquals(2L, IntentJs.lng(IntentArtifacts.resolveParamPath(params, "action.params.k-1").value));
        assertEquals(params.get("a"), IntentArtifacts.resolveParamPath(params, "action.params.a").value);
        for (Object p : new Object[] {"action.params.a.", "action.params.a.c", "action.params.s.x", "action.params.a.__proto__", "action.params.", "action.params",
            "x.params.a", "action.paramsa", 5L, null, "action.params.a..b"}) {
            Predicates.Resolved x = IntentArtifacts.resolveParamPath(params, p);
            assertNotNull(x, String.valueOf(p));
            assertFalse(x.found, String.valueOf(p));
            assertNull(x.value, String.valueOf(p));
        }
        assertFalse(IntentArtifacts.resolveParamPath(list(), "action.params.a").found);
        assertFalse(IntentArtifacts.resolveParamPath(null, "action.params.a").found);

        for (String p : new String[] {"action.params.a", "action.params.a.b.c.d.e.f.g.h", "action.params." + "x".repeat(64), "action.params.a-b.C_9"})
            assertTrue(IntentArtifacts.isParamPath(p), p);
        for (Object p : new Object[] {"action.params.a.b.c.d.e.f.g.h.i", "action.params.", "action.params.a.", "action.params..a", "action.params.a..b",
            "action.params.__proto__", "action.params.a.constructor", "action.params", "params.a", "action.paramsa", "action.params." + "x".repeat(65), 5L, null})
            assertFalse(IntentArtifacts.isParamPath(p), String.valueOf(p));
        // a 7-segment path is 9 dotted segments when the "action.params." prefix is not stripped
        assertTrue(IntentArtifacts.isParamPath("action.params.a.b.c.d.e.f.g"));
    }

    @Test void nestedSet() {
        Map<String, Object> root = new LinkedHashMap<>();
        assertTrue(IntentArtifacts.setNested(root, "a.b", 1L));
        assertTrue(IntentArtifacts.setNested(root, "a.c", 2L));
        assertTrue(IntentArtifacts.setNested(root, "d", 3L));
        assertEquals("{\"a\":{\"b\":1,\"c\":2},\"d\":3}", Json.canonicalize(root));
        assertFalse(IntentArtifacts.setNested(root, "a.b", 9L));
        assertFalse(IntentArtifacts.setNested(root, "a.b.x", 9L));
        assertFalse(IntentArtifacts.setNested(root, "d.x", 9L));
        assertFalse(IntentArtifacts.setNested(root, "a", 9L));
        assertEquals("{\"a\":{\"b\":1,\"c\":2},\"d\":3}", Json.canonicalize(root));
        Map<String, Object> t = new LinkedHashMap<>();
        assertTrue(IntentArtifacts.setNested(t, "a.", 1L));
        assertEquals("{\"a\":{\"\":1}}", Json.canonicalize(t));
        assertFalse(IntentArtifacts.setNested(t, "a", 1L));
    }

    @Test void listsAndParams() {
        List<Object> l = list("x");
        assertSame(l, IntentArtifacts.iterable(l));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> IntentArtifacts.iterable(null));
        assertEquals("not a list", e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> IntentArtifacts.iterable(map()));
        Object p = IntentArtifacts.actionParams(map());
        assertEquals(Map.of(), p);
        assertTrue(p instanceof Map);
        Map<String, Object> ps = map("x", 1L);
        assertSame(ps, IntentArtifacts.actionParams(map("params", ps)));
        IllegalArgumentException a = assertThrows(IllegalArgumentException.class, () -> IntentArtifacts.actionParams(map("params", null)));
        assertEquals("action.params is not an object", a.getMessage());
        assertThrows(IllegalArgumentException.class, () -> IntentArtifacts.actionParams(map("params", list())));
        assertEquals(Map.of(), IntentArtifacts.actionParams(null));
    }
}
