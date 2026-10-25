package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Rule 19 (V15 committed map) mutation kills: leaf / node / commit hashing with per-kind tags and u64be size, the RFC 9162
 * tree shape and audit-path folding, the closed leaf and disclosure shapes, the cell of the action (cut cells, exact over
 * longer prefix over shorter prefix over other), the layout and position checks and the ε bound. The committed map is built
 * here with the same leaf order as packages/pca/src/intent-map-commit.ts commitMap.
 */
public class IntentMapKillTest {
    static Map<String, Object> map(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }
    @SafeVarargs static <T> List<Object> list(T... xs) { return new ArrayList<>(Arrays.asList(xs)); }
    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static <T> T deep(T o) { return (T) IntentJs.normalize(Json.parseLenient(Json.canonicalize(o))); }

    static byte[] seed(String label) {
        try { return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8)); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    // ---- the committed map: air.book (total: [0,39999],{40000},[40001,100000]; cabin: economy, business, other) + air.cancel ----
    static final Map<String, Object> BOOK = map("verb", "air.book", "first", 2L, "cells", 9L, "dims", list(
        map("kind", "num", "path", "action.params.total", "lo", 0L, "hi", 100_000L, "cuts", list(40_000L)),
        map("kind", "cat", "path", "action.params.cabin", "values", list(map("kind", "exact", "value", "economy"), map("kind", "exact", "value", "business"),
            map("kind", "other", "value", IntentMap.MAP_OTHER)))));
    static final Map<String, Object> CANCEL = map("verb", "air.cancel", "first", 11L, "cells", 1L, "dims", list());
    static final Map<String, Object> METRICS = map("residual_risk_ppm", 1200L, "burden_ppm", 3L, "uncertainty_ppm", 4L, "disagreement_ppm", 0L,
        "mean_harm_ppm", 10L, "fidelity_est_ppm", 990_000L, "entropy_mbits", 12L, "questions", 2L, "conflicts", 0L);

    static final List<Object[]> LEAVES = new ArrayList<>(); // {kind, leaf}
    static {
        LEAVES.add(new Object[] {"header", BOOK});
        LEAVES.add(new Object[] {"header", CANCEL});
        for (long f = 0; f < 9; f++) {
            long t = f / 3, c = f % 3;
            LEAVES.add(new Object[] {"cell", map("verb", "air.book", "cell", list(t, c), "p_ppm", 1000L + f, "in_grant", t < 2 && c == 0)});
        }
        LEAVES.add(new Object[] {"cell", map("verb", "air.cancel", "cell", list(), "p_ppm", 0L, "in_grant", false)});
        LEAVES.add(new Object[] {"metrics", METRICS});
        LEAVES.add(new Object[] {"learner", map("learner_digest", Pca.b64(seed("map/learner")))});
    }
    static final int SIZE = LEAVES.size();
    static byte[] salt(int i) { return seed("map/salt/" + i); }
    static List<byte[]> hashes() {
        List<byte[]> hs = new ArrayList<>();
        for (int i = 0; i < SIZE; i++) hs.add(IntentMap.leafHash((String) LEAVES.get(i)[0], salt(i), deep(LEAVES.get(i)[1])));
        return hs;
    }
    static long split(long n) { long k = 1; while (k * 2 < n) k *= 2; return k; }
    static byte[] root(List<byte[]> hs) {
        if (hs.size() == 1) return hs.get(0);
        int k = (int) split(hs.size());
        return IntentMap.nodeHash(root(hs.subList(0, k)), root(hs.subList(k, hs.size())));
    }
    static void path(List<byte[]> hs, int idx, List<Object> out) {
        if (hs.size() == 1) return;
        int k = (int) split(hs.size());
        if (idx < k) { path(hs.subList(0, k), idx, out); out.add(Pca.b64(root(hs.subList(k, hs.size())))); }
        else { path(hs.subList(k, hs.size()), idx - k, out); out.add(Pca.b64(root(hs.subList(0, k)))); }
    }
    static final String COMMIT = IntentMap.commitOf(SIZE, root(hashes()));

    static Map<String, Object> entry(int i) {
        List<Object> p = new ArrayList<>();
        path(hashes(), i, p);
        return map("index", (long) i, "salt", Pca.b64(salt(i)), "leaf", LEAVES.get(i)[1], "path", p);
    }
    static Map<String, Object> disclosure(int cellIndex) { return map("size", (long) SIZE, "header", entry(0), "cell", entry(cellIndex), "metrics", entry(SIZE - 2)); }
    static Map<String, Object> params(long total, String cabin) { return map("total", total, "cabin", cabin); }
    static IntentMap.Decision decide(Map<String, Object> d, Map<String, Object> params, String verb, Double eps) {
        Map<String, Object> action = map("verb", verb, "resource", "r", "params_digest", Pca.paramsDigest(deep(params)));
        return IntentMap.decide(COMMIT, deep(action), true, deep(params), deep(d), eps);
    }
    static IntentMap.Decision ok(Map<String, Object> d) { return decide(d, params(38_900L, "economy"), "air.book", null); }

    @Test void commitmentMatchesTheReferenceShape() {
        List<Object> leaves = new ArrayList<>();
        for (int i = 0; i < SIZE; i++) leaves.add(map("kind", LEAVES.get(i)[0], "salt", Pca.b64(salt(i)), "leaf", LEAVES.get(i)[1]));
        assertEquals(COMMIT, IntentMap.commitLeaves(leaves));
        // the commitment binds the size (u64be) and the kind tags
        assertNotEquals(COMMIT, IntentMap.commitOf(SIZE + 1, root(hashes())));
        assertFalse(Arrays.equals(IntentMap.leafHash("cell", salt(0), deep(BOOK)), IntentMap.leafHash("header", salt(0), deep(BOOK))));
        assertArrayEquals(new byte[] {0, 0, 0, 0, 0, 1, 0, 2}, IntentMap.u64be(65_538L));
        assertThrows(IllegalArgumentException.class, () -> IntentMap.leafHash("header", new byte[31], deep(BOOK)));
    }

    @Test void grantedCellAndPolicyBound() {
        IntentMap.Decision d = ok(disclosure(2));
        assertTrue(d.ok, d.reason);
        assertEquals(List.of(0L, 0L), d.cell);
        assertEquals(1000L, d.pPpm);
        assertTrue(decide(disclosure(2), params(38_900L, "economy"), "air.book", 1200.0).ok);
        assertFalse(decide(disclosure(2), params(38_900L, "economy"), "air.book", 1199.0).ok);
        // the cut value is its own cell [1]; [40001, ...] is cell [2] (outside the grant)
        assertTrue(decide(disclosure(2 + 3), params(40_000L, "economy"), "air.book", null).ok);
        assertEquals("the action's cell is outside the committed grant", decide(disclosure(2 + 6), params(40_001L, "economy"), "air.book", null).reason);
        // other cabin: the last (other) value
        assertEquals("the action's cell is outside the committed grant", decide(disclosure(2 + 2), params(1L, "first"), "air.book", null).reason);
        // the zero-dimension verb has the single cell []
        Map<String, Object> cancel = map("size", (long) SIZE, "header", entry(1), "cell", entry(11), "metrics", entry(SIZE - 2));
        assertEquals("the action's cell is outside the committed grant", decide(cancel, map(), "air.cancel", null).reason);
    }

    @Test void valuesOutsideTheirDimension() {
        for (Object total : new Object[] {"38900", new Json.Num("1.5"), 100_001L, -1L, null}) {
            Map<String, Object> p = params(0L, "economy");
            p.put("total", total);
            assertEquals("the action's value lies outside the committed map's dimension", decide(disclosure(2), p, "air.book", null).reason, String.valueOf(total));
        }
        assertEquals("the action's value lies outside the committed map's dimension", decide(disclosure(2), map("total", 38_900L), "air.book", null).reason);
        assertEquals("the action's value lies outside the committed map's dimension", decide(disclosure(2), map("total", 38_900L, "cabin", 1L), "air.book", null).reason);
    }

    @Test void prefixOrder() {
        Map<String, Object> h = map("verb", "x", "first", 1L, "cells", 4L, "dims", list(map("kind", "cat", "path", "action.resource", "values", list(
            map("kind", "prefix", "value", "a/"), map("kind", "prefix", "value", "a/b"), map("kind", "exact", "value", "a/bc"), map("kind", "other", "value", IntentMap.MAP_OTHER)))));
        assertNull(IntentMap.headerError(deep(h)));
        assertEquals(2L, IntentMap.cellOf(deep(h), "a/bc", map())[0][0]);
        assertEquals(1L, IntentMap.cellOf(deep(h), "a/bx", map())[0][0]);
        assertEquals(0L, IntentMap.cellOf(deep(h), "a/x", map())[0][0]);
        assertEquals(3L, IntentMap.cellOf(deep(h), "b", map())[0][0]);
        assertNull(IntentMap.cellOf(deep(h), 7L, map()));
    }

    @Test void openingsAndLayout() {
        Map<String, Object> d = disclosure(2);
        m(d.get("cell")).put("salt", Pca.b64(seed("other")));
        assertEquals("the cell leaf does not open the map commitment", ok(d).reason);
        Map<String, Object> shortPath = disclosure(2);
        ((List<?>) m(shortPath.get("cell")).get("path")).remove(0);
        assertEquals("the cell leaf does not open the map commitment", ok(shortPath).reason);
        Map<String, Object> size = disclosure(2);
        size.put("size", (long) SIZE + 1);
        assertNotNull(ok(size).reason);
        // the header presented as a cell does not open (kind tags differ)
        Map<String, Object> kind = disclosure(2);
        kind.put("cell", entry(0));
        assertFalse(ok(kind).ok);
        // the learner leaf is not the metrics entry
        Map<String, Object> learner = disclosure(2);
        learner.put("metrics", map("index", (long) SIZE - 1, "salt", Pca.b64(salt(SIZE - 1)), "leaf", METRICS, "path", list()));
        assertFalse(ok(learner).ok);
        // a correctly opening cell that is not the action's cell
        assertEquals("the disclosed cell is not the action's cell", ok(disclosure(3)).reason);
        // verb and layout
        assertEquals("the disclosed header is not the action's verb", decide(disclosure(2), params(38_900L, "economy"), "air.search", null).reason);
        assertEquals("the params do not hash to action.params_digest",
            IntentMap.decide(COMMIT, deep(map("verb", "air.book", "params_digest", Pca.paramsDigest(map()))), true, deep(params(1L, "economy")), deep(disclosure(2)), null).reason);
        assertEquals("the PCActn carries no map commitment", IntentMap.decide("abc", map(), true, map(), deep(disclosure(2)), null).reason);
        assertEquals("params must be an object", IntentMap.decide(COMMIT, map(), true, null, deep(disclosure(2)), null).reason);
    }

    @Test void rootFromPathShape() {
        List<byte[]> hs = hashes();
        for (int i = 0; i < SIZE; i++) {
            List<Object> p = new ArrayList<>();
            path(hs, i, p);
            List<byte[]> bp = new ArrayList<>();
            for (Object x : p) bp.add(Pca.decodeB64uStrict(x, 32));
            assertArrayEquals(root(hs), IntentMap.rootFromPath(i, SIZE, hs.get(i), bp), "index " + i);
            assertNull(IntentMap.rootFromPath(i, SIZE, hs.get(i), bp.subList(0, bp.size() - 1)));
        }
        assertNull(IntentMap.rootFromPath(SIZE, SIZE, hs.get(0), List.of()));
        assertNull(IntentMap.rootFromPath(-1, SIZE, hs.get(0), List.of()));
    }

    @Test void closedShapes() {
        assertNull(IntentMap.disclosureError(deep(disclosure(2))));
        Map<String, Object> d = disclosure(2);
        d.put("extra", 1L);
        assertNotNull(IntentMap.disclosureError(deep(d)));
        for (Object size : new Object[] {null, "15", 3L, (long) (1 << 24) + 1}) {
            Map<String, Object> x = disclosure(2);
            x.put("size", size);
            assertNotNull(IntentMap.disclosureError(deep(x)), String.valueOf(size));
        }
        Map<String, Object> mt = new LinkedHashMap<>(METRICS);
        assertNull(IntentMap.metricsError(deep(mt)));
        mt.put("log2_vs_mbits", 4500L);
        assertNull(IntentMap.metricsError(deep(mt)));
        mt.put("log2_vs_mbits", null);
        assertNotNull(IntentMap.metricsError(deep(mt)));
        assertNotNull(IntentMap.cellError(deep(map("verb", "a", "cell", list(), "p_ppm", 1_000_001L, "in_grant", true))));
        assertNotNull(IntentMap.cellError(deep(map("verb", "a", "cell", list(), "p_ppm", 0L, "in_grant", 1L))));
        assertNull(IntentMap.learnerError(deep(map("learner_digest", Pca.b64(seed("x"))))));
        assertNotNull(IntentMap.learnerError(deep(map("learner_digest", "x"))));
        Map<String, Object> h = deep(BOOK);
        m(((List<?>) h.get("dims")).get(0)).put("cuts", list(40_000L, 40_000L));
        assertNotNull(IntentMap.headerError(h));
        Map<String, Object> h2 = deep(BOOK);
        h2.put("cells", 8L);
        assertEquals("header.cells is not the product of the dimensions' cell counts", IntentMap.headerError(h2));
        Map<String, Object> h3 = deep(BOOK);
        m(((List<?>) h3.get("dims")).get(0)).put("path", "env.hour");
        assertNotNull(IntentMap.headerError(h3));
        Map<String, Object> h4 = deep(BOOK);
        java.util.Collections.reverse((List<?>) m(((List<?>) h4.get("dims")).get(1)).get("values"));
        assertNotNull(IntentMap.headerError(h4));
    }

    @Test void primitiveEntry() {
        Map<String, Object> in = map("map_commit", COMMIT, "action", map("verb", "air.book", "resource", "r", "params_digest", Pca.paramsDigest(deep(params(38_900L, "economy")))),
            "params", params(38_900L, "economy"), "disclosure", disclosure(2));
        assertTrue(IntentMap.decidePrimitive(in).ok);
        in.put("max_residual_risk_ppm", 1199L);
        assertFalse(IntentMap.decidePrimitive(in).ok);
        in.remove("max_residual_risk_ppm");
        in.remove("params");
        assertFalse(IntentMap.decidePrimitive(in).ok);
    }

    @Test void wireAndGoal() {
        String s = Pca.b64(seed("s"));
        assertEquals("pca-intent:v2c:" + s + ":" + COMMIT, IntentSession.intentGoalV2c(s, COMMIT));
        assertNotEquals(Pca.intentGoalCommitV2c(s, COMMIT, "x"), Pca.intentGoalCommitV2(s, COMMIT, "x"));
        Map<String, Object> is = map("session", s, "root", s, "seq", 0L, "schema", s);
        assertNull(IntentSession.validateWire(is));
        is.put("map_form", "commit");
        assertNull(IntentSession.validateWire(is));
        for (Object bad : new Object[] {"plain", null, true}) {
            is.put("map_form", bad);
            assertEquals("'intent_session.map_form' must be \"commit\" when present", IntentSession.validateWire(is));
        }
    }
}
