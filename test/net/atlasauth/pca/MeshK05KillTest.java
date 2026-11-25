package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link Mesh} beyond the k05 differential oracle: the caveat-type text (JavaScript template-literal
 * printing), the narrowing relation, revocation-set leaves and non-membership on generated trees, RFC 9162 consistency over every
 * (old, new) size pair of generated logs, the trust/table bounds, PQ root pins, pinned-head truthiness, and tampered copies of the
 * oracle's valid proof. Every expectation is the exact verdict (reason and hop).
 */
public class MeshK05KillTest {

    // ---- helpers ----

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }
    static Object js(String text) { return Json.parseLenient(text); }
    static Json.Num n(long v) { return IntentJs.ofLong(v); }
    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked")
    static List<Object> l(Object o) { return (List<Object>) o; }
    static String v(Mesh.Verdict r) { return r.ok ? "ok" : r.reason + "|" + r.hop; }

    // ---- Verdict ----

    @Test void verdictText() {
        assertEquals("Verdict{ok=false, reason=x, hop=2}", new Mesh.Verdict(false, "x", 2).toString());
        assertEquals("Verdict{ok=true, reason=, hop=-1}", new Mesh.Verdict(true, "", -1).toString());
    }

    // ---- effectiveAuthority: errors and the caveat-type text ----

    static String err(String caveats) { return Mesh.effective(js(caveats)).err; }
    static String unknown(String text) { return "unknown caveat type \"" + text + "\" (fail closed)"; }

    @Test void malformedCaveatLists() {
        assertEquals("malformed proof", Mesh.effective("x").err);
        assertEquals("malformed proof", Mesh.effective(null).err);
        assertEquals("malformed proof", err("{}"));
        assertEquals("malformed proof", err("[\"x\"]"));
        assertEquals("malformed proof", err("[null]"));
        assertEquals("malformed proof", err("[{\"type\":\"scope\",\"actions\":[\"a\"]},7]"));
        assertNull(err("[]"));
        assertNull(err("[{\"type\":\"scope\",\"actions\":[\"a\"]}]"));
    }

    @Test void caveatTypeIsPrintedLikeJavaScript() {
        assertEquals(unknown("undefined"), err("[{}]"));
        assertEquals(unknown("null"), err("[{\"type\":null}]"));
        assertEquals(unknown("true"), err("[{\"type\":true}]"));
        assertEquals(unknown("false"), err("[{\"type\":false}]"));
        assertEquals(unknown(""), err("[{\"type\":\"\"}]"));
        assertEquals(unknown("x"), err("[{\"type\":\"x\"}]"));
        assertEquals(unknown("[object Object]"), err("[{\"type\":{}}]"));
        assertEquals(unknown("[object Object]"), err("[{\"type\":{\"a\":1}}]"));
        // arrays: String(array) joins the members' texts with commas, null members print empty
        assertEquals(unknown(""), err("[{\"type\":[]}]"));
        assertEquals(unknown(""), err("[{\"type\":[null]}]"));
        assertEquals(unknown(","), err("[{\"type\":[null,null]}]"));
        assertEquals(unknown("x"), err("[{\"type\":[\"x\"]}]"));
        assertEquals(unknown("1,a,,2,3,[object Object],true,false"), err("[{\"type\":[1,\"a\",null,[2,3],{},true,false]}]"));
        assertEquals(unknown("1.5,,"), err("[{\"type\":[1.50,null,[]]}]"));
        // numbers: String(n)
        assertEquals(unknown("2"), err("[{\"type\":2}]"));
        assertEquals(unknown("1.5"), err("[{\"type\":1.50}]"));
        assertEquals(unknown("-2.5"), err("[{\"type\":-2.5}]"));
        assertEquals(unknown("0"), err("[{\"type\":-0}]"));
        assertEquals(unknown("0"), err("[{\"type\":0.0}]"));
        assertEquals(unknown("1e+21"), err("[{\"type\":1e21}]"));
        assertEquals(unknown("123456789012345680000"), err("[{\"type\":123456789012345680000}]"));
        assertEquals(unknown("1e-7"), err("[{\"type\":1e-7}]"));
        assertEquals(unknown("0.000001"), err("[{\"type\":0.000001}]"));
        assertEquals(unknown("Infinity"), err("[{\"type\":1e999}]"));
        assertEquals(unknown("-Infinity"), err("[{\"type\":-1e999}]"));
        // the first unknown caveat ends the walk
        assertEquals(unknown("b"), err("[{\"type\":\"scope\",\"actions\":[]},{\"type\":\"b\"},{\"type\":\"c\"}]"));
    }

    @Test void caveatTypeTextFromJavaNumbers() {
        assertEquals(unknown("NaN"), Mesh.effective(List.of(obj("type", Double.NaN))).err);
        assertEquals(unknown("Infinity"), Mesh.effective(List.of(obj("type", Double.POSITIVE_INFINITY))).err);
        assertEquals(unknown("-Infinity"), Mesh.effective(List.of(obj("type", Double.NEGATIVE_INFINITY))).err);
        assertEquals(unknown("7"), Mesh.effective(List.of(obj("type", 7L))).err);
        assertEquals(unknown("7,0.25"), Mesh.effective(List.of(obj("type", List.of(7, 0.25d)))).err);
    }

    // ---- the narrowing relation ----

    static boolean narrows(String child, String parent) { return Mesh.narrowsCaveats(js(child), js(parent)); }

    @Test void narrowingAudience() {
        String p = "[{\"type\":\"audience\",\"domains\":[\"a\",\"b\"]}]";
        assertFalse(narrows("[]", p));
        assertFalse(narrows("[{\"type\":\"audience\",\"domains\":[\"c\"]}]", p));
        assertFalse(narrows("[{\"type\":\"audience\",\"domains\":[\"a\",\"c\"]}]", p));
        assertTrue(narrows("[{\"type\":\"audience\",\"domains\":[\"a\"]}]", p));
        assertTrue(narrows("[{\"type\":\"audience\",\"domains\":[\"b\",\"a\"]}]", p));
        assertTrue(narrows("[{\"type\":\"audience\",\"domains\":[]}]", p));
        assertTrue(narrows("[{\"type\":\"audience\",\"domains\":[\"z\"]}]", "[]"));
    }

    @Test void narrowingExpiry() {
        String p = "[{\"type\":\"expires\",\"at\":10}]";
        assertFalse(narrows("[]", p));
        assertFalse(narrows("[{\"type\":\"expires\",\"at\":11}]", p));
        assertFalse(narrows("[{\"type\":\"expires\",\"at\":10.5}]", p));
        assertTrue(narrows("[{\"type\":\"expires\",\"at\":10}]", p));
        assertTrue(narrows("[{\"type\":\"expires\",\"at\":9}]", p));
        assertTrue(narrows("[{\"type\":\"expires\",\"at\":99}]", "[]"));
    }

    @Test void narrowingHops() {
        String p = "[{\"type\":\"max_hops\",\"n\":2}]";
        assertFalse(narrows("[]", p));
        assertFalse(narrows("[{\"type\":\"max_hops\",\"n\":3}]", p));
        assertTrue(narrows("[{\"type\":\"max_hops\",\"n\":2}]", p));
        assertTrue(narrows("[{\"type\":\"max_hops\",\"n\":1}]", p));
        assertTrue(narrows("[{\"type\":\"max_hops\",\"n\":2}]", "[]"));
        assertTrue(narrows("[]", "[]"));
    }

    @Test void anErroredSideNeverNarrows() {
        assertFalse(narrows("[{\"type\":\"bogus\"}]", "[]"));
        assertFalse(narrows("[]", "[{\"type\":\"bogus\"}]"));
        assertFalse(narrows("[{\"type\":\"scope\",\"actions\":5}]", "[]"));
        assertFalse(narrows("[]", "[{\"type\":\"expires\",\"at\":\"x\"}]"));
        assertFalse(Mesh.narrowsCaveats("x", List.of()));
        assertFalse(Mesh.narrowsCaveats(List.of(), "x"));
    }

    // ---- revocation sets: leaves and non-membership on generated trees ----

    static List<byte[]> leaves(String... ids) {
        List<byte[]> out = new ArrayList<>();
        for (String s : ids) out.add(Pca.leafHash(s));
        return out;
    }

    /** The audit path (leaf to root) of leaf idx, in the {side, hash} form leafOk reads. */
    static List<Object> path(List<byte[]> hs, int idx) {
        List<Object> out = new ArrayList<>();
        if (hs.size() == 1) return out;
        int k = Pca.split(hs.size());
        if (idx < k) {
            out.addAll(path(hs.subList(0, k), idx));
            out.add(obj("side", "R", "hash", Pca.b64(Pca.build(hs.subList(k, hs.size())))));
        } else {
            out.addAll(path(hs.subList(k, hs.size()), idx - k));
            out.add(obj("side", "L", "hash", Pca.b64(Pca.build(hs.subList(0, k)))));
        }
        return out;
    }

    static String revRoot(List<byte[]> hs) { return Mesh.bindRevRoot(hs.size(), Pca.b64(Pca.build(hs))); }
    static Map<String, Object> proof(long index, long size, List<Object> path) { return obj("index", n(index), "size", n(size), "path", path); }
    static Map<String, Object> leaf(Object id, long index, long size, List<Object> path) { return obj("id", id, "proof", proof(index, size, path)); }

    @Test void leafBoundsAreChecked() {
        List<byte[]> hs = leaves("b", "d");
        String root = revRoot(hs);
        assertTrue(Mesh.leafOk(root, 2, "b", proof(0, 2, path(hs, 0))));
        assertTrue(Mesh.leafOk(root, 2, "d", proof(1, 2, path(hs, 1))));
        // the same audit paths under an index outside [0, size): the path shape alone would fit, the bounds refuse
        assertFalse(Mesh.leafOk(root, 2, "d", proof(2, 2, path(hs, 1))));
        assertFalse(Mesh.leafOk(root, 2, "d", proof(3, 2, path(hs, 1))));
        assertFalse(Mesh.leafOk(root, 2, "b", proof(-1, 2, path(hs, 0))));
        assertFalse(Mesh.leafOk(root, 2, "b", proof(0, 3, path(hs, 0))));
        assertFalse(Mesh.leafOk(root, 2, "b", obj("index", "0", "size", n(2), "path", path(hs, 0))));
        assertFalse(Mesh.leafOk(root, 2, "b", obj("index", n(0), "size", 2.5d, "path", path(hs, 0))));
        assertFalse(Mesh.leafOk(root, 2, "b", obj("index", n(0), "size", n(2))));
        assertFalse(Mesh.leafOk(root, 2, "b", proof(0, 2, new ArrayList<>())));
        assertFalse(Mesh.leafOk(root, 2, "c", proof(0, 2, path(hs, 0))));
        List<byte[]> one = leaves("q");
        assertTrue(Mesh.leafOk(revRoot(one), 1, "q", proof(0, 1, new ArrayList<>())));
        assertFalse(Mesh.leafOk(revRoot(one), 1, "q", proof(1, 1, new ArrayList<>())));
        assertFalse(Mesh.leafOk(revRoot(one), 1, "q", proof(-1, 1, new ArrayList<>())));
    }

    @Test void nonMembershipOnGeneratedTrees() {
        List<byte[]> hs = leaves("b", "d", "f");
        String root = revRoot(hs);
        Map<String, Object> b = leaf("b", 0, 3, path(hs, 0)), d = leaf("d", 1, 3, path(hs, 1)), f = leaf("f", 2, 3, path(hs, 2));
        assertTrue(Mesh.nonMembership(root, obj("size", n(3), "lo", b, "hi", d), "c"));
        assertTrue(Mesh.nonMembership(root, obj("size", n(3), "lo", d, "hi", f), "e"));
        assertTrue(Mesh.nonMembership(root, obj("size", n(3), "hi", b), "a"));
        assertTrue(Mesh.nonMembership(root, obj("size", n(3), "lo", f), "g"));
        // a member, a wrong side, non-adjacent bounds, a bound that is not the extreme leaf
        assertFalse(Mesh.nonMembership(root, obj("size", n(3), "lo", b, "hi", d), "d"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(3), "lo", b, "hi", d), "b"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(3), "lo", d, "hi", b), "c"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(3), "lo", b, "hi", f), "c"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(3), "lo", d), "e"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(3), "hi", d), "c"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(3)), "c"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(4), "lo", b, "hi", d), "c"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(-1), "lo", b, "hi", d), "c"));
        assertFalse(Mesh.nonMembership(root, obj("size", "3", "lo", b, "hi", d), "c"));
        // non-string bound ids read as "" and never bound anything (no exception)
        assertFalse(Mesh.nonMembership(root, obj("size", n(3), "lo", b, "hi", obj("id", n(5), "proof", proof(1, 3, path(hs, 1)))), "c"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(3), "hi", obj("id", null, "proof", proof(0, 3, path(hs, 0)))), "a"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(3), "lo", obj("id", n(5), "proof", proof(2, 3, path(hs, 2)))), "g"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(3), "lo", obj("id", "b"), "hi", d), "c"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(3), "lo", b, "hi", obj("id", "d", "proof", "x")), "c"));
        // the empty set
        String empty = Mesh.bindRevRoot(0, Ledger.EMPTY_TREE_ROOT);
        assertTrue(Mesh.nonMembership(empty, obj("size", n(0)), "x"));
        assertFalse(Mesh.nonMembership(root, obj("size", n(0)), "x"));
        assertFalse(Mesh.nonMembership(empty, obj("size", n(0), "lo", b), "x"));
        assertFalse(Mesh.nonMembership(empty, obj("size", n(0), "hi", b), "x"));
    }

    // ---- checkHeadAdvance: consistency proofs ----

    static final List<byte[]> LOG = new ArrayList<>();
    static {
        for (int i = 0; i < 24; i++) LOG.add(Pca.leafHash("entry-" + i));
    }

    static String logRoot(int size) { return size == 0 ? "" : Pca.b64(Pca.build(LOG.subList(0, size))); }

    /** RFC 9162 section 2.1.4.1 SUBPROOF. */
    static List<byte[]> subproof(int m, List<byte[]> d, boolean b) {
        int n = d.size();
        List<byte[]> out = new ArrayList<>();
        if (m == n) {
            if (!b) out.add(Pca.build(d));
            return out;
        }
        int k = Pca.split(n);
        if (m <= k) {
            out.addAll(subproof(m, d.subList(0, k), b));
            out.add(Pca.build(d.subList(k, n)));
        } else {
            out.addAll(subproof(m - k, d.subList(k, n), false));
            out.add(Pca.build(d.subList(0, k)));
        }
        return out;
    }

    static List<Object> consistencyPath(int first, int second) {
        List<Object> out = new ArrayList<>();
        if (first == 0) return out;
        for (byte[] h : subproof(first, LOG.subList(0, second), true)) out.add(Pca.b64(h));
        return out;
    }

    static Map<String, Object> head(long size, String root) {
        return obj("domain", "D", "root", root, "rev_root", "r", "size", n(size), "rev_size", n(0), "timestamp", n(0));
    }
    static Map<String, Object> cproof(long oldSize, long newSize, Object path) { return obj("oldSize", n(oldSize), "newSize", n(newSize), "path", path); }

    static final String FORK = "head is not consistent with the previous head (fork or rewrite)";
    static final String NEED = "consistency proof required for a larger head";

    @Test void consistencyOverEverySizePair() {
        String stranger = Pca.b64(Pca.leafHash("stranger"));
        for (int first = 0; first < 18; first++) {
            for (int second = first + 1; second <= 18; second++) {
                String at = first + "->" + second;
                List<Object> p = consistencyPath(first, second);
                Map<String, Object> prev = head(first, logRoot(first)), next = head(second, logRoot(second));
                assertEquals("", Mesh.checkHeadAdvance(prev, next, cproof(first, second, p)), at);
                // an empty old tree is consistent with any new root under an empty path
                assertEquals(first == 0 ? "" : FORK, Mesh.checkHeadAdvance(prev, head(second, stranger), cproof(first, second, p)), at + " other new root");
                List<Object> longer = new ArrayList<>(p);
                longer.add(Pca.b64(LOG.get(first)));
                assertEquals(FORK, Mesh.checkHeadAdvance(prev, next, cproof(first, second, longer)), at + " extra element");
                if (!p.isEmpty()) {
                    List<Object> shorter = new ArrayList<>(p.subList(0, p.size() - 1));
                    assertEquals(FORK, Mesh.checkHeadAdvance(prev, next, cproof(first, second, shorter)), at + " truncated");
                    List<Object> bent = new ArrayList<>(p);
                    bent.set(0, stranger);
                    assertEquals(FORK, Mesh.checkHeadAdvance(prev, next, cproof(first, second, bent)), at + " altered");
                    if (first > 0) assertEquals(FORK, Mesh.checkHeadAdvance(head(first, stranger), next, cproof(first, second, p)), at + " other old root");
                }
            }
        }
    }

    /** The path runs out of new-tree levels (sn == 0) before its last element: refused even when both roots absorb that element. */
    @Test void consistencyRefusesElementsPastTheNewRoot() {
        byte[] h01 = Pca.build(LOG.subList(0, 2)), h2 = LOG.get(2), h3 = LOG.get(3), extra = LOG.get(7);
        // the RFC 9162 proof 3 -> 4 is [h2, h3, h01]; one more element folded into both roots
        String oldRoot = Pca.b64(Pca.nodeHash(extra, Pca.nodeHash(h01, h2)));
        String newRoot = Pca.b64(Pca.nodeHash(extra, Pca.nodeHash(h01, Pca.nodeHash(h2, h3))));
        List<Object> p = List.of(Pca.b64(h2), Pca.b64(h3), Pca.b64(h01), Pca.b64(extra));
        assertEquals(FORK, Mesh.checkHeadAdvance(head(3, oldRoot), head(4, newRoot), cproof(3, 4, p)));
        // a power-of-two old size: 2 -> 3 is [h2] after the old root
        String old2 = Pca.b64(Pca.nodeHash(extra, h01)), new3 = Pca.b64(Pca.nodeHash(extra, Pca.nodeHash(h01, h2)));
        assertEquals(FORK, Mesh.checkHeadAdvance(head(2, old2), head(3, new3), cproof(2, 3, List.of(Pca.b64(h2), Pca.b64(extra)))));
        // not 32-byte hashes
        assertEquals(FORK, Mesh.checkHeadAdvance(head(3, logRoot(3)), head(4, logRoot(4)), cproof(3, 4, List.of("AAAA", Pca.b64(h3), Pca.b64(h01)))));
        assertEquals(FORK, Mesh.checkHeadAdvance(head(2, "AAAA"), head(3, logRoot(3)), cproof(2, 3, List.of(Pca.b64(h2)))));
        // a non-power-of-two old size with an empty path
        assertEquals(FORK, Mesh.checkHeadAdvance(head(3, logRoot(3)), head(4, logRoot(4)), cproof(3, 4, List.of())));
        assertEquals(FORK, Mesh.checkHeadAdvance(head(0, ""), head(3, logRoot(3)), cproof(0, 3, List.of(Pca.b64(h2)))));
    }

    @Test void consistencyProofShape() {
        Map<String, Object> prev = head(1, logRoot(1)), next = head(2, logRoot(2));
        String ok = Pca.b64(LOG.get(1));
        assertEquals("", Mesh.checkHeadAdvance(prev, next, cproof(1, 2, List.of(ok))));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, null));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, "x"));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, obj()));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, obj("oldSize", n(1), "newSize", n(2))));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, obj("oldSize", n(1), "newSize", n(2), "path", "x")));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, obj("oldSize", n(1), "newSize", n(2), "path", obj())));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, cproof(1, 2, List.of(n(1)))));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, cproof(1, 2, js("[\"" + ok + "\",null]"))));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, obj("oldSize", "1", "newSize", n(2), "path", List.of(ok))));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, obj("oldSize", n(1), "newSize", 2.5d, "path", List.of(ok))));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, obj("oldSize", n(-1), "newSize", n(2), "path", List.of(ok))));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, cproof(0, 2, List.of(ok))));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, cproof(1, 3, List.of(ok))));
        List<Object> p128 = new ArrayList<>(), p129 = new ArrayList<>();
        for (int i = 0; i < 128; i++) p128.add(ok);
        p129.addAll(p128);
        p129.add(ok);
        assertEquals(FORK, Mesh.checkHeadAdvance(prev, next, cproof(1, 2, p128)));
        assertEquals(NEED, Mesh.checkHeadAdvance(prev, next, cproof(1, 2, p129)));
    }

    // ---- verifyMeshProof: trust and table bounds on a junk chain ----

    static final String TRUST = "{\"humanPrincipal\":\"h\",\"witnesses\":[\"w\"],\"threshold\":1,\"now\":0,\"allowedDomains\":[\"d\"],\"rootDomain\":\"d\"}";

    static Map<String, Object> trust() { return m(js(TRUST)); }

    static Map<String, Object> junk(int chain, int heads, int leaves) {
        List<Object> c = new ArrayList<>(), h = new ArrayList<>(), r = new ArrayList<>();
        for (int i = 0; i < chain; i++) c.add(obj());
        for (int i = 0; i < heads; i++) h.add(obj());
        for (int i = 0; i < leaves; i++) r.add(obj());
        return obj("chain", c, "hops", new ArrayList<>(), "heads", h, "rev_leaves", r,
            "action", obj("type", "t", "resource", "r", "service_domain", "d", "nonce", "n", "at", n(0)), "action_sig", "s");
    }

    static final String BAD_HOP = "chain: hop 0: malformed capability|-1";
    static final String TOO_LONG = "chain: chain too long (max " + Pca.MAX_CHAIN_HOPS + " hops)|-1";
    static final String BOUNDS = "chain length out of bounds|-1";

    @Test void chainLengthBounds() {
        assertEquals(BOUNDS, v(Mesh.verifyMeshProof(junk(0, 0, 0), trust())));
        assertEquals(BAD_HOP, v(Mesh.verifyMeshProof(junk(1, 0, 0), trust())));
        assertEquals(TOO_LONG, v(Mesh.verifyMeshProof(junk(64, 0, 0), trust())));
        assertEquals(BOUNDS, v(Mesh.verifyMeshProof(junk(65, 0, 0), trust())));
        Map<String, Object> t = trust();
        t.put("maxChainLength", n(3));
        assertEquals(BAD_HOP, v(Mesh.verifyMeshProof(junk(3, 0, 0), t)));
        assertEquals(BOUNDS, v(Mesh.verifyMeshProof(junk(4, 0, 0), t)));
        t.put("maxChainLength", n(1));
        assertEquals(BAD_HOP, v(Mesh.verifyMeshProof(junk(1, 0, 0), t)));
        assertEquals(BOUNDS, v(Mesh.verifyMeshProof(junk(2, 0, 0), t)));
    }

    @Test void evidenceTableBounds() {
        String exceed = "evidence tables exceed chain size|-1";
        assertEquals(BAD_HOP, v(Mesh.verifyMeshProof(junk(1, 1, 2), trust())));
        assertEquals(exceed, v(Mesh.verifyMeshProof(junk(1, 0, 3), trust())));
        assertEquals(exceed, v(Mesh.verifyMeshProof(junk(1, 2, 0), trust())));
        assertEquals("chain: hop 0: malformed capability|-1", v(Mesh.verifyMeshProof(junk(2, 2, 4), trust())));
        assertEquals(exceed, v(Mesh.verifyMeshProof(junk(2, 2, 5), trust())));
        assertEquals(exceed, v(Mesh.verifyMeshProof(junk(3, 0, 7), trust())));
    }

    @Test void pinProofTableBound() {
        Map<String, Object> pin = obj("domain", "d", "proof", cproof(0, 0, new ArrayList<>()));
        for (int count : new int[] {0, 1, 256, 257}) {
            Map<String, Object> p = junk(1, 0, 0);
            List<Object> pins = new ArrayList<>();
            for (int i = 0; i < count; i++) pins.add(pin);
            p.put("pin_proofs", pins);
            assertEquals(count > 256 ? "malformed pin proofs|-1" : BAD_HOP, v(Mesh.verifyMeshProof(p, trust())), "pins " + count);
        }
        Map<String, Object> p = junk(1, 0, 0);
        p.put("pin_proofs", "x");
        assertEquals("malformed pin proofs|-1", v(Mesh.verifyMeshProof(p, trust())));
    }

    @Test void malformedProofAndTrust() {
        assertEquals("malformed proof|-1", v(Mesh.verifyMeshProof("x", trust())));
        assertEquals("malformed proof|-1", v(Mesh.verifyMeshProof(null, trust())));
        assertEquals("malformed proof|-1", v(Mesh.verifyMeshProof(List.of(), trust())));
        assertEquals("invalid trust configuration|-1", v(Mesh.verifyMeshProof("x", "x")));
        String bad = "invalid trust configuration: threshold|-1";
        for (Object th : new Object[] {"1", 1.5d, js("1.5"), n(0), n(2), n(-1), null, true}) {
            Map<String, Object> t = trust();
            t.put("threshold", th);
            assertEquals(bad, v(Mesh.verifyMeshProof(junk(1, 0, 0), t)), String.valueOf(th));
        }
        Map<String, Object> t = trust();
        t.remove("threshold");
        assertEquals(bad, v(Mesh.verifyMeshProof(junk(1, 0, 0), t)));
        for (Object mc : new Object[] {n(0), n(-1), "3", 1.5d}) {
            Map<String, Object> u = trust();
            u.put("maxChainLength", mc);
            assertEquals("invalid trust configuration: maxChainLength|-1", v(Mesh.verifyMeshProof(junk(1, 0, 0), u)), String.valueOf(mc));
        }
    }

    // ---- PQ root pins ----

    @Test void pqRootPins() throws Exception {
        String issuer = PqChainTest.pub("principal"), agent = PqChainTest.pub("agent");
        AsymmetricCipherKeyPair k = PqChainTest.pqKey();
        Map<String, Object> root = PqChainTest.cap(issuer, agent, new ArrayList<>(), null, "principal", "ml-dsa-65", k, null);
        Map<String, Object> p = junk(0, 0, 0);
        p.put("chain", new ArrayList<Object>(List.of(root)));
        String refused = "chain: " + PqChainTest.refusal("ml-dsa-65") + "|-1";
        String passed = "hop evidence count does not match chain length|-1";
        Object[][] pins = {
            {obj(issuer, PqChainTest.pk(k)), passed},
            {obj("other", n(5), issuer, PqChainTest.pk(k)), passed},
            {null, refused},
            {obj(), refused},
            {obj(issuer, n(5)), refused},
            {obj(issuer, agent), refused},
            {obj("other", PqChainTest.pk(k)), refused},
            {"x", refused},
            {List.of(PqChainTest.pk(k)), refused},
        };
        for (Object[] row : pins) {
            Map<String, Object> t = trust();
            t.put("humanPrincipal", issuer);
            if (row[0] != null) t.put("pqPins", row[0]);
            assertEquals(row[1], v(Mesh.verifyMeshProof(p, t)), String.valueOf(row[0]));
        }
    }

    // ---- tampered copies of the oracle's valid proof ----

    static Map<String, Object> baseCase() throws Exception {
        for (Map<String, Object> c : K05Oracle.of("k05-mesh", "verifyMeshProof")) {
            if ("verifyMeshProof/conf valid/base".equals(c.get("name"))) return c;
        }
        throw new IllegalStateException("no base case");
    }
    /** A deep copy of the base case's proof (0) or trust (1). */
    static Map<String, Object> base(int i) throws Exception { return m(IntentJs.normalize(l(baseCase().get("args")).get(i))); }

    @Test void baseProofIsValid() throws Exception {
        assertEquals("ok", v(Mesh.verifyMeshProof(base(0), base(1))));
    }

    @Test void pinnedHeadTruthiness() throws Exception {
        Map<String, Object> proof = base(0);
        String rootDomain = (String) base(1).get("rootDomain");
        String malformed = "source-domain anchor: malformed head (vs pinned head)|0";
        Object[][] pins = {
            {"null", "ok"}, {"false", "ok"}, {"\"\"", "ok"}, {"0", "ok"}, {"-0", "ok"},
            {"true", malformed}, {"\"x\"", malformed}, {"1", malformed}, {"-1", malformed}, {"0.5", malformed}, {"[]", malformed}, {"{}", malformed},
        };
        for (Object[] row : pins) {
            Map<String, Object> t = base(1);
            Map<String, Object> pinned = new LinkedHashMap<>();
            pinned.put(rootDomain, js((String) row[0]));
            t.put("pinnedHeads", pinned);
            assertEquals(row[1], v(Mesh.verifyMeshProof(proof, t)), (String) row[0]);
        }
        Map<String, Object> t = base(1);
        t.put("pinnedHeads", obj("some-other-domain", true));
        assertEquals("ok", v(Mesh.verifyMeshProof(proof, t)));
    }

    @Test void revocationLeafPathBound() throws Exception {
        for (int len : new int[] {128, 129}) {
            Map<String, Object> p = base(0);
            List<Object> path = new ArrayList<>();
            for (int i = 0; i < len; i++) path.add(obj());
            p.put("rev_leaves", new ArrayList<Object>(List.of(leaf("x", 0, 1, path))));
            assertEquals(len > 128 ? "malformed revocation leaves|-1" : "ok", v(Mesh.verifyMeshProof(p, base(1))), "path " + len);
        }
    }

    /** A tip carrying a member strict canonical JSON refuses: verifyChain never hashes the tip, the inclusion step does. */
    @Test void unhashableTipIsNotIncluded() throws Exception {
        Map<String, Object> p = base(0);
        List<Object> chain = l(p.get("chain"));
        m(chain.get(chain.size() - 1)).put("x", "\uD800");
        assertEquals("hop not included in the issuing domain log|" + (chain.size() - 1), v(Mesh.verifyMeshProof(p, base(1))));
        Map<String, Object> q = base(0);
        m(l(q.get("chain")).get(0)).put("x", "\uD800"); // a parent: verifyChain cannot hash the next hop's parent link
        assertEquals("chain: hop 1: broken parent link|-1", v(Mesh.verifyMeshProof(q, base(1))));
    }
}
