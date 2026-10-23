package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.AbstractList;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.Test;

/** Direct kill tests for the IntentJs value helpers and the Predicates internals (0.4.2 PIT survivors). */
public class K042PredJsUnitTest {
    static Map<String, Object> map(Object... kv) { return PredicatesKillTest.map(kv); }
    @SafeVarargs static <T> List<Object> list(T... xs) { return PredicatesKillTest.list(xs); }
    static Json.Num n(String s) { return new Json.Num(s); }
    static final Predicates.Tri T = Predicates.Tri.TRUE, F = Predicates.Tri.FALSE, U = Predicates.Tri.UNKNOWN;

    // ---- value predicates ----
    @Test void typePredicates() {
        assertTrue(IntentJs.isObj(map()));
        assertFalse(IntentJs.isObj(list()));
        assertFalse(IntentJs.isObj("x"));
        assertTrue(IntentJs.isArr(list()));
        assertFalse(IntentJs.isArr(map()));
        assertTrue(IntentJs.isStr("x"));
        assertFalse(IntentJs.isStr(n("1")));
        List<Object> l = list("a", "b");
        assertSame(l, IntentJs.arr(l));
        assertEquals(2, IntentJs.arr(l).size());
    }

    @Test void numbers() {
        assertEquals(5.0, IntentJs.num(5));
        assertEquals(5.0, IntentJs.num(5L));
        assertEquals(2.5, IntentJs.num(2.5d));
        assertEquals(7.0, IntentJs.num(n("7")));
        assertNull(IntentJs.num(n("x")));
        assertNull(IntentJs.num("5"));
        assertNull(IntentJs.num(null));
        assertNull(IntentJs.num(5.0f));
        assertNull(IntentJs.num(true));

        assertTrue(IntentJs.isFinite(n("1")));
        assertTrue(IntentJs.isFinite(0.0d));
        assertFalse(IntentJs.isFinite(Double.NaN));
        assertFalse(IntentJs.isFinite(Double.POSITIVE_INFINITY));
        assertFalse(IntentJs.isFinite(Double.NEGATIVE_INFINITY));
        assertFalse(IntentJs.isFinite(n("1e400")));
        assertFalse(IntentJs.isFinite("1"));
        assertFalse(IntentJs.isFinite(null));

        assertTrue(IntentJs.isSafeInteger(5));
        assertTrue(IntentJs.isSafeInteger(n("-0")));
        assertTrue(IntentJs.isSafeInteger(n("9007199254740991")));
        assertTrue(IntentJs.isSafeInteger(n("-9007199254740991")));
        assertFalse(IntentJs.isSafeInteger(n("9007199254740992")));
        assertFalse(IntentJs.isSafeInteger(n("-9007199254740992")));
        assertFalse(IntentJs.isSafeInteger(n("-1152921504606846976")));
        assertFalse(IntentJs.isSafeInteger(n("1.5")));
        assertFalse(IntentJs.isSafeInteger(n("0.5")));
        assertFalse(IntentJs.isSafeInteger(Double.NaN));
        assertFalse(IntentJs.isSafeInteger(Double.POSITIVE_INFINITY));
        assertFalse(IntentJs.isSafeInteger(Double.NEGATIVE_INFINITY));
        assertFalse(IntentJs.isSafeInteger("5"));
        assertFalse(IntentJs.isSafeInteger(null));
    }

    @Test void normalizeTrees() {
        Map<String, Object> in = map("a", n("1.0"), "b", list(n("1e3"), map("c", n("950000.0")), "s", true, null), "d", 0.1d, "e", "x");
        Map<String, Object> out = IntentJs.obj(IntentJs.normalize(in));
        assertNotSame(in, out);
        assertEquals("1", ((Json.Num) out.get("a")).raw);
        List<Object> b = IntentJs.arr(out.get("b"));
        assertEquals(5, b.size());
        assertEquals("1000", ((Json.Num) b.get(0)).raw);
        assertEquals("950000", ((Json.Num) IntentJs.obj(b.get(1)).get("c")).raw);
        assertEquals("s", b.get(2));
        assertEquals(Boolean.TRUE, b.get(3));
        assertNull(b.get(4));
        assertEquals("0.1", ((Json.Num) out.get("d")).raw);
        assertEquals("x", out.get("e"));
        assertEquals(List.of("a", "b", "d", "e"), new ArrayList<>(out.keySet()));
        // non-finite doubles keep their Java spelling (refused by every strict consumer); -0 stays "-0"
        assertEquals("NaN", ((Json.Num) IntentJs.normalize(Double.NaN)).raw);
        assertEquals("Infinity", ((Json.Num) IntentJs.normalize(Double.POSITIVE_INFINITY)).raw);
        assertEquals("-Infinity", ((Json.Num) IntentJs.normalize(Double.NEGATIVE_INFINITY)).raw);
        assertEquals("-0", ((Json.Num) IntentJs.normalize(-0.0d)).raw);
        assertEquals("1e400", IntentJs.normNum("1e400").raw);
        assertEquals("-1e400", IntentJs.normNum("-1e400").raw);
        assertEquals("abc", IntentJs.normNum("abc").raw);
        assertEquals("-0", IntentJs.normNum("-0.0").raw);
        // other values pass through unchanged
        assertEquals(5, IntentJs.normalize(5));
        assertEquals("s", IntentJs.normalize("s"));
        assertNull(IntentJs.normalize(null));
    }

    @Test void shortestDigits() {
        assertEquals("0.1", IntentJs.shortest(0.1));
        assertEquals("0.30000000000000004", IntentJs.shortest(0.1 + 0.2));
        assertEquals("1.5", IntentJs.shortest(1.5));
        assertEquals("100000000000000000000000", IntentJs.shortest(1e23));
        assertEquals("5", IntentJs.shortest(5.0));
        assertEquals("1152921504606847000", IntentJs.shortest(1152921504606846976.0));
        assertEquals("0.0000001", IntentJs.shortest(1e-7));
    }

    @Test void jsonEqualsOnJavaValues() {
        assertTrue(IntentJs.jsonEquals(null, null));
        assertFalse(IntentJs.jsonEquals(null, n("0")));
        assertFalse(IntentJs.jsonEquals(n("0"), null));
        assertFalse(IntentJs.jsonEquals("null", null));
        assertTrue(IntentJs.jsonEquals(5, n("5.0")));
        assertTrue(IntentJs.jsonEquals(5L, 5.0d));
        assertTrue(IntentJs.jsonEquals(-0.0d, 0));
        assertFalse(IntentJs.jsonEquals(Double.NaN, Double.NaN));
        assertFalse(IntentJs.jsonEquals(Double.POSITIVE_INFINITY, Double.POSITIVE_INFINITY));
        assertFalse(IntentJs.jsonEquals(1, Double.POSITIVE_INFINITY));
        assertFalse(IntentJs.jsonEquals(Double.POSITIVE_INFINITY, 1));
        assertFalse(IntentJs.jsonEquals(n("1"), "1"));
        assertFalse(IntentJs.jsonEquals("1", n("1")));
        assertTrue(IntentJs.jsonEquals("a", "a"));
        assertFalse(IntentJs.jsonEquals("a", "b"));
        assertTrue(IntentJs.jsonEquals(true, true));
        assertFalse(IntentJs.jsonEquals(true, false));
        assertFalse(IntentJs.jsonEquals(true, n("1")));
        assertFalse(IntentJs.jsonEquals(n("1"), true));
        assertFalse(IntentJs.jsonEquals(map(), list()));
        assertFalse(IntentJs.jsonEquals(list(), map()));
        assertTrue(IntentJs.jsonEquals(map(), map()));
        assertTrue(IntentJs.jsonEquals(list(), list()));
        assertTrue(IntentJs.jsonEquals(map("a", list(1, map("b", "c"))), map("a", list(n("1"), map("b", "c")))));
        assertFalse(IntentJs.jsonEquals(map("a", list(1)), map("a", list(2))));
        assertFalse(IntentJs.jsonEquals(map("a", null), map("b", null)));
        assertTrue(IntentJs.jsonEquals(map("a", null), map("a", null)));
        assertFalse(IntentJs.jsonEquals(list(1, 2), list(1)));
        assertFalse(IntentJs.jsonEquals(list(1), list(1, 2)));
        assertFalse(IntentJs.jsonEquals(list(1, 2), list(1, 3)));
        assertFalse(IntentJs.jsonEquals(new Object(), new Object()));
        Object same = new Object();
        assertFalse(IntentJs.jsonEquals(same, same));
        assertFalse(IntentJs.jsonEquals(map(), new Object()));
    }

    @Test void stringsAndBase64() {
        assertEquals(0, IntentJs.u8len(""));
        assertEquals(4, IntentJs.u8len("a\ud83d"));
        assertTrue(IntentJs.hasLoneSurrogate("\ud800"));
        assertFalse(IntentJs.hasLoneSurrogate("😀"));
        assertFalse(IntentJs.hasLoneSurrogate("abc"));
        assertTrue(IntentJs.compareUtf8("￿", "😀") < 0);
        assertTrue(IntentJs.compareUtf8("b", "a") > 0);
        assertEquals(0, IntentJs.compareUtf8("a", "a"));
        assertEquals(List.of("a", "b", "￿", "😀"), IntentJs.sortedUtf8(List.of("😀", "b", "￿", "a")));
        assertTrue(IntentJs.b64any("AAAA"));
        assertTrue(IntentJs.b64any("AA"));
        assertTrue(IntentJs.b64any(""));
        assertFalse(IntentJs.b64any("A"));
        assertFalse(IntentJs.b64any("AB"));
        assertFalse(IntentJs.b64any("AA=="));
        assertFalse(IntentJs.b64any(5));
        assertFalse(IntentJs.b64any(null));
    }

    // ---- suites / signatures ----
    static byte[] msg() { return "k042-predjs".getBytes(StandardCharsets.UTF_8); }

    @Test void ed25519AndSuiteHelpers() throws Exception {
        String pub = PqChainTest.pub("agent"), sig = PqChainTest.edSign("agent", msg());
        assertTrue(IntentJs.verifyEd(pub, msg(), sig));
        assertFalse(IntentJs.verifyEd(pub, msg(), PqChainTest.edSign("principal", msg())));
        assertFalse(IntentJs.verifyEd(5, msg(), sig));
        assertFalse(IntentJs.verifyEd(pub, msg(), 5));
        assertFalse(IntentJs.verifyEd(null, msg(), sig));

        assertEquals("ed25519", IntentJs.suiteOf(map()));
        assertEquals("ml-dsa-65", IntentJs.suiteOf(map("alg", "ml-dsa-65")));
        assertNull(IntentJs.suiteOf(map("alg", "nope")));
        assertNull(IntentJs.suiteOf(map("alg", 5)));

        Map<String, Object> base = map("a", 1);
        assertSame(base, IntentJs.bindSuiteFields(base, null, false, "PK", true));
        assertSame(base, IntentJs.bindSuiteFields(base, "ed25519", true, "PK", true));
        assertSame(base, IntentJs.bindSuiteFields(base, "nope", true, "PK", true));
        Map<String, Object> b = IntentJs.bindSuiteFields(base, "ml-dsa-65", true, "PK", true);
        assertEquals(map("a", 1, "alg", "ml-dsa-65", "pq_pk", "PK"), b);
        assertEquals(List.of("a", "alg", "pq_pk"), new ArrayList<>(b.keySet()));
        assertEquals(map("a", 1), base);
        Map<String, Object> np = IntentJs.bindSuiteFields(base, "ml-dsa-65", true, null, false);
        assertEquals(map("a", 1, "alg", "ml-dsa-65"), np);
        assertFalse(np.containsKey("pq_pk"));
        assertTrue(IntentJs.bindSuiteFields(base, "ml-dsa-65", true, null, true).containsKey("pq_pk"));

        assertNull(IntentJs.pin("id", 5));
        assertNull(IntentJs.pin("id", null));
        assertEquals(map("id", "PK"), IntentJs.pin("id", "PK"));
    }

    @Test void verifyPinnedSuite() throws Exception {
        String pub = PqChainTest.pub("agent");
        byte[] m = msg();
        String ed = PqChainTest.edSign("agent", m);
        // ed25519 (absent alg and explicit)
        assertTrue(IntentJs.verifyPinnedSuite(null, false, pub, null, m, ed, null, null));
        assertTrue(IntentJs.verifyPinnedSuite("ed25519", true, pub, null, m, ed, null, null));
        assertFalse(IntentJs.verifyPinnedSuite("ed25519", true, pub, null, m, PqChainTest.edSign("principal", m), null, null));
        // unknown / non-string suite
        assertFalse(IntentJs.verifyPinnedSuite("nope", true, pub, null, m, ed, null, null));
        assertFalse(IntentJs.verifyPinnedSuite(5, true, pub, null, m, ed, null, null));
        // pure ML-DSA-65: verifies only under a verifier pin for the identity
        AsymmetricCipherKeyPair k = PqChainTest.pqKey();
        String pk = PqChainTest.pk(k), ps = PqChainTest.pqSign(k, m);
        assertTrue(IntentJs.verifyPinnedSuite("ml-dsa-65", true, pub, pk, m, ps, null, IntentJs.pin(pub, pk)));
        assertFalse(IntentJs.verifyPinnedSuite("ml-dsa-65", true, pub, pk, m, ps, null, null));
        assertFalse(IntentJs.verifyPinnedSuite("ml-dsa-65", true, pub, pk, m, ps, null, IntentJs.pin(pub, PqChainTest.pk(PqChainTest.pqKey()))));
        assertFalse(IntentJs.verifyPinnedSuite("ml-dsa-65", true, pub, pk, m, PqChainTest.pqSign(k, new byte[] {1}), null, IntentJs.pin(pub, pk)));
        // hybrid
        assertTrue(IntentJs.verifyPinnedSuite("hybrid-ed25519-ml-dsa-65", true, pub, pk, m, ed, ps, IntentJs.pin(pub, pk)));
        assertFalse(IntentJs.verifyPinnedSuite("hybrid-ed25519-ml-dsa-65", true, pub, pk, m, ed, PqChainTest.pqSign(k, new byte[] {1}), IntentJs.pin(pub, pk)));
        // a pin map that throws: never throws, refuses
        Map<String, Object> boom = new AbstractMap<String, Object>() {
            @Override public Set<Entry<String, Object>> entrySet() { throw new IllegalStateException("boom"); }
            @Override public boolean containsKey(Object key) { throw new IllegalStateException("boom"); }
            @Override public Object get(Object key) { throw new IllegalStateException("boom"); }
        };
        assertFalse(IntentJs.verifyPinnedSuite("ml-dsa-65", true, pub, pk, m, ps, null, boom));
    }

    // ---- Predicates internals ----
    @Test void globDirect() {
        assertNull(Predicates.globMatch("a\\", "a"));
        assertNull(Predicates.globMatch("\\", ""));
        assertEquals(Boolean.TRUE, Predicates.globMatch("", ""));
        assertEquals(Boolean.FALSE, Predicates.globMatch("", "a"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("*", ""));
        assertEquals(Boolean.TRUE, Predicates.globMatch("**", ""));
        assertEquals(Boolean.FALSE, Predicates.globMatch("?", ""));
        assertEquals(Boolean.TRUE, Predicates.globMatch("a\\*b", "a*b"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("a\\*b", "axb"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("a\\?b", "a?b"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("a\\?b", "axb"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("a*", "a"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("a*b", "a"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("Ana", "xAna"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("na", "Ana"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("*a*a*a", "banana"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("*a*a*a*a", "banana"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("a\u0000", "a\u0000"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("a*", "b\u0000"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("?", "\u0000\u0000"));
    }

    static final class BoomCtx extends AbstractMap<String, Object> {
        @Override public Set<Entry<String, Object>> entrySet() { throw new IllegalStateException("boom"); }
        @Override public boolean containsKey(Object key) { throw new IllegalStateException("boom"); }
        @Override public Object get(Object key) { throw new IllegalStateException("boom"); }
    }

    @Test void evaluatorsFailClosedOnAThrowingContext() {
        Map<String, Object> boom = new BoomCtx();
        assertEquals(U, Predicates.evaluateConditionTri(map("field", "env.a", "op", "exists"), boom));
        assertEquals(U, Predicates.evaluateConditionTri(map("all_of", list(map("field", "env.a", "op", "exists"))), boom));
        assertFalse(Predicates.evaluateCondition(map("field", "env.a", "op", "exists"), boom));
        assertFalse(Predicates.predicateMatches(map("verb", "*"), boom));
        assertFalse(Predicates.evaluatePredicates(list(map("verb", "*")), boom));
        Map<String, Object> ok = map("action", map("verb", "v", "resource", "r"));
        assertTrue(Predicates.evaluatePredicates(list(map("verb", "*")), ok));
        List<Object> throwingList = new AbstractList<Object>() {
            @Override public Object get(int i) { throw new IllegalStateException("boom"); }
            @Override public int size() { return 1; }
            @Override public Iterator<Object> iterator() { throw new IllegalStateException("boom"); }
        };
        assertFalse(Predicates.evaluatePredicates(throwingList, ok));
        assertFalse(Predicates.evaluatePredicates(null, ok));
        assertFalse(Predicates.evaluatePredicates(map("verb", "*"), ok));
        assertFalse(Predicates.evaluatePredicates(list(), ok));
    }

    @Test void resolvePathDirect() {
        Map<String, Object> ctx = map("action", map("verb", "v", "resource", "r", "params", map("tags", list("a", "b"), "", "e")));
        Predicates.Resolved r = Predicates.resolvePath(ctx, "action.params.tags.1");
        assertTrue(r.found);
        assertEquals("b", r.value);
        assertFalse(Predicates.resolvePath(ctx, "action.params.tags.2").found);
        assertNull(Predicates.resolvePath(ctx, "action.params.tags.2").value);
        assertFalse(Predicates.resolvePath(ctx, "action.params.tags.01").found);
        assertEquals("e", Predicates.resolvePath(ctx, "action.params.").value);
        assertFalse(Predicates.resolvePath(ctx, "").found);
        assertFalse(Predicates.resolvePath(ctx, 5).found);
        assertFalse(Predicates.resolvePath(null, "action").found);
        assertFalse(Predicates.resolvePath(ctx, "env").found);
        assertTrue(Predicates.resolvePath(map("env", null), "env").found);
        Map<String, Object> l = new LinkedHashMap<>();
        l.put("x", 1);
        assertEquals(1, Predicates.resolvePath(map("env", l), "env.x").value);
    }
}
