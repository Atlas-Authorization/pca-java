package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Prohibitions: the JavaScript-flavoured helpers, an omitted optional argument versus an explicit null, and the unbound-evidence refusal. */
class ProhibitionsPitKillTest {
    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static Object j(String s) { return Json.parseLenient(s.replace('\'', '"')); }

    static Json.Num n(String raw) { return new Json.Num(raw); }

    @Test void negZeroIsOnlyMinusZero() {
        assertTrue(Prohibitions.negZero(n("-0")));
        assertTrue(Prohibitions.negZero(Double.valueOf(-0.0)));
        for (Object v : new Object[] {n("0"), Double.valueOf(0.0), n("-1"), n("1"), n("-0.5"), n("0.5"), null, "x", Boolean.TRUE, List.of()}) assertFalse(Prohibitions.negZero(v), String.valueOf(v));
    }

    @Test void isIntegerIsNumberIsInteger() {
        for (Object v : new Object[] {n("0"), n("-0"), n("2"), n("-2"), n("1e21"), Long.valueOf(7)}) assertTrue(Prohibitions.isInteger(v), String.valueOf(v));
        for (Object v : new Object[] {n("1.5"), n("-1.5"), n("0.5"), n("-0.5"), n("1e400"), null, "2", Boolean.TRUE}) assertFalse(Prohibitions.isInteger(v), String.valueOf(v));
    }

    @Test void propAndGetReadMissingAsUndefinedAndNullAsNull() {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("a", "x");
        o.put("z", null);
        assertEquals("x", Prohibitions.prop(o, "a"));
        assertEquals(null, Prohibitions.prop(o, "z"));
        assertSame(Prohibitions.UNDEF, Prohibitions.prop(o, "missing"));
        assertSame(Prohibitions.UNDEF, Prohibitions.prop("str", "a"));
        assertSame(Prohibitions.UNDEF, Prohibitions.prop(null, "a"));
        assertSame(Prohibitions.UNDEF, Prohibitions.prop(List.of("a"), "a"));
        assertEquals("x", Prohibitions.get(o, "a"));
        assertEquals(null, Prohibitions.get(o, "z"));
        assertSame(Prohibitions.UNDEF, Prohibitions.get(o, "missing"));
    }

    @Test void presentTextTruthyAndStrEq() {
        assertFalse(Prohibitions.present(Prohibitions.UNDEF));
        assertTrue(Prohibitions.present(null));
        assertTrue(Prohibitions.present("x"));
        assertEquals("undefined", Prohibitions.text(Prohibitions.UNDEF));
        assertEquals("null", Prohibitions.text(null));
        assertEquals("abc", Prohibitions.text("abc"));
        assertEquals("5", Prohibitions.text(n("5")));
        assertEquals("a,b", Prohibitions.text(new ArrayList<Object>(List.of("a", "b"))));
        assertFalse(Prohibitions.truthy(Prohibitions.UNDEF));
        assertFalse(Prohibitions.truthy(null));
        assertFalse(Prohibitions.truthy(""));
        assertFalse(Prohibitions.truthy(n("0")));
        assertFalse(Prohibitions.truthy(Boolean.FALSE));
        assertTrue(Prohibitions.truthy("a"));
        assertTrue(Prohibitions.truthy(n("1")));
        assertTrue(Prohibitions.truthy(Boolean.TRUE));
        assertTrue(Prohibitions.truthy(new ArrayList<>()));
        assertTrue(Prohibitions.truthy(new LinkedHashMap<>()));
        assertTrue(Prohibitions.strEq("a", "a"));
        assertFalse(Prohibitions.strEq("b", "a"));
        assertFalse(Prohibitions.strEq(null, "a"));
        assertFalse(Prohibitions.strEq(Integer.valueOf(1), "1"));
    }

    @Test void safeAnswersUnhashableOnAnyFailureAndOtherwiseThePlainValue() {
        assertEquals("v", Prohibitions.safe(() -> "v"));
        assertEquals(Prohibitions.UNHASHABLE, Prohibitions.safe(() -> { throw new IllegalStateException("x"); }));
        assertEquals(Prohibitions.UNHASHABLE, Prohibitions.safe(() -> { throw new AssertionError("x"); }));
        assertEquals(Prohibitions.UNHASHABLE, Prohibitions.safe(() -> { throw new StackOverflowError(); }));
    }

    @Test void joinIdsJoinsTheJavaScriptTextWithCommas() {
        assertEquals("", Prohibitions.joinIds(new ArrayList<>()));
        assertEquals("a", Prohibitions.joinIds(new ArrayList<Object>(List.of("a"))));
        assertEquals("a,b,c", Prohibitions.joinIds(new ArrayList<Object>(List.of("a", "b", "c"))));
        List<Object> withNull = new ArrayList<>();
        withNull.add("a");
        withNull.add(null);
        assertEquals("a,null", Prohibitions.joinIds(withNull));
    }

    static final String C = "{'version':1,'principal':'p','invariants':[{'id':'n','kind':'never','when':{'verb':'delete'}}]}";
    static final String S = "{'now':1000,'seq':0,'parent':null,'ledger':{},'latched':{}}";
    static final String A = "{'action':{'verb':'pay','resource':'/r'}}";

    @Test void anOmittedNowIsTheStatesOwnAndAnExplicitNullIsAClockRegression() {
        Map<String, Object> omitted = Prohibitions.advanceStateStrict(j(A), j(C), j(S), null);
        assertEquals(true, omitted.get("ok"), String.valueOf(omitted));
        assertEquals("1000", m(omitted.get("state")).get("now").toString());
        assertEquals("1", m(omitted.get("state")).get("seq").toString());
        Map<String, Object> later = Prohibitions.advanceStateStrict(j(A), j(C), j(S), n("2000"));
        assertEquals("2000", m(later.get("state")).get("now").toString());
        assertEquals("clock regression", Prohibitions.advanceStateStrict(j(A), j(C), j(S), n("999")).get("reason"));
        Map<String, Object> explicit = Prohibitions.advanceStateStrictRef(j(A), j(C), j(S), null);
        assertEquals(false, explicit.get("ok"));
        assertEquals("clock regression", explicit.get("reason"));
        Map<String, Object> absent = Prohibitions.advanceStateStrictRef(j(A), j(C), j(S), Prohibitions.ABSENT);
        assertEquals(true, absent.get("ok"));
        assertEquals("malformed monitor state", Prohibitions.advanceStateStrict(j(A), j(C), null, null).get("reason"));
        assertEquals("malformed monitor state", Prohibitions.advanceStateStrict(j(A), j(C), "x", null).get("reason"));
    }

    @Test void anOmittedExpectedSeqIsNoCheckAndAnExplicitNullIsAStaleHead() {
        Map<String, Object> none = Prohibitions.checkAndAdvance(true, j(A), j(C), j(S), null, null);
        assertEquals(true, none.get("allow"), String.valueOf(none));
        assertEquals("none", none.get("decidedBy"));
        assertNotNull(none.get("next"));
        assertEquals(true, Prohibitions.checkAndAdvance(true, j(A), j(C), j(S), n("0"), null).get("allow"));
        Map<String, Object> stale = Prohibitions.checkAndAdvance(true, j(A), j(C), j(S), n("1"), null);
        assertEquals(false, stale.get("allow"));
        assertEquals("state", stale.get("decidedBy"));
        assertEquals("stale state head (seq)", stale.get("reason"));
        Map<String, Object> explicit = Prohibitions.checkAndAdvanceRef(true, j(A), j(C), j(S), null, null);
        assertEquals(false, explicit.get("allow"));
        assertEquals("stale state head (seq)", explicit.get("reason"));
        assertEquals(true, Prohibitions.checkAndAdvanceRef(true, j(A), j(C), j(S), Prohibitions.ABSENT, null).get("allow"));
        String digest = Prohibitions.stateDigest(j(S));
        assertEquals(true, Prohibitions.checkAndAdvance(true, j(A), j(C), j(S), null, digest).get("allow"));
        Map<String, Object> wrong = Prohibitions.checkAndAdvance(true, j(A), j(C), j(S), null, "nope");
        assertEquals(false, wrong.get("allow"));
        assertEquals("stale state head (digest)", wrong.get("reason"));
        Map<String, Object> notPermitted = Prohibitions.checkAndAdvance(false, j(A), j(C), j(S), null, null);
        assertEquals(false, notPermitted.get("allow"));
        assertEquals("permission", notPermitted.get("decidedBy"));
        assertFalse(notPermitted.containsKey("reason"));
        // a state that is not an object cannot match any expected seq
        assertEquals("stale state head (seq)", Prohibitions.checkAndAdvance(true, j(A), j(C), "x", n("0"), null).get("reason"));
    }

    @Test void evidenceBindingNeedsEveryBoundDigestToExist() {
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("constitution", "c");
        ev.put("action_digest", "a");
        ev.put("state_digest", "s");
        assertEquals(43, Prohibitions.safetyBindingId(ev, "signer").length());
        for (String k : new String[] {"constitution", "action_digest", "state_digest"}) {
            Map<String, Object> cut = new LinkedHashMap<>(ev);
            cut.remove(k);
            assertEquals("canonicalize: unsupported type undefined", assertThrows(IllegalArgumentException.class, () -> Prohibitions.safetyBindingId(cut, "signer")).getMessage(), k);
        }
    }

    @Test void aDescriptionThatIsNotATextStaysItselfInTheRow() {
        String c = "{'version':1,'principal':'p','invariants':[{'id':'n','kind':'never','when':{'verb':'pay'},'description':5}]}";
        Map<String, Object> r = Prohibitions.checkProhibitions(j(A), j(c), j(S));
        assertEquals(false, r.get("ok"));
        Map<String, Object> row = m(((List<?>) r.get("evaluated")).get(0));
        assertEquals("5", row.get("reason").toString());
        assertFalse(row.get("reason") instanceof String, "the raw number, not its text");
        assertEquals("n: 5", ((List<?>) r.get("reasons")).get(0));
    }
}
