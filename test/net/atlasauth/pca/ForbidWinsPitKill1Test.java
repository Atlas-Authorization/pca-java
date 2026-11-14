package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Mutation kills for {@code ForbidWins}: trigger and condition validation, the fail-closed trigger match, the decision order and the certificate rules. */
class ForbidWinsPitKill1Test {
    static Map<String, Object> o(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static Map<String, Object> leaf() { return o("field", "action.verb", "op", "eq", "value", "read"); }

    static Map<String, Object> ctx(String verb, String resource) { return o("action", o("verb", verb, "resource", resource)); }

    static final Map<String, Object> READ = ctx("read", "doc/1");

    static Map<String, Object> clause(String id, String kind, String signer, Object when) {
        Map<String, Object> c = o("id", id, "kind", kind);
        if (signer != null) c.put("signer", signer);
        c.put("when", when);
        return c;
    }

    static Map<String, Object> hit() { return o("verb", "read"); }
    static Map<String, Object> miss() { return o("verb", "write"); }
    /** Matches the verb, but its where-condition cannot be decided (the field is absent), so a veto clause is "unknown". */
    static Map<String, Object> unknownWhen() { return o("verb", "read", "where", List.<Object>of(o("field", "env.nothing", "op", "eq", "value", "x"))); }

    static List<Object> list(Object... xs) { return new ArrayList<>(java.util.Arrays.asList(xs)); }

    // ---- validateCondition

    @Test void validateConditionRejectsANonObject() {
        assertEquals("condition not an object", ForbidWins.validateCondition(null, 0));
        assertEquals("condition not an object", ForbidWins.validateCondition("x", 0));
        assertEquals("condition not an object", ForbidWins.validateCondition(List.of(), 0));
        assertEquals("condition not an object", ForbidWins.validateCondition(5L, 0));
    }

    @Test void validateConditionDepthLimitIsInclusiveAt32() {
        assertNull(ForbidWins.validateCondition(leaf(), 32));
        assertEquals("condition nesting too deep", ForbidWins.validateCondition(leaf(), 33));
        assertEquals("condition nesting too deep", ForbidWins.validateCondition(leaf(), 34));
        assertNull(ForbidWins.validateCondition(o("not", leaf()), 31));
        assertEquals("condition nesting too deep", ForbidWins.validateCondition(o("not", leaf()), 32));
        assertNull(ForbidWins.validateCondition(o("all_of", List.<Object>of(leaf())), 31));
        assertEquals("condition nesting too deep", ForbidWins.validateCondition(o("all_of", List.<Object>of(leaf())), 32));
        assertNull(ForbidWins.validateCondition(o("any_of", List.<Object>of(leaf())), 31));
        assertEquals("condition nesting too deep", ForbidWins.validateCondition(o("any_of", List.<Object>of(leaf())), 32));
        // an empty grouping is refused before its children are looked at, even at the limit
        assertEquals("condition.all_of must be a non-empty array", ForbidWins.validateCondition(o("all_of", List.of()), 32));
    }

    @Test void validateConditionGroupings() {
        assertNull(ForbidWins.validateCondition(o("all_of", List.<Object>of(leaf(), leaf())), 0));
        assertNull(ForbidWins.validateCondition(o("any_of", List.<Object>of(leaf())), 0));
        assertNull(ForbidWins.validateCondition(o("not", leaf()), 0));
        assertEquals("condition.all_of must be a non-empty array", ForbidWins.validateCondition(o("all_of", List.of()), 0));
        assertEquals("condition.all_of must be a non-empty array", ForbidWins.validateCondition(o("all_of", "x"), 0));
        assertEquals("condition.all_of must be a non-empty array", ForbidWins.validateCondition(o("all_of", null), 0));
        assertEquals("condition.any_of must be a non-empty array", ForbidWins.validateCondition(o("any_of", List.of()), 0));
        assertEquals("condition.any_of must be a non-empty array", ForbidWins.validateCondition(o("any_of", "x"), 0));
        // all_of is read before any_of when both are present
        assertEquals("condition.all_of must be a non-empty array", ForbidWins.validateCondition(o("all_of", List.of(), "any_of", List.<Object>of(leaf())), 0));
        assertNull(ForbidWins.validateCondition(o("any_of", List.<Object>of(leaf()), "all_of", List.<Object>of(leaf())), 0));
        // not wins over the other groupings
        assertEquals("condition.field missing", ForbidWins.validateCondition(o("all_of", List.<Object>of(leaf()), "not", o("op", "eq")), 0));
        assertNull(ForbidWins.validateCondition(o("all_of", List.of(), "not", leaf()), 0));
        assertNull(ForbidWins.validateCondition(o("any_of", "x", "not", leaf()), 0));
        assertEquals("condition not an object", ForbidWins.validateCondition(o("not", null), 0));
        // the first bad child is reported, whatever its position
        assertEquals("condition.field missing", ForbidWins.validateCondition(o("all_of", List.<Object>of(leaf(), o("op", "eq"))), 0));
        assertEquals("unknown condition op zz", ForbidWins.validateCondition(o("any_of", List.<Object>of(o("field", "f", "op", "zz"), o("op", "eq"))), 0));
        assertEquals("condition not an object", ForbidWins.validateCondition(o("all_of", List.<Object>of(leaf(), "x")), 0));
        assertEquals("condition.field missing", ForbidWins.validateCondition(o("not", o("not", o("op", "eq"))), 0));
    }

    @Test void validateConditionLeafFieldOpRefAndCollection() {
        assertEquals("condition.field missing", ForbidWins.validateCondition(o("op", "eq"), 0));
        assertEquals("condition.field missing", ForbidWins.validateCondition(o("field", 5L, "op", "eq"), 0));
        assertEquals("condition.field missing", ForbidWins.validateCondition(o("field", "", "op", "eq"), 0));
        assertEquals("unknown condition op undefined", ForbidWins.validateCondition(o("field", "f"), 0));
        assertEquals("unknown condition op null", ForbidWins.validateCondition(o("field", "f", "op", null), 0));
        assertEquals("unknown condition op 5", ForbidWins.validateCondition(o("field", "f", "op", 5L), 0));
        assertEquals("unknown condition op zz", ForbidWins.validateCondition(o("field", "f", "op", "zz"), 0));
        assertEquals("unknown condition op a,b", ForbidWins.validateCondition(o("field", "f", "op", List.of("a", "b")), 0));
        assertEquals("unknown condition op [object Object]", ForbidWins.validateCondition(o("field", "f", "op", o()), 0));
        assertEquals("unknown condition op EQ", ForbidWins.validateCondition(o("field", "f", "op", "EQ"), 0));
        for (String op : new String[] {"eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists", "like", "matches", "is_a", "member_of"}) {
            assertNull(ForbidWins.validateCondition(o("field", "f", "op", op), 0), op);
        }
        assertEquals("bad condition.ref", ForbidWins.validateCondition(o("field", "f", "op", "eq", "ref", 5L), 0));
        assertEquals("bad condition.ref", ForbidWins.validateCondition(o("field", "f", "op", "eq", "ref", ""), 0));
        assertEquals("bad condition.ref", ForbidWins.validateCondition(o("field", "f", "op", "eq", "ref", null), 0));
        assertNull(ForbidWins.validateCondition(o("field", "f", "op", "eq", "ref", "g"), 0));
        assertEquals("bad condition.collection", ForbidWins.validateCondition(o("field", "f", "op", "member_of", "collection", ""), 0));
        assertEquals("bad condition.collection", ForbidWins.validateCondition(o("field", "f", "op", "member_of", "collection", 5L), 0));
        assertEquals("bad condition.collection", ForbidWins.validateCondition(o("field", "f", "op", "member_of", "collection", null), 0));
        assertNull(ForbidWins.validateCondition(o("field", "f", "op", "member_of", "collection", "c"), 0));
        assertNull(ForbidWins.validateCondition(o("field", "f", "op", "member_of"), 0));
        assertNull(ForbidWins.validateCondition(o("field", "f", "op", "eq", "collection", 5L), 0));
        assertNull(ForbidWins.validateCondition(o("field", "f", "op", "eq", "collection", ""), 0));
        // the ref check precedes the collection check
        assertEquals("bad condition.ref", ForbidWins.validateCondition(o("field", "f", "op", "member_of", "ref", 1L, "collection", 5L), 0));
    }

    // ---- validateWhen

    @Test void validateWhenLabelsEveryRefusal() {
        assertEquals("L: not an object", ForbidWins.validateWhen(null, "L"));
        assertEquals("L: not an object", ForbidWins.validateWhen("x", "L"));
        assertEquals("L: not an object", ForbidWins.validateWhen(List.of(), "L"));
        assertEquals("L: bad verb", ForbidWins.validateWhen(o(), "L"));
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb", ""), "L"));
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb", 5L), "L"));
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb", List.of()), "L"));
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb", List.of("a", "")), "L"));
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb", List.of("")), "L"));
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb", list("a", 5L)), "L"));
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb", list(5L, "a")), "L"));
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("verb", list("a", "b", null)), "L"));
        assertNull(ForbidWins.validateWhen(o("verb", "a"), "L"));
        assertNull(ForbidWins.validateWhen(o("verb", List.of("a")), "L"));
        assertNull(ForbidWins.validateWhen(o("verb", List.of("a", "b", "c")), "L"));
    }

    @Test void validateWhenResource() {
        assertEquals("L: bad resource", ForbidWins.validateWhen(o("verb", "a", "resource", 5L), "L"));
        assertEquals("L: bad resource", ForbidWins.validateWhen(o("verb", "a", "resource", null), "L"));
        assertNull(ForbidWins.validateWhen(o("verb", "a", "resource", "a"), "L"));
        assertNull(ForbidWins.validateWhen(o("verb", "a", "resource", "re"), "L"));
        assertNull(ForbidWins.validateWhen(o("verb", "a", "resource", "doc/*"), "L"));
        assertNull(ForbidWins.validateWhen(o("verb", "a", "resource", "re:abc"), "L"));
        // the source after the prefix is what is judged
        assertEquals("L: unsafe regex resource", ForbidWins.validateWhen(o("verb", "a", "resource", "re:*"), "L"));
        assertEquals("L: unsafe regex resource", ForbidWins.validateWhen(o("verb", "a", "resource", "re:(a+)+"), "L"));
        assertNull(ForbidWins.validateWhen(o("verb", "a", "resource", "re:" + "a".repeat(200)), "L"));
        assertEquals("L: unsafe regex resource", ForbidWins.validateWhen(o("verb", "a", "resource", "re:" + "a".repeat(201)), "L"));
    }

    @Test void validateWhenWhere() {
        assertEquals("L: where not an array", ForbidWins.validateWhen(o("verb", "a", "where", "x"), "L"));
        assertEquals("L: where not an array", ForbidWins.validateWhen(o("verb", "a", "where", null), "L"));
        assertNull(ForbidWins.validateWhen(o("verb", "a", "where", List.of()), "L"));
        assertNull(ForbidWins.validateWhen(o("verb", "a", "where", List.<Object>of(leaf())), "L"));
        assertEquals("L: condition.field missing", ForbidWins.validateWhen(o("verb", "a", "where", List.<Object>of(leaf(), o("op", "eq"))), "L"));
        assertEquals("L: condition not an object", ForbidWins.validateWhen(o("verb", "a", "where", List.<Object>of("x")), "L"));
        // where conditions start at depth 0: 32 nested nots pass, 33 do not
        Object deep32 = leaf();
        for (int i = 0; i < 32; i++) deep32 = o("not", deep32);
        assertNull(ForbidWins.validateWhen(o("verb", "a", "where", List.of(deep32)), "L"));
        assertEquals("L: condition nesting too deep", ForbidWins.validateWhen(o("verb", "a", "where", List.of(o("not", deep32))), "L"));
        // verb is judged before resource, resource before where
        assertEquals("L: bad verb", ForbidWins.validateWhen(o("resource", 5L, "where", "x"), "L"));
        assertEquals("L: bad resource", ForbidWins.validateWhen(o("verb", "a", "resource", 5L, "where", "x"), "L"));
    }

    // ---- clausesError

    @Test void clausesErrorMessages() {
        assertEquals("clauses must be an array", ForbidWins.clausesError("x"));
        assertEquals("clauses must be an array", ForbidWins.clausesError(null));
        assertNull(ForbidWins.clausesError(List.of()));
        assertEquals("clauses[0] must be an object", ForbidWins.clausesError(List.of("x")));
        assertEquals("clauses[1].id must be a string of 1..128 characters", ForbidWins.clausesError(List.<Object>of(clause("a", "permit", null, hit()), o("id", 5L))));
        assertEquals("clauses[0].id must be a string of 1..128 characters", ForbidWins.clausesError(List.<Object>of(o("id", ""))));
        assertEquals("clauses[0].id must be a string of 1..128 characters", ForbidWins.clausesError(List.<Object>of(o("id", "a".repeat(129), "kind", "permit", "when", hit()))));
        assertNull(ForbidWins.clausesError(List.<Object>of(clause("a".repeat(128), "permit", null, hit()))));
        assertEquals("clauses[1].id 'a' is a duplicate", ForbidWins.clausesError(List.<Object>of(clause("a", "permit", null, hit()), clause("a", "forbid", null, hit()))));
        for (Object kind : new Object[] {"allow", "", 5L, null}) {
            Map<String, Object> c = o("id", "a", "kind", kind, "when", hit());
            assertEquals("clauses[0].kind must be permit, forbid or escalate", ForbidWins.clausesError(List.<Object>of(c)), "kind " + kind);
        }
        Map<String, Object> noKind = o("id", "a", "when", hit());
        assertEquals("clauses[0].kind must be permit, forbid or escalate", ForbidWins.clausesError(List.<Object>of(noKind)));
        for (String k : new String[] {"permit", "forbid", "escalate"}) assertNull(ForbidWins.clausesError(List.<Object>of(clause("a", k, null, hit()))));
        Map<String, Object> bad = clause("a", "permit", null, hit());
        bad.put("signer", 5L);
        assertEquals("clauses[0].signer must be a string of at most 256 characters", ForbidWins.clausesError(List.<Object>of(bad)));
        bad.put("signer", "s".repeat(257));
        assertEquals("clauses[0].signer must be a string of at most 256 characters", ForbidWins.clausesError(List.<Object>of(bad)));
        bad.put("signer", "s".repeat(256));
        assertNull(ForbidWins.clausesError(List.<Object>of(bad)));
        assertEquals("clauses[0].when must be a predicate object", ForbidWins.clausesError(List.<Object>of(o("id", "a", "kind", "permit"))));
        assertEquals("clauses[0].when must be a predicate object", ForbidWins.clausesError(List.<Object>of(o("id", "a", "kind", "permit", "when", "x"))));
        List<Object> many = new ArrayList<>();
        for (int i = 0; i < 512; i++) many.add(clause("c" + i, "permit", null, hit()));
        assertNull(ForbidWins.clausesError(many));
        many.add(clause("extra", "permit", null, hit()));
        assertEquals("more than 512 clauses", ForbidWins.clausesError(many));
    }

    // ---- whenMatches

    @Test void whenMatchesIsTheVetoPolarity() {
        assertTrue(ForbidWins.whenMatches(hit(), READ));
        assertFalse(ForbidWins.whenMatches(miss(), READ));
        assertTrue(ForbidWins.whenMatches(o("verb", List.of("x", "read")), READ));
        assertTrue(ForbidWins.whenMatches(o("verb", "read", "resource", "doc/*"), READ));
        assertFalse(ForbidWins.whenMatches(o("verb", "read", "resource", "other/*"), READ));
        assertTrue(ForbidWins.whenMatches(o("verb", "read", "resource", "re:doc/[0-9]"), READ));
        assertFalse(ForbidWins.whenMatches(o("verb", "read", "resource", "re:zzz"), READ));
        // a where that is cleanly false clears the veto; true or undecidable keeps it
        assertTrue(ForbidWins.whenMatches(o("verb", "read", "where", List.<Object>of(leaf())), READ));
        assertFalse(ForbidWins.whenMatches(o("verb", "read", "where", List.<Object>of(o("field", "action.verb", "op", "ne", "value", "read"))), READ));
        assertFalse(ForbidWins.whenMatches(o("verb", "read", "where", List.<Object>of(leaf(), o("field", "action.verb", "op", "ne", "value", "read"))), READ));
        assertTrue(ForbidWins.whenMatches(unknownWhen(), READ));
        assertFalse(ForbidWins.whenMatches(o("verb", "write", "where", List.<Object>of(leaf())), READ));
        assertTrue(ForbidWins.whenMatches(o("verb", "read", "where", List.of()), READ));
    }

    @Test void whenMatchesFailsClosedOnAMalformedTriggerOrContext() {
        assertTrue(ForbidWins.whenMatches(o("verb", ""), READ));
        assertTrue(ForbidWins.whenMatches("x", READ));
        assertTrue(ForbidWins.whenMatches(o("verb", "read", "resource", "re:(a+)+"), READ));
        assertTrue(ForbidWins.whenMatches(o("verb", "read", "where", "x"), READ));
        assertTrue(ForbidWins.whenMatches(hit(), null));
        assertTrue(ForbidWins.whenMatches(hit(), o()));
        assertTrue(ForbidWins.whenMatches(hit(), o("action", "x")));
        assertTrue(ForbidWins.whenMatches(hit(), o("action", o("verb", 5L, "resource", "doc/1"))));
        assertTrue(ForbidWins.whenMatches(hit(), o("action", o("verb", "read"))));
        assertTrue(ForbidWins.whenMatches(hit(), o("action", o("verb", "read", "resource", 5L))));
        assertTrue(ForbidWins.whenMatches(hit(), o("action", o("resource", "doc/1"))));
        // a trigger without a resource still matches by verb alone, and does not by another verb
        assertTrue(ForbidWins.whenMatches(o("verb", "read"), READ));
        assertFalse(ForbidWins.whenMatches(o("verb", "zzz"), READ));
        // a context that throws when read is undecidable: the veto applies
        Map<String, Object> throwing = new HashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("boom"); }
        };
        assertTrue(ForbidWins.whenMatches(miss(), throwing));
    }

    @Test void whenMatchesOversizedRegexSubjectCountsAsMatched() {
        Map<String, Object> w = o("verb", "read", "resource", "re:b");
        assertFalse(ForbidWins.whenMatches(w, ctx("read", "a".repeat(512))));
        assertTrue(ForbidWins.whenMatches(w, ctx("read", "a".repeat(513))));
        assertTrue(ForbidWins.whenMatches(w, ctx("read", "a".repeat(2000))));
        // the same long subject against a literal pattern is an ordinary mismatch
        assertFalse(ForbidWins.whenMatches(o("verb", "read", "resource", "b"), ctx("read", "a".repeat(513))));
        assertFalse(ForbidWins.whenMatches(o("verb", "read", "resource", "b*"), ctx("read", "a".repeat(513))));
        // an oversized subject still honours a cleanly false where
        assertFalse(ForbidWins.whenMatches(o("verb", "read", "resource", "re:b", "where", List.<Object>of(o("field", "action.verb", "op", "ne", "value", "read"))), ctx("read", "a".repeat(513))));
        // a trigger that names no resource has no oversize case: a wrong verb is a plain mismatch
        assertFalse(ForbidWins.whenMatches(o("verb", "zzz"), ctx("read", "a".repeat(513))));
    }

    @Test void whenMatchesTreatsARefusedRegexAsMatchedButNotAPlainMismatch() {
        // a fresh open budget: an ordinary regex mismatch stays a mismatch
        assertFalse(inBudget(() -> ForbidWins.whenMatches(o("verb", "read", "resource", "re:b"), ctx("read", "a"))));
        // exhausted budget: a regex that could not be evaluated is undecidable, so the veto applies
        assertTrue(inBudget(() -> {
            for (int i = 0; i < 70; i++) SafeRegex.charge("a", 1);
            assertTrue(SafeRegex.refusals() > 0);
            return ForbidWins.whenMatches(o("verb", "read", "resource", "re:a"), ctx("read", "a"));
        }));
        // ... and a refusal followed by a where that is cleanly false still clears it
        assertFalse(inBudget(() -> {
            for (int i = 0; i < 70; i++) SafeRegex.charge("a", 1);
            return ForbidWins.whenMatches(o("verb", "read", "resource", "re:a", "where", List.<Object>of(o("field", "action.verb", "op", "ne", "value", "read"))), ctx("read", "a"));
        }));
        // earlier refusals in the document do not turn a later plain mismatch into a match
        assertFalse(inBudget(() -> {
            for (int i = 0; i < 70; i++) SafeRegex.charge("a", 1);
            return ForbidWins.whenMatches(o("verb", "write"), ctx("read", "a"));
        }));
        assertFalse(inBudget(() -> {
            for (int i = 0; i < 70; i++) SafeRegex.charge("a", 1);
            return ForbidWins.whenMatches(o("verb", "read", "resource", "other"), ctx("read", "a"));
        }));
    }

    static boolean inBudget(java.util.function.Supplier<Boolean> s) { return SafeRegex.withBudget(s); }

    // ---- decide

    static ForbidWins.Decision decide(Object clauses, Map<String, Object> c, List<String> prec, List<String> permitSigners) {
        return ForbidWins.decide(clauses, c, prec, permitSigners);
    }

    static void assertMalformed(ForbidWins.Decision d) {
        assertNotNull(d);
        assertEquals("deny", d.decision);
        assertEquals("malformed", d.winnerKind);
        assertNull(d.winnerId);
        assertTrue(d.shadowed.isEmpty());
        assertTrue(d.values.isEmpty());
    }

    @Test void decideRefusesMalformedClausesAndContexts() {
        List<Object> ok = list(clause("p", "permit", null, hit()));
        assertMalformed(decide("x", READ, null, null));
        assertMalformed(decide(list(clause("p", "weird", null, hit())), READ, null, null));
        assertMalformed(decide(ok, null, null, null));
        assertMalformed(decide(ok, o(), null, null));
        assertMalformed(decide(ok, o("action", "x"), null, null));
        assertMalformed(decide(ok, o("action", o("verb", 5L, "resource", "doc/1")), null, null));
        assertMalformed(decide(ok, o("action", o("resource", "doc/1")), null, null));
        assertMalformed(decide(ok, o("action", o("verb", "read", "resource", 5L)), null, null));
        assertMalformed(decide(ok, o("action", o("verb", "read")), null, null));
        assertEquals("allow", decide(ok, READ, null, null).decision);
    }

    @Test void decideFallsBackToMalformedWhenEvaluationThrows() {
        List<Object> clauses = list(clause("p", "permit", "s1", hit()));
        List<String> throwing = new ArrayList<String>() {
            @Override public boolean contains(Object x) { throw new IllegalStateException("boom"); }
        };
        assertMalformed(decide(clauses, READ, null, throwing));
    }

    @Test void decideValuesForEachKind() {
        List<Object> clauses = list(
            clause("p1", "permit", null, hit()), clause("p2", "permit", null, miss()),
            clause("f1", "forbid", null, hit()), clause("f2", "forbid", null, miss()), clause("f3", "forbid", null, unknownWhen()),
            clause("e1", "escalate", null, hit()), clause("e2", "escalate", null, miss()), clause("e3", "escalate", null, unknownWhen()));
        ForbidWins.Decision d = decide(clauses, READ, null, null);
        String[] want = {"true", "false", "true", "false", "unknown", "true", "false", "unknown"};
        String[] ids = {"p1", "p2", "f1", "f2", "f3", "e1", "e2", "e3"};
        String[] kinds = {"permit", "permit", "forbid", "forbid", "forbid", "escalate", "escalate", "escalate"};
        assertEquals(8, d.values.size());
        for (int i = 0; i < 8; i++) {
            assertEquals(ids[i], d.values.get(i).get("id"));
            assertEquals(kinds[i], d.values.get(i).get("kind"));
            assertEquals(want[i], d.values.get(i).get("value"), ids[i]);
            assertEquals(3, d.values.get(i).size());
        }
        assertEquals("deny", d.decision);
        assertEquals("forbid", d.winnerKind);
        assertEquals("f1", d.winnerId);
        assertEquals(List.of("f3", "p1", "e1", "e3"), d.shadowed);
    }

    @Test void decideOutcomes() {
        // allow: the first matching permit wins; the rest are shadowed in forbid, permit, escalate order
        ForbidWins.Decision d = decide(list(clause("p1", "permit", null, hit()), clause("p2", "permit", null, hit()), clause("e", "escalate", null, miss())), READ, null, null);
        assertEquals("allow", d.decision); assertEquals("permit", d.winnerKind); assertEquals("p1", d.winnerId);
        assertEquals(List.of("p2"), d.shadowed);
        // escalate
        d = decide(list(clause("p1", "permit", null, hit()), clause("e1", "escalate", null, hit()), clause("e2", "escalate", null, hit())), READ, null, null);
        assertEquals("escalate", d.decision); assertEquals("escalate", d.winnerKind); assertEquals("e1", d.winnerId);
        assertEquals(List.of("p1", "e2"), d.shadowed);
        // a forbid beats a permit and an escalate
        d = decide(list(clause("p1", "permit", null, hit()), clause("e1", "escalate", null, hit()), clause("f1", "forbid", null, hit())), READ, null, null);
        assertEquals("deny", d.decision); assertEquals("forbid", d.winnerKind); assertEquals("f1", d.winnerId);
        assertEquals(List.of("p1", "e1"), d.shadowed);
        // no permit: deny with no winner; the matched escalates are still listed as shadowed
        d = decide(list(clause("p1", "permit", null, miss()), clause("e1", "escalate", null, hit())), READ, null, null);
        assertEquals("deny", d.decision); assertEquals("none", d.winnerKind); assertNull(d.winnerId);
        assertEquals(List.of("e1"), d.shadowed);
        d = decide(list(), READ, null, null);
        assertEquals("deny", d.decision); assertEquals("none", d.winnerKind); assertNull(d.winnerId);
        assertTrue(d.shadowed.isEmpty());
        // an undecidable forbid still vetoes
        d = decide(list(clause("p1", "permit", null, hit()), clause("f1", "forbid", null, unknownWhen())), READ, null, null);
        assertEquals("deny", d.decision); assertEquals("f1", d.winnerId);
    }

    @Test void decideForbidWinnerOrderIsPrecedenceThenId() {
        List<String> prec = List.of("s1", "s2");
        // same rank: the smaller id wins, whatever the clause order
        ForbidWins.Decision d = decide(list(clause("b", "forbid", null, hit()), clause("a", "forbid", null, hit())), READ, prec, null);
        assertEquals("a", d.winnerId); assertEquals(List.of("b"), d.shadowed);
        d = decide(list(clause("a", "forbid", null, hit()), clause("b", "forbid", null, hit())), READ, prec, null);
        assertEquals("a", d.winnerId);
        d = decide(list(clause("b", "forbid", "s1", hit()), clause("a", "forbid", "s1", hit())), READ, null, null);
        assertEquals("a", d.winnerId);
        // a more authoritative signer wins over a smaller id
        d = decide(list(clause("a", "forbid", "s2", hit()), clause("b", "forbid", "s1", hit())), READ, prec, null);
        assertEquals("b", d.winnerId); assertEquals(List.of("a"), d.shadowed);
        // no precedence at all: every signer ranks alike, so the id decides
        d = decide(list(clause("a", "forbid", "s2", hit()), clause("b", "forbid", "s1", hit())), READ, null, null);
        assertEquals("a", d.winnerId);
        // an unsigned or unlisted signer ranks below every listed one
        d = decide(list(clause("a", "forbid", null, hit()), clause("z", "forbid", "s1", hit())), READ, List.of("s1"), null);
        assertEquals("z", d.winnerId);
        d = decide(list(clause("a", "forbid", "other", hit()), clause("z", "forbid", "s1", hit())), READ, List.of("s1"), null);
        assertEquals("z", d.winnerId);
        d = decide(list(clause("z", "forbid", null, hit()), clause("a", "forbid", "s1", hit())), READ, List.of("s1"), null);
        assertEquals("a", d.winnerId);
        // unsigned and unlisted tie, and the id decides
        d = decide(list(clause("b", "forbid", null, hit()), clause("a", "forbid", "other", hit())), READ, List.of("s1"), null);
        assertEquals("a", d.winnerId);
        d = decide(list(clause("b", "forbid", "other", hit()), clause("a", "forbid", null, hit())), READ, List.of("s1"), null);
        assertEquals("a", d.winnerId);
    }

    @Test void decidePermitSignersDropOtherSignersPermits() {
        List<String> only = List.of("s1");
        // a listed signer's permit counts
        ForbidWins.Decision d = decide(list(clause("p", "permit", "s1", hit())), READ, null, only);
        assertEquals("allow", d.decision);
        assertEquals("true", d.values.get(0).get("value"));
        // another signer's permit, and an unsigned one, are dropped
        d = decide(list(clause("p", "permit", "s2", hit())), READ, null, only);
        assertEquals("deny", d.decision); assertEquals("none", d.winnerKind);
        assertEquals("false", d.values.get(0).get("value"));
        d = decide(list(clause("p", "permit", null, hit())), READ, null, only);
        assertEquals("deny", d.decision);
        assertEquals("false", d.values.get(0).get("value"));
        // forbid and escalate clauses are never dropped
        d = decide(list(clause("p", "permit", "s1", hit()), clause("f", "forbid", "s2", hit())), READ, null, only);
        assertEquals("deny", d.decision); assertEquals("f", d.winnerId);
        assertEquals("true", d.values.get(1).get("value"));
        d = decide(list(clause("p", "permit", "s1", hit()), clause("e", "escalate", null, hit())), READ, null, only);
        assertEquals("escalate", d.decision);
        assertEquals("true", d.values.get(1).get("value"));
        // a null list means every permit counts
        d = decide(list(clause("p", "permit", "s2", hit())), READ, null, null);
        assertEquals("allow", d.decision);
        d = decide(list(clause("p", "permit", null, hit())), READ, null, null);
        assertEquals("allow", d.decision);
        // an empty list drops them all
        d = decide(list(clause("p", "permit", "s1", hit())), READ, null, List.of());
        assertEquals("deny", d.decision);
    }

    // ---- certify

    @Test void certifyBuildsTheCanonicalCertificate() {
        List<Object> clauses = list(clause("p", "permit", "s1", hit()), clause("e", "escalate", null, hit()));
        Map<String, Object> cert = ForbidWins.certify(clauses, READ, null, null);
        assertEquals(List.of("v", "kind", "policy", "action", "decision", "winner", "shadowed", "clauses"), new ArrayList<>(cert.keySet()));
        assertEquals("1", ((Json.Num) cert.get("v")).raw);
        assertEquals("forbid-wins", cert.get("kind"));
        assertEquals(Pca.hashCanonical(clauses), cert.get("policy"));
        assertEquals(Pca.hashCanonical(READ), cert.get("action"));
        assertEquals("escalate", cert.get("decision"));
        Map<?, ?> winner = (Map<?, ?>) cert.get("winner");
        assertEquals("escalate", winner.get("kind"));
        assertEquals("e", winner.get("id"));
        assertEquals(List.of("p"), cert.get("shadowed"));
        List<?> rows = (List<?>) cert.get("clauses");
        assertEquals(2, rows.size());
        Map<?, ?> r0 = (Map<?, ?>) rows.get(0), r1 = (Map<?, ?>) rows.get(1);
        assertEquals(List.of("id", "kind", "signer", "value"), new ArrayList<>(r0.keySet()));
        assertEquals("s1", r0.get("signer"));
        assertEquals("true", r0.get("value"));
        // an unsigned clause has no signer key at all
        assertEquals(List.of("id", "kind", "value"), new ArrayList<>(r1.keySet()));
        assertFalse(r1.containsKey("signer"));
    }

    @Test void certifyAMalformedPolicyIsADenyCertificate() {
        Map<String, Object> cert = ForbidWins.certify("x", READ, null, null);
        assertEquals("deny", cert.get("decision"));
        assertEquals("malformed", ((Map<?, ?>) cert.get("winner")).get("kind"));
        assertNull(((Map<?, ?>) cert.get("winner")).get("id"));
        assertEquals(List.of(), cert.get("shadowed"));
        assertEquals(List.of(), cert.get("clauses"));
        // clauses that are not all well-formed objects with string ids do not break the id index
        List<Object> mixed = list("x", o("id", 5L), o("id", "ok", "kind", "permit", "when", hit()));
        cert = ForbidWins.certify(mixed, READ, null, null);
        assertEquals("deny", cert.get("decision"));
        assertEquals("malformed", ((Map<?, ?>) cert.get("winner")).get("kind"));
        assertEquals(List.of(), cert.get("clauses"));
        cert = ForbidWins.certify(list(o("id", "ok", "kind", "permit", "when", hit()), 7L), READ, null, null);
        assertEquals(List.of(), cert.get("clauses"));
        cert = ForbidWins.certify(list(o("kind", "permit", "when", hit())), READ, null, null);
        assertEquals(List.of(), cert.get("clauses"));
    }

    // ---- consistent / check

    static Map<String, Object> goodCert() {
        return ForbidWins.certify(list(clause("p", "permit", null, hit()), clause("e", "escalate", null, hit())), READ, null, null);
    }

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object x) { return (Map<String, Object>) x; }
    @SuppressWarnings("unchecked") static List<Object> l(Object x) { return (List<Object>) x; }

    @Test void consistentAcceptsTheCertificatesCertifyBuilds() {
        assertTrue(ForbidWins.consistent(goodCert(), null));
        assertTrue(ForbidWins.consistent(ForbidWins.certify("x", READ, null, null), null));
        assertTrue(ForbidWins.consistent(ForbidWins.certify(list(clause("p", "permit", null, miss())), READ, null, null), null));
        assertTrue(ForbidWins.consistent(ForbidWins.certify(list(clause("p", "permit", null, hit())), READ, null, null), null));
        Map<String, Object> longV = goodCert();
        longV.put("v", 1L);
        assertTrue(ForbidWins.consistent(longV, null));
    }

    @Test void consistentRefusesAStructurallyBrokenCertificate() {
        assertFalse(ForbidWins.consistent(null, null));
        assertFalse(ForbidWins.consistent("x", null));
        assertFalse(ForbidWins.consistent(List.of(), null));
        Map<String, Object> c = goodCert();
        c.put("v", IntentJs.ofLong(2));
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); c.put("v", new Json.Num("1.5"));
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); c.put("v", "1");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); c.remove("v");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); c.put("kind", "other");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); c.remove("kind");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); c.remove("clauses");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); c.put("clauses", "x");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); l(c.get("clauses")).add("x");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); l(c.get("clauses")).add(null);
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); c.remove("winner");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); c.put("winner", "x");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); c.remove("shadowed");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); c.put("shadowed", "x");
        assertFalse(ForbidWins.consistent(c, null));
    }

    @Test void consistentChecksEachRowOfTheTable() {
        Map<String, Object> c = goodCert();
        m(l(c.get("clauses")).get(0)).put("kind", "weird");
        assertFalse(ForbidWins.consistent(c, null));
        // an unknown kind would otherwise read as an escalate and make this table entail its own decision
        c = ForbidWins.certify(list(clause("p", "permit", null, hit())), READ, null, null);
        l(c.get("clauses")).add(o("id", "x", "kind", "weird", "value", "true"));
        c.put("decision", "escalate");
        m(c.get("winner")).put("kind", "escalate");
        m(c.get("winner")).put("id", "x");
        c.put("shadowed", list("p"));
        assertFalse(ForbidWins.consistent(c, null));
        // a missing or unknown row value
        c = ForbidWins.certify(list(clause("p", "permit", null, hit())), READ, null, null);
        m(l(c.get("clauses")).get(0)).remove("value");
        assertFalse(ForbidWins.consistent(c, null));
        c = ForbidWins.certify(list(clause("p", "permit", null, hit())), READ, null, null);
        m(l(c.get("clauses")).get(0)).put("value", "maybe");
        assertFalse(ForbidWins.consistent(c, null));
        c = ForbidWins.certify(list(clause("p", "permit", null, hit())), READ, null, null);
        m(l(c.get("clauses")).get(0)).put("value", 5L);
        assertFalse(ForbidWins.consistent(c, null));
        // a row without a kind
        c = ForbidWins.certify(list(clause("p", "permit", null, hit())), READ, null, null);
        m(l(c.get("clauses")).get(0)).remove("kind");
        assertFalse(ForbidWins.consistent(c, null));
        // an unknown (not false) row value counts as a hit
        c = ForbidWins.certify(list(clause("p", "permit", null, hit()), clause("f", "forbid", null, unknownWhen())), READ, null, null);
        assertTrue(ForbidWins.consistent(c, null));
    }

    @Test void consistentChecksDecisionWinnerAndShadowedAgainstTheTable() {
        Map<String, Object> c = goodCert();
        c.put("decision", "allow");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); c.remove("decision");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); m(c.get("winner")).put("kind", "permit");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); m(c.get("winner")).remove("kind");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); m(c.get("winner")).put("id", "p");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); m(c.get("winner")).remove("id");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); l(c.get("shadowed")).add("zz");
        assertFalse(ForbidWins.consistent(c, null));
        c = goodCert(); l(c.get("shadowed")).clear();
        assertFalse(ForbidWins.consistent(c, null));
        // shadowed order is part of the entailment
        c = ForbidWins.certify(list(clause("p", "permit", null, hit()), clause("e1", "escalate", null, hit()), clause("e2", "escalate", null, hit())), READ, null, null);
        assertTrue(ForbidWins.consistent(c, null));
        c.put("shadowed", list("e2", "p"));
        assertFalse(ForbidWins.consistent(c, null));
        // a deny with no permit has no winner id
        c = ForbidWins.certify(list(clause("p", "permit", null, miss())), READ, null, null);
        m(c.get("winner")).put("id", "p");
        assertFalse(ForbidWins.consistent(c, null));
        c = ForbidWins.certify(list(clause("p", "permit", null, miss())), READ, null, null);
        c.put("decision", "allow");
        assertFalse(ForbidWins.consistent(c, null));
    }

    @Test void consistentMalformedCertificateMustBeEmptyDenyWithNoWinner() {
        Map<String, Object> base = ForbidWins.certify("x", READ, null, null);
        assertTrue(ForbidWins.consistent(base, null));
        Map<String, Object> c = ForbidWins.certify("x", READ, null, null);
        l(c.get("clauses")).add(o("id", "p", "kind", "permit", "value", "true"));
        assertFalse(ForbidWins.consistent(c, null));
        c = ForbidWins.certify("x", READ, null, null); c.put("decision", "allow");
        assertFalse(ForbidWins.consistent(c, null));
        c = ForbidWins.certify("x", READ, null, null); c.remove("decision");
        assertFalse(ForbidWins.consistent(c, null));
        c = ForbidWins.certify("x", READ, null, null); m(c.get("winner")).put("id", "p");
        assertFalse(ForbidWins.consistent(c, null));
        c = ForbidWins.certify("x", READ, null, null); c.remove("shadowed");
        assertFalse(ForbidWins.consistent(c, null));
        c = ForbidWins.certify("x", READ, null, null); l(c.get("shadowed")).add("p");
        assertFalse(ForbidWins.consistent(c, null));
        c = ForbidWins.certify("x", READ, null, null); c.put("shadowed", "x");
        assertFalse(ForbidWins.consistent(c, null));
        // a winner that is not an object is not the malformed form
        c = ForbidWins.certify("x", READ, null, null); c.put("winner", "malformed");
        assertFalse(ForbidWins.consistent(c, null));
    }

    @Test void consistentOrdersForbidsByPrecedenceThenId() {
        List<Object> twoSame = list(clause("b", "forbid", "s1", hit()), clause("a", "forbid", "s1", hit()));
        assertTrue(ForbidWins.consistent(ForbidWins.certify(twoSame, READ, List.of("s1"), null), List.of("s1")));
        Map<String, Object> c = ForbidWins.certify(twoSame, READ, List.of("s1"), null);
        m(c.get("winner")).put("id", "b");
        c.put("shadowed", list("a"));
        assertFalse(ForbidWins.consistent(c, List.of("s1")));
        // the more authoritative signer wins over the smaller id, and only when the precedence says so
        List<Object> two = list(clause("a", "forbid", "s2", hit()), clause("b", "forbid", "s1", hit()));
        Map<String, Object> withPrec = ForbidWins.certify(two, READ, List.of("s1", "s2"), null);
        assertEquals("b", m(withPrec.get("winner")).get("id"));
        assertTrue(ForbidWins.consistent(withPrec, List.of("s1", "s2")));
        assertFalse(ForbidWins.consistent(withPrec, null));
        assertFalse(ForbidWins.consistent(withPrec, List.of("s2", "s1")));
        // an unsigned forbid ranks below a listed signer (an immutable precedence list must not be asked about null)
        List<Object> mixed = list(clause("a", "forbid", null, hit()), clause("z", "forbid", "s1", hit()));
        Map<String, Object> mixedCert = ForbidWins.certify(mixed, READ, List.of("s1"), null);
        assertEquals("z", m(mixedCert.get("winner")).get("id"));
        assertTrue(ForbidWins.consistent(mixedCert, List.of("s1")));
        mixed = list(clause("z", "forbid", null, hit()), clause("a", "forbid", "other", hit()));
        mixedCert = ForbidWins.certify(mixed, READ, List.of("s1"), null);
        assertEquals("a", m(mixedCert.get("winner")).get("id"));
        assertTrue(ForbidWins.consistent(mixedCert, List.of("s1")));
        mixed = list(clause("z", "forbid", "s1", hit()), clause("a", "forbid", null, hit()));
        mixedCert = ForbidWins.certify(mixed, READ, List.of("s1"), null);
        assertEquals("z", m(mixedCert.get("winner")).get("id"));
        assertTrue(ForbidWins.consistent(mixedCert, List.of("s1")));
        // the rank of a signer that is not in the list equals the list size, not zero or minus one
        mixed = list(clause("a", "forbid", "other", hit()), clause("z", "forbid", "s1", hit()));
        mixedCert = ForbidWins.certify(mixed, READ, List.of("s1"), null);
        assertTrue(ForbidWins.consistent(mixedCert, List.of("s1")));
        m(mixedCert.get("winner")).put("id", "a");
        mixedCert.put("shadowed", list("z"));
        assertFalse(ForbidWins.consistent(mixedCert, List.of("s1")));
    }

    @Test void consistentIsFalseWhenTheTableCannotBeRead() {
        Map<String, Object> c = o("v", IntentJs.ofLong(1), "kind", "forbid-wins", "decision", "deny",
            "winner", o("kind", "forbid", "id", "a"), "shadowed", list("b"));
        c.put("clauses", list(o("id", "a", "kind", "forbid", "signer", 5L, "value", "true"), o("id", "b", "kind", "forbid", "signer", 5L, "value", "true")));
        assertFalse(ForbidWins.consistent(c, null));
        c.put("clauses", list(o("id", "a", "kind", "forbid", "signer", "s", "value", "true"), o("id", 7L, "kind", "forbid", "signer", "s", "value", "true")));
        assertFalse(ForbidWins.consistent(c, null));
    }

    @Test void checkNamesEachRefusal() {
        List<Object> clauses = list(clause("p", "permit", null, hit()), clause("e", "escalate", null, hit()));
        Map<String, Object> cert = ForbidWins.certify(clauses, READ, null, null);
        assertNull(ForbidWins.check(cert, clauses, READ, null, null));
        assertEquals("malformed clauses", ForbidWins.check(cert, "x", READ, null, null));
        Map<String, Object> broken = ForbidWins.certify(clauses, READ, null, null);
        broken.put("decision", "allow");
        assertEquals("certificate table does not entail its decision", ForbidWins.check(broken, clauses, READ, null, null));
        Map<String, Object> other = ForbidWins.certify(clauses, ctx("read", "doc/2"), null, null);
        assertTrue(ForbidWins.consistent(other, null));
        assertEquals("certificate does not match the recomputed decision", ForbidWins.check(other, clauses, READ, null, null));
        Map<String, Object> odd = ForbidWins.certify(clauses, READ, null, null);
        odd.put("extra", new Object());
        assertEquals("certificate check error (fail closed)", ForbidWins.check(odd, clauses, READ, null, null));
    }
}
