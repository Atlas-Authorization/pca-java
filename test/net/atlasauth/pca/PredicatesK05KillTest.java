package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;

import org.junit.jupiter.api.Test;

/** Predicates: membership closure over an immutable adjacency, guard order in the reason builders, and the shown operands. */
public class PredicatesK05KillTest {
    static Object j(String text) { return Json.parseLenient(text); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> ctx(String text) { return (Map<String, Object>) j(text); }

    static final Map<String, Object> CTX = ctx("{\"action\":{\"verb\":\"pay\",\"resource\":\"acct/1\",\"params\":{\"amount\":500}}}");

    @Test void membershipClosureStopsWhenTheQueueIsEmpty() {
        // an immutable caller-built adjacency (Map.of refuses a null key): the walk never asks for a node past the queue
        Map<String, Object> c = Map.of("subject", Map.of("user", "alice", "groups", Map.of("alice", "staff", "staff", "all")));
        Object cond = j("{\"field\":\"subject.user\",\"op\":\"member_of\",\"collection\":\"subject.groups\",\"value\":\"all\"}");
        assertEquals(Predicates.Tri.TRUE, Predicates.evaluateConditionTri(cond, c));
        Object miss = j("{\"field\":\"subject.user\",\"op\":\"member_of\",\"collection\":\"subject.groups\",\"value\":\"root\"}");
        assertEquals(Predicates.Tri.FALSE, Predicates.evaluateConditionTri(miss, c));
    }

    @Test void aMalformedPredicateDoesNotHideALaterOne() {
        Object preds = j("[{\"verb\":\"pay\",\"resource\":5},{\"verb\":\"pay\",\"resource\":\"acct/1\"}]");
        assertTrue(Predicates.evaluatePredicates(preds, CTX));
        assertFalse(Predicates.evaluatePredicates(j("[]"), CTX));
        assertFalse(Predicates.evaluatePredicates(j("{}"), CTX));
    }

    @Test void firstUnmetLimitSkipsWhatIsOutOfScopeOrMalformed() {
        String limit = "[\"x\",{\"verb\":\"pay\",\"resource\":5,\"where\":[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":1}]},"
            + "{\"verb\":\"pay\",\"resource\":\"acct/1\"},"
            + "{\"verb\":\"pay\",\"resource\":\"acct/1\",\"where\":5},"
            + "{\"verb\":\"pay\",\"resource\":\"acct/1\",\"where\":[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":100}]}]";
        assertEquals("amount <= 100", Predicates.firstUnmetLimit(j(limit), CTX));
        assertNull(Predicates.firstUnmetLimit(j("[{\"verb\":\"other\"}]"), CTX));
        assertNull(Predicates.firstUnmetLimit(j("{}"), CTX));
        assertNull(Predicates.firstUnmetLimit(j("[]"), ctx("{\"action\":5}")));
        assertNull(Predicates.firstUnmetLimit(j("[{\"verb\":\"pay\"}]"), ctx("{\"action\":{\"verb\":5,\"resource\":\"r\"}}")));
        assertNull(Predicates.firstUnmetLimit(j("[{\"verb\":\"pay\"}]"), ctx("{\"action\":{\"verb\":\"pay\",\"resource\":5}}")));
        // an absent verb or resource is no action in scope, even for a predicate that matches any verb or resource
        String unmet = "[{\"verb\":\"*\",\"where\":[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":1}]}]";
        assertNull(Predicates.firstUnmetLimit(j(unmet), ctx("{\"action\":{\"resource\":\"acct/1\",\"params\":{\"amount\":5}}}")));
        assertNull(Predicates.firstUnmetLimit(j(unmet), ctx("{\"action\":{\"verb\":\"pay\",\"params\":{\"amount\":5}}}")));
        assertEquals("amount <= 1", Predicates.firstUnmetLimit(j(unmet), ctx("{\"action\":{\"verb\":\"pay\",\"resource\":\"acct/1\",\"params\":{\"amount\":5}}}")));
    }

    @Test void firstUnmetLimitAnswersNullWhenTheContextThrows() {
        // an evaluation error is "no limit to describe" (null), never an empty description
        Map<String, Object> boom = new java.util.HashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("boom"); }
        };
        assertNull(Predicates.firstUnmetLimit(j("[]"), boom));
    }

    @Test void denialReasons() {
        assertEquals("envelope grants no predicates", Predicates.denialReason(j("[]"), CTX));
        assertEquals("envelope grants no predicates", Predicates.denialReason(j("\"x\""), CTX));
        assertEquals("no predicate permits pay on acct/1", Predicates.denialReason(j("[{\"verb\":\"get\"}]"), CTX));
        // no action at all: still a reason, never an exception
        assertEquals("no predicate permits undefined on undefined", Predicates.denialReason(j("[{\"verb\":\"get\"}]"), ctx("{}")));
        assertEquals("no predicate permits undefined on undefined", Predicates.denialReason(j("[{\"verb\":\"get\"}]"), ctx("{\"action\":5}")));
    }

    @Test void shownValues() {
        assertEquals("5", Predicates.showValue(new Json.Num("5"), 0));
        assertEquals("5", Predicates.showValue(5L, 0));
        assertEquals("5", Predicates.showValue(5, 0));
        assertEquals("<number>", Predicates.showValue(new Json.Num("1.5"), 0));
        String s64 = "a".repeat(64);
        assertEquals("\"" + s64 + "\"", Predicates.showValue(s64, 0));
        assertEquals("\"...\"", Predicates.showValue(s64 + "a", 0));
        assertEquals("\"...\"", Predicates.showValue("\"ab", 0));
        assertEquals("\"a b\"", Predicates.showValue("a b", 0));
        assertEquals("\"a!b\"", Predicates.showValue("a!b", 0));
        assertEquals("\"...\"", Predicates.showValue("a\u001fb", 0));
        assertEquals("\"...\"", Predicates.showValue("\ud800", 0));
        assertEquals("\"...\"", Predicates.showValue("\udfff", 0));
        assertEquals("\"퟿\"", Predicates.showValue("퟿", 0));
        assertEquals("\"\"", Predicates.showValue("", 0));
    }

    @Test void describedConditions() {
        assertEquals("not (not ((...)))", Predicates.describeCondition(j("{\"not\":{\"not\":{\"not\":{\"field\":\"a\",\"op\":\"eq\",\"value\":1}}}}"), 0));
        assertEquals("<condition>", Predicates.describeCondition(j("{\"all_of\":5}"), 0));
        assertEquals("a <condition>", Predicates.describeCondition(j("{\"field\":\"a\",\"op\":5,\"value\":1}"), 0));
        assertEquals("a <condition>", Predicates.describeCondition(j("{\"field\":\"a\",\"value\":1}"), 0));
    }
}
