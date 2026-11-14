package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Exact-outcome tests of the goal helpers (canonical form, meet, pep, units, polarity, commit, claim, decide). */
public class GoalKillTest {
    @SuppressWarnings("unchecked")
    private static Map<String, Object> j(String s) { return (Map<String, Object>) Json.parseLenient(s); }

    @Test void canonSortsKeysByUtf8BytesNotUtf16() {
        // U+FF5E (EF BD 9E in UTF-8) sorts before the emoji (F0 9F ..) by bytes, but after its high surrogate in UTF-16
        Map<String, Object> m = j("{\"😀\":1,\"～\":2,\"b\":3,\"a\":4}");
        assertEquals("{\"a\":4,\"b\":3,\"～\":2,\"😀\":1}", GoalSemantics.canon(m));
    }

    @Test void canonEscapesAndLiterals() {
        assertEquals("\"\\b\\t\\n\\f\\r\\u0001\\\"\\\\\"", GoalSemantics.canon("\b\t\n\f\r\u0001\"\\"));
        assertEquals("\"é\u007f\"", GoalSemantics.canon("é\u007f"));
        assertEquals("[null,true,false,-5,{}]", GoalSemantics.canon(Json.parseLenient("[null,true,false,-5,{}]")));
    }

    @Test void goalDigestIsPrefixedHash() throws Exception {
        String want = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest("{\"d\":\"atlas-pca/goal-ir/v1\",\"goal\":{\"a\":1}}".getBytes(StandardCharsets.UTF_8)));
        assertEquals(want, GoalSemantics.goalDigest(j("{\"a\":1}")));
    }

    @Test void meetIsTheMinimum() {
        assertEquals("escalate", GoalSemantics.meet("allow", "escalate"));
        assertEquals("deny", GoalSemantics.meet("allow", "deny"));
        assertEquals("deny", GoalSemantics.meet("escalate", "deny"));
        assertEquals("escalate", GoalSemantics.meet("escalate", "allow"));
        assertEquals("allow", GoalSemantics.meet("allow", "ok"));
        assertEquals("deny", GoalSemantics.meet("deny", "allow"));
    }

    @Test void pepNeverUpgradesDenyAndNeedsABoundAnswer() {
        Map<String, Object> ctx = j("{\"policy_digest\":\"p\",\"action_digest\":\"a\",\"history_head\":\"h\"}");
        Map<String, Object> ok = j("{\"valid\":true,\"policy_digest\":\"p\",\"action_digest\":\"a\",\"history_head\":\"h\"}");
        assertTrue(GoalSemantics.pep("allow", ctx, null));
        assertFalse(GoalSemantics.pep("deny", ctx, ok));
        assertTrue(GoalSemantics.pep("escalate", ctx, ok));
        assertFalse(GoalSemantics.pep("escalate", ctx, null));
        assertFalse(GoalSemantics.pep("escalate", ctx, j("{}")));
        assertFalse(GoalSemantics.pep("escalate", ctx, j("{\"valid\":false,\"policy_digest\":\"p\",\"action_digest\":\"a\",\"history_head\":\"h\"}")));
        for (String k : new String[] {"policy_digest", "action_digest", "history_head"}) {
            Map<String, Object> bad = j("{\"valid\":true,\"policy_digest\":\"p\",\"action_digest\":\"a\",\"history_head\":\"h\"}");
            bad.put(k, "other");
            assertFalse(GoalSemantics.pep("escalate", ctx, bad), k);
        }
    }

    @Test void unitsListsMissingAndDifferingTagsSorted() {
        Map<String, Object> schema = j("{\"a\":{\"u\":1},\"c\":{\"u\":3}}");
        Map<String, Object> terms = j("{\"b\":{\"u\":2},\"a\":{\"u\":9},\"c\":{\"u\":3}}");
        assertEquals(List.of("a", "b"), GoalSemantics.units(schema, terms));
        assertEquals(List.of(), GoalSemantics.units(schema, j("{\"c\":{\"u\":3}}")));
    }

    @Test void polarityFindsModelPathsThroughConnectives() {
        Map<String, Object> c = j("{\"k\":\"not\",\"c\":{\"k\":\"and\",\"a\":{\"k\":\"cmp\",\"op\":\"eq\",\"l\":{\"k\":\"param\",\"path\":\"env.prov.x\"},\"r\":{\"k\":\"param\",\"path\":\"amount\"}},"
            + "\"b\":{\"k\":\"or\",\"a\":{\"k\":\"cmp\",\"op\":\"eq\",\"l\":{\"k\":\"param\",\"path\":\"amount\"},\"r\":{\"k\":\"param\",\"path\":\"env.class.y\"}},\"b\":{\"k\":\"cmp\",\"op\":\"eq\",\"l\":{\"k\":\"param\",\"path\":\"env.classy\"},\"r\":{\"k\":\"param\",\"path\":\"env.world.z\"}}}}}");
        assertEquals(List.of("env.class.y", "env.prov.x", "env.world.z"), GoalSemantics.polarity(List.of(c)));
    }

    @Test void commitBindsAllThreeParts() throws Exception {
        String want = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest("pca-goal:v3:commit:g:p:s".getBytes(StandardCharsets.UTF_8)));
        assertEquals(want, GoalSemantics.commit("g", "p", "s"));
        assertNotEquals(want, GoalSemantics.commit("g", "p", "t"));
        assertNotEquals(want, GoalSemantics.commit("h", "p", "s"));
        assertNotEquals(want, GoalSemantics.commit("g", "q", "s"));
    }

    @Test void claimCapsAtEscalateOnlyBelowTheMinimum() {
        BigInteger min = BigInteger.valueOf(900000);
        assertEquals("escalate", GoalSemantics.claim("allow", min, BigInteger.valueOf(899999)));
        assertEquals("allow", GoalSemantics.claim("allow", min, min));
        assertEquals("allow", GoalSemantics.claim("allow", min, null));
        assertEquals("deny", GoalSemantics.claim("deny", min, BigInteger.ZERO));
        assertEquals("escalate", GoalSemantics.claim("escalate", min, BigInteger.ZERO));
    }

    private static final String ONT = "{\"verbs\":[{\"verb\":\"pay\",\"cls\":\"financial_out\",\"params\":[]}],\"rels\":[]}";

    private static String goal(String extra) {
        return "{\"v\":1,\"principal\":\"p\",\"grants\":[{\"gid\":\"g1\",\"verb\":\"pay\",\"res\":{\"k\":\"any\"},\"cond\":{\"k\":\"true\"}}],\"prohibits\":[],\"bounds\":[],"
            + "\"validity\":{\"notBefore\":0,\"notAfter\":1000,\"maxIdle\":0},\"deleg\":{\"maxDepth\":0,\"narrowOnly\":true,\"mayTouch\":[]},\"escalateOn\":[],\"holes\":[]" + extra + "}";
    }

    private static Map<String, Object> act(long t, int depth) {
        return j("{\"verb\":\"pay\",\"res\":\"x\",\"params\":{},\"t\":" + t + ",\"sess\":\"s\",\"prin\":\"p\",\"org\":\"o\",\"agent\":\"a\",\"depth\":" + depth + "}");
    }

    private static final String NOHIST = "{\"adms\":[],\"last\":-1,\"aggs\":{}}";

    private static String d(String goalJson, Map<String, Object> a, String hist) {
        return (String) GoalSemantics.decide(j(goalJson), j(ONT), a, j(hist)).get("decision");
    }

    @Test void decideAllowCarriesTheWitness() {
        Map<String, Object> v = GoalSemantics.decide(j(goal("")), j(ONT), act(5, 0), j(NOHIST));
        assertEquals("{\"decision\":\"allow\",\"witness\":{\"bids\":[],\"gid\":\"g1\"}}", GoalSemantics.canon(v));
    }

    @Test void decideValidityDelegationAndHoles() {
        assertEquals("deny", d(goal(""), act(1001, 0), NOHIST));
        assertEquals("allow", d(goal(""), act(1000, 0), NOHIST));
        assertEquals("deny", d(goal(""), act(5, 1), NOHIST));
        assertNull(GoalSemantics.decide(j(goal("")), j(ONT), act(5, 1), j(NOHIST)).get("witness"));
        String hole = goal("").replace("\"holes\":[]", "\"holes\":[{\"hid\":\"h\",\"q\":\"?\",\"domain\":[],\"affects\":[\"g1\"],\"global\":false}]");
        assertEquals("deny", d(hole, act(5, 0), NOHIST));
    }

    @Test void decideEscalatesOnAnUnknownEscalateCondition() {
        String esc = goal("").replace("\"escalateOn\":[]", "\"escalateOn\":[{\"k\":\"cmp\",\"op\":\"eq\",\"l\":{\"k\":\"param\",\"path\":\"missing\"},\"r\":{\"k\":\"param\",\"path\":\"missing\"}}]");
        assertEquals("escalate", d(esc, act(5, 0), NOHIST));
    }

    @Test void decideCountBoundDenyVersusEscalate() {
        String bound = "\"bounds\":[{\"bid\":\"b1\",\"sel\":{\"k\":\"gids\",\"gids\":[\"g1\"]},\"agg\":\"count\",\"value\":null,\"key\":\"\",\"window\":{\"k\":\"sliding\",\"ms\":1000},"
            + "\"scope\":{\"k\":\"principal\"},\"cap\":{\"n\":1},\"onExceed\":\"ON\"}]";
        String hist = "{\"adms\":[{\"gid\":\"g1\",\"act\":" + "{\"verb\":\"pay\",\"res\":\"x\",\"params\":{},\"t\":4,\"sess\":\"s\",\"prin\":\"p\",\"org\":\"o\",\"agent\":\"a\",\"depth\":0}" + "}],\"last\":4,\"aggs\":{}}";
        String deny = goal("").replace("\"bounds\":[]", bound.replace("ON", "deny"));
        String esc = goal("").replace("\"bounds\":[]", bound.replace("ON", "escalate"));
        assertEquals("deny", d(deny, act(5, 0), hist));
        assertEquals("escalate", d(esc, act(5, 0), hist));
        assertEquals("allow", d(deny, act(5, 0), NOHIST));
        // the earlier admission (t=4) falls out of a 1 ms sliding window at t=5
        assertEquals("allow", d(deny.replace("\"ms\":1000", "\"ms\":1"), act(5, 0), hist));
    }
}
