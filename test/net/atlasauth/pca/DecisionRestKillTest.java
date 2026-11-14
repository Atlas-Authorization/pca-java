package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Exact-outcome kill tests for {@link Decision}: key order, verdict decoding, the depth cap, rule 21 / rule 20 edge texts and the catches. */
public class DecisionRestKillTest {
    static Object j(String s) { return AuthorizeFixtures.j(s); }
    static Map<String, Object> jm(String s) { return AuthorizeFixtures.jm(s); }

    static Map<String, Object> keys(String... ks) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (String k : ks) m.put(k, 1);
        return m;
    }

    @Test void jsKeysPutCanonicalIndicesFirstInNumericOrder() {
        assertEquals(List.of("zz", "4294967295"), Decision.jsKeys(keys("zz", "4294967295")));
        assertEquals(List.of("4294967294", "zz"), Decision.jsKeys(keys("zz", "4294967294")));
        assertEquals(List.of("9", "10", "x", "01"), Decision.jsKeys(keys("10", "x", "9", "01")));
        assertEquals(List.of("1", "4294967294"), Decision.jsKeys(keys("4294967294", "1")));
    }

    @Test void verdictDecodingFailsClosedAndSkipsForeignValues() {
        assertEquals("deny", Decision.decisionOf(false, null, List.of()));
        assertEquals("deny", Decision.decisionOf((Map<String, Object>) null));
        assertEquals("deny", Decision.decisionOf(jm("{'allow':false,'checks':'x','reasons':[]}")));
        assertEquals("deny", Decision.decisionOf(jm("{'allow':false}")));
        Map<String, String> c = new LinkedHashMap<>();
        c.put("c", "fail");
        assertEquals("escalate", Decision.decisionOf(false, c, Arrays.asList(null, "c: escalate: y")));
        assertEquals("escalate", Decision.decisionOf(false, c, List.of("c: escalate: a", "c: intent_required: b")));
        assertEquals("deny", Decision.decisionOf(false, c, List.of("c: escalate: a", "c: hard")));
        assertEquals("deny", Decision.decisionOf(false, c, List.of("d: escalate: a")));
        assertEquals("escalate", Decision.decisionOf(jm("{'allow':false,'checks':{'a':1,'b':'fail'},'reasons':[1,'b: escalate: z']}")));
        assertEquals("deny", Decision.decisionOf(jm("{'allow':false,'checks':{'a':1,'b':'fail'},'reasons':'b: escalate: z'}")));
    }

    static Object allOfChain(int depth, Object leaf) {
        Object c = leaf;
        for (int i = 0; i < depth; i++) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("all_of", new ArrayList<>(List.of(c)));
            c = m;
        }
        return c;
    }

    static List<Object> predicates(Object cond) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("verb", "*");
        p.put("where", new ArrayList<>(List.of(cond)));
        return new ArrayList<>(List.of(new ArrayList<>(List.of(p))));
    }

    @Test void modelPathsAreReadDownToDepthSixtyFour() {
        Object leaf = jm("{'field':'env.class.x','op':'eq','value':1}");
        assertEquals(List.of("env.class.x"), Decision.modelPathsRead(predicates(allOfChain(64, leaf)), List.of()));
        assertEquals(List.of(), Decision.modelPathsRead(predicates(allOfChain(65, leaf)), List.of()));
    }

    @Test void tightenResultsAreImmutableAndPrintExactly() {
        Map<String, Object> in = new LinkedHashMap<>();
        in.put("predicates", predicates(jm("{'field':'env.class.risk','op':'eq','value':1}")));
        in.put("polarity", "legacy");
        Decision.TightenResult r = Decision.decideTighten(in);
        assertEquals("ok", r.outcome);
        assertTrue(r.legacy);
        assertEquals(List.of("env.class.risk"), r.offending);
        assertNull(r.reason);
        assertThrows(UnsupportedOperationException.class, () -> r.offending.add("x"));
        assertEquals("TightenResult{ok, legacy=true, [env.class.risk], null}", r.toString());
        assertEquals("TightenResult{deny, legacy=false, [], model_polarity must be 'legacy' when present}", Decision.decideTighten(jm("{'polarity':'x'}")).toString());
        assertEquals("UnitsResult{false, units must be an object}", Decision.decideUnits(jm("{}")).toString());
        assertEquals("UnitsResult{true, null}", Decision.decideUnits(jm("{'units':{},'verb':'pay','verb_params':{}}")).toString());
    }

    @Test void aRuleOverAnAbsentContextIsUndecided() {
        Decision.TightenResult r = Decision.decideTighten(jm("{'tighten':[{'id':'r1','when':{'field':'env.x','op':'eq','value':1},'signal':'deny'}]}"));
        assertEquals("escalate", r.outcome);
        assertEquals("escalate: rule 'r1' could not be decided (a value it reads is missing or ill-typed)", r.reason);
        Decision.TightenResult e = Decision.decideTighten(jm("{'tighten':[{'id':'r1','when':{'field':'env.x','op':'exists','value':false},'signal':'deny','reason':'no x'}]}"));
        assertEquals("deny", e.outcome);
        assertEquals("denied by tighten rule 'r1' (no x)", e.reason);
    }

    /** A map that refuses every read: drives the fail-closed catches. */
    static Map<String, Object> refusing() {
        return new HashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("refused"); }
        };
    }

    @Test void aThrowingInputFailsClosedWithTheExceptionName() {
        Decision.TightenResult t = Decision.decideTighten(refusing());
        assertEquals("deny", t.outcome);
        assertFalse(t.legacy);
        assertEquals(List.of(), t.offending);
        assertEquals("evaluation error (fail closed): IllegalStateException", t.reason);
        Decision.UnitsResult u = Decision.decideUnits(refusing());
        assertFalse(u.ok);
        assertEquals("evaluation error (fail closed): IllegalStateException", u.reason);
    }

    static final String AMOUNT = "action.params.amount";

    /** Rule 20 over one declared parameter: the schema tag {@code schema} against the policy tag {@code policy}. */
    static Decision.UnitsResult units(String schema, String policy) {
        return Decision.decideUnits(jm("{'units':{'" + AMOUNT + "':" + policy + "},'schema_units':{'u1':" + schema + "},"
            + "'verb_params':{'" + AMOUNT + "':{'unit':'u1'}},'verb':'pay'}"));
    }

    static void confused(String schema, String policy, String schemaText, String policyText) {
        Decision.UnitsResult r = units(schema, policy);
        assertFalse(r.ok, schema);
        assertEquals("'" + AMOUNT + "' is declared as " + schemaText + " by the action schema but the policy term is tagged " + policyText + " (unit confusion)", r.reason);
    }

    static void same(String schema, String policy) {
        Decision.UnitsResult r = units(schema, policy);
        assertTrue(r.ok, schema + " " + r.reason);
        assertNull(r.reason);
    }

    @Test void unitTagsCompareMemberByMemberAsJavaScriptStrictEquality() {
        same("{'kind':'money','exponent':2}", "{'kind':'money','exponent':2}");
        same("{'kind':'money','exponent':2.0}", "{'kind':'money','exponent':2}");
        same("{'kind':'money','currency':'USD'}", "{'kind':'money','currency':'USD'}");
        same("{'kind':'count'}", "{'kind':'count'}");
        confused("{}", "{'kind':'money'}", "?", "money");
        confused("{'kind':'money'}", "{'kind':'money','currency':'USD'}", "money", "money/USD");
        confused("{'kind':'money','currency':'USD'}", "{'kind':'money'}", "money/USD", "money");
        confused("{'kind':'money','currency':null}", "{'kind':'money','currency':'USD'}", "money/null", "money/USD");
        confused("{'kind':'money','currency':'EUR'}", "{'kind':'money','currency':'USD'}", "money/EUR", "money/USD");
        confused("{'kind':'money','currency':'USD','exponent':2.5}", "{'kind':'money','currency':'USD','exponent':2}", "money/USD/e2.5", "money/USD/e2");
        confused("{'kind':'money','currency':'USD','exponent':2.0}", "{'kind':'money','currency':'USD','exponent':3}", "money/USD/e2", "money/USD/e3");
        confused("{'kind':1}", "{'kind':'1'}", "1", "1");
        confused("{'kind':'money','exponent':'2'}", "{'kind':'money','exponent':2}", "money/e2", "money/e2");
    }

    @Test void untaggedReadsAreReportedInSortedOrderAndOnlyForParamPaths() {
        // HashSet order of these two paths is b before a: the report must still name a
        Decision.UnitsResult r = Decision.decideUnits(jm("{'units':{},'schema_units':{'u':{'kind':'count'}},"
            + "'verb_params':{'action.params.a':{'unit':'u'},'action.params.b':{'unit':'u'}},'verb':'pay',"
            + "'predicates':[[{'verb':'pay','where':[{'field':'action.params.b','op':'eq','value':1},{'field':'action.params.a','op':'eq','value':1}]}]]}"));
        assertFalse(r.ok);
        assertEquals("a policy term reads 'action.params.a' (count) without a unit tag", r.reason);
        Decision.UnitsResult dotted = Decision.decideUnits(jm("{'units':{},'schema_units':{'u':{'kind':'count'}},"
            + "'verb_params':{'action.params.a.b':{'unit':'u'}},'verb':'pay',"
            + "'predicates':[[{'verb':'pay','where':[{'field':'action.params.a.b','op':'eq','value':1}]}]]}"));
        assertTrue(dotted.ok, dotted.reason);
        Decision.UnitsResult foreign = Decision.decideUnits(jm("{'units':{'" + AMOUNT + "':{'kind':'count'}},'schema_units':{'u':{'kind':'count'}},"
            + "'verb_params':{'" + AMOUNT + "':{'unit':'u'}},'verb':'pay','predicates':[['x',{'verb':'other','where':[{'field':'action.params.zz','op':'eq','value':1}]}]]}"));
        assertTrue(foreign.ok, foreign.reason);
    }

    @Test void aNonStringUnitIdNamesNoTag() {
        Map<Object, Object> su = new LinkedHashMap<>();
        su.put(1, jm("{'kind':'money'}"));
        Map<String, Object> param = new LinkedHashMap<>();
        param.put("unit", 1);
        Map<String, Object> vp = new LinkedHashMap<>();
        vp.put(AMOUNT, param);
        Map<String, Object> in = jm("{'units':{'" + AMOUNT + "':{'kind':'money'}},'verb':'pay'}");
        in.put("schema_units", su);
        in.put("verb_params", vp);
        Decision.UnitsResult r = Decision.decideUnits(in);
        assertFalse(r.ok);
        assertEquals("'" + AMOUNT + "' is declared as no unit by the action schema but the policy term is tagged money (unit confusion)", r.reason);
    }
}
