package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for Decision (reference decision.ts), ParamProvenance (label-receipts.ts), GoalSemantics (goal.ts) and the
 * RevocationStaleness policy/proof wrappers.
 */
public class K05R5G3DecisionTest {
    static Object j(String s) { return AuthorizeFixtures.j(s); }

    // ---- Decision ------------------------------------------------------------------------------------------------------

    @Test void objectKeysOrderEveryCanonicalIndexNumerically() {
        assertEquals(List.of("1", "2", "3"), Decision.jsKeys(DecisionRestKillTest.keys("1", "2", "3")));
        assertEquals(List.of("1", "2", "3"), Decision.jsKeys(DecisionRestKillTest.keys("3", "2", "1")));
        assertEquals(List.of("2", "10", "x"), Decision.jsKeys(DecisionRestKillTest.keys("x", "10", "2")));
    }

    @Test void aModelDerivedPathIsReadSegmentBySegment() {
        List<String> one = List.of("a");
        assertTrue(Decision.isModelDerivedPath("env.class.x", List.of()));
        assertTrue(Decision.isModelDerivedPath("env.world", one));
        assertFalse(Decision.isModelDerivedPath("env.world", List.of()));
        assertTrue(Decision.isModelDerivedPath("env.world.a", one));
        assertFalse(Decision.isModelDerivedPath("env.world.b", one));
        // a trailing dot names an empty segment, not the whole world
        assertFalse(Decision.isModelDerivedPath("env.world.", one));
        // only the model roots and the world are model-derived
        assertFalse(Decision.isModelDerivedPath("env.foo", one));
        assertFalse(Decision.isModelDerivedPath("env.foo.a", one));
        assertFalse(Decision.isModelDerivedPath("env", one));
        assertFalse(Decision.isModelDerivedPath(5, one));
    }

    @Test void conditionsOfImmutableMapsAreWalkedWithoutNullProbes() {
        // Map.of throws on get(null): a walk that reads a phantom member would throw here
        Map<String, Object> field = Map.of("field", "env.class.a");
        Map<String, Object> ref = Map.of("ref", "env.prov.b");
        Map<String, Object> coll = Map.of("collection", "env.judge.c");
        Map<String, Object> group = Map.of("all_of", List.of(ref), "not", Map.of("field", "env.detect.d"));
        Map<String, Object> any = Map.of("any_of", List.of(coll));
        Map<String, Object> notE = Map.of("not", Map.of("ref", "env.class.e"));
        List<Object> conds = List.of(field, group, any, notE);
        Map<String, Object> where = Map.of("verb", "*", "where", conds);
        assertEquals(List.of("env.class.a", "env.class.e", "env.detect.d", "env.judge.c", "env.prov.b"),
            Decision.modelPathsRead(List.of(List.of(where)), List.of()));
    }

    @Test void nullAndMissingTagMembersAreDifferentUnits() {
        DecisionRestKillTest.confused("{'kind':'money','currency':null}", "{'kind':'money'}", "money/null", "money");
        // a null currency in the POLICY term is refused by the units validator before any comparison
        Decision.UnitsResult r = DecisionRestKillTest.units("{'kind':'money'}", "{'kind':'money','currency':null}");
        assertFalse(r.ok);
        assertEquals("units['action.params.amount'].currency must be a string of 1..16 characters", r.reason);
    }

    // ---- ParamProvenance -----------------------------------------------------------------------------------------------

    @Test void taintLevelsAndModesAreNamesOnly() {
        for (String l : List.of("trusted", "first_party", "tool", "web", "agent")) assertTrue(ParamProvenance.isTaintLevel(l), l);
        assertFalse(ParamProvenance.isTaintLevel("nope"));
        assertFalse(ParamProvenance.isTaintLevel(null));
        assertFalse(ParamProvenance.isTaintLevel(3));
        assertEquals(4, ParamProvenance.rank("nope"));
        assertEquals(1, ParamProvenance.rank("first_party"));
        for (String m : List.of("allow", "question", "question_typed", "deny")) assertTrue(ParamProvenance.isMode(m), m);
        assertFalse(ParamProvenance.isMode("nope"));
        assertFalse(ParamProvenance.isMode(null));
        assertFalse(ParamProvenance.isMode(7));
    }

    @Test void aFlowRuleNeedsAListOfAudiences() {
        assertTrue(ParamProvenance.flowAllowed(Map.of("c", List.of("aud")), "c", "origin", "aud"));
        assertFalse(ParamProvenance.flowAllowed(Map.of("c", List.of("x")), "c", "origin", "aud"));
        assertFalse(ParamProvenance.flowAllowed(Map.of("c", "aud"), "c", "origin", "aud"), "a text is not a list of audiences");
        assertFalse(ParamProvenance.flowAllowed(Map.of("c", Map.of("aud", 1)), "c", "origin", "aud"));
        assertTrue(ParamProvenance.flowAllowed(Map.of(), "c", "aud", "aud"), "the origin itself");
        assertTrue(ParamProvenance.flowAllowed(Map.of(), "public", "origin", "aud"));
        assertFalse(ParamProvenance.flowAllowed(Map.of(), "c", "origin", "aud"));
    }

    @Test void twoDistinctProvenancePathsAreNotAnOverlap() {
        ParamProvenance.ProvResult r = ParamProvenance.decide(j("{'aud':'a','session':'s','action':{'params':{'x':1,'y':2}},"
            + "'prov':{'action.params.x':['agent'],'action.params.y':['agent']},'policy':{'params':{}}}"));
        assertEquals("pass", r.outcome, r.reason);
        assertNull(r.reason);
        assertEquals("agent", r.labels.get("action.params.x"));
        assertEquals("agent", r.labels.get("action.params.y"));
    }

    @Test void aLabelRefWithoutAFieldIsMalformed() {
        assertNull(ParamProvenance.parseLabelRef("pca-labels:#f"));
        assertNull(ParamProvenance.parseLabelRef("pca-labels:abc"));
        assertNull(ParamProvenance.parseLabelRef("other:abc#f"));
    }

    // ---- GoalSemantics (private helpers, driven by reflection) --------------------------------------------------------

    @SuppressWarnings("unchecked")
    static Object call(String name, Object... args) throws Exception {
        Method m = GoalSemantics.class.getDeclaredMethod(name, Map.class, Map.class, Map.class);
        m.setAccessible(true);
        return m.invoke(null, args);
    }

    static Map<String, Object> num(String k, long v) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put(k, v);
        return m;
    }

    static Map<String, Object> period(long ms, long t0) {
        Map<String, Object> w = new LinkedHashMap<>();
        w.put("k", "period");
        w.put("ms", ms);
        w.put("t0", t0);
        return w;
    }

    static boolean inWindow(Map<String, Object> w, long at, long xt) throws Exception {
        return (Boolean) call("inWindow", w, num("t", at), num("t", xt));
    }

    @Test void aPeriodWindowOfOneMillisecondHoldsOnlyTheSameInstant() throws Exception {
        assertTrue(inWindow(period(1, 0), 5, 5));
        assertFalse(inWindow(period(1, 0), 5, 6));
        assertTrue(inWindow(period(10, 0), 11, 19));
        assertFalse(inWindow(period(10, 0), 19, 20));
        assertFalse(inWindow(period(0, 0), 5, 5), "a zero period holds nothing");
        assertFalse(inWindow(period(-3, 0), 5, 5));
    }

    @Test void anAggregateTermNamesItsAggregate() throws Exception {
        Map<String, Object> agg = new LinkedHashMap<>();
        agg.put("n", 3L);
        Map<String, Object> aggs = new LinkedHashMap<>();
        aggs.put("b1", agg);
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("aggs", aggs);
        Map<String, Object> a = new LinkedHashMap<>();
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("k", "agg");
        t.put("bid", "b1");
        Map<String, Object> want = new LinkedHashMap<>();
        want.put("k", "q");
        want.put("q", agg);
        assertEquals(want, call("term", t, a, h));
        Map<String, Object> missing = new LinkedHashMap<>(t);
        missing.put("bid", "zz");
        assertNull(call("term", missing, a, h));
        // a literal is its value, a parameter its bound value
        Map<String, Object> litV = new LinkedHashMap<>();
        litV.put("k", "int");
        Map<String, Object> lit = new LinkedHashMap<>();
        lit.put("k", "lit");
        lit.put("v", litV);
        assertSame(litV, call("term", lit, a, h));
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("p", litV);
        a.put("params", params);
        Map<String, Object> par = new LinkedHashMap<>();
        par.put("k", "param");
        par.put("path", "p");
        assertSame(litV, call("term", par, a, h));
    }

    @Test void aNullTermIsNotTheSameUnitAsAMissingOne() {
        Map<String, Object> terms = new LinkedHashMap<>();
        terms.put("p", null);
        assertEquals(List.of("p"), GoalSemantics.units(new LinkedHashMap<>(), terms));
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("p", null);
        assertEquals(List.of(), GoalSemantics.units(schema, terms));
    }

    // ---- RevocationStaleness -------------------------------------------------------------------------------------------

    @Test void thePolicyIsOnOnlyOnceAWindowOrAStalenessSetIsGiven() {
        assertFalse(new RevocationStaleness().isOn());
        assertTrue(new RevocationStaleness().staleness(null, null).isOn(), "setting the staleness turns the policy on even with no window");
        assertTrue(new RevocationStaleness().staleness(5.0, null).isOn());
        assertTrue(new RevocationStaleness().staleness(null, 5.0).isOn());
        assertTrue(new RevocationStaleness().maxRevocationAgeMs(1000).isOn());
        assertTrue(new RevocationStaleness().staleness(null, null).maxRevocationAgeMs(1000).isOn());
    }

    @Test void aProofThatCannotBeReadIsNoNonMembership() {
        Map<String, Object> hostile = new HashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("hostile"); }
        };
        assertFalse(RevocationStaleness.verifyNonMembership("root", hostile, "c1"));
    }
}
