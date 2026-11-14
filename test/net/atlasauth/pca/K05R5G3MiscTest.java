package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** PCA 0.5 mutation kills: Actions floors and schema checks, the registry key lookup, the passport identity, hostile inputs that must fail closed. */
public class K05R5G3MiscTest {
    static Object j(String s) { return AuthorizeFixtures.j(s); }

    static Map<String, Object> m(Object... kv) { return K05R4ActionsAKillTest.m(kv); }

    static Map<String, Object> hostile() {
        return new HashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("hostile"); }
        };
    }

    // ---- Actions -------------------------------------------------------------------------------------------------------

    @Test void aStringParameterIsNeverIntegerLikeEvenWithIntegerItems() {
        String minMsg = "x: min must be a safe integer on an integer parameter";
        assertEquals(minMsg, K05R4ActionsAKillTest.withParam(m("type", "string", "items", "integer", "min", 1L)));
        assertEquals(minMsg, K05R4ActionsAKillTest.withParam(m("type", "array", "items", "string", "min", 1L)));
        assertEquals("x: max must be a safe integer on an integer parameter", K05R4ActionsAKillTest.withParam(m("type", "string", "items", "integer", "max", 1L)));
        assertNull(K05R4ActionsAKillTest.withParam(m("type", "array", "items", "integer", "min", 1L)));
    }

    @Test void theSensitivityFloorFollowsTheRoleAndTheTags() {
        assertEquals("free", Actions.sensitivityFloor(m()));
        assertEquals("critical", Actions.sensitivityFloor(m("role", "money.amount")));
        assertEquals("material", Actions.sensitivityFloor(m("role", "money.currency")));
        assertEquals("free", Actions.sensitivityFloor(m("role", "unknown.role")));
        assertEquals("material", Actions.sensitivityFloor(m("tags", K05R4ActionsAKillTest.list("pii"))));
        assertEquals("critical", Actions.sensitivityFloor(m("tags", K05R4ActionsAKillTest.list("pii", "secret"))));
        assertEquals("critical", Actions.sensitivityFloor(m("role", "contact.email", "tags", K05R4ActionsAKillTest.list("secret"))));
        assertEquals("critical", Actions.sensitivityFloor(m("role", "money.amount", "tags", K05R4ActionsAKillTest.list("pii"))));
    }

    static boolean leq(Actions.Profile p, String q) throws Exception {
        Method mt = Actions.class.getDeclaredMethod("jsLeq", Actions.Profile.class, Object.class);
        mt.setAccessible(true);
        return (Boolean) mt.invoke(null, p, j(q));
    }

    static final String Q = "{'risk':2,'rev':'rate_limited','blast_ppm':100,'esc':1,'caveats':['a'],'context':[],'prules':[]}";

    @Test void aProfileIsBelowTheFloorsOnlyWhenEveryMemberIs() throws Exception {
        Actions.Profile p = new Actions.Profile(2, "rate_limited", 100, 1, List.of("a"), List.of(), List.of());
        assertTrue(leq(p, Q));
        assertFalse(leq(p, Q.replace("'risk':2", "'risk':1")));
        assertTrue(leq(p, Q.replace("'risk':2", "'risk':3")));
        assertFalse(leq(p, Q.replace("'blast_ppm':100", "'blast_ppm':99")));
        assertTrue(leq(p, Q.replace("'blast_ppm':100", "'blast_ppm':101")));
        assertFalse(leq(p, Q.replace("'esc':1", "'esc':0")));
        assertTrue(leq(p, Q.replace("'esc':1", "'esc':2")));
        assertFalse(leq(p, Q.replace("'rev':'rate_limited'", "'rev':'reversible'")));
        assertTrue(leq(p, Q.replace("'rev':'rate_limited'", "'rev':'irreversible'")));
        assertFalse(leq(p, Q.replace("'rev':'rate_limited',", "")), "an absent class ranks nothing");
        assertFalse(leq(p, Q.replace("'rev':'rate_limited'", "'rev':'nonsense'")));
        assertFalse(leq(p, Q.replace("'caveats':['a']", "'caveats':[]")));
        assertFalse(leq(p, Q.replace("'esc':1,", "")), "an absent member is NaN: no comparison holds");
    }

    @Test void aNumberIsReadFromAOneElementArrayLikeJavaScript() {
        assertEquals(5.0, Actions.jsNumber(List.of("5"), true), 0.0);
        assertEquals(7.0, Actions.jsNumber("7", true), 0.0);
        assertEquals(0.0, Actions.jsNumber(List.of(), true), 0.0);
        assertTrue(Double.isNaN(Actions.jsNumber("x", true)));
        assertTrue(Double.isNaN(Actions.jsNumber(null, false)));
    }

    static int revRank(Object x) throws Exception {
        Method mt = Actions.class.getDeclaredMethod("jsRevRank", Object.class);
        mt.setAccessible(true);
        return (Integer) mt.invoke(null, x);
    }

    @Test void aReversibilityClassRanksOnlyWhenItIsANameOrAOneElementArrayOfOne() throws Exception {
        assertEquals(2, revRank("irreversible"));
        assertEquals(0, revRank("reversible"));
        assertEquals(1, revRank(List.of("rate_limited")));
        assertEquals(-1, revRank(new Json.Num("5")));
        assertEquals(-1, revRank(new HashMap<String, Object>()));
        assertEquals(-1, revRank(null));
        assertEquals(-1, revRank(Boolean.TRUE));
    }

    @Test void aNullReversibilityMapThrowsLikeObjectValues() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Actions.worstReversibility(m("by", "action.params.m", "map", null), Map.of()));
        assertEquals("Cannot convert undefined or null to object", e.getMessage());
        IllegalArgumentException e2 = assertThrows(IllegalArgumentException.class, () -> Actions.worstReversibility(m("by", "action.params.m"), Map.of()));
        assertEquals("Cannot convert undefined or null to object", e2.getMessage());
        assertEquals("reversible", Actions.worstReversibility(m("by", "action.params.m", "map", m(), "default", "reversible"), Map.of()));
    }

    // ---- Authorize -----------------------------------------------------------------------------------------------------

    @Test void aCaveatWhoseTypeCannotBeReadIsAnEvaluationError() {
        Caveats.Result r = Authorize.evaluateAgentCaveats(List.of(hostile()), new LinkedHashMap<>(), null, null);
        assertFalse(r.ok);
        assertEquals(List.of("<evaluation error>"), r.failed);
    }

    // ---- Passport ------------------------------------------------------------------------------------------------------

    @Test void theMeasuredIdentityMustEqualTheClaims() {
        Map<String, Object> p = m("model_id", "mdl", "operator", "op");
        Map<String, Object> measured = m("model_id", "mdl", "operator", "op");
        assertTrue(Passport.identityMatches(p, measured));
        assertFalse(Passport.identityMatches(p, null));
        assertFalse(Passport.identityMatches(m("operator", "op"), measured), "no model claim");
        assertFalse(Passport.identityMatches(m("model_id", "mdl"), measured), "no operator claim");
        assertFalse(Passport.identityMatches(m("model_id", 5L, "operator", "op"), m("model_id", 5L, "operator", "op")), "numbers are not names");
        assertFalse(Passport.identityMatches(p, m("model_id", "mdl")), "nothing measured for the operator");
        assertFalse(Passport.identityMatches(p, m("model_id", "other", "operator", "op")));
        assertFalse(Passport.identityMatches(p, m("model_id", "mdl", "operator", "other")));
        // a stated optional digest must be measured equal
        p.put("weights_digest", null);
        assertFalse(Passport.identityMatches(p, measured), "a null claim is not a string");
        p.put("weights_digest", "d");
        assertFalse(Passport.identityMatches(p, measured), "claimed but not measured");
        measured.put("weights_digest", "e");
        assertFalse(Passport.identityMatches(p, measured));
        measured.put("weights_digest", "d");
        assertTrue(Passport.identityMatches(p, measured));
        measured.put("weights_digest", 5L);
        p.put("weights_digest", 5L);
        assertFalse(Passport.identityMatches(p, measured), "equal numbers are not equal digests");
    }

    // ---- CaveatLang ----------------------------------------------------------------------------------------------------

    @Test void aGrantThatCannotBeReadHasNoBoundCaveats() {
        assertNull(CaveatLang.boundCaveats(hostile(), null));
    }

    // ---- ActionRegistry ------------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    static Map<String, Object> keyOf(List<Object> keys) { return (Map<String, Object>) keys.get(0); }

    @Test void theRegistryKeyLookupSkipsKeysThatAreNotObjectsOrHaveNoKid() {
        List<Object> good = ActionRegistryRestKillTest.keyWithKid("reg-1");
        // a key list entry that is not an object is skipped, not an error
        assertNull(ActionRegistry.verifyRegistrySig("dom", ActionRegistryRestKillTest.BODY, ActionRegistryRestKillTest.sig("reg-1"),
            ActionRegistryRestKillTest.list(5L, good.get(0))));
        // a key with no kid never matches a signature with no kid
        List<Object> noKid = ActionRegistryRestKillTest.keyWithKid("reg-1");
        keyOf(noKid).remove("kid");
        Map<String, Object> noKidSig = ActionRegistryRestKillTest.sig("reg-1");
        noKidSig.remove("kid");
        assertEquals("no registry key with kid 'undefined'", ActionRegistry.verifyRegistrySig("dom", ActionRegistryRestKillTest.BODY, noKidSig, noKid));
        // nor does a key whose kid is null match a signature whose kid is null
        assertEquals("no registry key with kid 'null'", ActionRegistry.verifyRegistrySig("dom", ActionRegistryRestKillTest.BODY,
            ActionRegistryRestKillTest.sig(null), ActionRegistryRestKillTest.keyWithKid(null)));
        // the member is looked up by its name, not compared as the name
        assertEquals("no registry key with kid 'kid'", ActionRegistry.verifyRegistrySig("dom", ActionRegistryRestKillTest.BODY,
            ActionRegistryRestKillTest.sig("kid"), ActionRegistryRestKillTest.keyWithKid("other")));
    }
}
