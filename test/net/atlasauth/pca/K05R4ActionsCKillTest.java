package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for {@link Actions} from line 950 up: the signed confirmation (attested / isConfirmed, confirmation.ts
 * verbConfirmationError), reviewer pins, rule 22 (derive.ts schemaVerbFloorError / schemaFloorError), the JavaScript-semantics helpers.
 */
public class K05R4ActionsCKillTest {
    static final String LABEL = "k05r4/actions-c/reviewer", OTHER = "k05r4/actions-c/other", KID = "rev1", DEF = "def-digest-of-the-verb";
    static final String X14 = "x".repeat(14);
    static final Actions.Registry CORE = Actions.CORE_REGISTRY;
    static final String UNCONFIRMED = "schema_traits_forged: unconfirmed action must carry every trait";

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }
    static Map<String, Object> map(Object... kv) { return IntentV2KillTest.map(kv); }
    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }
    static Json.Num n(long v) { return IntentJs.ofLong(v); }
    static String canon(Object o) { return Json.canonicalize(o); }

    // ---- fixtures: a def, a pinned reviewer, a signed attestation ----

    static Map<String, Object> baseDef() {
        return map("v", n(1), "kind", "pca-action-def", "verb", "acme.report.get", "title", "Get a report", "effects", list("read"),
            "resource", map("type", "acme.report", "id", "*", "scope", "tenant"),
            "params", map("q", map("type", "string", "role", "query.search", "max_len", n(64)),
                "n", map("type", "integer", "role", "count.limit", "min", n(1), "max", n(50)),
                "total", map("type", "integer", "role", "money.amount"), "rows", map("type", "array", "items", "string")),
            "reversibility", "reversible", "idempotency", map("mode", "natural"));
    }

    static Map<String, Object> pins() {
        return map("keys", list(map("kid", KID, "pk", IntentV2KillTest.pub(LABEL), "roles", list("reviewer"), "not_before", n(100), "not_after", n(2000000000L))));
    }

    static Map<String, Object> dismissal(String trait, Object reason) { return map("trait", trait, "reason", reason); }

    static Map<String, Object> att(Object defDigest, Object facts, List<Object> fin, List<Object> dismissed) {
        return map("def_digest", defDigest, "traits_digest", Actions.traitsDigest(CORE), "facts_digest", facts, "final_traits", fin, "dismissed", dismissed,
            "reviewer_kid", KID, "ts", n(1000));
    }

    /** Re-signs {@code a} (any member changed) with the pinned reviewer key. */
    static Map<String, Object> signed(Map<String, Object> a) {
        a.remove("sig");
        a.put("sig", IntentV2KillTest.sign(LABEL, Actions.reviewMessage(a)));
        return a;
    }

    static Map<String, Object> confirmedDef(List<Object> declared, List<Object> dismissed) {
        Map<String, Object> d = baseDef();
        d.put("traits", declared);
        Map<String, Object> a = att(Actions.defDigest(d), "facts", new ArrayList<>(declared), dismissed);
        d.put("review", map("state", "confirmed", "attestation", signed(a)));
        return d;
    }

    static Map<String, Object> goodDef() { return confirmedDef(list(), list(dismissal("pca.bulk", "not relevant"))); }
    static Map<String, Object> attOf(Map<String, Object> d) { return m(m(d.get("review")).get("attestation")); }

    // ---- attested / isConfirmed (confirmation.ts:114-139) ----

    @Test void aSignedConfirmationOfTheDeclaredTraitsCounts() {
        assertTrue(Actions.isConfirmed(goodDef(), CORE, pins()));
        assertTrue(Actions.isConfirmed(confirmedDef(list("pca.impersonation"), list()), CORE, pins()));
    }

    @Test void onlyTheConfirmedStateCounts() {
        for (Object state : new Object[] {"pending", "draft", "rejected", null}) {
            Map<String, Object> d = goodDef();
            m(d.get("review")).put("state", state);
            assertFalse(Actions.isConfirmed(d, CORE, pins()), String.valueOf(state));
        }
        Map<String, Object> d = goodDef();
        d.remove("review");
        assertFalse(Actions.isConfirmed(d, CORE, pins()));
    }

    @Test void anythingThatThrowsIsNotConfirmed() {
        assertFalse(Actions.isConfirmed(null, CORE, pins()));
    }

    @Test void noPinsOrUnsoundPinsConfirmNothing() {
        assertFalse(Actions.isConfirmed(goodDef(), CORE, null));
        Map<String, Object> badRole = pins();
        l(badRole.get("keys")).add(map("kid", "rev2", "pk", IntentV2KillTest.pub(OTHER), "roles", list("nonsense")));
        assertFalse(Actions.isConfirmed(goodDef(), CORE, badRole), "an unsound pin set voids the whole set even though the signer's key is fine");
        Map<String, Object> twice = pins();
        l(twice.get("keys")).add(map("kid", KID, "pk", IntentV2KillTest.pub(OTHER), "roles", list("reviewer")));
        assertFalse(Actions.isConfirmed(goodDef(), CORE, twice));
    }

    @Test void theAttestationMustBeAnObjectWithAStringDigestForTheSameDef() {
        Map<String, Object> d = goodDef();
        m(d.get("review")).put("attestation", "not an object");
        assertFalse(Actions.isConfirmed(d, CORE, pins()));
        Map<String, Object> e = goodDef();
        attOf(e).put("def_digest", "a-different-def");
        signed(attOf(e));
        assertFalse(Actions.isConfirmed(e, CORE, pins()));
        Map<String, Object> f = goodDef();
        attOf(f).remove("sig");
        assertFalse(Actions.isConfirmed(f, CORE, pins()));
    }

    @Test void theTraitsDigestMustBeTheRegistrysOrAPinnedPreviousOne() {
        Map<String, Object> d = goodDef();
        attOf(d).put("traits_digest", "an-old-registry-digest");
        signed(attOf(d));
        assertFalse(Actions.isConfirmed(d, CORE, pins()));
        Map<String, Object> p = pins();
        p.put("traits_digests", list("an-old-registry-digest"));
        assertTrue(Actions.isConfirmed(d, CORE, p), "a pinned previous digest is accepted");
        p.put("traits_digests", list("some-other-digest"));
        assertFalse(Actions.isConfirmed(d, CORE, p));
        Map<String, Object> q = pins();
        q.put("traits_digests", list("some-other-digest"));
        assertTrue(Actions.isConfirmed(goodDef(), CORE, q), "the registry's own digest needs no pin");
    }

    @Test void theFinalTraitsAndTheTimestampAreRequired() {
        Map<String, Object> noFinal = goodDef();
        attOf(noFinal).remove("final_traits");
        signed(attOf(noFinal));
        assertFalse(Actions.isConfirmed(noFinal, CORE, pins()), "an absent final_traits is not the empty set");

        Map<String, Object> noTs = goodDef();
        attOf(noTs).remove("ts");
        signed(attOf(noTs));
        Map<String, Object> open = pins();
        m(l(open.get("keys")).get(0)).remove("not_before");
        m(l(open.get("keys")).get(0)).remove("not_after");
        assertFalse(Actions.isConfirmed(noTs, CORE, open), "no timestamp, no validity window to read it against");

        Map<String, Object> fractional = goodDef();
        attOf(fractional).put("ts", new Json.Num("1.5"));
        boolean signedOk;
        try { signed(attOf(fractional)); signedOk = true; } catch (IllegalArgumentException e) { signedOk = false; }
        if (signedOk) assertFalse(Actions.isConfirmed(fractional, CORE, pins()), "ts must be a safe integer");
    }

    @Test void theValidityWindowIsHonoured() {
        Map<String, Object> early = pins();
        m(l(early.get("keys")).get(0)).put("not_before", n(1001));
        assertFalse(Actions.isConfirmed(goodDef(), CORE, early));
        Map<String, Object> late = pins();
        m(l(late.get("keys")).get(0)).put("not_after", n(999));
        assertFalse(Actions.isConfirmed(goodDef(), CORE, late));
        Map<String, Object> edge = pins();
        m(l(edge.get("keys")).get(0)).put("not_before", n(1000));
        m(l(edge.get("keys")).get(0)).put("not_after", n(1000));
        assertTrue(Actions.isConfirmed(goodDef(), CORE, edge));
    }

    @Test void aWrongSignatureOrAKeyWithoutTheReviewerRoleIsNotConfirmed() {
        Map<String, Object> d = goodDef();
        attOf(d).put("sig", IntentV2KillTest.sign(OTHER, Actions.reviewMessage(attOf(d))));
        assertFalse(Actions.isConfirmed(d, CORE, pins()));
        Map<String, Object> publisher = pins();
        m(l(publisher.get("keys")).get(0)).put("roles", list("publisher"));
        assertFalse(Actions.isConfirmed(goodDef(), CORE, publisher));
    }

    @Test void dismissalsMustBeSoundStringTraitsWithRealReasons() {
        // one dismissal each, so the sort never compares: only the soundness check can refuse them
        Map<String, Object> numericTrait = confirmedDef(list(), list(map("trait", n(5), "reason", "why")));
        assertFalse(Actions.isConfirmed(numericTrait, CORE, pins()));
        Map<String, Object> numericReason = confirmedDef(list(), list(dismissal("pca.bulk", n(5))));
        assertFalse(Actions.isConfirmed(numericReason, CORE, pins()));
        Map<String, Object> noReason = confirmedDef(list(), list(map("trait", "pca.bulk")));
        assertFalse(Actions.isConfirmed(noReason, CORE, pins()));
        for (String blank : new String[] {"", "   ", "\t\n", " ", "﻿", "  "}) {
            assertFalse(Actions.isConfirmed(confirmedDef(list(), list(dismissal("pca.bulk", blank))), CORE, pins()), "blank reason [" + blank.length() + "]");
        }
        assertTrue(Actions.isConfirmed(confirmedDef(list(), list(dismissal("pca.bulk", " x "))), CORE, pins()));
        assertFalse(Actions.isConfirmed(confirmedDef(list("pca.bulk"), list(dismissal("pca.bulk", "dismissed and final"))), CORE, pins()));
    }

    @Test void theReviewMessageSortsDismissalsByTrait() {
        List<Object> uv = list(dismissal("u", "r1"), dismissal("v", "r2")), vu = list(dismissal("v", "r2"), dismissal("u", "r1"));
        assertArrayEquals(Actions.reviewMessage(att("d", "f", list(), uv)), Actions.reviewMessage(att("d", "f", list(), vu)));
        List<Object> sorted = list(dismissal("u", "r1"), dismissal("v", "r2"), dismissal("w", "r3"));
        List<Object> shuffled = list(dismissal("w", "r3"), dismissal("u", "r1"), dismissal("v", "r2"));
        assertArrayEquals(Actions.reviewMessage(att("d", "f", list(), sorted)), Actions.reviewMessage(att("d", "f", list(), shuffled)));
    }

    @Test void blankIsWhiteSpaceOnly() throws Exception {
        for (String s : new String[] {"", " ", "\t \n", " ", "﻿", " "}) assertTrue((Boolean) call("blank", new Class<?>[] {String.class}, s), "[" + s.length() + "]");
        for (String s : new String[] {"a", " a", "a ", " x"}) assertFalse((Boolean) call("blank", new Class<?>[] {String.class}, s), s);
    }

    // ---- traitsOf / effective ----

    @Test void traitsOfIsTheHintWhenConfirmedAndTheTopOtherwise() {
        Map<String, Object> d = confirmedDef(list("pca.impersonation"), list());
        List<String> hint = Actions.hintTraits(d), top = Actions.topTraits(CORE);
        assertNotEquals(hint, top);
        assertEquals(hint, Actions.traitsOf(d, CORE, pins()));
        assertEquals(top, Actions.traitsOf(d, CORE, null));
        assertEquals(top, Actions.traitsOf(d, CORE, map("keys", list())));
    }

    @Test void effectiveWithoutPinsIsUnconfirmedAndAtTheTop() {
        Map<String, Object> d = confirmedDef(list("pca.impersonation"), list());
        Map<String, Object> e = Actions.effective(d, CORE);
        List<String> top = Actions.topTraits(CORE);
        assertEquals(Boolean.FALSE, e.get("confirmed"));
        assertEquals(new ArrayList<Object>(top), e.get("traits"));
        assertEquals(new ArrayList<Object>(Actions.closure(CORE, top)), e.get("closure"));
        assertEquals(canon(Actions.floorOf(CORE, top).toMap()), canon(e.get("floor")));
        assertEquals(canon(Actions.declProfile(d).toMap()), canon(e.get("decl")));
        assertEquals(canon(Actions.effective(d, CORE, null)), canon(e));
    }

    @Test void effectiveConfirmedCarriesTheHintAndItsClosure() {
        Map<String, Object> d = confirmedDef(list("pca.impersonation"), list());
        Map<String, Object> e = Actions.effective(d, CORE, pins());
        List<String> hint = Actions.hintTraits(d);
        assertEquals(Boolean.TRUE, e.get("confirmed"));
        assertEquals(new ArrayList<Object>(hint), e.get("traits"));
        assertFalse(hint.contains("pca.external_communication"));
        assertTrue(l(e.get("closure")).contains("pca.external_communication"), "impersonation implies external_communication");
        assertEquals(new ArrayList<Object>(Actions.closure(CORE, hint)), e.get("closure"));
        assertEquals(canon(Actions.floorOf(CORE, hint).toMap()), canon(e.get("floor")));
    }

    // ---- reviewerPinsError / factsDigest ----

    @Test void pinsWithImmutableMembersAreSound() {
        Map<String, Object> key = Map.of("kid", "k1", "pk", IntentV2KillTest.pub(LABEL), "roles", List.of("reviewer"));
        assertNull(Actions.reviewerPinsError(Map.of("keys", List.of(key))));
        assertNull(Actions.reviewerPinsError(pins()));
    }

    @Test void rolesMustBeDistinctKnownNonNull() {
        for (Object roles : new Object[] {list("reviewer", null), list(), list("reviewer", "reviewer"), list("nonsense"), "reviewer", null}) {
            Map<String, Object> p = map("keys", list(map("kid", "k1", "pk", IntentV2KillTest.pub(LABEL), "roles", roles)));
            assertEquals("key 'k1': roles must be distinct known roles", Actions.reviewerPinsError(p), String.valueOf(roles));
        }
    }

    @Test void theFactsDigestLeavesOutTheMembersTheConfirmationDecides() {
        Map<String, Object> v = map("verb", "a.b", "effects", list("read"));
        String base = Actions.factsDigest(v);
        Map<String, Object> w = new LinkedHashMap<>(v);
        w.put("traits", list("pca.bulk")); w.put("floors", map()); w.put("confirmation", map()); w.put("def", "x");
        assertEquals(base, Actions.factsDigest(w));
        w.put("title", "changed");
        assertNotEquals(base, Actions.factsDigest(w));
    }

    // ---- verbFloorError: the confirmation on a schema verb, rule 22 (derive.ts:178-199) ----

    static Map<String, Object> facts() { return map("verb", "acme.v", "kind", "read", "effects", list("read"), "params", map()); }

    static Map<String, Object> factsWith(Object... kv) {
        Map<String, Object> f = facts();
        for (int i = 0; i < kv.length; i += 2) f.put((String) kv[i], kv[i + 1]);
        return f;
    }

    static Map<String, Object> confirmedVerb(Map<String, Object> facts, List<Object> traits, List<Object> fin) {
        Map<String, Object> v = new LinkedHashMap<>(facts);
        String fd = Actions.factsDigest(v);
        v.put("traits", traits);
        v.put("def", DEF);
        v.put("floors", Actions.floorOf(CORE, traits).toMap());
        v.put("confirmation", signed(att(DEF, fd, fin, list())));
        return v;
    }

    static Map<String, Object> bare(Object... kv) {
        Map<String, Object> v = map("verb", "acme.v", "kind", "read", "effects", list("read"), "traits", list(), "floors", map());
        for (int i = 0; i < kv.length; i += 2) v.put((String) kv[i], kv[i + 1]);
        return v;
    }

    static String err(Object v) { return Actions.verbFloorError(v, CORE, pins()); }

    @Test void aVerbWithAValidConfirmationNeedsNoMoreThanItsImpliedTraits() {
        assertNull(err(confirmedVerb(facts(), list(), list())));
    }

    @Test void withoutAValidConfirmationTheVerbMustCarryEveryTrait() {
        Map<String, Object> v = confirmedVerb(facts(), list(), list());
        assertTrue(Actions.verbFloorError(v, CORE, null).startsWith(UNCONFIRMED));
        assertTrue(Actions.verbFloorError(v, CORE, map("keys", list())).startsWith(UNCONFIRMED));
        Map<String, Object> badPins = pins();
        l(badPins.get("keys")).add(map("kid", "rev2", "pk", IntentV2KillTest.pub(OTHER), "roles", list("nonsense")));
        assertTrue(Actions.verbFloorError(v, CORE, badPins).startsWith(UNCONFIRMED), "unsound pins confirm nothing");
        List<Object> top = new ArrayList<Object>(Actions.topTraits(CORE));
        Map<String, Object> all = new LinkedHashMap<>(facts());
        all.put("traits", top); all.put("floors", Actions.floorOf(CORE, top).toMap());
        assertNull(Actions.verbFloorError(all, CORE, null), "carrying every trait needs no confirmation");
    }

    @Test void theConfirmedFinalTraitsMustAllBeCarried() {
        Map<String, Object> v = confirmedVerb(facts(), list(), list("pca.bulk"));
        assertTrue(err(v).startsWith(UNCONFIRMED), err(v));
        assertNull(err(confirmedVerb(facts(), list("pca.bulk"), list("pca.bulk"))));
    }

    @Test void theConfirmedDefMustBeAString() {
        Map<String, Object> v = confirmedVerb(facts(), list(), list());
        Json.Num defNum = n(5);
        v.put("def", defNum);
        m(v.get("confirmation")).put("def_digest", defNum);
        signed(m(v.get("confirmation")));
        assertTrue(err(v).startsWith(UNCONFIRMED), "a signed numeric def digest confirms nothing");
    }

    @Test void theFactsTheReviewerSawAreBound() {
        Map<String, Object> v = confirmedVerb(facts(), list(), list());
        v.put("title", "edited after review");
        assertTrue(err(v).startsWith(UNCONFIRMED));
    }

    @Test void nothingElseThrowsOutOfVerbFloorError() {
        String e = Actions.verbFloorError(null, CORE, null);
        assertTrue(e.startsWith("schema_floor_forged: "), e);
        assertTrue(e.contains("Cannot read properties of null (reading 'effects')"), e);
        assertEquals("schema_floor_forged: not a v2 verb", Actions.verbFloorError(map("effects", list(), "traits", list()), CORE, null));
        assertEquals("schema_floor_forged: not a v2 verb", Actions.verbFloorError("text", CORE, null));
    }

    @Test void paramsAreReadAsObjectEntries() {
        Map<String, Object> noParams = bare();
        String e = Actions.verbFloorError(noParams, CORE, null);
        assertTrue(e.startsWith("schema_floor_forged: ") && e.contains("Cannot convert undefined or null to object"), e);
        Map<String, Object> nullParams = bare("params", null);
        e = Actions.verbFloorError(nullParams, CORE, null);
        assertTrue(e.startsWith("schema_floor_forged: ") && e.contains("Cannot convert undefined or null to object"), e);
        e = Actions.verbFloorError(bare("params", map("action.params.x", null)), CORE, null);
        assertTrue(e.startsWith("schema_floor_forged: ") && e.contains("Cannot read properties of null (reading 'type')"), e);
        // an array's entries are its elements: the first is an unbounded array (implies bulk), the second would not be
        assertEquals("schema_traits_forged: missing implied trait pca.bulk",
            Actions.verbFloorError(bare("params", list(map("type", "array"), map("type", "string"))), CORE, null));
        assertEquals("schema_traits_forged: missing implied trait pca.bulk",
            Actions.verbFloorError(bare("params", list(map("type", "string"), map("type", "array"))), CORE, null));
    }

    @Test void reversibilityByNeedsAParamThatCanBeSliced() {
        for (Object rb : new Object[] {"x", true, n(1), map("map", map()), list("a")}) {
            String e = Actions.verbFloorError(bare("params", map(), "reversibility_by", rb), CORE, null);
            assertTrue(e.startsWith("schema_floor_forged: ") && e.contains("Cannot read properties of undefined (reading 'slice')"), canon(rb) + " -> " + e);
        }
        String e = Actions.verbFloorError(bare("params", map(), "reversibility_by", map("param", n(5), "map", map())), CORE, null);
        assertTrue(e.startsWith("schema_floor_forged: ") && e.contains("v.reversibility_by.param.slice is not a function"), e);
    }

    @Test void theDeclaredReversibilityFollowsTheNamedParam() {
        Map<String, Object> allReversible = map("true", "reversible", "false", "reversible");
        Map<String, Object> bool = map("action.params.m", map("type", "boolean"));
        // a string param: the first 14 characters are dropped, whatever they are
        assertNull(err(confirmedVerb(factsWith("params", bool, "reversibility_by", map("param", X14 + "m", "map", allReversible, "default", "irreversible")), list(), list())));
        // an array param is sliced from element 14; the property key of the rest is its text
        List<Object> prm = new ArrayList<>();
        for (int i = 0; i < 14; i++) prm.add("j");
        prm.add("m");
        assertNull(err(confirmedVerb(factsWith("params", bool, "reversibility_by", map("param", prm, "map", allReversible, "default", "irreversible")), list(), list())));
        // the wrong name leaves the domain uncovered: the default decides
        assertEquals("schema_traits_forged: missing implied trait pca.irreversible",
            err(confirmedVerb(factsWith("params", bool, "reversibility_by", map("param", X14 + "z", "map", allReversible, "default", "irreversible")), list(), list())));
        // a string param with a values domain
        Map<String, Object> str = map("action.params.s", map("type", "string", "values", list("a", "b")));
        assertNull(err(confirmedVerb(factsWith("params", str, "reversibility_by", map("param", X14 + "s", "map", map("a", "reversible", "b", "reversible"), "default", "irreversible")), list(), list())));
        assertEquals("schema_traits_forged: missing implied trait pca.irreversible",
            err(confirmedVerb(factsWith("params", str, "reversibility_by", map("param", X14 + "s", "map", map("a", "reversible"), "default", "irreversible")), list(), list())));
    }

    @Test void aShortParamPathSlicesToNothing() {
        Map<String, Object> bool = map("action.params.m", map("type", "boolean"));
        assertNull(err(confirmedVerb(factsWith("params", bool, "reversibility_by", map("param", list("a", "b", "c"), "map", map(), "default", "reversible")), list(), list())));
        assertNull(err(confirmedVerb(factsWith("params", bool, "reversibility_by", map("param", "abc", "map", map(), "default", "reversible")), list(), list())));
        assertNull(err(confirmedVerb(factsWith("params", bool, "reversibility_by", map("param", "action.params.", "map", map(), "default", "reversible")), list(), list())));
    }

    @Test void theDefaultAndTheMapOfReversibilityByAreCarried() {
        Map<String, Object> noParam = map("action.params.m", map("type", "string"));
        assertNull(err(confirmedVerb(factsWith("params", noParam, "reversibility_by", map("param", X14 + "z", "map", map(), "default", "reversible")), list(), list())));
        assertEquals("schema_traits_forged: missing implied trait pca.irreversible",
            err(confirmedVerb(factsWith("params", noParam, "reversibility_by", map("param", X14 + "z", "map", map())), list(), list())));
        assertEquals("schema_traits_forged: missing implied trait pca.irreversible",
            err(confirmedVerb(factsWith("params", noParam, "reversibility_by", map("param", X14 + "z", "map", map(), "default", null)), list(), list())));
        // a map of rate_limited decides over a reversible default
        assertEquals("schema_floor_forged: floors.rev is below the declared reversibility",
            err(confirmedVerb(factsWith("params", noParam, "reversibility_by", map("param", X14 + "z", "map", map("a", "rate_limited"), "default", "reversible")), list(), list())));
        String e = Actions.verbFloorError(bare("params", map(), "reversibility_by", map("param", X14 + "z", "default", "reversible")), CORE, null);
        assertTrue(e.startsWith("schema_floor_forged: ") && e.contains("Cannot convert undefined or null to object"), "no map: " + e);
    }

    @Test void withoutReversibilityTheKindDecides() {
        assertNull(err(confirmedVerb(factsWith("kind", "read"), list(), list())));
        assertEquals("schema_traits_forged: missing implied trait pca.irreversible", err(confirmedVerb(factsWith("kind", "write", "effects", list("update")), list(), list())));
        Map<String, Object> explicit = factsWith("kind", "write", "effects", list("update"), "reversibility", "reversible");
        assertNull(err(confirmedVerb(explicit, list(), list())));
        Map<String, Object> nullRev = factsWith("kind", "write", "effects", list("update"), "reversibility", null);
        assertEquals("schema_traits_forged: missing implied trait pca.irreversible", err(confirmedVerb(nullRev, list(), list())));
        Map<String, Object> nullRevRead = factsWith("kind", "read", "reversibility", null);
        assertNull(err(confirmedVerb(nullRevRead, list(), list())));
    }

    @Test void theFloorsRevMustCoverTheDeclaredReversibility() {
        String below = "schema_floor_forged: floors.rev is below the declared reversibility";
        Map<String, Object> v = confirmedVerb(factsWith("reversibility", "rate_limited"), list(), list());
        m(v.get("floors")).put("rev", "reversible");
        assertEquals(below, err(v));
        m(v.get("floors")).put("rev", "rate_limited");
        assertNull(err(v));
        m(v.get("floors")).put("rev", "irreversible");
        assertNull(err(v));
        Map<String, Object> reversible = confirmedVerb(facts(), list(), list());
        m(reversible.get("floors")).put("rev", "reversible");
        assertNull(err(reversible));
        // Array.prototype.indexOf is strict equality: an array never ranks, whatever it names
        m(reversible.get("floors")).put("rev", list("reversible"));
        assertEquals(below, err(reversible));
        // a rev that is not a class is no floor at all
        m(reversible.get("floors")).put("rev", "nonsense");
        assertEquals("schema_floor_forged: floors are below the floor of the carried traits", err(reversible));
    }

    @Test void theFloorsMustBeAtLeastTheFloorOfTheCarriedTraits() {
        String forged = "schema_floor_forged: floors are below the floor of the carried traits";
        Map<String, Object> v = confirmedVerb(factsWith("reversibility", "irreversible"), list("pca.irreversible"), list());
        assertNull(err(v));
        m(v.get("floors")).put("risk", n(0));
        assertEquals(forged, err(v));
        Map<String, Object> w = confirmedVerb(facts(), list(), list());
        w.put("floors", "not a profile");
        assertEquals(forged, err(w));
        w.put("floors", null);
        assertTrue(err(w).startsWith("schema_floor_forged: "));
    }

    // ---- the JavaScript-semantics helpers ----

    static Object call(String name, Class<?>[] types, Object... args) throws Exception {
        Method mm = Actions.class.getDeclaredMethod(name, types);
        mm.setAccessible(true);
        try { return mm.invoke(null, args); }
        catch (InvocationTargetException e) { if (e.getCause() instanceof Exception) throw (Exception) e.getCause(); throw e; }
    }

    static List<?> entries(Object o, boolean present) throws Exception { return (List<?>) call("jsEntries", new Class<?>[] {Object.class, boolean.class}, o, present); }

    @Test void entriesOfAJsonValue() throws Exception {
        for (Object o : new Object[] {null, "x", map()}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> entries(o, false));
            assertEquals("Cannot convert undefined or null to object", e.getMessage());
        }
        assertEquals("Cannot convert undefined or null to object", assertThrows(IllegalArgumentException.class, () -> entries(null, true)).getMessage());
        List<?> arr = entries(list("x", "y", "z"), true);
        assertEquals(3, arr.size());
        for (int i = 0; i < 3; i++) {
            assertEquals(String.valueOf(i), ((Map.Entry<?, ?>) arr.get(i)).getKey());
            assertEquals(list("x", "y", "z").get(i), ((Map.Entry<?, ?>) arr.get(i)).getValue());
        }
        List<?> str = entries("abc", true);
        assertEquals(3, str.size());
        for (int i = 0; i < 3; i++) {
            assertEquals(String.valueOf(i), ((Map.Entry<?, ?>) str.get(i)).getKey());
            assertEquals(String.valueOf("abc".charAt(i)), ((Map.Entry<?, ?>) str.get(i)).getValue());
        }
        assertEquals(0, entries("", true).size());
        assertEquals(0, entries(list(), true).size());
        assertEquals(0, entries(n(5), true).size());
        assertEquals(0, entries(Boolean.TRUE, true).size());
        List<?> obj = entries(map("k", n(1), "j", "v"), true);
        assertEquals(2, obj.size());
        assertEquals("k", ((Map.Entry<?, ?>) obj.get(0)).getKey());
    }

    @Test void numberOfAJsonMember() {
        assertTrue(Double.isNaN(Actions.jsNumber(n(7), false)));
        assertTrue(Double.isNaN(Actions.jsNumber(null, false)));
        assertEquals(0.0, Actions.jsNumber(null, true), 0.0);
        assertEquals(1.0, Actions.jsNumber(Boolean.TRUE, true), 0.0);
        assertEquals(0.0, Actions.jsNumber(Boolean.FALSE, true), 0.0);
        assertEquals(7.0, Actions.jsNumber(n(7), true), 0.0);
        assertTrue(Double.isNaN(Actions.jsNumber(map(), true)));
        assertTrue(Double.isNaN(Actions.jsNumber(map("a", n(1)), true)));
        assertEquals(5.0, Actions.jsNumber(list("5"), true), 0.0);
        assertEquals(0.0, Actions.jsNumber(list(), true), 0.0);
        assertTrue(Double.isNaN(Actions.jsNumber(list("a", "b"), true)));
        assertEquals(12.0, Actions.jsNumber("  12 ", true), 0.0);
        assertEquals(0.0, Actions.jsNumber("", true), 0.0);
        assertTrue(Double.isNaN(Actions.jsNumber("twelve", true)));
    }

    static boolean subset(List<String> a, Object b, boolean present) throws Exception { return (Boolean) call("jsSubset", new Class<?>[] {List.class, Object.class, boolean.class}, a, b, present); }

    @Test void subsetFollowsArrayEvery() throws Exception {
        List<String> none = new ArrayList<>(), ab = new ArrayList<>(Arrays.asList("a", "b"));
        assertTrue(subset(none, null, false), "an empty a is vacuously a subset of anything, even of undefined");
        assertTrue(subset(none, null, true));
        assertTrue(subset(none, n(5), true));
        String undef = "Cannot read properties of null (reading 'includes')";
        assertEquals(undef, assertThrows(IllegalArgumentException.class, () -> subset(ab, null, false)).getMessage());
        assertEquals(undef, assertThrows(IllegalArgumentException.class, () -> subset(ab, null, true)).getMessage());
        assertEquals(undef, assertThrows(IllegalArgumentException.class, () -> subset(ab, list("a", "b"), false)).getMessage());
        assertEquals("b.includes is not a function", assertThrows(IllegalArgumentException.class, () -> subset(ab, n(5), true)).getMessage());
        assertEquals("b.includes is not a function", assertThrows(IllegalArgumentException.class, () -> subset(ab, map("a", "b"), true)).getMessage());
        assertEquals("b.includes is not a function", assertThrows(IllegalArgumentException.class, () -> subset(ab, Boolean.TRUE, true)).getMessage());
        assertTrue(subset(ab, list("b", "a", "c"), true));
        assertFalse(subset(ab, list("a"), true));
        assertTrue(subset(ab, "xxabxx", true), "a string b is a substring test");
        assertFalse(subset(ab, "xxaxx", true));
        assertTrue(subset(new ArrayList<>(Arrays.asList("ab")), "xabx", true));
    }

    static boolean leq(Actions.Profile p, Object q) throws Exception { return (Boolean) call("jsLeq", new Class<?>[] {Actions.Profile.class, Object.class}, p, q); }

    static Map<String, Object> q(long risk, String rev, long blast, long esc) {
        return map("risk", n(risk), "rev", rev, "blast_ppm", n(blast), "esc", n(esc), "caveats", list(), "context", list(), "prules", list());
    }

    @Test void leqFollowsTheReferenceComparisons() throws Exception {
        Actions.Profile p = new Actions.Profile(2, "rate_limited", 5, 1, List.of(), List.of(), List.of());
        assertEquals("Cannot read properties of null (reading 'risk')", assertThrows(IllegalArgumentException.class, () -> leq(p, null)).getMessage());
        assertTrue(leq(p, q(2, "rate_limited", 5, 1)));
        assertTrue(leq(p, q(3, "irreversible", 6, 2)));
        assertFalse(leq(p, q(1, "irreversible", 6, 2)), "risk");
        assertFalse(leq(p, q(3, "reversible", 6, 2)), "rev");
        assertFalse(leq(p, q(3, "irreversible", 4, 2)), "blast_ppm");
        assertFalse(leq(p, q(3, "irreversible", 6, 0)), "esc");
        assertFalse(leq(p, q(3, "nonsense", 6, 2)), "an unranked rev");
        assertFalse(leq(p, "text"), "members of a primitive are undefined");
        assertFalse(leq(p, list(n(1))));
        Map<String, Object> noRisk = q(3, "irreversible", 6, 2);
        noRisk.remove("risk");
        assertFalse(leq(p, noRisk), "undefined is NaN: no comparison holds");
        Map<String, Object> nullRisk = q(3, "irreversible", 6, 2);
        nullRisk.put("risk", null);
        assertFalse(leq(p, nullRisk), "null is 0 and 2 <= 0 is false");
        Actions.Profile zero = new Actions.Profile(0, "reversible", 0, 0, List.of(), List.of(), List.of());
        nullRisk.put("rev", "irreversible");
        assertTrue(leq(zero, nullRisk), "null reads as 0");
        Actions.Profile withCaveat = new Actions.Profile(0, "reversible", 0, 0, List.of("amount_cap"), List.of(), List.of());
        Map<String, Object> noCaveats = q(3, "irreversible", 6, 2);
        noCaveats.remove("caveats");
        assertEquals("Cannot read properties of null (reading 'includes')", assertThrows(IllegalArgumentException.class, () -> leq(withCaveat, noCaveats)).getMessage());
        Map<String, Object> has = q(3, "irreversible", 6, 2);
        has.put("caveats", list("amount_cap"));
        assertTrue(leq(withCaveat, has));
        assertFalse(leq(withCaveat, q(3, "irreversible", 6, 2)));
    }

    // ---- registryOfSchema / schemaFloorError ----

    @Test void theCoreRegistryServesADocumentWithoutCustomTraits() {
        assertSame(CORE, Actions.registryOfSchema(map()));
        assertSame(CORE, Actions.registryOfSchema(map("trait_defs", list())));
        assertSame(CORE, Actions.registryOfSchema(map("trait_defs", "not a list")));
        Map<String, Object> custom = map("id", "x.one", "implies", list(), "floor", Actions.Profile.BOTTOM.toMap(), "card_phrase", "does one");
        Actions.Registry reg = Actions.registryOfSchema(map("trait_defs", list(custom)));
        assertNotNull(reg.traits.get("x.one"));
        assertTrue(reg.traits.containsKey("pca.bulk"));
        assertNull(CORE.traits.get("x.one"));
    }

    @Test void aDocumentThatBreaksTheEngineIsBadRegistry() {
        String e = Actions.schemaFloorError(map(), null);
        assertTrue(e.startsWith("bad_registry: java.lang.NullPointerException"), e);
        assertNotEquals("bad_registry: ", e);
        assertNull(Actions.schemaFloorError(map("verbs", list()), null));
        assertNull(Actions.schemaFloorError(map("verbs", list())));
    }
}
