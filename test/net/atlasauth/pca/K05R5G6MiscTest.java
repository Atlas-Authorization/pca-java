package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills (round 5, tag G6, first part): Pca.allocationsError, IntentJs number / equality helpers, IntentArtifacts.scalarEq and
 * isParamPath, RuntimeClaim.verifiedClass (self-signed claims) and the strict number guard of Json.numberError.
 */
public class K05R5G6MiscTest {

    static Json.Num n(long v) { return IntentJs.ofLong(v); }
    static Map<String, Object> obj(Object... kv) { return MeshK05KillTest.obj(kv); }
    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    // ---- Pca.allocationsError: null (not "") when every allocation is monotone ----

    @Test void allocationsMonotoneReturnsNull() {
        assertNull(Pca.allocationsError(list()));
        assertNull(Pca.allocationsError(list(obj("type", "scope"), obj("type", "budget_alloc", "limit", n(5)), obj("type", "budget_alloc", "limit", n(5)),
            obj("type", "budget_alloc", "limit", n(0)))));
        assertEquals("budget_alloc caveat 1: allocation 7 widens the parent's carried allocation 5 (monotone: a child can only allocate <= its parent)",
            Pca.allocationsError(list(obj("type", "budget_alloc", "limit", n(5)), obj("type", "budget_alloc", "limit", n(7)))));
        assertEquals("budget_alloc caveat 0: limit must be a finite number >= 0", Pca.allocationsError(list(obj("type", "budget_alloc", "limit", n(-1)))));
        assertEquals("budget_alloc caveat 0: limit must be a finite number >= 0", Pca.allocationsError(list(obj("type", "budget_alloc", "limit", "x"))));
    }

    // ---- IntentJs.isSafeInteger ----

    @Test void safeIntegerBoundaries() {
        assertTrue(IntentJs.isSafeInteger(9007199254740991L));
        assertTrue(IntentJs.isSafeInteger(-9007199254740991L));
        assertFalse(IntentJs.isSafeInteger(9007199254740992L));
        assertFalse(IntentJs.isSafeInteger(-9007199254740992L));
        assertTrue(IntentJs.isSafeInteger(0L));
        assertTrue(IntentJs.isSafeInteger(-0.0d));
        assertTrue(IntentJs.isSafeInteger(3.0d));
        assertTrue(IntentJs.isSafeInteger(new Json.Num("42")));
        assertTrue(IntentJs.isSafeInteger(new Json.Num("1e3")));
        assertFalse(IntentJs.isSafeInteger(1.5d));
        assertFalse(IntentJs.isSafeInteger(-1.5d));
        assertFalse(IntentJs.isSafeInteger(0.5d));
        assertFalse(IntentJs.isSafeInteger(new Json.Num("0.25")));
        assertFalse(IntentJs.isSafeInteger(Double.NaN));
        assertFalse(IntentJs.isSafeInteger(Double.POSITIVE_INFINITY));
        assertFalse(IntentJs.isSafeInteger(Double.NEGATIVE_INFINITY));
        assertFalse(IntentJs.isSafeInteger(1e300d));
        assertFalse(IntentJs.isSafeInteger(null));
        assertFalse(IntentJs.isSafeInteger("3"));
        assertFalse(IntentJs.isSafeInteger(Boolean.TRUE));
        assertFalse(IntentJs.isSafeInteger(list()));
        assertEquals(7L, IntentJs.lng(7.0d));
    }

    // ---- IntentJs.jsonEquals ----

    @Test void jsonEqualsTypesAndNulls() {
        assertTrue(IntentJs.jsonEquals(null, null));
        assertFalse(IntentJs.jsonEquals(null, 1L));
        assertFalse(IntentJs.jsonEquals(1L, null));
        assertFalse(IntentJs.jsonEquals(null, "a"));
        assertFalse(IntentJs.jsonEquals("a", null));
        assertFalse(IntentJs.jsonEquals(null, Boolean.FALSE));
        assertFalse(IntentJs.jsonEquals(Boolean.FALSE, null));
        assertFalse(IntentJs.jsonEquals(null, list()));
        assertFalse(IntentJs.jsonEquals(list(), null));
        assertFalse(IntentJs.jsonEquals(null, obj()));
        assertFalse(IntentJs.jsonEquals(obj(), null));
        assertTrue(IntentJs.jsonEquals("a", "a"));
        assertFalse(IntentJs.jsonEquals("a", "b"));
        assertFalse(IntentJs.jsonEquals("1", 1L));
        assertFalse(IntentJs.jsonEquals(1L, "1"));
        assertFalse(IntentJs.jsonEquals("true", Boolean.TRUE));
        assertFalse(IntentJs.jsonEquals(Boolean.TRUE, "true"));
        assertFalse(IntentJs.jsonEquals("a", list("a")));
        assertFalse(IntentJs.jsonEquals(list("a"), "a"));
        assertTrue(IntentJs.jsonEquals(Boolean.TRUE, Boolean.TRUE));
        assertFalse(IntentJs.jsonEquals(Boolean.TRUE, Boolean.FALSE));
        assertFalse(IntentJs.jsonEquals(Boolean.TRUE, 1L));
        assertFalse(IntentJs.jsonEquals(1L, Boolean.TRUE));
        assertFalse(IntentJs.jsonEquals(Boolean.FALSE, 0L));
        assertTrue(IntentJs.jsonEquals(1L, new Json.Num("1.0")));
        assertTrue(IntentJs.jsonEquals(new Json.Num("0"), new Json.Num("-0")));
        assertFalse(IntentJs.jsonEquals(1L, 2L));
        assertFalse(IntentJs.jsonEquals(Double.NaN, Double.NaN));
        assertFalse(IntentJs.jsonEquals(1L, list()));
    }

    // ---- IntentArtifacts.scalarEq ----

    @Test void scalarEqSameTypeAndValue() {
        assertTrue(IntentArtifacts.scalarEq("a", "a"));
        assertFalse(IntentArtifacts.scalarEq("a", "b"));
        assertFalse(IntentArtifacts.scalarEq("1", 1L));
        assertFalse(IntentArtifacts.scalarEq(1L, "1"));
        assertFalse(IntentArtifacts.scalarEq("true", Boolean.TRUE));
        assertFalse(IntentArtifacts.scalarEq(Boolean.TRUE, "true"));
        assertFalse(IntentArtifacts.scalarEq("", null));
        assertFalse(IntentArtifacts.scalarEq(null, ""));
        assertTrue(IntentArtifacts.scalarEq(Boolean.TRUE, Boolean.TRUE));
        assertTrue(IntentArtifacts.scalarEq(Boolean.FALSE, Boolean.FALSE));
        assertFalse(IntentArtifacts.scalarEq(Boolean.TRUE, Boolean.FALSE));
        assertFalse(IntentArtifacts.scalarEq(Boolean.TRUE, 1L));
        assertFalse(IntentArtifacts.scalarEq(1L, Boolean.TRUE));
        assertFalse(IntentArtifacts.scalarEq(Boolean.FALSE, 0L));
        assertFalse(IntentArtifacts.scalarEq(0L, Boolean.FALSE));
        assertFalse(IntentArtifacts.scalarEq(Boolean.FALSE, null));
        assertFalse(IntentArtifacts.scalarEq(null, Boolean.FALSE));
        assertTrue(IntentArtifacts.scalarEq(null, null));
        assertFalse(IntentArtifacts.scalarEq(null, 1L));
        assertFalse(IntentArtifacts.scalarEq(1L, null));
        assertTrue(IntentArtifacts.scalarEq(1L, new Json.Num("1")));
        assertTrue(IntentArtifacts.scalarEq(new Json.Num("5"), 5L));
        assertFalse(IntentArtifacts.scalarEq(1L, 2L));
    }

    @Test void paramPathShape() {
        assertTrue(IntentArtifacts.isParamPath("action.params.a"));
        assertTrue(IntentArtifacts.isParamPath("action.params.a.b"));
        assertTrue(IntentArtifacts.isParamPath("action.params.a.b.c.d.e.f.g.h"));
        assertFalse(IntentArtifacts.isParamPath("action.params.a.b.c.d.e.f.g.h.i"));
        assertFalse(IntentArtifacts.isParamPath("action.params."));
        assertFalse(IntentArtifacts.isParamPath("action.params"));
        assertFalse(IntentArtifacts.isParamPath("action.params.a."));
        assertFalse(IntentArtifacts.isParamPath("action.params..a"));
        assertFalse(IntentArtifacts.isParamPath("action.resource"));
        assertFalse(IntentArtifacts.isParamPath(null));
        assertFalse(IntentArtifacts.isParamPath(n(1)));
    }

    // ---- RuntimeClaim ----

    static final K05R5G2MeshTest.Key ATT = new K05R5G2MeshTest.Key("g6-attestor");
    static final String PD = "passport-digest-1", ED = "evidence-digest-1";

    static Map<String, Object> claim(Map<String, Object> over, boolean sign) {
        Map<String, Object> c = obj("v", n(1), "class", "os_confined", "passport_digest", PD, "evidence_digest", ED, "iat", n(1), "exp", n(100), "attestor", ATT.pub);
        c.putAll(over);
        Map<String, Object> body = new LinkedHashMap<>(c);
        body.remove("sig");
        c.put("sig", ATT.sign(Pca.concat(RuntimeClaim.DOMAIN.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body))));
        if (!sign) c.put("sig", ATT.sign(new byte[] {1}));
        return c;
    }
    static Map<String, Object> claim(Map<String, Object> over) { return claim(over, true); }
    static String cls(Object claim) { return cls(claim, PD, ED, n(50)); }
    static String cls(Object claim, String passport, String evidence, Object now) {
        return RuntimeClaim.verifiedClass(claim, List.of(ATT.pub), passport, List.of(evidence), now);
    }

    @Test void aSignedClaimGivesItsClass() {
        assertEquals("os_confined", cls(claim(obj())));
        for (String c : new String[] {"none", "os_confined", "egress_default_deny", "wasi_no_ambient"}) assertEquals(c, cls(claim(obj("class", c))));
        assertEquals("none", cls(claim(obj("class", "bogus"))));
        assertEquals("none", cls(claim(obj("class", n(5)))));
        assertEquals("none", cls(claim(obj("class", null))));
        assertEquals("none", cls("x"));
        assertEquals("none", cls(null));
        assertEquals("none", cls(claim(obj(), false)));
    }

    @Test void claimShapeIsClosed() {
        Map<String, Object> extra = claim(obj());
        extra.put("x", n(1));
        assertEquals("none", cls(extra));
        Map<String, Object> missing = claim(obj());
        missing.remove("exp");
        assertEquals("none", cls(missing));
        assertEquals("none", cls(claim(obj("v", n(2)))));
        assertEquals("none", cls(claim(obj("v", "1"))));
        assertEquals("none", cls(claim(obj("v", null))));
    }

    @Test void claimDigestsAreBoundedStrings() {
        String s128 = "d".repeat(128), s129 = "d".repeat(129);
        assertEquals("os_confined", cls(claim(obj("passport_digest", s128)), s128, ED, n(50)));
        assertEquals("none", cls(claim(obj("passport_digest", s129)), s129, ED, n(50)));
        assertEquals("none", cls(claim(obj("passport_digest", "")), "", ED, n(50)));
        assertEquals("none", cls(claim(obj("passport_digest", n(5))), PD, ED, n(50)));
        assertEquals("os_confined", cls(claim(obj("evidence_digest", s128)), PD, s128, n(50)));
        assertEquals("none", cls(claim(obj("evidence_digest", s129)), PD, s129, n(50)));
        assertEquals("none", cls(claim(obj("evidence_digest", "")), PD, "", n(50)));
        assertEquals("none", cls(claim(obj("evidence_digest", null)), PD, ED, n(50)));
        // the attestor must be a string that is the pinned key
        assertEquals("none", cls(claim(obj("attestor", "")), PD, ED, n(50)));
        assertEquals("none", cls(claim(obj("attestor", n(5))), PD, ED, n(50)));
    }

    @Test void claimTimeWindowIsHalfOpen() {
        assertEquals("os_confined", cls(claim(obj()), PD, ED, n(1)));
        assertEquals("none", cls(claim(obj()), PD, ED, n(0)));
        assertEquals("os_confined", cls(claim(obj()), PD, ED, n(99)));
        assertEquals("none", cls(claim(obj()), PD, ED, n(100)));
        assertEquals("none", cls(claim(obj("iat", n(-1))), PD, ED, n(50)));
        assertEquals("none", cls(claim(obj("iat", "1")), PD, ED, n(50)));
        assertEquals("none", cls(claim(obj("exp", "100")), PD, ED, n(50)));
        assertEquals("none", cls(claim(obj("exp", n(-1))), PD, ED, n(50)));
        assertEquals("none", cls(claim(obj("iat", n(-10), "exp", n(100))), PD, ED, n(-5)));
        assertEquals("none", cls(claim(obj()), PD, ED, "50"));
        assertEquals("none", cls(claim(obj()), PD, ED, null));
        assertEquals("none", cls(claim(obj()), PD, ED, new Json.Num("50.5")));
    }

    @Test void claimMustBePinnedAndMatchPassportAndEvidence() {
        assertEquals("none", RuntimeClaim.verifiedClass(claim(obj()), List.of("someone-else"), PD, List.of(ED), n(50)));
        assertEquals("none", RuntimeClaim.verifiedClass(claim(obj()), List.of(ATT.pub), "other-passport", List.of(ED), n(50)));
        assertEquals("none", RuntimeClaim.verifiedClass(claim(obj()), List.of(ATT.pub), PD, List.of("other-evidence"), n(50)));
        assertEquals("none", RuntimeClaim.verifiedClass(claim(obj()), List.of(ATT.pub), PD, List.of(), n(50)));
        assertEquals("os_confined", RuntimeClaim.verifiedClass(claim(obj()), List.of("x", ATT.pub), PD, List.of("y", ED), n(50)));
    }

    // ---- Json.numberError: an oversized integer lexeme is refused without parsing it ----

    @Test void hugeIntegerLexemeIsRefusedFast() {
        String huge = "1" + "0".repeat(1_500_000);
        String why = assertTimeoutPreemptively(Duration.ofSeconds(2), () -> Json.numberError(huge));
        assertEquals("integer outside the safe range", why);
        assertEquals("integer outside the safe range", Json.numberError("-" + "9".repeat(17)));
        assertEquals("integer outside the safe range", Json.numberError("9007199254740992"));
        assertNull(Json.numberError("9007199254740991"));
        assertNull(Json.numberError("-9007199254740991"));
        assertNull(Json.numberError("1234567890123456"));
    }
}
