package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for Actions.java lines 600-949 (sensitivity floors, worstReversibility and its JavaScript-semantics
 * helpers, normalize, impliedFromFacts). Expectations follow packages/pca-actions/src (normalize.ts, effective.ts).
 */
public class K05R4ActionsBKillTest {
    @SuppressWarnings("unchecked") static Map<String, Object> m(String j) { return (Map<String, Object>) Json.parse(j); }
    @SuppressWarnings("unchecked") static List<Object> l(String j) { return (List<Object>) Json.parse(j); }

    static String wr(String rev, String params) { return Actions.worstReversibility(Json.parse(rev), m(params)); }

    // ---- jsHasOwn / jsValues through worstReversibility ----------------------------------------------------------------------

    /** True iff the map covers the one-value domain {v}: then no default enters and an all-reversible map stays reversible. */
    static boolean covered(String mapJson, String v) {
        String r = wr("{\"by\":\"k\",\"map\":" + mapJson + ",\"default\":\"rate_limited\"}",
            "{\"k\":{\"type\":\"string\",\"values\":[" + Json.canonicalize(v) + "]}}");
        assertTrue(r.equals("reversible") || r.equals("rate_limited"), r);
        return r.equals("reversible");
    }

    @Test void hasOwnOnOneElementArray() {
        String a = "[\"reversible\"]";
        for (String k : new String[] {"0", "length"}) assertTrue(covered(a, k), k);
        for (String k : new String[] {"1", "-1", "01", "+0", "-0", "abc", "", "99999999999", "1.0", " 0"}) assertFalse(covered(a, k), k);
    }

    @Test void hasOwnOnTwoElementArray() {
        String a = "[\"reversible\",\"reversible\"]";
        for (String k : new String[] {"0", "1", "length"}) assertTrue(covered(a, k), k);
        assertFalse(covered(a, "2"));
        assertFalse(covered(a, "3"));
    }

    @Test void hasOwnOnEmptyArrayAndStrings() {
        assertTrue(covered("[]", "length"));
        assertFalse(covered("[]", "0"));
        assertTrue(covered("\"ab\"", "0"));
        assertTrue(covered("\"ab\"", "1"));
        assertTrue(covered("\"ab\"", "length"));
        assertFalse(covered("\"ab\"", "2"));
        assertTrue(covered("\"\"", "length"));
        assertFalse(covered("\"\"", "0"));
    }

    @Test void hasOwnOnNonContainers() {
        for (String mp : new String[] {"5", "true", "false"}) {
            assertFalse(covered(mp, "length"), mp);
            assertFalse(covered(mp, "0"), mp);
        }
    }

    @Test void hasOwnOnObjectIsKeyMembership() {
        assertTrue(covered("{\"x\":\"reversible\"}", "x"));
        assertFalse(covered("{\"x\":\"reversible\"}", "y"));
        assertFalse(covered("{\"x\":\"reversible\"}", "length"));
        assertFalse(covered("{\"0\":\"reversible\"}", "1"));
    }

    @Test void mapMemberMissingOrNullThrows() {
        String p = "{\"k\":{\"type\":\"boolean\"}}";
        for (String r : new String[] {"{\"by\":\"k\"}", "{\"by\":\"k\",\"map\":null}", "5", "true"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> wr(r, p), r);
            assertEquals("Cannot convert undefined or null to object", e.getMessage(), r);
        }
    }

    @Test void nullDeclarationThrowsItsOwnMessage() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> wr("null", "{}"));
        assertEquals("Cannot read properties of null (reading 'by')", e.getMessage());
    }

    @Test void arrayDeclarationHasNoMapValuesAndDefaultsIrreversible() {
        assertEquals("irreversible", wr("[]", "{}"));
        assertEquals("irreversible", wr("[\"rate_limited\"]", "{}"));
    }

    @Test void stringDeclarationIsReturnedAsIs() {
        assertEquals("rate_limited", wr("\"rate_limited\"", "{}"));
    }

    @Test void arrayMapValuesRankAndNonClassValuesAreIgnored() {
        // Object.values of an array map are its elements; the domain {"0"} is an own index, {"9"} is not
        String p = "{\"k\":{\"type\":\"string\",\"values\":[\"0\"]}}";
        String q = "{\"k\":{\"type\":\"string\",\"values\":[\"9\"]}}";
        assertEquals("rate_limited", wr("{\"by\":\"k\",\"map\":[\"reversible\",\"rate_limited\"]}", p));
        assertEquals("irreversible", wr("{\"by\":\"k\",\"map\":[\"irreversible\",\"rate_limited\"]}", p));
        assertEquals("reversible", wr("{\"by\":\"k\",\"map\":[\"bogus\",5,null,true,\"x\"],\"default\":\"reversible\"}", p));
        assertEquals("reversible", wr("{\"by\":\"k\",\"map\":[\"bogus\"]}", p));
        assertEquals("irreversible", wr("{\"by\":\"k\",\"map\":[\"bogus\"]}", q));
        assertEquals("rate_limited", wr("{\"by\":\"k\",\"map\":[\"rate_limited\"],\"default\":\"reversible\"}", q));
    }

    // ---- maxRev / jsRevRank -------------------------------------------------------------------------------------------------------

    @Test void booleanDomainCovered() {
        String p = "{\"k\":{\"type\":\"boolean\"}}";
        assertEquals("rate_limited", wr("{\"by\":\"k\",\"map\":{\"true\":\"rate_limited\",\"false\":\"reversible\"},\"default\":\"irreversible\"}", p));
        assertEquals("irreversible", wr("{\"by\":\"k\",\"map\":{\"true\":\"rate_limited\"},\"default\":\"irreversible\"}", p));
        assertEquals("irreversible", wr("{\"by\":\"k\",\"map\":{\"false\":\"rate_limited\"}}", p));
    }

    @Test void mappedValueRanksByStringAndOneElementArray() {
        String p = "{\"k\":{\"type\":\"boolean\"}}";
        String r = "{\"by\":\"k\",\"map\":{\"true\":%s,\"false\":%s}}";
        assertEquals("irreversible", wr(String.format(r, "\"irreversible\"", "\"reversible\""), p));
        assertEquals("rate_limited", wr(String.format(r, "\"rate_limited\"", "\"reversible\""), p));
        assertEquals("irreversible", wr(String.format(r, "[\"irreversible\"]", "\"reversible\""), p));
        assertEquals("rate_limited", wr(String.format(r, "[\"rate_limited\"]", "\"reversible\""), p));
        assertEquals("reversible", wr(String.format(r, "[\"bogus\"]", "\"reversible\""), p));
        assertEquals("reversible", wr(String.format(r, "7", "{}"), p));
        assertEquals("reversible", wr(String.format(r, "null", "true"), p));
        assertEquals("rate_limited", wr(String.format(r, "7", "\"rate_limited\""), p));
    }

    // ---- the `by` property key ---------------------------------------------------------------------------------------------------

    @Test void byIsAJavaScriptPropertyKey() {
        String dom = "{\"type\":\"boolean\"}";
        String map = "\"map\":{\"true\":\"rate_limited\",\"false\":\"rate_limited\"}";
        // covered by the boolean domain -> rate_limited; an uncovered lookup would add the irreversible default
        assertEquals("rate_limited", wr("{\"by\":1," + map + "}", "{\"1\":" + dom + "}"));
        assertEquals("rate_limited", wr("{\"by\":true," + map + "}", "{\"true\":" + dom + "}"));
        assertEquals("rate_limited", wr("{\"by\":[\"k\"]," + map + "}", "{\"k\":" + dom + "}"));
        assertEquals("rate_limited", wr("{\"by\":null," + map + "}", "{\"null\":" + dom + "}"));
        assertEquals("irreversible", wr("{\"by\":null," + map + "}", "{\"undefined\":" + dom + "}"));
        assertEquals("rate_limited", wr("{" + map + "}", "{\"undefined\":" + dom + "}"));
        assertEquals("irreversible", wr("{" + map + "}", "{\"null\":" + dom + "}"));
        assertEquals("rate_limited", wr("{\"by\":\"k\"," + map + "}", "{\"k\":" + dom + "}"));
    }

    // ---- truthy / domain.every ---------------------------------------------------------------------------------------------------

    static String tv(Object values) {
        Map<String, Object> k = new LinkedHashMap<>();
        k.put("type", "string");
        k.put("values", values);
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("k", k);
        try { return Actions.worstReversibility(Json.parse("{\"by\":\"k\",\"map\":{},\"default\":\"rate_limited\"}"), params); }
        catch (IllegalArgumentException e) { return "THROW:" + e.getMessage(); }
    }

    @Test void valuesTruthinessDecidesDomain() {
        String boom = "THROW:domain.every is not a function";
        assertEquals("rate_limited", tv(null));
        assertEquals("rate_limited", tv(Boolean.FALSE));
        assertEquals(boom, tv(Boolean.TRUE));
        assertEquals("rate_limited", tv(""));
        assertEquals(boom, tv("x"));
        assertEquals("rate_limited", tv(new Json.Num("0")));
        assertEquals("rate_limited", tv(new Json.Num("-0")));
        assertEquals("rate_limited", tv(new Json.Num("0.0")));
        assertEquals("rate_limited", tv(new Json.Num("NaN")));
        assertEquals(boom, tv(new Json.Num("1")));
        assertEquals(boom, tv(new Json.Num("-1")));
        assertEquals(boom, tv(new Json.Num("2.5")));
        assertEquals(boom, tv(m("{}")));
        assertEquals("reversible", tv(l("[]")));          // an empty enum is covered vacuously
        assertEquals("rate_limited", tv(l("[\"a\"]")));   // "a" is not a key of the empty map
    }

    @Test void nonStringDomainEntriesAreStringifiedLikeJs() {
        String p = "{\"k\":{\"type\":\"string\",\"values\":[1]}}";
        assertEquals("reversible", wr("{\"by\":\"k\",\"map\":{\"1\":\"reversible\"},\"default\":\"irreversible\"}", p));
        assertEquals("irreversible", wr("{\"by\":\"k\",\"map\":{\"2\":\"reversible\"},\"default\":\"irreversible\"}", p));
        String q = "{\"k\":{\"type\":\"string\",\"values\":[[\"a\"],\"b\"]}}";
        assertEquals("reversible", wr("{\"by\":\"k\",\"map\":{\"a\":\"reversible\",\"b\":\"reversible\"},\"default\":\"irreversible\"}", q));
        String n = "{\"k\":{\"type\":\"string\",\"values\":[null]}}";
        assertEquals("reversible", wr("{\"by\":\"k\",\"map\":{\"null\":\"reversible\"},\"default\":\"irreversible\"}", n));
    }

    @Test void stringDomainWithoutValuesIsUncovered() {
        assertEquals("rate_limited", wr("{\"by\":\"k\",\"map\":{},\"default\":\"rate_limited\"}", "{\"k\":{\"type\":\"string\"}}"));
        assertEquals("rate_limited", wr("{\"by\":\"k\",\"map\":{},\"default\":\"rate_limited\"}", "{\"k\":{\"type\":\"number\",\"values\":[\"a\"]}}"));
        assertEquals("irreversible", wr("{\"by\":\"k\",\"map\":{},\"default\":null}", "{}"));
    }

    // ---- sensitivity -------------------------------------------------------------------------------------------------------------

    @Test void sensitivityFloorFromRoleAndTags() {
        assertEquals("critical", Actions.sensitivityFloor(m("{\"role\":\"money.amount\"}")));
        assertEquals("material", Actions.sensitivityFloor(m("{\"role\":\"money.currency\"}")));
        assertEquals("free", Actions.sensitivityFloor(m("{\"role\":\"zzz\"}")));
        assertEquals("free", Actions.sensitivityFloor(m("{\"role\":[\"money.amount\"]}")));
        assertEquals("free", Actions.sensitivityFloor(m("{\"role\":null}")));
        assertEquals("free", Actions.sensitivityFloor(m("{}")));
        assertEquals("material", Actions.sensitivityFloor(m("{\"tags\":[\"pii\"]}")));
        assertEquals("critical", Actions.sensitivityFloor(m("{\"tags\":[\"pii\",\"secret\"]}")));
        assertEquals("critical", Actions.sensitivityFloor(m("{\"tags\":[\"secret\",\"pii\"]}")));
        assertEquals("free", Actions.sensitivityFloor(m("{\"tags\":[\"zzz\"]}")));
        assertEquals("free", Actions.sensitivityFloor(m("{\"tags\":[5]}")));
        assertEquals("critical", Actions.sensitivityFloor(m("{\"role\":\"money.currency\",\"tags\":[\"secret\"]}")));
        assertEquals("critical", Actions.sensitivityFloor(m("{\"role\":\"money.amount\",\"tags\":[\"pii\"]}")));
        // a string iterates its characters (no tag), null iterates nothing: neither is a List
        assertEquals("free", Actions.sensitivityFloor(m("{\"tags\":\"pii\"}")));
        assertEquals("free", Actions.sensitivityFloor(m("{\"tags\":null}")));
    }

    @Test void effectiveSensitivityIsDeclaredRaisedToFloor() {
        assertEquals("critical", Actions.effectiveParamSensitivity(m("{\"sensitivity\":\"critical\",\"role\":\"money.currency\"}")));
        assertEquals("material", Actions.effectiveParamSensitivity(m("{\"role\":\"money.currency\"}")));
        assertEquals("material", Actions.effectiveParamSensitivity(m("{\"sensitivity\":\"free\",\"tags\":[\"pii\"]}")));
        assertEquals("critical", Actions.effectiveParamSensitivity(m("{\"sensitivity\":\"critical\"}")));
        assertEquals("material", Actions.effectiveParamSensitivity(m("{\"sensitivity\":\"material\"}")));
        assertEquals("free", Actions.effectiveParamSensitivity(m("{}")));
    }

    // ---- normalize ---------------------------------------------------------------------------------------------------------------

    static Map<String, Object> def(String rev, String params, String more) {
        return m("{\"kind\":\"action\",\"verb\":\"x.y\",\"aliases\":[\"b\",\"a\"],\"title\":\"T\",\"effects\":[\"update\"],"
            + "\"resource\":{\"type\":\"t\",\"id\":\"i\",\"scope\":\"one\"},\"params\":" + params + ",\"reversibility\":" + rev
            + ",\"context\":[],\"traits\":[]" + more + "}");
    }

    @SuppressWarnings("unchecked") static Map<String, Object> mm(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    @Test void bindingsAreDeepCopied() {
        Map<String, Object> d = def("\"reversible\"", "{}", ",\"bindings\":{\"a\":{\"b\":{\"c\":[1,{\"d\":\"x\"},[\"z\"]]}},\"l\":[[\"q\"],{\"r\":[]}],\"s\":\"t\",\"n\":null}");
        Map<String, Object> out = Actions.normalize(d);
        Object in = d.get("bindings"), got = out.get("bindings");
        assertEquals(Json.canonicalize(in), Json.canonicalize(got));
        assertNotSame(in, got);
        Map<String, Object> ia = mm(mm(in).get("a")), ga = mm(mm(got).get("a"));
        assertNotSame(ia, ga);
        assertNotSame(ia.get("b"), ga.get("b"));
        List<Object> ic = (List<Object>) mm(ia.get("b")).get("c"), gc = (List<Object>) mm(ga.get("b")).get("c");
        assertNotSame(ic, gc);
        assertNotSame(ic.get(1), gc.get(1));
        assertNotSame(ic.get(2), gc.get(2));
        assertEquals(3, gc.size());
        List<Object> il = (List<Object>) mm(in).get("l"), gl = (List<Object>) mm(got).get("l");
        assertNotSame(il, gl);
        assertNotSame(il.get(0), gl.get(0));
        assertNotSame(il.get(1), gl.get(1));
        assertEquals("t", mm(got).get("s"));
        assertTrue(mm(got).containsKey("n"));
        assertNull(mm(got).get("n"));
        // mutating the copy leaves the source alone
        mm(got).put("extra", 1);
        assertFalse(mm(in).containsKey("extra"));
        assertEquals("{}", Json.canonicalize(Actions.normalize(def("\"reversible\"", "{}", "")).get("bindings")));
    }

    @Test void sideEffectsSortByTargetThenKind() {
        String exp = Json.canonicalize(Json.parse("[{\"target\":\"a\",\"kind\":\"y\"},{\"target\":\"a\",\"kind\":\"z\"},{\"target\":\"b\",\"kind\":\"w\"},{\"target\":\"b\",\"kind\":\"x\"},{\"target\":\"c\",\"kind\":\"a\"}]"));
        String[] orders = {
            "[{\"target\":\"b\",\"kind\":\"x\"},{\"target\":\"a\",\"kind\":\"z\"},{\"target\":\"a\",\"kind\":\"y\"},{\"target\":\"b\",\"kind\":\"w\"},{\"target\":\"c\",\"kind\":\"a\"}]",
            "[{\"target\":\"c\",\"kind\":\"a\"},{\"target\":\"b\",\"kind\":\"x\"},{\"target\":\"b\",\"kind\":\"w\"},{\"target\":\"a\",\"kind\":\"z\"},{\"target\":\"a\",\"kind\":\"y\"}]",
            "[{\"target\":\"a\",\"kind\":\"y\"},{\"target\":\"a\",\"kind\":\"z\"},{\"target\":\"b\",\"kind\":\"w\"},{\"target\":\"b\",\"kind\":\"x\"},{\"target\":\"c\",\"kind\":\"a\"}]",
            "[{\"target\":\"b\",\"kind\":\"w\"},{\"target\":\"a\",\"kind\":\"z\"},{\"target\":\"c\",\"kind\":\"a\"},{\"target\":\"a\",\"kind\":\"y\"},{\"target\":\"b\",\"kind\":\"x\"}]"};
        for (String o : orders) assertEquals(exp, Json.canonicalize(Actions.normalize(def("\"reversible\"", "{}", ",\"side_effects\":" + o)).get("side_effects")), o);
        // extra members of a side effect are dropped; equal pairs stay
        assertEquals(Json.canonicalize(Json.parse("[{\"target\":\"a\",\"kind\":\"k\"},{\"target\":\"a\",\"kind\":\"k\"}]")),
            Json.canonicalize(Actions.normalize(def("\"reversible\"", "{}", ",\"side_effects\":[{\"target\":\"a\",\"kind\":\"k\",\"z\":1},{\"target\":\"a\",\"kind\":\"k\"}]")).get("side_effects")));
        assertEquals("[]", Json.canonicalize(Actions.normalize(def("\"reversible\"", "{}", "")).get("side_effects")));
    }

    @Test void reversibilityMapIsRebuiltFromByMapDefaultOnly() {
        Map<String, Object> d = def("{\"by\":\"k\",\"map\":{\"a\":\"reversible\"},\"extra\":1}", "{\"k\":{\"type\":\"string\",\"values\":[\"a\"]}}", "");
        Map<String, Object> out = Actions.normalize(d);
        assertEquals(Json.canonicalize(Json.parse("{\"by\":\"k\",\"map\":{\"a\":\"reversible\"}}")), Json.canonicalize(out.get("reversibility")));
        assertNotSame(mm(d.get("reversibility")).get("map"), mm(out.get("reversibility")).get("map"));
        Map<String, Object> d2 = def("{\"by\":\"k\",\"map\":{\"a\":\"reversible\"},\"default\":\"rate_limited\"}", "{\"k\":{\"type\":\"string\",\"values\":[\"a\"]}}", "");
        assertEquals(Json.canonicalize(Json.parse("{\"by\":\"k\",\"map\":{\"a\":\"reversible\"},\"default\":\"rate_limited\"}")), Json.canonicalize(Actions.normalize(d2).get("reversibility")));
        assertEquals("irreversible", Actions.normalize(def("\"irreversible\"", "{}", "")).get("reversibility"));
        assertEquals("rate_limited", Actions.normalize(def("\"rate_limited\"", "{}", "")).get("reversibility"));
    }

    @Test void paramValuesCopiedAndAbsentValuesStayAbsent() {
        Map<String, Object> d = def("\"reversible\"", "{\"a\":{\"type\":\"string\",\"values\":[\"y\",\"x\"]},\"b\":{\"type\":\"number\"}}", "");
        Map<String, Object> ps = mm(Actions.normalize(d).get("params"));
        Object in = mm(mm(d.get("params")).get("a")).get("values"), got = mm(ps.get("a")).get("values");
        assertEquals("[\"y\",\"x\"]", Json.canonicalize(got));
        assertNotSame(in, got);
        assertFalse(mm(ps.get("b")).containsKey("values"));
        assertEquals(Boolean.TRUE, mm(ps.get("b")).get("required"));
        assertEquals("free", mm(ps.get("b")).get("sensitivity"));
    }

    @Test void moneyAmountAccumulatesOnlyWithAMoneyUnitCurrency() {
        String ps = "{"
            + "\"p1\":{\"type\":\"number\",\"role\":\"money.amount\",\"unit\":{\"kind\":\"money\",\"ccy\":\"USD\"}},"
            + "\"p2\":{\"type\":\"number\",\"role\":\"money.fee\",\"unit\":{\"kind\":\"money\",\"ccy\":\"USD\"}},"
            + "\"p3\":{\"type\":\"number\",\"role\":\"money.amount\"},"
            + "\"p4\":{\"type\":\"number\",\"role\":\"money.amount\",\"unit\":{\"kind\":\"count\",\"ccy\":\"USD\"}},"
            + "\"p5\":{\"type\":\"number\",\"role\":\"money.amount\",\"unit\":{\"kind\":\"money\",\"ccy\":5}},"
            + "\"p6\":{\"type\":\"number\",\"role\":\"money.amount\",\"unit\":{\"kind\":\"money\",\"ccy\":\"USD\"},\"accumulates\":[\"z\",\"a\",\"z\"]},"
            + "\"p7\":{\"type\":\"number\",\"role\":\"money.amount\",\"unit\":\"money\"},"
            + "\"p8\":{\"type\":\"number\",\"role\":\"money.amount\",\"unit\":{\"kind\":\"money\"}},"
            + "\"p9\":{\"type\":\"number\",\"unit\":{\"kind\":\"money\",\"ccy\":\"USD\"}}}";
        Map<String, Object> out = mm(Actions.normalize(def("\"reversible\"", ps, "")).get("params"));
        assertEquals("[\"money.usd\"]", Json.canonicalize(mm(out.get("p1")).get("accumulates")));
        for (String k : new String[] {"p2", "p3", "p4", "p5", "p7", "p8", "p9"}) assertFalse(mm(out.get(k)).containsKey("accumulates"), k);
        assertEquals("[\"a\",\"z\"]", Json.canonicalize(mm(out.get("p6")).get("accumulates")));
    }

    // ---- impliedFromFacts ---------------------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    static List<String> imp(String effects, String params) {
        return Actions.impliedFromFacts(l(effects), (List<Map<String, Object>>) (List<?>) l(params), null, "reversible");
    }

    @Test void effectsMayBeOneElementArraysAndUnknownOnesThrow() {
        assertEquals(List.of("pca.external_communication"), imp("[\"send\"]", "[]"));
        assertEquals(List.of("pca.external_communication"), imp("[[\"send\"]]", "[]"));
        assertEquals(List.of("pca.destructive", "pca.external_communication"), imp("[[\"delete\"],\"send\"]", "[]"));
        assertEquals(List.of(), imp("[\"read\"]", "[]"));
        for (String[] c : new String[][] {{"[\"foo\"]", "foo"}, {"[5]", "5"}, {"[[\"nope\",\"x\"]]", "nope,x"}, {"[null]", "null"}, {"[\"read\",\"zzz\"]", "zzz"}}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> imp(c[0], "[]"), c[0]);
            assertEquals("unknown effect " + c[1], e.getMessage(), c[0]);
        }
    }

    @Test void rolesMayBeOneElementArraysAndReadOnlyNeedsStringRoles() {
        assertEquals(List.of("pca.credential_access"), imp("[\"update\"]", "[{\"role\":\"credential.key\"}]"));
        assertEquals(List.of("pca.credential_access"), imp("[\"update\"]", "[{\"role\":[\"credential.key\"]}]"));
        assertEquals(List.of("pca.network_egress"), imp("[\"update\"]", "[{\"role\":[\"url.target\"]}]"));
        assertEquals(List.of(), imp("[\"update\"]", "[{\"role\":[\"zzz\"]}]"));
        assertEquals(List.of(), imp("[\"update\"]", "[{\"role\":5}]"));
        assertEquals(List.of(), imp("[\"update\"]", "[{\"role\":\"zzz\"}]"));
        assertEquals(List.of(), imp("[\"update\"]", "[{\"role\":\"money.amount\"}]"));
        assertEquals(List.of("pca.financial_data_read"), imp("[\"read\"]", "[{\"role\":\"money.amount\"}]"));
        assertEquals(List.of("pca.credential_access"), imp("[\"read\"]", "[{\"role\":\"credential.key\"}]"));
        assertEquals(List.of(), imp("[\"read\"]", "[{\"role\":\"text.message\"}]"));
        for (String role : new String[] {"[\"money.amount\"]", "5", "[\"credential.key\"]", "{}", "true"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> imp("[\"read\"]", "[{\"role\":" + role + "}]"), role);
            assertEquals("p.role.startsWith is not a function", e.getMessage(), role);
        }
    }

    @Test void tagsAreLooksUpsByStringifiedElement() {
        assertEquals(List.of("pca.pii_access", "pca.regulated_data"), imp("[\"update\"]", "[{\"tags\":[\"pii\",\"zzz\",[\"phi\"],5]}]"));
        assertEquals(List.of("pca.credential_access"), imp("[\"update\"]", "[{\"tags\":[[\"secret\"]]}]"));
        assertEquals(List.of(), imp("[\"update\"]", "[{\"tags\":[\"zzz\"]}]"));
        assertEquals(List.of(), imp("[\"update\"]", "[{\"tags\":[[\"zzz\"],7]}]"));
        assertEquals(List.of("pca.pii_access"), imp("[\"update\"]", "[{\"tags\":[\"pii\"]}]"));
        assertEquals(List.of("pca.regulated_data"), imp("[\"update\"]", "[{\"tags\":[\"pci\"]}]"));
        assertEquals(List.of(), imp("[\"update\"]", "[{\"tags\":\"pii\"}]"));
        assertEquals(List.of(), imp("[\"update\"]", "[{\"tags\":null}]"));
        assertEquals(List.of(), imp("[\"update\"]", "[{}]"));
        for (String tags : new String[] {"5", "true", "{}", "{\"pii\":1}"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> imp("[\"update\"]", "[{\"tags\":" + tags + "}]"), tags);
            assertEquals("tags is not iterable", e.getMessage(), tags);
        }
    }
}
