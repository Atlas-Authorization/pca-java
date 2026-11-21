package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Parity with the TypeScript reference on three facade and canonical-JSON details. Every expected string is the reference's output
 * for the same input: the lenient canonical form prints a number as JSON.stringify does (hash.ts ser), a catalog resource is used as
 * given with only an absent one meaning '*' (facade.ts compilePolicy: s.resource ?? '*'), and a risk-policy weights override is
 * object-spread (facade.ts compilePolicy: {...riskPolicy.weights, ...(opts.riskPolicy.weights ?? {})}).
 */
public class ReferenceParityKillTest {
    static String canon(Object o) { return Json.canonicalize(o); }

    static Catalog bank() {
        return new Catalog(List.of(new Catalog.Spec("bank", "transfer", "bank.transfer", "reversible", 0.3, "amt", "t", null, null)));
    }

    // ---- lenient canonical numbers: JavaScript Number#toString -----------------------------------------------------------------

    @Test void lenientNumbersUseTheExponentFormAtAndAbove1e21AndBelow1e6() {
        String[][] cases = {
            {"1e21", "1e+21"}, {"1000000000000000000000", "1e+21"}, {"999999999999999999999", "1e+21"}, {"-1e21", "-1e+21"},
            {"1.2345e21", "1.2345e+21"}, {"1.7976931348623157e308", "1.7976931348623157e+308"},
            {"1e-7", "1e-7"}, {"0.0000001", "1e-7"}, {"-1.5e-7", "-1.5e-7"}, {"5e-324", "5e-324"},
            // just inside the plain range on both sides
            {"1e20", "100000000000000000000"}, {"0.0000010", "0.000001"}, {"123456789012345678", "123456789012345680"},
            // canonical lexemes as given; zero and negative zero print 0
            {"0.000001", "0.000001"}, {"-12.5", "-12.5"}, {"-0", "0"}, {"0.0", "0"}, {"1e-400", "0"}};
        for (String[] c : cases) assertEquals(c[1], canon(new Json.Num(c[0])), c[0]);
        assertEquals("[1e+21,{\"a\":1e-7}]", canon(Json.parseLenient("[1e21,{\"a\":1e-7}]")));
    }

    @Test void aFacadeNumberIsPlainTextSoTheStrictFormRefusesItForTheReferenceReason() {
        assertEquals("1000000000000000000000", ((Json.Num) Facade.jn(1e21)).raw);
        assertEquals("0.0000001", ((Json.Num) Facade.jn(1e-7)).raw);
        assertEquals("-0.00000015", ((Json.Num) Facade.jn(-1.5e-7)).raw);
        // the reference: 'integer outside the safe range (|n| > 2^53-1)' and 'non-integer magnitude below 1e-6 (...)'
        assertEquals("canonicalize: integer outside the safe range",
            assertThrows(IllegalArgumentException.class, () -> Json.canonicalizeStrict(Facade.jn(1e21))).getMessage());
        assertEquals("canonicalize: non-integer magnitude below 1e-6",
            assertThrows(IllegalArgumentException.class, () -> Json.canonicalizeStrict(Facade.jn(1e-7))).getMessage());
    }

    @Test void aCompiledLimitAtOrAbove1e21OrBelow1e6PrintsLikeTheReference() {
        Facade.CompiledPolicy big = Facade.compilePolicy(Map.of("bank", List.of("transfer")), Map.of("transfer", "$1000000000000000000000"),
            bank(), null, null, 1_000_000L);
        assertEquals("[{\"resource\":\"*\",\"verb\":\"bank.transfer\",\"where\":[{\"field\":\"action.params.amt\",\"op\":\"lte\",\"value\":1e+21},"
            + "{\"field\":\"action.params.amt\",\"op\":\"gte\",\"value\":0}]}]", canon(big.predicates));
        assertEquals("{\"bMax\":1e+21,\"kappa\":1e+21,\"lambda\":0,\"rho\":0.5,\"theta1\":1,\"theta2\":1,"
            + "\"weights\":{\"alpha\":0,\"beta\":0,\"delta\":0,\"epsilon\":0,\"gamma\":1,\"zeta\":0}}", canon(big.riskPolicy));
        assertEquals("{\"bank.transfer\":{\"amount\":1e+21,\"unit\":\"usd\"}}", canon(big.toJson().get("limits")));

        Facade.CompiledPolicy small = Facade.compilePolicy(Map.of("bank", List.of("transfer")), Map.of("transfer", "$0.0000001"),
            bank(), null, null, 1_000_000L);
        assertEquals("[{\"resource\":\"*\",\"verb\":\"bank.transfer\",\"where\":[{\"field\":\"action.params.amt\",\"op\":\"lte\",\"value\":1e-7},"
            + "{\"field\":\"action.params.amt\",\"op\":\"gte\",\"value\":0}]}]", canon(small.predicates));
        assertEquals("{\"bank.transfer\":{\"amount\":1e-7,\"unit\":\"usd\"}}", canon(small.toJson().get("limits")));

        Facade.CompiledPolicy rate = Facade.compilePolicy(Map.of("bank", List.of("transfer")), Map.of("transfer", "1000000000000000000000/day"),
            bank(), null, null, 1_000_000L);
        assertEquals("[{\"class\":\"reversible\",\"type\":\"reversibility_max\"},{\"at\":87400000,\"type\":\"expires\"},"
            + "{\"max\":1e+21,\"per_secs\":86400,\"type\":\"rate\"}]", canon(rate.caveats));
    }

    // ---- catalog resource -------------------------------------------------------------------------------------------------------

    @Test void aCatalogResourceIsUsedAsGivenAndOnlyAnAbsentOneIsAny() {
        assertNull(new Catalog.Spec("c", "n", "c.n", "reversible", 0.1, null, "d", null, null).resource);
        Catalog cat = new Catalog(List.of(
            new Catalog.Spec("c", "a", "c.a", "reversible", 0.1, null, "d", null, null, ""),
            new Catalog.Spec("c", "b", "c.b", "reversible", 0.1, null, "d", null, null, "repo:x"),
            new Catalog.Spec("c", "n", "c.n", "reversible", 0.1, null, "d", null, null, null)));
        Facade.CompiledPolicy p = Facade.compilePolicy(Map.of("c", List.of("a", "b", "n", "z")), null, cat, null, null, 0L);
        // an empty resource stays empty (never widened to '*'); an uncatalogued verb and a null resource are '*'
        assertEquals("[{\"resource\":\"\",\"verb\":\"c.a\"},{\"resource\":\"repo:x\",\"verb\":\"c.b\"},{\"resource\":\"*\",\"verb\":\"c.n\"},"
            + "{\"resource\":\"*\",\"verb\":\"c.z\"}]", canon(p.predicates));
    }

    // ---- weights override: object spread ----------------------------------------------------------------------------------------

    static final String DEFAULT_WEIGHTS = "\"alpha\":0.25,\"beta\":0.2,\"delta\":0.2,\"epsilon\":0.1,\"gamma\":0.2,\"zeta\":0.05";

    static String policyWith(Object weights) {
        Facade.CompiledPolicy p = Facade.compilePolicy(Map.of("bank", List.of("transfer")), null, bank(), null, Issue.obj("weights", weights), 0L);
        return canon(p.riskPolicy);
    }

    static String expect(String extra) {
        return "{\"bMax\":1,\"kappa\":1,\"lambda\":0.0005,\"rho\":0.5,\"theta1\":0.25,\"theta2\":0.6,\"weights\":{" + extra + DEFAULT_WEIGHTS + "}}";
    }

    @Test void aStringOrArrayWeightsSpreadsItsIndicesAndNothingElseIsAdded() {
        assertEquals(expect("\"0\":\"a\",\"1\":\"b\","), policyWith("ab"));
        assertEquals(expect("\"0\":0.5,\"1\":\"q\","), policyWith(new ArrayList<Object>(List.of(new Json.Num("0.5"), "q"))));
        assertEquals(expect(""), policyWith(""));
        assertEquals(expect(""), policyWith(new ArrayList<Object>()));
        assertEquals(expect(""), policyWith(7L));
        assertEquals(expect(""), policyWith(Boolean.TRUE));
        assertEquals(expect(""), policyWith(null));
        // a string spreads by UTF-16 code unit, as the reference does ("😀" has two)
        Map<String, Object> w = Pca.asMap(Facade.compilePolicy(Map.of("bank", List.of("transfer")), null, bank(), null,
            Issue.obj("weights", "😀"), 0L).riskPolicy.get("weights"));
        assertEquals("\uD83D", w.get("0"));
        assertEquals("\uDE00", w.get("1"));
        assertEquals(8, w.size());
        // an object still overrides a named weight
        assertEquals(expect("").replace("\"gamma\":0.2", "\"gamma\":1"), policyWith(Issue.obj("gamma", 1L)));
    }

    // ---- lone surrogates in the lenient canonical form: JSON.stringify escapes them, keys sort as the reference's compareUtf8 ------

    @Test void aLoneSurrogateIsEscapedAndSortsAsTheReferenceDoes() {
        assertEquals("[\"\\ud83d\",\"a\\ude00\",\"\uD83D\uDE00\"]", canon(new ArrayList<Object>(List.of("\uD83D", "a\uDE00", "\uD83D\uDE00"))));
        // a lone surrogate encodes as U+FFFD (after 'z'); equal bytes fall back to UTF-16 code-unit order (insertion order reversed here)
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("\uFFFD", 4L);
        m.put("\uD801", 3L);
        m.put("\uD800", 1L);
        m.put("z\uDE00", 5L);
        m.put("a", 2L);
        assertEquals("{\"a\":2,\"z\\ude00\":5,\"\\ud800\":1,\"\\ud801\":3,\"\uFFFD\":4}", canon(m));
        assertEquals(expect("\"0\":\"\\ud83d\",\"1\":\"\\ude00\","), policyWith("\uD83D\uDE00"));
    }
}
