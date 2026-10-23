package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Unit tests for Json (numbers, serializers, parser edges), Pq (suites, ML-DSA seam) and Threshold (share binding). */
public class JsonPqThresholdUnitTest {
    static Json.Num n(String s) { return new Json.Num(s); }
    static Map<String, Object> map(Object... kv) { return PcaUnitTest.map(kv); }

    static String err(String raw) { return Json.numberError(raw); }

    @Test void numberErrors() {
        assertEquals("malformed number", err(null));
        for (String s : new String[] {"", "01", ".5", "1.", "+1", "1e", "--1", "-", "1.e1", "0x1", "1 ", " 1", "1e+", "abc", "-01", "00"})
            assertEquals("malformed number", err(s), s);
        assertEquals("exponent form is not allowed", err("1e5"));
        assertEquals("exponent form is not allowed", err("1E5"));
        assertEquals("exponent form is not allowed", err("1.5e5"));
        assertEquals("exponent form is not allowed", err("-1E-5"));
        assertEquals("negative zero is not allowed", err("-0"));
        assertNull(err("0"));
        assertEquals("trailing fractional zero is not canonical", err("1.50"));
        assertEquals("trailing fractional zero is not canonical", err("0.0"));
        assertEquals("trailing fractional zero is not canonical", err("-0.0"));
        assertNull(err("0.5"));
        assertNull(err("-0.5"));
        assertNull(err("12345678901234.5"));            // 15 significant digits
        assertNull(err("-12345678901234.5"));
        assertEquals("more than 15 significant digits", err("123456789012345.5"));
        assertEquals("more than 15 significant digits", err("-123456789012345.5"));
        assertEquals("more than 15 significant digits", err("1234567890123456.5"));
        assertNull(err("0.000001"));
        assertNull(err("-0.000001"));
        assertNull(err("0.000012345678901"));          // leading zeros are not significant
        assertEquals("non-integer magnitude below 1e-6", err("0.0000001"));
        assertEquals("non-integer magnitude below 1e-6", err("-0.0000001"));
        assertNull(err("9007199254740991"));
        assertNull(err("-9007199254740991"));
        assertEquals("integer outside the safe range", err("9007199254740992"));
        assertEquals("integer outside the safe range", err("-9007199254740992"));
        assertEquals("integer outside the safe range", err("10000000000000000"));
        assertEquals("integer outside the safe range", err("99999999999999999999"));
        assertNull(err("1000000000000000"));
        assertNull(err("-5"));
        assertNull(err("123"));
    }

    @Test void numberKinds() {
        assertTrue(Json.isSafeInt(n("5")));
        assertTrue(Json.isSafeInt(n("-5")));
        assertFalse(Json.isSafeInt(n("5.5")));
        assertFalse(Json.isSafeInt(n("1.0")));
        assertFalse(Json.isSafeInt(n("-0")));
        assertFalse(Json.isSafeInt(n("9007199254740992")));
        assertTrue(Json.isSafeInt(n("9007199254740991")));
        assertTrue(Json.isSafeInt(5));
        assertTrue(Json.isSafeInt(-5));
        assertTrue(Json.isSafeInt(9007199254740991L));
        assertTrue(Json.isSafeInt(-9007199254740991L));
        assertFalse(Json.isSafeInt(9007199254740992L));
        assertFalse(Json.isSafeInt(-9007199254740992L));
        assertFalse(Json.isSafeInt(Long.MIN_VALUE));
        assertFalse(Json.isSafeInt(Long.MAX_VALUE));
        assertFalse(Json.isSafeInt(5.0));
        assertFalse(Json.isSafeInt("5"));
        assertFalse(Json.isSafeInt(null));
        assertTrue(Json.isStrictNumber(n("5")));
        assertTrue(Json.isStrictNumber(n("5.5")));
        assertFalse(Json.isStrictNumber(n("1e5")));
        assertFalse(Json.isStrictNumber(n("1.0")));
        assertTrue(Json.isStrictNumber(5));
        assertTrue(Json.isStrictNumber(7L));
        assertFalse(Json.isStrictNumber(Long.MAX_VALUE));
        assertFalse(Json.isStrictNumber("5"));
        assertFalse(Json.isStrictNumber(null));
        assertFalse(Json.isStrictNumber(5.5));
        assertEquals(5L, Json.asLong(n("5")));
        assertEquals(-7L, Json.asLong(n("-7")));
        assertEquals(7L, Json.asLong(7));
        assertEquals(9007199254740991L, Json.asLong(9007199254740991L));
        assertEquals(new BigDecimal("1.5"), Json.asDecimal(n("1.5")));
        assertEquals(new BigDecimal("-0.000001"), Json.asDecimal(n("-0.000001")));
        assertEquals(new BigDecimal("7"), Json.asDecimal(7));
        assertEquals(new BigDecimal("9007199254740991"), Json.asDecimal(9007199254740991L));
        assertEquals("1.50", n("1.50").toString());
        assertEquals("12", n("12").raw);
    }

    @Test void surrogates() {
        assertFalse(Json.hasLoneSurrogate(""));
        assertFalse(Json.hasLoneSurrogate("abc"));
        assertFalse(Json.hasLoneSurrogate("\ud83d\ude00"));
        assertFalse(Json.hasLoneSurrogate("a\ud83d\ude00b"));
        assertFalse(Json.hasLoneSurrogate("\ud83d\ude00\ud83d\ude00"));
        assertTrue(Json.hasLoneSurrogate("\ud83d"));
        assertTrue(Json.hasLoneSurrogate("\ude00"));
        assertTrue(Json.hasLoneSurrogate("\ude00\ud83d"));
        assertTrue(Json.hasLoneSurrogate("\ud83dx"));
        assertTrue(Json.hasLoneSurrogate("a\ud83d"));
        assertTrue(Json.hasLoneSurrogate("\ud83d\ud83d\ude00"));
        assertTrue(Json.hasLoneSurrogate("\ud83d\ude00\ude00"));
    }

    @Test void canonicalForms() {
        assertEquals("null", Json.canonicalize(null));
        assertEquals("true", Json.canonicalize(true));
        assertEquals("false", Json.canonicalize(false));
        assertEquals("5", Json.canonicalize(5));
        assertEquals("-5", Json.canonicalize(-5L));
        assertEquals("[]", Json.canonicalize(new ArrayList<>()));
        assertEquals("{}", Json.canonicalize(map()));
        assertEquals("[1,2,3]", Json.canonicalize(new ArrayList<>(List.of(1, 2, 3))));
        assertEquals("{\"a\":1,\"b\":[true,null]}", Json.canonicalize(map("b", new ArrayList<>(java.util.Arrays.asList(true, null)), "a", 1)));
        // keys in UTF-8 byte order: B < a < e-acute < fullwidth tilde < emoji (UTF-16 order would put the emoji before the tilde)
        assertEquals("{\"B\":1,\"a\":2,\"\u00e9\":3,\"\uff5e\":4,\"\ud83d\ude00\":5}", Json.canonicalize(map("\ud83d\ude00", 5, "\uff5e", 4, "\u00e9", 3, "a", 2, "B", 1)));
        assertEquals("\"\\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f \u007f\"", Json.canonicalize("\"\\\b\f\n\r\t\u0001\u001f \u007f"));
        assertEquals("\"\u00e9\ud83d\ude00\"", Json.canonicalize("\u00e9\ud83d\ude00"));
        assertEquals("\"\ufffd\"", Json.canonicalize("\ud83d"));
        assertEquals("\"\ufffdx\"", Json.canonicalize("\ud83dx"));
        assertEquals("\"\ufffd\"", Json.canonicalize("\ude00"));
        assertEquals("\"a\ufffd\"", Json.canonicalize("a\ud83d"));
        assertEquals("\"\ufffd\ud83d\ude00\"", Json.canonicalize("\ud83d\ud83d\ude00"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Json.canonicalizeStrict("\ud83d"));
        assertEquals("canonicalize: lone surrogate in string", e.getMessage());
        e = assertThrows(IllegalArgumentException.class, () -> Json.canonicalizeStrict(map("\ude00", 1)));
        assertEquals("canonicalize: lone surrogate in string", e.getMessage());
        // lenient number formatting
        assertEquals("100000", Json.canonicalize(n("1e5")));
        assertEquals("1.5", Json.canonicalize(n("1.50")));
        assertEquals("0", Json.canonicalize(n("-0")));
        assertEquals("0", Json.canonicalize(n("0.0")));
        assertEquals("0", Json.canonicalize(n("1e-400")));
        assertEquals("1", Json.canonicalize(n("1.0")));
        assertEquals("123456789012345680", Json.canonicalize(n("123456789012345678")));
        assertEquals("12", Json.canonicalize(n("12")));
        assertEquals("-12.5", Json.canonicalize(n("-12.5")));
        assertEquals("0.1", Json.canonicalize(n("1e-1")));
        assertEquals("canonicalize: non-finite number", assertThrows(IllegalArgumentException.class, () -> Json.canonicalize(n("1e400"))).getMessage());
        assertEquals("canonicalize: non-finite number", assertThrows(IllegalArgumentException.class, () -> Json.canonicalize(n("-1e400"))).getMessage());
        assertEquals("1", Json.fmtNumber("1"));
        assertEquals("1.5", Json.fmtNumber("1.5"));
        assertEquals("1.5", Json.fmtNumber("1.50"));
        // strict
        assertEquals("[1,1.5]", Json.canonicalizeStrict(new ArrayList<>(List.of(n("1"), n("1.5")))));
        assertEquals("canonicalize: exponent form is not allowed", assertThrows(IllegalArgumentException.class, () -> Json.canonicalizeStrict(n("1e5"))).getMessage());
        assertEquals("canonicalize: integer outside the safe range", assertThrows(IllegalArgumentException.class, () -> Json.canonicalizeStrict(9007199254740992L)).getMessage());
        assertEquals("9007199254740991", Json.canonicalizeStrict(9007199254740991L));
        assertEquals("5", Json.canonicalizeStrict(5));
        assertEquals("9007199254740992", Json.canonicalize(9007199254740992L));
        assertEquals("canonicalize: unsupported type class java.lang.Double", assertThrows(IllegalArgumentException.class, () -> Json.canonicalize(1.5)).getMessage());
        assertEquals("canonicalize: unsupported type class java.lang.Double", assertThrows(IllegalArgumentException.class, () -> Json.canonicalizeStrict(1.5)).getMessage());
        assertEquals("canonicalize: unsupported type class java.lang.Object", assertThrows(IllegalArgumentException.class, () -> Json.canonicalize(new ArrayList<>(List.of(new Object())))).getMessage());
        // depth: the top-level container is depth 1; 32 nested ok, 33 too deep (strict only)
        Object a = 1;
        for (int i = 0; i < 32; i++) a = new ArrayList<>(List.of(a));
        assertNotNull(Json.canonicalizeStrict(a));
        Object a33 = new ArrayList<>(List.of(a));
        assertEquals("canonicalize: nesting too deep", assertThrows(IllegalArgumentException.class, () -> Json.canonicalizeStrict(a33)).getMessage());
        assertNotNull(Json.canonicalize(a33));
        Object o = 1;
        for (int i = 0; i < 32; i++) o = map("k", o);
        assertNotNull(Json.canonicalizeStrict(o));
        Object o33 = map("k", o);
        assertEquals("canonicalize: nesting too deep", assertThrows(IllegalArgumentException.class, () -> Json.canonicalizeStrict(o33)).getMessage());
        assertNotNull(Json.canonicalize(o33));
        // the value at depth in maps/lists is serialised at depth + 1
        Object mix = 1;
        for (int i = 0; i < 16; i++) mix = map("k", new ArrayList<>(List.of(mix)));
        assertNotNull(Json.canonicalizeStrict(mix));
        Object mix2 = map("k", new ArrayList<>(List.of(mix)));
        assertThrows(IllegalArgumentException.class, () -> Json.canonicalizeStrict(mix2));
        assertEquals(0, Json.compareUtf8("a", "a"));
        assertTrue(Json.compareUtf8("a", "b") < 0);
        assertTrue(Json.compareUtf8("\uff5e", "\ud83d\ude00") < 0);
        assertTrue(Json.compareUtf8("\u00e9", "z") > 0);
        assertTrue(Json.compareUtf8("a", "ab") < 0);
    }

    @Test void parserEdges() {
        assertEquals("input is not a string", assertThrows(IllegalArgumentException.class, () -> Json.parse(null)).getMessage());
        assertEquals("input is not a string", assertThrows(IllegalArgumentException.class, () -> Json.parseLenient(null)).getMessage());
        assertEquals("input too large", assertThrows(IllegalArgumentException.class, () -> Json.parse("[" + " ".repeat(1048575) + "]")).getMessage());
        assertEquals(List.of(), Json.parse("[" + " ".repeat(1048574) + "]"));
        assertEquals(List.of(), Json.parseLenient("[" + " ".repeat(1048600) + "]"));
        String euro = "\"" + "\u20ac".repeat(349524);
        assertEquals("input too large", assertThrows(IllegalArgumentException.class, () -> Json.parse(euro + "aaa\"")).getMessage());
        assertEquals(349526, ((String) Json.parse(euro + "aa\"")).length());
        assertEquals(Boolean.TRUE, Json.parse("true"));
        assertEquals(Boolean.FALSE, Json.parse(" false "));
        assertNull(Json.parse("null"));
        assertEquals("a", Json.parse("\"a\""));
        assertEquals("x\u00e9\ud83d\ude00\n\t\"\\/\b\f\r", Json.parse("\"x\\u00e9\\ud83d\\ude00\\n\\t\\\"\\\\\\/\\b\\f\\r\""));
        assertEquals("\u00e9\u00E9", Json.parse("\"\\u00e9\\u00E9\""));
        assertEquals("09afAF", Json.parse("\"\\u0030\\u0039\\u0061\\u0066\\u0041\\u0046\""));
        assertEquals("{a=1}", ((Map<?, ?>) Json.parse("{\"a\":1}")).toString());
        assertEquals("1", ((Json.Num) ((List<?>) Json.parse("[1]")).get(0)).raw);
        assertEquals("-12.5", ((Json.Num) Json.parse("-12.5")).raw);
        assertEquals("0", ((Json.Num) Json.parse("0")).raw);
        assertEquals("1e5", ((Json.Num) Json.parseLenient("1e5")).raw);
        assertEquals("1E+5", ((Json.Num) Json.parseLenient("1E+5")).raw);
        assertEquals("1e-5", ((Json.Num) Json.parseLenient("1e-5")).raw);
        assertEquals("9", ((Json.Num) Json.parse("9")).raw);
        assertEquals("1.5", ((Json.Num) Json.parse("1.5")).raw);
        assertEquals("19", ((Json.Num) Json.parse("19")).raw);
        assertEquals("1.0", ((Json.Num) Json.parseLenient("1.0")).raw);
        // lenient accepts what strict rejects
        assertEquals(2, ((Map<?, ?>) Json.parseLenient("{\"a\":1,\"a\":2}")).size() + 1);
        assertEquals("\ud800", Json.parseLenient("\"\\ud800\""));
        // exact messages
        for (String[] c : new String[][] {
            {"", "unexpected end at 0"}, {"   ", "unexpected end at 3"}, {"[", "unexpected end at 1"}, {"[1", "unterminated array at 2"}, {"[1,", "unexpected end at 3"},
            {"{", "expected key at 1"}, {"{\"a\"", "expected ':' at 4"}, {"{\"a\":1", "unterminated object at 6"}, {"{\"a\":1,", "expected key at 7"},
            {"\"abc", "unterminated string at 4"}, {"\"\\", "bad escape at 2"}, {"\"\\x\"", "bad escape at 3"}, {"\"\\u12", "bad \\u escape at 3"}, {"\"\\u12G4\"", "bad \\u escape at 3"},
            {"\"\\u00:0\"", "bad \\u escape at 3"}, {"\"\\u00/0\"", "bad \\u escape at 3"}, {"\"\\u00@0\"", "bad \\u escape at 3"}, {"\"\\u00`0\"", "bad \\u escape at 3"}, {"\"\\u00g0\"", "bad \\u escape at 3"},
            {"tru", "bad literal at 0"}, {"nul", "bad literal at 0"}, {"-", "bad number at 1"}, {"-x", "bad number at 1"}, {"1.", "bad number at 2"}, {"1e", "bad number at 2"}, {"1e+", "bad number at 3"},
            {"x", "bad number at 0"}, {"[1,]", "bad number at 3"}, {"[1 2]", "expected ',' or ']' at 4"}, {"{\"a\":1 \"b\":2}", "expected ',' or '}' at 8"},
            {"1 2", "trailing data at 2"}, {"\"\u0001\"", "control char in string at 2"}, {"\"\ud800\"", "lone surrogate in string at 3"},
            {"01", "trailing data at 1"},
            {"{\"a\":1,\"a\":2}", "duplicate key at 10"}, {"1.0", "trailing fractional zero is not canonical at 3"}, {"1e5", "exponent form is not allowed at 3"},
        }) {
            final String in = c[0];
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Json.parse(in), in);
            assertEquals(c[1], e.getMessage(), in);
        }
        // depth boundary
        assertNotNull(Json.parse("[".repeat(32) + "]".repeat(32)));
        assertEquals("nesting too deep at 32", assertThrows(IllegalArgumentException.class, () -> Json.parse("[".repeat(33) + "]".repeat(33))).getMessage());
        assertNotNull(Json.parseLenient("[".repeat(100) + "]".repeat(100)));
        assertNotNull(Json.parse("{\"a\":".repeat(32) + "1" + "}".repeat(32)));
        assertTrue(assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\":".repeat(33) + "1" + "}".repeat(33))).getMessage().startsWith("nesting too deep at "));
        // whitespace handling inside containers
        assertEquals(List.of(), Json.parse("[ ]"));
        assertEquals(Map.of(), Json.parse("{ }"));
        assertEquals(1, ((List<?>) Json.parse("[ 1 ]")).size());
        assertEquals(1, ((Map<?, ?>) Json.parse("{ \"a\" : 1 }")).size());
        assertEquals(2, ((List<?>) Json.parse("[\t1\r\n,\n2 ]")).size());
        assertEquals(1, ((Map<?, ?>) Json.parse("\t{\n\"a\"\r:\n1\t}\n")).size());
        assertThrows(IllegalArgumentException.class, () -> Json.parse("\u00a0[]"));
        assertEquals(List.of(), Json.parse("\n[\n]\n"));
    }

    // ------------------------------------------------------------------ Pq
    @Test void suites() {
        Pq.Suite ed = Pq.resolveSigAlg(null, false);
        assertEquals("ed25519", ed.alg); assertEquals(64, ed.sigBytes); assertTrue(ed.hasEd25519); assertNull(ed.pq); assertFalse(ed.needsPqPk); assertFalse(ed.needsPqSig);
        assertEquals("ed25519", Pq.resolveSigAlg("ed25519", true).alg);
        Pq.Suite ml = Pq.resolveSigAlg("ml-dsa-65", true);
        assertEquals("ml-dsa-65", ml.alg); assertEquals(3309, ml.sigBytes); assertFalse(ml.hasEd25519); assertEquals(Pq.Prim.ML_DSA_65, ml.pq); assertTrue(ml.needsPqPk); assertFalse(ml.needsPqSig);
        Pq.Suite hy = Pq.resolveSigAlg("hybrid-ed25519-ml-dsa-65", true);
        assertEquals("hybrid-ed25519-ml-dsa-65", hy.alg); assertEquals(64, hy.sigBytes); assertTrue(hy.hasEd25519); assertEquals(Pq.Prim.ML_DSA_65, hy.pq); assertTrue(hy.needsPqPk); assertTrue(hy.needsPqSig);
        assertEquals(Pq.Prim.ML_DSA_87, Pq.resolveSigAlg("ml-dsa-87", true).pq);
        assertNull(Pq.resolveSigAlg("fn-dsa-512", true)); // registered, not implemented: unsupported_suite
        assertEquals("unsupported_suite: fn-dsa-512", Pq.refusal("fn-dsa-512"));
        assertEquals("unknown signature alg 'ml-dsa-99'", Pq.refusal("ml-dsa-99"));
        assertNull(Pq.resolveSigAlg(5, true));
        assertNull(Pq.resolveSigAlg(null, true));
        assertEquals(LessNative.available() ? 12 : 10, Pq.SUITES.size()); // ed25519 + every registered suite BC implements (+ LESS with libatlas_less)
        assertEquals(1952, Pq.ML_DSA_65_PUBLIC_KEY_BYTES);
        assertEquals(3309, Pq.ML_DSA_65_SIGNATURE_BYTES);
        assertEquals(64, Pq.ED25519_SIGNATURE_BYTES);
        assertEquals("ed25519", Pq.DEFAULT_SIG_ALG);
    }

    @Test void validateSigWire() {
        String pk = "A".repeat(2603), sg = "A".repeat(4412), ed = "A".repeat(86);
        assertNull(Pq.validateSignatureWire(map("sig", ed)));
        assertEquals("'alg' must be a string", Pq.validateSignatureWire(map("alg", 5, "sig", ed)));
        assertEquals("'alg' must be a string", Pq.validateSignatureWire(map("alg", null, "sig", ed)));
        assertEquals("unknown signature alg 'zz'", Pq.validateSignatureWire(map("alg", "zz", "sig", ed)));
        assertEquals("'sig' is not canonical base64url (64 bytes) for alg 'ed25519'", Pq.validateSignatureWire(map("sig", "x")));
        assertEquals("'sig' is not canonical base64url (64 bytes) for alg 'ed25519'", Pq.validateSignatureWire(map("alg", "ed25519", "sig", sg)));
        assertEquals("'pq_pk' must be absent for alg 'ed25519'", Pq.validateSignatureWire(map("sig", ed, "pq_pk", pk)));
        assertEquals("'pq_sig' must be absent for alg 'ed25519'", Pq.validateSignatureWire(map("sig", ed, "pq_sig", sg)));
        assertNull(Pq.validateSignatureWire(map("alg", "ml-dsa-65", "sig", sg, "pq_pk", pk)));
        assertEquals("'pq_pk' is not canonical base64url (1952 bytes)", Pq.validateSignatureWire(map("alg", "ml-dsa-65", "sig", sg)));
        assertEquals("'pq_sig' must be absent for alg 'ml-dsa-65'", Pq.validateSignatureWire(map("alg", "ml-dsa-65", "sig", sg, "pq_pk", pk, "pq_sig", sg)));
        assertNull(Pq.validateSignatureWire(map("alg", "hybrid-ed25519-ml-dsa-65", "sig", ed, "pq_pk", pk, "pq_sig", sg)));
        assertEquals("'pq_sig' is not canonical base64url (3309 bytes)", Pq.validateSignatureWire(map("alg", "hybrid-ed25519-ml-dsa-65", "sig", ed, "pq_pk", pk)));
        assertEquals("'pq_pk' is not canonical base64url (1952 bytes)", Pq.validateSignatureWire(map("alg", "hybrid-ed25519-ml-dsa-65", "sig", ed, "pq_sig", sg)));
        assertEquals("'sig' is not canonical base64url (64 bytes) for alg 'hybrid-ed25519-ml-dsa-65'", Pq.validateSignatureWire(map("alg", "hybrid-ed25519-ml-dsa-65", "sig", sg, "pq_pk", pk, "pq_sig", sg)));
    }

    @SuppressWarnings("unchecked")
    @Test void leafSuiteSeam() throws Exception {
        for (String nm : new String[] {"pq-leaf-ml-dsa-65-valid", "pq-leaf-hybrid-ed25519-ml-dsa-65-valid"}) {
            Map<String, Object> v = PcaUnitTest.vec(nm);
            Map<String, Object> p = (Map<String, Object>) v.get("pcactn");
            List<Object> chain = (List<Object>) p.get("cap_chain");
            String holder = (String) ((Map<String, Object>) chain.get(chain.size() - 1)).get("holder");
            byte[] msg = Pca.thresholdMessage(p);
            Object alg = p.get("alg");
            assertTrue(Pq.verifyLeafSuiteCallerVouched(alg, true, holder, p.get("pq_pk"), msg, p.get("sig"), p.get("pq_sig")), nm);
            assertTrue(Pq.verifyArtifactSignature((String) alg, holder, p.get("pq_pk"), msg, p.get("sig"), p.get("pq_sig")), nm);
            assertFalse(Pq.verifyLeafSuiteCallerVouched(alg, true, holder, p.get("pq_pk"), msg, 5, p.get("pq_sig")));
            assertFalse(Pq.verifyLeafSuiteCallerVouched("bogus", true, holder, p.get("pq_pk"), msg, p.get("sig"), p.get("pq_sig")));
            assertFalse(Pq.verifyLeafSuiteCallerVouched(alg, true, holder, p.get("pq_pk"), new byte[] {1}, p.get("sig"), p.get("pq_sig")));
            if (alg.equals("hybrid-ed25519-ml-dsa-65")) {
                assertFalse(Pq.verifyLeafSuiteCallerVouched(alg, true, holder, p.get("pq_pk"), msg, p.get("sig"), null));
                assertFalse(Pq.verifyLeafSuiteCallerVouched(alg, true, holder, p.get("pq_pk"), msg, p.get("sig"), 5));
                assertFalse(Pq.verifyLeafSuiteCallerVouched(alg, true, holder, p.get("pq_pk"), msg, p.get("sig"), "A".repeat(4412)));
                assertFalse(Pq.verifyLeafSuiteCallerVouched(alg, true, holder, p.get("pq_pk"), msg, "A".repeat(86), p.get("pq_sig")));
                assertFalse(Pq.verifyLeafSuiteCallerVouched(alg, true, "A".repeat(43), p.get("pq_pk"), msg, p.get("sig"), p.get("pq_sig")));
                assertFalse(Pq.verifyLeafSuiteCallerVouched(alg, true, holder, "A".repeat(2603), msg, p.get("sig"), p.get("pq_sig")));
                // the ed25519 half alone is not enough, and neither is the ML-DSA half alone
                assertTrue(Pca.verifyB64u(holder, msg, (String) p.get("sig")));
                assertTrue(Pq.mlDsa65VerifyB64u(p.get("pq_pk"), msg, p.get("pq_sig")));
            } else {
                assertFalse(Pq.verifyLeafSuiteCallerVouched(alg, true, holder, "A".repeat(2603), msg, p.get("sig"), null));
                assertFalse(Pq.verifyLeafSuiteCallerVouched(alg, true, holder, p.get("pq_pk"), msg, "A".repeat(4412), null));
                assertTrue(Pq.mlDsa65VerifyB64u(p.get("pq_pk"), msg, p.get("sig")));
                assertFalse(Pq.mlDsa65VerifyB64u(p.get("pq_pk"), msg, "A".repeat(4412)));
                assertFalse(Pq.mlDsa65VerifyB64u("A".repeat(2603), msg, p.get("sig")));
                assertFalse(Pq.mlDsa65VerifyB64u(null, msg, p.get("sig")));
                assertFalse(Pq.mlDsa65VerifyB64u(p.get("pq_pk"), msg, null));
                byte[] pkb = Pca.decodeB64uStrict(p.get("pq_pk"), 1952), sgb = Pca.decodeB64uStrict(p.get("sig"), 3309);
                assertTrue(Pq.mlDsa65Verify(pkb, msg, sgb));
                assertFalse(Pq.mlDsa65Verify(null, msg, sgb));
                assertFalse(Pq.mlDsa65Verify(pkb, msg, null));
                assertFalse(Pq.mlDsa65Verify(new byte[1951], msg, sgb));
                assertFalse(Pq.mlDsa65Verify(new byte[1953], msg, sgb));
                assertFalse(Pq.mlDsa65Verify(pkb, msg, new byte[3308]));
                assertFalse(Pq.mlDsa65Verify(pkb, msg, new byte[3310]));
                assertFalse(Pq.mlDsa65Verify(pkb, null, sgb));
                assertFalse(Pq.mlDsa65Verify(pkb, new byte[] {1}, sgb));
                byte[] bad = sgb.clone(); bad[10] ^= 1;
                assertFalse(Pq.mlDsa65Verify(pkb, msg, bad));
            }
        }
        assertFalse(Pq.verifyLeafSuiteCallerVouched(null, false, "x", null, new byte[0], null, null));
        assertFalse(Pq.verifyLeafSuiteCallerVouched("ed25519", true, "x", null, new byte[0], "A".repeat(86), null));
    }

    // ------------------------------------------------------------------ Threshold
    @SuppressWarnings("unchecked")
    @Test void thresholdBinding() throws Exception {
        assertEquals("2.1", Threshold.AGENT_LEAF_SHARE_BINDING_VERSION);
        assertArrayEquals(new byte[0], Threshold.shareSuiteTag(null, false));
        assertArrayEquals(new byte[0], Threshold.shareSuiteTag("ed25519", true));
        assertArrayEquals(new byte[0], Threshold.shareSuiteTag("bogus", true));
        assertArrayEquals(new byte[0], Threshold.shareSuiteTag(5, true));
        assertArrayEquals("\0atlas-pca/share-suite/v1\0ml-dsa-65".getBytes(StandardCharsets.UTF_8), Threshold.shareSuiteTag("ml-dsa-65", true));
        assertArrayEquals("\0atlas-pca/share-suite/v1\0hybrid-ed25519-ml-dsa-65".getBytes(StandardCharsets.UTF_8), Threshold.shareSuiteTag("hybrid-ed25519-ml-dsa-65", true));

        List<Object> set = new ArrayList<>(List.of(map("publicKey", "b", "role", "guardian"), map("publicKey", "a", "role", "guardian"), map("publicKey", "z", "role", "agent")));
        List<Object> sorted = new ArrayList<>(List.of(map("publicKey", "z", "role", "agent"), map("publicKey", "a", "role", "guardian"), map("publicKey", "b", "role", "guardian")));
        assertArrayEquals(Threshold.signerSetHash(sorted), Threshold.signerSetHash(set));
        List<Object> notSorted = new ArrayList<>(List.of(map("publicKey", "z", "role", "agent"), map("publicKey", "b", "role", "guardian"), map("publicKey", "a", "role", "guardian")));
        assertArrayEquals(Threshold.signerSetHash(sorted), Threshold.signerSetHash(notSorted));
        byte[] expect = Pca.sha(Threshold.SIGNER_SET_DOMAIN.getBytes(StandardCharsets.UTF_8),
            "[{\"publicKey\":\"z\",\"role\":\"agent\"},{\"publicKey\":\"a\",\"role\":\"guardian\"},{\"publicKey\":\"b\",\"role\":\"guardian\"}]".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(expect, Threshold.signerSetHash(set));
        // role sorts before publicKey; pq_pk carried only when a string; missing fields stringify to "null"
        List<Object> pq = new ArrayList<>(List.of(map("publicKey", "a", "role", "r", "pq_pk", "PQ"), map("publicKey", "a", "role", "q", "pq_pk", 5), map("role", "q")));
        byte[] expect2 = Pca.sha(Threshold.SIGNER_SET_DOMAIN.getBytes(StandardCharsets.UTF_8),
            "[{\"publicKey\":\"a\",\"role\":\"q\"},{\"publicKey\":\"null\",\"role\":\"q\"},{\"pq_pk\":\"PQ\",\"publicKey\":\"a\",\"role\":\"r\"}]".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(expect2, Threshold.signerSetHash(pq));
        assertEquals(32, Threshold.signerSetHash(new ArrayList<>()).length);
        assertFalse(java.util.Arrays.equals(Threshold.signerSetHash(sorted), Threshold.signerSetHash(new ArrayList<>())));

        byte[] tm = new byte[] {1, 2, 3};
        for (int t : new int[] {0, 4, -1}) {
            final int tt = t;
            assertEquals("shareMessage: t must be 1, 2 or 3", assertThrows(IllegalArgumentException.class, () -> Threshold.shareMessage("agent", tm, sorted, tt, null, false)).getMessage());
        }
        for (int t = 1; t <= 3; t++) {
            byte[] msg = Threshold.shareMessage("agent", tm, sorted, t, null, false);
            byte[] want = Pca.concat("atlas-pca/share/agent\0".getBytes(StandardCharsets.UTF_8), Pca.sha(tm), Threshold.signerSetHash(sorted), new byte[] {(byte) t});
            assertArrayEquals(want, msg);
        }
        byte[] pqMsg = Threshold.shareMessage("agent", tm, sorted, 2, "ml-dsa-65", true);
        assertArrayEquals(Pca.concat("atlas-pca/share/agent\0".getBytes(StandardCharsets.UTF_8), Pca.sha(tm), Threshold.signerSetHash(sorted), new byte[] {2}, Threshold.shareSuiteTag("ml-dsa-65", true)), pqMsg);

        // corpus shares verify with the right role/t, and fail-closed on malformed input
        List<Object> shares = (List<Object>) ((Map<String, Object>) SnapshotTest.core().get("primitives")).get("threshold_share");
        int validSeen = 0;
        for (Object x : shares) {
            Map<String, Object> e = (Map<String, Object>) x;
            if (e.containsKey("valid") && !(Boolean) e.get("valid")) continue;
            Object ealg = ((Map<String, Object>) e.get("share")).get("alg");
            if (ealg instanceof String && !List.of("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65").contains(ealg)) continue;
            byte[] tmsg = PcaUnitTestSupport.b64(e.get("threshold_message"));
            List<Object> ss = (List<Object>) e.get("signer_set");
            int t = (int) Json.asLong(e.get("t"));
            Map<String, Object> share = (Map<String, Object>) e.get("share");
            String role = (String) e.get("role");
            assertTrue(Threshold.verifyShare(role, tmsg, ss, t, share), String.valueOf(e.get("name")));
            assertFalse(Threshold.verifyShare(role + "x", tmsg, ss, t, share));
            assertFalse(Threshold.verifyShare(role, new byte[] {9}, ss, t, share));
            assertFalse(Threshold.verifyShare(role, tmsg, ss, t == 1 ? 2 : 1, share));
            assertFalse(Threshold.verifyShare(role, tmsg, ss, 0, share));
            assertFalse(Threshold.verifyShare(role, tmsg, ss, 4, share));
            assertFalse(Threshold.verifyShare(role, null, ss, t, share));
            assertFalse(Threshold.verifyShare(role, tmsg, new ArrayList<>(), t, share));
            Map<String, Object> noSig = new LinkedHashMap<>(share); noSig.remove("sig");
            assertFalse(Threshold.verifyShare(role, tmsg, ss, t, noSig));
            Map<String, Object> noPk = new LinkedHashMap<>(share); noPk.remove("publicKey");
            if (!share.containsKey("alg") || "ed25519".equals(share.get("alg"))) assertFalse(Threshold.verifyShare(role, tmsg, ss, t, noPk));
            Map<String, Object> badAlg = new LinkedHashMap<>(share); badAlg.put("alg", "bogus");
            assertFalse(Threshold.verifyShare(role, tmsg, ss, t, badAlg));
            if (share.containsKey("alg") && !"ed25519".equals(share.get("alg"))) {
                Map<String, Object> noAlg = new LinkedHashMap<>(share); noAlg.remove("alg");
                assertFalse(Threshold.verifyShare(role, tmsg, ss, t, noAlg));
                Map<String, Object> noPq = new LinkedHashMap<>(share); noPq.remove("pq_pk");
                // the PQ key is the signer set's registered pq_pk; the share's own pq_pk (absent here) vouches for nothing
                assertTrue(Threshold.verifyShare(role, tmsg, ss, t, noPq));
            }
            validSeen++;
        }
        assertTrue(validSeen > 3, "valid shares " + validSeen);
        assertFalse(Threshold.verifyShare("agent", tm, new ArrayList<>(List.of("x")), 1, map()));
    }

    // ------------------------------------------------------------------ additions (round 2)
    @Test void suiteConstructor() {
        Pq.Suite s = new Pq.Suite("a", 5, true, null, true, false, true);
        assertEquals("a", s.alg); assertEquals(5, s.sigBytes); assertTrue(s.hasEd25519); assertNull(s.pq); assertTrue(s.needsPqPk); assertFalse(s.needsPqSig); assertTrue(s.nested);
        Pq.Suite t = new Pq.Suite("b", 7, false, Pq.Prim.SLH_DSA_SHA2_256S, false, true, false);
        assertEquals("b", t.alg); assertEquals(7, t.sigBytes); assertFalse(t.hasEd25519); assertEquals(Pq.Prim.SLH_DSA_SHA2_256S, t.pq); assertFalse(t.needsPqPk); assertTrue(t.needsPqSig); assertFalse(t.nested);
    }

    @Test void resolveKey() {
        String commit = Pca.holderPqCommitment("PK");
        assertNotNullKey(Pq.resolvePqKey("i", "PK", null, null, "T"), "T");
        assertNull(Pq.resolvePqKey("i", "PK", null, null, ""));
        assertNull(Pq.resolvePqKey("i", "PK", null, null, null));
        assertNull(Pq.resolvePqKey("i", "", null, null, null));
        assertNull(Pq.resolvePqKey("i", 5, commit, null, null));
        assertNull(Pq.resolvePqKey("i", null, commit, null, null));
        assertNull(Pq.resolvePqKey("i", "", Pca.holderPqCommitment(""), null, null));
        assertNotNullKey(Pq.resolvePqKey("i", "PK", commit, null, null), "PK");
        assertNull(Pq.resolvePqKey("i", "PK", "wrong", null, null));
        assertNull(Pq.resolvePqKey("i", "PK", 5, null, null));
        assertNull(Pq.resolvePqKey("i", "PK", null, null, null));
        // pins: own entry only, exact match; a present pin disables the holderPq fallback
        assertNotNullKey(Pq.resolvePqKey("i", "PK", null, map("i", "PK"), null), "PK");
        assertNull(Pq.resolvePqKey("i", "PK", commit, map("i", "OTHER"), null));
        assertNull(Pq.resolvePqKey("i", "PK", commit, map("i", 5), null));
        assertNotNullKey(Pq.resolvePqKey("i", "PK", commit, map("j", "PK2"), null), "PK");
        assertNull(Pq.resolvePqKey("i", "PK", null, map("j", "PK"), null));
        assertNotNullKey(Pq.resolvePqKey(null, "PK", commit, map("i", "PK2"), null), "PK");
        assertNotNullKey(Pq.resolvePqKey("i", "PK", commit, new LinkedHashMap<>(), null), "PK");
        // a trusted key wins over everything (even an empty artifact key)
        assertNotNullKey(Pq.resolvePqKey("i", null, null, map("i", "X"), "T"), "T");
    }
    static void assertNotNullKey(Pq.PinnedPq k, String key) {
        assertNotNull(k);
        try {
            java.lang.reflect.Field f = Pq.PinnedPq.class.getDeclaredField("key");
            f.setAccessible(true);
            assertEquals(key, f.get(k));
        } catch (ReflectiveOperationException e) { throw new AssertionError(e); }
    }

    @SuppressWarnings("unchecked")
    @Test void callerVouched() throws Exception {
        Map<String, Object> v = PcaUnitTest.vec("pq-leaf-ml-dsa-65-valid");
        Map<String, Object> p = (Map<String, Object>) v.get("pcactn");
        byte[] msg = Pca.thresholdMessage(p);
        assertTrue(Pq.verifyLeafSuiteCallerVouched("ml-dsa-65", true, "h", p.get("pq_pk"), msg, p.get("sig"), null));
        assertFalse(Pq.verifyLeafSuiteCallerVouched("ml-dsa-65", true, "h", 5, msg, p.get("sig"), null));
        assertFalse(Pq.verifyLeafSuiteCallerVouched("ml-dsa-65", true, "h", null, msg, p.get("sig"), null));
        assertFalse(Pq.verifyLeafSuiteCallerVouched("ml-dsa-65", true, "h", "", msg, p.get("sig"), null));
        assertFalse(Pq.verifyLeafSuite("ml-dsa-65", true, "h", null, msg, p.get("sig"), null));
        Map<String, Object> hv = PcaUnitTest.vec("pq-leaf-hybrid-ed25519-ml-dsa-65-valid");
        Map<String, Object> hp = (Map<String, Object>) hv.get("pcactn");
        List<Object> chain = (List<Object>) hp.get("cap_chain");
        String holder = (String) ((Map<String, Object>) chain.get(chain.size() - 1)).get("holder");
        assertFalse(Pq.verifyLeafSuite("hybrid-ed25519-ml-dsa-65", true, holder, null, Pca.thresholdMessage(hp), hp.get("sig"), hp.get("pq_sig")));
        assertTrue(Pq.verifyArtifactSignature("hybrid-ed25519-ml-dsa-65", holder, hp.get("pq_pk"), Pca.thresholdMessage(hp), hp.get("sig"), hp.get("pq_sig")));
        assertFalse(Pq.verifyArtifactSignature("hybrid-ed25519-ml-dsa-65", holder, 5, Pca.thresholdMessage(hp), hp.get("sig"), hp.get("pq_sig")));
    }

    @SuppressWarnings("unchecked")
    @Test void parserFullwidthHex() {
        // Character.digit accepts non-ASCII digits; the \\u escape must not
        for (String digits : new String[] {"\uff10\uff10\uff10\uff11", "\u0660\u0660\u0660\u0661", "00\uff10\uff11", "\uff1000"}) {
            String in = "\"" + "\\" + "u" + digits + "\"";
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Json.parse(in));
            assertEquals("bad \\u escape at 3", e.getMessage());
            assertThrows(IllegalArgumentException.class, () -> Json.parseLenient(in));
        }
        assertEquals("A", Json.parse("\"\\u0041\""));
        ((Map<String, Object>) Json.parse("{ }")).put("k", 1);
        ((List<Object>) Json.parse("[ ]")).add(1);
        ((Map<String, Object>) Json.parse("{}")).put("k", 1);
        ((List<Object>) Json.parse("[]")).add(1);
        assertTrue(Json.parse("{}") instanceof LinkedHashMap);
        assertTrue(Json.parse("[]") instanceof ArrayList);
    }

    @Test void hugeExponent() {
        assertEquals("canonicalize: non-finite number", assertThrows(IllegalArgumentException.class, () -> Json.fmtNumber("1e99999999999")).getMessage());
        assertEquals("canonicalize: non-finite number", assertThrows(IllegalArgumentException.class, () -> Json.canonicalize(n("1e99999999999"))).getMessage());
    }
}

final class PcaUnitTestSupport {
    static byte[] b64(Object o) {
        byte[] b = Pca.decodeB64uStrict(o, -1);
        if (b == null) throw new IllegalArgumentException("b64");
        return b;
    }
}