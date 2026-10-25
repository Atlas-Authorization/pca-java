package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Differential kill tests for the 0.4.2 Predicates.java / IntentJs.java mutation survivors against the TypeScript
 * reference (packages/pca/src/predicates.ts + hash.ts + JavaScript number semantics). The golden
 * test-data/k042-predjs.json is produced by tools/pca-audit/java-mutate/k042-predjs-oracle.mjs; every input is carried
 * as JSON text so both sides parse identical lexemes (1e400, -0, lone surrogates).
 */
@SuppressWarnings("unchecked")
public class K042PredJsOracleTest {
    static Map<String, Object> G;

    @BeforeAll static void load() throws Exception {
        G = (Map<String, Object>) Json.parseLenient(Files.readString(Path.of("test-data/k042-predjs.json")));
    }

    static List<Object> cases(String k) { return (List<Object>) G.get(k); }
    static Predicates.Tri tri(String s) {
        switch (s) {
            case "true": return Predicates.Tri.TRUE;
            case "false": return Predicates.Tri.FALSE;
            default: return Predicates.Tri.UNKNOWN;
        }
    }

    @Test void conditionsMatchTheReference() {
        Map<String, String> ctxs = (Map<String, String>) (Map<?, ?>) G.get("ctx");
        List<String> bad = new ArrayList<>();
        int n = 0;
        for (Object o : cases("tri")) {
            Map<String, Object> c = (Map<String, Object>) o;
            Map<String, Object> cx = (Map<String, Object>) Json.parseLenient(ctxs.get((String) c.get("ctx")));
            Object cond = Json.parseLenient((String) c.get("cond"));
            Predicates.Tri want = tri((String) c.get("tri"));
            Predicates.Tri got = Predicates.evaluateConditionTri(cond, cx);
            boolean gotB = Predicates.evaluateCondition(cond, (Map<String, Object>) Json.parseLenient(ctxs.get((String) c.get("ctx"))));
            if (got != want || gotB != (want == Predicates.Tri.TRUE)) bad.add(c.get("name") + ": want " + want + " got " + got + "/" + gotB);
            n++;
        }
        assertTrue(n > 400, "golden too small: " + n);
        assertEquals(List.of(), bad);
    }

    @Test void predicatesMatchTheReference() {
        Map<String, String> ctxs = (Map<String, String>) (Map<?, ?>) G.get("ctx");
        List<String> bad = new ArrayList<>();
        for (Object o : cases("preds")) {
            Map<String, Object> c = (Map<String, Object>) o;
            String ct = ctxs.get((String) c.get("ctx"));
            Object preds = Json.parseLenient((String) c.get("preds"));
            boolean want = (Boolean) c.get("allowed");
            boolean got = Predicates.evaluatePredicates(preds, (Map<String, Object>) Json.parseLenient(ct));
            if (got != want) bad.add(c.get("name") + ": allowed want " + want + " got " + got);
            List<Object> each = (List<Object>) c.get("each");
            if (preds instanceof List) {
                List<Object> ps = (List<Object>) preds;
                assertEquals(each.size(), ps.size(), (String) c.get("name"));
                for (int i = 0; i < ps.size(); i++) {
                    boolean m = Predicates.predicateMatches(ps.get(i), (Map<String, Object>) Json.parseLenient(ct));
                    if (m != (Boolean) each.get(i)) bad.add(c.get("name") + "[" + i + "]: want " + each.get(i) + " got " + m);
                }
            }
        }
        assertEquals(List.of(), bad);
    }

    @Test void jsonEqualsIsTheLenientCanonicalTextEquality() {
        List<String> bad = new ArrayList<>();
        for (Object o : cases("eq")) {
            Map<String, Object> c = (Map<String, Object>) o;
            Object a = Json.parseLenient((String) c.get("a")), b = Json.parseLenient((String) c.get("b"));
            boolean want = (Boolean) c.get("eq");
            if (IntentJs.jsonEquals(a, b) != want) bad.add(c.get("a") + " == " + c.get("b") + ": want " + want);
        }
        assertEquals(List.of(), bad);
    }

    /**
     * Numbers: the binary64 value, Number.isSafeInteger / isFinite, and the normalized spelling. Within the strict
     * profile the spelling is exactly JavaScript's {@code String(n)}. Outside it (never accepted by a strict consumer) Java
     * prints without an exponent: an integral value below 1e21 by its EXACT binary64 digits (identical to JavaScript for
     * every safe integer; past 2^53 JavaScript pads its shortest digits with zeros), anything else by JavaScript's
     * shortest digits written out in plain decimal.
     */
    @Test void numbersMatchJavaScript() {
        List<String> bad = new ArrayList<>();
        for (Object o : cases("nums")) {
            Map<String, Object> c = (Map<String, Object>) o;
            String raw = (String) c.get("raw"), js = (String) c.get("js");
            Json.Num n = new Json.Num(raw);
            double d = Double.parseDouble(raw);
            if (IntentJs.isSafeInteger(n) != (Boolean) c.get("safe")) bad.add(raw + ": isSafeInteger");
            if (IntentJs.isFinite(n) != (Boolean) c.get("finite")) bad.add(raw + ": isFinite");
            if (!IntentJs.num(n).equals(d)) bad.add(raw + ": num");
            String want;
            if (!(Boolean) c.get("finite")) want = raw;
            else if (js.equals("-0")) want = "-0";
            else if (d == Math.rint(d) && Math.abs(d) < 1e21) want = new BigDecimal(d).toPlainString();
            else want = new BigDecimal(js).toPlainString();
            if ((Boolean) c.get("plain") && (Boolean) c.get("finite") && (Boolean) c.get("safe") && !want.equals(js)) bad.add(raw + ": safe spelling differs from JS");
            if ((Boolean) c.get("plain") && (Boolean) c.get("finite") && d != Math.rint(d) && !want.equals(js)) bad.add(raw + ": decimal spelling differs from JS");
            String got = IntentJs.normNum(raw).raw;
            if (!got.equals(want)) bad.add(raw + ": normNum " + got + " want " + want);
            Object norm = IntentJs.normalize(n);
            if (!(norm instanceof Json.Num) || !((Json.Num) norm).raw.equals(want)) bad.add(raw + ": normalize");
            if ((Boolean) c.get("finite")) {
                Object nd = IntentJs.normalize(Double.valueOf(d));
                if (!(nd instanceof Json.Num) || !((Json.Num) nd).raw.equals(want)) bad.add(raw + ": normalize(Double) " + nd);
            }
        }
        assertEquals(List.of(), bad);
    }

    @Test void utf8LengthsAndSurrogates() {
        for (Object o : cases("u8")) {
            Map<String, Object> c = (Map<String, Object>) o;
            String s = (String) c.get("s");
            assertEquals(((Json.Num) c.get("n")).raw, Integer.toString(IntentJs.u8len(s)), "u8len " + escape(s));
            assertEquals(c.get("lone"), IntentJs.hasLoneSurrogate(s), "lone " + escape(s));
        }
        for (Object o : cases("cmp")) {
            Map<String, Object> c = (Map<String, Object>) o;
            String a = (String) c.get("a"), b = (String) c.get("b");
            assertEquals(Integer.parseInt(((Json.Num) c.get("sign")).raw), Integer.signum(IntentJs.compareUtf8(a, b)), escape(a) + " vs " + escape(b));
        }
    }

    static String escape(String s) {
        StringBuilder b = new StringBuilder();
        for (char ch : s.toCharArray()) b.append(ch < 0x80 ? String.valueOf(ch) : String.format("\\u%04x", (int) ch));
        return b.toString();
    }

    // ---- member_of closure caps (same recipes as the oracle) ----
    static Map<String, Object> chainCtx(int n) {
        Map<String, Object> g = new LinkedHashMap<>();
        for (int i = 0; i < n; i++) g.put("n" + i, "n" + (i + 1));
        return PredicatesKillTest.map("action", PredicatesKillTest.map("verb", "v", "resource", "r"), "subject", PredicatesKillTest.map("id", "n0", "g", g));
    }
    static Map<String, Object> fanCtx() {
        Map<String, Object> g = new LinkedHashMap<>();
        List<Object> s = new ArrayList<>(), cs = new ArrayList<>();
        for (int j = 0; j < 100; j++) cs.add("c" + j);
        g.put("s", s);
        for (int i = 0; i < 100; i++) { s.add("a" + i); g.put("a" + i, cs); }
        g.put("c0", "e");
        g.put("e", "t");
        return PredicatesKillTest.map("action", PredicatesKillTest.map("verb", "v", "resource", "r"), "subject", PredicatesKillTest.map("id", "s", "g", g));
    }
    static Map<String, Object> mo(String v) { return PredicatesKillTest.map("field", "subject.id", "op", "member_of", "collection", "subject.g", "value", v); }

    @Test void memberClosureIsCappedLikeTheReference() {
        Map<String, Object> chain = (Map<String, Object>) G.get("chain"), fan = (Map<String, Object>) G.get("fan");
        Map<String, Object> cc = chainCtx(10005);
        for (Map.Entry<String, Object> e : chain.entrySet()) assertEquals(tri((String) e.getValue()), Predicates.evaluateConditionTri(mo(e.getKey()), cc), e.getKey());
        Map<String, Object> fc = fanCtx();
        for (Map.Entry<String, Object> e : fan.entrySet()) assertEquals(tri((String) e.getValue()), Predicates.evaluateConditionTri(mo(e.getKey()), fc), e.getKey());
        assertEquals(Predicates.Tri.TRUE, tri((String) chain.get("n10000")));
        assertEquals(Predicates.Tri.FALSE, tri((String) chain.get("n10001")));
    }
}
