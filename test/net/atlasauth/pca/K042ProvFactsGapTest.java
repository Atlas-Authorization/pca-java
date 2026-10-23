package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/** Gap kills for ParamProvenance / OracleFacts: direct package-level helpers, read-purpose malformed shapes, and number-spelling normalization. */
class K042ProvFactsGapTest {
    static Map<String, Object> map(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }
    static List<Object> list(Object... xs) { return new ArrayList<>(List.of(xs)); }

    @Test void verifyLabelsRefusesMalformedReceiptsBeforeAnythingElse() {
        String w = ParamProvenance.validateLabelsWire("x");
        assertEquals("label receipt must be an object", w);
        assertEquals(w, ParamProvenance.verifyLabels("x", List.of()));
        assertEquals("label receipt must be an object", ParamProvenance.verifyLabels(null, List.of()));
        assertEquals("label receipt must be an object", ParamProvenance.verifyLabels(List.of(), List.of()));
        Map<String, Object> bad = map("v", 1L);
        String w2 = ParamProvenance.validateLabelsWire(bad);
        assertNotNull(w2);
        assertEquals(w2, ParamProvenance.verifyLabels(bad, List.of()));
    }

    @Test void flowRulePrefersTheLongestPrefixInEitherOrder() {
        for (boolean longFirst : new boolean[] {true, false}) {
            Map<String, Object> rules = new LinkedHashMap<>();
            if (longFirst) { rules.put("pii.identity.*", list("a")); rules.put("pii.*", list("b")); rules.put("*", list("c")); }
            else { rules.put("*", list("c")); rules.put("pii.*", list("b")); rules.put("pii.identity.*", list("a")); }
            assertEquals("pii.identity.*", ParamProvenance.flowRuleFor(rules, "pii.identity.passport"), "longFirst " + longFirst);
            assertEquals("pii.*", ParamProvenance.flowRuleFor(rules, "pii.contact"));
            assertEquals("*", ParamProvenance.flowRuleFor(rules, "other"));
            assertEquals("pii.*", ParamProvenance.flowRuleFor(rules, "pii.x.y"));
        }
        Map<String, Object> exact = new LinkedHashMap<>();
        exact.put("pii.*", list("b"));
        exact.put("pii.identity", list("a"));
        assertEquals("pii.identity", ParamProvenance.flowRuleFor(exact, "pii.identity"));
        assertEquals("pii.*", ParamProvenance.flowRuleFor(exact, "pii.identity.x"));
        assertNull(ParamProvenance.flowRuleFor(exact, "other"));
        assertNull(ParamProvenance.flowRuleFor(new LinkedHashMap<>(), "pii"));
        // a pattern is a prefix only with its dot: "pii.*" does not cover "pii" or "piix"
        assertNull(ParamProvenance.flowRuleFor(exact, "pii"));
        assertNull(ParamProvenance.flowRuleFor(exact, "piix.y"));
    }

    @Test void labelRefsAreSplitAtTheFirstHash() {
        String d = "A".repeat(43);
        assertNull(ParamProvenance.parseLabelRef("x#y"));
        assertNull(ParamProvenance.parseLabelRef(d + "#f"));
        assertNull(ParamProvenance.parseLabelRef("pca-labels:" + d));
        assertNull(ParamProvenance.parseLabelRef("pca-labels:" + d + "#"));
        assertNull(ParamProvenance.parseLabelRef("pca-labels:short#f"));
        assertNull(ParamProvenance.parseLabelRef("pca-labels:#f"));
        assertArrayEquals(new String[] {d, "f"}, ParamProvenance.parseLabelRef("pca-labels:" + d + "#f"));
        assertArrayEquals(new String[] {d, "a#b"}, ParamProvenance.parseLabelRef("pca-labels:" + d + "#a#b"));
        assertArrayEquals(new String[] {d, "#"}, ParamProvenance.parseLabelRef("pca-labels:" + d + "##"));
    }

    private static ParamProvenance.ReadPurposeResult read(Object fields, Object purpose, Object coverage, Object... onUncovered) {
        Map<String, Object> in = map("fields", fields, "purpose", purpose, "coverage", coverage);
        if (onUncovered.length > 0) in.put("on_uncovered", onUncovered[0]);
        return ParamProvenance.decideReadPurpose(in);
    }
    private static void assertDeny(ParamProvenance.ReadPurposeResult r, String why) {
        assertNotNull(r, why);
        assertEquals("deny", r.outcome, why);
        assertEquals(List.of(), r.minimise, why);
        assertEquals(List.of(), r.uncovered, why);
    }

    @Test void readPurposeIsTotalAndStrict() {
        for (Object bad : new Object[] {null, 5L, "x", List.of(), true}) assertDeny(ParamProvenance.decideReadPurpose(bad), "input " + bad);
        Map<String, Object> cov = map("p", list("pii.*"));
        List<Object> f = list(map("path", "a", "class", "pii.x"));
        assertEquals("allow", read(f, "p", cov).outcome);
        assertDeny(read(map(), "p", cov), "fields object");
        assertDeny(read(null, "p", cov), "fields null");
        assertDeny(read(f, 5L, cov), "purpose number");
        assertDeny(read(f, null, cov), "purpose null");
        assertDeny(read(f, "p", list()), "coverage list");
        assertDeny(read(f, "p", null), "coverage null");
        assertDeny(read(f, "p", cov, "allow"), "on_uncovered allow");
        assertDeny(read(f, "p", cov, 5L), "on_uncovered number");
        assertDeny(read(f, "p", cov, (Object) null), "on_uncovered null");
        assertEquals("allow", read(f, "p", cov, "deny").outcome);
        assertEquals("allow", read(f, "p", cov, "question").outcome);
        assertDeny(read(f, "p", map("p", "pii.*")), "coverage value not a list");
        assertDeny(read(f, "p", map("p", list(5L))), "coverage pattern not a string");
        assertDeny(read(f, "p", map("q", map())), "coverage value of another purpose is still checked");
        // every field member is checked even when its class would be covered
        assertDeny(read(list(map("path", 5L, "class", "public")), "p", cov), "path number, class covered");
        assertDeny(read(list(map("class", "public")), "p", cov), "path missing, class covered");
        assertDeny(read(list(map("path", "a", "class", 5L)), "p", cov), "class number");
        assertDeny(read(list(map("path", "a")), "p", cov), "class missing");
        assertDeny(read(list("x"), "p", cov), "field not an object");
        assertDeny(read(list(map("path", "a", "class", "public", "optional", "yes")), "p", cov), "optional string");
        assertDeny(read(list(map("path", "a", "class", "public", "optional", 1L)), "p", cov), "optional number");
        assertDeny(read(list(map("path", "a", "class", "public", "optional", (Object) null)), "p", cov), "optional null");
        assertEquals("allow", read(list(map("path", "a", "class", "public", "optional", true)), "p", cov).outcome);
        assertEquals("allow", read(list(map("path", "a", "class", "public", "optional", false)), "p", cov).outcome);
        // classification
        ParamProvenance.ReadPurposeResult r = read(list(map("path", "z", "class", "fin.x"), map("path", "a", "class", "fin.y", "optional", true),
            map("path", "b", "class", "fin.y", "optional", true), map("path", "a", "class", "fin.y", "optional", true), map("path", "c", "class", "public")), "p", cov);
        assertEquals("question", r.outcome);
        assertEquals(List.of("a", "b"), r.minimise);
        assertEquals(List.of("z"), r.uncovered);
        assertEquals("deny", read(list(map("path", "z", "class", "fin.x")), "p", cov, "deny").outcome);
        ParamProvenance.ReadPurposeResult opt = read(list(map("path", "a", "class", "fin.y", "optional", true)), "p", cov);
        assertEquals("allow", opt.outcome);
        assertEquals(List.of("a"), opt.minimise);
        assertEquals(List.of(), opt.uncovered);
        assertEquals("allow", read(list(), "p", cov).outcome);
        assertEquals("question", read(f, "unknown-purpose", cov).outcome);
        assertEquals("allow", read(list(map("path", "a", "class", "public")), "unknown-purpose", cov).outcome);
        assertEquals("allow", read(list(map("path", "a", "class", "anything")), "p", map("p", list("*"))).outcome);
        assertEquals("allow", read(list(map("path", "a", "class", "pii")), "p", map("p", list("pii"))).outcome);
        assertEquals("question", read(list(map("path", "a", "class", "piix")), "p", map("p", list("pii"))).outcome);
        assertEquals("question", read(list(map("path", "a", "class", "pii")), "p", cov).outcome);   // "pii.*" needs the dot
        assertEquals("allow", read(list(map("path", "a", "class", "pii.deep.er")), "p", cov).outcome);
    }

    // ---- number-spelling normalization: the same documents with every integer respelled "N.0" must decide identically ----
    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> oracleCases() throws Exception {
        try (InputStream in = new GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-oracleprov.json.gz")))) {
            Object doc = IntentJs.normalize(Json.parseLenient(new String(in.readAllBytes(), StandardCharsets.UTF_8)));
            return (List<Map<String, Object>>) (List<?>) IntentJs.arr(IntentJs.get(doc, "cases"));
        }
    }
    static Object respell(Object v) {
        if (v instanceof Json.Num) { String raw = ((Json.Num) v).raw; return raw.matches("-?[0-9]+") ? new Json.Num(raw + ".0") : v; }
        if (v instanceof Map) { Map<String, Object> o = new LinkedHashMap<>(); for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) o.put((String) e.getKey(), respell(e.getValue())); return o; }
        if (v instanceof List) { List<Object> o = new ArrayList<>(); for (Object x : (List<?>) v) o.add(respell(x)); return o; }
        return v;
    }

    @Test void worldAndProvenanceNormalizeNumberSpellings() throws Exception {
        List<String> bad = new ArrayList<>();
        int n = 0;
        for (Map<String, Object> c : oracleCases()) {
            String kind = (String) c.get("kind"), name = (String) c.get("name");
            if (!kind.equals("world") && !kind.equals("prov")) continue;
            if (name.contains("k042-input-")) continue;
            Object plain = c.get("input"), spelled = respell(plain);
            if (Json.canonicalize(plain).equals(Json.canonicalize(spelled)) && !hasNumber(plain)) continue;
            n++;
            String a, b;
            if (kind.equals("world")) {
                a = render(OracleFacts.decideIntentWorld(plain));
                b = render(OracleFacts.decideIntentWorld(spelled));
            } else {
                a = render(ParamProvenance.decide(plain));
                b = render(ParamProvenance.decide(spelled));
            }
            if (!a.equals(b)) bad.add(name + "\n  plain   " + a + "\n  spelled " + b);
        }
        assertTrue(n > 300, "cases with numbers: " + n);
        assertTrue(bad.isEmpty(), bad.size() + " differ:\n" + String.join("\n", bad.subList(0, Math.min(10, bad.size()))));
    }
    static boolean hasNumber(Object v) {
        if (v instanceof Json.Num) return true;
        if (v instanceof Map) { for (Object x : ((Map<?, ?>) v).values()) if (hasNumber(x)) return true; }
        if (v instanceof List) { for (Object x : (List<?>) v) if (hasNumber(x)) return true; }
        return false;
    }
    static String render(OracleFacts.WorldResult r) { return r.ok ? "ok " + K042OracleProvOracleTest.ser(r.world) + K042OracleProvOracleTest.ser(r.singleSource) : "fail " + r.reason; }
    static String render(ParamProvenance.ProvResult r) {
        return String.join("|", r.outcome, String.valueOf(r.reason), String.valueOf(r.friction), K042OracleProvOracleTest.ser(r.labels), K042OracleProvOracleTest.ser(r.classes), K042OracleProvOracleTest.ser(r.env));
    }
}
