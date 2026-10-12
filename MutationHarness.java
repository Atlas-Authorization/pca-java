import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.GZIPInputStream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * JUnit harness used ONLY for mutation testing (PIT): runs the existing JUnit-free suites in-process and the FULL
 * adversarial corpus (vectors-adversarial.json.gz) split in chunks so a mutant is killed by the first failing chunk.
 */
public class MutationHarness {
    static final String DIR = "conformance/";
    static final Set<String> IMPL = Set.of("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65");
    static final Set<String> REG = Set.of("ed25519", "ml-dsa-65", "ml-dsa-87", "hybrid-ed25519-ml-dsa-65", "hybrid-ed25519-ml-dsa-87",
        "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s",
        "hybrid-ed25519-slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-256s");
    static final int CHUNKS = 16;
    static Map<String, Object> adv;

    @SuppressWarnings("unchecked")
    static synchronized Map<String, Object> adv() throws Exception {
        if (adv == null) {
            try (InputStream in = new GZIPInputStream(Files.newInputStream(Path.of(DIR + "vectors-adversarial.json.gz")))) {
                adv = (Map<String, Object>) Json.parseLenient(new String(in.readAllBytes(), StandardCharsets.UTF_8));
            }
        }
        return adv;
    }

    static { System.setProperty("pca.noexit", "1"); }

    @Test void conformanceMain() throws Exception {
        ConformanceTest.main(new String[0]);
        Assertions.assertEquals(0, ConformanceTest.fails);
    }

    @Test void middlewareMain() throws Exception {
        PcaMiddlewareTest.main(new String[0]);
        Assertions.assertEquals(0, PcaMiddlewareTest.fails);
    }

    @SuppressWarnings("unchecked")
    void chunk(int k) throws Exception {
        List<Object> vs = (List<Object>) adv().get("vectors");
        for (int i = k; i < vs.size(); i += CHUNKS) {
            Map<String, Object> v = (Map<String, Object>) vs.get(i);
            boolean skip = false;
            for (String s : ConformanceTest.suitesExercised(v)) if (REG.contains(s) && !IMPL.contains(s)) skip = true;
            if (skip) continue;
            Map<String, Object> ctx = (Map<String, Object>) v.get("context");
            List<String> allowedSuites = null;
            if (ctx.get("allowed_suites") instanceof List) {
                allowedSuites = new ArrayList<>();
                for (Object o : (List<Object>) ctx.get("allowed_suites")) allowedSuites.add(String.valueOf(o));
            }
            long now = Json.asLong(ctx.get("now"));
            String aud = (String) ctx.get("aud");
            Map<String, Object> grant = (Map<String, Object>) v.get("grant");
            Pca.Verdict got;
            try {
                got = v.containsKey("pcactn_json") ? Pca.verifyPcactnJson((String) v.get("pcactn_json"), grant, now, aud, allowedSuites)
                    : Pca.verifyPcactn(v.get("pcactn"), grant, now, aud, allowedSuites);
            } catch (StackOverflowError | RuntimeException e) { Assertions.fail(v.get("name") + " threw " + e); return; }
            Map<String, Object> exp = (Map<String, Object>) v.get("expect");
            Assertions.assertEquals(exp.get("allow"), got.allow, String.valueOf(v.get("name")));
            Map<String, Object> want = (Map<String, Object>) exp.get("checks");
            Assertions.assertEquals(want.keySet(), got.checks.keySet(), String.valueOf(v.get("name")));
            for (Map.Entry<String, Object> e : want.entrySet())
                Assertions.assertEquals(e.getValue(), got.checks.get(e.getKey()), v.get("name") + ":" + e.getKey());
        }
    }

    @SuppressWarnings("unchecked")
    @Test void advPrimitives() throws Exception {
        Map<String, Object> prim = (Map<String, Object>) adv().get("primitives");
        if (prim.get("canonical") != null) for (Object x : (List<Object>) prim.get("canonical")) {
            Map<String, Object> c = (Map<String, Object>) x;
            String s = Json.canonicalizeStrict(c.get("value"));
            Assertions.assertEquals(c.get("expect"), s);
            if (c.get("hash") != null) Assertions.assertEquals(c.get("hash"), Pca.hashStrict(c.get("value")));
        }
        if (prim.get("json_parse") != null) for (Object x : (List<Object>) prim.get("json_parse")) {
            Map<String, Object> j = (Map<String, Object>) x;
            String in = (String) j.get("input");
            boolean accepted; String canon = null;
            try { canon = Json.canonicalizeStrict(Json.parse(in)); accepted = true; } catch (RuntimeException | StackOverflowError e) { accepted = false; }
            Assertions.assertEquals(j.get("accept"), accepted, "json_parse " + in);
            if (accepted && j.containsKey("canonical")) Assertions.assertEquals(j.get("canonical"), canon);
        }
        if (prim.get("b64u") != null) for (Object x : (List<Object>) prim.get("b64u")) {
            Map<String, Object> b = (Map<String, Object>) x;
            int len = b.containsKey("len") ? (int) Json.asLong(b.get("len")) : -1;
            Assertions.assertEquals(b.get("valid"), Pca.decodeB64uStrict(b.get("input"), len) != null, "b64u " + b.get("input"));
        }
    }

    @Test void c00() throws Exception { chunk(0); }
    @Test void c01() throws Exception { chunk(1); }
    @Test void c02() throws Exception { chunk(2); }
    @Test void c03() throws Exception { chunk(3); }
    @Test void c04() throws Exception { chunk(4); }
    @Test void c05() throws Exception { chunk(5); }
    @Test void c06() throws Exception { chunk(6); }
    @Test void c07() throws Exception { chunk(7); }
    @Test void c08() throws Exception { chunk(8); }
    @Test void c09() throws Exception { chunk(9); }
    @Test void c10() throws Exception { chunk(10); }
    @Test void c11() throws Exception { chunk(11); }
    @Test void c12() throws Exception { chunk(12); }
    @Test void c13() throws Exception { chunk(13); }
    @Test void c14() throws Exception { chunk(14); }
    @Test void c15() throws Exception { chunk(15); }
}
