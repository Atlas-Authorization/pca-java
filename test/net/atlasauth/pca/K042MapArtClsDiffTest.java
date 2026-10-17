package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
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

/**
 * 0.4.2 mutation kills for {@link IntentMap} (rule 19), {@link IntentClassifier} (rule 18) and their shared
 * {@link IntentArtifacts} helpers: a differential test against the TS reference (oracle
 * tools/pca-audit/java-mutate/k042-mapartcls-oracle.mjs -> test-data/k042-mapartcls.json.gz). Every validator case
 * asserts the EXACT reason (or null), every decision the exact verdict and every result member.
 *
 * <p>One documented wording difference: TS names the dimension path in "the action's &lt;path&gt; lies outside the committed
 * map's dimension"; the Java verifier (like every native verifier) says "the action's value lies outside ...".
 */
public class K042MapArtClsDiffTest {
    static final String OUTSIDE = "the action's value lies outside the committed map's dimension";

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> cases() throws Exception {
        try (InputStream in = new GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-mapartcls.json.gz")))) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            in.transferTo(b);
            return (List<Map<String, Object>>) IntentJs.normalize(Json.parseLenient(b.toString(StandardCharsets.UTF_8)));
        }
    }

    static List<Map<String, Object>> of(List<Map<String, Object>> all, String fn) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> c : all) if (fn.equals(c.get("fn"))) out.add(c);
        assertFalse(out.isEmpty(), "no oracle cases for " + fn);
        return out;
    }
    static List<?> args(Map<String, Object> c) { return (List<?>) c.get("args"); }
    static String str(Object o) { return o == null ? null : (String) o; }
    static void report(List<String> bad) { assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad)); }

    interface Validator { String apply(Object o); }
    void validators(String fn, Validator v) throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of(cases(), fn)) {
            String want = str(c.get("out"));
            String got;
            try { got = v.apply(args(c).get(0)); } catch (Throwable t) { got = "THROWS " + t; }
            if (want == null ? got != null : !want.equals(got)) bad.add(c.get("name") + "\n  want: " + want + "\n  got:  " + got);
        }
        report(bad);
    }

    @Test void headerLeaf() throws Exception { validators("header", IntentMap::headerError); }
    @Test void cellLeaf() throws Exception { validators("cell", IntentMap::cellError); }
    @Test void metricsLeaf() throws Exception { validators("metrics", IntentMap::metricsError); }
    @Test void learnerLeaf() throws Exception { validators("learner", IntentMap::learnerError); }
    @Test void disclosureShape() throws Exception { validators("disclosure", IntentMap::disclosureError); }
    @Test void verdictWire() throws Exception { validators("verdictwire", IntentClassifier::validateVerdictWire); }
    @Test void classifierPolicy() throws Exception { validators("policy", IntentClassifier::validatePolicy); }

    @Test void numericCells() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of(cases(), "numcells")) {
            List<long[]> got = IntentMap.numCells(IntentJs.obj(args(c).get(0)));
            List<?> want = (List<?>) c.get("out");
            boolean same = got.size() == want.size();
            for (int i = 0; same && i < got.size(); i++) {
                List<?> w = (List<?>) want.get(i);
                same = got.get(i).length == 2 && got.get(i)[0] == IntentJs.lng(w.get(0)) && got.get(i)[1] == IntentJs.lng(w.get(1));
            }
            if (!same) {
                StringBuilder g = new StringBuilder();
                for (long[] r : got) g.append(java.util.Arrays.toString(r));
                bad.add(c.get("name") + "\n  want: " + Json.canonicalize(want) + "\n  got:  " + g);
            }
        }
        report(bad);
    }

    @Test void cellOfTheAction() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of(cases(), "cellof")) {
            List<?> a = args(c);
            Object want = c.get("out");
            String got, w;
            try {
                long[][] r = IntentMap.cellOf(IntentJs.obj(a.get(0)), a.get(1), a.size() > 2 ? a.get(2) : null);
                if (r == null) got = "null";
                else {
                    List<Object> cell = new ArrayList<>();
                    for (long x : r[0]) cell.add(x);
                    got = r.length + " " + cell + " " + java.util.Arrays.toString(r[1]);
                }
            } catch (Throwable t) { got = "THROWS " + t; }
            if (want == null) w = "null";
            else {
                List<Object> cell = new ArrayList<>();
                for (Object x : (List<?>) IntentJs.get(want, "cell")) cell.add(IntentJs.lng(x));
                w = "2 " + cell + " [" + IntentJs.lng(IntentJs.get(want, "flat")) + "]";
            }
            if (!w.equals(got)) bad.add(c.get("name") + "\n  want: " + w + "\n  got:  " + got);
        }
        report(bad);
    }

    @Test void commitment() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of(cases(), "commit")) {
            String got;
            try { got = IntentMap.commitLeaves(args(c).get(0)); } catch (Throwable t) { got = "THROWS " + t; }
            if (!c.get("out").equals(got)) bad.add(c.get("name") + "\n  want: " + c.get("out") + "\n  got:  " + got);
        }
        report(bad);
    }

    static String render(IntentMap.Decision d) {
        return d.ok + "|" + d.reason + "|" + d.cell + "|" + d.pPpm + "|" + d.residualRiskPpm;
    }
    static String renderWant(Map<?, ?> o) {
        if (Boolean.TRUE.equals(o.get("ok"))) {
            List<Long> cell = new ArrayList<>();
            for (Object x : (List<?>) o.get("cell")) cell.add(IntentJs.lng(x));
            return "true|null|" + cell + "|" + IntentJs.lng(o.get("p_ppm")) + "|" + IntentJs.lng(o.get("residual_risk_ppm"));
        }
        String r = (String) o.get("reason");
        if (r.startsWith("the action's ") && r.endsWith(" lies outside the committed map's dimension")) r = OUTSIDE;
        return "false|" + r + "|null|0|0";
    }

    @Test void mapDecisions() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of(cases(), "decide")) {
            String want = renderWant((Map<?, ?>) c.get("out"));
            String got;
            try { got = render(IntentMap.decidePrimitive(args(c).get(0))); } catch (Throwable t) { got = "THROWS " + t; }
            if (!want.equals(got)) bad.add(c.get("name") + "\n  want: " + want + "\n  got:  " + got);
        }
        report(bad);
    }

    @Test void classifierDecisions() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of(cases(), "classify")) {
            Map<?, ?> o = (Map<?, ?>) c.get("out");
            String want = o.get("ok") + "|" + o.get("reason") + "|" + (o.get("classes") == null ? null : Json.canonicalize(o.get("classes")));
            String got;
            try {
                IntentClassifier.ClassResult r = IntentClassifier.decide(args(c).get(0));
                got = r.ok + "|" + r.reason + "|" + (r.classes == null ? null : Json.canonicalize(r.classes));
            } catch (Throwable t) { got = "THROWS " + t; }
            if (!want.equals(got)) bad.add(c.get("name") + "\n  want: " + want + "\n  got:  " + got);
        }
        report(bad);
    }

    /** The classifier decision through the already-normalized entry (no second normalization) agrees too. */
    @Test void classifierDecisionsNormalizedEntry() throws Exception {
        for (Map<String, Object> c : of(cases(), "classify")) {
            Object in = args(c).get(0);
            if (!(in instanceof Map)) continue;
            Map<?, ?> o = (Map<?, ?>) c.get("out");
            IntentClassifier.ClassResult r = IntentClassifier.decide(IntentJs.obj(in));
            assertEquals(o.get("reason"), r.reason, (String) c.get("name"));
            assertEquals(o.get("ok"), r.ok, (String) c.get("name"));
        }
    }

    // ---- the signed verdict fixture: IntentArtifacts.verifyArtifactSig under the pinned key ----
    static Object[] sigFixture() throws Exception {
        List<?> a = args(of(cases(), "sigfixture").get(0));
        return new Object[] {IntentJs.obj(a.get(0)), a.get(1), a.get(2)};
    }

    @Test void artifactSignature() throws Exception {
        Object[] f = sigFixture();
        @SuppressWarnings("unchecked") Map<String, Object> v = (Map<String, Object>) f[0];
        String pk = (String) f[1], other = (String) f[2];
        String dom = IntentClassifier.INTENT_CLASSIFIER_DOMAIN;
        assertTrue(IntentArtifacts.verifyArtifactSig(dom, v, pk, null));
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, v, other, null));
        assertFalse(IntentArtifacts.verifyArtifactSig(dom + "x", v, pk, null));
        // sig absent / not a string; pinned key absent / not a string
        Map<String, Object> noSig = new LinkedHashMap<>(v);
        noSig.remove("sig");
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, noSig, pk, null));
        Map<String, Object> numSig = new LinkedHashMap<>(v);
        numSig.put("sig", 5L);
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, numSig, pk, null));
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, v, null, null));
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, v, 5L, null));
        // a body without a strict canonical form is a failed signature (never an exception, never a pass)
        Map<String, Object> lone = new LinkedHashMap<>(v);
        lone.put("label", "a\uD800");
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, lone, pk, null));
        Map<String, Object> dbl = new LinkedHashMap<>(v);
        dbl.put("v", new Json.Num("1.0"));
        assertFalse(IntentArtifacts.verifyArtifactSig(dom, dbl, pk, null));
    }

    /** A content value spelled non-canonically: the normalizing entry hashes 1.0 as 1; the inner entry fails closed. */
    @Test void contentNormalization() throws Exception {
        Map<String, Object> c = null;
        for (Map<String, Object> x : of(cases(), "classify")) if ("classify/content-number".equals(x.get("name"))) c = x;
        assertNotNull(c);
        @SuppressWarnings("unchecked") Map<String, Object> in = (Map<String, Object>) Json.parseLenient(Json.canonicalize(args(c).get(0)));
        in = IntentJs.obj(IntentJs.normalize(in));
        IntentJs.obj(IntentJs.obj(in.get("action")).get("params")).put("text", new Json.Num("1.0"));
        IntentClassifier.ClassResult r = IntentClassifier.decide((Object) in);
        assertTrue(r.ok, r.reason);
        assertEquals(Map.of("tone", "calm"), r.classes);
        IntentClassifier.ClassResult inner = IntentClassifier.decide(in);
        assertFalse(inner.ok);
        assertEquals("classes: evaluation error (fail closed): IllegalArgumentException", inner.reason);
        assertNull(inner.classes);
    }
}
