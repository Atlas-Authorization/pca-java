package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/**
 * Mutation-style differential (tools/pca-audit/java-mutate/k042-oracleprov-mut-oracle.mjs -> test-data/k042-oracleprov-mut.json.gz):
 * every structural path of the rule 16/17 corpus and of the predicate corpus is replaced / deleted / extended and the TS
 * reference result recomputed. Compared exactly, except that an internal-error reason ("... evaluation error (fail closed): X")
 * is compared up to the colon (the exception name is language-specific).
 */
public class K042OracleProvMutTest {
    static Map<String, Object> doc;

    @SuppressWarnings("unchecked")
    static synchronized Map<String, Object> doc() throws Exception {
        if (doc == null) try (InputStream in = new GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-oracleprov-mut.json.gz")))) {
            doc = (Map<String, Object>) IntentJs.normalize(Json.parseLenient(new String(in.readAllBytes(), StandardCharsets.UTF_8)));
        }
        return doc;
    }

    static final String EE = "evaluation error (fail closed): ";
    static String cut(String s) {
        if (s == null) return null;
        int k = s.indexOf(EE);
        return k < 0 ? s : s.substring(0, k + EE.length());
    }
    static String cutAll(String ser) { return ser.replaceAll("evaluation error \\(fail closed\\): [A-Za-z]+", "evaluation error (fail closed): "); }

    static void dump(List<String> bad, String f) throws Exception {
        if (Files.isDirectory(Path.of("target"))) Files.writeString(Path.of("target/" + f), String.join("\n", bad));
    }

    @Test void oracleprov() throws Exception {
        List<Object> cs = IntentJs.arr(doc().get("oracleprov"));
        assertTrue(cs.size() > 20000, "cases " + cs.size());
        List<String> bad = new ArrayList<>();
        for (Object co : cs) {
            Map<String, Object> c = IntentJs.obj(co);
            String name = (String) c.get("name"), kind = (String) c.get("kind");
            String got, want;
            try {
                switch (kind) {
                    case "fn":
                        got = K042OracleProvOracleTest.ser(K042OracleProvOracleTest.VALIDATORS.get((String) c.get("fn")).apply(c.get("arg")));
                        want = K042OracleProvOracleTest.ser(c.get("want"));
                        break;
                    case "active":
                        got = K042OracleProvOracleTest.ser(OracleFacts.intentWorldActive(c.get("committed"), c.get("policy")));
                        want = K042OracleProvOracleTest.ser(c.get("expect"));
                        break;
                    case "read": {
                        ParamProvenance.ReadPurposeResult r = ParamProvenance.decideReadPurpose(c.get("input"));
                        Map<String, Object> e = IntentJs.obj(c.get("expect"));
                        got = K042OracleProvOracleTest.ser(Map.of("outcome", r.outcome, "minimise", r.minimise, "uncovered", r.uncovered));
                        want = K042OracleProvOracleTest.ser(Map.of("outcome", e.get("outcome"), "minimise", e.get("minimise"), "uncovered", e.get("uncovered")));
                        break;
                    }
                    case "world": {
                        OracleFacts.WorldResult r = OracleFacts.decideIntentWorld(c.get("input"));
                        Map<String, Object> e = IntentJs.obj(c.get("expect"));
                        got = r.ok ? "ok " + K042OracleProvOracleTest.ser(r.world) + " " + K042OracleProvOracleTest.ser(r.singleSource)
                            : "fail " + K042OracleProvOracleTest.ser(r.reason);
                        want = Boolean.TRUE.equals(e.get("ok")) ? "ok " + K042OracleProvOracleTest.ser(e.get("world")) + " " + K042OracleProvOracleTest.ser(e.get("single_source"))
                            : "fail " + K042OracleProvOracleTest.ser(e.get("reason"));
                        got = cutAll(got); want = cutAll(want);
                        break;
                    }
                    case "prov": {
                        ParamProvenance.ProvResult r = ParamProvenance.decide(c.get("input"));
                        Map<String, Object> e = IntentJs.obj(c.get("expect"));
                        got = String.join(" | ", r.outcome, K042OracleProvOracleTest.ser(r.reason), K042OracleProvOracleTest.ser(r.friction), K042OracleProvOracleTest.ser(r.labels), K042OracleProvOracleTest.ser(r.classes), K042OracleProvOracleTest.ser(r.env));
                        want = String.join(" | ", (String) e.get("outcome"), K042OracleProvOracleTest.ser(e.get("reason")), K042OracleProvOracleTest.ser(e.get("friction")), K042OracleProvOracleTest.ser(e.get("labels")), K042OracleProvOracleTest.ser(e.get("classes")), K042OracleProvOracleTest.ser(e.get("env")));
                        got = cutAll(got); want = cutAll(want);
                        break;
                    }
                    default: throw new AssertionError(kind);
                }
            } catch (RuntimeException ex) { bad.add(name + " threw " + ex); continue; }
            if (!got.equals(want)) bad.add(name + "\n    got  " + got + "\n    want " + want);
        }
        dump(bad, "k042-oracleprov-mut-bad.txt");
        assertTrue(bad.isEmpty(), bad.size() + " mismatches:\n" + String.join("\n", bad.subList(0, Math.min(40, bad.size()))));
    }

    @SuppressWarnings("unchecked")
    @Test void predicates() throws Exception {
        Map<String, Object> pj = IntentJs.obj(doc().get("predjs"));
        Map<String, String> ctxs = (Map<String, String>) (Map<?, ?>) pj.get("ctx");
        List<String> bad = new ArrayList<>();
        for (Object o : IntentJs.arr(pj.get("tri"))) {
            Map<String, Object> c = IntentJs.obj(o);
            Object cond = Json.parseLenient((String) c.get("cond"));
            Predicates.Tri want = K042PredJsOracleTest.tri((String) c.get("tri"));
            Predicates.Tri got = Predicates.evaluateConditionTri(cond, (Map<String, Object>) Json.parseLenient(ctxs.get((String) c.get("ctx"))));
            if (got != want) bad.add(c.get("name") + ": want " + want + " got " + got);
        }
        for (Object o : IntentJs.arr(pj.get("preds"))) {
            Map<String, Object> c = IntentJs.obj(o);
            String ct = ctxs.get((String) c.get("ctx"));
            Object preds = Json.parseLenient((String) c.get("preds"));
            boolean got = Predicates.evaluatePredicates(preds, (Map<String, Object>) Json.parseLenient(ct));
            if (got != (Boolean) c.get("allowed")) bad.add(c.get("name") + ": allowed want " + c.get("allowed") + " got " + got);
            List<Object> each = IntentJs.arr(c.get("each"));
            List<Object> ps = (List<Object>) preds;
            for (int i = 0; i < ps.size(); i++) {
                boolean m = Predicates.predicateMatches(ps.get(i), (Map<String, Object>) Json.parseLenient(ct));
                if (m != (Boolean) each.get(i)) bad.add(c.get("name") + "[" + i + "]: want " + each.get(i) + " got " + m);
            }
        }
        dump(bad, "k042-predmut-bad.txt");
        assertTrue(bad.isEmpty(), bad.size() + " mismatches:\n" + String.join("\n", bad.subList(0, Math.min(40, bad.size()))));
    }
}
