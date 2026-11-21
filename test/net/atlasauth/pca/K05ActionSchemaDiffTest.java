package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for {@link ActionSchema}: a differential test against the TS reference (shared oracle
 * test-data/k05-actionschema.json.gz, written by tools/pca-audit/k05-oracles/actionschema-oracle.mts): generated variants of a
 * fully populated v2 and v1 schema (every member deleted / retyped / at its byte limit), every collection limit, the parameter
 * paths, every declaration rule per type, reversibility_by, the confirmation and floors shapes, paramValueViolation over every
 * type and every v2 format, and formatCheck. Exact strings; the strict canonicalizer's own message is language-specific (only the
 * "malformed schema: canonicalize: " prefix is compared) and four value-domain reasons carry the bound only in TS
 * ({@link K042ActionSchemaTest#javaReason}).
 */
public class K05ActionSchemaDiffTest {
    static final String MODULE = "k05-actionschema";
    static final String MALFORMED = "malformed schema: canonicalize: ";

    static List<Map<String, Object>> cases(String fn) throws Exception {
        List<Map<String, Object>> cs = K05Oracle.of(MODULE, fn);
        assertFalse(cs.isEmpty(), "no " + fn + " cases");
        return cs;
    }

    @SuppressWarnings("unchecked")
    static List<Object> args(Map<String, Object> c) { return (List<Object>) c.get("args"); }

    static boolean refThrows(Object out) { return out instanceof Map && ((Map<?, ?>) out).containsKey("$throws"); }

    static void report(String fn, List<String> bad, int n) {
        if (!bad.isEmpty()) fail(fn + ": " + bad.size() + "/" + n + " mismatches:\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 60))));
    }

    interface StrFn { String apply(Object x); }

    static void strings(String fn, StrFn f) throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases(fn);
        for (Map<String, Object> c : cs) {
            Object out = c.get("out");
            String got;
            try {
                got = f.apply(args(c).get(0));
            } catch (RuntimeException e) {
                got = "threw " + e;
            }
            if (refThrows(out)) {
                if (got == null) bad.add(c.get("name") + ": reference threw, got null"); // any refusal is fine
                continue;
            }
            String want = (String) out;
            if (want != null && got != null && want.startsWith(MALFORMED) && got.startsWith(MALFORMED) && !got.endsWith("null")) continue;
            if (!Objects.equals(want, got)) bad.add(c.get("name") + ": want <" + want + "> got <" + got + ">");
        }
        report(fn, bad, cs.size());
    }

    @Test void shape() throws Exception { strings("shape", ActionSchema::shapeError); }

    @Test void shapeUnsigned() throws Exception { strings("shapeUnsigned", x -> ActionSchema.shapeError(x, false)); }

    @Test void confirmation() throws Exception { strings("confirmation", ActionSchema::confirmationShapeError); }

    @Test void floors() throws Exception { strings("floors", ActionSchema::schemaFloorsError); }

    @Test
    void paramValueViolation() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases("pvv");
        for (Map<String, Object> c : cs) {
            Object out = c.get("out");
            String got;
            try {
                String[] r = ActionSchema.paramValueViolation(IntentJs.obj(args(c).get(0)), args(c).get(1));
                got = r == null ? null : r.length != 2 ? "length " + r.length : r[0] + "|" + r[1];
            } catch (RuntimeException e) {
                got = "threw " + e;
            }
            if (refThrows(out)) {
                if (got == null || !got.startsWith("threw ")) bad.add(c.get("name") + ": reference threw, got <" + got + ">");
                continue;
            }
            String want = out == null ? null : IntentJs.get(out, "code") + "|" + K042ActionSchemaTest.javaReason((String) IntentJs.get(out, "reason"));
            if (!Objects.equals(want, got)) bad.add(c.get("name") + ": want <" + want + "> got <" + got + ">");
        }
        report("pvv", bad, cs.size());
    }

    @Test
    void formatCheck() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases("format");
        for (Map<String, Object> c : cs) {
            Object want = c.get("out");
            Object got;
            try {
                java.util.function.Predicate<String> ck = ActionSchema.formatCheck((String) args(c).get(0));
                got = ck == null ? "unknown" : (Object) ck.test((String) args(c).get(1));
            } catch (RuntimeException e) {
                got = "threw " + e;
            }
            if (!Objects.equals(want, got)) bad.add(c.get("name") + ": want <" + want + "> got <" + got + ">");
        }
        report("format", bad, cs.size());
    }
}
