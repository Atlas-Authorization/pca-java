package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Rule 14 (signed action schemas, closed-world conformance) 0.4.2 mutation kills, DIFFERENTIAL against the TypeScript
 * reference: test-data/k042-actionschema.json is written by tools/pca-audit/java-mutate/k042-actionschema-oracle.mts
 * (actionSchemaShapeError / verifyActionSchema / paramValueViolation / conformAction / accumulationParams /
 * canonProjection on targeted inputs at the exact boundary of every rule). Every input is raw JSON text so both sides see
 * the same value. Exact reasons are compared; the four value-domain reasons Java spells without the bound (pinned by the
 * conformance reason snapshot, reasons are not part of the compared verdict) are mapped by {@link #javaReason}.
 */
public class K042ActionSchemaTest {
    static final String DATA = "test-data/k042-actionschema.json";

    @SuppressWarnings("unchecked")
    static Map<String, Object> data() throws Exception {
        return (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(DATA), StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> cases(String kind) throws Exception { return (List<Map<String, Object>>) (Object) data().get(kind); }

    /** A raw JSON input as the verifier sees it. */
    static Object j(Object raw) { return IntentJs.normalize(Json.parseLenient((String) raw)); }

    /** The Java spelling of a TS value-domain reason (Java omits the bound in four reasons). */
    static String javaReason(String ts) {
        if (ts == null) return null;
        return ts.replaceAll("longer than \\d+ UTF-8 bytes$", "longer than the declared max_len")
            .replaceAll("below min -?\\d+$", "below min")
            .replaceAll("above max -?\\d+$", "above max")
            .replaceAll("array items must be strings of at most \\d+ UTF-8 bytes$", "array items must be strings within max_len UTF-8 bytes");
    }

    static void report(List<String> bad, int n) {
        if (!bad.isEmpty()) fail(bad.size() + "/" + n + " mismatches:\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 60))));
    }

    @Test
    void shape() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases("shape");
        for (Map<String, Object> c : cs) {
            String want = (String) c.get("expect");
            String got = ActionSchema.shapeError(j(c.get("doc")));
            // the strict canonicalizer's own message is language-specific: compare the shape-level prefix (the exact
            // Java texts are pinned in malformedMessages)
            if (want != null && want.startsWith(MALFORMED) && got != null && got.startsWith(MALFORMED) && !got.endsWith("null")) continue;
            if (!java.util.Objects.equals(want, got)) bad.add(c.get("name") + ": want <" + want + "> got <" + got + ">");
        }
        report(bad, cs.size());
    }

    static final String MALFORMED = "malformed schema: canonicalize: ";

    @Test
    void malformedMessages() {
        Map<String, Object> d = IntentJs.obj(j(cases0("shape/base")));
        d.put("state", j("[-0]"));
        assertEquals("malformed schema: canonicalize: negative zero is not allowed", ActionSchema.shapeError(d));
        d.put("state", j("[1e21]"));
        assertEquals("malformed schema: canonicalize: integer outside the safe range", ActionSchema.shapeError(d));
    }

    static Object cases0(String name) {
        try {
            for (Map<String, Object> c : cases("shape")) if (name.equals(c.get("name"))) return c.get("doc");
        } catch (Exception e) { throw new IllegalStateException(e); }
        throw new IllegalStateException("no case " + name);
    }

    @Test
    void paramValueViolation() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases("pvv");
        for (Map<String, Object> c : cs) {
            Object e = c.get("expect");
            String want = e == null ? null : IntentJs.get(e, "code") + "|" + javaReason((String) IntentJs.get(e, "reason"));
            String[] r = ActionSchema.paramValueViolation(IntentJs.obj(j(c.get("d"))), j(c.get("x")));
            String got = r == null ? null : r.length + ":" + r[0] + "|" + r[1];
            if (r != null && r.length == 2) got = r[0] + "|" + r[1];
            if (!java.util.Objects.equals(want, got)) bad.add(c.get("name") + ": want <" + want + "> got <" + got + ">");
        }
        report(bad, cs.size());
    }

    @Test
    void conform() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases("conform");
        for (Map<String, Object> c : cs) {
            Map<String, Object> e = IntentJs.obj(c.get("expect"));
            String want = Boolean.TRUE.equals(e.get("ok")) ? "ok|null|null|null"
                : "false|" + e.get("code") + "|" + e.get("path") + "|" + javaReason((String) e.get("reason"));
            String got;
            try {
                ActionSchema.Conform r = ActionSchema.conform(j(c.get("doc")), (String) c.get("verb"), j(c.get("params")));
                got = (r.ok ? "ok" : "false") + "|" + r.code + "|" + r.path + "|" + r.reason;
            } catch (RuntimeException x) {
                got = "threw " + x;
            }
            if (!want.equals(got)) bad.add(c.get("name") + ": want <" + want + "> got <" + got + ">");
        }
        report(bad, cs.size());
    }

    @Test
    void verify() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases("verify");
        for (Map<String, Object> c : cs) {
            String want = (String) c.get("expect");
            String got = ActionSchema.verify(j(c.get("doc")), j(c.get("keys")));
            if (!java.util.Objects.equals(want, got)) bad.add(c.get("name") + ": want <" + want + "> got <" + got + ">");
        }
        report(bad, cs.size());
    }

    @Test
    void accumulationParams() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases("acc");
        for (Map<String, Object> c : cs) {
            Object want = c.get("expect");
            Object got;
            try { got = ActionSchema.accumulationParams(IntentJs.obj(j(c.get("v"))), (String) c.get("unit")); }
            catch (RuntimeException x) { got = "threw " + x; }
            if (!java.util.Objects.equals(want, got)) bad.add(c.get("name") + ": want <" + want + "> got <" + got + ">");
        }
        report(bad, cs.size());
    }

    @Test
    void canonProjection() throws Exception {
        List<String> bad = new ArrayList<>();
        List<Map<String, Object>> cs = cases("canon");
        for (Map<String, Object> c : cs) {
            Map<String, Object> e = IntentJs.obj(c.get("expect"));
            Object want = Boolean.TRUE.equals(e.get("ok")) ? e.get("out") : "threw";
            Object got;
            try { got = ActionSchema.canonProjection(j(c.get("doc")), (String) c.get("verb"), IntentJs.obj(j(c.get("params")))); }
            catch (RuntimeException x) { got = "threw"; }
            if (!java.util.Objects.equals(want, got)) bad.add(c.get("name") + ": want <" + want + "> got <" + got + ">");
        }
        report(bad, cs.size());
    }

    /** The verdict record keeps every field it is built with (Conform.OK itself is built once, in the static initializer). */
    @Test
    void conformRecord() {
        ActionSchema.Conform ok = new ActionSchema.Conform(true, "c", "p", "r");
        assertTrue(ok.ok);
        assertEquals("c", ok.code);
        assertEquals("p", ok.path);
        assertEquals("r", ok.reason);
        assertTrue(ActionSchema.Conform.OK.ok);
        assertNull(ActionSchema.Conform.OK.code);
    }

    /** An unknown verb projects to an EMPTY, MUTABLE map, like a known verb (the caller owns the env it is put into). */
    @Test
    void canonProjectionUnknownVerbIsAFreshMap() {
        Map<String, Object> doc = IntentJs.obj(j("{\"verbs\":[{\"verb\":\"v\",\"kind\":\"read\",\"params\":{}}]}"));
        for (String verb : new String[] {"v", "nope"}) {
            Map<String, Object> out = ActionSchema.canonProjection(doc, verb, new java.util.LinkedHashMap<>());
            assertTrue(out.isEmpty());
            out.put("x", "y");
            assertEquals("y", out.get("x"));
        }
    }
}
