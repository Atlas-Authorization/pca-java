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
 * 0.5 mutation kills for {@link Approval}: a differential test against the TS reference (the shared k05 approval oracle,
 * test-data/k05-approval.json.gz). Strings and digests compare exactly, objects by JSON value, a reference throw requires a
 * refusal and, where the reference names a code, an {@link Actions.ActionKitError} with that code.
 *
 * <p>Not run here: {@code spcExpectation} and {@code cibaApprovalDetails} (this SDK has no SPC / CIBA profile).
 * {@code minorToDecimal} is typed (long, long): cases whose arguments are not JSON integers are skipped (the reference refuses
 * every one of them); {@code -0} passes as 0.
 */
public class K05ApprovalDiffTest {
    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> cases() throws Exception {
        try (InputStream in = new GZIPInputStream(Files.newInputStream(Path.of("test-data/k05-approval.json.gz")))) {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            in.transferTo(b);
            Map<String, Object> doc = (Map<String, Object>) IntentJs.normalize(Json.parseLenient(b.toString(StandardCharsets.UTF_8)));
            return (List<Map<String, Object>>) doc.get("cases");
        }
    }

    static List<Map<String, Object>> of(String fn) throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> c : cases()) if (fn.equals(c.get("fn"))) out.add(c);
        assertFalse(out.isEmpty(), "no oracle cases for " + fn);
        return out;
    }
    static List<?> args(Map<String, Object> c) { return (List<?>) c.get("args"); }
    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    static void report(List<String> bad) { assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad)); }

    interface Call { Object get() throws Exception; }

    /** Null when the native agrees with the case's {@code out}, else the divergence. */
    static String diff(Map<String, Object> c, Object want, Call f) {
        Object got = null;
        Throwable err = null;
        try { got = f.get(); } catch (Throwable t) { err = t; }
        if (want instanceof Map && m(want).containsKey("$throws")) {
            Object code = m(want).get("code");
            if (err == null) return c.get("name") + "\n  want: throw " + want + "\n  got:  " + got;
            if (code != null && !(err instanceof Actions.ActionKitError && code.equals(((Actions.ActionKitError) err).code)))
                return c.get("name") + "\n  want: code " + code + "\n  got:  " + err;
            return null;
        }
        if (err != null) return c.get("name") + "\n  want: " + want + "\n  got:  THROWS " + err;
        return IntentJs.jsonEquals(want, got) ? null : c.get("name") + "\n  want: " + want + "\n  got:  " + got;
    }

    interface Fn { Object apply(List<?> a) throws Exception; }
    static void each(String fn, Fn f) throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of(fn)) {
            String d = diff(c, c.get("out"), () -> f.apply(args(c)));
            if (d != null) bad.add(d);
        }
        report(bad);
    }

    @Test void renderShapeError() throws Exception { each("approvalRenderShapeError", a -> Approval.renderShapeError(a.get(0))); }
    @Test void renderDigest() throws Exception { each("approvalRenderDigest", a -> Approval.renderDigest(a.get(0))); }
    @Test void challenge() throws Exception { each("approvalChallengeB64u", a -> Approval.challenge(a.get(0), a.get(1))); }
    @Test void bindingWords() throws Exception { each("bindingWords", a -> Approval.bindingWords(a.get(0))); }
    @Test void render() throws Exception { each("renderApproval", a -> Approval.render(m(a.get(0)), a.get(1), false)); }
    @Test void validateDef() throws Exception { each("validateDef", a -> Actions.validateDef(a.get(0))); }
    @Test void psd2Linking() throws Exception { each("psd2Linking", a -> Approval.psd2Linking(m(a.get(0)))); }

    /** A JSON integer that fits a long (beyond 2^53 included: the native must refuse it), else null (skipped). */
    static Long integral(Object o) {
        Double d = IntentJs.num(o);
        if (d == null || d != Math.rint(d) || Math.abs(d) > 1e18) return null;
        return (long) (double) d;
    }

    @Test void minorToDecimal() throws Exception {
        List<String> bad = new ArrayList<>();
        int run = 0;
        for (Map<String, Object> c : of("minorToDecimal")) {
            Long mi = integral(args(c).get(0)), ex = integral(args(c).get(1));
            if (mi == null || ex == null) continue;
            run++;
            String d = diff(c, c.get("out"), () -> Approval.minorToDecimal(mi, ex));
            if (d != null) bad.add(d);
        }
        assertTrue(run > 100, "too few integral minorToDecimal cases: " + run);
        report(bad);
    }

    @Test void batch() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of("approvalBatch")) {
            Object want = c.get("out");
            if (want instanceof Map && m(want).get("challenge") instanceof Map) {
                // the reference returns the challenge as bytes ({$bytes: b64url}); this SDK returns the b64url string
                Map<String, Object> w = new LinkedHashMap<>(m(want));
                w.put("challenge", m(w.get("challenge")).get("$bytes"));
                want = w;
            }
            String d = diff(c, want, () -> Approval.batch((List<?>) args(c).get(0)));
            if (d != null) bad.add(d);
        }
        report(bad);
    }
}
