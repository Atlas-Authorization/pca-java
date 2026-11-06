package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link Undo}: a differential test against the TS reference (the shared k05 undo oracle,
 * test-data/k05-undo.json.gz). Strings, codes and digests compare exactly, objects by JSON value; a reference throw requires a
 * refusal (the reference's {@code signer_missing} code is the key loader's refusal here: a secret that is not 32 bytes never
 * becomes a key). A non-object record argument reads like JavaScript property access: {@code null} stays null (the reference
 * throws), any other scalar or array is an object without members.
 */
public class K05UndoDiffTest {
    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> cases() throws Exception {
        try (InputStream in = new GZIPInputStream(Files.newInputStream(Path.of("test-data/k05-undo.json.gz")))) {
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

    /** JavaScript property reads on a non-object: null stays null, anything else has no members. */
    static Map<String, Object> js(Object o) { return o == null ? null : o instanceof Map ? m(o) : new LinkedHashMap<>(); }
    static Keys.EdKey key(Object b64u) { return Keys.edFromSeed(Base64.getUrlDecoder().decode((String) b64u)); }
    static Double dbl(Object o) { return o == null ? null : IntentJs.num(o); }

    interface Call { Object get() throws Exception; }

    static String diff(Map<String, Object> c, Object want, Call f) {
        Object got = null;
        Throwable err = null;
        try { got = f.get(); } catch (Throwable t) { err = t; }
        if (want instanceof Map && m(want).containsKey("$throws"))
            return err != null ? null : c.get("name") + "\n  want: throw " + want + "\n  got:  " + got;
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

    @Test void compensationDigest() throws Exception { each("compensationDigest", a -> Undo.compensationDigest(js(a.get(0)))); }
    @Test void signToken() throws Exception { each("signUndoToken", a -> Undo.signToken(js(a.get(0)), key(a.get(1)))); }
    @Test void tokenCheck() throws Exception {
        each("undoTokenCheck", a -> Undo.tokenCheck(a.get(0), (String) a.get(1), js(a.get(2)), a.get(3)));
    }
    @Test void encodeToken() throws Exception { each("encodeUndoToken", a -> Undo.encodeToken(m(a.get(0)))); }
    @Test void tokenDigest() throws Exception { each("undoTokenDigest", a -> Undo.tokenDigest(m(a.get(0)))); }
    @Test void signReceipt() throws Exception { each("signUndoReceipt", a -> Undo.signReceipt(m(a.get(0)), key(a.get(1)))); }
    @Test void receiptDigest() throws Exception { each("undoReceiptDigest", a -> Undo.receiptDigest(m(a.get(0)))); }
    @Test void verifyReceipt() throws Exception { each("verifyUndoReceipt", a -> Undo.verifyReceipt(a.get(0), (String) a.get(1))); }
    @Test void receiptChainError() throws Exception { each("undoReceiptChainError", a -> Undo.receiptChainError(js(a.get(0)), (String) a.get(1))); }


    @Test void decodeToken() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : of("decodeUndoToken")) {
            String d = diff(c, c.get("out"), () -> Undo.decodeToken(args(c).get(0)));
            if (d != null) bad.add(d);
        }
        report(bad);
    }

    @Test void transition() throws Exception {
        each("undoTransition", a -> {
            Undo.Transition t = Undo.transition(a.get(0), a.get(1), a.get(2));
            Map<String, Object> got = new LinkedHashMap<>();
            got.put("outcome", t.outcome);
            if ("refused".equals(t.outcome)) {
                got.put("code", t.code);
                got.put("reason", t.reason);
            } else {
                got.put("record", t.record);
                if ("applied".equals(t.outcome)) {
                    Map<String, Object> r = new LinkedHashMap<>();
                    r.put("event", t.event);
                    r.put("note", t.note);
                    got.put("receipt", r);
                }
            }
            return got;
        });
    }

    @Test void resolveWindow() throws Exception {
        each("resolveUndoWindow", a -> {
            Map<String, Object> p = js(a.get(1));
            return Undo.resolveWindow(dbl(a.get(0)), dbl(p.get("minMs")), dbl(p.get("maxMs")), dbl(p.get("defaultMs")));
        });
    }
}
