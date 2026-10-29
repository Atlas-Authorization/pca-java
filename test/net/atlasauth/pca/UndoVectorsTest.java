package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Undo windows: undo-vectors.json (compensation digests, the one-click token and its checks, receipts and chains, the state
 * machine, the window clamp and the {@code undo_window} obligation), computed by the TypeScript reference. Every section is replayed
 * with full equality; signing is deterministic Ed25519, so the signed artifacts are reproduced byte for byte. A missing file FAILS.
 */
public class UndoVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("undo-vectors.json");

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Object> l(Object o) {
        assertTrue(o instanceof List && !((List<?>) o).isEmpty(), "missing or empty table");
        return (List<Object>) o;
    }

    static void same(Object want, Object got, String name) {
        assertTrue(IntentJs.jsonEquals(want, got), name + ": want " + want + ", got " + got);
    }

    /** The vector signer: Ed25519 seed = SHA-256(seed_label). */
    static Keys.EdKey signer() throws Exception {
        String label = (String) m(DOC.get("signer")).get("seed_label");
        return Keys.edFromSeed(MessageDigest.getInstance("SHA-256").digest(label.getBytes(StandardCharsets.UTF_8)));
    }

    static String pub() { return (String) m(DOC.get("signer")).get("public"); }

    static Double dbl(Object o) { return o == null ? null : IntentJs.num(o); }

    @Test void format() throws Exception {
        assertEquals("pca-undo-vectors", DOC.get("format"));
        assertEquals(1L, Json.asLong(DOC.get("ver")));
        assertEquals(pub(), signer().id(), "the signer seed derives the published key");
    }

    @Test void compensation() {
        List<Object> rs = l(DOC.get("compensation"));
        assertEquals(3, rs.size());
        for (Object o : rs) {
            Map<String, Object> c = m(o);
            assertEquals(c.get("digest"), Undo.compensationDigest(m(c.get("compensation"))), "compensation " + c.get("name"));
        }
    }

    @Test void token() throws Exception {
        Map<String, Object> t = m(DOC.get("token"));
        Map<String, Object> token = Undo.signToken(m(t.get("record")), signer());
        same(t.get("token"), token, "signToken");
        assertEquals(t.get("encoded"), Undo.encodeToken(token), "encodeToken");
        assertEquals(t.get("digest"), Undo.tokenDigest(token), "tokenDigest");
        same(t.get("token"), Undo.decodeToken(t.get("encoded")), "decodeToken");
        assertNull(Undo.decodeToken(((String) t.get("encoded")) + "="), "a padded encoding is not a token");
    }

    @Test void tokenChecks() {
        List<Object> rs = l(m(DOC.get("token")).get("checks"));
        assertEquals(12, rs.size());
        for (Object o : rs) {
            Map<String, Object> c = m(o);
            assertEquals(c.get("expect"), Undo.tokenCheck(c.get("token"), (String) c.get("signer"), m(c.get("record")), c.get("now")),
                "token check " + c.get("name"));
        }
    }

    @Test void receipts() throws Exception {
        List<Object> rs = l(m(DOC.get("receipts")).get("list"));
        assertEquals(4, rs.size());
        for (Object o : rs) {
            Map<String, Object> x = m(o), r = m(x.get("receipt"));
            assertTrue(Undo.verifyReceipt(r, pub()), "receipt verifies: " + r.get("event"));
            assertEquals(x.get("digest"), Undo.receiptDigest(r), "receipt digest " + r.get("event"));
            Map<String, Object> body = new LinkedHashMap<>();
            for (String k : new String[] {"record", "event", "state", "at", "compensation_digest", "prev", "note"}) body.put(k, r.get(k));
            same(r, Undo.signReceipt(body, signer()), "signReceipt " + r.get("event"));
        }
    }

    @Test void chains() {
        List<Object> rs = l(m(DOC.get("receipts")).get("chains"));
        assertEquals(12, rs.size());
        for (Object o : rs) {
            Map<String, Object> c = m(o);
            Map<String, Object> rec = new LinkedHashMap<>(m(c.get("record")));
            rec.put("receipts", c.get("receipts"));
            String signer = c.get("signer") instanceof String ? (String) c.get("signer") : pub();
            String err = Undo.receiptChainError(rec, signer);
            assertEquals(Boolean.TRUE.equals(m(c.get("expect")).get("ok")), err == null, "chain " + c.get("name") + ": " + err);
        }
    }

    @Test void transitions() {
        List<Object> rs = l(DOC.get("transitions"));
        assertEquals(33, rs.size());
        for (Object o : rs) {
            Map<String, Object> c = m(o), e = m(c.get("expect"));
            Undo.Transition t = Undo.transition(c.get("record"), c.get("event"), c.get("now"));
            Map<String, Object> got = new LinkedHashMap<>();
            got.put("outcome", t.outcome);
            if ("refused".equals(t.outcome)) got.put("code", t.code);
            if ("applied".equals(t.outcome)) {
                got.put("state", t.record.get("state"));
                got.put("ver", t.record.get("ver"));
                if (e.containsKey("attempt")) got.put("attempt", t.record.get("attempt"));
            }
            same(e, got, "transition " + c.get("name"));
        }
    }

    @Test void window() {
        List<Object> rs = l(DOC.get("window"));
        assertEquals(9, rs.size());
        for (Object o : rs) {
            Map<String, Object> c = m(o), p = m(c.get("policy"));
            long got = Undo.resolveWindow(dbl(c.get("requested")), dbl(p.get("minMs")), dbl(p.get("maxMs")), dbl(p.get("defaultMs")));
            assertEquals(Json.asLong(c.get("expect")), got, "window " + c.get("name"));
        }
    }

    @Test void obligation() {
        List<Object> rs = l(DOC.get("obligation"));
        assertEquals(6, rs.size());
        for (Object o : rs) {
            Map<String, Object> c = m(o);
            String err = Obligations.listError(List.of(c.get("obligation")));
            assertEquals(Boolean.TRUE.equals(m(c.get("expect")).get("ok")), err == null, "obligation " + c.get("name") + ": " + err);
        }
    }
}
