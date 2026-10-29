package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** 0.5 mutation kills (undo windows): every boundary of {@link Undo} and the {@code undo_window} obligation, with literal expectations. */
public class UndoKillTest {
    static Keys.EdKey key(int b) {
        byte[] x = new byte[32];
        Arrays.fill(x, (byte) b);
        return Keys.edFromSeed(x);
    }

    static final Keys.EdKey K = key(3), OTHER = key(4);
    static final long END = 1_800_000_900_000L, T0 = 1_800_000_000_000L;
    static final String D = Pca.b64(new byte[32]);

    static Map<String, Object> record() {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("id", "op_1");
        r.put("aud", "drafts-rs");
        r.put("principal", "P");
        r.put("compensation_digest", D);
        r.put("render_digest", "R");
        r.put("window_end", END);
        return r;
    }

    static Map<String, Object> with(Map<String, Object> m, String k, Object v) {
        Map<String, Object> c = new LinkedHashMap<>(m);
        if (v == null) c.remove(k);
        else c.put(k, v);
        return c;
    }

    @Test void constants() {
        assertEquals(List.of("atlas-pca/undo-token/v1\0", "atlas-pca/undo-receipt/v1\0", "atlas-pca/undo-compensation/v1", "atlas-pca/undo-receipt-ref/v1",
            "atlas-pca/undo-token-ref/v1", "pca-undo-token", "pca-undo-receipt"),
            List.of(Undo.TOKEN_DOMAIN, Undo.RECEIPT_DOMAIN, Undo.COMPENSATION_DOMAIN, Undo.RECEIPT_REF_DOMAIN, Undo.TOKEN_REF_DOMAIN, Undo.TOKEN_KIND, Undo.RECEIPT_KIND));
        assertEquals(List.of(30_000L, 900_000L, 86_400_000L), List.of(Undo.MIN_WINDOW_MS, Undo.DEFAULT_WINDOW_MS, Undo.MAX_WINDOW_MS));
    }

    @Test void idBounds() {
        assertTrue(Undo.idOk("x"));
        assertTrue(Undo.idOk("x".repeat(256)));
        assertFalse(Undo.idOk("x".repeat(257)));
        assertFalse(Undo.idOk(""));
        assertFalse(Undo.idOk("a\u001fb"));
        assertTrue(Undo.idOk("a b"));
        assertFalse(Undo.idOk(1L));
    }

    @Test void compensationDigestBindsTargetParamOnlyWhenPresent() {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("verb", "drafts.delete");
        c.put("resource", "drafts:box1");
        c.put("params", Map.of("box", "box1"));
        c.put("undo_of", "op_1");
        c.put("def_digest", D);
        String base = Undo.compensationDigest(c);
        assertEquals(base, Undo.compensationDigest(c));
        assertFalse(base.equals(Undo.compensationDigest(with(c, "target_param", "draft"))));
        assertFalse(base.equals(Undo.compensationDigest(with(c, "verb", "drafts.restore"))));
        assertEquals(base, Undo.compensationDigest(with(c, "extra", "ignored")), "only the defined members are bound");
    }

    @Test void everyTokenCheckCodeInOrder() {
        Map<String, Object> rec = record(), t = Undo.signToken(rec, K);
        String s = K.id();
        assertEquals("ok", Undo.tokenCheck(t, s, rec, T0));
        // malformed: shape first, before the signer is even looked at
        assertEquals("malformed", Undo.tokenCheck(with(t, "x", 1L), OTHER.id(), rec, T0));
        assertEquals("malformed", Undo.tokenCheck(with(t, "sig", null), s, rec, T0));
        assertEquals("malformed", Undo.tokenCheck(with(t, "v", 2L), s, rec, T0));
        assertEquals("malformed", Undo.tokenCheck(with(t, "exp", 1.5), s, rec, T0));
        assertEquals("malformed", Undo.tokenCheck(with(t, "sig", "AAAA"), s, rec, T0));
        assertEquals("malformed", Undo.tokenCheck(with(t, "record", ""), s, rec, T0));
        assertEquals("malformed", Undo.tokenCheck("token", s, rec, T0));
        // signer before signature
        assertEquals("signer", Undo.tokenCheck(with(t, "exp", END + 1), OTHER.id(), rec, T0));
        // signature before record and binding
        assertEquals("signature", Undo.tokenCheck(with(t, "record", "op_2"), s, rec, T0));
        assertEquals("signature", Undo.tokenCheck(with(Undo.signToken(rec, OTHER), "signer", s), s, rec, T0), "another key claiming the pinned signer");
        // record before binding
        assertEquals("record", Undo.tokenCheck(Undo.signToken(with(rec, "id", "op_2"), K), s, with(rec, "aud", "x"), T0));
        for (String k : new String[] {"aud", "principal", "compensation_digest", "render_digest"})
            assertEquals("binding", Undo.tokenCheck(Undo.signToken(with(rec, k, "other"), K), s, rec, T0), k);
        assertEquals("binding", Undo.tokenCheck(Undo.signToken(with(rec, "window_end", END + 1), K), s, rec, T0), "exp");
        // a record without a render digest binds the empty string
        Map<String, Object> noRender = with(rec, "render_digest", null);
        assertEquals("", Undo.signToken(noRender, K).get("render_digest"));
        assertEquals("ok", Undo.tokenCheck(Undo.signToken(noRender, K), s, noRender, T0));
        assertEquals("binding", Undo.tokenCheck(Undo.signToken(noRender, K), s, rec, T0));
        // expired: valid THROUGH exp, inclusive
        assertEquals("ok", Undo.tokenCheck(t, s, rec, END));
        assertEquals("expired", Undo.tokenCheck(t, s, rec, END + 1));
        assertEquals("expired", Undo.tokenCheck(t, s, rec, (Object) 1.5));
        assertEquals("expired", Undo.tokenCheck(t, s, rec, (Object) null));
    }

    @Test void tokenEncodingIsStrict() {
        Map<String, Object> t = Undo.signToken(record(), K);
        String enc = Undo.encodeToken(t);
        assertTrue(IntentJs.jsonEquals(t, Undo.decodeToken(enc)));
        assertNull(Undo.decodeToken(enc + "="));
        assertNull(Undo.decodeToken(""));
        assertNull(Undo.decodeToken("x".repeat(4097)));
        assertNull(Undo.decodeToken(Pca.b64("[1]".getBytes(java.nio.charset.StandardCharsets.UTF_8))));
        assertNull(Undo.decodeToken(Pca.b64(new byte[] {(byte) 0xff, '{', '}'})));
        assertNull(Undo.decodeToken(1L));
        assertFalse(Undo.tokenDigest(t).equals(Undo.tokenDigest(with(t, "exp", END + 1))));
    }

    static Map<String, Object> receiptBody(String event, String state, long at, String prev) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("record", "op_1");
        b.put("event", event);
        b.put("state", state);
        b.put("at", at);
        b.put("compensation_digest", D);
        b.put("prev", prev);
        b.put("note", "");
        return b;
    }

    @Test void receiptMembersAreExactlyEleven() {
        Map<String, Object> r = Undo.signReceipt(receiptBody("opened", "open", T0, ""), K);
        assertEquals(11, r.size());
        assertTrue(Undo.verifyReceipt(r, K.id()));
        assertFalse(Undo.verifyReceipt(with(r, "x", 1L), K.id()));
        assertFalse(Undo.verifyReceipt(with(r, "note", null), K.id()));
        assertFalse(Undo.verifyReceipt(r, OTHER.id()));
        assertFalse(Undo.verifyReceipt(with(r, "note", "tampered"), K.id()));
        assertFalse(Undo.verifyReceipt(Undo.signReceipt(receiptBody("exploded", "open", T0, ""), K), K.id()));
        assertFalse(Undo.verifyReceipt(Undo.signReceipt(receiptBody("opened", "pending", T0, ""), K), K.id()));
        assertFalse(Undo.verifyReceipt(null, K.id()));
    }

    static Map<String, Object> chain(String state, List<Map<String, Object>> rs) {
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("id", "op_1");
        rec.put("compensation_digest", D);
        rec.put("state", state);
        rec.put("receipts", rs);
        return rec;
    }

    @Test void chainPrevAtAndLastState() {
        Map<String, Object> r0 = Undo.signReceipt(receiptBody("opened", "open", T0, ""), K);
        Map<String, Object> r1 = Undo.signReceipt(receiptBody("vetoed", "vetoed", T0, Undo.receiptDigest(r0)), K); // equal at is fine
        Map<String, Object> r2 = Undo.signReceipt(receiptBody("compensated", "compensated", T0 + 5, Undo.receiptDigest(r1)), K);
        assertNull(Undo.receiptChainError(chain("compensated", List.of(r0, r1, r2)), K.id()));
        assertNull(Undo.receiptChainError(chain("vetoed", List.of(r0, r1)), K.id()));
        assertEquals("no receipts", Undo.receiptChainError(chain("open", List.of()), K.id()));
        assertEquals("the last receipt does not state the record state", Undo.receiptChainError(chain("open", List.of(r0, r1)), K.id()));
        assertEquals("receipt 1 does not link to the previous one", Undo.receiptChainError(chain("compensated", List.of(r0, r2)), K.id()));
        // the first prev is the empty string
        Map<String, Object> firstLinked = Undo.signReceipt(receiptBody("opened", "open", T0, Undo.receiptDigest(r0)), K);
        assertEquals("receipt 0 does not link to the previous one", Undo.receiptChainError(chain("open", List.of(firstLinked)), K.id()));
        Map<String, Object> back = Undo.signReceipt(receiptBody("vetoed", "vetoed", T0 - 1, Undo.receiptDigest(r0)), K);
        assertEquals("receipt 1 goes back in time", Undo.receiptChainError(chain("vetoed", List.of(r0, back)), K.id()));
        assertEquals("the first receipt is not opened", Undo.receiptChainError(chain("vetoed", List.of(Undo.signReceipt(receiptBody("vetoed", "vetoed", T0, ""), K))), K.id()));
        assertEquals("receipt 0 does not verify", Undo.receiptChainError(chain("vetoed", List.of(r0, r1)), OTHER.id()));
        assertEquals("receipt 0 is for another record", Undo.receiptChainError(with(chain("vetoed", List.of(r0, r1)), "id", "op_2"), K.id()));
        assertEquals("receipt 0 is for another record", Undo.receiptChainError(with(chain("vetoed", List.of(r0, r1)), "compensation_digest", "x"), K.id()));
    }

    static Map<String, Object> rec(String state, Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("state", state);
        r.put("window_end", END);
        r.put("ver", 3L);
        r.put("attempt", 0L);
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }

    static Map<String, Object> veto(String via, String by) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("at", T0);
        v.put("via", via);
        v.put("by", by);
        return Map.of("kind", "veto", "veto", v);
    }

    static String code(Undo.Transition t) { return t.outcome + (t.code == null ? "" : ":" + t.code); }

    @Test void transitions() {
        Map<String, Object> eff = Map.of("at", T0);
        // the veto window is inclusive of window_end
        Undo.Transition v = Undo.transition(rec("open"), veto("token", "P"), END);
        assertEquals("applied", v.outcome);
        assertEquals("vetoed", v.record.get("state"));
        assertEquals(4L, IntentJs.lng(v.record.get("ver")));
        assertEquals("vetoed", v.event);
        assertEquals("token", v.note);
        assertTrue(IntentJs.jsonEquals(veto("token", "P").get("veto"), v.record.get("veto")));
        assertEquals("refused:window_closed", code(Undo.transition(rec("open"), veto("token", "P"), END + 1)));
        for (String s : new String[] {"vetoed", "compensated", "compensation_failed"}) assertEquals("replayed", code(Undo.transition(rec(s), veto("operator", "P"), T0)));
        assertEquals("refused:finalized", code(Undo.transition(rec("finalized"), veto("token", "P"), T0)));
        assertEquals("refused:invalid", code(Undo.transition(rec("open"), veto("email", "P"), T0)));
        assertEquals("refused:invalid", code(Undo.transition(rec("open"), veto("token", ""), T0)));
        // finalize only strictly after window_end
        assertEquals("refused:window_open", code(Undo.transition(rec("open"), Map.of("kind", "finalize"), END)));
        Undo.Transition f = Undo.transition(rec("open"), Map.of("kind", "finalize"), END + 1);
        assertEquals("finalized", f.record.get("state"));
        assertTrue(IntentJs.jsonEquals(Map.of("at", END + 1, "status", "finalized"), f.record.get("outcome")));
        assertEquals("replayed", code(Undo.transition(rec("finalized"), Map.of("kind", "finalize"), END + 1)));
        assertEquals("refused:vetoed", code(Undo.transition(rec("vetoed"), Map.of("kind", "finalize"), END + 1)));
        // abort: only before the effect; the reason is cut to 512 (record) and 128 (receipt note) characters
        Undo.Transition a = Undo.transition(rec("open"), Map.of("kind", "abort", "reason", "r".repeat(600)), T0);
        assertEquals("finalized", a.record.get("state"));
        assertEquals(512, ((String) ((Map<?, ?>) a.record.get("outcome")).get("reason")).length());
        assertEquals(128, a.note.length());
        assertEquals("aborted", a.event);
        assertEquals("refused:effect_recorded", code(Undo.transition(rec("open", "effect", eff), Map.of("kind", "abort", "reason", "x"), T0)));
        assertEquals("replayed", code(Undo.transition(rec("finalized", "outcome", Map.of("at", T0, "status", "aborted")), Map.of("kind", "abort", "reason", "x"), T0)));
        assertEquals("refused:finalized", code(Undo.transition(rec("finalized", "outcome", Map.of("at", T0, "status", "finalized")), Map.of("kind", "abort", "reason", "x"), T0)));
        // effect
        Undo.Transition e = Undo.transition(rec("open"), Map.of("kind", "effect", "result", Map.of("id", "d_1")), T0);
        assertTrue(IntentJs.jsonEquals(Map.of("at", T0, "result", Map.of("id", "d_1")), e.record.get("effect")));
        assertEquals("replayed", code(Undo.transition(rec("open", "effect", eff), Map.of("kind", "effect"), T0)));
        assertEquals("refused:finalized", code(Undo.transition(rec("finalized"), Map.of("kind", "effect"), T0)));
        // compensation
        assertEquals("compensated", Undo.transition(rec("compensation_failed", "effect", eff), Map.of("kind", "compensated"), T0).record.get("state"));
        assertEquals("refused:not_vetoed", code(Undo.transition(rec("open", "effect", eff), Map.of("kind", "compensated"), T0)));
        assertEquals("refused:not_vetoed", code(Undo.transition(rec("open", "effect", eff), Map.of("kind", "compensation_failed", "reason", "x"), T0)));
        assertEquals("replayed", code(Undo.transition(rec("compensation_failed"), Map.of("kind", "compensation_failed", "reason", "x"), T0)));
        Undo.Transition r = Undo.transition(rec("compensation_failed", "attempt", 2L), Map.of("kind", "retry"), T0);
        assertEquals("vetoed", r.record.get("state"));
        assertEquals(3L, IntentJs.lng(r.record.get("attempt")));
        assertEquals("retried", r.event);
        assertEquals("refused:not_failed", code(Undo.transition(rec("vetoed"), Map.of("kind", "retry"), T0)));
        // malformed inputs refuse, never throw
        assertEquals("refused:invalid", code(Undo.transition(rec("open"), Map.of("kind", "explode"), T0)));
        assertEquals("refused:invalid", code(Undo.transition(rec("pending"), veto("token", "P"), T0)));
        assertEquals("refused:invalid", code(Undo.transition(rec("open"), veto("token", "P"), (Object) 1.5)));
        assertEquals("refused:invalid", code(Undo.transition(null, veto("token", "P"), T0)));
        assertEquals("refused:invalid", code(Undo.transition(rec("open"), null, T0)));
        // the input record is never modified
        Map<String, Object> before = rec("open");
        Undo.transition(before, veto("token", "P"), T0);
        assertEquals("open", before.get("state"));
        assertEquals(3L, before.get("ver"));
    }

    @Test void windowClampEdges() {
        assertEquals(900_000L, Undo.resolveWindow(null, null, null, null));
        assertEquals(900_000L, Undo.resolveWindow(Double.NaN, null, null, null));
        assertEquals(900_000L, Undo.resolveWindow(Double.POSITIVE_INFINITY, null, null, null));
        assertEquals(30_000L, Undo.resolveWindow(29_999.0, null, null, null));
        assertEquals(30_000L, Undo.resolveWindow(30_000.0, null, null, null));
        assertEquals(30_001L, Undo.resolveWindow(30_001.0, null, null, null));
        assertEquals(86_400_000L, Undo.resolveWindow(86_400_001.0, null, null, null));
        assertEquals(86_400_000L, Undo.resolveWindow(86_400_000.0, null, null, null));
        assertEquals(86_400_000L, Undo.resolveWindow(null, null, 1e12, 1e12), "a host default above 24 h is clamped");
        assertEquals(86_400_000L, Undo.resolveWindow(1e12, null, 1e12, null), "the host max never exceeds 24 h");
        assertEquals(300_000L, Undo.resolveWindow(600_000.0, null, 300_000.0, null));
        assertEquals(30_000L, Undo.resolveWindow(5.0, 1.0, null, null));
        assertEquals(120_000L, Undo.resolveWindow(1.0, 120_000.0, 60_000.0, null));
        assertEquals(60_000L, Undo.resolveWindow(null, null, null, 60_000.0));
        assertEquals(30_000L, Undo.resolveWindow(30_000.9, null, null, null), "floored to whole milliseconds");
    }

    static Map<String, Object> obl(Object params) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("kind", "undo_window");
        if (params != null) o.put("params", params);
        return o;
    }

    @Test void obligationParams() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", "op_1");
        p.put("window_end", END);
        assertNull(Obligations.error(obl(p)));
        assertNull(Obligations.error(with(obl(p), "due", END)));
        assertNotNull(Obligations.error(obl(with(p, "by", "x"))), "an extra parameter");
        assertNull(Obligations.error(obl(with(p, "id", "i".repeat(128)))));
        assertNotNull(Obligations.error(obl(with(p, "id", "i".repeat(129)))), "a 129-character id");
        assertNotNull(Obligations.error(obl(with(p, "id", ""))));
        assertNull(Obligations.error(obl(with(p, "window_end", 0L))));
        assertNotNull(Obligations.error(obl(with(p, "window_end", -1L))), "a negative window_end");
        assertNotNull(Obligations.error(obl(with(p, "window_end", 1.5))));
        assertNotNull(Obligations.error(obl(with(p, "id", null))));
        assertNotNull(Obligations.error(obl(with(p, "window_end", null))));
        assertNotNull(Obligations.error(obl(null)));
        assertTrue(Obligations.KINDS.contains("undo_window"));
    }

    @Test void admissionShapeAndObligation() {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("id", "op_1");
        a.put("window_end", END);
        a.put("compensation", Map.of("verb", "drafts.delete", "resource", "drafts:box1"));
        assertNull(Undo.admissionError(a));
        assertNull(Undo.admissionError(with(a, "id", "i".repeat(128))));
        assertNotNull(Undo.admissionError(with(a, "id", "i".repeat(129))));
        assertNotNull(Undo.admissionError(with(a, "id", "")));
        assertNotNull(Undo.admissionError(with(a, "window_end", -1L)));
        assertNotNull(Undo.admissionError(with(a, "window_end", 1.5)));
        assertNotNull(Undo.admissionError(with(a, "compensation", Map.of("resource", "r"))));
        assertNotNull(Undo.admissionError(with(a, "compensation", Map.of("verb", ""))));
        assertNotNull(Undo.admissionError(null));
        Map<String, Object> o = Undo.obligation(a);
        assertTrue(IntentJs.jsonEquals(Map.of("kind", "undo_window", "params", Map.of("id", "op_1", "window_end", END), "due", END), o));
        assertNull(Obligations.listError(new ArrayList<>(List.of(o))));
    }
}
