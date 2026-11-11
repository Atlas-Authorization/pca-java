package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** 0.5 mutation kills for {@link Undo}: exact messages, the normalized (JSON-number) inputs, every receipt member, the window clamp. */
public class UndoRestKillTest {
    static byte[] fill(int b) { byte[] x = new byte[32]; Arrays.fill(x, (byte) b); return x; }

    static final Keys.EdKey K = Keys.edFromSeed(fill(21));
    static final Keys.EdKey OTHER = Keys.edFromSeed(fill(22));

    static Map<String, Object> m(Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        return o;
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    @Test void admissionMessages() {
        assertNull(Undo.admissionError(m("id", "a", "window_end", 5, "compensation", m("verb", "x.undo"))));
        assertEquals("an admission must be an object", Undo.admissionError("a"));
        assertEquals("admission id must be a non-empty string of at most 128 characters", Undo.admissionError(m("id", "", "window_end", 5, "compensation", m("verb", "x"))));
        assertEquals("admission window_end must be a non-negative safe integer", Undo.admissionError(m("id", "a", "window_end", -1, "compensation", m("verb", "x"))));
        assertEquals("admission compensation.verb must be a non-empty string", Undo.admissionError(m("id", "a", "window_end", 5, "compensation", m("verb", ""))));
    }

    @Test void clipUnitsNeverSplitsAPair() {
        assertEquals("ab", Undo.clipUnits("ab", 2));
        assertEquals("a\uD800", Undo.clipUnits("a\uD800", 2));          // exactly n units: returned whole
        assertEquals("", Undo.clipUnits("ab", 0));
        assertEquals("a", Undo.clipUnits("ab", 1));
        assertEquals("a", Undo.clipUnits("a\uDC00x", 1));                // a low surrogate after the cut, no high before it
        assertEquals("\uD83D", Undo.clipUnits("\uD83Dx", 1));            // a high surrogate before the cut, no low after it
        assertEquals("a", Undo.clipUnits("a😀b", 2));          // a pair across the cut
        assertEquals("a😀", Undo.clipUnits("a😀b", 3));
    }

    static Map<String, Object> comp(Object params) {
        return m("verb", "drafts.delete", "resource", "drafts:b", "params", params, "undo_of", "op_1", "def_digest", "d");
    }

    @Test void digestsNormalizeNumbers() {
        assertEquals(Undo.compensationDigest(comp(m("n", new Json.Num("1.5")))), Undo.compensationDigest(comp(m("n", 1.5d))));
        assertEquals("missing member 'verb'", assertThrows(IllegalArgumentException.class, () -> Undo.compensationDigest(m("resource", "r"))).getMessage());
        Map<String, Object> num = m("a", new Json.Num("2")), dbl = m("a", 2.0d);
        assertEquals(Undo.encodeToken(num), Undo.encodeToken(dbl));
        assertEquals(Undo.tokenDigest(num), Undo.tokenDigest(dbl));
        assertEquals(Undo.receiptDigest(num), Undo.receiptDigest(dbl));
    }

    static String b64(String json) { return Pca.b64(json.getBytes(StandardCharsets.UTF_8)); }

    @Test void decodeTokenBounds() {
        String fits = b64("{\"a\":\"" + "x".repeat(3064) + "\"}");
        assertEquals(4096, fits.length());
        assertEquals(m("a", "x".repeat(3064)), Undo.decodeToken(fits));
        String over = b64("{\"a\":\"" + "x".repeat(3065) + "\"}");
        assertTrue(over.length() > 4096);
        assertNull(Undo.decodeToken(over));
        assertNull(Undo.decodeToken(Undo.encodeToken(m("a", "x".repeat(5000)))));
        assertNull(Undo.decodeToken(null));
        assertNull(Undo.decodeToken(5));
        assertNull(Undo.decodeToken(""));
        assertNull(Undo.decodeToken("!!"));
        assertNull(Undo.decodeToken(b64("[1]")));
        assertNull(Undo.decodeToken(b64("\"s\"")));
        assertNull(Undo.decodeToken(b64("null")));
        assertNull(Undo.decodeToken(Pca.b64(new byte[] {(byte) 0xff})));
        assertEquals(m("a", "b"), Undo.decodeToken(b64("{\"a\":\"b\"}")));
    }

    // ---- tokens ---------------------------------------------------------------------------------------------------------------

    static Map<String, Object> record(Object windowEnd) {
        return m("id", "rec1", "aud", "aud", "principal", "p", "compensation_digest", "cd", "window_end", windowEnd);
    }

    @Test void tokenKeyAndNumbers() {
        assertEquals("signToken: the undo service key is required", assertThrows(IllegalArgumentException.class, () -> Undo.signToken(record(100L), null)).getMessage());
        Map<String, Object> t = Undo.signToken(record(100.0d), K);
        assertEquals(Undo.OK, Undo.tokenCheck(t, K.id(), record(100L), 50L));
        assertEquals(Undo.OK, Undo.tokenCheck(t, K.id(), record(100.0d), 100L));
        // a decoded token may carry the exp as a Java double: it is the same JSON number
        Map<String, Object> d = new LinkedHashMap<>(t);
        d.put("exp", 100.0d);
        assertEquals(Undo.OK, Undo.tokenCheck(d, K.id(), record(100L), 50L));
    }

    @Test void tokenMembers() {
        Map<String, Object> t = Undo.signToken(record(100L), K);
        // an eleventh member, signed over: still malformed
        Map<String, Object> body = new LinkedHashMap<>(t);
        body.remove("sig");
        body.put("x", 1);
        Map<String, Object> eleven = new LinkedHashMap<>(body);
        eleven.put("sig", Pca.b64(K.sign(IntentJs.message(Undo.TOKEN_DOMAIN, body))));
        assertEquals(Undo.MALFORMED, Undo.tokenCheck(eleven, K.id(), record(100L), 50L));
        // ten members with one unknown in place of a known one
        Map<String, Object> swapped = new LinkedHashMap<>(t);
        swapped.remove("render_digest");
        swapped.put("x", "");
        assertEquals(Undo.MALFORMED, Undo.tokenCheck(swapped, K.id(), record(100L), 50L));
        assertEquals(Undo.MALFORMED, Undo.tokenCheck("token", K.id(), record(100L), 50L));
        assertEquals(Undo.MALFORMED, Undo.tokenCheck(null, K.id(), record(100L), 50L));
        assertEquals(Undo.MALFORMED, Undo.tokenCheck(list(t), K.id(), record(100L), 50L));
    }

    // ---- receipts -------------------------------------------------------------------------------------------------------------

    static Map<String, Object> rbody() {
        return m("v", 1, "kind", Undo.RECEIPT_KIND, "record", "rec1", "event", "opened", "state", "open", "at", 5, "compensation_digest", "cd",
            "prev", "", "note", "", "signer", K.id());
    }

    /** Signed by K over exactly these members, whatever they hold. */
    static Map<String, Object> signed(Map<String, Object> b) {
        Map<String, Object> r = new LinkedHashMap<>(b);
        r.put("sig", Pca.b64(K.sign(IntentJs.message(Undo.RECEIPT_DOMAIN, b))));
        return r;
    }

    static Map<String, Object> with(String k, Object v) { Map<String, Object> b = rbody(); b.put(k, v); return b; }

    @Test void receiptEveryMember() {
        assertTrue(Undo.verifyReceipt(signed(rbody()), K.id()));
        Object[][] bad = {
            {"v", 2}, {"kind", "pca-other"}, {"record", ""}, {"record", "a\u0001"}, {"record", 5}, {"event", "x"}, {"state", "x"},
            {"at", new Json.Num("1.5")}, {"at", "5"}, {"compensation_digest", 5}, {"prev", 5}, {"prev", null}, {"note", 5}, {"signer", OTHER.id()}, {"signer", 5},
        };
        for (Object[] b : bad) assertFalse(Undo.verifyReceipt(signed(with((String) b[0], b[1])), K.id()), b[0] + "=" + b[1]);
        for (String k : new String[] {"v", "kind", "record", "event", "state", "at", "compensation_digest", "prev", "note", "signer"}) {
            Map<String, Object> b = rbody();
            b.remove(k);
            assertFalse(Undo.verifyReceipt(signed(b), K.id()), "without " + k);
        }
        Map<String, Object> extra = rbody();
        extra.put("x", 1);
        assertFalse(Undo.verifyReceipt(signed(extra), K.id()));
        Map<String, Object> r = signed(rbody());
        assertFalse(Undo.verifyReceipt(r, null));
        assertFalse(Undo.verifyReceipt(r, OTHER.id()));
        assertFalse(Undo.verifyReceipt("receipt", K.id()));
        assertFalse(Undo.verifyReceipt(null, K.id()));
        Map<String, Object> shortSig = new LinkedHashMap<>(r);
        shortSig.put("sig", "AAAA");
        assertFalse(Undo.verifyReceipt(shortSig, K.id()));
        Map<String, Object> numSig = new LinkedHashMap<>(r);
        numSig.put("sig", 5);
        assertFalse(Undo.verifyReceipt(numSig, K.id()));
        Map<String, Object> noSig = new LinkedHashMap<>(r);
        noSig.remove("sig");
        noSig.put("y", "");
        assertFalse(Undo.verifyReceipt(noSig, K.id()));
        // a Java double at is the same JSON number
        Map<String, Object> dbl = new LinkedHashMap<>(r);
        dbl.put("at", 5.0d);
        assertTrue(Undo.verifyReceipt(dbl, K.id()));
    }

    @Test void signReceiptKeyAndNumbers() {
        assertEquals("signReceipt: the undo service key is required", assertThrows(IllegalArgumentException.class, () -> Undo.signReceipt(rbody(), null)).getMessage());
        Map<String, Object> b = rbody();
        b.put("at", 5.0d);
        Map<String, Object> r = Undo.signReceipt(b, K);
        assertTrue(Undo.verifyReceipt(r, K.id()));
        assertEquals(Undo.receiptDigest(Undo.signReceipt(rbody(), K)), Undo.receiptDigest(r));
    }

    @Test void receiptChainEdges() {
        assertEquals("no receipts", Undo.receiptChainError(null, K.id()));
        Map<String, Object> hostile = new LinkedHashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("x"); }
        };
        assertEquals("evaluation error (fail closed)", Undo.receiptChainError(hostile, K.id()));
        Map<String, Object> rec = m("id", "rec1", "compensation_digest", "cd", "state", "open", "receipts", list(Undo.signReceipt(rbody(), K)));
        assertNull(Undo.receiptChainError(rec, K.id()));
    }

    // ---- transitions ----------------------------------------------------------------------------------------------------------

    @Test void transitionNormalizesAndFailsClosed() {
        Map<String, Object> hostile = new LinkedHashMap<String, Object>() {
            @Override public Set<Map.Entry<String, Object>> entrySet() { throw new IllegalStateException("x"); }
        };
        Undo.Transition bad = Undo.transition(hostile, m("kind", "finalize"), 5L);
        assertEquals("refused", bad.outcome);
        assertEquals("invalid", bad.code);
        assertEquals("evaluation error (fail closed)", bad.reason);
        Undo.Transition badEv = Undo.transition(m("state", "open", "window_end", 10, "ver", 1), hostile, 5L);
        assertEquals("evaluation error (fail closed)", badEv.reason);

        Map<String, Object> rec = m("state", "open", "window_end", 10, "ver", 1, "x", 1.5d);
        Undo.Transition t = Undo.transition(rec, m("kind", "veto", "veto", m("at", 2.0d, "via", "token", "by", "u")), 5L);
        assertEquals("applied", t.outcome);
        assertTrue(t.record.get("x") instanceof Json.Num);
        assertEquals("1.5", ((Json.Num) t.record.get("x")).raw);
        Object at = ((Map<?, ?>) t.record.get("veto")).get("at");
        assertTrue(at instanceof Json.Num);
        assertEquals("2", ((Json.Num) at).raw);
    }

    @Test void resolveWindowClamp() {
        assertEquals(30_000L, Undo.resolveWindow(5.0, null, null, null));
        assertEquals(40_000L, Undo.resolveWindow(5.0, 40_000.0, null, null));
        assertEquals(30_000L, Undo.resolveWindow(5.0, 10.0, null, null));
        assertEquals(900_000L, Undo.resolveWindow(null, null, null, null));
        assertEquals(45_000L, Undo.resolveWindow(45_000.9, null, null, null));
        assertEquals(86_400_000L, Undo.resolveWindow(1e12, null, null, null));
        assertEquals(60_000L, Undo.resolveWindow(1e12, null, 60_000.0, null));
        assertEquals(50_000L, Undo.resolveWindow(Double.NaN, null, null, 50_000.0));
    }
}
