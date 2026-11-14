package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.junit.jupiter.api.Test;

/** 0.5 mutation kills for {@link A2a}: every need check at its bound, signed receipts that fail exactly one check, whole chain results. */
public class A2aRestKillTest {
    static final byte[] SEED = new byte[32];
    static final String PUB;
    static {
        Arrays.fill(SEED, (byte) 7);
        byte[] pk = new byte[32];
        Ed25519.generatePublicKey(SEED, 0, pk, 0);
        PUB = Pca.b64(pk);
    }
    static final List<String> IDS = List.of("a", "b");
    static final String CH = PcaGrant.chainDigest(IDS);
    static final String OTHER = Pca.b64(new byte[32]);

    static Json.Num n(long v) { return IntentJs.ofLong(v); }

    static Map<String, Object> need(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", n(1));
        m.put("kind", "scope");
        m.put("verb", "a");
        m.put("resource", "r");
        for (int i = 0; i < kv.length; i += 2) {
            if (kv[i + 1] == DEL) m.remove((String) kv[i]); else m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }
    static final Object DEL = new Object();

    static List<Object> strs(int count, String s) { List<Object> l = new ArrayList<>(); for (int i = 0; i < count; i++) l.add(s + i); return l; }
    static Map<String, Object> lim(int count, Object v) { Map<String, Object> m = new LinkedHashMap<>(); for (int i = 0; i < count; i++) m.put("k" + i, v); return m; }
    static Map<String, Object> dis(Object issuer, Object claim) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (issuer != DEL) m.put("issuer", issuer);
        if (claim != DEL) m.put("claim", claim);
        return m;
    }
    static List<Object> disList(int count) { List<Object> l = new ArrayList<>(); for (int i = 0; i < count; i++) l.add(dis("i", "c")); return l; }

    @Test void needErrorAtEveryBound() {
        String F = "bad_field";
        assertNull(A2a.needError(need()));
        assertEquals("bad_shape", A2a.needError("x"));
        assertEquals("unknown_member", A2a.needError(need("zz", n(1))));
        assertEquals("bad_version", A2a.needError(need("v", n(2))));
        assertEquals("bad_version", A2a.needError(need("v", "1")));
        assertEquals("bad_version", A2a.needError(need("v", DEL)));
        assertEquals("bad_version", A2a.needError(need("v", new Json.Num("x"))));
        assertNull(A2a.needError(need("v", new Json.Num("1.0"))));
        assertNull(A2a.needError(need("kind", "grant")));
        assertNull(A2a.needError(need("kind", "discharge")));
        assertEquals("bad_kind", A2a.needError(need("kind", "x")));
        assertEquals("bad_kind", A2a.needError(need("kind", n(1))));
        // verb / resource
        assertNull(A2a.needError(need("verb", "v".repeat(128), "resource", "r".repeat(512))));
        assertEquals(F, A2a.needError(need("verb", "v".repeat(129))));
        assertEquals(F, A2a.needError(need("resource", "r".repeat(513))));
        assertEquals(F, A2a.needError(need("verb", "")));
        assertEquals(F, A2a.needError(need("verb", DEL)));
        assertEquals(F, A2a.needError(need("resource", DEL)));
        assertEquals(F, A2a.needError(need("verb", n(1))));
        // scopes
        assertNull(A2a.needError(need("scopes", strs(16, "s"))));
        assertNull(A2a.needError(need("scopes", List.of("s".repeat(128)))));
        assertEquals(F, A2a.needError(need("scopes", strs(17, "s"))));
        assertEquals(F, A2a.needError(need("scopes", List.of("s".repeat(129)))));
        assertEquals(F, A2a.needError(need("scopes", List.of("a b"))));
        assertEquals(F, A2a.needError(need("scopes", List.of(""))));
        assertEquals(F, A2a.needError(need("scopes", List.of(n(1)))));
        assertEquals(F, A2a.needError(need("scopes", "s")));
        // grant_ref / policy_digest
        for (String k : List.of("grant_ref", "policy_digest")) {
            assertNull(A2a.needError(need(k, "g".repeat(128))), k);
            assertEquals(F, A2a.needError(need(k, "g".repeat(129))), k);
            assertEquals(F, A2a.needError(need(k, n(1))), k);
            assertEquals(F, A2a.needError(need(k, "")), k);
        }
        // tier
        assertNull(A2a.needError(need("kind", "escalate", "tier", n(2))));
        assertNull(A2a.needError(need("kind", "escalate", "tier", n(3))));
        assertEquals(F, A2a.needError(need("kind", "escalate", "tier", n(1))));
        assertEquals(F, A2a.needError(need("kind", "escalate", "tier", n(4))));
        assertEquals(F, A2a.needError(need("kind", "escalate", "tier", "2")));
        assertEquals(F, A2a.needError(need("kind", "escalate")));
        assertEquals(F, A2a.needError(need("tier", n(2))));
        assertEquals(F, A2a.needError(need("kind", "grant", "tier", n(3))));
        // limits
        assertNull(A2a.needError(need("limits", lim(16, n(0)))));
        assertNull(A2a.needError(need("limits", Map.of("k".repeat(64), n(5)))));
        assertEquals(F, A2a.needError(need("limits", lim(17, n(0)))));
        assertEquals(F, A2a.needError(need("limits", Map.of("k".repeat(65), n(5)))));
        assertEquals(F, A2a.needError(need("limits", Map.of("", n(5)))));
        assertEquals(F, A2a.needError(need("limits", Map.of("k", n(-1)))));
        assertEquals(F, A2a.needError(need("limits", Map.of("k", new Json.Num("x")))));
        assertEquals(F, A2a.needError(need("limits", Map.of("k", new Json.Num("1e999")))));
        assertEquals(F, A2a.needError(need("limits", Map.of("k", "1"))));
        assertEquals(F, A2a.needError(need("limits", "x")));
        // discharges
        assertNull(A2a.needError(need("discharges", disList(16))));
        assertNull(A2a.needError(need("discharges", List.of(dis("i".repeat(512), "c".repeat(256))))));
        assertEquals(F, A2a.needError(need("discharges", disList(17))));
        assertEquals(F, A2a.needError(need("discharges", List.of(dis("i".repeat(513), "c")))));
        assertEquals(F, A2a.needError(need("discharges", List.of(dis("i", "c".repeat(257))))));
        assertEquals(F, A2a.needError(need("discharges", List.of(dis(DEL, "c")))));
        assertEquals(F, A2a.needError(need("discharges", List.of(dis("i", DEL)))));
        assertEquals(F, A2a.needError(need("discharges", List.of("x"))));
        Map<String, Object> extra = dis("i", "c");
        extra.put("x", "y");
        assertEquals(F, A2a.needError(need("discharges", List.of(extra))));
        assertEquals(F, A2a.needError(need("discharges", "x")));
    }

    static String enc(String json) { return Pca.b64(json.getBytes(StandardCharsets.UTF_8)); }

    @Test void decodeAndResume() {
        assertEquals("bad_base64", A2a.decodeNeed("").code);
        assertEquals("bad_base64", A2a.decodeNeed(7).code);
        assertEquals("bad_base64", A2a.decodeNeed(null).code);
        assertEquals("bad_json", A2a.decodeNeed("A".repeat(2048)).code);
        assertEquals("too_long", A2a.decodeNeed("A".repeat(2049)).code);
        String e = enc("{\"v\":1,\"kind\":\"scope\",\"verb\":\"a\",\"resource\":\"r\"}");
        A2a.Decoded d = A2a.decodeNeed(e);
        assertNull(d.code);
        String dig = A2a.needDigest(d.need);
        assertNull(A2a.resumeGate("auth-required", e, dig, "a", "r"));
        assertNull(A2a.resumeGate("TASK_STATE_AUTH_REQUIRED", e, dig, "a", "r"));
        assertEquals("no_proof", A2a.resumeGate("auth-required", e, dig, "a", null));
        assertEquals("no_proof", A2a.resumeGate("auth-required", e, dig, null, "r"));
        assertEquals("no_valid_need", A2a.resumeGate("auth-required", null, dig, "a", "r"));
        assertEquals("action_mismatch", A2a.resumeGate("auth-required", e, dig, "a", "x"));
    }

    @Test void pushTokens() {
        assertNull(A2a.pushToken("t", IDS, 7));
        assertNull(A2a.pushToken("t", IDS, "s".repeat(15)));
        String salt = "s".repeat(16);
        String tok = A2a.pushToken("t", IDS, salt);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", "atlas-pca/a2a-push/v1");
        m.put("task_id", "t");
        m.put("chain", CH);
        m.put("salt", salt);
        assertEquals(Pca.hashCanonical(m), tok);
        assertEquals("token_mismatch", A2a.checkPush("t", IDS, "short", "tok", null));
        assertEquals("token_mismatch", A2a.checkPush("t", IDS, salt, "tok", null));
        assertEquals("no_token", A2a.checkPush("t", IDS, salt, "", null));
        assertNull(A2a.checkPush("t", IDS, salt, tok, Map.of("task", Map.of("id", "t"))));
        assertNull(A2a.checkPush("t", IDS, salt, tok, Map.of("statusUpdate", Map.of("taskId", "t"))));
        assertNull(A2a.checkPush("t", IDS, salt, tok, Map.of("artifactUpdate", Map.of("taskId", "t"))));
        assertEquals("task_mismatch", A2a.checkPush("t", IDS, salt, tok, Map.of("statusUpdate", Map.of("taskId", "u"))));
        assertEquals("task_mismatch", A2a.checkPush("t", IDS, salt, tok, Map.of("task", Map.of("taskId", "t"))));
        assertEquals("task_mismatch", A2a.checkPush("t", IDS, salt, tok, Map.of()));
        assertEquals("task_mismatch", A2a.checkPush("t", IDS, salt, tok, "x"));
        assertEquals("task_mismatch", A2a.checkPush("t", IDS, salt, tok, null));
    }

    @Test void chainExtension() {
        Object[] a = A2a.checkChainExtension(List.of(List.of()));
        assertEquals(List.of(0, "no_chain"), Arrays.asList(a));
        Object[] b = A2a.checkChainExtension(List.of(List.of("a"), List.of("b")));
        assertEquals(List.of(1, "chain_does_not_extend_previous_hop"), Arrays.asList(b));
        assertNull(A2a.checkChainExtension(List.of(List.of("a"), List.of("a", "b"))));
    }

    static final String[] BODY = {"v", "task_id", "state", "seq", "prev", "chain", "issued_at", "signer"};

    static Map<String, Object> sign(Map<String, Object> r) {
        Map<String, Object> body = new LinkedHashMap<>();
        for (String k : BODY) body.put(k, r.get(k));
        byte[] msg = Pca.concat(A2a.RECEIPT_DOMAIN.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body));
        byte[] sig = new byte[64];
        Ed25519.sign(SEED, 0, msg, 0, msg.length, sig, 0);
        r.put("sig", Pca.b64(sig));
        return r;
    }

    static Map<String, Object> rec(String state, long seq, Object prev, Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("v", n(1));
        r.put("task_id", "t1");
        r.put("state", state);
        r.put("seq", n(seq));
        r.put("prev", prev);
        r.put("chain", CH);
        r.put("issued_at", n(1000));
        r.put("signer", PUB);
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return sign(r);
    }

    static final String W = "TASK_STATE_WORKING", C = "TASK_STATE_COMPLETED";

    @Test void receiptsFailingOneCheck() {
        Map<String, Object> r0 = rec(W, 0, null);
        String d0 = A2a.receiptDigest(r0);
        assertTrue(A2a.verifyReceipt(r0, PUB));
        assertTrue(A2a.verifyReceipt(rec(W, 1, d0), PUB));
        assertTrue(A2a.verifyReceipt(rec(W, 0, null, "task_id", "x".repeat(4096)), PUB));
        assertTrue(A2a.verifyReceipt(rec(W, 0, null, "issued_at", n(0)), PUB));
        assertFalse(A2a.verifyReceipt("x", PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, null, "v", n(2)), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, null, "v", null), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, null, "signer", OTHER), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, null, "task_id", ""), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, null, "task_id", null), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, null, "task_id", "x".repeat(4097)), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, null, "state", n(1)), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, null, "state", null), PUB));
        assertFalse(A2a.verifyReceipt(rec("TASK_STATE_BOGUS", 0, null), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 1, d0, "seq", "1"), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, -1, d0), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, null, "issued_at", n(-1)), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, null, "issued_at", "1"), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, null, "chain", "abc"), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, null, "chain", null), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 1, "abc"), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 0, d0), PUB));
        assertFalse(A2a.verifyReceipt(rec(W, 1, null), PUB));
        assertFalse(A2a.verifyReceipt(r0, OTHER));
    }

    static String rc(A2a.ReceiptChain r) { return r.code + "/" + r.at + "/" + r.terminal + "/" + r.lastState; }
    static String chain(Object... recs) { return rc(A2a.checkReceiptChain(Arrays.asList(recs), PUB, "t1", IDS)); }

    @Test void receiptChains() {
        Map<String, Object> r0 = rec(W, 0, null), c0 = rec(C, 0, null);
        String d0 = A2a.receiptDigest(r0), dc0 = A2a.receiptDigest(c0);
        assertEquals("empty/-1/false/null", chain());
        assertEquals("bad_receipt/0/false/null", chain("x"));
        assertEquals("bad_receipt/1/false/null", chain(r0, "x"));
        assertEquals("wrong_task/0/false/null", chain(rec(W, 0, null, "task_id", "t2")));
        assertEquals("wrong_chain/0/false/null", chain(rec(W, 0, null, "chain", OTHER)));
        assertEquals("bad_start/0/false/null", chain(rec(W, 1, d0)));
        assertEquals("after_terminal/1/false/null", chain(c0, rec(W, 1, dc0)));
        assertEquals("broken_link/1/false/null", chain(r0, rec(W, 2, d0)));
        assertEquals("broken_link/1/false/null", chain(r0, rec(W, 1, OTHER)));
        assertEquals("null/-1/false/" + W, chain(r0));
        assertEquals("null/-1/true/" + C, chain(r0, rec(C, 1, d0)));
        assertEquals("null/-1/true/" + C, chain(c0));
        List<Object> ok = List.of(r0, rec(C, 1, d0));
        assertTrue(A2a.mayTriggerNext(ok, PUB, "t1", IDS));
        assertFalse(A2a.mayTriggerNext(List.of(r0), PUB, "t1", IDS));
        assertFalse(A2a.mayTriggerNext(ok, PUB, "t2", IDS));
        assertFalse(A2a.mayTriggerNext(List.of(rec(C, 0, null, "chain", OTHER)), PUB, "t1", IDS));
    }
}
