package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills (K4 exception paths, K3 cursor / authority comparison, Ledger witness trust, OracleFacts offer helpers).
 * References: packages/pca/src/{k4,k3,ledger,oracle-facts}.ts. Signing keys come from fixed seeds.
 */
public class K05R5G5Test {
    static byte[] fill(int b) { byte[] s = new byte[32]; Arrays.fill(s, (byte) b); return s; }

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    // ---- K4: a hostile value that throws inside the check is a refusal with the function's own code ----

    @Test void bindingWithoutAHolderIsMalformed() {
        String h = K4K05KillTest.HOLDER.id();
        assertEquals("binding_malformed", K4.verifyBinding(K4K05KillTest.binding("visa", h), K4K05KillTest.GRANT, null, "nonce-0123456789", null));
        assertEquals("binding_malformed", K4.verifyBinding(K4K05KillTest.binding("visa", h), K4K05KillTest.GRANT, h, null, null));
        assertNull(K4.verifyBinding(K4K05KillTest.binding("visa", h), K4K05KillTest.GRANT, h, "nonce-0123456789", null));
    }

    @Test void aConfigThatCannotBeCanonicalisedIsMalformed() {
        Map<String, Object> c = K4K05KillTest.cfg();
        assertNull(K4.pricingConfigError(c));
        c.put("x", "\uD800"); // a lone surrogate: strict canonicalisation throws while hashing the body
        assertEquals("config_malformed", K4.pricingConfigError(c));
        // a non-string principal is malformed before any amount is looked at
        assertEquals("config_malformed", K4.pricingConfigError(K4K05KillTest.cfg("principal", "5", "interruptionCost", "\"x\"")));
        assertEquals("config_malformed", K4.pricingConfigError(K4K05KillTest.cfg("v", "2", "interruptionCost", "\"x\"")));
    }

    @Test void anAnswerThatCannotBeCanonicalisedFoldsNothing() {
        Map<String, Object> c = K4K05KillTest.cfg();
        Map<String, Object> bad = K4K05KillTest.ans("nonce-001", "d1", "deny");
        assertEquals("1500000 [start-nonce, nonce-001]", K4K05KillTest.fold(c, K4K05KillTest.ans("nonce-001", "d1", "deny")));
        bad.put("x", "\uD800");
        assertEquals("1000000 [start-nonce]", K4K05KillTest.fold(c, bad));
    }

    @Test void aMissingRequestIsAMalformedResponse() {
        assertEquals("response_malformed", K4K05KillTest.vg(K4K05KillTest.ENV, "null", K4K05KillTest.GOT, List.of(K4K05KillTest.MGR), K4K05KillTest.CTX));
        assertEquals("response_malformed", K4K05KillTest.vg("null", K4K05KillTest.SENT, K4K05KillTest.GOT, List.of(K4K05KillTest.MGR), K4K05KillTest.CTX));
    }

    // ---- K3 ----

    static String cursor(String sig) {
        String json = "{\"v\":1,\"bind\":\"x\",\"skip\":0,\"signer\":\"S\"}";
        return Pca.b64(json.getBytes(StandardCharsets.UTF_8)) + "." + sig;
    }

    @Test void aCursorWithoutASignatureIsMalformedNotUnsigned() {
        K3.CursorVerdict v = K3.verifyListCursor(cursor(""), "S", null);
        assertFalse(v.ok);
        assertEquals("malformed", v.reason);
        K3.CursorVerdict w = K3.verifyListCursor(cursor("AAAA"), "S", null);
        assertFalse(w.ok);
        assertEquals("signature", w.reason);
        assertEquals("malformed", K3.verifyListCursor(cursor("AAAA") + ".x", "S", null).reason);
    }

    static Object auth(String resources, String limits) {
        return Json.parseLenient("{\"verbs\":[\"v\"],\"resources\":" + resources + (limits == null ? "" : ",\"limits\":" + limits) + "}");
    }

    @Test void resourcePatternsOrderByCoverage() {
        String[][] cases = {
            {"[\"a*\"]", "[\"ab\"]", "narrower"}, {"[\"ab\"]", "[\"a*\"]", "wider"},
            {"[\"a*\"]", "[\"ab*\"]", "narrower"}, {"[\"ab*\"]", "[\"a*\"]", "wider"},
            {"[\"a*\"]", "[\"a*\"]", "equal"}, {"[\"ab\"]", "[\"ab\"]", "equal"},
            {"[\"a\"]", "[\"b\"]", "incomparable"}, {"[\"a*\"]", "[\"b*\"]", "incomparable"}, {"[\"ab\"]", "[\"a\"]", "incomparable"},
            {"[\"a*\"]", "[\"a\"]", "narrower"}, {"[\"a\"]", "[\"a*\"]", "wider"},
            {"[\"a*\",\"b\"]", "[\"ab\",\"b\"]", "narrower"}};
        for (String[] c : cases) assertEquals(c[2], K3.compareAuthority(auth(c[0], null), auth(c[1], null)), c[0] + " -> " + c[1]);
    }

    @Test void aNonFiniteCeilingIsMalformed() {
        Object inf = auth("[\"r\"]", "{\"x\":1e400}");
        assertEquals("incomparable", K3.compareAuthority(inf, inf));
        Object ok = auth("[\"r\"]", "{\"x\":5}");
        assertEquals("equal", K3.compareAuthority(ok, ok));
        assertEquals("incomparable", K3.compareAuthority(ok, auth("[\"r\"]", "{\"x\":\"5\"}")));
        assertEquals("incomparable", K3.compareAuthority(ok, auth("[\"r\"]", "{\"x\":-1}")));
    }

    // ---- Ledger ----

    @Test void anUntrustedWitnessKeyIsNotCounted() {
        Keys.EdKey w = Keys.edFromSeed(fill(0x41)), trusted = Keys.edFromSeed(fill(0x42));
        Map<String, Object> sth = map("instance_id", "i", "principal", "p", "size", 5L, "root", "r1", "prev_root", "r0");
        Map<String, Object> body = new LinkedHashMap<>(sth);
        body.put("guardian_epoch", 0L);
        byte[] msg = Pca.concat(Ledger.STH_WITNESS_DOMAIN.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body));
        sth.put("witnesses", Arrays.asList(map("key", w.id(), "sig", Keys.b64u(w.sign(msg)))));
        assertTrue(Ledger.verifyWitnessCosignatures(sth, map("threshold", 1L, "witnessKeys", Arrays.asList(w.id()))));
        assertFalse(Ledger.verifyWitnessCosignatures(sth, map("threshold", 1L, "witnessKeys", Arrays.asList(trusted.id()))));
        assertFalse(Ledger.verifyWitnessCosignatures(sth, map("threshold", 1L, "witnessKeys", Arrays.asList())));
        assertFalse(Ledger.verifyWitnessCosignatures(sth, map("threshold", "x", "witnessKeys", Arrays.asList(w.id()))));
        assertFalse(Ledger.verifyWitnessCosignatures(sth, map("witnessKeys", Arrays.asList(w.id()))));
        assertTrue(Ledger.verifyWitnessCosignatures(sth, map("threshold", 0L)));
    }

    // ---- OracleFacts ----

    @Test void anOfferLackingAFilterKeyDoesNotMatch() {
        Map<String, Object> filter = new HashMap<>();
        filter.put("k", null);
        assertFalse(OracleFacts.offerMatches(new HashMap<String, Object>(), filter));
        assertFalse(OracleFacts.queryCovers(filter, new HashMap<String, Object>()));
        Map<String, Object> has = new HashMap<>();
        has.put("k", null);
        assertTrue(OracleFacts.offerMatches(has, filter));
        assertTrue(OracleFacts.queryCovers(filter, has));
        assertFalse(OracleFacts.offerMatches(map("k", "a"), map("k", "b")));
        assertFalse(OracleFacts.queryCovers(map("k", "a"), map("k", "b")));
        assertTrue(OracleFacts.queryCovers(map(), map("z", 1L)));
    }

    @Test void anAdmittedOfferSetReportsExactlyTheResultAndTheExcess() {
        Map<String, Object> os = IntentWbKillTest.offerSet();
        Map<String, Object> osn = IntentJs.obj(IntentJs.normalize(os));
        Map<String, Object> policy = IntentJs.obj(IntentWbKillTest.offersPolicy(60_000L).get("offers"));
        Object[] r = OracleFacts.decideOfferSet(policy, OracleFacts.offerSetRef(osn), true, osn, map("offer_id", "B"), IntentWbKillTest.AUD,
            IntentWbKillTest.SESSION, true, (double) IntentWbKillTest.NOW, 60_000.0);
        assertEquals(2, r.length);
        assertNull(r[0]);
        assertEquals(50L, r[1]);
        Object[] eq = OracleFacts.decideOfferSet(policy, OracleFacts.offerSetRef(osn), true, osn, map("offer_id", "A"), IntentWbKillTest.AUD,
            IntentWbKillTest.SESSION, true, (double) IntentWbKillTest.NOW, 60_000.0);
        assertEquals(2, eq.length);
        assertEquals(0L, eq[1]);
    }
}
