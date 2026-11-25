package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * The vector driver: key lookup by name (a fresh driver per test, so every lookup is a first lookup), the suite resolution order,
 * and the optional arguments the shared producer vectors leave at their defaults. Post-quantum work stays on ML-DSA (fast).
 */
class ProducerOpsPitKill1Test {
    static final Map<String, Object> DOC = Track3Vectors.load("producer-vectors.json");
    static final Map<String, Object> PQ = Track3Vectors.load("producer-pq-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }
    static String canon(Object o) { return Json.canonicalize(o); }
    static Map<String, Object> copy(Object o) { return m(Json.parseLenient(Json.canonicalize(o))); }
    static String refusal(Executable f) { return assertThrows(IllegalArgumentException.class, f).getMessage(); }

    static Map<String, Object> kase(Map<String, Object> doc, String name) {
        for (Object c : l(doc.get("cases"))) if (name.equals(m(c).get("name"))) return m(c);
        throw new AssertionError("no vector named " + name);
    }

    static ProducerOps edOps() { return new ProducerOps(m(DOC.get("keys")), null); }
    static ProducerOps pqOps() { return new ProducerOps(m(PQ.get("ed_keys")), m(PQ.get("pq_keys"))); }

    // ---- key tables ---------------------------------------------------------------------------------------------------------

    @Test void withoutKeyTablesEveryNameIsUnknown() {
        ProducerOps ops = new ProducerOps(null, null);
        assertEquals("unknown key 'x'", refusal(() -> ops.ed("x")));
        assertEquals("unknown post-quantum key 'y'", refusal(() -> ops.pq("y")));
        assertNull(ops.pq(null));
    }

    @Test void theGivenKeyTablesAreTheOnesSearched() {
        ProducerOps ops = pqOps();
        assertEquals(m(m(PQ.get("ed_keys")).get("agent")).get("public"), ops.ed("agent").id());
        assertEquals(m(m(PQ.get("pq_keys")).get("agent/ml-dsa-65")).get("public"), ops.pq("agent/ml-dsa-65").pkB64u());
    }

    @Test void aPostQuantumKeyIsBuiltOncePerNameFromItsOwnFamilyAndSeed() {
        ProducerOps ops = pqOps();
        Map<String, Object> table = m(PQ.get("pq_keys"));
        Keys.PqKey a = ops.pq("agent/ml-dsa-65");
        assertNotNull(a);
        assertEquals(Pq.Prim.ML_DSA_65, a.prim);
        assertEquals(m(table.get("agent/ml-dsa-65")).get("public"), a.pkB64u());
        assertSame(a, ops.pq("agent/ml-dsa-65"));
        Keys.PqKey p = ops.pq("principal/ml-dsa-87");
        assertEquals(Pq.Prim.ML_DSA_87, p.prim);
        assertEquals(m(table.get("principal/ml-dsa-87")).get("public"), p.pkB64u());
        assertNotSame(a, p);
        assertSame(p, ops.pq("principal/ml-dsa-87"));
        assertSame(a, ops.pq("agent/ml-dsa-65"));
        assertEquals("unsupported_suite: fn-dsa-512", refusal(() -> ops.pq("agent/fn-dsa-512")));
        assertEquals("unknown post-quantum key 'nobody'", refusal(() -> ops.pq("nobody")));
        assertNull(ops.pq(null));
    }

    @Test void aSeedThatIsNotCanonicalBase64urlIsRefused() {
        assertEquals("not canonical base64url", refusal(() -> new ProducerOps(null, null).run("ed25519_sign", Issue.obj("seed", "***", "message_utf8", "m"))));
    }

    // ---- suite resolution -----------------------------------------------------------------------------------------------------

    @Test void noAlgMeansEd25519AndEd25519IgnoresAnyPostQuantumKey() {
        ProducerOps ops = pqOps();
        String want = Pca.b64(ops.ed("agent").sign("m".getBytes(StandardCharsets.UTF_8)));
        assertEquals("{\"sig\":\"" + want + "\"}", canon(ops.run("suite_sign", Issue.obj("ed", "agent", "message_utf8", "m"))));
        assertEquals("{\"sig\":\"" + want + "\"}", canon(ops.run("suite_sign", Issue.obj("alg", "ed25519", "ed", "agent", "pq", "nobody", "message_utf8", "m"))));
    }

    @Test void anUnknownOrUnsignableSuiteIsRefusedBeforeItsKeys() {
        ProducerOps ops = pqOps();
        assertEquals("unknown signature alg 'no-such-alg'",
            refusal(() -> ops.run("suite_sign", Issue.obj("alg", "no-such-alg", "ed", "nobody", "pq", "nobody", "message_utf8", "m"))));
        assertEquals("unsupported_suite: fn-dsa-512",
            refusal(() -> ops.run("suite_sign", Issue.obj("alg", "fn-dsa-512", "ed", "nobody", "pq", "nobody", "message_utf8", "m"))));
    }

    @Test void theMlDsa65CasesReplayOnAFreshDriver() {
        for (String n : List.of("suite-sign-ml-dsa-65", "suite-sign-hybrid-ed25519-ml-dsa-65", "mint-root-ml-dsa-65", "delegate-hybrid-ed25519-ml-dsa-65")) {
            Map<String, Object> c = kase(PQ, n);
            assertEquals(canon(c.get("expect")), canon(pqOps().run((String) c.get("op"), m(c.get("args")))), n);
        }
    }

    // ---- optional arguments -----------------------------------------------------------------------------------------------------

    @Test void grantsAreMintedUnderTheKeysTheCaseNames() {
        Map<String, Object> renamed = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : m(DOC.get("keys")).entrySet()) renamed.put("k-" + e.getKey(), e.getValue());
        ProducerOps ops = new ProducerOps(renamed, null);
        int n = 0;
        for (Object o : l(DOC.get("cases"))) {
            Map<String, Object> c = m(o);
            String op = (String) c.get("op");
            if (!"mint_grant".equals(op) && !"mint_session_grant".equals(op)) continue;
            Map<String, Object> a = copy(c.get("args"));
            a.put("principal", "k-" + a.get("principal"));
            a.put("holder", "k-" + a.get("holder"));
            assertEquals(canon(c.get("expect")), canon(ops.run(op, a)), (String) c.get("name"));
            n++;
        }
        assertEquals(4, n);
    }

    @Test void aSessionGrantCarriesTheCaseCaveats() {
        Map<String, Object> c = kase(DOC, "session-grant-delta-commit");
        assertTrue(canon(m(edOps().run("mint_session_grant", copy(c.get("args")))).get("grant")).contains("\"type\":\"budget_alloc\""));
        Map<String, Object> none = copy(c.get("args"));
        none.remove("caveats");
        String without = canon(m(edOps().run("mint_session_grant", none)).get("grant"));
        assertFalse(without.contains("budget_alloc"));
        none.put("caveats", new java.util.ArrayList<Object>());
        assertEquals(without, canon(m(edOps().run("mint_session_grant", none)).get("grant"))); // the reference: caveats ?? []
    }

    @Test void aSuiteDelegationWithoutANewHolderKeepsTheParentsHolder() {
        ProducerOps ops = pqOps();
        Map<String, Object> a = copy(kase(PQ, "delegate-ed25519").get("args"));
        assertEquals(ops.ed("subagent").id(), m(ops.run("delegate_suite", a)).get("holder"));
        a.remove("to_holder");
        assertEquals(m(a.get("parent")).get("holder"), m(ops.run("delegate_suite", a)).get("holder"));
        assertNotEquals(ops.ed("subagent").id(), m(a.get("parent")).get("holder"));
    }

    @Test void anActCarriesTheCallersIssuedAtAndExpiry() {
        Map<String, Object> a = copy(kase(DOC, "act-root-refund").get("args"));
        a.put("iat", 1_800_000_123_456L);
        a.put("exp", 1_800_000_135_801L);
        Map<String, Object> p = m(m(edOps().run("act", a)).get("pcactn"));
        assertEquals(1_800_000_123_456L, Json.asLong(p.get("iat")));
        assertEquals(1_800_000_135_801L, Json.asLong(p.get("exp")));
    }

    @Test void theEscalationHistoryHeadFollowsTheLastCounter() {
        Map<String, Object> a = copy(kase(DOC, "escalation-digests").get("args"));
        a.put("last_counter", 7L);
        assertEquals(Escalation.historyHead(7L), m(edOps().run("escalation_digests", a)).get("history_head"));
        assertNotEquals(Escalation.historyHead(0L), Escalation.historyHead(7L));
        a.put("last_counter", null);
        assertEquals(Escalation.historyHead(null), m(edOps().run("escalation_digests", a)).get("history_head"));
    }

    // ---- facade_act: the principal's key, the act's optional counter and clock ----------------------------------------------

    @Test void aFacadeGrantIsIssuedByTheNamedPrincipalKey() {
        ProducerOps ops = edOps();
        Map<String, Object> a = copy(kase(DOC, "facade-act-refund").get("args"));
        a.put("principal", "guardian");
        Map<String, Object> grant = m(m(ops.run("facade_act", a)).get("grant"));
        assertEquals(ops.ed("guardian").id(), grant.get("issuer"));
        assertNotEquals(ops.ed("principal").id(), grant.get("issuer"));
    }

    @Test void aFacadeActWithoutACounterTakesTheNextOne() {
        Map<String, Object> c = kase(DOC, "facade-act-refund");
        Map<String, Object> a = copy(c.get("args"));
        assertEquals(1L, Json.asLong(m(a.get("act")).remove("counter")));
        assertEquals(1L, Json.asLong(m(m(edOps().run("facade_act", a)).get("pcactn")).get("counter"))); // a fresh handle's next counter is 1
        m(a.get("act")).put("counter", 7L);
        assertEquals(7L, Json.asLong(m(m(edOps().run("facade_act", a)).get("pcactn")).get("counter")));
    }

    @Test void aFacadeActWithoutAClockIsIssuedNow() {
        Map<String, Object> a = copy(kase(DOC, "facade-act-refund").get("args"));
        m(a.get("act")).remove("now");
        long before = System.currentTimeMillis();
        Map<String, Object> p = m(m(edOps().run("facade_act", a)).get("pcactn"));
        long after = System.currentTimeMillis();
        long iat = Json.asLong(p.get("iat"));
        assertTrue(iat >= before && iat <= after, "iat " + iat);
        assertEquals(1L, Json.asLong(p.get("counter")));
        m(a.get("act")).put("now", 1_800_000_777_000L);
        assertEquals(1_800_000_777_000L, Json.asLong(m(m(edOps().run("facade_act", a)).get("pcactn")).get("iat")));
    }
}
