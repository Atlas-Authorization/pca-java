package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** The producer side (Keys / Issue / Agent), round-tripped through this SDK's own verifier. */
public class ProducerTest {
    static final long NOW = 1_800_000_000_000L;
    static final String AUD = "ins_producer_test";

    static byte[] hex(String h) {
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static String hexOf(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    static Map<String, Object> envelope() {
        List<Object> preds = new ArrayList<>();
        preds.add(Issue.obj("verb", "*"));
        return Issue.obj("predicates", preds, "caveats", new ArrayList<Object>(), "risk_policy", Issue.defaultRiskPolicy());
    }

    static Pca.Verdict verify(Map<String, Object> pcactn, Map<String, Object> grant) {
        return Pca.verifyPcactnJson(Issue.encode(pcactn), Issue.norm(grant), NOW, AUD);
    }

    @Test void ed25519Rfc8032Vector1() {
        Keys.EdKey k = Keys.edFromSeed(hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
        assertEquals("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", hexOf(k.pub));
        assertEquals("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            hexOf(k.sign(new byte[0])));
    }

    @Test void edSuiteRoundTripAndPcactnHeader() {
        Keys.SuiteKey principal = Keys.ed25519(Keys.edFromSeed(new byte[32]));
        Keys.SuiteKey me = Keys.ed25519(Keys.edFromSeed(hex("01".repeat(32))));
        Issue.Grant g = Issue.mintGrant(principal, me.id(), null, envelope(), "pay invoices", Pca.b64(new byte[16]));
        assertEquals(Issue.goalCommit("pay invoices", Pca.b64(new byte[16])), g.goalCommit);
        assertEquals("", Pca.verifyChain(new ArrayList<Object>(List.of(Issue.norm(g.grant))), principal.id(), true, null));
        Agent agent = Agent.create(me, AUD, g.grant, null).clock(() -> NOW);
        Map<String, Object> a1 = agent.act("pay", "invoice/7", Issue.obj("amount", 1200L));
        Pca.Verdict v = verify(a1, g.grant);
        assertTrue(v.allow, v.reason);
        assertEquals(1L, a1.get("counter"));
        Map<String, Object> a2 = agent.act("pay", "invoice/8", null);
        assertEquals(2L, a2.get("counter"));
        assertNotEquals(a1.get("nonce"), a2.get("nonce"));
        assertEquals(Issue.encode(a1), new String(Pca.decodeB64uStrict(Agent.header(a1), -1), StandardCharsets.UTF_8));
        assertEquals(Issue.encode(a1), Pca.decodePcaHeader(Agent.header(a1)));
        assertTrue(Agent.actionsBody(a1).startsWith("{\"pcactn\":{"));
    }

    @Test void tamperedActionIsRefused() {
        Keys.SuiteKey principal = Keys.ed25519(Keys.edFromSeed(new byte[32]));
        Keys.SuiteKey me = Keys.ed25519(Keys.edFromSeed(hex("02".repeat(32))));
        Issue.Grant g = Issue.mintGrant(principal, me.id(), null, envelope(), "g", null);
        Map<String, Object> a = Agent.create(me, AUD, g.grant, null).clock(() -> NOW).act("read", "x", null);
        @SuppressWarnings("unchecked") Map<String, Object> action = (Map<String, Object>) a.get("action");
        action.put("resource", "y");
        assertFalse(verify(a, g.grant).allow);
    }

    @Test void multiNodePlanProofs() {
        Keys.SuiteKey principal = Keys.ed25519(Keys.edFromSeed(new byte[32]));
        Keys.SuiteKey me = Keys.ed25519(Keys.edFromSeed(hex("03".repeat(32))));
        Issue.Grant g = Issue.mintGrant(principal, me.id(), null, envelope(), "g", null);
        Agent agent = Agent.create(me, AUD, g.grant, null).clock(() -> NOW);
        List<Map<String, Object>> nodes = new ArrayList<>();
        for (int i = 0; i < 5; i++) nodes.add(Issue.obj("id", "s" + i, "verb", "step", "resource", "r/" + i));
        Issue.Plan p = agent.commitPlan(nodes);
        for (int i = 0; i < 5; i++) {
            Pca.Verdict v = verify(agent.actNode("s" + i, null), g.grant);
            assertTrue(v.allow, "node " + i + ": " + v.reason);
        }
        assertEquals(p.root, Pca.merkleRoot(new ArrayList<Object>(nodes.stream().map(n -> (Object) Pca.planLeaf(n.get("id"), n, Pca.conditionsDigest(null, null))).toList())));
    }

    @Test void delegationNarrows() {
        Keys.SuiteKey principal = Keys.ed25519(Keys.edFromSeed(new byte[32]));
        Keys.SuiteKey me = Keys.ed25519(Keys.edFromSeed(hex("04".repeat(32))));
        Keys.SuiteKey sub = Keys.ed25519(Keys.edFromSeed(hex("05".repeat(32))));
        Issue.Grant g = Issue.mintGrant(principal, me.id(), null, envelope(), "g", null);
        List<Object> add = new ArrayList<>();
        add.add(Issue.obj("type", "max_uses", "id", "u1", "n", 3L, "until", NOW + 3_600_000L));
        Agent child = Agent.create(me, AUD, g.grant, null).clock(() -> NOW).delegate(sub, add);
        assertEquals(2, child.chain.size());
        assertEquals("", Pca.verifyChain(new ArrayList<Object>(Issue.norm(child.chain)), principal.id(), true, null));
        Pca.Verdict v = verify(child.act("read", "x", null), g.grant);
        assertTrue(v.allow, v.reason);
    }

    /** Set in CI (PCA_PRODUCER_OUT): this SDK's post-quantum PCActns, for the reference implementation to verify. Randomised
     *  signatures cannot be byte vectors, so the reference checks them instead (packages/pca producer-native fixtures). */
    static final List<Object> EMITTED = java.util.Collections.synchronizedList(new ArrayList<>());

    static void emit(String alg, Map<String, Object> grant, Map<String, Object> pcactn) throws java.io.IOException {
        EMITTED.add(Issue.obj("alg", alg, "grant", Issue.norm(grant), "pcactn", Issue.norm(pcactn)));
        String out = System.getenv("PCA_PRODUCER_OUT");
        if (out == null || out.isEmpty()) return;
        java.nio.file.Files.writeString(java.nio.file.Path.of(out),
            Json.canonicalize(Issue.obj("lang", "java", "aud", AUD, "now", NOW, "cases", new ArrayList<>(EMITTED))), StandardCharsets.UTF_8);
    }

    @Test void hybridMlDsaLeafAndRoot() throws Exception {
        Keys.EdKey pEd = Keys.edFromSeed(new byte[32]);
        Keys.PqKey pPq = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, new byte[32]);
        Keys.SuiteKey principal = Keys.suite("hybrid-ed25519-ml-dsa-65", pEd, pPq);
        Keys.EdKey aEd = Keys.edFromSeed(hex("06".repeat(32)));
        Keys.PqKey aPq = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, hex("07".repeat(32)));
        Keys.SuiteKey me = Keys.suite("hybrid-ed25519-ml-dsa-65", aEd, aPq);
        assertEquals(1952, aPq.pk.length);
        Issue.Grant g = Issue.mintGrant(principal, aEd.id(), aPq.pkB64u(), envelope(), "g", null);
        assertEquals("hybrid-ed25519-ml-dsa-65", g.grant.get("alg"));
        Map<String, Object> a = Agent.create(me, AUD, g.grant, null).clock(() -> NOW).act("read", "x", null);
        assertEquals("hybrid-ed25519-ml-dsa-65", a.get("alg"));
        Pca.Verdict v = verify(a, g.grant);
        assertTrue(v.allow, v.reason);
        emit("hybrid-ed25519-ml-dsa-65 (root and leaf)", g.grant, a);
        // deterministic: same seed, same key
        assertArrayEquals(aPq.pk, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, hex("07".repeat(32))).pk);
    }

    @Test void everyPqSuiteLeafRoundTrips() throws Exception {
        Keys.SuiteKey principal = Keys.ed25519(Keys.edFromSeed(new byte[32]));
        Object[][] cases = {
            {"ml-dsa-65", Pq.Prim.ML_DSA_65}, {"hybrid-nested-ed25519-ml-dsa-65", Pq.Prim.ML_DSA_65}, {"ml-dsa-87", Pq.Prim.ML_DSA_87},
            {"hybrid-ed25519-ml-dsa-87", Pq.Prim.ML_DSA_87}, {"slh-dsa-sha2-128f", Pq.Prim.SLH_DSA_SHA2_128F},
            {"hybrid-ed25519-slh-dsa-sha2-128f", Pq.Prim.SLH_DSA_SHA2_128F},
        };
        for (Object[] c : cases) {
            String alg = (String) c[0];
            Keys.EdKey ed = Keys.edFromSeed(hex("08".repeat(32)));
            Keys.PqKey pq = Keys.pqGenerate((Pq.Prim) c[1]);
            Keys.SuiteKey me = Keys.suite(alg, ed, pq);
            Issue.Grant g = Issue.mintGrant(principal, ed.id(), pq.pkB64u(), envelope(), "g", null);
            Map<String, Object> a = Agent.create(me, AUD, g.grant, null).clock(() -> NOW).act("read", "x", null);
            Pca.Verdict v = verify(a, g.grant);
            assertTrue(v.allow, alg + ": " + v.reason);
            emit(alg, g.grant, a);
        }
    }

    @Test void suiteKeysFailClosed() {
        Keys.EdKey ed = Keys.edGenerate();
        assertThrows(IllegalArgumentException.class, () -> Keys.suite("ml-dsa-65", null, null));
        assertThrows(IllegalArgumentException.class, () -> Keys.suite("hybrid-ed25519-ml-dsa-65", ed, null));
        assertThrows(IllegalArgumentException.class, () -> Keys.suite("fn-dsa-512", ed, null));
        assertThrows(IllegalArgumentException.class, () -> Keys.suite("hybrid-ed25519-ml-dsa-65", null, Keys.pqGenerate(Pq.Prim.ML_DSA_65)));
        assertThrows(IllegalArgumentException.class, () -> Keys.suite("ml-dsa-87", ed, Keys.pqGenerate(Pq.Prim.ML_DSA_65)));
        assertThrows(IllegalArgumentException.class, () -> Keys.edFromSeed(new byte[31]));
    }

    @Test void escalationAnswerVerifies() {
        Keys.SuiteKey principal = Keys.ed25519(Keys.edFromSeed(new byte[32]));
        Keys.SuiteKey me = Keys.ed25519(Keys.edFromSeed(hex("09".repeat(32))));
        Issue.Grant g = Issue.mintGrant(principal, me.id(), null, envelope(), "g", null);
        Map<String, Object> a = Agent.create(me, AUD, g.grant, null).clock(() -> NOW).act("read", "x", null);
        Map<String, Object> grant = Issue.norm(g.grant);
        Map<String, Object> pa = Issue.norm(a);
        Map<String, Object> ans = Issue.escalationAnswer(principal, grant, pa, null, true, NOW, NOW + 60_000, null);
        Escalation.Binding b = new Escalation.Binding(Escalation.policyDigest(grant), Escalation.actionDigest(pa), Escalation.historyHead(null));
        Escalation.Result r = Escalation.verify(ans, List.of(principal.id()), b, NOW + 1);
        assertTrue(r.ok, r.reason);
        assertEquals("allow", r.decision);
        assertFalse(Escalation.verify(ans, List.of(me.id()), b, NOW + 1).ok);
        assertFalse(Escalation.verify(ans, List.of(principal.id()), b, NOW + 120_000).ok);
        assertThrows(IllegalArgumentException.class, () -> Issue.escalationAnswer(principal, grant, pa, null, true, NOW, NOW + 90_000_000L, null));
    }

    @Test void dischargeVerifies() {
        Keys.SuiteKey principal = Keys.ed25519(Keys.edFromSeed(new byte[32]));
        Keys.SuiteKey me = Keys.ed25519(Keys.edFromSeed(hex("0a".repeat(32))));
        Keys.SuiteKey oracle = Keys.ed25519(Keys.edFromSeed(hex("0b".repeat(32))));
        Issue.Grant g = Issue.mintGrant(principal, me.id(), null, envelope(), "g", null);
        Map<String, Object> hop = Issue.norm(g.grant);
        Map<String, Object> claims = Issue.obj("approved", true);
        Map<String, Object> d = Issue.discharge(oracle, "kyc", "kyc-service", hop, "chain_hop", null, claims, NOW, NOW + 60_000);
        Map<String, Object> caveat = Issue.norm(Issue.obj("type", "needs_discharge", "id", "kyc", "issuer", "kyc-service", "issuer_class", "workload", "bind", "chain_hop",
            "ttl_ms", 3_600_000L, "require", List.of(Issue.obj("claim", "approved", "op", "eq", "value", true))));
        Map<String, Object> pin = Issue.obj("label", "kyc-service", "class", "workload", "pk", oracle.id());
        Map<String, Object> bind = Issue.norm(Issue.obj("cap_hash", Pca.capHash(hop), "pins", List.of(pin), "now", NOW + 1));
        CaveatLang.DischargeVerdict v = CaveatLang.verifyDischarge(d, caveat, bind);
        assertTrue(v.ok, v.reason);
    }

    @Test void narrowVerifies() {
        Keys.SuiteKey principal = Keys.ed25519(Keys.edFromSeed(new byte[32]));
        Keys.SuiteKey me = Keys.ed25519(Keys.edFromSeed(hex("0c".repeat(32))));
        Issue.Grant g = Issue.mintGrant(principal, me.id(), null, envelope(), "g", null);
        Map<String, Object> hop = Issue.norm(g.grant);
        List<Object> cav = new ArrayList<>();
        cav.add(Issue.obj("type", "max_uses", "id", "u2", "n", 2L, "until", NOW + 3_600_000L));
        Map<String, Object> n = Issue.narrow(me, hop, cav, null, NOW, NOW + 60_000);
        CaveatLang.NarrowVerdict v = CaveatLang.verifyNarrow(n, hop, null, Issue.norm(Issue.obj("now", NOW + 1)));
        assertTrue(v.ok, v.reason);
    }

    @Test void passportVerifies() {
        Keys.SuiteKey issuer = Keys.ed25519(Keys.edFromSeed(new byte[32]));
        Keys.SuiteKey agent = Keys.ed25519(Keys.edFromSeed(hex("0d".repeat(32))));
        Map<String, Object> p = Issue.issuePassport(Issue.obj("model_id", "m1", "operator", "acme", "hardware_rooted", false, "issued_at", NOW));
        Map<String, Object> sp = Issue.signPassport(p, issuer, agent.id(), NOW, null, NOW + 3_600_000L, null);
        Passport.Options o = new Passport.Options();
        o.trustedIssuers = List.of(issuer.id());
        o.nowMs = NOW + 1;
        o.revoked = (id, iss, sub) -> false;
        assertEquals("", Passport.verify(sp, o));
        assertThrows(IllegalArgumentException.class, () -> Issue.signPassport(Issue.issuePassport(Issue.obj("model_id", "m", "operator", "o", "hardware_rooted", true, "issued_at", NOW)), issuer, agent.id(), NOW, null, NOW + 1, null));
    }
}
