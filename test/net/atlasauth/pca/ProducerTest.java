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
        return Pca.verifyPcactnJson(Issue.encode(pcactn), Issue.norm(grant), NOW, AUD, null, null, null, null, Pca.PlanRoots.SKIP);
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

    @Test void hybridMlDsaLeafAndRoot() {
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
        // deterministic: same seed, same key
        assertArrayEquals(aPq.pk, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, hex("07".repeat(32))).pk);
    }

    @Test void everyPqSuiteLeafRoundTrips() {
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

    // ---- natives -> reference: this SDK's signed artifacts for the reference verifier ------------------------------------------

    static final String V3_AUD = "rs-java-producer";
    static final long V3_NOW = NOW + 1000;

    static Map<String, Object> pins(Keys.SuiteKey k, Object... extra) {
        Map<String, Object> p = Issue.obj(extra);
        p.put("pk", k.ed.id());
        if (k.pqPk() != null) p.put("pq_pk", k.pqPk());
        return p;
    }

    static Map<String, Object> pcactnCase(String alg, Map<String, Object> grant, Map<String, Object> pcactn) {
        return Issue.obj("kind", "pcactn", "alg", alg, "grant", Issue.norm(grant), "pcactn", Issue.norm(pcactn));
    }

    static Map<String, Object> artifactCase(String kind, String alg, Map<String, Object> pins, Map<String, Object> artifact) {
        return Issue.obj("kind", kind, "alg", alg, "pins", pins, "artifact", Issue.norm(artifact));
    }

    /**
     * One PCActn per suite this SDK signs (and one from a delegated sub-agent under each), one facade act with params, and each
     * artifact kind under Ed25519 and a hybrid ML-DSA suite. PCActns and escalation answers are checked here; the reference checks all.
     */
    static Map<String, Object> nativeFile() {
        Keys.EdKey principalEd = ProducerVectorsTest.key("principal"), agentEd = ProducerVectorsTest.key("agent"), subEd = ProducerVectorsTest.key("subagent");
        Keys.SuiteKey principal = Keys.ed25519(principalEd);
        List<Object> preds = new ArrayList<>();
        preds.add(Issue.obj("verb", "refund", "resource", "orders/*"));
        Map<String, Object> env = Issue.obj("predicates", preds, "caveats", new ArrayList<Object>(), "agent_binding", Issue.obj(), "risk_policy", Issue.defaultRiskPolicy());
        List<Object> cases = new ArrayList<>();
        int i = 0;
        for (String alg : Pq.supportedSuites()) {
            Pq.Suite st = Pq.SUITES.get(alg);
            if (st.pq == Pq.Prim.LESS_CAT1) continue; // LESS signing is not offered by this SDK
            i++;
            Keys.PqKey pq = st.pq == null ? null : Keys.pqFromSeed(st.pq, seed(st.pq, i));
            Keys.SuiteKey me = st.pq == null ? Keys.ed25519(agentEd) : Keys.suite(alg, agentEd, pq);
            Issue.Grant g = Issue.mintGrant(principal, agentEd.id(), me.pqPk(), env, "refund an order", "s");
            Agent a = Agent.create(me, V3_AUD, g.grant, null).clock(() -> NOW);
            cases.add(pcactnCase(alg, g.grant, a.act("refund", "orders/1", Issue.obj("amount", 5L))));
            Keys.SuiteKey sub = st.pq == null ? Keys.ed25519(subEd) : Keys.suite(alg, subEd, Keys.pqFromSeed(st.pq, seed(st.pq, 100 + i)));
            List<Object> add = new ArrayList<>();
            add.add(Issue.obj("type", "budget_alloc", "limit", 5L));
            cases.add(pcactnCase(alg, g.grant, a.delegate(sub, add).act("refund", "orders/2", Issue.obj("amount", 1L))));
        }
        Map<String, Object> perms = Issue.obj("stripe", new ArrayList<Object>(List.of("refund")));
        Facade.Handle h = Agent.fromPrincipal(new Facade.AgentOptions(principal, "refund order 1", perms)
            .limits(Issue.obj("refund", "$500/day")).holder(Keys.ed25519(agentEd)).aud(V3_AUD).now(NOW));
        h.provenance.principal("refund order 1");
        Facade.ActOptions ao = new Facade.ActOptions();
        ao.now = NOW;
        cases.add(pcactnCase("ed25519", h.grant, h.act("stripe.refund", "charge:ch_1", Issue.obj("amount", 42L, "currency", "usd"), ao).pcactn));

        String hyb = "hybrid-ed25519-ml-dsa-65";
        Keys.PqKey pq1 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(42, 32)), pq2 = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(43, 32));
        Keys.EdKey guardianEd = ProducerVectorsTest.key("guardian"), siteEd = ProducerVectorsTest.key("site"), oracleEd = ProducerVectorsTest.key("oracle");
        for (String alg : List.of("ed25519", hyb)) {
            boolean ed = "ed25519".equals(alg);
            Keys.SuiteKey p = ed ? principal : Keys.suite(alg, principalEd, pq1);
            Keys.SuiteKey guardian = ed ? Keys.ed25519(guardianEd) : Keys.suite(alg, guardianEd, pq2);
            Keys.SuiteKey site = ed ? Keys.ed25519(siteEd) : Keys.suite(alg, siteEd, pq2);
            Keys.SuiteKey oracle = ed ? Keys.ed25519(oracleEd) : Keys.suite(alg, oracleEd, pq1);
            Map<String, Object> ans = new java.util.LinkedHashMap<>(ProducerVectorsTest.m(ProducerVectorsTest.args("escalation-answer-allow").get("body")));
            ans.put("principal", principalEd.id());
            cases.add(artifactCase("escalation_answer", alg, pins(p), Issue.signEscalationAnswer(ans, p)));
            cases.add(artifactCase("revocation_epoch", alg, pins(guardian),
                SignersMore.signRevocationEpoch(guardian, ProducerVectorsTest.m(ProducerVectorsTest.args("revocation-epoch").get("body")))));
            cases.add(artifactCase("session_root", alg, pins(p),
                SignersMore.signSessionRoot(ProducerVectorsTest.m(ProducerVectorsTest.args("session-root").get("body")), p)));
            cases.add(artifactCase("action_schema", alg, pins(site, "kid", "site-k1", "alg", alg),
                SignersMore.signActionSchema(ProducerVectorsTest.m(ProducerVectorsTest.args("action-schema").get("doc")), "site-k1", site)));
            cases.add(artifactCase("intent_required", alg, pins(site, "kid", "site-k1", "alg", alg),
                SignersMore.signIntentRequired(ProducerVectorsTest.m(ProducerVectorsTest.args("intent-required").get("body")), "site-k1", site)));
            Map<String, Object> lb = ProducerVectorsTest.m(ProducerVectorsTest.args("labels").get("body"));
            cases.add(artifactCase("labels", alg, pins(site, "kid", lb.get("kid"), "site", lb.get("site")), SignersMore.signLabels(lb, site)));
            cases.add(artifactCase("fact", alg, pins(oracle), SignersMore.signFact(ProducerVectorsTest.m(ProducerVectorsTest.args("fact-integer").get("body")), oracle)));
        }
        cases.add(artifactCase("caution", "ed25519", pins(Keys.ed25519(agentEd)),
            SignersMore.signCaution(ProducerVectorsTest.m(ProducerVectorsTest.args("caution").get("body")), agentEd)));
        cases.add(artifactCase("pq_binding", "ed25519", pins(Keys.ed25519(agentEd)),
            SignersMore.signPqBinding(agentEd, (String) ProducerVectorsTest.args("pq-binding").get("pq_pk"), 1, V3_AUD)));
        return Issue.obj("lang", "java", "aud", V3_AUD, "now", V3_NOW, "cases", cases);
    }

    static byte[] fill(int b, int n) {
        byte[] out = new byte[n];
        java.util.Arrays.fill(out, (byte) b);
        return out;
    }

    /** A fixed seed of the length the primitive's seeded key generation takes. */
    static byte[] seed(Pq.Prim p, int b) {
        return fill(b, p == Pq.Prim.SLH_DSA_SHA2_128F ? 48 : p == Pq.Prim.SLH_DSA_SHA2_256S ? 96 : 32);
    }

    /** Builds this SDK's artifacts for the reference verifier; with PCA_PRODUCER_OUT set (CI) writes them there. */
    @Test void nativeProducerFile() throws java.io.IOException {
        Map<String, Object> doc = nativeFile();
        List<Object> cases = ProducerVectorsTest.l(doc.get("cases"));
        java.util.Set<Object> kinds = new java.util.TreeSet<>();
        for (Object c : cases) kinds.add(ProducerVectorsTest.m(c).get("kind"));
        assertEquals("[action_schema, caution, escalation_answer, fact, intent_required, labels, pcactn, pq_binding, revocation_epoch, session_root]", kinds.toString());
        int pcactns = 0, subs = 0;
        for (Object o : cases) {
            Map<String, Object> c = ProducerVectorsTest.m(o);
            if ("pcactn".equals(c.get("kind"))) {
                Map<String, Object> p = ProducerVectorsTest.m(c.get("pcactn"));
                Pca.Verdict v = Pca.verifyPcactn(p, ProducerVectorsTest.m(c.get("grant")), V3_NOW, V3_AUD, null, null, null, null, Pca.PlanRoots.SKIP);
                assertTrue(v.allow, c.get("alg") + ": " + v.reason);
                pcactns++;
                if (ProducerVectorsTest.l(p.get("cap_chain")).size() == 2) subs++;
            }
            if ("escalation_answer".equals(c.get("kind"))) {
                Map<String, Object> a = ProducerVectorsTest.m(c.get("artifact"));
                Map<String, Object> pin = ProducerVectorsTest.m(c.get("pins"));
                Escalation.Binding b = new Escalation.Binding((String) a.get("policy_digest"), (String) a.get("action_digest"), (String) a.get("history_head"));
                Escalation.Result r = Escalation.verify(a, List.of(pin), b, V3_NOW);
                assertTrue(r.ok, c.get("alg") + ": " + r.reason);
            }
        }
        assertEquals((pcactns - 1) / 2, subs, "one delegated sub-agent PCActn per suite");
        String out = System.getenv("PCA_PRODUCER_OUT");
        if (out == null || out.isEmpty()) return;
        java.nio.file.Files.writeString(java.nio.file.Path.of(out), Json.canonicalize(doc), StandardCharsets.UTF_8);
    }
}
