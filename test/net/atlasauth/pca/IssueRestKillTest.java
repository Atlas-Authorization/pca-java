package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link Issue} (the producer side): exact defaults, every refusal with its message, the optional members
 * that are present only when given, the PQ suite members, and the strict-canonical deep copy (numbers come back as {@link Json.Num},
 * nested values are fresh objects).
 */
public class IssueRestKillTest {
    static final long NOW = 1_800_000_000_000L;
    static final String AUD = "ins_issue_kill";

    static byte[] fill(int b) { byte[] x = new byte[32]; java.util.Arrays.fill(x, (byte) b); return x; }

    static final Keys.SuiteKey P = Keys.ed25519(Keys.edFromSeed(fill(11)));
    static final Keys.SuiteKey ME = Keys.ed25519(Keys.edFromSeed(fill(12)));
    static final Keys.SuiteKey SUB = Keys.ed25519(Keys.edFromSeed(fill(13)));
    static final String D32 = Pca.b64(fill(14));

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }
    static String canon(Object o) { return Json.canonicalize(o); }
    static long num(Object o) { return Json.asLong(o); }

    static void iae(String msg, org.junit.jupiter.api.function.Executable ex) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, ex);
        assertEquals(msg, e.getMessage());
    }

    static void iaePrefix(String prefix, org.junit.jupiter.api.function.Executable ex) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, ex);
        assertTrue(e.getMessage().startsWith(prefix) && e.getMessage().length() > prefix.length(), e.getMessage());
    }

    static void nonce16(Object n) {
        assertEquals(22, ((String) n).length());
        assertEquals(16, Pca.decodeB64uStrict(n, -1).length);
    }

    // ---- defaults ----------------------------------------------------------------------------------------------------

    @Test void defaultRiskPolicyIsExact() {
        String lit = "{\"weights\":{\"alpha\":0.25,\"beta\":0.2,\"gamma\":0.2,\"delta\":0.2,\"epsilon\":0.1,\"zeta\":0.05},"
            + "\"theta1\":0.25,\"theta2\":0.6,\"kappa\":1,\"lambda\":0.0005,\"rho\":0.5,\"bMax\":1}";
        assertEquals(canon(Json.parse(lit)), canon(Issue.defaultRiskPolicy()));
        Map<String, Object> p = Issue.defaultRiskPolicy();
        assertEquals(List.of("weights", "theta1", "theta2", "kappa", "lambda", "rho", "bMax"), new ArrayList<>(p.keySet()));
        assertEquals(List.of("alpha", "beta", "gamma", "delta", "epsilon", "zeta"), new ArrayList<>(m(p.get("weights")).keySet()));
        assertEquals(1L, p.get("kappa"));
        assertEquals(1L, p.get("bMax"));
    }

    // ---- roots, grants, delegation ----------------------------------------------------------------------------------

    static List<Object> cavs() {
        List<Object> c = new ArrayList<>();
        c.add(Issue.obj("type", "max_uses", "id", "u1", "n", 3L, "until", NOW + 3_600_000L));
        return c;
    }

    @Test void rootSuiteMembers() {
        Map<String, Object> ed = Issue.mintRoot(P, ME.id(), null, cavs());
        assertFalse(ed.containsKey("alg"));
        assertFalse(ed.containsKey("pq_pk"));
        assertFalse(ed.containsKey("pq_sig"));
        assertFalse(ed.containsKey("holder_pq"));
        assertFalse(ed.containsKey("parent"));
        assertEquals(P.id(), ed.get("issuer"));
        assertEquals(ed.get("id"), ed.get("body_digest"));

        Keys.SuiteKey hybrid = Keys.suite("hybrid-ed25519-ml-dsa-65", Keys.edFromSeed(fill(15)), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(16)));
        Map<String, Object> h = Issue.mintRoot(hybrid, ME.id(), "pq-holder", cavs());
        assertEquals("hybrid-ed25519-ml-dsa-65", h.get("alg"));
        assertEquals(hybrid.pqPk(), h.get("pq_pk"));
        assertTrue(h.get("pq_sig") instanceof String);
        assertNotEquals(h.get("sig"), h.get("pq_sig"));
        assertTrue(((String) h.get("pq_sig")).length() > 1000);
        assertEquals(Pca.holderPqCommitment("pq-holder"), h.get("holder_pq"));

        Keys.SuiteKey pure = Keys.suite("ml-dsa-65", Keys.edFromSeed(fill(15)), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(16)));
        Map<String, Object> pr = Issue.mintRoot(pure, ME.id(), null, cavs());
        assertEquals("ml-dsa-65", pr.get("alg"));
        assertEquals(pure.pqPk(), pr.get("pq_pk"));
        assertFalse(pr.containsKey("pq_sig"));

        Keys.SuiteKey noEd = Keys.suite("ml-dsa-65", null, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(16)));
        iae("a root issuer needs an Ed25519 identity", () -> Issue.mintRoot(noEd, ME.id(), null, cavs()));
    }

    @Test void rootCaveatsAreAStrictCopy() {
        List<Object> c = cavs();
        Map<String, Object> r = Issue.mintRoot(P, ME.id(), null, c);
        assertNotSame(c, r.get("caveats"));
        assertNotSame(c.get(0), l(r.get("caveats")).get(0));
        assertTrue(m(l(r.get("caveats")).get(0)).get("n") instanceof Json.Num);
        assertEquals(canon(c), canon(r.get("caveats")));
        c.add("later");
        assertEquals(1, l(r.get("caveats")).size());
    }

    static Map<String, Object> envelope() { return ProducerTest.envelope(); }

    @Test void mintGrantRefusals() {
        iae("mintGrant: goal required", () -> Issue.mintGrant(P, ME.id(), null, envelope(), null, "s"));
        iae("mintGrant: goal required", () -> Issue.mintGrant(P, ME.id(), null, envelope(), "", "s"));
        for (String k : new String[] {"predicates", "caveats", "risk_policy"}) {
            // a missing risk policy is refused by the risk-policy check, with the reference's text
            String want = "risk_policy".equals(k) ? "mintGrant: " + Authorize.validateRiskPolicy(null) : "mintGrant: envelope." + k + " is required";
            Map<String, Object> e = envelope();
            e.remove(k);
            iae(want, () -> Issue.mintGrant(P, ME.id(), null, e, "g", "s"));
            Map<String, Object> n = envelope();
            n.put(k, null);
            iae(want, () -> Issue.mintGrant(P, ME.id(), null, n, "g", "s"));
        }
    }

    @Test void mintGrantSaltAndEnvelope() {
        Issue.Grant a = Issue.mintGrant(P, ME.id(), null, envelope(), "goal", null);
        nonce16(a.goalSalt);
        assertEquals(Issue.goalCommit("goal", a.goalSalt), a.goalCommit);
        Issue.Grant b = Issue.mintGrant(P, ME.id(), null, envelope(), "goal", null);
        assertNotEquals(a.goalSalt, b.goalSalt);
        Issue.Grant c = Issue.mintGrant(P, ME.id(), null, envelope(), "goal", "my-salt");
        assertEquals("my-salt", c.goalSalt);
        assertEquals(Issue.goalCommit("goal", "my-salt"), c.goalCommit);

        Map<String, Object> e = envelope();
        e.put("type", "evil");
        e.put("goal_commit", "forged");
        e.put("surprise", "u");
        Map<String, Object> env = m(l(Issue.mintGrant(P, ME.id(), null, e, "goal", "s").grant.get("caveats")).get(0));
        assertEquals(Set.of("type", "goal_commit", "predicates", "caveats", "risk_policy", "agent_binding"), env.keySet());
        assertEquals("envelope", env.get("type"));
        assertEquals(Issue.goalCommit("goal", "s"), env.get("goal_commit"));
        assertEquals("{}", canon(env.get("agent_binding")));
        assertEquals(canon(e.get("risk_policy")), canon(env.get("risk_policy")));

        Map<String, Object> e2 = envelope();
        e2.put("agent_binding", Issue.obj("model_id", "m"));
        Map<String, Object> env2 = m(l(Issue.mintGrant(P, ME.id(), null, e2, "goal", "s").grant.get("caveats")).get(0));
        assertEquals("{\"model_id\":\"m\"}", canon(env2.get("agent_binding")));
        assertEquals(1, l(Issue.mintGrant(P, ME.id(), null, e2, "goal", "s").grant.get("caveats")).size());
    }

    @Test void delegateHolderPqAndCaveats() {
        Map<String, Object> parent = Issue.mintRoot(P, ME.id(), "pqA", cavs());
        assertEquals(Pca.holderPqCommitment("pqA"), parent.get("holder_pq"));
        List<Object> added = new ArrayList<>();
        added.add(Issue.obj("type", "max_uses", "id", "u2", "n", 1L, "until", NOW + 60_000L));

        // a new PQ key is committed (not copied raw)
        Map<String, Object> a = Issue.delegate(parent, SUB.id(), null, ME, "pqB");
        assertEquals(Pca.holderPqCommitment("pqB"), a.get("holder_pq"));
        assertEquals(canon(parent.get("caveats")), canon(a.get("caveats")));
        assertEquals(ME.id(), a.get("issuer"));
        assertEquals(SUB.id(), a.get("holder"));
        assertEquals(Pca.capHash(parent), a.get("parent"));
        assertNotSame(l(parent.get("caveats")).get(0), l(a.get("caveats")).get(0));

        // same holder: the parent's commitment carries over
        Map<String, Object> b = Issue.delegate(parent, ME.id(), added, ME, null);
        assertEquals(parent.get("holder_pq"), b.get("holder_pq"));
        assertEquals(2, l(b.get("caveats")).size());
        assertEquals(canon(added.get(0)), canon(l(b.get("caveats")).get(1)));
        assertNotSame(added.get(0), l(b.get("caveats")).get(1));
        assertTrue(m(l(b.get("caveats")).get(1)).get("n") instanceof Json.Num);

        // another holder: no commitment
        Map<String, Object> c = Issue.delegate(parent, SUB.id(), added, ME, null);
        assertFalse(c.containsKey("holder_pq"));
        assertEquals(2, l(c.get("caveats")).size());

        // same holder, parent without a commitment
        Map<String, Object> plain = Issue.mintRoot(P, ME.id(), null, cavs());
        assertFalse(Issue.delegate(plain, ME.id(), added, ME, null).containsKey("holder_pq"));
    }

    @Test void attenuateIsDelegateToTheSameHolder() {
        Map<String, Object> parent = Issue.mintRoot(P, ME.id(), "pqA", cavs());
        List<Object> added = new ArrayList<>();
        added.add(Issue.obj("type", "max_uses", "id", "u3", "n", 1L, "until", NOW + 60_000L));
        Map<String, Object> at = Issue.attenuate(parent, added, ME);
        assertEquals(canon(Issue.delegate(parent, ME.id(), added, ME, null)), canon(at));
        assertEquals(ME.id(), at.get("holder"));
        assertEquals(parent.get("holder_pq"), at.get("holder_pq"));
        assertEquals(2, l(at.get("caveats")).size());
        assertEquals(Pca.capHash(parent), at.get("parent"));
    }

    // ---- plans -------------------------------------------------------------------------------------------------------

    @Test void planRefusals() {
        List<Map<String, Object>> nodes = new ArrayList<>();
        nodes.add(Issue.obj("id", "a", "verb", "read", "resource", "r"));
        nodes.add(Issue.obj("id", "b", "verb", "read", "resource", "r"));
        Issue.Plan p = Issue.commitPlan(nodes);
        iae("commitPlan: unknown node zz", () -> p.proofFor("zz"));
        assertEquals(1L, num(p.proofFor("b").get("index")));
        assertEquals(0L, num(p.proofFor("a").get("index")));
        assertEquals(2L, num(p.proofFor("a").get("size")));

        List<Map<String, Object>> dup = new ArrayList<>(nodes);
        dup.add(Issue.obj("id", "a", "verb", "x", "resource", "y"));
        iae("commitPlan: missing or duplicate node id a", () -> Issue.commitPlan(dup));
        List<Map<String, Object>> noId = new ArrayList<>();
        noId.add(Issue.obj("verb", "x", "resource", "y"));
        iae("commitPlan: missing or duplicate node id null", () -> Issue.commitPlan(noId));
        iae("commitPlan: empty plan", () -> Issue.commitPlan(new ArrayList<Map<String, Object>>()));
    }

    // ---- PCActn ------------------------------------------------------------------------------------------------------

    static final Map<String, Object> PARAMS = Issue.obj("amount", 5L);

    static Issue.ActSpec spec() {
        Map<String, Object> g = Issue.mintGrant(P, ME.id(), null, envelope(), "g", "s").grant;
        List<Map<String, Object>> nodes = new ArrayList<>();
        nodes.add(Issue.obj("id", "a", "verb", "read", "resource", "r"));
        nodes.add(Issue.obj("id", "b", "verb", "pay", "resource", "r2", "params_digest", Pca.paramsDigest(PARAMS)));
        Issue.ActSpec s = new Issue.ActSpec();
        s.grant = g;
        s.chain = new ArrayList<Object>(List.of(g));
        s.plan = Issue.commitPlan(nodes);
        s.nodeId = "a";
        s.counter = 3;
        s.signer = ME;
        s.aud = AUD;
        s.iat = NOW;
        return s;
    }

    @Test void buildPCActnRefusals() {
        Issue.ActSpec s = spec();
        s.aud = null;
        iae("buildPCActn: aud (audience) is required", () -> Issue.buildPCActn(s));
        s.aud = "";
        iae("buildPCActn: aud (audience) is required", () -> Issue.buildPCActn(s));
        s.aud = AUD;
        s.nodeId = "zz";
        iae("buildPCActn: unknown plan node zz", () -> Issue.buildPCActn(s));
        s.nodeId = "b";
        s.params = Issue.obj("amount", 6L);
        iae("buildPCActn: params do not match plan node b's params_digest", () -> Issue.buildPCActn(s));
        s.params = null;
        iae("buildPCActn: params do not match plan node b's params_digest", () -> Issue.buildPCActn(s));
        s.params = PARAMS;
        assertEquals(Pca.paramsDigest(PARAMS), m(Issue.buildPCActn(s).get("action")).get("params_digest"));
        // a node without params_digest takes any params
        s.nodeId = "a";
        s.params = Issue.obj("x", "y");
        Map<String, Object> p = Issue.buildPCActn(s);
        assertEquals(Pca.paramsDigest(s.params), m(p.get("action")).get("params_digest"));
        assertEquals("a", m(p.get("plan")).get("node_id"));
        assertEquals(3L, num(p.get("counter")));
    }

    @Test void buildPCActnTimes() {
        Issue.ActSpec s = spec();
        s.exp = NOW + 42L;
        s.ttlMs = 9_000L;
        Map<String, Object> a = Issue.buildPCActn(s);
        assertEquals(NOW, num(a.get("iat")));
        assertEquals(NOW + 42L, num(a.get("exp")));
        s.exp = null;
        assertEquals(NOW + 9_000L, num(Issue.buildPCActn(s).get("exp")));
        s.ttlMs = null;
        assertEquals(NOW + 1_200_000L, num(Issue.buildPCActn(s).get("exp")));
        s.iat = null;
        long before = System.currentTimeMillis();
        Map<String, Object> b = Issue.buildPCActn(s);
        long after = System.currentTimeMillis();
        long iat = num(b.get("iat"));
        assertTrue(iat >= before && iat <= after, "iat " + iat);
        assertEquals(iat + 1_200_000L, num(b.get("exp")));
    }

    @Test void buildPCActnDefaultsAndOptionalMembers() {
        Issue.ActSpec s = spec();
        Map<String, Object> d = Issue.buildPCActn(s);
        assertEquals(canon(Issue.obj("quote_digest", "", "epoch", 0L, "model_id", "unattested", "measurement", "", "operator", "unattested")), canon(d.get("attestation")));
        assertEquals(canon(Issue.obj("causal_hash", "", "taint_level", 0L, "trusted_refs", new ArrayList<Object>())), canon(d.get("provenance")));
        assertEquals(canon(Issue.obj("beacon_ref", "", "epoch", 0L, "accumulator_witness", "")), canon(d.get("freshness")));
        assertEquals(canon(Issue.obj("r", 0L, "inputs", new LinkedHashMap<String, Object>())), canon(d.get("risk_claim")));
        for (String k : new String[] {"nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding", "intent", "intent_session", "fresh_at", "alg", "pq_pk", "pq_sig"})
            assertFalse(d.containsKey(k), k);

        s.attestation = Issue.obj("x", "att");
        s.provenance = Issue.obj("x", "prov");
        s.freshness = Issue.obj("x", "fresh");
        s.riskClaim = Issue.obj("x", "risk");
        s.progressStep = Issue.obj("x", "ps");
        s.prohibitionEvidence = new ArrayList<Object>(List.of("pe"));
        s.toolBinding = "tb";
        s.intent = Issue.obj("x", "intent");
        s.intentSession = Issue.obj("x", "is");
        s.freshAt = Issue.obj("x", "fa");
        s.nonce = "nonce";
        s.caution = new Json.Num("0.5");
        s.rationaleCommitment = "rc";
        Map<String, Object> f = Issue.buildPCActn(s);
        assertSame(s.attestation, f.get("attestation"));
        assertSame(s.provenance, f.get("provenance"));
        assertSame(s.freshness, f.get("freshness"));
        assertSame(s.riskClaim, f.get("risk_claim"));
        assertSame(s.progressStep, f.get("progress_step"));
        assertSame(s.prohibitionEvidence, f.get("prohibition_evidence"));
        assertSame(s.toolBinding, f.get("tool_binding"));
        assertSame(s.intent, f.get("intent"));
        assertSame(s.intentSession, f.get("intent_session"));
        assertSame(s.freshAt, f.get("fresh_at"));
        assertSame(s.nonce, f.get("nonce"));
        assertSame(s.caution, f.get("caution"));
        assertSame(s.rationaleCommitment, f.get("rationale_commitment"));
    }

    // ---- signed artifacts --------------------------------------------------------------------------------------------

    @Test void signArtifactCopiesStrictly() {
        Map<String, Object> body = Issue.obj("v", 1L, "nested", Issue.obj("a", "b"));
        Map<String, Object> s = Issue.signArtifact("atlas-pca/test/v1\0", body, ME);
        assertNotSame(body.get("nested"), s.get("nested"));
        assertTrue(s.get("v") instanceof Json.Num);
        assertEquals(canon(body.get("nested")), canon(s.get("nested")));
        assertFalse(body.containsKey("sig"));
        assertTrue(s.get("sig") instanceof String);
    }

    static Map<String, Object> hop() { return Issue.norm(Issue.mintGrant(P, ME.id(), null, envelope(), "g", "s").grant); }

    @Test void dischargeMembers() {
        Keys.SuiteKey oracle = Keys.ed25519(Keys.edFromSeed(fill(17)));
        Map<String, Object> hop = hop();
        Map<String, Object> d = Issue.discharge(oracle, "kyc", "kyc-service", hop, "chain_hop", null, null, NOW, NOW + 60_000L);
        assertEquals("{}", canon(d.get("claims")));
        assertFalse(d.containsKey("action_digest"));
        nonce16(d.get("nonce"));
        assertEquals(Pca.capHash(hop), d.get("cap_hash"));
        Map<String, Object> a = Issue.discharge(oracle, "kyc", "kyc-service", hop, "action", D32, Issue.obj("approved", true), NOW, NOW + 60_000L);
        assertEquals(D32, a.get("action_digest"));
        assertEquals("{\"approved\":true}", canon(a.get("claims")));
        assertEquals("action", a.get("bind"));
        iaePrefix("signDischarge: ", () -> Issue.signDischarge(Issue.obj("v", 1L), oracle));
    }

    @Test void narrowMembers() {
        Map<String, Object> hop = hop();
        List<Object> cav = new ArrayList<>();
        cav.add(Issue.obj("type", "max_uses", "id", "u2", "n", 2L, "until", NOW + 3_600_000L));
        Map<String, Object> n = Issue.narrow(ME, hop, cav, null, NOW, NOW + 60_000L);
        assertFalse(n.containsKey("action_digest"));
        nonce16(n.get("nonce"));
        assertEquals(ME.id(), n.get("holder"));
        Map<String, Object> a = Issue.narrow(ME, hop, cav, D32, NOW, NOW + 60_000L);
        assertEquals(D32, a.get("action_digest"));
        iaePrefix("signNarrow: ", () -> Issue.signNarrow(Issue.obj("v", 1L), ME));
    }

    @Test void escalationAnswerMembers() {
        Issue.Grant g = Issue.mintGrant(P, ME.id(), null, envelope(), "g", "s");
        Map<String, Object> pa = Issue.norm(Agent.create(ME, AUD, g.grant, null).clock(() -> NOW).act("read", "x", null));
        Map<String, Object> grant = Issue.norm(g.grant);
        Map<String, Object> deny = Issue.escalationAnswer(P, grant, pa, null, false, NOW, NOW + 60_000L, null);
        assertEquals("deny", deny.get("decision"));
        assertFalse(deny.containsKey("render_digest"));
        nonce16(deny.get("nonce"));
        Map<String, Object> allow = Issue.escalationAnswer(P, grant, pa, 4L, true, NOW, NOW + 60_000L, D32);
        assertEquals("allow", allow.get("decision"));
        assertEquals(D32, allow.get("render_digest"));
        assertEquals(Escalation.historyHead(4L), allow.get("history_head"));
    }

    // ---- workflow, receipts, read grants (bodies from the producer vectors) -----------------------------------------

    static Map<String, Object> args(String name) {
        for (Object c : l(ProducerVectorsTest.DOC.get("cases"))) if (name.equals(m(c).get("name"))) return Issue.norm(m(m(c).get("args")));
        throw new IllegalStateException("no producer vector " + name);
    }

    @Test void signWorkflowRefusals() {
        Keys.EdKey principal = ProducerVectorsTest.key("principal");
        Map<String, Object> body = m(args("workflow-sign").get("body"));
        Map<String, Object> ok = Issue.signWorkflow(principal, body);
        assertEquals(Set.of("body", "sig"), ok.keySet());
        assertNotSame(body, ok.get("body"));
        assertNotSame(body.get("steps"), m(ok.get("body")).get("steps"));
        assertEquals(canon(body), canon(ok.get("body")));
        iae("signWorkflow: principal is not the signer", () -> Issue.signWorkflow(ProducerVectorsTest.key("agent"), body));
        Map<String, Object> noSteps = Issue.norm(body);
        noSteps.remove("steps");
        iae("signWorkflow: malformed workflow", () -> Issue.signWorkflow(principal, noSteps));
        Map<String, Object> cycle = Issue.norm(body);
        m(l(cycle.get("steps")).get(0)).put("deps", new ArrayList<Object>(List.of("s2")));
        assertTrue(Workflow.validWorkflowBody(cycle));
        assertEquals("cycle", Workflow.dagError(cycle));
        iae("signWorkflow: malformed workflow", () -> Issue.signWorkflow(principal, cycle));
    }

    @Test void stepReceiptsChainTheirSeq() {
        Map<String, Object> a = args("workflow-receipt-first");
        Keys.EdKey rs = ProducerVectorsTest.key("rs");
        Map<String, Object> wf = m(a.get("workflow"));
        Map<String, Object> r0 = Issue.signStepReceipt(rs, wf, "s1", "ok", (String) a.get("params_digest"), m(a.get("outputs")), NOW, null);
        assertEquals(0L, num(r0.get("seq")));
        assertNull(r0.get("prev"));
        assertTrue(r0.get("issued_at") instanceof Json.Num);
        Map<String, Object> r1 = Issue.signStepReceipt(rs, wf, "s2", "ok", (String) a.get("params_digest"), new LinkedHashMap<String, Object>(), NOW + 1, r0);
        assertEquals(1L, num(r1.get("seq")));
        assertEquals(Workflow.receiptRef(r0), r1.get("prev"));
        Map<String, Object> r2 = Issue.signStepReceipt(rs, wf, "s2", "ok", (String) a.get("params_digest"), new LinkedHashMap<String, Object>(), NOW + 2, r1);
        assertEquals(2L, num(r2.get("seq")));
        Map<String, Object> r9 = Issue.signStepReceipt(rs, wf, "s2", "ok", (String) a.get("params_digest"), new LinkedHashMap<String, Object>(), NOW + 3,
            Issue.obj("seq", 8L, "sig", "x"));
        assertEquals(9L, num(r9.get("seq")));
    }

    @Test void wfOutputIsExact() {
        List<String> labels = new ArrayList<>(List.of("b", "a"));
        Map<String, Object> o = Issue.wfOutput(5L, labels, "usd", true);
        assertEquals(List.of("digest", "num", "unit", "labels"), new ArrayList<>(o.keySet()));
        assertEquals(Workflow.valueDigest(5L), o.get("digest"));
        assertEquals(5L, o.get("num"));
        assertEquals("usd", o.get("unit"));
        assertEquals(List.of("a", "b"), o.get("labels"));
        assertEquals(List.of("b", "a"), labels);
        assertEquals(canon(Issue.obj("digest", Workflow.valueDigest(5L), "num", 5L, "unit", "usd", "labels", List.of("a", "b"))), canon(o));

        Map<String, Object> n = Issue.wfOutput(5L, null, null, false);
        assertEquals(List.of("digest", "num", "unit", "labels"), new ArrayList<>(n.keySet()));
        assertNull(n.get("num"));
        assertNull(n.get("unit"));
        assertEquals(List.of(), n.get("labels"));
        assertEquals(canon(Issue.obj("digest", Workflow.valueDigest(5L), "num", null, "unit", null, "labels", List.of())), canon(n));

        Map<String, Object> s = Issue.wfOutput("x", List.of("z"), "u", true);
        assertNull(s.get("num"));
        assertEquals(Workflow.valueDigest("x"), s.get("digest"));
        assertEquals(List.of("z"), s.get("labels"));
    }

    @Test void readAndAggregateGrantRefusals() {
        Keys.EdKey principal = ProducerVectorsTest.key("principal");
        Keys.EdKey other = ProducerVectorsTest.key("agent");
        Map<String, Object> rg = m(args("read-grant-sign").get("body"));
        Map<String, Object> rok = Issue.signReadGrant(principal, rg);
        assertNotSame(rg, rok.get("body"));
        assertNotSame(rg.get("reads"), m(rok.get("body")).get("reads"));
        assertEquals(canon(rg), canon(rok.get("body")));
        iae("signReadGrant: malformed grant", () -> Issue.signReadGrant(other, rg));
        Map<String, Object> rbad = Issue.norm(rg);
        rbad.remove("reads");
        iae("signReadGrant: malformed grant", () -> Issue.signReadGrant(principal, rbad));

        Map<String, Object> ag = m(args("aggregate-grant-sign").get("body"));
        Map<String, Object> aok = Issue.signAggregateGrant(principal, ag);
        assertNotSame(ag, aok.get("body"));
        assertNotSame(ag.get("rules"), m(aok.get("body")).get("rules"));
        assertEquals(canon(ag), canon(aok.get("body")));
        iae("signAggregateGrant: malformed grant", () -> Issue.signAggregateGrant(other, ag));
        Map<String, Object> abad = Issue.norm(ag);
        abad.remove("rules");
        iae("signAggregateGrant: malformed grant", () -> Issue.signAggregateGrant(principal, abad));
    }

    // ---- passports ---------------------------------------------------------------------------------------------------

    static final String[] ID_FIELDS = {"model_id", "weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement", "operator", "hardware_rooted"};

    static Map<String, Object> identity(boolean hw) {
        return Issue.obj("model_id", "m1", "weights_digest", "w1", "system_prompt_digest", "sp", "tool_manifest_digest", "tm",
            "runtime_measurement", "rm", "operator", "acme", "hardware_rooted", hw, "issued_at", NOW);
    }

    @Test void passportFingerprintCoversEveryIdentityField() {
        Map<String, Object> id = identity(false);
        String fp = Issue.passportFingerprint(id);
        assertEquals(Pca.hashCanonical(Issue.obj("d", "atlas-pca/passport/v1", "model_id", "m1", "weights_digest", "w1", "system_prompt_digest", "sp",
            "tool_manifest_digest", "tm", "runtime_measurement", "rm", "operator", "acme", "hardware_rooted", false)), fp);
        for (String k : ID_FIELDS) {
            Map<String, Object> c = new LinkedHashMap<>(id);
            c.put(k, k.equals("hardware_rooted") ? (Object) Boolean.TRUE : (Object) (id.get(k) + "-changed"));
            assertNotEquals(fp, Issue.passportFingerprint(c), k);
            c.remove(k);
            assertNotEquals(fp, Issue.passportFingerprint(c), k);
        }
        Map<String, Object> extra = new LinkedHashMap<>(id);
        extra.put("issued_at", NOW + 1);
        assertEquals(fp, Issue.passportFingerprint(extra));
        assertEquals(fp, Issue.issuePassport(id).get("id"));
    }

    @Test void signPassportRefusalsAndTimes() {
        Map<String, Object> p = Issue.issuePassport(identity(false));
        Map<String, Object> forged = new LinkedHashMap<>(p);
        forged.put("id", D32);
        iae("signPassport: passport.id is not the fingerprint of its identity (use issuePassport)", () -> Issue.signPassport(forged, P, ME.id(), NOW, null, NOW + 10, null));
        Map<String, Object> hw = Issue.issuePassport(identity(true));
        iae("signPassport: hardware_rooted requires attestation evidence (fail closed)", () -> Issue.signPassport(hw, P, ME.id(), NOW, null, NOW + 10, null));
        assertEquals(NOW, num(Issue.signPassport(hw, P, ME.id(), NOW, null, NOW + 10, Issue.obj("kind", "tdx")).get("iat")));

        iae("signPassport: exp must be after nbf", () -> Issue.signPassport(p, P, ME.id(), NOW, null, NOW, null));
        iae("signPassport: exp must be after nbf", () -> Issue.signPassport(p, P, ME.id(), NOW, null, NOW - 1, null));
        iae("signPassport: exp must be after nbf", () -> Issue.signPassport(p, P, ME.id(), NOW, NOW + 50, NOW + 50, null));
        Map<String, Object> a = Issue.signPassport(p, P, ME.id(), NOW, null, NOW + 1, null);
        assertEquals(NOW, num(a.get("nbf")));
        assertEquals(NOW + 1, num(a.get("exp")));
        assertTrue(a.get("iat") instanceof Json.Num);
        assertFalse(a.containsKey("evidence"));
        Map<String, Object> b = Issue.signPassport(p, P, ME.id(), NOW, NOW + 50, NOW + 51, null);
        assertEquals(NOW + 50, num(b.get("nbf")));
        assertEquals(NOW, num(b.get("iat")));
    }

    @Test void signPassportEvidenceAndSuites() {
        Map<String, Object> p = Issue.issuePassport(identity(true));
        Map<String, Object> ev = Issue.obj("kind", "tdx");
        Map<String, Object> s = Issue.signPassport(p, P, ME.id(), NOW, null, NOW + 10, ev);
        assertEquals(NOW, num(m(s.get("evidence")).get("at")));
        assertEquals("tdx", m(s.get("evidence")).get("kind"));
        assertFalse(ev.containsKey("at"));
        Map<String, Object> ev2 = Issue.obj("kind", "tdx", "at", 5L);
        Map<String, Object> s2 = Issue.signPassport(p, P, ME.id(), NOW, null, NOW + 10, ev2);
        assertEquals(5L, num(m(s2.get("evidence")).get("at")));
        assertFalse(s2.containsKey("alg"));
        assertFalse(s2.containsKey("pq_pk"));
        assertFalse(s2.containsKey("pq_sig"));
        assertEquals(P.id(), s2.get("iss"));
        assertEquals(ME.id(), s2.get("sub"));
        assertEquals(Issue.PASSPORT_VERSION_TYPE, s2.get("typ"));

        Keys.SuiteKey hybrid = Keys.suite("hybrid-ed25519-ml-dsa-65", Keys.edFromSeed(fill(18)), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(19)));
        Map<String, Object> h = Issue.signPassport(p, hybrid, ME.id(), NOW, null, NOW + 10, ev);
        assertEquals("hybrid-ed25519-ml-dsa-65", h.get("alg"));
        assertEquals(hybrid.pqPk(), h.get("pq_pk"));
        assertTrue(h.get("pq_sig") instanceof String);
        assertNotEquals(h.get("sig"), h.get("pq_sig"));
        Keys.SuiteKey pure = Keys.suite("ml-dsa-65", Keys.edFromSeed(fill(18)), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(19)));
        Map<String, Object> pr = Issue.signPassport(p, pure, ME.id(), NOW, null, NOW + 10, ev);
        assertEquals("ml-dsa-65", pr.get("alg"));
        assertEquals(pure.pqPk(), pr.get("pq_pk"));
        assertFalse(pr.containsKey("pq_sig"));
    }

    @Test void freshAtIsNormalized() {
        Keys.EdKey rs = Keys.edFromSeed(fill(20));
        Map<String, Object> st = Issue.obj("revocation_epoch", 1L, "ledger_tree_size", 2L, "budget_version", 3L, "policy_revision", 4L, "policy_digest", D32);
        Map<String, Object> f = Issue.signFreshAt(rs, "ins_x", st, NOW);
        assertTrue(f.get("issued_at") instanceof Json.Num);
        assertTrue(f.get("revocation_epoch") instanceof Json.Num);
        assertEquals(NOW, num(f.get("issued_at")));
        assertEquals(rs.id(), f.get("signer"));
    }
}
