package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Replays producer-vectors.json: every producer must reproduce the TypeScript reference's output byte for byte (Ed25519 is deterministic). */
public class ProducerVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("producer-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static Keys.EdKey key(String name) { return Keys.edFromSeed(Pca.decodeB64uStrict(m(m(DOC.get("keys")).get(name)).get("seed"), 32)); }
    static Keys.SuiteKey suite(String name) { return Keys.ed25519(key(name)); }
    static String canon(Object o) { return Json.canonicalize(o); }
    static Map<String, Object> obj(Object... kv) { return Issue.obj(kv); }

    static Object run(String op, Map<String, Object> a) {
        switch (op) {
            case "ed25519_sign": {
                Keys.EdKey k = Keys.edFromSeed(Pca.decodeB64uStrict(a.get("seed"), 32));
                return obj("public", k.id(), "sig", Pca.b64(k.sign(((String) a.get("message_utf8")).getBytes(java.nio.charset.StandardCharsets.UTF_8))));
            }
            case "goal_commit": return obj("commit", Issue.goalCommit((String) a.get("goal"), (String) a.get("salt")));
            case "params_digest": return obj("digest", Pca.paramsDigest(a.get("params")));
            case "plan_commit": {
                List<Map<String, Object>> nodes = new ArrayList<>();
                for (Object n : l(a.get("nodes"))) nodes.add(m(n));
                Issue.Plan p = Issue.commitPlan(nodes);
                Map<String, Object> proofs = new java.util.LinkedHashMap<>();
                for (Map<String, Object> n : nodes) proofs.put((String) n.get("id"), p.proofFor((String) n.get("id")));
                return obj("root", p.root, "proofs", proofs);
            }
            case "mint_grant": {
                Issue.Grant g = Issue.mintGrant(suite((String) a.get("principal")), key((String) a.get("holder")).id(), null, m(a.get("envelope")), (String) a.get("goal"), (String) a.get("salt"));
                return obj("grant", g.grant, "goal_commit", g.goalCommit, "goal_salt", g.goalSalt);
            }
            case "delegate": {
                Map<String, Object> parent = m(a.get("parent"));
                String to = a.get("to_holder") == null ? (String) parent.get("holder") : key((String) a.get("to_holder")).id();
                return Issue.delegate(parent, to, l(a.get("added_caveats")), suite((String) a.get("signer")), null);
            }
            case "act": {
                Issue.ActSpec s = new Issue.ActSpec();
                s.grant = m(a.get("grant"));
                s.chain = l(a.get("chain"));
                List<Map<String, Object>> nodes = new ArrayList<>();
                for (Object n : l(a.get("plan"))) nodes.add(m(n));
                s.plan = Issue.commitPlan(nodes);
                s.nodeId = (String) a.get("node_id");
                s.params = a.containsKey("params") ? m(a.get("params")) : null;
                s.counter = Json.asLong(a.get("counter"));
                s.signer = suite((String) a.get("signer"));
                s.aud = (String) a.get("aud");
                s.iat = Json.asLong(a.get("iat"));
                s.exp = Json.asLong(a.get("exp"));
                s.nonce = (String) a.get("nonce");
                s.caution = a.get("caution");
                s.rationaleCommitment = (String) a.get("rationale_commitment");
                s.toolBinding = (String) a.get("tool_binding");
                s.freshAt = a.containsKey("fresh_at") ? m(a.get("fresh_at")) : null;
                Map<String, Object> p = Issue.buildPCActn(s);
                return obj("pcactn", p, "threshold_message", Pca.b64(Pca.thresholdMessage(p)), "header", Issue.header(p));
            }
            case "fresh_at": return Issue.signFreshAt(key((String) a.get("signer")), (String) a.get("scope"), m(a.get("state")), Json.asLong(a.get("issued_at")));
            case "escalation_digests": {
                Long last = a.get("last_counter") == null ? null : Json.asLong(a.get("last_counter"));
                return obj("policy_digest", Escalation.policyDigest(m(a.get("grant"))), "action_digest", Escalation.actionDigest(m(a.get("pcactn"))), "history_head", Escalation.historyHead(last));
            }
            case "sign_escalation_answer": return Issue.signEscalationAnswer(m(a.get("body")), suite((String) a.get("signer")));
            case "sign_discharge": return Issue.signDischarge(m(a.get("body")), suite((String) a.get("signer")));
            case "discharge_digest": return obj("digest", CaveatLang.dischargeDigest(a.get("discharge")));
            case "sign_narrow": return Issue.signNarrow(m(a.get("body")), suite((String) a.get("signer")));
            case "sign_passport": {
                Map<String, Object> pp = Issue.issuePassport(m(a.get("identity")));
                Map<String, Object> signed = Issue.signPassport(pp, suite((String) a.get("issuer")), key((String) a.get("subject")).id(),
                    Json.asLong(m(a.get("identity")).get("issued_at")), null, Json.asLong(a.get("exp")), null);
                return obj("passport", pp, "signed", signed);
            }
            case "sign_workflow": return Issue.signWorkflow(key((String) a.get("signer")), m(a.get("body")));
            case "sign_step_receipt": return Issue.signStepReceipt(key((String) a.get("signer")), m(a.get("workflow")), (String) a.get("step"), (String) a.get("outcome"),
                (String) a.get("params_digest"), m(a.get("outputs")), Json.asLong(a.get("issued_at")), a.get("prev") == null ? null : m(a.get("prev")));
            case "sign_read_grant": return Issue.signReadGrant(key((String) a.get("signer")), m(a.get("body")));
            case "sign_aggregate_grant": return Issue.signAggregateGrant(key((String) a.get("signer")), m(a.get("body")));
            default: throw new IllegalStateException("unknown op " + op);
        }
    }

    @Test void everyCaseIsReproducedByteForByte() {
        List<Object> cases = l(DOC.get("cases"));
        assertTrue(cases.size() >= 30, "the corpus shrank: " + cases.size());
        for (Object c : cases) {
            Map<String, Object> v = m(c);
            Object got = run((String) v.get("op"), m(v.get("args")));
            assertEquals(canon(v.get("expect")), canon(got), v.get("name").toString());
        }
    }

    /** Cross-verification: the TS-produced PCActns pass THIS SDK's verifier. */
    @Test void referenceActionsVerify() {
        int n = 0;
        for (Object c : l(DOC.get("cases"))) {
            Map<String, Object> v = m(c);
            if (!"act".equals(v.get("op")) || m(v.get("args")).containsKey("fresh_at")) continue; // fresh_at is refused without a fresh_at policy (fail closed)
            Map<String, Object> a = m(v.get("args"));
            Map<String, Object> pcactn = m(m(v.get("expect")).get("pcactn"));
            Pca.Verdict d = Pca.verifyPcactn(pcactn, m(a.get("grant")), Json.asLong(a.get("iat")) + 1000, (String) a.get("aud"));
            assertTrue(d.allow, v.get("name") + ": " + d.reason);
            n++;
        }
        assertTrue(n >= 4);
    }

    @Test void seededMlDsaKeysAreReproducibleAndKeepTheirSeed() {
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte) i;
        Keys.PqKey a = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed), b = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed);
        assertEquals(a.pkB64u(), b.pkB64u());
        seed[0] ^= 1;
        assertTrue(!a.pkB64u().equals(Keys.pqFromSeed(Pq.Prim.ML_DSA_65, seed).pkB64u()));
    }

    /** FIPS 204 KeyGen_internal step 1: (rho, rho', K) = SHAKE256(xi || k || l, 128 bytes), and pk starts with rho. Proves BouncyCastle used the seed as xi. */
    @Test void seededMlDsaKeysFollowFips204KeyGenInternal() {
        Object[][] levels = {{Pq.Prim.ML_DSA_65, 6, 5}, {Pq.Prim.ML_DSA_87, 8, 7}};
        for (Object[] lv : levels) {
            byte[] xi = new byte[32];
            for (int i = 0; i < 32; i++) xi[i] = (byte) (i * 7 + 1);
            org.bouncycastle.crypto.digests.SHAKEDigest d = new org.bouncycastle.crypto.digests.SHAKEDigest(256);
            d.update(xi, 0, 32);
            d.update((byte) (int) lv[1]);
            d.update((byte) (int) lv[2]);
            byte[] out = new byte[128];
            d.doFinal(out, 0, 128);
            Keys.PqKey k = Keys.pqFromSeed((Pq.Prim) lv[0], xi);
            assertArrayEquals(java.util.Arrays.copyOfRange(out, 0, 32), java.util.Arrays.copyOfRange(k.pk, 0, 32), lv[0] + ": rho");
        }
    }
}
