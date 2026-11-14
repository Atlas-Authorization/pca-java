package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs one case of the shared producer vectors (the conformance files {@code producer-vectors.json} and
 * {@code producer-pq-vectors.json}) through this SDK's producers and returns the artifact in the shape of the case's
 * {@code expect}. A refusal throws (its message is the reference's); an op this SDK does not produce throws
 * {@code unsupported_op: <op>} and a suite it cannot sign throws {@code unsupported_suite: <alg>}. Shared by the producer tests
 * and the cross-language driver, so both run exactly the same code.
 */
public final class ProducerOps {
    private final Map<String, Object> keys, pqKeys;
    private final Map<String, Keys.PqKey> pqCache = new HashMap<>();

    /** {@code keys}: name to {@code {seed, public}} (Ed25519); {@code pqKeys}: name to {@code {family, seed}} (may be null). */
    public ProducerOps(Map<String, Object> keys, Map<String, Object> pqKeys) {
        this.keys = keys == null ? new HashMap<String, Object>() : keys;
        this.pqKeys = pqKeys == null ? new HashMap<String, Object>() : pqKeys;
    }

    private static Map<String, Object> m(Object o) { return Pca.asMap(o); }
    private static List<Object> l(Object o) { return Pca.asList(o); }
    private static String s(Object o) { return (String) o; }
    private static long n(Object o) { return Json.asLong(o); }
    private static Map<String, Object> obj(Object... kv) { return Issue.obj(kv); }
    private static Map<String, Object> mOrNull(Map<String, Object> a, String k) { return a.get(k) == null ? null : m(a.get(k)); }

    private static byte[] b64(Object v) {
        byte[] b = Pca.decodeB64uStrict(v, -1);
        if (b == null) throw new IllegalArgumentException("not canonical base64url");
        return b;
    }

    Keys.EdKey ed(Object name) {
        Object e = keys.get(s(name));
        if (e == null) throw new IllegalArgumentException("unknown key '" + name + "'");
        return Keys.edFromSeed(b64(m(e).get("seed")));
    }

    Keys.SuiteKey edSuite(Object name) { return Keys.ed25519(ed(name)); }

    /** The wire's lower-case family name as this SDK's primitive; a family it cannot sign is {@code unsupported_suite}. */
    static Pq.Prim prim(String family) {
        switch (family) {
            case "ml-dsa-65": return Pq.Prim.ML_DSA_65;
            case "ml-dsa-87": return Pq.Prim.ML_DSA_87;
            case "slh-dsa-sha2-128f": return Pq.Prim.SLH_DSA_SHA2_128F;
            case "slh-dsa-sha2-256s": return Pq.Prim.SLH_DSA_SHA2_256S;
            default: throw new IllegalArgumentException(Pq.UNSUPPORTED_SUITE + ": " + family);
        }
    }

    Keys.PqKey pq(Object name) {
        if (name == null) return null;
        Keys.PqKey k = pqCache.get(s(name));
        if (k == null) {
            Object raw = pqKeys.get(s(name));
            if (raw == null) throw new IllegalArgumentException("unknown post-quantum key '" + name + "'");
            Map<String, Object> e = m(raw);
            k = Keys.pqFromSeed(prim(s(e.get("family"))), b64(e.get("seed")));
            pqCache.put(s(name), k);
        }
        return k;
    }

    /** The suite key of a PQ-vector case: {@code alg} with the named Ed25519 key (when given) and PQ key (when given). */
    Keys.SuiteKey suite(Map<String, Object> a, String edMember) {
        String alg = s(a.get("alg"));
        if (alg == null || "ed25519".equals(alg)) return edSuite(a.get(edMember));
        if (!Pq.SUITES.containsKey(alg)) throw new IllegalArgumentException(Pq.refusal(alg));
        return Keys.suite(alg, a.get(edMember) == null ? null : ed(a.get(edMember)), pq(a.get("pq")));
    }

    /** Run {@code op} on {@code args}. */
    public Object run(String op, Map<String, Object> a) {
        switch (op) {
            // ---- producer-vectors.json (Ed25519) -----------------------------------------------------------------------------
            case "ed25519_sign": {
                Keys.EdKey k = Keys.edFromSeed(b64(a.get("seed")));
                return obj("public", k.id(), "sig", Pca.b64(k.sign(s(a.get("message_utf8")).getBytes(StandardCharsets.UTF_8))));
            }
            case "goal_commit": return obj("commit", Issue.goalCommit(s(a.get("goal")), s(a.get("salt"))));
            case "params_digest": return obj("digest", Pca.paramsDigest(a.get("params")));
            case "plan_commit": {
                List<Map<String, Object>> nodes = new ArrayList<>();
                for (Object x : l(a.get("nodes"))) nodes.add(m(x));
                Issue.Plan p = Issue.commitPlan(nodes);
                Map<String, Object> proofs = new LinkedHashMap<>();
                for (Map<String, Object> x : nodes) proofs.put(s(x.get("id")), p.proofFor(s(x.get("id"))));
                return obj("root", p.root, "proofs", proofs);
            }
            case "mint_grant": {
                Issue.Grant g = Issue.mintGrant(edSuite(a.get("principal")), ed(a.get("holder")).id(), null, m(a.get("envelope")), s(a.get("goal")), s(a.get("salt")));
                return obj("grant", g.grant, "goal_commit", g.goalCommit, "goal_salt", g.goalSalt);
            }
            case "delegate": {
                Map<String, Object> parent = m(a.get("parent"));
                String to = a.get("to_holder") == null ? s(parent.get("holder")) : ed(a.get("to_holder")).id();
                return Issue.delegate(parent, to, l(a.get("added_caveats")), edSuite(a.get("signer")), null);
            }
            case "act": {
                Issue.ActSpec sp = new Issue.ActSpec();
                sp.grant = m(a.get("grant"));
                sp.chain = l(a.get("chain"));
                List<Map<String, Object>> nodes = new ArrayList<>();
                for (Object x : l(a.get("plan"))) nodes.add(m(x));
                sp.plan = Issue.commitPlan(nodes);
                sp.nodeId = s(a.get("node_id"));
                sp.params = mOrNull(a, "params");
                sp.counter = n(a.get("counter"));
                sp.signer = edSuite(a.get("signer"));
                sp.aud = s(a.get("aud"));
                sp.iat = n(a.get("iat"));
                sp.exp = n(a.get("exp"));
                sp.nonce = s(a.get("nonce"));
                sp.caution = a.get("caution");
                sp.rationaleCommitment = s(a.get("rationale_commitment"));
                sp.toolBinding = s(a.get("tool_binding"));
                sp.freshAt = mOrNull(a, "fresh_at");
                Map<String, Object> p = Issue.buildPCActn(sp);
                return obj("pcactn", p, "threshold_message", Pca.b64(Pca.thresholdMessage(p)), "header", Issue.header(p));
            }
            case "fresh_at": return Issue.signFreshAt(ed(a.get("signer")), s(a.get("scope")), m(a.get("state")), n(a.get("issued_at")));
            case "escalation_digests":
                return obj("policy_digest", Escalation.policyDigest(m(a.get("grant"))), "action_digest", Escalation.actionDigest(m(a.get("pcactn"))),
                    "history_head", Escalation.historyHead(a.get("last_counter") == null ? null : n(a.get("last_counter"))));
            case "sign_escalation_answer": return Issue.signEscalationAnswer(m(a.get("body")), edSuite(a.get("signer")));
            case "sign_discharge": return Issue.signDischarge(m(a.get("body")), edSuite(a.get("signer")));
            case "discharge_digest": return obj("digest", CaveatLang.dischargeDigest(a.get("discharge")));
            case "sign_narrow": return Issue.signNarrow(m(a.get("body")), edSuite(a.get("signer")));
            case "sign_passport": {
                Map<String, Object> pp = Issue.issuePassport(m(a.get("identity")));
                Map<String, Object> signed = Issue.signPassport(pp, edSuite(a.get("issuer")), ed(a.get("subject")).id(), n(m(a.get("identity")).get("issued_at")),
                    null, n(a.get("exp")), null);
                return obj("passport", pp, "signed", signed);
            }
            case "sign_workflow": return Issue.signWorkflow(ed(a.get("signer")), m(a.get("body")));
            case "sign_step_receipt":
                return Issue.signStepReceipt(ed(a.get("signer")), m(a.get("workflow")), s(a.get("step")), s(a.get("outcome")), s(a.get("params_digest")),
                    m(a.get("outputs")), n(a.get("issued_at")), mOrNull(a, "prev"));
            case "sign_read_grant": return Issue.signReadGrant(ed(a.get("signer")), m(a.get("body")));
            case "sign_aggregate_grant": return Issue.signAggregateGrant(ed(a.get("signer")), m(a.get("body")));
            case "sign_revocation_epoch": return SignersMore.signRevocationEpoch(edSuite(a.get("signer")), m(a.get("body")));
            case "sign_undo_token": return Undo.signToken(m(a.get("record")), ed(a.get("signer")));
            case "sign_undo_receipt": return Undo.signReceipt(m(a.get("body")), ed(a.get("signer")));
            case "sign_contract": return Contracts.signContract(m(a.get("contract")), ed(a.get("signer")).seed);
            case "sign_contract_reset": return obj("sig", ContractEnforcer.signReset(ed(a.get("signer")).seed, s(a.get("contract_id")), n(a.get("seq"))));
            case "sign_constitution": return SignersMore.signConstitution(m(a.get("constitution")), ed(a.get("signer")));
            case "sign_safety_evidence": {
                Keys.EdKey k = ed(a.get("signer"));
                return Prohibitions.signSafetyEvidence(a.get("evidence"), k.seed, k.id());
            }
            case "sign_threshold_share":
                return SignersMore.signThresholdShare(s(a.get("role")), edSuite(a.get("signer")), b64(a.get("message")), l(a.get("signer_set")), (int) n(a.get("t")));
            case "sign_prepared_share": return SignersMore.signPreparedShare(s(a.get("role")), edSuite(a.get("signer")), b64(a.get("prepared")));
            case "sign_pq_binding": return SignersMore.signPqBinding(ed(a.get("signer")), s(a.get("pq_pk")), n(a.get("epoch")), s(a.get("aud")));
            case "sign_caution": return SignersMore.signCaution(m(a.get("body")), ed(a.get("signer")));
            case "sign_heartbeat": return SignersMore.signHeartbeat(m(a.get("body")), ed(a.get("signer")));
            case "prov_recorder": return provRecorder(a);
            case "sign_mesh_action": return obj("sig", SignersMore.signMeshAction(l(a.get("chain")), m(a.get("action")), ed(a.get("signer"))));
            case "sign_session_root": return SignersMore.signSessionRoot(m(a.get("body")), edSuite(a.get("signer")));
            case "mint_session_grant": {
                SignersMore.SessionGrant g = SignersMore.mintSessionGrant(edSuite(a.get("principal")), ed(a.get("holder")).id(), s(a.get("session")),
                    n(a.get("seq")), s(a.get("root")), s(a.get("prev")), s(a.get("map_digest")), s(a.get("map_form")), l(a.get("predicates")),
                    a.get("caveats") == null ? null : l(a.get("caveats")), null, null, s(a.get("salt")), null);
                return obj("grant", g.grant, "goal_salt", g.goalSalt);
            }
            case "sign_intent_required": return SignersMore.signIntentRequired(m(a.get("body")), s(a.get("kid")), edSuite(a.get("signer")));
            case "sign_action_schema": return SignersMore.signActionSchema(m(a.get("doc")), s(a.get("kid")), edSuite(a.get("signer")));
            case "sign_labels": return SignersMore.signLabels(m(a.get("body")), edSuite(a.get("signer")));
            case "sign_fact": return SignersMore.signFact(m(a.get("body")), edSuite(a.get("signer")));
            case "sign_offer_set": return SignersMore.signOfferSet(m(a.get("body")), edSuite(a.get("signer")));
            case "sign_progress_step": return SignersMore.signProgressStep(m(a.get("step")), ed(a.get("signer")));
            case "sign_read_receipt":
                return SignersMore.signReadReceipt(ed(a.get("signer")), m(a.get("grant")), s(a.get("verb")), s(a.get("resource")), s(a.get("purpose")),
                    m(a.get("fields")), l(a.get("labels")), n(a.get("issued_at")), mOrNull(a, "prev"));
            case "sign_template": return SignersMore.signTemplate(m(a.get("def")), ed(a.get("signer")));
            case "sign_tighten": return SignersMore.signTighten(m(a.get("overlay")), ed(a.get("signer")));
            case "parse_limit": return Facade.parseLimit(a.get("limit")).toJson();
            case "compile_policy":
                return Facade.compilePolicy(m(a.get("permissions")), mOrNull(a, "limits"), null, s(a.get("budget_model")), null, n(a.get("now"))).toJson();
            case "facade_act": return facadeAct(a);
            // ---- producer-pq-vectors.json (every suite) ----------------------------------------------------------------------
            case "pq_keygen": return obj("public", Keys.pqFromSeed(prim(s(a.get("family"))), b64(a.get("seed"))).pkB64u());
            case "suite_sign": {
                String[] sg = suite(a, "ed").sign(s(a.get("message_utf8")).getBytes(StandardCharsets.UTF_8));
                Map<String, Object> o = obj("sig", sg[0]);
                if (sg[1] != null) o.put("pq_sig", sg[1]);
                return o;
            }
            case "mint_root_suite":
                return Issue.mintRoot(suite(a, "principal"), ed(a.get("holder")).id(), a.get("holder_pq") == null ? null : pq(a.get("holder_pq")).pkB64u(), l(a.get("caveats")));
            case "delegate_suite": {
                Map<String, Object> parent = m(a.get("parent"));
                String to = a.get("to_holder") == null ? s(parent.get("holder")) : ed(a.get("to_holder")).id();
                return Issue.delegate(parent, to, l(a.get("added_caveats")), suite(a, "signer"), a.get("holder_pq") == null ? null : pq(a.get("holder_pq")).pkB64u());
            }
            case "sign_pcactn_suite": return obj("pcactn", Issue.signPCActn(m(a.get("body")), suite(a, "signer")));
            case "sign_artifact_suite": {
                Keys.SuiteKey k = suite(a, "signer");
                if ("escalation_answer".equals(a.get("kind"))) return Issue.signEscalationAnswer(m(a.get("body")), k);
                if ("revocation_epoch".equals(a.get("kind"))) return SignersMore.signRevocationEpoch(k, m(a.get("body")));
                throw new IllegalArgumentException("unsupported_op: sign_artifact_suite/" + a.get("kind"));
            }
            default: throw new IllegalArgumentException("unsupported_op: " + op);
        }
    }

    private Map<String, Object> provRecorder(Map<String, Object> a) {
        Iterator<Object> clock = l(a.get("clock")).iterator();
        ArgProvenance.Recorder r = new ArgProvenance.Recorder(s(a.get("mediator")), s(a.get("kid")), edSuite(a.get("key")), s(a.get("session")), () -> n(clock.next()));
        List<Object> outs = new ArrayList<>();
        for (Object stO : l(a.get("steps"))) {
            Map<String, Object> st = m(stO);
            switch (s(st.get("kind"))) {
                case "principal": outs.add(r.principal(s(st.get("text")))); break;
                case "tool": outs.add(r.tool(s(st.get("name")), st.get("output"))); break;
                case "web": outs.add(r.web(s(st.get("url")), st.get("content"))); break;
                case "retrieval": outs.add(r.retrieval(s(st.get("source")), st.get("content"))); break;
                default: {
                    Map<String, Object> op = m(st.get("op"));
                    outs.add(r.forAction(new Authorize.Operation(s(op.get("verb")), s(op.get("resource")), m(op.get("params")))));
                }
            }
        }
        return obj("pin", new LinkedHashMap<>(r.pin()), "receipts", new ArrayList<>(outs.subList(0, outs.size() - 1)), "bundle", outs.get(outs.size() - 1));
    }

    private Map<String, Object> facadeAct(Map<String, Object> a) {
        long now = n(a.get("now"));
        ArgProvenance.Recorder rec = new ArgProvenance.Recorder("agent-harness", "k1", edSuite(a.get("recorder_key")), s(a.get("session")), () -> now);
        Facade.AgentOptions o = new Facade.AgentOptions(edSuite(a.get("principal")), s(a.get("goal")), m(a.get("permissions")))
            .limits(mOrNull(a, "limits")).holder(edSuite(a.get("holder"))).aud(s(a.get("aud"))).now(now).goalSalt(s(a.get("goal_salt"))).provenance(rec);
        Facade.Handle base = Agent.fromPrincipal(o);
        if (a.get("principal_messages") != null) for (Object t : l(a.get("principal_messages"))) base.provenance.principal(s(t));
        Facade.Handle h = base;
        if (a.get("sub_agent") != null) {
            Map<String, Object> sa = m(a.get("sub_agent"));
            h = base.subAgent(edSuite(sa.get("holder")), l(sa.get("added_caveats")));
        }
        Map<String, Object> act = m(a.get("act"));
        Facade.ActOptions ao = new Facade.ActOptions();
        ao.counter = act.get("counter") == null ? null : n(act.get("counter"));
        ao.now = act.get("now") == null ? null : n(act.get("now"));
        ao.nonce = s(act.get("nonce"));
        Facade.ActResult r = h.act(s(act.get("verb")), s(act.get("resource")), mOrNull(act, "params"), ao);
        return obj("grant", base.grant, "goal_commit", m(l(base.grant.get("caveats")).get(0)).get("goal_commit"), "chain", h.chain, "pcactn", r.pcactn,
            "encoded", r.encoded, "provenance", r.provenance);
    }
}
