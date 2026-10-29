package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The producer side of PCA: everything an agent or an issuer needs to MAKE a proof, with the same wire as the TypeScript
 * reference ({@code @atlasauth/pca}). Root grants, delegation, plans, PCActns, and the signed artifacts (discharges, narrow
 * blocks, escalation answers, passports, workflow commitments and step receipts, read grants).
 *
 * <p>Values are the verifier's JSON model: {@code Map<String,Object>} / {@code List<Object>} / {@code String} / {@code Boolean} /
 * {@code Long} / {@code Integer} / {@code null}; a fractional number is a {@link Json.Num} (for example {@code new Json.Num("0.5")}).
 * Everything signed passes through the STRICT canonical form, so an out-of-profile value throws instead of producing a proof no
 * verifier would accept.
 */
public final class Issue {
    private Issue() {}

    static final SecureRandom RNG = new SecureRandom();
    public static final long DEFAULT_TTL_MS = 20L * 60_000L;
    public static final String ENVELOPE_CAVEAT = "envelope";
    public static final String PASSPORT_VERSION_TYPE = "atlas-pca/passport";

    /** The reference default risk policy (the same numbers as {@code DEFAULT_RISK_POLICY} in the TypeScript package). */
    public static Map<String, Object> defaultRiskPolicy() {
        return obj("weights", obj("alpha", new Json.Num("0.25"), "beta", new Json.Num("0.2"), "gamma", new Json.Num("0.2"),
            "delta", new Json.Num("0.2"), "epsilon", new Json.Num("0.1"), "zeta", new Json.Num("0.05")),
            "theta1", new Json.Num("0.25"), "theta2", new Json.Num("0.6"), "kappa", 1L, "lambda", new Json.Num("0.0005"), "rho", new Json.Num("0.5"), "bMax", 1L);
    }

    /** Ordered map from alternating keys and values. */
    public static Map<String, Object> obj(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }

    /** A deep copy through the strict canonical form (throws on anything out of profile); numbers come back as {@link Json.Num}. */
    @SuppressWarnings("unchecked")
    public static <T> T norm(T v) { return (T) Json.parse(Json.canonicalizeStrict(v)); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    /** {@code n} random bytes, b64u. */
    public static String randomB64u(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return Pca.b64(b);
    }

    private static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    // ---- capability chain ----------------------------------------------------------------------------------------

    private static Map<String, Object> seal(String issuer, String holder, List<Object> caveats, String parent, String holderPq, Keys.SuiteKey signer) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("issuer", issuer);
        body.put("holder", holder);
        body.put("caveats", caveats);
        body.put("parent", parent);
        if (holderPq != null) body.put("holder_pq", holderPq);
        String pqPk = signer.pqPk();
        if (!"ed25519".equals(signer.alg)) {
            body.put("alg", signer.alg);
            body.put("pq_pk", pqPk);
        }
        String digest = Pca.hashCanonical(body);
        String[] sg = signer.sign(Pca.concat(Pca.CAP_DOMAIN, Pca.decodeB64uStrict(digest, 32)));
        Map<String, Object> cap = new LinkedHashMap<>();
        cap.put("id", digest);
        cap.put("issuer", issuer);
        cap.put("holder", holder);
        cap.put("caveats", caveats);
        cap.put("body_digest", digest);
        cap.put("sig", sg[0]);
        if (parent != null) cap.put("parent", parent);
        if (holderPq != null) cap.put("holder_pq", holderPq);
        if (!"ed25519".equals(signer.alg)) {
            cap.put("alg", signer.alg);
            cap.put("pq_pk", pqPk);
            if (sg[1] != null) cap.put("pq_sig", sg[1]);
        }
        return cap;
    }

    private static String commitment(String holderPqPk) { return holderPqPk == null ? null : Pca.holderPqCommitment(holderPqPk); }

    /**
     * A root capability signed by the principal. {@code holderPqPk} (b64u, optional) is the holder's post-quantum public key, committed
     * into the body as {@code holder_pq}: required for a hybrid / pure-PQ agent.
     */
    public static Map<String, Object> mintRoot(Keys.SuiteKey principal, String holder, String holderPqPk, List<Object> caveats) {
        if (principal.ed == null) throw new IllegalArgumentException("a root issuer needs an Ed25519 identity");
        return seal(principal.ed.id(), holder, Issue.<List<Object>>norm(caveats), null, commitment(holderPqPk), principal);
    }

    public static final class Grant {
        public final Map<String, Object> grant;
        public final String goalCommit;
        public final String goalSalt;
        Grant(Map<String, Object> grant, String goalCommit, String goalSalt) { this.grant = grant; this.goalCommit = goalCommit; this.goalSalt = goalSalt; }
    }

    /** The salted goal commitment: {@code b64u(sha256(canonical({d, goal, salt})))}. */
    public static String goalCommit(String goal, String salt) {
        return Pca.hashCanonical(obj("d", Pca.INTENT_GOAL_COMMIT_DOMAIN, "goal", goal, "salt", salt));
    }

    /**
     * A root intent grant: a root capability whose first caveat is the {@code envelope}. {@code envelope} needs {@code predicates},
     * {@code caveats} and {@code risk_policy}; {@code agent_binding} defaults to {@code {}} and {@code objective_risk}, {@code progress},
     * {@code units}, {@code tighten}, {@code model_polarity}, {@code template_ref} and {@code actions} (action-definition pins) pass through.
     * Only the salted hash of {@code goal} goes in the grant. For an approved goal use {@code goal = Pca.intentGoalV3(ref)}.
     */
    public static Grant mintGrant(Keys.SuiteKey principal, String holder, String holderPqPk, Map<String, Object> envelope, String goal, String salt) {
        if (goal == null || goal.isEmpty()) throw new IllegalArgumentException("mintGrant: goal required");
        for (String k : new String[] {"predicates", "caveats", "risk_policy"})
            if (envelope.get(k) == null) throw new IllegalArgumentException("mintGrant: envelope." + k + " is required");
        String s = salt != null ? salt : randomB64u(16);
        String commit = goalCommit(goal, s);
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("type", ENVELOPE_CAVEAT);
        env.put("goal_commit", commit);
        for (Map.Entry<String, Object> e : envelope.entrySet()) if (!e.getKey().equals("goal_commit") && !e.getKey().equals("type")) env.put(e.getKey(), e.getValue());
        if (!env.containsKey("agent_binding")) env.put("agent_binding", new LinkedHashMap<String, Object>());
        List<Object> cavs = new ArrayList<>();
        cavs.add(env);
        return new Grant(mintRoot(principal, holder, holderPqPk, cavs), commit, s);
    }

    /** Child capability: caveats are the parent's followed by {@code added} (append-only); signed by the parent's holder. */
    public static Map<String, Object> delegate(Map<String, Object> parent, String toHolder, List<Object> added, Keys.SuiteKey signer, String holderPqPk) {
        List<Object> cav = new ArrayList<>(norm(Pca.asList(parent.get("caveats"))));
        cav.addAll(norm(added == null ? new ArrayList<Object>() : added));
        String hp = holderPqPk != null ? commitment(holderPqPk) : toHolder.equals(parent.get("holder")) ? (String) parent.get("holder_pq") : null;
        return seal((String) parent.get("holder"), toHolder, cav, Pca.capHash(parent), hp, signer);
    }

    /** Like {@link #delegate} with the holder unchanged: only narrows. */
    public static Map<String, Object> attenuate(Map<String, Object> parent, List<Object> added, Keys.SuiteKey signer) {
        return delegate(parent, (String) parent.get("holder"), added, signer, null);
    }

    // ---- plans ----------------------------------------------------------------------------------------------------

    public static final class Plan {
        public final String root;
        public final List<Map<String, Object>> nodes;
        private final List<byte[]> leaves = new ArrayList<>();
        Plan(String root, List<Map<String, Object>> nodes, List<byte[]> leaves) { this.root = root; this.nodes = nodes; this.leaves.addAll(leaves); }

        public Map<String, Object> proofFor(String nodeId) {
            int idx = -1;
            for (int i = 0; i < nodes.size(); i++) if (nodeId.equals(nodes.get(i).get("id"))) idx = i;
            if (idx < 0) throw new IllegalArgumentException("commitPlan: unknown node " + nodeId);
            List<Object> path = new ArrayList<>();
            prove(leaves, idx, path);
            return obj("index", (long) idx, "size", (long) leaves.size(), "path", path);
        }

        private static void prove(List<byte[]> hs, int idx, List<Object> out) {
            if (hs.size() == 1) return;
            int k = Pca.split(hs.size());
            if (idx < k) {
                prove(hs.subList(0, k), idx, out);
                out.add(obj("side", "R", "hash", Pca.b64(Pca.build(hs.subList(k, hs.size())))));
            } else {
                prove(hs.subList(k, hs.size()), idx - k, out);
                out.add(obj("side", "L", "hash", Pca.b64(Pca.build(hs.subList(0, k)))));
            }
        }
    }

    /** Plan node leaf: {@code {id, verb, resource, params_digest?, reversibility_class?, pre?, post?}}. */
    public static Plan commitPlan(List<Map<String, Object>> nodes) {
        List<String> ids = new ArrayList<>();
        List<byte[]> leaves = new ArrayList<>();
        List<Map<String, Object>> copy = new ArrayList<>();
        for (Map<String, Object> n : nodes) {
            String id = (String) n.get("id");
            if (id == null || ids.contains(id)) throw new IllegalArgumentException("commitPlan: missing or duplicate node id " + id);
            ids.add(id);
            leaves.add(Pca.leafHash(Pca.planLeaf(id, n, Pca.conditionsDigest(n.get("pre"), n.get("post")))));
            copy.add(n);
        }
        if (leaves.isEmpty()) throw new IllegalArgumentException("commitPlan: empty plan");
        return new Plan(Pca.b64(Pca.build(leaves)), copy, leaves);
    }

    // ---- PCActn ---------------------------------------------------------------------------------------------------

    /** Inputs of {@link #buildPCActn}. Only {@code grant}, {@code chain}, {@code plan}, {@code nodeId}, {@code counter}, {@code signer} and {@code aud} are required. */
    public static final class ActSpec {
        public Map<String, Object> grant;
        public List<Object> chain;
        public Plan plan;
        public String nodeId;
        public Map<String, Object> params;
        public long counter;
        public Keys.SuiteKey signer;
        /** The resource server / Atlas instance this action is FOR. */
        public String aud;
        public Long iat, exp, ttlMs;
        public String nonce;
        /** A number in [0,1] (a {@link Json.Num} for a fraction): can only RAISE the verifier's risk. */
        public Object caution;
        public String rationaleCommitment, toolBinding;
        public Map<String, Object> progressStep, intent, intentSession, freshAt, provenance, attestation, freshness, riskClaim;
        public Object prohibitionEvidence;
    }

    private static void put(Map<String, Object> m, String k, Object v) { if (v != null) m.put(k, v); }

    public static Map<String, Object> buildPCActn(ActSpec s) {
        if (s.aud == null || s.aud.isEmpty()) throw new IllegalArgumentException("buildPCActn: aud (audience) is required");
        Map<String, Object> node = null;
        for (Map<String, Object> n : s.plan.nodes) if (s.nodeId.equals(n.get("id"))) node = n;
        if (node == null) throw new IllegalArgumentException("buildPCActn: unknown plan node " + s.nodeId);
        String digest = Pca.paramsDigest(s.params);
        if (node.get("params_digest") != null && !digest.equals(node.get("params_digest")))
            throw new IllegalArgumentException("buildPCActn: params do not match plan node " + s.nodeId + "'s params_digest");
        long iat = s.iat != null ? s.iat : System.currentTimeMillis();
        long exp = s.exp != null ? s.exp : iat + (s.ttlMs != null ? s.ttlMs : DEFAULT_TTL_MS);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ver", (long) Pca.WIRE_VERSION);
        body.put("action", obj("verb", node.get("verb"), "resource", node.get("resource"), "params_digest", digest,
            "reversibility_class", node.get("reversibility_class") != null ? node.get("reversibility_class") : Pca.DEFAULT_REV));
        body.put("grant_ref", s.grant.get("id"));
        body.put("cap_chain", s.chain);
        body.put("plan", obj("root", s.plan.root, "inclusion_proof", s.plan.proofFor(s.nodeId), "node_id", s.nodeId,
            "conditions_digest", Pca.conditionsDigest(node.get("pre"), node.get("post"))));
        body.put("attestation", s.attestation != null ? s.attestation
            : obj("quote_digest", "", "epoch", 0L, "model_id", "unattested", "measurement", "", "operator", "unattested"));
        body.put("provenance", s.provenance != null ? s.provenance : obj("causal_hash", "", "taint_level", 0L, "trusted_refs", new ArrayList<Object>()));
        body.put("freshness", s.freshness != null ? s.freshness : obj("beacon_ref", "", "epoch", 0L, "accumulator_witness", ""));
        body.put("counter", s.counter);
        body.put("risk_claim", s.riskClaim != null ? s.riskClaim : obj("r", 0L, "inputs", new LinkedHashMap<String, Object>()));
        body.put("aud", s.aud);
        body.put("iat", iat);
        body.put("exp", exp);
        put(body, "nonce", s.nonce);
        put(body, "caution", s.caution);
        put(body, "rationale_commitment", s.rationaleCommitment);
        put(body, "progress_step", s.progressStep);
        put(body, "prohibition_evidence", s.prohibitionEvidence);
        put(body, "tool_binding", s.toolBinding);
        put(body, "intent", s.intent);
        put(body, "intent_session", s.intentSession);
        put(body, "fresh_at", s.freshAt);
        if (!"ed25519".equals(s.signer.alg)) {
            body.put("alg", s.signer.alg);
            body.put("pq_pk", s.signer.pqPk());
        }
        String[] sg = s.signer.sign(Pca.thresholdMessage(body));
        body.put("sig", sg[0]);
        if (sg[1] != null) body.put("pq_sig", sg[1]);
        return body;
    }

    /** The lenient canonical JSON text of a PCActn (what is sent). */
    public static String encode(Map<String, Object> pcactn) { return Json.canonicalize(pcactn); }

    /** The {@code PCA-Action} header value: the unpadded base64url of the PCActn JSON. */
    public static String header(Map<String, Object> pcactn) { return Pca.b64(utf8(encode(pcactn))); }

    // ---- signed artifacts (discharge, narrow, escalation answer, ...) ---------------------------------------------

    /**
     * Sign an artifact body under a suite: the signature covers {@code utf8(domain) || strictCanonical(body)} where a non-default
     * suite adds {@code alg} and {@code pq_pk} to the SIGNED body; a hybrid also returns {@code pq_sig}.
     */
    public static Map<String, Object> signArtifact(String domain, Map<String, Object> body, Keys.SuiteKey signer) {
        Map<String, Object> full = new LinkedHashMap<>(norm(body));
        if (!"ed25519".equals(signer.alg)) {
            full.put("alg", signer.alg);
            full.put("pq_pk", signer.pqPk());
        }
        String[] sg = signer.sign(IntentArtifacts.artifactMessage(domain, full));
        full.put("sig", sg[0]);
        if (sg[1] != null) full.put("pq_sig", sg[1]);
        return full;
    }

    private static Map<String, Object> checked(String what, Map<String, Object> signed, String err) {
        if (err != null) throw new IllegalArgumentException(what + ": " + err);
        return signed;
    }

    /** A third-party discharge for a {@code needs_discharge} caveat. Throws on a malformed body (a signer never emits a weaker artifact). */
    public static Map<String, Object> signDischarge(Map<String, Object> body, Keys.SuiteKey issuer) {
        Map<String, Object> s = signArtifact(CaveatLang.DISCHARGE_DOMAIN, body, issuer);
        return checked("signDischarge", s, CaveatLang.dischargeShapeError(s));
    }

    /**
     * Build and sign a discharge. {@code bind} is {@code "chain_hop"} or {@code "action"} (then {@code actionDigest} is
     * {@code CaveatLang.dischargeActionDigest(pcactn)}). {@code issuerLabel} is the label the caveat names, not a key.
     */
    public static Map<String, Object> discharge(Keys.SuiteKey issuer, String caveatId, String issuerLabel, Map<String, Object> hop, String bind,
                                                String actionDigest, Map<String, Object> claims, long iat, long notAfter) {
        Map<String, Object> b = obj("v", 1L, "kind", "pca-discharge", "caveat_id", caveatId, "issuer", issuerLabel, "cap_hash", Pca.capHash(hop),
            "bind", bind, "claims", claims == null ? new LinkedHashMap<String, Object>() : claims, "iat", iat, "not_after", notAfter, "nonce", randomB64u(16));
        if ("action".equals(bind)) b.put("action_digest", actionDigest);
        return signDischarge(b, issuer);
    }

    /** A holder-signed per-action self-attenuation that rides beside the PCActn (no new hop). */
    public static Map<String, Object> signNarrow(Map<String, Object> body, Keys.SuiteKey holder) {
        Map<String, Object> s = signArtifact(CaveatLang.NARROW_DOMAIN, body, holder);
        return checked("signNarrow", s, CaveatLang.narrowShapeError(s));
    }

    public static Map<String, Object> narrow(Keys.SuiteKey holder, Map<String, Object> leafHop, List<Object> caveats, String actionDigest, long iat, long notAfter) {
        Map<String, Object> b = obj("v", 1L, "kind", "pca-narrow", "cap_hash", Pca.capHash(leafHop), "holder", holder.ed.id(), "caveats", caveats,
            "iat", iat, "not_after", notAfter, "nonce", randomB64u(16));
        if (actionDigest != null) b.put("action_digest", actionDigest);
        return signNarrow(b, holder);
    }

    /** The principal's signed answer to an escalation. Throws on a malformed body. */
    public static Map<String, Object> signEscalationAnswer(Map<String, Object> body, Keys.SuiteKey principal) {
        Map<String, Object> s = signArtifact(Escalation.ANSWER_DOMAIN, body, principal);
        return checked("signEscalationAnswer", s, Escalation.answerShapeError(s));
    }

    /**
     * Answer an escalation: bound to exactly this grant (policy), this PCActn (action) and this history head. {@code renderDigest}
     * (optional) is the digest of the canonical approval render the principal saw.
     */
    public static Map<String, Object> escalationAnswer(Keys.SuiteKey principal, Map<String, Object> grant, Map<String, Object> pcactn, Long lastCounter,
                                                       boolean allow, long iat, long expiresAt, String renderDigest) {
        Map<String, Object> b = obj("v", 1L, "kind", "pca-escalation-answer", "principal", principal.ed.id(), "policy_digest", Escalation.policyDigest(grant),
            "action_digest", Escalation.actionDigest(pcactn), "history_head", Escalation.historyHead(lastCounter), "decision", allow ? "allow" : "deny",
            "iat", iat, "expires_at", expiresAt, "nonce", randomB64u(16));
        if (renderDigest != null) b.put("render_digest", renderDigest);
        return signEscalationAnswer(b, principal);
    }

    // ---- Ed25519 body signatures (workflow, receipts, read grants) ------------------------------------------------

    /** {@code b64u(Ed25519(domain || strictCanonical(body)))}. */
    public static String signBody(Keys.EdKey key, String domain, Object body) {
        return Pca.b64(key.sign(Pca.concat(utf8(domain), Json.canonicalizeStrict(body).getBytes(StandardCharsets.UTF_8))));
    }

    /** Sign a workflow commitment: {@code {body, sig}}. Throws on a malformed body, a cycle, or a body naming another principal. */
    public static Map<String, Object> signWorkflow(Keys.EdKey principal, Map<String, Object> body) {
        Map<String, Object> b = norm(body);
        if (!Workflow.validWorkflowBody(b) || Workflow.dagError(b) != null) throw new IllegalArgumentException("signWorkflow: malformed workflow");
        if (!principal.id().equals(b.get("principal"))) throw new IllegalArgumentException("signWorkflow: principal is not the signer");
        return obj("body", b, "sig", signBody(principal, Workflow.WORKFLOW_DOMAIN, b));
    }

    /** Sign a step receipt (resource server). {@code prev} is the previous receipt of the same workflow, null for the first. */
    public static Map<String, Object> signStepReceipt(Keys.EdKey rs, Map<String, Object> workflow, String step, String outcome, String paramsDigest,
                                                      Map<String, Object> outputs, long issuedAt, Map<String, Object> prev) {
        Map<String, Object> base = obj("v", 1L, "wf", Workflow.workflowDigest(workflow), "step", step,
            "seq", prev == null ? 0L : Json.asLong(prev.get("seq")) + 1, "prev", prev == null ? null : Workflow.receiptRef(prev), "outcome", outcome,
            "params_digest", paramsDigest, "outputs", outputs, "issued_at", issuedAt, "signer", rs.id());
        Map<String, Object> n = norm(base);
        String sig = signBody(rs, Workflow.WF_RECEIPT_DOMAIN, n);
        n.put("sig", sig);
        return n;
    }

    /** A receipt output for a scalar {@code value}; {@code num} is carried only for integers an edge may compare. */
    public static Map<String, Object> wfOutput(Object value, List<String> labels, String unit, boolean num) {
        List<String> ls = new ArrayList<>(labels == null ? new ArrayList<String>() : labels);
        java.util.Collections.sort(ls);
        return obj("digest", Workflow.valueDigest(value), "num", num && value instanceof Number ? value : null, "unit", unit, "labels", new ArrayList<Object>(ls));
    }

    /** Sign a read grant: {@code {body, sig}}. */
    public static Map<String, Object> signReadGrant(Keys.EdKey principal, Map<String, Object> body) {
        Map<String, Object> b = norm(body);
        if (!ReadSide.validReadGrantBody(b) || !principal.id().equals(b.get("principal"))) throw new IllegalArgumentException("signReadGrant: malformed grant");
        return obj("body", b, "sig", signBody(principal, ReadSide.READ_GRANT_DOMAIN, b));
    }

    // ---- passports ------------------------------------------------------------------------------------------------

    /** Content fingerprint over a passport's identity fields (its {@code id}). */
    public static String passportFingerprint(Map<String, Object> p) {
        return Pca.hashCanonical(obj("d", "atlas-pca/passport/v1", "model_id", p.get("model_id"), "weights_digest", p.get("weights_digest"),
            "system_prompt_digest", p.get("system_prompt_digest"), "tool_manifest_digest", p.get("tool_manifest_digest"),
            "runtime_measurement", p.get("runtime_measurement"), "operator", p.get("operator"), "hardware_rooted", p.get("hardware_rooted")));
    }

    /** Fill {@code id} from the fingerprint of the identity fields. */
    public static Map<String, Object> issuePassport(Map<String, Object> identity) {
        Map<String, Object> p = new LinkedHashMap<>(identity);
        p.put("id", passportFingerprint(identity));
        return p;
    }

    /** Sign a passport for {@code subject} (the agent's Ed25519 key id). {@code evidence} (optional) is required for a hardware-rooted passport. */
    public static Map<String, Object> signPassport(Map<String, Object> passport, Keys.SuiteKey issuer, String subject, long iat, Long nbf, long exp, Map<String, Object> evidence) {
        if (!passport.get("id").equals(passportFingerprint(passport))) throw new IllegalArgumentException("signPassport: passport.id is not the fingerprint of its identity (use issuePassport)");
        if (Boolean.TRUE.equals(passport.get("hardware_rooted")) && evidence == null) throw new IllegalArgumentException("signPassport: hardware_rooted requires attestation evidence (fail closed)");
        long nb = nbf != null ? nbf : iat;
        if (exp <= nb) throw new IllegalArgumentException("signPassport: exp must be after nbf");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("typ", PASSPORT_VERSION_TYPE);
        body.put("ver", 1L);
        body.put("passport", passport);
        body.put("iss", issuer.ed.id());
        body.put("sub", subject);
        body.put("iat", iat);
        body.put("nbf", nb);
        body.put("exp", exp);
        if (evidence != null) {
            Map<String, Object> ev = new LinkedHashMap<>(evidence);
            if (!ev.containsKey("at")) ev.put("at", iat);
            body.put("evidence", ev);
        }
        if (!"ed25519".equals(issuer.alg)) {
            body.put("alg", issuer.alg);
            body.put("pq_pk", issuer.pqPk());
        }
        Map<String, Object> n = norm(body);
        String[] sg = issuer.sign(Pca.concat(Passport.SIG_DOMAIN, Json.canonicalizeStrict(n).getBytes(StandardCharsets.UTF_8)));
        n.put("sig", sg[0]);
        if (sg[1] != null) n.put("pq_sig", sg[1]);
        return n;
    }

    // ---- fresh_at token and aggregate grant -----------------------------------------------------------------------

    /** A signed consistency token ({@code fresh_at}) from the resource server. {@code state} holds revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest. */
    public static Map<String, Object> signFreshAt(Keys.EdKey rs, String scope, Map<String, Object> state, long issuedAt) {
        Map<String, Object> b = obj("v", 1L, "scope", scope);
        for (String k : new String[] {"revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest"}) b.put(k, state.get(k));
        b.put("issued_at", issuedAt);
        b.put("signer", rs.id());
        Map<String, Object> n = norm(b);
        n.put("sig", signBody(rs, K3.FRESH_AT_DOMAIN, n));
        return n;
    }

    /** Sign an aggregate (differential-privacy) read grant: {@code {body, sig}}. */
    public static Map<String, Object> signAggregateGrant(Keys.EdKey principal, Map<String, Object> body) {
        Map<String, Object> b = norm(body);
        if (!ReadVault.validAggregateGrantBody(b) || !principal.id().equals(b.get("principal"))) throw new IllegalArgumentException("signAggregateGrant: malformed grant");
        return obj("body", b, "sig", signBody(principal, ReadVault.AGGREGATE_DOMAIN, b));
    }
}
