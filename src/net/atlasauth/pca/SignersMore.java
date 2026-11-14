package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * More producer-side signers: the artifacts an agent, a principal, a guardian, a site, an oracle or a resource server signs beyond
 * the grant and the PCActn ({@link Issue}). Same wire as the TypeScript reference, byte for byte for Ed25519 and the deterministic
 * post-quantum suites. Every signer runs the reference's checks before signing and throws {@link IllegalArgumentException} on a
 * malformed body (fail closed): a signer never emits an artifact the verifier would refuse.
 *
 * <p>Signers that take a {@link Keys.SuiteKey} sign under that key's suite; a suite this SDK cannot sign is refused when the key is
 * made ({@code unsupported_suite: <alg>}).
 */
public final class SignersMore {
    private SignersMore() {}

    private static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    private static Map<String, Object> copy(Map<String, Object> m) { return new LinkedHashMap<>(m); }

    private static Keys.EdKey edOf(Keys.SuiteKey k, String who) {
        if (k.ed == null) throw new IllegalArgumentException(who + ": the signer needs an Ed25519 identity");
        return k.ed;
    }

    // ---- threshold shares (threshold.ts signShare / signPreparedShare) --------------------------------------------------------

    /**
     * Sign already-computed share bytes (the share message a step-up hands a principal device). Ed25519 gives
     * {@code {role, publicKey, sig}}, byte-identical to the pre-agility share; another suite adds {@code alg} (and {@code pq_sig}
     * for a hybrid). The role's PQ public key is registered in the signer set, not carried in the share.
     */
    public static Map<String, Object> signPreparedShare(String role, Keys.SuiteKey signer, byte[] prepared) {
        Keys.EdKey ed = edOf(signer, "signPreparedShare");
        String[] sg = signer.sign(prepared);
        Map<String, Object> share = Issue.obj("role", role, "publicKey", ed.id(), "sig", sg[0]);
        if (!"ed25519".equals(signer.alg)) {
            share.put("alg", signer.alg);
            if (sg[1] != null) share.put("pq_sig", sg[1]);
        }
        return share;
    }

    /**
     * A role's EXPLICIT threshold share (agent, guardian or principal) over the bound share message
     * {@code "atlas-pca/share/<role>\0" || sha256(message) || signerSetHash || t [|| suite tag]}, where {@code message} is the
     * PCActn's threshold message. The share cannot be replayed into another signer set or threshold.
     */
    public static Map<String, Object> signThresholdShare(String role, Keys.SuiteKey signer, byte[] message, List<Object> signerSet, int t) {
        if (signerSet == null) throw new IllegalArgumentException("signShare: a '" + role + "' share must bind {signerSet, t}");
        if (t < 1 || t > 3) throw new IllegalArgumentException("shareMessage: t must be 1, 2 or 3");
        return signPreparedShare(role, signer, Threshold.shareMessage(role, message, signerSet, t, signer.alg, true));
    }

    // ---- PQ key binding (pq.ts signPqBinding) ----------------------------------------------------------------------------------

    static final String PQ_BIND_DOMAIN = "atlas-pca/pq-binding/v2\0";

    static byte[] pqBindingMessage(String ed, String pq, long epoch, String aud) {
        return utf8(PQ_BIND_DOMAIN + ed + "\0" + pq + "\0" + epoch + "\0" + aud);
    }

    /**
     * An identity's signed statement "this PQ key is mine, as of {@code epoch}, for audience {@code aud}": an Ed25519 signature
     * over the domain, the identity, the PQ key, the epoch and the audience. {@code epoch} grows on every rotation (at least 1).
     */
    public static Map<String, Object> signPqBinding(Keys.EdKey key, String pqPublicKey, long epoch, String aud) {
        if (epoch < 1 || epoch > 9007199254740991L) throw new IllegalArgumentException("signPqBinding: epoch must be a positive safe integer");
        if (aud == null || aud.isEmpty()) throw new IllegalArgumentException("signPqBinding: aud (the instance/audience id) is required");
        return Issue.obj("ed", key.id(), "pq", pqPublicKey, "epoch", epoch, "aud", aud,
            "sig", Pca.b64(key.sign(pqBindingMessage(key.id(), pqPublicKey, epoch, aud))));
    }

    // ---- agent-native: caution, lease heartbeat --------------------------------------------------------------------------------

    public static final int MAX_CAUTION_REASON_LEN = 64;
    private static final java.util.regex.Pattern REASON_RE = java.util.regex.Pattern.compile("^[A-Za-z0-9_.:-]+$");

    private static byte[] msgOf(String domain, Object body) { return Pca.canonBytes(Issue.obj("d", domain, "b", body)); }

    private static boolean nonEmpty(Object v) { return v instanceof String && !((String) v).isEmpty(); }

    /** The reference's caution body check; null when the body may be signed. */
    static String cautionBodyError(Object bO) {
        if (!(bO instanceof Map)) return "not an object";
        Map<?, ?> b = (Map<?, ?>) bO;
        if (!nonEmpty(b.get("action_digest"))) return "action_digest required";
        if (!nonEmpty(b.get("holder"))) return "holder required";
        Object c = b.get("caution");
        if (!IntentJs.isFinite(c) || IntentJs.num(c) < 0 || IntentJs.num(c) > 1) return "caution must be a finite number in [0,1]";
        if (b.containsKey("reason")) {
            Object r = b.get("reason");
            if (!(r instanceof String) || ((String) r).length() > MAX_CAUTION_REASON_LEN || !REASON_RE.matcher((String) r).matches()) return "invalid reason";
        }
        return null;
    }

    /**
     * The holder's signed caution claim about an action ({@code {action_digest, caution in [0,1], reason?, holder}}). Throws on an
     * invalid body (an out-of-range caution, a bad reason); members beyond these are dropped.
     */
    public static Map<String, Object> signCaution(Map<String, Object> body, Keys.EdKey holder) {
        String err = cautionBodyError(body);
        if (err != null) throw new IllegalArgumentException("signCaution: " + err);
        Map<String, Object> clean = Issue.obj("action_digest", body.get("action_digest"), "caution", body.get("caution"), "holder", body.get("holder"));
        if (body.containsKey("reason")) clean.put("reason", body.get("reason"));
        Map<String, Object> out = copy(clean);
        out.put("sig", Pca.b64(holder.sign(msgOf("atlas-pca/caution/v1", clean))));
        return out;
    }

    /** The lease holder's signed liveness proof ({@code {cap_id, seq, at, holder, lease_issued_at}}); other members are dropped. */
    public static Map<String, Object> signHeartbeat(Map<String, Object> body, Keys.EdKey holder) {
        Map<String, Object> clean = new LinkedHashMap<>();
        for (String k : new String[] {"cap_id", "seq", "at", "holder", "lease_issued_at"}) {
            if (!body.containsKey(k)) throw new IllegalArgumentException("signHeartbeat: " + k + " required");
            clean.put(k, body.get(k));
        }
        Map<String, Object> out = copy(clean);
        out.put("sig", Pca.b64(holder.sign(msgOf("atlas-pca/lease-hb/v2", clean))));
        return out;
    }

    // ---- read receipt (readside.ts signReadReceipt, resource-server side) ------------------------------------------------------

    /** The resource server's signed receipt for a read under {@code grant} (the read grant BODY); {@code prev} is the previous receipt or null. */
    public static Map<String, Object> signReadReceipt(Keys.EdKey rs, Map<String, Object> grant, String verb, String resource, String purpose,
                                                      Map<String, Object> fields, List<Object> labels, long issuedAt, Map<String, Object> prev) {
        Map<String, Object> base = Issue.obj("v", 1L, "grant", ReadSide.readGrantDigest(grant), "verb", verb, "resource", resource, "purpose", purpose,
            "seq", prev == null ? 0L : Json.asLong(prev.get("seq")) + 1, "prev", prev == null ? null : ReadSide.readReceiptRef(prev),
            "fields", fields, "labels", labels, "issued_at", issuedAt, "signer", rs.id());
        Map<String, Object> n = Issue.norm(base);
        String sig = Issue.signBody(rs, ReadSide.READ_RECEIPT_DOMAIN, n);
        n.put("sig", sig);
        return n;
    }

    // ---- cross-domain mesh (mesh.ts signMeshAction / assembleMeshProof) --------------------------------------------------------

    /** The leaf holder's signature over {@code {action, tip = capHash(last hop)}}. */
    public static String signMeshAction(List<Object> chain, Map<String, Object> action, Keys.EdKey leaf) {
        if (chain == null || chain.isEmpty()) throw new IllegalArgumentException("signMeshAction: empty chain");
        String tip = Pca.capHash(Pca.asMap(chain.get(chain.size() - 1)));
        return Pca.b64(leaf.sign(Pca.concat(utf8(Mesh.ACTION_DOMAIN), Pca.canonBytes(Issue.obj("action", action, "tip", tip)))));
    }

    /**
     * A compact mesh proof: hops issued against the same head share one table entry (their cosignatures merged by witness),
     * identical revocation bracketing leaves are carried once, and the leaf holder signs the action. Each hop is
     * {@code {domain, head: {head, sig, cosigs}, inclusion, revocation: {cap, issuer_key}, binding?}}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> assembleMeshProof(List<Object> chain, List<Object> hops, Map<String, Object> action, Keys.EdKey leaf, List<Object> pinProofs) {
        List<Object> heads = new ArrayList<>(), leaves = new ArrayList<>(), outHops = new ArrayList<>();
        Map<String, Integer> headIdx = new HashMap<>(), leafIdx = new HashMap<>();
        java.util.function.Function<Object, Map<String, Object>> compact = nO -> {
            Map<String, Object> n = Pca.asMap(nO);
            Map<String, Object> o = Issue.obj("size", n.get("size"));
            for (String side : new String[] {"lo", "hi"}) {
                Object lp = n.get(side);
                if (lp == null) continue;
                String k = Json.canonicalize(lp);
                Integer i = leafIdx.get(k);
                if (i == null) { i = leaves.size(); leaves.add(lp); leafIdx.put(k, i); }
                o.put(side, (long) i);
            }
            return o;
        };
        for (Object evO : hops) {
            Map<String, Object> ev = Pca.asMap(evO);
            Map<String, Object> h = Pca.asMap(ev.get("head"));
            String k = h.get("sig") + "|" + Json.canonicalize(h.get("head"));
            Integer i = headIdx.get(k);
            if (i == null) {
                i = heads.size();
                heads.add(Issue.obj("head", h.get("head"), "sig", h.get("sig"), "cosigs", new ArrayList<Object>(Pca.asList(h.get("cosigs")))));
                headIdx.put(k, i);
            } else {
                List<Object> cos = (List<Object>) Pca.asMap(heads.get(i)).get("cosigs");
                Set<Object> have = new HashSet<>();
                for (Object c : cos) have.add(Pca.asMap(c).get("witness"));
                for (Object c : Pca.asList(h.get("cosigs"))) if (!have.contains(Pca.asMap(c).get("witness"))) cos.add(c);
            }
            Map<String, Object> rev = Pca.asMap(ev.get("revocation"));
            Map<String, Object> o = Issue.obj("domain", ev.get("domain"), "head", (long) i, "inclusion", ev.get("inclusion"),
                "revocation", Issue.obj("cap", compact.apply(rev.get("cap")), "issuer_key", compact.apply(rev.get("issuer_key"))));
            if (ev.get("binding") != null) o.put("binding", ev.get("binding"));
            outHops.add(o);
        }
        Map<String, Object> proof = Issue.obj("chain", new ArrayList<Object>(chain), "heads", heads, "rev_leaves", leaves, "hops", outHops,
            "action", action, "action_sig", signMeshAction(chain, action, leaf));
        if (pinProofs != null && !pinProofs.isEmpty()) proof.put("pin_proofs", new ArrayList<Object>(pinProofs));
        return proof;
    }

    // ---- Intent v2 session root and session grant (intent-session.ts) ---------------------------------------------------------

    private static final String[] ROOT_MEMBERS = {"v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri"};

    /** Sign the session root as one of its principals: the signer's Ed25519 key must be listed in {@code principals}. */
    public static Map<String, Object> signSessionRoot(Map<String, Object> body, Keys.SuiteKey principal) {
        String signer = edOf(principal, "signSessionRoot").id();
        Map<String, Object> base = new LinkedHashMap<>();
        for (String k : ROOT_MEMBERS) base.put(k, body.get(k));
        for (String k : new String[] {"revocation", "flows"}) if (body.containsKey(k)) base.put(k, body.get(k));
        base.put("expires_at", body.get("expires_at"));
        base.put("signer", signer);
        // the reference's unsigned shape check: the body as given (unknown members included) with the signer and a placeholder sig
        Map<String, Object> probe = copy(body);
        for (String k : new String[] {"sig", "alg", "pq_pk", "pq_sig"}) probe.remove(k);
        probe.put("signer", signer);
        probe.put("sig", "");
        String bad = IntentSession.rootShapeError(probe);
        if ("signer is not one of the session principals".equals(bad)) throw new IllegalArgumentException("signSessionRoot: the signer is not one of the session principals");
        if (bad != null) throw new IllegalArgumentException("signSessionRoot: " + bad);
        return Issue.signArtifact(IntentSession.INTENT_SESSION_SIG_DOMAIN, base, principal);
    }

    /** A session grant and the salt that opens its goal commitment (it goes in the PCActn's {@code intent.goal_salt}). */
    public static final class SessionGrant {
        public final Map<String, Object> grant;
        public final String goalSalt;
        SessionGrant(Map<String, Object> grant, String goalSalt) { this.grant = grant; this.goalSalt = goalSalt; }
    }

    /**
     * G_0 (seq 0) or a delta grant D_k: a principal-signed root capability whose caveats are the envelope (goal
     * {@code pca-intent:v2:<session>:<mapDigest>}, or {@code v2c} over a committed map when {@code mapForm} is {@code "commit"}) and
     * the {@code intent_session} caveat. {@code prev}, {@code mapForm}, {@code caveats} ([] when null), {@code agentBinding} ({} when
     * null), {@code riskPolicy} (the default when null), {@code salt} (random when null) and {@code holderPqPk} are optional.
     */
    public static SessionGrant mintSessionGrant(Keys.SuiteKey principal, String holder, String session, long seq, String root, String prev,
                                                String mapDigest, String mapForm, List<Object> predicates, List<Object> caveats,
                                                Map<String, Object> agentBinding, Map<String, Object> riskPolicy, String salt, String holderPqPk) {
        Map<String, Object> sc = Issue.obj("type", "intent_session", "session", session, "seq", seq, "root", root);
        if (prev != null) sc.put("prev", prev);
        String bad = IntentSession.caveatError(sc);
        if (bad != null) throw new IllegalArgumentException("mintSessionGrant: " + bad);
        if (!IntentJs.b32(mapDigest)) throw new IllegalArgumentException("mintSessionGrant: mapDigest must be canonical base64url (32 bytes)");
        String goalSalt = salt != null ? salt : Issue.randomB64u(16);
        String goal = IntentMap.MAP_FORM_COMMIT.equals(mapForm) ? IntentSession.intentGoalV2c(session, mapDigest) : IntentSession.intentGoalV2(session, mapDigest);
        Map<String, Object> envelope = Issue.obj("type", Issue.ENVELOPE_CAVEAT, "goal_commit", Issue.goalCommit(goal, goalSalt), "predicates", predicates,
            "caveats", caveats != null ? caveats : new ArrayList<Object>(), "agent_binding", agentBinding != null ? agentBinding : new LinkedHashMap<String, Object>(),
            "risk_policy", riskPolicy != null ? riskPolicy : Issue.defaultRiskPolicy());
        List<Object> cavs = new ArrayList<>();
        cavs.add(envelope);
        cavs.add(sc);
        return new SessionGrant(Issue.mintRoot(principal, holder, holderPqPk, cavs), goalSalt);
    }

    // ---- site-signed documents: action schema, labels; oracle facts -----------------------------------------------------------

    /**
     * Sign an action schema as the site: {@code sig = {alg, kid, value, pq_value?}} over {@code utf8(domain) || strictCanonical(doc)}.
     * {@code kid} names the site's discovery key entry ({@link #actionSchemaKeyOf}).
     */
    public static Map<String, Object> signActionSchema(Map<String, Object> doc, String kid, Keys.SuiteKey site) {
        String bad = ActionSchema.shapeError(doc, false);
        if (bad != null) throw new IllegalArgumentException("signActionSchema: " + bad);
        Map<String, Object> body = copy(doc);
        body.remove("sig");
        String[] sg = site.sign(Pca.concat(utf8(ActionSchema.ACTION_SCHEMA_DOMAIN), Pca.canonBytes(body)));
        Map<String, Object> sig = Issue.obj("alg", site.alg, "kid", kid, "value", sg[0]);
        if (sg[1] != null) sig.put("pq_value", sg[1]);
        Map<String, Object> out = copy(doc);
        out.put("sig", sig);
        return out;
    }

    /** The discovery key entry {@code {kid, alg, pk, pq_pk?}} a verifier pins for a site signer. */
    public static Map<String, Object> actionSchemaKeyOf(String kid, Keys.SuiteKey site) {
        Map<String, Object> k = Issue.obj("kid", kid, "alg", site.alg, "pk", edOf(site, "actionSchemaKeyOf").id());
        if (site.pqPk() != null) k.put("pq_pk", site.pqPk());
        return k;
    }

    // ---- intent_required (intent-required.ts signIntentRequired, site side) ---------------------------------------------------

    public static final String INTENT_REQUIRED_DOMAIN = "atlas-pca/intent-required/v1\0";
    private static final List<String> IR_KEYS = java.util.Arrays.asList("v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest",
        "cell", "reason", "question_id", "friction", "delivered_to", "expires_at", "sig");
    private static final java.util.regex.Pattern QUESTION_ID_RE = java.util.regex.Pattern.compile("[A-Za-z0-9_-]{1,64}");

    static String cellCoordsError(Object cO) {
        if (!(cO instanceof Map) || ((Map<?, ?>) cO).isEmpty() || ((Map<?, ?>) cO).size() > 64) return "coords must be an object of 1..64 dimensions";
        for (Map.Entry<?, ?> e : ((Map<?, ?>) cO).entrySet()) {
            String k = (String) e.getKey();
            Object v = e.getValue();
            if (k.isEmpty() || k.length() > 256) return "a coordinate path must be 1..256 characters";
            List<?> l = v instanceof List ? (List<?>) v : null;
            boolean range = l != null && l.size() == 2 && IntentJs.isInt(l.get(0)) && IntentJs.isInt(l.get(1));
            if (range) {
                if (!(IntentJs.num(l.get(0)) >= 0 && IntentJs.num(l.get(0)) <= IntentJs.num(l.get(1)))) return "coords '" + k + "': need 0 <= lo <= hi";
                continue;
            }
            boolean set = l != null && !l.isEmpty() && l.size() <= 256;
            if (set) for (Object x : l) if (!(x instanceof String)) set = false;
            if (!set) return "coords '" + k + "': an index range [lo, hi] or a value set";
            if (new HashSet<Object>(l).size() != l.size()) return "coords '" + k + "': values must be distinct";
        }
        return null;
    }

    /** The reference's shape check of an UNSIGNED {@code pca-intent-required} v1 body (the signer's pre-check); null when well formed. */
    public static String intentRequiredShapeError(Object bO) {
        if (!(bO instanceof Map)) return "not an object";
        Map<?, ?> b = (Map<?, ?>) bO;
        for (Object k : b.keySet()) if (!IR_KEYS.contains(k)) return "unknown member '" + k + "'";
        if (!OracleFacts.isOne(b.get("v")) || !"pca-intent-required".equals(b.get("kind"))) return "not a pca-intent-required v1";
        for (String k : new String[] {"session", "map_digest", "schema", "pcactn_digest", "action_digest"})
            if (!IntentJs.b32(b.get(k))) return k + " must be canonical base64url (32 bytes)";
        Object cell = b.get("cell");
        if (!(cell instanceof Map) || ((Map<?, ?>) cell).size() != 2 || !((Map<?, ?>) cell).containsKey("coords") || !((Map<?, ?>) cell).containsKey("verb")
            || !nonEmpty(((Map<?, ?>) cell).get("verb"))) return "cell must be {verb, coords}";
        String ce = cellCoordsError(((Map<?, ?>) cell).get("coords"));
        if (ce != null) return ce;
        if (!"uncertain".equals(b.get("reason"))) return "reason must be 'uncertain'";
        if (!(b.get("question_id") instanceof String) || !QUESTION_ID_RE.matcher((String) b.get("question_id")).matches()) return "question_id must match [A-Za-z0-9_-]{1,64}";
        if (!java.util.Arrays.asList("tap", "hold", "typed", "device").contains(b.get("friction"))) return "unknown friction tier";
        if (!"wallet".equals(b.get("delivered_to")) && !"agent".equals(b.get("delivered_to"))) return "delivered_to must be 'wallet' or 'agent'";
        if (!IntentJs.isNonNeg(b.get("expires_at"))) return "expires_at must be a non-negative safe integer";
        if (b.containsKey("sig")) return "an unsigned body must not carry sig";
        return null;
    }

    /**
     * The site's signed {@code pca-intent-required} v1 body: {@code sig = {alg, kid, value, pq_value?}} over
     * {@code utf8(domain) || strictCanonical(body)}, pinned by the same discovery key entry as the action schema.
     */
    public static Map<String, Object> signIntentRequired(Map<String, Object> body, String kid, Keys.SuiteKey site) {
        String bad = intentRequiredShapeError(body);
        if (bad != null) throw new IllegalArgumentException("signIntentRequired: " + bad);
        String[] sg = site.sign(Pca.concat(utf8(INTENT_REQUIRED_DOMAIN), Pca.canonBytes(body)));
        Map<String, Object> sig = Issue.obj("alg", site.alg, "kid", kid, "value", sg[0]);
        if (sg[1] != null) sig.put("pq_value", sg[1]);
        Map<String, Object> out = copy(body);
        out.put("sig", sig);
        return out;
    }

    // ---- progress step (progress.ts signProgressStep, holder side) ------------------------------------------------------------

    public static final String PROGRESS_SIG_DOMAIN = "atlas-pca/progress-step/v2";

    /**
     * The holder's signed progress step {@code {step, holder, sig}}: Ed25519 over the domain-separated binding of the step to the
     * holder, goal, action, before/after state, sequence, chain link and step digest.
     */
    public static Map<String, Object> signProgressStep(Map<String, Object> step, Keys.EdKey holder) {
        Map<String, Object> b = Issue.obj("holder", holder.id(), "goal_commitment", step.get("goal_commitment"), "action_digest", step.get("action_digest"),
            "before_digest", step.get("before_digest"), "after_digest", step.get("after_digest"), "seq", step.get("seq"), "prev", step.get("prev"),
            "step_digest", step.get("digest"));
        return Issue.obj("step", step, "holder", holder.id(), "sig", Pca.b64(holder.sign(msgOf(PROGRESS_SIG_DOMAIN, b))));
    }

    /** A site's signed label receipt ({@code pca-labels} v1). */
    public static Map<String, Object> signLabels(Map<String, Object> body, Keys.SuiteKey site) {
        Map<String, Object> full = Issue.obj("v", 1L, "kind", "pca-labels");
        full.putAll(body);
        return Issue.signArtifact(ParamProvenance.LABELS_DOMAIN, full, site);
    }

    /** An oracle's signed fact ({@code pca-fact} v1). */
    public static Map<String, Object> signFact(Map<String, Object> body, Keys.SuiteKey oracle) {
        Map<String, Object> full = Issue.obj("v", 1L, "kind", "pca-fact");
        full.putAll(body);
        return Issue.signArtifact(OracleFacts.FACT_DOMAIN, full, oracle);
    }

    /**
     * A site's signed offer set ({@code pca-offer-set} v1; the body carries its own v / kind). As in the reference, only the
     * strict canonical profile is checked before signing (the verifier checks the wire).
     */
    public static Map<String, Object> signOfferSet(Map<String, Object> body, Keys.SuiteKey site) {
        if (body == null) throw new IllegalArgumentException("signOfferSet: not an object");
        return Issue.signArtifact(OracleFacts.OFFER_SET_DOMAIN, body, site);
    }

    // ---- linked policy templates (policy-link.ts signTemplate / signTighten) ---------------------------------------------------

    private static final String TEMPLATE_SIG_DOMAIN = "atlas-pca/policy-template/v1\0";
    private static final String TIGHTEN_SIG_DOMAIN = "atlas-pca/template-tighten/v1\0";

    private static byte[] digestMessage(String domain, String digest) { return Pca.concat(utf8(domain), Pca.sha(utf8(digest))); }

    /** The principal's signed policy template {@code {def, signer, sig}}. */
    public static Map<String, Object> signTemplate(Map<String, Object> def, Keys.EdKey principal) {
        String e = PolicyAuthoring.templateDefError(def);
        if (e != null) throw new IllegalArgumentException("signTemplate: " + e);
        return Issue.obj("def", def, "signer", principal.id(), "sig", Pca.b64(principal.sign(digestMessage(TEMPLATE_SIG_DOMAIN, PolicyAuthoring.templateDigest(def)))));
    }

    /** The principal's signed tighten overlay {@code {overlay, signer, sig}} (it can only add where conditions and caveats). */
    public static Map<String, Object> signTighten(Map<String, Object> overlay, Keys.EdKey principal) {
        String e = PolicyAuthoring.tightenOverlayError(overlay);
        if (e != null) throw new IllegalArgumentException("signTighten: " + e);
        return Issue.obj("overlay", overlay, "signer", principal.id(), "sig", Pca.b64(principal.sign(digestMessage(TIGHTEN_SIG_DOMAIN, Pca.hashCanonical(overlay)))));
    }

    // ---- revocation epoch (revocation.ts signRevocationEpoch, guardian side) ---------------------------------------------------

    private static final String[] EPOCH_FIELDS = {"instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after"};

    /**
     * The guardian's signed revocation epoch over {@code {instance_id, grant_ref, epoch, set_size, root, issued_at, not_after}}; a
     * non-ed25519 suite binds {@code alg} and {@code pq_pk} into the signed bytes.
     */
    public static Map<String, Object> signRevocationEpoch(Keys.SuiteKey guardian, Map<String, Object> body) {
        Keys.EdKey ed = edOf(guardian, "signRevocationEpoch");
        Map<String, Object> fields = new LinkedHashMap<>();
        for (String k : EPOCH_FIELDS) {
            if (!body.containsKey(k)) throw new IllegalArgumentException("signRevocationEpoch: " + k + " required");
            fields.put(k, body.get(k));
        }
        Map<String, Object> bound = copy(fields);
        if (!"ed25519".equals(guardian.alg)) {
            bound.put("alg", guardian.alg);
            bound.put("pq_pk", guardian.pqPk());
        }
        String[] sg = guardian.sign(Pca.concat(utf8(IntentRevocation.REVEPOCH_DOMAIN), Pca.canonBytes(bound)));
        Map<String, Object> out = Issue.norm(fields);
        out.put("guardian", ed.id());
        out.put("sig", sg[0]);
        if (!"ed25519".equals(guardian.alg)) {
            out.put("alg", guardian.alg);
            out.put("pq_pk", guardian.pqPk());
            if (sg[1] != null) out.put("pq_sig", sg[1]);
        }
        return out;
    }

    // ---- constitution (prohibitions.ts signConstitution) ----------------------------------------------------------------------

    /** The principal signs a constitution: {@code {...body, id, sig}}. Refuses a malformed one (every problem, joined with "; "). */
    public static Map<String, Object> signConstitution(Map<String, Object> c, Keys.EdKey principal) {
        List<String> problems = Prohibitions.validateConstitution(c);
        if (!problems.isEmpty()) throw new IllegalArgumentException("signConstitution: " + String.join("; ", problems));
        String id = Prohibitions.constitutionId(c);
        Map<String, Object> out = Prohibitions.body(c);
        out.put("id", id);
        out.put("sig", Pca.b64(principal.sign(Prohibitions.domainMessage(Prohibitions.CONSTITUTION_SIG_DOMAIN, id))));
        return out;
    }
}
