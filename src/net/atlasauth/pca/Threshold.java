package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Threshold-share verification, mirroring {@code packages/pca/src/threshold.ts}. Covers the v2.1 AGENT-LEAF
 * BINDING (conformance {@code agent_leaf_binding: "2.1"}): every role's EXPLICIT share — {@code guardian},
 * {@code principal} AND (new in v2.1) {@code agent} — signs the SAME role/signer-set/threshold-bound bytes
 *
 * <pre>"atlas-pca/share/&lt;role&gt;\0" || sha256(thresholdMessage) || signerSetHash || t(1 byte) || suiteTag</pre>
 *
 * so a share cannot be replayed under another role, in a different signer set, or at a different threshold. The
 * OLD bare-threshold-message agent share (GAP 2) MUST be rejected because it does not verify over these bound
 * bytes, and a share bound to signer set A MUST be rejected against signer set B (the {@code signerSetHash}
 * binding defeats cross-signer-set replay).
 *
 * <p>Fail-closed throughout: an unknown suite, a malformed signer set, a bad base64url field, or a signature
 * that does not verify all return {@code false}; nothing in the verify path swallows an exception into a pass.
 */
public final class Threshold {
    private Threshold() {}

    /** The legal required thresholds (L1 agent only, L2 plus guardian, L3 plus principal). */
    public static final List<Integer> VALID_THRESHOLDS = java.util.Collections.unmodifiableList(java.util.Arrays.asList(1, 2, 3));

    static final String SIGNER_SET_DOMAIN = "atlas-pca/signerset/v1\0";
    /** Domain-separated suite tag appended for a NON-default suite; ed25519 / absent / unknown => empty. */
    static final String SHARE_SUITE_TAG = "\0atlas-pca/share-suite/v1\0";
    /** Version marker for the v2.1 agent-leaf share binding (matches {@code vectors.json.agent_leaf_binding}). */
    public static final String AGENT_LEAF_SHARE_BINDING_VERSION = "2.1";

    private static byte[] utf8(String s) { return Json.utf8(s); }

    /**
     * {@code sha256(DOMAIN || canonical(sorted [{publicKey, role[, pq_pk]}]))}, the rows sorted bytewise by
     * {@code (role, publicKey)} so signer and verifier agree however the set is listed. ADDITIVE: a registered
     * {@code pq_pk} is carried into the bound set; an ed25519-only set hashes byte-identically to pre-agility.
     */
    static byte[] signerSetHash(List<Object> signerSet) {
        List<Object> rows = new ArrayList<>();
        for (Object o : signerSet) {
            Map<String, Object> s = Pca.asMap(o);
            Map<String, Object> row = new java.util.LinkedHashMap<>();
            row.put("publicKey", String.valueOf(s.get("publicKey")));
            row.put("role", String.valueOf(s.get("role")));
            if (s.get("pq_pk") instanceof String) row.put("pq_pk", s.get("pq_pk"));
            rows.add(row);
        }
        rows.sort((a, b) -> {
            Map<String, Object> ma = Pca.asMap(a), mb = Pca.asMap(b);
            int c = Json.compareUtf8((String) ma.get("role"), (String) mb.get("role"));
            return c != 0 ? c : Json.compareUtf8((String) ma.get("publicKey"), (String) mb.get("publicKey"));
        });
        return Pca.sha(utf8(SIGNER_SET_DOMAIN), Pca.canonBytes(rows));
    }

    /** Empty for ed25519 / absent / unknown, else {@code SHARE_SUITE_TAG || suite.alg}. */
    static byte[] shareSuiteTag(Object alg, boolean algPresent) {
        Pq.Suite suite = Pq.resolveSigAlg(alg, algPresent);
        if (suite == null || "ed25519".equals(suite.alg)) return new byte[0];
        return utf8(SHARE_SUITE_TAG + suite.alg);
    }

    /** The bytes a share of {@code role} signs. {@code t} MUST be 1, 2 or 3. */
    static byte[] shareMessage(String role, byte[] thresholdMessage, List<Object> signerSet, int t, Object alg, boolean algPresent) {
        if (t < 1 || t > 3) throw new IllegalArgumentException("shareMessage: t must be 1, 2 or 3");
        return Pca.concat(
            utf8("atlas-pca/share/" + role + "\0"),
            Pca.sha(thresholdMessage),
            signerSetHash(signerSet),
            new byte[] {(byte) t},
            shareSuiteTag(alg, algPresent));
    }

    /** Registered PQ public-key lengths of every suite (ml-dsa-65/87, slh-dsa-128f/256s, fn-dsa-512/1024, less-cat1). */
    static final java.util.Set<Integer> PQ_PK_LENGTHS = new java.util.HashSet<>(java.util.Arrays.asList(1952, 2592, 32, 64, 897, 1793, 97484));
    static final java.util.Set<String> ROLES = new java.util.HashSet<>(java.util.Arrays.asList("agent", "guardian", "principal"));

    /**
     * R6-03: the reference's signer-set validation (decideThreshold BuildReg). Every entry is an object with a known role
     * (case-sensitive) and a canonical 32-byte publicKey; a PRESENT pq_pk (JSON null is present) is canonical base64url of a
     * registered PQ key length; one key per role; one role per key; a duplicate (role, key) only with the same pq_pk.
     * Returns role -> {publicKey, pq_pk or null}, or null when the set is malformed.
     */
    static Map<String, String[]> validatedRegistry(List<Object> signerSet) {
        Map<String, String[]> reg = new java.util.HashMap<>();
        for (Object o : signerSet) {
            if (!(o instanceof Map)) return null;
            Map<?, ?> e = (Map<?, ?>) o;
            Object ro = e.get("role"), ko = e.get("publicKey");
            if (!(ro instanceof String) || !ROLES.contains(ro)) return null;
            if (!(ko instanceof String) || Pca.decodeB64uStrict(ko, 32) == null) return null;
            String pq = null;
            if (e.containsKey("pq_pk")) {
                Object po = e.get("pq_pk");
                if (!(po instanceof String)) return null;
                byte[] pb = Pca.decodeB64uStrict(po, -1);
                if (pb == null || !PQ_PK_LENGTHS.contains(pb.length)) return null;
                pq = (String) po;
            }
            String[] prev = reg.get(ro);
            if (prev != null) {
                if (!prev[0].equals(ko)) return null;                  // two keys for one role
                if (!java.util.Objects.equals(prev[1], pq)) return null; // duplicate (role, key) with a conflicting pq_pk
                continue;
            }
            for (String[] other : reg.values()) if (other[0].equals(ko)) return null; // one key under two roles
            reg.put((String) ro, new String[] {(String) ko, pq});
        }
        return reg;
    }

    /** The signer-set hash (base64url) of a raw signer set; null when the set is not a list of objects with string role / publicKey. */
    public static String signerSetHashB64u(Object signerSet) {
        try {
            if (!(signerSet instanceof List)) return null;
            for (Object o : (List<?>) signerSet) {
                if (!(o instanceof Map)) return null;
                Map<?, ?> m = (Map<?, ?>) o;
                if (!(m.get("role") instanceof String) || !(m.get("publicKey") instanceof String)) return null;
            }
            @SuppressWarnings("unchecked") List<Object> l = (List<Object>) signerSet;
            return Pca.b64(signerSetHash(l));
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Verify a {@code primitives.threshold_share[]}-shaped ENTRY {@code {role, t, signer_set, threshold_message, share}} of ANY JSON
     * shape. TOTAL (R6-05): anything malformed is {@code false}, never an exception. {@code t} must be exactly 1, 2 or 3.
     */
    @SuppressWarnings("unchecked")
    public static boolean verifyShareEntry(Object entry) {
        try {
            if (!(entry instanceof Map)) return false;
            Map<String, Object> e = (Map<String, Object>) entry;
            if (!(e.get("role") instanceof String)) return false;
            Integer t = exactT(e.get("t"));
            if (t == null) return false;
            if (!(e.get("signer_set") instanceof List)) return false;
            byte[] tm = Pca.decodeB64uStrict(e.get("threshold_message"), -1);
            if (tm == null) return false;
            if (!(e.get("share") instanceof Map)) return false;
            return verifyShare((String) e.get("role"), tm, (List<Object>) e.get("signer_set"), t, (Map<String, Object>) e.get("share"));
        } catch (RuntimeException ex) {
            return false;
        }
    }

    /** 1, 2 or 3 when {@code o} is a JSON number of exactly that value, else null. */
    static Integer exactT(Object o) {
        if (o instanceof Boolean || o == null) return null;
        java.math.BigDecimal d;
        try {
            if (o instanceof Json.Num || o instanceof Number) d = o instanceof Json.Num ? new java.math.BigDecimal(((Json.Num) o).raw) : new java.math.BigDecimal(o.toString());
            else return null;
        } catch (RuntimeException ex) {
            return null;
        }
        for (int t = 1; t <= 3; t++) if (d.compareTo(java.math.BigDecimal.valueOf(t)) == 0) return t;
        return null;
    }

    /**
     * Verify a single EXPLICIT threshold share by RECOMPUTING the role/set/t-bound {@link #shareMessage} from
     * the entry (never trusting a precomputed {@code share_message}) and checking {@code share.sig} over it under
     * {@code share.publicKey} (ed25519) / {@code share.pq_pk} (PQ) per {@code share.alg}. Fail-closed; never throws.
     *
     * @param role             the binding role (the threshold_share entry's {@code role})
     * @param thresholdMessage the RAW threshold message bytes (base64url-decoded {@code threshold_message})
     * @param signerSet        the signer set the share is bound into
     * @param t                the threshold (1..3)
     * @param share            {@code {role, publicKey, sig[, alg, pq_pk, pq_sig]}}
     */
    public static boolean verifyShare(String role, byte[] thresholdMessage, List<Object> signerSet, int t, Map<String, Object> share) {
        try {
            if (t < 1 || t > 3) return false; // R6-04: exactly 1, 2 or 3
            // R6-03: validate the WHOLE signer set like the reference before looking at the share.
            Map<String, String[]> reg = validatedRegistry(signerSet);
            if (reg == null) return false;
            // share.role is required and must name the verified role (reference: a share without a string role is malformed).
            if (!(share.get("role") instanceof String) || !role.equals(share.get("role"))) return false;
            // R5-A1: the share must be for the ONE key the verifier's signer set registers for `role`; the
            // share's own publicKey / pq_pk never vouch for themselves.
            String publicKey = Pca.asStr(share.get("publicKey"));
            String[] r = reg.get(role);
            if (r == null || !r[0].equals(publicKey)) return false;
            String regPq = r[1];
            boolean roleHasPq = regPq != null;
            Object shareAlg = share.get("alg");
            boolean algPresent = share.containsKey("alg");
            Pq.Suite suite = Pq.resolveSigAlg(shareAlg, algPresent);
            // A share that NAMES a pq_pk must name exactly its role's registered one (any suite; a role registering
            // none has nothing it could equal). The key used is always the registered one.
            if (share.containsKey("pq_pk") && (regPq == null || !regPq.equals(share.get("pq_pk")))) return false;
            // R6-02: a role that registers a pq_pk REQUIRES a PQ (pure or hybrid) share; an ed25519-only share
            // for it is refused (otherwise an Ed25519 break would still forge the role).
            if (roleHasPq && suite != null && "ed25519".equals(suite.alg)) return false;
            Object pqPk = share.get("pq_pk");
            if (suite == null || !"ed25519".equals(suite.alg)) {
                // PQ key = the signer set's registered pq_pk, never the share's own.
                if (regPq == null) return false;
                pqPk = regPq;
            }
            byte[] msg = shareMessage(role, thresholdMessage, signerSet, t, shareAlg, algPresent);
            return Pq.verifyLeafSuiteCallerVouched(shareAlg, algPresent, publicKey,
                pqPk, msg, share.get("sig"), share.get("pq_sig"));
        } catch (RuntimeException e) {
            return false; // fail-closed: a malformed share never counts as a valid one
        }
    }

    /** Collect shares into a threshold signature {@code {shares: [...]}} (a defensive copy; a non-list is no shares). */
    public static Map<String, Object> assembleThreshold(Object shares) {
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("shares", shares instanceof List ? new java.util.ArrayList<>((List<?>) shares) : new java.util.ArrayList<>());
        return m;
    }

    // ---- the t-of-n verifier and the threshold hook (threshold.ts verifyThreshold / createThresholdVerifier) -------------------------

    /** The role / signer-set / t / suite-bound bytes a share signs (the reference's {@code shareMessage}); {@code alg} null is the default suite. */
    public static byte[] shareMessage(String role, byte[] thresholdMessage, List<Object> signerSet, int t, Object alg) {
        return shareMessage(role, thresholdMessage, signerSet, t, alg, alg != null);
    }

    /** A role's explicit share (the reference's {@code signShare}); see {@link SignersMore#signThresholdShare}. */
    public static Map<String, Object> signShare(String role, Keys.SuiteKey signer, byte[] message, List<Object> signerSet, int t) {
        return SignersMore.signThresholdShare(role, signer, message, signerSet, t);
    }

    /** Sign already-computed share bytes; see {@link SignersMore#signPreparedShare}. */
    public static Map<String, Object> signPreparedShare(String role, Keys.SuiteKey signer, byte[] prepared) {
        return SignersMore.signPreparedShare(role, signer, prepared);
    }

    private static Map<String, Object> verdict(boolean ok, int count, List<String> roles, String reason) {
        Map<String, Object> v = new java.util.LinkedHashMap<>();
        v.put("ok", ok);
        v.put("count", count);
        v.put("roles", new ArrayList<Object>(roles));
        if (reason != null) v.put("reason", reason);
        return v;
    }

    /** Reason text for a possibly hostile value: primitives as {@code String(v)}, containers by kind only. */
    private static String show(Object v) {
        return v instanceof List ? "<array>" : v instanceof Map ? "<object>" : IntentRevocation.jsText(v, true);
    }

    private static boolean suiteHasPq(Object alg, boolean algPresent) {
        Pq.Suite s = Pq.resolveSigAlg(alg, algPresent);
        return s != null && s.needsPqPk;
    }

    /**
     * Verify a t-of-n multi-signature over {@code message} (the PCActn's {@link Pca#thresholdMessage}): {@code {ok, count, roles, reason?}}.
     *
     * <p>The signer set is validated FIRST and the whole verification fails closed if it is malformed: every role is a known role, each role
     * has exactly one registered key, no key is registered under two roles, a registered {@code pq_pk} is well formed. {@code t} must be exactly
     * 1, 2 or 3. A share counts iff its role and key are registered and its signature verifies over that role's signer-set and t-bound share
     * message (a bare agent share is rejected); the count is of DISTINCT keys. {@code baseline} ({@code {holder, sig, alg?, pq_pk?, pq_sig?,
     * holder_pq?}}) admits the PCActn leaf signature as the agent's effective-t=1 share; it never counts when it is not the agent's registered
     * key, when the agent already has an explicit share, or when a PQ leaf is not bound to the agent (a registered {@code pq_pk} or its
     * {@code holder_pq} commitment). The legacy {@code allowUnboundPq} opt-out is not offered. Total: never throws.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyThreshold(Object sig, byte[] message, Object signerSet, Object t, Map<String, Object> baseline) {
        List<String> none = new ArrayList<>();
        try {
            Integer tt = exactT(t);
            if (tt == null) return verdict(false, 0, none, "invalid threshold t=" + show(t) + " (must be 1, 2 or 3)");
            List<Object> set = signerSet instanceof List ? (List<Object>) signerSet : new ArrayList<>();
            Map<String, String> reg = new java.util.HashMap<>();
            Map<String, String> pqOf = new java.util.HashMap<>();
            Map<String, String> seen = new java.util.HashMap<>();
            for (Object o : set) {
                Map<String, Object> e = o instanceof Map ? (Map<String, Object>) o : null;
                Object ro = e == null ? null : e.get("role"), ko = e == null ? null : e.get("publicKey");
                if (!(ro instanceof String) || !ROLES.contains(ro) || !(ko instanceof String) || Pca.decodeB64uStrict(ko, 32) == null)
                    return verdict(false, 0, none, "malformed signer set");
                String role = (String) ro, key = (String) ko;
                boolean pqOk = true;
                String pq = null;
                if (e.containsKey("pq_pk")) {
                    Object po = e.get("pq_pk");
                    byte[] pb = po instanceof String ? Pca.decodeB64uStrict(po, -1) : null;
                    pqOk = pb != null && PQ_PK_LENGTHS.contains(pb.length);
                    if (po instanceof String) pq = (String) po;
                }
                if (pqOk) {
                    String id = role + "\0" + key;
                    if (seen.containsKey(id)) { if (!java.util.Objects.equals(seen.get(id), pq)) pqOk = false; }
                    else seen.put(id, pq);
                }
                if (!pqOk) return verdict(false, 0, none, "malformed signer set (pq_pk)");
                if (reg.containsKey(role) && !reg.get(role).equals(key)) return verdict(false, 0, none, "signer set registers more than one key for role " + show(role));
                for (Map.Entry<String, String> r : reg.entrySet()) if (r.getValue().equals(key) && !r.getKey().equals(role)) return verdict(false, 0, none, "signer set registers one key under two roles");
                if (!reg.containsKey(role)) { reg.put(role, key); pqOf.put(role, pq); }
            }
            Object sharesO = sig instanceof Map ? ((Map<String, Object>) sig).get("shares") : null;
            List<Object> shares = sharesO instanceof List ? (List<Object>) sharesO : new ArrayList<>();
            List<String> keys = new ArrayList<>(), roles = new ArrayList<>();
            String[] reason = {null};
            for (Object so : shares) {
                Map<String, Object> share = so instanceof Map ? (Map<String, Object>) so : null;
                Object ro = share == null ? null : share.get("role"), ko = share == null ? null : share.get("publicKey");
                if (!(ro instanceof String) || !(ko instanceof String)) { if (reason[0] == null) reason[0] = "malformed share"; continue; }
                String srole = (String) ro, spk = (String) ko;
                if (keys.contains(spk)) continue; // one key counts once
                String regKey = ROLES.contains(srole) ? reg.get(srole) : null;
                if (regKey == null) { if (reason[0] == null) reason[0] = "role " + show(srole) + " is not in the signer set"; continue; }
                if (!regKey.equals(spk)) { if (reason[0] == null) reason[0] = "share for role " + show(srole) + " uses a key not registered for that role"; continue; }
                if (!Pq.sigAlgKnown(share.get("alg"), share.containsKey("alg"))) { if (reason[0] == null) reason[0] = "share for role " + show(srole) + " declares an unknown signature alg"; continue; }
                if (share.containsKey("pq_pk") && !(share.get("pq_pk") instanceof String && share.get("pq_pk").equals(pqOf.get(srole)))) {
                    if (reason[0] == null) reason[0] = "share for role " + show(srole) + " names a pq_pk that is not the key its role registers";
                    continue;
                }
                if (!verifyShare(srole, message, set, tt, share)) { if (reason[0] == null) reason[0] = "invalid signature for role " + show(srole); continue; }
                keys.add(spk);
                roles.add(srole);
            }
            // the agent-leaf baseline (effective t=1): the PCActn leaf signature over the BARE message, admitted as the agent's share
            String agentKey = reg.get("agent");
            if (baseline != null && agentKey != null && baseline.get("holder") instanceof String && baseline.get("holder").equals(agentKey) && !keys.contains(agentKey)
                    && baselineCounts(baseline, message, agentKey, pqOf.get("agent"))) {
                keys.add(agentKey);
                roles.add("agent");
            }
            int count = keys.size();
            if (count >= tt) return verdict(true, count, roles, null);
            return verdict(false, count, roles, reason[0] != null ? reason[0] : "only " + count + " distinct valid key(s), need " + show(t));
        } catch (RuntimeException e) {
            return verdict(false, 0, none, "threshold verification error (fail closed)");
        }
    }

    private static boolean baselineCounts(Map<String, Object> b, byte[] message, String agentKey, String registeredPq) {
        Object alg = b.get("alg");
        boolean algPresent = b.containsKey("alg");
        if (registeredPq == null && Pca.pqBindingError(alg, algPresent, b.get("pq_pk"), b.get("holder_pq"), "threshold baseline") != null) return false;
        if (registeredPq != null && !suiteHasPq(alg, algPresent)) return false; // an agent that registers a PQ key needs a PQ / hybrid leaf
        Pq.PinnedPq key = registeredPq != null ? Pq.resolvePqKey(agentKey, null, null, null, registeredPq) : Pq.resolvePqKey(agentKey, b.get("pq_pk"), b.get("holder_pq"), null, null);
        return Pq.verifyLeafSuite(alg, algPresent, agentKey, key, message, b.get("sig"), b.get("pq_sig"));
    }

    /**
     * The {@code threshold} hook of the verifier (the reference's {@code createThresholdVerifier}). Given a PCActn it recomputes the signed
     * threshold message, verifies the explicit shares in {@code pcactn.threshold}, admits the PCActn's own leaf signature as the agent's
     * effective-t=1 baseline and returns an ENFORCED pass or fail that reports the {@code t} it enforced, so the server verifier can refuse a hook
     * that enforced less than its own decision. Exactly one of {@code t} (fixed by the server) and {@code requiredT} (derived from SERVER-held data
     * only; never from the PCActn's {@code risk_claim}, which is the agent's own claim) is mandatory. {@code scheme} labels how the signer keys
     * are held: {@code multisig} (default), {@code frost}, {@code frost_dkg} or {@code mpc} (the last three are reported as awaiting audit).
     */
    public static PcaCore.Hook createThresholdVerifier(List<Object> signerSet, Integer t, java.util.function.Function<PcaCore.Ctx, Integer> requiredT, String scheme) {
        if (requiredT == null && t == null)
            throw new IllegalArgumentException("createThresholdVerifier: supply `t` or `requiredT` derived from SERVER-held data. The risk_claim.r-derived default was removed (F-1): it is the agent's own claim.");
        final List<Object> set = new ArrayList<>();
        if (signerSet != null) for (Object o : signerSet) set.add(o instanceof Map ? new java.util.LinkedHashMap<>((Map<?, ?>) o) : o); // a snapshot: later edits by the caller change nothing
        final String sch = scheme == null ? "multisig" : scheme;
        final java.util.function.Function<PcaCore.Ctx, Integer> resolve = requiredT != null ? requiredT : c -> t;
        PcaCore.Hook hook = ctx -> {
            Map<String, Object> p = ctx.pcactn;
            byte[] message = Pca.thresholdMessage(p);
            Object thr = p.get("threshold");
            Object explicit = thr instanceof Map && ((Map<?, ?>) thr).get("shares") instanceof List ? ((Map<?, ?>) thr).get("shares") : new ArrayList<Object>();
            Object chain = p.get("cap_chain");
            Object leaf = chain instanceof List && !((List<?>) chain).isEmpty() ? ((List<?>) chain).get(((List<?>) chain).size() - 1) : null;
            Map<String, Object> baseline = null;
            if (leaf instanceof Map && ((Map<?, ?>) leaf).get("holder") instanceof String && p.get("sig") instanceof String) {
                baseline = new java.util.LinkedHashMap<>();
                baseline.put("holder", ((Map<?, ?>) leaf).get("holder"));
                baseline.put("sig", p.get("sig"));
                for (String k : new String[] {"alg", "pq_pk", "pq_sig"}) if (p.containsKey(k)) baseline.put(k, p.get(k));
                if (((Map<?, ?>) leaf).containsKey("holder_pq")) baseline.put("holder_pq", ((Map<?, ?>) leaf).get("holder_pq"));
            }
            Integer want = resolve.apply(ctx);
            Map<String, Object> shares = new java.util.LinkedHashMap<>();
            shares.put("shares", explicit);
            Map<String, Object> v = verifyThreshold(shares, message, set, want, baseline);
            Double tt = want == null ? null : Double.valueOf(want);
            if (Boolean.TRUE.equals(v.get("ok"))) return PcaCore.HookResult.enforced(true, null, tt);
            return PcaCore.HookResult.enforced(false, v.get("reason") instanceof String ? (String) v.get("reason") : "threshold not met", tt);
        };
        return Assurance.setLabel(hook, Assurance.Label.of(sch).awaitingAudit(Assurance.isAwaitingAuditScheme(sch)));
    }

    /** {@link #createThresholdVerifier} with a fixed {@code t} and the default {@code multisig} scheme. */
    public static PcaCore.Hook createThresholdVerifier(List<Object> signerSet, int t) { return createThresholdVerifier(signerSet, t, null, null); }
}
