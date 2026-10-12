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

    static final String SIGNER_SET_DOMAIN = "atlas-pca/signerset/v1\0";
    /** Domain-separated suite tag appended for a NON-default suite; ed25519 / absent / unknown => empty. */
    static final String SHARE_SUITE_TAG = "\0atlas-pca/share-suite/v1\0";
    /** Version marker for the v2.1 agent-leaf share binding (matches {@code vectors.json.agent_leaf_binding}). */
    public static final String AGENT_LEAF_SHARE_BINDING_VERSION = "2.1";

    private static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }

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
}
