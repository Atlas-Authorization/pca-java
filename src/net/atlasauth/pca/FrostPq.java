package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Frost.FrostParticipantShare;

/**
 * Post-quantum layer of the networked FROST group: the group-algorithm registry ({@code ed25519} or the hybrid with a guardian
 * ML-DSA-65 co-signature), the signer-set digest and co-sign representative the guardian signs, and the PQ quorum block (t ML-DSA-65
 * signatures by distinct pooled keys over a domain-separated digest of the message). Values are JSON-shaped maps and lists.
 */
public final class FrostPq {
    private FrostPq() {}

    public static final String DEFAULT_FROST_GROUP_ALG = "ed25519";
    public static final String HYBRID_FROST_GROUP_ALG = "hybrid-ed25519-ml-dsa-65";
    public static final int PQ_QUORUM_VERSION = 2;
    public static final String PQ_QUORUM_ALG = "ml-dsa-65";
    public static final int MAX_PQ_QUORUM_ENTRIES = 256;
    private static final String FROST_COSIGN_DOMAIN = "atlas-pca/frost-pq-cosign/v1\0";
    private static final String FROST_SIGNER_SET_DOMAIN = "atlas-pca/frost-signer-set/v1\0";
    private static final String PQ_QUORUM_DOMAIN = "atlas-pca/pq-quorum/v2\0";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static boolean isKnown(Object x) { return DEFAULT_FROST_GROUP_ALG.equals(x) || HYBRID_FROST_GROUP_ALG.equals(x); }

    /** The default algorithm for an absent value. */
    public static String resolveFrostGroupAlg() { return DEFAULT_FROST_GROUP_ALG; }

    /** The algorithm itself when it is registered, else null (an unknown value never resolves to a default). */
    public static String resolveFrostGroupAlg(Object groupAlg) { return isKnown(groupAlg) ? (String) groupAlg : null; }

    private static Map<String, Object> mapOf(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** sha256 of a domain tag and the canonical sorted, de-duplicated signer identifiers. */
    public static byte[] frostSignerSetDigest(Object signerSet) {
        if (!(signerSet instanceof List) || ((List<?>) signerSet).isEmpty()) throw new IllegalArgumentException("frostSignerSetDigest: empty signer set");
        Set<Double> seen = new LinkedHashSet<>();
        for (Object id : (List<?>) signerSet) {
            Double d = IntentJs.num(id);
            if (d == null) throw new IllegalArgumentException("frostSignerSetDigest: participant identifiers must be positive safe integers");
            seen.add(d == 0.0 ? 0.0 : d);
        }
        List<Double> ids = new ArrayList<>(seen);
        for (Double d : ids) {
            if (!IntentJs.isSafeInteger(d) || d <= 0) throw new IllegalArgumentException("frostSignerSetDigest: participant identifiers must be positive safe integers");
        }
        ids.sort(Double::compare);
        List<Object> canon = new ArrayList<>();
        for (Double d : ids) canon.add((long) (double) d);
        return Pca.sha(Pca.concat(Json.utf8(FROST_SIGNER_SET_DOMAIN), Pca.canonBytes(canon)));
    }

    /** The bytes the guardian signs: domain, algorithm label, group key, sha256(message), signer-set digest. */
    public static byte[] frostCosignRepresentative(Object groupPublicKeyB64u, byte[] message, Object signerSet, Object groupAlg) {
        byte[] gpk = Pca.decodeB64uStrict(groupPublicKeyB64u, 32);
        if (gpk == null) throw new IllegalArgumentException("frostCosignRepresentative: groupPublicKey must be a 32-byte base64url point");
        if (message == null) throw new IllegalArgumentException("Uint8Array expected");
        return Pca.concat(Json.utf8(FROST_COSIGN_DOMAIN), Json.utf8(AttestNvidia.jsString(groupAlg)), new byte[] {0}, gpk, Pca.sha(message), frostSignerSetDigest(signerSet));
    }

    /**
     * Sign with a quorum in-process and, for the hybrid algorithm, add the guardian ML-DSA-65 co-signature. {@code opts}: groupAlg
     * (absent or null is ed25519), guardianMlDsa ({@link Pq.KeyPair}), threshold. Returns {sig, groupAlg?, pq_sig?, pq_pk?}.
     */
    public static Map<String, Object> signHybridFrostCosign(byte[] groupPublicKey, List<FrostParticipantShare> quorum, byte[] message, Map<String, Object> opts) {
        Object alg = opts.get("groupAlg") != null ? opts.get("groupAlg") : DEFAULT_FROST_GROUP_ALG;
        if (!isKnown(alg)) throw new IllegalArgumentException("signHybridFrostCosign: unknown groupAlg '" + AttestNvidia.jsString(alg) + "'");
        Object thr = opts.get("threshold");
        byte[] aggregate = Frost.cosign(groupPublicKey, quorum, message, thr == null ? null : (Integer) (int) IntentJs.lng(thr));
        String sig = Pca.b64(aggregate);
        if (DEFAULT_FROST_GROUP_ALG.equals(alg)) return mapOf("sig", sig);
        Object g = opts.get("guardianMlDsa");
        if (!(g instanceof Pq.KeyPair)) throw new IllegalArgumentException("signHybridFrostCosign: '" + alg + "' requires a guardian ML-DSA-65 key pair");
        Pq.KeyPair kp = (Pq.KeyPair) g;
        List<Object> ids = new ArrayList<>();
        for (FrostParticipantShare p : quorum) ids.add(p.identifier);
        byte[] rep = frostCosignRepresentative(Pca.b64(groupPublicKey), message, ids, alg);
        return mapOf("sig", sig, "groupAlg", alg, "pq_sig", Pca.b64(Pq.mlDsa65Sign(kp.secretKey, rep)), "pq_pk", Pca.b64(kp.publicKey));
    }

    private static Map<String, Object> deny(String reason, Object groupAlg) {
        Map<String, Object> m = mapOf("ok", false, "edOk", false, "pqOk", false);
        if (groupAlg != null) m.put("groupAlg", groupAlg);
        m.put("reason", reason);
        return m;
    }

    /**
     * Verify a hybrid FROST artifact: the Ed25519 group signature, and for the hybrid algorithm a guardian ML-DSA-65 co-signature
     * by a REGISTERED key over the representative. {@code opts}: guardianPqPublicKey, expectGroupAlg (no downgrade).
     */
    public static Map<String, Object> verifyHybridFrostCosign(Object artifactO, byte[] message, Object groupPublicKeyB64u, Object signerSet, Map<String, Object> opts) {
        Map<String, Object> artifact = obj(artifactO);
        if (artifact == null || !(artifact.get("sig") instanceof String)) return deny("malformed artifact", null);
        if (!(groupPublicKeyB64u instanceof String) || Pca.decodeB64uStrict(groupPublicKeyB64u, 32) == null) return deny("malformed group public key", null);
        String gpk = (String) groupPublicKeyB64u;

        Object declared = artifact.containsKey("groupAlg") ? artifact.get("groupAlg") : DEFAULT_FROST_GROUP_ALG;
        if (!isKnown(declared)) return deny("unknown groupAlg '" + AttestNvidia.jsString(declared) + "'", null);
        String groupAlg = (String) declared;
        if (opts.containsKey("expectGroupAlg")) {
            Object want = opts.get("expectGroupAlg");
            if (!isKnown(want)) return deny("unknown expected groupAlg '" + AttestNvidia.jsString(want) + "'", null);
            if (!want.equals(groupAlg)) return deny("groupAlg '" + groupAlg + "' does not match the required '" + want + "'", groupAlg);
        }

        boolean edOk;
        try { edOk = Pca.verifyB64u(gpk, message, (String) artifact.get("sig")); } catch (RuntimeException e) { edOk = false; }

        if (DEFAULT_FROST_GROUP_ALG.equals(groupAlg)) {
            if (!edOk) return deny("FROST Ed25519 group signature did not verify", groupAlg);
            return mapOf("ok", true, "groupAlg", groupAlg, "edOk", true, "pqOk", false);
        }

        Object registered = opts.get("guardianPqPublicKey");
        if (!(registered instanceof String) || Pca.decodeB64uStrict(registered, Pq.ML_DSA_65_PUBLIC_KEY_BYTES) == null) {
            return deny("hybrid groupAlg requires a registered guardian ML-DSA-65 public key", groupAlg);
        }
        if (artifact.containsKey("pq_pk") && !registered.equals(artifact.get("pq_pk"))) return deny("artifact pq_pk does not match the registered guardian ML-DSA key", groupAlg);
        if (!(artifact.get("pq_sig") instanceof String)) return deny("hybrid groupAlg declared but the guardian ML-DSA co-signature is missing", groupAlg);

        boolean pqOk;
        try {
            byte[] rep = frostCosignRepresentative(gpk, message, signerSet, groupAlg);
            pqOk = Pq.mlDsa65VerifyB64u(registered, rep, artifact.get("pq_sig"));
        } catch (RuntimeException e) {
            pqOk = false;
        }
        if (!edOk || !pqOk) {
            return mapOf("ok", false, "groupAlg", groupAlg, "edOk", edOk, "pqOk", pqOk,
                "reason", !edOk ? "FROST Ed25519 group signature did not verify" : "guardian ML-DSA-65 co-signature did not verify");
        }
        return mapOf("ok", true, "groupAlg", groupAlg, "edOk", true, "pqOk", true);
    }

    // ---- PQ quorum block -------------------------------------------------------------------------------------------

    /** The bytes every quorum member signs: a domain tag and sha256(message). */
    public static byte[] pqQuorumRepresentative(byte[] message) {
        if (message == null) throw new IllegalArgumentException("Uint8Array expected");
        return Pca.concat(Json.utf8(PQ_QUORUM_DOMAIN), Pca.sha(message));
    }

    /** One ML-DSA-65 signature per key pair over the representative; pqT defaults to the signer count (informational). */
    public static Map<String, Object> signPqQuorum(byte[] message, List<Pq.KeyPair> keyPairs, Object pqT) {
        byte[] rep = pqQuorumRepresentative(message);
        List<Object> signers = new ArrayList<>();
        for (Pq.KeyPair k : keyPairs) signers.add(mapOf("pk", Pca.b64(k.publicKey), "sig", Pca.b64(Pq.mlDsa65Sign(k.secretKey, rep))));
        return mapOf("v", PQ_QUORUM_VERSION, "alg", PQ_QUORUM_ALG, "pqT", pqT != null ? pqT : (Object) signers.size(), "signers", signers);
    }

    /** The trusted pool as canonical base64url ML-DSA-65 public keys: bytes are encoded, anything malformed is dropped. */
    public static Set<String> normalizePqQuorumPool(List<Object> pks) {
        Set<String> pool = new LinkedHashSet<>();
        for (Object p : pks) {
            Object s = p instanceof byte[] ? Pca.b64((byte[]) p) : p;
            if (s instanceof String && Pca.decodeB64uStrict(s, Pq.ML_DSA_65_PUBLIC_KEY_BYTES) != null) pool.add((String) s);
        }
        return pool;
    }

    private static Map<String, Object> no(String reason, Object need) { return mapOf("ok", false, "count", 0, "need", need, "reason", reason); }

    /** Count the distinct trusted keys whose ML-DSA-65 signature over the representative verifies; at least {@code pqT} are required. */
    public static Map<String, Object> verifyPqQuorum(Object block, byte[] message, Set<String> trustedPool, Object pqT) {
        if (!IntentJs.isSafeInteger(pqT) || IntentJs.num(pqT) < 1) return no("pqT must be a positive integer", pqT);
        Map<String, Object> b = obj(block);
        if (b == null && !(block instanceof List)) return no("malformed pq block", pqT);
        if (b == null) b = new LinkedHashMap<>();
        Object v = b.get("v");
        if (!b.containsKey("v")) return no("pq quorum version missing (pre-0.5 format is refused)", pqT);
        Double vn = IntentJs.num(v);
        if (vn != null && vn == 1.0) return no("pq quorum version 1 is no longer accepted (pre-0.5 format)", pqT);
        if (vn == null || vn != (double) PQ_QUORUM_VERSION) return no("unsupported pq quorum version", pqT);
        if (!PQ_QUORUM_ALG.equals(b.get("alg")) || !(b.get("signers") instanceof List)) return no("malformed pq block", pqT);
        byte[] rep = pqQuorumRepresentative(message);
        Set<String> counted = new HashSet<>();
        List<?> signers = (List<?>) b.get("signers");
        for (Object entry : signers.subList(0, Math.min(signers.size(), MAX_PQ_QUORUM_ENTRIES))) {
            Map<String, Object> s = obj(entry);
            if (s == null || !(s.get("pk") instanceof String) || !(s.get("sig") instanceof String)) continue;
            String pk = (String) s.get("pk");
            if (!trustedPool.contains(pk) || counted.contains(pk)) continue;
            if (!Pq.mlDsa65VerifyB64u(pk, rep, s.get("sig"))) continue;
            counted.add(pk);
        }
        int count = counted.size();
        long need = IntentJs.lng(pqT);
        if (count >= need) return mapOf("ok", true, "count", count, "need", pqT);
        return mapOf("ok", false, "count", count, "need", pqT, "reason", "post-quantum quorum short: " + count + " of " + AttestNvidia.jsString(pqT) + " required ML-DSA co-signatures");
    }
}
