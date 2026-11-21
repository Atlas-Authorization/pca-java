package net.atlasauth.pca.pqthreshold;

import static net.atlasauth.pca.pqthreshold.GroupDescriptor.isInteger;
import static net.atlasauth.pca.pqthreshold.GroupDescriptor.member;
import static net.atlasauth.pca.pqthreshold.GroupDescriptor.numOf;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Pq;
import net.atlasauth.pca.W3Bridge;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

/**
 * Post-quantum threshold step-up for PCActn: a hybrid of a classical FROST(Ed25519) aggregate (verified as the plain Ed25519 signature it is, under
 * the verifier's pinned group key, with the threshold bound by a signed {@link GroupDescriptor}) AND a pqT-of-m ML-DSA-65 co-signature quorum
 * over the same action digest. Both must hold; either short fails closed.
 *
 * <p>Scope of this port: the verifier side and the quorum signer. The FROST signing protocol (dealer, nonces, cosign) lives in a FROST
 * implementation this SDK does not carry yet, so {@link #hybridThresholdAssemble} takes an aggregate produced elsewhere and refuses one that does not
 * verify. The research lattice-threshold prototype in the reference is intentionally not ported (it is labelled not-for-production).
 */
public final class PqThreshold {
    private PqThreshold() {}

    public static final int HYBRID_ARTIFACT_VERSION = 2, PQ_QUORUM_VERSION = 2, MAX_PQ_QUORUM_ENTRIES = 256;
    public static final String HYBRID_CLASSICAL_ALG = "frost-ed25519", PQ_QUORUM_ALG = "ml-dsa-65";
    /** The post-quantum half of a hybrid artifact: the quorum algorithm. */
    public static final String HYBRID_PQ_ALG = PQ_QUORUM_ALG;
    /** The most PQ co-signer entries a hybrid artifact carries. */
    public static final int MAX_PQ_SIGNER_ENTRIES = MAX_PQ_QUORUM_ENTRIES;
    private static final byte[] PQ_QUORUM_DOMAIN = "atlas-pca/pq-quorum/v2\0".getBytes(StandardCharsets.UTF_8);

    private static byte[] sha256(byte[] b) {
        try { return MessageDigest.getInstance("SHA-256").digest(b); } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    /** The quorum verdict: {@code need} is the pqT as given, a JSON null included. */
    private static Map<String, Object> quorumVerdict(boolean ok, Object count, Object need, String reason) {
        Map<String, Object> m = verdict(ok, count, need, reason);
        m.put("need", need);
        return m;
    }

    private static Map<String, Object> verdict(boolean ok, Object count, Object need, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok); m.put("count", count);
        if (need != null) m.put("need", need);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    /** The bytes every quorum co-signature covers: DOMAIN || sha256(message). */
    public static byte[] pqQuorumRepresentative(byte[] message) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.writeBytes(PQ_QUORUM_DOMAIN);
        o.writeBytes(sha256(message));
        return o.toByteArray();
    }

    /** The trusted pool as canonical b64u strings (String or byte[] entries); anything that is not a well-formed ML-DSA-65 public key is ignored. */
    public static Set<String> normalizePqQuorumPool(List<?> pks) {
        Set<String> pool = new LinkedHashSet<>();
        for (Object p : pks) {
            String s = GroupDescriptor.asB64u(p);
            if (s != null && Pca.decodeB64uStrict(s, Pq.ML_DSA_65_PUBLIC_KEY_BYTES) != null) pool.add(s);
        }
        return pool;
    }

    private static boolean mlDsa65VerifyB64u(Object pk, byte[] msg, Object sig) {
        byte[] p = Pca.decodeB64uStrict(pk, Pq.ML_DSA_65_PUBLIC_KEY_BYTES), s = Pca.decodeB64uStrict(sig, Pq.ML_DSA_65_SIGNATURE_BYTES);
        return p != null && s != null && Pq.mlDsa65Verify(p, msg, s);
    }

    /** An ML-DSA-65 co-signer key pair (FIPS 204 encodings). */
    public static final class MlDsaKeyPair {
        public final byte[] publicKey, secretKey;
        public MlDsaKeyPair(byte[] publicKey, byte[] secretKey) { this.publicKey = publicKey; this.secretKey = secretKey; }
    }

    private static byte[] mlDsa65Sign(byte[] sk, byte[] msg) {
        MLDSASigner s = new MLDSASigner(); // pure ML-DSA, empty context
        s.init(true, new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, sk));
        s.update(msg, 0, msg.length);
        try { return s.generateSignature(); } catch (CryptoException e) { throw new IllegalStateException(e); }
    }

    /** One ML-DSA-65 co-signature per key pair over the representative; pqT defaults to the signer count. */
    public static Map<String, Object> signPqQuorum(byte[] message, List<MlDsaKeyPair> keyPairs, Integer pqT) {
        byte[] rep = pqQuorumRepresentative(message);
        List<Object> signers = new ArrayList<>();
        for (MlDsaKeyPair k : keyPairs) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("pk", Keys.b64u(k.publicKey)); e.put("sig", Keys.b64u(mlDsa65Sign(k.secretKey, rep)));
            signers.add(e);
        }
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("v", (long) PQ_QUORUM_VERSION); b.put("alg", PQ_QUORUM_ALG); b.put("pqT", (long) (pqT != null ? pqT : signers.size())); b.put("signers", signers);
        return b;
    }

    /**
     * Count DISTINCT trusted keys whose co-signature verifies over {@code message}; ok iff the count reaches {@code pqT}. Total: never throws. A key outside
     * the pool, a repeated key, a signature over another message and every malformed entry count for nothing; a block whose version is missing (pre-0.5),
     * 1 or unknown is refused before any verification. Returns {ok, count, need, reason?}.
     */
    public static Map<String, Object> verifyPqQuorum(Object block, byte[] message, Set<String> trustedPool, Object pqT) {
        if (!isInteger(pqT) || numOf(pqT) < 1) return quorumVerdict(false, 0L, pqT, "pqT must be a positive integer");
        if (!GroupDescriptor.isObject(block)) return quorumVerdict(false, 0L, pqT, "malformed pq block");
        Map<?, ?> b = block instanceof Map ? (Map<?, ?>) block : Map.of();
        if (!b.containsKey("v")) return quorumVerdict(false, 0L, pqT, "pq quorum version missing (pre-0.5 format is refused)");
        Double v = numOf(b.get("v"));
        if (v != null && v == 1) return quorumVerdict(false, 0L, pqT, "pq quorum version 1 is no longer accepted (pre-0.5 format)");
        if (v == null || v != PQ_QUORUM_VERSION) return quorumVerdict(false, 0L, pqT, "unsupported pq quorum version");
        if (!PQ_QUORUM_ALG.equals(b.get("alg")) || !(b.get("signers") instanceof List)) return quorumVerdict(false, 0L, pqT, "malformed pq block");
        byte[] rep = pqQuorumRepresentative(message);
        Set<String> counted = new HashSet<>();
        int seen = 0;
        for (Object entry : (List<?>) b.get("signers")) {
            if (seen++ >= MAX_PQ_QUORUM_ENTRIES) break;
            Object pk = member(entry, "pk"), sig = member(entry, "sig");
            if (!(pk instanceof String) || !(sig instanceof String)) continue;
            if (!trustedPool.contains(pk) || counted.contains(pk)) continue;
            if (!mlDsa65VerifyB64u(pk, rep, sig)) continue;
            counted.add((String) pk);
        }
        long count = counted.size();
        if (count >= numOf(pqT)) return quorumVerdict(true, count, pqT, null);
        return quorumVerdict(false, count, pqT, "post-quantum quorum short: " + count + " of " + pqT + " required ML-DSA co-signatures");
    }

    // ---- hybrid ----------------------------------------------------------------------------------------------------

    private static String normalizeGroupKeyB64u(Object k) {
        String s = GroupDescriptor.asB64u(k);
        return s != null && Pca.decodeB64uStrict(s, 32) != null ? s : null;
    }

    /** The FROST aggregate is a plain strict Ed25519 signature under the TRUSTED group key (never one the artifact declares). */
    private static boolean verifyFrostAggregate(Object sig, byte[] message, String trustedGroupKey) {
        return sig instanceof String && W3Bridge.verifyB64u(trustedGroupKey, message, (String) sig);
    }

    /** Options for {@link #verifyHybridThreshold}; every field is a wire/config value as parsed JSON (keys may be String or byte[]). */
    public static final class HybridVerifyOpts {
        public Object groupKey, pqPublicKeys, t, pqT, groupDescriptor, trustedAuthorities;
        public String signerSetCommitment;
    }

    private static Map<String, Object> malformed() {
        String reason = "malformed action or verifier options";
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false); m.put("frost", false); m.put("pq", verdict(false, 0L, 0L, reason)); m.put("reason", reason);
        return m;
    }

    /**
     * Verify a standalone hybrid artifact over {@code action} (a PCActn or body as a JSON object). BOTH the classical aggregate and the pqT-of-m
     * quorum must hold; the declared classical threshold must not be below the required t (downgrade). Never throws: malformed input is a refusal.
     * Returns {ok, frost, pq, reason?}.
     */
    public static Map<String, Object> verifyHybridThreshold(Map<String, Object> action, Object artifact, HybridVerifyOpts opts) {
        try {
            return verifyInner(action, artifact, opts);
        } catch (RuntimeException e) {
            return malformed();
        }
    }

    private static Map<String, Object> verifyInner(Map<String, Object> action, Object artifact, HybridVerifyOpts opts) {
        boolean hasV = artifact instanceof Map && ((Map<?, ?>) artifact).containsKey("v");
        Object version = member(artifact, "v");
        Double vn = numOf(version);
        if (!hasV || vn == null || vn != HYBRID_ARTIFACT_VERSION) {
            String reason = !hasV ? "artifact version missing (pre-0.5 format is refused)" : vn != null && vn == 1 ? "artifact version 1 is no longer accepted (pre-0.5 format)" : "unsupported artifact version";
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", false); m.put("frost", false); m.put("pq", verdict(false, 0L, opts.pqT, reason)); m.put("reason", reason);
            return m;
        }
        byte[] message = Pca.thresholdMessage(action);
        String trustedGroupKey = normalizeGroupKeyB64u(opts.groupKey);
        if (!(opts.pqPublicKeys instanceof List)) throw new IllegalArgumentException("pqPublicKeys is not iterable");
        Set<String> pool = normalizePqQuorumPool((List<?>) opts.pqPublicKeys);

        boolean frostOk = false;
        String frostReason = null;
        Map<String, Object> dr = GroupDescriptor.verifyGroupDescriptor(opts.groupDescriptor, opts.trustedAuthorities, opts.groupKey, opts.t, opts.signerSetCommitment);
        String descriptorReason = Boolean.TRUE.equals(dr.get("ok")) ? null : (String) dr.get("reason");
        Object frost = member(artifact, "frost");
        if (!isInteger(opts.t) || numOf(opts.t) < 1) {
            frostReason = "t must be a positive integer";
        } else if (trustedGroupKey == null) {
            frostReason = "trusted FROST group key is not a canonical b64u(32) point";
        } else if (!GroupDescriptor.isObject(frost) || !HYBRID_CLASSICAL_ALG.equals(member(frost, "alg"))) {
            frostReason = "malformed or missing FROST part";
        } else if (descriptorReason != null) {
            frostReason = descriptorReason;
        } else if (!isInteger(member(frost, "t")) || numOf(member(frost, "t")) < numOf(opts.t)) {
            frostReason = "FROST declared threshold " + GroupDescriptorFmt.show(member(frost, "t")) + " is below the required t=" + GroupDescriptorFmt.show(opts.t) + " (downgrade)";
        } else if (!verifyFrostAggregate(member(frost, "sig"), message, trustedGroupKey)) {
            frostReason = "FROST aggregate does not verify under the trusted group key (quorum short, wrong group, or forged)";
        } else {
            frostOk = true;
        }
        Map<String, Object> pq = verifyPqQuorum(member(artifact, "pq"), message, pool, opts.pqT);
        if (opts.pqT == null) pq.remove("need"); // an undefined pqT is dropped from the verdict (only a JSON null is kept)
        boolean ok = frostOk && Boolean.TRUE.equals(pq.get("ok"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", ok); out.put("frost", frostOk); out.put("pq", pq);
        if (!ok) { Object r = frostOk ? pq.get("reason") : frostReason; if (r != null) out.put("reason", r); }
        return out;
    }

    /**
     * Assemble a hybrid artifact from a FROST aggregate produced by a FROST implementation (the signing protocol is not carried here) and the ML-DSA co-signers.
     * Fails closed: a sub-threshold quorum count, no co-signer, a non-canonical group key, or an aggregate that does not verify under the group key all throw.
     */
    public static Map<String, Object> hybridThresholdAssemble(Map<String, Object> action, byte[] groupPublicKey, byte[] frostAggregate, int t, int quorum, List<MlDsaKeyPair> pqSigners, Integer pqT) {
        if (t < 1) throw new IllegalArgumentException("hybridThresholdAssemble: t must be a positive integer (got " + t + ")");
        if (quorum < t) throw new IllegalArgumentException("hybridThresholdAssemble: FROST quorum of " + quorum + " is below the threshold t=" + t);
        if (pqSigners.isEmpty()) throw new IllegalArgumentException("hybridThresholdAssemble: at least one ML-DSA co-signer is required");
        if (groupPublicKey == null || groupPublicKey.length != 32) throw new IllegalArgumentException("hybridThresholdAssemble: FROST group public key must be 32 bytes");
        byte[] message = Pca.thresholdMessage(action);
        if (frostAggregate == null || !W3Bridge.verifyB64u(Keys.b64u(groupPublicKey), message, Keys.b64u(frostAggregate))) {
            throw new IllegalArgumentException("hybridThresholdAssemble: the FROST aggregate does not verify under the group key");
        }
        Map<String, Object> frost = new LinkedHashMap<>();
        frost.put("alg", HYBRID_CLASSICAL_ALG); frost.put("group_pk", Keys.b64u(groupPublicKey)); frost.put("sig", Keys.b64u(frostAggregate)); frost.put("t", (long) t); frost.put("quorum", (long) quorum);
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("v", (long) HYBRID_ARTIFACT_VERSION); a.put("digest", Keys.b64u(sha256(message))); a.put("frost", frost); a.put("pq", signPqQuorum(message, pqSigners, pqT));
        return a;
    }

    /** Number printing for reasons (JavaScript style: integers without a fraction). */
    private static final class GroupDescriptorFmt {
        static String show(Object o) {
            Double d = numOf(o);
            if (d == null) return String.valueOf(o);
            return d == Math.floor(d) && Math.abs(d) < 1e21 ? new java.math.BigDecimal(d).toBigInteger().toString() : String.valueOf(d);
        }
    }
}
