package net.atlasauth.pca.ratchet;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.EdStrict;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * Verifier-side bindings that the stateless primitives cannot give on their own: a spent-leaf store so a SECOND signature at the same leaf is
 * detected (replay) and a different message at the same leaf is flagged as equivocation, and action-bound risk commitments, created by the party
 * that COMPUTES the risk and signed together with the action digest, so a prover cannot commit 0 for a 1.0-risk action or move a commitment
 * between actions.
 */
public final class Binding {
    private Binding() {}

    /** The outcome of a {@link SpentLeafStore#claim}: first claim, or the record stored earlier. */
    public static final class Claim {
        public final boolean first;
        public final String record;

        private Claim(boolean first, String record) {
            this.first = first;
            this.record = record;
        }

        public static Claim first() { return new Claim(true, null); }

        public static Claim seen(String record) { return new Claim(false, record); }
    }

    /** Atomic first-claim store keyed by leaf nullifier. */
    public interface SpentLeafStore {
        /** Atomically record {@code record} under {@code nullifier} if absent; return {@link Claim#first()} or the earlier record. */
        Claim claim(String nullifier, String record);
    }

    /** In-process {@link SpentLeafStore}. Per process: use a shared store for a verifier fleet. */
    public static SpentLeafStore memorySpentLeafStore() {
        Map<String, String> seen = new java.util.HashMap<>();
        return (nullifier, record) -> {
            synchronized (seen) {
                String prev = seen.get(nullifier);
                if (prev != null) return Claim.seen(prev);
                seen.put(nullifier, record);
                return Claim.first();
            }
        };
    }

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, Object> result(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    private static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        return o instanceof Number ? Double.valueOf(((Number) o).doubleValue()) : null;
    }

    /**
     * Verify a leaf signature AND enforce one-time use at the verifier: the first valid signature at a leaf is accepted and its message digest
     * recorded; a later signature at that leaf is refused as {@code replay} (same message) or {@code equivocation} (a different message: the
     * evidence of a holder that kept an old state). Fail closed: a store that throws denies. Returns {@code {ok}} or {@code {ok: false, reason, ...}}.
     */
    public static Map<String, Object> verifyLeafSignatureOnce(String rootCommitment, Object leafIndex, byte[] message, Object signature, SpentLeafStore store) {
        if (!Ratchet.verifyLeafSignature(rootCommitment, leafIndex, message, signature)) return result("ok", false, "reason", "invalid");
        String nullifier = Ratchet.leafNullifier(rootCommitment, leafIndex);
        String idx = ((Json.Num) IntentJs.normalize(Double.valueOf(num(leafIndex)))).raw;
        String mine = Keys.b64u(sha256(message)) + "@" + idx;
        try {
            Claim r = store.claim(nullifier, mine);
            if (r.first) return result("ok", true);
            if (mine.equals(r.record)) return result("ok", false, "reason", "replay", "nullifier", nullifier);
            return result("ok", false, "reason", "equivocation", "nullifier", nullifier, "firstMessageDigest", r.record, "secondMessageDigest", mine);
        } catch (RuntimeException e) {
            return result("ok", false, "reason", "store-error");
        }
    }

    private static final byte[] ATTEST_DOMAIN = "atlas-pca-ratchet/risk-attestation/v1\0".getBytes(StandardCharsets.UTF_8);

    private static byte[] attestMessage(String actionDigest, String commitment) {
        byte[] a = Json.utf8(actionDigest);
        byte[] c = Json.utf8(commitment);
        ByteBuffer out = ByteBuffer.allocate(ATTEST_DOMAIN.length + 4 + a.length + 4 + c.length);
        out.put(ATTEST_DOMAIN).putInt(a.length).put(a).putInt(c.length).put(c);
        return out.array();
    }

    /** What {@link #issueRiskCommitment} returns; hand {@code blinding} privately to the prover, publish the rest. */
    public static final class Issued {
        public final String commitment;
        public final BigInteger blinding;
        public final Map<String, Object> rangeProof;
        /** {@code {actionDigest, sig}}. */
        public final Map<String, Object> attestation;

        Issued(String commitment, BigInteger blinding, Map<String, Object> rangeProof, Map<String, Object> attestation) {
            this.commitment = commitment;
            this.blinding = blinding;
            this.rangeProof = rangeProof;
            this.attestation = attestation;
        }
    }

    /**
     * RISK AUTHORITY side: commit to the risk it computed for {@code actionDigest}, prove the range, and sign (actionDigest, commitment) with the
     * authority's 32-byte Ed25519 secret.
     */
    public static Issued issueRiskCommitment(Object risk, String actionDigest, byte[] authoritySecretKey) {
        Accumulator.RiskCommitment c = Accumulator.commitRisk(risk, null);
        Map<String, Object> rangeProof = Accumulator.proveRiskRange(risk, c.blinding);
        String sig = Keys.b64u(Keys.edFromSeed(authoritySecretKey).sign(attestMessage(actionDigest, c.commitment)));
        return new Issued(c.commitment, c.blinding, rangeProof, result("actionDigest", actionDigest, "sig", sig));
    }

    /** Verify one attestation against the risk authority's public key (b64u). Never throws. */
    public static boolean verifyRiskAttestation(Object commitment, Object attestation, Object authorityPublicKey) {
        try {
            if (!(attestation instanceof Map)) return false;
            Object ad = ((Map<?, ?>) attestation).get("actionDigest");
            Object sig = ((Map<?, ?>) attestation).get("sig");
            if (!(ad instanceof String) || !(sig instanceof String)) return false;
            byte[] pk = Pca.decodeB64uStrict(authorityPublicKey, 32);
            byte[] sg = Pca.decodeB64uStrict(sig, 64);
            if (pk == null || sg == null) return false;
            return EdStrict.verify(pk, attestMessage((String) ad, (String) commitment), sg);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Sound end-to-end budget check over ATTESTED commitments. For the verifier's own list of action digests (in order), every item must carry a
     * valid authority attestation for exactly that digest and commitment, then {@link Accumulator#verifyBoundedBudget} must hold. Never throws.
     */
    public static boolean verifyAttestedBudget(Object items, Object expectedActionDigests, Object authorityPublicKey, Object bMax, Object budgetProof) {
        try {
            if (!(items instanceof List) || !(expectedActionDigests instanceof List) || ((List<?>) items).size() != ((List<?>) expectedActionDigests).size()) return false;
            List<?> its = (List<?>) items;
            List<?> exp = (List<?>) expectedActionDigests;
            List<Object> commitments = new ArrayList<>();
            List<Object> proofs = new ArrayList<>();
            for (int i = 0; i < its.size(); i++) {
                Map<?, ?> it = (Map<?, ?>) its.get(i);
                Object att = it.get("attestation");
                Object ad = att instanceof Map ? ((Map<?, ?>) att).get("actionDigest") : null;
                if (ad == null || !ad.equals(exp.get(i))) return false;
                if (!verifyRiskAttestation(it.get("commitment"), att, authorityPublicKey)) return false;
                commitments.add(it.get("commitment"));
                proofs.add(it.get("rangeProof"));
            }
            return Accumulator.verifyBoundedBudget(commitments, proofs, bMax, budgetProof);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
