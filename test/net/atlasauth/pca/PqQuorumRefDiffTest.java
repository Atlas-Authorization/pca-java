package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * Quorum sets, quorum proofs and rotation chains against the reference corpus (ref-pq-threshold-quorum, 389 cases): every function,
 * every case. Signing cases derive their keys from the corpus seed labels (Ed25519 seeds, ML-DSA key generation seeds); the SLH-DSA
 * signatures are data and are only verified.
 */
class PqQuorumRefDiffTest {
    static final String MODULE = "ref-pq-threshold-quorum";
    static final int TOTAL = 389;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    /** {"$bytes": base64url} as bytes; any other value as it is. */
    private static Object bytes(Object o) {
        Map<String, Object> b = m(o);
        return b != null && b.size() == 1 && b.get("$bytes") instanceof String ? Keys.unb64u((String) b.get("$bytes")) : o;
    }

    private static byte[] seed(Object s) {
        byte[] b = Pca.decodeB64uStrict(s, 32);
        if (b == null) throw new IllegalArgumentException("not a seed");
        return b;
    }

    /** The key material of a signing case: the loader has replaced each {"$seed": label} by the base64url seed. */
    private static Pq.SuiteSecretKeys keys(Object o) {
        Map<String, Object> k = m(o);
        if (k == null) return null;
        Pq.SuiteSecretKeys out = new Pq.SuiteSecretKeys();
        if (k.containsKey("edSecret")) out.edSecret = seed(k.get("edSecret"));
        if (k.containsKey("mlDsa")) out.mlDsa = Pq.mlDsa65Keygen(seed(k.get("mlDsa")));
        if (k.containsKey("mlDsa87")) out.mlDsa87 = Pq.mlDsa87Keygen(seed(k.get("mlDsa87")));
        return out;
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", a -> Issue.obj("PQ_QUORUM_MAX_SIGNERS", PqQuorum.PQ_QUORUM_MAX_SIGNERS, "PQ_QUORUM_MAX_CHAIN", PqQuorum.PQ_QUORUM_MAX_CHAIN));
        f.put("buildQuorumSet", a -> a.size() < 3 ? PqQuorum.buildQuorumSet(arg(a, 0), arg(a, 1)) : PqQuorum.buildQuorumSet(a.get(0), a.get(1), a.get(2)));
        f.put("loadQuorumSet", a -> PqQuorum.loadQuorumSet(arg(a, 0)));
        f.put("quorumMessage", a -> PqQuorum.quorumMessage(arg(a, 0), arg(a, 1), arg(a, 2)));
        f.put("quorumActionDigest", a -> PqQuorum.quorumActionDigest(bytes(arg(a, 0))));
        f.put("signQuorumShare", a -> PqQuorum.signQuorumShare(arg(a, 0), arg(a, 1), arg(a, 2), arg(a, 3), keys(arg(a, 4))));
        f.put("assembleQuorumProof", a -> PqQuorum.assembleQuorumProof(arg(a, 0), arg(a, 1)));
        f.put("verifyQuorum", a -> PqQuorum.verifyQuorum(arg(a, 0)));
        f.put("verifyQuorumApproval", a -> {
            Object msg = bytes(arg(a, 2));
            return PqQuorum.verifyQuorumApproval(arg(a, 0), arg(a, 1), msg instanceof byte[] ? (byte[]) msg : null, arg(a, 3), m(arg(a, 4)));
        });
        f.put("rotationActionDigest", a -> PqQuorum.rotationActionDigest(arg(a, 0), arg(a, 1)));
        f.put("signRotationShare", a -> PqQuorum.signRotationShare(arg(a, 0), arg(a, 1), arg(a, 2), arg(a, 3), keys(arg(a, 4))));
        f.put("buildRotationCert", a -> PqQuorum.buildRotationCert(arg(a, 0), arg(a, 1), arg(a, 2), arg(a, 3)));
        f.put("verifyRotationChain", a -> PqQuorum.verifyRotationChain(arg(a, 0), arg(a, 1), arg(a, 2)));
        f.put("isRotationFork", a -> PqQuorum.isRotationFork(arg(a, 0), arg(a, 1)));
        f.put("quorumProofSize", a -> a.size() < 2 ? PqQuorum.quorumProofSize(arg(a, 0)) : PqQuorum.quorumProofSize(a.get(0), a.get(1)));

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }
}
