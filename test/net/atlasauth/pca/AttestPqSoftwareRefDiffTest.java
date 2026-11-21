package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The post-quantum software attestation root against the reference corpus (ref-attest-pq-software, 137 cases): statement minting under
 * every signing suite, construction refusals, and the verifier across every suite (SLH-DSA statements are verify-only inputs).
 */
class AttestPqSoftwareRefDiffTest {
    static final String MODULE = "ref-attest-pq-software";
    static final int TOTAL = 137;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    @SuppressWarnings("unchecked")
    private static List<String> strings(Object o) { return o instanceof List ? (List<String>) o : null; }

    /** The key material of a corpus keySpec {alg, edSecret?, seed?}: the seed is the ML-DSA keygen seed of the suite's family. */
    private static Pq.SignerSuiteOpts keys(Map<String, Object> spec, boolean wrongFamily) {
        Pq.SignerSuiteOpts k = new Pq.SignerSuiteOpts();
        k.alg = (String) spec.get("alg");
        if (spec.get("edSecret") instanceof String) k.edSecret = Keys.unb64u((String) spec.get("edSecret"));
        if (spec.get("seed") instanceof String) {
            byte[] seed = Keys.unb64u((String) spec.get("seed"));
            Pq.Suite s = k.alg == null ? null : Pq.resolveSigAlg(k.alg, true);
            if (wrongFamily || (s != null && s.pq == Pq.Prim.ML_DSA_65)) k.mlDsa = Pq.mlDsa65Keygen(seed);
            else if (s != null && s.pq == Pq.Prim.ML_DSA_87) k.mlDsa87 = Pq.mlDsa87Keygen(seed);
        }
        return k;
    }

    private static Object built(AttestPqSoftware.Attestor a) {
        Map<String, Object> o = Issue.obj("pqPublicKey", a.pqPublicKey);
        if (a.ed25519PublicKey != null) o.put("ed25519PublicKey", a.ed25519PublicKey);
        return o;
    }

    private static AttestPqSoftware.VerifierOptions options(Map<String, Object> c, Object evidence, boolean seam) {
        AttestPqSoftware.VerifierOptions o = new AttestPqSoftware.VerifierOptions();
        o.trustedPqPublicKeys = strings(c.get("trustedPqPublicKeys"));
        o.trustedEd25519PublicKeys = strings(c.get("trustedEd25519PublicKeys"));
        if (c.containsKey("requirePq")) o.requirePq = !Boolean.FALSE.equals(c.get("requirePq"));
        o.requireHybrid = Boolean.TRUE.equals(c.get("requireHybrid"));
        if (c.containsKey("allowedSuites")) o.allowedSuites = c.get("allowedSuites") instanceof List ? strings(c.get("allowedSuites")) : new ArrayList<>(); // a non-array fails closed (empty)
        Map<String, Object> pol = m(c.get("policy"));
        if (pol != null) {
            o.policy = new AttestPqSoftware.Policy();
            o.policy.measurements = strings(pol.get("measurements"));
            o.policy.weightsMeasurements = strings(pol.get("weightsMeasurements"));
        }
        if (seam) o.resolveEvidence = (doc, ctx) -> evidence;
        return o;
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> Issue.obj("PQ_ATTEST_DOMAIN", AttestPqSoftware.PQ_ATTEST_DOMAIN));
        f.put("attest", x -> {
            AttestPqSoftware.Attestor a = AttestPqSoftware.createPqSoftwareAttestor(keys(m(arg(x, 0)), false));
            Map<String, Object> o = (Map<String, Object>) built(a);
            o.put("statement", a.attest(m(arg(x, 1))));
            return o;
        });
        f.put("buildAttestor", x -> built(AttestPqSoftware.createPqSoftwareAttestor(keys(m(arg(x, 0)), "ml-dsa-87".equals(m(arg(x, 0)).get("alg")) && m(arg(x, 0)).get("seed") != null
            && !m(arg(x, 0)).containsKey("edSecret") && isFamily65Seed(m(arg(x, 0)).get("seed"))))));
        f.put("verifyPq", x -> {
            Map<String, Object> sc = m(arg(x, 0)), in = m(sc.get("input"));
            Map<String, Object> cfg = m(sc.get("config"));
            AttestPqSoftware.Verifier v = AttestPqSoftware.createPqSoftwareVerifier(options(cfg, sc.get("evidence"), !Boolean.TRUE.equals(cfg.get("noEvidenceSeam"))));
            Map<String, Object> input = Issue.obj("document", new LinkedHashMap<String, Object>(), "ctx", new LinkedHashMap<String, Object>(), "nowMs", in.get("nowMs"));
            if (in.containsKey("expected")) input.put("expected", in.get("expected"));
            return v.verify(input);
        });
        f.put("buildVerifier", x -> {
            AttestPqSoftware.createPqSoftwareVerifier(options(m(arg(x, 0)), null, !Boolean.TRUE.equals(m(arg(x, 0)).get("noEvidenceSeam"))));
            return Issue.obj("built", true);
        });

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), e.getValue());
    }

    /** The corpus case "wrong-key-family" hands ML-DSA-65 key material to an ml-dsa-87 attestor: the seed is that of the 65 label. */
    private static boolean isFamily65Seed(Object seed) {
        return Keys.b64u(Keys.unb64u((String) seed)).equals(Pca.b64(Pca.sha("atlas-pca-conformance/pq-software/ml-dsa-65/pq".getBytes(java.nio.charset.StandardCharsets.UTF_8))));
    }
}
