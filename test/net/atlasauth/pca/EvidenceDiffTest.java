package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.evidence.EvidenceBundle;
import net.atlasauth.pca.evidence.EvidenceScitt;
import net.atlasauth.pca.evidence.EvidenceVerify;
import org.junit.jupiter.api.Test;

class EvidenceDiffTest {
    private static final String M = "ref-evidence";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("not an object");
        return (Map<String, Object>) o;
    }

    @Test void bundleShapeError() throws Exception { OracleCases.each(M, "bundleShapeError", a -> EvidenceBundle.bundleShapeError(a.get(0))); }

    @Test void normalizeBundle() throws Exception { OracleCases.each(M, "normalizeBundle", a -> EvidenceBundle.normalizeBundle(a.get(0))); }

    @Test void buildEvidenceBundle() throws Exception { OracleCases.each(M, "buildEvidenceBundle", a -> EvidenceBundle.buildEvidenceBundle(map(a.get(0)))); }

    @Test void commitmentForm() throws Exception { OracleCases.each(M, "commitmentForm", a -> EvidenceBundle.commitmentForm(a.get(0))); }

    @Test void evidenceSignedStatement() throws Exception {
        OracleCases.each("ref-evidence-java-extra", "evidenceSignedStatement", a -> {
            Map<String, Object> spec = map(a.get(1));
            net.atlasauth.pca.scitt.Scitt.SignStatementOpts opts = new net.atlasauth.pca.scitt.Scitt.SignStatementOpts(
                net.atlasauth.pca.scitt.Scitt.CoseAlg.EdDSA, net.atlasauth.pca.scitt.Scitt.ed25519PrivateKey(Keys.unb64u((String) spec.get("seed"))), (String) spec.get("issuer"));
            if (spec.containsKey("subject")) opts.subject((String) spec.get("subject"));
            return EvidenceScitt.evidenceSignedStatement(a.get(0), opts);
        });
    }

    @Test void evidenceDigest() throws Exception { OracleCases.each(M, "evidenceDigest", a -> EvidenceBundle.evidenceDigest(a.get(0))); }

    @Test void evidenceRef() throws Exception { OracleCases.each(M, "evidenceRef", a -> EvidenceScitt.evidenceRef(a.get(0))); }

    @Test void evidenceAnchorCommit() throws Exception {
        OracleCases.each(M, "evidenceAnchorCommit", a -> EvidenceScitt.evidenceAnchorCommit((String) a.get(0)));
    }

    @Test void anchorCommit() throws Exception { OracleCases.each(M, "anchorCommit", a -> EvidenceVerify.anchorCommit((String) a.get(0), (String) a.get(1))); }

    @Test void capOf() throws Exception { OracleCases.each(M, "capOf", a -> EvidenceVerify.capOf(a.get(0), (String) a.get(1), (String) a.get(2))); }

    @Test void principalsTrustError() throws Exception {
        // no argument = undefined = valid
        OracleCases.each(M, "principalsTrustError", a -> a.isEmpty() ? null : EvidenceVerify.principalsTrustError(a.get(0)));
    }

    @Test void accTrustError() throws Exception {
        OracleCases.each(M, "accTrustError", a -> a.isEmpty() ? null : EvidenceVerify.accTrustError(a.get(0)));
    }

    @Test void consts() throws Exception {
        OracleCases.each(M, "consts", a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("EVIDENCE_DOMAIN", EvidenceBundle.EVIDENCE_DOMAIN);
            m.put("EVIDENCE_REPORT_DOMAIN", EvidenceVerify.EVIDENCE_REPORT_DOMAIN);
            m.put("EVIDENCE_CONTENT_TYPE", EvidenceScitt.EVIDENCE_CONTENT_TYPE);
            return m;
        });
    }
}
