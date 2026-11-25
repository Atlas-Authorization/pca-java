package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.explain.Explain;
import org.junit.jupiter.api.Test;

class ExplainDiffTest {
    private static final String M = "ref-explain";

    @Test void cleanText() throws Exception { OracleCases.each(M, "cleanText", a -> Explain.cleanText(a.get(0))); }

    @Test void explainVerification() throws Exception { OracleCases.each(M, "explainVerification", a -> Explain.explainVerification(a.get(0), a.get(1), a.get(2))); }

    @Test void explainVerificationText() throws Exception {
        OracleCases.each(M, "explainVerificationText", a -> Explain.verificationToText(Explain.explainVerification(a.get(0), a.get(1), a.get(2))));
    }

    @Test void explainDecision() throws Exception { OracleCases.each(M, "explainDecision", a -> Explain.explainDecision(a.get(0), a.get(1), a.get(2))); }

    @Test void explainDecisionText() throws Exception {
        OracleCases.each(M, "explainDecisionText", a -> Explain.decisionToText(Explain.explainDecision(a.get(0), a.get(1), a.get(2))));
    }

    @Test void explainChain() throws Exception { OracleCases.each(M, "explainChain", a -> Explain.explainChain(a.get(0), a.get(1))); }

    @Test void explainChainText() throws Exception {
        OracleCases.each(M, "explainChainText", a -> Explain.chainToText(Explain.explainChain(a.get(0), a.get(1))));
    }

    @Test void consts() throws Exception {
        OracleCases.each(M, "consts", a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("VERIFY_CHECK_ORDER", Explain.VERIFY_CHECK_ORDER);
            m.put("MAX_TEXT", Explain.MAX_TEXT);
            return m;
        });
    }
}
