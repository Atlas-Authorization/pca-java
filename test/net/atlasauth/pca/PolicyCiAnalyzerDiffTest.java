package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.policyci.Authoring;
import net.atlasauth.pca.policyci.PolicyCi;
import org.junit.jupiter.api.Test;

/** The policy-ci parts that run on the analyzer: the schema rule, the test command and the coverage command. */
class PolicyCiAnalyzerDiffTest {
    private static final String MODULE = "ref-policy-ci-java-extra";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @Test void lintPolicy() throws Exception { OracleCases.each(MODULE, "lintPolicy", a -> PolicyCi.lintPolicy(a.get(0), a.size() > 1 ? m(a.get(1)) : null)); }

    @Test void testCommand() throws Exception {
        OracleCases.each(MODULE, "testCommand", a -> Authoring.testCommand(a.get(0), a.get(1), a.size() > 2 ? m(a.get(2)) : new LinkedHashMap<>(), Authoring.ANALYZER_BACKEND));
    }

    @Test void coverageCommand() throws Exception {
        OracleCases.each(MODULE, "coverageCommand", a -> Authoring.coverageCommand(a.get(0), a.get(1), a.size() > 2 ? m(a.get(2)) : new LinkedHashMap<>(), Authoring.ANALYZER_BACKEND));
    }
}
