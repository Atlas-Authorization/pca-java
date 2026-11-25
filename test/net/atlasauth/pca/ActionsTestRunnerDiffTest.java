package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionTestRunner;
import org.junit.jupiter.api.Test;

class ActionsTestRunnerDiffTest {
    private static final String M = "ref-actions-test-runner";
    private static final Actions.Registry CORE = Actions.CORE_REGISTRY;

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void decide() throws Exception { OracleCases.each(M, "decideExample", a -> ActionTestRunner.decideExample(m(a.get(0)), m(a.get(1)), CORE, l(a.get(2)))); }
    @Test void runTests() throws Exception {
        OracleCases.each(M, "runDefTests", a -> ActionTestRunner.runDefTests(l(a.get(0)), CORE, a.get(1) == null ? null : (int) Double.parseDouble(((Json.Num) a.get(1)).raw), null));
    }
    @Test void text() throws Exception { OracleCases.each(M, "testText", a -> ActionTestRunner.testText(m(a.get(0)))); }
}
