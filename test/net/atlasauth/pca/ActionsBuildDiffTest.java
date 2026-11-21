package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionBuild;
import org.junit.jupiter.api.Test;

class ActionsBuildDiffTest {
    private static final String M = "ref-actions-build";
    private static final Actions.Registry CORE = Actions.CORE_REGISTRY;

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }
    private static byte[] seed(Object o) { return Keys.unb64u((String) m(o).get("$bytes")); }

    @Test void build() throws Exception { OracleCases.each(M, "buildArtifacts", a -> ActionBuild.buildArtifacts(l(a.get(0)), m(a.get(1)), CORE, null)); }
    @Test void types() throws Exception { OracleCases.each(M, "generateTypes", a -> ActionBuild.generateTypes(l(a.get(0)))); }
    @Test void toolAction() throws Exception { OracleCases.each(M, "toolAction", a -> ActionBuild.toolActionMapOf(l(a.get(0))).apply((String) a.get(1), m(a.get(2)))); }
    @Test void consistency() throws Exception { OracleCases.each(M, "packConsistencyError", a -> ActionBuild.packConsistencyError(a.get(0), CORE)); }
    @Test void sign() throws Exception { OracleCases.each(M, "signPack", a -> ActionBuild.signPack(m(a.get(0)), (String) a.get(1), seed(a.get(2)), CORE)); }
    @Test void keyOf() throws Exception { OracleCases.each(M, "packKeyOf", a -> ActionBuild.packKeyOf((String) a.get(0), seed(a.get(1)))); }
    @Test void verify() throws Exception { OracleCases.each(M, "verifyPack", a -> ActionBuild.verifyPack(a.get(0), a.get(1), CORE)); }
}
