package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionPacks;
import net.atlasauth.pca.actions.ActionTransparency;
import org.junit.jupiter.api.Test;

class ActionsPackDiffTest {
    private static final String M = "ref-actions-pack";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void buildPack() throws Exception {
        OracleCases.each(M, "buildPack", a -> ActionPacks.buildPack(m(a.get(0)), Keys.ed25519(Keys.edFromSeed(Keys.unb64u((String) m(a.get(1)).get("$bytes")))), null, d -> false, null));
    }
    @Test void shardDefs() throws Exception { OracleCases.each(M, "shardDefs", a -> ActionPacks.shardDefs(l(a.get(0)), a.get(1))); }
    @Test void verifyUpgrade() throws Exception {
        OracleCases.each(M, "verifyUpgrade", a -> ActionPacks.verifyUpgrade(m(a.get(0)), m(a.get(1)), a.get(2), a.get(3) == null ? null : m(a.get(3)), a.get(4) == null ? null : m(a.get(4)), d -> false));
    }
    @Test void statementPayload() throws Exception { OracleCases.each(M, "packStatementPayload", a -> ActionTransparency.packStatementPayload(m(a.get(0)))); }
}
