package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionUndoEngine;
import org.junit.jupiter.api.Test;

class ActionsUndoEngineDiffTest {
    private static final String M = "ref-actions-undo-engine";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void plan() throws Exception {
        OracleCases.each(M, "undoPlan", a -> ActionUndoEngine.undoEngine(l(a.get(0)), a.get(1), null).plan(m(a.get(2))));
    }
    @Test void attested() throws Exception {
        OracleCases.each(M, "attested", a -> ActionUndoEngine.attestationVerifier(a.get(1), Actions.CORE_REGISTRY).test(m(a.get(0))));
    }
}
