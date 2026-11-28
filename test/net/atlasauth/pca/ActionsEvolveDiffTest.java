package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionEvolve;
import org.junit.jupiter.api.Test;

class ActionsEvolveDiffTest {
    private static final String M = "ref-actions-evolve";
    private static final Actions.Registry CORE = Actions.CORE_REGISTRY;

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void evolutionRecords() throws Exception {
        OracleCases.each(M, "evolutionRecords", a -> { boolean c = (Boolean) a.get(3); return ActionEvolve.evolutionRecords((String) a.get(0), l(a.get(1)), l(a.get(2)), CORE, d -> c); });
    }
    @Test void signEvolution() throws Exception {
        OracleCases.each(M, "signEvolution", a -> ActionEvolve.signEvolution(l(a.get(0)), (String) a.get(1), Keys.unb64u((String) m(a.get(2)).get("$bytes"))));
    }
    @Test void evolutionError() throws Exception {
        OracleCases.each(M, "evolutionError", a -> { boolean c = (Boolean) a.get(5); return ActionEvolve.evolutionError((String) a.get(0), l(a.get(1)), l(a.get(2)), l(a.get(3)), l(a.get(4)), CORE, d -> c); });
    }
}
