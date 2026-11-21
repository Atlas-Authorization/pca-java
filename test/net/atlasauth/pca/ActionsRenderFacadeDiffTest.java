package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import net.atlasauth.pca.actions.ActionApprovals;
import net.atlasauth.pca.actions.ActionFacade;
import net.atlasauth.pca.actions.ActionProvenance;
import org.junit.jupiter.api.Test;

class ActionsRenderFacadeDiffTest {
    private static final String M = "ref-actions-render-facade";
    private static final Actions.Registry CORE = Actions.CORE_REGISTRY;

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void renderApproval() throws Exception { OracleCases.each(M, "renderApproval", a -> ActionApprovals.renderApproval(m(a.get(0)), a.get(1), (Boolean) a.get(2))); }
    @Test void renderDigestForAction() throws Exception {
        OracleCases.each(M, "renderDigestForAction", a -> ActionApprovals.renderDigestForAction(m(a.get(0)), m(a.get(1)), m(a.get(2)), (Boolean) a.get(3)));
    }
    @Test void approverRenderCheck() throws Exception {
        OracleCases.each(M, "approverRenderCheck", a -> ActionApprovals.approverRenderCheck(m(a.get(0)), m(a.get(1)), (String) a.get(2), (Boolean) a.get(3)));
    }
    @Test void singleTapAllowed() throws Exception { OracleCases.each(M, "singleTapAllowed", a -> ActionApprovals.singleTapAllowed(m(a.get(0)))); }
    @Test void renderersFromDefs() throws Exception {
        OracleCases.each(M, "renderersFromDefs", a -> ActionApprovals.renderFromDefs(l(a.get(0)), (String) a.get(1), a.get(2) == null ? null : m(a.get(2)), (Boolean) a.get(3)));
    }
    @Test void specOfDef() throws Exception {
        OracleCases.each(M, "specOfDef", a -> { boolean c = (Boolean) a.get(2); return ActionFacade.specOfDef(m(a.get(0)), CORE, (Boolean) a.get(1), d -> c); });
    }
    @Test void facadeSpecs() throws Exception {
        OracleCases.each(M, "facadeSpecs", a -> { boolean c = (Boolean) a.get(2); return ActionFacade.facadeSpecs(l(a.get(0)), CORE, (Boolean) a.get(1), d -> c); });
    }
    @Test void provenanceInfoOf() throws Exception {
        OracleCases.each(M, "provenanceInfoOf", a -> { boolean c = (Boolean) a.get(1); return ActionProvenance.provenanceInfoOf(m(a.get(0)), CORE, d -> c); });
    }
    @Test void provenanceActions() throws Exception {
        OracleCases.each(M, "provenanceActions", a -> {
            boolean c = (Boolean) a.get(1);
            Function<String, Map<String, Object>> f = ActionProvenance.provenanceActions(l(a.get(0)), CORE, d -> c);
            List<Object> out = new ArrayList<>();
            for (Object v : l(a.get(2))) out.add(f.apply((String) v));
            return out;
        });
    }
}
