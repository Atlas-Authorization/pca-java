package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ActionDerive;
import net.atlasauth.pca.actions.ActionEffective;
import net.atlasauth.pca.actions.ActionExplain;
import org.junit.jupiter.api.Test;

class ActionsDeriveDiffTest {
    private static final String M = "ref-actions-derive";
    private static final Actions.Registry CORE = Actions.CORE_REGISTRY;

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }
    private static Map<String, Object> eff(Object d, boolean c) { return ActionEffective.effective(m(d), CORE, x -> c); }
    private static Actions.Registry reg(Object defs) { return defs == null ? CORE : Actions.extendRegistry(CORE, l(defs)); }

    @Test void flattenParams() throws Exception { OracleCases.each(M, "flattenParams", a -> ActionDerive.flattenParams(m(a.get(0)))); }
    @Test void paramByRole() throws Exception { OracleCases.each(M, "paramByRole", a -> ActionDerive.paramByRole(m(a.get(0)), (String) a.get(1))); }
    @Test void effectClass() throws Exception { OracleCases.each(M, "effectClass", a -> ActionDerive.effectClass(m(a.get(0)))); }
    @Test void resourceMatcher() throws Exception { OracleCases.each(M, "resourceMatcher", a -> ActionDerive.resourceMatcher(m(a.get(0)))); }
    @Test void toSchemaVerb() throws Exception {
        OracleCases.each(M, "toSchemaVerb", a -> { boolean c = (Boolean) a.get(1); return ActionDerive.toSchemaVerb(m(a.get(0)), CORE, x -> c); });
    }
    @Test void cardOf() throws Exception {
        OracleCases.each(M, "cardOf", a -> ActionDerive.cardOf(m(a.get(0)), eff(a.get(0), (Boolean) a.get(1)), CORE));
    }
    @Test void escalationOf() throws Exception { OracleCases.each(M, "escalationOf", a -> ActionDerive.escalationOf(eff(a.get(0), (Boolean) a.get(1)))); }
    @Test void mcpAnnotationsOf() throws Exception { OracleCases.each(M, "mcpAnnotationsOf", a -> ActionDerive.mcpAnnotationsOf(m(a.get(0)), eff(a.get(0), (Boolean) a.get(1)))); }
    @Test void explainDef() throws Exception {
        OracleCases.each(M, "explainDef", a -> { boolean c = (Boolean) a.get(1); return ActionExplain.explainDef(m(a.get(0)), CORE, x -> c); });
    }
    @Test void operationOf() throws Exception { OracleCases.each(M, "operationOf", a -> ActionDerive.operationOf(m(a.get(0)), m(a.get(1)))); }
    @Test void riskOf() throws Exception {
        OracleCases.each(M, "riskOf", a -> ActionDerive.riskOf(m(a.get(0)), eff(a.get(0), (Boolean) a.get(1)), a.get(2) == null ? null : m(a.get(2)), a.get(3) == null ? null : m(a.get(3))));
    }
    @Test void predicatesOf() throws Exception { OracleCases.each(M, "predicatesOf", a -> ActionDerive.predicatesOf(m(a.get(0)), a.size() > 1 ? m(a.get(1)) : null)); }
    @Test void reversibilityScore() throws Exception { OracleCases.each(M, "REVERSIBILITY_SCORE", a -> ActionDerive.REVERSIBILITY_SCORE); }
    @Test void toSchemaDoc() throws Exception {
        OracleCases.each(M, "toSchemaDoc", a -> { boolean c = (Boolean) a.get(2); return ActionDerive.toSchemaDoc(l(a.get(0)), reg(a.get(3)), m(a.get(1)), x -> c); });
    }
    @Test void toOntology() throws Exception {
        OracleCases.each(M, "toOntology", a -> { boolean c = (Boolean) a.get(1); return ActionDerive.toOntology(l(a.get(0)), CORE, x -> c); });
    }
}
