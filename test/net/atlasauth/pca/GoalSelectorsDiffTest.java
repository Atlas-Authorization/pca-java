package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import net.atlasauth.pca.goal.GoalOntologies;
import net.atlasauth.pca.goal.GoalOntology;
import net.atlasauth.pca.goal.GoalSelectors;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle of the selector layer: catalog, class verbs, roles, expansion, typing, card, carrier, catalog tape. */
class GoalSelectorsDiffTest {
    private static final String M = "ref-goal-selectors";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    /** A shipped domain stands for its IR ontology. */
    private static Map<String, Object> ont(Object o) { return o instanceof String ? GoalOntology.toIrOntology(GoalOntologies.ontology((String) o), null, null) : m(o); }

    /** A shipped domain stands for its selector catalog. */
    private static Map<String, Object> cat(Object o) { return o instanceof String ? GoalOntologies.selCatalog((String) o) : m(o); }

    @Test void selCatalogDigest() throws Exception { OracleCases.each(M, "selCatalogDigest", a -> GoalSelectors.selCatalogDigest(cat(a.get(0)))); }
    @Test void selGoalDigest() throws Exception { OracleCases.each(M, "selGoalDigest", a -> GoalSelectors.selGoalDigest(m(a.get(0)))); }
    @Test void encodeSelCatalog() throws Exception { OracleCases.each(M, "encodeSelCatalog", a -> GoalSelectors.encodeSelCatalog(cat(a.get(0)))); }
    @Test void catalogOfDomain() throws Exception { OracleCases.each(M, "catalogOfDomain", a -> GoalSelectors.selCatalogOfDomain((String) a.get(0))); }
    @Test void classVerbs() throws Exception { OracleCases.each(M, "classVerbs", a -> GoalSelectors.classVerbs(cat(a.get(0)), l(a.get(1)), l(a.get(2)))); }
    @Test void allowClassVerbs() throws Exception { OracleCases.each(M, "allowClassVerbs", a -> GoalSelectors.allowClassVerbs(cat(a.get(0)), l(a.get(1)), l(a.get(2)))); }
    @Test void floatClassVerbs() throws Exception { OracleCases.each(M, "floatClassVerbs", a -> GoalSelectors.floatClassVerbs(cat(a.get(0)), l(a.get(1)), l(a.get(2)))); }
    @Test void resolveRole() throws Exception { OracleCases.each(M, "resolveRole", a -> GoalSelectors.resolveRole(ont(a.get(0)), cat(a.get(1)), (String) a.get(2), (String) a.get(3))); }
    @Test void selReasons() throws Exception { OracleCases.each(M, "selReasons", a -> GoalSelectors.selReasons(m(a.get(0)), ont(a.get(1)), cat(a.get(2)))); }
    @Test void expandSelGoal() throws Exception { OracleCases.each(M, "expandSelGoal", a -> GoalSelectors.expandSelGoal(m(a.get(0)), ont(a.get(1)), cat(a.get(2)))); }
    @Test void selCarrier() throws Exception { OracleCases.each(M, "selCarrier", a -> GoalSelectors.selCarrier(m(a.get(0)))); }
    @Test void renderSelCard() throws Exception { OracleCases.each(M, "renderSelCard", a -> GoalSelectors.renderSelCard(m(a.get(0)), ont(a.get(1)), cat(a.get(2)), null)); }
    @Test void withRoleParams() throws Exception { OracleCases.each(M, "withRoleParams", a -> GoalSelectors.withRoleParams(m(a.get(0)), cat(a.get(1)))); }
    @Test void traitClosure() throws Exception { OracleCases.each(M, "traitClosure", a -> GoalSelectors.traitClosure(l(a.get(0)), null)); }

    @Test void compileSelGoal() throws Exception {
        // only inputs the selector layer refuses: the proved compiler is not carried natively, so it must never be reached
        OracleCases.each(M, "compileSelGoal", a -> GoalSelectors.compileSelGoal(m(a.get(0)), ont(a.get(1)), cat(a.get(2)), (g, o) -> { throw new IllegalStateException("compiler reached"); }));
    }

    @Test void catalogOfDefs() throws Exception { OracleCases.each(M, "catalogOfDefs", a -> GoalSelectors.selCatalogOfDefs(l(a.get(0)), null, null)); }
}
