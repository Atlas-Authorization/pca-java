package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.goal.GoalOntologies;
import net.atlasauth.pca.goal.GoalOntology;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle of the intent ontology: verb resolution, IR projection, checker, template instantiation, slot typing, amounts. */
class GoalOntologyDiffTest {
    private static final String M = "ref-goal-ontology";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    /** A shipped ontology travels by name; the hand-written one inline. */
    private static Map<String, Object> ont(Object o) { return o instanceof String ? GoalOntologies.ontology((String) o) : m(o); }

    private static int i(Object o) { return Double.valueOf(String.valueOf(o instanceof Json.Num ? ((Json.Num) o).raw : o)).intValue(); }

    @Test void shippedOntology() throws Exception { OracleCases.each(M, "shippedOntology", a -> GoalOntologies.ontology((String) a.get(0))); }
    @Test void shippedCatalog() throws Exception { OracleCases.each(M, "shippedCatalog", a -> GoalOntologies.selCatalog((String) a.get(0))); }
    @Test void ontologyDigest() throws Exception { OracleCases.each(M, "ontologyDigest", a -> GoalOntology.ontologyDigest(ont(a.get(0)))); }
    @Test void resolveVerb() throws Exception { OracleCases.each(M, "resolveVerb", a -> GoalOntology.resolveVerb(ont(a.get(0)), (String) a.get(1))); }
    @Test void goalCcy() throws Exception { OracleCases.each(M, "goalCcy", a -> GoalOntology.goalCcy(m(a.get(0)))); }
    @Test void goalAnchors() throws Exception { OracleCases.each(M, "goalAnchors", a -> GoalOntology.goalAnchors(m(a.get(0)))); }

    @Test void toIrOntology() throws Exception {
        OracleCases.each(M, "toIrOntology", a -> {
            Map<String, Object> opts = m(a.get(1));
            return GoalOntology.toIrOntology(ont(a.get(0)), opts == null ? null : (String) opts.get("ccy"), opts == null ? null : l(opts.get("rels")));
        });
    }

    @Test void ontologyForGoal() throws Exception { OracleCases.each(M, "ontologyForGoal", a -> GoalOntology.ontologyForGoal(ont(a.get(0)), m(a.get(1)), a.size() > 2 && a.get(2) != null ? l(a.get(2)) : null)); }
    @Test void checkOntology() throws Exception { OracleCases.each(M, "checkOntology", a -> GoalOntology.checkOntology(ont(a.get(0)))); }

    @Test void instantiateTemplate() throws Exception {
        OracleCases.each(M, "instantiateTemplate", a -> {
            Map<String, Object> opts = m(a.get(3));
            List<String> src = null;
            if (opts.get("sources") != null) { src = new ArrayList<>(); for (Object s : l(opts.get("sources"))) src.add((String) s); }
            return GoalOntology.instantiateTemplate(ont(a.get(0)), (String) a.get(1), m(a.get(2)), (String) opts.get("principal"), (String) opts.get("nl"), src);
        });
    }

    @Test void slotLits() throws Exception { OracleCases.each(M, "slotLits", a -> GoalOntology.slotLits(ont(a.get(0)), m(a.get(1)), a.get(2))); }
    @Test void parseHumanAmount() throws Exception { OracleCases.each(M, "parseHumanAmount", a -> GoalOntology.parseHumanAmount((String) a.get(0), i(a.get(1)), (String) a.get(2))); }
    @Test void parseMoney() throws Exception { OracleCases.each(M, "parseMoney", a -> GoalOntology.parseMoney((String) a.get(0), i(a.get(1)), (String) a.get(2))); }
}
