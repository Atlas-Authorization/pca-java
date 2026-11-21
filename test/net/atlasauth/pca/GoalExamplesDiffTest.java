package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.goal.GoalExamples;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle of the goal examples: decision cells, boundary examples, goal tests, policy pin. */
class GoalExamplesDiffTest {
    private static final String M = "ref-goal-examples";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static List<Map<String, Object>> maps(Object o) {
        if (o == null) return null;
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object x : l(o)) out.add(m(x));
        return out;
    }

    private static List<String> strs(Object o) {
        if (o == null) return null;
        List<String> out = new ArrayList<>();
        for (Object x : l(o)) out.add((String) x);
        return out;
    }

    @Test void buildSpace() throws Exception { OracleCases.each(M, "buildSpace", a -> GoalExamples.buildSpace(maps(a.get(0)), strs(a.get(1))).toJson()); }

    @Test void cells() throws Exception {
        OracleCases.each(M, "cells", a -> GoalExamples.cells(GoalExamples.buildSpace(maps(a.get(0)), strs(a.get(1))), strs(a.get(2))));
    }

    @Test void cellKey() throws Exception {
        OracleCases.each(M, "cellKey", a -> GoalExamples.cellKey(GoalExamples.buildSpace(maps(a.get(0)), strs(a.get(1))), m(a.get(2))));
    }

    @Test void decideCase() throws Exception { OracleCases.each(M, "decideCase", a -> GoalExamples.decideCase(m(a.get(0)), m(a.get(1)), m(a.get(2)))); }
    @Test void replay() throws Exception { OracleCases.each(M, "replay", a -> GoalExamples.replay(m(a.get(0)), m(a.get(1)), l(a.get(2)), l(a.get(3)))); }

    @Test void allowWitness() throws Exception {
        OracleCases.each(M, "allowWitness", a -> {
            Map<String, Object> g = m(a.get(0));
            int i = Integer.parseInt(a.get(1).toString());
            return GoalExamples.allowWitness(g, m(l(g.get("grants")).get(i)), m(a.get(2)));
        });
    }

    @Test void boundaryExamples() throws Exception {
        OracleCases.each(M, "boundaryExamples", a -> GoalExamples.boundaryExamples(m(a.get(0)), m(a.get(1)), maps(a.get(2)), strs(a.get(3))));
    }

    @Test void reviewSet() throws Exception { OracleCases.each(M, "reviewSet", a -> GoalExamples.reviewSet(l(a.get(0)), Integer.parseInt(a.get(1).toString()))); }
    @Test void testsDigest() throws Exception { OracleCases.each(M, "testsDigest", a -> GoalExamples.testsDigest(l(a.get(0)))); }
    @Test void makeGoalTests() throws Exception { OracleCases.each(M, "makeGoalTests", a -> GoalExamples.makeGoalTests(m(a.get(0)), l(a.get(1)))); }

    @Test void signGoalTests() throws Exception {
        OracleCases.each(M, "signGoalTestsSeed", a -> GoalExamples.signGoalTests(m(a.get(0)), Keys.unb64u((String) a.get(1))));
    }

    @Test void checkGoalTests() throws Exception {
        OracleCases.each(M, "checkGoalTests", a -> {
            String mode = (String) a.get(2);
            Map<String, Object> g = m(a.get(3)), ont = m(a.get(4));
            return GoalExamples.checkGoalTests(m(a.get(0)), l(a.get(1)), t -> mode.equals("ref")
                ? (String) GoalExamples.decideCase(g, ont, t).get("decision")
                : mode.equals("allow") ? "allow" : mode.equals("deny") ? "deny" : "escalate");
        });
    }

    @Test void signPin() throws Exception { OracleCases.each(M, "signPinSeed", a -> GoalExamples.signPin(m(a.get(0)), Keys.unb64u((String) a.get(1)))); }
    @Test void checkPin() throws Exception { OracleCases.each(M, "checkPin", a -> GoalExamples.checkPin(m(a.get(0)), l(a.get(1)), m(a.get(2)))); }
}
