package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.goal.GoalBench;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle of the benchmark: seeded cases, simulated model fixtures, the four-level evaluation and the calibration report. */
class GoalBenchDiffTest {
    private static final String M = "ref-goal-bench";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static List<Map<String, Object>> cases(Object o) {
        List<Map<String, Object>> r = new ArrayList<>();
        for (Object c : (List<?>) o) r.add(m(c));
        return r;
    }

    private static long lng(Object o) { return Double.valueOf(((Json.Num) o).raw).longValue(); }

    @Test void rngSeq() throws Exception {
        OracleCases.each(M, "rngSeq", a -> {
            GoalBench.Rng r = GoalBench.rng(lng(a.get(0)));
            List<Object> out = new ArrayList<>();
            for (long i = 0, n = lng(a.get(1)); i < n; i++) out.add(r.next());
            return out;
        });
    }

    @Test void generateCases() throws Exception {
        OracleCases.each(M, "generateCases", a -> GoalBench.generateCases((String) a.get(0), (int) lng(a.get(1)), lng(a.get(2)), a.get(3) == null ? null : (int) lng(a.get(3)), Boolean.TRUE.equals(a.get(4))));
    }

    @Test void truthGoalOf() throws Exception { OracleCases.each(M, "truthGoalOf", a -> GoalBench.truthGoal(m(a.get(0)))); }

    @Test void simulateOutputOf() throws Exception {
        OracleCases.each(M, "simulateOutputOf", a -> {
            Object[] spec = null;
            for (Object[] s : GoalBench.SIM_SPECS) if (s[0].equals(a.get(1))) spec = s;
            return GoalBench.simulateOutput(m(a.get(0)), (String) spec[0], (Double) spec[1], (Double) spec[2]);
        });
    }

    @Test void recordFixturesOf() throws Exception { OracleCases.each(M, "recordFixturesOf", a -> GoalBench.recordFixtures(cases(a.get(0)))); }
    @Test void caseSetDigest() throws Exception { OracleCases.each(M, "caseSetDigest", a -> GoalBench.caseSetDigest(cases(a.get(0)))); }

    @Test void evalCaseOf() throws Exception {
        OracleCases.each(M, "evalCaseOf", a -> {
            Map<String, Object> c = m(a.get(0));
            return GoalBench.evalCase(c, GoalBench.completionsFrom(GoalBench.recordFixtures(List.of(c))), null, false, null);
        });
    }

    @Test void compileWideningOf() throws Exception {
        OracleCases.each(M, "compileWideningOf", a -> {
            List<Map<String, Object>[]> items = new ArrayList<>();
            for (Map<String, Object> c : cases(a.get(0))) {
                Map<String, Object> goal = GoalBench.truthGoal(c);
                @SuppressWarnings("unchecked") Map<String, Object>[] it = new Map[] {goal, GoalBench.truthOnt(c, goal)};
                items.add(it);
            }
            return GoalBench.compileWideningCount(items, null);
        });
    }

    @Test void summarizeOf() throws Exception { OracleCases.each(M, "summarizeOf", a -> GoalBench.summarize((String) a.get(0), cases(a.get(1)), (String) a.get(2), m(a.get(3)))); }

    @Test void runDomainOf() throws Exception {
        OracleCases.each(M, "runDomainOf", a -> {
            List<Map<String, Object>> cs = cases(a.get(1));
            return GoalBench.runDomain((String) a.get(0), cs, GoalBench.recordFixtures(cs), null, false);
        });
    }
}
