package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.goal.GoalDisambiguate;
import net.atlasauth.pca.goal.GoalNVersion;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle of the goal N-version meet and active disambiguation. */
class GoalNVersionDiffTest {
    private static final String M = "ref-goal-nversion";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static List<Map<String, Object>> maps(Object o) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object x : l(o)) out.add(m(x));
        return out;
    }

    @Test void meet() throws Exception { OracleCases.each(M, "meet", a -> GoalNVersion.meet(maps(a.get(0)))); }
    @Test void meetGrants() throws Exception { OracleCases.each(M, "meetGrants", a -> GoalNVersion.meetGrants(l(a.get(0)), l(a.get(1)))); }
    @Test void checkPanel() throws Exception { OracleCases.each(M, "checkPanel", a -> GoalNVersion.checkPanel(maps(a.get(0)))); }
    @Test void disagreementMass() throws Exception { OracleCases.each(M, "disagreementMass", a -> GoalDisambiguate.disagreementMass(maps(a.get(0)), m(a.get(1)))); }
    @Test void questions() throws Exception { OracleCases.each(M, "questions", a -> GoalDisambiguate.questions(maps(a.get(0)), new GoalDisambiguate.Opts(m(a.get(1))))); }

    @Test void nVersion() throws Exception {
        OracleCases.each(M, "nVersion", a -> GoalNVersion.nVersion(maps(a.get(0)), new GoalDisambiguate.Opts(m(a.get(1))), a.size() > 2 && a.get(2) != null ? Double.valueOf(a.get(2).toString()) : null));
    }

    @Test void allowsWitness() throws Exception { OracleCases.each(M, "allowsWitness", a -> GoalDisambiguate.allowsWitness(m(a.get(0)), m(a.get(1)), m(a.get(2)))); }

    @Test void disambiguate() throws Exception {
        OracleCases.each(M, "disambiguate", a -> {
            List<Map<String, Object>> readings = maps(a.get(0));
            Map<String, Object> ont = m(a.get(1));
            String mode = (String) a.get(2);
            GoalDisambiguate.Opts opts = new GoalDisambiguate.Opts(ont);
            if (a.get(3) != null) opts.budget = Integer.valueOf(a.get(3).toString());
            return GoalDisambiguate.disambiguate(readings, q -> mode.equals("allow") ? "allow" : mode.equals("deny") ? "deny"
                : GoalDisambiguate.allowsWitness(m(readings.get(Integer.parseInt(mode.substring(6))).get("goal")), ont, q) ? "allow" : "deny", opts);
        });
    }
}
