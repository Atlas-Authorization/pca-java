package net.atlasauth.pca;

import java.util.Map;
import net.atlasauth.pca.goal.GoalLegacy;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle of liftLegacy (default catalog). */
class GoalLegacyDiffTest {
    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Long lng(Object o) { return o == null ? null : Long.valueOf(((Json.Num) o).raw); }

    @Test void liftLegacy() throws Exception {
        OracleCases.each("ref-goal-legacy", "liftLegacy", a -> {
            Object perms = a.get(0);
            if (!(perms instanceof Map)) throw new IllegalArgumentException("permissions must be an object");
            return GoalLegacy.liftLegacy(m(perms), m(a.get(1)), null, (String) a.get(2), lng(a.get(3)), lng(a.get(4)), (String) a.get(5));
        });
    }
}
