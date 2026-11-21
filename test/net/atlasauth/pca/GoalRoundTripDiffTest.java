package net.atlasauth.pca;

import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import net.atlasauth.pca.goal.GoalRoundTrip;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle of the goal round-trip checks and widening mutations. */
class GoalRoundTripDiffTest {
    private static final String M = "ref-goal-roundtrip";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static Function<List<String>, String> explainer(String mode) {
        return lines -> {
            if (mode.equals("throw")) throw new IllegalStateException("boom");
            return GoalRoundTrip.deterministicExplain(lines);
        };
    }

    private static BiFunction<String, String, Map<String, Object>> comparator(String mode) {
        return (text, e) -> {
            if (mode.equals("throw")) throw new IllegalStateException("boom");
            if (mode.equals("ok")) return Map.of("equivalent", true);
            if (mode.equals("no")) return Map.of("equivalent", false);
            return Map.of("equivalent", e.contains(mode.substring(9)));
        };
    }

    @Test void cardRoundTrips() throws Exception { OracleCases.each(M, "cardRoundTrips", a -> GoalRoundTrip.cardRoundTrips(m(a.get(0)))); }
    @Test void mutateGoal() throws Exception { OracleCases.each(M, "mutateGoal", a -> GoalRoundTrip.mutateGoal(m(a.get(0)), (String) a.get(1), m(a.get(2)))); }

    @Test void roundTrip() throws Exception {
        OracleCases.each(M, "roundTrip", a -> GoalRoundTrip.roundTrip(m(a.get(0)), (String) a.get(1), explainer((String) a.get(2)), comparator((String) a.get(3))));
    }

    @Test void measureDetection() throws Exception {
        OracleCases.each(M, "measureDetection", a -> GoalRoundTrip.measureDetection(l(a.get(0)), m(a.get(1)), explainer((String) a.get(2)), comparator((String) a.get(3))));
    }
}
