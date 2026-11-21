package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Maps the results of the frontier checks (semantic threshold, progress, objective risk binding) onto the one three-valued model signal the
 * decision lattice consumes ({@code ok}, {@code escalate}, {@code deny}), and tightens risk inputs: they can raise friction, never lower it.
 * Anything malformed is {@code deny}.
 */
public final class FrontierSignals {
    private FrontierSignals() {}

    private static final Set<String> PROGRESS_ESCALATE = Set.of("exploration-exhausted", "budget-exceeded");

    /** {@code ok} when the semantic threshold held, {@code escalate} when it did not, {@code deny} for a missing or malformed result. */
    public static String semanticSignal(Object result) {
        Map<String, Object> r = StoreJs.map(result);
        if (r == null || !(r.get("ok") instanceof Boolean)) return "deny";
        return (Boolean) r.get("ok") ? "ok" : "escalate";
    }

    /** A progress result: {@code ok}; a failure whose reason is exploration-exhausted or budget-exceeded escalates; every other failure is {@code deny}. */
    public static String progressSignal(Object result) {
        Map<String, Object> r = StoreJs.map(result);
        if (r == null || !(r.get("ok") instanceof Boolean)) return "deny";
        if ((Boolean) r.get("ok")) return "ok";
        return r.get("reason") instanceof String && PROGRESS_ESCALATE.contains(r.get("reason")) ? "escalate" : "deny";
    }

    /** An objective risk resolution: mode none or objective is {@code ok}; a mismatch is {@code ok} only under the heuristic fallback; anything else {@code deny}. */
    public static String objectiveSignal(Object res) {
        Map<String, Object> r = StoreJs.map(res);
        if (r == null) return "deny";
        Object mode = r.get("mode");
        if ("none".equals(mode) || "objective".equals(mode)) return "ok";
        if ("mismatch".equals(mode)) return "heuristic".equals(r.get("onMismatch")) ? "ok" : "deny";
        return "deny";
    }

    private static boolean fin(Object x) { return StoreJs.isFinite(x); }

    /** The number as JSON text, keeping the sign of zero (the reference's min(0, -0) is -0 and the comparison is signed). */
    private static Json.Num signed(double d) { return d == 0 && 1 / d < 0 ? new Json.Num("-0") : StoreJs.num(d); }

    /**
     * The safer of a baseline and an objective set of risk inputs: the lower reversibility, the higher blast radius, the objective semantic
     * distance (1 when it is not a finite number). Any non-finite input gives the worst case (reversibility 0, blast radius 1).
     */
    public static Map<String, Object> tightenRiskInputs(Map<String, Object> baseline, Map<String, Object> objective) {
        boolean ok = fin(baseline.get("reversibility")) && fin(objective.get("reversibility")) && fin(baseline.get("blastRadius")) && fin(objective.get("blastRadius"));
        double rev = ok ? Math.min(StoreJs.dbl(baseline.get("reversibility")), StoreJs.dbl(objective.get("reversibility"))) : 0;
        double blast = ok ? Math.max(StoreJs.dbl(baseline.get("blastRadius")), StoreJs.dbl(objective.get("blastRadius"))) : 1;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("reversibility", signed(rev));
        m.put("blastRadius", signed(blast));
        m.put("semanticDistance", fin(objective.get("semanticDistance")) ? objective.get("semanticDistance") : StoreJs.num(1L));
        return m;
    }
}
