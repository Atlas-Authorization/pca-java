package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Public doors onto package-private core checks, for the safety-invariant harness in {@code net.atlasauth.pca.invariants}. Each method
 * delegates to the core; the budget admission composes the core threshold band, cost and admission as the reference's {@code admit} does.
 */
public final class InvariantsBridge {
    private InvariantsBridge() {}

    /** allocationsMonotone: null when every budget_alloc limit is finite, non-negative and never above the one before it, else the reason. */
    public static String allocationsError(List<Object> caveats) { return Pca.allocationsError(caveats); }

    /** validateRiskPolicy: null when the policy is well formed, else the reason. */
    public static String validateRiskPolicy(Object policy) { return Authorize.validateRiskPolicy(policy); }

    /** The reference {@code admit(r, {B}, policy)}: {admit, needStepUp, t, metered}. */
    public static Map<String, Object> admit(double r, double budgetB, double theta1, double theta2, double kappa) {
        int t = Risk.requiredThreshold(r, theta1, theta2, false).t;
        Risk.Admission a = Risk.admit(t, Double.isFinite(budgetB) && budgetB >= Risk.cost(r, kappa));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("admit", a.admit);
        m.put("needStepUp", a.needStepUp);
        m.put("t", (long) a.t);
        m.put("metered", a.metered);
        return m;
    }
}
