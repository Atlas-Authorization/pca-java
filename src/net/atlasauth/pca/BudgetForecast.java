package net.atlasauth.pca;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.research.PolicySim;

/** The budget forecaster and policy sizing helpers: how a plan drains the trust budget, how large a trust budget lets an agent act autonomously for a number of actions, and the autonomy bound of a risk policy. */
public final class BudgetForecast {
    private BudgetForecast() {}

    private static String fixed3(double x) { return new BigDecimal(x).setScale(3, RoundingMode.HALF_UP).toPlainString(); } // JavaScript toFixed(3)

    /**
     * Forecast a plan {@code [{verb, resource, params?, at?}]} against a compiled policy: how the trust budget drains step by step,
     * the index of the first action forced to a step-up ({@code firstStepUpAt}, absent when none is), the risk the machine-only
     * actions add up to, and how many co-signs the whole plan needs. Composes {@link PolicySim#simulate}. {@code start} is the clock
     * the budget starts at (null = 0); {@code catalog} null is the built-in one, and a verb unknown to the catalog given fails closed.
     */
    public static Map<String, Object> forecast(Facade.CompiledPolicy policy, List<Map<String, Object>> plan, Double start, Catalog catalog) {
        Map<String, Object> rep = PolicySim.simulate(policy, plan, catalog, start == null ? 0 : start);
        List<Object> steps = new ArrayList<>();
        int first = -1;
        for (Object o : (List<?>) rep.get("results")) {
            Map<String, Object> r = StoreJs.map(o), action = StoreJs.map(r.get("action")), step = new LinkedHashMap<>();
            if (action.containsKey("verb")) step.put("verb", action.get("verb"));
            if (action.containsKey("resource")) step.put("resource", action.get("resource"));
            step.put("outcome", r.get("outcome"));
            step.put("r", r.get("r"));
            step.put("budgetAfter", r.get("budgetAfter"));
            if (first < 0 && "step_up".equals(r.get("outcome"))) first = steps.size();
            steps.add(step);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("steps", steps);
        if (first >= 0) out.put("firstStepUpAt", StoreJs.num((long) first));
        out.put("autonomousRisk", rep.get("autonomousRisk"));
        out.put("forcesCosign", StoreJs.dbl(rep.get("stepUp")) > 0);
        out.put("cosignsNeeded", rep.get("stepUp"));
        out.put("endBudget", rep.get("endBudget"));
        return out;
    }

    /**
     * The smallest trust budget {@code bMax = n * r * kappa} that lets an agent run {@code targetActions} actions of per-action risk
     * {@code perActionRisk} (clamped to [1e-6, 1]) before a human co-sign is needed. {@code kappa} may be null (1). Throws
     * {@link IllegalArgumentException} (the reference's RangeError) on a non-positive kappa or a non-finite count or risk.
     */
    public static Map<String, Object> recommendPolicy(double targetActions, double perActionRisk, Double kappaOrNull) {
        double kappa = kappaOrNull != null ? kappaOrNull : 1;
        if (Double.isNaN(kappa) || Double.isInfinite(kappa) || kappa <= 0) throw new IllegalArgumentException("recommendPolicy: kappa must be a positive finite number");
        if (Double.isNaN(targetActions) || Double.isInfinite(targetActions) || Double.isNaN(perActionRisk) || Double.isInfinite(perActionRisk)) {
            throw new IllegalArgumentException("recommendPolicy: targetActions and perActionRisk must be finite numbers");
        }
        double r = Math.max(1e-6, Math.min(1, perActionRisk));
        double n = Math.max(0, targetActions);
        double bMax = n * r * kappa;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kappa", StoreJs.num(kappa));
        m.put("bMax", StoreJs.num(bMax));
        m.put("autonomousBound", StoreJs.num(bMax / kappa));
        m.put("rationale", "Σr ≤ bMax/κ = " + fixed3(bMax / kappa) + " ≥ " + AttestCommon.jsNumString(n) + "×" + fixed3(r) + " actions before a human co-sign");
        return m;
    }

    /** The autonomy bound of a risk policy {@code {bMax, kappa}}: the total risk an agent can accrue autonomously, {@code max(0, bMax) / kappa} (0 when kappa is not positive). */
    public static double autonomyBoundOf(Map<String, Object> policy) {
        Double kappa = StoreJs.dbl(policy.get("kappa")), bMax = StoreJs.dbl(policy.get("bMax"));
        if (kappa == null || !(kappa > 0)) return 0;
        return bMax == null ? Double.NaN : Math.max(0, bMax) / kappa; // an absent bMax is NaN, as in the reference
    }
}
