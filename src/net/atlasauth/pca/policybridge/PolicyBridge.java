package net.atlasauth.pca.policybridge;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Predicates;

/**
 * Import external authorization policy into PCA: each translator compiles a policy source into PCA envelope predicates plus
 * a report of what was and was not translated; everything unmodeled fails closed (default deny). A result is the JSON map
 * {@code {predicates, denies, caveats, report: {source, translated, skipped, errors}}}.
 *
 * <ul>
 * <li>{@link Cedar#cedarToPca} Cedar permit/forbid policies</li>
 * <li>{@link Rego#regoToPca} OPA/Rego allow-rule subset</li>
 * <li>{@link OpenFga#openfgaToPca} OpenFGA / Zanzibar ReBAC model and tuples</li>
 * <li>{@link Cel} strict CEL conditions (Google IAM Conditions, Kubernetes admission policy, SpiceDB caveats)</li>
 * </ul>
 *
 * The emitted predicates plug into an envelope's predicates; {@code denies} (Cedar forbid) is applied by {@link #decide}
 * (deny-overrides-permit) on top of the core evaluator.
 */
public final class PolicyBridge {
    private PolicyBridge() {}

    static Map<String, Object> newReport(String source) {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("source", source);
        report.put("translated", new ArrayList<Object>());
        report.put("skipped", new ArrayList<Object>());
        report.put("errors", new ArrayList<Object>());
        return report;
    }

    @SuppressWarnings("unchecked")
    static List<Object> list(Map<String, Object> report, String key) { return (List<Object>) report.get(key); }

    static Map<String, Object> result(List<Object> predicates, List<Object> denies, Map<String, Object> report) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("predicates", predicates);
        r.put("denies", denies);
        r.put("caveats", new ArrayList<Object>());
        r.put("report", report);
        return r;
    }

    /**
     * Decide one action under a translation with deny-overrides-permit (Cedar's combining rule) on the core evaluator: any
     * matching deny denies; otherwise the permit predicates decide. Fails closed on an incomplete translation (a result whose
     * report carries errors). Returns {@code {allowed, matched?, reason?}}.
     */
    public static Map<String, Object> decide(Map<String, Object> result, Map<String, Object> ctx) {
        Object report = result.get("report");
        if (report instanceof Map && ((Map<?, ?>) report).get("errors") instanceof List && !((List<?>) ((Map<?, ?>) report).get("errors")).isEmpty()) {
            return Js.obj("allowed", false, "reason", "translation incomplete (fail closed)");
        }
        Object denies = result.get("denies");
        if (denies instanceof List && !((List<?>) denies).isEmpty() && Predicates.evaluatePredicates(denies, ctx)) {
            return Js.obj("allowed", false, "matched", firstMatch((List<?>) denies, ctx), "reason", "forbidden by deny policy");
        }
        Object permits = result.get("predicates");
        if (Predicates.evaluatePredicates(permits, ctx)) return Js.obj("allowed", true, "matched", firstMatch((List<?>) permits, ctx));
        return Js.obj("allowed", false, "reason", Predicates.denialReason(permits, ctx));
    }

    /** The first predicate of an allowing list that matches. */
    private static Object firstMatch(List<?> predicates, Map<String, Object> ctx) {
        for (Object p : predicates) if (Predicates.predicateMatches(p, ctx)) return p;
        return null;
    }
}
