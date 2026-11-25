package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Replayable policy debugger (the reference's policy-debug module). The decision core is pure and total, so a "why" is a re-run, not a
 * log: {@link #explainRisk} decomposes the risk functional into its six weighted terms, {@link #explainDecision} explains a
 * {@link Decide#decide} input (risk, threshold, budget trajectory), {@link #applyDelta} / {@link #counterfactual} re-run the core under
 * hypothetical single edits and report which one flips the outcome or moves the threshold, {@link #auditPCActn} adds the verifier's
 * per-check table. Inputs and results are JSON trees (maps and lists), the members of the reference's explanation objects.
 */
public final class PolicyDebug {
    private PolicyDebug() {}

    private static final String[] TERMS = Risk.KEYS;
    private static final boolean[] INVERTED = {false, true, false, false, true, false};
    private static final String[] WEIGHT_KEYS = {"alpha", "beta", "gamma", "delta", "epsilon", "zeta"};

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("not an object");
        return (Map<String, Object>) o;
    }

    private static Map<String, Object> mapOrEmpty(Object o) { return o instanceof Map ? IntentJs.obj(o) : new LinkedHashMap<>(); }

    private static double dbl(Object o) { Double d = Caveats.fin(o); return d == null ? Double.NaN : d; }

    private static double nz(double x) { return !Double.isNaN(x) && !Double.isInfinite(x) && x > 0 ? x : 0; }

    private static Map<String, Object> obj(Object... kv) { return Issue.obj(kv); }

    /** {@code r = max(score, rFloor)} with the six terms in the reference's fixed order; {@code rFloor} null / not finite reads as 0. */
    public static Map<String, Object> explainRisk(Object inputsO, Object weightsO, Object rFloorIn) {
        Map<String, Object> inputs = map(inputsO), weights = map(weightsO);
        Double rf = Caveats.fin(rFloorIn);
        double rFloor = rf == null ? 0 : rf;
        List<Object> terms = new ArrayList<>();
        double rawSum = 0;
        for (int i = 0; i < TERMS.length; i++) {
            Double raw = Caveats.fin(inputs.get(TERMS[i]));
            double input = raw == null ? Risk.WORST[i] : Risk.clamp01(raw);
            double effective = INVERTED[i] ? 1 - input : input;
            double weight = Risk.wt(dbl(weights.get(WEIGHT_KEYS[i])));
            double contribution = weight * effective;
            terms.add(obj("term", TERMS[i], "weight", weight, "input", input, "effective", effective, "contribution", contribution, "inverted", INVERTED[i]));
            rawSum += contribution;
        }
        double rScore = Risk.clamp01(rawSum);
        double r = Math.max(rScore, Risk.clamp01(rFloor));
        return obj("inputs", inputs, "weights", weights, "terms", terms, "rawSum", rawSum, "rScore", rScore, "rFloor", Risk.clamp01(rFloor), "r", r);
    }

    private static double safetyBound(Map<String, Object> pol) {
        double kappa = dbl(pol.get("kappa"));
        return kappa > 0 ? Math.max(0, dbl(pol.get("bMax"))) / kappa : 0;
    }

    /** Explains one decision input (the {@link Decide#decide} input); the decision itself is under {@code decision}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> explainDecision(Map<String, Object> input) {
        Map<String, Object> decision = Decide.decide(input);
        Map<String, Object> env = Authorize.readEnvelope(input.get("grant"));
        Map<String, Object> pol = env != null && env.get("risk_policy") instanceof Map ? IntentJs.obj(env.get("risk_policy")) : Issue.defaultRiskPolicy();
        double dr = dbl(decision.get("r"));
        Map<String, Object> risk;
        Object leaked;
        if (env != null) {
            Risk.Budget b = Risk.Budget.of(input.get("budget"));
            if (b == null) {
                // the reference reads B / tau / asOf as undefined and computes NaN fields; decide() still denies this input
                Map<String, Object> bm = map(input.get("budget"));
                double tau = dbl(bm.get("tau"));
                b = new Risk.Budget(dbl(bm.get("B")), tau, bm.get("asOf") == null ? tau : dbl(bm.get("asOf")));
            }
            double now = dbl(input.get("now"));
            Risk.Budget lk = Risk.leak(b, now, dbl(pol.get("lambda")));
            leaked = lk.toMap();
            Map<String, Object> inputs = new LinkedHashMap<>();
            for (int i = 0; i < TERMS.length; i++) inputs.put(TERMS[i], Risk.WORST[i]);
            Map<String, Object> rk = mapOrEmpty(input.get("risk"));
            for (String k : TERMS) { Double v = Caveats.fin(rk.get(k)); if (v != null) inputs.put(k, v); }
            Object nodeId = input.get("nodeId");
            Object planO = input.get("plan");
            if (planO instanceof List && !rk.containsKey("semanticDistance")) {
                List<Object> plan = (List<Object>) planO;
                Object goal = input.get("goalNodeId") != null ? input.get("goalNodeId") : plan.isEmpty() ? null : mapOrEmpty(plan.get(plan.size() - 1)).get("id");
                inputs.put("semanticDistance", nodeId instanceof String && goal instanceof String ? Risk.planGeodesic(plan, (String) nodeId, (String) goal) : 1d);
            }
            if (!rk.containsKey("age")) {
                inputs.put("age", Risk.ageSinceTouch(lk, now, Decide.horizonOf(input)));
            }
            Double rf = Caveats.fin(input.get("rFloor"));
            risk = explainRisk(inputs, pol.get("weights"), rf == null ? 0d : Math.min(1, Math.max(0, rf)));
        } else {
            // fail-closed denial (no envelope): the decision is r = 1; keep the shape coherent
            leaked = input.get("budget");
            Map<String, Object> inputs = new LinkedHashMap<>();
            Map<String, Object> zero = new LinkedHashMap<>();
            for (int i = 0; i < TERMS.length; i++) { inputs.put(TERMS[i], Risk.WORST[i]); zero.put(WEIGHT_KEYS[i], 0L); }
            risk = obj("inputs", inputs, "weights", zero, "terms", new ArrayList<Object>(), "rawSum", dr, "rScore", dr, "rFloor", 0L, "r", dr);
        }
        Object thr = decision.get("requiredThreshold");
        Map<String, Object> budget = obj("before", input.get("budget"), "leaked", leaked, "after", decision.get("budget"),
            "cost", Risk.cost(dr, dbl(pol.get("kappa"))), "safetyBound", safetyBound(pol));
        return obj("decision", decision, "risk", risk, "requiredThreshold", thr, "t", mapOrEmpty(thr).get("t"),
            "autoAllow", decision.get("admit"), "needStepUp", decision.get("needStepUp"), "releaseGuardianShare", decision.get("releaseGuardianShare"),
            "budget", budget, "reasons", decision.get("reasons"), "envelopeValid", env != null);
    }

    private static Map<String, Object> merged(Object base, Object over) {
        Map<String, Object> out = new LinkedHashMap<>(mapOrEmpty(base));
        out.putAll(mapOrEmpty(over));
        return out;
    }

    /**
     * The hypothetical decision input a delta {@code {label?, risk?, budget?, rFloor?, now?, caveatContext?, humanCosign?}} denotes;
     * {@code humanCosign} recharges the budget (full when {@code {full: true}}) before deciding. Does not mutate {@code input}.
     */
    public static Map<String, Object> applyDelta(Map<String, Object> input, Map<String, Object> d) {
        Object now = d.get("now") != null ? d.get("now") : input.get("now");
        Map<String, Object> budget = merged(input.get("budget"), d.get("budget"));
        if (Zk.truthy(d.get("humanCosign"))) {
            Map<String, Object> env = Authorize.readEnvelope(input.get("grant"));
            Map<String, Object> pol = env != null && env.get("risk_policy") instanceof Map ? IntentJs.obj(env.get("risk_policy")) : Issue.defaultRiskPolicy();
            Object hc = d.get("humanCosign");
            boolean full = hc instanceof Map && Boolean.TRUE.equals(((Map<?, ?>) hc).get("full"));
            Map<String, Object> nb = new LinkedHashMap<>();
            nb.put("B", full ? nz(dbl(pol.get("bMax"))) : Math.min(nz(dbl(pol.get("bMax"))), dbl(budget.get("B")) + nz(dbl(pol.get("rho")))));
            nb.put("tau", now);
            nb.put("asOf", now);
            budget = nb;
        }
        Map<String, Object> next = new LinkedHashMap<>(input);
        if (now != null || input.containsKey("now")) next.put("now", now);
        next.put("budget", budget);
        next.put("risk", merged(input.get("risk"), d.get("risk")));
        next.put("caveatContext", merged(input.get("caveatContext"), d.get("caveatContext")));
        if (d.containsKey("rFloor")) next.put("rFloor", d.get("rFloor"));
        return next;
    }

    private static String describe(Map<String, Object> d) {
        if (Zk.truthy(d.get("label"))) return IntentRevocation.jsText(d.get("label"), true);
        List<String> parts = new ArrayList<>();
        Object hc = d.get("humanCosign");
        if (Zk.truthy(hc)) parts.add(hc instanceof Map && Zk.truthy(((Map<?, ?>) hc).get("full")) ? "human re-confirms goal (B←Bmax)" : "human co-signs (B+ρ)");
        if (d.get("risk") instanceof Map) for (Map.Entry<String, Object> e : IntentJs.obj(d.get("risk")).entrySet()) parts.add(e.getKey() + "=" + IntentRevocation.jsText(e.getValue(), true));
        if (d.get("budget") instanceof Map) for (Map.Entry<String, Object> e : IntentJs.obj(d.get("budget")).entrySet()) parts.add("budget." + e.getKey() + "=" + IntentRevocation.jsText(e.getValue(), true));
        if (d.containsKey("rFloor")) parts.add("caution=" + IntentRevocation.jsText(d.get("rFloor"), true));
        if (d.containsKey("now")) parts.add("now=" + IntentRevocation.jsText(d.get("now"), true));
        if (d.get("caveatContext") instanceof Map) for (Map.Entry<String, Object> e : IntentJs.obj(d.get("caveatContext")).entrySet()) parts.add("ctx." + e.getKey() + "=" + Json.stringify(e.getValue()));
        return parts.isEmpty() ? "no-op" : String.join(", ", parts);
    }

    /** Re-runs the decision under each delta: {@code {baseline, outcomes, flipping, thresholdChanging}} (the labels that flip allow, that move t). */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> counterfactual(Map<String, Object> input, List<Object> deltas) {
        Map<String, Object> baseline = explainDecision(input);
        double bt = dbl(baseline.get("t")), br = dbl(((Map<String, Object>) baseline.get("risk")).get("r"));
        List<Object> outcomes = new ArrayList<>(), flipping = new ArrayList<>(), changing = new ArrayList<>();
        for (Object o : deltas) {
            Map<String, Object> d = map(o);
            Map<String, Object> ex = explainDecision(applyDelta(input, d));
            double t = dbl(ex.get("t"));
            String dir = t > bt ? "raised" : t < bt ? "lowered" : "same";
            String label = describe(d);
            boolean flips = !java.util.Objects.equals(ex.get("autoAllow"), baseline.get("autoAllow"));
            outcomes.add(obj("label", label, "delta", d, "explanation", ex, "flipsAllow", flips, "allow", ex.get("autoAllow"),
                "thresholdDirection", dir, "changesThreshold", !dir.equals("same"), "t", ex.get("t"),
                "rDelta", dbl(((Map<String, Object>) ex.get("risk")).get("r")) - br));
            if (flips) flipping.add(label);
            if (!dir.equals("same")) changing.add(label);
        }
        return obj("baseline", baseline, "outcomes", outcomes, "flipping", flipping, "thresholdChanging", changing);
    }

    /** The verifier's per-check table for the PCActn plus the decomposition of the decision for the same action: {@code {verify, explanation}}. */
    public static Map<String, Object> auditPCActn(Object pcactn, Map<String, Object> input, PcaCore.Options opts) {
        PcaCore.Result r = PcaCore.verify(pcactn, opts);
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("allow", r.allow);
        v.put("checks", new LinkedHashMap<String, Object>(r.checks));
        if (r.reason != null) v.put("reason", r.reason);
        if (r.assurance != null) v.put("assurance", r.assurance);
        return obj("verify", v, "explanation", explainDecision(input));
    }
}
