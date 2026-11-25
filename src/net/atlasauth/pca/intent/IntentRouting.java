package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Runtime conformance: how an action the grant admits is routed (deny / allow / optimistic / jit-consent) from the map's posterior, the
 * judge-panel hook and its intent-conformance attestation (IC-Att), re-verification of an IC-Att, and recording a just-in-time consent
 * decision as a runtime observation.
 */
public final class IntentRouting {
    private IntentRouting() {}

    private static Map<String, Object> lm() { return new LinkedHashMap<>(); }

    /** Routing options; every field optional (null = default): theta2 (0.5), hMax (the space's harm maximum), bondPolicy. */
    public static final class RouteOptions {
        public Double theta2, hMax;
        public IntentBond.BondPolicy bondPolicy;

        public static RouteOptions fromJson(Object o) {
            RouteOptions r = new RouteOptions();
            if (o == null) return r;
            Map<String, Object> m = IntentOmega.obj(o);
            r.theta2 = IntentLearner.numOrNull(m.get("theta2"));
            r.hMax = IntentLearner.numOrNull(m.get("hMax"));
            if (m.get("bondPolicy") != null) r.bondPolicy = IntentBond.BondPolicy.fromJson(m.get("bondPolicy"));
            return r;
        }
    }

    private static VerbSpace verbOf(IntentLearner l, String verb) {
        for (VerbSpace v : l.omega.verbs) if (v.verb.equals(verb)) return v;
        return null;
    }

    /** The routing decision {route, p, inGrant, vetoed, reversibility, harm, risk, judges, bond?, reason}. */
    public static Map<String, Object> routeAction(IntentLearner l, Outcome o, RouteOptions opts) {
        VerbSpace vs = verbOf(l, o.verb());
        Map<String, Object> r = lm();
        if (vs == null || IntentOmega.cellOf(vs, o) == null) {
            r.put("route", "deny"); r.put("p", 0.0); r.put("inGrant", false); r.put("vetoed", false);
            r.put("reversibility", vs == null ? "unknown" : vs.reversibility);
            r.put("harm", 0.0); r.put("risk", 1.0); r.put("judges", false);
            r.put("reason", "outside the Intent Map's outcome space");
            return r;
        }
        double p = l.acceptance(o);
        boolean inGrant = l.admitsOutcome(o);
        boolean vetoed = l.isVetoed(o);
        double harm = IntentOmega.harmOf(vs, o, l.harm);
        double hMax = opts.hMax != null ? opts.hMax : IntentOmega.harmMax(l.omega, l.harm);
        double risk = Math.min(1, Math.max(0, ((1 - p) * harm) / (hMax > 0 ? hMax : 1)));
        double theta2 = opts.theta2 != null ? opts.theta2 : 0.5;
        r.put("p", p); r.put("inGrant", inGrant); r.put("vetoed", vetoed); r.put("reversibility", vs.reversibility); r.put("harm", harm); r.put("risk", risk);
        if (!inGrant) {
            r.put("route", "deny"); r.put("judges", false);
            r.put("reason", vetoed ? "the cell was vetoed by a runtime divergence" : "outside the conservative grant (p_n < τ)");
            return r;
        }
        boolean judges = vs.reversibility.equals("irreversible") || p < 1 - 1e-12 || risk >= theta2;
        if (vs.reversibility.equals("irreversible")) {
            r.put("route", "jit-consent"); r.put("judges", judges);
            r.put("reason", "irreversible: just-in-time consent on the rendered action");
            return r;
        }
        if (judges) {
            r.put("route", "optimistic"); r.put("judges", true);
            r.put("bond", IntentBond.bondAmount(opts.bondPolicy != null ? opts.bondPolicy : IntentBond.DEFAULT_BOND_POLICY, harm));
            r.put("reason", p < 1 - 1e-12 ? "unconfirmed region (p_n < 1): bonded claim + judges" : "risk ≥ θ₂: bonded claim + judges");
            return r;
        }
        r.put("route", "allow"); r.put("judges", false);
        r.put("reason", "confirmed region, reversible, low risk");
        return r;
    }

    /** The judge input for an outcome: ctx = {intentRef, mapDigest, statementText, slots, goalCommitment}. */
    public static Map<String, Object> judgeInputOf(IntentLearner l, Outcome o, Map<String, Object> ctx) {
        VerbSpace vs = verbOf(l, o.verb());
        if (vs == null) throw new IllegalArgumentException("judgeInputOf: no verb " + o.verb() + " in Ω");
        return IntentRuntime.judgeInputOf(vs, o, l.acceptance(o), ctx);
    }

    /** The consent prompt for an action. */
    public static Map<String, Object> jitConsentRequest(IntentLearner l, Outcome o, String intentRef, String mapDigest) {
        VerbSpace vs = verbOf(l, o.verb());
        if (vs == null) throw new IllegalArgumentException("jitConsentRequest: no verb " + o.verb() + " in Ω");
        return IntentRuntime.jitConsentRequest(vs, o, l.acceptance(o), intentRef, mapDigest);
    }

    /** Record the principal's consent decision (approve = 1, deny = 0 and the cell is vetoed) as a runtime observation. */
    public static Map<String, Object> recordJitDecision(IntentLearner l, Map<String, Object> req, String decision) {
        Map<String, Object> vals = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : IntentOmega.obj(req.get("values")).entrySet()) vals.put(e.getKey(), IntentOmega.isNumber(e.getValue()) ? (Object) IntentOmega.dbl(e.getValue()) : e.getValue());
        return IntentMapKit.applyDivergence(l, new Outcome((String) req.get("verb"), vals), "approve".equals(decision) ? 1 : 0);
    }

    private static Object toPpm(double x) { return Double.isFinite(x) ? IntentJs.normalize((Object) IntentMapKit.jsRound(x * 1_000_000)) : null; }

    /** Verify a panel's verdicts for one action and produce the IC-Att. {@code opts}: judgeKeys, k, calibration?, pqPins?. */
    public static Map<String, Object> intentConformanceAttestation(Map<String, Object> input, List<Object> verdicts, Map<String, Object> opts, Predicate<Map<String, Object>> attestationGate) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("judgeKeys", opts.get("judgeKeys"));
        o.put("k", opts.get("k"));
        o.put("goalCommitment", input.get("goalCommitment"));
        o.put("actionDigest", input.get("actionDigest"));
        if (opts.get("calibration") != null) o.put("calibration", opts.get("calibration"));
        if (opts.get("pqPins") != null) o.put("pqPins", opts.get("pqPins"));
        Map<String, Object> r = IntentSemantic.verifySemanticThreshold(verdicts, o, attestationGate);
        List<String> digests = new ArrayList<>();
        for (Object v : verdicts) digests.add(IntentRuntime.verdictDigest(v));
        Collections.sort(digests);
        Map<String, Object> att = lm();
        att.put("v", 1L);
        att.put("kind", "pca-ic-att");
        att.put("intent_ref", input.get("intentRef"));
        att.put("map_digest", input.get("mapDigest"));
        att.put("action_digest", input.get("actionDigest"));
        att.put("goal_commitment", input.get("goalCommitment"));
        att.put("verdict_digests", new ArrayList<Object>(digests));
        att.put("calibration_digest", opts.get("calibration") != null ? IntentRuntime.calibrationDigest(IntentOmega.obj(opts.get("calibration"))) : null);
        att.put("k", opts.get("k"));
        att.put("ok", r.get("ok"));
        att.put("agree_count", r.get("agreeCount"));
        Object agg = toPpm((Double) r.get("aggregateScore"));
        att.put("aggregate_score_ppm", agg == null ? (Object) 0L : agg);
        att.put("cutoff_ppm", r.containsKey("cutoff") ? toPpm((Double) r.get("cutoff")) : null);
        if (r.get("reason") != null) att.put("reason", r.get("reason"));
        return att;
    }

    /** A judge panel: any set of model judges. Returns their signed verdicts. */
    @FunctionalInterface public interface JudgePanel { List<Object> verdicts(Map<String, Object> input); }

    /** Ask the panel and attest: {att, verdicts}. */
    public static Map<String, Object> checkIntentConformance(JudgePanel panel, Map<String, Object> input, Map<String, Object> opts, Predicate<Map<String, Object>> attestationGate) {
        List<Object> verdicts = panel.verdicts(input);
        Map<String, Object> r = lm();
        r.put("att", intentConformanceAttestation(input, verdicts, opts, attestationGate));
        r.put("verdicts", verdicts);
        return r;
    }

    /** Re-verify an IC-Att from the verdicts it names: {ok, problems}. */
    public static Map<String, Object> verifyICAtt(Object att, Map<String, Object> input, List<Object> verdicts, Map<String, Object> opts, Predicate<Map<String, Object>> attestationGate) {
        Map<String, Object> again = intentConformanceAttestation(input, verdicts, opts, attestationGate);
        List<Object> problems = new ArrayList<>();
        if (!IntentRuntime.icAttDigest(again).equals(IntentRuntime.icAttDigest(att))) problems.add("IC-Att does not match the recomputation from its verdicts");
        if (!Boolean.TRUE.equals(again.get("ok"))) problems.add("panel does not pass: " + (again.get("reason") != null ? again.get("reason") : "unknown"));
        Map<String, Object> r = lm();
        r.put("ok", problems.isEmpty());
        r.put("problems", problems);
        return r;
    }
}
