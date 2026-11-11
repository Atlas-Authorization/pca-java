package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The ported risk functional, threshold map, trust budget and plan geodesic (risk.ts), and their use by authorize (F2). */
class RiskTest {
    static final double EPS = 1e-12;

    static Map<String, Object> weights(double a, double b, double g, double d, double e, double z) {
        Map<String, Object> w = new LinkedHashMap<>();
        w.put("alpha", a); w.put("beta", b); w.put("gamma", g); w.put("delta", d); w.put("epsilon", e); w.put("zeta", z);
        return w;
    }

    static final Map<String, Object> DEFAULT = weights(0.25, 0.2, 0.2, 0.2, 0.1, 0.05);

    @Test void riskScoreIsTheWeightedSumClampedToUnit() {
        assertEquals(1.0, Risk.riskScore(Risk.WORST.clone(), DEFAULT), EPS);
        assertEquals(0.0, Risk.riskScore(new double[] {0, 1, 0, 0, 1, 0}, DEFAULT), EPS);
        assertEquals(0.5, Risk.riskScore(new double[] {0.5, 0.5, 0.5, 0.5, 0.5, 0.5}, DEFAULT), EPS);
        // one input at a time (each weight pairs with its own input)
        assertEquals(0.25, Risk.riskScore(new double[] {1, 1, 0, 0, 1, 0}, DEFAULT), EPS);
        assertEquals(0.2, Risk.riskScore(new double[] {0, 0, 0, 0, 1, 0}, DEFAULT), EPS);
        assertEquals(0.2, Risk.riskScore(new double[] {0, 1, 1, 0, 1, 0}, DEFAULT), EPS);
        assertEquals(0.2, Risk.riskScore(new double[] {0, 1, 0, 1, 1, 0}, DEFAULT), EPS);
        assertEquals(0.1, Risk.riskScore(new double[] {0, 1, 0, 0, 0, 0}, DEFAULT), EPS);
        assertEquals(0.05, Risk.riskScore(new double[] {0, 1, 0, 0, 1, 1}, DEFAULT), EPS);
        // out-of-range inputs clamp; non-finite inputs are the worst case; weights that are negative or non-finite count as 0
        assertEquals(1.0, Risk.riskScore(new double[] {5, -3, 9, 7, -1, 2}, DEFAULT), EPS);
        assertEquals(1.0, Risk.riskScore(new double[] {Double.NaN, Double.NaN, Double.POSITIVE_INFINITY, Double.NaN, Double.NaN, Double.NaN}, DEFAULT), EPS);
        assertEquals(0.0, Risk.riskScore(Risk.WORST.clone(), weights(-1, -1, -1, -1, -1, -1)), EPS);
        assertEquals(0.0, Risk.riskScore(Risk.WORST.clone(), weights(Double.NaN, 0, 0, 0, 0, 0)), EPS);
        assertEquals(1.0, Risk.riskScore(Risk.WORST.clone(), weights(7, 7, 7, 7, 7, 7)), EPS);
    }

    @Test void theThresholdMapIsPiecewiseAndOptimisticOnlyAtT1() {
        Risk.Required a = Risk.requiredThreshold(0.25, 0.25, 0.6, false);
        assertEquals(1, a.t);
        assertEquals("claim", a.proof);
        assertTrue(a.optimisticAllowed);
        assertFalse(Risk.requiredThreshold(0.25, 0.25, 0.6, true).optimisticAllowed);
        Risk.Required b = Risk.requiredThreshold(0.2500001, 0.25, 0.6, false);
        assertEquals(2, b.t);
        assertEquals("standard", b.proof);
        assertFalse(b.optimisticAllowed);
        assertEquals(2, Risk.requiredThreshold(0.6, 0.25, 0.6, false).t);
        Risk.Required c = Risk.requiredThreshold(0.6000001, 0.25, 0.6, false);
        assertEquals(3, c.t);
        assertEquals("strong", c.proof);
        assertEquals(3, Risk.requiredThreshold(Double.NaN, 0.25, 0.6, false).t); // non-finite risk is the worst case
        // escalate never lowers and keeps the proof coherent
        Risk.Required e = Risk.escalate(a, 3);
        assertEquals(3, e.t);
        assertEquals("strong", e.proof);
        assertFalse(e.optimisticAllowed);
        assertEquals(2, Risk.escalate(b, 1).t);
        assertEquals("standard", Risk.escalate(b, 1).proof);
        assertEquals(2, Risk.escalate(a, 2).t);
        assertEquals("standard", Risk.escalate(a, 2).proof);
        assertTrue(Risk.escalate(a, 1).optimisticAllowed);
        assertEquals("strong", Risk.escalate(c, 2).proof);
    }

    @Test void theBudgetLeaksIsDebitedAndAdmitsOnlyWhenItCovers() {
        Risk.Budget b = new Risk.Budget(10, 0, 0);
        Risk.Budget l = Risk.leak(b, 4000, 0.5); // 4 s at 0.5 per second
        assertEquals(8.0, l.b, EPS);
        assertEquals(4000.0, l.asOf, EPS);
        assertEquals(0.0, l.tau, EPS);
        assertEquals(l.b, Risk.leak(l, 4000, 0.5).b, EPS); // idempotent at the same instant
        assertEquals(0.0, Risk.leak(b, 1_000_000, 1).b, EPS); // never below 0
        assertEquals(10.0, Risk.leak(b, 4000, -1).b, EPS); // a negative lambda leaks nothing
        assertEquals(10.0, Risk.leak(b, -5, 1).b, EPS); // time never runs backwards
        assertEquals(7.5, Risk.debit(b, 2.5).b, EPS);
        assertEquals(0.0, Risk.debit(b, 99).b, EPS);
        assertEquals(10.0, Risk.debit(b, Double.NaN).b, EPS);
        assertEquals(0.4, Risk.cost(0.4, 1), EPS);
        assertEquals(1.0, Risk.cost(Double.NaN, 1), EPS);
        assertEquals(0.0, Risk.cost(0.4, -1), EPS);
        assertEquals(1.0, Risk.cost(7, 1), EPS);
        Risk.Admission a1 = Risk.admit(1, true);
        assertTrue(a1.admit && !a1.needStepUp && a1.metered && a1.t == 1);
        Risk.Admission a2 = Risk.admit(2, true);
        assertTrue(!a2.admit && a2.needStepUp && a2.metered && a2.t == 2);
        Risk.Admission a3 = Risk.admit(3, true);
        assertTrue(!a3.admit && a3.needStepUp && !a3.metered && a3.t == 3);
        Risk.Admission broke = Risk.admit(1, false); // the budget cannot cover it: a human step-up, unmetered
        assertTrue(!broke.admit && broke.needStepUp && !broke.metered && broke.t == 3);
        assertEquals(3, Risk.admit(2, false).t);
        assertEquals(0.0, Risk.ageSinceTouch(new Risk.Budget(1, 1000, 1000), 1000, 3_600_000), EPS);
        assertEquals(0.5, Risk.ageSinceTouch(new Risk.Budget(1, 0, 0), 1_800_000, 3_600_000), EPS);
        assertEquals(1.0, Risk.ageSinceTouch(new Risk.Budget(1, 0, 0), 9_000_000, 3_600_000), EPS);
        assertEquals(1.0, Risk.ageSinceTouch(new Risk.Budget(1, 0, 0), Double.NaN, 3_600_000), EPS);
        assertEquals(1.0, Risk.ageSinceTouch(new Risk.Budget(1, 0, 0), 10, 0), EPS);
        assertNull(Risk.Budget.of("x"));
        assertNull(Risk.Budget.of(Map.of("B", 1)));
        assertNotNull(Risk.Budget.of(Map.of("B", 1, "tau", 2)));
        assertEquals(2.0, Risk.Budget.of(Map.of("B", 1, "tau", 2)).asOf, EPS);
    }

    static Map<String, Object> node(String id, Object pre, Object post) {
        Map<String, Object> n = new LinkedHashMap<>();
        n.put("id", id);
        if (pre != null) n.put("pre", pre);
        if (post != null) n.put("post", post);
        return n;
    }

    @Test void theGeodesicIsAUndirectedBfsOverThePlan() {
        List<Object> chain = new ArrayList<>(List.of(node("a", null, null), node("b", "a", null), node("c", Map.of("after", List.of("b")), null), node("d", null, null)));
        assertEquals(0.0, Risk.planGeodesic(chain, "a", "a"), EPS);
        assertEquals(1.0 / 3, Risk.planGeodesic(chain, "a", "b"), EPS);
        assertEquals(2.0 / 3, Risk.planGeodesic(chain, "a", "c"), EPS);
        assertEquals(2.0 / 3, Risk.planGeodesic(chain, "c", "a"), EPS); // behind is as far as ahead
        assertEquals(1.0, Risk.planGeodesic(chain, "a", "d"), EPS); // unreachable
        assertEquals(1.0, Risk.planGeodesic(chain, "a", "zzz"), EPS);
        assertEquals(1.0, Risk.planGeodesic(chain, "zzz", "a"), EPS);
        // successors by post references
        List<Object> post = new ArrayList<>(List.of(node("a", null, Map.of("then", "b")), node("b", null, null), node("c", null, null)));
        assertEquals(0.5, Risk.planGeodesic(post, "a", "b"), EPS);
        // no edges at all: index distance
        List<Object> flat = new ArrayList<>(List.of(node("a", null, null), node("b", null, null), node("c", null, null), node("d", null, null), node("e", null, null)));
        assertEquals(0.25, Risk.planGeodesic(flat, "a", "b"), EPS);
        assertEquals(1.0, Risk.planGeodesic(flat, "a", "e"), EPS);
        // an id that is not in the plan is not an edge
        List<Object> ghost = new ArrayList<>(List.of(node("a", "nope", null), node("b", null, null)));
        assertEquals(1.0, Risk.planGeodesic(ghost, "a", "b"), EPS);
    }

    // ---- through authorize: the signed caution floors r; t above 1 needs an enforced threshold hook that reported at least t

    static final long NOW = AuthorizeK05KillTest.NOW;

    static Map<String, Object> budget(double b) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("B", b); m.put("tau", NOW); m.put("asOf", NOW);
        return m;
    }

    /** Server-supplied inputs that price an action at zero risk: only the signed caution (a floor) then moves r. */
    static Map<String, Object> zeroRisk() {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("semanticDistance", 0L); r.put("reversibility", 1L); r.put("blastRadius", 0L); r.put("taint", 0L); r.put("confidence", 1L); r.put("age", 0L);
        return r;
    }

    static Map<String, Object> ctxOf(Map<String, Object> budget) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("risk", zeroRisk());
        if (budget != null) c.put("budget", budget);
        return c;
    }

    /** The shared test input without the zero-risk source: the risk the decision sees is exactly what the test supplies. */
    static Authorize.Input noRisk() { return K05ParityAuditTest.input().risk(null); }

    static Authorize.AuthorizeResult run(String caution, Map<String, Object> budget, Authorize.ThresholdHook hook) {
        Map<String, Object> pc = caution == null ? K05ParityAuditTest.agentSigned() : K05ParityAuditTest.agentSigned("caution", new Json.Num(caution));
        Authorize.Input in = noRisk();
        in.context(p -> ctxOf(budget));
        if (hook != null) in.thresholdHook(hook);
        return Authorize.authorize(pc, in);
    }

    @Test void cautionRaisesTheRequiredThresholdAndTheHookMustEnforceIt() {
        // a bare guard supplies no risk input: each is priced at its worst case (the plan fills the distance, the seeded budget the age),
        // so the default policy (theta2 0.6) needs t = 3 and no threshold hook is enforced
        Authorize.AuthorizeResult bare = Authorize.authorize(K05ParityAuditTest.agentSigned(), noRisk());
        assertFalse(bare.allow);
        assertEquals("pass", bare.checks.get("budget")); // a fresh stream is seeded with the grant's bMax
        assertEquals("fail", bare.checks.get("threshold"));
        assertTrue(bare.reasons.contains("threshold: t=3 (strong) required but no threshold verifier is enforced"), bare.reasons.toString());
        assertTrue(bare.reasons.contains("policy: risk input(s) missing, assumed worst case: reversibility, blastRadius, taint, confidence"), bare.reasons.toString());
        // risk inputs that price the action at zero, no caution, no budget: r = 0, t = 1, the zero cost is covered by B = 0
        Authorize.AuthorizeResult base = run(null, null, null);
        assertTrue(base.allow, base.reasons.toString());
        assertEquals(0.0, base.risk, EPS);
        assertEquals(Integer.valueOf(1), base.requiredThreshold);
        assertEquals("pass", base.checks.get("budget")); // seeded with bMax (1); the zero cost leaves it whole
        assertNull(base.checks.get("threshold"));
        assertEquals(1.0, ((Number) base.budget.get("B")).doubleValue(), EPS);
        // caution 0.2 <= theta1 0.25: t = 1 with a budget that covers the cost 0.2; the machine admission debits it
        Authorize.AuthorizeResult low = run("0.2", budget(1000), null);
        assertTrue(low.allow, low.reasons.toString());
        assertEquals(0.2, low.risk, EPS);
        assertEquals(Integer.valueOf(1), low.requiredThreshold);
        assertEquals("pass", low.checks.get("budget"));
        assertEquals(999.8, ((Number) low.budget.get("B")).doubleValue(), 1e-9);
        // the same caution with no budget: B = 0 cannot cover 0.2, so a human step-up (t = 3) is required
        Authorize.AuthorizeResult poor = Authorize.authorize(K05ParityAuditTest.agentSigned("caution", new Json.Num("0.2")), noRisk().seedBudget(false).context(p -> ctxOf(null)));
        assertFalse(poor.allow);
        assertEquals("fail", poor.checks.get("threshold"));
        assertTrue(poor.reasons.contains("threshold: t=3 (strong) required but no threshold verifier is enforced"), poor.reasons.toString());
        assertTrue(poor.reasons.contains("policy: trust budget depleted: human recharge required"), poor.reasons.toString());
        assertTrue(poor.reasons.stream().anyMatch(r -> r.startsWith("budget: no budget supplied")), poor.reasons.toString());
        // caution 0.4 between theta1 0.25 and theta2 0.6: t = 2 (standard)
        Authorize.AuthorizeResult mid = run("0.4", budget(1000), null);
        assertFalse(mid.allow);
        assertTrue(mid.reasons.contains("threshold: t=2 (standard) required but no threshold verifier is enforced"), mid.reasons.toString());
        assertTrue(mid.reasons.contains("policy: risk 0.400 exceeds auto threshold: step-up to t=2"), mid.reasons.toString());
        assertTrue(run("0.4", budget(1000), p -> new Authorize.ThresholdOutcome(true, true, 2)).allow);
        assertTrue(run("0.4", budget(1000), p -> new Authorize.ThresholdOutcome(true, true, 3)).allow);
        Authorize.AuthorizeResult below = run("0.9", budget(1000), p -> new Authorize.ThresholdOutcome(true, true, 2));
        assertFalse(below.allow);
        assertTrue(below.reasons.contains("threshold: threshold hook enforced t=2 but the server requires t=3 (below the server-derived threshold; derive t from server-held data)"), below.reasons.toString());
        Authorize.AuthorizeResult unreported = run("0.9", budget(1000), p -> new Authorize.ThresholdOutcome(true, true, null));
        assertTrue(unreported.reasons.contains("threshold: threshold hook enforced t=unreported but the server requires t=3 (below the server-derived threshold; derive t from server-held data)"), unreported.reasons.toString());
        Authorize.AuthorizeResult rejected = run("0.9", budget(1000), p -> new Authorize.ThresholdOutcome(true, false, 3));
        assertFalse(rejected.allow);
        assertTrue(rejected.reasons.contains("threshold: t=3 required and the threshold proof was rejected"), rejected.reasons.toString());
        Authorize.AuthorizeResult unenforced = run("0.9", budget(1000), p -> new Authorize.ThresholdOutcome(false, true, 3));
        assertTrue(unenforced.reasons.contains("threshold: t=3 (strong) required but no threshold verifier is enforced"), unenforced.reasons.toString());
        Authorize.AuthorizeResult thrown = run("0.9", budget(1000), p -> { throw new IllegalStateException("x"); });
        assertTrue(thrown.reasons.contains("threshold: t=3 required and the threshold proof was rejected"), thrown.reasons.toString());
        assertTrue(run("0.9", budget(1000), p -> new Authorize.ThresholdOutcome(true, true, 3)).allow);
        assertEquals(Integer.valueOf(3), run("0.9", budget(1000), p -> new Authorize.ThresholdOutcome(true, true, 3)).requiredThreshold);
    }

    static Authorize.Input withCtx(Map<String, Object> risk) {
        return noRisk().context(p -> {
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("risk", risk);
            c.put("budget", budget(1000));
            return c;
        });
    }

    @Test void requireRiskInputsNamesWhatTheServerDidNotSupply() {
        Map<String, Object> risk = zeroRisk();
        risk.remove("blastRadius");
        Authorize.AuthorizeResult none = Authorize.authorize(K05ParityAuditTest.agentSigned(), withCtx(risk).requireRiskInputs(List.of("blastRadius", "taint")));
        assertFalse(none.allow);
        assertEquals("fail", none.checks.get("risk_inputs"));
        assertTrue(none.reasons.contains("risk_inputs: required risk input(s) not supplied by the server: blastRadius"), none.reasons.toString());
        risk.put("blastRadius", Double.NaN); // not finite: still missing
        Authorize.AuthorizeResult nan = Authorize.authorize(K05ParityAuditTest.agentSigned(), withCtx(risk).requireRiskInputs(List.of("blastRadius", "taint")));
        assertTrue(nan.reasons.contains("risk_inputs: required risk input(s) not supplied by the server: blastRadius"), nan.reasons.toString());
        risk.put("blastRadius", 0L);
        Authorize.AuthorizeResult ok = Authorize.authorize(K05ParityAuditTest.agentSigned(), withCtx(risk).requireRiskInputs(List.of("blastRadius", "taint")));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("risk_inputs"));
        assertNull(Authorize.authorize(K05ParityAuditTest.agentSigned(), withCtx(risk)).checks.get("risk_inputs"));
    }

    @Test void anAdaptivePolicyCanOnlyNarrow() {
        Map<String, Object> pol = new LinkedHashMap<>();
        pol.put("weights", DEFAULT);
        pol.put("theta1", 0.1); pol.put("theta2", 0.15); pol.put("kappa", 1L); pol.put("lambda", 0L); pol.put("rho", 0L); pol.put("bMax", 10L);
        // grant policy: theta1 0.25 / theta2 0.6, so a caution of 0.2 is t = 1 under the grant and t = 3 under the tightened policy
        Json.Num caution = new Json.Num("0.2");
        Authorize.AuthorizeResult tight = Authorize.authorize(K05ParityAuditTest.agentSigned("caution", caution), withCtx(zeroRisk()).adaptivePolicy(now -> pol));
        assertFalse(tight.allow);
        assertEquals("fail", tight.checks.get("adaptive"));
        assertTrue(tight.reasons.contains("adaptive: tightened policy requires threshold t=3 (grant policy: t=1)"), tight.reasons.toString());
        // a looser policy is ignored; none is no policy
        Map<String, Object> loose = new LinkedHashMap<>(pol);
        loose.put("theta1", 0.9); loose.put("theta2", 0.95);
        assertTrue(Authorize.authorize(K05ParityAuditTest.agentSigned("caution", caution), withCtx(zeroRisk()).adaptivePolicy(now -> loose)).allow);
        assertTrue(Authorize.authorize(K05ParityAuditTest.agentSigned("caution", caution), withCtx(zeroRisk()).adaptivePolicy(now -> null)).allow);
        // an invalid policy refuses
        Map<String, Object> bad = new LinkedHashMap<>(pol);
        bad.put("theta1", 0.9); bad.put("theta2", 0.1);
        Authorize.AuthorizeResult invalid = Authorize.authorize(K05ParityAuditTest.agentSigned("caution", caution), withCtx(zeroRisk()).adaptivePolicy(now -> bad));
        assertFalse(invalid.allow);
        assertTrue(invalid.reasons.contains("adaptive: invalid policy (risk_policy requires 0 <= theta1 <= theta2)"), invalid.reasons.toString());
        Authorize.AuthorizeResult thrown = Authorize.authorize(K05ParityAuditTest.agentSigned("caution", caution), withCtx(zeroRisk()).adaptivePolicy(now -> { throw new IllegalStateException("x"); }));
        assertFalse(thrown.allow);
        assertTrue(thrown.reasons.contains("adaptive: the adaptive policy could not be read (fail closed)"), thrown.reasons.toString());
    }
}
