package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Mutation kills for the risk step of authorize: inputs, merge, plan distance, caution, budget, threshold hook, plus the replay and linked-template steps around it. */
class AuthorizeRiskPitKill1Test {
    static final long NOW = AuthorizeK05KillTest.NOW;
    static final String SALT = Pca.b64(new byte[16]);

    @AfterEach void clearHook() { Authorize.coreHook = null; }

    // ---- fixtures

    static Json.Num n(String s) { return new Json.Num(s); }

    static Map<String, Object> weights() {
        return Issue.obj("alpha", n("0.25"), "beta", n("0.2"), "gamma", n("0.2"), "delta", n("0.2"), "epsilon", n("0.1"), "zeta", n("0.05"));
    }

    static Map<String, Object> policy(String th1, String th2, String kappa, String lambda, String bMax) {
        return Issue.obj("weights", weights(), "theta1", n(th1), "theta2", n(th2), "kappa", n(kappa), "lambda", n(lambda), "rho", n("0.5"), "bMax", n(bMax));
    }

    /** Any risk above zero steps up to t = 2 (theta1 0, theta2 1): the reason then prints the risk to three decimals. */
    static Map<String, Object> stepUp() { return policy("0", "1", "1", "0.0005", "1000"); }

    static List<Object> star() { return AuthorizeRunK05bKillTest.star(); }

    static Map<String, Object> envelope(Map<String, Object> riskPolicy, List<Object> preds) {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("type", "envelope");
        env.put("goal_commit", Issue.goalCommit("pay invoices", SALT));
        env.put("predicates", preds);
        env.put("caveats", new ArrayList<Object>());
        if (riskPolicy != null) env.put("risk_policy", riskPolicy);
        env.put("agent_binding", new LinkedHashMap<String, Object>());
        return env;
    }

    static Map<String, Object> grantOf(Map<String, Object> env) {
        List<Object> cavs = new ArrayList<>();
        cavs.add(env);
        return Issue.mintRoot(AuthorizeK05KillTest.PRINCIPAL, AuthorizeK05KillTest.AGENT.id(), null, cavs);
    }

    static Map<String, Object> grant(Map<String, Object> riskPolicy, List<Object> preds) { return grantOf(envelope(riskPolicy, preds)); }

    static Map<String, Object> c(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static Map<String, Object> bud(double b, long tau, long asOf) { return c("B", b, "tau", tau, "asOf", asOf); }

    static Map<String, Object> caution(String v) { return Issue.obj("caution", n(v)); }

    static Authorize.AuthorizeResult go(Map<String, Object> g, Map<String, Object> slots, UnaryOperator<Authorize.Input> cfg) {
        Map<String, Object> pc = AuthorizeRunK05bKillTest.agent(g).act("payments.send", "payments/acme", Issue.obj("amount", 50L), slots);
        return Authorize.authorize(pc, cfg.apply(AuthorizeRunK05bKillTest.in(g).risk(null)));
    }

    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static String exceeds(String r, int t) { return "policy: risk " + r + " exceeds auto threshold: step-up to t=" + t; }

    static final String MISSING4 = "policy: risk input(s) missing, assumed worst case: reversibility, blastRadius, taint, confidence";

    static void noInternalError(Authorize.AuthorizeResult r) {
        assertNotNull(r);
        assertFalse(r.checks.containsKey("authorize"), r.checks + " " + r.reasons);
    }

    // ---- the inputs and their worst case

    @Test void anUnpricedActionIsPricedAtTheWorstCaseOfEveryInput() {
        Authorize.AuthorizeResult r = go(grant(stepUp(), star()), null, in -> in);
        assertFalse(r.allow);
        int missing = r.reasons.indexOf(MISSING4);
        assertTrue(missing >= 0, r.reasons.toString());
        assertEquals(exceeds("0.700", 2), r.reasons.get(missing + 1));
        assertTrue(r.reasons.contains("threshold: t=2 (standard) required but no threshold verifier is enforced"), r.reasons.toString());
        assertEquals("pass", r.checks.get("budget"));
    }

    @Test void everyInputIsReadFromItsOwnMember() {
        Map<String, Object> risk = c("semanticDistance", 0.4, "reversibility", 0.5, "blastRadius", 0.3, "taint", 0.2, "confidence", 0.6, "age", 0.1);
        Authorize.AuthorizeResult r = go(grant(stepUp(), star()), null, in -> in.context(p -> c("risk", risk, "budget", bud(1000, NOW, NOW))));
        assertTrue(r.reasons.contains(exceeds("0.345", 2)), r.reasons.toString());
        assertFalse(r.reasons.stream().anyMatch(x -> x.contains("missing")), r.reasons.toString());
    }

    @Test void anAbsentAgeIsComputedFromTheLastHumanTouchAndAGivenOneIsKept() {
        Map<String, Object> zero = RiskCtx.zero();
        zero.remove("age");
        long touched = NOW - 1_800_000L; // half of the one hour horizon
        Authorize.AuthorizeResult computed = go(grant(stepUp(), star()), null, in -> in.context(p -> c("risk", zero, "budget", bud(1000, touched, NOW))));
        assertTrue(computed.reasons.contains(exceeds("0.025", 2)), computed.reasons.toString());
        assertFalse(computed.reasons.stream().anyMatch(x -> x.contains("missing")), computed.reasons.toString());
        Map<String, Object> given = RiskCtx.zero(); // age 0 is supplied
        Authorize.AuthorizeResult kept = go(grant(stepUp(), star()), null, in -> in.context(p -> c("risk", given, "budget", bud(1000, touched, NOW))));
        assertTrue(kept.allow, kept.reasons.toString());
        assertFalse(kept.reasons.stream().anyMatch(x -> x.startsWith("policy: risk ")), kept.reasons.toString());
    }

    @Test void aRiskContextThatIsNotAnObjectIsNoRiskAtAll() {
        Authorize.AuthorizeResult r = go(grant(stepUp(), star()), null, in -> in.context(p -> c("risk", "not an object")));
        noInternalError(r);
        assertTrue(r.reasons.contains(MISSING4), r.reasons.toString());
    }

    // ---- the plan distance

    static Map<String, Object> node(String id, String... post) {
        return Issue.obj("id", id, "verb", "payments.send", "resource", "payments/acme", "params_digest", Pca.paramsDigest(Issue.obj("amount", 50L)),
            "post", new ArrayList<Object>(Arrays.asList((Object[]) post)));
    }

    static Authorize.AuthorizeResult onPlan(String actOn, List<Object> ctxPlan, Map<String, Object> risk) {
        Map<String, Object> g = grant(stepUp(), star());
        Agent a = AuthorizeRunK05bKillTest.agent(g);
        a.commitPlan(List.of(node("a", "b"), node("b", "c"), node("c", "d"), node("d")));
        Map<String, Object> pc = a.actNode(actOn, Issue.obj("amount", 50L));
        return Authorize.authorize(pc, AuthorizeRunK05bKillTest.in(g).risk(null).plan(null)
            .context(p -> c("plan", ctxPlan, "plan_authorized", true, "risk", risk, "budget", bud(1000, NOW, NOW))));
    }

    static List<Object> chain() { return new ArrayList<>(List.<Object>of(node("a", "b"), node("b", "c"), node("c", "d"), node("d"))); }

    static Map<String, Object> riskWithoutDistance() {
        Map<String, Object> risk = RiskCtx.zero();
        risk.remove("semanticDistance");
        return risk;
    }

    @Test void theDistanceComesFromTheCommittedPlan() {
        Authorize.AuthorizeResult b = onPlan("b", chain(), riskWithoutDistance());
        assertTrue(b.reasons.contains(exceeds("0.167", 2)), b.reasons.toString());
        assertFalse(b.reasons.stream().anyMatch(x -> x.contains("missing")), b.reasons.toString());
        Authorize.AuthorizeResult a = onPlan("a", chain(), riskWithoutDistance());
        assertTrue(a.reasons.contains(exceeds("0.250", 2)), a.reasons.toString());
        // the last node is at distance 0
        Authorize.AuthorizeResult d = onPlan("d", chain(), riskWithoutDistance());
        assertTrue(d.reasons.stream().noneMatch(x -> x.startsWith("policy: risk ")), d.reasons.toString());
    }

    @Test void aSuppliedDistanceBeatsThePlan() {
        Map<String, Object> risk = RiskCtx.zero();
        risk.put("semanticDistance", 0.9);
        Authorize.AuthorizeResult r = onPlan("b", chain(), risk);
        assertTrue(r.reasons.contains(exceeds("0.225", 2)), r.reasons.toString());
        Map<String, Object> zero = RiskCtx.zero(); // distance 0 supplied
        Authorize.AuthorizeResult none = onPlan("a", chain(), zero);
        assertTrue(none.reasons.stream().noneMatch(x -> x.startsWith("policy: risk ")), none.reasons.toString());
    }

    @Test void aPlanWhoseLastEntryHasNoUsableIdPricesTheDistanceAtTheWorstCase() {
        List<Object> junkLast = chain();
        junkLast.add("not a node");
        Authorize.AuthorizeResult junk = onPlan("b", junkLast, riskWithoutDistance());
        noInternalError(junk);
        assertTrue(junk.reasons.contains(exceeds("0.250", 2)), junk.reasons.toString());
        List<Object> numericLast = chain();
        numericLast.add(Issue.obj("id", 5L, "verb", "payments.send", "resource", "payments/acme"));
        Authorize.AuthorizeResult numeric = onPlan("b", numericLast, riskWithoutDistance());
        noInternalError(numeric);
        assertTrue(numeric.reasons.contains(exceeds("0.250", 2)), numeric.reasons.toString());
        Authorize.AuthorizeResult empty = onPlan("b", new ArrayList<>(), riskWithoutDistance());
        noInternalError(empty);
        assertTrue(empty.reasons.contains(exceeds("0.250", 2)), empty.reasons.toString());
    }

    @Test void withNoPlanAtAllTheDistanceIsAnInputLikeTheRest() {
        Authorize.AuthorizeResult r = Authorize.authorize(AuthorizeRunK05bKillTest.pcactn(), AuthorizeRunK05bKillTest.input().risk(null).plan(null)
            .context(p -> c("risk", RiskCtx.zero())));
        noInternalError(r);
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("plan_root_authorized"));
        assertTrue(r.reasons.stream().noneMatch(x -> x.startsWith("policy: risk ")), r.reasons.toString());
    }

    // ---- merging the server's risk source with the request context

    static final String[] KEYS = {"semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"};

    static Authorize.AuthorizeResult merged(String key, Object ctxVal, Object srcVal) {
        Map<String, Object> ctxRisk = RiskCtx.zero();
        if (ctxVal == null) ctxRisk.remove(key); else ctxRisk.put(key, ctxVal);
        Map<String, Object> src = new LinkedHashMap<>();
        src.put(key, srcVal);
        return go(grant(stepUp(), star()), null, in -> in.risk((op, g, pc) -> src).context(p -> c("risk", ctxRisk, "budget", bud(1000, NOW, NOW))));
    }

    @Test void theRiskierOfTheContextAndTheSourceWinsPerInput() {
        // risk-increasing inputs: the larger wins; reversibility and confidence: the smaller wins
        String[] want = {"0.150", "0.100", "0.120", "0.120", "0.050", "0.030"};
        for (int i = 0; i < 6; i++) {
            boolean higherIsWorse = i != 1 && i != 4;
            Object worse = higherIsWorse ? 0.6 : 0.5, better = higherIsWorse ? 0.2 : 0.9;
            Authorize.AuthorizeResult a = merged(KEYS[i], better, worse);
            Authorize.AuthorizeResult b = merged(KEYS[i], worse, better);
            assertTrue(a.reasons.contains(exceeds(want[i], 2)), KEYS[i] + " context better: " + a.reasons);
            assertTrue(b.reasons.contains(exceeds(want[i], 2)), KEYS[i] + " context worse: " + b.reasons);
            // an input only the source has, a source value that is not a number, and a context value that is not a number
            Authorize.AuthorizeResult only = merged(KEYS[i], null, worse);
            assertTrue(only.reasons.contains(exceeds(want[i], 2)), KEYS[i] + " source only: " + only.reasons);
            Authorize.AuthorizeResult nan = merged(KEYS[i], worse, Double.NaN);
            assertTrue(nan.reasons.contains(exceeds(want[i], 2)), KEYS[i] + " source NaN: " + nan.reasons);
            Authorize.AuthorizeResult text = merged(KEYS[i], "not a number", worse);
            assertTrue(text.reasons.contains(exceeds(want[i], 2)), KEYS[i] + " context text: " + text.reasons);
        }
    }

    @Test void whicheverSideIsAbsentTheOtherIsUsed() {
        Map<String, Object> risk = RiskCtx.zero();
        risk.put("blastRadius", 0.6);
        Authorize.AuthorizeResult sourceOnly = go(grant(stepUp(), star()), null, in -> in.risk((op, g, pc) -> risk).context(p -> c("budget", bud(1000, NOW, NOW))));
        assertTrue(sourceOnly.reasons.contains(exceeds("0.120", 2)), sourceOnly.reasons.toString());
        Authorize.AuthorizeResult contextOnly = go(grant(stepUp(), star()), null, in -> in.risk((op, g, pc) -> null).context(p -> c("risk", risk, "budget", bud(1000, NOW, NOW))));
        assertTrue(contextOnly.reasons.contains(exceeds("0.120", 2)), contextOnly.reasons.toString());
        Authorize.AuthorizeResult neither = go(grant(stepUp(), star()), null, in -> in.risk((op, g, pc) -> null));
        assertTrue(neither.reasons.contains(MISSING4), neither.reasons.toString());
    }

    @Test void theContextMapIsNotChangedByTheMerge() {
        Map<String, Object> ctxRisk = RiskCtx.zero();
        Map<String, Object> src = c("blastRadius", 0.6);
        go(grant(stepUp(), star()), null, in -> in.risk((op, g, pc) -> src).context(p -> c("risk", ctxRisk, "budget", bud(1000, NOW, NOW))));
        assertEquals(RiskCtx.zero(), ctxRisk);
        assertEquals(c("blastRadius", 0.6), src);
    }

    @Test void aRiskSourceThatThrowsRefuses() {
        Authorize.AuthorizeResult r = go(grant(stepUp(), star()), null, in -> in.risk((op, g, pc) -> { throw new IllegalStateException("down"); }));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("risk"));
        assertTrue(r.reasons.contains("risk: the risk source failed (fail closed)"), r.reasons.toString());
        assertFalse(r.checks.containsKey("budget"), r.checks.toString());
    }

    // ---- required risk inputs

    @Test void requiredRiskInputsAreNamedInOrderAndThePlanSuppliesTheDistance() {
        Map<String, Object> g = grant(stepUp(), star());
        Authorize.AuthorizeResult two = go(g, null, in -> in.requireRiskInputs(List.of("blastRadius", "taint")));
        assertEquals("fail", two.checks.get("risk_inputs"));
        assertTrue(two.reasons.contains("risk_inputs: required risk input(s) not supplied by the server: blastRadius, taint"), two.reasons.toString());
        Authorize.AuthorizeResult distance = go(g, null, in -> in.requireRiskInputs(List.of("semanticDistance")));
        assertEquals("pass", distance.checks.get("risk_inputs"));
        Authorize.AuthorizeResult empty = go(g, null, in -> in.requireRiskInputs(List.of()));
        assertFalse(empty.checks.containsKey("risk_inputs"), empty.checks.toString());
        Authorize.AuthorizeResult none = go(g, null, in -> in.requireRiskInputs(null));
        assertFalse(none.checks.containsKey("risk_inputs"), none.checks.toString());
        Map<String, Object> partial = c("blastRadius", 0.0);
        Authorize.AuthorizeResult one = go(g, null, in -> in.context(p -> c("risk", partial)).requireRiskInputs(List.of("blastRadius", "age")));
        assertEquals("fail", one.checks.get("risk_inputs"));
        assertTrue(one.reasons.contains("risk_inputs: required risk input(s) not supplied by the server: age"), one.reasons.toString());
    }

    // ---- caution, thresholds and the hook

    @Test void theSignedCautionFloorsTheRisk() {
        Authorize.AuthorizeResult r = go(grant(stepUp(), star()), caution("0.9"), in -> in.context(p -> c("risk", RiskCtx.zero(), "budget", bud(1000, NOW, NOW))));
        assertTrue(r.reasons.contains(exceeds("0.900", 2)), r.reasons.toString());
        Authorize.AuthorizeResult wholeNumber = go(grant(stepUp(), star()), Issue.obj("caution", 1L), in -> in.context(p -> c("risk", RiskCtx.zero(), "budget", bud(1000, NOW, NOW))));
        assertTrue(wholeNumber.reasons.contains(exceeds("1.000", 2)), wholeNumber.reasons.toString());
        Authorize.AuthorizeResult zero = go(grant(stepUp(), star()), Issue.obj("caution", 0L), in -> in.context(p -> c("risk", RiskCtx.zero(), "budget", bud(1000, NOW, NOW))));
        assertTrue(zero.allow, zero.reasons.toString());
        // the larger of the computed score and the caution
        Map<String, Object> risk = RiskCtx.zero();
        risk.put("blastRadius", 0.6);
        Authorize.AuthorizeResult score = go(grant(stepUp(), star()), caution("0.05"), in -> in.context(p -> c("risk", risk, "budget", bud(1000, NOW, NOW))));
        assertTrue(score.reasons.contains(exceeds("0.120", 2)), score.reasons.toString());
    }

    static Map<String, Object> mid() { return policy("0.25", "0.6", "2", "0.0005", "10"); }

    @Test void theBudgetLeaksAndIsDebitedByTheMachineAdmission() {
        long touched = NOW - 100_000L;
        Authorize.AuthorizeResult r = go(grant(mid(), star()), caution("0.2"), in -> in.context(p -> c("risk", RiskCtx.zero(), "budget", bud(10, touched, touched))));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals(0.2, r.risk, 1e-9);
        assertEquals(Integer.valueOf(1), r.requiredThreshold);
        // 10 - 0.0005 * 100 s (leak) - 2 * 0.2 (cost)
        assertEquals(9.55, ((Number) r.budget.get("B")).doubleValue(), 1e-9);
        assertEquals((double) touched, ((Number) r.budget.get("tau")).doubleValue());
        assertEquals((double) NOW, ((Number) r.budget.get("asOf")).doubleValue());
        assertEquals(3, r.budget.size());
    }

    @Test void aMidBandRiskNeedsAThresholdHookAtTwoOrMore() {
        long touched = NOW - 100_000L;
        Authorize.AuthorizeResult ok = go(grant(mid(), star()), caution("0.4"), in -> in.context(p -> c("risk", RiskCtx.zero(), "budget", bud(10, touched, touched)))
            .thresholdHook(pc -> new Authorize.ThresholdOutcome(true, true, 2)));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals(Integer.valueOf(2), ok.requiredThreshold);
        assertEquals("pass", ok.checks.get("threshold"));
        assertTrue(ok.reasons.contains(exceeds("0.400", 2)), ok.reasons.toString());
        Authorize.AuthorizeResult none = go(grant(mid(), star()), caution("0.4"), in -> in.context(p -> c("risk", RiskCtx.zero(), "budget", bud(10, touched, touched))));
        assertFalse(none.allow);
        assertTrue(none.reasons.contains("threshold: t=2 (standard) required but no threshold verifier is enforced"), none.reasons.toString());
    }

    @Test void aTopBandActionIsNotDebitedByTheMachineAdmission() {
        long touched = NOW - 100_000L;
        Authorize.AuthorizeResult r = go(grant(mid(), star()), caution("0.9"), in -> in.context(p -> c("risk", RiskCtx.zero(), "budget", bud(10, touched, touched)))
            .thresholdHook(pc -> new Authorize.ThresholdOutcome(true, true, 3)));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals(Integer.valueOf(3), r.requiredThreshold);
        assertEquals(9.95, ((Number) r.budget.get("B")).doubleValue(), 1e-9);
        assertEquals("pass", r.checks.get("threshold"));
        assertTrue(r.reasons.contains(exceeds("0.900", 3)), r.reasons.toString());
    }

    @Test void aHookAtTheLowBandRecordsItsOutcome() {
        Authorize.AuthorizeResult ok = go(grant(mid(), star()), null, in -> in.context(p -> c("risk", RiskCtx.zero())).thresholdHook(pc -> new Authorize.ThresholdOutcome(true, true, 1)));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("threshold"));
        Authorize.AuthorizeResult no = go(grant(mid(), star()), null, in -> in.context(p -> c("risk", RiskCtx.zero())).thresholdHook(pc -> new Authorize.ThresholdOutcome(true, false, 1)));
        assertFalse(no.allow);
        assertEquals("fail", no.checks.get("threshold"));
        Authorize.AuthorizeResult unenforced = go(grant(mid(), star()), null, in -> in.context(p -> c("risk", RiskCtx.zero())).thresholdHook(pc -> new Authorize.ThresholdOutcome(false, true, 1)));
        assertTrue(unenforced.allow, unenforced.reasons.toString());
        assertFalse(unenforced.checks.containsKey("threshold"), unenforced.checks.toString());
    }

    @Test void aRefusedPolicyReleasesNeitherTheThresholdNorTheAdaptivePolicy() {
        List<Object> nope = new ArrayList<>(List.<Object>of(Issue.obj("verb", "other")));
        Map<String, Object> tight = new LinkedHashMap<>();
        tight.put("weights", RiskTest.DEFAULT);
        tight.put("theta1", 0.0); tight.put("theta2", 0.01); tight.put("kappa", 1L); tight.put("lambda", 0L); tight.put("rho", 0L); tight.put("bMax", 10L);
        Authorize.AuthorizeResult r = go(grant(mid(), nope), caution("0.9"), in -> in.context(p -> c("risk", RiskCtx.zero(), "budget", bud(10, NOW, NOW))).adaptivePolicy(now -> tight));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("policy"));
        assertFalse(r.checks.containsKey("threshold"), r.checks.toString());
        assertFalse(r.checks.containsKey("adaptive"), r.checks.toString());
        assertTrue(r.reasons.stream().noneMatch(x -> x.startsWith("threshold: ") || x.startsWith("adaptive: ")), r.reasons.toString());
    }

    @Test void aDelegationThatFailsItsCaveatsReleasesNeitherTheThreshold() {
        Map<String, Object> g = grant(mid(), star());
        Agent child = AuthorizeRunK05bKillTest.agent(g).delegate(AuthorizeRunK05bKillTest.CHILD, List.<Object>of(Issue.obj("type", "max_blast_radius", "max", 10L)));
        Map<String, Object> pc = child.act("payments.send", "payments/acme", Issue.obj("amount", 50L), caution("0.9"));
        Authorize.AuthorizeResult r = Authorize.authorize(pc, AuthorizeRunK05bKillTest.in(g).risk(null).context(p -> c("blast_radius", 50L, "risk", RiskCtx.zero(), "budget", bud(10, NOW, NOW))));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("delegated_caveats"), r.checks.toString());
        assertFalse(r.checks.containsKey("threshold"), r.checks.toString());
        assertTrue(r.reasons.stream().noneMatch(x -> x.startsWith("threshold: ")), r.reasons.toString());
        // control: the same call with the caveat met is held to the threshold
        Authorize.AuthorizeResult ok = Authorize.authorize(child.act("payments.send", "payments/acme", Issue.obj("amount", 50L), caution("0.9")),
            AuthorizeRunK05bKillTest.in(g).risk(null).context(p -> c("blast_radius", 5L, "risk", RiskCtx.zero(), "budget", bud(10, NOW, NOW))));
        assertTrue(ok.reasons.contains("threshold: t=3 (strong) required but no threshold verifier is enforced"), ok.reasons.toString());
    }

    @Test void theAdaptivePolicyAcceptsAnyOtherPolicyThatIsNoTighter() {
        Map<String, Object> loose = new LinkedHashMap<>();
        loose.put("weights", RiskTest.DEFAULT);
        loose.put("theta1", 0.9); loose.put("theta2", 0.95); loose.put("kappa", 1L); loose.put("lambda", 0L); loose.put("rho", 0L); loose.put("bMax", 10L);
        long touched = NOW - 100_000L;
        Authorize.AuthorizeResult r = go(grant(mid(), star()), caution("0.2"), in -> in.context(p -> c("risk", RiskCtx.zero(), "budget", bud(10, touched, touched))).adaptivePolicy(now -> loose));
        assertTrue(r.allow, r.reasons.toString());
        assertFalse(r.checks.containsKey("adaptive"), r.checks.toString());
        // a policy that is tighter only in its upper band is still seen
        Map<String, Object> upper = new LinkedHashMap<>(loose);
        upper.put("theta1", 0.25); upper.put("theta2", 0.3);
        Authorize.AuthorizeResult band = go(grant(mid(), star()), caution("0.4"), in -> in.context(p -> c("risk", RiskCtx.zero(), "budget", bud(10, touched, touched)))
            .thresholdHook(pc -> new Authorize.ThresholdOutcome(true, true, 2)).adaptivePolicy(now -> upper));
        assertFalse(band.allow);
        assertEquals("fail", band.checks.get("adaptive"));
        assertTrue(band.reasons.contains("adaptive: tightened policy requires threshold t=3 (grant policy: t=2)"), band.reasons.toString());
    }

    // ---- no budget

    @Test void anUnseededStreamHasNoBudgetAndSaysSo() {
        Authorize.AuthorizeResult r = go(grant(mid(), star()), null, in -> in.seedBudget(false).context(p -> c("risk", RiskCtx.zero())));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("not-enforced", r.checks.get("budget"));
        assertNull(r.budget);
        assertTrue(r.reasons.stream().anyMatch(x -> x.startsWith("budget: no budget supplied")), r.reasons.toString());
        Authorize.AuthorizeResult seeded = go(grant(mid(), star()), null, in -> in.context(p -> c("risk", RiskCtx.zero())));
        assertTrue(seeded.allow, seeded.reasons.toString());
        assertEquals("pass", seeded.checks.get("budget"));
        assertNotNull(seeded.budget);
        assertEquals(10.0, ((Number) seeded.budget.get("B")).doubleValue(), 1e-9);
        assertEquals((double) NOW, ((Number) seeded.budget.get("tau")).doubleValue());
        assertTrue(seeded.reasons.stream().noneMatch(x -> x.startsWith("budget: ")), seeded.reasons.toString());
    }

    /** A store that holds no budgets: nothing is seeded, nothing is read back. */
    static final class NoBudgetStore implements StateStore {
        final MemoryStateStore m = new MemoryStateStore();
        @Override public StateStore.ClaimResult claim(String key, long counter) { return m.claim(key, counter); }
    }

    @Test void aStoreThatHoldsNoBudgetsIsNotSeeded() {
        Authorize.AuthorizeResult r = go(grant(mid(), star()), null, in -> in.stateStore(new NoBudgetStore()).context(p -> c("risk", RiskCtx.zero())));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("not-enforced", r.checks.get("budget"));
        assertNull(r.budget);
    }

    @Test void aSuppliedBudgetIsNeverReplacedByTheSeed() {
        Authorize.AuthorizeResult r = go(grant(mid(), star()), null, in -> in.context(p -> c("risk", RiskCtx.zero(), "budget", bud(3, NOW, NOW))));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals(3.0, ((Number) r.budget.get("B")).doubleValue(), 1e-9);
    }

    @Test void aGrantWithoutAValidEnvelopeIsRefusedWithoutAnInternalError() {
        Map<String, Object> g = grant(null, star());
        Authorize.AuthorizeResult r = go(g, null, in -> in);
        noInternalError(r);
        assertFalse(r.allow);
        assertTrue(r.reasons.contains("policy: grant carries no valid envelope"), r.reasons.toString());
        assertNull(r.risk);
        assertFalse(r.checks.containsKey("budget") && "pass".equals(r.checks.get("budget")), r.checks.toString());
    }

    @Test void theBudgetReasonSitsBeforeThePolicyReasonsAndAfterEarlierOnes() {
        Authorize.ForbidOptions none = new Authorize.ForbidOptions((op, g) -> new ArrayList<>());
        // no policy reason: appended after every earlier reason
        Authorize.AuthorizeResult tail = go(grant(mid(), star()), null, in -> in.seedBudget(false).isRevoked((p, g) -> true).forbid(none).context(p -> c("risk", RiskCtx.zero())));
        int f = tail.reasons.indexOf("forbid: deny by none");
        assertTrue(f >= 0, tail.reasons.toString());
        assertTrue(tail.reasons.get(f + 1).startsWith("budget: no budget supplied"), tail.reasons.toString());
        assertEquals("revocation: the grant is revoked", tail.reasons.get(0));
        // a policy reason: the budget reason goes in front of the first one, behind the earlier ones
        List<Object> nope = new ArrayList<>(List.<Object>of(Issue.obj("verb", "other")));
        Authorize.AuthorizeResult head = go(grant(mid(), nope), null, in -> in.seedBudget(false).isRevoked((p, g) -> true).forbid(none).context(p -> c("risk", RiskCtx.zero())));
        int b = -1;
        for (int i = 0; i < head.reasons.size(); i++) if (head.reasons.get(i).startsWith("budget: no budget supplied")) b = i;
        assertTrue(b > 0, head.reasons.toString());
        assertEquals("revocation: the grant is revoked", head.reasons.get(b - 1));
        assertTrue(head.reasons.get(b + 1).startsWith("policy: "), head.reasons.toString());
    }

    // ---- amountRisk

    @Test void amountRiskIsTheAmountOverKappaClampedToTheUnitInterval() {
        Map<String, Object> g = grant(policy("0.25", "0.6", "100", "0.0005", "10"), star());
        assertEquals(Map.of("blastRadius", 0.5), Authorize.amountRisk(g, Map.of("amount", 50L)));
        assertEquals(Map.of("blastRadius", 1.0), Authorize.amountRisk(g, Map.of("amount", 100L)));
        assertEquals(Map.of("blastRadius", 1.0), Authorize.amountRisk(g, Map.of("amount", 250L)));
        assertEquals(Map.of("blastRadius", 0.0), Authorize.amountRisk(g, Map.of("amount", 0L)));
        assertEquals(Map.of("blastRadius", 0.0), Authorize.amountRisk(g, Map.of("amount", -30L)));
        assertEquals(Map.of("blastRadius", 0.25), Authorize.amountRisk(g, Map.of("amount", n("25"))));
        assertEquals(Map.of("blastRadius", 0.125), Authorize.amountRisk(g, Map.of("amount", 12.5)));
        assertEquals(1, Authorize.amountRisk(g, Map.of("amount", 50L)).size());
        assertNull(Authorize.amountRisk(g, null));
        assertNull(Authorize.amountRisk(g, Map.of()));
        assertNull(Authorize.amountRisk(g, Map.of("amount", "fifty")));
        assertNull(Authorize.amountRisk(g, Map.of("other", 5L)));
        // kappa of exactly 1 is positive
        Map<String, Object> one = grant(policy("0.25", "0.6", "1", "0.0005", "10"), star());
        assertEquals(Map.of("blastRadius", 0.5), Authorize.amountRisk(one, Map.of("amount", n("0.5"))));
        // a grant without a readable envelope prices nothing
        assertNull(Authorize.amountRisk(grant(null, star()), Map.of("amount", 50L)));
        assertNull(Authorize.amountRisk(Map.of(), Map.of("amount", 50L)));
        assertNull(Authorize.amountRisk(Map.of(), null));
    }

    // ---- the replay counter seen again while an escalation is pending

    /** A store whose pin answers with a counter that was lower the first time it was read (a concurrent writer moved the stream on). */
    static final class MovingStore implements StateStore, LastStore {
        final MemoryStateStore m = new MemoryStateStore();
        final long first, later;
        int reads;
        MovingStore(long first, long later) { this.first = first; this.later = later; }
        @Override public StateStore.ClaimResult claim(String key, long counter) { return m.claim(key, counter); }
        @Override public boolean holdsBudgets() { return true; }
        @Override public Map<String, Object> budget(String key) { return m.budget(key); }
        @Override public StateStore.ClaimResult claim(String key, long counter, Map<String, Object> before, Map<String, Object> after) { return m.claim(key, counter, before, after); }
        @Override public Long last(String key) { return reads++ == 0 ? first : later; }
    }

    @Test void aCounterTheStreamPassedWhileEscalatingIsAReplayNotAnEscalation() {
        AuthorizeRunK05bKillTest.escalate();
        Map<String, Object> pc = AuthorizeRunK05bKillTest.pcactn();
        long counter = Json.asLong(pc.get("counter"));
        Authorize.AuthorizeResult equal = Authorize.authorize(pc, AuthorizeRunK05bKillTest.input().stateStore(new MovingStore(counter - 1, counter)));
        assertEquals("deny", equal.decision, equal.reasons.toString());
        assertEquals("fail", equal.checks.get("replay"));
        assertTrue(equal.reasons.contains("replay: " + counter + " is not greater than last seen " + counter + " (replay)"), equal.reasons.toString());
        assertNull(equal.escalation);
        // one below the counter is not a replay
        Authorize.AuthorizeResult below = Authorize.authorize(AuthorizeRunK05bKillTest.pcactn(), AuthorizeRunK05bKillTest.input().stateStore(new MovingStore(counter - 1, counter - 1)));
        assertEquals("escalate", below.decision, below.reasons.toString());
    }

    // ---- the linked-template check

    @Test void aLinkedTemplateIsVerifiedAgainstTheRegistry() throws Exception {
        Map<String, Object> c = K05R5G3PolicyTest.caseNamed("a reference resolves");
        Map<String, Object> reg = PolicyAuthoringTest.m(c.get("registry"));
        Map<String, Object> pol = PolicyAuthoringTest.m(PolicyAuthoringTest.m(c.get("expect")).get("policy"));
        Map<String, Object> env = envelope(Issue.defaultRiskPolicy(), l(pol.get("predicates")));
        env.put("caveats", pol.get("caveats"));
        env.put("template_ref", c.get("ref"));
        Map<String, Object> g = grantOf(env);
        Authorize.AuthorizeResult ok = go(g, null, in -> in.requireLinkedTemplate(() -> reg));
        assertEquals("pass", ok.checks.get("template"), ok.reasons.toString());
        assertTrue(ok.reasons.stream().noneMatch(x -> x.startsWith("template: ")), ok.reasons.toString());
        // the grant's policy edited: refused with the verifier's reason
        Map<String, Object> edited = new LinkedHashMap<>(env);
        edited.put("caveats", new ArrayList<>(List.of(Issue.obj("type", "max_blast_radius", "max", 1L))));
        Authorize.AuthorizeResult no = go(grantOf(edited), null, in -> in.requireLinkedTemplate(() -> reg));
        assertEquals("fail", no.checks.get("template"));
        assertTrue(no.reasons.contains("template: grant policy differs from the linked template instantiation"), no.reasons.toString());
        // a registry that cannot be read fails closed
        Authorize.AuthorizeResult boom = go(g, null, in -> in.requireLinkedTemplate(() -> { throw new IllegalStateException("down"); }));
        assertEquals("fail", boom.checks.get("template"));
        assertTrue(boom.reasons.contains("template: link verification error (fail closed)"), boom.reasons.toString());
        // a grant with no readable envelope
        Authorize.AuthorizeResult bare = go(grant(null, star()), null, in -> in.requireLinkedTemplate(() -> reg));
        assertEquals("fail", bare.checks.get("template"));
        assertTrue(bare.reasons.contains("template: the grant has no readable envelope"), bare.reasons.toString());
        // a readable envelope with no link
        Authorize.AuthorizeResult unlinked = go(grant(Issue.defaultRiskPolicy(), star()), null, in -> in.requireLinkedTemplate(() -> reg));
        assertTrue(unlinked.reasons.contains("template: the grant carries no template_ref"), unlinked.reasons.toString());
    }
}
