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

/** Mutation kills for {@code Risk}: non-finite and boundary handling, the budget, and the plan geodesic's graph building. */
class RiskPitKill1Test {
    static final double NAN = Double.NaN;
    static final double PINF = Double.POSITIVE_INFINITY;
    static final double NINF = Double.NEGATIVE_INFINITY;
    static final double EPS = 1e-12;

    static Map<String, Object> weights(double a, double b, double g, double d, double e, double z) {
        Map<String, Object> w = new LinkedHashMap<>();
        w.put("alpha", a); w.put("beta", b); w.put("gamma", g); w.put("delta", d); w.put("epsilon", e); w.put("zeta", z);
        return w;
    }

    // ---- clamp01 / unit / wt / nz

    @Test void clamp01KeepsSignedZeroAndClampsBothSides() {
        assertEquals(-0.0, Risk.clamp01(-0.0));
        assertEquals(0.0, Risk.clamp01(-5));
        assertEquals(1.0, Risk.clamp01(5));
        assertEquals(1.0, Risk.clamp01(1));
        assertEquals(0.3, Risk.clamp01(0.3));
    }

    @Test void unitFailsClosedOnEveryNonFiniteSign() {
        assertEquals(1.0, Risk.unit(NAN, 1));
        assertEquals(0.0, Risk.unit(NAN, 0));
        assertEquals(1.0, Risk.unit(PINF, 1));
        assertEquals(0.0, Risk.unit(PINF, 0));
        assertEquals(1.0, Risk.unit(NINF, 1));
        assertEquals(0.0, Risk.unit(NINF, 0));
        assertEquals(1.0, Risk.unit(5, 0));
        assertEquals(0.0, Risk.unit(-5, 1));
        assertEquals(0.4, Risk.unit(0.4, 1));
    }

    @Test void weightsAreFiniteAndPositiveElseZero() {
        assertEquals(0.0, Risk.wt(NAN));
        assertEquals(0.0, Risk.wt(PINF));
        assertEquals(0.0, Risk.wt(NINF));
        assertEquals(0.0, Risk.wt(-1));
        assertEquals(0.0, Risk.wt(0.0));
        assertEquals(0.0, Risk.wt(-0.0));
        assertEquals(0.25, Risk.wt(0.25));
    }

    @Test void costUsesAPositiveFiniteKappaAndTheWorstCaseForANonFiniteRisk() {
        assertEquals(0.0, Risk.cost(0.5, -0.0));
        assertEquals(0.0, Risk.cost(0.5, 0.0));
        assertEquals(0.0, Risk.cost(0.5, -3));
        assertEquals(0.0, Risk.cost(0.5, NAN));
        assertEquals(0.0, Risk.cost(0.5, PINF));
        assertEquals(0.0, Risk.cost(0.5, NINF));
        assertEquals(2.0, Risk.cost(NAN, 2));
        assertEquals(2.0, Risk.cost(PINF, 2));
        assertEquals(2.0, Risk.cost(NINF, 2));
        assertEquals(1.0, Risk.cost(0.5, 2));
    }

    // ---- riskScore

    @Test void riskScoreWeightsAreSanitisedOnePerSlot() {
        double[] worst = Risk.WORST.clone();
        // a negative weight counts as 0, not as a subtraction
        double[] neg = {-0.1, -0.1, -0.1, -0.1, -0.1, -0.1};
        for (int i = 0; i < 6; i++) {
            double[] ws = {0.1, 0.1, 0.1, 0.1, 0.1, 0.1};
            ws[i] = neg[i];
            Map<String, Object> w = weights(ws[0], ws[1], ws[2], ws[3], ws[4], ws[5]);
            assertEquals(0.5, Risk.riskScore(worst, w), EPS, "negative weight in slot " + i);
            w.remove(new String[] {"alpha", "beta", "gamma", "delta", "epsilon", "zeta"}[i]);
            assertEquals(0.5, Risk.riskScore(worst, w), EPS, "missing weight in slot " + i);
            w.put(new String[] {"alpha", "beta", "gamma", "delta", "epsilon", "zeta"}[i], NAN);
            assertEquals(0.5, Risk.riskScore(worst, w), EPS, "NaN weight in slot " + i);
        }
        assertEquals(0.0, Risk.riskScore(worst, null));
        // all weights negative zero stay a (positive) zero
        assertEquals(0.0, Risk.riskScore(new double[] {0, 1, 0, 0, 1, 0}, weights(-0.0, -0.0, -0.0, -0.0, -0.0, -0.0)));
    }

    @Test void riskScoreTreatsANonFiniteInputAsItsOwnWorstCase() {
        Map<String, Object> w = weights(0.1, 0.1, 0.1, 0.1, 0.1, 0.1);
        double[] calm = {0, 1, 0, 0, 1, 0};
        for (int i = 0; i < 6; i++) {
            double[] in = calm.clone();
            in[i] = NAN;
            assertEquals(0.1, Risk.riskScore(in, w), EPS, "NaN in slot " + i);
            in[i] = PINF;
            assertEquals(0.1, Risk.riskScore(in, w), EPS, "+Inf in slot " + i);
            in[i] = NINF;
            assertEquals(0.1, Risk.riskScore(in, w), EPS, "-Inf in slot " + i);
        }
    }

    // ---- requiredThreshold / escalate / admit

    @Test void requiredThresholdMapsANonFiniteRiskToTheWorstCaseOne() {
        for (double r : new double[] {NAN, PINF, NINF}) {
            Risk.Required q = Risk.requiredThreshold(r, 0.3, 1.5, false);
            assertEquals(2, q.t, "r=" + r);
            assertEquals("standard", q.proof);
            assertFalse(q.optimisticAllowed);
        }
        assertEquals(1, Risk.requiredThreshold(NAN, 1.5, 2, false).t);
        Risk.Required top = Risk.requiredThreshold(0.9, 0.3, 0.6, false);
        assertEquals(3, top.t);
        assertEquals("strong", top.proof);
        assertFalse(top.optimisticAllowed);
        assertTrue(Risk.requiredThreshold(0.1, 0.3, 0.6, false).optimisticAllowed);
        assertFalse(Risk.requiredThreshold(0.1, 0.3, 0.6, true).optimisticAllowed);
    }

    @Test void escalateKeepsAStrongerProofAndFloorsAWeakerOne() {
        assertEquals("strong", Risk.escalate(new Risk.Required(3, "strong", false), 2).proof);
        assertEquals("strong", Risk.escalate(new Risk.Required(2, "strong", false), 2).proof);
        assertEquals("strong", Risk.escalate(new Risk.Required(1, "strong", false), 1).proof);
        assertEquals("standard", Risk.escalate(new Risk.Required(1, "claim", true), 2).proof);
        assertEquals("strong", Risk.escalate(new Risk.Required(1, "claim", true), 3).proof);
        assertEquals("strong", Risk.escalate(new Risk.Required(1, "standard", true), 3).proof);
        assertEquals("claim", Risk.escalate(new Risk.Required(1, "claim", true), 1).proof);
        // an unranked proof ranks with the strongest, so an equal rank keeps it
        assertEquals("custom", Risk.escalate(new Risk.Required(3, "custom", false), 3).proof);
        Risk.Required e = Risk.escalate(new Risk.Required(1, "claim", true), 1);
        assertTrue(e.optimisticAllowed);
        assertFalse(Risk.escalate(new Risk.Required(1, "claim", true), 2).optimisticAllowed);
    }

    @Test void admitSendsAnUncoveredCostBelowTheTopBandToStepUp() {
        Risk.Admission a = Risk.admit(1, false);
        assertFalse(a.admit); assertTrue(a.needStepUp); assertEquals(3, a.t); assertFalse(a.metered);
        a = Risk.admit(2, false);
        assertFalse(a.admit); assertTrue(a.needStepUp); assertEquals(3, a.t); assertFalse(a.metered);
        a = Risk.admit(1, true);
        assertTrue(a.admit); assertFalse(a.needStepUp); assertEquals(1, a.t); assertTrue(a.metered);
        a = Risk.admit(2, true);
        assertFalse(a.admit); assertTrue(a.needStepUp); assertEquals(2, a.t); assertTrue(a.metered);
        a = Risk.admit(3, true);
        assertFalse(a.admit); assertTrue(a.needStepUp); assertEquals(3, a.t); assertFalse(a.metered);
        a = Risk.admit(3, false);
        assertFalse(a.admit); assertTrue(a.needStepUp); assertEquals(3, a.t); assertFalse(a.metered);
    }

    // ---- Budget

    @Test void budgetOfRequiresBAndTauAndDefaultsAsOfToTau() {
        assertNull(Risk.Budget.of("x"));
        assertNull(Risk.Budget.of(null));
        Map<String, Object> m = new LinkedHashMap<>();
        assertNull(Risk.Budget.of(m));
        m.put("B", 4.0);
        assertNull(Risk.Budget.of(m));
        m.remove("B");
        m.put("tau", 10.0);
        assertNull(Risk.Budget.of(m));
        m.put("B", 4.0);
        Risk.Budget b = Risk.Budget.of(m);
        assertNotNull(b);
        assertEquals(4.0, b.b); assertEquals(10.0, b.tau); assertEquals(10.0, b.asOf);
        m.put("asOf", 25.0);
        b = Risk.Budget.of(m);
        assertEquals(25.0, b.asOf);
        assertEquals(10.0, b.tau);
        m.put("asOf", "soon");
        assertEquals(10.0, Risk.Budget.of(m).asOf);
    }

    @Test void budgetToMapCarriesAllThreeFields() {
        Map<String, Object> m = new Risk.Budget(4.0, 10.0, 25.0).toMap();
        assertEquals(3, m.size());
        assertEquals(4.0, m.get("B"));
        assertEquals(10.0, m.get("tau"));
        assertEquals(25.0, m.get("asOf"));
    }

    @Test void leakDrainsPerSecondAndIgnoresNonFiniteClocks() {
        Risk.Budget b = new Risk.Budget(5, 0, 1000);
        Risk.Budget l = Risk.leak(b, 3000, 1);
        assertEquals(3.0, l.b, EPS); assertEquals(3000.0, l.asOf); assertEquals(0.0, l.tau);
        // same instant and a clock that went backwards drain nothing and do not rewind asOf
        l = Risk.leak(b, 1000, 1000);
        assertEquals(5.0, l.b); assertEquals(1000.0, l.asOf);
        l = Risk.leak(b, 500, 1000);
        assertEquals(5.0, l.b); assertEquals(1000.0, l.asOf);
        // non-finite now: nothing drains and asOf is kept
        for (double now : new double[] {NAN, PINF, NINF}) {
            l = Risk.leak(b, now, 1);
            assertEquals(5.0, l.b, "now=" + now); assertEquals(1000.0, l.asOf, "now=" + now);
        }
        // non-finite asOf: nothing drains
        l = Risk.leak(new Risk.Budget(5, 0, NAN), 3000, 1);
        assertEquals(5.0, l.b);
        l = Risk.leak(new Risk.Budget(5, 0, NINF), 3000, 1);
        assertEquals(5.0, l.b);
        l = Risk.leak(new Risk.Budget(5, 0, PINF), 3000, 1);
        assertEquals(5.0, l.b);
        // the budget floors at zero; a non-positive or non-finite lambda drains nothing
        assertEquals(0.0, Risk.leak(b, 100000, 1).b);
        assertEquals(5.0, Risk.leak(b, 3000, -1).b);
        assertEquals(5.0, Risk.leak(b, 3000, NAN).b);
        assertEquals(5.0, Risk.leak(b, 3000, PINF).b);
        assertEquals(5.0, Risk.leak(b, 3000, 0).b);
    }

    @Test void ageSinceTouchIsNormalisedAndFailsClosed() {
        Risk.Budget b = new Risk.Budget(1, 100, 100);
        assertEquals(0.5, Risk.ageSinceTouch(b, 150, 100));
        assertEquals(0.0, Risk.ageSinceTouch(b, 100, 100));
        assertEquals(0.0, Risk.ageSinceTouch(b, 50, 100));
        assertEquals(1.0, Risk.ageSinceTouch(b, 500, 100));
        // horizon: positive only (1 is the smallest probed)
        assertEquals(0.5, Risk.ageSinceTouch(new Risk.Budget(1, 0, 0), 0.5, 1));
        assertEquals(1.0, Risk.ageSinceTouch(new Risk.Budget(1, 100, 100), 100, 0));
        assertEquals(1.0, Risk.ageSinceTouch(b, 150, 0));
        assertEquals(1.0, Risk.ageSinceTouch(b, 150, -10));
        assertEquals(1.0, Risk.ageSinceTouch(b, 150, NAN));
        // each unusable clock on its own
        assertEquals(1.0, Risk.ageSinceTouch(b, NAN, 100));
        assertEquals(1.0, Risk.ageSinceTouch(b, PINF, 100));
        assertEquals(1.0, Risk.ageSinceTouch(b, NINF, 100));
        assertEquals(1.0, Risk.ageSinceTouch(new Risk.Budget(1, NAN, 100), 150, 100));
        assertEquals(1.0, Risk.ageSinceTouch(new Risk.Budget(1, PINF, 100), 150, 100));
        assertEquals(1.0, Risk.ageSinceTouch(new Risk.Budget(1, NINF, 100), 150, 100));
    }

    @Test void debitFloorsAtZeroAndIgnoresABadCost() {
        Risk.Budget b = new Risk.Budget(5, 1, 2);
        assertEquals(3.0, Risk.debit(b, 2).b);
        assertEquals(0.0, Risk.debit(b, 9).b);
        assertEquals(5.0, Risk.debit(b, -2).b);
        assertEquals(5.0, Risk.debit(b, NAN).b);
        assertEquals(1.0, Risk.debit(b, 2).tau);
        assertEquals(2.0, Risk.debit(b, 2).asOf);
    }

    // ---- planGeodesic

    static Map<String, Object> node(String id, Object pre, Object post) {
        Map<String, Object> n = new LinkedHashMap<>();
        if (id != null) n.put("id", id);
        if (pre != null) n.put("pre", pre);
        if (post != null) n.put("post", post);
        return n;
    }

    @Test void geodesicWithoutEdgesIsIndexDistance() {
        List<Object> plan = new ArrayList<>();
        for (String id : new String[] {"a", "b", "c", "d", "e"}) plan.add(node(id, null, null));
        assertEquals(0.75, Risk.planGeodesic(plan, "b", "e"), EPS);
        assertEquals(0.75, Risk.planGeodesic(plan, "e", "b"), EPS);
        assertEquals(0.25, Risk.planGeodesic(plan, "c", "d"), EPS);
        assertEquals(1.0, Risk.planGeodesic(plan, "a", "e"), EPS);
        assertEquals(0.0, Risk.planGeodesic(plan, "c", "c"), EPS);
        assertEquals(1.0, Risk.planGeodesic(plan, "a", "nope"), EPS);
        assertEquals(1.0, Risk.planGeodesic(plan, "nope", "a"), EPS);
        assertEquals(1.0, Risk.planGeodesic(plan, null, "a"), EPS);
    }

    @Test void geodesicSkipsNodesWithoutAStringId() {
        List<Object> plan = new ArrayList<>();
        plan.add(node(null, null, null));
        plan.add(node("b", null, null));
        plan.add("not a node");
        Map<String, Object> numeric = new LinkedHashMap<>();
        numeric.put("id", 7L);
        plan.add(numeric);
        plan.add(node("e", null, null));
        assertEquals(1.0, Risk.planGeodesic(plan, null, "b"), EPS);
        assertEquals(0.75, Risk.planGeodesic(plan, "b", "e"), EPS);
    }

    @Test void geodesicIgnoresASelfReference() {
        List<Object> plan = new ArrayList<>();
        plan.add(node("a", List.of("a"), null));
        plan.add(node("b", null, null));
        plan.add(node("c", null, null));
        plan.add(node("d", null, List.of("d")));
        // no real edge, so the index fallback applies
        assertEquals(1.0 / 3, Risk.planGeodesic(plan, "a", "b"), EPS);
        assertEquals(1.0, Risk.planGeodesic(plan, "a", "d"), EPS);
    }

    @Test void geodesicSingleLinkIsOneHop() {
        List<Object> plan = new ArrayList<>();
        plan.add(node("a", null, null));
        plan.add(node("b", null, null));
        plan.add(node("c", List.of("a"), null));
        plan.add(node("d", null, null));
        assertEquals(1.0 / 3, Risk.planGeodesic(plan, "a", "c"), EPS);
        assertEquals(1.0 / 3, Risk.planGeodesic(plan, "c", "a"), EPS);
        // a node off the graph is unreachable once any edge exists
        assertEquals(1.0, Risk.planGeodesic(plan, "a", "b"), EPS);
    }

    @Test void geodesicWalksPreAndPostReferencesOverTheWholeGraph() {
        // a -post-> d, c -pre-> d (string form), b -pre-> {depends_on: [c, 5]}; e hangs off an unknown reference
        List<Object> plan = new ArrayList<>();
        plan.add(node("a", null, new ArrayList<Object>(List.of("d", 7L, "zzz"))));
        plan.add(node("b", new LinkedHashMap<String, Object>(Map.of("depends_on", new ArrayList<Object>(List.of("c", 5L)))), null));
        plan.add(node("c", "d", null));
        plan.add(node("d", null, null));
        plan.add(node("e", List.of("zzz"), null));
        assertEquals(0.75, Risk.planGeodesic(plan, "a", "b"), EPS);
        assertEquals(0.75, Risk.planGeodesic(plan, "b", "a"), EPS);
        assertEquals(0.25, Risk.planGeodesic(plan, "a", "d"), EPS);
        assertEquals(0.5, Risk.planGeodesic(plan, "a", "c"), EPS);
        assertEquals(0.5, Risk.planGeodesic(plan, "d", "b"), EPS);
        assertEquals(1.0, Risk.planGeodesic(plan, "c", "e"), EPS);
        assertEquals(1.0, Risk.planGeodesic(plan, "e", "a"), EPS);
    }

    @Test void geodesicReadsEveryReferenceKeyAndNodeZero() {
        // node 0 carries the only link, through each of the map keys
        String[] pre = {"after", "depends_on", "requires", "nodes"};
        for (String k : pre) {
            List<Object> plan = new ArrayList<>();
            plan.add(node("a", new LinkedHashMap<String, Object>(Map.of(k, "d")), null));
            plan.add(node("b", null, null));
            plan.add(node("c", null, null));
            plan.add(node("d", null, null));
            assertEquals(1.0 / 3, Risk.planGeodesic(plan, "a", "d"), EPS, k);
            assertEquals(1.0, Risk.planGeodesic(plan, "a", "b"), EPS, k);
        }
        String[] post = {"before", "enables", "then", "next"};
        for (String k : post) {
            List<Object> plan = new ArrayList<>();
            plan.add(node("a", null, new LinkedHashMap<String, Object>(Map.of(k, "d"))));
            plan.add(node("b", null, null));
            plan.add(node("c", null, null));
            plan.add(node("d", null, null));
            assertEquals(1.0 / 3, Risk.planGeodesic(plan, "a", "d"), EPS, k);
            assertEquals(1.0, Risk.planGeodesic(plan, "a", "b"), EPS, k);
        }
    }

    @Test void geodesicIndexFallbackUsesBothOperands() {
        List<Object> plan = new ArrayList<>();
        for (String id : new String[] {"a", "b", "c", "d", "e"}) plan.add(node(id, null, null));
        assertEquals(0.75, Risk.planGeodesic(plan, "b", "e"), EPS);
        assertEquals(0.5, Risk.planGeodesic(plan, "b", "d"), EPS);
        assertEquals(0.5, Risk.planGeodesic(plan, "c", "e"), EPS);
    }
}
