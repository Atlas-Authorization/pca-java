package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import net.atlasauth.pca.servlet.PcaFilter;
import org.junit.jupiter.api.Test;

/** Mutation kills for the conformance runners, session revocation text, break-glass reads, the signature-only filter and the authorize risk and forbid steps. */
class SurvivorKillLaneBTest {
    // ---- the budget conformance runner: a replay answer is refused AND not a conflict AND carries the stored counter

    @Test void aReplayAnswerThatIsOkOrAConflictIsNotAReplay() throws Exception {
        String t = "fail budget-replay-spends-nothing: a replay must report the stored counter, got ";
        StateStore.ClaimResult okWithCounter = new StateStore.ClaimResult(true, 1L);
        StoreConformancePitKill1Test.budgetFault(2, t + "ClaimResult{ok=true, lastCounter=1}",
            (h, p, c, bf, af, r) -> p.equals("b3") && bf != null ? okWithCounter : r.get(), null);
        Constructor<StateStore.ClaimResult> ct = StateStore.ClaimResult.class.getDeclaredConstructor(boolean.class, Long.class, boolean.class);
        ct.setAccessible(true);
        StateStore.ClaimResult conflictWithCounter = ct.newInstance(false, 1L, true);
        StoreConformancePitKill1Test.budgetFault(2, t + "ClaimResult{ok=false, lastCounter=1}",
            (h, p, c, bf, af, r) -> p.equals("b3") && bf != null ? conflictWithCounter : r.get(), null);
    }

    // ---- the kv conformance runner: the shard-count test works whatever the store was first pinned to

    static StoreConformance.Report kvWithThird(AtomicKv third) {
        MemoryAtomicKv shared = new MemoryAtomicKv();
        AtomicInteger opens = new AtomicInteger();
        return StoreConformance.runKvRegistryConformance(() -> opens.getAndIncrement() == 2 ? third : shared, new StoreConformance.Options().threads(3).handles(2),
            StoreConformancePitKill1Test.lease(), StoreConformancePitKill1Test.bg(), StoreConformancePitKill1Test.bp());
    }

    @Test void theShardCountTestPinsAnUnpinnedStoreToThreeWithTheFirstLeaseRecord() {
        MemoryAtomicKv third = new MemoryAtomicKv();
        StoreConformance.Report rep = kvWithThird(third);
        assertEquals(StoreConformancePitKill1Test.kvRender(-1, null), rep.render());
        Map<?, ?> rec = (Map<?, ?>) ((List<?>) StoreConformancePitKill1Test.lease().get("records")).get(0);
        String id = (String) rec.get("lease_id");
        assertEquals(3L, Json.asLong(((Map<?, ?>) third.get("lease/meta")).get("shards")));
        Object shard = third.get("lease/3/" + Lease.shardOf(id, 3));
        assertNotNull(shard);
        assertTrue(Json.canonicalize(shard).contains("\"lease_id\":\"" + id + "\""), Json.canonicalize(shard));
    }

    @Test void theShardCountTestAlsoPassesOnAStoreAlreadyPinnedToFive() {
        MemoryAtomicKv third = new MemoryAtomicKv();
        assertTrue(Lease.pinShards(third, "lease/meta", 5));
        assertEquals(StoreConformancePitKill1Test.kvRender(-1, null), kvWithThird(third).render());
        assertEquals(5L, Json.asLong(((Map<?, ?>) third.get("lease/meta")).get("shards")));
    }

    // ---- IntentRevocation

    @Test void jsTextPrintsEveryJavaNumberTheWayJavaScriptDoes() {
        assertEquals("1e+21", IntentRevocation.jsText(1e21, true));
        assertEquals("2", IntentRevocation.jsText(2.0, true));
        assertEquals("0.5", IntentRevocation.jsText(0.5, true));
        assertEquals("5", IntentRevocation.jsText(5L, true));
        assertEquals("undefined", IntentRevocation.jsText(5L, false));
    }

    @Test void thePrimitiveInputIsNormalizedBeforeItsSignedNumbersAreRead() {
        long issued = IntentV2KillTest.NOW - 1_000;
        Map<String, Object> evidence = IntentV2KillTest.evidence(List.of("pca-intent:zzz"), issued, IntentV2KillTest.REV);
        Map<String, Object> ep = IntentV2KillTest.m(evidence.get("epoch"));
        ep.put("issued_at", new Json.Num(issued + ".0")); // the same number, spelled the way a decoder may hand it over
        Map<String, Object> in = IntentV2KillTest.map("epoch", ep, "revoked", IntentV2KillTest.list("pca-intent:zzz"), "session", IntentV2KillTest.SESSION,
            "authority", IntentV2KillTest.pub(IntentV2KillTest.REV), "ids", IntentV2KillTest.list(IntentV2KillTest.ID_SESSION), "now", IntentV2KillTest.NOW,
            "max_age_ms", 60_000L);
        assertNull(IntentRevocation.primitiveReason(in));
        assertTrue(IntentRevocation.checkPrimitive(in));
    }

    // ---- BreakGlass.uses on a store pinned to another shard count answers with a fresh mutable list

    @Test void theUseLogOfAStorePinnedElsewhereIsAFreshEmptyList() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        assertTrue(Lease.pinShards(kv, "breakglass/meta", 3));
        BreakGlass.Registry r = new BreakGlass.Registry(List.of("a"), List.of("r"), kv, 5);
        List<Object> first = r.uses("holder", "id");
        assertTrue(first.isEmpty());
        first.add("x");
        assertEquals(1, first.size());
        assertTrue(r.uses("holder", "id").isEmpty());
    }

    // ---- PcaFilter: a null list of authorized roots is not the opt-out

    @Test void aNullListOfAuthorizedPlanRootsStillEnforcesTheCheck() throws Exception {
        PcaFilter f = WiringAndDerPitKill1Test.signatureOnly();
        assertSame(f, f.withAuthorizedPlanRoots(null));
        WiringAndDerPitKill1Test.refused(WiringAndDerPitKill1Test.status(f), "no list given authorizes nothing, it does not skip the check");
    }

    // ---- authorize: forbid context, amount risk, required inputs, adaptive policy

    @Test void aForbidContextThatReturnsNothingAddsNothingAndStillAllows() {
        Authorize.ForbidOptions fo = new Authorize.ForbidOptions((op, g) -> new ArrayList<>(List.<Object>of(
            AuthorizeGatesPitKill1Test.clause("p", "permit", AuthorizeGatesPitKill1Test.verbWhen()))));
        fo.context = op -> null;
        Authorize.AuthorizeResult r = AuthorizeGatesPitKill1Test.forbid(fo);
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("pass", r.checks.get("forbid"));
    }

    @Test void aKappaThatIsNotPositivePricesNothing() {
        for (String kappa : new String[] {"0", "-1"}) {
            Map<String, Object> g = AuthorizeRiskPitKill1Test.grant(AuthorizeRiskPitKill1Test.policy("0.25", "0.6", kappa, "0.0005", "10"), AuthorizeRiskPitKill1Test.star());
            assertNull(Authorize.amountRisk(g, Map.of("amount", 50L)), kappa);
            assertNull(Authorize.amountRisk(g, Map.of("amount", 0L)), kappa);
        }
    }

    @Test void aRequiredDistanceIsMissingWhenThereIsNeitherARiskInputNorAPlan() {
        Map<String, Object> g = AuthorizeRiskPitKill1Test.grant(AuthorizeRiskPitKill1Test.stepUp(), AuthorizeRiskPitKill1Test.star());
        Map<String, Object> pc = AuthorizeRunK05bKillTest.agent(g).act("payments.send", "payments/acme", Issue.obj("amount", 50L), null);
        Authorize.AuthorizeResult r = Authorize.authorize(pc, AuthorizeRunK05bKillTest.in(g).risk(null).plan(null)
            .context(p -> AuthorizeRiskPitKill1Test.c("risk", AuthorizeRiskPitKill1Test.riskWithoutDistance(), "budget", AuthorizeRiskPitKill1Test.bud(1000, AuthorizeRiskPitKill1Test.NOW, AuthorizeRiskPitKill1Test.NOW)))
            .requireRiskInputs(List.of("semanticDistance")));
        assertEquals("fail", r.checks.get("risk_inputs"), r.reasons.toString());
        assertTrue(r.reasons.contains("risk_inputs: required risk input(s) not supplied by the server: semanticDistance"), r.reasons.toString());
        assertTrue(r.reasons.contains("policy: risk input(s) missing, assumed worst case: semanticDistance"), r.reasons.toString());
        assertFalse(r.checks.containsKey("authorize"), r.checks.toString());
    }

    static Map<String, Object> adaptive(double theta1, double theta2) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("weights", RiskTest.DEFAULT);
        m.put("theta1", theta1);
        m.put("theta2", theta2);
        m.put("kappa", 1L);
        m.put("lambda", 0L);
        m.put("rho", 0L);
        m.put("bMax", 10L);
        return m;
    }

    @Test void anAdaptivePolicyWhoseMiddleBandStillCoversTheRiskIsNoTighter() {
        long touched = AuthorizeRiskPitKill1Test.NOW - 100_000L;
        Map<String, Object> same = adaptive(0.25, 0.5);
        Authorize.AuthorizeResult r = AuthorizeRiskPitKill1Test.go(AuthorizeRiskPitKill1Test.grant(AuthorizeRiskPitKill1Test.mid(), AuthorizeRiskPitKill1Test.star()), AuthorizeRiskPitKill1Test.caution("0.4"),
            in -> in.context(p -> AuthorizeRiskPitKill1Test.c("risk", RiskCtx.zero(), "budget", AuthorizeRiskPitKill1Test.bud(10, touched, touched)))
                .thresholdHook(pc -> new Authorize.ThresholdOutcome(true, true, 2)).adaptivePolicy(now -> same));
        assertTrue(r.allow, r.reasons.toString());
        assertFalse(r.checks.containsKey("adaptive"), r.checks.toString());
        // the same call under a policy whose middle band ends below the risk needs t=3: tighter
        Map<String, Object> tighter = adaptive(0.25, 0.3);
        Authorize.AuthorizeResult t = AuthorizeRiskPitKill1Test.go(AuthorizeRiskPitKill1Test.grant(AuthorizeRiskPitKill1Test.mid(), AuthorizeRiskPitKill1Test.star()), AuthorizeRiskPitKill1Test.caution("0.4"),
            in -> in.context(p -> AuthorizeRiskPitKill1Test.c("risk", RiskCtx.zero(), "budget", AuthorizeRiskPitKill1Test.bud(10, touched, touched)))
                .thresholdHook(pc -> new Authorize.ThresholdOutcome(true, true, 2)).adaptivePolicy(now -> tighter));
        assertFalse(t.allow);
        assertEquals("fail", t.checks.get("adaptive"));
    }

    @Test void theAdaptivePolicyIsNotEvenReadWhenThePolicyIsNotReleased() {
        List<Object> nope = new ArrayList<>(List.<Object>of(Issue.obj("verb", "other")));
        AtomicInteger reads = new AtomicInteger();
        Map<String, Object> invalid = new LinkedHashMap<>();
        Authorize.AuthorizeResult r = AuthorizeRiskPitKill1Test.go(AuthorizeRiskPitKill1Test.grant(AuthorizeRiskPitKill1Test.mid(), nope), AuthorizeRiskPitKill1Test.caution("0.9"),
            in -> in.context(p -> AuthorizeRiskPitKill1Test.c("risk", RiskCtx.zero(), "budget", AuthorizeRiskPitKill1Test.bud(10, AuthorizeRiskPitKill1Test.NOW, AuthorizeRiskPitKill1Test.NOW)))
                .adaptivePolicy(now -> { reads.incrementAndGet(); return invalid; }));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("policy"));
        assertEquals(0, reads.get());
        assertFalse(r.checks.containsKey("adaptive"), r.checks.toString());
    }
}
