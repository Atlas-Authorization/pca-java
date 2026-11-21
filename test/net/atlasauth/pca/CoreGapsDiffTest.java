package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The salted ledger commit, the v2 goal parser, the profile revocation scope and exposure window and the budget-allocation caveat against the reference corpus, plus the dispute game's fail-closed set. */
class CoreGapsDiffTest {
    private static final String MOD = "ref-core-kotlin-gaps";

    @Test void everyCaseIsReplayed() throws Exception {
        assertEquals(112, BaseOracle.of(MOD, null).size());
        int n = 0;
        for (String fn : new String[] {"entryCommit", "verifyOpening", "ledgerRootOf", "parseIntentGoalV2", "profileRevocationScope", "revocationExposureEnd", "budgetAllocCaveat"}) n += OracleCases.of(MOD, fn).size();
        assertEquals(112, n, "a case of an fn this test does not replay");
    }

    @Test void ledgerCommits() throws Exception {
        OracleCases.each(MOD, "entryCommit", a -> Ledger.entryCommit((String) a.get(0), a.get(1)));
        OracleCases.each(MOD, "verifyOpening", a -> Ledger.verifyOpening((String) a.get(0), a.get(1)));
        OracleCases.each(MOD, "ledgerRootOf", a -> {
            List<String> cs = new ArrayList<>();
            for (Object c : (List<?>) a.get(0)) cs.add((String) c);
            return Ledger.ledgerRootOf(cs);
        });
    }

    @Test void goalScopeWindowAndCaveat() throws Exception {
        OracleCases.each(MOD, "parseIntentGoalV2", a -> IntentSession.parseIntentGoalV2(a.get(0)));
        OracleCases.each(MOD, "profileRevocationScope", a -> IntentRevocation.profileRevocationScope((String) a.get(0)));
        OracleCases.each(MOD, "revocationExposureEnd", a -> a.get(2) == null
            ? IntentRevocation.revocationExposureEnd(OracleCases.num(a.get(0)), OracleCases.num(a.get(1)))
            : IntentRevocation.revocationExposureEnd(OracleCases.num(a.get(0)), OracleCases.num(a.get(1)), OracleCases.num(a.get(2))));
        OracleCases.each(MOD, "budgetAllocCaveat", a -> Pca.budgetAllocCaveat(OracleCases.num(a.get(0))));
        assertEquals(60, (int) IntentRevocation.DEFAULT_REVOCATION_MAX_AGE_S.get("payment"));
        assertEquals(300, (int) IntentRevocation.DEFAULT_REVOCATION_MAX_AGE_S.get("default"));
    }

    private static Map<String, Object> failed(Map<String, Object> r, String reason) {
        assertEquals(Boolean.FALSE, r.get("converged"));
        assertEquals("-1", Json.canonicalize(r.get("contestedStep")));
        Map<String, Object> v = StoreJs.map(r.get("verdict"));
        assertEquals("indeterminate", v.get("outcome"));
        assertEquals(Boolean.FALSE, v.get("fraudulent"));
        assertEquals(Boolean.FALSE, v.get("slashCounterBond"));
        assertFalse(v.containsKey("slashBondRef"));
        assertEquals(reason, v.get("reason"));
        return v;
    }

    /** Every refusal of the dispute game slashes no one. */
    @Test void theDisputeGameFailsClosed() {
        Map<String, Object> claim = Issue.obj("pcactn_digest", "d", "bond_ref", "b", "claimed_r", IntentJs.ofLong(0));
        OptimisticAdjudication.ObjectiveOracle oracle = (in, s) -> null;
        Map<String, Object> snap = new LinkedHashMap<>();
        failed(OptimisticAdjudication.adjudicateDisputeGame(claim, null, null, snap, oracle, null), "malformed dispute game");
        failed(OptimisticAdjudication.adjudicateDisputeGame(claim, Issue.obj("pcactn_digest", "x", "bond_ref", "b"), null, snap, oracle, null), "dispute game targets a different PCActn than the claim");
        failed(OptimisticAdjudication.adjudicateDisputeGame(claim, Issue.obj("pcactn_digest", "d", "bond_ref", "x"), null, snap, oracle, null), "dispute game names a different bond than the claim");
        failed(OptimisticAdjudication.adjudicateDisputeGame(claim, Issue.obj("pcactn_digest", "d", "bond_ref", "b", "steps", new ArrayList<>()), null, snap, oracle, null), "dispute game has no steps");
        failed(OptimisticAdjudication.adjudicateDisputeGame(claim, Issue.obj("pcactn_digest", "d", "bond_ref", "b", "steps", List.of("nope")), null, snap, oracle, null), "unknown disputed input: nope");
        Map<String, Object> short1 = Issue.obj("pcactn_digest", "d", "bond_ref", "b", "steps", List.of("blastRadius"), "defender", new ArrayList<>(), "challenger", new ArrayList<>());
        assertEquals("blastRadius", failed(OptimisticAdjudication.adjudicateDisputeGame(claim, short1, null, snap, oracle, null), "party assertions do not cover every step").get("input"));
        Map<String, Object> full = Issue.obj("pcactn_digest", "d", "bond_ref", "b", "steps", List.of("blastRadius"),
            "defender", List.of(Issue.obj("value", IntentJs.ofLong(0))), "challenger", List.of(Issue.obj("value", IntentJs.ofLong(1))));
        failed(OptimisticAdjudication.adjudicateDisputeGame(claim, full, null, null, oracle, null), "no frozen open-time snapshot supplied; cannot adjudicate");
        failed(OptimisticAdjudication.adjudicateDisputeGame(claim, full, null, snap, null, null), "no objective oracle supplied");
    }
}
