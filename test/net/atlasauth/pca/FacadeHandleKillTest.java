package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * The facade's agent handle: options, minting, the starting budget, the advisory dry run, the risk claim, acting and sub-agents.
 * Expected values are the TypeScript reference's (facade.ts {@code agent}) for the same inputs; the Ed25519-identity and
 * post-quantum sub-agent checks are this SDK's own.
 */
public class FacadeHandleKillTest {
    static final long NOW = 1_800_000_000_000L;
    static final Keys.SuiteKey PRINCIPAL = Keys.ed25519(Keys.edFromSeed(new byte[32]));
    static final Keys.EdKey AGENT_ED = Keys.edFromSeed(ProducerTest.fill(1, 32));
    static final Keys.SuiteKey AGENT = Keys.ed25519(AGENT_ED);

    static String canon(Object o) { return Json.canonicalize(o); }

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static Facade.AgentOptions opts(Map<String, Object> permissions) {
        return new Facade.AgentOptions(PRINCIPAL, "goal", permissions).holder(AGENT).aud("rs").now(NOW).goalSalt("s");
    }

    static Facade.Handle handle(Map<String, Object> permissions) { return Facade.agent(opts(permissions)); }

    static Facade.Handle handle(Map<String, Object> permissions, Map<String, Object> limits) { return Facade.agent(opts(permissions).limits(limits)); }

    static Facade.Handle withRisk(Map<String, Object> permissions, Map<String, Object> riskPolicy) { return Facade.agent(opts(permissions).riskPolicy(riskPolicy)); }

    static Facade.ActOptions at(long now) {
        Facade.ActOptions o = new Facade.ActOptions();
        o.now = now;
        return o;
    }

    static Map<String, Object> envelope(Facade.Handle h) { return m(l(h.grant.get("caveats")).get(0)); }

    // ---- options -------------------------------------------------------------------------------------------------------------

    @Test void theOptionsKeepEveryMemberTheyAreGiven() {
        ArgProvenance.Recorder rec = ArgProvenance.Recorder.create("m1", "k9");
        Catalog cat = new Catalog(List.of());
        Map<String, Object> permissions = Issue.obj("stripe", List.of("refund"));
        Map<String, Object> limits = Issue.obj("refund", "$5"), binding = Issue.obj("operator", "acme"), risk = Issue.obj("rho", new Json.Num("0.9"));
        Facade.AgentOptions o = new Facade.AgentOptions(PRINCIPAL, "the goal", permissions);
        assertSame(o, o.limits(limits));
        assertSame(o, o.holder(AGENT));
        assertSame(o, o.agentBinding(binding));
        assertSame(o, o.riskPolicy(risk));
        assertSame(o, o.budgetModel("risk"));
        assertSame(o, o.catalog(cat));
        assertSame(o, o.aud("aud-1"));
        assertSame(o, o.now(77L));
        assertSame(o, o.goalSalt("salt-1"));
        assertSame(o, o.provenance(rec));
        assertSame(PRINCIPAL, o.principal);
        assertEquals("the goal", o.goal);
        assertSame(permissions, o.permissions);
        assertSame(limits, o.limits);
        assertSame(AGENT, o.holder);
        assertSame(binding, o.agentBinding);
        assertSame(risk, o.riskPolicy);
        assertEquals("risk", o.budgetModel);
        assertSame(cat, o.catalog);
        assertEquals("aud-1", o.aud);
        assertEquals(77L, o.now);
        assertEquals("salt-1", o.goalSalt);
        assertSame(rec, o.recorder);
    }

    // ---- minting -------------------------------------------------------------------------------------------------------------

    @Test void aHandleExposesTheGrantTheChainAndTheKeys() {
        ArgProvenance.Recorder rec = ArgProvenance.Recorder.create("m1", "k9");
        Map<String, Object> binding = Issue.obj("operator", "acme");
        Facade.Handle h = Facade.agent(opts(Issue.obj("github", List.of("read"))).agentBinding(binding).goalSalt("salt-1").provenance(rec));
        assertEquals(1, h.chain.size());
        assertSame(h.grant, h.chain.get(0));
        assertEquals("salt-1", h.goalSalt);
        assertSame(AGENT, h.holder);
        assertEquals(PRINCIPAL.ed.id(), h.principalPublic);
        assertSame(rec, h.provenance);
        assertEquals(AGENT_ED.id(), h.grant.get("holder"));
        assertEquals(PRINCIPAL.ed.id(), h.grant.get("issuer"));
        assertFalse(h.grant.containsKey("holder_pq"));
        Map<String, Object> env = envelope(h);
        assertEquals("{\"operator\":\"acme\"}", canon(env.get("agent_binding")));
        assertEquals(canon(Issue.obj("mediators", List.of(rec.pin()))), canon(env.get("provenance")));
        assertEquals(Issue.goalCommit("goal", "salt-1"), env.get("goal_commit"));
        assertEquals(canon(h.policy.predicates), canon(env.get("predicates")));
        assertEquals(canon(h.policy.caveats), canon(env.get("caveats")));
        assertEquals(canon(h.policy.riskPolicy), canon(env.get("risk_policy")));
        assertEquals(Json.canonicalize(h.grant), h.encodeGrant());
        // no binding: the envelope carries {}
        assertEquals("{}", canon(envelope(handle(Issue.obj("github", List.of("read")))).get("agent_binding")));
    }

    @Test void aHandleBuiltWithDefaultsGeneratesItsKeySaltClockAndRecorder() {
        long before = System.currentTimeMillis();
        Facade.Handle h = Facade.agent(new Facade.AgentOptions(PRINCIPAL, "goal", Issue.obj("github", List.of("read"))));
        assertEquals("ed25519", h.holder.alg);
        assertNotNull(h.holder.ed);
        assertEquals(h.holder.ed.id(), h.grant.get("holder"));
        assertEquals(22, h.goalSalt.length());
        assertEquals("agent-harness", h.provenance.pin().get("mediator"));
        assertEquals("k1", h.provenance.pin().get("kid"));
        long tau = Json.asLong(h.budget().get("tau"));
        assertTrue(tau >= before && tau <= System.currentTimeMillis(), Long.toString(tau));
        Facade.Handle other = Facade.agent(new Facade.AgentOptions(PRINCIPAL, "goal", Issue.obj("github", List.of("read"))));
        assertNotEquals(h.goalSalt, other.goalSalt);
        assertNotEquals(h.holder.ed.id(), other.holder.ed.id());
        assertEquals("{}", canon(envelope(h).get("agent_binding")));
    }

    static String agentRefusal(Facade.AgentOptions o) { return FacadeKillTest.refusal(() -> Facade.agent(o)); }

    @Test void aHandleNeedsAnEd25519HolderAndPrincipal() {
        Keys.SuiteKey purePq = Keys.suite("ml-dsa-65", null, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ProducerTest.fill(7, 32)));
        Map<String, Object> perms = Issue.obj("github", List.of("read"));
        assertEquals("agent: the holder needs an Ed25519 identity", agentRefusal(new Facade.AgentOptions(PRINCIPAL, "g", perms).holder(purePq)));
        assertEquals("agent: the principal needs an Ed25519 identity", agentRefusal(new Facade.AgentOptions(purePq, "g", perms).holder(AGENT)));
        assertEquals("agent: the principal needs an Ed25519 identity", agentRefusal(new Facade.AgentOptions(null, "g", perms).holder(AGENT)));
    }

    @Test void aPostQuantumHolderCommitsItsKeyInTheGrant() {
        Keys.PqKey pq = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ProducerTest.fill(7, 32));
        Facade.Handle h = Facade.agent(opts(Issue.obj("github", List.of("read"))).holder(Keys.suite("hybrid-ed25519-ml-dsa-65", AGENT_ED, pq)));
        assertEquals(Pca.holderPqCommitment(pq.pkB64u()), h.grant.get("holder_pq"));
        assertEquals(AGENT_ED.id(), h.grant.get("holder"));
    }

    @Test void aHandleUsesTheCatalogItWasGiven() {
        Facade.Handle h = Facade.agent(opts(Issue.obj("bank", List.of("transfer"))).limits(Issue.obj("transfer", "$100")).catalog(FacadeKillTest.bank()));
        assertEquals(List.of("bank.transfer"), FacadeKillTest.verbs(h.policy));
        Facade.ActResult r = h.act("bank.transfer", "acct:1", Issue.obj("amt", 50L), at(NOW));
        assertEquals("reversible", m(r.pcactn.get("action")).get("reversibility_class"));
        assertEquals("{\"inputs\":{\"blastRadius\":0.5},\"r\":0.5}", canon(r.pcactn.get("risk_claim")));
        assertTrue(r.dryRun.allowed);
        assertEquals(1, r.dryRun.t);
        // and the budget model and risk policy it was given
        Facade.Handle risk = Facade.agent(opts(Issue.obj("stripe", List.of("refund"))).limits(Issue.obj("refund", "$500")).budgetModel("risk"));
        assertEquals("risk", risk.policy.budgetModel);
        assertEquals("0.9", canon(withRisk(Issue.obj("github", List.of("read")), Issue.obj("rho", new Json.Num("0.9"))).policy.riskPolicy.get("rho")));
    }

    // ---- budget --------------------------------------------------------------------------------------------------------------

    @Test void theStartingBudgetAndTheAutonomyBoundFollowThePolicy() {
        Facade.Handle h = handle(Issue.obj("stripe", List.of("refund", "payout")), Issue.obj("refund", "$200", "payout", "$200"));
        Map<String, Object> b = h.budget();
        assertEquals(List.of("B", "tau", "asOf"), new ArrayList<>(b.keySet()));
        assertEquals(400L, b.get("B"));
        assertEquals(NOW, b.get("tau"));
        assertEquals(NOW, b.get("asOf"));
        assertEquals(400.0, h.autonomyBound(), 0.0);
        Facade.Handle risk = handle(Issue.obj("github", List.of("read")));
        assertEquals("{\"B\":1,\"asOf\":" + NOW + ",\"tau\":" + NOW + "}", canon(risk.budget()));
        assertEquals(1.0, risk.autonomyBound(), 0.0);
        Facade.Handle frac = handle(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$12.5"));
        assertEquals("12.5", canon(frac.budget().get("B")));
        assertEquals(12.5, frac.autonomyBound(), 0.0);
        Facade.Handle small = withRisk(Issue.obj("github", List.of("read")), Issue.obj("bMax", new Json.Num("0.4")));
        assertEquals("0.4", canon(small.budget().get("B")));
        assertEquals(0.4, small.autonomyBound(), 1e-12);
        // bMax / kappa * kappa: a cap other than one
        Facade.Handle k4 = withRisk(Issue.obj("github", List.of("read")), Issue.obj("kappa", 4L, "bMax", 2L));
        assertEquals(2.0, k4.autonomyBound(), 0.0);
        Facade.Handle half = withRisk(Issue.obj("github", List.of("read")), Issue.obj("kappa", new Json.Num("0.5")));
        assertEquals(1.0, half.autonomyBound(), 0.0);
    }

    @Test void theAutonomyBoundReadsThePolicyAsTheReferenceFormulaDoes() {
        // the policy is a plain map: the formula max(0, bMax) / kappa * kappa, and 0 for a cap that is not positive, holds for any value in it
        Facade.Handle neg = handle(Issue.obj("github", List.of("read")));
        neg.policy.riskPolicy.put("bMax", -2L);
        assertEquals(0.0, neg.autonomyBound(), 0.0);
        Facade.Handle zero = handle(Issue.obj("github", List.of("read")));
        zero.policy.riskPolicy.put("kappa", 0L);
        assertEquals(0.0, zero.autonomyBound(), 0.0);
        Facade.Handle below = handle(Issue.obj("github", List.of("read")));
        below.policy.riskPolicy.put("kappa", -1L);
        assertEquals(0.0, below.autonomyBound(), 0.0);
    }

    // ---- the advisory pre-check ----------------------------------------------------------------------------------------------

    static Integer tier(Facade.Handle h, String verb, Map<String, Object> params) {
        Facade.DryRun d = h.dryRun(verb, "r", params, NOW);
        assertTrue(d.allowed, d.reason);
        assertNull(d.reason);
        return d.t;
    }

    @Test void aDryRunSaysWhichTierAdmissionWouldAssign() {
        Facade.Handle h = handle(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$500"));
        long[][] cases = {{100, 1}, {300, 2}, {400, 3}, {125, 1}, {126, 2}, {301, 3}, {500, 3}, {0, 1}};
        for (long[] c : cases) assertEquals((int) c[1], tier(h, "stripe.refund", Issue.obj("amount", c[0])), Long.toString(c[0]));
    }

    @Test void aDryRunEscalatesWhenTheBudgetDoesNotCoverTheCost() {
        // blast radius 0.5: tier 2 on the default policy; a cost above the budget needs a human co-sign
        assertEquals(3, tier(withRisk(Issue.obj("slack", List.of("post_message")), Issue.obj("bMax", new Json.Num("0.4"))), "slack.post_message", null));
        assertEquals(2, tier(handle(Issue.obj("slack", List.of("post_message"))), "slack.post_message", null));
        assertEquals(2, tier(withRisk(Issue.obj("slack", List.of("post_message")), Issue.obj("bMax", new Json.Num("0.5"))), "slack.post_message", null));
        // tier 1 stays tier 1 only while the budget covers kappa * r
        assertEquals(3, tier(withRisk(Issue.obj("github", List.of("read")), Issue.obj("bMax", new Json.Num("0.04"))), "github.read", null));
        assertEquals(1, tier(withRisk(Issue.obj("github", List.of("read")), Issue.obj("bMax", new Json.Num("0.05"))), "github.read", null));
        assertEquals(1, tier(withRisk(Issue.obj("github", List.of("read")), Issue.obj("kappa", 2L, "bMax", new Json.Num("0.1"))), "github.read", null));
        assertEquals(3, tier(withRisk(Issue.obj("github", List.of("read")), Issue.obj("kappa", 2L, "bMax", new Json.Num("0.09"))), "github.read", null));
    }

    @Test void aDryRunNamesWhyNoPredicatePermits() {
        Facade.Handle h = handle(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$500"));
        String[][] cases = {{"stripe.charge", "5", "no predicate permits stripe.charge on charge:1"},
            {"stripe.refund", "501", "amount <= 500 not satisfied for stripe.refund on charge:1"},
            {"stripe.refund", "-1", "amount >= 0 not satisfied for stripe.refund on charge:1"},
            {"stripe.refund", null, "amount <= 500 not satisfied for stripe.refund on charge:1"}};
        for (String[] c : cases) {
            Facade.DryRun d = h.dryRun(c[0], "charge:1", c[1] == null ? null : Issue.obj("amount", Long.parseLong(c[1])), NOW);
            assertFalse(d.allowed, c[2]);
            assertEquals(c[2], d.reason);
            assertNull(d.t);
        }
        assertEquals("no predicate permits foo on r", handle(Issue.obj("stripe", List.of("refund"))).dryRun("foo", "r", null, NOW).reason);
        assertEquals("no predicate permits stripe.issue_refund on r", handle(Issue.obj("stripe", List.of("refund"))).dryRun("stripe.issue_refund", "r", null, NOW).reason);
    }

    @Test void aDryRunNamesEveryFailedCaveatInOrder() {
        Facade.Handle h = handle(Issue.obj("github", List.of("comment")), Issue.obj("comment", "0/hour"));
        Facade.DryRun within = h.dryRun("github.comment", "pr:1", null, NOW + 1000);
        assertFalse(within.allowed);
        assertEquals("caveat(s) failed: rate", within.reason);
        assertNull(within.t);
        assertEquals("caveat(s) failed: expires, rate", h.dryRun("github.comment", "pr:1", null, NOW + 3_600_001L).reason);
        // the grant lifetime ends at the window: valid one millisecond before, expired at the instant
        Facade.Handle h2 = handle(Issue.obj("github", List.of("comment")), Issue.obj("comment", "5/hour"));
        assertTrue(h2.dryRun("github.comment", "pr:1", null, NOW + 3_600_000L - 1).allowed);
        assertEquals("caveat(s) failed: expires", h2.dryRun("github.comment", "pr:1", null, NOW + 3_600_000L).reason);
        // a rate limit with room is satisfied: there is no admitted-action history locally
        Facade.DryRun ok = h2.dryRun("github.comment", "pr:1", null, NOW);
        assertTrue(ok.allowed);
        assertEquals(1, ok.t);
    }

    @Test void aDryRunUsesTheClockItIsGivenElseTheCurrentTime() {
        Facade.Handle old = Facade.agent(opts(Issue.obj("github", List.of("comment"))).limits(Issue.obj("comment", "5/day")).now(1_000L));
        assertEquals("caveat(s) failed: expires", old.dryRun("github.comment", "pr:1", null, null).reason);
        assertTrue(old.dryRun("github.comment", "pr:1", null, 2_000L).allowed);
        assertEquals("caveat(s) failed: expires", old.dryRun("github.comment", "pr:1", null, 1_000L + 2 * 86_400_000L).reason);
        Facade.Handle fresh = Facade.agent(opts(Issue.obj("github", List.of("comment"))).limits(Issue.obj("comment", "5/day")).now(System.currentTimeMillis()));
        assertTrue(fresh.dryRun("github.comment", "pr:1", null, null).allowed);
    }

    @Test void aDryRunChecksTheActionItBuilds() {
        // the action context carries the params ({} when none) and the catalog's reversibility class; the caveat context the blast
        // radius and the delegation depth. The handle's own predicates and caveats never read these, so extra ones are added here.
        Facade.Handle h = handle(Issue.obj("github", List.of("read")));
        h.policy.predicates.add(Issue.obj("verb", "x.none", "where", List.of(Issue.obj("field", "action.params.amount", "op", "exists", "value", false))));
        h.policy.predicates.add(Issue.obj("verb", "x.irrev", "where", List.of(Issue.obj("field", "action.reversibility_class", "op", "eq", "value", "irreversible"))));
        h.policy.caveats.set(0, Issue.obj("type", "reversibility_max", "class", "irreversible"));
        assertTrue(h.dryRun("x.none", "r", null, NOW).allowed);
        assertTrue(h.dryRun("x.irrev", "r", null, NOW).allowed);
        h.policy.caveats.add(Issue.obj("type", "max_blast_radius", "max", new Json.Num("0.5")));
        h.policy.caveats.add(Issue.obj("type", "delegation_depth", "max", 0L));
        assertTrue(h.dryRun("github.read", "r", null, NOW).allowed);
        assertEquals("caveat(s) failed: max_blast_radius", h.dryRun("x.irrev", "r", null, NOW).reason);
        Facade.Handle sub = h.subAgent(null, new ArrayList<Object>());
        assertEquals("caveat(s) failed: delegation_depth", sub.dryRun("github.read", "r", null, NOW).reason);
        Facade.Handle subSub = sub.subAgent(null, new ArrayList<Object>());
        assertEquals("caveat(s) failed: delegation_depth", subSub.dryRun("github.read", "r", null, NOW).reason);
        h.policy.caveats.set(h.policy.caveats.size() - 1, Issue.obj("type", "delegation_depth", "max", 1L));
        assertTrue(sub.dryRun("github.read", "r", null, NOW).allowed);
        assertEquals("caveat(s) failed: delegation_depth", subSub.dryRun("github.read", "r", null, NOW).reason);
    }

    @Test void theRiskTierOfADryRunUsesTheAmountOnlyForAMoneyVerb() {
        Facade.Handle h = Facade.agent(opts(Issue.obj("stripe", List.of("refund"), "gmail", List.of("draft"))).limits(Issue.obj("refund", "$500")));
        // gmail.draft has no amount field: its blast radius (0.2) decides, whatever the params hold, even under a null key
        Map<String, Object> odd = new LinkedHashMap<>();
        odd.put(null, 400L);
        odd.put("amount", 400L);
        assertEquals(1, tier(h, "gmail.draft", odd));
    }

    // ---- the risk claim ------------------------------------------------------------------------------------------------------

    static String claim(Facade.Handle h, String verb, Map<String, Object> params, Facade.ActOptions o) {
        return canon(h.act(verb, "charge:1", params, o).pcactn.get("risk_claim"));
    }

    static String claimOf(String r) { return "{\"inputs\":{\"blastRadius\":" + r + "},\"r\":" + r + "}"; }

    static Map<String, Object> amount(Object v) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("amount", v);
        return p;
    }

    @Test void theRiskOfADollarActionIsItsShareOfTheCapReadAsJavaScriptNumber() {
        Facade.Handle h = handle(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$500"));
        Object[][] cases = {{100L, "0.2"}, {"100", "0.2"}, {" 100 ", "0.2"}, {"1e2", "0.2"}, {new Json.Num("100"), "0.2"}, {new Json.Num("12.5"), "0.025"},
            {true, "0.002"}, {false, "0"}, {null, "0"}, {"", "0"}, {"  ", "0"}, {0L, "0"}, {-50L, "0"}, {500L, "1"}, {5000L, "1"},
            {List.of(1L), "0.002"}, {List.of(List.of(5L)), "0.01"}, {List.of(), "0"}, {"0x10", "0.032"}, {"0b11", "0.006"}, {"0o7", "0.014"},
            {"  7﻿", "0.014"}, {"+5", "0.01"}, {".5", "0.001"}, {"5.", "0.01"}};
        for (Object[] c : cases) assertEquals(claimOf((String) c[1]), claim(h, "stripe.refund", amount(c[0]), at(NOW)), String.valueOf(c[0]));
    }

    @Test void anAmountThatIsNotAFiniteNumberFallsBackToTheBlastRadius() {
        Facade.Handle h = handle(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$500"));
        String blast = claimOf("0.9");
        assertEquals(blast, claim(h, "stripe.refund", null, at(NOW)));
        assertEquals(blast, claim(h, "stripe.refund", Issue.obj(), at(NOW)));
        assertEquals(blast, claim(h, "stripe.refund", Issue.obj("other", 1L), at(NOW)));
        for (Object v : new Object[] {"abc", "NaN", "Infinity", "-Infinity", "1e400", "1d", "1_0", "\u001C5", List.of(1L, 2L), Issue.obj()})
            assertEquals(blast, claim(h, "stripe.refund", amount(v), at(NOW)), String.valueOf(v));
    }

    @Test void aCapBelowOneStillScalesTheAmount() {
        Facade.Handle h = handle(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$0.5"));
        assertEquals(claimOf("0.5"), claim(h, "stripe.refund", amount(new Json.Num("0.25")), at(NOW)));
        assertEquals(claimOf("1"), claim(h, "stripe.refund", amount(new Json.Num("0.5")), at(NOW)));
    }

    @Test void aCapThatIsNotPositiveScalesNothing() {
        // the policy is a plain map: with a cap of 0 the amount is not divided by it and the blast radius decides
        Facade.Handle h = handle(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$500"));
        h.policy.riskPolicy.put("kappa", 0L);
        assertEquals(claimOf("0.9"), claim(h, "stripe.refund", amount(100L), at(NOW)));
    }

    @Test void theBlastRadiusOfAnActionIsClampedToZeroAndOne() {
        Catalog cat = new Catalog(List.of(new Catalog.Spec("c", "wide", "c.wide", "reversible", 5.0, null, "d", null, null),
            new Catalog.Spec("c", "neg", "c.neg", "reversible", -0.5, null, "d", null, null)));
        Facade.Handle h = Facade.agent(opts(Issue.obj("c", List.of("wide", "neg"))).catalog(cat));
        assertEquals(claimOf("1"), claim(h, "c.wide", null, at(NOW)));
        assertEquals(claimOf("0"), claim(h, "c.neg", null, at(NOW)));
        assertEquals(3, tier(h, "c.wide", null));
        assertEquals(1, tier(h, "c.neg", null));
    }

    @Test void aRiskModelIgnoresTheAmountAndAVerbWithoutAnAmountFieldUsesItsBlastRadius() {
        Facade.Handle risk = Facade.agent(opts(Issue.obj("stripe", List.of("refund"))).limits(Issue.obj("refund", "$500")).budgetModel("risk"));
        assertEquals(claimOf("0.9"), claim(risk, "stripe.refund", amount(100L), at(NOW)));
        assertEquals(claimOf("0.05"), claim(handle(Issue.obj("github", List.of("read"))), "github.read", null, at(NOW)));
        Facade.Handle dollars = handle(Issue.obj("stripe", List.of("refund"), "gmail", List.of("draft")), Issue.obj("refund", "$500"));
        assertEquals(claimOf("0.2"), claim(dollars, "gmail.draft", amount(400L), at(NOW)));
        // an uncatalogued verb is irreversible with blast radius 0.8
        Facade.ActResult u = handle(Issue.obj("stripe", List.of("refund"))).act("foo", "r", null, at(NOW));
        assertEquals(claimOf("0.8"), canon(u.pcactn.get("risk_claim")));
        assertEquals("irreversible", m(u.pcactn.get("action")).get("reversibility_class"));
    }

    @Test void aClaimedRiskOverridesTheDerivedOneWithinZeroAndOne() {
        Facade.Handle h = handle(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$500"));
        Object[][] cases = {{0.7, "0.7"}, {5.0, "1"}, {-1.0, "0"}, {0.0, "0"}, {null, "0.2"}};
        for (Object[] c : cases) {
            Facade.ActOptions o = at(NOW);
            o.risk = (Double) c[0];
            assertEquals(claimOf((String) c[1]), claim(h, "stripe.refund", amount(100L), o), String.valueOf(c[0]));
        }
    }

    // ---- acting --------------------------------------------------------------------------------------------------------------

    @Test void anActionIsAOneNodePlanTheRiskClaimAndTheNextCounter() {
        Facade.Handle h = handle(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$500"));
        Map<String, Object> params = amount(100L);
        Facade.ActResult r = h.act("stripe.refund", "charge:1", params, at(NOW));
        Map<String, Object> p = r.pcactn;
        assertEquals(1L, p.get("counter"));
        assertEquals("rs", p.get("aud"));
        assertEquals(NOW, p.get("iat"));
        assertEquals(NOW + Issue.DEFAULT_TTL_MS, p.get("exp"));
        assertEquals("n0", m(p.get("plan")).get("node_id"));
        Map<String, Object> a = m(p.get("action"));
        assertEquals("stripe.refund", a.get("verb"));
        assertEquals("charge:1", a.get("resource"));
        assertEquals("irreversible", a.get("reversibility_class"));
        assertEquals(Pca.paramsDigest(params), a.get("params_digest"));
        assertFalse(p.containsKey("nonce"));
        assertFalse(p.containsKey("caution"));
        assertEquals(h.grant.get("id"), p.get("grant_ref"));
        assertEquals(r.encoded, Issue.encode(p));
        assertEquals(Set.of(Agent.HEADER, ArgProvenance.HEADER), r.headers.keySet());
        assertEquals(Issue.header(p), r.headers.get(Agent.HEADER));
        assertEquals(Json.canonicalizeStrict(r.provenance), new String(Pca.decodeB64uStrict(r.headers.get(ArgProvenance.HEADER), -1), StandardCharsets.UTF_8));
        assertTrue(r.dryRun.allowed);
        assertEquals(1, r.dryRun.t);
        assertTrue(Pca.verifyPcactn(p, h.grant, NOW + 1000, "rs", null, null, null, null, Pca.PlanRoots.SKIP).allow);
        // the dry run is the one for the same action at the same clock
        Facade.ActResult over = h.act("stripe.refund", "charge:1", amount(501L), at(NOW));
        assertFalse(over.dryRun.allowed);
        assertEquals("amount <= 500 not satisfied for stripe.refund on charge:1", over.dryRun.reason);
    }

    @Test void anActionWithoutOptionsUsesTheHandlesAudienceAndTheCurrentTime() {
        Facade.Handle h = handle(Issue.obj("github", List.of("read")));
        long t = System.currentTimeMillis();
        Map<String, Object> u = h.act("github.read", "r", null, null).pcactn;
        assertEquals("rs", u.get("aud"));
        assertEquals(1L, u.get("counter"));
        assertTrue(Json.asLong(u.get("iat")) >= t);
        assertTrue(Json.asLong(u.get("iat")) < t + 60_000L);
        long t2 = System.currentTimeMillis();
        Map<String, Object> v = h.act("github.read", "r", null, new Facade.ActOptions()).pcactn;
        assertTrue(Json.asLong(v.get("iat")) >= t2);
        assertEquals(2L, v.get("counter"));
    }

    @Test void theCounterAdvancesAndNeverGoesBack() {
        Facade.Handle h = handle(Issue.obj("github", List.of("read")));
        Long[] given = {null, null, 10L, null, 3L, null, 0L, null};
        long[] expect = {1, 2, 10, 11, 3, 12, 0, 13};
        for (int i = 0; i < given.length; i++) {
            Facade.ActOptions o = at(NOW);
            o.counter = given[i];
            assertEquals(expect[i], Json.asLong(h.act("github.read", "r", null, o).pcactn.get("counter")), Integer.toString(i));
        }
    }

    @Test void anActionCarriesTheCallersNonceCautionLifetimeAndAudience() {
        Facade.Handle h = handle(Issue.obj("github", List.of("read")));
        Facade.ActOptions o = at(1234L);
        o.ttlMs = 5000L;
        o.aud = "other";
        o.nonce = "nonce-1";
        o.caution = new Json.Num("0.5");
        Map<String, Object> p = h.act("github.read", "r", null, o).pcactn;
        assertEquals("other", p.get("aud"));
        assertEquals("nonce-1", p.get("nonce"));
        assertEquals("0.5", canon(p.get("caution")));
        assertEquals(1234L, p.get("iat"));
        assertEquals(6234L, p.get("exp"));
        Map<String, Object> d = h.act("github.read", "r", null, at(1234L)).pcactn;
        assertEquals("rs", d.get("aud"));
        assertEquals(1234L + Issue.DEFAULT_TTL_MS, d.get("exp"));
    }

    @Test void anActionNeedsAnAudience() {
        String text = "act: aud (resource-server / instance id) is required (pass opts.aud or AgentOptions.aud)";
        Facade.Handle none = Facade.agent(new Facade.AgentOptions(PRINCIPAL, "goal", Issue.obj("github", List.of("read"))).holder(AGENT).now(NOW));
        assertEquals(text, FacadeKillTest.refusal(() -> none.act("github.read", "r", null, null)));
        Facade.ActOptions empty = at(NOW);
        empty.aud = "";
        assertEquals(text, FacadeKillTest.refusal(() -> none.act("github.read", "r", null, empty)));
        Facade.ActOptions given = at(NOW);
        given.aud = "given";
        assertEquals("given", none.act("github.read", "r", null, given).pcactn.get("aud"));
        Facade.Handle blank = Facade.agent(opts(Issue.obj("github", List.of("read"))).aud(""));
        assertEquals(text, FacadeKillTest.refusal(() -> blank.act("github.read", "r", null, at(NOW))));
        Facade.ActOptions x = at(NOW);
        x.aud = "x";
        assertEquals("x", blank.act("github.read", "r", null, x).pcactn.get("aud"));
    }

    @Test void anActionRecordsItselfWithTheProvenanceRecorder() {
        Facade.Handle h = handle(Issue.obj("github", List.of("read")));
        Facade.ActResult r = h.act("github.read", "repo:1", Issue.obj("x", 1L), at(NOW));
        assertEquals(Json.canonicalizeStrict(r.provenance), new String(Pca.decodeB64uStrict(r.headers.get(ArgProvenance.HEADER), -1), StandardCharsets.UTF_8));
        assertEquals(1, l(r.provenance.get("receipts")).size());
        assertEquals(2, l(h.act("github.read", "repo:1", null, at(NOW)).provenance.get("receipts")).size());
    }

    // ---- sub-agents ----------------------------------------------------------------------------------------------------------

    @Test void aSubAgentIsOneMoreHopSignedByTheParentKey() {
        Facade.Handle h = handle(Issue.obj("github", List.of("read")));
        Keys.EdKey childEd = Keys.edFromSeed(ProducerTest.fill(2, 32));
        Keys.SuiteKey child = Keys.ed25519(childEd);
        List<Object> added = new ArrayList<>(List.of(Issue.obj("type", "expires", "at", 5L)));
        Facade.Handle s = h.subAgent(child, added);
        assertEquals(2, s.chain.size());
        assertSame(h.chain.get(0), s.chain.get(0));
        Map<String, Object> hop = m(s.chain.get(1));
        assertEquals(childEd.id(), hop.get("holder"));
        assertEquals(AGENT_ED.id(), hop.get("issuer"));
        assertFalse(hop.containsKey("holder_pq"));
        List<Object> cav = l(hop.get("caveats"));
        assertEquals(l(m(s.chain.get(0)).get("caveats")).size() + 1, cav.size());
        assertEquals("{\"at\":5,\"type\":\"expires\"}", canon(cav.get(cav.size() - 1)));
        assertSame(h.grant, s.grant);
        assertEquals(h.goalSalt, s.goalSalt);
        assertSame(h.policy, s.policy);
        assertEquals(h.principalPublic, s.principalPublic);
        assertSame(h.provenance, s.provenance);
        assertSame(child, s.holder);
        assertEquals(canon(h.budget()), canon(s.budget()));
        // the parent is unchanged; the sub-agent counts on its own and acts under the same audience and catalog
        assertEquals(1, h.chain.size());
        Facade.ActResult a = s.act("github.read", "r", null, at(NOW));
        assertEquals(1L, a.pcactn.get("counter"));
        assertEquals("rs", a.pcactn.get("aud"));
        assertEquals(2, l(a.pcactn.get("cap_chain")).size());
        assertEquals("reversible", m(a.pcactn.get("action")).get("reversibility_class"));
        assertEquals(1L, h.act("github.read", "r", null, at(NOW)).pcactn.get("counter"));
    }

    @Test void aSubAgentWithoutAKeyGetsAFreshEd25519One() {
        Facade.Handle h = handle(Issue.obj("github", List.of("read")));
        Facade.Handle s = h.subAgent(null, null);
        assertEquals("ed25519", s.holder.alg);
        assertNull(s.holder.pq);
        assertNotEquals(h.holder.ed.id(), s.holder.ed.id());
        assertEquals(s.holder.ed.id(), m(s.chain.get(1)).get("holder"));
        assertFalse(m(s.chain.get(1)).containsKey("holder_pq"));
        assertEquals(l(m(h.chain.get(0)).get("caveats")).size(), l(m(s.chain.get(1)).get("caveats")).size());
        assertNotEquals(s.holder.ed.id(), h.subAgent(null, null).holder.ed.id());
    }

    @Test void aPostQuantumParentGetsAFreshKeyOfTheSameSuiteForItsSubAgent() {
        Keys.PqKey pq = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ProducerTest.fill(7, 32));
        Facade.Handle h = Facade.agent(opts(Issue.obj("github", List.of("read"))).holder(Keys.suite("hybrid-ed25519-ml-dsa-65", AGENT_ED, pq)));
        Facade.Handle s = h.subAgent(null, null);
        assertEquals("hybrid-ed25519-ml-dsa-65", s.holder.alg);
        assertNotNull(s.holder.pq);
        assertNotEquals(pq.pkB64u(), s.holder.pq.pkB64u());
        assertNotEquals(AGENT_ED.id(), s.holder.ed.id());
        Map<String, Object> hop = m(s.chain.get(1));
        assertEquals(Pca.holderPqCommitment(s.holder.pq.pkB64u()), hop.get("holder_pq"));
        assertEquals("hybrid-ed25519-ml-dsa-65", hop.get("alg"));
        assertEquals(pq.pkB64u(), hop.get("pq_pk"));
        // a given post-quantum child commits its own key
        Keys.PqKey cpq = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ProducerTest.fill(8, 32));
        Facade.Handle g = h.subAgent(Keys.suite("hybrid-ed25519-ml-dsa-65", Keys.edFromSeed(ProducerTest.fill(3, 32)), cpq), null);
        assertEquals(Pca.holderPqCommitment(cpq.pkB64u()), m(g.chain.get(1)).get("holder_pq"));
    }

    @Test void aSubAgentNeedsAnEd25519Identity() {
        Facade.Handle h = handle(Issue.obj("github", List.of("read")));
        Keys.SuiteKey purePq = Keys.suite("ml-dsa-65", null, Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ProducerTest.fill(7, 32)));
        assertEquals("subAgent: the sub-agent needs an Ed25519 identity", FacadeKillTest.refusal(() -> h.subAgent(purePq, null)));
    }
}
