package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import net.atlasauth.pca.spring.Protect;

/**
 * 0.5 mutation kills, round 3: the Authorize.run paths reached only by a PCActn member replaced after the core checks, a plan
 * that is no object, a host context that already supplies a plan, a chain emptied before the K1 and escalation paths; the
 * schema validators on non-JSON values; and the suite policy through Options.run and Protect. References: server/verify.ts
 * (class ranks, depth, slice), server/require-pca.ts (plans, workflow), reversibility.ts.
 */
@SuppressWarnings("unchecked")
public class K05R3AuthorizeKillTest {
    static final long NOW = AuthorizeK05KillTest.NOW;
    static final String CAVEAT_LANGUAGE = "delegated_caveats: delegation caveat(s) not satisfied: <caveat language>";

    @AfterEach void clearHook() { Authorize.coreHook = null; }

    static Authorize.AuthorizeResult run(Object pc, Authorize.Input in) { return Authorize.authorize(pc, in); }

    static Authorize.Input input() { return AuthorizeRunK05bKillTest.input(); }

    static Authorize.Input in(Map<String, Object> g) { return AuthorizeRunK05bKillTest.in(g); }

    static Map<String, Object> act(Map<String, Object> g) { return AuthorizeRunK05bKillTest.act(g); }

    static Map<String, Object> pcactn() { return AuthorizeRunK05bKillTest.pcactn(); }

    static Map<String, Object> mutable(Map<String, Object> pc) { return AuthorizeRunK05bKillTest.mutable(pc); }

    static Authorize.RevocationCheck after(Consumer<Map<String, Object>> edit) { return AuthorizeRunK05bKillTest.after(edit); }

    static Map<String, Object> ctx(Object... kv) { return AuthorizeRunK05bKillTest.ctx(kv); }

    static void noError(Authorize.AuthorizeResult r) { AuthorizeRunK05bKillTest.noError(r); }

    /** An object that throws when hashed, so a lookup with it (rather than the type test before the lookup) is observable. */
    static final Object UNHASHABLE = new Object() {
        @Override public int hashCode() { throw new IllegalStateException("hashed"); }
        @Override public String toString() { return "unhashable"; }
    };

    // ---- jsEq, schema validation --------------------------------------------------------------------------------------------

    /** A non-boolean left side is never asked to compare itself: a null left side answers false. */
    @Test void jsEqNullAgainstABoolean() {
        assertFalse(Authorize.jsEq(null, Boolean.TRUE));
        assertFalse(Authorize.jsEq(null, Boolean.FALSE));
    }

    @Test void aRequiredMemberThatIsNoStringIsNeverLookedUp() {
        Map<String, Object> schema = Issue.obj("props", Issue.obj("a", Issue.obj("type", "string")), "required", List.of(UNHASHABLE));
        assertEquals("required names an undeclared property", Authorize.validateArgSchema(schema));
    }

    @Test void aSpecTypeThatIsNoStringIsNeverLookedUp() {
        Map<String, Object> schema = Issue.obj("props", Issue.obj("a", Issue.obj("type", UNHASHABLE)));
        assertEquals("a: unknown type", Authorize.validateArgSchema(schema));
    }

    // ---- the reversibility class ------------------------------------------------------------------------------------------

    /** The class the PCActn declares, set after the core checks (no signed member needs to carry it). */
    static Authorize.AuthorizeResult declared(Map<String, Object> g, Object declared, Object server) {
        return run(mutable(act(g)), in(g).context(p -> ctx("reversibility_class", server))
            .isRevoked(after(p -> ((Map<String, Object>) p.get("action")).put("reversibility_class", declared))));
    }

    static Map<String, Object> grantReadingClass(String cls) {
        return AuthorizeRunK05bKillTest.grant(AuthorizeRunK05bKillTest.allowWhere(Issue.obj("field", "action.reversibility_class", "op", "eq", "value", cls)));
    }

    /** reversibility.ts classRank: a non-string class and "irreversible" both rank 2, so neither is less restrictive. */
    @Test void aNonStringClassRanksWithIrreversible() {
        Authorize.AuthorizeResult r = declared(AuthorizeRunK05bKillTest.grant(), 5L, "irreversible");
        noError(r);
        assertEquals("pass", r.checks.get("reversibility"), r.reasons.toString());
    }

    /** verify.ts: `useDeclaredClass(dr, sr) ? declared : server`: a stricter declared class is the one the predicates read. */
    @Test void aStricterDeclaredClassIsTheEffectiveOne() {
        Authorize.AuthorizeResult r = declared(grantReadingClass("irreversible"), "irreversible", "reversible");
        noError(r);
        assertEquals("pass", r.checks.get("reversibility"), r.reasons.toString());
        assertEquals("pass", r.checks.get("policy"), r.reasons.toString());
    }

    @Test void onEqualRanksTheServerClassIsTheEffectiveOne() {
        Authorize.AuthorizeResult r = declared(grantReadingClass("rate_limited"), "costly", "rate_limited");
        noError(r);
        assertEquals("pass", r.checks.get("reversibility"), r.reasons.toString());
        assertEquals("pass", r.checks.get("policy"), r.reasons.toString());
    }

    // ---- the predicate and caveat context ---------------------------------------------------------------------------------

    @Test void noHostSubjectLeavesNoSubjectMember() {
        Map<String, Object> g = AuthorizeRunK05bKillTest.grant(AuthorizeRunK05bKillTest.allowWhere(Issue.obj("field", "subject", "op", "exists", "value", false)));
        AuthorizeRunK05bKillTest.allowed(run(act(g), in(g)));
    }

    /** verify.ts: depth = Math.max(0, chain.length - 1): an emptied chain is depth 0, never -1. */
    @Test void anEmptyChainIsDepthZero() {
        Map<String, Object> g = AuthorizeRunK05bKillTest.grant(Issue.obj("type", "delegation_depth", "max", -1L));
        Authorize.AuthorizeResult r = run(mutable(act(g)), in(g).isRevoked(after(p -> ((List<?>) p.get("cap_chain")).clear())));
        noError(r);
        assertEquals("fail", r.checks.get("policy"), r.reasons.toString());
        assertTrue(r.reasons.contains("policy: caveat(s) not satisfied: delegation_depth"), r.reasons.toString());
    }

    /** intent-v2.ts rule 22: an action pin in the envelope runs the v2 pipeline even when the host configures no v2 context. */
    @Test void anActionPinInTheEnvelopeRunsTheModelRules() {
        Map<String, Object> pin = Issue.obj("pack", Issue.obj("ns", "stripe", "root", "A".repeat(43)), "on_new_action", "deny");
        Map<String, Object> g = AuthorizeRunK05cKillTest.envGrant(AuthorizeRunK05bKillTest.star(), Issue.obj("actions", pin));
        Authorize.AuthorizeResult none = run(act(g), in(g));
        noError(none);
        assertFalse(none.allow, none.reasons.toString());
        assertTrue(none.reasons.contains("pin: " + AuthorizeRunK05cKillTest.NO_SCHEMA), none.reasons.toString());
        // with a host context: the core keeps intent_session (first), the pin refusal is reported only by the fold
        AuthorizeRunK05cKillTest.has(run(act(g), in(g).intentV2(AuthorizeRunK05cKillTest.v2(AuthorizeRunK05cKillTest.SESSION_REQUIRED))),
            AuthorizeRunK05cKillTest.NO_SESSION, "pin: " + AuthorizeRunK05cKillTest.NO_SCHEMA);
    }

    // ---- the plan registry --------------------------------------------------------------------------------------------------

    static final Map<String, Object> NODE = Issue.obj("id", "a", "verb", "payments.send", "resource", "payments/acme",
        "params_digest", Pca.paramsDigest(Issue.obj("amount", 50L)));

    static Map<String, Object> nodeAct(Map<String, Object> g) {
        Agent a = AuthorizeRunK05bKillTest.agent(g);
        a.commitPlan(List.of(NODE));
        return a.actNode("a", Issue.obj("amount", 50L));
    }

    /** require-pca.ts: `plans && base.plan === undefined`: a plan the host context supplies is never looked up in the registry. */
    @Test void aPlanFromTheHostContextSkipsTheRegistry() {
        Map<String, Object> g = AuthorizeRunK05bKillTest.grant();
        Authorize.AuthorizeResult r = run(nodeAct(g), in(g).plan(null).plans(new PlanRegistry())
            .context(p -> ctx("plan", List.of(NODE), "plan_authorized", true)));
        AuthorizeRunK05bKillTest.allowed(r);
        assertFalse(r.checks.containsKey("plan_state"), r.checks.toString());
    }

    /** A registry lookup of a plan that is no object, or whose root is no string, is the core's wire refusal, not an internal error. */
    @Test void aMalformedPlanReachesTheWireCheckWithARegistry() {
        for (Object plan : new Object[] {"x", Issue.obj("root", 5L)}) {
            Authorize.AuthorizeResult r = run(AuthorizeK05KillTest.with(pcactn(), "plan", plan), input().plans(new PlanRegistry()));
            assertEquals(401, r.status, r.reasons.toString());
            assertEquals("fail", r.checks.get("wire"), r.checks.toString());
            assertFalse(r.checks.containsKey("authorize"), r.checks.toString());
            assertFalse(r.checks.containsKey("plans"), r.checks.toString());
        }
    }

    /** The registry judges the plan at the verifier's clock, not its own (require-pca.ts: plans.context(ref, root, now)). */
    @Test void theRegistryJudgesAtTheVerifiersClock() {
        Map<String, Object> g = AuthorizeRunK05bKillTest.grant();
        AtomicLong registryClock = new AtomicLong(NOW);
        PlanRegistry reg = new PlanRegistry(new MemoryAtomicKv(), "pca-plan:", registryClock::get, null);
        List<Object> nodes = new ArrayList<>();
        nodes.add(NODE);
        PlanRegistryKillTest.authorized(reg, (String) g.get("id"), nodes, NOW + 1_000L);
        registryClock.set(NOW + 2_000L); // the registry's own clock is past the approval's expiry; the verifier's is not
        Authorize.AuthorizeResult r = run(nodeAct(g), in(g).plan(null).plans(reg).provenanceGate(new ArgProvenance.Options()));
        noError(r);
        assertEquals("pass", r.checks.get("plan_state"), r.reasons.toString());
        assertTrue(r.allow, r.reasons.toString());
    }

    // ---- the workflow gate --------------------------------------------------------------------------------------------------

    static Authorize.WorkflowStep badStep() { return new Authorize.WorkflowStep("not a commitment", List.of(), "quote", null, "g"); }

    @Test void anOptionalWorkflowWithoutAStepPasses() {
        AuthorizeRunK05bKillTest.allowed(run(pcactn(), input().workflow(AuthorizeRunK05bKillTestFlowsTest.PIN)));
    }

    @Test void aRequiredWorkflowWithAStepIsAdmittedNotRefusedAsMissing() {
        Authorize.WorkflowPin pin = AuthorizeRunK05bKillTestFlowsTest.PIN;
        Authorize.WorkflowPin required = new Authorize.WorkflowPin(pin.principal, pin.rsSigner, true);
        AuthorizeRunK05bKillTestFlowsTest.refused(run(pcactn(), input().workflow(required).workflowStep(badStep())), 403, "workflow", "workflow: bad_workflow");
    }

    @Test void aStepWithoutAConfiguredWorkflowIsIgnored() {
        AuthorizeRunK05bKillTest.allowed(run(pcactn(), input().workflowStep(badStep())));
    }

    @Test void aPlanThatIsNoObjectHasNoRootForTheWorkflowGate() {
        Map<String, Object> pc = AuthorizeK05KillTest.with(pcactn(), "plan", "x");
        Authorize.AuthorizeResult r = run(pc, input().workflow(AuthorizeRunK05bKillTestFlowsTest.PIN).workflowStep(badStep()));
        assertEquals(Map.of("workflow", "fail"), r.checks, r.reasons.toString());
    }

    // ---- staleness proofs, provenance observations --------------------------------------------------------------------------

    @Test void aProofSourceThatThrowsSuppliesNoProof() {
        RevocationStaleness pol = AuthorizeRunK05bKillTest.policy().ids(p -> List.of("cap-x")).proofs((id, pc) -> { throw new IllegalStateException("down"); });
        AuthorizeRunK05bKillTest.denied(AuthorizeRunK05bKillTest.stale(pcactn(), pol, ctx("revocation_state", AuthorizeRunK05bKillTest.freshRoot())),
            "freshness: no non-membership proof for cap-x");
    }

    @Test void theObservedHookGetsTheBundlesSession() {
        Map<String, Object> bundle = ProvHarness.bundle(AuthorizeOptionsK05cKillTest.OP);
        Object session = ((Map<?, ?>) ((List<?>) bundle.get("receipts")).get(0)).get("session");
        assertNotNull(session);
        String[] seen = new String[1];
        ArgProvenance.Options gate = ProvHarness.options().bundle((p, o) -> bundle).observed((p, o, s) -> {
            seen[0] = s;
            return List.of();
        });
        noError(run(pcactn(), input().provenanceGate(gate)));
        assertEquals(session, seen[0]);
    }

    // ---- delegated caveats --------------------------------------------------------------------------------------------------

    /** verify.ts: leaf.caveats.slice(grant.caveats.length): a leaf shorter than the grant adds nothing (and never throws). */
    @Test void aLeafShorterThanTheGrantAddsNoCaveat() {
        Map<String, Object> g = AuthorizeRunK05bKillTest.grant(new ArrayList<>(), AuthorizeRunK05bKillTest.star(),
            List.<Object>of(Issue.obj("type", "expires", "at", NOW + 60_000L)));
        Map<String, Object> leaf = Issue.obj("holder", AuthorizeRunK05bKillTest.AGENT.id(), "caveats", List.of(Issue.obj("type", "note")));
        Authorize.AuthorizeResult r = run(mutable(act(g)), in(g).isRevoked(after(p -> ((List<Object>) p.get("cap_chain")).set(0, leaf))));
        noError(r);
        assertEquals("pass", r.checks.get("delegated_caveats"), r.reasons.toString());
    }

    /** A K1 evaluation that throws is reported even when the chain was emptied (no hop and no K1 result to enter the block). */
    @Test void aCaveatLanguageFailureOnAnEmptyChainIsReported() {
        Map<String, Object> g = AuthorizeRunK05bKillTest.usesGrant();
        Map<String, Object> boom = new AbstractMap<String, Object>() {
            @Override public Set<Map.Entry<String, Object>> entrySet() { throw new IllegalStateException("boom"); }
            @Override public boolean containsKey(Object k) { return false; }
        };
        Authorize.AuthorizeResult r = run(mutable(act(g)), in(g).k1(boom).isRevoked(after(p -> ((List<?>) p.get("cap_chain")).clear())));
        AuthorizeRunK05bKillTest.denied(r, CAVEAT_LANGUAGE, "policy: root caveat(s) not satisfied: max_uses");
        assertEquals("fail", r.checks.get("delegated_caveats"));
    }

    /** A leaf with no caveat list: no list to add the K1 result's plain caveats to, so the malformed report stands. */
    @Test void aLeafWithNoCaveatListStaysMalformedWithAK1Result() {
        Map<String, Object> g = AuthorizeRunK05bKillTest.usesGrant();
        Authorize.AuthorizeResult r = run(mutable(act(g)), in(g).isRevoked(after(p -> ((List<Object>) p.get("cap_chain")).set(0, "x"))));
        noError(r);
        assertEquals("fail", r.checks.get("delegated_caveats"), r.reasons.toString());
        assertTrue(r.reasons.stream().anyMatch(x -> x.startsWith("delegated_caveats: delegation caveat(s) not satisfied: <malformed caveats>")), r.reasons.toString());
    }

    // ---- escalation -----------------------------------------------------------------------------------------------------------

    /** No holder, no counter stream: an escalate-class failure denies and builds no request. */
    @Test void anEscalationWithoutAHolderDenies() {
        AuthorizeRunK05bKillTest.escalate();
        Authorize.AuthorizeResult r = run(mutable(pcactn()), input().isRevoked(after(p -> ((List<?>) p.get("cap_chain")).clear())));
        assertEquals("deny", r.decision, r.reasons.toString());
        assertNull(r.escalation);
        assertEquals(List.of(AuthorizeRunK05bKillTest.ESCALATE_REASON), r.reasons);
    }

    // ---- the suite policy ---------------------------------------------------------------------------------------------------

    @Test void optionsRunForwardsTheSuitePolicy() {
        Authorize.AuthorizeResult ok = AuthorizeOptionsK05cKillTest.base().withAllowedSuites(List.of("ed25519"))
            .run(pcactn(), AuthorizeOptionsK05cKillTest.OP, AuthorizeK05KillTest.AUD, AuthorizeOptionsK05cKillTest.RESOLVE, NOW);
        AuthorizeRunK05bKillTest.allowed(ok);
        Authorize.AuthorizeResult r = AuthorizeOptionsK05cKillTest.base().withAllowedSuites(List.of("ml-dsa-65"))
            .run(pcactn(), AuthorizeOptionsK05cKillTest.OP, AuthorizeK05KillTest.AUD, AuthorizeOptionsK05cKillTest.RESOLVE, NOW);
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("chain"), r.checks.toString());
        assertTrue(r.reasons.stream().anyMatch(x -> x.contains("signature suite is not allowed by this verifier's suite policy")), r.reasons.toString());
    }

    @Test void protectForwardsTheSuitePolicy() {
        List<String> suites = List.of("ml-dsa-65");
        Protect.Config c = new Protect.Config("a", (req, body) -> null).grants(ref -> null);
        assertSame(c, c.allowedSuites(suites));
        assertEquals(suites, Protect.protect(c).options().allowedSuites);
    }
}
