package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Authorize.run, the paths the K05b kill tests left open: the Intent Layer v2 context the pipeline builds (rules 20 / 21 read
 * the grant's envelope), the v2 reasons it folds, the predicate env of an intent_session, the legacy-polarity assurance
 * degradation, the tool call, the K1 derive action, a policy evaluation that throws, an admitted escalation answer, and the
 * provenance commitments of an executable registry plan and an admitted workflow step. Every expected value is traced
 * through Authorize.run and IntentV2.decide.
 */
public class AuthorizeRunK05cKillTest {
    static final long NOW = AuthorizeK05KillTest.NOW;
    static final Keys.SuiteKey PRINCIPAL = AuthorizeK05KillTest.PRINCIPAL, AGENT = AuthorizeK05KillTest.AGENT;
    static final String Z = Pca.b64(new byte[32]);

    @AfterEach void clearHook() { Authorize.coreHook = null; }

    static Map<String, Object> grant() { return AuthorizeRunK05bKillTest.grant(); }

    static Map<String, Object> act(Map<String, Object> g) { return AuthorizeRunK05bKillTest.act(g); }

    static Authorize.Input in(Map<String, Object> g) { return AuthorizeRunK05bKillTest.in(g); }

    static Authorize.AuthorizeResult run(Object pc, Authorize.Input in) { return Authorize.authorize(pc, in); }

    /** A root grant whose envelope allows {@code preds} and carries the {@code extra} members (units, tighten, model_polarity). */
    static Map<String, Object> envGrant(List<Object> preds, Map<String, Object> extra) {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("type", "envelope");
        env.put("goal_commit", Issue.goalCommit("pay invoices", AuthorizeRunK05bKillTest.SALT));
        env.put("predicates", preds);
        env.put("caveats", new ArrayList<Object>());
        env.put("risk_policy", Issue.defaultRiskPolicy());
        env.put("agent_binding", new LinkedHashMap<String, Object>());
        env.putAll(extra);
        List<Object> cavs = new ArrayList<>();
        cavs.add(env);
        return Issue.mintRoot(PRINCIPAL, AGENT.id(), null, cavs);
    }

    static List<Object> star() { return AuthorizeRunK05bKillTest.star(); }

    static IntentV2.Context v2(Map<String, Object> raw) { return IntentV2.Context.fromJson(raw); }

    /** policy.session.require: the v2 check intent_session fails first for a PCActn without one. */
    static final Map<String, Object> SESSION_REQUIRED = Issue.obj("policy", Issue.obj("session", Issue.obj("require", true)));

    static final String NO_SESSION = "intent_session: this verifier requires an intent_session but the PCActn carries none";
    static final String NO_SCHEMA = "this verifier has no action schema configured";

    static void has(Authorize.AuthorizeResult r, String... reasons) {
        assertFalse(r.checks.containsKey("authorize"), r.reasons.toString());
        for (String x : reasons) assertTrue(r.reasons.contains(x), "missing '" + x + "' in " + r.reasons);
    }

    // ---- rules 20 / 21: each envelope member alone makes the pipeline fold every failed v2 reason --------------------------

    @Test void aUnitsEnvelopeFoldsEveryV2Reason() {
        Map<String, Object> units = Issue.obj("action.params.amount", Issue.obj("currency", "USD", "exponent", 2L, "kind", "money"));
        Map<String, Object> g = envGrant(star(), Issue.obj("units", units));
        // the core keeps intent_session (first); the units refusal is reported only by the fold
        has(run(act(g), in(g).intentV2(v2(SESSION_REQUIRED))), NO_SESSION, "units: " + NO_SCHEMA);
    }

    @Test void aModelPolarityEnvelopeFoldsEveryV2Reason() {
        Map<String, Object> g = envGrant(star(), Issue.obj("model_polarity", "strict"));
        has(run(act(g), in(g).intentV2(v2(SESSION_REQUIRED))), NO_SESSION, "tighten: model_polarity must be 'legacy' when present");
    }

    @Test void aModelDerivedWhereFoldsEveryV2Reason() {
        List<Object> preds = new ArrayList<>();
        preds.add(Issue.obj("verb", "*", "where", List.<Object>of(Issue.obj("field", "env.judge.tone", "op", "ne", "value", "hostile"))));
        Map<String, Object> g = envGrant(preds, new LinkedHashMap<>());
        has(run(act(g), in(g).intentV2(v2(SESSION_REQUIRED))), NO_SESSION,
            "tighten: a grant's where reads model-derived path(s) env.judge.tone: a model may only tighten (move them into tighten[]) (rule 21)");
    }

    /** A grant with none of them and a PCActn without intent_session: only the core's first v2 reason, never the fold. */
    @Test void aPlainGrantKeepsOnlyTheCoresFirstV2Reason() {
        Map<String, Object> g = grant();
        Map<String, Object> ctx = Issue.obj("policy", Issue.obj("schema", Issue.obj("closed_world", true), "session", Issue.obj("require", true)));
        Authorize.AuthorizeResult r = run(act(g), in(g).intentV2(v2(ctx)));
        assertEquals("fail", r.checks.get("schema"));
        assertEquals("fail", r.checks.get("intent_session"));
        assertEquals(List.of("schema: " + NO_SCHEMA), r.reasons);
    }

    // ---- intent_session: the fold and the predicate env ------------------------------------------------------------------

    static Map<String, Object> sessionAct(Map<String, Object> g) {
        Map<String, Object> is = Issue.obj("session", Z, "root", Z, "schema", Z, "seq", 0L);
        return AuthorizeRunK05bKillTest.agent(g).act("payments.send", "payments/acme", Issue.obj("amount", 50L), Issue.obj("intent_session", is));
    }

    @Test void anIntentSessionFoldsEveryV2Reason() {
        Map<String, Object> g = grant();
        has(run(sessionAct(g), in(g)), "schema: " + NO_SCHEMA, "intent_session: an intent_session needs the envelope.intent binding");
    }

    @Test void anIntentSessionsPredicatesSeeTheVerifierEnv() {
        Map<String, Object> g = AuthorizeRunK05bKillTest.grant(AuthorizeRunK05bKillTest.allowWhere(Issue.obj("field", "env", "op", "exists", "value", false)));
        // premise: without intent_session the host has no env, so the predicate holds
        assertEquals("pass", run(act(g), in(g)).checks.get("policy"));
        // with one, the env is the verifier-computed v2 env (an object even when the host has none)
        Authorize.AuthorizeResult r = run(sessionAct(g), in(g));
        assertEquals("fail", r.checks.get("policy"), r.reasons.toString());
        has(r, "policy: caveat(s) not satisfied: predicates");
    }

    // ---- the v2 context the pipeline rebuilds ----------------------------------------------------------------------------

    static final String MALFORMED = "malformed v2 context: the v2 verifier context must be an object";

    @Test void aMalformedContextIsNeverRebuilt() {
        Map<String, Object> g = grant();
        Authorize.AuthorizeResult r = run(act(g), in(g).intentV2(IntentV2.Context.fromJson("x")));
        assertFalse(r.allow);
        assertEquals(List.of("schema: " + MALFORMED), r.reasons);
        // a grant with model rules folds both malformed reasons and still never reads the context as well formed
        Map<String, Object> u = envGrant(star(), Issue.obj("units", Issue.obj("action.params.amount", Issue.obj("currency", "USD", "exponent", 2L, "kind", "money"))));
        Authorize.AuthorizeResult ru = run(act(u), in(u).intentV2(IntentV2.Context.fromJson("x")));
        assertFalse(ru.allow);
        assertEquals(List.of("schema: " + MALFORMED, "intent_session: " + MALFORMED), ru.reasons);
    }

    static Map<String, Object> capGrant() {
        Map<String, Object> rule = Issue.obj("id", "cap", "signal", "deny", "when", Issue.obj("field", "action.params.amount", "op", "gt", "value", 10L));
        return envGrant(star(), Issue.obj("tighten", List.<Object>of(rule)));
    }

    @Test void aWellFormedContextGetsTheOperationsParamsOnlyWhenItHasNone() {
        Map<String, Object> g = capGrant();
        // {} has no params: the operation's (amount 50) are judged, so the cap denies
        AuthorizeRunK05bKillTest.denied(run(act(g), in(g).intentV2(v2(new LinkedHashMap<>()))), "tighten: denied by tighten rule 'cap'");
        // the host's own plaintext params (amount 5) are kept
        AuthorizeRunK05bKillTest.allowed(run(act(g), in(g).intentV2(v2(Issue.obj("params", Issue.obj("amount", 5L))))));
    }

    // ---- assurance: a legacy-polarity admission is degraded --------------------------------------------------------------

    @Test void aLegacyPolarityAdmissionFailsAnAssuranceRequirement() {
        List<Object> preds = new ArrayList<>();
        preds.add(Issue.obj("verb", "*", "where", List.<Object>of(Issue.obj("field", "env.judge.tone", "op", "ne", "value", "hostile"))));
        Map<String, Object> g = envGrant(preds, Issue.obj("model_polarity", "legacy"));
        Authorize.Input base = in(g).context(p -> AuthorizeRunK05bKillTest.ctx("env", Issue.obj("judge", Issue.obj("tone", "calm"))));
        Authorize.AuthorizeResult plain = run(act(g), base);
        AuthorizeRunK05bKillTest.allowed(plain);
        assertEquals("pass", plain.checks.get("tighten"));
        Authorize.AuthorizeResult r = run(act(g), in(g).context(p -> AuthorizeRunK05bKillTest.ctx("env", Issue.obj("judge", Issue.obj("tone", "calm"))))
            .requireAssurance(new Assurance.Requirement()));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("assurance"));
        has(r, "assurance: tighten rests on a degraded compatibility mode (" + Authorize.DEGRADED_LEGACY_POLARITY + "); a high-assurance policy never accepts it");
    }

    // ---- the tool call and the K1 derive action --------------------------------------------------------------------------

    @Test void theToolCallNamesTheVerb() {
        Map<String, Object> schema = AuthorizeRestK05bKillTest.schema(Issue.obj("amount", AuthorizeRestK05bKillTest.spec("type", "integer")));
        Map<String, Object> g = AuthorizeRunK05bKillTest.grant(AuthorizeRestK05bKillTest.toolCaveat("payments.send", schema));
        AuthorizeRunK05bKillTest.allowed(run(act(g), in(g)));
        Map<String, Object> other = AuthorizeRunK05bKillTest.grant(AuthorizeRestK05bKillTest.toolCaveat("payments.other", schema));
        AuthorizeRunK05bKillTest.denied(run(act(other), in(other)), "policy: caveat(s) not satisfied: tool_schema");
    }

    @Test void aDeriveCaveatReadsTheAction() {
        Map<String, Object> derive = Issue.obj("type", "derive", "id", "d1",
            "defs", List.<Object>of(Issue.obj("name", "v", "kind", "action", "field", "verb")),
            "check", Issue.obj("op", "eq", "a", Issue.obj("ref", "v"), "b", Issue.obj("const", "payments.send")));
        Map<String, Object> g = AuthorizeRunK05bKillTest.grant(new ArrayList<>(), star(), List.<Object>of(derive));
        AuthorizeRunK05bKillTest.allowed(run(act(g), in(g).k1(new LinkedHashMap<>())));
    }

    // ---- a policy evaluation that throws ---------------------------------------------------------------------------------

    /** A predicate list that throws on every read once armed. */
    @SuppressWarnings("serial")
    static final class Trap extends ArrayList<Object> {
        volatile boolean armed;
        Trap(Collection<?> c) { super(c); }
        private void check() { if (armed) throw new IllegalStateException("trap"); }
        @Override public Iterator<Object> iterator() { check(); return super.iterator(); }
        @Override public boolean isEmpty() { check(); return super.isEmpty(); }
        @Override public int size() { check(); return super.size(); }
        @Override public Object get(int i) { check(); return super.get(i); }
    }

    @SuppressWarnings("unchecked")
    @Test void aPolicyEvaluationThatThrowsFailsClosed() {
        Map<String, Object> g = grant();
        Map<String, Object> tg = new LinkedHashMap<>(g);
        List<Object> cavs = new ArrayList<>();
        Trap trap = null;
        for (Object c : (List<Object>) g.get("caveats")) {
            if (c instanceof Map && "envelope".equals(((Map<String, Object>) c).get("type"))) {
                Map<String, Object> e = new LinkedHashMap<>((Map<String, Object>) c);
                trap = new Trap((List<Object>) e.get("predicates"));
                e.put("predicates", trap);
                cavs.add(e);
            } else {
                cavs.add(c);
            }
        }
        tg.put("caveats", cavs);
        final Trap t = trap;
        // the same content: the grant verifies; the revocation check (after the core checks) arms the trap
        Authorize.AuthorizeResult r = run(act(g), in(tg).isRevoked((p, gr) -> {
            t.armed = true;
            return false;
        }));
        assertFalse(r.checks.containsKey("authorize"), r.reasons.toString());
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("policy"));
        has(r, "policy: policy evaluation error (fail closed)");
    }

    // ---- an admitted escalation answer -----------------------------------------------------------------------------------

    @Test void anAdmittedAnswerLiftsOnlyTheFailedChecks() {
        AuthorizeRunK05bKillTest.escalate();
        Map<String, Object> pc = AuthorizeRunK05bKillTest.pcactn();
        Map<String, Object> answer = Issue.escalationAnswer(PRINCIPAL, AuthorizeK05KillTest.GRANT, pc, null, true, NOW - 1000L, NOW + 600_000L, null);
        Authorize.AuthorizeResult r = run(pc, AuthorizeRunK05bKillTest.input().revocationStaleness(AuthorizeRunK05bKillTest.policy())
            .escalationAnswer(answer).escalationPrincipals(List.of(PRINCIPAL.id())).insecureUnboundApproval(true));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("pass", r.checks.get("classes"));
        assertEquals("pass", r.checks.get("escalation"));
        // a check that was not failed (not enforced) is not turned into a pass
        assertEquals("not-enforced", r.checks.get("freshness"));
        has(r, "escalation: answered allow by principal " + PRINCIPAL.id().substring(0, 8));
    }

    // ---- a required check's failure is never overwritten ------------------------------------------------------------------

    static final String PF_REQUIRED = "provenance_flow: required check is absent (default-deny: not enforced by this resource server)";

    @Test void aRequiredProvenanceFlowStaysRefusedWhenTheGatePasses() {
        Map<String, Object> pc = AuthorizeRunK05bKillTest.pcactn();
        Authorize.AuthorizeResult control = run(pc, AuthorizeRunK05bKillTest.input());
        assertTrue(control.allow, control.reasons.toString());
        assertEquals("pass", control.checks.get("provenance_flow"));
        Authorize.AuthorizeResult r = run(pc, AuthorizeRunK05bKillTest.input().require("provenance_flow"));
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("deny", r.decision);
        assertEquals("fail", r.checks.get("provenance_flow"));
        assertEquals(List.of(PF_REQUIRED), r.reasons);
    }

    @Test void aRequiredProvenanceFlowKeepsAFailingGatesReason() {
        Map<String, Object> pc = AuthorizeRunK05bKillTest.pcactn();
        Authorize.AuthorizeResult control = run(pc, AuthorizeRunK05bKillTest.input().provenanceGate(null));
        assertEquals("escalate", control.decision, control.reasons.toString());
        Authorize.AuthorizeResult r = run(pc, AuthorizeRunK05bKillTest.input().provenanceGate(null).require("provenance_flow"));
        assertEquals("deny", r.decision, r.reasons.toString());
        assertEquals("fail", r.checks.get("provenance_flow"));
        assertEquals(PF_REQUIRED, r.reasons.get(0));
        assertTrue(r.reasons.get(1).startsWith("provenance_flow: escalate: "), r.reasons.toString());
    }

    @Test void anotherEscalateClassFailureCannotMakeARequiredProvenanceFlowAnswerable() {
        AuthorizeRunK05bKillTest.escalate();
        Map<String, Object> pc = AuthorizeRunK05bKillTest.pcactn();
        Authorize.AuthorizeResult control = run(pc, AuthorizeRunK05bKillTest.input());
        assertEquals("escalate", control.decision, control.reasons.toString());
        Map<String, Object> answer = Issue.escalationAnswer(PRINCIPAL, AuthorizeK05KillTest.GRANT, pc, null, true, NOW - 1000L, NOW + 600_000L, null);
        Authorize.AuthorizeResult answered = run(pc, AuthorizeRunK05bKillTest.input()
            .escalationAnswer(answer).escalationPrincipals(List.of(PRINCIPAL.id())).insecureUnboundApproval(true));
        assertTrue(answered.allow, "control: the same answer allows without the require: " + answered.reasons);
        Authorize.AuthorizeResult r = run(pc, AuthorizeRunK05bKillTest.input().require("provenance_flow")
            .escalationAnswer(answer).escalationPrincipals(List.of(PRINCIPAL.id())).insecureUnboundApproval(true));
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("deny", r.decision);
        assertEquals("fail", r.checks.get("provenance_flow"));
        assertNull(r.escalation);
    }

    // ---- the provenance commitments: an executable registry plan, an admitted workflow step -----------------------------

    @Test void anExecutableRegistryPlanCommitsEveryValue() {
        Map<String, Object> g = grant();
        Map<String, Object> node = Issue.obj("id", "a", "verb", "payments.send", "resource", "payments/acme",
            "params_digest", Pca.paramsDigest(Issue.obj("amount", 50L)));
        Agent a = AuthorizeRunK05bKillTest.agent(g);
        a.commitPlan(List.of(node));
        Map<String, Object> pc = a.actNode("a", Issue.obj("amount", 50L));
        List<Object> nodes = new ArrayList<>();
        nodes.add(node);
        PlanRegistry reg = new PlanRegistry(new MemoryAtomicKv(), "pca-plan:", () -> NOW, null);
        PlanRegistryKillTest.authorized(reg, (String) g.get("id"), nodes, null);
        // no provenance bundle: only the principal's authorization of the plan makes the values (and the choice) trusted
        Authorize.AuthorizeResult r = run(pc, in(g).plan(null).plans(reg).provenanceGate(new ArgProvenance.Options()));
        AuthorizeRunK05bKillTest.allowed(r);
        assertEquals("pass", r.checks.get("provenance_flow"));
        // premise: a plan that is only drafted commits nothing
        PlanRegistry drafted = new PlanRegistry(new MemoryAtomicKv(), "pca-plan:", () -> NOW, null);
        assertTrue(drafted.draft((String) g.get("id"), nodes).ok);
        Authorize.AuthorizeResult d = run(pc, in(g).plan(null).plans(drafted).provenanceGate(new ArgProvenance.Options()));
        assertEquals("fail", d.checks.get("provenance_flow"), d.reasons.toString());
    }

    static Authorize.AuthorizeResult payAfterQuote(boolean withWorkflow) {
        Map<String, Object> f = AuthorizeWorkflowTest.F;
        Map<String, Object> s = AuthorizeWorkflowTest.m(AuthorizeWorkflowTest.l(AuthorizeWorkflowTest.kase("pay-after-quote").get("steps")).get(0));
        Map<String, Object> op = AuthorizeWorkflowTest.m(s.get("operation"));
        Map<String, Object> grant = AuthorizeWorkflowTest.m(f.get("grant"));
        List<Object> plan = AuthorizeWorkflowTest.l(f.get("plan"));
        Authorize.Input in = new Authorize.Input().risk(RiskCtx.ZERO)
            .operation(Authorize.Operation.of((String) op.get("verb"), (String) op.get("resource"), AuthorizeWorkflowTest.m(op.get("params"))))
            .audience((String) f.get("audience")).resolveGrant(ref -> ref.equals(grant.get("id")) ? grant : null)
            .stateStore(new MemoryStateStore()).isRevoked((p, g) -> false).now(Json.asLong(f.get("now"))).plan(null)
            .context(p -> Map.of("plan", plan, "plan_authorized", Boolean.TRUE))
            .provenanceGate(new ArgProvenance.Options()); // no bundle: the context is untrusted
        if (withWorkflow) {
            Map<String, Object> w = AuthorizeWorkflowTest.m(s.get("workflow"));
            in.workflow(AuthorizeRunK05bKillTestFlowsTest.PIN).workflowStep(new Authorize.WorkflowStep(w.get("commitment"), w.get("receipts"),
                (String) w.get("step"), w.get("units") == null ? null : AuthorizeWorkflowTest.m(w.get("units")), (String) w.get("goal_digest")));
        }
        return Authorize.authorize(s.get("pcactn"), in);
    }

    @Test void anAdmittedWorkflowStepCommitsTheChoiceOfAction() {
        Authorize.AuthorizeResult bare = payAfterQuote(false);
        assertTrue(bare.reasons.stream().anyMatch(x -> x.startsWith("provenance_flow: escalate: the choice of ")), bare.reasons.toString());
        Authorize.AuthorizeResult r = payAfterQuote(true);
        assertFalse(r.checks.containsKey("authorize"), r.reasons.toString());
        assertFalse(r.checks.containsKey("workflow"), r.reasons.toString());
        assertTrue(r.reasons.stream().noneMatch(x -> x.contains("the choice of ")), r.reasons.toString());
    }
}
