package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * Mutation kills for {@code Authorize.Options}: every {@code with...} copy keeps every other member and leaves the receiver alone,
 * and each configured member reaches the decision through {@code run}.
 */
class AuthorizeOptionsPitKill1Test {
    static final long NOW = AuthorizeK05KillTest.NOW;
    static final String AUD = AuthorizeK05KillTest.AUD;
    static final Authorize.Operation OP = Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 50L));
    static final Function<String, Map<String, Object>> RESOLVE = ref -> ref.equals(AuthorizeK05KillTest.GRANT.get("id")) ? AuthorizeK05KillTest.GRANT : null;

    static Authorize.Options base() {
        return new Authorize.Options(new MemoryStateStore(), (p, g) -> false, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO).withProvenance(ProvHarness.options());
    }

    static Authorize.AuthorizeResult run(Authorize.Options o) { return o.run(AuthorizeK05KillTest.pcactn(), OP, AUD, RESOLVE, NOW); }

    // ---- the copies keep every member

    static final int N = 25;

    static Object[] st(Authorize.Options o) {
        return new Object[] {o.k1, o.usesStore, o.escalationRender, o.insecureUnboundApproval, o.workflow, o.provenance, o.undo, o.allowedSuites, o.pqPins,
            o.multiInstance, o.thresholdHook, o.requireRiskInputs, o.adaptivePolicy, o.resolvePrincipal, o.requireVerifiedPrincipal, o.riskSource, o.noSeedBudget,
            o.requirePassport, o.passportHardware, o.enforceFreshness, o.taintContext, o.taintMax, o.linkedTemplateRegistry, o.forbid, o.contracts};
    }

    /** Asserts the receiver kept its state, the copy is another object, and the copy carries exactly the expected state. */
    static Authorize.Options check(Authorize.Options before, Object[] stateBefore, Authorize.Options after, Object[] stateAfter, String what) {
        assertNotNull(after, what);
        assertNotSame(before, after, what);
        assertArrayEquals(stateBefore, st(before), what + ": the receiver is unchanged");
        assertArrayEquals(stateAfter, st(after), what + ": the copy");
        assertSame(before.stateStore, after.stateStore, what);
        assertSame(before.isRevoked, after.isRevoked, what);
        assertEquals(before.plan, after.plan, what);
        assertEquals(before.require, after.require, what);
        return after;
    }

    static Object[] with(Object[] s, int i, Object v) {
        Object[] n = s.clone();
        n[i] = v;
        return n;
    }

    @Test void everyWithCopyKeepsEveryOtherMemberAndLeavesTheReceiverAlone() {
        Authorize.Options o = new Authorize.Options(new MemoryStateStore(), (p, g) -> false, Authorize.SINGLE_STEP, null, null);
        Map<String, Object> k1 = new LinkedHashMap<>();
        k1.put("a", 1L);
        MemoryStateStore uses = new MemoryStateStore();
        Function<Map<String, Object>, String> render = p -> "d";
        o.k1(k1).usesStore(uses).escalationRender(render).insecureUnboundApproval(true);
        Object[] s = new Object[N];
        s[0] = k1; s[1] = uses; s[2] = render; s[3] = true;
        s[9] = null; s[16] = false; s[18] = false; s[21] = 0.0;
        s[14] = false;
        assertArrayEquals(s, st(o));

        Authorize.WorkflowPin pin = new Authorize.WorkflowPin("p", "s", false);
        Authorize.Options n = check(o, s, o.withWorkflow(pin), with(s, 4, pin), "workflow");
        s = with(s, 4, pin); o = n;
        assertSame(pin, o.workflow());

        ArgProvenance.Options prov = ProvHarness.options();
        n = check(o, s, o.withProvenance(prov), with(s, 5, prov), "provenance");
        s = with(s, 5, prov); o = n;

        Undo.Admit undo = (pc, g, op) -> null;
        n = check(o, s, o.withUndo(undo), with(s, 6, undo), "undo");
        s = with(s, 6, undo); o = n;

        List<String> suites = List.of("ed25519");
        n = check(o, s, o.withAllowedSuites(suites), with(s, 7, suites), "allowedSuites");
        s = with(s, 7, suites); o = n;

        Map<String, Object> pins = Map.of("issuer", "pk");
        n = check(o, s, o.withPqPins(pins), with(s, 8, pins), "pqPins");
        s = with(s, 8, pins); o = n;

        n = check(o, s, o.withMultiInstance(false), with(s, 9, Boolean.FALSE), "multiInstance");
        s = with(s, 9, Boolean.FALSE); o = n;
        assertFalse(o.multiInstance());

        Authorize.ThresholdHook hook = p -> new Authorize.ThresholdOutcome(true, true, 1);
        n = check(o, s, o.withThresholdHook(hook), with(s, 10, hook), "thresholdHook");
        s = with(s, 10, hook); o = n;

        List<String> names = List.of("blastRadius");
        n = check(o, s, o.withRequireRiskInputs(names), with(s, 11, names), "requireRiskInputs");
        s = with(s, 11, names); o = n;

        java.util.function.LongFunction<Map<String, Object>> adaptive = now -> null;
        n = check(o, s, o.withAdaptivePolicy(adaptive), with(s, 12, adaptive), "adaptivePolicy");
        s = with(s, 12, adaptive); o = n;

        Authorize.PrincipalResolver resolver = (iss, g) -> null;
        Object[] s2 = with(with(s, 13, resolver), 14, Boolean.TRUE);
        n = check(o, s, o.withPrincipal(resolver, true), s2, "principal");
        s = s2; o = n;

        n = check(o, s, o.withRisk(RiskCtx.ZERO), with(s, 15, RiskCtx.ZERO), "risk");
        s = with(s, 15, RiskCtx.ZERO); o = n;

        n = check(o, s, o.withSeedBudget(false), with(s, 16, Boolean.TRUE), "seedBudget(false)");
        s = with(s, 16, Boolean.TRUE); o = n;
        n = check(o, s, o.withSeedBudget(true), with(s, 16, Boolean.FALSE), "seedBudget(true)");
        s = with(s, 16, Boolean.FALSE); o = n;
        n = check(o, s, o.withSeedBudget(false), with(s, 16, Boolean.TRUE), "seedBudget(false) again");
        s = with(s, 16, Boolean.TRUE); o = n;

        Passport.Options po = new Passport.Options();
        s2 = with(with(s, 17, po), 18, Boolean.TRUE);
        n = check(o, s, o.withRequirePassport(po, true), s2, "requirePassport");
        s = s2; o = n;
        s2 = with(with(s, 17, po), 18, Boolean.FALSE);
        n = check(o, s, o.withRequirePassport(po, false), s2, "requirePassport(false)");
        s = s2; o = n;
        s2 = with(with(s, 17, po), 18, Boolean.TRUE);
        n = check(o, s, o.withRequirePassport(po, true), s2, "requirePassport(true) again");
        s = s2; o = n;

        Authorize.FreshnessGate gate = new Authorize.FreshnessGate(1000L);
        n = check(o, s, o.withEnforceFreshness(gate), with(s, 19, gate), "enforceFreshness");
        s = with(s, 19, gate); o = n;

        Taint.Context tc = new Taint.Context(new Taint.InMemoryRegistry(), d -> true);
        s2 = with(with(s, 20, tc), 21, 0.5);
        n = check(o, s, o.withEnforceTaint(tc, 0.5), s2, "enforceTaint");
        s = s2; o = n;

        java.util.function.Supplier<Object> registry = () -> null;
        n = check(o, s, o.withRequireLinkedTemplate(registry), with(s, 22, registry), "requireLinkedTemplate");
        s = with(s, 22, registry); o = n;

        Authorize.ForbidOptions fo = new Authorize.ForbidOptions((op, g) -> List.of());
        n = check(o, s, o.withForbid(fo), with(s, 23, fo), "forbid");
        s = with(s, 23, fo); o = n;

        ContractEnforcer ce = K05HardeningPipelineTest.enforcer("x", new MemoryAtomicKv());
        n = check(o, s, o.withContracts(ce), with(s, 24, ce), "contracts");
        s = with(s, 24, ce); o = n;

        // the remaining copies keep all of it too
        assertArrayEquals(s, st(o.withAllowedSuites(suites)));
        assertArrayEquals(s, st(o.withProvenance(prov)));
        assertArrayEquals(s, st(o.withUndo(undo)));
        assertArrayEquals(s, st(o.withWorkflow(pin)));
        assertArrayEquals(s, st(o.withPlans(null)));
        assertArrayEquals(s, st(o.withIntentPolicy(null)));
        assertArrayEquals(s, st(o.withRequireAssurance(null)));
        assertArrayEquals(s, st(o.withRevocationStaleness(null)));
        assertArrayEquals(s, st(o.withRevocationState(p -> null)));
    }

    @Test void principalInfoKeepsItsFields() {
        Authorize.PrincipalInfo pi = new Authorize.PrincipalInfo(true, "agent", "a1");
        assertTrue(pi.verified);
        assertEquals("agent", pi.subjectType);
        assertEquals("a1", pi.subjectId);
        pi = new Authorize.PrincipalInfo(false, "user", "u9");
        assertFalse(pi.verified);
        assertEquals("user", pi.subjectType);
        assertEquals("u9", pi.subjectId);
    }

    @Test void pinKeysNameTheGrantAndTheStream() {
        assertEquals("pin:g1:beacon", Authorize.beaconPinKey("g1"));
        assertEquals("pin:g1:epoch", Authorize.epochPinKey("g1"));
    }

    // ---- the configured members reach the decision through run

    @Test void theControlAllows() {
        Authorize.AuthorizeResult r = run(base());
        assertTrue(r.allow, r.reasons.toString());
        for (String k : new String[] {"pq_pin", "threshold", "risk_inputs", "adaptive", "principal", "passport", "freshness", "taint_gate", "template", "forbid", "contract"}) {
            assertFalse(r.checks.containsKey(k), k);
        }
    }

    @Test void pqPinsReachTheDecision() {
        Authorize.AuthorizeResult r = run(base().withPqPins(Map.of(AuthorizeK05KillTest.PRINCIPAL.id(), "some-pq-key")));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("pq_pin"));
        assertTrue(r.reasons.contains("pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused"), r.reasons.toString());
        Authorize.AuthorizeResult other = run(base().withPqPins(Map.of("someone-else", "k")));
        assertTrue(other.allow, other.reasons.toString());
        assertEquals("pass", other.checks.get("pq_pin"));
    }

    @Test void theThresholdHookReachesTheDecision() {
        Authorize.AuthorizeResult ok = run(base().withThresholdHook(p -> new Authorize.ThresholdOutcome(true, true, 1)));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("threshold"));
        Authorize.AuthorizeResult rejected = run(base().withThresholdHook(p -> new Authorize.ThresholdOutcome(true, false, 1)));
        assertFalse(rejected.allow);
        assertEquals("fail", rejected.checks.get("threshold"));
    }

    @Test void requiredRiskInputsReachTheDecision() {
        Authorize.AuthorizeResult ok = run(base().withRequireRiskInputs(List.of("blastRadius")));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("risk_inputs"));
        Authorize.AuthorizeResult missing = run(base().withRequireRiskInputs(List.of("blastRadius", "nonexistent")));
        assertFalse(missing.allow);
        assertEquals("fail", missing.checks.get("risk_inputs"));
        assertTrue(missing.reasons.contains("risk_inputs: required risk input(s) not supplied by the server: nonexistent"), missing.reasons.toString());
    }

    @Test void theAdaptivePolicyReachesTheDecision() {
        Map<String, Object> pol = new LinkedHashMap<>();
        pol.put("weights", RiskTest.DEFAULT);
        pol.put("theta1", 0.1); pol.put("theta2", 0.15); pol.put("kappa", 1L); pol.put("lambda", 0L); pol.put("rho", 0L); pol.put("bMax", 10L);
        Map<String, Object> pc = K05ParityAuditTest.agentSigned("caution", new Json.Num("0.2"));
        Authorize.AuthorizeResult none = base().run(pc, OP, AUD, RESOLVE, NOW);
        assertNull(none.checks.get("adaptive"));
        Authorize.AuthorizeResult tight = base().withAdaptivePolicy(now -> pol).run(pc, OP, AUD, RESOLVE, NOW);
        assertFalse(tight.allow);
        assertEquals("fail", tight.checks.get("adaptive"));
        assertTrue(tight.reasons.contains("adaptive: tightened policy requires threshold t=3 (grant policy: t=1)"), tight.reasons.toString());
    }

    @Test void thePrincipalResolverReachesTheDecision() {
        Authorize.AuthorizeResult unverified = run(base().withPrincipal((iss, g) -> new Authorize.PrincipalInfo(false, null, null), true));
        assertFalse(unverified.allow);
        assertEquals("fail", unverified.checks.get("principal"));
        assertTrue(unverified.reasons.contains("principal: the grant issuer is not an enrolled, verified principal"), unverified.reasons.toString());
        Authorize.AuthorizeResult verified = run(base().withPrincipal((iss, g) -> new Authorize.PrincipalInfo(true, "agent", "a1"), true));
        assertTrue(verified.allow, verified.reasons.toString());
        assertEquals("pass", verified.checks.get("principal"));
        // not required: an unverified or unknown principal is recorded, not refused
        Authorize.AuthorizeResult soft = run(base().withPrincipal((iss, g) -> new Authorize.PrincipalInfo(false, null, null), false));
        assertTrue(soft.allow, soft.reasons.toString());
        assertEquals("not-enforced", soft.checks.get("principal"));
        Authorize.AuthorizeResult unknown = run(base().withPrincipal((iss, g) -> null, false));
        assertTrue(unknown.allow, unknown.reasons.toString());
        assertEquals("not-enforced", unknown.checks.get("principal"));
        // required but no resolver
        Authorize.AuthorizeResult noResolver = run(base().withPrincipal(null, true));
        assertFalse(noResolver.allow);
        assertTrue(noResolver.reasons.contains("principal: requireVerifiedPrincipal needs a resolvePrincipal resolver"), noResolver.reasons.toString());
        // the resolver is asked about the grant issuer and the stored grant
        String[] seen = new String[1];
        Object[] seenGrant = new Object[1];
        Authorize.PrincipalResolver spy = (iss, g) -> { seen[0] = iss; seenGrant[0] = g; return new Authorize.PrincipalInfo(true, null, null); };
        run(base().withPrincipal(spy, false));
        assertEquals(AuthorizeK05KillTest.PRINCIPAL.id(), seen[0]);
        assertSame(AuthorizeK05KillTest.GRANT, seenGrant[0]);
        // a resolver that throws refuses
        Authorize.AuthorizeResult thrown = run(base().withPrincipal((iss, g) -> { throw new IllegalStateException("x"); }, false));
        assertFalse(thrown.allow);
        assertTrue(thrown.reasons.contains("principal: the principal resolver failed (fail closed)"), thrown.reasons.toString());
    }

    @Test void theSeedBudgetSwitchReachesTheDecision() {
        Authorize.AuthorizeResult seeded = run(base());
        assertEquals("pass", seeded.checks.get("budget"));
        Authorize.AuthorizeResult bare = run(base().withSeedBudget(false));
        assertEquals("not-enforced", bare.checks.get("budget"));
        assertTrue(bare.reasons.stream().anyMatch(r -> r.startsWith("budget: no budget supplied")), bare.reasons.toString());
        Authorize.AuthorizeResult again = run(base().withSeedBudget(false).withSeedBudget(true));
        assertEquals("pass", again.checks.get("budget"));
    }

    @Test void aRequiredPassportReachesTheDecision() {
        Authorize.AuthorizeResult r = run(base().withRequirePassport(PassportKillTest.opts(), false));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("passport"));
        assertTrue(r.reasons.contains("passport: malformed"), r.reasons.toString());
    }

    @Test void theFreshnessGateReachesTheDecision() {
        Authorize.AuthorizeResult r = run(base().withEnforceFreshness(new Authorize.FreshnessGate(1000L)));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("freshness"));
    }

    @Test void theTaintGateReachesTheDecision() {
        Authorize.AuthorizeResult r = run(base().withEnforceTaint(new Taint.Context(new Taint.InMemoryRegistry(), d -> true), 0.5));
        assertTrue(r.checks.containsKey("taint_gate"), r.checks.toString());
    }

    @Test void theLinkedTemplateRegistryReachesTheDecision() {
        Authorize.AuthorizeResult r = run(base().withRequireLinkedTemplate(() -> null));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("template"));
        assertTrue(r.reasons.contains("template: the grant carries no template_ref"), r.reasons.toString());
        Authorize.AuthorizeResult in = Authorize.authorize(AuthorizeK05KillTest.pcactn(), AuthorizeK05KillTest.input(Map.of("amount", 50L)).requireLinkedTemplate(() -> null));
        assertFalse(in.allow);
        assertEquals("fail", in.checks.get("template"));
    }

    static List<Object> forbidAll(Authorize.Operation op, Map<String, Object> grant) {
        Map<String, Object> when = new LinkedHashMap<>();
        when.put("verb", "payments.send");
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("id", "f1");
        c.put("kind", "forbid");
        c.put("when", when);
        return new ArrayList<>(List.<Object>of(c));
    }

    @Test void theForbidClausesReachTheDecision() {
        Authorize.AuthorizeResult r = run(base().withForbid(new Authorize.ForbidOptions(AuthorizeOptionsPitKill1Test::forbidAll)));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("forbid"));
        assertTrue(r.reasons.contains("forbid: deny by forbid f1"), r.reasons.toString());
    }

    @Test void theContractReachesTheDecision() {
        Authorize.AuthorizeResult r = run(base().withContracts(K05HardeningPipelineTest.enforcer("payments.send", new MemoryAtomicKv())));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("contract"));
        assertTrue(r.reasons.contains("contract: violated (no-send)"), r.reasons.toString());
    }

    // ---- the Input-level passport requirement

    static Authorize.Input passportInput(Passport.Options o, boolean hardware) {
        return AuthorizeK05KillTest.input(Map.of("amount", 50L)).stateStore(new MemoryStateStore()).requirePassport(o, hardware);
    }

    @Test void aHardwareRequirementRefusesASoftwarePassport() {
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        Map<String, Object> soft = K05HardeningPipelineTest.passportFor(K05HardeningPipelineTest.leafOf(pc), PassportKillTest.identity(false), null);
        Authorize.AuthorizeResult plain = Authorize.authorize(pc, passportInput(PassportKillTest.opts(), false).passport(soft));
        assertTrue(plain.allow, plain.reasons.toString());
        assertEquals("pass", plain.checks.get("passport"));
        Authorize.AuthorizeResult hw = Authorize.authorize(AuthorizeK05KillTest.pcactn(), passportInput(PassportKillTest.opts(), true).passport(soft));
        assertFalse(hw.allow);
        assertEquals("fail", hw.checks.get("passport"));
        assertTrue(hw.reasons.contains("passport: hardware_evidence_missing"), hw.reasons.toString());
    }

    @Test void aHardwarePassportSatisfiesAHardwareRequirement() {
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        Passport.Options o = PassportKillTest.opts();
        o.attest = PassportKillTest.good();
        Map<String, Object> ev = PassportKillTest.evidence(NOW, "n1");
        Map<String, Object> hw = K05HardeningPipelineTest.passportFor(K05HardeningPipelineTest.leafOf(pc), PassportKillTest.identity(true), ev);
        Authorize.AuthorizeResult r = Authorize.authorize(pc, passportInput(o, true).passport(hw));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("pass", r.checks.get("passport"));
    }

    @Test void thePassportOptionsReachTheVerifier() {
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        Object leaf = K05HardeningPipelineTest.leafOf(pc);
        // a passport that starts 500 ms after the call clock needs the configured skew
        Map<String, Object> future = PassportKillTest.body(PassportKillTest.identity(false), null);
        future.put("sub", leaf);
        future.put("iat", NOW + 500); future.put("nbf", NOW + 500); future.put("exp", NOW + 1_000_000L);
        Map<String, Object> signedFuture = PassportKillTest.signBody(future);
        Authorize.AuthorizeResult strict = Authorize.authorize(pc, passportInput(PassportKillTest.opts(), false).passport(signedFuture));
        assertFalse(strict.allow);
        assertTrue(strict.reasons.contains("passport: not_yet_valid"), strict.reasons.toString());
        Passport.Options skewed = PassportKillTest.opts();
        skewed.clockSkewMs = 1000L;
        Authorize.AuthorizeResult ok = Authorize.authorize(AuthorizeK05KillTest.pcactn(), passportInput(skewed, false).passport(signedFuture));
        assertTrue(ok.allow, ok.reasons.toString());
        // hardware evidence older than the configured maximum age is stale (the default is a day)
        Map<String, Object> ev = PassportKillTest.evidence(NOW - 5_000L, "n1");
        Map<String, Object> hw = K05HardeningPipelineTest.passportFor(leaf, PassportKillTest.identity(true), ev);
        Passport.Options fresh = PassportKillTest.opts();
        fresh.attest = PassportKillTest.good();
        Authorize.AuthorizeResult dayOk = Authorize.authorize(AuthorizeK05KillTest.pcactn(), passportInput(fresh, true).passport(hw));
        assertTrue(dayOk.allow, dayOk.reasons.toString());
        Passport.Options tight = PassportKillTest.opts();
        tight.attest = PassportKillTest.good();
        tight.maxEvidenceAgeMs = 1_000L;
        Authorize.AuthorizeResult stale = Authorize.authorize(AuthorizeK05KillTest.pcactn(), passportInput(tight, true).passport(hw));
        assertFalse(stale.allow);
        assertTrue(stale.reasons.contains("passport: hardware_evidence_stale"), stale.reasons.toString());
        // the built-in hardware seam is used when no verifier is given
        Passport.Options seam = PassportKillTest.opts();
        seam.defaultHardware = nowMs -> PassportKillTest.good();
        Authorize.AuthorizeResult viaSeam = Authorize.authorize(AuthorizeK05KillTest.pcactn(), passportInput(seam, true).passport(hw));
        assertTrue(viaSeam.allow, viaSeam.reasons.toString());
        Authorize.AuthorizeResult none = Authorize.authorize(AuthorizeK05KillTest.pcactn(), passportInput(PassportKillTest.opts(), true).passport(hw));
        assertFalse(none.allow);
        assertTrue(none.reasons.contains("passport: hardware_verifier_missing"), none.reasons.toString());
        // the revocation source is the configured one
        Passport.Options revoked = PassportKillTest.opts();
        revoked.revoked = (id, iss, sub) -> true;
        Authorize.AuthorizeResult gone = Authorize.authorize(AuthorizeK05KillTest.pcactn(), passportInput(revoked, false).passport(K05HardeningPipelineTest.passportFor(leaf, PassportKillTest.identity(false), null)));
        assertFalse(gone.allow);
        assertTrue(gone.reasons.contains("passport: revoked"), gone.reasons.toString());
    }

    @Test void aPcactnWithAnEmptyChainSkipsThePassportCheck() {
        Map<String, Object> pc = K05ParityAuditTest.agentSigned("cap_chain", new ArrayList<Object>());
        Authorize.AuthorizeResult r = Authorize.authorize(pc, passportInput(PassportKillTest.opts(), false));
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("chain"), r.checks.toString());
        assertFalse(r.checks.containsKey("passport"), r.checks.toString());
        assertFalse(r.checks.containsKey("authorize"), r.checks.toString());
    }
}
