package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** PCA 0.5 hardening of the pipeline: host callbacks that throw an Error other than OutOfMemoryError deny (H14). */
class K05HardeningPipelineTest {
    static final Throwable[] FAULTS = {new AssertionError("x"), new StackOverflowError(), new NoClassDefFoundError("x"), new UnsatisfiedLinkError("x")};

    @Test void passportHostCallbacksDenyOnAnyNonFatalThrowable() {
        for (Throwable t : FAULTS) {
            Passport.Options o = PassportKillTest.opts();
            o.revoked = (id, iss, sub) -> boom(t);
            PassportKillTest.is("revocation_unavailable", PassportKillTest.soft(), o);
            o = PassportKillTest.opts();
            o.attest = (d, b) -> boom(t);
            PassportKillTest.is("hardware_attestation_failed", PassportKillTest.hardware(), o);
        }
    }

    @SuppressWarnings("unchecked")
    static <T extends Throwable> void doThrow(Throwable t) throws T { throw (T) t; }

    /** Throws any Throwable without declaring it (a statement call: no cast is inserted at the call site). */
    static <R> R boom(Throwable t) {
        K05HardeningPipelineTest.<RuntimeException>doThrow(t);
        return null;
    }

    @Test void authorizeHostCallbacksDenyOnAnyNonFatalThrowable() {
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        for (Throwable t : FAULTS) {
            AuthorizeK05KillTest.refused(AuthorizeK05KillTest.run(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).resolveGrant(ref -> boom(t))),
                403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)");
            AuthorizeK05KillTest.refused(AuthorizeK05KillTest.run(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).context(p -> boom(t))),
                403, "context", "context: the context callback failed (fail closed)");
            Authorize.AuthorizeResult r = AuthorizeK05KillTest.run(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).isRevoked((p, g) -> boom(t)));
            assertFalse(r.allow);
            assertEquals("fail", r.checks.get("revocation"));
            assertTrue(r.reasons.contains("revocation: the revocation check failed (fail closed)"), r.reasons.toString());
        }
    }

    @Test void outOfMemoryIsNotContained() {
        Passport.Options o = PassportKillTest.opts();
        o.revoked = (id, iss, sub) -> { throw new OutOfMemoryError("x"); };
        assertThrows(OutOfMemoryError.class, () -> Passport.verify(PassportKillTest.soft(), o));
    }

    // ---- P3: a bare Options has no plan and denies plan_root_authorized, exactly like TS authorize(); single-step is explicit

    @Test void aBareOptionsHasNoPlanSoPlanRootAuthorizedDenies() {
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        Authorize.Input in = new Authorize.Input().risk(RiskCtx.ZERO).operation(Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 50L)))
            .audience(AuthorizeK05KillTest.AUD).resolveGrant(ref -> AuthorizeK05KillTest.GRANT).stateStore(new MemoryStateStore())
            .isRevoked((p, g) -> false).now(AuthorizeK05KillTest.NOW).provenanceGate(ProvHarness.options());
        Authorize.AuthorizeResult bare = Authorize.authorize(pc, in);
        assertFalse(bare.allow);
        assertEquals("fail", bare.checks.get("plan_root_authorized"));
        assertTrue(bare.reasons.contains("plan_root_authorized: default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)"), bare.reasons.toString());
        Authorize.Options bareOptions = new Authorize.Options(new MemoryStateStore(), (p, g) -> false).withRisk(RiskCtx.ZERO);
        assertEquals(null, bareOptions.plan);
        Authorize.Options explicit = new Authorize.Options(new MemoryStateStore(), (p, g) -> false, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO);
        assertEquals(Authorize.SINGLE_STEP, explicit.plan);
        Authorize.AuthorizeResult ok = Authorize.authorize(pc, in.plan(Authorize.SINGLE_STEP).stateStore(new MemoryStateStore()));
        assertTrue(ok.allow, ok.reasons.toString());
    }

    // ---- F6: a present JSON null obligations member is not the absent list

    @Test void aPresentNullObligationsMemberIsRefused() {
        Map<String, Object> nul = new java.util.LinkedHashMap<>();
        nul.put("obligations", null);
        assertEquals("obligations must be an array", Obligations.memberError(nul));
        assertEquals(null, Obligations.memberError(new java.util.LinkedHashMap<>()));
        assertEquals(null, Obligations.memberError(Map.of("obligations", java.util.List.of())));
        assertEquals("obligations must be an array", Obligations.memberError(Map.of("obligations", "x")));
        assertEquals(null, Obligations.listError(null)); // the value API: a Java null is the absent list
    }

    // ---- H16: a process-scoped store is refused for a multi-instance guard

    @Test void multiInstanceNeedsASharedStore() {
        Authorize.Options process = new Authorize.Options(new MemoryStateStore(), (p, g) -> false, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO);
        assertFalse(process.multiInstance());
        assertEquals("multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)",
            assertThrows(IllegalArgumentException.class, () -> process.withMultiInstance(true)).getMessage());
        assertFalse(process.withMultiInstance(false).multiInstance());
        StateStore shared = (key, counter) -> StateStore.ClaimResult.claimed();
        assertFalse(shared.processScoped());
        Authorize.Options sharedOptions = new Authorize.Options(shared, (p, g) -> false, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO);
        assertTrue(sharedOptions.multiInstance());
        assertTrue(sharedOptions.withMultiInstance(true).multiInstance());
        assertFalse(sharedOptions.withMultiInstance(false).multiInstance());
        assertTrue(new MemoryStateStore().processScoped());
    }

    // ---- H13: the revocation-epoch rollback pin is automatic

    static Map<String, Object> epochN(String grantRef, long now, long e) {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("instance_id", "i");
        body.put("grant_ref", grantRef);
        body.put("epoch", IntentJs.ofLong(e));
        body.put("set_size", IntentJs.ofLong(0));
        body.put("root", Mesh.bindRevRoot(0, Ledger.EMPTY_TREE_ROOT));
        body.put("issued_at", IntentJs.ofLong(now - 30_000));
        body.put("not_after", IntentJs.ofLong(now - 30_000 + 600_000));
        byte[] msg = Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.getBytes(java.nio.charset.StandardCharsets.UTF_8), IntentJs.canonBytes(body));
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(StalenessVectorsTest.seed("staleness/guardian"), 0, msg, 0, msg.length, sig, 0);
        Map<String, Object> ep = new java.util.LinkedHashMap<>(body);
        ep.put("guardian", StalenessVectorsTest.pub());
        ep.put("sig", Pca.b64(sig));
        return ep;
    }

    static Authorize.AuthorizeResult withEpoch(StateStore store, long epoch, Long hostPin) {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Map<String, Object> pcactn = AuthorizeFixtures.pcactn(c, 0);
        long now = AuthorizeFixtures.now();
        Object state = RevocationStaleness.State.epoch(epochN((String) pcactn.get("grant_ref"), now, epoch), null, hostPin);
        Map<String, Object> proof = new java.util.LinkedHashMap<>();
        proof.put("size", IntentJs.ofLong(0));
        RevocationStaleness policy = new RevocationStaleness().maxRevocationAgeMs(300_000).guardianPublic(StalenessVectorsTest.pub()).proofs((id, pc) -> proof);
        return Authorize.authorize(pcactn, AuthorizeFixtures.input(c, 0).stateStore(store).revocationStaleness(policy).context(pc -> {
            Map<String, Object> m = new java.util.LinkedHashMap<>();
            m.put("revocation_state", state);
            return m;
        }));
    }

    static String pinKey() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        return Authorize.epochPinKey((String) AuthorizeFixtures.pcactn(c, 0).get("grant_ref"));
    }

    static final String ROLLBACK = "freshness: revocation epoch 0 is older than the last accepted ";

    @Test void theRollbackPinIsRaisedByAnAllowAndNeverLowered() {
        MemoryStateStore store = new MemoryStateStore();
        assertNull(store.last(pinKey()));
        Authorize.AuthorizeResult first = withEpoch(store, 0, null);
        assertTrue(first.allow, first.reasons.toString());
        assertEquals(Long.valueOf(0), store.last(pinKey())); // an allow raises the pin to the accepted epoch
        // a stored pin above the epoch makes it a rollback, with no host pin at all; a denied action never moves the pin
        MemoryStateStore seeded = new MemoryStateStore();
        seeded.claim(pinKey(), 5);
        Authorize.AuthorizeResult old = withEpoch(seeded, 0, null);
        assertFalse(old.allow);
        assertTrue(old.reasons.contains(ROLLBACK + "5 (rollback)"), old.reasons.toString());
        assertEquals(Long.valueOf(5), seeded.last(pinKey()));
        // the effective pin is the higher of the host's value and the stored one
        MemoryStateStore hostHigher = new MemoryStateStore();
        hostHigher.claim(pinKey(), 2);
        Authorize.AuthorizeResult h = withEpoch(hostHigher, 0, 9L);
        assertFalse(h.allow);
        assertTrue(h.reasons.contains(ROLLBACK + "9 (rollback)"), h.reasons.toString());
        MemoryStateStore storeHigher = new MemoryStateStore();
        storeHigher.claim(pinKey(), 9);
        Authorize.AuthorizeResult sh = withEpoch(storeHigher, 0, 2L);
        assertFalse(sh.allow);
        assertTrue(sh.reasons.contains(ROLLBACK + "9 (rollback)"), sh.reasons.toString());
        // a pin equal to the epoch is not a rollback
        MemoryStateStore equal = new MemoryStateStore();
        equal.claim(pinKey(), 0);
        assertTrue(withEpoch(equal, 0, 0L).allow);
    }

    @Test void aStoreThatCannotHoldPinsIsRefused() {
        StateStore plain = (key, counter) -> StateStore.ClaimResult.claimed();
        String msg = "revocation staleness needs a state store that implements pins (rollback protection)";
        Authorize.Options o = new Authorize.Options(plain, (p, g) -> false, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO);
        assertEquals(msg, assertThrows(IllegalArgumentException.class, () -> o.withRevocationStaleness(new RevocationStaleness().maxRevocationAgeMs(1))).getMessage());
        assertEquals(msg, assertThrows(IllegalArgumentException.class, () -> o.withRevocationStaleness(new RevocationStaleness())).getMessage());
        assertNull(o.withRevocationStaleness(null).revocationStaleness);
        new Authorize.Options(new MemoryStateStore(), (p, g) -> false, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO).withRevocationStaleness(new RevocationStaleness().maxRevocationAgeMs(1));
        // the Input path refuses at decision time (fail closed)
        Authorize.AuthorizeResult r = withEpoch(plain, 5, null);
        assertFalse(r.allow);
        assertTrue(r.reasons.contains("freshness: " + msg), r.reasons.toString());
    }

    // ---- F3: requireVerifiedPrincipal + resolvePrincipal

    @Test void aVerifiedPrincipalCanBeRequired() {
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        Authorize.Input base = AuthorizeK05KillTest.input(Map.of("amount", 50L));
        Authorize.AuthorizeResult none = Authorize.authorize(pc, base);
        assertNull(none.checks.get("principal")); // not configured: not reported
        Authorize.AuthorizeResult verified = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L))
            .principal((issuer, grant) -> new Authorize.PrincipalInfo(true, "user", "u1"), true));
        assertTrue(verified.allow, verified.reasons.toString());
        assertEquals("pass", verified.checks.get("principal"));
        Authorize.AuthorizeResult unverified = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L))
            .principal((issuer, grant) -> new Authorize.PrincipalInfo(false, "unverified", null), true));
        assertFalse(unverified.allow);
        assertEquals("fail", unverified.checks.get("principal"));
        assertTrue(unverified.reasons.contains("principal: the grant issuer is not an enrolled, verified principal"), unverified.reasons.toString());
        Authorize.AuthorizeResult unknown = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).principal((issuer, grant) -> null, true));
        assertEquals("fail", unknown.checks.get("principal"));
        // not required: an unverified principal is reported as not-enforced and admitted
        Authorize.AuthorizeResult soft = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).principal((issuer, grant) -> new Authorize.PrincipalInfo(false, "unverified", null), false));
        assertTrue(soft.allow, soft.reasons.toString());
        assertEquals("not-enforced", soft.checks.get("principal"));
        // required without a resolver
        Authorize.AuthorizeResult noResolver = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).principal(null, true));
        assertFalse(noResolver.allow);
        assertTrue(noResolver.reasons.contains("principal: requireVerifiedPrincipal needs a resolvePrincipal resolver"), noResolver.reasons.toString());
        // a resolver that throws denies
        Authorize.AuthorizeResult thrown = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).principal((issuer, grant) -> boom(new AssertionError("x")), false));
        assertFalse(thrown.allow);
        assertTrue(thrown.reasons.contains("principal: the principal resolver failed (fail closed)"), thrown.reasons.toString());
        String[] seen = new String[1];
        Authorize.authorize(AuthorizeK05KillTest.pcactn(), AuthorizeK05KillTest.input(Map.of("amount", 50L)).principal((issuer, grant) -> { seen[0] = issuer; return null; }, false));
        assertEquals(AuthorizeK05KillTest.GRANT.get("issuer"), seen[0]);
    }

    // ---- F3: enforce.freshness (the signed freshness anchor)

    static Authorize.AuthorizeResult withAnchor(Object epoch, Authorize.FreshnessGate gate) {
        Map<String, Object> fr = new java.util.LinkedHashMap<>();
        fr.put("beacon_ref", "beacon-1");
        fr.put("epoch", epoch);
        fr.put("accumulator_witness", "");
        Map<String, Object> pc = K05ParityAuditTest.agentSigned("freshness", fr);
        return Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).enforceFreshness(gate));
    }

    @Test void theFreshnessAnchorGate() {
        long e = AuthorizeK05KillTest.NOW / 60_000L;
        Authorize.FreshnessGate gate = new Authorize.FreshnessGate(60_000L);
        Authorize.AuthorizeResult ok = withAnchor(IntentJs.ofLong(e), gate);
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("freshness"));
        // exactly maxAge old passes, one millisecond more is stale (an anchor five epochs back, so maxAge stays valid)
        long old = e - 5;
        long anchor = old * 60_000L;
        gate.maxAgeMs = AuthorizeK05KillTest.NOW - anchor;
        assertTrue(withAnchor(IntentJs.ofLong(old), gate).allow);
        gate.maxAgeMs = AuthorizeK05KillTest.NOW - anchor - 1;
        Authorize.AuthorizeResult stale = withAnchor(IntentJs.ofLong(old), gate);
        assertFalse(stale.allow);
        assertTrue(stale.reasons.contains("freshness: freshness anchor is stale (older than " + gate.maxAgeMs + " ms)"), stale.reasons.toString());
        // the future, with and without a skew that covers it
        gate.maxAgeMs = 3_600_000L;
        Authorize.AuthorizeResult future = withAnchor(IntentJs.ofLong(e + 10), gate);
        assertFalse(future.allow);
        assertTrue(future.reasons.contains("freshness: freshness anchor is in the future"), future.reasons.toString());
        gate.clockSkewMs = 10 * 60_000L;
        assertTrue(withAnchor(IntentJs.ofLong(e + 10), gate).allow);
        gate.clockSkewMs = -5L;
        assertFalse(withAnchor(IntentJs.ofLong(e + 10), gate).allow); // a negative skew reads as 0
        // a stub anchor (epoch 0 / empty beacon) is missing
        gate.clockSkewMs = null;
        for (Object stub : new Object[] {IntentJs.ofLong(0), IntentJs.ofLong(-1)}) {
            Authorize.AuthorizeResult missing = withAnchor(stub, gate);
            assertFalse(missing.allow);
            assertTrue(missing.reasons.contains("freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)"), missing.reasons.toString());
        }
        Authorize.AuthorizeResult none = Authorize.authorize(K05ParityAuditTest.agentSigned(), AuthorizeK05KillTest.input(Map.of("amount", 50L)).enforceFreshness(gate));
        assertFalse(none.allow);
        // misconfigured
        Authorize.FreshnessGate bad = new Authorize.FreshnessGate(-1L);
        Authorize.AuthorizeResult mis = withAnchor(IntentJs.ofLong(e), bad);
        assertTrue(mis.reasons.contains("freshness: freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)"), mis.reasons.toString());
        Authorize.FreshnessGate zero = new Authorize.FreshnessGate(1000L);
        zero.epochMs = 0L;
        assertFalse(withAnchor(IntentJs.ofLong(e), zero).allow);
        // the gate's own clock
        Authorize.FreshnessGate clock = new Authorize.FreshnessGate(1000L);
        clock.nowMs = e * 60_000L + 500;
        assertTrue(withAnchor(IntentJs.ofLong(e), clock).allow);
        // off by default
        assertTrue(Authorize.authorize(K05ParityAuditTest.agentSigned(), AuthorizeK05KillTest.input(Map.of("amount", 50L))).allow);
    }

    // ---- F3: requirePassport (checked before any replay state is written)

    @Test void aPassportIsRequiredBeforeTheCounterIsSpent() {
        MemoryStateStore store = new MemoryStateStore();
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        Authorize.Input in = AuthorizeK05KillTest.input(Map.of("amount", 50L)).stateStore(store).requirePassport(PassportKillTest.opts(), false);
        Authorize.AuthorizeResult absent = Authorize.authorize(pc, in);
        assertFalse(absent.allow);
        assertEquals("fail", absent.checks.get("passport"));
        assertTrue(absent.reasons.contains("passport: malformed"), absent.reasons.toString());
        // a genuine passport for ANOTHER subject than the PCActn's leaf holder is refused, and nothing was consumed
        Map<String, Object> pb = PassportKillTest.body(PassportKillTest.identity(false), null);
        pb.put("iat", AuthorizeK05KillTest.NOW - 1000L); pb.put("nbf", AuthorizeK05KillTest.NOW - 1000L); pb.put("exp", AuthorizeK05KillTest.NOW + 1_000_000L); // a window around this call's clock, so only the subject can refuse it
        Authorize.AuthorizeResult other = Authorize.authorize(pc, in.passport(PassportKillTest.signBody(pb)));
        assertFalse(other.allow);
        assertEquals("fail", other.checks.get("passport"));
        assertTrue(other.reasons.contains("passport: subject_mismatch"), other.reasons.toString());
        assertNull(store.last(Authorize.stateKey((String) AuthorizeK05KillTest.GRANT.get("id"), (String) leafOf(pc))));
        // not configured: no passport check at all
        assertNull(Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L))).checks.get("passport"));
    }

    /** A passport for the PCActn's own leaf holder, valid around this call's clock. */
    static Map<String, Object> passportFor(Object subject, Map<String, Object> identity, Map<String, Object> evidence) {
        Map<String, Object> pb = PassportKillTest.body(identity, evidence);
        pb.put("sub", subject);
        pb.put("iat", AuthorizeK05KillTest.NOW - 1000L); pb.put("nbf", AuthorizeK05KillTest.NOW - 1000L); pb.put("exp", AuthorizeK05KillTest.NOW + 1_000_000L);
        return PassportKillTest.signBody(pb);
    }

    @Test void anAllowedCallWithAPassportCarriesTheReferencePassportAssurance() {
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        // software passport: {outcome: pass, level: software}
        Authorize.AuthorizeResult soft = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).stateStore(new MemoryStateStore())
            .requirePassport(PassportKillTest.opts(), false).passport(passportFor(leafOf(pc), PassportKillTest.identity(false), null)));
        assertTrue(soft.allow, soft.reasons.toString());
        assertEquals(Map.of("outcome", "pass", "level", "software"), soft.assurance().get("passport"));
        // hardware passport: level and vendor come from the verifier's label (unknown without one)
        for (boolean labelled : new boolean[] {true, false}) {
            Passport.Attest att = (d, b) -> new Passport.Attestation(true, true, PassportKillTest.identity(true));
            if (labelled) Assurance.setLabel(att, Assurance.Label.of("hardware").vendor("acme"));
            Passport.Options o = PassportKillTest.opts();
            o.attest = att;
            Map<String, Object> ev = PassportKillTest.evidence(AuthorizeK05KillTest.NOW, "n1");
            Authorize.AuthorizeResult hw = Authorize.authorize(AuthorizeK05KillTest.pcactn(), AuthorizeK05KillTest.input(Map.of("amount", 50L)).stateStore(new MemoryStateStore())
                .requirePassport(o, true).passport(passportFor(leafOf(pc), PassportKillTest.identity(true), ev)));
            assertTrue(hw.allow, hw.reasons.toString());
            assertEquals(labelled ? Map.of("outcome", "pass", "level", "hardware", "vendor", "acme") : Map.of("outcome", "pass", "level", "unknown"), hw.assurance().get("passport"));
        }
        // no passport configured, or a refused one: no entry
        assertNull(Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).stateStore(new MemoryStateStore())).assurance().get("passport"));
    }

    @SuppressWarnings("unchecked")
    static Object leafOf(Map<String, Object> pc) {
        java.util.List<Object> chain = (java.util.List<Object>) pc.get("cap_chain");
        return ((Map<String, Object>) chain.get(chain.size() - 1)).get("holder");
    }

    // ---- F3: forbid-wins clauses before the counter is spent

    static java.util.List<Object> clauses(String forbidResource) {
        Map<String, Object> permit = new java.util.LinkedHashMap<>();
        permit.put("id", "p"); permit.put("kind", "permit"); permit.put("signer", "user");
        permit.put("when", Map.of("verb", "payments.send"));
        Map<String, Object> forbid = new java.util.LinkedHashMap<>();
        forbid.put("id", "f"); forbid.put("kind", "forbid"); forbid.put("signer", "org");
        forbid.put("when", Map.of("verb", "payments.send", "resource", forbidResource));
        return new java.util.ArrayList<>(java.util.List.of(permit, forbid));
    }

    @Test void aForbidClauseRefusesBeforeTheCounterIsSpent() {
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        Authorize.ForbidOptions open = new Authorize.ForbidOptions((op, g) -> clauses("other/*"));
        Authorize.AuthorizeResult ok = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).forbid(open));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("forbid"));
        MemoryStateStore store = new MemoryStateStore();
        Authorize.ForbidOptions blocked = new Authorize.ForbidOptions((op, g) -> clauses("payments/*"));
        Authorize.AuthorizeResult no = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).stateStore(store).forbid(blocked));
        assertFalse(no.allow);
        assertEquals("fail", no.checks.get("forbid"));
        assertTrue(no.reasons.contains("forbid: deny by forbid f"), no.reasons.toString());
        assertNull(store.last(Authorize.stateKey((String) AuthorizeK05KillTest.GRANT.get("id"), (String) leafOf(pc))));
        // a certificate is demanded and recomputed
        Authorize.ForbidOptions need = new Authorize.ForbidOptions((op, g) -> clauses("other/*"));
        need.requireCertificate = true;
        Authorize.AuthorizeResult none = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).forbid(need));
        assertTrue(none.reasons.contains("forbid: the call carries no certificate (fail closed)"), none.reasons.toString());
        Map<String, Object> ctx = Map.of("action", Map.of("verb", "payments.send", "resource", "payments/acme", "params", Map.of("amount", 50L)));
        Map<String, Object> cert = ForbidWins.certify(clauses("other/*"), ctx, null, null);
        assertTrue(Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).forbid(need).forbidCertificate(cert)).allow);
        Map<String, Object> wrong = ForbidWins.certify(clauses("payments/*"), ctx, null, null);
        Authorize.AuthorizeResult bad = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).forbid(need).forbidCertificate(wrong));
        assertFalse(bad.allow);
        // a throwing clause source refuses
        Authorize.AuthorizeResult thrown = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).forbid(new Authorize.ForbidOptions((op, g) -> { throw new IllegalStateException("x"); })));
        assertTrue(thrown.reasons.contains("forbid: the clause source failed (fail closed)"), thrown.reasons.toString());
    }

    // ---- F3: contracts (peek before the counter, commit after the guard admits)

    static ContractEnforcer enforcer(String forbiddenVerb, MemoryAtomicKv kv) {
        byte[] seed = new byte[32];
        java.util.Arrays.fill(seed, (byte) 7);
        Keys.EdKey principal = Keys.edFromSeed(seed);
        Map<String, Object> c = new java.util.LinkedHashMap<>();
        c.put("version", IntentJs.ofLong(1));
        c.put("principal", principal.id());
        c.put("clauses", new java.util.ArrayList<Object>(java.util.List.of(Map.of("id", "no-send", "kind", "never", "p", Map.of("verb", forbiddenVerb)))));
        return ContractEnforcer.open(kv, Contracts.signContract(c, seed), principal.id(), "k", () -> 1_800_000_000_000.0, true);
    }

    @Test void aContractRefusesAndCommits() {
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        MemoryAtomicKv kv = new MemoryAtomicKv();
        ContractEnforcer ok = enforcer("delete", kv);
        Authorize.AuthorizeResult allowed = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).contracts(ok));
        assertTrue(allowed.allow, allowed.reasons.toString());
        assertEquals("pass", allowed.checks.get("contract"));
        assertEquals(1.0, Prohibitions.dv(ok.state().get("state") instanceof Map ? ((Map<?, ?>) ok.state().get("state")).get("seq") : null), 1e-12); // the action was committed
        // a contract the operation violates refuses BEFORE the counter is spent, and the violation is not latched by the peek
        MemoryStateStore store = new MemoryStateStore();
        ContractEnforcer blocked = enforcer("payments.send", new MemoryAtomicKv());
        Authorize.AuthorizeResult no = Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).stateStore(store).contracts(blocked));
        assertFalse(no.allow);
        assertEquals("fail", no.checks.get("contract"));
        assertTrue(no.reasons.contains("contract: violated (no-send)"), no.reasons.toString());
        assertNull(store.last(Authorize.stateKey((String) AuthorizeK05KillTest.GRANT.get("id"), (String) leafOf(pc))));
        assertNull(blocked.state());
    }
}
