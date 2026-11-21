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
import org.junit.jupiter.api.Test;

/** Mutation kills for the end of authorize: the replay claim, the contract commit, the raised pins, the passport assurance and the PQ pin check. */
class AuthorizeCommitPitKill1Test {
    static final long NOW = AuthorizeK05KillTest.NOW;
    static final String GID = (String) AuthorizeK05KillTest.GRANT.get("id");

    static Authorize.Input input() { return AuthorizeK05KillTest.input(Map.of("amount", 50L)); }

    // ---- the replay claim

    /** A store that answers every claim with a fixed result (null is a store that failed to answer). */
    static final class FixedStore implements StateStore {
        final StateStore.ClaimResult answer;
        FixedStore(StateStore.ClaimResult answer) { this.answer = answer; }
        @Override public StateStore.ClaimResult claim(String key, long counter) { return answer; }
        @Override public boolean holdsBudgets() { return true; }
    }

    static Authorize.AuthorizeResult claimed(StateStore.ClaimResult answer) {
        return Authorize.authorize(AuthorizeK05KillTest.pcactn(), input().stateStore(new FixedStore(answer)));
    }

    static long counter() { return Json.asLong(AuthorizeK05KillTest.pcactn().get("counter")); }

    static void replayRefused(Authorize.AuthorizeResult r, String why) {
        assertNotNull(r);
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("deny", r.decision);
        assertEquals("fail", r.checks.get("replay"), r.checks.toString());
        assertTrue(r.reasons.contains("replay: " + why), r.reasons.toString());
    }

    @Test void aBudgetConflictIsNamedAndRefused() {
        replayRefused(claimed(StateStore.ClaimResult.conflict()), "the trust budget changed under this decision (concurrent update): retry");
    }

    @Test void aRefusedClaimNamesTheLastSeenCounterWhenTheStoreKnowsIt() {
        long c = counter();
        replayRefused(claimed(new StateStore.ClaimResult(false, 7L)), c + " is not greater than last seen 7 (replay)");
        replayRefused(claimed(new StateStore.ClaimResult(false, null)), c + " was already claimed (replay)");
        replayRefused(claimed(null), "the replay store failed (fail closed)");
        StateStore throwing = new StateStore() {
            @Override public ClaimResult claim(String key, long counter) { throw new IllegalStateException("down"); }
        };
        replayRefused(Authorize.authorize(AuthorizeK05KillTest.pcactn(), input().stateStore(throwing)), "the replay store failed (fail closed)");
    }

    // ---- the contract is committed after the counter is spent

    /** A key-value store whose atomic update is down while reads work. */
    static final class ReadOnlyKv implements AtomicKv {
        final MemoryAtomicKv inner = new MemoryAtomicKv();
        @Override public Object get(String key) { return inner.get(key); }
        @Override public void set(String key, Object value) { inner.set(key, value); }
        @Override public Object update(String key, java.util.function.UnaryOperator<Object> fn) { throw new IllegalStateException("update down"); }
    }

    @Test void aContractThatCannotBeCommittedRefusesAfterTheCounterIsSpent() {
        List<Object> clauses = new ArrayList<>(List.<Object>of(AuthorizeGatesPitKill1Test.never("a", new LinkedHashMap<>(Map.of("verb", "other")))));
        assertTrue(Authorize.authorize(AuthorizeK05KillTest.pcactn(), input().contracts(AuthorizeGatesPitKill1Test.enforcer(clauses, new MemoryAtomicKv()))).allow,
            "control: a contract that can commit admits");
        MemoryStateStore store = new MemoryStateStore();
        Authorize.AuthorizeResult r = Authorize.authorize(AuthorizeK05KillTest.pcactn(), input().stateStore(store).contracts(AuthorizeGatesPitKill1Test.enforcer(clauses, new ReadOnlyKv())));
        assertNotNull(r);
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("deny", r.decision);
        assertEquals("fail", r.checks.get("contract"));
        assertTrue(r.reasons.contains("contract: store-error"), r.reasons.toString());
    }

    // ---- the pins raised by an allow

    /** A store that cannot record a pin whose key ends with a given suffix. */
    static final class PinThrowStore implements StateStore, LastStore {
        final MemoryStateStore m = new MemoryStateStore();
        final String suffix;
        PinThrowStore(String suffix) { this.suffix = suffix; }
        @Override public StateStore.ClaimResult claim(String key, long counter) {
            if (key.endsWith(suffix)) throw new IllegalStateException("pin store down");
            return m.claim(key, counter);
        }
        @Override public boolean holdsBudgets() { return true; }
        @Override public Map<String, Object> budget(String key) { return m.budget(key); }
        @Override public StateStore.ClaimResult claim(String key, long counter, Map<String, Object> before, Map<String, Object> after) { return m.claim(key, counter, before, after); }
        @Override public Long last(String key) { return m.last(key); }
    }

    static Authorize.AuthorizeResult epoch(StateStore store, long revocationEpoch) {
        Map<String, Object> fr = new LinkedHashMap<>();
        fr.put("beacon_ref", "");
        fr.put("epoch", IntentJs.ofLong(5));
        fr.put("accumulator_witness", "");
        Map<String, Object> pc = K05ParityAuditTest.agentSigned("freshness", fr);
        RevocationStaleness pol = new RevocationStaleness().guardianPublic(StalenessVectorsTest.pub()).ids(p -> List.of());
        RevocationStaleness.State state = RevocationStaleness.State.epoch(AuthorizeRunK05bKillTest.signedEpoch(GID, revocationEpoch), null, null);
        return Authorize.authorize(pc, input().stateStore(store).revocationStaleness(pol).context(p -> AuthorizeRunK05bKillTest.ctx("revocation_state", state)));
    }

    @Test void anAcceptedRevocationEpochRaisesTheRollbackPin() {
        MemoryStateStore store = new MemoryStateStore();
        Authorize.AuthorizeResult r = epoch(store, 3);
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("pass", r.checks.get("freshness"));
        assertEquals(Long.valueOf(3), store.last(Authorize.epochPinKey(GID)));
    }

    @Test void aPinThatCannotBeRecordedRefusesTheDecision() {
        Authorize.AuthorizeResult r = epoch(new PinThrowStore(":epoch"), 3);
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("deny", r.decision);
        assertEquals("fail", r.checks.get("freshness"));
        assertTrue(r.reasons.contains("freshness: the revocation epoch pin could not be recorded (fail closed)"), r.reasons.toString());
    }

    @Test void anAdmittedBeaconRaisesItsSequencePinAndAFailingPinStoreRefuses() {
        Map<String, Object> b = BeaconTest.good();
        MemoryStateStore store = new MemoryStateStore();
        Authorize.AuthorizeResult ok = AuthorizeGatesPitKill1Test.beacon(store, AuthorizeGatesPitKill1Test.bc(b), Beacons.ref(b));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals(Long.valueOf(5), store.last(Authorize.beaconPinKey(GID)));
        Authorize.AuthorizeResult down = AuthorizeGatesPitKill1Test.beacon(new PinThrowStore(":beacon"), AuthorizeGatesPitKill1Test.bc(b), Beacons.ref(b));
        assertFalse(down.allow, down.reasons.toString());
        assertEquals("deny", down.decision);
        assertEquals("fail", down.checks.get("beacon"));
        assertTrue(down.reasons.contains("beacon: the beacon sequence pin could not be recorded (fail closed)"), down.reasons.toString());
        // without a beacon in the context no pin is written
        MemoryStateStore bare = new MemoryStateStore();
        assertTrue(Authorize.authorize(AuthorizeK05KillTest.pcactn(), input().stateStore(bare)).allow);
        assertNull(bare.last(Authorize.beaconPinKey(GID)));
    }

    // ---- the passport assurance carried by an allow

    static Authorize.AuthorizeResult hardwareAllowed(Passport.Attest att) {
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        Passport.Options o = PassportKillTest.opts();
        o.attest = att;
        Map<String, Object> ev = PassportKillTest.evidence(NOW, "n1");
        Map<String, Object> hw = K05HardeningPipelineTest.passportFor(K05HardeningPipelineTest.leafOf(pc), PassportKillTest.identity(true), ev);
        return Authorize.authorize(pc, input().stateStore(new MemoryStateStore()).requirePassport(o, true).passport(hw));
    }

    static Passport.Attest labelled(Assurance.Label label) {
        Passport.Attest att = new Passport.Attest() {
            public Passport.Attestation verify(Map<String, Object> d, Passport.Binding b) { return new Passport.Attestation(true, true, PassportKillTest.identity(true)); }
        };
        return label == null ? att : Assurance.setLabel(att, label);
    }

    @Test void theHardwareLevelAndVendorComeFromTheVerifiersLabel() {
        Authorize.AuthorizeResult vendor = hardwareAllowed(labelled(Assurance.Label.of("hardware").vendor("acme")));
        assertTrue(vendor.allow, vendor.reasons.toString());
        assertEquals(Map.of("outcome", "pass", "level", "hardware", "vendor", "acme"), vendor.assurance().get("passport"));
        Authorize.AuthorizeResult noVendor = hardwareAllowed(labelled(Assurance.Label.of("hardware")));
        assertEquals(Map.of("outcome", "pass", "level", "hardware"), noVendor.assurance().get("passport"));
        Authorize.AuthorizeResult emptyVendor = hardwareAllowed(labelled(Assurance.Label.of("hardware").vendor("")));
        assertEquals(Map.of("outcome", "pass", "level", "hardware"), emptyVendor.assurance().get("passport"));
        Authorize.AuthorizeResult unlabelled = hardwareAllowed(labelled(null));
        assertEquals(Map.of("outcome", "pass", "level", "unknown"), unlabelled.assurance().get("passport"));
    }

    // ---- the server-side PQ pin for a post-quantum grant

    static byte[] fill(int b) {
        byte[] x = new byte[32];
        Arrays.fill(x, (byte) b);
        return x;
    }

    static final Keys.SuiteKey HP = Keys.suite("hybrid-ed25519-ml-dsa-65", Keys.edFromSeed(fill(41)), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(42)));

    static Authorize.AuthorizeResult pinned(Map<String, Object> pins) {
        List<Object> cavs = new ArrayList<>();
        cavs.add(AuthorizeRiskPitKill1Test.envelope(Issue.defaultRiskPolicy(), AuthorizeRiskPitKill1Test.star()));
        Map<String, Object> g = Issue.mintRoot(HP, AuthorizeK05KillTest.AGENT.id(), null, cavs);
        Map<String, Object> pc = AuthorizeRunK05bKillTest.act(g);
        return Authorize.authorize(pc, AuthorizeRunK05bKillTest.in(g).pqPins(pins));
    }

    @Test void aPostQuantumGrantNeedsItsIssuersPinnedKey() {
        Authorize.AuthorizeResult ok = pinned(Keys.pqPin(HP));
        assertEquals("pass", ok.checks.get("pq_pin"), ok.reasons.toString());
        Authorize.AuthorizeResult other = pinned(Map.of(HP.id(), "another-key"));
        assertEquals("fail", other.checks.get("pq_pin"));
        assertTrue(other.reasons.contains("pq_pin: the grant pq_pk does not match the server-side pin"), other.reasons.toString());
        Map<String, Object> odd = new LinkedHashMap<>();
        odd.put(HP.id(), new LinkedHashMap<String, Object>());
        Authorize.AuthorizeResult notText = pinned(odd);
        assertEquals("fail", notText.checks.get("pq_pin"));
        assertTrue(notText.reasons.contains("pq_pin: the grant pq_pk does not match the server-side pin"), notText.reasons.toString());
        Authorize.AuthorizeResult missing = pinned(Map.of("someone-else", "k"));
        assertEquals("fail", missing.checks.get("pq_pin"));
        assertTrue(missing.reasons.contains("pq_pin: no server-side PQ pin for the grant issuer (suite hybrid-ed25519-ml-dsa-65)"), missing.reasons.toString());
    }

    // ---- the PQ pins of the passport verifier

    @Test void thePassportVerifierGetsTheConfiguredPqPins() {
        Map<String, Object> pc = AuthorizeK05KillTest.pcactn();
        Map<String, Object> body = PassportKillTest.body(PassportKillTest.identity(false), null);
        body.put("iss", HP.id());
        body.put("sub", K05HardeningPipelineTest.leafOf(pc));
        body.put("iat", NOW - 1000L); body.put("nbf", NOW - 1000L); body.put("exp", NOW + 1_000_000L);
        body.put("alg", HP.alg);
        body.put("pq_pk", HP.pqPk());
        byte[] msg = Pca.concat(Passport.SIG_DOMAIN, Json.canonicalizeStrict(body).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String[] sig = HP.sign(msg);
        Map<String, Object> signed = new LinkedHashMap<>(body);
        signed.put("sig", sig[0]);
        signed.put("pq_sig", sig[1]);
        Passport.Options pinned = PassportKillTest.opts();
        pinned.trustedIssuers = List.of(HP.id());
        pinned.pqPins = Keys.pqPin(HP);
        Authorize.AuthorizeResult ok = Authorize.authorize(pc, input().stateStore(new MemoryStateStore()).requirePassport(pinned, false).passport(signed));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("passport"));
        Passport.Options unpinned = PassportKillTest.opts();
        unpinned.trustedIssuers = List.of(HP.id());
        Authorize.AuthorizeResult no = Authorize.authorize(AuthorizeK05KillTest.pcactn(), input().stateStore(new MemoryStateStore()).requirePassport(unpinned, false).passport(signed));
        assertFalse(no.allow);
        assertTrue(no.reasons.contains("passport: bad_signature"), no.reasons.toString());
    }
}
