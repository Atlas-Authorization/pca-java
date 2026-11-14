package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Mutation kills for the beacon step, the freshness-anchor gate, the revocation epoch pin, the forbid-wins step and the contract step of authorize. */
class AuthorizeGatesPitKill1Test {
    static final long NOW = AuthorizeK05KillTest.NOW;
    static final String GID = (String) AuthorizeK05KillTest.GRANT.get("id");

    /** A state store that implements no {@link LastStore} (so no pin can be read from it). */
    static final class PlainStore implements StateStore {
        final MemoryStateStore m = new MemoryStateStore();
        @Override public StateStore.ClaimResult claim(String key, long counter) { return m.claim(key, counter); }
        @Override public boolean holdsBudgets() { return true; }
        @Override public Map<String, Object> budget(String key) { return m.budget(key); }
        @Override public StateStore.ClaimResult claim(String key, long counter, Map<String, Object> before, Map<String, Object> after) { return m.claim(key, counter, before, after); }
    }

    // ---- the beacon step

    static final Keys.EdKey ISSUER = BeaconTest.ISSUER;

    static Map<String, Object> bc(Map<String, Object> beacon) {
        Map<String, Object> bc = new LinkedHashMap<>();
        bc.put("beacon", beacon);
        bc.put("issuers", List.of(ISSUER.id()));
        bc.put("instance", "inst");
        return bc;
    }

    static Authorize.AuthorizeResult beacon(StateStore store, Map<String, Object> bcCtx, Object ref) {
        Map<String, Object> fr = new LinkedHashMap<>();
        fr.put("beacon_ref", ref);
        fr.put("epoch", IntentJs.ofLong(1));
        fr.put("accumulator_witness", "");
        Map<String, Object> pc = K05ParityAuditTest.agentSigned("freshness", fr);
        return Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).stateStore(store).context(p -> Map.of("beacon", bcCtx)));
    }

    static void beaconRefused(Authorize.AuthorizeResult r, String why) {
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("fail", r.checks.get("beacon"), r.checks.toString());
        assertTrue(r.reasons.contains("beacon: " + why), r.reasons.toString());
    }

    @Test void theBaselineBeaconPasses() {
        Map<String, Object> b = BeaconTest.good();
        Authorize.AuthorizeResult r = beacon(new MemoryStateStore(), bc(b), Beacons.ref(b));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("pass", r.checks.get("beacon"));
    }

    @Test void onlyPinnedStringIssuersCount() {
        Map<String, Object> b = BeaconTest.good();
        Map<String, Object> none = bc(b);
        none.remove("issuers");
        beaconRefused(beacon(new MemoryStateStore(), none, Beacons.ref(b)), "issuer not pinned");
        Map<String, Object> mixed = bc(b);
        mixed.put("issuers", Arrays.<Object>asList(5L, ISSUER.id(), null));
        Authorize.AuthorizeResult r = beacon(new MemoryStateStore(), mixed, Beacons.ref(b));
        assertTrue(r.allow, r.reasons.toString());
        Map<String, Object> notList = bc(b);
        notList.put("issuers", ISSUER.id());
        beaconRefused(beacon(new MemoryStateStore(), notList, Beacons.ref(b)), "issuer not pinned");
    }

    @Test void theInstanceMustBeAStringThatMatches() {
        Map<String, Object> b = BeaconTest.good();
        Map<String, Object> num = bc(b);
        num.put("instance", 5L);
        beaconRefused(beacon(new MemoryStateStore(), num, Beacons.ref(b)), "wrong instance");
        Map<String, Object> absent = bc(b);
        absent.remove("instance");
        beaconRefused(beacon(new MemoryStateStore(), absent, Beacons.ref(b)), "wrong instance");
        Map<String, Object> other = bc(b);
        other.put("instance", "elsewhere");
        beaconRefused(beacon(new MemoryStateStore(), other, Beacons.ref(b)), "wrong instance");
    }

    @Test void theBeaconIsScopedToTheGrant() {
        Map<String, Object> mine = BeaconTest.beacon("inst", GID, 5, BeaconTest.ISSUED, BeaconTest.ISSUED + 300_000L, ISSUER);
        Authorize.AuthorizeResult ok = beacon(new MemoryStateStore(), bc(mine), Beacons.ref(mine));
        assertTrue(ok.allow, ok.reasons.toString());
        Map<String, Object> other = BeaconTest.beacon("inst", "another-grant", 5, BeaconTest.ISSUED, BeaconTest.ISSUED + 300_000L, ISSUER);
        beaconRefused(beacon(new MemoryStateStore(), bc(other), Beacons.ref(other)), "scope not covered");
    }

    static byte[] fill(int b) {
        byte[] x = new byte[32];
        Arrays.fill(x, (byte) b);
        return x;
    }

    static final Keys.SuiteKey HYBRID = Keys.suite("hybrid-ed25519-ml-dsa-65", Keys.edFromSeed(fill(7)), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(8)));

    static Map<String, Object> hybridBeacon() {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("v", IntentJs.ofLong(2));
        b.put("instance", "inst");
        b.put("scope", "*");
        b.put("epoch", IntentJs.ofLong(Math.floorDiv(BeaconTest.ISSUED, Beacons.EPOCH_MS)));
        b.put("seq", IntentJs.ofLong(5));
        b.put("issued_at", IntentJs.ofLong(BeaconTest.ISSUED));
        b.put("not_after", IntentJs.ofLong(BeaconTest.ISSUED + 300_000L));
        b.put("issuer", HYBRID.id());
        Map<String, Object> bound = IntentJs.bindSuiteFields(b, HYBRID.alg, true, HYBRID.pqPk(), true);
        byte[] msg = Pca.concat(Beacons.LIVENESS_DOMAIN.getBytes(StandardCharsets.UTF_8), IntentJs.canonBytes(bound));
        String[] sig = HYBRID.sign(msg);
        Map<String, Object> out = new LinkedHashMap<>(bound);
        out.put("sig", sig[0]);
        out.put("pq_sig", sig[1]);
        return out;
    }

    @Test void aPostQuantumBeaconNeedsTheServerSidePins() {
        Map<String, Object> b = hybridBeacon();
        Map<String, Object> ctx = bc(b);
        ctx.put("issuers", List.of(HYBRID.id()));
        ctx.put("pq_pins", Keys.pqPin(HYBRID));
        Authorize.AuthorizeResult ok = beacon(new MemoryStateStore(), ctx, Beacons.ref(b));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("beacon"));
        ctx.remove("pq_pins");
        beaconRefused(beacon(new MemoryStateStore(), ctx, Beacons.ref(b)), "bad signature");
        ctx.put("pq_pins", "not a map");
        beaconRefused(beacon(new MemoryStateStore(), ctx, Beacons.ref(b)), "bad signature");
        // a pin for another key does not satisfy it
        ctx.put("pq_pins", Map.of(HYBRID.id(), BeaconTest.good().get("sig")));
        beaconRefused(beacon(new MemoryStateStore(), ctx, Beacons.ref(b)), "bad signature");
    }

    static Authorize.AuthorizeResult pinned(Long pin, Object hostLast) {
        MemoryStateStore store = new MemoryStateStore();
        if (pin != null) store.claim(Authorize.beaconPinKey(GID), pin);
        Map<String, Object> b = BeaconTest.good();
        Map<String, Object> ctx = bc(b);
        if (hostLast != null) ctx.put("last_accepted_seq", hostLast);
        return beacon(store, ctx, Beacons.ref(b));
    }

    static final String OLDER_9 = "beacon seq 5 is older than the last accepted 9 (replay)";

    @Test void theHigherOfTheStoredPinAndTheHostValueIsTheFloor() {
        beaconRefused(pinned(9L, IntentJs.ofLong(3)), OLDER_9);
        beaconRefused(pinned(3L, IntentJs.ofLong(9)), OLDER_9);
        beaconRefused(pinned(null, IntentJs.ofLong(9)), OLDER_9);
        beaconRefused(pinned(9L, null), OLDER_9);
        beaconRefused(pinned(9L, IntentJs.ofLong(9)), OLDER_9);
        assertTrue(pinned(3L, null).allow);
        assertTrue(pinned(null, IntentJs.ofLong(3)).allow);
        assertTrue(pinned(3L, IntentJs.ofLong(3)).allow);
        assertTrue(pinned(5L, IntentJs.ofLong(5)).allow);
        assertTrue(pinned(5L, null).allow);
        assertTrue(pinned(null, null).allow);
        beaconRefused(pinned(6L, null), "beacon seq 5 is older than the last accepted 6 (replay)");
        beaconRefused(pinned(null, IntentJs.ofLong(6)), "beacon seq 5 is older than the last accepted 6 (replay)");
    }

    @Test void anUnreadablePinFailsClosed() {
        Map<String, Object> b = BeaconTest.good();
        Authorize.AuthorizeResult r = beacon(new AuthorizeRunK05bKillTest.LastDown(), bc(b), Beacons.ref(b));
        beaconRefused(r, "the beacon sequence pin could not be read (fail closed)");
    }

    @Test void aStoreWithoutPinsStillAdmitsAFreshBeacon() {
        Map<String, Object> b = BeaconTest.good();
        Authorize.AuthorizeResult r = beacon(new PlainStore(), bc(b), Beacons.ref(b));
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("pass", r.checks.get("beacon"));
    }

    @Test void thePcactnMustCommitTheBeaconReference() {
        Map<String, Object> b = BeaconTest.good();
        beaconRefused(beacon(new MemoryStateStore(), bc(b), "not-the-ref"), "PCActn freshness.beacon_ref does not bind the presented beacon");
        beaconRefused(beacon(new MemoryStateStore(), bc(b), ""), "PCActn freshness.beacon_ref does not bind the presented beacon");
    }

    // ---- the freshness-anchor gate

    static final long E0 = NOW / Beacons.EPOCH_MS; // NOW is a whole epoch

    static Authorize.AuthorizeResult gate(Authorize.FreshnessGate g, Object ref, long epoch) {
        Map<String, Object> fr = new LinkedHashMap<>();
        fr.put("beacon_ref", ref);
        fr.put("epoch", IntentJs.ofLong(epoch));
        fr.put("accumulator_witness", "");
        return Authorize.authorize(K05ParityAuditTest.agentSigned("freshness", fr), AuthorizeK05KillTest.input(Map.of("amount", 50L)).enforceFreshness(g));
    }

    static Authorize.FreshnessGate gate(long maxAge, Long epochMs, Long skew, Long nowMs) {
        Authorize.FreshnessGate g = new Authorize.FreshnessGate(maxAge);
        g.epochMs = epochMs;
        g.clockSkewMs = skew;
        g.nowMs = nowMs;
        return g;
    }

    static void gateFails(Authorize.AuthorizeResult r, String why) {
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("fail", r.checks.get("freshness"), r.checks.toString());
        assertTrue(r.reasons.contains("freshness: " + why), r.reasons.toString());
    }

    static void gatePasses(Authorize.AuthorizeResult r) {
        assertTrue(r.allow, r.reasons.toString());
        assertEquals("pass", r.checks.get("freshness"));
    }

    @Test void anAnchorAtTheDecisionTimePasses() {
        gatePasses(gate(gate(0, null, null, null), "ref", E0));
        gatePasses(gate(gate(60_000, null, null, null), "ref", E0 - 1));
    }

    @Test void theAgeBoundaryIsInclusive() {
        gatePasses(gate(gate(1, null, null, NOW + 1), "ref", E0));
        gateFails(gate(gate(0, null, null, NOW + 1), "ref", E0), "freshness anchor is stale (older than 0 ms)");
        gateFails(gate(gate(59_999, null, null, null), "ref", E0 - 1), "freshness anchor is stale (older than 59999 ms)");
        gatePasses(gate(gate(60_000, null, null, null), "ref", E0 - 1));
        // the gate's own clock replaces the decision time
        gateFails(gate(gate(1000, null, null, NOW + 120_000L), "ref", E0), "freshness anchor is stale (older than 1000 ms)");
        gatePasses(gate(gate(1000, null, null, null), "ref", E0));
    }

    @Test void theSkewBoundaryIsInclusiveAndNegativeSkewCountsAsZero() {
        long future = NOW + 1; // epochMs 1: the anchor is the epoch itself
        gateFails(gate(gate(100, 1L, null, null), "ref", future), "freshness anchor is in the future");
        gateFails(gate(gate(100, 1L, 0L, null), "ref", future), "freshness anchor is in the future");
        gateFails(gate(gate(100, 1L, -5L, null), "ref", future), "freshness anchor is in the future");
        gatePasses(gate(gate(100, 1L, 1L, null), "ref", future));
        gatePasses(gate(gate(100, 1L, 5L, null), "ref", future));
        gateFails(gate(gate(100, 1L, 5L, null), "ref", NOW + 6), "freshness anchor is in the future");
        gatePasses(gate(gate(100, 1L, 5L, null), "ref", NOW + 5));
        // a negative skew must not move the anchor already at the decision time into the future
        gatePasses(gate(gate(100, 1L, -5L, null), "ref", NOW));
    }

    @Test void theEpochLengthIsConfigurable() {
        gatePasses(gate(gate(0, 1000L, null, null), "ref", NOW / 1000));
        gateFails(gate(gate(0, null, null, null), "ref", NOW / 1000), "freshness anchor is in the future");
    }

    @Test void aMisconfiguredGateFailsClosed() {
        String why = "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)";
        gateFails(gate(gate(0, 0L, null, null), "ref", E0), why);
        gateFails(gate(gate(0, -1L, null, null), "ref", E0), why);
        gateFails(gate(gate(-1, null, null, null), "ref", E0), why);
        gateFails(gate(gate(-1, 1L, null, null), "ref", NOW), why);
        gatePasses(gate(gate(0, 1L, null, null), "ref", NOW));
    }

    @Test void anAnchorWithoutAReferenceOrAPositiveEpochIsMissing() {
        String why = "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)";
        gateFails(gate(gate(1000, null, null, null), "", E0), why);
        gateFails(gate(gate(1000, null, null, null), "ref", 0), why);
        gateFails(gate(gate(1000, null, null, null), "ref", -1), why);
        // epoch 1 is positive: it is an anchor, a very old one
        gateFails(gate(gate(1000, null, null, null), "ref", 1), "freshness anchor is stale (older than 1000 ms)");
    }

    @Test void aFailedRevocationFreshnessIsNotOverwrittenByAPassingGate() {
        Map<String, Object> fr = new LinkedHashMap<>();
        fr.put("beacon_ref", "ref");
        fr.put("epoch", IntentJs.ofLong(E0));
        fr.put("accumulator_witness", "");
        Authorize.AuthorizeResult r = Authorize.authorize(K05ParityAuditTest.agentSigned("freshness", fr),
            AuthorizeRunK05bKillTest.input().stateStore(new PlainStore()).revocationStaleness(AuthorizeRunK05bKillTest.policy())
                .context(p -> AuthorizeRunK05bKillTest.ctx("revocation_state", AuthorizeRunK05bKillTest.freshRoot())).enforceFreshness(gate(0, null, null, null)));
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("fail", r.checks.get("freshness"));
        assertTrue(r.reasons.contains("freshness: " + Authorize.PIN_STORE_REQUIRED), r.reasons.toString());
    }

    // ---- the revocation epoch pin

    @Test void withoutRevocationStateAStoreWithoutPinsIsNotAnError() {
        Authorize.AuthorizeResult r = AuthorizeRunK05bKillTest.run(AuthorizeRunK05bKillTest.pcactn(),
            AuthorizeRunK05bKillTest.input().stateStore(new PlainStore()).revocationStaleness(AuthorizeRunK05bKillTest.policy()).context(p -> AuthorizeRunK05bKillTest.ctx()));
        AuthorizeRunK05bKillTest.allowed(r);
        assertEquals("not-enforced", r.checks.get("freshness"));
    }

    @Test void withoutRevocationStateAStoredPinIsNotConsulted() {
        MemoryStateStore store = new MemoryStateStore();
        assertTrue(store.claim(Authorize.epochPinKey(GID), 5L).ok);
        Authorize.AuthorizeResult r = AuthorizeRunK05bKillTest.run(AuthorizeRunK05bKillTest.pcactn(),
            AuthorizeRunK05bKillTest.input().stateStore(store).revocationStaleness(AuthorizeRunK05bKillTest.policy()).context(p -> AuthorizeRunK05bKillTest.ctx()));
        AuthorizeRunK05bKillTest.allowed(r);
        assertEquals("not-enforced", r.checks.get("freshness"));
    }

    @Test void anUnreadableEpochPinFailsClosedAndStaysFailed() {
        Authorize.AuthorizeResult r = AuthorizeRunK05bKillTest.run(AuthorizeRunK05bKillTest.pcactn(),
            AuthorizeRunK05bKillTest.input().stateStore(new AuthorizeRunK05bKillTest.LastDown()).revocationStaleness(AuthorizeRunK05bKillTest.policy())
                .context(p -> AuthorizeRunK05bKillTest.ctx("revocation_state", AuthorizeRunK05bKillTest.freshRoot())));
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("fail", r.checks.get("freshness"));
        assertTrue(r.reasons.contains("freshness: the revocation epoch pin could not be read (fail closed)"), r.reasons.toString());
        assertEquals(1, r.reasons.stream().filter(x -> x.startsWith("freshness: ")).count(), r.reasons.toString());
        Authorize.AuthorizeResult store = AuthorizeRunK05bKillTest.run(AuthorizeRunK05bKillTest.pcactn(),
            AuthorizeRunK05bKillTest.input().stateStore(new PlainStore()).revocationStaleness(AuthorizeRunK05bKillTest.policy())
                .context(p -> AuthorizeRunK05bKillTest.ctx("revocation_state", AuthorizeRunK05bKillTest.freshRoot(), "reversibility_class", "irreversible")));
        assertFalse(store.allow);
        assertEquals("fail", store.checks.get("freshness"));
        assertEquals(List.of("freshness: " + Authorize.PIN_STORE_REQUIRED), store.reasons.stream().filter(x -> x.startsWith("freshness: ")).toList());
    }

    // ---- the forbid-wins step

    static Map<String, Object> clause(String id, String kind, Map<String, Object> when) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("id", id);
        c.put("kind", kind);
        c.put("when", when);
        return c;
    }

    static Map<String, Object> verbWhen() {
        Map<String, Object> w = new LinkedHashMap<>();
        w.put("verb", "payments.send");
        return w;
    }

    static Authorize.AuthorizeResult forbid(Authorize.ForbidOptions fo) {
        return Authorize.authorize(AuthorizeK05KillTest.pcactn(), AuthorizeK05KillTest.input(Map.of("amount", 50L)).forbid(fo));
    }

    @Test void theForbidDecisionIsNamedInTheReason() {
        Authorize.AuthorizeResult none = forbid(new Authorize.ForbidOptions((op, g) -> new ArrayList<>(List.<Object>of(clause("p", "permit", new LinkedHashMap<>(Map.of("verb", "other")))))));
        assertFalse(none.allow);
        assertTrue(none.reasons.contains("forbid: deny by none"), none.reasons.toString());
        Authorize.AuthorizeResult esc = forbid(new Authorize.ForbidOptions((op, g) -> new ArrayList<>(List.<Object>of(clause("p", "permit", verbWhen()), clause("e1", "escalate", verbWhen())))));
        assertFalse(esc.allow);
        assertTrue(esc.reasons.contains("forbid: escalate by escalate e1"), esc.reasons.toString());
        Authorize.AuthorizeResult veto = forbid(new Authorize.ForbidOptions((op, g) -> new ArrayList<>(List.<Object>of(clause("p", "permit", verbWhen()), clause("f1", "forbid", verbWhen())))));
        assertTrue(veto.reasons.contains("forbid: deny by forbid f1"), veto.reasons.toString());
        Authorize.AuthorizeResult ok = forbid(new Authorize.ForbidOptions((op, g) -> new ArrayList<>(List.<Object>of(clause("p", "permit", verbWhen())))));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("forbid"));
    }

    @Test void theClauseContextIsMergedIntoTheAction() {
        // the veto only fires unless the context proves the tier: an undecidable where keeps the veto
        Map<String, Object> vetoWhen = verbWhen();
        vetoWhen.put("where", new ArrayList<>(List.<Object>of(new LinkedHashMap<>(Map.of("field", "env.tier", "op", "ne", "value", "gold")))));
        Authorize.ForbidOptions fo = new Authorize.ForbidOptions((op, g) -> new ArrayList<>(List.<Object>of(clause("p", "permit", verbWhen()), clause("f1", "forbid", vetoWhen))));
        Authorize.AuthorizeResult bare = forbid(fo);
        assertFalse(bare.allow);
        assertTrue(bare.reasons.contains("forbid: deny by forbid f1"), bare.reasons.toString());
        fo.context = op -> Map.of("env", Map.of("tier", "gold"));
        Authorize.AuthorizeResult merged = forbid(fo);
        assertTrue(merged.allow, merged.reasons.toString());
        assertEquals("pass", merged.checks.get("forbid"));
        // a context that returns nothing changes nothing
        fo.context = op -> null;
        assertFalse(forbid(fo).allow);
    }

    // ---- the contract step

    static ContractEnforcer enforcer(List<Object> clauses, AtomicKv kv) {
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 7);
        Keys.EdKey principal = Keys.edFromSeed(seed);
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("version", IntentJs.ofLong(1));
        c.put("principal", principal.id());
        c.put("clauses", clauses);
        return ContractEnforcer.open(kv, Contracts.signContract(c, seed), principal.id(), "k", () -> 1_800_000_000_000.0, true);
    }

    static Map<String, Object> never(String id, Map<String, Object> p) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("id", id);
        c.put("kind", "never");
        c.put("p", p);
        return c;
    }

    static Authorize.AuthorizeResult contract(ContractEnforcer en, long amount) {
        return Authorize.authorize(AuthorizeK05KillTest.pcactn(), AuthorizeK05KillTest.input(Map.of("amount", 50L)).operation(Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", amount))).contracts(en));
    }

    @Test void everyViolatedClauseIsNamed() {
        ContractEnforcer en = enforcer(new ArrayList<>(List.<Object>of(never("a", new LinkedHashMap<>(Map.of("verb", "payments.send"))), never("b", new LinkedHashMap<>(Map.of("verb", "payments.send"))))), new MemoryAtomicKv());
        Authorize.AuthorizeResult r = contract(en, 50);
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("contract"));
        assertTrue(r.reasons.contains("contract: violated (a,b)"), r.reasons.toString());
        ContractEnforcer one = enforcer(new ArrayList<>(List.<Object>of(never("a", new LinkedHashMap<>(Map.of("verb", "payments.send"))))), new MemoryAtomicKv());
        assertTrue(contract(one, 50).reasons.contains("contract: violated (a)"));
    }

    @Test void aReasonWithoutViolatedClausesHasNoList() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        kv.set("k", "not a state document");
        ContractEnforcer en = enforcer(new ArrayList<>(List.<Object>of(never("a", new LinkedHashMap<>(Map.of("verb", "other"))))), kv);
        Authorize.AuthorizeResult r = contract(en, 50);
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("contract"));
        assertTrue(r.reasons.contains("contract: state-error"), r.reasons.toString());
    }

    @Test void theContractSeesTheOperationParams() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("verb", "payments.send");
        p.put("where", new ArrayList<>(List.<Object>of(new LinkedHashMap<>(Map.of("field", "action.params.amount", "op", "gt", "value", 100L)))));
        ContractEnforcer small = enforcer(new ArrayList<>(List.<Object>of(never("big", p))), new MemoryAtomicKv());
        Authorize.AuthorizeResult ok = contract(small, 50);
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("contract"));
        ContractEnforcer large = enforcer(new ArrayList<>(List.<Object>of(never("big", p))), new MemoryAtomicKv());
        Authorize.AuthorizeResult no = contract(large, 500);
        assertFalse(no.allow);
        assertTrue(no.reasons.contains("contract: violated (big)"), no.reasons.toString());
        assertNull(large.state());
    }
}
