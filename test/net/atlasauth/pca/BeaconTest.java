package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Liveness beacons v2 and the authorize beacon check (the beacon must verify, not be replayed, and be the one the PCActn commits). */
class BeaconTest {
    static final Keys.EdKey ISSUER = Keys.edGenerate();
    static final long ISSUED = 1_800_000_000_000L - 120_000L; // two minutes before the fixture clock
    static final long NOW = AuthorizeK05KillTest.NOW;

    static Map<String, Object> beacon(String instance, String scope, long seq, long issuedAt, long notAfter, Keys.EdKey key) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("v", IntentJs.ofLong(2));
        b.put("instance", instance);
        b.put("scope", scope);
        b.put("epoch", IntentJs.ofLong(Math.floorDiv(issuedAt, Beacons.EPOCH_MS)));
        b.put("seq", IntentJs.ofLong(seq));
        b.put("issued_at", IntentJs.ofLong(issuedAt));
        b.put("not_after", IntentJs.ofLong(notAfter));
        b.put("issuer", key.id());
        byte[] msg = Pca.concat(Beacons.LIVENESS_DOMAIN.getBytes(java.nio.charset.StandardCharsets.UTF_8), IntentJs.canonBytes(b));
        Map<String, Object> out = new LinkedHashMap<>(b);
        out.put("sig", Pca.b64(key.sign(msg)));
        return out;
    }

    static Map<String, Object> good() { return beacon("inst", "*", 5, ISSUED, ISSUED + 300_000L, ISSUER); }

    static String verify(Object b, long now, String scope) { return Beacons.verify(b, List.of(ISSUER.id()), now, "inst", scope, null); }

    @Test void aBeaconVerifiesOnlyWhereItIsBoundAndFresh() {
        assertNull(verify(good(), NOW, "g1"));
        assertEquals("malformed beacon", verify(null, NOW, null));
        assertEquals("malformed beacon", verify("x", NOW, null));
        Map<String, Object> v3 = good();
        v3.put("v", IntentJs.ofLong(3));
        assertEquals("malformed beacon", verify(v3, NOW, null));
        Map<String, Object> badAlg = good();
        badAlg.put("alg", "nope");
        assertEquals("malformed beacon", verify(badAlg, NOW, null));
        assertEquals("wrong instance", Beacons.verify(good(), List.of(ISSUER.id()), NOW, "other", null, null));
        assertEquals("issuer not pinned", Beacons.verify(good(), List.of("someone-else"), NOW, "inst", null, null));
        Map<String, Object> forged = good();
        forged.put("seq", IntentJs.ofLong(6));
        assertEquals("bad signature", verify(forged, NOW, null));
        // the window: valid from issued - 30 s, until not_after inclusive
        Map<String, Object> g = good();
        assertNull(verify(g, ISSUED - Beacons.CLOCK_SKEW_MS, null));
        assertEquals("not yet valid", verify(g, ISSUED - Beacons.CLOCK_SKEW_MS - 1, null));
        assertNull(verify(g, ISSUED + 300_000L, null));
        assertEquals("expired", verify(g, ISSUED + 300_001L, null));
        // the hard maximum validity: one hour exactly passes, one millisecond more is refused (signed bodies)
        assertNull(verify(beacon("inst", "*", 5, ISSUED, ISSUED + Beacons.MAX_VALIDITY_MS, ISSUER), ISSUED, null));
        assertEquals("validity exceeds the hard maximum", verify(beacon("inst", "*", 5, ISSUED, ISSUED + Beacons.MAX_VALIDITY_MS + 1, ISSUER), ISSUED, null));
        assertEquals("validity exceeds the hard maximum", verify(beacon("inst", "*", 5, ISSUED, ISSUED, ISSUER), ISSUED, null));
        // the epoch must be floor(issued_at / 60000)
        Map<String, Object> wrongEpoch = new LinkedHashMap<>(good());
        wrongEpoch.remove("sig");
        wrongEpoch.put("epoch", IntentJs.ofLong(Math.floorDiv(ISSUED, Beacons.EPOCH_MS) + 1));
        byte[] msg = Pca.concat(Beacons.LIVENESS_DOMAIN.getBytes(java.nio.charset.StandardCharsets.UTF_8), IntentJs.canonBytes(wrongEpoch));
        wrongEpoch.put("sig", Pca.b64(ISSUER.sign(msg)));
        assertEquals("epoch does not match issued_at", verify(wrongEpoch, NOW, null));
        // a negative seq is a malformed window
        assertEquals("malformed window", verify(beacon("inst", "*", -1, ISSUED, ISSUED + 1000, ISSUER), NOW, null));
        // scope: the global scope or the grant's own
        assertNull(verify(beacon("inst", "g1", 5, ISSUED, ISSUED + 300_000L, ISSUER), NOW, "g1"));
        assertEquals("scope not covered", verify(beacon("inst", "g1", 5, ISSUED, ISSUED + 300_000L, ISSUER), NOW, "g2"));
        assertNull(verify(beacon("inst", "g1", 5, ISSUED, ISSUED + 300_000L, ISSUER), NOW, null)); // no scope given: not checked
        // the reference is a function of the whole beacon
        assertEquals(Beacons.ref(good()), Beacons.ref(good()));
        assertNotEquals(Beacons.ref(good()), Beacons.ref(forged));
        assertEquals(43, Beacons.ref(good()).length());
    }

    static Authorize.AuthorizeResult run(MemoryStateStore store, Map<String, Object> beacon, Object last, Object ref) {
        Map<String, Object> fr = new LinkedHashMap<>();
        fr.put("beacon_ref", ref == null ? Beacons.ref(beacon) : ref);
        fr.put("epoch", IntentJs.ofLong(1));
        fr.put("accumulator_witness", "");
        Map<String, Object> pc = K05ParityAuditTest.agentSigned("freshness", fr);
        Map<String, Object> bc = new LinkedHashMap<>();
        bc.put("beacon", beacon);
        bc.put("issuers", List.of(ISSUER.id()));
        bc.put("instance", "inst");
        if (last != null) bc.put("last_accepted_seq", last);
        return Authorize.authorize(pc, AuthorizeK05KillTest.input(Map.of("amount", 50L)).stateStore(store).context(p -> Map.of("beacon", bc)));
    }

    @Test void authorizeChecksTheBeaconAndKeepsItsSequencePin() {
        MemoryStateStore store = new MemoryStateStore();
        String pin = Authorize.beaconPinKey((String) AuthorizeK05KillTest.GRANT.get("id"));
        Authorize.AuthorizeResult ok = run(store, good(), null, null);
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("beacon"));
        assertEquals(Long.valueOf(5), store.last(pin)); // an allow raises the pin
        // a replayed older beacon: below the stored pin, with no host value at all
        MemoryStateStore seeded = new MemoryStateStore();
        seeded.claim(pin, 9);
        Authorize.AuthorizeResult old = run(seeded, good(), null, null);
        assertFalse(old.allow);
        assertTrue(old.reasons.contains("beacon: beacon seq 5 is older than the last accepted 9 (replay)"), old.reasons.toString());
        assertEquals(Long.valueOf(9), seeded.last(pin));
        // the host's value counts too (the higher of the two); an equal seq is not a replay
        assertFalse(run(new MemoryStateStore(), good(), IntentJs.ofLong(6), null).allow);
        assertTrue(run(new MemoryStateStore(), good(), IntentJs.ofLong(5), null).allow);
        // a PCActn that commits another beacon
        Authorize.AuthorizeResult unbound = run(new MemoryStateStore(), good(), null, "not-the-ref");
        assertFalse(unbound.allow);
        assertTrue(unbound.reasons.contains("beacon: PCActn freshness.beacon_ref does not bind the presented beacon"), unbound.reasons.toString());
        // a beacon that does not verify
        Map<String, Object> expired = beacon("inst", "*", 5, ISSUED - 3_000_000L, ISSUED - 3_000_000L + 60_000L, ISSUER);
        Authorize.AuthorizeResult exp = run(new MemoryStateStore(), expired, null, null);
        assertFalse(exp.allow);
        assertTrue(exp.reasons.contains("beacon: expired"), exp.reasons.toString());
        // none supplied: not enforced
        assertEquals("not-enforced", Authorize.authorize(K05ParityAuditTest.agentSigned(), AuthorizeK05KillTest.input(Map.of("amount", 50L))).checks.get("beacon"));
    }
}
