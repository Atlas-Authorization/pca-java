package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

/**
 * Revocation staleness (T9): the shared staleness vectors (max_age, effective_reversibility, age, epoch, gate, membership, gate_ids) and the
 * {@code Authorize} wiring. A missing vector file or a table of the wrong size FAILS.
 */
public class StalenessVectorsTest {
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> table(Map<String, Object> doc, String name, int size) {
        Object t = doc.get(name);
        assertTrue(t instanceof List, name + ": missing table");
        assertEquals(size, ((List<?>) t).size(), name + ": vector count");
        return (List<Map<String, Object>>) (List<?>) t;
    }

    private static Object nan(Object v) { return "NaN".equals(v) ? (Object) Double.NaN : v; }

    private static double dbl(Object v) {
        Object x = nan(v);
        Double d = x instanceof Double ? (Double) x : IntentJs.num(x);
        assertNotNull(d, "number expected: " + v);
        return d;
    }

    @SuppressWarnings("unchecked")
    private static void assertResult(Map<String, Object> want, RevocationStaleness.Check got, boolean okOnly, String name) {
        assertEquals(Boolean.TRUE.equals(want.get("ok")), got.ok, name + ": " + got);
        if (!okOnly && !got.ok) assertEquals(want.get("reason"), got.reason, name);
        if (!okOnly && got.ok) assertFalse(want.containsKey("reason"), name);
    }

    @Test void constants() {
        Map<String, Object> doc = Track3Vectors.load("staleness-vectors.json");
        Map<String, Object> c = IntentJs.obj(doc.get("constants"));
        assertEquals(RevocationStaleness.REVOCATION_EPOCH_REFRESH_MS, Json.asLong(c.get("refresh_ms")));
        assertEquals(RevocationStaleness.REVOCATION_EPOCH_VALIDITY_MS, Json.asLong(c.get("validity_ms")));
        assertEquals(RevocationStaleness.REVOCATION_IRREVERSIBLE_MAX_AGE_MS, Json.asLong(c.get("irreversible_max_age_ms")));
        assertEquals(RevocationStaleness.SKEW_MS, Json.asLong(c.get("skew_ms")));
    }

    @Test void maxAge() {
        Map<String, Object> doc = Track3Vectors.load("staleness-vectors.json");
        for (Map<String, Object> v : table(doc, "max_age", 15)) {
            RevocationStaleness p = RevocationStaleness.fromJson(v.get("policy"));
            assertEquals(dbl(v.get("max_age_ms")), p.revocationMaxAgeMs((String) v.get("class")), v.toString());
        }
    }

    @Test void effectiveReversibility() {
        Map<String, Object> doc = Track3Vectors.load("staleness-vectors.json");
        for (Map<String, Object> v : table(doc, "effective_reversibility", 14))
            assertEquals(v.get("effective"), RevocationStaleness.effectiveReversibility(v.get("server_class"), v.get("signed_class")), v.toString());
    }

    @Test void age() {
        Map<String, Object> doc = Track3Vectors.load("staleness-vectors.json");
        int n = 0;
        for (Map<String, Object> v : table(doc, "age", 13)) {
            String what = v.get("what") instanceof String ? (String) v.get("what") : "revocation state";
            RevocationStaleness.Check got = RevocationStaleness.checkRevocationAge(nan(v.get("issued_at")), dbl(v.get("now")), dbl(v.get("max_age_ms")), what);
            assertResult(IntentJs.obj(v.get("result")), got, Boolean.TRUE.equals(v.get("ok_only")), "age#" + n++);
        }
    }

    @Test void epoch() {
        Map<String, Object> doc = Track3Vectors.load("staleness-vectors.json");
        for (Map<String, Object> v : table(doc, "epoch", 25)) {
            RevocationStaleness.EpochOptions o = new RevocationStaleness.EpochOptions((String) v.get("guardian_public"), dbl(v.get("now")));
            if (v.get("grant_ref") instanceof String) o.grantRef = (String) v.get("grant_ref");
            if (v.containsKey("last_accepted_epoch")) o.lastAcceptedEpoch = dbl(v.get("last_accepted_epoch"));
            if (v.containsKey("pcactn_epoch")) o.pcactnEpoch = dbl(v.get("pcactn_epoch"));
            if (v.containsKey("max_age_ms")) o.maxAgeMs = dbl(v.get("max_age_ms"));
            assertResult(IntentJs.obj(v.get("result")), RevocationStaleness.checkRevocationEpoch(v.get("epoch"), o), Boolean.TRUE.equals(v.get("ok_only")), (String) v.get("name"));
        }
    }

    @Test void gate() {
        Map<String, Object> doc = Track3Vectors.load("staleness-vectors.json");
        String guardian = (String) doc.get("guardian_public");
        String setRoot = (String) doc.get("revocation_root");
        for (Map<String, Object> v : table(doc, "gate", 28)) {
            RevocationStaleness policy = v.get("policy") == null ? null : RevocationStaleness.fromJson(v.get("policy"));
            if (Boolean.TRUE.equals(v.get("allow_unsigned_root_for_irreversible"))) policy = policy.allowUnsignedRootForIrreversible(true);
            String mode = (String) v.get("mode");
            RevocationStaleness.State state = null;
            if ("epoch".equals(mode)) state = RevocationStaleness.State.epoch(IntentJs.obj(v.get("epoch")), (String) v.get("bare_root"), null);
            else if ("root".equals(mode)) {
                Object at = v.get("root_issued_at");
                state = RevocationStaleness.State.root(setRoot, at == null ? null : (long) dbl(at));
            }
            RevocationStaleness.Check got = RevocationStaleness.checkState(policy, state, dbl(v.get("now")), "g1", v.get("signed_class"), v.get("server_class"), 0.0, guardian);
            assertResult(IntentJs.obj(v.get("result")), got, false, (String) v.get("name"));
        }
    }

    @Test void membership() {
        Map<String, Object> doc = Track3Vectors.load("staleness-vectors.json");
        Map<String, Object> set = IntentJs.obj(doc.get("revocation_set"));
        List<Map<String, Object>> rows = table(doc, "membership", 27);
        for (Map<String, Object> v : rows) {
            Object proof = v.get("proof");
            boolean got = RevocationStaleness.verifyNonMembership((String) v.get("root"),
                proof instanceof Map ? IntentJs.obj(proof) : null, (String) v.get("id"));
            assertEquals(Boolean.TRUE.equals(v.get("ok")), got, (String) v.get("name"));
        }
        assertTrue(rows.stream().anyMatch(v -> "main".equals(v.get("set")) && set.get("root").equals(v.get("root"))));
        assertTrue(rows.stream().anyMatch(v -> "empty".equals(v.get("set")) && set.get("empty_root").equals(v.get("root"))));
        assertTrue(rows.stream().anyMatch(v -> "one".equals(v.get("set")) && IntentJs.obj(set.get("single")).get("root").equals(v.get("root"))));
    }

    /** The vectors' guardian (32 bytes of 0x0b) signs an epoch over the main set, issued {@code issued}. */
    private static Map<String, Object> mainEpoch(Map<String, Object> set, long issued) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("instance_id", "i");
        body.put("grant_ref", "g1");
        body.put("epoch", IntentJs.ofLong(0));
        body.put("set_size", set.get("size"));
        body.put("root", set.get("root"));
        body.put("issued_at", IntentJs.ofLong(issued));
        body.put("not_after", IntentJs.ofLong(issued + 600_000));
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 0x0b);
        byte[] pk = new byte[32];
        org.bouncycastle.math.ec.rfc8032.Ed25519.generatePublicKey(key, 0, pk, 0);
        byte[] msg = Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.getBytes(StandardCharsets.UTF_8), IntentJs.canonBytes(body));
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(key, 0, msg, 0, msg.length, sig, 0);
        Map<String, Object> ep = new LinkedHashMap<>(body);
        ep.put("guardian", Pca.b64(pk));
        ep.put("sig", Pca.b64(sig));
        return ep;
    }

    @Test void gateIds() {
        Map<String, Object> doc = Track3Vectors.load("staleness-vectors.json");
        String guardian = (String) doc.get("guardian_public");
        Map<String, Object> set = IntentJs.obj(doc.get("revocation_set"));
        RevocationStaleness policy = new RevocationStaleness().maxRevocationAgeMs(RevocationStaleness.REVOCATION_EPOCH_VALIDITY_MS);
        for (Map<String, Object> v : table(doc, "gate_ids", 10)) {
            Map<String, Object> ep = mainEpoch(set, (long) dbl(v.get("epoch_issued_at")));
            assertEquals(guardian, ep.get("guardian"), "the test key must be the vectors' guardian");
            List<String> ids = new ArrayList<>();
            for (Object o : (List<?>) v.get("ids")) ids.add((String) o);
            Map<String, Object> proofs = IntentJs.obj(v.get("proofs"));
            RevocationStaleness.Check got = RevocationStaleness.checkState(policy, RevocationStaleness.State.epoch(ep, null, null),
                dbl(v.get("now")), "g1", "costly", null, 0.0, guardian, ids,
                id -> proofs.get(id) instanceof Map ? IntentJs.obj(proofs.get(id)) : null);
            assertResult(IntentJs.obj(v.get("result")), got, false, (String) v.get("name"));
        }
    }

    @Test void authorizeEveryChainCapabilityNeedsAProof() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        String grantRef = (String) AuthorizeFixtures.pcactn(c, 0).get("grant_ref");
        long now = AuthorizeFixtures.now();
        Object state = RevocationStaleness.State.epoch(epoch(grantRef, now, 30_000), null, null);
        // default ids = the cap_chain; no proof source: denied, naming the first id
        RevocationStaleness policy = new RevocationStaleness().maxRevocationAgeMs(300_000).guardianPublic(pub());
        Authorize.AuthorizeResult none = run(new MemoryStateStore(), policy, state);
        assertFalse(none.allow);
        assertEquals("fail", none.checks.get("freshness"));
        assertTrue(String.join("\n", none.reasons).contains("freshness: no non-membership proof for "), none.reasons.toString());
        // a proof that does not fold to the epoch root: denied
        Map<String, Object> bad = new LinkedHashMap<>();
        bad.put("size", IntentJs.ofLong(1));
        Authorize.AuthorizeResult invalid = run(new MemoryStateStore(), policy.proofs((id, pc) -> bad), state);
        assertFalse(invalid.allow);
        assertTrue(String.join("\n", invalid.reasons).contains(" is revoked or proof invalid"), invalid.reasons.toString());
        // a throwing proof source denies
        assertFalse(run(new MemoryStateStore(), policy.proofs((id, pc) -> { throw new IllegalStateException("down"); }), state).allow);
    }

    // ---- unit checks ---------------------------------------------------------------------------------------------------

    @Test void malformedPolicyIsAConfigurationError() {
        assertThrows(IllegalArgumentException.class, () -> new RevocationStaleness().maxRevocationAgeMs(0));
        assertThrows(IllegalArgumentException.class, () -> new RevocationStaleness().maxRevocationAgeMs(Double.NaN));
        assertThrows(IllegalArgumentException.class, () -> new RevocationStaleness().staleness(-1.0, null));
        assertThrows(IllegalArgumentException.class, () -> new RevocationStaleness().staleness(null, Double.POSITIVE_INFINITY));
        assertThrows(IllegalArgumentException.class, () -> RevocationStaleness.fromJson(Json.parseLenient("{\"staleness\":{\"costly\":\"x\"}}")));
        assertFalse(new RevocationStaleness().isOn());
        assertTrue(new RevocationStaleness().maxRevocationAgeMs(1).isOn());
        assertTrue(new RevocationStaleness().staleness(null, null).isOn());
    }

    @Test void windowsAreCappedByTheMaximum() {
        RevocationStaleness p = new RevocationStaleness().maxRevocationAgeMs(50_000).staleness(null, 90_000.0);
        assertEquals(50_000.0, p.revocationMaxAgeMs("costly"));
        assertEquals(50_000.0, p.revocationMaxAgeMs("irreversible"));
        assertEquals(50_000.0, p.revocationMaxAgeMs("reversible"));
    }

    // ---- authorize wiring ----------------------------------------------------------------------------------------------

    static byte[] seed(String label) {
        try { return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8)); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    static String pub() {
        byte[] pk = new byte[32];
        org.bouncycastle.math.ec.rfc8032.Ed25519.generatePublicKey(seed("staleness/guardian"), 0, pk, 0);
        return Pca.b64(pk);
    }

    /** A guardian-signed epoch (epoch 0) for the grant, issued {@code ageMs} before {@code now}. */
    static Map<String, Object> epoch(String grantRef, long now, long ageMs) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("instance_id", "i");
        body.put("grant_ref", grantRef);
        body.put("epoch", IntentJs.ofLong(0));
        body.put("set_size", IntentJs.ofLong(0));
        body.put("root", "r");
        body.put("issued_at", IntentJs.ofLong(now - ageMs));
        body.put("not_after", IntentJs.ofLong(now - ageMs + 600_000));
        byte[] msg = Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.getBytes(StandardCharsets.UTF_8), IntentJs.canonBytes(body));
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(seed("staleness/guardian"), 0, msg, 0, msg.length, sig, 0);
        Map<String, Object> ep = new LinkedHashMap<>(body);
        ep.put("guardian", pub());
        ep.put("sig", Pca.b64(sig));
        return ep;
    }

    private static Authorize.AuthorizeResult run(StateStore store, RevocationStaleness policy, Object state) {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Map<String, Object> p = AuthorizeFixtures.pcactn(c, 0);
        return Authorize.authorize(p, AuthorizeFixtures.input(c, 0).stateStore(store).revocationStaleness(policy)
            .context(pc -> {
                Map<String, Object> m = new LinkedHashMap<>();
                if (state != null) m.put("revocation_state", state);
                return m;
            }));
    }

    @Test void authorizeCapsTheAgeOfSignedState() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        String grantRef = (String) AuthorizeFixtures.pcactn(c, 0).get("grant_ref");
        long now = AuthorizeFixtures.now();
        AtomicReference<Map<String, Object>> accepted = new AtomicReference<>();
        RevocationStaleness policy = new RevocationStaleness().maxRevocationAgeMs(300_000).guardianPublic(pub()).ids(pc -> List.of())
            .onEpochAccepted((ep, p) -> accepted.set(ep));
        StateStore store = new MemoryStateStore();

        // the signed class of this proof is irreversible: 2 minutes. A 3 minute old epoch is refused ...
        Authorize.AuthorizeResult stale = run(store, policy, RevocationStaleness.State.epoch(epoch(grantRef, now, 180_000), null, null));
        assertFalse(stale.allow);
        assertEquals("fail", stale.checks.get("freshness"));
        assertTrue(String.join("\n", stale.reasons).contains(
            "freshness: revocation epoch is 180000 ms old, over the verifier's maximum of 120000 ms (stale revocation state)"), stale.reasons.toString());
        assertNull(accepted.get());

        // ... and nothing was spent: the same proof passes with fresh state
        Authorize.AuthorizeResult fresh = run(store, policy, RevocationStaleness.State.epoch(epoch(grantRef, now, 30_000), null, null));
        assertTrue(fresh.allow, fresh.reasons.toString());
        assertEquals("pass", fresh.checks.get("freshness"));
        assertNotNull(accepted.get());
        // the context may also carry the state as a plain object
        Map<String, Object> asMap = new LinkedHashMap<>();
        asMap.put("kind", "epoch");
        asMap.put("epoch", epoch(grantRef, now, 30_000));
        assertTrue(run(new MemoryStateStore(), policy, asMap).allow);
    }

    @Test void authorizeRefusesUnverifiableStateForIrreversible() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        String grantRef = (String) AuthorizeFixtures.pcactn(c, 0).get("grant_ref");
        long now = AuthorizeFixtures.now();
        RevocationStaleness policy = new RevocationStaleness().maxRevocationAgeMs(300_000).guardianPublic(pub()).ids(pc -> List.of());

        Authorize.AuthorizeResult none = run(new MemoryStateStore(), policy, null);
        assertFalse(none.allow);
        assertTrue(none.reasons.contains("freshness: no verifiable (guardian-signed) revocation state for an irreversible action"), none.reasons.toString());

        Authorize.AuthorizeResult root = run(new MemoryStateStore(), policy, RevocationStaleness.State.root("r", now - 1_000L));
        assertFalse(root.allow);
        assertTrue(root.reasons.contains("freshness: unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)"), root.reasons.toString());

        RevocationStaleness lenient = policy.allowUnsignedRootForIrreversible(true);
        assertTrue(run(new MemoryStateStore(), lenient, null).allow);
        assertTrue(run(new MemoryStateStore(), lenient, RevocationStaleness.State.root("r", now - 1_000L)).allow);
        Authorize.AuthorizeResult old = run(new MemoryStateStore(), lenient, RevocationStaleness.State.root("r", now - 400_000L));
        assertFalse(old.allow);

        // an epoch for another grant, or from another guardian, never passes
        assertFalse(run(new MemoryStateStore(), policy, RevocationStaleness.State.epoch(epoch(grantRef + "x", now, 1_000), null, null)).allow);
        assertFalse(run(new MemoryStateStore(), policy.guardianPublic(Pca.b64(new byte[32])), RevocationStaleness.State.epoch(epoch(grantRef, now, 1_000), null, null)).allow);

        // staleness off: the revocation_state member is ignored and no freshness check is recorded
        Authorize.AuthorizeResult off = run(new MemoryStateStore(), null, null);
        assertTrue(off.allow);
        assertFalse(off.checks.containsKey("freshness"));
    }
}
