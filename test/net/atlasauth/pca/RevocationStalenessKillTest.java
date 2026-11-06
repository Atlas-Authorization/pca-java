package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Revocation staleness (T9) member by member: the policy builders and the JSON policy, the JavaScript number text, the age
 * check, every refusal of the signed-epoch check (including a hybrid post-quantum epoch under its pin) and of the state gate,
 * and the context form of the state.
 */
public class RevocationStalenessKillTest {
    static final long T = 1_800_000_000_000L;
    static final byte[] SEED = StalenessVectorsTest.seed("staleness/guardian");
    static final String G = StalenessVectorsTest.pub();
    static final String NOT_PINNED = "revocation epoch not signed by the pinned guardian";

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static Map<String, Object> body(long epoch, Object root) {
        return map("instance_id", "i", "grant_ref", "g1", "epoch", IntentJs.ofLong(epoch), "set_size", IntentJs.ofLong(0), "root", root,
            "issued_at", IntentJs.ofLong(T), "not_after", IntentJs.ofLong(T + 600_000));
    }

    static byte[] msg(Map<String, Object> signed) {
        return Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.getBytes(StandardCharsets.UTF_8), IntentJs.canonBytes(signed));
    }

    /** An Ed25519 epoch by the vectors' guardian over {@code body} (signed as given). */
    static Map<String, Object> ed(Map<String, Object> body) {
        byte[] m = msg(body);
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(SEED, 0, m, 0, m.length, sig, 0);
        Map<String, Object> ep = new LinkedHashMap<>(body);
        ep.put("guardian", G);
        ep.put("sig", Pca.b64(sig));
        return ep;
    }

    static byte[] fill(int b) {
        byte[] x = new byte[32];
        Arrays.fill(x, (byte) b);
        return x;
    }

    static final Keys.SuiteKey HYBRID = Keys.suite("hybrid-ed25519-ml-dsa-65", Keys.edFromSeed(fill(7)), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(8)));

    /** A hybrid Ed25519 + ML-DSA-65 epoch (alg and pq_pk bound into the signed body). */
    static Map<String, Object> hybrid(long epoch) {
        Map<String, Object> bound = IntentJs.bindSuiteFields(body(epoch, "r"), HYBRID.alg, true, HYBRID.pqPk(), true);
        String[] sig = HYBRID.sign(msg(bound));
        Map<String, Object> ep = new LinkedHashMap<>(bound);
        ep.put("guardian", HYBRID.id());
        ep.put("sig", sig[0]);
        ep.put("pq_sig", sig[1]);
        return ep;
    }

    static RevocationStaleness.EpochOptions opts(String guardian) { return new RevocationStaleness.EpochOptions(guardian, T + 1000); }

    static void assertBad(String reason, RevocationStaleness.Check c) {
        assertFalse(c.ok, String.valueOf(c));
        assertEquals(reason, c.reason);
        assertNull(c.epoch);
        assertEquals("Check{" + reason + "}", c.toString());
    }

    static void assertPass(RevocationStaleness.Check c) {
        assertTrue(c.ok, String.valueOf(c));
        assertNull(c.reason);
        assertEquals("Check{ok}", c.toString());
    }

    // ---- the policy ------------------------------------------------------------------------------------------------

    @Test void builtAndReadPolicies() {
        Map<String, Object> pins = map("id", "pk");
        RevocationStaleness p = new RevocationStaleness().pqPins(pins);
        assertEquals(pins, p.pqPins);
        assertNotSame(pins, p.pqPins);
        pins.put("other", "x");
        assertEquals(map("id", "pk"), p.pqPins);
        assertEquals(map("id", "pk"), p.maxRevocationAgeMs(5).pqPins, "every builder keeps the pins");
        assertNull(new RevocationStaleness().pqPins(null).pqPins);

        assertEquals("revocation staleness policy must be an object",
            assertThrows(IllegalArgumentException.class, () -> RevocationStaleness.fromJson("x")).getMessage());
        RevocationStaleness rl = RevocationStaleness.fromJson(map("staleness", map("rate_limited", IntentJs.ofLong(5000))));
        assertEquals(Double.valueOf(5000.0), rl.costlyMs);
        assertNull(rl.irreversibleMs);
        assertEquals(5000.0, rl.revocationMaxAgeMs("rate_limited"));
        assertEquals(Double.valueOf(7000.0), RevocationStaleness.fromJson(map("staleness", map("costly", IntentJs.ofLong(7000)))).costlyMs);
        assertEquals(Double.valueOf(5000.0), RevocationStaleness.fromJson(map("staleness", map("rate_limited", IntentJs.ofLong(5000), "costly", IntentJs.ofLong(7000)))).costlyMs);
        RevocationStaleness odd = RevocationStaleness.fromJson(map("staleness", "x"));
        assertTrue(odd.isOn());
        assertNull(odd.costlyMs);
        assertFalse(RevocationStaleness.fromJson(map()).isOn());
        assertTrue(RevocationStaleness.fromJson(map("maxRevocationAgeMs", IntentJs.ofLong(1))).isOn());
        assertTrue(RevocationStaleness.fromJson(map("allowUnsignedRootForIrreversible", true)).allowUnsignedRootForIrreversible);
        assertFalse(RevocationStaleness.fromJson(map("allowUnsignedRootForIrreversible", "true")).allowUnsignedRootForIrreversible);
        assertFalse(RevocationStaleness.fromJson(map()).allowUnsignedRootForIrreversible);

        assertEquals(2, RevocationStaleness.classRank(IntentJs.ofLong(1)));
        assertEquals(2, RevocationStaleness.classRank("bogus"));
        assertEquals(2, RevocationStaleness.classRank("irreversible"));
        assertEquals(1, RevocationStaleness.classRank("costly"));
        assertEquals(1, RevocationStaleness.classRank("rate_limited"));
        assertEquals(0, RevocationStaleness.classRank("reversible"));
    }

    @Test void numbersPrintAsJavaScriptDoes() {
        Object[][] cases = {
            {Double.NaN, "NaN"}, {Double.POSITIVE_INFINITY, "Infinity"}, {Double.NEGATIVE_INFINITY, "-Infinity"},
            {0.0, "0"}, {-0.0, "0"}, {5.0, "5"}, {-5.0, "-5"}, {2.5, "2.5"}, {0.1, "0.1"}, {1800000000100.0, "1800000000100"},
            {1e20, "100000000000000000000"}, {1e21, "1e+21"}, {-1e22, "-1e+22"}, {Math.pow(2, 60), "1152921504606847000"},
            {1e-7, "1e-7"}, {0.000001, "0.000001"},
        };
        for (Object[] c : cases) assertEquals(c[1], RevocationStaleness.jsNum((Double) c[0]), String.valueOf(c[0]));
    }

    @Test void nonMembershipNeedsAnIdAndAProof() {
        Map<String, Object> set = IntentJs.obj(Track3Vectors.load("staleness-vectors.json").get("revocation_set"));
        String empty = (String) set.get("empty_root");
        Map<String, Object> none = map("size", IntentJs.ofLong(0));
        assertTrue(RevocationStaleness.verifyNonMembership(empty, none, "c1"));
        assertFalse(RevocationStaleness.verifyNonMembership(empty, none, null));
        assertFalse(RevocationStaleness.verifyNonMembership(empty, null, "c1"));
        assertFalse(RevocationStaleness.verifyNonMembership(null, none, "c1"));
    }

    @Test void anUnknownIssueTimeIsUnverifiable() {
        for (Object at : new Object[] {null, "x", Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY})
            assertBad("root age is unknown (unverifiable revocation state)", RevocationStaleness.checkRevocationAge(at, T, 1000, "root"));
        assertPass(RevocationStaleness.checkRevocationAge(IntentJs.ofLong(T - 1000), T, 1000, "root"));
        assertBad("root is 1001 ms old, over the verifier's maximum of 1000 ms (stale revocation state)",
            RevocationStaleness.checkRevocationAge(IntentJs.ofLong(T - 1001), T, 1000, "root"));
    }

    // ---- the signed epoch ------------------------------------------------------------------------------------------

    @Test void epochRefusals() {
        assertPass(RevocationStaleness.checkRevocationEpoch(ed(body(0, "r")), opts(G)));
        assertBad(NOT_PINNED, RevocationStaleness.checkRevocationEpoch(ed(body(0, "r")), opts(null)));
        assertBad(NOT_PINNED, RevocationStaleness.checkRevocationEpoch("x", opts(G)));
        // an explicit alg is bound and resolved
        Map<String, Object> withAlg = new LinkedHashMap<>(ed(body(0, "r")));
        withAlg.put("alg", "ed25519");
        assertPass(RevocationStaleness.checkRevocationEpoch(withAlg, opts(G)));
        for (Object[] c : new Object[][] {{"fn-dsa-512", "unsupported_suite: fn-dsa-512"}, {"foo", NOT_PINNED}, {IntentJs.ofLong(1), NOT_PINNED}, {null, NOT_PINNED}}) {
            Map<String, Object> ep = new LinkedHashMap<>(ed(body(0, "r")));
            ep.put("alg", c[0]);
            assertBad((String) c[1], RevocationStaleness.checkRevocationEpoch(ep, opts(G)));
        }
        // a body the store cannot pick (no instance_id), or cannot canonicalize (a lone surrogate)
        Map<String, Object> noInstance = body(0, "r");
        noInstance.remove("instance_id");
        assertBad("revocation epoch check error", RevocationStaleness.checkRevocationEpoch(withGuardian(noInstance), opts(G)));
        Map<String, Object> surrogate = body(0, "r");
        surrogate.put("instance_id", "\uD800");
        assertBad("revocation epoch check error", RevocationStaleness.checkRevocationEpoch(withGuardian(surrogate), opts(G)));
        // the age cap passes, the rollback still applies
        RevocationStaleness.EpochOptions o = opts(G);
        o.maxAgeMs = 600_000.0;
        o.lastAcceptedEpoch = 5.0;
        assertBad("revocation epoch 0 is older than the last accepted 5 (rollback)", RevocationStaleness.checkRevocationEpoch(ed(body(0, "r")), o));
        RevocationStaleness.EpochOptions young = opts(G);
        young.maxAgeMs = 10.0;
        assertBad("revocation epoch is 1000 ms old, over the verifier's maximum of 10 ms (stale revocation state)",
            RevocationStaleness.checkRevocationEpoch(ed(body(0, "r")), young));
    }

    static Map<String, Object> withGuardian(Map<String, Object> body) {
        Map<String, Object> ep = new LinkedHashMap<>(body);
        ep.put("guardian", G);
        ep.put("sig", Pca.b64(new byte[64]));
        return ep;
    }

    @Test void aHybridEpochVerifiesOnlyUnderItsPin() {
        Map<String, Object> ep = hybrid(0);
        RevocationStaleness.EpochOptions pinned = opts(HYBRID.id());
        pinned.pqPins = Keys.pqPin(HYBRID);
        assertPass(RevocationStaleness.checkRevocationEpoch(ep, pinned));
        assertBad("revocation epoch signature invalid", RevocationStaleness.checkRevocationEpoch(ep, opts(HYBRID.id())));
        for (String k : new String[] {"pq_sig", "sig", "pq_pk"}) {
            Map<String, Object> cut = new LinkedHashMap<>(ep);
            cut.remove(k);
            assertBad("revocation epoch signature invalid", RevocationStaleness.checkRevocationEpoch(cut, pinned));
        }
        // the gate passes the policy's pins on; without a policy there are none
        RevocationStaleness policy = new RevocationStaleness().pqPins(Keys.pqPin(HYBRID));
        assertPass(RevocationStaleness.checkState(policy, RevocationStaleness.State.epoch(ep, null, null), T + 1000, "g1", "reversible", null, null, HYBRID.id()));
        assertBad("revocation epoch signature invalid",
            RevocationStaleness.checkState(null, RevocationStaleness.State.epoch(ep, null, null), T + 1000, "g1", "reversible", null, null, HYBRID.id()));
    }

    // ---- the state gate --------------------------------------------------------------------------------------------

    static RevocationStaleness.Check gate(RevocationStaleness policy, RevocationStaleness.State s, String gp) {
        return RevocationStaleness.checkState(policy, s, T + 1000, "g1", "reversible", null, null, gp);
    }

    @Test void theStateGate() {
        Map<String, Object> ep = ed(body(0, "r"));
        // no policy: an unsigned root is taken as it is
        assertPass(gate(null, RevocationStaleness.State.root("r", T), null));
        // the guardian: the argument, else the policy's, else none
        RevocationStaleness.Check viaPolicy = gate(new RevocationStaleness().guardianPublic(G), RevocationStaleness.State.epoch(ep, null, null), null);
        assertPass(viaPolicy);
        assertSame(ep, viaPolicy.epoch);
        assertPass(gate(new RevocationStaleness().guardianPublic("other"), RevocationStaleness.State.epoch(ep, null, null), G));
        assertBad("no signed revocation epoch", gate(null, RevocationStaleness.State.epoch(ep, null, null), null));
        assertBad("no signed revocation epoch", gate(null, RevocationStaleness.State.epoch(ep, null, null), ""));
        assertBad("no signed revocation epoch", gate(null, RevocationStaleness.State.epoch(null, null, null), G));
        assertBad("no signed revocation epoch", gate(null, null, G));
        assertPass(gate(null, RevocationStaleness.State.epoch(ep, "r", null), G));
        assertBad("revocation root does not match the signed epoch", gate(null, RevocationStaleness.State.epoch(ep, "s", null), G));
        // the rollback pin and the PCActn's freshness epoch reach the epoch check
        assertBad("revocation epoch 0 is older than the last accepted 5 (rollback)", gate(null, RevocationStaleness.State.epoch(ep, null, 5L), G));
        assertPass(gate(null, RevocationStaleness.State.epoch(ep, null, 0L), G));
        Map<String, Object> ep3 = ed(body(3, "r"));
        assertBad("PCActn freshness.epoch 2 predates the revocation epoch 3",
            RevocationStaleness.checkState(null, RevocationStaleness.State.epoch(ep3, null, null), T + 1000, "g1", "reversible", null, 2.0, G));
        assertPass(RevocationStaleness.checkState(null, RevocationStaleness.State.epoch(ep3, null, null), T + 1000, "g1", "reversible", null, 3.0, G));
        // a signed root that is not a string is no root
        assertBad("no revocation root", gate(null, RevocationStaleness.State.epoch(ed(body(0, IntentJs.ofLong(1))), null, null), G));
        // a bare root: empty or missing is no root, also when the policy's age check passed
        RevocationStaleness on = new RevocationStaleness().maxRevocationAgeMs(300_000);
        assertBad("no revocation root", gate(on, RevocationStaleness.State.root("", T), null));
        assertBad("no revocation root", gate(null, RevocationStaleness.State.root(null, T), null));
        assertBad("revocation root is 301000 ms old, over the verifier's maximum of 300000 ms (stale revocation state)",
            gate(on, RevocationStaleness.State.root("r", T - 300_000), null));
        // capability proofs
        List<String> ids = List.of("c1");
        assertBad("no non-membership proof for c1", RevocationStaleness.checkState(null, RevocationStaleness.State.root("r", T), T, "g1", null, null, null, null, ids, null));
        assertBad("no non-membership proof for c1", RevocationStaleness.checkState(null, RevocationStaleness.State.root("r", T), T, "g1", null, null, null, null, ids, id -> null));
        assertBad("capability c1 is revoked or proof invalid", RevocationStaleness.checkState(null, RevocationStaleness.State.root("r", T), T, "g1", null, null, null, null, ids,
            id -> map("size", IntentJs.ofLong(1))));
        assertBad("revocation state check error (fail closed)", RevocationStaleness.checkState(null, RevocationStaleness.State.root("r", T), T, "g1", null, null, null, null, ids,
            id -> { throw new IllegalStateException("down"); }));
    }

    @Test void theContextFormOfTheState() {
        RevocationStaleness.State s = RevocationStaleness.State.root("r", 5L);
        assertSame(s, RevocationStaleness.State.of(s));
        assertNull(RevocationStaleness.State.of("x"));
        assertNull(RevocationStaleness.State.of(map("kind", "other", "root", "r")));
        assertNull(RevocationStaleness.State.of(map("kind", "epoch", "epoch", "x", "root", "r")));
        assertNull(RevocationStaleness.State.of(map("root", "r")));

        Map<String, Object> ep = ed(body(0, "r"));
        RevocationStaleness.State e = RevocationStaleness.State.of(map("kind", "epoch", "epoch", ep, "root", "r", "last_accepted_epoch", IntentJs.ofLong(4)));
        assertTrue(e.signed);
        assertSame(ep, e.epoch);
        assertEquals("r", e.root);
        assertEquals(Double.valueOf(4.0), e.lastAcceptedEpoch);
        assertNull(e.issuedAt);
        RevocationStaleness.State e2 = RevocationStaleness.State.of(map("kind", "epoch", "epoch", ep, "root", IntentJs.ofLong(1)));
        assertNull(e2.root);
        assertNull(e2.lastAcceptedEpoch);

        Object at = IntentJs.ofLong(9);
        RevocationStaleness.State r = RevocationStaleness.State.of(map("kind", "root", "root", "r", "issued_at", at));
        assertFalse(r.signed);
        assertNull(r.epoch);
        assertEquals("r", r.root);
        assertSame(at, r.issuedAt);
        assertNull(r.lastAcceptedEpoch);
        assertNull(RevocationStaleness.State.of(map("kind", "root", "root", IntentJs.ofLong(1))).root);

        RevocationStaleness.State built = RevocationStaleness.State.epoch(ep, "r", 7L);
        assertEquals(Double.valueOf(7.0), built.lastAcceptedEpoch);
        assertNull(RevocationStaleness.State.epoch(ep, "r", null).lastAcceptedEpoch);
        assertEquals(5L, RevocationStaleness.State.root("r", 5L).issuedAt);
    }
}
