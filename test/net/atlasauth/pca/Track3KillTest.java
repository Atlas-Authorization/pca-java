package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Exact-outcome tests for the Track 3 verifiers (ledger, optimistic, mesh, session histories), independent of the shared corpora. */
public class Track3KillTest {
    static Object j(String text) { return Json.parseLenient(text); }

    static Map<String, Object> proof(long oldSize, long newSize, String... path) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("oldSize", oldSize);
        p.put("newSize", newSize);
        p.put("path", new ArrayList<Object>(List.of(path)));
        return p;
    }

    // ---- ledger ----

    @Test void consistencyOneToTwoLeaves() {
        String a = Pca.b64(Pca.leafHash("a")), b = Pca.b64(Pca.leafHash("b"));
        String root2 = Pca.merkleRoot(new ArrayList<Object>(List.of("a", "b")));
        assertEquals(Pca.b64(Pca.nodeHash(Pca.leafHash("a"), Pca.leafHash("b"))), root2);
        assertTrue(Ledger.verifyLedgerConsistency(a, root2, proof(1, 2, b)));
        assertFalse(Ledger.verifyLedgerConsistency(a, root2, proof(1, 2, a)), "wrong sibling");
        assertFalse(Ledger.verifyLedgerConsistency(root2, a, proof(1, 2, b)), "roots swapped");
        assertFalse(Ledger.verifyLedgerConsistency(a, root2, proof(1, 2)), "empty path for different sizes");
        assertFalse(Ledger.verifyLedgerConsistency(a, root2, proof(2, 1, b)), "old size above new size");
    }

    @Test void consistencyEmptyAndEqualSizes() {
        String e = Ledger.EMPTY_TREE_ROOT, a = Pca.b64(Pca.leafHash("a"));
        assertTrue(Ledger.verifyLedgerConsistency(e, e, proof(0, 0)));
        assertTrue(Ledger.verifyLedgerConsistency(e, a, proof(0, 1)), "an empty old tree is vacuously consistent");
        assertFalse(Ledger.verifyLedgerConsistency(a, a, proof(0, 1)), "size 0 pins the empty root");
        assertFalse(Ledger.verifyLedgerConsistency(e, a, proof(0, 0)), "size 0 to size 0 needs the empty root");
        assertTrue(Ledger.verifyLedgerConsistency(a, a, proof(1, 1)));
        assertFalse(Ledger.verifyLedgerConsistency(a, e, proof(1, 1)));
        assertFalse(Ledger.verifyLedgerConsistency(a, a, proof(1, 1, a)), "equal sizes take no path");
    }

    @Test void consistencyPathLengthIsBounded() {
        String a = Pca.b64(Pca.leafHash("a"));
        String[] path = new String[Ledger.MAX_CONSISTENCY_PATH + 1];
        java.util.Arrays.fill(path, a);
        assertFalse(Ledger.verifyLedgerConsistency(a, a, proof(1, 9007199254740991L, path)));
    }

    @Test void unsafeSizesAreRefused() {
        String a = Pca.b64(Pca.leafHash("a"));
        Object p = j("{\"oldSize\":1,\"newSize\":9007199254740992,\"path\":[]}");
        assertFalse(Ledger.verifyLedgerConsistency(a, a, p));
        Object q = j("{\"oldSize\":1.5,\"newSize\":2,\"path\":[]}");
        assertFalse(Ledger.verifyLedgerConsistency(a, a, q));
    }

    @Test void inclusionOfOneLeafTree() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("index", 0L);
        p.put("size", 1L);
        p.put("path", new ArrayList<Object>());
        String root = Pca.b64(Pca.leafHash("c1"));
        assertTrue(Ledger.verifyLedgerInclusion(root, p, "c1"));
        assertFalse(Ledger.verifyLedgerInclusion(root, p, "c2"));
        assertFalse(Ledger.verifyLedgerInclusion(root, "not a proof", "c1"));
    }

    @Test void thresholdRules() {
        Object sth = j("{\"witnesses\":[]}");
        assertTrue(Ledger.verifyWitnessCosignatures(sth, Track3Vectors.mapOrNull(j("{\"threshold\":0}"))), "threshold 0 is vacuous");
        assertFalse(Ledger.verifyWitnessCosignatures(sth, Track3Vectors.mapOrNull(j("{\"threshold\":-1}"))));
        assertFalse(Ledger.verifyWitnessCosignatures(sth, Track3Vectors.mapOrNull(j("{\"threshold\":1.5,\"witnessKeys\":[\"k\"]}"))));
        assertFalse(Ledger.verifyWitnessCosignatures(sth, Track3Vectors.mapOrNull(j("{\"threshold\":1}"))), "no trusted keys");
        assertFalse(Ledger.verifyWitnessCosignatures(sth, Track3Vectors.mapOrNull(j("{\"threshold\":1,\"witnessKeys\":[\"k\"]}"))), "no cosignatures");
        assertFalse(Ledger.verifyWitnessCosignatures(sth, null));
    }

    @Test void nonEd25519ArtifactsAreRefused() {
        assertFalse(Ledger.verifyTreeHead(j("{\"guardian\":\"g\",\"alg\":\"ml-dsa-65\",\"size\":1}"), "g", null));
        assertFalse(Ledger.verifyTreeHead(j("{\"guardian\":\"g\",\"alg\":\"ed25519\",\"size\":-1}"), "g", null), "negative size");
        assertFalse(Ledger.verifyWitnessedHead(j("{\"witness\":\"w\",\"alg\":null}"), "w"));
    }

    @Test void emptyCheckpointChainFailsAtZero() {
        Ledger.CheckpointVerdict v = Ledger.verifyCheckpointChain(j("[]"), "g", null);
        assertFalse(v.ok);
        assertEquals(0, v.at);
        Ledger.CheckpointVerdict w = Ledger.verifyCheckpointChain(j("[{\"sth\":null}]"), "g", null);
        assertFalse(w.ok);
        assertEquals(0, w.at);
    }

    // ---- optimistic ----

    @Test void challengeWindowBoundaries() {
        assertEquals(150.0, Optimistic.challengeWindowEnd(100, 50));
        assertTrue(Optimistic.withinChallengeWindow(100, 50, 150), "the end instant is inclusive");
        assertFalse(Optimistic.withinChallengeWindow(100, 50, 151));
        assertFalse(Optimistic.withinChallengeWindow(100, 50, Double.NaN));
        assertFalse(Optimistic.withinChallengeWindow(100, 50, Double.POSITIVE_INFINITY));
        assertEquals("open", Optimistic.claimStatus(100, 50, 150));
        assertEquals("finalized", Optimistic.claimStatus(100, 50, 151));
    }

    static final String CLAIM = "{\"pcactn_digest\":\"d\",\"claimed_r\":0.1,\"issued_at\":1000,\"challenge_window_ms\":60000";

    @Test void claimChecksRunInTheDocumentedOrder() {
        Optimistic.ChallengeWindowPolicy p = Optimistic.DEFAULT_POLICY;
        assertEquals("malformed", Optimistic.claimCheck("x", "d", "k", 1000, p));
        assertEquals("irreversible", Optimistic.claimCheck(j("{\"reversibility_class\":\"irreversible\",\"pcactn_digest\":\"other\"}"), "d", "k", 1000, p));
        assertEquals("digest", Optimistic.claimCheck(j(CLAIM + "}"), "other", "k", 1000, p));
        assertEquals("claimed_r", Optimistic.claimCheck(j("{\"pcactn_digest\":\"d\"}"), "d", "k", 1000, p));
        assertEquals("window", Optimistic.claimCheck(j("{\"pcactn_digest\":\"d\",\"claimed_r\":0.1,\"issued_at\":1000,\"challenge_window_ms\":999}"), "d", "k", 1000, p), "below the minimum");
        assertEquals("window", Optimistic.claimCheck(j("{\"pcactn_digest\":\"d\",\"claimed_r\":0.1,\"issued_at\":1000,\"challenge_window_ms\":86400001}"), "d", "k", 1000, p), "above the maximum");
        assertEquals("window", Optimistic.claimCheck(j(CLAIM + "}"), "d", "k", 6001, p), "skew above the maximum");
        assertEquals("signature", Optimistic.claimCheck(j(CLAIM + "}"), "d", "k", 6000, p), "skew at the maximum passes to the signature");
        assertEquals("signature", Optimistic.claimCheck(j(CLAIM + ",\"sig\":\"x\"}"), "d", "k", 1000, p));
    }

    static final String PROOF_HEAD = "{\"pcactn_digest\":\"d\",\"bond_ref\":\"b\",\"claimed_r\":0.25,\"reason\":\"r\"";

    @Test void fraudProofKinds() {
        Object claim = j("{\"pcactn_digest\":\"d\",\"bond_ref\":\"b\",\"claimed_r\":0.25,\"reversibility_class\":\"reversible\"}");
        String denied = PROOF_HEAD + ",\"kind\":\"policy-denied\",\"decision\":{\"releaseGuardianShare\":false,\"optimisticAllowed\":true,\"r\":0.9}}";
        assertEquals("ok", Optimistic.fraudProofWireCheck(claim, j(denied)));
        assertEquals("consistency", Optimistic.fraudProofWireCheck(claim, j(denied.replace("false", "true"))));
        String notAllowed = PROOF_HEAD + ",\"kind\":\"optimistic-not-allowed\",\"decision\":{\"releaseGuardianShare\":true,\"optimisticAllowed\":false,\"r\":0.9}}";
        assertEquals("ok", Optimistic.fraudProofWireCheck(claim, j(notAllowed)));
        String understated = PROOF_HEAD + ",\"kind\":\"risk-understated\",\"decision\":{\"releaseGuardianShare\":true,\"optimisticAllowed\":true,\"r\":0.9}}";
        assertEquals("ok", Optimistic.fraudProofWireCheck(claim, j(understated)));
        assertEquals("consistency", Optimistic.fraudProofWireCheck(claim, j(understated.replace("0.9", "0.25"))), "r equal to claimed_r is not understated");
        assertEquals("kind", Optimistic.fraudProofWireCheck(claim, j(denied.replace("policy-denied", "other"))));
        assertEquals("digest", Optimistic.fraudProofWireCheck(j("{\"pcactn_digest\":\"e\",\"bond_ref\":\"b\",\"claimed_r\":0.25}"), j(denied)));
        assertEquals("bond", Optimistic.fraudProofWireCheck(j("{\"pcactn_digest\":\"d\",\"bond_ref\":\"z\",\"claimed_r\":0.25}"), j(denied)));
        assertEquals("claimed_r", Optimistic.fraudProofWireCheck(j("{\"pcactn_digest\":\"d\",\"bond_ref\":\"b\",\"claimed_r\":0.5}"), j(denied)));
        assertEquals("malformed", Optimistic.fraudProofWireCheck(claim, j("{\"decision\":{}}")));
        String irreversible = PROOF_HEAD + ",\"kind\":\"irreversible\",\"decision\":{\"releaseGuardianShare\":true,\"optimisticAllowed\":true,\"r\":0.1},\"evidence\":{\"action\":{\"action\":{\"reversibility_class\":\"irreversible\"}}}}";
        assertEquals("ok", Optimistic.fraudProofWireCheck(claim, j(irreversible)), "irreversible through the evidence");
        assertEquals("consistency", Optimistic.fraudProofWireCheck(claim, j(irreversible.replace("\"irreversible\"}}}", "\"reversible\"}}}"))));
    }

    static final String SLASH = "{\"claimId\":\"c\",\"action\":\"slash\",\"amount\":100,\"from\":\"a\",\"to\":\"t\",\"at\":1,\"evidenceDigest\":\"e\",\"sig\":\"x\",\"split\":";

    @Test void settlementShapeSuiteAndSplit() {
        assertEquals("malformed", Optimistic.settlementWireCheck("x", "k"));
        assertEquals("suite", Optimistic.settlementWireCheck(j("{\"alg\":\"no-such-suite\"}"), "k"));
        assertEquals("shape", Optimistic.settlementWireCheck(j("{\"action\":\"open\"}"), "k"));
        assertEquals("shape", Optimistic.settlementWireCheck(j("{\"claimId\":\"c\",\"action\":\"open\",\"amount\":0,\"from\":\"a\",\"to\":\"t\",\"at\":1,\"evidenceDigest\":\"\",\"sig\":\"x\"}"), "k"), "amount must be positive");
        assertEquals("shape", Optimistic.settlementWireCheck(j("{\"claimId\":\"c\",\"action\":\"open\",\"amount\":1,\"from\":\"a\",\"to\":\"t\",\"at\":1,\"evidenceDigest\":\"e\",\"sig\":\"x\"}"), "k"), "only a slash carries evidence");
        assertEquals("signature", Optimistic.settlementWireCheck(j("{\"claimId\":\"c\",\"action\":\"open\",\"amount\":1,\"from\":\"a\",\"to\":\"t\",\"at\":1,\"evidenceDigest\":\"\",\"sig\":\"x\"}"), "k"));
        String ok = "{\"amount\":100,\"challengerReward\":10,\"victimCompensation\":20,\"treasuryRemainder\":70,\"victimAccount\":\"v\",\"treasuryAccount\":\"t\",\"challengerAccount\":\"ch\"}}";
        assertEquals("signature", Optimistic.settlementWireCheck(j(SLASH + ok), "k"), "a conserved split reaches the signature");
        assertEquals("split", Optimistic.settlementWireCheck(j(SLASH + ok.replace("\"treasuryRemainder\":70", "\"treasuryRemainder\":69")), "k"), "the parts must add up");
        assertEquals("split", Optimistic.settlementWireCheck(j(SLASH + ok.replace("\"amount\":100", "\"amount\":99")), "k"), "the split amount must equal the record's");
        assertEquals("split", Optimistic.settlementWireCheck(j(SLASH + ok.replace("\"treasuryAccount\":\"t\"", "\"treasuryAccount\":\"u\"")), "k"), "the treasury account must be the destination");
        assertEquals("split", Optimistic.settlementWireCheck(j(SLASH + ok.replace("\"victimAccount\":\"v\"", "\"victimAccount\":\"\"")), "k"));
        assertEquals("split", Optimistic.settlementWireCheck(j(SLASH + ok.replace("\"challengerAccount\":\"ch\"", "\"challengerAccount\":\"\"")), "k"));
        String anon = "{\"amount\":100,\"challengerReward\":0,\"victimCompensation\":0,\"treasuryRemainder\":100,\"victimAccount\":\"v\",\"treasuryAccount\":\"t\",\"challengerAccount\":null}}";
        assertEquals("signature", Optimistic.settlementWireCheck(j(SLASH + anon), "k"), "an anonymous challenge sends everything to the treasury");
        assertEquals("split", Optimistic.settlementWireCheck(j(SLASH + anon.replace("\"victimAccount\":\"v\"", "\"victimAccount\":\"\"")), "k"), "an anonymous split still needs a victim account");
        assertEquals("split", Optimistic.settlementWireCheck(j(SLASH + anon.replace("\"challengerReward\":0,\"victimCompensation\":0,\"treasuryRemainder\":100", "\"challengerReward\":10,\"victimCompensation\":0,\"treasuryRemainder\":90")), "k"));
    }

    // ---- mesh ----

    static final String TRUST = "{\"humanPrincipal\":\"h\",\"witnesses\":[\"w\"],\"threshold\":1,\"now\":1000,\"allowedDomains\":[\"d\"],\"rootDomain\":\"d\"}";

    @Test void meshRefusesMalformedInput() {
        Mesh.Verdict v = Mesh.verifyMeshProof(j("{}"), j("[]"));
        assertFalse(v.ok);
        assertEquals("invalid trust configuration", v.reason);
        assertEquals(-1, v.hop);
        assertEquals("invalid trust configuration: threshold", Mesh.verifyMeshProof(j("{}"), j(TRUST.replace("\"threshold\":1", "\"threshold\":2"))).reason);
        assertEquals("invalid trust configuration: now", Mesh.verifyMeshProof(j("{}"), j(TRUST.replace("\"now\":1000", "\"now\":\"x\""))).reason);
        assertEquals("invalid trust configuration: rootDomain is required and must be in allowedDomains", Mesh.verifyMeshProof(j("{}"), j(TRUST.replace("\"rootDomain\":\"d\"", "\"rootDomain\":\"z\""))).reason);
        assertEquals("malformed proof", Mesh.verifyMeshProof(j("[]"), j(TRUST)).reason);
        assertEquals("malformed proof", Mesh.verifyMeshProof(j("{}"), j(TRUST)).reason);
        assertEquals("malformed proof", Mesh.verifyMeshProof(null, j(TRUST)).reason);
        String lists = "\"chain\":[],\"hops\":[],\"heads\":[],\"rev_leaves\":[]";
        assertEquals("malformed action", Mesh.verifyMeshProof(j("{" + lists + "}"), j(TRUST)).reason);
        String action = "\"action\":{\"type\":\"t\",\"resource\":\"r\",\"service_domain\":\"d\",\"nonce\":\"n\",\"at\":1},\"action_sig\":\"x\"";
        assertEquals("chain length out of bounds", Mesh.verifyMeshProof(j("{" + lists + "," + action + "}"), j(TRUST)).reason);
        assertEquals("malformed pin proofs", Mesh.verifyMeshProof(j("{" + lists + "," + action + ",\"pin_proofs\":5}"), j(TRUST)).reason);
    }

    // ---- session histories ----

    static final String SUM = "{\"id\":\"s\",\"agg\":\"sum\",\"val\":\"action.params.total\",\"unit\":\"usd\",\"sel\":{\"verbs\":[\"shop.buy\"]},\"win\":{\"kind\":\"task\"},\"key\":null,\"holder\":{\"kind\":\"site_local\"}}";

    static Map<String, Object> m(String text) { return IntentJs.obj(j(text)); }

    @Test void windowBoundaries() {
        Map<String, Object> sliding = m("{\"kind\":\"sliding\",\"ms\":100}");
        assertFalse(IntentHistory.inWindow(sliding, j("900"), j("1000")), "the window is (t-ms, t]");
        assertTrue(IntentHistory.inWindow(sliding, j("901"), j("1000")));
        assertTrue(IntentHistory.inWindow(sliding, j("1000"), j("1000")));
        assertTrue(IntentHistory.inWindow(sliding, j("1001"), j("1000")), "a future-stamped event has not left the window");
        Map<String, Object> period = m("{\"kind\":\"period\",\"ms\":100,\"t0\":0}");
        assertTrue(IntentHistory.inWindow(period, j("900"), j("999")));
        assertFalse(IntentHistory.inWindow(period, j("899"), j("900")));
        assertTrue(IntentHistory.inWindow(m("{\"kind\":\"task\"}"), j("0"), j("5000")));
        assertFalse(IntentHistory.inWindow(m("{\"kind\":\"other\"}"), j("0"), j("5")));
        assertFalse(IntentHistory.inWindow(m("{\"kind\":\"task\"}"), j("1.5"), j("5")), "a non-integer time is in no window");
        assertFalse(IntentHistory.inWindow(m("{\"kind\":\"task\"}"), j("-0"), j("5")), "negative zero is not a time");
    }

    @Test void preStateCountsReservedAndCommittedOnly() {
        List<Object> history = IntentJs.arr(j("[{\"verb\":\"shop.buy\",\"params\":{\"total\":5},\"t\":1,\"status\":\"committed\"},"
                + "{\"verb\":\"shop.buy\",\"params\":{\"total\":9},\"t\":2,\"status\":\"reserved\"},"
                + "{\"verb\":\"shop.buy\",\"params\":{\"total\":100},\"t\":3,\"status\":\"released\"},"
                + "{\"verb\":\"shop.other\",\"params\":{\"total\":1000},\"t\":4,\"status\":\"committed\"}]"));
        Map<String, Object> a = m(SUM);
        Map<String, Object> pre = IntentHistory.accPreState(a, history, m("{\"total\":2}"), j("10"), null);
        assertEquals("{\"sum\":14}", Json.canonicalize(pre));
        assertEquals(Long.valueOf(16), IntentHistory.accPost(a, history, "shop.buy", m("{\"total\":2}"), j("10"), null));
        assertEquals(Long.valueOf(14), IntentHistory.accPost(a, history, "shop.other", m("{\"total\":2}"), j("10"), null), "an unselected verb leaves the value");
        assertNull(IntentHistory.accPreState(a, history, m("{\"total\":2}"), j("1.5"), null), "a non-integer candidate time throws in the reference");
    }

    @Test void accumulatorKeys() {
        Map<String, Object> grouped = m(SUM.replace("\"key\":null", "\"key\":\"action.params.payee\""));
        assertEquals("•", IntentHistory.accKeyOf(m(SUM), m("{}")));
        assertEquals("\"p1\"", IntentHistory.accKeyOf(grouped, m("{\"payee\":\"p1\"}")));
        assertEquals("7", IntentHistory.accKeyOf(grouped, m("{\"payee\":7}")));
        assertNull(IntentHistory.accKeyOf(grouped, m("{}")));
        assertNull(IntentHistory.accKeyOf(grouped, m("{\"payee\":1.5}")));
    }

    static final String VERIFY = "{\"id\":\"m\",\"kind\":\"requires_prior\",\"p\":{\"verb\":\"shop.verify\",\"resource\":\"*\"},\"q\":{\"verb\":\"shop.buy\",\"resource\":\"*\"}}";

    @Test void monitorFolds() {
        Map<String, Object> m = m(VERIFY);
        assertEquals("unmet", IntentHistory.monitorState(m, new ArrayList<Object>()));
        assertEquals("met", IntentHistory.monitorState(m, IntentJs.arr(j("[{\"verb\":\"shop.verify\",\"resource\":\"r\",\"params\":{},\"status\":\"committed\"}]"))));
        assertEquals("unmet", IntentHistory.monitorState(m, IntentJs.arr(j("[{\"verb\":\"shop.verify\",\"resource\":\"r\",\"params\":{},\"status\":\"released\"}]"))), "a released event does not count");
        Map<String, Object> never = m(VERIFY.replace("requires_prior", "never"));
        assertEquals("clean", IntentHistory.monitorState(never, new ArrayList<Object>()));
        assertEquals("seen", IntentHistory.monitorState(never, IntentJs.arr(j("[{\"verb\":\"shop.verify\",\"resource\":\"r\",\"params\":{},\"status\":\"reserved\"}]"))));
        Map<String, Object> committedOnly = m(VERIFY.replace("requires_prior", "never").replace("\"id\":\"m\"", "\"id\":\"m\",\"status\":\"committed\""));
        assertEquals("clean", IntentHistory.monitorState(committedOnly, IntentJs.arr(j("[{\"verb\":\"shop.verify\",\"resource\":\"r\",\"params\":{},\"status\":\"reserved\"}]"))), "status committed ignores reservations");
        Map<String, Object> always = m(VERIFY.replace("requires_prior", "always"));
        assertEquals("ok", IntentHistory.monitorState(always, new ArrayList<Object>()));
        assertEquals("broken", IntentHistory.monitorState(always, IntentJs.arr(j("[{\"verb\":\"shop.buy\",\"resource\":\"r\",\"params\":{},\"status\":\"committed\"}]"))));
    }

    @Test void respondsWithinCountsDown() {
        Map<String, Object> m = m("{\"id\":\"m\",\"kind\":\"responds_within\",\"within\":2,\"p\":{\"verb\":\"shop.verify\",\"resource\":\"*\"},\"q\":{\"verb\":\"shop.buy\",\"resource\":\"*\"}}");
        Map<String, Object> verify = m("{\"verb\":\"shop.verify\",\"resource\":\"r\",\"params\":{},\"status\":\"committed\"}");
        Map<String, Object> other = m("{\"verb\":\"shop.other\",\"resource\":\"r\",\"params\":{},\"status\":\"committed\"}");
        Map<String, Object> buy = m("{\"verb\":\"shop.buy\",\"resource\":\"r\",\"params\":{},\"status\":\"committed\"}");
        assertEquals("pending:2", IntentHistory.monitorStep(m, "idle", verify));
        assertEquals("pending:1", IntentHistory.monitorStep(m, "pending:2", other));
        assertEquals("missed", IntentHistory.monitorStep(m, "pending:1", other));
        assertEquals("idle", IntentHistory.monitorStep(m, "pending:2", buy));
        assertEquals("missed", IntentHistory.monitorStep(m, "missed", buy));
        assertEquals("idle", IntentHistory.monitorStep(m, "idle", other));
    }
}
