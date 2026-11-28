package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.ciba.CibaApproval;
import net.atlasauth.pca.ciba.CibaStoreConformance;
import net.atlasauth.pca.conformance.Conformance;
import net.atlasauth.pca.intent.IntentLayers;
import net.atlasauth.pca.intent.IntentMapAttestation;
import net.atlasauth.pca.research.Immune;
import org.junit.jupiter.api.Test;

/** The small public helpers and constants ported from the reference's single-purpose modules (capability, threshold, beacons, intent, ...). */
class SiblingPortsTest {
    @Test void budgetAllocCaveatBuildsWhatTheDetectorAccepts() {
        assertEquals("budget_alloc", Pca.BUDGET_ALLOC_CAVEAT);
        Map<String, Object> cv = Pca.budgetAllocCaveat(12.5);
        assertEquals("budget_alloc", cv.get("type"));
        assertTrue(Pca.isBudgetAllocCaveat(cv));
        assertFalse(Pca.isBudgetAllocCaveat(Pca.budgetAllocCaveat(-1)));
        assertEquals("{\"limit\":12.5,\"type\":\"budget_alloc\"}", Json.canonicalize(cv));
    }

    @Test void constantsAndSmallHelpers() {
        assertEquals(List.of(1, 2, 3), Threshold.VALID_THRESHOLDS);
        assertEquals(1, PolicyAuthoring.TEMPLATE_VERSION);
        assertEquals(1_000 + 2_000 + 60_000, IntentRevocation.revocationExposureEnd(1_000, 2_000), 0);
        assertEquals(1_000 + 2_000 + 5, IntentRevocation.revocationExposureEnd(1_000, 2_000, 5), 0);
        assertEquals(2L, OracleFacts.lowerMedian(List.of(9L, 1L, 2L, 3L)));
        assertEquals(5L, OracleFacts.lowerMedian(List.of(5L)));
        assertThrows(IllegalArgumentException.class, () -> OracleFacts.lowerMedian(List.of()));
        assertEquals(402, (int) net.atlasauth.pca.acp.X402Http.X402_HTTP_STATUS.get("payment_required"));
        assertEquals(200, (int) net.atlasauth.pca.acp.X402Http.X402_HTTP_STATUS.get("settled"));
        assertEquals("/.well-known/pca-actions.json", ActionSchema.WELL_KNOWN_PCA_ACTIONS_PATH);
        assertEquals(8, ActionSchema.SCHEMA_V2_CAVEATS.size());
        assertEquals(8, ActionSchema.SCHEMA_V2_PRULES.size());
        assertEquals(6, ActionSchema.SCHEMA_V2_CONTEXT.size());
        assertEquals(List.of("first_party", "tool", "agent"), ActionSchema.SCHEMA_V2_PROVENANCE);
        assertEquals("0.3", Json.canonicalize(Immune.DEFAULT_IMMUNE_CONFIG.get("alpha")));
        assertEquals("0.4", Json.canonicalize(Immune.DEFAULT_ADAPT_CONFIG.get("minThetaMult")));
    }

    @Test void mcpHintsGiveALowerBoundOnly() {
        Map<String, Object> ro = new LinkedHashMap<>();
        ro.put("readOnlyHint", true);
        assertEquals("{\"atLeast\":\"reversible\",\"kind\":\"read\"}", Json.canonicalize(ActionSchema.reversibilityFromMcpHints(ro)));
        Map<String, Object> destructive = new LinkedHashMap<>();
        destructive.put("destructiveHint", true);
        assertEquals("{\"atLeast\":\"rate_limited\",\"kind\":\"write\"}", Json.canonicalize(ActionSchema.reversibilityFromMcpHints(destructive)));
        assertEquals("{\"atLeast\":\"reversible\",\"kind\":\"write\"}", Json.canonicalize(ActionSchema.reversibilityFromMcpHints(null)));
        Map<String, Object> both = new LinkedHashMap<>(ro);
        both.put("destructiveHint", true);
        assertEquals("read", ActionSchema.reversibilityFromMcpHints(both).get("kind"));
    }

    @Test void layerPolicyAndLabelKeyShapes() {
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("predicates", new ArrayList<>());
        assertTrue(IntentLayers.isLayerPolicy(ok));
        assertFalse(IntentLayers.isLayerPolicy(null));
        assertFalse(IntentLayers.isLayerPolicy(new LinkedHashMap<>()));
        assertFalse(IntentLayers.isLayerPolicy(Issue.obj("predicates", "x")));
        assertFalse(IntentLayers.isLayerPolicy(Issue.obj("predicates", new ArrayList<>(), "extra", 1L)));
        Map<String, Object> key = Issue.obj("site", "s", "kid", "k1", "pk", Pca.b64(new byte[32]));
        assertTrue(ParamProvenance.isLabelKey(key));
        assertFalse(ParamProvenance.isLabelKey(Issue.obj("site", "s", "kid", "k1")));
        assertFalse(ParamProvenance.isLabelKey(Issue.obj("site", "s", "kid", "k1", "pk", Pca.b64(new byte[32]), "pq_pk", "")));
        assertFalse(ParamProvenance.isLabelKey(Issue.obj("site", "s", "kid", "k1", "pk", Pca.b64(new byte[32]), "x", "y")));
    }

    @Test void deriveWithoutAGrantIsATypedRefusal() {
        DecideInputGrantRequired e = assertThrows(DecideInputGrantRequired.class, () -> Decide.deriveDecideInput(new LinkedHashMap<>(), new LinkedHashMap<>()));
        assertEquals("grant_required", e.code);
        assertTrue(e instanceof IllegalArgumentException);
    }

    @Test void conformanceFirstFailedCheckFollowsInsertionOrder() {
        Map<String, String> checks = new LinkedHashMap<>();
        assertNull(Conformance.firstFailedCheck(checks));
        checks.put("wire", "pass");
        checks.put("audience", "not-enforced");
        assertNull(Conformance.firstFailedCheck(checks));
        checks.put("validity", "fail");
        checks.put("cap_chain", "fail");
        assertEquals("validity", Conformance.firstFailedCheck(checks));
    }

    @Test void beaconsAcceptOnlyAStrictlyHigherSeq() {
        Map<String, Object> five = BeaconTest.good();
        Map<String, Object> six = BeaconTest.beacon("inst", "*", 6, BeaconTest.ISSUED, BeaconTest.ISSUED + 300_000L, BeaconTest.ISSUER);
        assertNull(Beacons.accept(null, five));
        assertNull(Beacons.accept(five, six));
        assertEquals("replayed beacon: seq 5 <= 6", Beacons.accept(six, five));
        assertEquals("replayed beacon: seq 5 <= 5", Beacons.accept(five, five));
        assertEquals("malformed beacon", Beacons.accept(null, null));
        assertEquals("malformed beacon", Beacons.accept(null, Issue.obj("seq", "5")));
        assertEquals("malformed beacon", Beacons.accept(null, Issue.obj("seq", IntentJs.ofLong(-1))));
    }

    @Test void frozenUnlessSomeBeaconVerifies() {
        List<String> issuers = List.of(BeaconTest.ISSUER.id());
        assertTrue(Beacons.isFrozen(List.of(), issuers, BeaconTest.NOW, "inst", null, null));
        assertTrue(Beacons.isFrozen(null, issuers, BeaconTest.NOW, "inst", null, null));
        assertFalse(Beacons.isFrozen(List.of(BeaconTest.good()), issuers, BeaconTest.NOW, "inst", null, null));
        assertTrue(Beacons.isFrozen(List.of(BeaconTest.good()), issuers, BeaconTest.NOW, "other", null, null));
    }

    @Test void theDurableAcceptorKeepsTheHighestSeqAndFailsClosed() {
        List<String> issuers = List.of(BeaconTest.ISSUER.id());
        MemoryAtomicKv kv = new MemoryAtomicKv();
        Beacons.Acceptor acc = new Beacons.Acceptor(kv);
        Map<String, Object> five = BeaconTest.good();
        Map<String, Object> six = BeaconTest.beacon("inst", "*", 6, BeaconTest.ISSUED, BeaconTest.ISSUED + 300_000L, BeaconTest.ISSUER);
        assertNull(acc.accept(five, issuers, BeaconTest.NOW, "inst", null, null));
        assertEquals("replayed beacon: seq 5 <= 5", acc.accept(five, issuers, BeaconTest.NOW, "inst", null, null));
        assertNull(acc.accept(six, issuers, BeaconTest.NOW, "inst", null, null));
        assertEquals("replayed beacon: seq 5 <= 6", acc.accept(five, issuers, BeaconTest.NOW, "inst", null, null));
        assertEquals("wrong instance", acc.accept(five, issuers, BeaconTest.NOW, "other", null, null));
        // a restart over the same store still refuses the old beacon
        assertEquals("replayed beacon: seq 5 <= 6", new Beacons.Acceptor(kv).accept(five, issuers, BeaconTest.NOW, "inst", null, null));
        // junk in the store refuses (fail closed) rather than accepting
        MemoryAtomicKv junk = new MemoryAtomicKv();
        junk.set("beacon-seq/v1/" + Json.canonicalize(List.of("inst", "*", BeaconTest.ISSUER.id())), "garbage");
        assertEquals("beacon state unavailable", new Beacons.Acceptor(junk).accept(five, issuers, BeaconTest.NOW, "inst", null, null));
        assertThrows(IllegalArgumentException.class, () -> new Beacons.Acceptor(null));
    }

    private static Map<String, Object> intentMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", IntentJs.ofLong(1));
        m.put("kind", "pca-intent-map");
        m.put("intent_ref", null);
        m.put("metrics", Issue.obj("fidelity_est_ppm", IntentJs.ofLong(990_000), "residual_risk_ppm", IntentJs.ofLong(7)));
        return m;
    }

    @Test void mapAttestationRoundTripAndRefusals() {
        Keys.EdKey signer = Keys.edGenerate();
        Map<String, Object> map = intentMap();
        Map<String, Object> att = IntentMapAttestation.signIntentMapAttestation(map, signer.seed, 1_700_000_000_000L);
        assertEquals(signer.id(), att.get("signer"));
        assertEquals(Boolean.TRUE, IntentMapAttestation.verifyIntentMapAttestation(att).get("ok"));
        assertEquals(Boolean.TRUE, IntentMapAttestation.verifyIntentMapAttestation(att, true, map, signer.id(), null).get("ok"));
        assertEquals("signer mismatch", IntentMapAttestation.verifyIntentMapAttestation(att, false, null, Keys.edGenerate().id(), null).get("reason"));
        Map<String, Object> other = intentMap();
        other.put("metrics", Issue.obj("fidelity_est_ppm", IntentJs.ofLong(1), "residual_risk_ppm", IntentJs.ofLong(7)));
        assertEquals("map digest mismatch", IntentMapAttestation.verifyIntentMapAttestation(att, true, other, null, null).get("reason"));
        Map<String, Object> forged = new LinkedHashMap<>(att);
        forged.put("signed_at", IntentJs.ofLong(1_700_000_000_001L));
        assertEquals("bad signature", IntentMapAttestation.verifyIntentMapAttestation(forged).get("reason"));
        Map<String, Object> pq = new LinkedHashMap<>(att);
        pq.put("pq_pk", "x");
        assertEquals("an ed25519 artifact must not carry pq_pk / pq_sig", IntentMapAttestation.verifyIntentMapAttestation(pq).get("reason"));
        assertEquals("not an intent map attestation v1", IntentMapAttestation.verifyIntentMapAttestation("x").get("reason"));
        Map<String, Object> bad = intentMap();
        bad.remove("intent_ref");
        assertThrows(IllegalArgumentException.class, () -> IntentMapAttestation.signIntentMapAttestation(bad, signer.seed, 1L));
        assertThrows(IllegalArgumentException.class, () -> IntentMapAttestation.signIntentMapAttestation(map, signer.seed, -1L));
        assertNotNull(IntentMapAttestation.intentMapShapeError(null));
    }

    @Test void theFrozenSnapshotCannotBeChanged() {
        Map<String, Object> in = new LinkedHashMap<>();
        in.put("now", IntentJs.ofLong(5));
        in.put("list", new ArrayList<Object>(List.of("a")));
        Map<String, Object> frozen = OptimisticAdjudication.freezeOpenSnapshot(in);
        assertEquals(Json.canonicalize(in), Json.canonicalize(frozen));
        assertThrows(UnsupportedOperationException.class, () -> frozen.put("x", 1L));
        assertThrows(UnsupportedOperationException.class, () -> ((List<Object>) frozen.get("list")).add("b"));
        in.put("now", IntentJs.ofLong(6));
        assertEquals("5", Json.canonicalize(frozen.get("now")));
        assertNull(OptimisticAdjudication.fileFraudProof(Issue.obj("pcactn_digest", "d"), new LinkedHashMap<>(), new LinkedHashMap<>(), null, null));
    }

    @Test void theApprovalStoreAndBrokerConformanceCasesPassOnTheReferenceStore() throws Exception {
        for (CibaStoreConformance.Case c : CibaStoreConformance.approvalStoreCases(CibaApproval::createMemoryApprovalStore, null)) c.run.run();
        for (CibaStoreConformance.Case c : CibaStoreConformance.approvalBrokerCases(CibaApproval::createMemoryApprovalStore)) c.run.run();
    }
}
