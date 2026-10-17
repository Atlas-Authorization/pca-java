package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.Test;

/**
 * 0.4.2 mutation kills for Pca.java: the intent-policy threshold parse and validity rule (both sides of every bound), the
 * fail-closed text of an intent binding fault, the 0.4.2 root PQ pin-vs-stored-grant agreement (each conjunct alone), and
 * the wire check that keeps validating after a well-formed {@code intent_session}.
 */
public class K042WbPcaMiscPcaTest {
    static final double MAX_SAFE = 9007199254740991.0;

    @Test
    void thresholdParse() {
        Pca.IntentPolicy p = Pca.IntentPolicy.fromJson(Map.of("min_fidelity_ppm", new Json.Num("950000.0"), "max_residual_risk_ppm", new Json.Num("1e3")));
        assertEquals(950000.0, p.minFidelityPpm);
        assertEquals(1000.0, p.maxResidualRiskPpm);
        assertTrue(p.isActive());
        assertFalse(p.require);
        // a Json.Num whose raw text is not a number: set and invalid (NaN), so the policy fails closed
        Pca.IntentPolicy bad = Pca.IntentPolicy.fromJson(Map.of("min_fidelity_ppm", new Json.Num("abc")));
        assertNotNull(bad.minFidelityPpm);
        assertTrue(bad.minFidelityPpm.isNaN());
        assertNull(bad.maxResidualRiskPpm);
        assertEquals("intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)",
            Pca.decideIntent(null, false, Map.of(), bad));
        Pca.IntentPolicy badMax = Pca.IntentPolicy.fromJson(Map.of("max_residual_risk_ppm", new Json.Num("--1")));
        assertTrue(badMax.maxResidualRiskPpm.isNaN());
        // plain Java numbers and non-numbers
        assertEquals(5.0, Pca.IntentPolicy.fromJson(Map.of("min_fidelity_ppm", 5L)).minFidelityPpm);
        assertTrue(Pca.IntentPolicy.fromJson(Map.of("min_fidelity_ppm", "5")).minFidelityPpm.isNaN());
        assertEquals(0.0, Pca.IntentPolicy.fromJsonText("{\"min_fidelity_ppm\": 0}").minFidelityPpm);
        assertEquals(7.0, Pca.IntentPolicy.fromJsonText("{\"max_residual_risk_ppm\": 7}").maxResidualRiskPpm);
    }

    @Test
    void okThresholdEveryBound() {
        assertTrue(Pca.okThreshold(null));
        assertTrue(Pca.okThreshold(0.0));
        assertTrue(Pca.okThreshold(1.0));
        assertTrue(Pca.okThreshold(950000.0));
        assertTrue(Pca.okThreshold(MAX_SAFE));
        assertFalse(Pca.okThreshold(MAX_SAFE + 1));
        assertFalse(Pca.okThreshold(Double.NaN));
        assertFalse(Pca.okThreshold(Double.POSITIVE_INFINITY));
        assertFalse(Pca.okThreshold(Double.NEGATIVE_INFINITY));
        assertFalse(Pca.okThreshold(1.5));
        assertFalse(Pca.okThreshold(0.5));
        assertFalse(Pca.okThreshold(-1.0));
        assertFalse(Pca.okThreshold(-0.0));
        assertFalse(Pca.okThreshold(Double.MAX_VALUE));
    }

    @Test
    void intentBindingFaultIsFailClosedWithTheExceptionClass() {
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("type", "envelope");
        envelope.put("goal_commit", "x");
        Map<String, Object> grant = new LinkedHashMap<>();
        grant.put("caveats", List.of(envelope));
        // an intent slot that is not an object (only reachable when wire validation is bypassed): a ClassCastException
        assertEquals("intent binding error (fail closed): ClassCastException", Pca.decideIntent("not-an-object", true, grant, null));
        assertEquals("intent binding error (fail closed): ClassCastException", Pca.decideIntent(7L, true, grant, Pca.IntentPolicy.required()));
        Map<String, Object> slot = new LinkedHashMap<>();
        slot.put("ref", 1L);
        assertEquals("intent binding error (fail closed): ClassCastException", Pca.decideIntent(slot, true, grant, null));
    }

    // ---------------------------------------------------------------- 0.4.2 root PQ: pin vs stored grant

    @Test
    void rootPqPinAndStoredGrant() throws Exception {
        String issuer = PqChainTest.pub("principal"), agent = PqChainTest.pub("agent");
        for (String alg : new String[] {"ml-dsa-65", "hybrid-ed25519-ml-dsa-65"}) {
            AsymmetricCipherKeyPair k = PqChainTest.pqKey();
            Map<String, Object> root = PqChainTest.cap(issuer, agent, new ArrayList<>(), null, "principal", alg, k, null);
            List<Object> chain = new ArrayList<>(List.of(root));
            String mismatch = "hop 0: root suite '" + alg + "': the server-side PQ pin for the root issuer (policy.pqPins) does not match the stored grant's pq_pk (fail closed)";
            // stored grant + a pin map WITHOUT the issuer: the grant vouches
            Map<String, Object> otherOnly = new LinkedHashMap<>();
            otherOnly.put(agent, PqChainTest.pk(PqChainTest.pqKey()));
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, otherOnly, root), alg);
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, new LinkedHashMap<>(), root), alg);
            // stored grant + null pins
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, null, root), alg);
            // stored grant + agreeing pin
            Map<String, Object> agree = new LinkedHashMap<>();
            agree.put(issuer, PqChainTest.pk(k));
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, agree, root), alg);
            // stored grant + disagreeing pin (and one that is not a string)
            Map<String, Object> disagree = new LinkedHashMap<>();
            disagree.put(issuer, PqChainTest.pk(PqChainTest.pqKey()));
            assertEquals(mismatch, Pca.verifyChain(chain, issuer, true, null, disagree, root), alg);
            Map<String, Object> nonString = new LinkedHashMap<>();
            nonString.put(issuer, 5L);
            assertEquals(mismatch, Pca.verifyChain(chain, issuer, true, null, nonString, root), alg);
            // no stored grant: the pin alone decides (a disagreeing pin is the generic refusal, not the mismatch)
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, agree, null), alg);
            assertEquals(PqChainTest.refusal(alg), Pca.verifyChain(chain, issuer, true, null, disagree, null), alg);
            // a stored grant that is a different capability does not count as the stored grant (no mismatch either)
            Map<String, Object> other = PqChainTest.cap(issuer, agent, new ArrayList<>(List.of(Map.of("type", "x"))), null, "principal", alg, k, null);
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, agree, other), alg);
            assertEquals(PqChainTest.refusal(alg), Pca.verifyChain(chain, issuer, true, null, disagree, other), alg);
        }
    }

    // ---------------------------------------------------------------- wire: validation continues after intent_session

    @Test
    void wireKeepsValidatingAfterAWellFormedIntentSession() throws Exception {
        String d = "A".repeat(43);
        Map<String, Object> is = new LinkedHashMap<>();
        is.put("session", d);
        is.put("root", d);
        is.put("seq", 0L);
        is.put("schema", d);
        Map<String, Object> p = PcaUnitTest.valid();
        p.put("intent_session", is);
        assertNull(Pca.validateWireV2(p));
        Map<String, Object> pe = new LinkedHashMap<>(p);
        pe.put("prohibition_evidence", 5L);
        assertEquals("'prohibition_evidence' must be an object or array", Pca.validateWireV2(pe));
        Map<String, Object> th = new LinkedHashMap<>(p);
        th.put("threshold", "x");
        assertEquals("'threshold' must be {shares:[...]}", Pca.validateWireV2(th));
        // and a malformed intent_session is reported as such
        Map<String, Object> bad = new LinkedHashMap<>(p);
        Map<String, Object> is2 = new LinkedHashMap<>(is);
        is2.remove("seq");
        bad.put("intent_session", is2);
        assertEquals("missing field 'intent_session.seq'", Pca.validateWireV2(bad));
    }
}
