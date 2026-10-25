package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.junit.jupiter.api.Test;

/** Positive and negative chains whose root / hops are signed under ML-DSA-65 and the hybrid suite (pins, trusted root, holder_pq binding). */
public class PqChainTest {
    static AsymmetricCipherKeyPair pqKey() {
        MLDSAKeyPairGenerator g = new MLDSAKeyPairGenerator();
        g.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_65));
        return g.generateKeyPair();
    }
    static String pk(AsymmetricCipherKeyPair k) { return Pca.b64(((MLDSAPublicKeyParameters) k.getPublic()).getEncoded()); }
    static String pqSign(AsymmetricCipherKeyPair k, byte[] msg) {
        MLDSASigner s = new MLDSASigner();
        s.init(true, k.getPrivate());
        s.update(msg, 0, msg.length);
        try { return Pca.b64(s.generateSignature()); } catch (Exception e) { throw new RuntimeException(e); }
    }
    @SuppressWarnings("unchecked")
    static byte[] seed(String name) throws Exception {
        Map<String, Object> keys = ReasonSnapshot.loadJson("keys.json");
        return Pca.decodeB64uStrict(((Map<String, Object>) keys.get(name)).get("seed"), 32);
    }
    @SuppressWarnings("unchecked")
    static String pub(String name) throws Exception {
        Map<String, Object> keys = ReasonSnapshot.loadJson("keys.json");
        return (String) ((Map<String, Object>) keys.get(name)).get("public");
    }
    static String edSign(String keyName, byte[] msg) throws Exception {
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(seed(keyName), 0, msg, 0, msg.length, sig, 0);
        return Pca.b64(sig);
    }

    /** Builds a capability signed by signerKey (ed25519 name) and, for PQ suites, by pqk. alg null => ed25519. */
    static Map<String, Object> cap(String issuerPub, String holderPub, List<Object> caveats, String parent, String signerEd,
                                   String alg, AsymmetricCipherKeyPair pqk, String holderPq) throws Exception {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("issuer", issuerPub); c.put("holder", holderPub); c.put("caveats", caveats);
        if (parent != null) c.put("parent", parent);
        if (holderPq != null) c.put("holder_pq", holderPq);
        if (alg != null) { c.put("alg", alg); c.put("pq_pk", pk(pqk)); }
        Map<String, Object> body = Pca.signableHopBody(c);
        String digest = Pca.hashCanonical(body);
        byte[] msg = Pca.concat(Pca.CAP_DOMAIN, Pca.decodeB64uStrict(digest, 32));
        Map<String, Object> out = new LinkedHashMap<>(c);
        out.put("id", digest); out.put("body_digest", digest);
        if (alg == null) out.put("sig", edSign(signerEd, msg));
        else if (alg.equals("ml-dsa-65")) out.put("sig", pqSign(pqk, msg));
        else { out.put("sig", edSign(signerEd, msg)); out.put("pq_sig", pqSign(pqk, msg)); }
        return out;
    }
    static String refusal(String alg) {
        return "hop 0: root suite '" + alg + "' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier's stored grant (policy.trustedRoot); the root's own pq_pk proves nothing about who issued it (R3-01)";
    }

    @Test void pqRoots() throws Exception {
        String issuer = pub("principal"), agent = pub("agent");
        for (String alg : new String[] {"ml-dsa-65", "hybrid-ed25519-ml-dsa-65"}) {
            AsymmetricCipherKeyPair k = pqKey();
            Map<String, Object> root = cap(issuer, agent, new ArrayList<>(), null, "principal", alg, k, null);
            List<Object> chain = new ArrayList<>(List.of(root));
            Map<String, Object> pins = new LinkedHashMap<>(); pins.put(issuer, pk(k));
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, pins, null), alg + " pinned");
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, null, root), alg + " trusted root");
            // 0.4.2: trusted root AND a pin for the issuer must agree (the stored grant never overrides a disagreeing pin)
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, pins, root), alg + " trusted root + agreeing pin");
            Map<String, Object> wrongWithRoot = new LinkedHashMap<>(); wrongWithRoot.put(issuer, pk(pqKey()));
            assertEquals("hop 0: root suite '" + alg + "': the server-side PQ pin for the root issuer (policy.pqPins) does not match the stored grant's pq_pk (fail closed)",
                Pca.verifyChain(chain, issuer, true, null, wrongWithRoot, root), alg + " trusted root + wrong pin");
            assertEquals("", Pca.verifyChain(chain, null, false, null, pins, null));
            assertEquals(refusal(alg), Pca.verifyChain(chain, issuer, true, null, null, null));
            Map<String, Object> wrongPin = new LinkedHashMap<>(); wrongPin.put(issuer, pk(pqKey()));
            assertEquals(refusal(alg), Pca.verifyChain(chain, issuer, true, null, wrongPin, null));
            // a pin keyed by another identity does not vouch
            Map<String, Object> otherPin = new LinkedHashMap<>(); otherPin.put(agent, pk(k));
            assertEquals(refusal(alg), Pca.verifyChain(chain, issuer, true, null, otherPin, null));
            // a trusted root that is a DIFFERENT capability does not vouch
            Map<String, Object> other = cap(issuer, agent, new ArrayList<>(List.of(Map.of("type", "x"))), null, "principal", alg, k, null);
            assertEquals(refusal(alg), Pca.verifyChain(chain, issuer, true, null, null, other));
            // tampered signature: pinned but the signature is wrong
            Map<String, Object> bad = new LinkedHashMap<>(root);
            bad.put(alg.equals("ml-dsa-65") ? "sig" : "pq_sig", pqSign(pqKey(), new byte[] {1}));
            assertEquals("hop 0: bad signature (not signed by expected key)", Pca.verifyChain(new ArrayList<>(List.of(bad)), issuer, true, null, pins, null));
            if (alg.startsWith("hybrid")) {
                Map<String, Object> badEd = new LinkedHashMap<>(root);
                badEd.put("sig", edSign("agent", new byte[] {1}));
                assertEquals("hop 0: bad signature (not signed by expected key)", Pca.verifyChain(new ArrayList<>(List.of(badEd)), issuer, true, null, pins, null));
            }
            // suite policy
            assertEquals("hop 0: signature suite is not allowed by this verifier's suite policy", Pca.verifyChain(chain, issuer, true, List.of("ed25519"), pins, null));
            assertEquals("", Pca.verifyChain(chain, issuer, true, List.of(alg), pins, null));
        }
    }

    @Test void pqHops() throws Exception {
        String issuer = pub("principal"), agent = pub("agent"), sub = pub("subagent");
        for (String alg : new String[] {"ml-dsa-65", "hybrid-ed25519-ml-dsa-65"}) {
            AsymmetricCipherKeyPair hk = pqKey();
            Map<String, Object> root = cap(issuer, agent, new ArrayList<>(), null, "principal", null, null, Pca.holderPqCommitment(pk(hk)));
            Map<String, Object> hop = cap(agent, sub, new ArrayList<>(), Pca.capHash(root), "agent", alg, hk, null);
            List<Object> chain = new ArrayList<>(List.of(root, hop));
            assertEquals("", Pca.verifyChain(chain, issuer, true, null), alg + " bound hop");
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, null, root));
            // a pin for the PARENT's holder must equal the hop key only when pinned; the policy passes when no pin exists
            // attacker key not committed by the parent's holder_pq
            Map<String, Object> evil = cap(agent, sub, new ArrayList<>(), Pca.capHash(root), "agent", alg, pqKey(), null);
            assertEquals("hop 1: pq_pk does not match the signer's committed holder_pq (F-2)", Pca.verifyChain(new ArrayList<>(List.of(root, evil)), issuer, true, null));
            // bad PQ signature under the committed key
            Map<String, Object> bad = new LinkedHashMap<>(hop);
            bad.put(alg.equals("ml-dsa-65") ? "sig" : "pq_sig", pqSign(hk, new byte[] {7}));
            assertEquals("hop 1: bad signature (not signed by expected key)", Pca.verifyChain(new ArrayList<>(List.of(root, bad)), issuer, true, null));
            // root without holder_pq: unbound PQ hop refused
            Map<String, Object> root2 = cap(issuer, agent, new ArrayList<>(), null, "principal", null, null, null);
            Map<String, Object> hop2 = cap(agent, sub, new ArrayList<>(), Pca.capHash(root2), "agent", alg, hk, null);
            assertTrue(Pca.verifyChain(new ArrayList<>(List.of(root2, hop2)), issuer, true, null).startsWith("hop 1: suite '" + alg + "' needs a PQ key bound"));
            // an explicit pin for the parent's holder overrides the holder_pq path: right pin passes, wrong pin refuses
            Map<String, Object> pinOk = new LinkedHashMap<>(); pinOk.put(agent, pk(hk));
            // (hop keys resolve with no pins at non-root hops; pins apply to the root only)
            assertEquals("", Pca.verifyChain(chain, issuer, true, null, pinOk, null));
        }
    }

    @Test void hybridShare() throws Exception {
        AsymmetricCipherKeyPair k = pqKey();
        String edPub = pub("agent");
        List<Object> set = new ArrayList<>(List.of(PcaUnitTest.map("publicKey", edPub, "role", "agent", "pq_pk", pk(k))));
        byte[] tm = new byte[] {4, 5, 6};
        byte[] msg = Threshold.shareMessage("agent", tm, set, 3, "hybrid-ed25519-ml-dsa-65", true);
        Map<String, Object> share = PcaUnitTest.map("role", "agent", "publicKey", edPub, "alg", "hybrid-ed25519-ml-dsa-65", "pq_pk", pk(k),
            "sig", edSign("agent", msg), "pq_sig", pqSign(k, msg));
        assertTrue(Threshold.verifyShare("agent", tm, set, 3, share));
        Map<String, Object> noPqSig = new LinkedHashMap<>(share); noPqSig.remove("pq_sig");
        assertFalse(Threshold.verifyShare("agent", tm, set, 3, noPqSig));
        Map<String, Object> badSig = new LinkedHashMap<>(share); badSig.put("sig", edSign("principal", msg));
        assertFalse(Threshold.verifyShare("agent", tm, set, 3, badSig));
        Map<String, Object> wrongPk = new LinkedHashMap<>(share); wrongPk.put("pq_pk", pk(pqKey()));
        assertFalse(Threshold.verifyShare("agent", tm, set, 3, wrongPk));
        Map<String, Object> noEd = new LinkedHashMap<>(share); noEd.put("publicKey", pub("principal"));
        assertFalse(Threshold.verifyShare("agent", tm, set, 3, noEd));
    }

    @Test void signerSetRegistry() throws Exception {
        String edPub = pub("agent"), other = pub("principal");
        byte[] tm = new byte[] {8, 8};
        List<Object> set = new ArrayList<>(List.of(PcaUnitTest.map("publicKey", edPub, "role", "agent")));
        byte[] msg = Threshold.shareMessage("agent", tm, set, 1, null, false);
        Map<String, Object> share = PcaUnitTest.map("role", "agent", "publicKey", edPub, "sig", edSign("agent", msg));
        assertTrue(Threshold.verifyShare("agent", tm, set, 1, share));
        // explicit ed25519 alg is accepted; a pq_pk naming a key its role does not register is refused (any suite, d00dba73)
        Map<String, Object> explicit = new LinkedHashMap<>(share); explicit.put("alg", "ed25519");
        assertTrue(Threshold.verifyShare("agent", tm, set, 1, explicit));
        explicit.put("pq_pk", "ignored");
        assertFalse(Threshold.verifyShare("agent", tm, set, 1, explicit));
        // R6-03: a share without a string role is malformed (reference wellFormed), refused
        Map<String, Object> noRole = new LinkedHashMap<>(share); noRole.remove("role");
        assertFalse(Threshold.verifyShare("agent", tm, set, 1, noRole));
        // a share naming another role is refused even though the key is registered for `role`
        Map<String, Object> wrongRole = new LinkedHashMap<>(share); wrongRole.put("role", "guardian");
        assertFalse(Threshold.verifyShare("agent", tm, set, 1, wrongRole));
        // two keys registered for one role: refused (the signature is over the set including both)
        List<Object> two = new ArrayList<>(List.of(PcaUnitTest.map("publicKey", edPub, "role", "agent"), PcaUnitTest.map("publicKey", other, "role", "agent")));
        byte[] m2 = Threshold.shareMessage("agent", tm, two, 1, null, false);
        assertFalse(Threshold.verifyShare("agent", tm, two, 1, PcaUnitTest.map("role", "agent", "publicKey", edPub, "sig", edSign("agent", m2))));
        // ... including when the share is for the LAST registered key (only the duplicate-key rule can refuse it)
        assertFalse(Threshold.verifyShare("agent", tm, two, 1, PcaUnitTest.map("role", "agent", "publicKey", other, "sig", edSign("principal", m2))));
        // the same key registered twice for one role is not a conflict
        List<Object> same = new ArrayList<>(List.of(PcaUnitTest.map("publicKey", edPub, "role", "agent"), PcaUnitTest.map("publicKey", edPub, "role", "agent")));
        byte[] m4 = Threshold.shareMessage("agent", tm, same, 1, null, false);
        assertTrue(Threshold.verifyShare("agent", tm, same, 1, PcaUnitTest.map("role", "agent", "publicKey", edPub, "sig", edSign("agent", m4))));
        // one key registered under two roles: refused
        List<Object> dual = new ArrayList<>(List.of(PcaUnitTest.map("publicKey", edPub, "role", "agent"), PcaUnitTest.map("publicKey", edPub, "role", "guardian")));
        byte[] m3 = Threshold.shareMessage("agent", tm, dual, 1, null, false);
        assertFalse(Threshold.verifyShare("agent", tm, dual, 1, PcaUnitTest.map("role", "agent", "publicKey", edPub, "sig", edSign("agent", m3))));
        // unregistered key / unregistered role
        assertFalse(Threshold.verifyShare("agent", tm, set, 1, PcaUnitTest.map("role", "agent", "publicKey", other, "sig", edSign("principal", msg))));
        assertFalse(Threshold.verifyShare("guardian", tm, set, 1, PcaUnitTest.map("publicKey", edPub, "sig", edSign("agent", msg))));
    }
}
