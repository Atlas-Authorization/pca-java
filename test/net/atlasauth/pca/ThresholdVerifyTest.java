package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The t-of-n threshold verifier and its hook ({@link Threshold#verifyThreshold}, {@link Threshold#createThresholdVerifier}) end to end: a real
 * PCActn, real role keys, shares signed with {@link Threshold#signShare}. Pins the reference's reasons and its security properties: the agent
 * leaf signature is the effective-t=1 baseline, a bare agent share and a share bound to another signer set or threshold never count, one key
 * counts once, and a malformed signer set fails closed.
 */
class ThresholdVerifyTest {
    static final Keys.SuiteKey AGENT = AuthorizeBaseKillTest.AGENT, GUARDIAN = AuthorizeBaseKillTest.key(41), PRINCIPAL = AuthorizeBaseKillTest.key(42);

    static Map<String, Object> entry(String role, Keys.SuiteKey k) { return Issue.obj("role", role, "publicKey", k.id()); }

    static List<Object> signerSet() {
        List<Object> s = new ArrayList<>();
        s.add(entry("agent", AGENT));
        s.add(entry("guardian", GUARDIAN));
        s.add(entry("principal", PRINCIPAL));
        return s;
    }

    static Map<String, Object> pcactn() { return AuthorizeBaseKillTest.pcactn(); }

    static Map<String, Object> baseline(Map<String, Object> p) {
        List<?> chain = (List<?>) p.get("cap_chain");
        Map<String, Object> leaf = (Map<String, Object>) chain.get(chain.size() - 1);
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("holder", leaf.get("holder"));
        b.put("sig", p.get("sig"));
        return b;
    }

    static Map<String, Object> shares(Object... s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("shares", Threshold.assembleThreshold(List.of(s)).get("shares"));
        return m;
    }

    @Test void theAgentLeafSignatureIsTheEffectiveT1Baseline() {
        Map<String, Object> p = pcactn();
        byte[] msg = Pca.thresholdMessage(p);
        Map<String, Object> v = Threshold.verifyThreshold(shares(), msg, signerSet(), IntentJs.ofLong(1), baseline(p));
        assertEquals(Boolean.TRUE, v.get("ok"), v.toString());
        assertEquals(1, v.get("count"));
        assertEquals(List.of("agent"), v.get("roles"));
        // without the baseline there is nothing to count
        Map<String, Object> none = Threshold.verifyThreshold(shares(), msg, signerSet(), IntentJs.ofLong(1), null);
        assertEquals(Boolean.FALSE, none.get("ok"));
        assertEquals("only 0 distinct valid key(s), need 1", none.get("reason"));
        // a baseline for a message it did not sign does not count
        byte[] other = Pca.thresholdMessage(AuthorizeBaseKillTest.GRANT);
        assertEquals(Boolean.FALSE, Threshold.verifyThreshold(shares(), other, signerSet(), IntentJs.ofLong(1), baseline(p)).get("ok"));
    }

    @Test void aGuardianShareLiftsTheBaselineToTwoAndABareAgentShareNeverCounts() {
        Map<String, Object> p = pcactn();
        byte[] msg = Pca.thresholdMessage(p);
        List<Object> set = signerSet();
        Map<String, Object> g = Threshold.signShare("guardian", GUARDIAN, msg, set, 2);
        Map<String, Object> ok = Threshold.verifyThreshold(shares(g), msg, set, IntentJs.ofLong(2), baseline(p));
        assertEquals(Boolean.TRUE, ok.get("ok"), ok.toString());
        assertEquals(List.of("guardian", "agent"), ok.get("roles"));
        Map<String, Object> short1 = Threshold.verifyThreshold(shares(), msg, set, IntentJs.ofLong(2), baseline(p));
        assertEquals("only 1 distinct valid key(s), need 2", short1.get("reason"));
        // the old bare agent share (signed over the message itself) is rejected: shares sign the role / set / t-bound bytes
        Map<String, Object> bare = Threshold.signPreparedShare("agent", AGENT, msg);
        Map<String, Object> r = Threshold.verifyThreshold(shares(bare), msg, set, IntentJs.ofLong(1), null);
        assertEquals(Boolean.FALSE, r.get("ok"));
        assertEquals("invalid signature for role agent", r.get("reason"));
    }

    @Test void aShareIsBoundToItsSignerSetAndItsThreshold() {
        Map<String, Object> p = pcactn();
        byte[] msg = Pca.thresholdMessage(p);
        List<Object> set = signerSet();
        Map<String, Object> g2 = Threshold.signShare("guardian", GUARDIAN, msg, set, 2);
        Map<String, Object> at3 = Threshold.verifyThreshold(shares(g2), msg, set, IntentJs.ofLong(3), baseline(p));
        assertEquals(Boolean.FALSE, at3.get("ok"));
        assertEquals("invalid signature for role guardian", at3.get("reason"));
        List<Object> other = signerSet();
        other.add(entry("guardian", GUARDIAN)); // a duplicate entry changes the signer-set hash
        assertEquals(Boolean.FALSE, Threshold.verifyThreshold(shares(g2), msg, other, IntentJs.ofLong(2), baseline(p)).get("ok"));
        // a role's share under another role's key
        Map<String, Object> wrong = Threshold.signShare("principal", GUARDIAN, msg, set, 2);
        assertEquals("share for role principal uses a key not registered for that role", Threshold.verifyThreshold(shares(wrong), msg, set, IntentJs.ofLong(2), null).get("reason"));
    }

    @Test void oneKeyCountsOnceAndAllThreeRolesMakeThree() {
        Map<String, Object> p = pcactn();
        byte[] msg = Pca.thresholdMessage(p);
        List<Object> set = signerSet();
        Map<String, Object> g = Threshold.signShare("guardian", GUARDIAN, msg, set, 3), pr = Threshold.signShare("principal", PRINCIPAL, msg, set, 3);
        Map<String, Object> dup = Threshold.verifyThreshold(shares(g, g), msg, set, IntentJs.ofLong(3), baseline(p));
        assertEquals(Boolean.FALSE, dup.get("ok"));
        assertEquals(2, dup.get("count"));
        Map<String, Object> all = Threshold.verifyThreshold(shares(g, pr), msg, set, IntentJs.ofLong(3), baseline(p));
        assertEquals(Boolean.TRUE, all.get("ok"), all.toString());
        assertEquals(3, all.get("count"));
        Map<String, Object> unknown = Issue.obj("role", "root", "publicKey", GUARDIAN.id(), "sig", "AAAA");
        assertEquals("role root is not in the signer set", Threshold.verifyThreshold(shares(unknown), msg, set, IntentJs.ofLong(1), null).get("reason"));
        assertEquals("malformed share", Threshold.verifyThreshold(shares("x"), msg, set, IntentJs.ofLong(1), null).get("reason"));
    }

    @Test void aMalformedSignerSetOrThresholdFailsClosed() {
        Map<String, Object> p = pcactn();
        byte[] msg = Pca.thresholdMessage(p);
        // a role not yet registered over a key that already has one (a role already registered with another key is refused first, as the reference orders it)
        List<Object> twoRoles = new ArrayList<>();
        twoRoles.add(entry("guardian", GUARDIAN));
        twoRoles.add(entry("principal", GUARDIAN));
        assertEquals("signer set registers one key under two roles", Threshold.verifyThreshold(shares(), msg, twoRoles, IntentJs.ofLong(1), baseline(p)).get("reason"));
        List<Object> twoKeys = signerSet();
        twoKeys.add(entry("guardian", PRINCIPAL));
        assertEquals("signer set registers more than one key for role guardian", Threshold.verifyThreshold(shares(), msg, twoKeys, IntentJs.ofLong(1), baseline(p)).get("reason"));
        List<Object> bad = signerSet();
        bad.add(Issue.obj("role", "boss", "publicKey", GUARDIAN.id()));
        assertEquals("malformed signer set", Threshold.verifyThreshold(shares(), msg, bad, IntentJs.ofLong(1), baseline(p)).get("reason"));
        assertEquals("malformed signer set", Threshold.verifyThreshold(shares(), msg, List.of("x"), IntentJs.ofLong(1), baseline(p)).get("reason"));
        List<Object> badPq = signerSet();
        ((Map<String, Object>) badPq.get(1)).put("pq_pk", "AAAA");
        assertEquals("malformed signer set (pq_pk)", Threshold.verifyThreshold(shares(), msg, badPq, IntentJs.ofLong(1), baseline(p)).get("reason"));
        for (Object t : new Object[] {IntentJs.ofLong(0), IntentJs.ofLong(4), "2", null, new ArrayList<>(), new LinkedHashMap<>()}) {
            Map<String, Object> v = Threshold.verifyThreshold(shares(), msg, signerSet(), t, baseline(p));
            assertEquals(Boolean.FALSE, v.get("ok"));
            assertTrue(((String) v.get("reason")).startsWith("invalid threshold t="), String.valueOf(v.get("reason")));
        }
        assertEquals("invalid threshold t=<array> (must be 1, 2 or 3)", Threshold.verifyThreshold(shares(), msg, signerSet(), new ArrayList<>(), null).get("reason"));
        assertEquals("invalid threshold t=<object> (must be 1, 2 or 3)", Threshold.verifyThreshold(shares(), msg, signerSet(), new LinkedHashMap<>(), null).get("reason"));
    }

    @Test void theHookEnforcesTheServersTAndReportsIt() throws Exception {
        List<Object> set = signerSet();
        Map<String, Object> p = new LinkedHashMap<>(pcactn());
        byte[] msg = Pca.thresholdMessage(p); // `threshold` and `sig` are not signed
        Map<String, Object> g = Threshold.signShare("guardian", GUARDIAN, msg, set, 2);
        Map<String, Object> carried = new LinkedHashMap<>();
        carried.put("shares", new ArrayList<Object>(List.of(g)));
        p.put("threshold", carried);
        PcaCore.Ctx ctx = new PcaCore.Ctx(p, AuthorizeBaseKillTest.GRANT, AuthorizeBaseKillTest.NOW);

        PcaCore.HookResult two = Threshold.createThresholdVerifier(set, 2).run(ctx);
        assertTrue(two.enforced && two.ok, String.valueOf(two.reason));
        assertEquals(2.0, two.t);
        PcaCore.HookResult three = Threshold.createThresholdVerifier(set, 3).run(ctx);
        assertTrue(three.enforced);
        assertFalse(three.ok);
        assertEquals("invalid signature for role guardian", three.reason); // the share is bound to t=2: under t=3 it does not verify
        assertEquals(3.0, three.t);
        // t from server-held data, per call
        PcaCore.HookResult derived = Threshold.createThresholdVerifier(set, null, c -> 2, null).run(ctx);
        assertTrue(derived.ok);
        // the label reports how the keys are held
        PcaCore.Hook frost = Threshold.createThresholdVerifier(set, 2, null, "frost");
        Assurance.Label label = Assurance.labelOf(frost);
        assertNotNull(label);
        assertEquals("frost", label.level);
        assertTrue(label.awaitingAudit);
        assertEquals("multisig", Assurance.labelOf(Threshold.createThresholdVerifier(set, 2)).level);
        assertFalse(Assurance.labelOf(Threshold.createThresholdVerifier(set, 2)).awaitingAudit);
        // the set is snapshotted: editing it afterwards changes nothing
        PcaCore.Hook snap = Threshold.createThresholdVerifier(set, 2);
        set.clear();
        assertTrue(snap.run(ctx).ok);
        // exactly one of t / requiredT is mandatory: there is no default derived from the agent's own risk claim
        assertThrows(IllegalArgumentException.class, () -> Threshold.createThresholdVerifier(signerSet(), null, null, null));
    }
}
