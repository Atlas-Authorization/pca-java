package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The attestation and zk verifier hooks of the core verifier ({@link Pca#verifyPcactn} with hooks) and of {@link Authorize}. A carried
 * zk_compliance proof is verified when a zk hook enforces it and is REFUSED otherwise (no hook, or a hook that did not enforce): the
 * fail-closed default. The PCActn, grant and statement are the reference's (ref-zk, case createZkVerifier/ok).
 */
class VerifierHooksTest {
    private static Map<String, Object> spec, pcactn, grant, plain;
    private static long now;
    private static String aud;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @BeforeAll static void load() throws Exception {
        for (Map<String, Object> c : OracleCases.of("ref-zk", "createZkVerifier")) {
            if (!"createZkVerifier/ok".equals(c.get("name"))) continue;
            List<?> a = (List<?>) c.get("args");
            spec = m(a.get(0));
            Map<String, Object> ctx = m(a.get(1));
            pcactn = m(ctx.get("pcactn"));
            grant = m(ctx.get("grant"));
        }
        now = Json.asLong(spec.get("nowMs"));
        aud = (String) pcactn.get("aud");
        plain = new LinkedHashMap<>(pcactn);
        plain.remove("zk_compliance");
    }

    private static Pca.Verdict core(Map<String, Object> p, PcaCore.Hook att, PcaCore.Hook zk) {
        return Pca.verifyPcactn(p, grant, now, aud, null, null, null, null, Pca.PlanRoots.SKIP, att, zk);
    }

    @SuppressWarnings("unchecked")
    private static Zk.ZkVerifier zkHook(boolean trusted, long clock) {
        Zk.VerifierOpts o = new Zk.VerifierOpts();
        o.trustedProverKeys = trusted ? (List<String>) spec.get("trustedProverKeys") : new ArrayList<>();
        o.policyCommitments = (List<String>) spec.get("policyCommitments");
        o.now = () -> clock;
        return Zk.createZkVerifier(o);
    }

    @Test void aCarriedProofWithNoZkHookIsRefused() {
        Pca.Verdict v = core(pcactn, null, null);
        assertFalse(v.allow);
        assertEquals(Boolean.FALSE, v.checks.get("zk_compliance"));
    }

    @Test void aHookThatDoesNotEnforceIsRefusedLikeNoHook() {
        for (PcaCore.Hook h : new PcaCore.Hook[] { ctx -> PcaCore.HookResult.notEnforced(), ctx -> null }) {
            Pca.Verdict v = core(pcactn, null, h);
            assertFalse(v.allow);
            assertEquals(Boolean.FALSE, v.checks.get("zk_compliance"));
        }
    }

    @Test void theZkVerifierHookPassesTheCheckForAValidStatement() {
        List<PcaCore.Ctx> seen = new ArrayList<>();
        Zk.ZkVerifier inner = zkHook(true, now);
        Pca.Verdict v = core(pcactn, null, ctx -> { seen.add(ctx); return inner.run(ctx); });
        assertEquals(Boolean.TRUE, v.checks.get("zk_compliance"));
        assertEquals(1, seen.size());
        assertEquals(now, seen.get(0).nowEpoch);
        assertTrue(seen.get(0).grant == grant);
        assertTrue(seen.get(0).pcactn.containsKey("zk_compliance"));
    }

    @Test void theZkVerifierHookFailsTheCheckForARejectedStatement() {
        assertEquals(Boolean.FALSE, core(pcactn, null, zkHook(false, now)).checks.get("zk_compliance"));
        assertEquals(Boolean.FALSE, core(pcactn, null, zkHook(true, now + 1_000_000_000L)).checks.get("zk_compliance"));
        Map<String, Object> tampered = new LinkedHashMap<>(pcactn);
        Map<String, Object> zk = new LinkedHashMap<>(m(pcactn.get("zk_compliance")));
        zk.put("plan_commit", "AAAA");
        tampered.put("zk_compliance", zk);
        assertEquals(Boolean.FALSE, core(tampered, null, zkHook(true, now)).checks.get("zk_compliance"));
    }

    @Test void anEnforcedRefusalWithoutAReasonAndAThrowingHookBothDeny() {
        assertEquals(Boolean.FALSE, core(pcactn, null, ctx -> PcaCore.HookResult.enforced(false)).checks.get("zk_compliance"));
        Pca.Verdict v = core(pcactn, null, ctx -> { throw new IllegalStateException("verifier down"); });
        assertFalse(v.allow);
        assertFalse(Boolean.TRUE.equals(v.checks.get("zk_compliance")));
        assertEquals(Boolean.FALSE, v.checks.get("malformed"));
    }

    @Test void noCarriedProofMeansNoZkCheckAndTheHookIsNotCalled() {
        List<PcaCore.Ctx> called = new ArrayList<>();
        Pca.Verdict v = core(plain, null, ctx -> { called.add(ctx); return PcaCore.HookResult.enforced(true); });
        assertFalse(v.checks.containsKey("zk_compliance"));
        assertTrue(called.isEmpty());
        assertEquals(core(plain, null, null).checks, v.checks);
    }

    @Test void theAttestationHookPassesFailsOrStaysUnreported() {
        assertEquals(Boolean.TRUE, core(plain, ctx -> PcaCore.HookResult.enforced(true), null).checks.get("attestation"));
        Pca.Verdict v = core(plain, ctx -> PcaCore.HookResult.enforced(false, "measurement not allowlisted", null), null);
        assertFalse(v.allow);
        assertEquals(Boolean.FALSE, v.checks.get("attestation"));
        assertFalse(core(plain, ctx -> PcaCore.HookResult.notEnforced(), null).checks.containsKey("attestation"));
        assertFalse(core(plain, null, null).checks.containsKey("attestation"));
        List<PcaCore.Ctx> seen = new ArrayList<>();
        core(plain, ctx -> { seen.add(ctx); return PcaCore.HookResult.notEnforced(); }, null);
        assertEquals(1, seen.size());
        assertEquals(now, seen.get(0).nowEpoch);
    }

    @Test void aPassingAttestationHookAloneChangesOnlyThatCheck() {
        Pca.Verdict base = core(plain, null, null), with = core(plain, ctx -> PcaCore.HookResult.enforced(true), null);
        Map<String, Boolean> rest = new LinkedHashMap<>(with.checks);
        rest.remove("attestation");
        assertEquals(base.checks, rest);
        assertEquals(base.allow, with.allow);
    }

    @Test void authorizeTakesAndForwardsBothHooks() {
        PcaCore.Hook h = ctx -> PcaCore.HookResult.notEnforced();
        Authorize.Input in = new Authorize.Input().attestationHook(h).zkHook(h);
        assertTrue(in.attestationHook == h && in.zkHook == h);
        Authorize.Options o = new Authorize.Options(new MemoryStateStore(), (p, g) -> false).withAttestationHook(h).withZkHook(h);
        assertTrue(o.attestationHook == h && o.zkHook == h);
        assertNull(new Authorize.Input().attestationHook);
    }
}
