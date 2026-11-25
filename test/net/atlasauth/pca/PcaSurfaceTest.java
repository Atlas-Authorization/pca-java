package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The small public helpers and constants of the core package that mirror the reference's hash / wire exports. */
public class PcaSurfaceTest {
    @Test void hashSuites() {
        assertEquals("sha256", Pca.DEFAULT_HASH_SUITE);
        assertTrue(Pca.isHashSuite("sha384"));
        assertFalse(Pca.isHashSuite("sha512"));
        assertFalse(Pca.isHashSuite(null));
        byte[] in = "abc".getBytes(StandardCharsets.UTF_8);
        assertEquals(32, Pca.hashWithSuite(in, null).length);
        assertEquals(48, Pca.hashWithSuite(in, "sha384").length);
        assertArrayEquals(Pca.sha(in), Pca.hashWithSuite(in, "sha256"));
        assertThrows(IllegalArgumentException.class, () -> Pca.hashWithSuite(in, "md5"));
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("a", 1L);
        assertEquals(Pca.hashCanonical(v), Pca.hashCanonical(v, null));
        assertEquals(Pca.b64(Pca.hashWithSuite(Pca.canonicalBytesStrict(v), "sha384")), Pca.hashCanonical(v, "sha384"));
        assertEquals(32, Pca.HASH_LEN.get("sha256"));
    }

    @Test void base64urlHelpers() {
        assertEquals(43, Pca.b64uLen(32));
        assertEquals(86, Pca.b64uLen(64));
        assertTrue(Pca.isCanonicalB64u(Pca.b64(new byte[32]), 32));
        assertFalse(Pca.isCanonicalB64u(Pca.b64(new byte[32]), 33));
        assertFalse(Pca.isCanonicalB64u("AB=="));
        assertFalse(Pca.isCanonicalB64u(7));
        assertArrayEquals(new byte[] {1, 2, 3}, Pca.decodeKey(Pca.encodeKey(new byte[] {1, 2, 3})));
        assertArrayEquals(new byte[] {9}, Pca.decodeSig(Pca.encodeSig(new byte[] {9})));
    }

    @Test void strictNumbers() {
        assertNull(Pca.strictNumberError(1.5));
        assertNull(Pca.strictNumberError(42));
        assertNotNull(Pca.strictNumberError(0.1 + 0.2));
        assertNotNull(Pca.strictNumberError(1e-7));
        assertNotNull(Pca.strictNumberError(-0.0));
        assertNotNull(Pca.strictNumberError(Double.NaN));
        assertNotNull(Pca.strictNumberError(9007199254740993.0));
        assertNull(Pca.strictNumberError(0.000001));
    }

    @Test void lenientVersusStrict() {
        assertEquals(Pca.hashCanonicalLenient(Map.of("a", 1L)), Pca.b64(Pca.sha(Pca.canonicalBytesLenient(Map.of("a", 1L)))));
        assertEquals("{\"a\":1}", Pca.canonicalizeLenientServerOnly(Map.of("a", 1L)));
    }

    @Test void wireConstants() {
        assertEquals(2, Pca.PCACTN_WIRE_VERSION);
        assertEquals(14, Pca.PCACTN_REQUIRED_FIELDS.size());
        assertTrue(Pca.PCACTN_OPTIONAL_FIELDS.contains("pq_sig"));
        assertEquals(1_200_000L, Pca.PCACTN_DEFAULT_TTL_MS);
        assertEquals(60_000L, Pca.DEFAULT_FRESHNESS_EPOCH_MS);
        assertEquals("reversible", Pca.DEFAULT_REVERSIBILITY_CLASS);
        assertEquals(Pca.paramsDigest(new LinkedHashMap<String, Object>()), Pca.EMPTY_PARAMS_DIGEST);
    }

    @Test void requiredCheckProfiles() {
        assertEquals(7, Authorize.STATEFUL_REQUIRED_CHECKS.size());
        assertEquals(6, Authorize.STATELESS_REQUIRED_CHECKS.size());
        assertFalse(Authorize.STATELESS_REQUIRED_CHECKS.contains("replay"));
        assertTrue(Authorize.STATEFUL_REQUIRED_CHECKS.containsAll(Authorize.STATELESS_REQUIRED_CHECKS));
        assertTrue(Authorize.EXECUTION_REQUIRED_CHECKS.containsAll(Authorize.STATEFUL_REQUIRED_CHECKS));
        assertTrue(Authorize.EXECUTION_REQUIRED_CHECKS.contains("params_digest") && Authorize.EXECUTION_REQUIRED_CHECKS.contains("policy"));
        assertTrue(Authorize.DEFAULT_REQUIRED_CHECKS.containsAll(Authorize.EXECUTION_REQUIRED_CHECKS));
        assertEquals(java.util.List.of(), Authorize.missingExecutionComponents("rs", new Object(), null, new Object(), new Object()));
        assertEquals(java.util.List.of("audience", "grant or resolveGrant", "state", "isRevoked"), Authorize.missingExecutionComponents("", null, null, null, null));
    }

    @Test void enforceRequiredIsDefaultDeny() {
        Pca.Verdict v = new Pca.Verdict();
        v.allow = true;
        v.checks.put("audience", true);
        v.checks.put("validity", true);
        Authorize.enforceRequired(v, java.util.List.of("audience", "validity", "revocation"));
        assertFalse(v.allow);
        assertEquals(false, v.checks.get("revocation"));
        assertEquals("revocation: required check is absent (default-deny: not enforced by this resource server)", v.reason);
        Pca.Verdict ok = new Pca.Verdict();
        ok.allow = true;
        ok.checks.put("replay", true);
        ok.checks.put("audience", true);
        assertTrue(Authorize.enforceRequired(ok, java.util.List.of("counter", "audience")).allow, "counter is the old name of replay");
        Pca.Verdict failed = new Pca.Verdict();
        failed.allow = true;
        failed.checks.put("audience", false);
        assertFalse(Authorize.enforceRequired(failed, java.util.List.of("audience")).allow);
    }

    @Test void packageConstantsMatchTheReference() {
        assertEquals(1, ActionSchema.ACTION_DEF_VERSION);
        assertEquals(java.util.List.of("string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref"), ActionSchema.PARAM_TYPES_V1);
        assertEquals(java.util.List.of("free", "material", "critical"), ActionSchema.SENSITIVITY_LEVELS);
        assertEquals(2, ActionSchema.SENSITIVITY_RANK.get("critical"));
        assertTrue(ActionSchema.TAINT_CONTEXT_RE.matcher("session_taint_max:web").matches());
        assertFalse(ActionSchema.TAINT_CONTEXT_RE.matcher("session_taint_max:Web1").matches());
        assertEquals(3, Actions.ESC_MAX);
        assertEquals("pca.", Actions.CORE_NAMESPACE);
        assertEquals(net.atlasauth.pca.pqthreshold.PqThreshold.PQ_QUORUM_ALG, net.atlasauth.pca.pqthreshold.PqThreshold.HYBRID_PQ_ALG);
        assertEquals(net.atlasauth.pca.pqthreshold.PqThreshold.MAX_PQ_QUORUM_ENTRIES, net.atlasauth.pca.pqthreshold.PqThreshold.MAX_PQ_SIGNER_ENTRIES);
        assertEquals(1.0, net.atlasauth.pca.wallet.WalletNoise.NOISE_PRIOR.get("a"));
        assertEquals(9.0, net.atlasauth.pca.wallet.WalletNoise.NOISE_PRIOR.get("b"));
    }

    @Test void calibrateStepsSizesAgainstTheAdversary() {
        long[] ticks = {0L, 100_000_000L}; // 100 ms for the sample
        int[] i = {0};
        net.atlasauth.pca.vdf.Timelock.Calibration c = net.atlasauth.pca.vdf.Timelock.calibrateSteps(java.math.BigInteger.valueOf(1000003), 2.0, 50_000, null, () -> ticks[i[0]++ % 2]);
        assertEquals(500_000.0, c.measuredSquaringsPerSecond, 1e-6);
        assertEquals(5_000_000.0, c.assumedAdversarySquaringsPerSecond, 1e-6);
        assertEquals(10_000_000L, c.steps);
        assertThrows(IllegalArgumentException.class, () -> net.atlasauth.pca.vdf.Timelock.calibrateSteps(java.math.BigInteger.valueOf(3), 1, null, null, null));
        assertThrows(IllegalArgumentException.class, () -> net.atlasauth.pca.vdf.Timelock.calibrateSteps(java.math.BigInteger.valueOf(101), 0, null, null, null));
        assertThrows(IllegalArgumentException.class, () -> net.atlasauth.pca.vdf.Timelock.calibrateSteps(java.math.BigInteger.valueOf(101), 1, 0, null, null));
        assertThrows(IllegalArgumentException.class, () -> net.atlasauth.pca.vdf.Timelock.calibrateSteps(java.math.BigInteger.valueOf(101), 1, null, 0.5, null));
    }

    @Test void refreshAssuranceFollowsTheChecks() {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("audience", new LinkedHashMap<>(Map.of("outcome", "pass", "level", "software")));
        report.put("zk", new LinkedHashMap<>(Map.of("outcome", "unsupported")));
        report.put("replay", new LinkedHashMap<>(Map.of("outcome", "fail")));
        Map<String, String> checks = new LinkedHashMap<>();
        checks.put("audience", "fail");
        checks.put("zk", "pass");
        checks.put("replay", "pass");
        checks.put("new_check", "pass");
        checks.put("other", "not-enforced");
        Assurance.refreshAssurance(report, checks);
        assertEquals(Map.of("outcome", "fail"), report.get("audience"), "a check that is no longer pass loses its level");
        assertEquals(Map.of("outcome", "unsupported"), report.get("zk"), "unsupported stays");
        assertEquals(Map.of("outcome", "pass"), report.get("replay"));
        assertEquals(Map.of("outcome", "pass"), report.get("new_check"));
        assertEquals(Map.of("outcome", "not-enforced"), report.get("other"));
        Map<String, Object> keep = new LinkedHashMap<>();
        keep.put("a", new LinkedHashMap<>(Map.of("outcome", "pass", "level", "hardware")));
        Assurance.refreshAssurance(keep, Map.of("a", "pass"));
        assertEquals("hardware", ((Map<?, ?>) keep.get("a")).get("level"), "a still-passing check keeps its level");
    }

    @Test void emptyAggregateStateIsZero() {
        Map<String, Object> s = ReadVault.emptyAggregateState();
        assertEquals(0L, s.get("spent_micro"));
        assertEquals(0L, s.get("queries"));
        assertTrue(((Map<?, ?>) s.get("answered")).isEmpty());
    }

    @Test void coreTraitDefsAreTheRegistry() {
        assertEquals(Actions.CORE_REGISTRY.traits.size(), Actions.CORE_TRAIT_DEFS.size());
        assertTrue(((Map<?, ?>) Actions.CORE_TRAIT_DEFS.get(0)).get("id").toString().startsWith(Actions.CORE_NAMESPACE));
        assertNull(net.atlasauth.pca.actions.ActionBuiltin.builtinReleaseCtx(), "no release attestation is carried");
    }
}
