package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import org.junit.jupiter.api.Test;

/** The pipeline and grants parity audit items: each case pins the reference file named beside it. */
public class K05ParityAuditTest {
    static final long NOW = AuthorizeK05KillTest.NOW;
    static final Keys.EdKey OPERATOR = Keys.edGenerate();

    static Map<String, Object> agentSigned(Object... extra) {
        Map<String, Object> p = new LinkedHashMap<>(AuthorizeK05KillTest.pcactn());
        p.remove("sig");
        for (int i = 0; i < extra.length; i += 2) p.put((String) extra[i], extra[i + 1]);
        byte[] seed = new byte[32];
        Arrays.fill(seed, (byte) 32);
        p.put("sig", Pca.b64(Keys.edFromSeed(seed).sign(Pca.thresholdMessage(p))));
        return p;
    }

    static Authorize.Input input() { return AuthorizeK05KillTest.input(Issue.obj("amount", 50L)); }

    // ---- A: pcactn.ts:549-555, server/verify.ts:531

    static final String BOND_REFUSED = "bond: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)";

    @Test void aRequiredBondStaysRefusedThoughAllowUnsupportedNamesIt() {
        Authorize.AuthorizeResult r = Authorize.authorize(agentSigned("bond_ref", "b"), input().allowUnsupported(List.of("bond")).require("bond"));
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("deny", r.decision);
        assertEquals("fail", r.checks.get("bond"));
    }

    @Test void aCarriedBondDeniesAndKeepsTheCounter() {
        assertTrue(Authorize.authorize(AuthorizeK05KillTest.pcactn(), input()).allow, "control");
        Map<String, Object> p = agentSigned("bond_ref", "b");
        MemoryStateStore store = new MemoryStateStore();
        Authorize.AuthorizeResult r = Authorize.authorize(p, input().stateStore(store));
        assertFalse(r.allow, r.reasons.toString());
        assertEquals("unsupported", r.checks.get("bond"));
        assertEquals(List.of(BOND_REFUSED), r.reasons);
        assertFalse(Authorize.authorize(p, input().stateStore(store).allowUnsupported(List.of("other"))).allow, "another name does not allow it");
        Authorize.AuthorizeResult ok = Authorize.authorize(p, input().stateStore(store).allowUnsupported(List.of("bond")));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("unsupported", ok.checks.get("bond"));
        assertNull(Authorize.authorize(AuthorizeK05KillTest.pcactn(), input()).checks.get("bond"), "no member, no check");
    }

    // ---- B: capability.ts:174-193, run by the chain check

    static String chainWith(Map<?, ?>... caveats) {
        List<Object> cavs = new ArrayList<>(Arrays.asList((Object[]) caveats));
        Map<String, Object> root = Issue.mintRoot(AuthorizeK05KillTest.PRINCIPAL, AuthorizeK05KillTest.AGENT.id(), null, cavs);
        return Pca.verifyChain(List.of((Object) root), AuthorizeK05KillTest.PRINCIPAL.id(), true, null);
    }

    static Map<String, Object> alloc(Object limit) { return Issue.obj("type", "budget_alloc", "limit", limit); }

    @Test void budgetAllocationsNeverWiden() {
        assertEquals("", chainWith());
        assertEquals("", chainWith(alloc(10L), alloc(10L), alloc(4L), alloc(0L)));
        assertEquals("budget_alloc caveat 1: allocation 100 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)",
            chainWith(alloc(10L), alloc(100L)));
        assertEquals("budget_alloc caveat 2: allocation 6 widens the parent's carried allocation 5 (monotone: a child can only allocate <= its parent)",
            chainWith(alloc(5L), Issue.obj("type", "note"), alloc(6L)), "other caveats are skipped and keep their index");
        assertEquals("budget_alloc caveat 0: limit must be a finite number >= 0", chainWith(alloc(-1L)));
        assertEquals("budget_alloc caveat 1: limit must be a finite number >= 0", chainWith(alloc(1L), alloc("3")));
    }

    // ---- C: pcactn.ts:835-841

    @Test void theCoreRefusesACarriedZkProof() {
        Map<String, Object> p = agentSigned("zk_compliance", new LinkedHashMap<String, Object>());
        Pca.Verdict v = Pca.verifyPcactn(p, AuthorizeK05KillTest.GRANT, NOW, AuthorizeK05KillTest.AUD, null, null, null, null, Pca.PlanRoots.SKIP);
        assertFalse(v.allow);
        assertEquals(Boolean.FALSE, v.checks.get("zk_compliance"));
        assertEquals("zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof", v.reason);
        Pca.Verdict plain = Pca.verifyPcactn(AuthorizeK05KillTest.pcactn(), AuthorizeK05KillTest.GRANT, NOW, AuthorizeK05KillTest.AUD, null, null, null, null, Pca.PlanRoots.SKIP);
        assertTrue(plain.allow, plain.reason);
        assertFalse(plain.checks.containsKey("zk_compliance"));
        Authorize.AuthorizeResult r = Authorize.authorize(p, input());
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("zk_compliance"));
        assertEquals(List.of(v.reason), r.reasons);
    }

    // ---- D: require-pca.ts:292

    @Test void guardOptionsForwardTheSuitePolicy() {
        Authorize.Options plain = new Authorize.Options(new MemoryStateStore(), (p, g) -> false, Authorize.SINGLE_STEP, null, null).withRisk(RiskCtx.ZERO);
        Authorize.Options none = plain.withAllowedSuites(List.of("ml-dsa-65"));
        assertEquals(List.of("ml-dsa-65"), none.withUndo(null).allowedSuites, "a later copy keeps it");
        assertNull(plain.allowedSuites);
    }

    // ---- F: blueprint.ts:86-92, 202-205

    static Map<String, Object> blueprint(Object... extra) {
        Map<String, Object> b = Issue.obj("v", 1L, "id", "bp", "key", "bp-key", "ceiling", new ArrayList<Object>(), "epoch", 1L, "status", "active",
            "issued_at", 1L, "operator", OPERATOR.id());
        for (int i = 0; i < extra.length; i += 2) b.put((String) extra[i], extra[i + 1]);
        return signedBlueprint(b);
    }

    static Map<String, Object> signedBlueprint(Map<String, Object> b) {
        b.remove("sig");
        b.put("sig", Issue.signBody(OPERATOR, Blueprint.DOMAIN, new LinkedHashMap<>(b)));
        return b;
    }

    static List<Object> pins(Object... pins) { return new ArrayList<>(Arrays.asList(pins)); }

    static final List<Object> CHAIN = pins(Issue.obj("issuer", "root", "holder", "bp-key"), Issue.obj("issuer", "bp-key", "holder", "instance"));

    static String gate(Map<String, Object> b, String mode) {
        Blueprint.Registry reg = new Blueprint.Registry(List.of(OPERATOR.id()), new MemoryAtomicKv());
        assertNull(reg.accept(b).code);
        return Blueprint.check(CHAIN, reg, NOW, mode, null).code;
    }

    @Test void aPinnedBlueprintDeniesAndNeverFallsThrough() {
        List<Object> ok = pins(Issue.obj("model_id", "m"));
        assertNull(gate(blueprint(), "any"), "control");
        assertEquals("admission_required", gate(blueprint("runtime_pins", ok), "any"));
        assertEquals("admission_required", gate(blueprint("runtime_pins", ok), "require"));
        Blueprint.Registry reg = new Blueprint.Registry(List.of(OPERATOR.id()), new MemoryAtomicKv());
        reg.accept(blueprint("runtime_pins", ok));
        assertEquals("bp", Blueprint.check(CHAIN, reg, NOW, "any", null).blueprint);
        // a group kill, an expiry and a depth cap come first
        assertEquals("blueprint_disabled", gate(blueprint("runtime_pins", ok, "status", "disabled"), "any"));
        assertEquals("blueprint_expired", gate(blueprint("runtime_pins", ok, "expires_at", 1L), "any"));
        // the ceiling comes after it
        assertEquals("admission_required", gate(blueprint("runtime_pins", ok, "ceiling", pins(Issue.obj("type", "x"))), "any"));
    }

    @Test void pinShapes() {
        String s256 = String.join("", Collections.nCopies(256, "x"));
        Map<String, Object> all = Issue.obj("runtime_measurement", "a", "model_id", "b", "weights_digest", "c", "operator", "d", "spiffe_id", s256);
        List<Object> sixteen = new ArrayList<>(Collections.nCopies(16, Issue.obj("model_id", "m")));
        assertTrue(Blueprint.verify(blueprint("runtime_pins", pins(all))));
        assertTrue(Blueprint.verify(blueprint("runtime_pins", sixteen)));
        List<Object> seventeen = new ArrayList<>(sixteen);
        seventeen.add(Issue.obj("model_id", "m"));
        Object[] bad = {null, "x", pins(), seventeen, pins("x"), pins(Issue.obj()), pins(Issue.obj("other", "x")), pins(Issue.obj("model_id", 1L)),
            pins(Issue.obj("model_id", "")), pins(Issue.obj("model_id", s256 + "x"))};
        Blueprint.Registry reg = new Blueprint.Registry(List.of(OPERATOR.id()), new MemoryAtomicKv());
        for (Object b : bad) {
            Map<String, Object> rec = Issue.obj("v", 1L, "id", "bp", "key", "bp-key", "ceiling", new ArrayList<Object>(), "epoch", 1L, "status", "active",
                "issued_at", 1L, "operator", OPERATOR.id(), "runtime_pins", b, "sig", "x".repeat(86));
            assertFalse(Blueprint.wellFormed(rec), String.valueOf(b));
            assertEquals("bad_record", reg.accept(rec).code);
        }
        // the pins are signed: dropping them breaks the record
        Map<String, Object> stripped = new LinkedHashMap<>(blueprint("runtime_pins", pins(Issue.obj("model_id", "m"))));
        stripped.remove("runtime_pins");
        assertEquals("bad_record", reg.accept(stripped).code);
    }

    // ---- G: one atomic update per registry

    /** A record that notes whether its reader holds the registry's lock. */
    static final class LockProbe extends LinkedHashMap<String, Object> {
        Object lock;
        boolean locked;

        @Override public Object get(Object k) {
            locked = Thread.holdsLock(lock);
            return super.get(k);
        }
    }

    static boolean readUnderLock(Object lock, java.util.function.Consumer<Object> call) {
        LockProbe p = new LockProbe();
        p.lock = lock;
        call.accept(p);
        return p.locked;
    }

    @Test void concurrentForksOfALeaseHaveOneWinner() throws Exception {
        Map<String, Object> base = K05GrantsDiffTest.m(K05GrantsDiffTest.arg0("verifyLease", "base"));
        Keys.EdKey authority = Keys.edGenerate();
        int n = 16;
        List<Map<String, Object>> forks = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            Map<String, Object> b = new LinkedHashMap<>(base);
            b.remove("sig");
            b.put("authority", authority.id());
            b.put("path", "fork/" + i);
            Map<String, Object> rec = new LinkedHashMap<>(b);
            rec.put("sig", Issue.signBody(authority, Lease.DOMAIN, b));
            assertTrue(Lease.verify(rec), "fixture");
            forks.add(rec);
        }
        Lease.Registry reg = new Lease.Registry(new Lease.Policy(List.of(authority.id())), new MemoryAtomicKv());
        Object[] rs = StoreConformance.race(new CyclicBarrier(n), n, i -> reg.accept(forks.get(i), List.of()));
        int won = 0, forked = 0;
        for (Object r : rs) {
            Lease.Accept a = (Lease.Accept) r;
            if (a.code == null) won++;
            else if ("lease_fork".equals(a.code)) forked++;
        }
        assertEquals(1, won);
        assertEquals(n - 1, forked);
    }

    // ---- H: pca-need.ts:69 (JS \s), I: a2a-auth.ts:273

    static Map<String, Object> need(String scope) {
        return Issue.obj("v", new Json.Num("1"), "kind", "scope", "verb", "v", "resource", "r", "scopes", pins(scope));
    }

    @Test void scopeWhitespaceIsJsWhitespace() {
        assertNull(A2a.needError(need("ab")));
        for (int c : new int[] {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff}) {
            assertEquals("bad_field", A2a.needError(need("a" + (char) c + "b")), Integer.toHexString(c));
        }
        for (int c : new int[] {0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0x180e, 0x200b}) {
            assertNull(A2a.needError(need("a" + (char) c + "b")), Integer.toHexString(c));
        }
    }

    @Test void pushTokenCompare() {
        String salt = "0123456789abcdef";
        String token = A2a.pushToken("t", List.of("c"), salt);
        assertNull(A2a.checkPush("t", List.of("c"), salt, token, Issue.obj("task", Issue.obj("id", "t"))));
        assertEquals("token_mismatch", A2a.checkPush("t", List.of("c"), salt, token + "x", null));
        assertEquals("token_mismatch", A2a.checkPush("t", List.of("c"), salt, token.substring(1) + "x", null));
    }

    // ---- N: hardware-sevsnp.ts:704,708, attest-intel-tdx.ts:636,645, attest-azure-maa.ts:765,809 throw on a mixed list; O: attest-intel-collateral.ts:460

    static final String M96 = "a".repeat(96);

    static String refusal(String vendor, String config) { return AttestVendorRows.constructError(vendor, config); }

    @Test void aMalformedListNeverMeansNoList() {
        String amd = "{\"family\":\"milan\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[\"aa\"],";
        assertEquals("createAmdSnpVerifier: policy.hostData must be an array of strings", refusal("amd-sev-snp", amd + "\"hostData\":[\"aa\",1]}}"));
        assertEquals("createAmdSnpVerifier: policy.chipIds must be an array of strings", refusal("amd-sev-snp", amd + "\"chipIds\":[1]}}"));
        assertNull(refusal("amd-sev-snp", amd + "\"hostData\":[\"aa\"],\"chipIds\":[]}}"));
        String tdx = "{\"binding\":\"report-data\",\"policy\":{\"mrtds\":[\"" + M96 + "\"],";
        assertEquals("createIntelDcapVerifier: policy.fmspcs must be an array of strings", refusal("intel-tdx-dcap", tdx + "\"fmspcs\":[\"aa\",1]}}"));
        assertEquals("createIntelDcapVerifier: policy.rtmrs must be an array of strings", refusal("intel-tdx-dcap", tdx + "\"rtmrs\":[1]}}"));
        assertNull(refusal("intel-tdx-dcap", tdx + "\"fmspcs\":[\"aa\"],\"rtmrs\":[\"bb\"]}}"));
        String maa = "{\"trustedIssuers\":[\"https://maa.test\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"aa\"]},\"policy\":{\"tdxMrtds\":[\"aa\"],";
        assertTrue(String.valueOf(refusal("azure-maa", maa + "\"sevSnpHostData\":[\"aa\",1]}}")).endsWith("policy.sevSnpHostData must be an array of strings"));
        assertTrue(String.valueOf(refusal("azure-maa", maa + "\"tdxRtmrs\":[1]}}")).endsWith("policy.tdxRtmrs must be an array of strings"));
        assertTrue(String.valueOf(refusal("azure-maa", maa + "\"tdxAllowedTcbStatuses\":5}}")).endsWith("policy.tdxAllowedTcbStatuses must be a list"));
        assertNull(refusal("azure-maa", maa + "\"sevSnpHostData\":[\"aa\"],\"tdxRtmrs\":[\"bb\"],\"tdxAllowedTcbStatuses\":[\"UpToDate\",1]}}"));
        // H10: a present non-array is not "no list"
        assertEquals("createAmdSnpVerifier: policy.hostData must be an array of strings", refusal("amd-sev-snp", amd + "\"hostData\":\"aa\"}}"));
        assertEquals("createAmdSnpVerifier: policy.chipIds must be an array of strings", refusal("amd-sev-snp", amd + "\"chipIds\":{}}}"));
        assertEquals("createIntelDcapVerifier: policy.fmspcs must be an array of strings", refusal("intel-tdx-dcap", tdx + "\"fmspcs\":\"aa\"}}"));
        assertEquals("createIntelDcapVerifier: policy.rtmrs must be an array of strings", refusal("intel-tdx-dcap", tdx + "\"rtmrs\":7}}"));
        assertTrue(String.valueOf(refusal("azure-maa", maa + "\"sevSnpHostData\":\"aa\"}}")).endsWith("policy.sevSnpHostData must be an array of strings"));
        assertTrue(String.valueOf(refusal("azure-maa", maa + "\"tdxRtmrs\":true}}")).endsWith("policy.tdxRtmrs must be an array of strings"));
        assertNull(refusal("amd-sev-snp", amd + "\"hostData\":null}}"));
    }

    @Test void statusListsAndTheEvaluationFloor() {
        assertEquals("x must be an array of strings", assertThrows(AttestException.class, () -> AttestCommon.optionalLowerList("aa", "x")).getMessage(), "not a list: refused, never read as no list");
        assertNull(AttestCommon.optionalLowerList(null, "x"));
        assertEquals(List.of("aa"), AttestCommon.optionalLowerList(pins("AA"), "x"));
        assertNull(AttestCommon.optionalStatusList(null, "x"));
        // the list stays as given, so a mixed one still refuses what it does not name
        assertEquals(List.of("SWHardeningNeeded"), AttestCommon.optionalStatusList(pins("SWHardeningNeeded", 1L), "x"));
        AttestIntelCollateral.Policy p = AttestIntel.collateralPolicy(Issue.obj("acceptStatuses", pins("SWHardeningNeeded", 1L)));
        assertTrue(p.hasAccept);
        assertEquals(List.of("SWHardeningNeeded"), p.acceptStatuses);
        assertFalse(p.hasMinEval);
        assertFalse(AttestIntel.collateralPolicy(Issue.obj()).hasAccept);
        assertThrowsAttest("createIntelDcapVerifier: policy.collateral.acceptStatuses must be a list", Issue.obj("acceptStatuses", "UpToDate"));
        p = AttestIntel.collateralPolicy(Issue.obj("minTcbEvaluationDataNumber", "5"));
        assertTrue(p.hasMinEval);
        assertEquals(5.0, p.minEval);
        assertEquals(7.0, AttestIntel.collateralPolicy(Issue.obj("minTcbEvaluationDataNumber", 7L)).minEval);
        assertThrowsAttest("createIntelDcapVerifier: policy.collateral.minTcbEvaluationDataNumber must be a number", Issue.obj("minTcbEvaluationDataNumber", "soon"));
    }

    private static void assertThrowsAttest(String message, Map<String, Object> cpw) {
        assertEquals(message, org.junit.jupiter.api.Assertions.assertThrows(AttestException.class, () -> AttestIntel.collateralPolicy(cpw)).getMessage());
    }

    // attestation parity audit F10: X509_verify compares the outer and signed algorithms
    @Test void theOuterSignatureAlgorithmMustBeTheSignedOne() throws Exception {
        java.security.KeyPair k = AttestTestDer.ecKey("secp256r1");
        java.util.function.Function<byte[], byte[]> certWithInner = inner -> {
            byte[] tbs = AttestTestDer.seq(AttestTestDer.withTag(0xa0, AttestTestDer.integer(2)), AttestTestDer.integer(258), inner, AttestTestDer.name("x"),
                AttestTestDer.seq(AttestTestDer.withTag(0x17, "250101000000Z".getBytes()), AttestTestDer.withTag(0x17, "350101000000Z".getBytes())),
                AttestTestDer.name("x"), k.getPublic().getEncoded());
            try {
                java.security.Signature s = java.security.Signature.getInstance("SHA256withECDSA");
                s.initSign(k.getPrivate());
                s.update(tbs);
                return AttestTestDer.seq(tbs, AttestTestDer.SIG_ALG_ECDSA_SHA256, AttestTestDer.bits((byte) 0, s.sign()));
            } catch (java.security.GeneralSecurityException e) {
                throw new AssertionError(e);
            }
        };
        CertKey key = CertKey.of(k.getPublic(), k.getPublic().getEncoded());
        assertTrue(AttestCert.certSigOk(AttestCert.parseCertDer(certWithInner.apply(AttestTestDer.SIG_ALG_ECDSA_SHA256)), key), "control");
        assertFalse(AttestCert.certSigOk(AttestCert.parseCertDer(certWithInner.apply(AttestTestDer.seq(AttestTestDer.oid("1.2.840.10045.4.3.3")))), key));
    }
}
