package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.bits;
import static net.atlasauth.pca.AttestTestDer.integer;
import static net.atlasauth.pca.AttestTestDer.oid;
import static net.atlasauth.pca.AttestTestDer.seq;
import static net.atlasauth.pca.AttestTestDer.withTag;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.spring.Protect;

/** Mutation kills for the public overload chains, the filter's signature-only policies, Protect's risk wiring, and a few parser and policy paths. */
public class WiringAndDerPitKill1Test {
    // ---- Pca.verifyPcactnJson overloads / null plan roots ---------------------------------------------------------------

    static final String NO_ROOTS = "plan_root_authorized: no authorized plan is configured for this verifier (set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)";

    @Test void everyJsonOverloadReachesTheFullVerifierWithNoPlanRootsConfigured() throws Exception {
        Map<String, Object> grant = PcaUnitTest.validGrant();
        String text = (String) PcaUnitTest.vec("valid-raw-json-format-insensitive").get("pcactn_json");
        long now = PcaUnitTest.NOW;
        String aud = PcaUnitTest.AUD;
        List<Pca.Verdict> vs = new ArrayList<>();
        vs.add(Pca.verifyPcactnJson(text, grant, now, aud));
        vs.add(Pca.verifyPcactnJson(text, grant, now, aud, null));
        vs.add(Pca.verifyPcactnJson(text, grant, now, aud, null, null));
        vs.add(Pca.verifyPcactnJson(text, grant, now, aud, null, null, null));
        vs.add(Pca.verifyPcactnJson(text, grant, now, aud, null, null, null, null));
        vs.add(Pca.verifyPcactnJson(text, grant, now, aud, null, null, null, null, null));
        Map<String, Object> parsed = PcaUnitTest.valid();
        vs.add(Pca.verifyPcactn(parsed, grant, now, aud, null, null, null, null, null));
        for (int i = 0; i < vs.size(); i++) {
            Pca.Verdict v = vs.get(i);
            assertNotNull(v, "overload " + i);
            assertFalse(v.allow, "overload " + i);
            assertEquals(NO_ROOTS, v.reason, "overload " + i);
            assertEquals(Boolean.FALSE, v.checks.get("plan_root_authorized"), "overload " + i);
        }
        Pca.Verdict skip = Pca.verifyPcactnJson(text, grant, now, aud, null, null, null, null, Pca.PlanRoots.SKIP);
        assertTrue(skip.allow, skip.reason);
    }

    // ---- PcaFilter signature-only policies ------------------------------------------------------------------------------

    static final Map<String, Object> C = AuthorizeFixtures.kase("envelope-predicate-within");
    static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(AuthorizeFixtures.now()), ZoneOffset.UTC);

    static PcaFilter signatureOnly() {
        return new PcaFilter(AuthorizeFixtures.audience(), ref -> AuthorizeFixtures.grant(C), CLOCK, null, null, true);
    }

    static int status(PcaFilter f) throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/pay");
        req.addHeader("PCA-Action", AuthorizeTest.hdr(AuthorizeFixtures.pcactn(C, 0)));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        AtomicInteger calls = new AtomicInteger();
        f.doFilter(req, resp, (a, b) -> calls.incrementAndGet());
        int s = resp.getStatus();
        assertEquals(s == 200 ? 1 : 0, calls.get(), "the chain runs iff the request is admitted");
        return s;
    }

    static void refused(int s, String why) { assertTrue(s >= 400 && s < 500, why + ": status " + s); }

    @SuppressWarnings("unchecked")
    @Test void aSignatureOnlyFilterEnforcesThePlanRootsAndSuitesItWasGiven() throws Exception {
        assertEquals(200, status(signatureOnly()));
        Map<String, Object> plan = (Map<String, Object>) AuthorizeFixtures.pcactn(C, 0).get("plan");
        String root = (String) plan.get("root");
        PcaFilter f = signatureOnly();
        assertSame(f, f.withAuthorizedPlanRoots(List.of()));
        refused(status(f), "an empty list authorizes nothing");
        assertSame(f, f.withAuthorizedPlanRoots(List.of("not-the-root")));
        refused(status(f), "a root that is not the plan's");
        assertSame(f, f.withAuthorizedPlanRoots(List.of(root)));
        assertEquals(200, status(f));
        PcaFilter g = signatureOnly();
        assertSame(g, g.withAllowedSuites(List.of()));
        refused(status(g), "a present, empty suite list refuses every suite");
        assertSame(g, g.withAllowedSuites(null));
        assertEquals(200, status(g), "no list is no restriction");
    }

    // ---- Protect risk wiring --------------------------------------------------------------------------------------------

    static Keys.SuiteKey key(int fill) {
        byte[] x = new byte[32];
        Arrays.fill(x, (byte) fill);
        return Keys.ed25519(Keys.edFromSeed(x));
    }

    @Test void protectPricesAMoneyOperationFromItsAmount() {
        Keys.SuiteKey principal = key(31), agent = key(32);
        List<Object> preds = new ArrayList<>();
        preds.add(Issue.obj("verb", "*"));
        Map<String, Object> env = Issue.obj("predicates", preds, "caveats", new ArrayList<Object>(), "risk_policy", Issue.defaultRiskPolicy());
        Map<String, Object> grant = Issue.mintGrant(principal, agent.id(), null, env, "pay invoices", Pca.b64(new byte[16])).grant;
        Authorize.RiskSource risk = Protect.protect(new Protect.Config("aud", (req, body) -> null).grants(List.of(grant))).options().riskSource;
        assertNotNull(risk);
        assertNull(risk.risk(null, grant, null));
        assertNull(risk.risk(Authorize.Operation.of("v", "r", null), grant, null));
        assertNull(risk.risk(Authorize.Operation.of("v", "r", Map.of("memo", "x")), grant, null));
        assertEquals(Map.of("blastRadius", 0.25), risk.risk(Authorize.Operation.of("v", "r", Map.of("amount", 0.25)), grant, null));
        assertEquals(Map.of("blastRadius", 1.0), risk.risk(Authorize.Operation.of("v", "r", Map.of("amount", 50L)), grant, null));
        assertNull(risk.risk(Authorize.Operation.of("v", "r", Map.of("amount", 0.25)), new LinkedHashMap<>(), null));
    }

    // ---- PolicyAuthoring.verifyLinkedPolicy ----------------------------------------------------------------------------

    @Test void aLinkVerificationThatThrowsFailsClosedWithItsOwnReason() throws Exception {
        Map<String, Object> c = K05R5G3PolicyTest.caseNamed("a reference resolves");
        Map<String, Object> reg = PolicyAuthoringTest.m(c.get("registry"));
        Map<String, Object> policy = PolicyAuthoringTest.m(PolicyAuthoringTest.m(c.get("expect")).get("policy"));
        Map<String, Object> env = new LinkedHashMap<String, Object>() {
            private static final long serialVersionUID = 1L;
            @Override public Object get(Object k) {
                if ("predicates".equals(k)) throw new IllegalStateException("hostile");
                return super.get(k);
            }
        };
        env.put("template_ref", c.get("ref"));
        env.put("predicates", policy.get("predicates"));
        env.put("caveats", policy.get("caveats"));
        assertEquals("link verification error (fail closed)", PolicyAuthoring.verifyLinkedPolicy(env, reg));
    }

    // ---- RevocationStaleness.State.withPin ------------------------------------------------------------------------------

    @Test void aBareRootHasNoEpochToPinAndASignedOneKeepsTheHigherPin() {
        RevocationStaleness.State bare = RevocationStaleness.State.root("r", 5L);
        assertSame(bare, bare.withPin(9));
        Map<String, Object> epoch = new LinkedHashMap<>();
        RevocationStaleness.State fresh = RevocationStaleness.State.epoch(epoch, "r", null);
        RevocationStaleness.State pinned = fresh.withPin(7);
        assertNotNull(pinned);
        assertTrue(pinned.signed);
        assertEquals(Double.valueOf(7), pinned.lastAcceptedEpoch);
        assertSame(epoch, pinned.epoch);
        assertEquals("r", pinned.root);
        RevocationStaleness.State high = RevocationStaleness.State.epoch(epoch, "r", 10L);
        assertEquals(Double.valueOf(10), high.withPin(7).lastAcceptedEpoch);
        assertEquals(Double.valueOf(12), high.withPin(12).lastAcceptedEpoch);
        assertEquals(Double.valueOf(10), high.withPin(10).lastAcceptedEpoch);
    }

    // ---- AttestDer.oidToDotted ------------------------------------------------------------------------------------------

    static String dotted(byte[] content) {
        return AttestDer.oidToDotted(content, new AttestDer.Tlv(0x06, 0, content.length));
    }

    static byte[] arc(int groups) {
        byte[] a = new byte[groups];
        Arrays.fill(a, (byte) 0x81);
        a[groups - 1] = 0x01;
        return a;
    }

    static BigInteger arcValue(int groups) {
        BigInteger v = BigInteger.ZERO;
        for (int i = 0; i < groups; i++) v = v.shiftLeft(7).or(BigInteger.ONE);
        return v;
    }

    static byte[] cat(byte[]... parts) { return AttestTestDer.cat(parts); }

    @Test void anArcOfSixtyFourGroupsIsReadAndSixtyFiveIsRefused() {
        BigInteger v = arcValue(64);
        // the FIRST arc (its group count starts at zero) and a later one (it restarts) each may carry 64 groups
        assertEquals("2." + v.subtract(BigInteger.valueOf(80)), dotted(arc(64)));
        assertEquals("2." + v.subtract(BigInteger.valueOf(80)) + "." + v, dotted(cat(arc(64), arc(64))));
        assertEquals("1.2." + v, dotted(cat(new byte[] {0x2a}, arc(64))));
        AttestException first = assertThrows(AttestException.class, () -> dotted(arc(65)));
        assertEquals("extension OID has an oversized arc", first.getMessage());
        AttestException later = assertThrows(AttestException.class, () -> dotted(cat(new byte[] {0x2a}, arc(65))));
        assertEquals("extension OID has an oversized arc", later.getMessage());
    }

    // ---- AttestCert.keyOfCert: RSASSA-PSS key parameters -----------------------------------------------------------------

    @Test void anRsaPssKeyCarriesItsParametersAndAnAbsentOneIsUnrestricted() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        KeyPair kp = g.generateKeyPair();
        RSAPublicKey rp = (RSAPublicKey) kp.getPublic();
        byte[] pkcs1 = seq(withTag(0x02, rp.getModulus().toByteArray()), withTag(0x02, rp.getPublicExponent().toByteArray()));
        byte[] pssOid = oid("1.2.840.113549.1.1.10");
        AttCert withParams = new AttCert();
        withParams.rawSpki = seq(seq(pssOid, seq(withTag(0xa2, integer(32)))), bits((byte) 0, pkcs1));
        CertKey k = AttestCert.keyOfCert(withParams);
        assertEquals("rsa-pss", k.typ);
        assertNotNull(k.keyPss);
        assertEquals(32, k.keyPss.salt);
        assertTrue(k.keyPss.ok);
        AttCert bare = new AttCert();
        bare.rawSpki = seq(seq(pssOid), bits((byte) 0, pkcs1));
        CertKey u = AttestCert.keyOfCert(bare);
        assertEquals("rsa-pss", u.typ);
        assertNull(u.keyPss);
        AttCert plain = new AttCert();
        plain.rawSpki = seq(seq(oid("1.2.840.113549.1.1.1"), new byte[] {5, 0}), bits((byte) 0, pkcs1));
        assertEquals("rsa", AttestCert.keyOfCert(plain).typ);
    }

    // ---- NVIDIA collateral hook ------------------------------------------------------------------------------------------

    @Test void aHookBuiltWithoutAConfigurationRequiresCrlsForCdpChains() {
        assertEquals("cdp", new AttestNvidiaRim.Hook().requireCrlFor);
    }

    @Test void theRootIsNeverDemandedByCdpAndAnUnknownOptionThrows() {
        List<AttCert> chain = Arrays.asList(AttestNvidiaCrlCoverageTest.leafCert(false), AttestNvidiaCrlCoverageTest.interCert(true)); // the LAST certificate names a CDP
        byte[] interCrl = AttestNvidiaRimKillTest.crlOf(AttestNvidiaCrlCoverageTest.INTER);
        assertEquals("", AttestNvidiaCrlCoverageTest.rev(chain, "cdp", interCrl));
        AttestException e = assertThrows(AttestException.class, () -> AttestNvidiaCrlCoverageTest.rev(chain, 5, interCrl));
        assertEquals("nvidiaCollateralHook: requireCrlFor must be 'cdp', 'all' or an array of chain indices", e.getMessage());
    }

    // ---- Sigstore: the timestamp cap in the bundle verifier --------------------------------------------------------------

    @SuppressWarnings("unchecked")
    @Test void aBundleWithMoreTimestampsThanTheCapIsRefusedBeforeAnyIsVerified() {
        K05R3SigstoreKillTest.Mini x = K05R3SigstoreKillTest.mini("secp256r1", "SHA256withECDSA", "SHA2_256", "sha256");
        Map<String, Object> tvd = (Map<String, Object>) ((Map<String, Object>) x.bundle.get("verificationMaterial")).get("timestampVerificationData");
        Object one = ((List<Object>) tvd.get("rfc3161Timestamps")).get(0);
        tvd.put("rfc3161Timestamps", new ArrayList<>(Collections.nCopies(9, one)));
        Sigstore.CoreResult r = x.verify();
        assertFalse(r.ok);
        assertTrue(r.detail.contains("too many RFC 3161 timestamps (9, at most 8)"), r.code + " | " + r.detail);
    }

    // ---- AttestJws.jsonSegment: the size cap -----------------------------------------------------------------------------

    @Test void aJsonSegmentOfExactlyTheCapIsParsedAndOneByteMoreIsTooLarge() {
        byte[] raw = new byte[16777217];
        Arrays.fill(raw, (byte) 'a');
        AttestException big = assertThrows(AttestException.class, () -> AttestJws.jsonSegment(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw), "p"));
        assertEquals("p: malformed JSON segment: input too large", big.getMessage());
        byte[] atCap = Arrays.copyOf(raw, 16777216);
        AttestException parse = assertThrows(AttestException.class, () -> AttestJws.jsonSegment(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(atCap), "p"));
        assertTrue(parse.getMessage().startsWith("p: malformed JSON segment: "), parse.getMessage());
        assertFalse(parse.getMessage().contains("input too large"), parse.getMessage());
    }
}
