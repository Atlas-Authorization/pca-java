package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** PCA 0.5 hardening of the attestation verifiers: RSA key rule, OID caps, XML depth, JSON size, PSS key parameters, config typing. */
class K05HardeningAttestTest {
    // ---- H1: RSA public-key rule (odd e >= 3, bitlen(e) <= 32, modulus 512..16384 bits)

    static BigInteger modulus(int bits) { return BigInteger.ONE.shiftLeft(bits - 1).setBit(0); }

    @Test
    void rsaKeyRuleBoundaries() {
        BigInteger e = BigInteger.valueOf(65537);
        assertTrue(CertKey.rsaKeyOk(modulus(512), e));
        assertFalse(CertKey.rsaKeyOk(modulus(511), e));
        assertTrue(CertKey.rsaKeyOk(modulus(16384), e));
        assertFalse(CertKey.rsaKeyOk(modulus(16385), e));
        assertTrue(CertKey.rsaKeyOk(modulus(2048), BigInteger.valueOf(3)));
        assertFalse(CertKey.rsaKeyOk(modulus(2048), BigInteger.ONE));
        assertFalse(CertKey.rsaKeyOk(modulus(2048), BigInteger.valueOf(4)));
        assertFalse(CertKey.rsaKeyOk(modulus(2048), BigInteger.valueOf(65536)));
        assertFalse(CertKey.rsaKeyOk(modulus(2048), BigInteger.ZERO));
        assertTrue(CertKey.rsaKeyOk(modulus(2048), BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE))); // 32 bits, odd
        assertFalse(CertKey.rsaKeyOk(modulus(2048), BigInteger.ONE.shiftLeft(32).add(BigInteger.ONE))); // 33 bits
        assertTrue(CertKey.rsaKeyOk(KeyPairHolder.RSA.getPublic()));
        assertTrue(CertKey.rsaKeyOk(KeyPairHolder.EC.getPublic())); // another key type is not this rule's business
    }

    @Test
    void jwkRsaKeyRefusesAnUnusableKey() throws Exception {
        java.security.interfaces.RSAPublicKey pub = (java.security.interfaces.RSAPublicKey) KeyPairHolder.RSA.getPublic();
        String n = Base64.getUrlEncoder().withoutPadding().encodeToString(unsigned(pub.getModulus()));
        String ok = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[] {1, 0, 1});
        assertEquals("rsa", AttestJws.jwkRsaKey(n, ok).typ);
        String even = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[] {4});
        assertEquals(AttestCert.OSSL_UNSUPPORTED, assertThrows(AttestException.class, () -> AttestJws.jwkRsaKey(n, even)).getMessage());
        String big = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[] {1, 0, 0, 0, 1}); // 2^32 + 1: 33 bits
        assertEquals(AttestCert.OSSL_UNSUPPORTED, assertThrows(AttestException.class, () -> AttestJws.jwkRsaKey(n, big)).getMessage());
        String three = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[] {3});
        assertEquals("rsa", AttestJws.jwkRsaKey(n, three).typ);
        String one = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[] {1});
        assertEquals(AttestCert.OSSL_UNSUPPORTED, assertThrows(AttestException.class, () -> AttestJws.jwkRsaKey(n, one)).getMessage());
    }

    static byte[] unsigned(BigInteger v) {
        byte[] b = v.toByteArray();
        return b[0] == 0 ? Arrays.copyOfRange(b, 1, b.length) : b;
    }

    static final class KeyPairHolder {
        static final KeyPair RSA = gen("RSA", 2048);
        static final KeyPair EC = gen("EC", 256);

        static KeyPair gen(String alg, int bits) {
            try {
                KeyPairGenerator g = KeyPairGenerator.getInstance(alg);
                g.initialize(bits);
                return g.generateKeyPair();
            } catch (java.security.GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    // ---- H2: OID content / arc caps

    static String dotted(byte[] b) { return AttestDer.oidToDotted(b, new AttestDer.Tlv(0x06, 0, b.length)); }

    static byte[] oidBytes(int len, int first, int rest) {
        byte[] b = new byte[len];
        Arrays.fill(b, (byte) rest);
        b[0] = (byte) first;
        return b;
    }

    @Test
    void oidSizeCaps() {
        assertEquals("2.5.29.19", dotted(new byte[] {0x55, 0x1d, 0x13}));
        assertEquals("2.5.29.19.1", dotted(new byte[] {0x55, 0x1d, 0x13, 0x01}));
        // 256 content bytes decode, 257 are refused before any big-integer work
        assertTrue(dotted(oidBytes(256, 0x55, 0x01)).startsWith("2.5.1.1."));
        assertEquals("extension OID is too long", assertThrows(AttestException.class, () -> dotted(oidBytes(257, 0x55, 0x01))).getMessage());
        // 64 base-128 groups in one arc decode, 65 are refused
        byte[] a64 = new byte[65];
        a64[0] = 0x55;
        Arrays.fill(a64, 1, 64, (byte) 0x81);
        a64[64] = 0x01;
        assertTrue(dotted(a64).startsWith("2.5."));
        byte[] a65 = new byte[66];
        a65[0] = 0x55;
        Arrays.fill(a65, 1, 65, (byte) 0x81);
        a65[65] = 0x01;
        assertEquals("extension OID has an oversized arc", assertThrows(AttestException.class, () -> dotted(a65)).getMessage());
        // 2.25.<UUID>: 19 groups
        byte[] uuid = new byte[20];
        uuid[0] = 0x69;
        Arrays.fill(uuid, 1, 19, (byte) 0xff);
        uuid[19] = 0x7f;
        assertTrue(dotted(uuid).startsWith("2.25."));
        // the group count restarts at every arc: many short arcs are fine
        assertEquals("extension OID is malformed", assertThrows(AttestException.class, () -> AttestDer.oidToDotted(new byte[1], new AttestDer.Tlv(0x06, 0, 0))).getMessage());
    }

    // ---- H5: XML nesting depth

    static String nested(int n) { return "<a>".repeat(n) + "</a>".repeat(n); }

    @Test
    void xmlNestingIsCappedAt64() {
        assertEquals("a", AttestXml.parseXml(nested(64)).root.name);
        assertEquals("XML nesting is too deep", assertThrows(AttestException.class, () -> AttestXml.parseXml(nested(65))).getMessage());
        assertEquals("XML nesting is too deep", assertThrows(AttestException.class, () -> AttestXml.parseXml("<a>".repeat(100000))).getMessage());
        // a self-closing element at depth 64 does not nest further; closing elements lowers the depth again
        assertEquals("a", AttestXml.parseXml("<a>".repeat(63) + "<a/>" + "</a>".repeat(63)).root.name);
        assertEquals("a", AttestXml.parseXml("<r>" + "<a><a><a></a></a></a>".repeat(40) + "</r>").root.name.equals("r") ? "a" : "x");
        // a wide document is linear (a start tag is read in place, not from a copy of the rest)
        StringBuilder wide = new StringBuilder("<r>");
        for (int i = 0; i < 200000; i++) wide.append("<a/>");
        long t0 = System.nanoTime();
        assertEquals(200000, AttestXml.parseXml(wide.append("</r>").toString()).root.children.size());
        assertTrue((System.nanoTime() - t0) / 1_000_000 < 20000);
    }

    // ---- H7: 16 MiB JSON segment cap

    @Test
    void jsonSegmentSizeCap() {
        int max = 16 * 1024 * 1024;
        assertEquals(max, AttestCommon.MAX_JSON_BYTES);
        byte[] ok = new byte[max];
        Arrays.fill(ok, (byte) ' ');
        ok[0] = '{';
        ok[1] = '}';
        assertEquals(new LinkedHashMap<String, Object>(), AttestJws.jsonSegment(Base64.getUrlEncoder().withoutPadding().encodeToString(ok), "JWS header"));
        byte[] big = Arrays.copyOf(ok, max + 1);
        big[max] = ' ';
        String seg = Base64.getUrlEncoder().withoutPadding().encodeToString(big);
        assertEquals("JWS header: malformed JSON segment: input too large", assertThrows(AttestException.class, () -> AttestJws.jsonSegment(seg, "JWS header")).getMessage());
        assertEquals("input too large", assertThrows(AttestException.class, () -> AttestCommon.jsonLenient(big)).getMessage());
        assertEquals(new LinkedHashMap<String, Object>(), AttestCommon.jsonLenient(ok));
    }

    // ---- H8: RSASSA-PSS key parameters restrict the signatures it verifies

    static byte[] hashAlg(String oid) { return seq(oid(oid)); }

    static byte[] pssParams(String hashOid, String mgfHashOid, long salt) {
        return seq(withTag(0xa0, hashAlg(hashOid)), withTag(0xa1, seq(oid("1.2.840.113549.1.1.8"), hashAlg(mgfHashOid))), withTag(0xa2, integer(salt)));
    }

    static final String SHA256 = "2.16.840.1.101.3.4.2.1";
    static final String SHA384 = "2.16.840.1.101.3.4.2.2";

    static AttCert pssSigned(KeyPair kp, String jcaHash, int salt, byte[] sigParams) throws Exception {
        AttCert c = new AttCert();
        c.rawTbs = "tbs".getBytes(StandardCharsets.US_ASCII);
        c.sigOid = AttestCert.OID_RSA_PSS;
        c.sigParams = sigParams;
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(new PSSParameterSpec(jcaHash, "MGF1", new MGF1ParameterSpec(jcaHash), salt, 1));
        s.initSign(kp.getPrivate());
        s.update(c.rawTbs);
        c.signature = s.sign();
        return c;
    }

    static CertKey pssKey(KeyPair kp, byte[] keyParams) {
        CertKey k = CertKey.of(kp.getPublic(), kp.getPublic().getEncoded()).withType("rsa-pss");
        if (keyParams != null) k.keyPss = AttestCert.pssParams(keyParams);
        return k;
    }

    @Test
    void pssKeyParametersRestrictTheSignatures() throws Exception {
        KeyPair kp = KeyPairHolder.RSA;
        AttCert s256 = pssSigned(kp, "SHA-256", 32, pssParams(SHA256, SHA256, 32));
        AttCert s384 = pssSigned(kp, "SHA-384", 48, pssParams(SHA384, SHA384, 48));
        AttCert s384lowSalt = pssSigned(kp, "SHA-384", 20, pssParams(SHA384, SHA384, 20));
        AttCert s384highSalt = pssSigned(kp, "SHA-384", 64, pssParams(SHA384, SHA384, 64));
        // an unrestricted key (no parameters) verifies any hash
        assertTrue(AttestCert.certSigOk(s256, pssKey(kp, null)));
        assertTrue(AttestCert.certSigOk(s384, pssKey(kp, null)));
        // a key restricted to SHA-384 / MGF1-SHA-384 / salt 48
        byte[] kp384 = pssParams(SHA384, SHA384, 48);
        assertFalse(AttestCert.certSigOk(s256, pssKey(kp, kp384)));
        assertTrue(AttestCert.certSigOk(s384, pssKey(kp, kp384)));
        assertFalse(AttestCert.certSigOk(s384lowSalt, pssKey(kp, kp384)));
        assertTrue(AttestCert.certSigOk(s384highSalt, pssKey(kp, kp384)));
        // a key whose MGF1 hash differs from its hash admits no signature of this verifier's profile
        assertFalse(AttestCert.certSigOk(s384, pssKey(kp, pssParams(SHA384, SHA256, 48))));
        // a key restricted to SHA-256 refuses a SHA-384 signature
        assertTrue(AttestCert.certSigOk(s256, pssKey(kp, pssParams(SHA256, SHA256, 32))));
        assertFalse(AttestCert.certSigOk(s384, pssKey(kp, pssParams(SHA256, SHA256, 32))));
        // unparsable key parameters refuse everything
        assertFalse(AttestCert.certSigOk(s256, pssKey(kp, new byte[] {0x05, 0x00})));
    }

    // ---- H9: NVIDIA verifier configuration typing

    static String nvidia(String collateral, String policyExtra) {
        AttestNvidiaTest.Gpu g = new AttestNvidiaTest.Gpu();
        return "{\"rootSpkiSha256\":[\"" + g.pin().toUpperCase() + "\"],\"policy\":{\"measurements\":{\"1\":\"aa\"}" + policyExtra + "}" + collateral + "}";
    }

    static String col(String inner) { return ",\"collateral\":{\"rimRootSpkiSha256\":[\"aa\"]" + inner + "}"; }

    @Test
    void nvidiaConfigIsTyped() {
        assertEquals("no error", AttestNvidiaTest.constructError(nvidia("", "")));
        assertEquals("no error", AttestNvidiaTest.constructError(nvidia(",\"collateral\":null", "")));
        assertEquals("no error", AttestNvidiaTest.constructError(nvidia(col(""), "")));
        assertEquals("createNvidiaSpdmVerifier: collateral must be an object", AttestNvidiaTest.constructError(nvidia(",\"collateral\":\"required\"", "")));
        assertEquals("createNvidiaSpdmVerifier: collateral must be an object", AttestNvidiaTest.constructError(nvidia(",\"collateral\":[]", "")));
        assertEquals("createNvidiaSpdmVerifier: policy.leafSubjectIncludes must be a string", AttestNvidiaTest.constructError(nvidia("", ",\"leafSubjectIncludes\":5")));
        assertEquals("no error", AttestNvidiaTest.constructError(nvidia("", ",\"leafSubjectIncludes\":\"GH100\"")));
        assertEquals("no error", AttestNvidiaTest.constructError(nvidia("", ",\"leafSubjectIncludes\":null")));
        assertEquals("nvidiaCollateralHook: firmware must be an object", AttestNvidiaTest.constructError(nvidia(col(",\"firmware\":\"x\""), "")));
        assertEquals("nvidiaCollateralHook: firmware must be an object", AttestNvidiaTest.constructError(nvidia(col(",\"firmware\":[]"), "")));
        assertEquals("no error", AttestNvidiaTest.constructError(nvidia(col(",\"firmware\":null"), "")));
        assertEquals("no error", AttestNvidiaTest.constructError(nvidia(col(",\"firmware\":{}"), "")));
        assertEquals("nvidiaCollateralHook: malformed minDriverVersion '535'", AttestNvidiaTest.constructError(nvidia(col(",\"firmware\":{\"minDriverVersion\":535}"), "")));
        assertEquals("nvidiaCollateralHook: malformed minVbiosVersion 'true'", AttestNvidiaTest.constructError(nvidia(col(",\"firmware\":{\"minVbiosVersion\":true}"), "")));
        assertEquals("no error", AttestNvidiaTest.constructError(nvidia(col(",\"firmware\":{\"minDriverVersion\":0,\"minVbiosVersion\":\"\"}"), "")));
        assertEquals("no error", AttestNvidiaTest.constructError(nvidia(col(",\"firmware\":{\"minDriverVersion\":\"535.1\",\"denyDriverVersions\":[\"535.2\"]}"), "")));
        assertEquals("nvidiaCollateralHook: malformed denyDriverVersions entry '5'", AttestNvidiaTest.constructError(nvidia(col(",\"firmware\":{\"denyDriverVersions\":[\"535.1\",5]}"), "")));
        assertEquals("nvidiaCollateralHook: malformed denyDriverVersions entry '535.1'", AttestNvidiaTest.constructError(nvidia(col(",\"firmware\":{\"denyDriverVersions\":\"535.1\"}"), "")));
        assertEquals("nvidiaCollateralHook: malformed denyVbiosVersions entry 'null'", AttestNvidiaTest.constructError(nvidia(col(",\"firmware\":{\"denyVbiosVersions\":[null]}"), "")));
        assertEquals("no error", AttestNvidiaTest.constructError(nvidia(col(",\"firmware\":{\"denyDriverVersions\":null}"), "")));
        assertEquals("nvidiaCollateralHook: requireCrlIssuers must list only strings", AttestNvidiaTest.constructError(nvidia(col(",\"requireCrlIssuers\":\"NVIDIA GH100\""), "")));
        assertEquals("nvidiaCollateralHook: requireCrlIssuers must list only strings", AttestNvidiaTest.constructError(nvidia(col(",\"requireCrlIssuers\":[\"a\",1]"), "")));
        assertEquals("no error", AttestNvidiaTest.constructError(nvidia(col(",\"requireCrlIssuers\":[\"a\"]"), "")));
        assertEquals("no error", AttestNvidiaTest.constructError(nvidia(col(",\"requireCrlIssuers\":null"), "")));
    }

    // ---- H11 / H12: Intel collateral policy and evidence typing

    static final String INTEL_CFG_TAIL = "\"policy\":{\"mrtds\":[\"" + "a".repeat(96) + "\"]";

    @Test
    void intelCollateralPolicyMustBeAnObject() {
        String base = "{\"binding\":\"report-data\",";
        assertEquals("createIntelDcapVerifier: policy.collateral must be an object", AttestVendorRows.constructError("intel-tdx-dcap", base + INTEL_CFG_TAIL + ",\"collateral\":\"x\"}}"));
        assertEquals("createIntelDcapVerifier: policy.collateral must be an object", AttestVendorRows.constructError("intel-tdx-dcap", base + INTEL_CFG_TAIL + ",\"collateral\":[]}}"));
        assertNull(AttestVendorRows.constructError("intel-tdx-dcap", base + INTEL_CFG_TAIL + ",\"collateral\":null}}"));
        assertNull(AttestVendorRows.constructError("intel-tdx-dcap", base + INTEL_CFG_TAIL + ",\"collateral\":{}}}"));
        assertNull(AttestVendorRows.constructError("intel-tdx-dcap", base + INTEL_CFG_TAIL + ",\"collateral\":{\"minTcbEvaluationDataNumber\":7}}}"));
    }

    @Test
    void aGarbageEvidenceCollateralIsNotMissing() {
        AttestIntelTest.Genuine g = new AttestIntelTest.Genuine();
        Map<String, Object> cfg = g.config(""); // allowMissingCollateral
        String quote = Base64.getEncoder().encodeToString(g.quote());
        for (Object bad : new Object[] {"x", 5L, java.util.Collections.emptyList(), Boolean.TRUE}) {
            Map<String, Object> ev = new LinkedHashMap<>(AttestIntelTest.ev("quote", quote));
            ev.put("collateral", bad);
            HardwareResult r = AttestVendorRows.run("intel-tdx-dcap", cfg, ev, AttestVendorRows.BINDING, AttestVendorRows.NOW);
            assertFalse(r.ok, String.valueOf(bad));
            assertEquals("Intel collateral: collateral incomplete (fail closed)", r.reason, String.valueOf(bad));
        }
        for (Object none : new Object[] {null, 0L, "", Boolean.FALSE}) {
            Map<String, Object> ev = new LinkedHashMap<>(AttestIntelTest.ev("quote", quote));
            ev.put("collateral", none);
            HardwareResult r = AttestVendorRows.run("intel-tdx-dcap", cfg, ev, AttestVendorRows.BINDING, AttestVendorRows.NOW);
            assertTrue(r.ok, r.reason);
            assertEquals("unevaluated", r.hostAsserted.get("tcb_status"));
        }
    }

    // ---- H6: at most 8 RFC 3161 timestamps

    @Test
    void theTimestampCountIsCappedAtEight() {
        Sigstore.requireTimestampCap(java.util.Collections.nCopies(0, "t"));
        Sigstore.requireTimestampCap(java.util.Collections.nCopies(8, "t"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Sigstore.requireTimestampCap(java.util.Collections.nCopies(9, "t")));
        assertEquals("too many RFC 3161 timestamps (9, at most 8)", e.getMessage());
        assertEquals(8, Sigstore.MAX_TIMESTAMPS);
    }
}
