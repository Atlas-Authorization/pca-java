package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The hardware-vendor attestation modules' public surface under the reference's names: constants, constructors, parsers, chain checks, fetchers, time readers. */
class AttestVendorsApiTest {
    private static X509Certificate selfSigned(String cn) throws Exception {
        Path dir = Files.createTempDirectory("vendors-api");
        Path ks = dir.resolve("k.p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Process p = new ProcessBuilder(keytool, "-genkeypair", "-alias", "k", "-keyalg", "EC", "-keysize", "256", "-sigalg", "SHA256withECDSA", "-dname", "CN=" + cn,
            "-validity", "2", "-storetype", "PKCS12", "-keystore", ks.toString(), "-storepass", "changeit", "-keypass", "changeit").redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, p.waitFor(), out);
        KeyStore k = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(ks)) { k.load(in, "changeit".toCharArray()); }
        return (X509Certificate) k.getCertificate("k");
    }

    @Test void constantsAndTheirShapes() {
        assertEquals("intel-tdx-dcap-ecdsa-p256", AttestVendorsApi.INTEL_DCAP_SUITE);
        assertEquals("amd-sev-snp-ecdsa-p384", AttestVendorsApi.AMD_SNP_SUITE);
        assertEquals(List.of("ES256", "RS256"), AttestVendorsApi.AZURE_MAA_SUITES);
        assertEquals(List.of("RS256", "ES256"), AttestVendorsApi.GCP_CS_SUITES);
        assertEquals(64, AttestVendorsApi.INTEL_SGX_ROOT_CA_SPKI_SHA256.length());
        Map<String, String> ark = AttestVendorsApi.amdArkSpkiSha384();
        assertEquals(Set.of("milan", "genoa", "turin"), ark.keySet());
        for (String v : ark.values()) assertEquals(96, v.length());
        assertFalse(AttestVendorsApi.builtinMaaPinsIssuerKeys().isEmpty());
    }

    @Test void everyConstructorRefusesAnAcceptAllConfiguration() {
        for (java.util.function.Function<Map<String, Object>, VendorVerifier> f : List.<java.util.function.Function<Map<String, Object>, VendorVerifier>>of(
                AttestVendorsApi::createAmdSnpVerifier, AttestVendorsApi::createIntelDcapVerifier, AttestVendorsApi::createAzureMaaVerifier,
                AttestVendorsApi::createGcpConfidentialSpaceVerifier, AttestVendorsApi::createNvidiaSpdmVerifier)) {
            assertThrows(AttestException.class, () -> f.apply(new LinkedHashMap<>()));
        }
    }

    @Test void teeTypeOfHwModel() {
        assertEquals("sev-snp", AttestVendorsApi.teeTypeOfHwModel("GCP_AMD_SEV"));
        assertEquals("sev-snp", AttestVendorsApi.teeTypeOfHwModel("gcp_amd_sev_snp"));
        assertEquals("tdx", AttestVendorsApi.teeTypeOfHwModel("GCP_INTEL_TDX"));
        assertNull(AttestVendorsApi.teeTypeOfHwModel("something else"));
        assertNull(AttestVendorsApi.teeTypeOfHwModel(null));
    }

    @Test void parseDcapTdReportReadsTheTd10Fields() {
        byte[] body = new byte[584];
        for (int i = 0; i < body.length; i++) body[i] = (byte) (i % 251);
        Map<String, Object> r = AttestVendorsApi.parseDcapTdReport(body);
        assertArrayEquals(Arrays.copyOfRange(body, 136, 184), (byte[]) r.get("mrTd"));
        assertArrayEquals(Arrays.copyOfRange(body, 520, 584), (byte[]) r.get("reportData"));
        assertArrayEquals(Arrays.copyOfRange(body, 472, 520), (byte[]) r.get("rtmr3"));
        assertArrayEquals(Arrays.copyOfRange(body, 120, 128), (byte[]) r.get("tdAttributes"));
        assertArrayEquals(body, (byte[]) r.get("raw"));
        body[136] ^= 1;
        assertFalse(Arrays.equals(body, (byte[]) r.get("raw")), "the fields are copies");
        assertThrows(IllegalArgumentException.class, () -> AttestVendorsApi.parseDcapTdReport(new byte[583]));
    }

    @Test void ecdsaP256PublicKeyAcceptsBothEncodingsAndRefusesAnOffCurvePoint() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        ECPublicKey pub = (ECPublicKey) g.generateKeyPair().getPublic();
        byte[] x = fixed(pub.getW().getAffineX()), y = fixed(pub.getW().getAffineY());
        byte[] unc = new byte[65];
        unc[0] = 4;
        System.arraycopy(x, 0, unc, 1, 32);
        System.arraycopy(y, 0, unc, 33, 32);
        byte[] comp = new byte[33];
        comp[0] = (byte) (2 + (y[31] & 1));
        System.arraycopy(x, 0, comp, 1, 32);
        assertArrayEquals(unc, AttestVendorsApi.ecdsaP256PublicKey(unc));
        assertArrayEquals(unc, AttestVendorsApi.ecdsaP256PublicKey(comp));
        byte[] bad = unc.clone();
        bad[64] ^= 1;
        assertThrows(RuntimeException.class, () -> AttestVendorsApi.ecdsaP256PublicKey(bad));
    }

    private static byte[] fixed(BigInteger v) {
        byte[] b = v.toByteArray(), out = new byte[32];
        System.arraycopy(b, Math.max(0, b.length - 32), out, Math.max(0, 32 - b.length), Math.min(32, b.length));
        return out;
    }

    @Test void collateralHelpers() {
        assertTrue(AttestVendorsApi.serialIsRevoked(Set.of("abc"), "00ABC"));
        assertFalse(AttestVendorsApi.serialIsRevoked(Set.of("abc"), "abd"));
        assertEquals("-----BEGIN CERTIFICATE-----\nab+c d", AttestVendorsApi.decodeIssuerChainHeader("-----BEGIN%20CERTIFICATE-----%0Aab+c%20d"));
    }

    @Test void validityWindowsOfARealCertificate() throws Exception {
        X509Certificate c = selfSigned("validity");
        double[] w = AttestVendorsApi.x509ValidityMs(c);
        assertEquals(c.getNotBefore().getTime() / 1000 * 1000, (long) w[0]);
        assertEquals(c.getNotAfter().getTime() / 1000 * 1000, (long) w[1]);
        assertArrayEquals(w, AttestVendorsApi.derValidityMs(c.getEncoded()));
        long now = System.currentTimeMillis();
        assertTrue(AttestVendorsApi.x509ValidAt(c, now, 0));
        assertFalse(AttestVendorsApi.x509ValidAt(c, now + 5L * 86_400_000L, 0), "expired");
        assertTrue(AttestVendorsApi.x509ValidAt(c, now + 5L * 86_400_000L, 4 * 86_400_000.0 * 2), "inside the skew");
        assertFalse(AttestVendorsApi.x509ValidAt(c, now, Double.NaN), "an unparseable skew fails closed");
        double[] bad = AttestVendorsApi.derValidityMs(new byte[] {1, 2, 3});
        assertTrue(Double.isNaN(bad[0]) && Double.isNaN(bad[1]));
    }

    @Test void parseOpenSslTime() {
        assertEquals(Instant.parse("2030-01-05T03:04:05Z").toEpochMilli(), (long) AttestVendorsApi.parseOpenSslTime("Jan  5 03:04:05 2030 GMT"));
        assertEquals(Instant.parse("2030-12-25T23:59:59Z").toEpochMilli() + 500, (long) AttestVendorsApi.parseOpenSslTime("Dec 25 23:59:59.5 2030 GMT"));
        for (Object bad : new Object[] {"Feb 30 00:00:00 2030 GMT", "Foo 01 00:00:00 2030 GMT", "Jan 01 24:00:00 2030 GMT", "garbage", "", 5, null})
            assertTrue(Double.isNaN(AttestVendorsApi.parseOpenSslTime(bad)), String.valueOf(bad));
    }

    @Test void x5cChainsFailClosedOnEmptyUnanchoredAndAnchorlessInput() throws Exception {
        assertEquals("empty x5c certificate chain", AttestVendorsApi.verifyX5cChain(List.of(), new LinkedHashMap<>(), 0, null).get("reason"));
        assertEquals("empty x5c certificate chain", AttestVendorsApi.verifyJwkX5cChain(List.of(), new LinkedHashMap<>(), 0, 0));
        X509Certificate c = selfSigned("chain");
        List<String> x5c = List.of(Base64.getEncoder().encodeToString(c.getEncoded()));
        Map<String, Object> none = AttestVendorsApi.verifyX5cChain(x5c, new LinkedHashMap<>(), System.currentTimeMillis(), null);
        assertEquals(Boolean.FALSE, none.get("ok"));
        assertEquals("no MAA trust anchor configured (fail closed)", none.get("reason"));
        Map<String, Object> anchors = new LinkedHashMap<>();
        anchors.put("rootSpkiSha256", new ArrayList<Object>(List.of("00".repeat(32))));
        Map<String, Object> wrong = AttestVendorsApi.verifyX5cChain(x5c, anchors, System.currentTimeMillis(), null);
        assertEquals(Boolean.FALSE, wrong.get("ok"));
        assertNotNull(wrong.get("reason"));
        Map<String, Object> expired = AttestVendorsApi.verifyX5cChain(x5c, anchors, System.currentTimeMillis() + 10L * 86_400_000L, null);
        assertEquals("x5c certificate at index 0 is outside its validity window", expired.get("reason"));
        assertEquals("x5c chain does not anchor in a configured GCP trust root", AttestVendorsApi.verifyJwkX5cChain(x5c, new LinkedHashMap<>(), System.currentTimeMillis(), 0));
    }

    @Test void theGcpFetcherFollowsTheDiscoveryDocumentAndRefusesRedirectsAndErrors() throws Exception {
        List<String> asked = new ArrayList<>();
        AttestMaaKeys.Fetch ok = url -> {
            asked.add(url);
            String body = url.endsWith("/.well-known/openid-configuration") ? "{\"jwks_uri\":\"https://g.example/keys\"}"
                : "{\"keys\":[{\"kid\":\"k1\",\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"junk\":1,\"x5c\":[\"QQ==\"]}]}";
            return new AttestMaaKeys.Response(200, url, null, body.getBytes(StandardCharsets.UTF_8));
        };
        Map<String, Object> r = AttestVendorsApi.fetchGcpConfidentialSpaceJwks("https://g.example/", ok, null);
        assertEquals(List.of("https://g.example/.well-known/openid-configuration", "https://g.example/keys"), asked);
        @SuppressWarnings("unchecked") Map<String, Object> key = (Map<String, Object>) ((List<?>) r.get("keys")).get(0);
        assertEquals("k1", key.get("kid"));
        assertFalse(key.containsKey("junk"));
        assertEquals(List.of("QQ=="), key.get("x5c"));
        assertThrows(IllegalStateException.class, () -> AttestVendorsApi.fetchGcpConfidentialSpaceJwks("https://g.example", u -> new AttestMaaKeys.Response(503, u, null, new byte[0]), null));
        assertThrows(IllegalStateException.class, () -> AttestVendorsApi.fetchGcpConfidentialSpaceJwks("https://g.example", u -> new AttestMaaKeys.Response(200, "https://evil.example/x", null, "{}".getBytes(StandardCharsets.UTF_8)), "https://g.example/keys"));
        assertThrows(IllegalStateException.class, () -> AttestVendorsApi.fetchGcpConfidentialSpaceJwks("https://g.example", u -> new AttestMaaKeys.Response(200, u, null, "{}".getBytes(StandardCharsets.UTF_8)), "https://g.example/keys"));
    }
}
