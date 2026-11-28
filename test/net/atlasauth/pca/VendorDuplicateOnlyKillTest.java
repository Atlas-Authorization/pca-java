package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.ecKey;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * Vendor attestation documents (MAA / Confidential Space JWT segments, Intel collateral, Azure runtime data) are real third-party JSON,
 * not canonical JSON: a repeated member is refused, every other number spelling (8.0, 1e3, -0) is read as written, a document up to
 * 16 MiB is read, and anything that does not parse has one engine-independent reason.
 */
public class VendorDuplicateOnlyKillTest {
    private static String seg(String json) { return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8)); }

    private static String why(String token) {
        try {
            AttestJws.parseJwt(token, "P");
        } catch (AttestException e) {
            return e.getMessage();
        }
        return "no error";
    }

    private static final String H = "{\"alg\":\"ES256\"}";
    private static final String SIG = "AQ";

    @Test void jwtSegmentsRefuseADuplicateAndKeepNumbersAsWritten() {
        assertEquals("P: malformed JSON segment: invalid JSON", why(seg(H) + "." + seg("{\"a\":1,\"a\":2}") + "." + SIG));
        assertEquals("P: malformed JSON segment: invalid JSON", why(seg("{\"alg\":\"ES256\",\"alg\":\"none\"}") + "." + seg("{}") + "." + SIG));
        assertEquals("no error", why(seg(H) + "." + seg("{\"a\":8.0,\"b\":1e3,\"c\":-0}") + "." + SIG));
        assertEquals("P: malformed JSON segment: invalid JSON", why(seg("not json") + "." + seg("{}") + "." + SIG));
        assertEquals("P: malformed JSON segment: invalid JSON", why(seg(H) + "." + seg("not json") + "." + SIG));
    }

    @Test void collateralRefusesADuplicateButReadsOtherSpellings() throws Exception {
        KeyPair k = ecKey("secp256r1");
        CertKey key = CertKey.of(k.getPublic(), k.getPublic().getEncoded());
        String dup = AttestIntelBaseKillTest.signed("tcbInfo", "{\"a\":1,\"a\":2}", k);
        assertEquals("tcbInfo document is not valid JSON", AttestIntelCollateral.verifySignedJson(dup, "tcbInfo", key).reason);
        AttestIntelCollateral.SignedBody ok = AttestIntelCollateral.verifySignedJson(AttestIntelBaseKillTest.signed("tcbInfo", "{\"a\":8.0,\"b\":1e3}", k), "tcbInfo", key);
        assertEquals("", ok.reason);
        assertNotNull(ok.body);
    }

    @Test void collateralSixteenMiBBound() throws Exception {
        KeyPair k = ecKey("secp256r1");
        CertKey key = CertKey.of(k.getPublic(), k.getPublic().getEncoded());
        int n = AttestCommon.MAX_JSON_BYTES;
        String head = "{\"tcbInfo\":{\"a\":\"", tail = "\"},\"signature\":\"zz\"}";
        String exact = head + "x".repeat(n - head.length() - tail.length()) + tail;
        assertEquals("tcbInfo signature missing or malformed", AttestIntelCollateral.verifySignedJson(exact, "tcbInfo", key).reason);
        AttestIntelCollateral.SignedBody over = AttestIntelCollateral.verifySignedJson(exact + " ", "tcbInfo", key);
        assertEquals("tcbInfo: malformed JSON segment: input too large", over.reason);
        assertNull(over.body);
    }

    @Test void azureRuntimeDataRefusesADuplicate() {
        byte[] rd = "{\"user-data\":\"a\",\"user-data\":\"b\"}".getBytes(StandardCharsets.UTF_8);
        byte[] report = new byte[64];
        System.arraycopy(AttestCommon.sha256Sum(rd), 0, report, 0, 32);
        assertEquals("runtime data is not valid JSON", AttestCommon.checkAzureRuntimeDataBinding(report, rd, null));
        byte[] plain = "{\"n\":8.0,\"e\":1e3}".getBytes(StandardCharsets.UTF_8);
        System.arraycopy(AttestCommon.sha256Sum(plain), 0, report, 0, 32);
        assertEquals("runtime data carries no 64-byte hex user-data", AttestCommon.checkAzureRuntimeDataBinding(report, plain, null));
    }

    private static java.util.Map<String, Object> certs(String body) {
        return AttestMaaKeys.fetchMaaCerts("https://maa.example", u -> new AttestMaaKeys.Response(200, u, null, body.getBytes(StandardCharsets.UTF_8)), null, null);
    }

    @Test void maaKeySetRefusesADuplicateButReadsOtherSpellings() {
        IllegalStateException e = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
            () -> certs("{\"keys\":[{\"kid\":\"a\",\"x5c\":[\"QQ==\"]}],\"keys\":[]}"));
        assertEquals("MAA certs response is not valid UTF-8 JSON", e.getMessage());
        java.util.List<?> keys = (java.util.List<?>) certs("{\"keys\":[{\"kid\":\"k\",\"x5c\":[\"QQ==\"],\"n\":8.0,\"e\":1e3}]}").get("keys");
        assertEquals("k", ((java.util.Map<?, ?>) keys.get(0)).get("kid"));
    }
}
