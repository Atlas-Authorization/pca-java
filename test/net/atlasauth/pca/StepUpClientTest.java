package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import net.atlasauth.pca.stepup.FileSecretStore;
import net.atlasauth.pca.stepup.MemorySecretStore;
import net.atlasauth.pca.stepup.PrincipalDeviceKey;
import net.atlasauth.pca.stepup.StepUpClient;
import net.atlasauth.pca.stepup.StepUpException;

/**
 * The step-up client for the principal's device: the device key (RFC 8032 vectors), the secret stores and the client against a
 * fake transport (no network).
 */
public class StepUpClientTest {
    static final long NOW = 1_799_999_999_000L; // one second before 2027-01-15T08:00:00Z (= 1_800_000_000_000 ms)
    static final byte[] MSG = "threshold message bytes".getBytes(StandardCharsets.UTF_8);

    static String b64(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
    static byte[] hex(String h) { return HexFormat.of().parseHex(h); }

    // RFC 8032 section 7.1 test 1 (empty message) and test 2 (one byte, 0x72)
    static final String[][] RFC = {
        {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
        {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
    };

    @Test void rfc8032Vectors() {
        for (String[] v : RFC) {
            PrincipalDeviceKey k = new PrincipalDeviceKey(new MemorySecretStore());
            assertEquals(b64(hex(v[1])), k.importSecret(b64(hex(v[0]))));
            assertEquals(b64(hex(v[1])), k.publicKey());
            assertEquals(b64(hex(v[3])), k.sign(hex(v[2])));
        }
    }

    @Test void keyLifecycle() {
        PrincipalDeviceKey k = new PrincipalDeviceKey(new MemorySecretStore());
        assertFalse(k.exists());
        assertThrows(StepUpException.NoDeviceKey.class, () -> k.sign(MSG));
        assertThrows(StepUpException.NoDeviceKey.class, k::publicKey);
        String pub = k.generate();
        assertTrue(k.exists());
        assertEquals(pub, k.publicKey());
        assertTrue(IntentJs.verifyEd(pub, MSG, k.sign(MSG)));
        PrincipalDeviceKey other = new PrincipalDeviceKey(new MemorySecretStore());
        assertEquals(pub, other.importSecret(k.exportSecret()));
        k.delete();
        assertFalse(k.exists());
    }

    @Test void importRejectsABadSecret() {
        for (String bad : new String[] {"", "AAAA", "not base64!", b64(new byte[31]), b64(new byte[33]), b64(new byte[32]) + "="})
            assertThrows(StepUpException.InvalidSecret.class, () -> new PrincipalDeviceKey(new MemorySecretStore()).importSecret(bad), bad);
    }

    @Test void fileStoreRoundTripsAndIsPrivate() throws Exception {
        Path dir = Files.createTempDirectory("pca-stepup");
        Path f = dir.resolve("principal.key");
        try {
            PrincipalDeviceKey k = new PrincipalDeviceKey(new FileSecretStore(f));
            String pub = k.generate();
            if (Files.getFileStore(f).supportsFileAttributeView("posix"))
                assertEquals("rw-------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(f)));
            assertEquals(pub, new PrincipalDeviceKey(new FileSecretStore(f)).publicKey());
            k.delete();
            assertFalse(Files.exists(f));
            assertFalse(k.exists());
        } finally {
            Files.deleteIfExists(f);
            Files.deleteIfExists(dir);
        }
    }

    // ---- the client ----------------------------------------------------------------------------------------------------

    static final class Fake implements StepUpClient.Transport {
        final LinkedList<Object> answers = new LinkedList<>();
        final List<String[]> calls = new ArrayList<>();
        final List<Map<String, String>> headers = new ArrayList<>();
        final List<byte[]> bodies = new ArrayList<>();

        Fake(Object... a) { for (Object o : a) answers.add(o); }

        @Override public StepUpClient.Response send(String method, String url, Map<String, String> h, byte[] body) throws IOException {
            calls.add(new String[] {method, url});
            headers.add(h);
            bodies.add(body);
            Object a = answers.removeFirst();
            if (a instanceof IOException) throw (IOException) a;
            return (StepUpClient.Response) a;
        }
    }

    static StepUpClient.Response answer(int status, String body) { return new StepUpClient.Response(status, body); }

    static StepUpClient client(Fake fake, PrincipalDeviceKey key) {
        if (!key.exists()) key.generate();
        Supplier<String> token = () -> "tok";
        return new StepUpClient("https://dash.example/", "https://atlas.example", "acct 1", "ins_1", key, token, fake, () -> NOW);
    }

    static StepUpClient client(Fake fake) { return client(fake, new PrincipalDeviceKey(new MemorySecretStore())); }

    static String item(String id, String exp, String msg, String requiredT) {
        return "{\"id\":\"" + id + "\",\"grant_ref\":\"g1\",\"action\":{\"verb\":\"payments.send\",\"resource\":\"payments/acme\"},\"required_t\":" + requiredT
            + ",\"threshold_message\":\"" + msg + "\",\"expires_at\":\"" + exp + "\"}";
    }
    static String item(String id, String exp) { return item(id, exp, b64(MSG), "2"); }
    static StepUpClient.Response list(String... items) { return answer(200, "{\"stepups\":[" + String.join(",", items) + "]}"); }

    @Test void pendingListsUnexpiredStepUpsAndSendsTheTokenToTheDashboardOnly() {
        Fake fake = new Fake(list(item("su_1", "2027-01-15T08:00:00.500Z"), item("su_old", "2020-01-01T00:00:00Z"), item("su_2", "2027-01-15T08:00:00Z")));
        List<StepUpClient.PendingStepUp> out = client(fake).pending();
        assertEquals(2, out.size());
        assertEquals("su_1", out.get(0).id);
        assertEquals("payments.send", out.get(0).actionVerb);
        assertEquals("payments/acme", out.get(0).actionResource);
        assertEquals(2, out.get(0).requiredT);
        assertEquals(1_800_000_000_500L, out.get(0).expiresAt);
        assertEquals("su_2", out.get(1).id);
        assertEquals(1_800_000_000_000L, out.get(1).expiresAt);
        assertEquals("GET", fake.calls.get(0)[0]);
        assertNull(fake.bodies.get(0));
        assertEquals("https://dash.example/v1/dashboard/accounts/acct%201/instances/ins_1/pca/stepups?status=pending", fake.calls.get(0)[1]);
        assertEquals("Bearer tok", fake.headers.get(0).get("Authorization"));
    }

    @Test void pendingParsesTheFractionExactly() {
        String[][] cases = {{"2027-01-15T08:00:00.5Z", "500"}, {"2027-01-15T08:00:00.123456Z", "123"}, {"2027-01-15T08:00:00Z", "0"}};
        for (String[] c : cases)
            assertEquals(1_800_000_000_000L + Long.parseLong(c[1]), client(new Fake(list(item("su", c[0])))).pending().get(0).expiresAt, c[0]);
    }

    @Test void pendingRejectsUnreadableAnswers() {
        StepUpClient.Response[] bad = {answer(200, "not json"), answer(200, "{\"stepups\":\"x\"}"), answer(200, "{}"),
            list(item("a", "yesterday")), list(item("a", "2027-01-15T08:00:00Z", b64(MSG), "true")), list("{\"id\":\"x\"}")};
        for (int i = 0; i < bad.length; i++) {
            StepUpClient c = client(new Fake(bad[i]));
            assertThrows(StepUpException.TransportError.class, c::pending, "case " + i);
        }
    }

    @Test void approveSignsTheThresholdMessageAndNeverSendsTheDashboardToken() {
        Fake fake = new Fake(list(item("su_1", "2027-01-15T08:00:00.500Z")), answer(200, "{\"status\":\"anchored\",\"allow\":true}"));
        PrincipalDeviceKey key = new PrincipalDeviceKey(new MemorySecretStore());
        StepUpClient c = client(fake, key);
        StepUpClient.ApproveResult r = c.approve(c.pending().get(0));
        assertEquals("anchored", r.status);
        assertTrue(r.anchored);
        assertEquals(200, r.httpStatus);
        assertEquals("POST", fake.calls.get(1)[0]);
        assertEquals("https://atlas.example/v1/pca/stepups/su_1/cosign", fake.calls.get(1)[1]);
        assertFalse(fake.headers.get(1).containsKey("Authorization"));
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) Json.parseLenient(new String(fake.bodies.get(1), StandardCharsets.UTF_8));
        assertEquals("principal", payload.get("role"));
        assertEquals(key.publicKey(), payload.get("publicKey"));
        assertTrue(IntentJs.verifyEd(payload.get("publicKey"), MSG, payload.get("sig")));
    }

    @Test void approve202MeansMoreRolesAreRequired() {
        StepUpClient c = client(new Fake(list(item("su_1", "2027-01-15T08:00:00Z")), answer(202, "{\"status\":\"pending\",\"allow\":false}")));
        StepUpClient.ApproveResult r = c.approve(c.pending().get(0));
        assertEquals("pending", r.status);
        assertFalse(r.anchored);
        assertEquals(202, r.httpStatus);
    }

    @Test void approveMapsErrors() {
        String err = "{\"errors\":[{\"code\":\"x\",\"message\":\"%s\"}]}";
        StepUpClient c = client(new Fake(list(item("su_1", "2027-01-15T08:00:00Z")), answer(403, String.format(err, "not the principal")),
            answer(500, String.format(err, "boom")), answer(502, "<html>")));
        StepUpClient.PendingStepUp s = c.pending().get(0);
        StepUpException.PrincipalMismatch pm = assertThrows(StepUpException.PrincipalMismatch.class, () -> c.approve(s));
        assertEquals("not the principal", pm.getMessage());
        StepUpException.ApiError e500 = assertThrows(StepUpException.ApiError.class, () -> c.approve(s));
        assertEquals(500, e500.status);
        assertEquals("boom", e500.getMessage());
        StepUpException.ApiError e502 = assertThrows(StepUpException.ApiError.class, () -> c.approve(s));
        assertEquals(502, e502.status);
        assertEquals("The request failed.", e502.getMessage());
    }

    @Test void approveRefusesANonCanonicalThresholdMessageBeforeSigning() {
        Fake fake = new Fake(list(item("su_1", "2027-01-15T08:00:00Z", "AAAA=", "2")));
        StepUpClient c = client(fake);
        StepUpClient.PendingStepUp s = c.pending().get(0);
        assertThrows(StepUpException.InvalidThresholdMessage.class, () -> c.approve(s));
        assertEquals(1, fake.calls.size()); // nothing was posted
    }

    @Test void aNetworkFailureIsATransportError() {
        StepUpClient c = client(new Fake(new IOException("down")));
        assertThrows(StepUpException.TransportError.class, c::pending);
    }

    @Test void denyPostsTheReasonToTheDashboard() {
        Fake fake = new Fake(list(item("su_1", "2027-01-15T08:00:00Z")), answer(200, "{}"), answer(200, "{}"));
        StepUpClient c = client(fake);
        StepUpClient.PendingStepUp s = c.pending().get(0);
        c.deny(s, "not me");
        c.deny(s);
        assertEquals("POST", fake.calls.get(1)[0]);
        assertEquals("https://dash.example/v1/dashboard/accounts/acct%201/instances/ins_1/pca/stepups/su_1/deny", fake.calls.get(1)[1]);
        assertEquals("{\"reason\":\"not me\"}", new String(fake.bodies.get(1), StandardCharsets.UTF_8));
        assertEquals("Bearer tok", fake.headers.get(1).get("Authorization"));
        assertEquals("{}", new String(fake.bodies.get(2), StandardCharsets.UTF_8));
    }

    @Test void urlsMustBeHttp() {
        for (String bad : new String[] {"ftp://x", "file:///etc/passwd", "dash.example", ""})
            assertThrows(IllegalArgumentException.class,
                () -> new StepUpClient(bad, "https://a.example", "a", "i", new PrincipalDeviceKey(new MemorySecretStore()), () -> "t"), bad);
        assertArrayEquals(new byte[] {1, 2}, new MemorySecretStoreProbe().roundTrip(new byte[] {1, 2}));
    }

    /** The memory store copies what it keeps. */
    static final class MemorySecretStoreProbe {
        byte[] roundTrip(byte[] b) {
            MemorySecretStore s = new MemorySecretStore();
            s.save(b);
            b[0] = 9;
            return s.load();
        }
    }
}
