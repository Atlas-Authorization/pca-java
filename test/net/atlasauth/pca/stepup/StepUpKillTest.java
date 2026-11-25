package net.atlasauth.pca.stepup;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.LongSupplier;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.Test;

import net.atlasauth.pca.Json;

/** The step-up client's edge cases, its built-in transport against a local server, the device key and the file store. */
public class StepUpKillTest {
    static final long NOW = 1_799_999_999_000L; // 2027-01-15T07:59:59Z
    static final String MSG = Base64.getUrlEncoder().withoutPadding().encodeToString("m".getBytes(StandardCharsets.UTF_8));

    static final class Fake implements StepUpClient.Transport {
        final LinkedList<Object> answers = new LinkedList<>();
        final List<String> urls = new ArrayList<>();
        final List<Map<String, String>> headers = new ArrayList<>();

        Fake(Object... a) { for (Object o : a) answers.add(o); }

        @Override public StepUpClient.Response send(String method, String url, Map<String, String> h, byte[] body) throws IOException {
            urls.add(url);
            headers.add(h);
            Object a = answers.removeFirst();
            if (a instanceof IOException) throw (IOException) a;
            return (StepUpClient.Response) a;
        }
    }

    static PrincipalDeviceKey key() {
        PrincipalDeviceKey k = new PrincipalDeviceKey(new MemorySecretStore());
        k.generate();
        return k;
    }

    static StepUpClient client(Fake f, LongSupplier now) {
        return new StepUpClient("https://dash.example", "https://atlas.example//", "acct", "ins 1", key(), () -> "tok", f, now);
    }

    static StepUpClient client(Fake f) { return client(f, () -> NOW); }

    static Map<String, Object> entry(String exp) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", "a b*c~d");
        m.put("grant_ref", "g1");
        m.put("action", new LinkedHashMap<>(Map.of("verb", "v", "resource", "r")));
        m.put("required_t", new Json.Num("2"));
        m.put("threshold_message", MSG);
        m.put("expires_at", exp);
        return m;
    }

    @SafeVarargs
    static StepUpClient.Response list(Map<String, Object>... es) {
        return new StepUpClient.Response(200, Json.canonicalize(Map.of("stepups", List.of((Object[]) es))));
    }

    static StepUpClient.Response ok(String body) { return new StepUpClient.Response(200, body); }

    // ---- construction ----

    @Test void requiredArgumentsAndUrls() {
        PrincipalDeviceKey k = key();
        String need = "accountId, instanceId, key and token are required";
        assertEquals(need, assertThrows(IllegalArgumentException.class, () -> new StepUpClient("https://d.example", "https://a.example", null, "i", k, () -> "t")).getMessage());
        assertEquals(need, assertThrows(IllegalArgumentException.class, () -> new StepUpClient("https://d.example", "https://a.example", "a", null, k, () -> "t")).getMessage());
        assertEquals(need, assertThrows(IllegalArgumentException.class, () -> new StepUpClient("https://d.example", "https://a.example", "a", "i", null, () -> "t")).getMessage());
        assertEquals(need, assertThrows(IllegalArgumentException.class, () -> new StepUpClient("https://d.example", "https://a.example", "a", "i", k, null)).getMessage());
        assertEquals("a step-up URL must be an http(s) URL: null",
            assertThrows(IllegalArgumentException.class, () -> new StepUpClient(null, "https://a.example", "a", "i", k, () -> "t")).getMessage());
        assertEquals("a step-up URL must be an http(s) URL: http://exa mple",
            assertThrows(IllegalArgumentException.class, () -> new StepUpClient("http://exa mple", "https://a.example", "a", "i", k, () -> "t")).getMessage());
        assertThrows(IllegalArgumentException.class, () -> new StepUpClient("https:///x", "https://a.example", "a", "i", k, () -> "t"));
        StepUpClient c = new StepUpClient("http://d.example", "https://a.example", "a", "i", k, () -> "t", new Fake(), () -> NOW);
        assertSame(k, c.key());
        new StepUpClient("https://d.example", "http://a.example", "a", "i", k, () -> "t", new Fake(), () -> NOW);
        assertEquals(Duration.ofSeconds(30), StepUpClient.DEFAULT_TIMEOUT);
    }

    // ---- pending ----

    @Test void pendingReadsEveryMemberAndQuotesThePath() {
        Fake f = new Fake(list(entry("2027-01-15T08:00:00Z")));
        StepUpClient.PendingStepUp p = client(f).pending().get(0);
        assertEquals("a b*c~d", p.id);
        assertEquals("g1", p.grantRef);
        assertEquals("v", p.actionVerb);
        assertEquals("r", p.actionResource);
        assertEquals(2, p.requiredT);
        assertEquals(MSG, p.thresholdMessage);
        assertEquals("https://dash.example/v1/dashboard/accounts/acct/instances/ins%201/pca/stepups?status=pending", f.urls.get(0));
        assertEquals("application/json", f.headers.get(0).get("Accept"));
        assertEquals("Bearer tok", f.headers.get(0).get("Authorization"));
    }

    @Test void pendingExpiryIsStrictAndUsesTheGivenClock() {
        // expiring exactly now is expired; one millisecond later is pending
        assertTrue(client(new Fake(list(entry("2027-01-15T07:59:59Z")))).pending().isEmpty());
        assertEquals(1, client(new Fake(list(entry("2027-01-15T07:59:59.001Z")))).pending().size());
        // a clock in 2030 sees a 2028 expiry as past
        assertTrue(client(new Fake(list(entry("2028-01-01T00:00:00Z"))), () -> 1_900_000_000_000L).pending().isEmpty());
        // no clock: the wall clock
        assertEquals(1, client(new Fake(list(entry("2020-01-01T00:00:00Z"), entry("2999-01-01T00:00:00Z"))), null).pending().size());
    }

    static Throwable unreadable(StepUpClient.Response r) {
        StepUpException.TransportError e = assertThrows(StepUpException.TransportError.class, client(new Fake(r))::pending);
        return e.getCause();
    }

    @SuppressWarnings("unchecked")
    @Test void anUnreadableEntryNamesItsCause() {
        Throwable c = unreadable(ok("{}"));
        assertInstanceOf(IllegalArgumentException.class, c);
        assertEquals("no stepups", c.getMessage());
        for (String member : new String[] {"id", "grant_ref", "threshold_message", "expires_at"}) {
            Map<String, Object> e = entry("2027-01-15T08:00:00Z");
            e.put(member, new Json.Num("5"));
            c = unreadable(list(e));
            assertInstanceOf(IllegalArgumentException.class, c, member);
            assertEquals("expected a string", c.getMessage(), member);
        }
        for (String member : new String[] {"verb", "resource"}) {
            Map<String, Object> e = entry("2027-01-15T08:00:00Z");
            ((Map<String, Object>) e.get("action")).remove(member);
            c = unreadable(list(e));
            assertEquals("expected a string", c.getMessage(), member);
        }
        c = unreadable(list(entry("yesterday")));
        assertInstanceOf(IllegalArgumentException.class, c);
        assertEquals("bad timestamp", c.getMessage());
        for (Object t : new Object[] {Boolean.TRUE, "2", new Json.Num("1.5")}) {
            Map<String, Object> e = entry("2027-01-15T08:00:00Z");
            e.put("required_t", t);
            c = unreadable(list(e));
            assertInstanceOf(IllegalArgumentException.class, c, String.valueOf(t));
            assertEquals("required_t", c.getMessage());
        }
    }

    @Test void isoTimestamps() {
        assertEquals(1_800_000_000_000L, StepUpClient.parseIso("2027-01-15T08:00:00Z"));
        // more than nine fraction digits: still cut to milliseconds
        assertEquals(1_800_000_000_123L, StepUpClient.parseIso("2027-01-15T08:00:00.1234567891Z"));
        assertEquals("bad timestamp", assertThrows(IllegalArgumentException.class, () -> StepUpClient.parseIso("2027-01-15 08:00:00Z")).getMessage());
    }

    // ---- call ----

    @Test void callMapsEveryFailure() {
        IOException down = new IOException("down");
        StepUpException.TransportError t = assertThrows(StepUpException.TransportError.class, client(new Fake(down))::pending);
        assertEquals("down", t.getMessage());
        assertSame(down, t.getCause());
        assertEquals("Network error.", assertThrows(StepUpException.TransportError.class, client(new Fake(new IOException()))::pending).getMessage());
        assertEquals("No answer.", assertThrows(StepUpException.TransportError.class, client(new Fake((Object) null))::pending).getMessage());
        for (int st : new int[] {199, 300, 404}) {
            StepUpException.ApiError a = assertThrows(StepUpException.ApiError.class, client(new Fake(new StepUpClient.Response(st, "{}")))::pending);
            assertEquals(st, a.status);
            assertEquals("The request failed.", a.getMessage());
        }
        assertEquals(0, client(new Fake(new StepUpClient.Response(299, "{\"stepups\":[]}"))).pending().size());
        StepUpException.ApiError a = assertThrows(StepUpException.ApiError.class,
            client(new Fake(new StepUpClient.Response(500, "{\"errors\":[{\"message\":5}]}")))::pending);
        assertEquals("The request failed.", a.getMessage());
    }

    // ---- approve / deny ----

    StepUpClient.PendingStepUp one() { return client(new Fake(list(entry("2027-01-15T08:00:00Z")))).pending().get(0); }

    @Test void approveHeadersPathAndOddAnswers() {
        Fake f = new Fake(ok("{\"status\":\"anchored\",\"allow\":true}"), ok("[1]"), ok("not json"), ok("null"), ok("{\"status\":5,\"allow\":true}"));
        StepUpClient c = client(f);
        StepUpClient.ApproveResult r = c.approve(one());
        assertTrue(r.anchored);
        assertEquals("https://atlas.example/v1/pca/stepups/a%20b%2Ac~d/cosign", f.urls.get(0));
        assertEquals("application/json", f.headers.get(0).get("Content-Type"));
        assertEquals("application/json", f.headers.get(0).get("Accept"));
        for (int i = 0; i < 3; i++) {
            r = c.approve(one());
            assertEquals("", r.status, "answer " + i);
            assertFalse(r.anchored, "answer " + i);
            assertEquals(200, r.httpStatus);
        }
        r = c.approve(one());
        assertEquals("", r.status);
        assertTrue(r.anchored);
    }

    @Test void denyHeadersAndPath() {
        Fake f = new Fake(ok("{}"));
        client(f).deny(one(), "r");
        assertEquals("https://dash.example/v1/dashboard/accounts/acct/instances/ins%201/pca/stepups/a%20b%2Ac~d/deny", f.urls.get(0));
        assertEquals("application/json", f.headers.get(0).get("Content-Type"));
        assertEquals("application/json", f.headers.get(0).get("Accept"));
        assertEquals("Bearer tok", f.headers.get(0).get("Authorization"));
    }

    // ---- the built-in transport, against a local server ----

    @Test void defaultTransportAgainstALocalServer() throws Exception {
        HttpServer srv = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        ExecutorService pool = Executors.newCachedThreadPool();
        srv.setExecutor(pool);
        srv.createContext("/echo", ex -> {
            byte[] in = ex.getRequestBody().readAllBytes();
            byte[] out = (ex.getRequestMethod() + "|" + ex.getRequestHeaders().getFirst("X-T") + "|" + new String(in, StandardCharsets.UTF_8) + "|é")
                .getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(201, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        srv.createContext("/redirect", ex -> {
            ex.getResponseHeaders().add("Location", "/echo");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        srv.createContext("/slow", ex -> {
            try { Thread.sleep(3000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        srv.createContext("/", ex -> {
            byte[] out = "{\"stepups\":[]}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        srv.start();
        try {
            String base = "http://127.0.0.1:" + srv.getAddress().getPort();
            StepUpClient.Transport t = StepUpClient.defaultTransport(Duration.ofSeconds(10));
            StepUpClient.Response r = t.send("POST", base + "/echo", Map.of("X-T", "v"), "hi".getBytes(StandardCharsets.UTF_8));
            assertEquals(201, r.status);
            assertEquals("POST|v|hi|é", r.body);
            r = t.send("GET", base + "/echo", Map.of(), null);
            assertEquals("GET|null||é", r.body);
            // redirects are not followed
            r = t.send("GET", base + "/redirect", Map.of(), null);
            assertEquals(302, r.status);
            // the timeout bounds the exchange
            StepUpClient.Transport quick = StepUpClient.defaultTransport(Duration.ofMillis(300));
            assertThrows(IOException.class, () -> quick.send("GET", base + "/slow", Map.of(), null));
            // an interrupted caller gets an IOException and keeps its interrupt flag
            Thread.currentThread().interrupt();
            try {
                IOException e = assertThrows(IOException.class, () -> t.send("GET", base + "/slow", Map.of(), null));
                assertEquals("interrupted", e.getMessage());
                assertInstanceOf(InterruptedException.class, e.getCause());
                assertTrue(Thread.currentThread().isInterrupted());
            } finally {
                Thread.interrupted();
            }
            // a client without a transport uses the built-in one (and the wall clock)
            StepUpClient c = new StepUpClient(base, base, "a", "i", key(), () -> "t");
            assertTrue(c.pending().isEmpty());
        } finally {
            srv.stop(0);
            pool.shutdownNow();
        }
    }

    // ---- the device key ----

    @Test void deviceKeyEdges() {
        assertEquals("store", assertThrows(IllegalArgumentException.class, () -> new PrincipalDeviceKey(null)).getMessage());
        SecretStore broken = new SecretStore() {
            @Override public byte[] load() { throw new IllegalStateException("x"); }
            @Override public void save(byte[] s) {}
            @Override public void delete() {}
        };
        assertFalse(new PrincipalDeviceKey(broken).exists());
        PrincipalDeviceKey k = new PrincipalDeviceKey(new MemorySecretStore());
        String a = k.generate(), b = k.generate();
        assertNotEquals(a, b);
        String zero = new PrincipalDeviceKey(new MemorySecretStore()).importSecret(Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]));
        assertNotEquals(zero, a);
        MemorySecretStore shortSeed = new MemorySecretStore();
        shortSeed.save(new byte[31]);
        assertEquals("The stored secret is not a 32-byte seed.",
            assertThrows(StepUpException.InvalidSecret.class, () -> new PrincipalDeviceKey(shortSeed).sign(new byte[1])).getMessage());
    }

    // ---- the file store ----

    @Test void fileStoreEdges() throws Exception {
        assertEquals("path", assertThrows(IllegalArgumentException.class, () -> new FileSecretStore(null)).getMessage());
        Path dir = Files.createTempDirectory("pca-stepup-kill");
        try {
            Path f = dir.resolve("k");
            FileSecretStore s = new FileSecretStore(f);
            assertNull(s.load());
            s.save(new byte[] {1, 2, 3});
            s.save(new byte[] {4, 5});
            assertArrayEquals(new byte[] {4, 5}, s.load());
            Files.writeString(f, "AQID\n");
            assertEquals(3, s.load().length);
            s.delete();
            assertFalse(Files.exists(f));
            // I/O failures surface as UncheckedIOException
            Path sub = Files.createDirectory(dir.resolve("sub"));
            Files.writeString(sub.resolve("x"), "x");
            assertThrows(UncheckedIOException.class, () -> new FileSecretStore(sub).load());
            assertThrows(UncheckedIOException.class, () -> new FileSecretStore(sub).delete());
            assertThrows(UncheckedIOException.class, () -> new FileSecretStore(dir.resolve("missing").resolve("k")).save(new byte[] {1}));
            Files.delete(sub.resolve("x"));
            Files.delete(sub);
            // a file system without POSIX permissions
            Path zip = dir.resolve("z.zip");
            try (FileSystem zfs = FileSystems.newFileSystem(zip, Map.of("create", "true"))) {
                FileSecretStore z = new FileSecretStore(zfs.getPath("/k"));
                z.save(new byte[] {7, 8});
                assertEquals(2, z.load().length);
                assertEquals(7, z.load()[0]);
            }
            Files.deleteIfExists(zip);
        } finally {
            try (var w = Files.walk(dir)) {
                w.sorted(java.util.Comparator.reverseOrder()).forEach(p -> { try { Files.deleteIfExists(p); } catch (IOException e) { /* best effort */ } });
            }
        }
    }
}
