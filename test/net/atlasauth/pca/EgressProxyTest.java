package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.sandbox.Egress;
import net.atlasauth.pca.sandbox.EgressProxy;
import net.atlasauth.pca.sandbox.Receipts;
import org.junit.jupiter.api.Test;

/** The forward proxy: admitted requests are relayed, everything else is refused and receipted, private upstreams are refused, CONNECT tunnels. */
public class EgressProxyTest {
    /** A one-shot HTTP upstream that answers every request with a fixed body. */
    private static ServerSocket upstream(List<String> seen) throws IOException {
        ServerSocket ss = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread t = new Thread(() -> {
            while (!ss.isClosed()) {
                try (Socket s = ss.accept()) {
                    InputStream in = s.getInputStream();
                    ByteArrayOutputStream head = new ByteArrayOutputStream();
                    int c, last = 0, n = 0;
                    while ((c = in.read()) != -1) { head.write(c); if (c == '\n' && last == '\n') break; if (c != '\r') last = c; if (++n > 8192) break; }
                    seen.add(head.toString(StandardCharsets.ISO_8859_1).split("\r\n")[0]);
                    s.getOutputStream().write("HTTP/1.1 200 OK\r\nx-up: 1\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello".getBytes(StandardCharsets.ISO_8859_1));
                } catch (IOException e) {
                    return;
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return ss;
    }

    private static Authorize.AuthorizeResult allowed(Authorize.Operation op) {
        Authorize.AuthorizedOperation a = new Authorize.AuthorizedOperation(op.verb, op.resource, Pca.hashCanonical(op.params), "op1");
        return new Authorize.AuthorizeResult(true, 200, new LinkedHashMap<String, String>(), new ArrayList<String>(), null, a, null, null, new ArrayList<String>());
    }

    private static void admit(Egress.EgressPolicy p, Map<String, Object> template, long uses) {
        Authorize.Operation op = new Authorize.Operation("http.get", "upstream", new LinkedHashMap<String, Object>());
        p.admit(allowed(op), op, o -> template, Long.valueOf(uses), null);
    }

    private static Map<String, Object> template(String scheme, int port, String method, String path, boolean tunnel) {
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("scheme", scheme);
        t.put("host", "127.0.0.1");
        t.put("port", (long) port);
        t.put("method", method);
        t.put("path", path);
        if (tunnel) t.put("tunnel", Boolean.TRUE);
        return t;
    }

    private static String roundTrip(int proxyPort, String request) throws IOException {
        try (Socket s = new Socket(InetAddress.getLoopbackAddress(), proxyPort)) {
            s.setSoTimeout(5000);
            s.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
            s.getOutputStream().flush();
            return new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }

    @Test void relaysAnAdmittedRequestAndRefusesTheRest() throws Exception {
        List<String> seen = new ArrayList<>();
        try (ServerSocket up = upstream(seen)) {
            Egress.EgressPolicy policy = new Egress.EgressPolicy(null);
            admit(policy, template("http", up.getLocalPort(), "GET", "/hello", false), 2);
            Receipts.ReceiptLog log = new Receipts.ReceiptLog();
            EgressProxy.Options o = new EgressProxy.Options(policy, log);
            o.allowPrivate = true;
            try (EgressProxy proxy = EgressProxy.start(o, null, 0)) {
                String url = "http://127.0.0.1:" + up.getLocalPort() + "/hello";
                String r = roundTrip(proxy.port(), "GET " + url + " HTTP/1.1\r\nhost: x\r\nproxy-connection: keep-alive\r\n\r\n");
                assertTrue(r.startsWith("HTTP/1.1 200 OK"), r);
                assertTrue(r.endsWith("hello"), r);
                assertTrue(r.toLowerCase().contains("x-up: 1"));
                assertEquals("GET /hello HTTP/1.1", seen.get(0));
                assertTrue(roundTrip(proxy.port(), "GET " + url + " HTTP/1.1\r\nhost: x\r\n\r\n").startsWith("HTTP/1.1 200"));
                String spent = roundTrip(proxy.port(), "GET " + url + " HTTP/1.1\r\nhost: x\r\n\r\n");
                assertTrue(spent.startsWith("HTTP/1.1 403"), spent);
                assertTrue(spent.contains("\"reason\":\"spent\""), spent);
                String other = roundTrip(proxy.port(), "GET http://127.0.0.1:" + up.getLocalPort() + "/other HTTP/1.1\r\nhost: x\r\n\r\n");
                assertTrue(other.startsWith("HTTP/1.1 403") && other.contains("\"error\":\"egress_denied\""), other);
                assertEquals(2, seen.size(), "only the two admitted requests reached the upstream");
            }
            List<Map<String, Object>> e = log.entries();
            assertEquals(4, e.size());
            assertEquals("ok", e.get(0).get("outcome"));
            assertEquals("status:200", e.get(0).get("reason"));
            assertEquals("refused", e.get(2).get("outcome"));
            assertEquals("egress", e.get(0).get("kind"));
            assertEquals("egress_default_deny", e.get(0).get("runtime_class"));
            assertEquals("op1", ((Map<?, ?>) e.get(0).get("subject")).get("op_id"));
            assertEquals("", ((Map<?, ?>) e.get(2).get("subject")).get("op_id"));
        }
    }

    @Test void aPrivateUpstreamIsRefusedUnlessAllowed() throws Exception {
        List<String> seen = new ArrayList<>();
        try (ServerSocket up = upstream(seen)) {
            Egress.EgressPolicy policy = new Egress.EgressPolicy(null);
            admit(policy, template("http", up.getLocalPort(), "GET", "/x", false), 1);
            Receipts.ReceiptLog log = new Receipts.ReceiptLog();
            try (EgressProxy proxy = EgressProxy.start(new EgressProxy.Options(policy, log), null, 0)) {
                String r = roundTrip(proxy.port(), "GET http://127.0.0.1:" + up.getLocalPort() + "/x HTTP/1.1\r\nhost: x\r\n\r\n");
                assertTrue(r.startsWith("HTTP/1.1 502"), r);
            }
            assertTrue(seen.isEmpty(), "the upstream was never contacted");
            assertEquals("error", log.entries().get(0).get("outcome"));
            assertEquals("upstream:EACCES", log.entries().get(0).get("reason"));
        }
    }

    @Test void anOversizedBodyIsRefusedBeforeTheClaim() throws Exception {
        Egress.EgressPolicy policy = new Egress.EgressPolicy(null);
        Receipts.ReceiptLog log = new Receipts.ReceiptLog();
        EgressProxy.Options o = new EgressProxy.Options(policy, log);
        o.maxBodyBytes = 4;
        try (EgressProxy proxy = EgressProxy.start(o, null, 0)) {
            String r = roundTrip(proxy.port(), "POST http://127.0.0.1:1/x HTTP/1.1\r\nhost: x\r\ncontent-length: 10\r\n\r\n0123456789");
            assertTrue(r.startsWith("HTTP/1.1 413"), r);
        }
        assertEquals("body_too_large", log.entries().get(0).get("reason"));
    }

    @Test void connectOpensATunnelOnlyWhenAdmitted() throws Exception {
        try (ServerSocket echo = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            Thread t = new Thread(() -> {
                try (Socket s = echo.accept()) {
                    InputStream in = s.getInputStream();
                    OutputStream out = s.getOutputStream();
                    byte[] buf = new byte[64];
                    int n = in.read(buf);
                    if (n > 0) out.write(buf, 0, n);
                    out.flush();
                } catch (IOException e) {
                    // the test ended
                }
            });
            t.setDaemon(true);
            t.start();
            Egress.EgressPolicy policy = new Egress.EgressPolicy(null);
            admit(policy, template("https", echo.getLocalPort(), "CONNECT", "/", true), 1);
            Receipts.ReceiptLog log = new Receipts.ReceiptLog();
            EgressProxy.Options o = new EgressProxy.Options(policy, log);
            o.allowPrivate = true;
            try (EgressProxy proxy = EgressProxy.start(o, null, 0)) {
                String target = "127.0.0.1:" + echo.getLocalPort();
                try (Socket s = new Socket(InetAddress.getLoopbackAddress(), proxy.port())) {
                    s.setSoTimeout(5000);
                    s.getOutputStream().write(("CONNECT " + target + " HTTP/1.1\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                    s.getOutputStream().flush();
                    InputStream in = s.getInputStream();
                    ByteArrayOutputStream head = new ByteArrayOutputStream();
                    int c, n = 0;
                    while ((c = in.read()) != -1) { head.write(c); if (head.toString(StandardCharsets.ISO_8859_1).endsWith("\r\n\r\n")) break; if (++n > 512) break; }
                    assertTrue(head.toString(StandardCharsets.ISO_8859_1).startsWith("HTTP/1.1 200 Connection Established"), head.toString(StandardCharsets.ISO_8859_1));
                    s.getOutputStream().write("ping".getBytes(StandardCharsets.ISO_8859_1));
                    s.getOutputStream().flush();
                    assertEquals("ping", new String(in.readNBytes(4), StandardCharsets.ISO_8859_1));
                }
                String second = roundTrip(proxy.port(), "CONNECT " + target + " HTTP/1.1\r\n\r\n");
                assertTrue(second.startsWith("HTTP/1.1 403"), second);
            }
            assertEquals("tunnel", log.entries().get(0).get("reason"));
            assertEquals("refused", log.entries().get(1).get("outcome"));
        }
    }
}
