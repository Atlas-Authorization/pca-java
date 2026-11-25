package net.atlasauth.pca.sandbox;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import net.atlasauth.pca.Json;

/**
 * A forward proxy for non-WASM tools: set it as the tool's only route out ({@code HTTP(S)_PROXY}, a network namespace, or the generated OS
 * profile that permits connecting only to this proxy). Every request is claimed against the {@link Egress.EgressPolicy} admissions; a refusal
 * answers 403 and is receipted. The upstream address is resolved HERE and the connection goes to the resolved address, refusing any private
 * address unless {@code allowPrivate}, so an admitted hostname cannot be re-pointed at an internal service (and a rebinding answer between a
 * check and a connect cannot happen). Plain HTTP requests are forwarded with the hop-by-hop headers dropped, {@code CONNECT} opens a tunnel.
 */
public final class EgressProxy implements AutoCloseable {
    /** The proxy's options. */
    public static final class Options {
        public final Egress.EgressPolicy policy;
        public final Receipts.ReceiptLog log;
        public String runtimeClass = "egress_default_deny";
        /** Permit upstreams that resolve to private or loopback addresses (tests, internal APIs). Default false (the SSRF guard). */
        public boolean allowPrivate;
        public int maxBodyBytes = 1 << 20;
        public int upstreamTimeoutMs = 10_000;
        public Options(Egress.EgressPolicy policy, Receipts.ReceiptLog log) { this.policy = policy; this.log = log; }
    }

    private static final Set<String> HOP = Set.of("connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer",
        "transfer-encoding", "upgrade", "host");
    private static final int MAX_HEADER_BYTES = 64 * 1024;

    private final Options o;
    private final ServerSocket server;
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> { Thread t = new Thread(r, "pca-egress-proxy"); t.setDaemon(true); return t; });
    private volatile boolean closed;

    private EgressProxy(Options o, ServerSocket server) { this.o = o; this.server = server; }

    /** Listen on {@code bind}:{@code port} (port 0 picks one; bind null is the loopback interface) and serve until {@link #close()}. */
    public static EgressProxy start(Options o, InetAddress bind, int port) throws IOException {
        if (o == null || o.policy == null || o.log == null) throw new IllegalArgumentException("an egress proxy needs a policy and a receipt log");
        ServerSocket ss = new ServerSocket(port, 50, bind != null ? bind : InetAddress.getLoopbackAddress());
        EgressProxy p = new EgressProxy(o, ss);
        Thread acceptor = new Thread(p::acceptLoop, "pca-egress-accept");
        acceptor.setDaemon(true);
        acceptor.start();
        return p;
    }

    public int port() { return server.getLocalPort(); }

    @Override
    public void close() {
        closed = true;
        try { server.close(); } catch (IOException e) { /* closing */ }
        pool.shutdownNow();
    }

    private void acceptLoop() {
        while (!closed) {
            try {
                Socket c = server.accept();
                pool.execute(() -> handle(c));
            } catch (IOException e) {
                if (closed) return;
            } catch (RuntimeException e) {
                return; // the pool was shut down
            }
        }
    }

    // ---- receipts ----

    private void receipt(String method, String url, Map<String, Object> d, String outcome, String reason) {
        boolean allow = Boolean.TRUE.equals(d.get("allow"));
        @SuppressWarnings("unchecked") Map<String, Object> adm = allow && d.get("admission") instanceof Map ? (Map<String, Object>) d.get("admission") : null;
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("op_id", allow ? String.valueOf(d.get("op_id")) : "");
        subject.put("verb", allow && adm != null ? String.valueOf(adm.get("verb")) : "");
        String res = (method + " " + url);
        subject.put("resource", allow && adm != null ? String.valueOf(adm.get("resource")) : res.substring(0, Math.min(256, res.length())));
        subject.put("params_digest", allow && adm != null ? String.valueOf(adm.get("params_digest")) : "");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("kind", "egress");
        body.put("subject", subject);
        body.put("outcome", outcome);
        body.put("reason", reason);
        try {
            o.log.append(o.runtimeClass, body);
        } catch (RuntimeException e) {
            // a throwing clock or signer appends nothing; the request was already decided
        }
    }

    private static Map<String, Object> refusal(String reason) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("allow", Boolean.FALSE);
        d.put("reason", reason);
        return d;
    }

    // ---- one client connection ----

    private static String readLine(InputStream in, int[] budget) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != -1) {
            if (--budget[0] < 0) throw new IOException("header too large");
            if (c == '\n') break;
            if (c != '\r') b.write(c);
        }
        if (c == -1 && b.size() == 0) return null;
        return b.toString(StandardCharsets.ISO_8859_1);
    }

    private static void respond(OutputStream out, int status, String reason, String body) throws IOException {
        byte[] b = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        String head = "HTTP/1.1 " + status + " " + reason + "\r\n" + (body != null ? "content-type: application/json\r\n" : "") + "content-length: " + b.length + "\r\nconnection: close\r\n\r\n";
        out.write(head.getBytes(StandardCharsets.ISO_8859_1));
        out.write(b);
        out.flush();
    }

    private void deny(OutputStream out, String method, String url, String reason, int status) throws IOException {
        receipt(method, url, refusal(reason), "refused", reason);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("error", "egress_denied");
        m.put("reason", reason);
        respond(out, status, status == 413 ? "Payload Too Large" : "Forbidden", Json.stringify(m));
    }

    private void handle(Socket client) {
        try (Socket c = client) {
            c.setSoTimeout(o.upstreamTimeoutMs);
            InputStream in = new java.io.BufferedInputStream(c.getInputStream());
            OutputStream out = c.getOutputStream();
            int[] budget = {MAX_HEADER_BYTES};
            String line = readLine(in, budget);
            if (line == null || line.isEmpty()) return;
            String[] parts = line.split(" ", 3);
            if (parts.length < 2) return;
            String method = parts[0], target = parts[1];
            Map<String, List<String>> headers = new LinkedHashMap<>();
            String h;
            while ((h = readLine(in, budget)) != null && !h.isEmpty()) {
                int i = h.indexOf(':');
                if (i <= 0) continue;
                headers.computeIfAbsent(h.substring(0, i).trim().toLowerCase(Locale.ROOT), k -> new ArrayList<>()).add(h.substring(i + 1).trim());
            }
            if (method.equalsIgnoreCase("CONNECT")) tunnel(c, in, out, target);
            else forward(in, out, method, target, headers);
        } catch (IOException | RuntimeException e) {
            // a broken client connection: nothing more to say to it
        }
    }

    // ---- the upstream address guard ----

    /** The addresses of {@code host}, or null when any of them is private and private upstreams are not allowed (the guard, applied to a literal too). */
    private InetAddress[] resolveGuarded(String host) throws IOException {
        String h = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        InetAddress[] all = InetAddress.getAllByName(h);
        if (!o.allowPrivate) for (InetAddress a : all) if (Egress.isPrivateAddress(a.getHostAddress())) return null;
        return all;
    }

    private Socket connect(String host, int port) throws IOException {
        InetAddress[] addrs = resolveGuarded(host);
        if (addrs == null) throw new java.net.SocketException("EACCES");
        IOException last = null;
        for (InetAddress a : addrs) {
            Socket s = new Socket();
            try {
                s.connect(new InetSocketAddress(a, port), o.upstreamTimeoutMs);
                s.setSoTimeout(o.upstreamTimeoutMs);
                return s;
            } catch (IOException e) {
                last = e;
                try { s.close(); } catch (IOException ignored) { /* try the next address */ }
            }
        }
        throw last != null ? last : new IOException("no address");
    }

    private static String code(IOException e) { return (e.getMessage() != null && e.getMessage().equals("EACCES") ? "EACCES" : e instanceof java.net.SocketTimeoutException ? "timeout" : e.getClass().getSimpleName()); }

    // ---- CONNECT ----

    private void tunnel(Socket client, InputStream in, OutputStream out, String target) throws IOException {
        Map<String, Object> d = o.policy.claim("CONNECT", target, null);
        if (!Boolean.TRUE.equals(d.get("allow"))) {
            receipt("CONNECT", target, d, "refused", String.valueOf(d.get("reason")));
            out.write("HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            return;
        }
        int colon = target.lastIndexOf(':');
        String host = colon > 0 ? target.substring(0, colon) : target;
        int port;
        try { port = Integer.parseInt(target.substring(colon + 1)); } catch (RuntimeException e) { port = -1; }
        Socket up;
        try {
            up = connect(host, port);
        } catch (IOException | RuntimeException e) {
            receipt("CONNECT", target, d, "error", ("upstream:" + (e instanceof IOException ? code((IOException) e) : "error")));
            out.write("HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            return;
        }
        try (Socket upstream = up) {
            receipt("CONNECT", target, d, "ok", "tunnel");
            out.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            client.setSoTimeout(0);
            upstream.setSoTimeout(0);
            Thread t = new Thread(() -> pipe(upstreamIn(upstream), out), "pca-egress-down");
            t.setDaemon(true);
            t.start();
            pipe(in, upstream.getOutputStream());
            try { upstream.shutdownOutput(); } catch (IOException ignored) { /* half close */ }
            try { t.join(o.upstreamTimeoutMs); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }

    private static InputStream upstreamIn(Socket s) {
        try { return s.getInputStream(); } catch (IOException e) { return new java.io.ByteArrayInputStream(new byte[0]); }
    }

    private static void pipe(InputStream from, OutputStream to) {
        byte[] buf = new byte[8192];
        try {
            int n;
            while ((n = from.read(buf)) != -1) { to.write(buf, 0, n); to.flush(); }
        } catch (IOException e) {
            // either side closed
        }
    }

    // ---- plain HTTP ----

    private static byte[] readBody(InputStream in, Map<String, List<String>> headers, int max, boolean[] over) throws IOException {
        List<String> te = headers.get("transfer-encoding");
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        if (te != null && te.toString().toLowerCase(Locale.ROOT).contains("chunked")) {
            int[] budget = {Integer.MAX_VALUE};
            while (true) {
                String sz = readLine(in, budget);
                if (sz == null) break;
                int semi = sz.indexOf(';');
                int n = Integer.parseInt((semi >= 0 ? sz.substring(0, semi) : sz).trim(), 16);
                if (n == 0) { while (true) { String t = readLine(in, budget); if (t == null || t.isEmpty()) break; } break; }
                byte[] chunk = in.readNBytes(n);
                if (b.size() + chunk.length > max) over[0] = true; else b.write(chunk);
                readLine(in, budget);
            }
            return b.toByteArray();
        }
        List<String> cl = headers.get("content-length");
        long n = cl == null || cl.isEmpty() ? 0 : Long.parseLong(cl.get(0));
        if (n > max) { over[0] = true; return new byte[0]; }
        return in.readNBytes((int) n);
    }

    private void forward(InputStream in, OutputStream out, String method, String url, Map<String, List<String>> headers) throws IOException {
        boolean[] over = {false};
        byte[] body = readBody(in, headers, o.maxBodyBytes, over);
        if (over[0]) { deny(out, method, url, "body_too_large", 413); return; }
        Map<String, Object> d = o.policy.claim(method, url, body);
        if (!Boolean.TRUE.equals(d.get("allow"))) { deny(out, method, url, String.valueOf(d.get("reason")), 403); return; }
        EgressUrl.Parsed u = EgressUrl.parse(url); // the policy already parsed it: an admitted request has a good URL
        int port = u.port >= 0 ? u.port : (u.scheme.equals("http") ? 80 : 443);
        Socket up = null;
        try {
            up = connect(u.host, port);
            Socket io = up;
            if (u.scheme.equals("https")) {
                SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(up, u.host, port, true);
                SSLParameters ps = ssl.getSSLParameters();
                ps.setEndpointIdentificationAlgorithm("HTTPS");
                ssl.setSSLParameters(ps);
                ssl.startHandshake();
                io = ssl;
            }
            StringBuilder req = new StringBuilder(method).append(' ').append(u.path).append(u.query.isEmpty() ? "" : (u.query.startsWith("?") ? u.query : "?" + u.query)).append(" HTTP/1.1\r\n");
            req.append("host: ").append(u.host).append(u.port >= 0 && !(u.scheme.equals("http") && u.port == 80) && !(u.scheme.equals("https") && u.port == 443) ? ":" + u.port : "").append("\r\n");
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (HOP.contains(e.getKey()) || e.getKey().equals("content-length")) continue;
                for (String v : e.getValue()) req.append(e.getKey()).append(": ").append(v).append("\r\n");
            }
            req.append("content-length: ").append(body.length).append("\r\nconnection: close\r\n\r\n");
            OutputStream uo = io.getOutputStream();
            uo.write(req.toString().getBytes(StandardCharsets.ISO_8859_1));
            uo.write(body);
            uo.flush();
            InputStream ui = new java.io.BufferedInputStream(io.getInputStream());
            int[] budget = {MAX_HEADER_BYTES};
            String status = readLine(ui, budget);
            if (status == null) throw new IOException("empty upstream answer");
            Map<String, List<String>> rh = new LinkedHashMap<>();
            String hl;
            while ((hl = readLine(ui, budget)) != null && !hl.isEmpty()) {
                int i = hl.indexOf(':');
                if (i > 0) rh.computeIfAbsent(hl.substring(0, i).trim().toLowerCase(Locale.ROOT), k -> new ArrayList<>()).add(hl.substring(i + 1).trim());
            }
            String[] sp = status.split(" ", 3);
            int code = sp.length > 1 ? Integer.parseInt(sp[1].trim()) : 502;
            byte[] respBody;
            boolean[] ignore = {false};
            if (rh.containsKey("transfer-encoding") || rh.containsKey("content-length")) respBody = readBody(ui, rh, Integer.MAX_VALUE, ignore);
            else respBody = ui.readAllBytes();
            StringBuilder head = new StringBuilder("HTTP/1.1 ").append(code).append(' ').append(sp.length > 2 ? sp[2] : "").append("\r\n");
            for (Map.Entry<String, List<String>> e : rh.entrySet()) {
                if (HOP.contains(e.getKey()) || e.getKey().equals("content-length")) continue;
                for (String v : e.getValue()) head.append(e.getKey()).append(": ").append(v).append("\r\n");
            }
            head.append("content-length: ").append(respBody.length).append("\r\nconnection: close\r\n\r\n");
            out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
            out.write(respBody);
            out.flush();
            receipt(method, url, d, "ok", "status:" + code);
        } catch (IOException | RuntimeException e) {
            String r = "upstream:" + (e instanceof IOException ? code((IOException) e) : "error");
            receipt(method, url, d, "error", r.substring(0, Math.min(64, r.length())));
            try { respond(out, 502, "Bad Gateway", null); } catch (IOException ignored) { /* the client is gone */ }
        } finally {
            if (up != null) try { up.close(); } catch (IOException ignored) { /* closing */ }
        }
    }
}
