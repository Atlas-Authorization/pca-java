package net.atlasauth.pca.mpc.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.mpc.NetWire;
import net.atlasauth.pca.mpc.NetWire.Frame;
import net.atlasauth.pca.mpc.NetWire.NetAbort;

/**
 * Authenticated, confidential, fail-closed point-to-point mesh over TLS 1.3.
 *
 * <ul>
 * <li>MUTUAL TLS with PINNED self-signed certificates ({@link Certs}). A peer is identified by the SHA-256 fingerprint of its
 *     certificate, never by anything it claims; the id in its hello frame must agree with the pinned fingerprint.</li>
 * <li>Strict framing and per-link sequence numbers. A malformed frame, a replayed or skipped one, a frame for the wrong round
 *     or session, or an oversize length prefix aborts the whole run with a {@link NetAbort} naming the sender.</li>
 * <li>Every receive has a timeout (no hangs); a silent peer is blamed after {@code recvTimeoutMs}.</li>
 * <li>ABORT PROPAGATION: the first failure poisons the mesh, wakes every pending receive, best-effort sends an {@code abort}
 *     frame to every peer, then closes the sockets. Once failed nothing further is sent as protocol data.</li>
 * </ul>
 * A node dials every lower-numbered link target and accepts from the higher-numbered ones.
 */
public final class Mesh {
    /** A node of the session: its address and PUBLIC certificate (the pinned trust anchor and identity). */
    public record NodeAddr(int id, String host, int port, String certPem) {}

    /** TEST HOOK input: a frame about to be sent and its honest encoding. */
    public record TamperEvent(int to, Frame frame, byte[] raw) {}

    public record LinkStats(int peer, long appBytesOut, long appBytesIn, long framesOut, long framesIn) {}

    public static final class Config {
        public int selfId;
        /** Every node of the session, including self. */
        public List<NodeAddr> nodes;
        /** Node ids this node keeps a link to (default: all others). */
        public List<Integer> linkTo;
        public String keyPem;
        public String certPem;
        public String sessionId;
        public String listenHost = "0.0.0.0";
        public long connectTimeoutMs = 30_000;
        public long recvTimeoutMs = 20_000;
        /** Time source for deadlines (default: real time). */
        public MeshClock clock = MeshClock.WALL;
        /** TEST HOOK: a (malicious) sender rewriting its own outgoing frames; refused unless {@link #unsafeTestHooks}. */
        public Function<TamperEvent, List<byte[]>> tamper;
        public boolean unsafeTestHooks;
        public int maxInboxFrames = 1024;
        public long maxInboxBytes = 32L * 1024 * 1024;
    }

    public static final int MAX_MESH_EVENTS = 64;
    private static final String[] TLS13 = {"TLSv1.3"};

    private static final class Item {
        final String rd;
        final Object d;
        final int size;
        final NetAbort abort;
        Item(String rd, Object d, int size, NetAbort abort) { this.rd = rd; this.d = d; this.size = size; this.abort = abort; }
    }

    private static final class Link {
        final int id;
        final NetWire.FrameSplitter splitter = new NetWire.FrameSplitter();
        final ArrayDeque<Item> inbox = new ArrayDeque<>();
        SSLSocket socket;
        OutputStream out;
        long inboxBytes;
        boolean paused;
        long sendSeq;
        long recvSeq;
        volatile boolean closed;
        volatile boolean helloSeen;
        final AtomicLong bytesIn = new AtomicLong(), bytesOut = new AtomicLong(), framesIn = new AtomicLong(), framesOut = new AtomicLong();
        Link(int id) { this.id = id; }
    }

    /** Trust exactly the pinned certificates (by SHA-256 fingerprint); no chain building, no hostnames. */
    private static final class PinTrust extends X509ExtendedTrustManager {
        private final Set<String> pins;
        PinTrust(Set<String> pins) { this.pins = pins; }
        private void check(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length == 0) throw new CertificateException("no peer certificate");
            chain[0].checkValidity();
            if (!pins.contains(Certs.fingerprint(chain[0]))) throw new CertificateException("peer certificate is not pinned");
        }
        @Override public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException { check(c); }
        @Override public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException { check(c); }
        @Override public void checkClientTrusted(X509Certificate[] c, String a, Socket s) throws CertificateException { check(c); }
        @Override public void checkServerTrusted(X509Certificate[] c, String a, Socket s) throws CertificateException { check(c); }
        @Override public void checkClientTrusted(X509Certificate[] c, String a, SSLEngine e) throws CertificateException { check(c); }
        @Override public void checkServerTrusted(X509Certificate[] c, String a, SSLEngine e) throws CertificateException { check(c); }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    public final int selfId;
    private final Config cfg;
    private final MeshClock clock;
    private final Map<Integer, Link> links = new TreeMap<>();
    private final Map<String, Integer> pinned = new HashMap<>();
    private final Map<Integer, NodeAddr> nodeById = new HashMap<>();
    private final PrivateKey privateKey;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition wake = lock.newCondition();
    private final List<String> events = Collections.synchronizedList(new ArrayList<>());
    private final AtomicLong eventsDropped = new AtomicLong();
    private volatile NetAbort failure;
    private volatile boolean finished;
    private volatile boolean closing;
    private volatile boolean deferAborts;
    private SSLContext ctx;
    private SSLServerSocket server;

    public Mesh(Config cfg) {
        this.cfg = cfg;
        this.clock = cfg.clock == null ? MeshClock.WALL : cfg.clock;
        this.selfId = cfg.selfId;
        if (cfg.tamper != null && !cfg.unsafeTestHooks) throw new IllegalArgumentException("mesh: the tamper test hook requires unsafeTestHooks (test-only)");
        if (cfg.nodes == null || cfg.sessionId == null || cfg.keyPem == null || cfg.certPem == null) throw new IllegalArgumentException("mesh: incomplete config");
        this.privateKey = Certs.parseKey(cfg.keyPem);
        String selfFp = Certs.fingerprintOf(cfg.certPem);
        boolean selfSeen = false;
        for (NodeAddr n : cfg.nodes) {
            if (nodeById.put(n.id(), n) != null) throw new IllegalArgumentException("mesh: duplicate node id " + n.id());
            String fp = Certs.fingerprintOf(n.certPem());
            if (n.id() == selfId) {
                selfSeen = true;
                if (!fp.equals(selfFp)) throw new IllegalArgumentException("mesh: own certificate differs from the one listed for this node");
            } else if (pinned.put(fp, n.id()) != null || fp.equals(selfFp)) {
                throw new IllegalArgumentException("mesh: two nodes share one certificate");
            }
        }
        if (!selfSeen) throw new IllegalArgumentException("mesh: self not in nodes");
        List<Integer> want = new ArrayList<>();
        if (cfg.linkTo != null) want.addAll(cfg.linkTo);
        else for (NodeAddr n : cfg.nodes) if (n.id() != selfId) want.add(n.id());
        for (int id : want) {
            if (!nodeById.containsKey(id) || id == selfId) throw new IllegalArgumentException("mesh: unknown link target " + id);
            links.put(id, new Link(id));
        }
    }

    private void note(String msg) {
        if (events.size() < MAX_MESH_EVENTS) events.add(msg);
        else eventsDropped.incrementAndGet();
    }

    public List<String> events() { synchronized (events) { return new ArrayList<>(events); } }
    public long eventsDropped() { return eventsDropped.get(); }
    public String sessionId() { return cfg.sessionId; }
    public NetAbort failed() { return failure; }
    public List<Integer> peers() { return new ArrayList<>(links.keySet()); }

    // ------------------------------------------------------------------ connect

    private SSLContext buildContext() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("node", privateKey, new char[0], new java.security.cert.Certificate[] {Certs.parseCert(cfg.certPem)});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);
        SSLContext c = SSLContext.getInstance("TLSv1.3");
        c.init(kmf.getKeyManagers(), new TrustManager[] {new PinTrust(new HashSet<>(pinned.keySet()))}, null);
        return c;
    }

    /** Port the TLS server is bound to (useful when the configured port was 0). */
    public int boundPort() { return server == null ? -1 : server.getLocalPort(); }

    /** Listen, dial every lower-numbered link target, and wait until all links are authenticated. */
    public void connect() {
        NodeAddr self = nodeById.get(selfId);
        long deadline = clock.now() + cfg.connectTimeoutMs;
        try {
            ctx = buildContext();
            server = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(self.port(), 128, InetAddress.getByName(cfg.listenHost));
            server.setEnabledProtocols(TLS13);
            server.setNeedClientAuth(true);
        } catch (Exception e) {
            throw new IllegalStateException("mesh: cannot listen: " + e.getMessage(), e);
        }
        daemon("mesh-accept-" + selfId, this::acceptLoop).start();
        for (int id : peers()) if (id < selfId) daemon("mesh-dial-" + selfId + "-" + id, () -> dial(id, deadline)).start();
        NetAbort toFail = null;
        lock.lock();
        try {
            for (;;) {
                if (failure != null) throw failure;
                List<Integer> missing = new ArrayList<>();
                for (Link l : links.values()) if (!l.helloSeen) missing.add(l.id);
                if (missing.isEmpty()) return;
                long left = deadline - clock.now();
                if (left <= 0) {
                    toFail = new NetAbort("timeout", missing.get(0), selfId, "connect: no authenticated link from " + missing);
                    break;
                }
                try {
                    wake.awaitNanos(20_000_000L); // a poll interval, not a decision: real time
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    toFail = new NetAbort("local", null, selfId, "connect interrupted");
                    break;
                }
            }
        } finally {
            lock.unlock();
        }
        fail(toFail, null);
        throw toFail;
    }

    private void wakeAll() {
        lock.lock();
        try {
            wake.signalAll();
        } finally {
            lock.unlock();
        }
    }

    private static Thread daemon(String name, Runnable r) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        return t;
    }

    private void acceptLoop() {
        while (!closing && failure == null) {
            Socket s;
            try {
                s = server.accept();
            } catch (IOException e) {
                if (!closing) note("server error: " + e.getMessage());
                return;
            }
            final SSLSocket sock = (SSLSocket) s;
            daemon("mesh-in-" + selfId, () -> onIncoming(sock)).start();
        }
    }

    private void dial(int id, long deadline) {
        NodeAddr node = nodeById.get(id);
        while (failure == null && !closing && clock.now() < deadline) {
            SSLSocket s = null;
            try {
                s = (SSLSocket) ctx.getSocketFactory().createSocket();
                s.connect(new InetSocketAddress(node.host(), node.port()), 3000);
                s.setEnabledProtocols(TLS13);
                s.setTcpNoDelay(true);
                s.setSoTimeout((int) Math.max(1, Math.min(Integer.MAX_VALUE, deadline - clock.now())));
                s.startHandshake();
                s.setSoTimeout(0);
                // We pin by certificate (not hostname): the peer must be exactly the pinned identity of node `id`.
                Integer got = pinned.get(Certs.fingerprint((X509Certificate) s.getSession().getPeerCertificates()[0]));
                if (got == null || got != id) {
                    closeQuietly(s);
                    fail(new NetAbort("identity", id, selfId, "dial: peer certificate is not the pinned identity of node " + id), null);
                    return;
                }
                attach(id, s);
                return;
            } catch (IOException e) {
                closeQuietly(s);
            }
            try {
                Thread.sleep(150); // retry pacing, not a decision
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void onIncoming(SSLSocket sock) {
        try {
            sock.setEnabledProtocols(TLS13);
            sock.setTcpNoDelay(true);
            sock.setSoTimeout((int) Math.min(Integer.MAX_VALUE, cfg.connectTimeoutMs));
            sock.startHandshake();
            sock.setSoTimeout(0);
            Integer id = pinned.get(Certs.fingerprint((X509Certificate) sock.getSession().getPeerCertificates()[0]));
            if (id == null || !links.containsKey(id) || id < selfId) {
                note("rejected incoming connection (peer " + id + ")");
                closeQuietly(sock);
                return;
            }
            attach(id, sock);
        } catch (IOException | RuntimeException e) {
            note("tlsClientError: " + sanitize(String.valueOf(e.getMessage()), 120));
            closeQuietly(sock);
        }
    }

    private static void closeQuietly(Socket s) {
        if (s == null) return;
        try { s.close(); } catch (IOException ignored) { /* already gone */ }
    }

    private void attach(int id, SSLSocket sock) {
        Link l = links.get(id);
        lock.lock();
        try {
            if (l.socket != null) {
                note("duplicate connection from node " + id);
                closeQuietly(sock);
                return;
            }
            try {
                l.out = sock.getOutputStream();
                l.socket = sock;
            } catch (IOException e) {
                closeQuietly(sock);
                return;
            }
        } finally {
            lock.unlock();
        }
        daemon("mesh-rd-" + selfId + "-" + id, () -> readLoop(l, sock)).start();
        // hello: first frame on every link (seq 0); carries our id so the peer can cross-check the pin.
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("id", selfId);
        sendFrame(l, "hello", "hello", d);
    }

    // ------------------------------------------------------------------ receive path

    private void readLoop(Link l, SSLSocket sock) {
        try {
            InputStream in = sock.getInputStream();
            byte[] buf = new byte[64 * 1024];
            for (;;) {
                int n = in.read(buf);
                if (n < 0) { onClosed(l, "peer ended"); return; }
                onData(l, Arrays.copyOf(buf, n));
                if (failure != null) return;
                lock.lock();
                try {
                    while (l.paused && failure == null && !l.closed) wake.awaitUninterruptibly();
                } finally {
                    lock.unlock();
                }
            }
        } catch (IOException e) {
            onClosed(l, "socket error: " + e.getMessage());
        }
    }

    private static Integer asInt(Object o) {
        if (!(o instanceof Json.Num)) return null;
        double d;
        try { d = Double.parseDouble(o.toString()); } catch (NumberFormatException e) { return null; }
        if (Double.isNaN(d) || Double.isInfinite(d) || d != Math.rint(d) || Math.abs(d) > 1e9 || (d == 0 && 1 / d < 0)) return null;
        return (int) d;
    }

    @SuppressWarnings("unchecked")
    private void onData(Link l, byte[] chunk) {
        if (failure != null) return;
        l.bytesIn.addAndGet(chunk.length);
        List<byte[]> bodies;
        try {
            bodies = l.splitter.push(chunk);
        } catch (IllegalStateException e) {
            fail(new NetAbort("oversize", l.id, selfId, "length prefix above MAX_FRAME_BYTES"), null);
            return;
        }
        for (byte[] b : bodies) {
            Map<String, Object> f = NetWire.parseFrame(b);
            if (f == null) {
                Long pv = NetWire.versionMismatch(b);
                if (pv != null) {
                    fail(new NetAbort("version", l.id, selfId, "peer " + l.id + " speaks wire version " + pv + ", this node speaks " + NetWire.WIRE_VERSION + "; upgrade both peers"), null);
                } else {
                    fail(new NetAbort("malformed", l.id, selfId, "undecodable or ill-shaped frame"), null);
                }
                return;
            }
            String ty = (String) f.get("ty");
            String rd = (String) f.get("rd");
            if (!cfg.sessionId.equals(f.get("sid"))) {
                fail(new NetAbort("wrong-session", l.id, selfId, "frame from another session"), null);
                return;
            }
            if (ty.equals("abort")) {
                // An abort frame is only a CLAIM by the peer that sent it: we blame that peer, never the party it names.
                Object dd = f.get("d");
                Map<String, Object> d = dd instanceof Map ? (Map<String, Object>) dd : Map.of();
                boolean relayed = Boolean.TRUE.equals(d.get("relayed"));
                String claimedKind = d.get("kind") instanceof String && NetWire.ABORT_KINDS.contains((String) d.get("kind")) ? (String) d.get("kind") : null;
                int maxId = 0;
                for (NodeAddr x : cfg.nodes) maxId = Math.max(maxId, x.id());
                Integer cb = asInt(d.get("blamed"));
                Integer claimedBlame = cb != null && cb >= 0 && cb <= maxId ? cb : null;
                String detail = d.get("detail") instanceof String ? sanitize((String) d.get("detail"), 120) : "";
                NetAbort claim = new NetAbort("peer-abort", relayed ? null : l.id, selfId,
                    "peer " + l.id + " " + (relayed ? "relayed" : "reported") + " an abort (" + (claimedKind == null ? "unspecified" : claimedKind) + ", accuses "
                        + (claimedBlame == null ? "no one" : claimedBlame.toString()) + ", unverified) " + detail,
                    claimedKind, claimedBlame,
                    relayed ? "relayed abort: a second-hand claim passed on by an honest peer; it names no one and is never evidence" : null, null, null);
                if (deferAborts) {
                    // Order-preserving: takes effect when READ, i.e. after every frame this peer sent before it.
                    lock.lock();
                    try { l.inbox.addLast(new Item(rd, null, b.length, claim)); } finally { lock.unlock(); }
                    continue;
                }
                fail(claim, l.id);
                return;
            }
            Double seqD = Double.parseDouble(f.get("seq").toString());
            long seq = seqD.longValue();
            if (seq != l.recvSeq) {
                String kind = seq < l.recvSeq ? "duplicate" : "out-of-order";
                fail(new NetAbort(kind, l.id, selfId, "expected seq " + l.recvSeq + ", got " + seq + " (round " + rd + ")"), null);
                return;
            }
            l.recvSeq++;
            l.framesIn.incrementAndGet();
            if (ty.equals("hello")) {
                Object dd = f.get("d");
                Integer hid = dd instanceof Map ? asInt(((Map<String, Object>) dd).get("id")) : null;
                if (l.helloSeen || hid == null || hid != l.id) {
                    fail(new NetAbort("identity", l.id, selfId, "hello claims id " + (hid == null ? "?" : hid.toString()) + " on the link pinned to " + l.id), null);
                    return;
                }
                lock.lock();
                try { l.helloSeen = true; wake.signalAll(); } finally { lock.unlock(); }
            } else {
                if (!l.helloSeen) {
                    fail(new NetAbort("malformed", l.id, selfId, "data before hello"), null);
                    return;
                }
                boolean flood;
                lock.lock();
                try {
                    l.inbox.addLast(new Item(rd, f.get("d"), b.length, null));
                    l.inboxBytes += b.length;
                    flood = l.inbox.size() > cfg.maxInboxFrames || l.inboxBytes > cfg.maxInboxBytes;
                    if (!flood && !l.paused && (l.inbox.size() > cfg.maxInboxFrames / 2 || l.inboxBytes > cfg.maxInboxBytes / 2)) l.paused = true;
                } finally {
                    lock.unlock();
                }
                if (flood) {
                    fail(new NetAbort("flood", l.id, selfId, "peer " + l.id + " queued more than the inbox cap allows"), null);
                    return;
                }
            }
        }
        lock.lock();
        try { wake.signalAll(); } finally { lock.unlock(); }
    }

    private void onClosed(Link l, String why) {
        if (l.closed) return;
        l.closed = true;
        if (!finished && failure == null && !l.helloSeen) note("link " + l.id + " closed before hello: " + why);
        lock.lock();
        try { wake.signalAll(); } finally { lock.unlock(); }
    }

    // ------------------------------------------------------------------ send path

    private void sendFrame(Link l, String ty, String rd, Object d) {
        synchronized (l) {
            Frame frame = new Frame(NetWire.WIRE_VERSION, ty, cfg.sessionId, Long.valueOf(l.sendSeq++), rd, d);
            byte[] raw = NetWire.encodeFrame(frame);
            List<byte[]> outs = cfg.tamper != null && !ty.equals("hello") ? cfg.tamper.apply(new TamperEvent(l.id, frame, raw)) : List.of(raw);
            writeAll(l, outs);
            l.framesOut.incrementAndGet();
        }
    }

    private void writeAll(Link l, List<byte[]> outs) {
        for (byte[] b : outs) {
            SSLSocket s = l.socket;
            if (s != null && !s.isClosed()) {
                try {
                    l.out.write(b);
                    l.out.flush();
                    l.bytesOut.addAndGet(b.length);
                } catch (IOException e) {
                    // the dead link surfaces as a disconnect on the read side
                }
            }
        }
    }

    /** Send a protocol message to one peer. Throws the mesh failure if already aborted (fail closed). */
    public void send(int to, String round, Object payload) {
        NetAbort f = failure;
        if (f != null) throw f;
        Link l = links.get(to);
        if (l == null) throw new IllegalArgumentException("mesh: no link to " + to);
        sendFrame(l, "msg", round, payload);
    }

    public void broadcast(String round, Object payload) { broadcast(round, payload, peers()); }

    public void broadcast(String round, Object payload, List<Integer> to) { for (int p : to) send(p, round, payload); }

    /** ECDSA-P256/SHA-256 (DER) signature over {@code data} with this node's TLS identity key. */
    public byte[] sign(byte[] data) {
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(privateKey);
            s.update(data);
            return s.sign();
        } catch (Exception e) {
            throw new IllegalStateException("mesh: sign failed", e);
        }
    }

    /** Verify {@code sig} over {@code data} against the PINNED certificate of node {@code peer}. False on any failure. */
    public boolean verify(int peer, byte[] data, byte[] sig) {
        NodeAddr n = nodeById.get(peer);
        if (n == null || peer == selfId) return false;
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initVerify(Certs.parseCert(n.certPem()).getPublicKey());
            s.update(data);
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    /** Receive the next message from {@code from}, which must belong to {@code round}. Times out; never hangs. */
    public Object recv(int from, String round) { return recv(from, round, cfg.recvTimeoutMs); }

    public Object recv(int from, String round, long timeoutMs) {
        Link l = links.get(from);
        if (l == null) throw new IllegalArgumentException("mesh: no link to " + from);
        long deadline = clock.now() + timeoutMs;
        Object timer = null;
        NetAbort toFail;
        Integer skip = null;
        lock.lock();
        try {
            for (;;) {
                NetAbort cur = failure;
                if (cur != null) throw cur;
                Item it = l.inbox.pollFirst();
                if (it != null) {
                    if (it.abort != null) { toFail = it.abort; skip = from; break; }
                    l.inboxBytes -= it.size;
                    if (l.paused && l.inbox.size() <= cfg.maxInboxFrames / 2 && l.inboxBytes <= cfg.maxInboxBytes / 2) {
                        l.paused = false;
                        wake.signalAll();
                    }
                    if (!it.rd.equals(round)) {
                        toFail = new NetAbort("wrong-round", from, selfId, "expected round '" + round + "', got '" + it.rd + "'");
                        break;
                    }
                    return it.d;
                }
                if (l.closed) {
                    toFail = new NetAbort("disconnect", from, selfId, "link to " + from + " closed while awaiting '" + round + "'");
                    break;
                }
                long left = deadline - clock.now();
                if (left <= 0) {
                    toFail = new NetAbort("timeout", from, selfId, "no '" + round + "' message from " + from + " within " + timeoutMs + "ms (deadline " + timeoutMs
                        + "ms; a silent peer is blamed on this local observation only)", null, null, null, null, (int) Math.min(Integer.MAX_VALUE, timeoutMs));
                    break;
                }
                try {
                    timer = clock.setTimer(this::wakeAll, left);
                    wake.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    toFail = new NetAbort("local", null, selfId, "receive interrupted");
                    break;
                } finally {
                    if (timer != null) clock.clearTimer(timer);
                }
            }
        } finally {
            lock.unlock();
        }
        fail(toFail, skip);
        throw toFail;
    }

    /**
     * While on, a peer's abort frame does not poison the mesh on arrival: it is queued behind that peer's earlier frames and
     * only takes effect when a receive from that peer reaches it (used for the blame round).
     */
    public void setDeferAborts(boolean on) { deferAborts = on; }

    /** Receive {@code round} from every peer in {@code from} concurrently; a failure on any link throws. */
    public Map<Integer, Object> collect(String round, List<Integer> from, Long timeoutMs) {
        long t = timeoutMs == null ? cfg.recvTimeoutMs : timeoutMs;
        Map<Integer, Object> out = new TreeMap<>();
        RuntimeException[] err = new RuntimeException[1];
        List<Thread> ts = new ArrayList<>();
        for (int p : from) {
            Thread th = daemon("mesh-collect-" + p, () -> {
                try {
                    Object v = recv(p, round, t);
                    synchronized (out) { out.put(p, v); }
                } catch (RuntimeException e) {
                    synchronized (out) { if (err[0] == null) err[0] = e; }
                }
            });
            ts.add(th);
            th.start();
        }
        for (Thread th : ts) {
            try {
                th.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new NetAbort("local", null, selfId, "collect interrupted");
            }
        }
        if (err[0] != null) throw err[0];
        return out;
    }

    public Map<Integer, Object> collect(String round) { return collect(round, peers(), null); }

    // ------------------------------------------------------------------ failure / shutdown

    /**
     * Poison the mesh: record the first failure, tell EVERY peer except {@code skipPeer} (a forwarded accusation stays a claim,
     * so an innocent bystander is never blamed for merely closing), close all.
     */
    public void fail(NetAbort err, Integer skipPeer) {
        lock.lock();
        try {
            if (failure != null) return;
            failure = err;
            wake.signalAll();
        } finally {
            lock.unlock();
        }
        boolean fwd = err.kind.equals("peer-abort");
        String kind = fwd ? (err.claimedKind != null ? err.claimedKind : "peer-abort") : err.kind;
        Integer blamed = fwd ? err.claimedBlame : err.blamed;
        for (Link l : links.values()) {
            if (skipPeer != null && l.id == skipPeer) continue;
            if (l.socket != null && !l.socket.isClosed() && !l.closed) {
                Map<String, Object> d = new LinkedHashMap<>();
                d.put("kind", kind);
                d.put("blamed", blamed);
                d.put("detail", sanitize(err.getMessage(), 200));
                if (fwd) d.put("relayed", Boolean.TRUE);
                try {
                    synchronized (l) {
                        Frame frame = new Frame(NetWire.WIRE_VERSION, "abort", cfg.sessionId, Long.valueOf(l.sendSeq++), "abort", d);
                        writeAll(l, List.of(NetWire.encodeFrame(frame)));
                    }
                } catch (RuntimeException ignored) {
                    // best effort
                }
            }
        }
        daemon("mesh-fail-close", () -> {
            try { Thread.sleep(50); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            closeAll();
        }).start();
    }

    /** Normal completion: flush and close. Peers that are still reading see EOF only after our data. */
    public void finish() {
        finished = true;
        try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        closeAll();
    }

    /** Abrupt shutdown with no abort frames (a crashed node; also the way a launcher stops a straggler). */
    public void kill() { closeAll(); }

    private void closeAll() {
        closing = true;
        for (Link l : links.values()) closeQuietly(l.socket);
        if (server != null) {
            try { server.close(); } catch (IOException ignored) { /* already closed */ }
        }
    }

    public List<LinkStats> stats() {
        List<LinkStats> out = new ArrayList<>();
        for (Link l : links.values()) out.add(new LinkStats(l.id, l.bytesOut.get(), l.bytesIn.get(), l.framesOut.get(), l.framesIn.get()));
        return out;
    }

    /** Printable-ASCII, length-capped copy of untrusted text (no control characters, no log forging). */
    static String sanitize(String x, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < x.length(); i++) {
            char c = x.charAt(i);
            sb.append(c >= 0x20 && c <= 0x7e ? c : '?');
        }
        return sb.length() > max ? sb.substring(0, max) : sb.toString();
    }
}
