package net.atlasauth.pca;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import net.atlasauth.pca.FrostDkgChannel.DkgChannel;
import net.atlasauth.pca.FrostDkgChannel.DkgChannelError;
import net.atlasauth.pca.FrostDkgChannel.DkgInbox;

/**
 * A mutual-TLS node for the FROST DKG over JSSE: one TLS 1.3 connection per pair of participants, mutually authenticated by pinned
 * certificate. Each side trusts exactly the other participants' certificates, and the SHA-256 fingerprint of the peer's certificate maps to
 * its participant id, so the sender identity the DKG driver sees comes from the handshake and never from message content. The
 * higher-numbered party dials the lower-numbered one. A peer without a pinned certificate, a plaintext client, a TLS 1.2 client, a second
 * connection for an already linked identity and a connection from a party that should have been dialled are all refused before any DKG
 * byte is read. Frames are a 4-byte big-endian length then the message ({@link FrostDkgTls}); the length is checked against the message cap
 * before any allocation. Certificate issuance, rotation and revocation are the deployer's.
 *
 * <p>Keys are PEM PKCS#8 (the unencrypted PKCS#8 PEM label; {@code openssl pkcs8 -topk8 -nocrypt} converts the older forms), certificates PEM.
 */
public final class FrostDkgTlsNode implements AutoCloseable {
    /** The pinned certificate of one OTHER participant. */
    public static final class PeerCert {
        public final long id;
        public final String certPem;
        public PeerCert(long id, String certPem) { this.id = id; this.certPem = certPem; }
    }

    /** {@code self}, {@code sessionId}, this node's PEM key and certificate, the pinned peers; {@code listenPort} 0 is ephemeral, the host defaults to 127.0.0.1. */
    public static final class Options {
        public long self;
        public byte[] sessionId;
        public String keyPem, certPem;
        public List<PeerCert> peerCerts = new ArrayList<>();
        public int listenPort;
        public String listenHost = "127.0.0.1";
    }

    /** Where to dial one lower-numbered peer. */
    public static final class Address {
        public final long id;
        public final String host;
        public final int port;
        public Address(long id, String host, int port) { this.id = id; this.host = host; this.port = port; }
    }

    private static final String[] TLS13 = {"TLSv1.3"};
    private static final int HANDSHAKE_TIMEOUT_MS = 10_000;

    private final Options opts;
    private final Map<String, Long> pinned = new HashMap<>();
    private final List<Long> peers;
    private final DkgInbox inbox;
    private final SSLContext ctx;
    private final SSLServerSocket server;
    private final Object lock = new Object();
    private final Map<Long, Link> links = new HashMap<>();
    private final Map<Long, FrostDkgTls.LinkWriter> writers = new ConcurrentHashMap<>();
    private final Set<Closeable> sockets = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private boolean closed;

    private static final class Link {
        final SSLSocket sock;
        final Object wlock = new Object();
        Link(SSLSocket sock) { this.sock = sock; }
    }

    private static String fingerprint(byte[] der) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(der);
            StringBuilder b = new StringBuilder();
            for (byte x : h) b.append(String.format("%02x", x & 0xff));
            return b.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] pemBody(String pem, String type) {
        String begin = "-----BEGIN " + type + "-----", end = "-----END " + type + "-----";
        int a = pem == null ? -1 : pem.indexOf(begin), b = pem == null ? -1 : pem.indexOf(end);
        if (a < 0 || b < a) throw new IllegalArgumentException("startTlsDkgNode: the key is not a PKCS#8 PEM private key");
        return Base64.getMimeDecoder().decode(pem.substring(a + begin.length(), b));
    }

    private static X509Certificate certOf(String pem) {
        try {
            if (pem == null || !pem.contains("-----BEGIN CERTIFICATE-----")) throw new IllegalArgumentException("startTlsDkgNode: a peer certificate is not a PEM certificate");
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        } catch (CertificateException e) {
            throw new IllegalArgumentException("startTlsDkgNode: a peer certificate is not a PEM certificate", e);
        }
    }

    private static PrivateKey keyOf(String pem) {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pemBody(pem, "PRIVATE KEY"));
        for (String alg : new String[] {"EC", "RSA", "Ed25519", "Ed448", "RSASSA-PSS"}) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(spec);
            } catch (java.security.GeneralSecurityException e) {
                // try the next key type
            }
        }
        throw new IllegalArgumentException("startTlsDkgNode: the private key is not a supported PKCS#8 key");
    }

    /** The pin check: the peer certificate is one of the pinned ones and inside its validity; the chain, issuer and host name play no part. */
    private final class PinTrust extends X509ExtendedTrustManager {
        private void check(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length == 0) throw new CertificateException("no certificate");
            if (!pinned.containsKey(fingerprint(chain[0].getEncoded()))) throw new CertificateException("certificate is not pinned");
            chain[0].checkValidity();
        }
        @Override public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException { check(c); }
        @Override public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException { check(c); }
        @Override public void checkClientTrusted(X509Certificate[] c, String a, Socket s) throws CertificateException { check(c); }
        @Override public void checkServerTrusted(X509Certificate[] c, String a, Socket s) throws CertificateException { check(c); }
        @Override public void checkClientTrusted(X509Certificate[] c, String a, SSLEngine e) throws CertificateException { check(c); }
        @Override public void checkServerTrusted(X509Certificate[] c, String a, SSLEngine e) throws CertificateException { check(c); }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    private FrostDkgTlsNode(Options o) throws Exception {
        this.opts = o;
        for (PeerCert p : o.peerCerts) pinned.put(fingerprint(certOf(p.certPem).getEncoded()), p.id);
        Set<Long> ids = new HashSet<>();
        for (PeerCert p : o.peerCerts) ids.add(p.id);
        if (pinned.size() != o.peerCerts.size() || ids.size() != o.peerCerts.size() || ids.contains(o.self))
            throw new IllegalArgumentException("startTlsDkgNode: peer certificates must be distinct and none may be this node");
        List<Long> sorted = new ArrayList<>(ids);
        Collections.sort(sorted);
        this.peers = Collections.unmodifiableList(sorted);
        this.inbox = new DkgInbox(o.sessionId, sorted);

        char[] pw = "pca-dkg-tls".toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("self", keyOf(o.keyPem), pw, new java.security.cert.Certificate[] {certOf(o.certPem)});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pw);
        this.ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), new TrustManager[] {new PinTrust()}, null);

        SSLServerSocket ss = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(o.listenPort, 50, InetAddress.getByName(o.listenHost));
        ss.setEnabledProtocols(TLS13);
        ss.setNeedClientAuth(true);
        this.server = ss;
        Thread t = new Thread(this::serve, "dkg-tls-accept-" + o.self);
        t.setDaemon(true);
        t.start();
    }

    /** Listens for the higher-numbered peers. */
    public static FrostDkgTlsNode start(Options o) throws Exception { return new FrostDkgTlsNode(o); }

    /** The port the node listens on. */
    public int port() { return server.getLocalPort(); }

    private boolean track(Closeable c) {
        synchronized (lock) {
            if (closed) return false;
            sockets.add(c);
            return true;
        }
    }

    private static void quiet(Closeable c) {
        try { c.close(); } catch (IOException e) { /* already closed */ }
    }

    private void serve() {
        while (true) {
            final SSLSocket s;
            try {
                s = (SSLSocket) server.accept();
            } catch (IOException e) {
                return; // closed
            }
            Thread t = new Thread(() -> inbound(s), "dkg-tls-in-" + opts.self);
            t.setDaemon(true);
            t.start();
        }
    }

    private void inbound(SSLSocket s) {
        try {
            if (!track(s)) { quiet(s); return; }
            s.setEnabledProtocols(TLS13);
            s.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            s.startHandshake();
            s.setSoTimeout(0);
            X509Certificate peer = (X509Certificate) s.getSession().getPeerCertificates()[0];
            String fp = fingerprint(peer.getEncoded());
            // only a pinned peer that is supposed to dial us (higher id), once
            Long id;
            synchronized (lock) { id = FrostDkgTls.acceptInbound(fp, pinned, opts.self, links.keySet()); }
            if (id == null || !attach(id, s)) quiet(s);
        } catch (Exception e) {
            quiet(s);
        }
    }

    /** Registers an authenticated link and starts reading it; false (the caller closes the socket) when the node is closed or the peer is already linked. */
    private boolean attach(long id, SSLSocket s) throws IOException {
        Link link = new Link(s);
        OutputStream out = s.getOutputStream();
        synchronized (lock) {
            if (closed || links.containsKey(id)) return false;
            links.put(id, link);
            writers.put(id, frame -> {
                synchronized (link.wlock) {
                    out.write(frame);
                    out.flush();
                }
            });
            lock.notifyAll();
        }
        InputStream in = s.getInputStream();
        FrostDkgTls.FrameReader reader = FrostDkgTls.FrameReader.forInbox(inbox, id, () -> quiet(s));
        Thread t = new Thread(() -> {
            byte[] buf = new byte[32 * 1024];
            try {
                int k;
                while ((k = in.read(buf)) >= 0) reader.feed(java.util.Arrays.copyOf(buf, k));
            } catch (IOException e) {
                // the link ended
            }
            synchronized (lock) {
                if (links.get(id) == link) { links.remove(id); writers.remove(id); }
            }
            quiet(s);
            inbox.peerGone(id);
        }, "dkg-tls-read-" + opts.self + "-" + id);
        t.setDaemon(true);
        t.start();
        return true;
    }

    private void dial(Address a, AtomicBoolean stop) {
        while (!stop.get() && !isClosed()) {
            Socket raw = null;
            try {
                raw = new Socket();
                raw.connect(new InetSocketAddress(a.host, a.port), 5000);
                SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(raw, a.host, a.port, true);
                s.setEnabledProtocols(TLS13);
                if (track(s)) {
                    s.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
                    s.startHandshake();
                    s.setSoTimeout(0);
                    X509Certificate peer = (X509Certificate) s.getSession().getPeerCertificates()[0];
                    Long id = pinned.get(fingerprint(peer.getEncoded()));
                    if (id != null && id == a.id && attach(a.id, s)) return;
                    quiet(s);
                } else {
                    quiet(s);
                }
            } catch (Exception e) {
                if (raw != null) quiet(raw);
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private boolean isClosed() {
        synchronized (lock) { return closed; }
    }

    /**
     * Dials the lower-numbered peers, waits for the higher-numbered ones and returns the channel once every link is authenticated.
     * {@code connectTimeoutMs} &lt;= 0 is 15000. A timeout closes the node and is a {@code timeout} {@link DkgChannelError}.
     */
    public DkgChannel connect(List<Address> addresses, long connectTimeoutMs) {
        long timeout = connectTimeoutMs <= 0 ? 15_000 : connectTimeoutMs;
        AtomicBoolean stop = new AtomicBoolean();
        for (Address a : addresses) {
            if (!peers.contains(a.id)) throw new DkgChannelError("identity", a.id, "address for a participant that is not a pinned peer");
        }
        for (Address a : addresses) {
            if (a.id < opts.self) {
                Thread t = new Thread(() -> dial(a, stop), "dkg-tls-dial-" + opts.self + "-" + a.id);
                t.setDaemon(true);
                t.start();
            }
        }
        long deadline = System.nanoTime() + timeout * 1_000_000L;
        List<Long> missing = new ArrayList<>();
        synchronized (lock) {
            while (links.size() < peers.size()) {
                long left = deadline - System.nanoTime();
                if (left <= 0 || closed) {
                    for (Long p : peers) if (!links.containsKey(p)) missing.add(p);
                    break;
                }
                try {
                    lock.wait(Math.max(1, left / 1_000_000L));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    for (Long p : peers) if (!links.containsKey(p)) missing.add(p);
                    break;
                }
            }
        }
        stop.set(true);
        if (!missing.isEmpty()) {
            close();
            StringBuilder b = new StringBuilder();
            for (Long p : missing) b.append(b.length() == 0 ? "" : ",").append(p);
            throw new DkgChannelError("timeout", missing.get(0), "no authenticated link to " + b);
        }
        return FrostDkgTls.channel(opts.self, opts.sessionId, peers, writers, inbox, this::close);
    }

    /** Ends every link and the listener. */
    @Override public void close() {
        synchronized (lock) {
            if (closed) return;
            closed = true;
            lock.notifyAll();
        }
        inbox.close();
        for (Closeable c : new ArrayList<>(sockets)) quiet(c);
        quiet(server);
    }
}
