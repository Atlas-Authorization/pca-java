package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import net.atlasauth.pca.mpc.NetWire;
import net.atlasauth.pca.mpc.NetWire.NetAbort;
import net.atlasauth.pca.mpc.net.Certs;
import net.atlasauth.pca.mpc.net.Certs.Identity;
import net.atlasauth.pca.mpc.net.Mesh;
import net.atlasauth.pca.mpc.net.Mesh.NodeAddr;
import org.junit.jupiter.api.Test;

/** The mutual-TLS mesh over loopback: an honest 3-node exchange, and the refusals (wrong pin, wrong hello id, oversize, replay, wrong round, early close). Identities are generated per run. */
class MpcMeshTest {
    private static final String SID = "mesh-test-session";
    /** Blocking tasks need real threads: the common pool can be as small as one thread on a small CI machine. */
    static final java.util.concurrent.ExecutorService EX = java.util.concurrent.Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r);
        t.setDaemon(true);
        return t;
    });

    /**
     * One mesh per identity, every node bound to a port the OS chose and kept, every peer told the real ports; not yet connected.
     * (A port probed and released before its node binds can be taken by another process in between.)
     */
    static Mesh[] bound(Identity[] ids, long connectMs, long recvMs) {
        List<NodeAddr> nodes = new ArrayList<>();
        for (int i = 0; i < ids.length; i++) nodes.add(new NodeAddr(i, "127.0.0.1", 0, ids[i].certPem()));
        Mesh[] meshes = new Mesh[ids.length];
        int[] ports = new int[ids.length];
        for (int i = 0; i < ids.length; i++) {
            meshes[i] = new Mesh(cfg(i, nodes, ids[i], connectMs, recvMs));
            ports[i] = meshes[i].listen();
        }
        for (int i = 0; i < ids.length; i++) for (int j = 0; j < ids.length; j++) if (i != j) meshes[i].setPeerPort(j, ports[j]);
        return meshes;
    }

    static Mesh.Config cfg(int self, List<NodeAddr> nodes, Identity id, long connectMs, long recvMs) {
        Mesh.Config c = new Mesh.Config();
        c.selfId = self;
        c.nodes = nodes;
        c.keyPem = id.keyPem();
        c.certPem = id.certPem();
        c.sessionId = SID;
        c.listenHost = "127.0.0.1";
        c.connectTimeoutMs = connectMs;
        c.recvTimeoutMs = recvMs;
        return c;
    }

    static NetAbort abortOf(Throwable t) {
        while (t != null && !(t instanceof NetAbort)) t = t.getCause();
        assertNotNull(t, "expected a NetAbort");
        return (NetAbort) t;
    }

    @Test void honestThreeNodeExchange() throws Exception {
        int n = 3;
        Identity[] ids = new Identity[n];
        for (int i = 0; i < n; i++) ids[i] = Certs.generate("node" + i);
        Mesh[] meshes = bound(ids, 20_000, 10_000);
        List<CompletableFuture<Void>> conn = new ArrayList<>();
        for (Mesh m : meshes) conn.add(CompletableFuture.runAsync(m::connect, EX));
        for (CompletableFuture<Void> f : conn) f.get(30, TimeUnit.SECONDS);

        List<CompletableFuture<Map<Integer, Object>>> runs = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            final int me = i;
            runs.add(CompletableFuture.supplyAsync(() -> {
                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("x", me);
                meshes[me].broadcast("r1", payload);
                return meshes[me].collect("r1");
            }, EX));
        }
        for (int i = 0; i < n; i++) {
            Map<Integer, Object> got = runs.get(i).get(30, TimeUnit.SECONDS);
            assertEquals(n - 1, got.size());
            for (Map.Entry<Integer, Object> e : got.entrySet()) {
                assertNotEquals(i, e.getKey().intValue());
                assertEquals(e.getKey().toString(), ((Map<?, ?>) e.getValue()).get("x").toString());
            }
        }
        // signatures are verifiable against the pinned certificate only
        byte[] data = "statement".getBytes();
        byte[] sig = meshes[0].sign(data);
        assertTrue(meshes[1].verify(0, data, sig));
        assertFalse(meshes[1].verify(2, data, sig));
        assertFalse(meshes[1].verify(0, "other".getBytes(), sig));
        assertFalse(meshes[0].verify(0, data, sig));
        for (Mesh m : meshes) m.finish();
    }

    /**
     * The acceptor's protocol thread sends the moment the link is open, before the attaching thread has sent our hello (the peer's hello
     * already arrived, so connect() returned). The hello must still be the first frame: the peer receives the data, not "data before hello".
     */
    @Test void aSendRacingTheHelloDoesNotOvertakeIt() throws Exception {
        Identity[] ids = {Certs.generate("h0"), Certs.generate("h1")};
        List<NodeAddr> nodes = new ArrayList<>();
        for (int i = 0; i < 2; i++) nodes.add(new NodeAddr(i, "127.0.0.1", 0, ids[i].certPem()));
        Mesh[] m = new Mesh[2];
        Mesh.Config c0 = cfg(0, nodes, ids[0], 20_000, 10_000);
        c0.unsafeTestHooks = true;
        c0.beforeHello = () -> {
            Thread sender = new Thread(() -> m[0].send(1, "r1", "payload"));
            sender.setDaemon(true);
            sender.start();
            // wait for a decision point, not a time: the sender either finished (the bug: it overtook the hello) or is parked on the link
            while (sender.isAlive() && sender.getState() != Thread.State.BLOCKED) Thread.onSpinWait();
        };
        m[0] = new Mesh(c0);
        m[1] = new Mesh(cfg(1, nodes, ids[1], 20_000, 10_000));
        int[] ports = {m[0].listen(), m[1].listen()};
        m[0].setPeerPort(1, ports[1]);
        m[1].setPeerPort(0, ports[0]);
        List<CompletableFuture<Void>> conn = new ArrayList<>();
        for (Mesh x : m) conn.add(CompletableFuture.runAsync(x::connect, EX));
        for (CompletableFuture<Void> f : conn) f.get(30, TimeUnit.SECONDS);
        assertEquals("payload", m[1].recv(0, "r1"));
        assertNull(m[1].failed());
        for (Mesh x : m) x.finish();
    }

    @Test void listenBindsOnceAndPeerPortsAreFixedAfterwards() throws Exception {
        Identity[] ids = {Certs.generate("a0"), Certs.generate("a1")};
        Mesh[] m = bound(ids, 5_000, 5_000);
        int port = m[0].listen();
        assertTrue(port > 0);
        assertEquals(port, m[0].listen());
        assertEquals(port, m[0].boundPort());
        m[0].setPeerPort(1, m[1].boundPort()); // still allowed: nothing has dialed
        assertThrows(IllegalArgumentException.class, () -> m[1].setPeerPort(1, 9)); // self
        assertThrows(IllegalArgumentException.class, () -> m[1].setPeerPort(7, 9)); // unknown
        Mesh.Config c = cfg(0, List.of(new NodeAddr(0, "127.0.0.1", 0, ids[0].certPem()), new NodeAddr(1, "127.0.0.1", 0, ids[1].certPem())), ids[0], 5_000, 5_000);
        c.linkTo = List.of(); // no link to wait for: connect() starts and finishes at once
        Mesh solo = new Mesh(c);
        solo.connect();
        assertThrows(IllegalStateException.class, () -> solo.setPeerPort(1, 9));
        solo.finish();
    }

    /** A peer's data frame followed by its abort frame: a deferring node reads the data first and meets the claim on its next receive. */
    @Test void aDeferredAbortClaimIsReadAfterTheDataSentBeforeIt() throws Exception {
        Identity[] ids = {Certs.generate("d0"), Certs.generate("d1")};
        Mesh[] m = bound(ids, 20_000, 10_000);
        m[1].setDeferAborts(true);
        List<CompletableFuture<Void>> conn = new ArrayList<>();
        for (Mesh x : m) conn.add(CompletableFuture.runAsync(x::connect, EX));
        for (CompletableFuture<Void> f : conn) f.get(30, TimeUnit.SECONDS);
        m[0].send(1, "r1", "payload");
        m[0].fail(new NetAbort("ot-check", 0, 0, "claim"), null);
        assertEquals("payload", m[1].recv(0, "r1", 10_000));
        NetAbort a = assertThrows(NetAbort.class, () -> m[1].recv(0, "r2", 10_000));
        assertEquals("peer-abort", a.kind);
        assertEquals("ot-check", a.claimedKind);
    }

    @Test void pinnedCertMismatchRefusesTheLink() throws Exception {
        Identity real0 = Certs.generate("real0");
        Identity imposter = Certs.generate("imposter");
        Identity id1 = Certs.generate("node1");
        // node 1 pins an imposter certificate for node 0, so the real node 0 must be refused
        List<NodeAddr> view0 = List.of(new NodeAddr(0, "127.0.0.1", 0, real0.certPem()), new NodeAddr(1, "127.0.0.1", 0, id1.certPem()));
        List<NodeAddr> view1 = List.of(new NodeAddr(0, "127.0.0.1", 0, imposter.certPem()), new NodeAddr(1, "127.0.0.1", 0, id1.certPem()));
        Mesh m0 = new Mesh(cfg(0, view0, real0, 2_500, 2_000));
        Mesh m1 = new Mesh(cfg(1, view1, id1, 2_500, 2_000));
        int p0 = m0.listen(), p1 = m1.listen();
        m0.setPeerPort(1, p1);
        m1.setPeerPort(0, p0);
        CompletableFuture<Void> c0 = CompletableFuture.runAsync(m0::connect, EX);
        CompletableFuture<Void> c1 = CompletableFuture.runAsync(m1::connect, EX);
        ExecutionException e1 = assertThrows(ExecutionException.class, () -> c1.get(20, TimeUnit.SECONDS));
        assertTrue(List.of("timeout", "identity").contains(abortOf(e1).kind));
        assertThrows(ExecutionException.class, () -> c0.get(20, TimeUnit.SECONDS));
    }

    @Test void tamperHookNeedsExplicitOptIn() throws Exception {
        Identity id0 = Certs.generate("n0");
        Identity id1 = Certs.generate("n1");
        List<NodeAddr> nodes = List.of(new NodeAddr(0, "127.0.0.1", 1, id0.certPem()), new NodeAddr(1, "127.0.0.1", 2, id1.certPem()));
        Mesh.Config c = cfg(0, nodes, id0, 1000, 1000);
        c.tamper = ev -> List.of(ev.raw());
        assertThrows(IllegalArgumentException.class, () -> new Mesh(c));
        // a node whose own certificate differs from the one listed for it is refused
        assertThrows(IllegalArgumentException.class, () -> new Mesh(cfg(0, nodes, id1, 1000, 1000)));
    }

    // ---- refusals from a hand-driven peer (node 1 dials node 0) ----

    /** A raw TLS client speaking the frame format, standing in for node 1. */
    static final class RawPeer implements AutoCloseable {
        final SSLSocket sock;
        final OutputStream out;
        final InputStream in;

        RawPeer(Identity me, String serverCertPem, int port) throws Exception {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("k", Certs.parseKey(me.keyPem()), new char[0], new java.security.cert.Certificate[] {Certs.parseCert(me.certPem())});
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, new char[0]);
            KeyStore ts = KeyStore.getInstance("PKCS12");
            ts.load(null, null);
            ts.setCertificateEntry("srv", Certs.parseCert(serverCertPem));
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
            SSLContext ctx = SSLContext.getInstance("TLSv1.3");
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            SSLSocket s = null;
            long end = System.nanoTime() + 10_000_000_000L;
            for (;;) {
                try {
                    s = (SSLSocket) ctx.getSocketFactory().createSocket();
                    s.connect(new InetSocketAddress("127.0.0.1", port), 2000);
                    s.setEnabledProtocols(new String[] {"TLSv1.3"});
                    s.startHandshake();
                    break;
                } catch (IOException e) {
                    if (s != null) s.close();
                    if (System.nanoTime() > end) throw e;
                    Thread.sleep(100);
                }
            }
            sock = s;
            out = s.getOutputStream();
            in = s.getInputStream();
        }

        void frame(String ty, String rd, long seq, Object d) throws IOException {
            out.write(NetWire.encodeFrame(new NetWire.Frame(NetWire.WIRE_VERSION, ty, SID, Long.valueOf(seq), rd, d)));
            out.flush();
        }

        void hello(int claimedId) throws IOException {
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("id", claimedId);
            frame("hello", "hello", 0, d);
        }

        @Override public void close() throws IOException { sock.close(); }
    }

    private record Rig(Identity id0, Identity id1, Mesh m0, CompletableFuture<Void> connect, int port) {}

    private static Rig rig(long connectMs, long recvMs) throws Exception {
        Identity id0 = Certs.generate("n0");
        Identity id1 = Certs.generate("n1");
        List<NodeAddr> nodes = List.of(new NodeAddr(0, "127.0.0.1", 0, id0.certPem()), new NodeAddr(1, "127.0.0.1", 1, id1.certPem()));
        Mesh m0 = new Mesh(cfg(0, nodes, id0, connectMs, recvMs));
        int p0 = m0.listen();
        return new Rig(id0, id1, m0, CompletableFuture.runAsync(m0::connect, EX), p0);
    }

    @Test void helloWithWrongPartyIdIsRefused() throws Exception {
        Rig r = rig(10_000, 5_000);
        try (RawPeer p = new RawPeer(r.id1(), r.id0().certPem(), r.port())) {
            p.hello(5);
            NetAbort a = abortOf(assertThrows(ExecutionException.class, () -> r.connect().get(15, TimeUnit.SECONDS)));
            assertEquals("identity", a.kind);
            assertEquals(Integer.valueOf(1), a.blamed);
        }
    }

    @Test void oversizeLengthPrefixIsRefused() throws Exception {
        Rig r = rig(10_000, 5_000);
        try (RawPeer p = new RawPeer(r.id1(), r.id0().certPem(), r.port())) {
            p.hello(1);
            r.connect().get(15, TimeUnit.SECONDS);
            int bad = NetWire.MAX_FRAME_BYTES + 1;
            p.out.write(new byte[] {(byte) (bad >>> 24), (byte) (bad >>> 16), (byte) (bad >>> 8), (byte) bad});
            p.out.flush();
            NetAbort a = assertThrows(NetAbort.class, () -> r.m0().recv(1, "x", 5_000));
            assertEquals("oversize", a.kind);
            assertEquals(Integer.valueOf(1), a.blamed);
        }
    }

    @Test void replayedSequenceNumberIsRefused() throws Exception {
        Rig r = rig(10_000, 5_000);
        try (RawPeer p = new RawPeer(r.id1(), r.id0().certPem(), r.port())) {
            p.hello(1);
            r.connect().get(15, TimeUnit.SECONDS);
            p.frame("msg", "x", 1, "a");
            p.frame("msg", "x", 1, "b");
            // the first frame may already be queued when the replay is seen: it is delivered, the next read must abort
            NetAbort a = assertThrows(NetAbort.class, () -> { r.m0().recv(1, "x", 5_000); r.m0().recv(1, "x", 5_000); });
            assertEquals("duplicate", a.kind);
        }
    }

    @Test void skippedSequenceNumberIsRefused() throws Exception {
        Rig r = rig(10_000, 5_000);
        try (RawPeer p = new RawPeer(r.id1(), r.id0().certPem(), r.port())) {
            p.hello(1);
            r.connect().get(15, TimeUnit.SECONDS);
            p.frame("msg", "x", 5, "a");
            NetAbort a = assertThrows(NetAbort.class, () -> r.m0().recv(1, "x", 5_000));
            assertEquals("out-of-order", a.kind);
        }
    }

    @Test void wrongRoundIsRefused() throws Exception {
        Rig r = rig(10_000, 5_000);
        try (RawPeer p = new RawPeer(r.id1(), r.id0().certPem(), r.port())) {
            p.hello(1);
            r.connect().get(15, TimeUnit.SECONDS);
            p.frame("msg", "other", 1, "a");
            NetAbort a = assertThrows(NetAbort.class, () -> r.m0().recv(1, "x", 5_000));
            assertEquals("wrong-round", a.kind);
            assertEquals(Integer.valueOf(1), a.blamed);
        }
    }

    @Test void earlyCloseIsADisconnect() throws Exception {
        Rig r = rig(10_000, 5_000);
        RawPeer p = new RawPeer(r.id1(), r.id0().certPem(), r.port());
        p.hello(1);
        r.connect().get(15, TimeUnit.SECONDS);
        p.close();
        NetAbort a = assertThrows(NetAbort.class, () -> r.m0().recv(1, "x", 5_000));
        assertEquals("disconnect", a.kind);
        assertEquals(Integer.valueOf(1), a.blamed);
    }

    @Test void silentPeerIsBlamedAfterTheDeadline() throws Exception {
        Rig r = rig(10_000, 5_000);
        try (RawPeer p = new RawPeer(r.id1(), r.id0().certPem(), r.port())) {
            p.hello(1);
            r.connect().get(15, TimeUnit.SECONDS);
            NetAbort a = assertThrows(NetAbort.class, () -> r.m0().recv(1, "x", 300));
            assertEquals("timeout", a.kind);
            assertEquals(Integer.valueOf(1), a.blamed);
            assertEquals(Integer.valueOf(300), a.deadlineMs);
        }
    }

    @Test void clientWithAnUnpinnedCertificateNeverLinks() throws Exception {
        Rig r = rig(2_000, 1_000);
        Identity stranger = Certs.generate("stranger");
        try (RawPeer p = new RawPeer(stranger, r.id0().certPem(), r.port())) {
            p.hello(1);
        } catch (IOException ignored) {
            // the server may refuse the unpinned client before or after the handshake completes on our side
        }
        NetAbort a = abortOf(assertThrows(ExecutionException.class, () -> r.connect().get(15, TimeUnit.SECONDS)));
        assertEquals("timeout", a.kind);
    }
}
