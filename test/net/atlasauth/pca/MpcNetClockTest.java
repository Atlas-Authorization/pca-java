package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import net.atlasauth.pca.mpc.NetWire.NetAbort;
import net.atlasauth.pca.mpc.net.Certs;
import net.atlasauth.pca.mpc.net.Certs.Identity;
import net.atlasauth.pca.mpc.net.Mesh;
import net.atlasauth.pca.mpc.net.Mesh.NodeAddr;
import net.atlasauth.pca.mpc.net.MeshClock;
import org.junit.jupiter.api.Test;

/** The injectable mesh clock: deadlines are decided by the clock the test drives, never by how fast the machine is. */
class MpcNetClockTest {
    private static int[] ports(int n) throws IOException {
        List<ServerSocket> held = new ArrayList<>();
        int[] p = new int[n];
        try {
            for (int i = 0; i < n; i++) {
                ServerSocket s = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
                held.add(s);
                p[i] = s.getLocalPort();
            }
        } finally {
            for (ServerSocket s : held) s.close();
        }
        return p;
    }

    private static Mesh mesh(int id, List<NodeAddr> nodes, Identity ident, MeshClock clock, long connectMs, long recvMs) {
        Mesh.Config c = new Mesh.Config();
        c.selfId = id;
        c.nodes = nodes;
        c.keyPem = ident.keyPem();
        c.certPem = ident.certPem();
        c.sessionId = "clock-test";
        c.listenHost = "127.0.0.1";
        c.connectTimeoutMs = connectMs;
        c.recvTimeoutMs = recvMs;
        c.clock = clock;
        return new Mesh(c);
    }

    private static List<NodeAddr> addrs(int[] ports, Identity[] ids) {
        List<NodeAddr> l = new ArrayList<>();
        for (int i = 0; i < ids.length; i++) l.add(new NodeAddr(i, "127.0.0.1", ports[i], ids[i].certPem()));
        return l;
    }

    @Test void theManualClockFiresTimersInDueOrderAndOnlyWhenAdvanced() {
        ManualClock c = new ManualClock();
        List<String> log = new ArrayList<>();
        c.setTimer(() -> log.add("b@" + c.now()), 200);
        c.setTimer(() -> log.add("a@" + c.now()), 100);
        Object gone = c.setTimer(() -> log.add("gone"), 50);
        c.clearTimer(gone);
        c.clearTimer(12345L); // unknown handles are ignored
        c.advance(99);
        assertTrue(log.isEmpty());
        c.advance(1);
        assertEquals(List.of("a@100"), log);
        c.advance(100);
        assertEquals(List.of("a@100", "b@200"), log);
        assertEquals(0, c.pending());
    }

    @Test void aTimerSetByAFiringTimerFiresInTheSameAdvanceAndTimeNeverGoesBackwards() {
        ManualClock c = new ManualClock();
        List<Long> log = new ArrayList<>();
        c.setTimer(() -> {
            log.add(c.now());
            c.setTimer(() -> log.add(c.now()), 50);
        }, 100);
        c.advance(200);
        assertEquals(List.of(100L, 150L), log);
        assertEquals(200, c.now());
        ManualClock d = new ManualClock();
        d.advance(100);
        d.setTimer(() -> { }, 0);
        d.advance(10);
        assertEquals(110, d.now());
    }

    @Test void theWallClockRunsAndCancelsTimers() throws Exception {
        MeshClock w = MeshClock.WALL;
        long t0 = w.now();
        CompletableFuture<Long> f = new CompletableFuture<>();
        w.setTimer(() -> f.complete(w.now()), 20);
        assertTrue(f.get(10, TimeUnit.SECONDS) - t0 >= 19);
        CompletableFuture<Boolean> never = new CompletableFuture<>();
        w.clearTimer(w.setTimer(() -> never.complete(true), 50));
        Thread.sleep(150);
        assertFalse(never.isDone());
    }

    @Test void aReceiveTimesOutExactlyWhenTheVirtualClockReachesItsDeadline() throws Exception {
        int[] p = ports(2);
        Identity[] ids = {Certs.generate("clock-0"), Certs.generate("clock-1")};
        List<NodeAddr> nodes = addrs(p, ids);
        ManualClock clock = new ManualClock();
        Mesh m0 = mesh(0, nodes, ids[0], clock, 60_000, 60_000);
        Mesh m1 = mesh(1, nodes, ids[1], clock, 60_000, 60_000);
        try {
            CompletableFuture<Void> c0 = CompletableFuture.runAsync(m0::connect);
            CompletableFuture<Void> c1 = CompletableFuture.runAsync(m1::connect);
            c0.get(60, TimeUnit.SECONDS);
            c1.get(60, TimeUnit.SECONDS);
            CompletableFuture<Object> r = CompletableFuture.supplyAsync(() -> m0.recv(1, "never", 5_000));
            Thread.sleep(400); // real time passes; virtual time does not
            assertFalse(r.isDone());
            clock.advance(4_999);
            Thread.sleep(200);
            assertFalse(r.isDone());
            clock.advance(1);
            expectTimeout(r);
        } finally {
            m0.kill();
            m1.kill();
        }
    }

    private static void expectTimeout(CompletableFuture<Object> r) throws Exception {
        try {
            r.get(30, TimeUnit.SECONDS);
            fail("the receive must time out");
        } catch (java.util.concurrent.ExecutionException e) {
            NetAbort a = assertInstanceOf(NetAbort.class, e.getCause());
            assertEquals("timeout", a.kind);
            assertEquals(Integer.valueOf(1), a.blamed);
            assertEquals(Integer.valueOf(5_000), a.deadlineMs);
        }
    }

    @Test void theConnectDeadlineFollowsTheVirtualClock() throws Exception {
        int[] p = ports(2);
        Identity[] ids = {Certs.generate("clock-0"), Certs.generate("clock-1")};
        ManualClock clock = new ManualClock();
        Mesh m1 = mesh(1, addrs(p, ids), ids[1], clock, 90_000, 90_000); // node 0 never starts
        try {
            CompletableFuture<Void> c = CompletableFuture.runAsync(m1::connect);
            Thread.sleep(500);
            assertFalse(c.isDone());
            clock.advance(89_999);
            Thread.sleep(200);
            assertFalse(c.isDone());
            clock.advance(1);
            try {
                c.get(30, TimeUnit.SECONDS);
                fail("connect must time out");
            } catch (java.util.concurrent.ExecutionException e) {
                NetAbort a = assertInstanceOf(NetAbort.class, e.getCause());
                assertEquals("timeout", a.kind);
                assertEquals(Integer.valueOf(0), a.blamed);
            }
        } finally {
            m1.kill();
        }
    }
}
