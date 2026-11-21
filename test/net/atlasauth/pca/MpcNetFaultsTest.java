package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import net.atlasauth.pca.mpc.net.FaultProxy;
import net.atlasauth.pca.mpc.net.FaultProxy.Dir;
import net.atlasauth.pca.mpc.net.FaultProxy.Kind;
import net.atlasauth.pca.mpc.net.FaultProxy.Pipe;
import net.atlasauth.pca.mpc.net.FaultProxy.Sink;
import net.atlasauth.pca.mpc.net.FaultProxy.WireFault;
import net.atlasauth.pca.mpc.net.LaunchLocal;
import org.junit.jupiter.api.Test;

/** The byte-level fault proxy: each fault kind driven through a scripted pipe, then over real sockets. */
class MpcNetFaultsTest {
    private static byte[] B(int... n) { byte[] b = new byte[n.length]; for (int i = 0; i < n.length; i++) b[i] = (byte) n[i]; return b; }

    private static final class Rec implements Sink {
        final List<byte[]> writes = new ArrayList<>();
        int ended, destroys;
        boolean destroyed;
        @Override public void write(byte[] b) { writes.add(b); }
        @Override public void end() { ended++; }
        @Override public void destroy() { destroys++; destroyed = true; }
        @Override public boolean destroyed() { return destroyed; }
        List<List<Integer>> seen() { List<List<Integer>> l = new ArrayList<>(); for (byte[] w : writes) { List<Integer> x = new ArrayList<>(); for (byte v : w) x.add((int) v); l.add(x); } return l; }
    }

    private static final class Rig {
        final Rec dst = new Rec();
        final ManualClock clock = new ManualClock();
        final List<String> log = new ArrayList<>();
        final Pipe pipe;
        Rig(WireFault f) { this(f, f.dir()); }
        Rig(WireFault f, Dir d) { pipe = new Pipe(f, d, dst, clock, log); }
        void send(byte[]... cs) { for (byte[] c : cs) pipe.data(c); }
    }

    private static List<Integer> L(int... n) { List<Integer> l = new ArrayList<>(); for (int v : n) l.add(v); return l; }

    @Test void kindNonePassesEverythingAndLogsNothing() {
        Rig r = new Rig(new WireFault(Kind.NONE, Dir.C2S, 0));
        r.send(B(1, 2, 3), B(4));
        assertEquals(List.of(L(1, 2, 3), L(4)), r.dst.seen());
        assertTrue(r.log.isEmpty());
    }

    @Test void aFaultForOneDirectionLeavesTheOtherAlone() {
        Rig r = new Rig(new WireFault(Kind.DROP, Dir.C2S, 0), Dir.S2C);
        r.send(B(7, 7));
        assertEquals(List.of(L(7, 7)), r.dst.seen());
        assertTrue(r.log.isEmpty());
    }

    @Test void dropPassesUpToAfterBytesThenBlackHoles() {
        Rig a = new Rig(new WireFault(Kind.DROP, Dir.C2S, 3));
        a.send(B(1, 2, 3), B(4, 5), B(6, 7));
        a.clock.advance(10_000);
        assertEquals(List.of(L(1, 2, 3)), a.dst.seen()); // a chunk ending exactly at afterBytes passes
        assertEquals(List.of("fault drop c2s after 3B"), a.log);
        Rig b = new Rig(new WireFault(Kind.DROP, Dir.S2C, 2));
        b.send(B(1, 2, 3), B(4));
        assertTrue(b.dst.writes.isEmpty()); // the straddling chunk is faulted whole
        assertEquals(List.of("fault drop s2c after 2B"), b.log);
    }

    @Test void delayDeliversAfterExactlyMsInOrder() {
        Rig r = new Rig(new WireFault(Kind.DELAY, Dir.C2S, 2, 300L));
        r.send(B(1, 2), B(3, 4), B(5));
        assertEquals(List.of(L(1, 2)), r.dst.seen());
        r.clock.advance(299);
        assertEquals(1, r.dst.writes.size());
        r.clock.advance(1);
        assertEquals(List.of(L(1, 2), L(3, 4), L(5)), r.dst.seen());
        assertEquals(List.of("fault delay c2s after 2B"), r.log);
        assertEquals(0, r.dst.ended);
    }

    @Test void delayDefaultsToOneSecond() {
        Rig r = new Rig(new WireFault(Kind.DELAY, Dir.C2S, 0));
        r.send(B(9));
        r.clock.advance(999);
        assertTrue(r.dst.writes.isEmpty());
        r.clock.advance(1);
        assertEquals(List.of(L(9)), r.dst.seen());
    }

    @Test void aSourceEndWhileWritesArePendingEndsTheDestinationAfterTheLastDelayedWrite() {
        Rig r = new Rig(new WireFault(Kind.DELAY, Dir.C2S, 0, 100L));
        r.send(B(1));
        r.clock.advance(50);
        r.send(B(2));
        r.pipe.end();
        assertEquals(0, r.dst.ended);
        r.clock.advance(50);
        assertEquals(List.of(L(1)), r.dst.seen());
        assertEquals(0, r.dst.ended);
        r.clock.advance(50);
        assertEquals(List.of(L(1), L(2)), r.dst.seen());
        assertEquals(1, r.dst.ended);
    }

    @Test void aSourceCloseWhileWritesArePendingDestroysTheDestinationOnlyAfterTheDelayedWrite() {
        Rig r = new Rig(new WireFault(Kind.DELAY, Dir.C2S, 0, 100L));
        r.send(B(1));
        r.pipe.close();
        assertEquals(0, r.dst.destroys);
        r.clock.advance(100);
        assertEquals(List.of(L(1)), r.dst.seen());
        assertEquals(1, r.dst.destroys);
    }

    @Test void nothingIsWrittenToADestinationDestroyedMeanwhile() {
        Rig r = new Rig(new WireFault(Kind.DELAY, Dir.C2S, 0, 100L));
        r.send(B(1));
        r.dst.destroyed = true;
        r.clock.advance(100);
        assertTrue(r.dst.writes.isEmpty());
    }

    @Test void aSourceEndWithNothingPendingEndsTheDestinationAtOnce() {
        Rig r = new Rig(new WireFault(Kind.DELAY, Dir.C2S, 0, 100L));
        r.pipe.end();
        assertEquals(1, r.dst.ended);
        r.pipe.close();
        assertEquals(1, r.dst.destroys);
    }

    @Test void truncateCutsTheStraddlingChunkToHalfAndEndsOnceThenPassesLaterChunks() {
        Rig r = new Rig(new WireFault(Kind.TRUNCATE, Dir.C2S, 2));
        r.send(B(1, 2), B(3, 4, 5, 6, 7), B(8, 9));
        assertEquals(List.of(L(1, 2), L(3, 4), L(8, 9)), r.dst.seen());
        assertEquals(1, r.dst.ended);
        assertEquals(List.of("fault truncate c2s after 2B"), r.log);
    }

    @Test void bitflipFlipsBitZeroOfTheMiddleByteOnceOnACopy() {
        Rig r = new Rig(new WireFault(Kind.BITFLIP, Dir.C2S, 1));
        byte[] c = B(10, 20, 30, 40);
        r.send(B(0), c, B(50, 60));
        assertEquals(List.of(L(0), L(10, 20, 31, 40), L(50, 60)), r.dst.seen());
        assertArrayEquals(B(10, 20, 30, 40), c);
        Rig odd = new Rig(new WireFault(Kind.BITFLIP, Dir.C2S, 0));
        odd.send(B(4, 4, 4, 4, 4));
        assertEquals(List.of(L(4, 4, 5, 4, 4)), odd.dst.seen());
    }

    @Test void duplicateWritesTheStraddlingChunkTwiceOnce() {
        Rig r = new Rig(new WireFault(Kind.DUPLICATE, Dir.C2S, 1));
        r.send(B(0), B(1, 2), B(3));
        assertEquals(List.of(L(0), L(1, 2), L(1, 2), L(3)), r.dst.seen());
    }

    @Test void reorderSwapsOnceThenPassesInOrderAndFlushesAHeldChunkOnEnd() {
        Rig a = new Rig(new WireFault(Kind.REORDER, Dir.C2S, 1));
        a.send(B(0), B(1, 2), B(3, 4), B(5), B(6));
        assertEquals(List.of(L(0), L(3, 4), L(1, 2), L(5), L(6)), a.dst.seen());
        Rig b = new Rig(new WireFault(Kind.REORDER, Dir.C2S, 1));
        b.send(B(0), B(1, 2));
        assertEquals(List.of(L(0)), b.dst.seen());
        b.pipe.end();
        assertEquals(List.of(L(0), L(1, 2)), b.dst.seen());
        assertEquals(1, b.dst.ended);
    }

    // ------------------------------------------------------------------------- real sockets

    private static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) { return s.getLocalPort(); }
    }

    private static byte[] readN(InputStream in, int n) throws IOException {
        byte[] b = in.readNBytes(n);
        assertEquals(n, b.length);
        return b;
    }

    @Test void kindNoneRelaysBothDirections() throws Exception {
        try (ServerSocket target = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            FaultProxy p = new FaultProxy(0, "127.0.0.1", target.getLocalPort(), new WireFault(Kind.NONE, Dir.C2S, 0));
            p.listen();
            try (Socket c = new Socket("127.0.0.1", p.port()); Socket s = target.accept()) {
                c.setSoTimeout(10_000);
                s.setSoTimeout(10_000);
                OutputStream co = c.getOutputStream();
                co.write(B(1, 2, 3));
                co.flush();
                assertArrayEquals(B(1, 2, 3), readN(s.getInputStream(), 3));
                s.getOutputStream().write(B(9, 8));
                s.getOutputStream().flush();
                assertArrayEquals(B(9, 8), readN(c.getInputStream(), 2));
            } finally {
                p.close();
            }
        }
    }

    @Test void aDropFaultAfterTheFirstBytesBlackHolesTheRestAndLogsIt() throws Exception {
        try (ServerSocket target = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            FaultProxy p = new FaultProxy(0, "127.0.0.1", target.getLocalPort(), new WireFault(Kind.DROP, Dir.C2S, 2));
            p.listen();
            try (Socket c = new Socket("127.0.0.1", p.port()); Socket s = target.accept()) {
                s.setSoTimeout(500);
                c.getOutputStream().write(B(1, 2));
                c.getOutputStream().flush();
                assertArrayEquals(B(1, 2), readN(s.getInputStream(), 2));
                c.getOutputStream().write(B(3, 4));
                c.getOutputStream().flush();
                assertThrows(java.net.SocketTimeoutException.class, () -> s.getInputStream().read());
                for (int i = 0; i < 100 && p.log.isEmpty(); i++) Thread.sleep(20);
                assertEquals(List.of("fault drop c2s after 2B"), p.log);
            } finally {
                p.close();
            }
        }
    }

    @Test void listenFailsWhenThePortIsTakenAndCloseStopsAccepting() throws Exception {
        FaultProxy p = new FaultProxy(0, "127.0.0.1", 1, new WireFault(Kind.NONE, Dir.C2S, 0));
        p.listen();
        int port = p.port();
        assertThrows(IOException.class, () -> new FaultProxy(port, "127.0.0.1", 1, new WireFault(Kind.NONE, Dir.C2S, 0)).listen());
        assertTrue(p.listening());
        p.close();
        // not a connect probe: the ephemeral port may already belong to another test's listener
        assertFalse(p.listening());
    }

    @Test void anUpstreamThatRefusesClosesTheClientSide() throws Exception {
        FaultProxy p = new FaultProxy(0, "127.0.0.1", freePort(), new WireFault(Kind.NONE, Dir.C2S, 0));
        p.listen();
        try (Socket c = new Socket("127.0.0.1", p.port())) {
            c.setSoTimeout(10_000);
            int r;
            try { r = c.getInputStream().read(); } catch (IOException e) { r = -1; }
            assertEquals(-1, r);
        } finally {
            p.close();
        }
    }

    // ------------------------------------------------------------------------- through the launcher

    @Test void aBitflipOnTheWireIsAttributedToTheLinkNeverAValue() throws Exception {
        LaunchLocal.Options o = new LaunchLocal.Options();
        o.n = 3;
        o.Q = 4;
        o.vectors = List.of(new net.atlasauth.pca.mpc.Party.DecisionVector(1, 1, 1), new net.atlasauth.pca.mpc.Party.DecisionVector(1, 2, 3), new net.atlasauth.pca.mpc.Party.DecisionVector(1, 1, 2));
        o.recvTimeoutMs = 30_000;
        o.killAfterMs = 120_000;
        o.wireFault = new LaunchLocal.WireFaultSpec(2, 0, new WireFault(Kind.BITFLIP, Dir.C2S, 6000));
        LaunchLocal.Launched l = LaunchLocal.launch(o);
        for (LaunchLocal.NodeOutput out : l.outputs()) {
            assertNull(out.result(), "a tampered link yields no output");
            assertNotNull(out.error(), "every node stops with an abort");
        }
        assertTrue(l.outputs().stream().anyMatch(x -> x.abort() != null), "some node names the failure");
    }
}
