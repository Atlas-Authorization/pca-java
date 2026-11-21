package net.atlasauth.pca.mpc.net;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * TEST-ONLY network adversary: a transparent TCP proxy that misbehaves once, after {@code afterBytes} bytes, in one direction
 * (drop / delay / truncate / bitflip / duplicate / reorder at the byte level). TLS 1.3 record authentication rejects tampering,
 * so the expected outcome is an attributable-to-the-link disconnect, never a silently corrupted value.
 */
public final class FaultProxy {
    public enum Kind { NONE, DROP, DELAY, TRUNCATE, BITFLIP, DUPLICATE, REORDER }

    public enum Dir { C2S, S2C }

    /** @param afterBytes the fault starts after this many bytes passed in that direction (skips the TLS handshake). @param ms delay (kind DELAY), default 1000. */
    public record WireFault(Kind kind, Dir dir, long afterBytes, Long ms) {
        public WireFault(Kind kind, Dir dir, long afterBytes) { this(kind, dir, afterBytes, null); }
    }

    /** The destination side of one pipe. */
    public interface Sink {
        void write(byte[] b);

        /** Half-close: nothing more will be written. */
        void end();

        void destroy();

        boolean destroyed();
    }

    /**
     * One direction of the proxy. Callers feed it {@link #data}, {@link #end} (source half-closed) and {@link #close} (source
     * gone); a delay is scheduled on the clock. A closed side tears down the other one only after that direction's delayed
     * bytes are delivered: a real network delays data, it does not drop what the sender wrote before it closed.
     */
    public static final class Pipe {
        private final WireFault f;
        private final boolean active;
        private final String dirName;
        private final Sink to;
        private final MeshClock clock;
        private final List<String> log;
        private long seen;
        private boolean fired, done, ended, closed;
        private byte[] held;
        private int pending; // delayed writes in flight: a half-close must not overtake them

        public Pipe(WireFault f, Dir dir, Sink to, MeshClock clock, List<String> log) {
            this.f = f;
            this.active = f.kind() != Kind.NONE && f.dir() == dir;
            this.dirName = dir == Dir.C2S ? "c2s" : "s2c";
            this.to = to;
            this.clock = clock;
            this.log = log;
        }

        public synchronized void data(byte[] chunk) {
            long before = seen;
            seen += chunk.length;
            if (!active || done || before + chunk.length <= f.afterBytes()) {
                if (active && f.kind() == Kind.DROP && fired) return; // black hole stays black
                to.write(chunk);
                return;
            }
            if (!fired) {
                fired = true;
                log.add("fault " + f.kind().name().toLowerCase() + " " + dirName + " after " + f.afterBytes() + "B");
            }
            switch (f.kind()) {
                case DROP:
                    return;
                case DELAY:
                    pending++;
                    clock.setTimer(() -> delivered(chunk), f.ms() == null ? 1000 : f.ms());
                    return;
                case TRUNCATE:
                    done = true;
                    to.write(Arrays.copyOf(chunk, chunk.length / 2));
                    to.end();
                    return;
                case BITFLIP: {
                    done = true;
                    byte[] b = chunk.clone();
                    b[b.length / 2] ^= 0x01;
                    to.write(b);
                    return;
                }
                case DUPLICATE:
                    done = true;
                    to.write(chunk);
                    to.write(chunk);
                    return;
                case REORDER:
                    if (held == null) {
                        held = chunk;
                    } else {
                        done = true;
                        to.write(chunk);
                        to.write(held);
                        held = null;
                    }
                    return;
                default:
                    to.write(chunk);
            }
        }

        private synchronized void delivered(byte[] chunk) {
            if (!to.destroyed()) to.write(chunk);
            pending--;
            if (pending == 0 && closed) {
                to.end();
                to.destroy();
            } else if (pending == 0 && ended) {
                to.end();
            }
        }

        public synchronized void end() {
            if (held != null) to.write(held);
            ended = true;
            if (pending == 0) to.end();
        }

        public synchronized void close() {
            closed = true;
            if (pending == 0) to.destroy();
        }
    }

    private static final class SocketSink implements Sink {
        private final Socket s;
        private final OutputStream out;
        SocketSink(Socket s) throws IOException { this.s = s; this.out = s.getOutputStream(); }
        @Override public void write(byte[] b) {
            try {
                out.write(b);
                out.flush();
            } catch (IOException e) {
                destroy();
            }
        }
        @Override public void end() {
            try {
                if (!s.isClosed()) s.shutdownOutput();
            } catch (IOException e) {
                destroy();
            }
        }
        @Override public void destroy() {
            try { s.close(); } catch (IOException e) { /* already gone */ }
        }
        @Override public boolean destroyed() { return s.isClosed(); }
    }

    private final int listenPort;
    private final String targetHost;
    private final int targetPort;
    private final WireFault fault;
    private final MeshClock clock;
    private ServerSocket server;
    public final List<String> log = Collections.synchronizedList(new ArrayList<>());

    public FaultProxy(int listenPort, String targetHost, int targetPort, WireFault fault) { this(listenPort, targetHost, targetPort, fault, MeshClock.WALL); }

    public FaultProxy(int listenPort, String targetHost, int targetPort, WireFault fault, MeshClock clock) {
        this.listenPort = listenPort;
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.fault = fault;
        this.clock = clock;
    }

    /** Bind to loopback only; throws if the port is taken. */
    public void listen() throws IOException {
        server = new ServerSocket(listenPort, 50, InetAddress.getByName("127.0.0.1"));
        Thread t = new Thread(this::acceptLoop, "fault-proxy-accept");
        t.setDaemon(true);
        t.start();
    }

    /** True while the listening socket is open (a closed proxy accepts nothing). */
    public boolean listening() { return server != null && !server.isClosed(); }

    public int port() { return server == null ? -1 : server.getLocalPort(); }

    public void close() {
        try { if (server != null) server.close(); } catch (IOException e) { /* closing */ }
    }

    private void acceptLoop() {
        for (;;) {
            Socket c;
            try {
                c = server.accept();
            } catch (IOException e) {
                return;
            }
            Thread t = new Thread(() -> onClient(c), "fault-proxy-conn");
            t.setDaemon(true);
            t.start();
        }
    }

    private void onClient(Socket c) {
        Socket up = new Socket();
        try {
            c.setTcpNoDelay(true);
            up.connect(new InetSocketAddress(targetHost, targetPort), 5000);
            up.setTcpNoDelay(true);
            Pipe c2s = new Pipe(fault, Dir.C2S, new SocketSink(up), clock, log);
            Pipe s2c = new Pipe(fault, Dir.S2C, new SocketSink(c), clock, log);
            Thread r = new Thread(() -> pump(c, up, c2s), "fault-proxy-s2c");
            r.setDaemon(true);
            r.start();
            pump(up, c, s2c);
        } catch (IOException e) {
            closeQuietly(c);
            closeQuietly(up);
        }
    }

    /** Read {@code from} until it ends, feeding {@code pipe}; an I/O error destroys both sides at once. */
    private static void pump(Socket from, Socket other, Pipe pipe) {
        byte[] buf = new byte[16 * 1024];
        try {
            InputStream in = from.getInputStream();
            for (int n; (n = in.read(buf)) >= 0; ) pipe.data(Arrays.copyOf(buf, n));
            pipe.end();
            pipe.close();
        } catch (IOException e) {
            closeQuietly(from);
            closeQuietly(other);
        }
    }

    private static void closeQuietly(Socket s) {
        try { s.close(); } catch (IOException e) { /* already gone */ }
    }
}
