package net.atlasauth.pca.mpc.net;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import net.atlasauth.pca.mpc.NetWire.NetAbort;
import net.atlasauth.pca.mpc.Party.DecisionVector;
import net.atlasauth.pca.mpc.Spdz.DealerFault;
import net.atlasauth.pca.mpc.net.Certs.Identity;
import net.atlasauth.pca.mpc.net.Mesh.NodeAddr;
import net.atlasauth.pca.mpc.net.Protocol.Behavior;
import net.atlasauth.pca.mpc.net.Protocol.DealerConfig;
import net.atlasauth.pca.mpc.net.Protocol.PartyConfig;
import net.atlasauth.pca.mpc.net.Protocol.PartyResult;

/**
 * Launches n parties (and, for the trusted-dealer mode, a dealer node) in this process on loopback, each with its own fresh
 * per-run identity, its own mutual-TLS mesh and its own thread, and collects what every node ended with. The nodes talk only
 * over TLS sockets, exactly as separate hosts would; a stuck run is cut off after {@code killAfterMs}.
 */
public final class LaunchLocal {
    private LaunchLocal() {}

    public static final class Options {
        public int n;
        public Integer Q;
        public List<DecisionVector> vectors;
        public long recvTimeoutMs = 30_000;
        public long connectTimeoutMs = 120_000;
        /** Hard wall-clock cap for the whole run. */
        public long killAfterMs = 120_000;
        /** TEST ONLY: protocol misbehaviour per node id (parties only). */
        public Map<Integer, Behavior> behaviors = Map.of();
        /** "no-dealer" (default) or "trusted-dealer" (spawns a dealer node; needs insecureTrustedDealer). */
        public String offline = "no-dealer";
        public boolean insecureTrustedDealer;
        public BigInteger dealerSeed;
        public DealerFault dealerFault;
        public Integer macFaultAtInput;
        /** TEST ONLY: route node {@code dialer}'s connection to node {@code target} through a byte-level fault proxy. */
        public WireFaultSpec wireFault;
    }

    public record WireFaultSpec(int dialer, int target, FaultProxy.WireFault fault) {}

    /** What a node ended with: a result (parties only), or the throwable that stopped it. */
    public record NodeOutput(int id, String role, PartyResult result, Throwable error) {
        public NetAbort abort() { return error instanceof NetAbort ? (NetAbort) error : null; }
    }

    public record Launched(List<NodeOutput> outputs, long wallMs) {}

    /** {@code count} DISTINCT free loopback ports, all held open at the same time and released together. */
    public static int[] reservePorts(int count) throws IOException {
        List<ServerSocket> held = new ArrayList<>();
        int[] ports = new int[count];
        try {
            for (int i = 0; i < count; i++) {
                ServerSocket s = new ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"));
                held.add(s);
                ports[i] = s.getLocalPort();
            }
        } finally {
            for (ServerSocket s : held) s.close();
        }
        return ports;
    }

    public static Launched launch(Options o) throws Exception {
        int n = o.n;
        if (o.vectors == null || o.vectors.size() != n) throw new IllegalArgumentException("launchLocal: one decision vector per party");
        boolean dealerMode = "trusted-dealer".equals(o.offline);
        if (dealerMode && !o.insecureTrustedDealer) throw new IllegalArgumentException("launchLocal: offline 'trusted-dealer' requires insecureTrustedDealer");
        int nodeCount = dealerMode ? n + 1 : n;
        byte[] sb = new byte[8];
        new SecureRandom().nextBytes(sb);
        String sessionId = HexFormat.of().formatHex(sb);
        int[] ports = reservePorts(nodeCount + 1); // the last one is for the optional fault proxy
        List<NodeAddr> nodes = new ArrayList<>();
        Identity[] ids = new Identity[nodeCount];
        for (int i = 0; i < nodeCount; i++) {
            ids[i] = Certs.generate("mpc-node-" + i);
            nodes.add(new NodeAddr(i, "127.0.0.1", ports[i], ids[i].certPem()));
        }
        FaultProxy proxy = null;
        if (o.wireFault != null) {
            proxy = new FaultProxy(ports[nodeCount], "127.0.0.1", ports[o.wireFault.target()], o.wireFault.fault());
            proxy.listen();
        }
        Mesh[] meshes = new Mesh[nodeCount];
        for (int i = 0; i < nodeCount; i++) {
            Mesh.Config c = new Mesh.Config();
            c.selfId = i;
            c.nodes = nodes;
            if (o.wireFault != null && i == o.wireFault.dialer()) {
                c.nodes = new ArrayList<>(nodes);
                NodeAddr t = nodes.get(o.wireFault.target());
                c.nodes.set(o.wireFault.target(), new NodeAddr(t.id(), t.host(), ports[nodeCount], t.certPem()));
            }
            c.keyPem = ids[i].keyPem();
            c.certPem = ids[i].certPem();
            c.sessionId = sessionId;
            c.listenHost = "127.0.0.1";
            c.recvTimeoutMs = o.recvTimeoutMs;
            c.connectTimeoutMs = o.connectTimeoutMs;
            if (dealerMode && i == n) {
                c.linkTo = new ArrayList<>();
                for (int j = 0; j < n; j++) c.linkTo.add(j);
            }
            meshes[i] = new Mesh(c);
        }
        ExecutorService ex = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "launch-local");
            t.setDaemon(true);
            return t;
        });
        long t0 = System.nanoTime();
        AtomicInteger active = new AtomicInteger(nodeCount), idle = new AtomicInteger();
        List<Future<NodeOutput>> fs = new ArrayList<>();
        for (int i = 0; i < nodeCount; i++) {
            final int id = i;
            Callable<NodeOutput> job = () -> {
                try {
                    return runNode(o, id, n, dealerMode, meshes[id], sessionId, active, idle);
                } finally {
                    active.decrementAndGet();
                }
            };
            fs.add(ex.submit(job));
        }
        List<NodeOutput> outs = new ArrayList<>();
        long deadline = System.nanoTime() + o.killAfterMs * 1_000_000L;
        try {
            for (int i = 0; i < nodeCount; i++) {
                try {
                    outs.add(fs.get(i).get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS));
                } catch (TimeoutException e) {
                    // a hang is a failure: cut the straggler off and record it
                    for (Mesh m : meshes) m.kill();
                    fs.get(i).cancel(true);
                    outs.add(new NodeOutput(i, role(dealerMode, i, n), null, new NetAbort("local", null, i, "killed after " + o.killAfterMs + "ms")));
                }
            }
        } finally {
            for (Mesh m : meshes) m.kill();
            if (proxy != null) proxy.close();
            ex.shutdownNow();
        }
        return new Launched(outs, (System.nanoTime() - t0) / 1_000_000L);
    }

    private static String role(boolean dealerMode, int id, int n) { return dealerMode && id == n ? "dealer" : "party"; }

    private static NodeOutput runNode(Options o, int id, int n, boolean dealerMode, Mesh mesh, String sessionId, AtomicInteger active, AtomicInteger idle) {
        String role = role(dealerMode, id, n);
        try {
            mesh.connect();
            if (role.equals("dealer")) {
                DealerConfig d = new DealerConfig();
                d.insecureTrustedDealer = o.insecureTrustedDealer;
                d.n = n;
                d.Q = o.Q;
                d.mesh = mesh;
                d.seed = o.dealerSeed;
                d.fault = o.dealerFault;
                d.macFaultAtInput = o.macFaultAtInput;
                Protocol.runDealer(d);
                return new NodeOutput(id, role, null, null);
            }
            PartyConfig c = new PartyConfig();
            c.id = id;
            c.n = n;
            c.Q = o.Q;
            c.input = o.vectors.get(id);
            c.mesh = mesh;
            c.offline = dealerMode ? "trusted-dealer" : "no-dealer";
            c.insecureTrustedDealer = o.insecureTrustedDealer;
            c.sessionId = sessionId;
            Behavior b = o.behaviors.get(id);
            if (b != null) {
                c.behavior = b;
                c.unsafeTestHooks = true;
            }
            return new NodeOutput(id, role, Protocol.runParty(c), null);
        } catch (Protocol.CrashParty e) {
            mesh.kill();
            return new NodeOutput(id, role, null, e);
        } catch (Protocol.SilentParty e) {
            // stays connected and stops participating; peers must time out. Idle until every other node has finished.
            idle.incrementAndGet();
            try {
                while (active.get() > idle.get()) Thread.sleep(50);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
            return new NodeOutput(id, role, null, e);
        } catch (Throwable e) {
            NetAbort f = mesh.failed();
            return new NodeOutput(id, role, null, e instanceof NetAbort ? e : (f != null ? f : e));
        }
    }
}
