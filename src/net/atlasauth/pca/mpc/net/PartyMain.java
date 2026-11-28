package net.atlasauth.pca.mpc.net;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.mpc.NetWire;
import net.atlasauth.pca.mpc.NetWire.NetAbort;
import net.atlasauth.pca.mpc.Party.DecisionVector;
import net.atlasauth.pca.mpc.Spdz.DealerFault;
import net.atlasauth.pca.mpc.net.Mesh.NodeAddr;
import net.atlasauth.pca.mpc.net.Protocol.Behavior;
import net.atlasauth.pca.mpc.net.Protocol.DealerConfig;
import net.atlasauth.pca.mpc.net.Protocol.PartyConfig;
import net.atlasauth.pca.mpc.net.Protocol.PartyResult;

/**
 * One MPC node (a party, the dealer, or one end of a base-OT demo) as its OWN OS process, talking to the others only over the
 * mutual-TLS mesh. Usage: {@code PartyMain <config.json>} or {@code PartyMain keygen <dir> <cn>}. Prints exactly one JSON line
 * (the result or the attributable abort) on stdout; exit code 3 on an abort. Test hooks need both {@code unsafeTestHooks} in the
 * config and the environment variable {@code PCA_MPC_UNSAFE_TEST_HOOKS=1}, else the node refuses to start.
 */
public final class PartyMain {
    private PartyMain() {}

    private static Map<String, Object> obj(Object o) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("config: object expected");
        @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) o;
        return m;
    }

    private static int num(Object o, String what) {
        if (!(o instanceof Json.Num)) throw new IllegalArgumentException("config: " + what + " must be a number");
        double d = Double.parseDouble(o.toString());
        if (d != Math.rint(d) || Math.abs(d) > 1e9) throw new IllegalArgumentException("config: " + what + " must be an integer");
        return (int) d;
    }

    private static String str(Object o, String what) {
        if (!(o instanceof String)) throw new IllegalArgumentException("config: " + what + " must be a string");
        return (String) o;
    }

    private static void out(Map<String, Object> m) { System.out.println(NetWire.stringify(m)); }

    private static Map<String, Object> resultJson(PartyResult r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", r.id());
        m.put("n", r.n());
        m.put("Q", r.Q());
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("allow", r.composed().allow());
        c.put("t", r.composed().t());
        c.put("rQuant", r.composed().rQuant());
        m.put("composed", c);
        m.put("transcriptDigest", r.transcriptDigest());
        List<Object> rs = new ArrayList<>();
        for (Protocol.RoundStat x : r.rounds()) {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("rd", x.rd());
            o.put("ms", x.ms());
            o.put("bytesOut", x.bytesOut());
            o.put("bytesIn", x.bytesIn());
            rs.add(o);
        }
        m.put("rounds", rs);
        m.put("wallMs", r.wallMs());
        m.put("multiplications", r.multiplications());
        m.put("opens", r.opens());
        m.put("offlineMode", r.offlineMode());
        m.put("macKeys", r.macKeys());
        m.put("sacrificedTriples", r.sacrificedTriples());
        m.put("sacrificePartners", r.sacrificePartners());
        m.put("identifiableAbort", r.identifiableAbort());
        return m;
    }

    private static List<Object> links(Mesh mesh) {
        List<Object> l = new ArrayList<>();
        for (Mesh.LinkStats s : mesh.stats()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("peer", s.peer());
            m.put("appBytesOut", s.appBytesOut());
            m.put("appBytesIn", s.appBytesIn());
            m.put("framesOut", s.framesOut());
            m.put("framesIn", s.framesIn());
            l.add(m);
        }
        return l;
    }

    private static Map<String, Object> abortJson(String role, int id, NetAbort e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("role", role);
        m.put("id", id);
        Map<String, Object> er = new LinkedHashMap<>();
        er.put("kind", e.kind);
        er.put("blamed", e.blamed);
        er.put("reporter", e.reporter);
        er.put("claimedKind", e.claimedKind);
        er.put("claimedBlame", e.claimedBlame);
        er.put("reason", e.reason);
        if (e.evidence != null) er.put("evidence", e.evidence);
        er.put("deadlineMs", e.deadlineMs);
        er.put("message", e.getMessage());
        m.put("error", er);
        return m;
    }

    /** The endemic-LWE base OT lives in the separate lwe-ot adapter (it depends on this core); absent from the classpath = refuse, never run as ec. */
    private static OtNet.Result runLwe(boolean sender, Mesh mesh, int peer, int count, int id) {
        java.lang.reflect.Method m;
        try {
            m = Class.forName("net.atlasauth.pca.mpc.lwe.EndemicOtNet").getMethod(sender ? "runOtSender" : "runOtReceiver", Mesh.class, int.class, int.class);
        } catch (ReflectiveOperationException | LinkageError e) {
            throw new NetAbort("local", null, id, "ot kind 'lwe' is not available in this build (lwe-ot adapter not on the classpath)");
        }
        try {
            return (OtNet.Result) m.invoke(null, mesh, peer, count);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException) throw (RuntimeException) e.getCause();
            throw new NetAbort("local", null, id, "lwe ot failed: " + e.getCause());
        } catch (IllegalAccessException e) {
            throw new NetAbort("local", null, id, "ot kind 'lwe' is not available in this build");
        }
    }

    /** Bind first: bind this node's listener (its own port may be 0), print {@code {"listening":port,"id":id}}, then read one stdin line {@code {"ports":{"<id>":port,...}}} and record every peer's real port before any dial. */
    private static void bindFirst(Mesh mesh, int id) throws IOException {
        Map<String, Object> l = new LinkedHashMap<>();
        l.put("listening", mesh.listen());
        l.put("id", id);
        out(l);
        System.out.flush();
        String line = new java.io.BufferedReader(new java.io.InputStreamReader(System.in, StandardCharsets.UTF_8)).readLine();
        if (line == null) throw new NetAbort("local", null, id, "stdin closed before the port map arrived");
        Map<String, Object> ports = obj(obj(Json.parseLenient(line)).get("ports"));
        for (Map.Entry<String, Object> e : ports.entrySet()) {
            int peer = Integer.parseInt(e.getKey());
            if (peer != id) mesh.setPeerPort(peer, num(e.getValue(), "ports." + e.getKey()));
        }
    }

    public static void main(String[] argv) throws Exception {
        System.exit(run(argv));
    }

    /** Runs the node and returns the process exit code (0 ok, 3 abort or refusal). */
    public static int run(String[] argv) throws IOException {
        if (argv.length >= 3 && argv[0].equals("keygen")) {
            Certs.Identity id = Certs.generate(argv[2]);
            Path dir = net.atlasauth.pca.PrivateFiles.createDirectories(Path.of(argv[1]));
            net.atlasauth.pca.PrivateFiles.write(dir.resolve("key.pem"), id.keyPem().getBytes(StandardCharsets.UTF_8));
            net.atlasauth.pca.PrivateFiles.write(dir.resolve("cert.pem"), id.certPem().getBytes(StandardCharsets.UTF_8));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("keyPath", dir.resolve("key.pem").toString());
            m.put("certPath", dir.resolve("cert.pem").toString());
            out(m);
            return 0;
        }
        if (argv.length != 1) throw new IllegalArgumentException("usage: PartyMain <config.json> | keygen <dir> <cn>");
        Map<String, Object> cfg = obj(Json.parseLenient(Files.readString(Path.of(argv[0]), StandardCharsets.UTF_8)));
        String role = str(cfg.get("role"), "role");
        int id = num(cfg.get("id"), "id");
        boolean hooksRequested = cfg.containsKey("behavior") || cfg.containsKey("frameFault") || cfg.containsKey("dealerFault");
        if (hooksRequested && !(Boolean.TRUE.equals(cfg.get("unsafeTestHooks")) && "1".equals(System.getenv("PCA_MPC_UNSAFE_TEST_HOOKS")))) {
            out(abortJson(role, id, new NetAbort("local", null, id, "refusing to start: test hooks are not enabled in this environment")));
            return 3;
        }
        Faults.FrameFault frameFault = null;
        if (cfg.containsKey("frameFault")) {
            try {
                Map<String, Object> ff = obj(cfg.get("frameFault"));
                frameFault = new Faults.FrameFault(Faults.Kind.of(str(ff.get("kind"), "frameFault.kind")), str(ff.get("round"), "frameFault.round"),
                    ff.get("to") == null ? null : Integer.valueOf(num(ff.get("to"), "frameFault.to")),
                    ff.get("accuse") == null ? null : Integer.valueOf(num(ff.get("accuse"), "frameFault.accuse")));
            } catch (IllegalArgumentException e) {
                out(abortJson(role, id, new NetAbort("local", null, id, "refusing to start: " + e.getMessage())));
                return 3;
            }
        }
        int n = num(cfg.get("n"), "n");
        List<NodeAddr> nodes = new ArrayList<>();
        for (Object o : (List<?>) cfg.get("nodes")) {
            Map<String, Object> x = obj(o);
            nodes.add(new NodeAddr(num(x.get("id"), "node id"), str(x.get("host"), "host"), num(x.get("port"), "port"),
                Files.readString(Path.of(str(x.get("certPath"), "certPath")), StandardCharsets.UTF_8)));
        }
        Mesh.Config mc = new Mesh.Config();
        mc.selfId = id;
        mc.nodes = nodes;
        if (role.equals("dealer")) {
            mc.linkTo = new ArrayList<>();
            for (NodeAddr x : nodes) if (x.id() < n) mc.linkTo.add(x.id());
        }
        mc.keyPem = Files.readString(Path.of(str(cfg.get("keyPath"), "keyPath")), StandardCharsets.UTF_8);
        mc.certPem = Files.readString(Path.of(str(cfg.get("certPath"), "certPath")), StandardCharsets.UTF_8);
        mc.sessionId = str(cfg.get("sessionId"), "sessionId");
        if (cfg.get("listenHost") != null) mc.listenHost = str(cfg.get("listenHost"), "listenHost");
        if (cfg.get("recvTimeoutMs") != null) mc.recvTimeoutMs = num(cfg.get("recvTimeoutMs"), "recvTimeoutMs");
        if (cfg.get("connectTimeoutMs") != null) mc.connectTimeoutMs = num(cfg.get("connectTimeoutMs"), "connectTimeoutMs");
        if (hooksRequested) mc.unsafeTestHooks = true;
        if (frameFault != null) mc.tamper = Faults.tamperFor(frameFault);
        Mesh mesh = new Mesh(mc);
        long startMs = System.currentTimeMillis();
        Integer Q = cfg.get("Q") == null ? null : Integer.valueOf(num(cfg.get("Q"), "Q"));
        try {
            if (Boolean.TRUE.equals(cfg.get("bindFirst"))) bindFirst(mesh, id);
            mesh.connect();
            long connectMs = System.currentTimeMillis() - startMs;
            Map<String, Object> res = new LinkedHashMap<>();
            res.put("ok", true);
            res.put("role", role);
            res.put("id", id);
            res.put("connectMs", connectMs);
            if (role.equals("dealer")) {
                DealerConfig d = new DealerConfig();
                d.n = n;
                d.Q = Q;
                d.mesh = mesh;
                d.insecureTrustedDealer = Boolean.TRUE.equals(cfg.get("insecureTrustedDealer"));
                if (cfg.get("dealerSeed") != null) d.seed = new BigInteger(str(cfg.get("dealerSeed"), "dealerSeed"));
                if (cfg.get("dealerFault") != null) {
                    Map<String, Object> df = obj(cfg.get("dealerFault"));
                    BigInteger keep = df.get("keepCDelta") == null ? null : new BigInteger(str(df.get("keepCDelta"), "keepCDelta"));
                    List<BigInteger> partners = null;
                    if (df.get("partnerCDelta") != null) {
                        partners = new ArrayList<>();
                        for (Object x : (List<?>) df.get("partnerCDelta")) partners.add(x == null ? null : new BigInteger(str(x, "partnerCDelta")));
                    }
                    d.fault = new DealerFault(keep, partners);
                    if (df.get("macFaultAtInput") != null) d.macFaultAtInput = num(df.get("macFaultAtInput"), "macFaultAtInput");
                }
                Protocol.runDealer(d);
            } else if (role.equals("ot-sender") || role.equals("ot-receiver")) {
                String kind = cfg.get("ot") == null ? "ec" : str(obj(cfg.get("ot")).get("kind"), "ot.kind");
                int count = cfg.get("ot") == null ? 128 : num(obj(cfg.get("ot")).get("count"), "ot.count");
                long otStart = System.nanoTime();
                OtNet.Result r;
                if (kind.equals("ec")) {
                    r = role.equals("ot-sender") ? OtNet.runOtSender(mesh, 1, count) : OtNet.runOtReceiver(mesh, 0, count);
                } else if (kind.equals("lwe")) {
                    r = runLwe(role.equals("ot-sender"), mesh, role.equals("ot-sender") ? 1 : 0, count, id);
                } else {
                    throw new NetAbort("local", null, id, "ot kind '" + kind + "' is not available in this build");
                }
                Map<String, Object> rm = new LinkedHashMap<>();
                rm.put("kind", r.kind());
                rm.put("role", r.role());
                rm.put("count", r.count());
                rm.put("matched", r.matched());
                rm.put("padDigest", r.padDigest());
                rm.put("ms", (System.nanoTime() - otStart) / 1e6);
                res.put("result", rm);
            } else {
                Map<String, Object> in = obj(cfg.get("input"));
                PartyConfig c = new PartyConfig();
                c.id = id;
                c.n = n;
                c.Q = Q;
                c.input = new DecisionVector(num(in.get("allow"), "allow"), num(in.get("t"), "t"), num(in.get("rQuant"), "rQuant"));
                c.mesh = mesh;
                if (cfg.get("offline") != null) c.offline = str(cfg.get("offline"), "offline");
                c.insecureTrustedDealer = Boolean.TRUE.equals(cfg.get("insecureTrustedDealer"));
                if (cfg.get("behavior") != null) {
                    Map<String, Object> b = obj(cfg.get("behavior"));
                    c.behavior = new Behavior(str(b.get("kind"), "behavior.kind"), b.get("round") == null ? null : str(b.get("round"), "behavior.round"));
                    c.unsafeTestHooks = true;
                }
                c.sessionId = mc.sessionId;
                res.put("result", resultJson(Protocol.runParty(c)));
            }
            res.put("links", links(mesh));
            res.put("events", new ArrayList<Object>(mesh.events()));
            out(res);
            return 0;
        } catch (Protocol.CrashParty e) {
            // the test-only crash behaviour: exit abruptly with no output (hooks are gated above)
            Runtime.getRuntime().halt(7);
            return 7;
        } catch (RuntimeException e) {
            NetAbort f = mesh.failed();
            NetAbort ne = e instanceof NetAbort ? (NetAbort) e : (f != null ? f : new NetAbort("local", null, id, String.valueOf(e.getMessage())));
            Map<String, Object> m = abortJson(role, id, ne);
            m.put("links", links(mesh));
            m.put("events", new ArrayList<Object>(mesh.events()));
            out(m);
            return 3;
        } finally {
            // give sockets a moment to flush abort frames
            try { Thread.sleep(300); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            mesh.kill();
        }
    }
}
