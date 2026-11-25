package net.atlasauth.pca.mpc.net;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.mpc.NetCodec;
import net.atlasauth.pca.mpc.NetWire.NetAbort;

/**
 * Agreement on the joint choice-bit gadget seeds: a signed commit-reveal with an echo round, so ONE corrupt party cannot make
 * honest parties derive different gadgets and then blame each other. Every commitment and opening is signed with the sender's
 * pinned TLS identity key; after the reveal each party echoes the signed values it got from every third party (round gd-e).
 * An echoed signature that does not verify blames the echoer; a verifying statement that differs from the one received
 * directly blames the signer with both statements as transferable evidence. With n = 2 the echo is skipped.
 */
public final class Gadget {
    private Gadget() {}

    private static final Pattern HEX64 = Pattern.compile("^[0-9a-f]{64}$");
    private static final Pattern HEXSIG = Pattern.compile("^[0-9a-f]{16,200}$");

    private static boolean isSigned(Object x, Pattern valueRe) {
        if (!(x instanceof Map)) return false;
        Map<?, ?> m = (Map<?, ?>) x;
        return m.get("v") instanceof String && valueRe.matcher((String) m.get("v")).matches() && m.get("s") instanceof String && HEXSIG.matcher((String) m.get("s")).matches();
    }

    private static Map<String, Object> signed(Mesh mesh, String round, String value) {
        byte[] sig = mesh.sign(NetCodec.gadgetStatement(mesh.sessionId(), round, mesh.selfId, value));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", value);
        m.put("s", HexFormat.of().formatHex(sig));
        return m;
    }

    private static boolean check(Mesh mesh, int signer, String round, Map<?, ?> m) {
        try {
            return mesh.verify(signer, NetCodec.gadgetStatement(mesh.sessionId(), round, signer, (String) m.get("v")), HexFormat.of().parseHex((String) m.get("s")));
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static Integer intOf(Object o) {
        if (!(o instanceof net.atlasauth.pca.Json.Num)) return null;
        try {
            double d = Double.parseDouble(o.toString());
            return d == Math.rint(d) && Math.abs(d) < 1e9 ? Integer.valueOf((int) d) : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public static byte[][] agreeGadgetSeeds(Mesh mesh, int n, Exchanger io) {
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        return agreeGadgetSeeds(mesh, n, io, seed);
    }

    /** Run the signed commit / reveal / echo and return every party's seed in party order (mine included). {@code mySeed} is injectable for tests. */
    @SuppressWarnings("unchecked")
    public static byte[][] agreeGadgetSeeds(Mesh mesh, int n, Exchanger io, byte[] mySeed) {
        int id = mesh.selfId;
        String sid = mesh.sessionId();
        String myCommit = NetCodec.gadgetCommit(sid, id, mySeed);
        Map<Integer, Map<String, Object>> commits = io.exchange("gd-c", p -> signed(mesh, "gd-c", myCommit), (p, raw) -> {
            if (!isSigned(raw, HEX64)) throw io.bad(p, "bad gadget commitment");
            if (!check(mesh, p, "gd-c", (Map<?, ?>) raw)) throw io.bad(p, "gadget commitment signature does not verify");
            return (Map<String, Object>) raw;
        });
        String mySeedHex = HexFormat.of().formatHex(mySeed);
        Map<Integer, Map<String, Object>> opens = io.exchange("gd-o", p -> signed(mesh, "gd-o", mySeedHex), (p, raw) -> {
            if (!isSigned(raw, HEX64)) throw io.bad(p, "bad gadget seed");
            Map<String, Object> m = (Map<String, Object>) raw;
            if (!check(mesh, p, "gd-o", m)) throw io.bad(p, "gadget seed signature does not verify");
            if (!NetCodec.gadgetCommit(sid, p, HexFormat.of().parseHex((String) m.get("v"))).equals(commits.get(p).get("v"))) {
                throw new NetAbort("commitment", p, id, "party " + p + " opened a gadget seed that does not match its commitment");
            }
            return m;
        });
        if (n >= 3) {
            List<Integer> others = new ArrayList<>();
            for (int i = 0; i < n; i++) if (i != id) others.add(i);
            io.exchange("gd-e", peer -> {
                List<Object> out = new ArrayList<>();
                for (int j : others) {
                    if (j == peer) continue;
                    Map<String, Object> e = new LinkedHashMap<>();
                    e.put("j", j);
                    e.put("c", commits.get(j));
                    e.put("o", opens.get(j));
                    out.add(e);
                }
                return out;
            }, (p, raw) -> {
                List<Integer> expect = new ArrayList<>();
                for (int j : others) if (j != p) expect.add(j);
                if (!(raw instanceof List) || ((List<?>) raw).size() != expect.size()) throw io.bad(p, "bad gadget echo");
                for (int k = 0; k < expect.size(); k++) {
                    Object eo = ((List<?>) raw).get(k);
                    int j = expect.get(k);
                    if (!(eo instanceof Map)) throw io.bad(p, "bad gadget echo entry");
                    Map<String, Object> e = (Map<String, Object>) eo;
                    Integer ej = intOf(e.get("j"));
                    if (ej == null || ej != j || !isSigned(e.get("c"), HEX64) || !isSigned(e.get("o"), HEX64)) throw io.bad(p, "bad gadget echo entry");
                    Map<String, Object> ec = (Map<String, Object>) e.get("c");
                    Map<String, Object> eoo = (Map<String, Object>) e.get("o");
                    // a statement that does not verify under j's pinned key was forged by the echoer p
                    if (!check(mesh, j, "gd-c", ec) || !check(mesh, j, "gd-o", eoo)) throw io.bad(p, "gadget echo carries a statement that party " + j + " did not sign");
                    Map<String, Object> mineC = commits.get(j);
                    Map<String, Object> mineO = opens.get(j);
                    boolean cDiff = !ec.get("v").equals(mineC.get("v"));
                    if (cDiff || !eoo.get("v").equals(mineO.get("v"))) {
                        // both statements verify under j's key and differ: j signed two values for one round
                        Map<String, Object> ev = new LinkedHashMap<>();
                        ev.put("signer", j);
                        ev.put("round", cDiff ? "gd-c" : "gd-o");
                        ev.put("statements", cDiff ? List.of(mineC, ec) : List.of(mineO, eoo));
                        throw new NetAbort("equivocation", j, id, "party " + j + " signed different gadget " + (cDiff ? "commitments" : "seeds")
                            + " for different parties (shown by party " + p + "'s echo)", null, null, null, ev, null);
                    }
                }
                return Boolean.TRUE;
            });
        }
        byte[][] out = new byte[n][];
        for (int p = 0; p < n; p++) out[p] = p == id ? mySeed.clone() : HexFormat.of().parseHex((String) opens.get(p).get("v"));
        return out;
    }

    static byte[] utf8(String s) { return Json.utf8(s); }
}
