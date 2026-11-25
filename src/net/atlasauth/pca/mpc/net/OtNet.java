package net.atlasauth.pca.mpc.net;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.mpc.Ec.Point;
import net.atlasauth.pca.mpc.Ec.SchnorrProof;
import net.atlasauth.pca.mpc.NetCodec;
import net.atlasauth.pca.mpc.NetWire;
import net.atlasauth.pca.mpc.NetWire.NetAbort;
import net.atlasauth.pca.mpc.Ot;
import net.atlasauth.pca.mpc.Ot.BaseOtAbort;
import net.atlasauth.pca.mpc.Ot.BaseOtBinding;
import net.atlasauth.pca.mpc.Ot.OtRandom;

/**
 * Pairwise base oblivious transfer OVER THE NETWORK: the malicious-secure Chou-Orlandi-style base OT on Ed25519 with a Schnorr
 * proof of knowledge and subgroup validation of every received point. A FUNCTIONAL-CORRECTNESS demonstration: afterwards the
 * receiver reveals its choice bits and a hash of each received pad (a demo-only step, NOT part of the OT) so the sender can
 * check the pads over a real network. The post-quantum endemic-LWE variant lives in the separate lwe-ot adapter (found by reflection, see PartyMain).
 */
public final class OtNet {
    private OtNet() {}

    public record Result(String kind, String role, int count, boolean matched, String padDigest) {
        public Result(String role, int count, boolean matched, String padDigest) { this("ec", role, count, matched, padDigest); }
    }

    public static byte[] sha(byte[]... parts) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) h.update(p);
            return h.digest();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Binding of a base OT on this mesh: session (hashed to a fixed length), who sends, who receives, which round. */
    public static BaseOtBinding netBinding(Mesh mesh, int senderIndex, int receiverIndex, String round) {
        byte[] sid = sha("atlas-pca-mpc/net-session/v2".getBytes(StandardCharsets.UTF_8), Json.utf8(mesh.sessionId()));
        return new BaseOtBinding(sid, senderIndex, receiverIndex, round);
    }

    public static <T> T parsing(Mesh mesh, int peer, String rd, java.util.function.Supplier<T> f) {
        try {
            return f.get();
        } catch (RuntimeException e) {
            NetAbort ne = new NetAbort("malformed", peer, mesh.selfId, "round '" + rd + "': " + e.getMessage());
            mesh.fail(ne, null);
            throw ne;
        }
    }

    public static int bit(Object o) {
        if (o instanceof Json.Num && o.toString().equals("0")) return 0;
        if (o instanceof Json.Num && o.toString().equals("1")) return 1;
        return -1;
    }

    public static String digest(byte[][] pads) {
        byte[] all = new byte[0];
        for (byte[] p : pads) {
            byte[] n = new byte[all.length + p.length];
            System.arraycopy(all, 0, n, 0, all.length);
            System.arraycopy(p, 0, n, all.length, p.length);
            all = n;
        }
        return HexFormat.of().formatHex(sha(all));
    }

    public static Result runOtSender(Mesh mesh, int peer, int count) {
        OtRandom rng = Ot.secureOtRandom();
        BaseOtBinding binding = netBinding(mesh, mesh.selfId, peer, "ot-ec");
        Ot.SenderSetup setup = Ot.malBaseOtSenderSetup(rng, binding);
        Map<String, Object> sm = new LinkedHashMap<>();
        sm.put("S", NetCodec.ptJ(setup.S()));
        sm.put("U", NetCodec.ptJ(setup.proof().U()));
        sm.put("z", NetWire.hx(setup.proof().z()));
        mesh.send(peer, "ot-S", sm);
        Object rRaw = mesh.recv(peer, "ot-R");
        Point[] R = parsing(mesh, peer, "ot-R", () -> {
            if (!(rRaw instanceof List) || ((List<?>) rRaw).size() != count) throw new IllegalArgumentException("bad R array");
            Point[] pts = new Point[count];
            for (int i = 0; i < count; i++) pts[i] = NetCodec.jPt(((List<?>) rRaw).get(i));
            return pts;
        });
        byte[][][] pads;
        try {
            pads = Ot.malBaseOtSenderDerive(setup.y(), setup.T(), R, setup.S(), binding);
        } catch (RuntimeException e) {
            NetAbort ne = new NetAbort("malformed", peer, mesh.selfId, String.valueOf(e.getMessage()));
            mesh.fail(ne, null);
            throw ne;
        }
        final byte[][][] padsF = pads;
        // demo-only verification: the receiver reveals choices + pad hashes
        Object v = mesh.recv(peer, "ot-verify");
        boolean ok = parsing(mesh, peer, "ot-verify", () -> {
            Map<?, ?> o = v instanceof Map ? (Map<?, ?>) v : null;
            if (o == null || !(o.get("choices") instanceof List) || !(o.get("padHashes") instanceof List)
                || ((List<?>) o.get("choices")).size() != count || ((List<?>) o.get("padHashes")).size() != count) throw new IllegalArgumentException("bad verify message");
            for (int i = 0; i < count; i++) {
                int c = bit(((List<?>) o.get("choices")).get(i));
                if (c < 0 || !HexFormat.of().formatHex(sha(padsF[i][c])).equals(((List<?>) o.get("padHashes")).get(i))) return false;
            }
            return true;
        });
        Map<String, Object> done = new LinkedHashMap<>();
        done.put("matched", ok);
        mesh.send(peer, "ot-done", done);
        mesh.finish();
        byte[][] flat = new byte[count * 2][];
        for (int i = 0; i < count; i++) {
            flat[2 * i] = pads[i][0];
            flat[2 * i + 1] = pads[i][1];
        }
        return new Result("sender", count, ok, digest(flat));
    }

    public static Result runOtReceiver(Mesh mesh, int peer, int count) {
        OtRandom rng = Ot.secureOtRandom();
        byte[] cb = rng.bytes(count);
        int[] choices = new int[count];
        for (int i = 0; i < count; i++) choices[i] = cb[i] & 1;
        Object sRaw = mesh.recv(peer, "ot-S");
        Point[] S = new Point[1];
        SchnorrProof proof = parsing(mesh, peer, "ot-S", () -> {
            if (!(sRaw instanceof Map)) throw new IllegalArgumentException("bad S message");
            Map<?, ?> o = (Map<?, ?>) sRaw;
            SchnorrProof pr = new SchnorrProof(NetCodec.jPt(o.get("U")), NetCodec.hexBig(o.get("z")));
            S[0] = NetCodec.jPt(o.get("S"));
            return pr;
        });
        Ot.ReceiverResponse res;
        try {
            res = Ot.malBaseOtReceiverRespond(S[0], proof, choices, rng, netBinding(mesh, peer, mesh.selfId, "ot-ec"));
        } catch (RuntimeException e) {
            NetAbort ne = new NetAbort(e instanceof BaseOtAbort ? "commitment" : "malformed", peer, mesh.selfId, String.valueOf(e.getMessage()));
            mesh.fail(ne, null);
            throw ne;
        }
        List<Object> rs = new ArrayList<>();
        for (Point r : res.R()) rs.add(NetCodec.ptJ(r));
        mesh.send(peer, "ot-R", rs);
        Map<String, Object> vm = new LinkedHashMap<>();
        List<Object> cs = new ArrayList<>(), hs = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            cs.add(choices[i]);
            hs.add(HexFormat.of().formatHex(sha(res.recvPads()[i])));
        }
        vm.put("choices", cs);
        vm.put("padHashes", hs);
        mesh.send(peer, "ot-verify", vm);
        Object d = mesh.recv(peer, "ot-done");
        boolean matched = d instanceof Map && Boolean.TRUE.equals(((Map<?, ?>) d).get("matched"));
        mesh.finish();
        return new Result("receiver", count, matched, digest(res.recvPads()));
    }
}
