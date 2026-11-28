package net.atlasauth.pca;

import static net.atlasauth.pca.MpcSupport.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import net.atlasauth.pca.mpc.Ec;
import net.atlasauth.pca.mpc.NetCodec;
import net.atlasauth.pca.mpc.NetForensics;
import net.atlasauth.pca.mpc.NetForensics.SlotDisclosure;
import net.atlasauth.pca.mpc.NetPa;
import net.atlasauth.pca.mpc.NetPa.AW;
import net.atlasauth.pca.mpc.NetPa.PA;
import net.atlasauth.pca.mpc.NetPa.PaEnv;
import net.atlasauth.pca.mpc.NetWire;
import org.junit.jupiter.api.Test;

/** Differential tests of the pure parts of the MPC networked runner (wire codec, pairwise-authenticated shares, forensics, codecs). */
class MpcNetDiffTest {
    private static final String MOD = "ref-mpc-net";

    private static byte[] by(Object o) { return Keys.unb64u((String) map(o).get("$bytes")); }

    private static List<Object> bl(List<byte[]> l) { return new ArrayList<>(l); }

    private static Integer nullableInt(Object o) { return o == null ? null : Integer.valueOf(I(o)); }

    // ---- wire ----
    @Test void frames() throws Exception {
        OracleCases.each(MOD, "encodeFrame", a -> {
            Map<String, Object> f = map(a.get(0));
            return NetWire.encodeFrame(new NetWire.Frame(f.get("v"), (String) f.get("ty"), (String) f.get("sid"), f.get("seq"), (String) f.get("rd"), f.get("d")));
        });
        OracleCases.each(MOD, "split", a -> {
            NetWire.FrameSplitter s = new NetWire.FrameSplitter();
            List<Object> out = new ArrayList<>();
            for (Object c : (List<?>) a.get(0)) out.addAll(bl(s.push(by(c))));
            return M("frames", out);
        });
        OracleCases.each(MOD, "peekVersion", a -> NetWire.peekVersion(by(a.get(0))));
        OracleCases.each(MOD, "parseFrame", a -> NetWire.parseFrame(by(a.get(0))));
        OracleCases.each(MOD, "versionMismatch", a -> NetWire.versionMismatch(by(a.get(0))));
        OracleCases.each(MOD, "hx", a -> NetWire.hx(B(a.get(0))));
        OracleCases.each(MOD, "unhx", a -> { BigInteger v = NetWire.unhx(a.get(0)); return v == null ? null : v.toString(); });
        OracleCases.each(MOD, "unhxArray", a -> { BigInteger[] v = NetWire.unhxArray(a.get(0), I(a.get(1))); return v == null ? null : L(v); });
        OracleCases.each(MOD, "netAbort", a -> {
            Object cb = a.get(5);
            Map<String, Object> op = a.get(6) == null ? null : map(a.get(6));
            NetWire.NetAbort e = new NetWire.NetAbort((String) a.get(0), nullableInt(a.get(1)), I(a.get(2)), (String) a.get(3), (String) a.get(4),
                cb instanceof Json.Num ? Integer.valueOf(I(cb)) : null, op == null ? null : (String) op.get("reason"), op == null ? null : op.get("evidence"),
                op == null || op.get("deadlineMs") == null ? null : Integer.valueOf(I(op.get("deadlineMs"))));
            return M("message", e.getMessage(), "name", "NetAbort", "kind", e.kind, "blamed", e.blamed, "reporter", e.reporter, "reason", e.reason,
                "claimedKind", e.claimedKind, "claimedBlame", e.claimedBlame, "evidence", e.evidence, "deadlineMs", e.deadlineMs);
        });
        OracleCases.each(MOD, "abortKinds", a -> new ArrayList<Object>(new TreeSet<>(NetWire.ABORT_KINDS)));
    }

    // ---- pairwise-authenticated shares ----
    private static PA pa(Object o) { Map<String, Object> m = map(o); return new PA(B(m.get("x")), BA(m.get("tag")), BA(m.get("key"))); }

    private static AW aw(Object o) {
        Map<String, Object> m = map(o);
        List<?> ms = (List<?>) m.get("m");
        PA[] arr = new PA[ms.size()];
        for (int i = 0; i < arr.length; i++) arr[i] = pa(ms.get(i));
        return new AW(pa(m.get("v")), arr);
    }

    private static Map<String, Object> paJ(PA p) { return M("x", p.x().toString(), "tag", L(p.tag()), "key", L(p.key())); }

    private static Map<String, Object> awJ(AW a) {
        List<Object> ms = new ArrayList<>();
        for (PA p : a.m()) ms.add(paJ(p));
        return M("v", paJ(a.v()), "m", ms);
    }

    private static List<Object> nums(List<BigInteger> l) { List<Object> o = new ArrayList<>(); for (BigInteger x : l) o.add(x.toString()); return o; }

    private static List<BigInteger> numsIn(List<BigInteger> l) { return l; }

    @Test void pairwiseShares() throws Exception {
        OracleCases.each(MOD, "pa", a -> {
            String op = (String) a.get(0);
            PA p = pa(a.get(1));
            int n = p.tag().length;
            switch (op) {
                case "add": return paJ(NetPa.paAdd(p, pa(a.get(2))));
                case "sub": return paJ(NetPa.paSub(p, pa(a.get(2))));
                case "neg": return paJ(NetPa.paNeg(p));
                case "scale": return paJ(NetPa.paScale(p, B(a.get(2))));
                case "addPublic0": return paJ(NetPa.paAddPublic0(new PaEnv(I(a.get(2)), n, B(a.get(3)), Boolean.TRUE.equals(a.get(4))), p, B(a.get(5))));
                case "verify": return NetPa.paVerify(new PaEnv(I(a.get(2)), n, B(a.get(3)), true), p, I(a.get(4)), B(a.get(5)), B(a.get(6)));
                case "flat": {
                    int id = I(a.get(2));
                    boolean tg = Boolean.TRUE.equals(a.get(3));
                    List<BigInteger> f = NetPa.paFlat(p, id, n, tg);
                    return M("f", nums(f), "w", NetPa.paWidth(n, tg), "back", paJ(NetPa.paParse(numsIn(f), 0, id, n, tg)));
                }
                default: throw new IllegalArgumentException(op);
            }
        });
        OracleCases.each(MOD, "aw", a -> {
            if (a.size() == 1) return NetCodec.sharingsPerTriple(I(a.get(0)));
            if (a.size() == 3) {
                AW x = aw(a.get(0));
                int n = x.v().tag().length, keys = x.m().length, id = I(a.get(1));
                boolean tg = Boolean.TRUE.equals(a.get(2));
                List<BigInteger> f = NetPa.awFlat(x, id, n, tg);
                return M("f", nums(f), "w", NetPa.awWidth(n, keys, tg), "back", awJ(NetPa.awParse(f, 0, id, n, keys, tg)));
            }
            AW x = aw(a.get(0)), y = aw(a.get(1));
            int n = x.v().tag().length;
            List<?> al = (List<?>) a.get(2);
            PA[] alpha = new PA[al.size()];
            for (int i = 0; i < alpha.length; i++) alpha[i] = pa(al.get(i));
            boolean tg = Boolean.TRUE.equals(a.get(3));
            BigInteger c = B(a.get(4));
            return M("add", awJ(NetPa.wAdd(x, y)), "sub", awJ(NetPa.wSub(x, y)), "neg", awJ(NetPa.wNeg(x)), "scale", awJ(NetPa.wScale(x, c)),
                "addPublic", awJ(NetPa.wAddPublic(new PaEnv(1, n, BigInteger.valueOf(7), tg), x, c, alpha)),
                "addPublic0", awJ(NetPa.wAddPublic(new PaEnv(0, n, BigInteger.valueOf(7), tg), x, c, alpha)));
        });
    }

    // ---- forensics ----
    private static List<Object> sideJ(Map<Integer, BigInteger[]> m) {
        List<Object> out = new ArrayList<>();
        for (Map.Entry<Integer, BigInteger[]> e : m.entrySet()) { List<Object> pr = new ArrayList<>(); pr.add(e.getKey()); pr.add(L(e.getValue())); out.add(pr); }
        return out;
    }

    private static List<SlotDisclosure> dis(Object o) {
        List<SlotDisclosure> out = new ArrayList<>();
        for (Object so : (List<?>) o) {
            Map<String, Object> s = map(so);
            out.add(new SlotDisclosure(IA(s.get("bits")), B(s.get("y")), B(s.get("z")), sideIn(s.get("recv")), sideIn(s.get("rho"))));
        }
        return out;
    }

    private static Map<Integer, BigInteger[]> sideIn(Object o) {
        Map<Integer, BigInteger[]> m = new LinkedHashMap<>();
        for (Object e : (List<?>) o) m.put(I(((List<?>) e).get(0)), BA(((List<?>) e).get(1)));
        return m;
    }

    @Test void forensics() throws Exception {
        OracleCases.each(MOD, "forensics", a -> {
            switch (a.size()) {
                case 1: return NetForensics.slotsFor(I(a.get(0)));
                case 3: {
                    if (a.get(0) instanceof Map) {
                        Map<Integer, List<SlotDisclosure>> all = new LinkedHashMap<>();
                        for (Map.Entry<String, Object> e : map(a.get(0)).entrySet()) all.put(Integer.valueOf(e.getKey()), dis(e.getValue()));
                        if (a.get(2) != null) all.remove(I(a.get(2)));
                        NetForensics.AuditResult res = NetForensics.auditDisclosures(all, BA(a.get(1)));
                        List<Object> pb = new ArrayList<>();
                        for (int[] p : res.pairBad()) pb.add(List.of(p[0], p[1]));
                        List<Object> blame = new ArrayList<>();
                        for (int me = 0; me < 3; me++) blame.add(NetForensics.blameFrom(me, res));
                        return M("selfBad", new ArrayList<Object>(new TreeSet<>(res.selfBad())), "pairBad", pb, "blame", blame);
                    }
                    java.util.Set<Integer> sb = new java.util.HashSet<>();
                    for (Object x : (List<?>) a.get(1)) sb.add(I(x));
                    List<int[]> pb = new ArrayList<>();
                    for (Object x : (List<?>) a.get(2)) pb.add(new int[] {I(((List<?>) x).get(0)), I(((List<?>) x).get(1))});
                    return NetForensics.blameFrom(I(a.get(0)), new NetForensics.AuditResult(sb, pb));
                }
                case 4: {
                    List<Integer> peers = new ArrayList<>();
                    for (Object x : (List<?>) a.get(3)) peers.add(I(x));
                    List<SlotDisclosure> dd = NetForensics.parseDisclosure(a.get(0), I(a.get(1)), I(a.get(2)), peers);
                    List<Object> ddj = new ArrayList<>();
                    for (SlotDisclosure s : dd) ddj.add(M("bits", L(s.bits()), "y", s.y().toString(), "z", s.z().toString(), "recv", sideJ(s.recv()), "rho", sideJ(s.rho())));
                    return M("dd", ddj, "back", NetForensics.wireDisclosure(dd));
                }
                case 6: return NetForensics.disclosureCommit((String) a.get(0), I(a.get(1)), I(a.get(2)), (long) D(a.get(3)), (String) a.get(4), a.get(5));
                default: throw new IllegalArgumentException("forensics arity");
            }
        });
    }

    // ---- codecs ----
    @Test void codecs() throws Exception {
        OracleCases.each(MOD, "codec", a -> {
            String op = (String) a.get(0);
            switch (op) {
                case "unb64": return NetCodec.unb64(a.get(1), a.get(2) == null ? -1 : I(a.get(2)));
                case "b64": return NetCodec.b64(by(a.get(1)));
                case "hexBig": return NetCodec.hexBig(a.get(1)).toString();
                case "jPt": return NetCodec.ptJ(NetCodec.jPt(a.get(1)));
                case "ptJ": return NetCodec.ptJ(Ec.mulBase(B(a.get(1))));
                case "gadgetCommit": return NetCodec.gadgetCommit((String) a.get(1), I(a.get(2)), by(a.get(3)));
                case "gadgetStatement": return NetCodec.gadgetStatement((String) a.get(1), (String) a.get(2), I(a.get(3)), (String) a.get(4));
                default: throw new IllegalArgumentException(op);
            }
        });
    }
}
