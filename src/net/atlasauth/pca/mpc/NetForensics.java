package net.atlasauth.pca.mpc;

import static net.atlasauth.pca.mpc.Field.fadd;
import static net.atlasauth.pca.mpc.Field.fmul;
import static net.atlasauth.pca.mpc.Field.fsub;
import static net.atlasauth.pca.mpc.Field.mod;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;

/**
 * Forensic disclosures of a failed offline triple: each party discloses its OT choice bits, operands, claimed product share and
 * the per-peer OT messages; the cross-check names the party whose own data are inconsistent or whose counterpart's transcript
 * disagrees. This class holds the pure parts (strict parsing, audit, blame, the commit-first binding); the timed exchange over
 * the mesh is part of the networked driver.
 */
public final class NetForensics {
    private NetForensics() {}

    /** One product item's disclosure; recv and rho are keyed by peer index (insertion ordered). */
    public record SlotDisclosure(int[] bits, BigInteger y, BigInteger z, Map<Integer, BigInteger[]> recv, Map<Integer, BigInteger[]> rho) {}

    public static int slotsFor(int partners) { return 1 + partners; }

    /** The wire (JSON) form of a disclosure. */
    public static List<Object> wireDisclosure(List<SlotDisclosure> d) {
        List<Object> out = new ArrayList<>();
        for (SlotDisclosure s : d) {
            Map<String, Object> m = new LinkedHashMap<>();
            StringBuilder bits = new StringBuilder();
            for (int b : s.bits()) bits.append(b);
            m.put("bits", bits.toString());
            m.put("y", NetWire.hx(s.y()));
            m.put("z", NetWire.hx(s.z()));
            m.put("recv", side(s.recv()));
            m.put("rho", side(s.rho()));
            out.add(m);
        }
        return out;
    }

    private static List<Object> side(Map<Integer, BigInteger[]> x) {
        List<Object> out = new ArrayList<>();
        for (Map.Entry<Integer, BigInteger[]> e : x.entrySet()) {
            List<Object> vals = new ArrayList<>();
            for (BigInteger v : e.getValue()) vals.add(NetWire.hx(v));
            List<Object> pair = new ArrayList<>();
            pair.add(e.getKey());
            pair.add(vals);
            out.add(pair);
        }
        return out;
    }

    private static BigInteger field(Object s) {
        BigInteger v = NetWire.unhx(s);
        if (v == null) throw new IllegalArgumentException("bad field element");
        return v;
    }

    /** Strict parse of a peer's disclosure; throws on any deviation from the expected shape. */
    public static List<SlotDisclosure> parseDisclosure(Object raw, int slots, int rows, List<Integer> peers) {
        if (!(raw instanceof List) || ((List<?>) raw).size() != slots) throw new IllegalArgumentException("bad forensic disclosure");
        List<SlotDisclosure> out = new ArrayList<>();
        Pattern bitsRe = Pattern.compile("^[01]{" + rows + "}$");
        for (Object o : (List<?>) raw) {
            if (!(o instanceof Map)) throw new IllegalArgumentException("bad choice bits");
            Map<?, ?> r = (Map<?, ?>) o;
            if (!(r.get("bits") instanceof String) || !bitsRe.matcher((String) r.get("bits")).matches()) throw new IllegalArgumentException("bad choice bits");
            String bs = (String) r.get("bits");
            int[] bits = new int[bs.length()];
            for (int i = 0; i < bits.length; i++) bits[i] = bs.charAt(i) == '1' ? 1 : 0;
            BigInteger y = field(r.get("y"));
            BigInteger z = field(r.get("z"));
            out.add(new SlotDisclosure(bits, y, z, sideParse(r.get("recv"), rows, peers), sideParse(r.get("rho"), rows, peers)));
        }
        return out;
    }

    private static Map<Integer, BigInteger[]> sideParse(Object x, int rows, List<Integer> peers) {
        if (!(x instanceof List) || ((List<?>) x).size() != peers.size()) throw new IllegalArgumentException("bad peer table");
        Map<Integer, BigInteger[]> m = new LinkedHashMap<>();
        for (Object e : (List<?>) x) {
            if (!(e instanceof List) || ((List<?>) e).size() != 2 || !(((List<?>) e).get(0) instanceof Json.Num)) throw new IllegalArgumentException("bad peer entry");
            double pd = Double.parseDouble(((List<?>) e).get(0).toString());
            Integer p = pd == Math.rint(pd) && Math.abs(pd) < 1e9 ? Integer.valueOf((int) pd) : null;
            if (p == null || !peers.contains(p) || m.containsKey(p)) throw new IllegalArgumentException("bad peer entry");
            Object vals = ((List<?>) e).get(1);
            if (!(vals instanceof List) || ((List<?>) vals).size() != rows) throw new IllegalArgumentException("bad row table");
            BigInteger[] arr = new BigInteger[rows];
            for (int i = 0; i < rows; i++) arr[i] = field(((List<?>) vals).get(i));
            m.put(p, arr);
        }
        return m;
    }

    /** selfBad: parties whose own disclosure is inconsistent; pairBad: ordered [receiver, sender] pairs whose OT transcripts disagree. */
    public record AuditResult(Set<Integer> selfBad, List<int[]> pairBad) {}

    /** Cross-checks every party's disclosure of one failed triple against the public gadget. */
    public static AuditResult auditDisclosures(Map<Integer, List<SlotDisclosure>> all, BigInteger[] gadget) {
        Set<Integer> selfBad = new HashSet<>();
        List<int[]> pairBad = new ArrayList<>();
        List<Integer> parties = new ArrayList<>(new TreeSet<>(all.keySet()));
        for (int i : parties) {
            List<SlotDisclosure> di = all.get(i);
            for (int s = 0; s < di.size(); s++) {
                SlotDisclosure sd = di.get(s);
                BigInteger value = BigInteger.ZERO;
                for (int k = 0; k < gadget.length; k++) if (k < sd.bits().length && sd.bits()[k] == 1) value = value.add(gadget[k]);
                BigInteger implied = fmul(mod(value), sd.y());
                for (int p : parties) {
                    if (p == i) continue;
                    for (BigInteger v : sd.recv().get(p)) implied = fadd(implied, mod(v));
                    for (BigInteger v : sd.rho().get(p)) implied = fsub(implied, v);
                }
                if (!implied.equals(sd.z())) selfBad.add(i);
                for (int p : parties) {
                    if (p == i) continue;
                    SlotDisclosure sp = all.get(p).get(s);
                    BigInteger[] rho = sp.rho().get(i);
                    BigInteger[] got = sd.recv().get(p);
                    BigInteger y = mod(sp.y());
                    boolean bad = false;
                    for (int k = 0; k < gadget.length && !bad; k++) {
                        BigInteger want = fadd(rho[k], k < sd.bits().length && sd.bits()[k] == 1 ? fmul(gadget[k], y) : BigInteger.ZERO);
                        if (!mod(got[k]).equals(want)) bad = true;
                    }
                    if (bad) pairBad.add(new int[] {i, p});
                }
            }
        }
        return new AuditResult(selfBad, pairBad);
    }

    /** The party the verifier {@code me} blames, or null when the evidence cannot name one. */
    public static Integer blameFrom(int me, AuditResult r) {
        TreeSet<Integer> own = new TreeSet<>();
        for (int p : r.selfBad()) if (p != me) own.add(p);
        if (!own.isEmpty()) return own.first();
        for (int[] pr : r.pairBad()) {
            if (pr[0] == me) return pr[1];
            if (pr[1] == me) return pr[0];
        }
        return null;
    }

    public static final int DEFAULT_FORENSIC_DEADLINE_MS = 30_000;

    /** Binding commitment to a disclosure: session, party, triple index, deadline, a 256-bit nonce and the canonical wire form. */
    public static String disclosureCommit(String sessionId, int party, int tripleIndex, long deadlineMs, String nonce, Object wire) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            h.update("atlas-pca-mpc/forensic-commit/v1\0".getBytes(StandardCharsets.UTF_8));
            List<Object> arr = new ArrayList<>();
            arr.add(sessionId);
            arr.add(party);
            arr.add(tripleIndex);
            arr.add(deadlineMs);
            arr.add(nonce);
            arr.add(wire);
            h.update(Json.utf8(NetWire.stringify(arr)));
            return HexFormat.of().formatHex(h.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
