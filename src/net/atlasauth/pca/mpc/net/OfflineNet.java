package net.atlasauth.pca.mpc.net;

import net.atlasauth.pca.Json;

import static net.atlasauth.pca.mpc.Field.PRIME;
import static net.atlasauth.pca.mpc.Field.fadd;
import static net.atlasauth.pca.mpc.Field.fmul;
import static net.atlasauth.pca.mpc.Field.fsub;
import static net.atlasauth.pca.mpc.Field.mod;
import static net.atlasauth.pca.mpc.NetWire.hx;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import net.atlasauth.pca.mpc.Ec;
import net.atlasauth.pca.mpc.Ec.Point;
import net.atlasauth.pca.mpc.Ec.PointValidationError;
import net.atlasauth.pca.mpc.Ec.SchnorrProof;
import net.atlasauth.pca.mpc.Enc;
import net.atlasauth.pca.mpc.Enc.EncShare;
import net.atlasauth.pca.mpc.Field.FieldSource;
import net.atlasauth.pca.mpc.Field.SecureFieldRng;
import net.atlasauth.pca.mpc.NetCodec;
import net.atlasauth.pca.mpc.NetForensics.SlotDisclosure;
import net.atlasauth.pca.mpc.NetPa.AW;
import net.atlasauth.pca.mpc.NetPa.PA;
import net.atlasauth.pca.mpc.NetWire;
import net.atlasauth.pca.mpc.NetWire.NetAbort;
import net.atlasauth.pca.mpc.Ot;
import net.atlasauth.pca.mpc.Ot.BaseOtAbort;
import net.atlasauth.pca.mpc.Ot.BaseOtBinding;
import net.atlasauth.pca.mpc.Ot.ExtRoundMsg;
import net.atlasauth.pca.mpc.Ot.MalOtAbort;
import net.atlasauth.pca.mpc.Ot.OtExtReceiver;
import net.atlasauth.pca.mpc.Ot.OtExtSender;
import net.atlasauth.pca.mpc.Ot.OtRandom;
import net.atlasauth.pca.mpc.Otx;
import net.atlasauth.pca.mpc.Thermometer;

/**
 * The NO-DEALER offline phase over the mutual-TLS mesh. Each party holds only its own shares; every party samples its own MAC
 * key shares and triple shares, and the products needed for the triples and MACs are computed by Gilboa OT multiplication
 * between every ordered pair (kappa = 128 base OTs per ordered pair, OT extension with the KOS correlation check). Two
 * multiplication layers (products and the MACs of known values, then the MACs of the products) and a third layer giving every
 * share pairwise tags T_ij = K_ij + Delta_j * x_i, so the online phase can name a party that lies. Receivers choose with the
 * privacy-amplified encoding of their share (selective-failure remedy) under a gadget all parties contribute a signed seed to.
 * The triple sacrifice and the input-consistency check run online. No security proof; a wrong OT operand in the offline
 * triple products is attributable from the OT transcript only after the sacrifice fails (see {@link Prep.Forensics}).
 */
public final class OfflineNet {
    private OfflineNet() {}

    /** Most OT rows per extension round (bounds frame size and memory). */
    private static final int ROWS_PER_ROUND = 128 * Enc.FIELD_BITS;
    private static final int T_M = 3;
    private static final Pattern HEX128 = Pattern.compile("^(0|[1-9a-f][0-9a-f]{0,31})$");

    /** The OT multiplication item: my choice bits (weights {@code gad}, public) against my sender operand {@code y}. */
    private record Item(int[] bits, BigInteger[] gad, BigInteger y) {}

    private record Rows(Map<Integer, BigInteger[]> recv, Map<Integer, BigInteger[]> sendSum, Kept kept) {}

    private record Kept(Map<Integer, Map<Integer, BigInteger[]>> recv, Map<Integer, Map<Integer, BigInteger[]>> rho) {}

    private record Layer(BigInteger[] z, Kept kept) {}

    private record Cipher(BigInteger[] y0, BigInteger[] y1) {}

    private record PointMsg(Point S, SchnorrProof proof) {}

    private record BaseCt(byte[][][] ct, byte[][][] com) {}

    private static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) h.update(p);
            return h.digest();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] utf8(String s) { return Json.utf8(s); }

    private static byte[] le8(long v) { return Otx.bigToBytes(BigInteger.valueOf(v), 8); }

    private static long fromLe8(byte[] b) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (b[i] & 0xffL);
        return v;
    }

    /** The public gadget: H(all seeds in party order, session) expanded by a hash chain; every party contributed a committed seed. */
    static BigInteger[] gadgetFromSeeds(String sessionId, byte[][] seeds) {
        ByteArrayOutputStream in = new ByteArrayOutputStream();
        byte[] tag = utf8("atlas-pca-mpc/enc-gadget");
        in.write(tag, 0, tag.length);
        byte[] sb = utf8(sessionId);
        in.write(sb, 0, sb.length);
        for (byte[] sd : seeds) in.write(sd, 0, sd.length);
        byte[] seed = sha256(in.toByteArray());
        long[] ctr = {0};
        FieldSource src = () -> {
            for (;;) {
                long v = fromLe8(sha256(seed, le8(ctr[0]++))) & ((1L << 61) - 1);
                if (v != (1L << 61) - 1) return BigInteger.valueOf(v);
            }
        };
        return Enc.makeGadget(Enc.STAT_SEC, src, false);
    }

    public static Prep run(Protocol.OfflineCtx ctx) { return new Run(ctx).go(); }

    private static BigInteger hex128(Object s) {
        if (!(s instanceof String) || !HEX128.matcher((String) s).matches()) throw new IllegalArgumentException("bad 128-bit value");
        return new BigInteger((String) s, 16);
    }

    private static List<Object> pairsB64(byte[][][] ps) {
        List<Object> out = new ArrayList<>();
        for (byte[][] p : ps) out.add(new ArrayList<Object>(List.of(NetCodec.b64(p[0]), NetCodec.b64(p[1]))));
        return out;
    }

    private static byte[][][] parsePairs(Object raw, int count, int len) {
        if (!(raw instanceof List) || ((List<?>) raw).size() != count) throw new IllegalArgumentException("bad pair array");
        byte[][][] out = new byte[count][][];
        for (int i = 0; i < count; i++) {
            Object p = ((List<?>) raw).get(i);
            if (!(p instanceof List) || ((List<?>) p).size() != 2) throw new IllegalArgumentException("bad pair");
            out[i] = new byte[][] {NetCodec.unb64(((List<?>) p).get(0), len), NetCodec.unb64(((List<?>) p).get(1), len)};
        }
        return out;
    }

    private static Object encodeU(ExtRoundMsg msg, int mExt) {
        int cb = (mExt + 7) / 8;
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        for (BigInteger c : msg.u()) {
            byte[] b = Otx.bigToBytes(c, cb);
            bo.write(b, 0, b.length);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("u", NetCodec.b64(bo.toByteArray()));
        m.put("x", msg.x().toString(16));
        m.put("t", msg.tComb().toString(16));
        return m;
    }

    private static ExtRoundMsg decodeU(Object raw, int mExt) {
        if (!(raw instanceof Map)) throw new IllegalArgumentException("bad extension message");
        Map<?, ?> o = (Map<?, ?>) raw;
        int cb = (mExt + 7) / 8;
        byte[] bytes = NetCodec.unb64(o.get("u"), Ot.KAPPA * cb);
        BigInteger[] u = new BigInteger[Ot.KAPPA];
        for (int i = 0; i < Ot.KAPPA; i++) u[i] = Otx.bytesToBig(Arrays.copyOfRange(bytes, i * cb, (i + 1) * cb));
        return new ExtRoundMsg(u, hex128(o.get("x")), hex128(o.get("t")));
    }

    private static byte[] packLe8(BigInteger[] vs) {
        byte[] out = new byte[vs.length * 8];
        for (int i = 0; i < vs.length; i++) System.arraycopy(Otx.bigToBytes(vs[i], 8), 0, out, i * 8, 8);
        return out;
    }

    private static BigInteger[] unpackLe8(byte[] b, int m) {
        BigInteger[] out = new BigInteger[m];
        for (int i = 0; i < m; i++) out[i] = Otx.bytesToBig(Arrays.copyOfRange(b, i * 8, i * 8 + 8));
        return out;
    }

    private static Object encodeY(Cipher c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("y0", NetCodec.b64(packLe8(c.y0())));
        m.put("y1", NetCodec.b64(packLe8(c.y1())));
        return m;
    }

    private static Cipher decodeY(Object raw, int m) {
        if (!(raw instanceof Map)) throw new IllegalArgumentException("bad ciphertext message");
        Map<?, ?> o = (Map<?, ?>) raw;
        return new Cipher(unpackLe8(NetCodec.unb64(o.get("y0"), m * 8), m), unpackLe8(NetCodec.unb64(o.get("y1"), m * 8), m));
    }

    private static final class Run {
        final Protocol.OfflineCtx a;
        final Mesh mesh;
        final int id, n, C, K, P;
        final Exchanger io;
        final List<Integer> others = new ArrayList<>();
        final OtRandom rng = Ot.secureOtRandom();
        final SecureFieldRng frng = new SecureFieldRng();
        final byte[] sid;
        final String behKind;
        BigInteger delta;
        BigInteger[] gadget;
        final Map<Integer, OtExtReceiver> recvCh = new TreeMap<>();
        final Map<Integer, OtExtSender> sendCh = new TreeMap<>();

        Run(Protocol.OfflineCtx a) {
            this.a = a;
            this.mesh = a.mesh();
            this.id = a.id();
            this.n = a.n();
            this.C = a.C();
            this.K = a.keys();
            this.P = a.partners();
            this.io = a.io();
            this.behKind = a.behavior() == null ? "" : a.behavior().kind();
            this.sid = sha256(utf8("atlas-pca-mpc/net-session/v2"), utf8(mesh.sessionId()));
            for (int i = 0; i < n; i++) if (i != id) others.add(i);
        }

        /** Binding of the channel whose EXTENSION RECEIVER (= base-OT sender) is {@code recv} and extension sender is {@code send}. */
        BaseOtBinding chan(int recv, int send, String round) { return new BaseOtBinding(sid, recv, send, round); }

        <T> T otGuard(int peer, String what, Supplier<T> f) {
            try {
                return f.get();
            } catch (NetAbort e) {
                throw e;
            } catch (RuntimeException e) {
                String kind = e instanceof BaseOtAbort || e instanceof MalOtAbort || e instanceof PointValidationError ? "ot-check" : "malformed";
                NetAbort ne = new NetAbort(kind, peer, id, what + ": " + e.getMessage());
                mesh.fail(ne, null);
                throw ne;
            }
        }

        BigInteger[] arr(int p, Object raw, int len) {
            BigInteger[] r = NetWire.unhxArray(raw, len);
            if (r == null) throw io.bad(p, "expected " + len + " canonical field elements");
            return r;
        }

        Prep go() {
            delta = frng.next();
            while (delta.signum() == 0) delta = frng.next();

            // ---------------------------------------------------------------- base OTs (kappa per ordered pair, both roles)
            Map<Integer, byte[][][]> seeds = new TreeMap<>();
            Map<Integer, Ot.SenderSetup> mySetup = new TreeMap<>();
            Map<Integer, int[]> selector = new TreeMap<>();
            for (int p : others) {
                OtExtReceiver r = new OtExtReceiver(rng, Ot.bindingBytes(chan(id, p, "iknp-kos")));
                seeds.put(p, r.makeSeeds());
                recvCh.put(p, r);
                mySetup.put(p, Ot.malBaseOtSenderSetup(rng, chan(id, p, "offline-kappa")));
                OtExtSender s = new OtExtSender(rng, Ot.bindingBytes(chan(p, id, "iknp-kos")));
                selector.put(p, s.makeSelector());
                sendCh.put(p, s);
            }
            Map<Integer, PointMsg> theirS = io.exchange("ob-S", peer -> {
                Ot.SenderSetup st = mySetup.get(peer);
                BigInteger z = "ot-proof-lie".equals(behKind) ? st.proof().z().add(BigInteger.ONE) : st.proof().z();
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("S", NetCodec.ptJ(st.S()));
                m.put("U", NetCodec.ptJ(st.proof().U()));
                m.put("z", hx(z));
                return m;
            }, (p, raw) -> {
                if (!(raw instanceof Map)) throw io.bad(p, "bad S message");
                Map<?, ?> o = (Map<?, ?>) raw;
                SchnorrProof proof = new SchnorrProof(NetCodec.jPt(o.get("U")), NetCodec.hexBig(o.get("z")));
                return new PointMsg(NetCodec.jPt(o.get("S")), proof);
            });
            Map<Integer, Ot.ReceiverResponse> respond = new TreeMap<>();
            for (int p : others) {
                PointMsg st = theirS.get(p);
                respond.put(p, otGuard(p, "base OT (receiver)", () -> Ot.malBaseOtReceiverRespond(st.S(), st.proof(), selector.get(p), rng, chan(p, id, "offline-kappa"))));
            }
            Map<Integer, Point[]> theirR = io.exchange("ob-R", peer -> {
                List<Object> out = new ArrayList<>();
                for (Point pt : respond.get(peer).R()) out.add(NetCodec.ptJ(pt));
                return out;
            }, (p, raw) -> {
                if (!(raw instanceof List) || ((List<?>) raw).size() != Ot.KAPPA) throw io.bad(p, "bad R array");
                Point[] pts = new Point[Ot.KAPPA];
                for (int i = 0; i < pts.length; i++) pts[i] = NetCodec.jPt(((List<?>) raw).get(i));
                return pts;
            });
            Map<Integer, byte[][][][]> enc = new TreeMap<>();
            for (int p : others) {
                Ot.SenderSetup st = mySetup.get(p);
                enc.put(p, otGuard(p, "base OT (sender)", () -> {
                    byte[][][] pads = Ot.malBaseOtSenderDerive(st.y(), st.T(), theirR.get(p), st.S(), chan(id, p, "offline-kappa"));
                    return Ot.baseOtSenderEncrypt(seeds.get(p), pads);
                }));
            }
            Map<Integer, BaseCt> theirCt = io.exchange("ob-C", peer -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("ct", pairsB64(enc.get(peer)[0]));
                m.put("com", pairsB64(enc.get(peer)[1]));
                return m;
            }, (p, raw) -> {
                if (!(raw instanceof Map)) throw io.bad(p, "bad ciphertext message");
                Map<?, ?> o = (Map<?, ?>) raw;
                return new BaseCt(parsePairs(o.get("ct"), Ot.KAPPA, 16), parsePairs(o.get("com"), Ot.KAPPA, 32));
            });
            for (int p : others) {
                BaseCt m = theirCt.get(p);
                byte[][] got = otGuard(p, "base OT (receiver)", () -> Ot.baseOtReceiverDecrypt(selector.get(p), respond.get(p).recvPads(), m.ct(), m.com()));
                sendCh.get(p).setSeeds(got);
            }

            // ---------------------------------------------------------------- the jointly contributed choice-bit gadget (signed commit / reveal / echo)
            byte[][] seedsAgreed = Gadget.agreeGadgetSeeds(mesh, n, io);
            gadget = gadgetFromSeeds(mesh.sessionId(), seedsAgreed);

            // ---------------------------------------------------------------- my randomness and the input sharings
            EncShare[] alphaEnc = new EncShare[K];
            BigInteger[] alphaShare = new BigInteger[K];
            for (int l = 0; l < K; l++) {
                alphaEnc[l] = Enc.sampleEnc(gadget, frng);
                alphaShare[l] = alphaEnc[l].value();
            }
            int[] tb = Thermometer.thermometerEncode(a.input().t(), T_M);
            int[] rb = Thermometer.thermometerEncode(a.input().rQuant(), a.Q());
            int[] myBits = new int[1 + tb.length + rb.length];
            myBits[0] = a.input().allow();
            System.arraycopy(tb, 0, myBits, 1, tb.length);
            System.arraycopy(rb, 0, myBits, 1 + tb.length, rb.length);
            if (myBits.length != C) throw new NetAbort("local", null, id, "input chain count mismatch");
            Map<Integer, BigInteger[]> outShares = new TreeMap<>();
            for (int p : others) {
                BigInteger[] sh = new BigInteger[C];
                for (int c = 0; c < C; c++) sh[c] = frng.next();
                outShares.put(p, sh);
            }
            BigInteger[] myOwn = new BigInteger[C];
            for (int c = 0; c < C; c++) {
                BigInteger s = BigInteger.valueOf(myBits[c]);
                for (int p : others) s = fsub(s, outShares.get(p)[c]);
                myOwn[c] = s;
            }
            Map<Integer, BigInteger[]> gotShares = io.exchange("in-share", peer -> {
                List<Object> out = new ArrayList<>();
                for (BigInteger v : outShares.get(peer)) out.add(hx(v));
                return out;
            }, (p, raw) -> arr(p, raw, C));
            BigInteger[] inputValue = new BigInteger[n * C]; // my value share of every (owner, chain)
            for (int o = 0; o < n; o++) for (int c = 0; c < C; c++) inputValue[o * C + c] = o == id ? myOwn[c] : gotShares.get(o)[c];
            BigInteger maskShare = frng.next(); // my share of the input-check mask

            int nT = (n - 1) * C;
            EncShare[] aE = new EncShare[nT];
            BigInteger[] bS = new BigInteger[nT];
            EncShare[][] ahE = new EncShare[nT][P];
            for (int t = 0; t < nT; t++) {
                aE[t] = Enc.sampleEnc(gadget, frng);
                bS[t] = frng.next();
                for (int r = 0; r < P; r++) ahE[t][r] = Enc.sampleEnc(gadget, frng);
            }
            BigInteger[] aS = new BigInteger[nT];
            BigInteger[][] ahS = new BigInteger[nT][P];
            for (int t = 0; t < nT; t++) {
                aS[t] = aE[t].value();
                for (int r = 0; r < P; r++) ahS[t][r] = ahE[t][r].value();
            }

            // ---------------------------------------------------------------- layer 1: products and the MACs of known values
            List<EncShare> xs1 = new ArrayList<>();
            List<BigInteger> ys1 = new ArrayList<>();
            int[] iC = new int[nT];
            int[][] iCh = new int[nT][P];
            int[][] iMa = new int[nT][K], iMb = new int[nT][K];
            int[][][] iMah = new int[nT][P][K];
            for (int t = 0; t < nT; t++) {
                iC[t] = push(xs1, ys1, aE[t], bS[t]);
                for (int r = 0; r < P; r++) iCh[t][r] = push(xs1, ys1, ahE[t][r], bS[t]);
                for (int l = 0; l < K; l++) iMa[t][l] = push(xs1, ys1, alphaEnc[l], aS[t]);
                for (int l = 0; l < K; l++) iMb[t][l] = push(xs1, ys1, alphaEnc[l], bS[t]);
                for (int r = 0; r < P; r++) for (int l = 0; l < K; l++) iMah[t][r][l] = push(xs1, ys1, alphaEnc[l], ahS[t][r]);
            }
            int[][] iIn = new int[n * C][K];
            for (int q = 0; q < n * C; q++) for (int l = 0; l < K; l++) iIn[q][l] = push(xs1, ys1, alphaEnc[l], inputValue[q]);
            int[] iMask = new int[K];
            for (int l = 0; l < K; l++) iMask[l] = push(xs1, ys1, alphaEnc[l], maskShare);
            Set<Integer> keepItems = new HashSet<>();
            for (int t = 0; t < nT; t++) {
                keepItems.add(iC[t]);
                for (int r = 0; r < P; r++) keepItems.add(iCh[t][r]);
            }
            Layer l1 = mulLayer("1", xs1.toArray(new EncShare[0]), ys1.toArray(new BigInteger[0]), "offline-lie".equals(behKind) && nT > 0 ? iC[0] : -1, keepItems);
            BigInteger[] z1 = l1.z();

            // ---------------------------------------------------------------- layer 2: the MACs of the products
            BigInteger[] cS = new BigInteger[nT];
            BigInteger[][] chS = new BigInteger[nT][P];
            for (int t = 0; t < nT; t++) {
                cS[t] = z1[iC[t]];
                for (int r = 0; r < P; r++) chS[t][r] = z1[iCh[t][r]];
            }
            List<EncShare> xs2 = new ArrayList<>();
            List<BigInteger> ys2 = new ArrayList<>();
            int[][] iMc = new int[nT][K];
            int[][][] iMch = new int[nT][P][K];
            for (int t = 0; t < nT; t++) {
                for (int l = 0; l < K; l++) iMc[t][l] = push(xs2, ys2, alphaEnc[l], cS[t]);
                for (int r = 0; r < P; r++) for (int l = 0; l < K; l++) iMch[t][r][l] = push(xs2, ys2, alphaEnc[l], chS[t][r]);
            }
            BigInteger[] z2 = mulLayer("2", xs2.toArray(new EncShare[0]), ys2.toArray(new BigInteger[0]), -1, null).z();

            // ---------------------------------------------------------------- assemble, then pairwise-tag every share
            AW[][] triples = new AW[nT][];
            for (int t = 0; t < nT; t++) {
                AW[] sh = new AW[3 + 2 * P];
                sh[0] = aw(aS[t], iMa[t], z1);
                sh[1] = aw(bS[t], iMb[t], z1);
                sh[2] = aw(cS[t], iMc[t], z2);
                for (int r = 0; r < P; r++) {
                    sh[3 + 2 * r] = aw(ahS[t][r], iMah[t][r], z1);
                    sh[4 + 2 * r] = aw(chS[t][r], iMch[t][r], z2);
                }
                triples[t] = sh;
            }
            AW[] inputs = new AW[n * C];
            for (int q = 0; q < n * C; q++) inputs[q] = aw(inputValue[q], iIn[q], z1);
            AW checkMask = aw(maskShare, iMask, z1);
            PA[] alpha = new PA[K];
            for (int l = 0; l < K; l++) alpha[l] = pa(alphaShare[l]);
            List<PA> allPA = new ArrayList<>(Arrays.asList(alpha));
            for (AW[] row : triples) for (AW w : row) addAll(allPA, w);
            for (AW w : inputs) addAll(allPA, w);
            addAll(allPA, checkMask);
            BigInteger[] plain = new BigInteger[allPA.size()];
            for (int u = 0; u < plain.length; u++) plain[u] = allPA.get(u).x();
            Map<Integer, BigInteger[]>[] tk = tagLayer("3", plain);
            for (int u = 0; u < plain.length; u++) {
                for (int p : others) {
                    allPA.get(u).tag()[p] = tk[0].get(p)[u];
                    allPA.get(u).key()[p] = tk[1].get(p)[u];
                }
            }
            BigInteger[] myPlain = new BigInteger[C];
            for (int c = 0; c < C; c++) myPlain[c] = BigInteger.valueOf(myBits[c]);
            Kept kept1 = l1.kept();
            Prep.Forensics fx = new Prep.Forensics(gadget, gadget.length, 1 + P, t -> {
                List<SlotDisclosure> out = new ArrayList<>();
                out.add(slot(kept1, iC[t], aE[t], bS[t], cS[t]));
                for (int r = 0; r < P; r++) out.add(slot(kept1, iCh[t][r], ahE[t][r], bS[t], chS[t][r]));
                return out;
            });
            return new Prep("no-dealer", true, delta, alpha, triples, inputs, myPlain, checkMask, fx);
        }

        SlotDisclosure slot(Kept kept, int item, EncShare x, BigInteger y, BigInteger z) {
            Map<Integer, BigInteger[]> recv = new LinkedHashMap<>(), rho = new LinkedHashMap<>();
            for (int p : others) {
                recv.put(p, kept.recv().get(p).get(item));
                rho.put(p, kept.rho().get(p).get(item));
            }
            return new SlotDisclosure(x.bits().clone(), y, z, recv, rho);
        }

        PA pa(BigInteger x) {
            BigInteger[] t = new BigInteger[n], k = new BigInteger[n];
            Arrays.fill(t, BigInteger.ZERO);
            Arrays.fill(k, BigInteger.ZERO);
            return new PA(x, t, k);
        }

        AW aw(BigInteger value, int[] macIdx, BigInteger[] z) {
            PA[] m = new PA[macIdx.length];
            for (int i = 0; i < m.length; i++) m[i] = pa(z[macIdx[i]]);
            return new AW(pa(value), m);
        }

        static void addAll(List<PA> out, AW w) {
            out.add(w.v());
            out.addAll(Arrays.asList(w.m()));
        }

        static int push(List<EncShare> xs, List<BigInteger> ys, EncShare x, BigInteger y) {
            xs.add(x);
            ys.add(y);
            return xs.size() - 1;
        }

        /**
         * The Gilboa OT core. For every peer p: as the OT RECEIVER towards p I choose with the bits of my xs[t] and get
         * recv[p][t] = x_t*y^p_t + sum(rho^p_t); as the OT SENDER I offer (rho_k, rho_k + gad_k*ys[t]) with fresh masks and keep
         * sendSum[p][t] = sum(rho). So recv - sendSum over the pair is an additive sharing of x_t*y_t.
         */
        Rows otRows(String layer, Item[] items, Set<Integer> keep) {
            int T = items.length;
            Map<Integer, BigInteger[]> recv = new TreeMap<>(), sendSum = new TreeMap<>();
            Kept kept = new Kept(new TreeMap<>(), new TreeMap<>());
            for (int p : others) {
                BigInteger[] r = new BigInteger[T], s = new BigInteger[T];
                Arrays.fill(r, BigInteger.ZERO);
                Arrays.fill(s, BigInteger.ZERO);
                recv.put(p, r);
                sendSum.put(p, s);
                kept.recv().put(p, new TreeMap<>());
                kept.rho().put(p, new TreeMap<>());
            }
            if (T == 0 || others.isEmpty()) return new Rows(recv, sendSum, kept);
            int rows = 0;
            for (Item it : items) rows += it.bits().length;
            int[] rowItem = new int[rows];
            int[] choice = new int[rows];
            Map<Integer, BigInteger[]> m0 = new TreeMap<>(), m1 = new TreeMap<>();
            for (int p : others) {
                m0.put(p, new BigInteger[rows]);
                m1.put(p, new BigInteger[rows]);
            }
            int off = 0;
            int[] itemOff = new int[T];
            for (int t = 0; t < T; t++) {
                Item it = items[t];
                int len = it.bits().length;
                itemOff[t] = off;
                boolean keepIt = keep != null && keep.contains(t);
                if (keepIt) for (int p : others) {
                    BigInteger[] z = new BigInteger[len];
                    Arrays.fill(z, BigInteger.ZERO);
                    kept.recv().get(p).put(t, z);
                }
                for (int k = 0; k < len; k++) {
                    choice[off + k] = it.bits()[k];
                    rowItem[off + k] = t;
                }
                for (int p : others) {
                    BigInteger[] a0 = m0.get(p), a1 = m1.get(p);
                    BigInteger sumRho = BigInteger.ZERO;
                    for (int k = 0; k < len; k++) {
                        BigInteger rho = frng.next();
                        sumRho = fadd(sumRho, rho);
                        a0[off + k] = rho;
                        a1[off + k] = fadd(rho, fmul(it.gad()[k], it.y()));
                    }
                    sendSum.get(p)[t] = sumRho;
                    if (keepIt) kept.rho().get(p).put(t, Arrays.copyOfRange(a0, off, off + len));
                }
                off += len;
            }
            int chunk = 0;
            for (int start = 0; start < rows; start += ROWS_PER_ROUND, chunk++) {
                int end = Math.min(rows, start + ROWS_PER_ROUND);
                int m = end - start;
                int mExt = m + Ot.KAPPA + Ot.SSEC;
                String tag = "ox" + layer + "." + chunk;
                Map<Integer, OtExtReceiver.Begin> begun = new TreeMap<>();
                if ("ot-u-lie".equals(behKind)) {
                    // an inconsistent matrix: flip the first row in 64 of the 128 columns only (not a different choice vector)
                    for (int p : others) recvCh.get(p).tamperU = (u, rd) -> { for (int i = 0; i < 64; i++) u[i] = u[i].xor(BigInteger.ONE); };
                }
                for (int p : others) begun.put(p, recvCh.get(p).begin(Arrays.copyOfRange(choice, start, end)));
                Map<Integer, ExtRoundMsg> us = io.exchange(tag + ".u", peer -> encodeU(begun.get(peer).msg(), mExt), (p, raw) -> decodeU(raw, mExt));
                Map<Integer, OtExtSender.Response> ys = new TreeMap<>();
                for (int p : others) {
                    final int s0 = start, e0 = end;
                    ys.put(p, otGuard(p, "OT extension (" + tag + ")", () -> sendCh.get(p).respond(us.get(p), Arrays.copyOfRange(m0.get(p), s0, e0), Arrays.copyOfRange(m1.get(p), s0, e0))));
                }
                Map<Integer, Cipher> cts = io.exchange(tag + ".y", peer -> encodeY(new Cipher(ys.get(peer).y0(), ys.get(peer).y1())), (p, raw) -> decodeY(raw, m));
                for (int p : others) {
                    BigInteger[] got = otGuard(p, "OT extension (" + tag + ")", () -> recvCh.get(p).finish(begun.get(p).pending(), cts.get(p).y0(), cts.get(p).y1()));
                    BigInteger[] rv = recv.get(p);
                    for (int j = 0; j < m; j++) {
                        int t = rowItem[start + j];
                        rv[t] = fadd(rv[t], mod(got[j]));
                        if (keep != null && keep.contains(t)) kept.recv().get(p).get(t)[start + j - itemOff[t]] = mod(got[j]);
                    }
                }
            }
            return new Rows(recv, sendSum, kept);
        }

        /** My additive share of X_t*Y_t = (sum x)(sum y): the diagonal x_i*y_i locally plus the Gilboa OT product of every ordered pair. */
        Layer mulLayer(String layer, EncShare[] xs, BigInteger[] ys, int lieAt, Set<Integer> keep) {
            BigInteger[] z = new BigInteger[xs.length];
            Item[] items = new Item[xs.length];
            for (int t = 0; t < xs.length; t++) {
                z[t] = fmul(xs[t].value(), ys[t]);
                items[t] = new Item(xs[t].bits(), gadget, t == lieAt ? fadd(ys[t], BigInteger.ONE) : ys[t]);
            }
            Rows r = otRows(layer, items, keep);
            for (int p : others) {
                BigInteger[] rv = r.recv().get(p), ss = r.sendSum().get(p);
                for (int t = 0; t < z.length; t++) z[t] = fsub(fadd(z[t], rv[t]), ss[t]);
            }
            return new Layer(z, r.kept());
        }

        /**
         * Pairwise tags for my shares: for every peer j a tag T_ij (mine) and a key K_ji with T_ij = K_ij + Delta_j*x_i. One OT
         * product of my x with j's Delta per item; each x is split as x = e + d with a fresh encoded e (a derived value has no
         * uniform choice-bit encoding of its own), both halves multiplied with Delta and added. Returns {tag, key} by peer.
         */
        @SuppressWarnings("unchecked")
        Map<Integer, BigInteger[]>[] tagLayer(String layer, BigInteger[] xs) {
            Item[] items = new Item[2 * xs.length];
            BigInteger[] plainGadget = Enc.plainGadget();
            for (int u = 0; u < xs.length; u++) {
                EncShare e = Enc.sampleEnc(gadget, frng);
                EncShare d = Enc.plainShare(fsub(xs[u], e.value()));
                items[2 * u] = new Item(e.bits(), gadget, delta);
                items[2 * u + 1] = new Item(d.bits(), plainGadget, delta);
            }
            Rows r = otRows(layer, items, null);
            Map<Integer, BigInteger[]> tag = new TreeMap<>(), key = new TreeMap<>();
            for (int p : others) {
                BigInteger[] rv = r.recv().get(p), kv = r.sendSum().get(p);
                BigInteger[] t = new BigInteger[xs.length], k = new BigInteger[xs.length];
                for (int u = 0; u < xs.length; u++) {
                    t[u] = fadd(rv[2 * u], rv[2 * u + 1]);
                    k[u] = fadd(kv[2 * u], kv[2 * u + 1]);
                }
                tag.put(p, t);
                key.put(p, k);
            }
            return new Map[] {tag, key};
        }
    }
}
