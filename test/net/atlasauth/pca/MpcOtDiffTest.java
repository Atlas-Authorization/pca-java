package net.atlasauth.pca;

import static net.atlasauth.pca.MpcSupport.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.mpc.Ec;
import net.atlasauth.pca.mpc.Ec.Point;
import net.atlasauth.pca.mpc.Field;
import net.atlasauth.pca.mpc.HybridOt;
import net.atlasauth.pca.mpc.KemOt;
import net.atlasauth.pca.mpc.Mascot;
import net.atlasauth.pca.mpc.Ot;
import net.atlasauth.pca.mpc.Ot.BaseOtBinding;
import net.atlasauth.pca.mpc.Ot.BaseOtTamper;
import net.atlasauth.pca.mpc.Ot.OtRandom;
import net.atlasauth.pca.mpc.Otx;
import net.atlasauth.pca.mpc.Spdz.AuthSV;
import net.atlasauth.pca.mpc.SpdzRunner;
import org.junit.jupiter.api.Test;

/** Differential tests of the MPC oblivious-transfer stack against the TypeScript reference corpus (every draw from a seeded stream). */
class MpcOtDiffTest {
    private static final String MOD = "ref-mpc-ot";

    // ---- argument / result codecs ----
    private static byte[] by(Object o) { return Keys.unb64u((String) map(o).get("$bytes")); }

    private static int[] words(Object o) {
        List<?> l = (List<?>) o;
        int[] out = new int[l.size()];
        for (int i = 0; i < out.length; i++) out[i] = (int) OracleCases.num(l.get(i)).longValue();
        return out;
    }

    private static List<Object> W(int[] w) {
        List<Object> out = new ArrayList<>();
        for (int x : w) out.add(x & 0xffffffffL);
        return out;
    }

    private static Point P(Object o) {
        List<?> l = (List<?>) o;
        return new Point(B(l.get(0)), B(l.get(1)), B(l.get(2)), B(l.get(3)));
    }

    private static Map<String, Object> aff(Point p) { BigInteger[] xy = Ec.toAffine(p); return M("x", xy[0].toString(), "y", xy[1].toString()); }

    private static List<Object> BL(byte[][] a) { List<Object> o = new ArrayList<>(); for (byte[] x : a) o.add(x); return o; }

    private static List<Object> PAIRS(byte[][][] a) {
        List<Object> o = new ArrayList<>();
        for (byte[][] p : a) { List<Object> pr = new ArrayList<>(); pr.add(p[0]); pr.add(p[1]); o.add(pr); }
        return o;
    }

    private static byte[][][] pairs(Object o) {
        List<?> l = (List<?>) o;
        byte[][][] out = new byte[l.size()][2][];
        for (int i = 0; i < out.length; i++) { out[i][0] = by(((List<?>) l.get(i)).get(0)); out[i][1] = by(((List<?>) l.get(i)).get(1)); }
        return out;
    }

    private static OtRandom orng(Object seed) { return Ot.otRandom(Ot.splitMix64(B(seed))); }

    private static final Point ORDER2 = new Point(BigInteger.ZERO, Ec.Q.subtract(BigInteger.ONE), BigInteger.ONE, BigInteger.ZERO);

    private static byte[] flip(byte[] b, int mask) { byte[] o = b.clone(); for (int i = 0; i < o.length; i++) o[i] ^= mask; return o; }

    private static BaseOtTamper tamper(String name) {
        BaseOtTamper t = new BaseOtTamper();
        switch (name) {
            case "none": return null;
            case "S_identity": t.tamperS = p -> Ec.IDENTITY; break;
            case "S_order2": t.tamperS = p -> ORDER2; break;
            case "S_other": t.tamperS = p -> Ec.addPoints(p, Ec.BASE); break;
            case "proof_z": t.tamperProof = p -> new Ec.SchnorrProof(p.U(), p.z().add(BigInteger.ONE).mod(Ec.L)); break;
            case "proof_U": t.tamperProof = p -> new Ec.SchnorrProof(Ec.addPoints(p.U(), Ec.BASE), p.z()); break;
            case "R0_identity": t.tamperR = R -> R[0] = Ec.IDENTITY; break;
            case "R1_order2": t.tamperR = R -> { if (R.length > 1) R[1] = ORDER2; }; break;
            case "R_swap": t.tamperR = R -> { if (R.length > 1) { Point x = R[0]; R[0] = R[1]; R[1] = x; } }; break;
            case "ct_flip": t.tamperCiphertext = ct -> ct[0][0] = flip(ct[0][0], 1); break;
            case "ct_flip1": t.tamperCiphertext = ct -> ct[ct.length - 1][1] = flip(ct[ct.length - 1][1], 0x80); break;
            default: throw new IllegalArgumentException(name);
        }
        return t;
    }

    private static BaseOtBinding binding(Object sess, Object a, Object b, Object round) {
        return new BaseOtBinding(by(sess), idx(a), idx(b), (String) round);
    }

    private static long idx(Object o) {
        double d = D(o);
        if (d != Math.rint(d)) throw new IllegalArgumentException("not an integer");
        return (long) d;
    }

    // ---- Ed25519 group ----
    @Test void genCorpusIsPresent() { BaseOracle.requireGen(MOD); }

    @Test void ec() throws Exception {
        OracleCases.each(MOD, "ecOp", a -> {
            String op = (String) a.get(0);
            switch (op) {
                case "mulBase": { Point p = Ec.mulBase(B(a.get(1))); return M("p", aff(p), "enc", Ec.encodePoint(p), "comp", Ec.compressPoint(p)); }
                case "mul": return aff(Ec.mul(B(a.get(1)), P(a.get(2))));
                case "add": return aff(Ec.addPoints(P(a.get(1)), P(a.get(2))));
                case "sub": return aff(Ec.sub(P(a.get(1)), P(a.get(2))));
                case "neg": return aff(Ec.neg(P(a.get(1))));
                case "dbl": return aff(Ec.dbl(P(a.get(1))));
                case "decompress": {
                    Point p = Ec.decompressPoint(by(a.get(1)));
                    return M("p", aff(p), "onCurve", Ec.isOnCurve(p), "identity", Ec.isIdentity(p), "prime", Ec.hasPrimeOrder(p), "inSub", Ec.isInSubgroup(p));
                }
                default: throw new IllegalArgumentException(op);
            }
        });
        OracleCases.each(MOD, "ecValidate", a -> {
            Point p = P(a.get(0));
            return M("onCurve", Ec.isOnCurve(p), "identity", Ec.isIdentity(p), "prime", Ec.hasPrimeOrder(p), "inSubgroup", Ec.isInSubgroup(p));
        });
        OracleCases.each(MOD, "ecAssert", a -> { Ec.assertInSubgroup(P(a.get(0)), "p"); return true; });
        OracleCases.each(MOD, "schnorr", a -> {
            BigInteger y = B(a.get(0)), nonce = B(a.get(1));
            byte[] ctx = Keys.unb64u((String) a.get(2));
            Point S = Ec.mulBase(y);
            Ec.SchnorrProof proof = Ec.schnorrProve(y, S, () -> nonce, ctx);
            byte[] other = "other-ctx".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Ec.SchnorrProof forged = new Ec.SchnorrProof(proof.U(), proof.z().add(BigInteger.ONE).mod(Ec.L));
            Ec.SchnorrProof oor = new Ec.SchnorrProof(proof.U(), Ec.L);
            return M("S", aff(S), "U", aff(proof.U()), "z", proof.z().toString(), "ok", Ec.schnorrVerify(S, proof, ctx), "badCtx", Ec.schnorrVerify(S, proof, other),
                "forged", Ec.schnorrVerify(S, forged, ctx), "oor", Ec.schnorrVerify(S, oor, ctx), "wrongS", Ec.schnorrVerify(Ec.mulBase(y.add(BigInteger.ONE)), proof, ctx),
                "identityS", Ec.schnorrVerify(Ec.IDENTITY, proof, ctx));
        });
    }

    // ---- word-array kernels ----
    @Test void kernels() throws Exception {
        OracleCases.each(MOD, "prg", a -> W(Otx.prgColumn(Keys.unb64u((String) a.get(0)), (long) D(a.get(1)), I(a.get(2)))));
        OracleCases.each(MOD, "maskTail", a -> { int[] w = words(a.get(0)); Otx.maskTail(w, I(a.get(1))); return W(w); });
        OracleCases.each(MOD, "transpose32", a -> { int[] w = words(a.get(0)); Otx.transpose32(w, 0); return W(w); });
        OracleCases.each(MOD, "transposeCols", a -> W(Otx.transposeCols(words(a.get(0)), I(a.get(1)), I(a.get(2)))));
        OracleCases.each(MOD, "gfMulX", a -> { int[] w = words(a.get(0)); Otx.gfMulX(w); return W(w); });
        OracleCases.each(MOD, "gfXorInto", a -> { int[] w = words(a.get(0)); Otx.gfXorInto(w, words(a.get(1)), 0); return W(w); });
        OracleCases.each(MOD, "gfBig", a -> { int[] w = words(a.get(0)); BigInteger v = Otx.gfToBig(w); return M("big", v.toString(), "back", W(Otx.gfFromBig(v))); });
        OracleCases.each(MOD, "accumColumn", a -> { int[] c = words(a.get(0)); int[] acc = new int[4]; Otx.accumColumn(c, 0, c.length, words(a.get(1)), acc); return W(acc); });
        OracleCases.each(MOD, "kosCombine", a -> W(Otx.kosCombine(words(a.get(0)), I(a.get(1)), words(a.get(2)))));
        OracleCases.each(MOD, "tmmo", a -> W(Otx.tmmoCrh(words(a.get(0)), I(a.get(1)), new Otx.OtTweak((long) D(a.get(2)), words(a.get(3))))));
        OracleCases.each(MOD, "tweakDomain", a -> W(Otx.otTweakDomain(Keys.unb64u((String) a.get(0)))));
        OracleCases.each(MOD, "bigBytes", a -> Otx.bigToBytes(B(a.get(0)), I(a.get(1))));
        OracleCases.each(MOD, "bytesBig", a -> Otx.bytesToBig(Keys.unb64u((String) a.get(0))).toString());
        OracleCases.each(MOD, "word64", a -> Otx.word64(words(a.get(0)), I(a.get(1))).toString());
    }

    // ---- base OT, KOS extension ----
    @Test void baseOt() throws Exception {
        OracleCases.each(MOD, "bindingBytes", a -> Ot.bindingBytes(binding(Map.of("$bytes", a.get(0)), a.get(1), a.get(2), a.get(3))));
        OracleCases.each(MOD, "baseOtKdf", a -> {
            BaseOtBinding b0 = Ot.randomBinding(orng("4242"), "base-ot");
            Point[] R = {Ec.mulBase(BigInteger.valueOf(5)), Ec.mulBase(BigInteger.valueOf(6))};
            byte[] th = Ot.baseOtTranscriptHash(b0, Ec.mulBase(BigInteger.valueOf(3)), R);
            return M("th", th, "k", Ot.baseOtKdf(th, I(a.get(0)), R[0], Ec.mulBase(BigInteger.valueOf(9))));
        });
        OracleCases.each(MOD, "randomOt", a -> {
            Ot.MalRandomOtResult r = Ot.malBaseRandomOT(IA(a.get(0)), orng(a.get(1)), tamper((String) a.get(2)), null);
            List<Object> R = new ArrayList<>();
            for (Point p : r.R()) R.add(aff(p));
            return M("S", aff(r.S()), "U", aff(r.proof().U()), "z", r.proof().z().toString(), "R", R, "senderPads", PAIRS(r.senderPads()), "recvPads", BL(r.recvPads()));
        });
        OracleCases.each(MOD, "baseOt", a -> {
            Ot.BaseOtResult res = Ot.baseOT(pairs(a.get(0)), IA(a.get(1)), orng(a.get(2)), tamper((String) a.get(3)), null);
            Ot.BaseOtTranscript t = res.transcript();
            List<Object> R = new ArrayList<>();
            for (Point p : t.R()) R.add(aff(p));
            return M("received", BL(res.received()), "S", aff(t.S()), "U", aff(t.proof().U()), "z", t.proof().z().toString(), "R", R, "ct", PAIRS(t.ct()), "com", PAIRS(t.com()));
        });
    }

    @Test void extension() throws Exception {
        OracleCases.each(MOD, "channel", a -> {
            Ot.OtChannel ch = new Ot.OtChannel(orng(a.get(3)));
            String tn = (String) a.get(5);
            if ("flip00".equals(tn)) ch.tamperU = (u, round) -> u[0] = u[0].xor(BigInteger.ONE);
            else if ("flipLast".equals(tn)) ch.tamperU = (u, round) -> u[127] = u[127].xor(BigInteger.ONE.shiftLeft(5));
            else if ("oversize".equals(tn)) ch.tamperU = (u, round) -> u[3] = u[3].or(BigInteger.ONE.shiftLeft(5000));
            else if ("negative".equals(tn)) ch.tamperU = (u, round) -> u[3] = BigInteger.ONE.negate();
            else if ("round2flip".equals(tn)) ch.tamperU = (u, round) -> { if (round == 1) u[10] = u[10].xor(BigInteger.TWO); };
            List<Object> outs = new ArrayList<>();
            for (int k = 0; k < I(a.get(4)); k++) {
                Ot.OtChannel.Extended e = ch.extend(IA(a.get(0)), BA(a.get(1)), BA(a.get(2)));
                outs.add(M("received", L(e.received()), "uMatrix", L(e.uMatrix())));
            }
            Object base = ch.baseTranscript == null ? null : M("S", aff(ch.baseTranscript.S()), "R", ch.baseTranscript.R().length);
            return M("selector", ch.selector().toString(), "outs", outs, "base", base);
        });
        OracleCases.each(MOD, "kosChi", a -> {
            byte[] b = Keys.unb64u((String) a.get(0));
            BigInteger[] u = BA(a.get(2));
            int mExt = I(a.get(3));
            BigInteger[] chi = Ot.kosChallenges(b, I(a.get(1)), u, mExt);
            return M("w", W(Ot.kosChiWords(b, I(a.get(1)), u, mExt, null)), "chi", L(chi));
        });
    }

    // ---- ML-KEM base OT, hybrid ----
    private static KemOt.KemMalTamper kemTamper(String tn) {
        KemOt.KemMalTamper t = new KemOt.KemMalTamper();
        if ("badKey".equals(tn)) t.tamperOpenedKeys = pk -> { byte[] x = pk[0][0]; pk[0][0] = pk[0][1]; pk[0][1] = x; };
        else if ("badSid".equals(tn)) t.tamperReceiverSid = s -> flip(s, 1);
        else return null;
        return t;
    }

    @Test void kem() throws Exception {
        OracleCases.each(MOD, "kemOt", a -> {
            String fn = (String) a.get(0);
            OtRandom g = orng(a.get(3));
            int[] choices = IA(a.get(2));
            String tn = (String) a.get(4);
            if (fn.equals("kemBaseOT")) {
                KemOt.KemBaseOtResult r = KemOt.kemBaseOT(pairs(a.get(1)), choices, g);
                KemOt.KemBaseOtTranscript t = r.transcript();
                return M("received", BL(r.received()), "transcript", M("publicKeys", PAIRS(t.publicKeys()), "ciphertexts", PAIRS(t.ciphertexts()), "encrypted", PAIRS(t.encrypted())));
            }
            if (fn.equals("kemBaseOtMal")) {
                KemOt.KemBaseOtMalResult r = KemOt.kemBaseOtMal(pairs(a.get(1)), choices, g, kemTamper(tn));
                KemOt.KemMalTranscript t = r.transcript();
                return M("received", BL(r.received()), "transcript", M("rn", t.rn(), "commitments", BL(t.commitments()), "sn", t.sn(), "publicKeys", PAIRS(t.publicKeys()),
                    "ciphertexts", PAIRS(t.ciphertexts()), "encrypted", PAIRS(t.encrypted())));
            }
            KemOt.KemBaseOtMalRandomResult r = KemOt.kemBaseOtMalRandom(choices, g, kemTamper(tn));
            KemOt.KemMalRandomTranscript t = r.transcript();
            return M("senderSecrets", PAIRS(r.senderSecrets()), "recvSecrets", BL(r.recvSecrets()), "sid", r.sid(), "transcript",
                M("rn", t.rn(), "commitments", BL(t.commitments()), "sn", t.sn(), "publicKeys", PAIRS(t.publicKeys()), "ciphertexts", PAIRS(t.ciphertexts())));
        });
        OracleCases.each(MOD, "kemPad", a -> {
            byte[] ss = new byte[32];
            for (int k = 0; k < 32; k++) ss[k] = (byte) k;
            return a.size() == 1 ? KemOt.kemOtPad(0, 0, new byte[32], I(a.get(0))) : KemOt.kemOtPad(I(a.get(0)), I(a.get(1)), ss, I(a.get(2)));
        });
        OracleCases.each(MOD, "hybridOt", a -> {
            String tn = (String) a.get(3);
            HybridOt.HybridBaseOtTamper t = null;
            if (tn != null) {
                t = new HybridOt.HybridBaseOtTamper();
                if (tn.equals("ec")) t.ec = tamper("ct_flip");
                else if (tn.equals("ecS")) t.ec = tamper("S_identity");
                else if (tn.equals("enc")) t.tamperEncrypted = e -> e[0][0] = flip(e[0][0], 1);
                else if (tn.equals("kem")) t.kem = kemTamper("badKey");
            }
            HybridOt.HybridBaseOtResult r = HybridOt.hybridBaseOT(pairs(a.get(0)), IA(a.get(1)), orng(a.get(2)), t);
            HybridOt.HybridBaseOtTranscript tr = r.transcript();
            return M("received", BL(r.received()), "sid", tr.sid(), "ecS", aff(tr.ecS()), "kemSid", tr.kemSid(), "encrypted", PAIRS(tr.encrypted()), "commitments", PAIRS(tr.commitments()));
        });
        OracleCases.each(MOD, "hybridKey", a -> HybridOt.hybridTransferKey(fill(32, 1), 3, 1, fill(16, 2), fill(32, 3), I(a.get(0))));
    }

    private static byte[] fill(int n, int v) { byte[] b = new byte[n]; java.util.Arrays.fill(b, (byte) v); return b; }

    // ---- MASCOT no-dealer offline phase and the no-dealer runner ----
    @Test void mascot() throws Exception {
        OracleCases.each(MOD, "offline", a -> {
            int n = I(a.get(0));
            BigInteger seed = B(a.get(1));
            String what = (String) a.get(2);
            Map<String, Object> o = a.get(3) == null ? null : map(a.get(3));
            Mascot.NoDealerOptions opts = null;
            if (o != null) {
                opts = new Mascot.NoDealerOptions();
                if (o.get("sacrifice") != null) opts.sacrifice = (Boolean) o.get("sacrifice");
                if (o.get("partners") != null) opts.sacrificePartners = I(o.get("partners"));
                if (o.get("keys") != null) opts.macKeys = I(o.get("keys"));
                if (o.get("statSec") != null) opts.statSec = I(o.get("statSec"));
                opts.unsafeStatSec = Boolean.TRUE.equals(o.get("unsafe"));
                if (o.get("dev") != null) { List<?> d = (List<?>) o.get("dev"); opts.deviation = new Mascot.OfflineDeviation(I(d.get(0)), B(d.get(1))); }
            }
            Mascot.NoDealerOffline off = Mascot.makeNoDealerOffline(n, seed, opts);
            Map<String, Object> base = M("n", off.n, "statSec", off.statSec, "ctx", ctx(off.macContext()));
            switch (what) {
                case "ctx": return base;
                case "triple": base.put("t", triple(off.genAuthTriple())); return base;
                case "input": base.put("v", authSV(off.authInput(B(o.get("value")), I(o.get("owner"))))); return base;
                case "multiply": {
                    BigInteger[] x = BA(o.get("x")), y = BA(o.get("y"));
                    BigInteger[] z = off.otShareMultiply(new ArrayList<Object>(java.util.Arrays.asList((Object[]) x)), y);
                    BigInteger sum = BigInteger.ZERO, sx = BigInteger.ZERO, sy = BigInteger.ZERO;
                    for (BigInteger v : z) sum = Field.fadd(sum, v);
                    for (BigInteger v : x) sx = Field.fadd(sx, v);
                    for (BigInteger v : y) sy = Field.fadd(sy, v);
                    base.put("z", L(z)); base.put("sum", sum.toString()); base.put("expect", Field.fmul(sx, sy).toString());
                    return base;
                }
                case "consistency": {
                    List<?> values = (List<?>) o.get("values");
                    List<AuthSV> ins = new ArrayList<>();
                    for (int i = 0; i < values.size(); i++) ins.add(off.authInput(B(values.get(i)), i % n));
                    if (Boolean.TRUE.equals(o.get("tamper"))) ins.get(0).value()[0] = Field.fadd(ins.get(0).value()[0], BigInteger.ONE);
                    off.checkInputConsistency(ins);
                    base.put("ok", true);
                    return base;
                }
                default: throw new IllegalArgumentException(what);
            }
        });
        OracleCases.each(MOD, "offlineBlame", a -> {
            Mascot.NoDealerOptions opts = new Mascot.NoDealerOptions();
            opts.deviation = new Mascot.OfflineDeviation(I(a.get(2)), B(a.get(3)));
            try {
                Mascot.makeNoDealerOffline(I(a.get(0)), B(a.get(1)), opts).genAuthTriple();
                return M("aborted", false);
            } catch (Mascot.OfflineCheatingAbort e) {
                List<Object> bl = new ArrayList<>(e.blamed());
                return M("aborted", true, "name", "OfflineCheatingAbort", "blamed", bl);
            }
        });
        OracleCases.each(MOD, "noDealerRun", a -> MpcDiffTest.summary(SpdzRunner.composeSecureMalicious(vectors(a.get(0)), MpcDiffTest.config(map(a.get(1))))));
    }
}
