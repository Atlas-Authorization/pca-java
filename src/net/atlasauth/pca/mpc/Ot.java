package net.atlasauth.pca.mpc;

import net.atlasauth.pca.Json;

import static net.atlasauth.pca.mpc.Otx.COLS;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.UnaryOperator;
import net.atlasauth.pca.mpc.Ec.Point;
import net.atlasauth.pca.mpc.Ec.SchnorrProof;
import org.bouncycastle.crypto.digests.SHAKEDigest;

/**
 * Oblivious transfer, the root of the no-dealer offline phase. (1) A maliciously secure Chou-Orlandi base OT over the Ed25519
 * subgroup: the sender proves knowledge of its discrete log with a Schnorr NIZK, every received point is validated, and the
 * core runs as a random OT so there is no selective-failure surface. (2) IKNP OT extension with the KOS consistency check
 * (a deviating receiver is caught and the protocol aborts). Both roles run in one process; the functions take both parties'
 * inputs and return the receiver's outputs plus an inspectable transcript.
 */
public final class Ot {
    private Ot() {}

    /** IKNP security parameter (number of base OTs / width of the selector s). */
    public static final int KAPPA = 128;
    /** KOS statistical parameter: extra random check rows beyond the kappa that mask the revealed combination. */
    public static final int SSEC = 128;
    static final int SEED_BYTES = KAPPA / 8;

    /** The KOS correlation check failed: a cheating OT-extension receiver is detected. */
    public static final class MalOtAbort extends RuntimeException {
        public MalOtAbort(String message) { super(message); }
    }

    /** A base OT aborted: a cheating sender (bad proof / inconsistent ciphertext) is detected. */
    public static final class BaseOtAbort extends RuntimeException {
        public BaseOtAbort(String message) { super(message); }
    }

    /** A source of scalars and seeds for OT needs. */
    public interface OtRandom {
        /** A uniform scalar in [1, L). */
        BigInteger scalar();
        /** n random bytes. */
        byte[] bytes(int n);
    }

    /** The CSPRNG-backed default: scalars by rejection over 32 random bytes. */
    public static OtRandom secureOtRandom() {
        SecureRandom rnd = new SecureRandom();
        return new OtRandom() {
            @Override public BigInteger scalar() {
                BigInteger bound = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE.shiftLeft(256).mod(Ec.L));
                byte[] b = new byte[32];
                for (;;) {
                    rnd.nextBytes(b);
                    BigInteger acc = new BigInteger(1, b);
                    if (acc.compareTo(bound) >= 0) continue;
                    BigInteger s = acc.mod(Ec.L);
                    if (s.signum() != 0) return s;
                }
            }
            @Override public byte[] bytes(int n) {
                byte[] b = new byte[n];
                rnd.nextBytes(b);
                return b;
            }
        };
    }

    /** A raw SplitMix64 stream (deterministic; for reproducible tests only). */
    public static LongSupplier splitMix64(BigInteger seed) {
        long[] s = {seed.longValue()};
        return () -> {
            s[0] += 0x9e3779b97f4a7c15L;
            long z = s[0];
            z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
            z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
            return z ^ (z >>> 31);
        };
    }

    private static BigInteger u64(long v) { return new BigInteger(Long.toUnsignedString(v)); }

    /** An OtRandom from a 64-bit stream (each long is an unsigned 64-bit value). */
    public static OtRandom otRandom(LongSupplier next64) {
        return new OtRandom() {
            @Override public BigInteger scalar() {
                for (int attempt = 0; attempt < 8; attempt++) {
                    BigInteger acc = BigInteger.ZERO;
                    for (int i = 0; i < 4; i++) acc = acc.shiftLeft(64).or(u64(next64.getAsLong()));
                    BigInteger s = acc.mod(Ec.L);
                    if (s.signum() != 0) return s;
                }
                throw new IllegalStateException("otRandom: entropy stream returned zero scalars repeatedly (RNG failure)");
            }
            @Override public byte[] bytes(int n) {
                byte[] out = new byte[n];
                int have = 0;
                while (have < n) {
                    long v = next64.getAsLong();
                    for (int i = 0; i < 8 && have < n; i++) {
                        out[have++] = (byte) v;
                        v >>>= 8;
                    }
                }
                return out;
            }
        };
    }

    private static byte[] sha256(byte[]... chunks) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            for (byte[] c : chunks) h.update(c);
            return h.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] u32(long x) {
        return new byte[] {(byte) (x >>> 24), (byte) (x >>> 16), (byte) (x >>> 8), (byte) x};
    }

    /** UTF-8 as the reference's TextEncoder writes it: a lone surrogate becomes U+FFFD (String.getBytes would write '?'). */
    private static byte[] utf8(String s) { return Json.utf8(s); }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    /** Session binding of one base OT: who runs it, in which session and round (indices are uint32). */
    public record BaseOtBinding(byte[] sessionId, long senderIndex, long receiverIndex, String round) {}

    private static final byte[] TAG_BINDING = utf8("atlas-pca-mpc/base-ot-binding");
    private static final byte[] TAG_TRANSCRIPT = utf8("atlas-pca-mpc/base-ot-transcript");
    private static final byte[] TAG_KDF = utf8("atlas-pca-mpc/ot-kdf");
    private static final byte[] TAG_KOS = utf8("atlas-pca-mpc/ot-kos");
    private static final byte[] TAG_COMMIT = utf8("atlas-pca-mpc/ot-msg-commit");

    /** Canonical, length-prefixed encoding of a binding (the Schnorr context and part of every KDF input). */
    public static byte[] bindingBytes(BaseOtBinding b) {
        if (b.sessionId() == null || b.sessionId().length < 8 || b.sessionId().length > 64) throw new IllegalArgumentException("base-OT binding: sessionId must be 8..64 bytes");
        if (b.senderIndex() < 0 || b.senderIndex() > 0xffffffffL) throw new IllegalArgumentException("base-OT binding: senderIndex must be a uint32");
        if (b.receiverIndex() < 0 || b.receiverIndex() > 0xffffffffL) throw new IllegalArgumentException("base-OT binding: receiverIndex must be a uint32");
        if (b.senderIndex() == b.receiverIndex()) throw new IllegalArgumentException("base-OT binding: sender and receiver must be different parties");
        byte[] round = utf8(b.round());
        if (round.length == 0 || round.length > 64) throw new IllegalArgumentException("base-OT binding: round label must be 1..64 bytes");
        return concat(TAG_BINDING, u32(b.sessionId().length), b.sessionId(), u32(b.senderIndex()), u32(b.receiverIndex()), u32(round.length), round);
    }

    /** A fresh binding for an in-process OT: a random 16-byte session id from {@code rng}. */
    public static BaseOtBinding randomBinding(OtRandom rng, String round, long senderIndex, long receiverIndex) {
        return new BaseOtBinding(rng.bytes(16), senderIndex, receiverIndex, round);
    }

    public static BaseOtBinding randomBinding(OtRandom rng, String round) { return randomBinding(rng, round, 0, 1); }

    /** Hash of the whole base-OT transcript: binding, S and every receiver point, in order. */
    public static byte[] baseOtTranscriptHash(BaseOtBinding binding, Point S, Point[] R) {
        List<byte[]> parts = new ArrayList<>(List.of(TAG_TRANSCRIPT, bindingBytes(binding), Ec.encodePoint(S), u32(R.length)));
        for (Point r : R) parts.add(Ec.encodePoint(r));
        return sha256(parts.toArray(new byte[0][]));
    }

    /** H("ot-kdf" || H(transcript) || index || R_i || P), SEED_BYTES bytes. */
    public static byte[] baseOtKdf(byte[] transcriptHash, int index, Point Ri, Point p) {
        return Arrays.copyOf(sha256(TAG_KDF, transcriptHash, u32(index), Ec.encodePoint(Ri), Ec.encodePoint(p)), SEED_BYTES);
    }

    /** The KOS row-weights as little-endian u32 words (4 per row): SHAKE256 over the binding, round and every column of u. */
    public static int[] kosChiWords(byte[] binding, int round, BigInteger[] u, int mExt, byte[][] colBytesList) {
        int colBytes = (mExt + 7) / 8;
        SHAKEDigest xof = new SHAKEDigest(256);
        absorb(xof, TAG_KOS);
        absorb(xof, u32(binding.length));
        absorb(xof, binding);
        absorb(xof, u32(round));
        absorb(xof, u32(mExt));
        absorb(xof, u32(u.length));
        if (colBytesList != null) for (byte[] cb : colBytesList) absorb(xof, cb);
        else for (BigInteger col : u) absorb(xof, Otx.bigToBytes(col, colBytes));
        byte[] out = new byte[mExt * 16];
        xof.doFinal(out, 0, out.length);
        return Otx.wordsFromLeBytes(out, mExt * 4);
    }

    private static void absorb(SHAKEDigest d, byte[] b) { d.update(b, 0, b.length); }

    public static BigInteger[] kosChallenges(byte[] binding, int round, BigInteger[] u, int mExt) {
        int[] w = kosChiWords(binding, round, u, mExt, null);
        BigInteger[] chi = new BigInteger[mExt];
        for (int j = 0; j < mExt; j++) chi[j] = Otx.gfToBig(w, 4 * j);
        return chi;
    }

    private static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }

    // ---- base OT ----

    /** TEST-ONLY injection points modelling a malicious sender or receiver in the base OT (null = honest). */
    public static final class BaseOtTamper {
        public UnaryOperator<Point> tamperS;
        public UnaryOperator<SchnorrProof> tamperProof;
        public Consumer<Point[]> tamperR;
        public Consumer<byte[][][]> tamperCiphertext;
    }

    /** The base-OT transcript. ct and com hold [i][0/1] byte strings. */
    public record BaseOtTranscript(Point S, SchnorrProof proof, Point[] R, byte[][][] ct, byte[][][] com) {}

    public record BaseOtResult(byte[][] received, BaseOtTranscript transcript) {}

    /** A pluggable chosen-message base OT: messages[i] = {m0, m1}; returns the receiver's recovered messages. */
    @FunctionalInterface
    public interface BaseOtFn { byte[][] run(byte[][][] messages, int[] choices, OtRandom rng); }

    /** Output of the malicious-secure random base OT: validated points and the two RO pads per index. */
    public record MalRandomOtResult(Point S, SchnorrProof proof, Point[] R, byte[][][] senderPads, byte[][] recvPads) {}

    private static byte[] otCommit(int i, int b, byte[] msg, byte[] pad) {
        return sha256(TAG_COMMIT, u32(i), new byte[] {(byte) (b & 1)}, msg, pad);
    }

    public static MalRandomOtResult malBaseRandomOT(int[] choices, OtRandom rng, BaseOtTamper tamper, BaseOtBinding binding) {
        if (rng == null) rng = secureOtRandom();
        if (binding == null) binding = randomBinding(rng, "base-ot");
        SenderSetup setup = malBaseOtSenderSetup(rng, binding);
        Point S = tamper != null && tamper.tamperS != null ? tamper.tamperS.apply(setup.S()) : setup.S();
        SchnorrProof proof = tamper != null && tamper.tamperProof != null ? tamper.tamperProof.apply(setup.proof()) : setup.proof();
        ReceiverResponse rr = malBaseOtReceiverRespond(S, proof, choices, rng, binding);
        if (tamper != null && tamper.tamperR != null) tamper.tamperR.accept(rr.R());
        byte[][][] senderPads = malBaseOtSenderDerive(setup.y(), setup.T(), rr.R(), S, binding);
        return new MalRandomOtResult(S, proof, rr.R(), senderPads, rr.recvPads());
    }

    public record SenderSetup(BigInteger y, Point T, Point S, SchnorrProof proof) {}

    public static SenderSetup malBaseOtSenderSetup(OtRandom rng, BaseOtBinding binding) {
        byte[] ctx = bindingBytes(binding);
        BigInteger y = rng.scalar();
        Point S = Ec.mulBase(y);
        Point T = Ec.mul(y, S);
        SchnorrProof proof = Ec.schnorrProve(y, S, rng::scalar, ctx);
        return new SenderSetup(y, T, S, proof);
    }

    public record ReceiverResponse(Point[] R, byte[][] recvPads) {}

    public static ReceiverResponse malBaseOtReceiverRespond(Point S, SchnorrProof proof, int[] choices, OtRandom rng, BaseOtBinding binding) {
        byte[] ctx = bindingBytes(binding);
        Ec.assertInSubgroup(S, "base-OT S (received by receiver)");
        if (!Ec.schnorrVerify(S, proof, ctx)) throw new BaseOtAbort("base OT: sender Schnorr proof-of-knowledge of S=y·B failed; aborting");
        Point[] R = new Point[choices.length];
        BigInteger[] xs = new BigInteger[choices.length];
        for (int i = 0; i < choices.length; i++) {
            BigInteger x = rng.scalar();
            int ci = choices[i] & 1;
            R[i] = ci == 1 ? Ec.addPoints(Ec.mulBase(x), S) : Ec.mulBase(x);
            xs[i] = x;
        }
        byte[] th = baseOtTranscriptHash(binding, S, R);
        byte[][] recvPads = new byte[choices.length][];
        for (int i = 0; i < choices.length; i++) recvPads[i] = baseOtKdf(th, i, R[i], Ec.mul(xs[i], S));
        return new ReceiverResponse(R, recvPads);
    }

    public static byte[][][] malBaseOtSenderDerive(BigInteger y, Point T, Point[] R, Point S, BaseOtBinding binding) {
        for (int i = 0; i < R.length; i++) Ec.assertInSubgroup(R[i], "base-OT R_" + i + " (received by sender)");
        byte[] th = baseOtTranscriptHash(binding, S, R);
        byte[][][] pads = new byte[R.length][2][];
        for (int i = 0; i < R.length; i++) {
            Point yR = Ec.mul(y, R[i]);
            pads[i][0] = baseOtKdf(th, i, R[i], yR);
            pads[i][1] = baseOtKdf(th, i, R[i], Ec.sub(yR, T));
        }
        return pads;
    }

    /** One-time-pads the messages under the sender pads and commits to each (message, pad). Returns {ct, com}. */
    public static byte[][][][] baseOtSenderEncrypt(byte[][][] messages, byte[][][] senderPads) {
        if (messages.length != senderPads.length) throw new IllegalArgumentException("baseOT: messages/pads length mismatch");
        for (int i = 0; i < messages.length; i++) {
            byte[] m0 = messages[i][0], m1 = messages[i][1];
            if (m0.length > SEED_BYTES || m1.length > SEED_BYTES || m0.length != m1.length) {
                throw new IllegalArgumentException("baseOT: message pair " + i + " must be equal length and at most " + SEED_BYTES + " bytes (pad width)");
            }
        }
        byte[][][] ct = new byte[messages.length][2][];
        byte[][][] com = new byte[messages.length][2][];
        for (int i = 0; i < messages.length; i++) {
            byte[] p0 = senderPads[i][0], p1 = senderPads[i][1];
            ct[i][0] = xorBytes(messages[i][0], p0);
            ct[i][1] = xorBytes(messages[i][1], p1);
            com[i][0] = otCommit(i, 0, messages[i][0], p0);
            com[i][1] = otCommit(i, 1, messages[i][1], p1);
        }
        return new byte[][][][] {ct, com};
    }

    public static byte[][] baseOtReceiverDecrypt(int[] choices, byte[][] recvPads, byte[][][] ct, byte[][][] com) {
        if (ct.length != choices.length || com.length != choices.length || recvPads.length != choices.length) {
            throw new BaseOtAbort("base OT: ciphertext/commitment count does not match the number of choices; aborting");
        }
        byte[][] received = new byte[choices.length][];
        for (int i = 0; i < choices.length; i++) {
            int ci = choices[i] & 1;
            byte[] c0 = ct[i][0], c1 = ct[i][1];
            if (c0.length != c1.length || c0.length > SEED_BYTES) throw new BaseOtAbort("base OT (index " + i + "): malformed ciphertext shape; aborting");
            byte[] m = xorBytes(ct[i][ci], recvPads[i]);
            byte[] check = otCommit(i, ci, m, recvPads[i]);
            if (!MessageDigest.isEqual(check, com[i][ci])) throw new BaseOtAbort("base OT (index " + i + "): sender ciphertext inconsistent with its commitment; aborting");
            received[i] = m;
        }
        return received;
    }

    /** Chosen-message 1-of-2 OT for {@code choices.length} transfers, built over the random base OT. */
    public static BaseOtResult baseOT(byte[][][] messages, int[] choices, OtRandom rng, BaseOtTamper tamper, BaseOtBinding binding) {
        if (rng == null) rng = secureOtRandom();
        if (binding == null) binding = randomBinding(rng, "base-ot");
        if (messages.length != choices.length) throw new IllegalArgumentException("baseOT: messages/choices length mismatch");
        MalRandomOtResult ro = malBaseRandomOT(choices, rng, tamper, binding);
        byte[][][][] enc = baseOtSenderEncrypt(messages, ro.senderPads());
        byte[][][] ct = enc[0], com = enc[1];
        if (tamper != null && tamper.tamperCiphertext != null) tamper.tamperCiphertext.accept(ct);
        byte[][] received = baseOtReceiverDecrypt(choices, ro.recvPads(), ct, com);
        return new BaseOtResult(received, new BaseOtTranscript(ro.S(), ro.proof(), ro.R(), ct, com));
    }

    // ---- OT extension (IKNP + KOS) ----

    /** The receiver's extension-round message: the u columns and the KOS values (x, t). */
    public record ExtRoundMsg(BigInteger[] u, BigInteger x, BigInteger tComb) {}

    /** The receiver's per-round state between {@code begin} and {@code finish}. */
    public record ExtPending(int m, int[] choiceBits, int[] t, int W, long rowOffset) {}

    private static void checkExtInputs(int[] choiceBits, BigInteger[] msg0, BigInteger[] msg1) {
        int m = choiceBits.length;
        BigInteger limit = BigInteger.ONE.shiftLeft(64);
        for (int j = 0; j < m; j++) {
            if (choiceBits[j] != 0 && choiceBits[j] != 1) throw new IllegalArgumentException("OtChannel.extend: choice bit " + j + " must be 0 or 1");
        }
        if (msg0 != null && msg1 != null) {
            for (int j = 0; j < m; j++) {
                BigInteger a = j < msg0.length ? msg0[j] : null, b = j < msg1.length ? msg1[j] : null;
                if (a == null || b == null || a.signum() < 0 || b.signum() < 0 || a.compareTo(limit) >= 0 || b.compareTo(limit) >= 0) {
                    throw new IllegalArgumentException("OtChannel.extend: message " + j + " must be a bigint in [0, 2^64) (the pad is 64 bits wide)");
                }
            }
        }
    }

    /** The extension receiver (base-OT sender): makes the seed pairs, then per round the u matrix and KOS values. */
    public static final class OtExtReceiver {
        private final OtRandom rng;
        private final byte[] kosBinding;
        private final List<byte[]> seed0 = new ArrayList<>(), seed1 = new ArrayList<>();
        private final long[] blk0 = new long[KAPPA], blk1 = new long[KAPPA];
        private int round = 0;
        private long rowsDone = 0;
        private final int[] tweakDomain;
        public boolean ready = false;
        /** TEST-ONLY: mutate the u columns on the wire (a malicious receiver). */
        public BiConsumer<BigInteger[], Integer> tamperU;

        public OtExtReceiver(OtRandom rng, byte[] kosBinding) {
            this.rng = rng;
            this.kosBinding = kosBinding;
            this.tweakDomain = Otx.otTweakDomain(kosBinding);
        }

        /** The kappa seed pairs, to be transferred by the base OT with the sender's selector as choices. */
        public byte[][][] makeSeeds() {
            byte[][][] messages = new byte[KAPPA][2][];
            for (int i = 0; i < KAPPA; i++) {
                byte[] k0 = rng.bytes(SEED_BYTES);
                byte[] k1 = rng.bytes(SEED_BYTES);
                seed0.add(k0);
                seed1.add(k1);
                messages[i][0] = k0;
                messages[i][1] = k1;
            }
            ready = true;
            return messages;
        }

        public record Begin(ExtRoundMsg msg, ExtPending pending) {}

        public Begin begin(int[] choiceBits) {
            if (!ready) throw new IllegalStateException("OtExtReceiver: base OT not done");
            checkExtInputs(choiceBits, null, null);
            int m = choiceBits.length;
            int roundIdx = round++;
            long rowOffset = rowsDone;
            rowsDone += m;
            int pad = KAPPA + SSEC;
            int mExt = m + pad;
            int W = (mExt + 31) >>> 5;
            int colBytes = (mExt + 7) / 8;
            int[] bvec = new int[W];
            for (int j = 0; j < m; j++) if ((choiceBits[j] & 1) != 0) bvec[j >>> 5] |= 1 << (j & 31);
            byte[] padBytes = rng.bytes(pad);
            for (int p = 0; p < pad; p++) {
                if ((padBytes[p] & 1) != 0) {
                    int j = m + p;
                    bvec[j >>> 5] |= 1 << (j & 31);
                }
            }
            int blocks = (W + 3) / 4;
            int[] t = new int[COLS * W];
            BigInteger[] u = new BigInteger[COLS];
            int[] uw = new int[W];
            byte[][] ubytes = new byte[COLS][];
            for (int i = 0; i < KAPPA; i++) {
                int[] ti = Otx.prgColumn(seed0.get(i), blk0[i], W);
                int[] gi = Otx.prgColumn(seed1.get(i), blk1[i], W);
                blk0[i] += blocks;
                blk1[i] += blocks;
                Otx.maskTail(ti, mExt);
                Otx.maskTail(gi, mExt);
                System.arraycopy(ti, 0, t, i * W, W);
                for (int w = 0; w < W; w++) uw[w] = gi[w] ^ ti[w] ^ bvec[w];
                byte[] all = new byte[4 * W];
                for (int w = 0; w < W; w++) {
                    all[4 * w] = (byte) uw[w];
                    all[4 * w + 1] = (byte) (uw[w] >>> 8);
                    all[4 * w + 2] = (byte) (uw[w] >>> 16);
                    all[4 * w + 3] = (byte) (uw[w] >>> 24);
                }
                ubytes[i] = Arrays.copyOf(all, colBytes);
                u[i] = Otx.bytesToBig(ubytes[i]);
            }
            if (tamperU != null) tamperU.accept(u, roundIdx);
            ExtPending pending = new ExtPending(m, choiceBits.clone(), t, W, rowOffset);
            BigInteger limit = BigInteger.ONE.shiftLeft(mExt);
            for (BigInteger c : u) {
                if (c == null || c.signum() < 0 || c.compareTo(limit) >= 0) return new Begin(new ExtRoundMsg(u, BigInteger.ZERO, BigInteger.ZERO), pending);
            }
            int[] chi = kosChiWords(kosBinding, roundIdx, u, mExt, tamperU != null ? null : ubytes);
            int[] x = new int[4];
            Otx.accumColumn(bvec, 0, W, chi, x);
            int[] tComb = Otx.kosCombine(t, W, chi);
            return new Begin(new ExtRoundMsg(u, Otx.gfToBig(x), Otx.gfToBig(tComb)), pending);
        }

        /** The receiver's outputs: m_{c_j} for every row j, from the sender's ciphertexts. */
        public BigInteger[] finish(ExtPending pending, BigInteger[] y0, BigInteger[] y1) {
            int m = pending.m();
            if (y0.length != m || y1.length != m) throw new MalOtAbort("OT extension: ciphertext count does not match the number of rows; aborting");
            int[] rows = Otx.transposeCols(pending.t(), pending.W(), m);
            int[] h = Otx.tmmoCrh(rows, m, new Otx.OtTweak(pending.rowOffset(), tweakDomain));
            BigInteger[] received = new BigInteger[m];
            for (int j = 0; j < m; j++) received[j] = (pending.choiceBits()[j] == 1 ? y1[j] : y0[j]).xor(Otx.word64(h, j));
            return received;
        }
    }

    /** The extension sender (base-OT receiver): holds the secret selector s and answers each round after the KOS check. */
    public static final class OtExtSender {
        private final OtRandom rng;
        private final byte[] kosBinding;
        private int[] s = new int[0];
        private BigInteger sBits = BigInteger.ZERO;
        private byte[][] seeds = new byte[0][];
        private long[] blk = new long[0];
        private int round = 0;
        private long rowsDone = 0;
        private final int[] tweakDomain;
        public boolean ready = false;

        public OtExtSender(OtRandom rng, byte[] kosBinding) {
            this.rng = rng;
            this.kosBinding = kosBinding;
            this.tweakDomain = Otx.otTweakDomain(kosBinding);
        }

        public int[] makeSelector() {
            s = new int[KAPPA];
            for (int i = 0; i < KAPPA; i++) s[i] = rng.bytes(1)[0] & 1;
            return s.clone();
        }

        public void setSeeds(byte[][] seeds) {
            if (seeds.length != KAPPA || s.length != KAPPA) throw new IllegalStateException("OtExtSender: wrong base-OT output size");
            this.seeds = seeds;
            this.blk = new long[KAPPA];
            BigInteger acc = BigInteger.ZERO;
            for (int i = 0; i < KAPPA; i++) if (s[i] == 1) acc = acc.setBit(i);
            this.sBits = acc;
            this.ready = true;
        }

        public BigInteger selector() { return sBits; }

        public record Response(BigInteger[] y0, BigInteger[] y1) {}

        public Response respond(ExtRoundMsg msg, BigInteger[] msg0, BigInteger[] msg1) {
            if (!ready) throw new IllegalStateException("OtExtSender: base OT not done");
            int m = msg0.length;
            if (msg1.length != m) throw new IllegalArgumentException("OtChannel.extend: length mismatch");
            checkExtInputs(new int[m], msg0, msg1);
            int roundIdx = round++;
            long rowOffset = rowsDone;
            rowsDone += m;
            int mExt = m + KAPPA + SSEC;
            BigInteger[] u = msg.u();
            if (u == null || u.length != KAPPA) {
                throw new MalOtAbort("KOS check (round " + roundIdx + "): wrong number of u columns; a cheating OT-extension receiver was detected; aborting");
            }
            BigInteger colLimit = BigInteger.ONE.shiftLeft(mExt);
            for (int i = 0; i < KAPPA; i++) {
                BigInteger ui = u[i];
                if (ui == null || ui.signum() < 0 || ui.compareTo(colLimit) >= 0) {
                    throw new MalOtAbort("KOS check (round " + roundIdx + "): malformed u column " + i + "; a cheating OT-extension receiver was detected; aborting");
                }
            }
            BigInteger lim128 = BigInteger.ONE.shiftLeft(128);
            if (msg.x() == null || msg.tComb() == null || msg.x().signum() < 0 || msg.x().compareTo(lim128) >= 0 || msg.tComb().signum() < 0 || msg.tComb().compareTo(lim128) >= 0) {
                throw new MalOtAbort("KOS check (round " + roundIdx + "): malformed (x, t); a cheating OT-extension receiver was detected; aborting");
            }
            int W = (mExt + 31) >>> 5;
            int colBytes = (mExt + 7) / 8;
            int blocks = (W + 3) / 4;
            int[] q = new int[COLS * W];
            byte[][] ubytes = new byte[COLS][];
            for (int i = 0; i < KAPPA; i++) {
                ubytes[i] = Otx.bigToBytes(u[i], colBytes);
                int[] ks = Otx.prgColumn(seeds[i], blk[i], W);
                blk[i] += blocks;
                Otx.maskTail(ks, mExt);
                if (s[i] == 1) {
                    byte[] ub = new byte[4 * W];
                    System.arraycopy(ubytes[i], 0, ub, 0, ubytes[i].length);
                    int[] uw = Otx.wordsFromLeBytes(ub, W);
                    for (int w = 0; w < W; w++) ks[w] ^= uw[w];
                }
                System.arraycopy(ks, 0, q, i * W, W);
            }
            int[] chi = kosChiWords(kosBinding, roundIdx, u, mExt, ubytes);
            BigInteger qComb = Otx.gfToBig(Otx.kosCombine(q, W, chi));
            BigInteger expected = msg.tComb().xor(Gf128.mul(msg.x(), sBits));
            if (!qComb.equals(expected)) {
                throw new MalOtAbort("KOS correlation check FAILED (round " + roundIdx + "): a cheating OT-extension receiver was detected; aborting");
            }
            int[] rows = Otx.transposeCols(q, W, m);
            Otx.OtTweak tweak = new Otx.OtTweak(rowOffset, tweakDomain);
            int[] h0 = Otx.tmmoCrh(rows, m, tweak);
            int[] sw = Otx.gfFromBig(sBits);
            int[] row = new int[4];
            for (int j = 0; j < m; j++) {
                System.arraycopy(rows, 4 * j, row, 0, 4);
                Otx.gfXorInto(row, sw, 0);
                System.arraycopy(row, 0, rows, 4 * j, 4);
            }
            int[] h1 = Otx.tmmoCrh(rows, m, tweak);
            BigInteger[] y0 = new BigInteger[m], y1 = new BigInteger[m];
            for (int j = 0; j < m; j++) {
                y0[j] = msg0[j].xor(Otx.word64(h0, j));
                y1[j] = msg1[j].xor(Otx.word64(h1, j));
            }
            return new Response(y0, y1);
        }
    }

    /**
     * An in-process OT-extension channel: one base-OT setup (kappa transfers) is amortised over every later extend(). The base
     * OT is the EC base OT unless {@code baseOtFn} supplies another (for example a post-quantum one).
     */
    public static final class OtChannel {
        private final OtRandom rng;
        private final BaseOtFn baseOtFn;
        private final BaseOtBinding bindingOpt;
        private OtExtReceiver recv;
        private OtExtSender send;
        private boolean ready = false;
        /** The EC base-OT transcript of the kappa setup transfers (null when a custom base OT is used). */
        public BaseOtTranscript baseTranscript;
        /** TEST-ONLY: mutate the extension receiver's u matrix. */
        public BiConsumer<BigInteger[], Integer> tamperU;

        /** @param binding only sessionId, senderIndex and receiverIndex are used; its round is ignored. May be null. */
        public OtChannel(OtRandom rng, BaseOtFn baseOtFn, BaseOtBinding binding) {
            this.rng = rng == null ? secureOtRandom() : rng;
            this.baseOtFn = baseOtFn;
            this.bindingOpt = binding;
        }

        public OtChannel(OtRandom rng) { this(rng, null, null); }

        private void setup() {
            BaseOtBinding base = bindingOpt != null ? bindingOpt : randomBinding(rng, "x");
            byte[] kos = bindingBytes(new BaseOtBinding(base.sessionId(), base.senderIndex(), base.receiverIndex(), "iknp-kos"));
            OtExtReceiver r = new OtExtReceiver(rng, kos);
            OtExtSender sd = new OtExtSender(rng, kos);
            byte[][][] messages = r.makeSeeds();
            int[] sel = sd.makeSelector();
            if (baseOtFn != null) {
                sd.setSeeds(baseOtFn.run(messages, sel, rng));
            } else {
                BaseOtResult res = baseOT(messages, sel, rng, null, new BaseOtBinding(base.sessionId(), base.senderIndex(), base.receiverIndex(), "iknp-kappa-setup"));
                sd.setSeeds(res.received());
                baseTranscript = res.transcript();
            }
            recv = r;
            send = sd;
            ready = true;
        }

        public BigInteger selector() {
            if (!ready) setup();
            return send.selector();
        }

        public record Extended(BigInteger[] received, BigInteger[] uMatrix) {}

        public Extended extend(int[] choiceBits, BigInteger[] msg0, BigInteger[] msg1) {
            if (!ready) setup();
            int m = choiceBits.length;
            if (msg0.length != m || msg1.length != m) throw new IllegalArgumentException("OtChannel.extend: length mismatch");
            if (m == 0) return new Extended(new BigInteger[0], new BigInteger[0]);
            checkExtInputs(choiceBits, msg0, msg1);
            recv.tamperU = tamperU;
            OtExtReceiver.Begin b = recv.begin(choiceBits);
            OtExtSender.Response r = send.respond(b.msg(), msg0, msg1);
            return new Extended(recv.finish(b.pending(), r.y0(), r.y1()), b.msg().u());
        }
    }
}
