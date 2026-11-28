package net.atlasauth.pca.mpc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Word-array kernels for the OT-extension hot path: AES-128-CTR column PRG, 32x32 bit transposes, GF(2^128) on four
 * little-endian u32 words (an {@code int[]} holds unsigned words), and the batched tweakable correlation-robust hash
 * H(x, t) = pi(pi(x) ^ t) ^ pi(x) with a fixed-key AES-128 truncated to 64 bits.
 */
public final class Otx {
    private Otx() {}

    /** Number of bit columns of the IKNP matrix (kappa). */
    public static final int COLS = 128;

    private static final byte[] TAG_PRG_KEY = "atlas-pca-mpc/ot-prg-aes".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TAG_CRH_KEY = "atlas-pca-mpc/ot-crh-aes-fixed-key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TAG_TWEAK_DOMAIN = "atlas-pca-mpc/ot-crh-tweak-domain/v2".getBytes(StandardCharsets.UTF_8);

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Little-endian bytes of a non-negative bigint, exactly {@code len} bytes (the low bytes). */
    public static byte[] bigToBytes(BigInteger v, int len) {
        byte[] out = new byte[len];
        BigInteger x = v;
        for (int i = 0; i < len; i++) {
            out[i] = (byte) x.and(BigInteger.valueOf(0xff)).intValue();
            x = x.shiftRight(8);
        }
        return out;
    }

    /** The bigint with the given little-endian bytes. */
    public static BigInteger bytesToBig(byte[] b) {
        byte[] be = new byte[b.length];
        for (int i = 0; i < b.length; i++) be[i] = b[b.length - 1 - i];
        return new BigInteger(1, be);
    }

    private static byte[] prgKey(byte[] seed) {
        MessageDigest md = sha256();
        md.update(TAG_PRG_KEY);
        md.update(seed);
        return java.util.Arrays.copyOf(md.digest(), 16);
    }

    private static int[] leWords(byte[] b, int off, int n) {
        int[] out = new int[n];
        for (int i = 0; i < n; i++) {
            int o = off + 4 * i;
            out[i] = (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8) | ((b[o + 2] & 0xff) << 16) | ((b[o + 3] & 0xff) << 24);
        }
        return out;
    }

    private static byte[] leBytes(int[] w, int n) {
        byte[] out = new byte[4 * n];
        for (int i = 0; i < n; i++) {
            out[4 * i] = (byte) w[i];
            out[4 * i + 1] = (byte) (w[i] >>> 8);
            out[4 * i + 2] = (byte) (w[i] >>> 16);
            out[4 * i + 3] = (byte) (w[i] >>> 24);
        }
        return out;
    }

    /** {@code nwords} u32 words of the PRG stream of {@code seed} from AES block {@code startBlock} (high tail bits unmasked). */
    public static int[] prgColumn(byte[] seed, long startBlock, int nwords) {
        byte[] iv = new byte[16];
        for (int i = 0; i < 8; i++) iv[15 - i] = (byte) (startBlock >>> (8 * i));
        try {
            Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(prgKey(seed), "AES"), new IvParameterSpec(iv));
            return leWords(c.doFinal(new byte[nwords * 4]), 0, nwords);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Clears the bits at positions >= nbits in a little-endian word column. */
    public static void maskTail(int[] col, int nbits) {
        int full = nbits >>> 5;
        int rem = nbits & 31;
        if (rem != 0) col[full] &= (1 << rem) - 1;
        for (int i = rem != 0 ? full + 1 : full; i < col.length; i++) col[i] = 0;
    }

    /** In-place transpose of a 32x32 bit matrix held as 32 u32 words from {@code off}. */
    public static void transpose32(int[] a, int off) {
        int m = 0x0000ffff;
        for (int j = 16; j != 0; j >>>= 1, m = m ^ (m << j)) {
            for (int k = 0; k < 32; k = (k + j + 1) & ~j) {
                int t = ((a[off + k] >>> j) ^ a[off + k + j]) & m;
                a[off + k] ^= t << j;
                a[off + k + j] ^= t;
            }
        }
    }

    /** Transposes COLS bit-columns (each {@code W} words, concatenated) into {@code rows} rows of four words. */
    public static int[] transposeCols(int[] cols, int W, int rows) {
        int[] out = new int[rows * 4];
        int[] tmp = new int[32];
        int blocks = (rows + 31) >>> 5;
        for (int rb = 0; rb < blocks; rb++) {
            for (int cb = 0; cb < 4; cb++) {
                for (int c = 0; c < 32; c++) tmp[c] = cols[(cb * 32 + c) * W + rb];
                transpose32(tmp, 0);
                int lim = Math.min(32, rows - rb * 32);
                for (int r = 0; r < lim; r++) out[(rb * 32 + r) * 4 + cb] = tmp[r];
            }
        }
        return out;
    }

    /** acc ^= the four-word element at {@code v[vo..]}. */
    public static void gfXorInto(int[] acc, int[] v, int vo) {
        acc[0] ^= v[vo];
        acc[1] ^= v[vo + 1];
        acc[2] ^= v[vo + 2];
        acc[3] ^= v[vo + 3];
    }

    /** acc *= x in GF(2^128) (x^128 = x^7 + x^2 + x + 1). */
    public static void gfMulX(int[] acc) {
        int carry = acc[3] >>> 31;
        acc[3] = (acc[3] << 1) | (acc[2] >>> 31);
        acc[2] = (acc[2] << 1) | (acc[1] >>> 31);
        acc[1] = (acc[1] << 1) | (acc[0] >>> 31);
        acc[0] = (acc[0] << 1) ^ (carry != 0 ? 0x87 : 0);
    }

    /** XORs into {@code acc} chi[j] (four words) for every set bit j of the word column {@code col[off..off+len)}. */
    public static void accumColumn(int[] col, int off, int len, int[] chi, int[] acc) {
        for (int w = 0; w < len; w++) {
            int x = col[off + w];
            int base = w << 5;
            while (x != 0) {
                int j = base + Integer.numberOfTrailingZeros(x);
                int o = j << 2;
                acc[0] ^= chi[o];
                acc[1] ^= chi[o + 1];
                acc[2] ^= chi[o + 2];
                acc[3] ^= chi[o + 3];
                x &= x - 1;
            }
        }
    }

    /** sum_i x^i * (sum_{j in col_i} chi_j) by Horner over the columns: the KOS combination of both roles. */
    public static int[] kosCombine(int[] cols, int W, int[] chi) {
        int[] acc = new int[4];
        int[] part = new int[4];
        for (int i = COLS - 1; i >= 0; i--) {
            gfMulX(acc);
            java.util.Arrays.fill(part, 0);
            accumColumn(cols, i * W, W, chi, part);
            gfXorInto(acc, part, 0);
        }
        return acc;
    }

    public static int[] gfFromBig(BigInteger v) {
        int[] out = new int[4];
        for (int i = 0; i < 4; i++) out[i] = v.shiftRight(32 * i).intValue();
        return out;
    }

    public static BigInteger gfToBig(int[] w, int off) {
        BigInteger v = BigInteger.ZERO;
        for (int i = 3; i >= 0; i--) v = v.shiftLeft(32).or(BigInteger.valueOf(w[off + i] & 0xffffffffL));
        return v;
    }

    public static BigInteger gfToBig(int[] w) { return gfToBig(w, 0); }

    private static byte[] crhKey() {
        MessageDigest md = sha256();
        md.update(TAG_CRH_KEY);
        return java.util.Arrays.copyOf(md.digest(), 16);
    }

    private static byte[] aesEcb(byte[] buf) {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(crhKey(), "AES"));
            return c.doFinal(buf);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The 64-bit session domain of a channel: SHA-256(tag, binding)[0..8] as two little-endian words. */
    public static int[] otTweakDomain(byte[] binding) {
        MessageDigest md = sha256();
        md.update(TAG_TWEAK_DOMAIN);
        md.update(binding);
        return leWords(md.digest(), 0, 2);
    }

    /** Tweak of a hash call: channel-global row offset plus the 2-word session domain. */
    public record OtTweak(long offset, int[] domain) {}

    /** H(tweak, row_j) for n rows of four words: two u32 words per row (the low 64 bits of the TMMO hash). */
    public static int[] tmmoCrh(int[] rows, int n, OtTweak tweak) {
        long offset = tweak == null ? 0 : tweak.offset();
        int[] dom = tweak == null ? new int[2] : tweak.domain();
        if (offset < 0 || offset > (1L << 53) - 1) throw new IllegalArgumentException("tmmoCrh: tweak offset must be a non-negative safe integer");
        if (dom.length != 2) throw new IllegalArgumentException("tmmoCrh: tweak domain must be 2 words");
        byte[] a = aesEcb(leBytes(rows, n * 4));
        int[] aw = leWords(a, 0, n * 4);
        int[] b = new int[n * 4];
        for (int j = 0; j < n; j++) {
            int o = j * 4;
            long v = offset + j;
            b[o] = aw[o] ^ (int) v;
            b[o + 1] = aw[o + 1] ^ (int) (v >>> 32);
            b[o + 2] = aw[o + 2] ^ dom[0];
            b[o + 3] = aw[o + 3] ^ dom[1];
        }
        int[] cw = leWords(aesEcb(leBytes(b, n * 4)), 0, n * 4);
        int[] out = new int[n * 2];
        for (int j = 0; j < n; j++) {
            out[2 * j] = cw[4 * j] ^ aw[4 * j];
            out[2 * j + 1] = cw[4 * j + 1] ^ aw[4 * j + 1];
        }
        return out;
    }

    /** The 64-bit value of the two words at index j of a {@link #tmmoCrh} output. */
    public static BigInteger word64(int[] h, int j) {
        return BigInteger.valueOf(h[2 * j + 1] & 0xffffffffL).shiftLeft(32).or(BigInteger.valueOf(h[2 * j] & 0xffffffffL));
    }

    static int[] wordsFromLeBytes(byte[] b, int nwords) { return leWords(b, 0, nwords); }
}
