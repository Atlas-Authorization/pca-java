package net.atlasauth.pca.mpc;

import static net.atlasauth.pca.mpc.Field.mod;

import java.math.BigInteger;
import net.atlasauth.pca.mpc.Field.FieldSource;

/**
 * Privacy-amplified OT choice-bit encoding (the selective-failure remedy): the receiver chooses with m = 61 + 3s uniform
 * bits b and takes x = sum g_k b_k (mod p) for a public gadget vector g. s = 0 is the legacy plain binary encoding.
 */
public final class Enc {
    private Enc() {}

    public static final int FIELD_BITS = 61;
    public static final int STAT_SEC = 64;
    public static final int MIN_STAT_SEC = 40;

    public static int encBits(int s) { return FIELD_BITS + 3 * s; }

    /** A receiver operand: its field value together with the choice bits that encode it. */
    public record EncShare(BigInteger value, int[] bits) {}

    public static BigInteger[] makeGadget(int s, FieldSource next, boolean unsafe) {
        if (s < 0 || s > 64) throw new IllegalArgumentException("statSec must be an integer in [0, 64]");
        if (s < MIN_STAT_SEC && !unsafe) {
            throw new IllegalArgumentException("statSec " + s + " is below " + MIN_STAT_SEC + ": refused (tests may pass the explicit unsafe flag)");
        }
        int m = encBits(s);
        BigInteger[] g = new BigInteger[m];
        for (int k = 0; k < m; k++) g[k] = s == 0 ? mod(BigInteger.ONE.shiftLeft(k)) : next.next();
        return g;
    }

    public static BigInteger encValue(BigInteger[] g, int[] bits) {
        if (g.length != bits.length) throw new IllegalArgumentException("encValue: gadget / bits length mismatch");
        BigInteger v = BigInteger.ZERO;
        for (int k = 0; k < g.length; k++) if (bits[k] == 1) v = v.add(g[k]);
        return mod(v);
    }

    public static EncShare plainShare(BigInteger x) {
        BigInteger v = mod(x);
        int[] bits = new int[FIELD_BITS];
        for (int k = 0; k < FIELD_BITS; k++) bits[k] = v.testBit(k) ? 1 : 0;
        return new EncShare(v, bits);
    }

    public static BigInteger[] plainGadget() {
        BigInteger[] g = new BigInteger[FIELD_BITS];
        for (int k = 0; k < FIELD_BITS; k++) g[k] = mod(BigInteger.ONE.shiftLeft(k));
        return g;
    }

    /** m uniform bits from a field source (the 60 low bits of each draw are uniform). */
    public static int[] randomBits(int m, FieldSource rng) {
        int[] out = new int[m];
        int k = 0;
        while (k < m) {
            BigInteger w = rng.next();
            for (int i = 0; i < 60 && k < m; i++, k++) out[k] = w.testBit(i) ? 1 : 0;
        }
        return out;
    }

    public static EncShare sampleEnc(BigInteger[] g, FieldSource rng) {
        int[] bits = randomBits(g.length, rng);
        return new EncShare(encValue(g, bits), bits);
    }
}
