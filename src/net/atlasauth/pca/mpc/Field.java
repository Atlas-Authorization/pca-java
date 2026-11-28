package net.atlasauth.pca.mpc;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Arithmetic in the prime field F_p (p = 2^61 - 1) used for additive secret sharing, plus the field randomness
 * sources: a deterministic SplitMix64 {@link FieldRng} (reproducible tests behind an explicit seed) and the CSPRNG
 * {@link SecureFieldRng} (the default for protocol randomness). All arithmetic is exact BigInteger.
 */
public final class Field {
    private Field() {}

    public static final BigInteger PRIME = BigInteger.ONE.shiftLeft(61).subtract(BigInteger.ONE);
    static final long PRIME_LONG = (1L << 61) - 1;
    // Largest multiple of p that fits in 64 bits is 2^64 - 8; anything at or above it is rejected so `% p` is uniform.
    static final long LIMIT = -8L;

    /** Canonical representative in [0, p). */
    public static BigInteger mod(BigInteger x) { return x.mod(PRIME); }
    public static BigInteger fadd(BigInteger a, BigInteger b) { return mod(a.add(b)); }
    public static BigInteger fsub(BigInteger a, BigInteger b) { return mod(a.subtract(b)); }
    public static BigInteger fmul(BigInteger a, BigInteger b) { return mod(a.multiply(b)); }
    public static BigInteger fneg(BigInteger a) { return mod(a.negate()); }

    /** A source of uniform field elements. */
    public interface FieldSource { BigInteger next(); }

    /** Deterministic SplitMix64 drawing unbiased field elements by rejection sampling. */
    public static class FieldRng implements FieldSource {
        private long s;

        public FieldRng() { this(new BigInteger("243f6a8885a308d3", 16)); }
        public FieldRng(BigInteger seed) { this.s = seed.longValue(); }

        long nextU64() {
            s += 0x9e3779b97f4a7c15L;
            long z = s;
            z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
            z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
            return z ^ (z >>> 31);
        }

        @Override public BigInteger next() {
            for (;;) {
                long u = nextU64();
                if (Long.compareUnsigned(u, LIMIT) < 0) return BigInteger.valueOf(Long.remainderUnsigned(u, PRIME_LONG));
            }
        }
    }

    /** CSPRNG-backed field source: fresh SecureRandom bytes, rejection sampled. */
    public static final class SecureFieldRng extends FieldRng {
        private final SecureRandom rnd;
        public SecureFieldRng() { this(new SecureRandom()); }
        public SecureFieldRng(SecureRandom rnd) { super(BigInteger.ZERO); this.rnd = rnd; }

        @Override public BigInteger next() {
            byte[] b = new byte[8];
            for (;;) {
                rnd.nextBytes(b);
                long u = 0;
                for (int i = 0; i < 8; i++) u = (u << 8) | (b[i] & 0xffL);
                if (Long.compareUnsigned(u, LIMIT) < 0) return BigInteger.valueOf(Long.remainderUnsigned(u, PRIME_LONG));
            }
        }
    }

    /** CSPRNG by default, a reproducible seeded {@link FieldRng} only when {@code testSeed} is non-null. */
    public static FieldSource fieldRandom(BigInteger testSeed) {
        return testSeed == null ? new SecureFieldRng() : new FieldRng(testSeed);
    }
}
