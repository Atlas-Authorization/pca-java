package net.atlasauth.pca.invariants;

import java.util.List;

/**
 * mulberry32, the seeded generator behind every generated case of the invariant checks: the same seed always yields the same
 * sequence, so a failing case is reproducible from {@code (seed, run index)}. No randomness from the platform is used.
 */
public final class Rng {
    private long a;

    public Rng(long seed) { this.a = seed & 0xffffffffL; }

    /** A double in [0, 1). */
    public double next() {
        a = (a + 0x6d2b79f5L) & 0xffffffffL;
        int t = (int) a;
        t = (t ^ (t >>> 15)) * (t | 1);
        t ^= t + (t ^ (t >>> 7)) * (t | 61);
        return ((t ^ (t >>> 14)) & 0xffffffffL) / 4294967296.0;
    }

    /** An integer in [lo, hi] inclusive. */
    public long integer(long lo, long hi) { return lo + (long) Math.floor(next() * (hi - lo + 1)); }

    public boolean bool() { return next() < 0.5; }

    public <T> T pick(List<T> xs) { return xs.get((int) integer(0, xs.size() - 1)); }

    @SafeVarargs public final <T> T pick(T... xs) { return xs[(int) integer(0, xs.length - 1)]; }

    public byte[] bytes(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) integer(0, 255);
        return b;
    }

    /** A double in [lo, hi], with the endpoints drawn on their own about one time in ten each (the edge cases a property must hold at). */
    public double real(double lo, double hi) {
        double x = next();
        if (x < 0.1) return lo;
        if (x < 0.2) return hi;
        return lo + next() * (hi - lo);
    }

    /** A printable-ASCII string of {@code min..max} characters. */
    public String string(int min, int max) {
        int n = (int) integer(min, max);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append((char) integer(0x20, 0x7e));
        return sb.toString();
    }
}
