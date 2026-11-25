package net.atlasauth.pca.mpc;

import static net.atlasauth.pca.mpc.Field.fadd;
import static net.atlasauth.pca.mpc.Field.fmul;
import static net.atlasauth.pca.mpc.Field.fneg;
import static net.atlasauth.pca.mpc.Field.fsub;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Pairwise-authenticated field shares for the identifiable-abort mode of the networked runner: each share carries one tag per
 * verifier and one key per peer, so a bad opening is attributable to the party that sent it. The operations are linear and local.
 */
public final class NetPa {
    private NetPa() {}

    /** x with tag[j] (my tag for verifier j) and key[j] (my key for verifying j's share). */
    public record PA(BigInteger x, BigInteger[] tag, BigInteger[] key) {}

    /** An authenticated value: a value share plus one MAC share per global key, each pairwise-authenticated. */
    public record AW(PA v, PA[] m) {}

    public record PaEnv(int id, int n, BigInteger delta, boolean tagged) {}

    private interface Op { BigInteger f(BigInteger a, BigInteger b); }

    private static BigInteger[] zip(BigInteger[] a, BigInteger[] b, Op f) {
        BigInteger[] o = new BigInteger[a.length];
        for (int i = 0; i < a.length; i++) o[i] = f.f(a[i], b[i]);
        return o;
    }

    private static BigInteger[] map(BigInteger[] a, java.util.function.UnaryOperator<BigInteger> f) {
        BigInteger[] o = new BigInteger[a.length];
        for (int i = 0; i < a.length; i++) o[i] = f.apply(a[i]);
        return o;
    }

    public static PA paAdd(PA a, PA b) { return new PA(fadd(a.x(), b.x()), zip(a.tag(), b.tag(), Field::fadd), zip(a.key(), b.key(), Field::fadd)); }
    public static PA paSub(PA a, PA b) { return new PA(fsub(a.x(), b.x()), zip(a.tag(), b.tag(), Field::fsub), zip(a.key(), b.key(), Field::fsub)); }
    public static PA paNeg(PA a) { return new PA(fneg(a.x()), map(a.tag(), Field::fneg), map(a.key(), Field::fneg)); }
    public static PA paScale(PA a, BigInteger c) { return new PA(fmul(a.x(), c), map(a.tag(), t -> fmul(t, c)), map(a.key(), k -> fmul(k, c))); }

    /** Adds a PUBLIC constant to party 0's share (every party applies the same call). */
    public static PA paAddPublic0(PaEnv env, PA a, BigInteger c) {
        if (env.id() == 0) return new PA(fadd(a.x(), c), a.tag(), a.key());
        if (!env.tagged()) return a;
        BigInteger[] key = a.key().clone();
        key[0] = fsub(key[0], fmul(env.delta(), c));
        return new PA(a.x(), a.tag(), key);
    }

    private static PA[] each(PA[] a, java.util.function.UnaryOperator<PA> f) {
        PA[] o = new PA[a.length];
        for (int i = 0; i < a.length; i++) o[i] = f.apply(a[i]);
        return o;
    }

    public static AW wAdd(AW a, AW b) {
        PA[] m = new PA[a.m().length];
        for (int l = 0; l < m.length; l++) m[l] = paAdd(a.m()[l], b.m()[l]);
        return new AW(paAdd(a.v(), b.v()), m);
    }

    public static AW wSub(AW a, AW b) {
        PA[] m = new PA[a.m().length];
        for (int l = 0; l < m.length; l++) m[l] = paSub(a.m()[l], b.m()[l]);
        return new AW(paSub(a.v(), b.v()), m);
    }

    public static AW wNeg(AW a) { return new AW(paNeg(a.v()), each(a.m(), NetPa::paNeg)); }

    public static AW wScale(AW a, BigInteger c) { return new AW(paScale(a.v(), c), each(a.m(), p -> paScale(p, c))); }

    /** x + c for a PUBLIC c: party 0's value share moves by c and every MAC share moves by alpha_i * c. */
    public static AW wAddPublic(PaEnv env, AW a, BigInteger c, PA[] alpha) {
        PA[] m = new PA[a.m().length];
        for (int l = 0; l < m.length; l++) m[l] = paAdd(a.m()[l], paScale(alpha[l], c));
        return new AW(paAddPublic0(env, a.v(), c), m);
    }

    /** Verifies peer {@code from}'s opened share x with tag against my key for that peer. */
    public static boolean paVerify(PaEnv env, PA a, int from, BigInteger x, BigInteger tag) {
        return fadd(a.key()[from], fmul(env.delta(), x)).equals(tag);
    }

    // ---- wire codec ----

    public static int paWidth(int n, boolean tagged) { return tagged ? 1 + 2 * (n - 1) : 1; }

    public static List<BigInteger> paFlat(PA a, int id, int n, boolean tagged) {
        List<BigInteger> out = new ArrayList<>();
        out.add(a.x());
        if (tagged) {
            for (int j = 0; j < n; j++) if (j != id) out.add(a.tag()[j]);
            for (int j = 0; j < n; j++) if (j != id) out.add(a.key()[j]);
        }
        return out;
    }

    public static PA paParse(List<BigInteger> nums, int off, int id, int n, boolean tagged) {
        BigInteger x = nums.get(off);
        if (!tagged) return new PA(x, new BigInteger[0], new BigInteger[0]);
        BigInteger[] tag = new BigInteger[n], key = new BigInteger[n];
        Arrays.fill(tag, BigInteger.ZERO);
        Arrays.fill(key, BigInteger.ZERO);
        int o = off + 1;
        for (int j = 0; j < n; j++) if (j != id) tag[j] = nums.get(o++);
        for (int j = 0; j < n; j++) if (j != id) key[j] = nums.get(o++);
        return new PA(x, tag, key);
    }

    public static int awWidth(int n, int keys, boolean tagged) { return (1 + keys) * paWidth(n, tagged); }

    public static List<BigInteger> awFlat(AW a, int id, int n, boolean tagged) {
        List<BigInteger> out = new ArrayList<>(paFlat(a.v(), id, n, tagged));
        for (PA p : a.m()) out.addAll(paFlat(p, id, n, tagged));
        return out;
    }

    public static AW awParse(List<BigInteger> nums, int off, int id, int n, int keys, boolean tagged) {
        int w = paWidth(n, tagged);
        PA v = paParse(nums, off, id, n, tagged);
        PA[] m = new PA[keys];
        for (int l = 0; l < keys; l++) m[l] = paParse(nums, off + (1 + l) * w, id, n, tagged);
        return new AW(v, m);
    }
}
