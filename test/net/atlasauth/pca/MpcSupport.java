package net.atlasauth.pca;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.mpc.Field.FieldRng;
import net.atlasauth.pca.mpc.Party.DecisionVector;
import net.atlasauth.pca.mpc.Spdz;
import net.atlasauth.pca.mpc.Spdz.AuthSV;
import net.atlasauth.pca.mpc.Spdz.AuthTriple;
import net.atlasauth.pca.mpc.Spdz.Deviation;
import net.atlasauth.pca.mpc.Spdz.MacContext;
import net.atlasauth.pca.mpc.Spdz.MacKey;

/** Argument decoding and result encoding shared by the MPC differential tests (bigints travel as decimal strings). */
final class MpcSupport {
    private MpcSupport() {}

    static BigInteger B(Object o) {
        if (!(o instanceof String)) throw new IllegalArgumentException("bigint arg");
        return new BigInteger((String) o);
    }

    /** A JavaScript integer argument (a non-integer is the reference's Number.isInteger failure). */
    static int I(Object o) {
        Double d = OracleCases.num(o);
        if (d == null || d.isInfinite() || d != Math.rint(d)) throw new IllegalArgumentException("not an integer");
        if (Math.abs(d) > 1e9) return d > 0 ? Integer.MAX_VALUE : Integer.MIN_VALUE;
        return d.intValue();
    }

    static double D(Object o) {
        Double d = OracleCases.num(o);
        if (d == null) throw new IllegalArgumentException("not a number");
        return d;
    }

    static FieldRng rng(Object seed) { return new FieldRng(B(seed)); }

    static BigInteger[] BA(Object o) {
        List<?> l = (List<?>) o;
        BigInteger[] out = new BigInteger[l.size()];
        for (int i = 0; i < out.length; i++) out[i] = l.get(i) == null ? null : B(l.get(i));
        return out;
    }

    static BigInteger[][] BAA(Object o) {
        List<?> l = (List<?>) o;
        BigInteger[][] out = new BigInteger[l.size()][];
        for (int i = 0; i < out.length; i++) out[i] = BA(l.get(i));
        return out;
    }

    static int[] IA(Object o) {
        List<?> l = (List<?>) o;
        int[] out = new int[l.size()];
        for (int i = 0; i < out.length; i++) out[i] = I(l.get(i));
        return out;
    }

    static List<Object> L(BigInteger[] a) {
        List<Object> out = new ArrayList<>();
        for (BigInteger x : a) out.add(x == null ? null : x.toString());
        return out;
    }

    static List<Object> LL(BigInteger[][] a) {
        List<Object> out = new ArrayList<>();
        for (BigInteger[] x : a) out.add(L(x));
        return out;
    }

    static List<Object> L(int[] a) {
        List<Object> out = new ArrayList<>();
        for (int x : a) out.add(x);
        return out;
    }

    static Map<String, Object> M(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Object o) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("not an object");
        return (Map<String, Object>) o;
    }

    static List<DecisionVector> vectors(Object o) {
        if (!(o instanceof List)) throw new IllegalArgumentException("decision vectors must be an array");
        List<DecisionVector> out = new ArrayList<>();
        for (Object e : (List<?>) o) {
            if (!(e instanceof Map)) throw new IllegalArgumentException("decision vector must be an object");
            Map<String, Object> m = map(e);
            out.add(new DecisionVector(I(m.get("allow")), I(m.get("t")), I(m.get("rQuant"))));
        }
        return out;
    }

    static Map<String, Object> authSV(AuthSV x) { return M("value", L(x.value()), "mac", L(x.mac()), "extraMac", LL(x.extraMac())); }

    static Map<String, Object> triple(AuthTriple t) { return M("a", authSV(t.a()), "b", authSV(t.b()), "c", authSV(t.c())); }

    static Map<String, Object> key(MacKey k) { return M("alphaShares", L(k.alphaShares()), "alpha", k.alpha().toString()); }

    static Map<String, Object> ctx(MacContext c) {
        List<Object> extra = new ArrayList<>();
        for (MacKey k : c.extraKeys()) extra.add(key(k));
        return M("n", c.n(), "alphaShares", L(c.alphaShares()), "alpha", c.alpha().toString(), "extraKeys", extra);
    }

    static List<Deviation> devs(Object o) {
        List<Deviation> out = new ArrayList<>();
        for (Object e : (List<?>) o) {
            List<?> d = (List<?>) e;
            out.add(new Deviation(I(d.get(0)), I(d.get(1)), d.get(2) == null ? null : B(d.get(2)), d.get(3) == null ? null : B(d.get(3)),
                d.get(4) == null ? null : I(d.get(4))));
        }
        return out;
    }

    static Spdz.DealerFault fault(Object o) {
        if (o == null) return null;
        Map<String, Object> m = map(o);
        List<BigInteger> p = null;
        if (m.get("partnerCDelta") != null) {
            p = new ArrayList<>();
            for (Object x : (List<?>) m.get("partnerCDelta")) p.add(x == null ? null : B(x));
        }
        return new Spdz.DealerFault(m.get("keepCDelta") == null ? null : B(m.get("keepCDelta")), p);
    }
}
