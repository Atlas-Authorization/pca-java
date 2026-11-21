package net.atlasauth.pca.mpc;

import static net.atlasauth.pca.mpc.Field.fadd;
import static net.atlasauth.pca.mpc.Field.fmul;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import net.atlasauth.pca.mpc.Field.FieldSource;

/** Secure multiplication of two additively-shared values with Beaver triples (a trusted dealer supplies the triples). */
public final class Beaver {
    private Beaver() {}

    /** A Beaver triple (a, b, c = a*b), each component additively shared. */
    public record Triple(BigInteger[] a, BigInteger[] b, BigInteger[] c) {}

    /** One opened (public) protocol message; {@code label} is "d" or "e". */
    public record OpenedMsg(String label, BigInteger value, BigInteger[] shares) {}

    public static List<Triple> genTriples(int count, int n, FieldSource rng) {
        List<Triple> out = new ArrayList<>();
        for (int i = 0; i < count; i++) out.add(genTriple(n, rng));
        return out;
    }

    public static Triple genTriple(int n, FieldSource rng) {
        BigInteger a = rng.next();
        BigInteger b = rng.next();
        BigInteger c = fmul(a, b);
        return new Triple(Sharing.share(a, n, rng), Sharing.share(b, n, rng), Sharing.share(c, n, rng));
    }

    /** x*y consuming {@code triple}; every opened value is appended to {@code transcript} when non-null. */
    public static BigInteger[] beaverMul(BigInteger[] x, BigInteger[] y, Triple triple, List<OpenedMsg> transcript) {
        if (x.length != y.length) throw new IllegalArgumentException("beaverMul: operand party counts differ");
        for (BigInteger[] part : new BigInteger[][] {triple.a(), triple.b(), triple.c()}) {
            if (part == null || part.length != x.length) throw new IllegalArgumentException("beaverMul: triple party count differs from the operands");
        }
        BigInteger[] dShares = Sharing.subSV(x, triple.a());
        BigInteger[] eShares = Sharing.subSV(y, triple.b());
        BigInteger d = Sharing.reconstruct(dShares);
        BigInteger e = Sharing.reconstruct(eShares);
        if (transcript != null) {
            transcript.add(new OpenedMsg("d", d, dShares));
            transcript.add(new OpenedMsg("e", e, eShares));
        }
        BigInteger de = fmul(d, e);
        BigInteger[] z = new BigInteger[x.length];
        for (int i = 0; i < z.length; i++) {
            BigInteger zi = fadd(triple.c()[i], fadd(fmul(d, triple.b()[i]), fmul(e, triple.a()[i])));
            z[i] = i == 0 ? fadd(zi, de) : zi;
        }
        return z;
    }
}
