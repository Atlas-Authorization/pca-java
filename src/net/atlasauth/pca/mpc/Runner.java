package net.atlasauth.pca.mpc;

import static net.atlasauth.pca.mpc.Sharing.notBitSV;
import static net.atlasauth.pca.mpc.Sharing.reconstruct;
import static net.atlasauth.pca.mpc.Sharing.share;
import static net.atlasauth.pca.mpc.Sharing.shareConstant;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import net.atlasauth.pca.mpc.Beaver.OpenedMsg;
import net.atlasauth.pca.mpc.Beaver.Triple;
import net.atlasauth.pca.mpc.Compose.ComposedDecision;
import net.atlasauth.pca.mpc.Field.FieldRng;
import net.atlasauth.pca.mpc.Field.FieldSource;
import net.atlasauth.pca.mpc.Party.DecisionVector;

/**
 * The simulated multi-party runner: all N parties in one process, exchanging shares and Beaver openings through
 * inspectable structures. {@link #composeSecure} computes exactly {@link Compose#composeClear} under MPC.
 */
public final class Runner {
    private Runner() {}

    private static final int T_M = 3;

    /** The full additive sharing of one party's secret bit (test inspection only). */
    public record SharingRecord(String label, int party, BigInteger secret, BigInteger[] shares) {}

    /** One party's complete view (a semi-honest corruption of that party). */
    public record PartyView(int party, List<BigInteger> heldShares, List<OpenedMsg> opened, ComposedDecision output) {}

    public record MpcResult(ComposedDecision composed, int parties, int Q, List<OpenedMsg> opened, List<SharingRecord> sharings,
                            List<PartyView> views, int multiplications) {}

    /** Composes under MPC. {@code seed} null means CSPRNG sharing randomness; a seed is for reproducible tests only. */
    public static MpcResult composeSecure(List<DecisionVector> vectors, Integer Qopt, BigInteger seed) {
        int n = vectors.size();
        if (n == 0) throw new IllegalArgumentException("composeSecure: no parties (fail closed)");
        int Q = Qopt == null ? Party.DEFAULT_Q : Qopt;
        Compose.assertDecisionVectors(vectors, Q);
        FieldSource rng = seed == null ? new Field.SecureFieldRng() : new FieldRng(seed);

        List<OpenedMsg> opened = new ArrayList<>();
        List<SharingRecord> sharings = new ArrayList<>();
        int[] mults = {0};

        class Ops {
            BigInteger[] shareBit(int bit, String label, int party) {
                BigInteger[] s = share(BigInteger.valueOf(bit), n, rng);
                sharings.add(new SharingRecord(label, party, BigInteger.valueOf(bit), s.clone()));
                return s;
            }
            BigInteger[] and(List<BigInteger[]> bits) {
                if (bits.isEmpty()) return shareConstant(BigInteger.ONE, n);
                BigInteger[] acc = bits.get(0);
                for (int i = 1; i < bits.size(); i++) {
                    acc = Beaver.beaverMul(acc, bits.get(i), Beaver.genTriple(n, rng), opened);
                    mults[0]++;
                }
                return acc;
            }
            BigInteger[] or(List<BigInteger[]> bits) {
                if (bits.isEmpty()) return shareConstant(BigInteger.ZERO, n);
                BigInteger[] prod = notBitSV(bits.get(0));
                for (int i = 1; i < bits.size(); i++) {
                    prod = Beaver.beaverMul(prod, notBitSV(bits.get(i)), Beaver.genTriple(n, rng), opened);
                    mults[0]++;
                }
                return notBitSV(prod);
            }
        }
        Ops ops = new Ops();

        List<BigInteger[]> allowBits = new ArrayList<>();
        for (int p = 0; p < n; p++) allowBits.add(ops.shareBit(vectors.get(p).allow(), "p" + p + ".allow", p));
        int allow = reconstruct(ops.and(allowBits)).equals(BigInteger.ONE) ? 1 : 0;

        int[][] tTherm = new int[n][];
        for (int p = 0; p < n; p++) tTherm[p] = Thermometer.thermometerEncode(vectors.get(p).t(), T_M);
        int[] tGe = new int[T_M];
        for (int k = 0; k < T_M; k++) {
            List<BigInteger[]> bitsAtK = new ArrayList<>();
            for (int p = 0; p < n; p++) bitsAtK.add(ops.shareBit(tTherm[p][k], "p" + p + ".t.ge" + (k + 1), p));
            tGe[k] = reconstruct(ops.or(bitsAtK)).equals(BigInteger.ONE) ? 1 : 0;
        }
        int t = Math.min(3, Math.max(1, Thermometer.thermometerDecode(tGe)));

        int[][] rTherm = new int[n][];
        for (int p = 0; p < n; p++) rTherm[p] = Thermometer.thermometerEncode(vectors.get(p).rQuant(), Q);
        int[] rGe = new int[Q];
        for (int k = 0; k < Q; k++) {
            List<BigInteger[]> bitsAtK = new ArrayList<>();
            for (int p = 0; p < n; p++) bitsAtK.add(ops.shareBit(rTherm[p][k], "p" + p + ".r.ge" + (k + 1), p));
            rGe[k] = reconstruct(ops.or(bitsAtK)).equals(BigInteger.ONE) ? 1 : 0;
        }
        int rQuant = Thermometer.thermometerDecode(rGe);

        ComposedDecision composed = new ComposedDecision(allow, t, rQuant);
        List<PartyView> views = new ArrayList<>();
        for (int p = 0; p < n; p++) {
            List<BigInteger> held = new ArrayList<>();
            for (SharingRecord s : sharings) held.add(s.shares()[p]);
            views.add(new PartyView(p, held, opened, composed));
        }
        return new MpcResult(composed, n, Q, opened, sharings, views, mults[0]);
    }
}
