package net.atlasauth.pca.mpc;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import net.atlasauth.pca.mpc.Compose.ComposedDecision;
import net.atlasauth.pca.mpc.Field.FieldRng;
import net.atlasauth.pca.mpc.Field.FieldSource;
import net.atlasauth.pca.mpc.Party.DecisionVector;
import net.atlasauth.pca.mpc.Spdz.AuthSV;
import net.atlasauth.pca.mpc.Spdz.AuthTriple;
import net.atlasauth.pca.mpc.Spdz.DealerFault;
import net.atlasauth.pca.mpc.Spdz.Deviation;
import net.atlasauth.pca.mpc.Spdz.MacContext;
import net.atlasauth.pca.mpc.Spdz.SpdzEngine;

/**
 * The malicious-secure (SPDZ) runner: the same composition as {@link Runner#composeSecure}, but every shared value carries a
 * MAC and nothing is accepted as output until the batched MAC-check passes (correct result or {@link Spdz.MacCheckAbort}).
 * Offline phase: a no-dealer provider (the default, OT-based), or an explicit trusted dealer with sacrifice-certified triples.
 */
public final class SpdzRunner {
    private SpdzRunner() {}

    /** Trusted-dealer options (honoured only with insecureTrustedDealer). Null verifyTriples means true. */
    public static final class DealerOptions {
        public Boolean verifyTriples;
        public Integer partners;
        public DealerFault fault;
    }

    public static final class MaliciousMpcConfig {
        public Integer Q;
        public BigInteger seed;
        public List<Deviation> deviations;
        public OfflineProvider offline;
        public boolean insecureTrustedDealer;
        public DealerOptions dealer;
    }

    public record MaliciousMpcResult(ComposedDecision composed, int parties, int Q, int opens, int multiplications, String offlineMode,
                                     boolean triplesVerified, boolean macChecked) {}

    private static final int T_M = 3;

    public static MaliciousMpcResult composeSecureMalicious(List<DecisionVector> vectors, MaliciousMpcConfig cfg) {
        if (cfg == null) cfg = new MaliciousMpcConfig();
        final MaliciousMpcConfig c = cfg;
        final int n = vectors.size();
        if (n == 0) throw new IllegalArgumentException("composeSecureMalicious: no parties (fail closed)");
        final int Q = c.Q == null ? Party.DEFAULT_Q : c.Q;
        Compose.assertDecisionVectors(vectors, Q);
        final FieldSource rng = c.seed == null ? new Field.SecureFieldRng() : new FieldRng(c.seed);

        if (c.offline != null && c.insecureTrustedDealer) {
            throw new IllegalStateException("composeSecureMalicious: offline and insecureTrustedDealer are mutually exclusive (fail closed)");
        }
        if (c.dealer != null && !c.insecureTrustedDealer && c.offline == null) {
            throw new IllegalStateException("composeSecureMalicious: dealer options require insecureTrustedDealer: true (fail closed)");
        }
        final OfflineProvider offline = c.offline != null ? c.offline : c.insecureTrustedDealer ? null : Mascot.makeNoDealerOffline(n, c.seed);
        if (offline != null && offline.n() != n) {
            throw new IllegalStateException("composeSecureMalicious: offline provider party count != number of vectors");
        }
        final MacContext ctx = offline != null ? offline.macContext() : Spdz.setupMac(n, rng);
        final SpdzEngine engine = new SpdzEngine(ctx, c.deviations == null ? List.of() : c.deviations);
        final int[] mults = {0};
        final boolean verify = c.dealer == null || c.dealer.verifyTriples == null || c.dealer.verifyTriples;

        class Ops {
            AuthTriple nextTriple() {
                if (offline != null) return offline.genAuthTriple();
                if (!verify) {
                    return c.dealer != null && c.dealer.fault != null
                        ? Spdz.genTripleWithPartners(ctx, rng, 1, c.dealer.fault).keep() : Spdz.genAuthTriple(ctx, rng);
                }
                int partners = c.dealer != null && c.dealer.partners != null ? c.dealer.partners : Spdz.SACRIFICE_PARTNERS;
                Spdz.TripleWithPartners dealt = Spdz.genTripleWithPartners(ctx, rng, partners, c.dealer == null ? null : c.dealer.fault);
                return Spdz.sacrificeVerify(List.of(dealt), ctx, rng, List.of()).get(0);
            }
            AuthSV shareBit(int bit, int owner) {
                return offline != null ? offline.authInput(BigInteger.valueOf(bit), owner) : Spdz.authShare(BigInteger.valueOf(bit), ctx, rng);
            }
            AuthSV and(List<AuthSV> bits) {
                if (bits.isEmpty()) return Spdz.authConstant(BigInteger.ONE, ctx);
                AuthSV acc = bits.get(0);
                for (int i = 1; i < bits.size(); i++) {
                    acc = Spdz.beaverMulAuth(acc, bits.get(i), nextTriple(), ctx, engine, "and" + i);
                    mults[0]++;
                }
                return acc;
            }
            AuthSV or(List<AuthSV> bits) {
                if (bits.isEmpty()) return Spdz.authConstant(BigInteger.ZERO, ctx);
                AuthSV prod = Spdz.notBitAuth(bits.get(0), ctx);
                for (int i = 1; i < bits.size(); i++) {
                    prod = Spdz.beaverMulAuth(prod, Spdz.notBitAuth(bits.get(i), ctx), nextTriple(), ctx, engine, "or" + i);
                    mults[0]++;
                }
                return Spdz.notBitAuth(prod, ctx);
            }
        }
        Ops ops = new Ops();

        List<AuthSV> allowBits = new ArrayList<>();
        for (int p = 0; p < n; p++) allowBits.add(ops.shareBit(vectors.get(p).allow(), p));
        AuthSV allowSV = ops.and(allowBits);

        int[][] tTherm = new int[n][];
        for (int p = 0; p < n; p++) tTherm[p] = Thermometer.thermometerEncode(vectors.get(p).t(), T_M);
        List<AuthSV> tGe = new ArrayList<>();
        for (int k = 0; k < T_M; k++) {
            List<AuthSV> bits = new ArrayList<>();
            for (int p = 0; p < n; p++) bits.add(ops.shareBit(tTherm[p][k], p));
            tGe.add(ops.or(bits));
        }
        int[][] rTherm = new int[n][];
        for (int p = 0; p < n; p++) rTherm[p] = Thermometer.thermometerEncode(vectors.get(p).rQuant(), Q);
        List<AuthSV> rGe = new ArrayList<>();
        for (int k = 0; k < Q; k++) {
            List<AuthSV> bits = new ArrayList<>();
            for (int p = 0; p < n; p++) bits.add(ops.shareBit(rTherm[p][k], p));
            rGe.add(ops.or(bits));
        }

        BigInteger allowOpen = engine.open(allowSV, "out:allow");
        int[] tOpen = new int[T_M];
        for (int k = 0; k < T_M; k++) tOpen[k] = engine.open(tGe.get(k), "out:t.ge" + (k + 1)).equals(BigInteger.ONE) ? 1 : 0;
        int[] rOpen = new int[Q];
        for (int k = 0; k < Q; k++) rOpen[k] = engine.open(rGe.get(k), "out:r.ge" + (k + 1)).equals(BigInteger.ONE) ? 1 : 0;

        engine.macCheck(rng);

        int allow = allowOpen.equals(BigInteger.ONE) ? 1 : 0;
        int t = Math.min(3, Math.max(1, Thermometer.thermometerDecode(tOpen)));
        int rQuant = Thermometer.thermometerDecode(rOpen);
        return new MaliciousMpcResult(new ComposedDecision(allow, t, rQuant), n, Q, engine.openCount(), mults[0],
            offline != null ? "no-dealer" : "trusted-dealer", offline != null || verify, true);
    }
}
