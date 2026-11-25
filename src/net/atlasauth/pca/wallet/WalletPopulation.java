package net.atlasauth.pca.wallet;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.DoubleSupplier;
import java.util.function.IntPredicate;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.oauth.JsVal;

/**
 * Opt-in, privacy-preserving population priors. A principal who opts in contributes cell-level answers keyed by (schema digest,
 * verb, semantic cell); each principal contributes at most ONE vote per cell per period and to at most a fixed number of cells
 * per period. The aggregator releases noisy counts under the Gaussian mechanism (central DP); a principal who does not trust the
 * aggregator uses randomized response (local DP). The mixture prior (beta below 1) keeps full support, so at tau = 1 under
 * noise-free answers the grant does not depend on it.
 *
 * <p>{@code priorAdmittedPpm} (the grant mass the prior alone admits) is {@link WalletLearner#priorAdmittedPpm}, over the intent learner.
 */
public final class WalletPopulation {
    private WalletPopulation() {}

    public static final String POPULATION_VOTE_DOMAIN = "atlas-pca/intent-population-cell/v1";
    public static final double BETA_MAX = 0.9;

    /** The semantic key of a cell: its coordinates in schema terms, bound to the schema digest and the verb. */
    public static String populationCellKey(String schemaDigest, Map<String, Object> vs, int[] idx) {
        return Pca.hashCanonical(Wallet.obj("d", POPULATION_VOTE_DOMAIN, "s", schemaDigest, "v", vs.get("verb"), "c", WalletBox.coordsOfCell(vs, idx)));
    }

    private static final SecureRandom SECURE = new SecureRandom();

    /** Uniform (0, 1) from 53 random bits of a CSPRNG. */
    public static double cryptoRand() {
        long hi = (SECURE.nextInt() & 0xffffffffL) >>> 5;
        long lo = (SECURE.nextInt() & 0xffffffffL) >>> 6;
        return (hi * 67108864.0 + lo + 0.5) / 9007199254740992.0;
    }

    /** A standard normal draw (Box-Muller) from a uniform source. */
    public static double gaussian(DoubleSupplier rand) {
        double u = rand.getAsDouble();
        while (u <= 0) u = rand.getAsDouble();
        double v = rand.getAsDouble();
        return Math.sqrt(-2 * StrictMath.log(u)) * StrictMath.cos(2 * Math.PI * v);
    }

    /** Sigma of the Gaussian mechanism for L2 sensitivity (requires epsilon in (0, 1), delta in (0, 1), sensitivity &gt; 0). */
    public static double gaussianSigma(double epsilon, double delta, double l2Sensitivity) {
        if (!(epsilon > 0 && epsilon < 1)) throw new IllegalArgumentException("gaussianSigma: the classic Gaussian mechanism needs epsilon in (0, 1)");
        if (!(delta > 0 && delta < 1)) throw new IllegalArgumentException("gaussianSigma: delta must be in (0, 1)");
        if (!(l2Sensitivity > 0)) throw new IllegalArgumentException("gaussianSigma: sensitivity must be > 0");
        return (l2Sensitivity * Math.sqrt(2 * StrictMath.log(1.25 / delta))) / epsilon;
    }

    /** The central aggregator (normally the Atlas instance). */
    public static final class Aggregator {
        private final Map<Object, double[]> votes = new HashMap<>();
        private final Map<Object, Set<Object>> perPrincipal = new HashMap<>();
        private final double maxCells;
        private final DoubleSupplier rand;
        public final String schemaDigest;
        public final double period;

        public Aggregator(String schemaDigest, double period) { this(schemaDigest, period, null, null); }

        /** {@code maxCellsPerPrincipal} (default 32) and {@code rand} (default a CSPRNG) may be null. */
        public Aggregator(String schemaDigest, double period, Double maxCellsPerPrincipal, DoubleSupplier rand) {
            if (!Wallet.isB64u32(schemaDigest)) throw new IllegalArgumentException("PopulationAggregator: schemaDigest must be a canonical b64u digest");
            this.schemaDigest = schemaDigest;
            this.period = period;
            this.maxCells = maxCellsPerPrincipal == null ? 32 : maxCellsPerPrincipal;
            if (!(maxCells == Math.rint(maxCells) && maxCells > 0 && !Double.isInfinite(maxCells))) throw new IllegalArgumentException("PopulationAggregator: maxCellsPerPrincipal must be a positive integer");
            this.rand = rand == null ? WalletPopulation::cryptoRand : rand;
        }

        /**
         * Accept a vote {principal, schemaDigest, cellKey, y, period}; refuses a second vote on a cell, a vote past the
         * per-principal cell cap, or a foreign schema or period. Returns {ok:true} or {ok:false, reason}.
         */
        public Map<String, Object> contribute(Map<String, Object> v) {
            if (!schemaDigest.equals(v.get("schemaDigest"))) return Wallet.obj("ok", false, "reason", "vote for another schema");
            if (!(JsVal.isNumber(v.get("period")) && Wallet.nv(v.get("period")) == period)) return Wallet.obj("ok", false, "reason", "vote for another period");
            Object y = v.get("y");
            if (!(JsVal.isNumber(y) && (Wallet.nv(y) == 0 || Wallet.nv(y) == 1))) return Wallet.obj("ok", false, "reason", "y must be 0 or 1");
            Object principal = v.get("principal");
            if (!(principal instanceof String) || ((String) principal).isEmpty()) return Wallet.obj("ok", false, "reason", "an accountable principal is required");
            Set<Object> mine = perPrincipal.getOrDefault(principal, new HashSet<>());
            Object key = v.get("cellKey");
            if (mine.contains(key)) return Wallet.obj("ok", false, "reason", "one vote per principal per cell per period (sensitivity 1)");
            if (mine.size() >= maxCells) return Wallet.obj("ok", false, "reason", "at most " + WalletCard.jsNum(maxCells) + " cells per principal per period");
            mine.add(key);
            perPrincipal.put(principal, mine);
            double[] c = votes.getOrDefault(key, new double[] {0, 0});
            votes.put(key, new double[] {c[0] + Wallet.nv(y), c[1] + 1});
            return Wallet.obj("ok", true);
        }

        public Map<String, Object> release(double epsilon, double delta) { return release(epsilon, delta, null, null); }

        /**
         * The (epsilon, delta)-DP release. Cells whose noisy count is below {@code minCount} (default 3 sigma) are suppressed.
         * {@code qMin} defaults to 0.02. Returns the population-prior object.
         */
        public Map<String, Object> release(double epsilon, double delta, Double qMinO, Double minCountO) {
            double sensitivity = Math.sqrt(2 * maxCells);
            double sigma = gaussianSigma(epsilon, delta, sensitivity);
            double qMin = qMinO == null ? 0.02 : qMinO;
            if (!(qMin > 0 && qMin < 0.5)) throw new IllegalArgumentException("release: qMin must be in (0, 0.5)");
            double minCount = minCountO == null ? 3 * sigma : minCountO;
            Map<String, Object> cells = new LinkedHashMap<>();
            List<String> keys = new ArrayList<>();
            for (Object k : votes.keySet()) keys.add((String) k);
            Collections.sort(keys);
            for (String key : keys) {
                double[] c = votes.get(key);
                double yes = c[0] + sigma * gaussian(rand);
                double total = c[1] + sigma * gaussian(rand);
                if (!(total >= minCount)) continue;
                cells.put(key, Wallet.obj("q", Math.min(1 - qMin, Math.max(qMin, yes / total)), "n", Math.floor(total + 0.5)));
            }
            return Wallet.obj("v", JsVal.n(1), "kind", "pca-intent-population-prior", "schema", schemaDigest, "period", period, "epsilon", epsilon, "delta", delta,
                "sigma", sigma, "sensitivity", sensitivity, "cells", cells);
        }
    }

    // ---- local DP -----------------------------------------------------------------------------------------------------

    public static double rrKeepProbability(double epsilon) {
        if (!(epsilon > 0 && !Double.isInfinite(epsilon))) throw new IllegalArgumentException("randomized response: epsilon must be > 0");
        return StrictMath.exp(epsilon) / (1 + StrictMath.exp(epsilon));
    }

    /** epsilon-LDP randomized response: report y with probability e^eps/(1+e^eps), else 1 - y. */
    public static long randomizedResponse(long y, double epsilon, DoubleSupplier rand) {
        return rand.getAsDouble() < rrKeepProbability(epsilon) ? y : 1 - y;
    }

    public static long randomizedResponse(long y, double epsilon) { return randomizedResponse(y, epsilon, WalletPopulation::cryptoRand); }

    /** Unbiased estimate of the true yes-rate from randomized reports: (ybar - (1 - p)) / (2p - 1). */
    public static double debiasRandomizedResponse(double yesReports, double total, double epsilon) {
        boolean ok = yesReports == Math.rint(yesReports) && total == Math.rint(total) && total > 0 && yesReports >= 0 && yesReports <= total && !Double.isInfinite(total);
        if (!ok) throw new IllegalArgumentException("debias: bad counts");
        double p = rrKeepProbability(epsilon);
        return (yesReports / total - (1 - p)) / (2 * p - 1);
    }

    // ---- the mixture prior ------------------------------------------------------------------------------------------------

    /** The learner's prior mixture for a population release: a weight per hypothesis (a set of cells) mixed with weight beta. */
    public static final class PriorMix {
        public final double beta;
        private final Map<String, Object> release;
        private final Map<Map<String, Object>, double[][]> tables = new IdentityHashMap<>();
        private final Map<Map<String, Object>, int[]> cellIds = new IdentityHashMap<>();

        PriorMix(Map<String, Object> release, double beta) { this.release = release; this.beta = beta; }

        @SuppressWarnings("unchecked")
        private void tablesOf(Map<String, Object> vs) {
            if (tables.containsKey(vs)) return;
            List<Integer> cells = new ArrayList<>();
            List<double[]> lq = new ArrayList<>();
            double n = WalletOmega.verbCellCount(vs);
            Map<String, Object> rc = (Map<String, Object>) release.get("cells");
            String schema = (String) release.get("schema");
            for (int c = 0; c < n; c++) {
                Object r = rc.get(populationCellKey(schema, vs, WalletOmega.decodeCell(vs, c)));
                if (r == null) continue;
                double q = Wallet.nv(((Map<String, Object>) r).get("q"));
                cells.add(c);
                lq.add(new double[] {StrictMath.log(q), StrictMath.log(1 - q)});
            }
            int[] ids = new int[cells.size()];
            for (int i = 0; i < ids.length; i++) ids[i] = cells.get(i);
            tables.put(vs, lq.toArray(new double[0][]));
            cellIds.put(vs, ids);
        }

        /** weight(theta) = product over the released cells of q^[c in theta] (1 - q)^[c not in theta]. */
        public double weight(Map<String, Object> vs, IntPredicate contains) {
            tablesOf(vs);
            double[][] t = tables.get(vs);
            int[] ids = cellIds.get(vs);
            double lw = 0;
            for (int i = 0; i < ids.length; i++) lw += contains.test(ids[i]) ? t[i][0] : t[i][1];
            return StrictMath.exp(lw);
        }
    }

    /** The prior mixture for a release; throws unless beta is in [0, BETA_MAX] (full support needs beta below 1). */
    public static PriorMix populationPrior(Map<String, Object> release, double beta) {
        if (!(beta >= 0 && beta <= BETA_MAX)) throw new IllegalArgumentException("populationPrior: beta must be in [0, " + BETA_MAX + "] (full support needs beta < 1)");
        return new PriorMix(release, beta);
    }
}
