package net.atlasauth.pca.wallet;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.DoubleSupplier;
import net.atlasauth.pca.oauth.JsVal;

/**
 * Attention canaries and the approval-fatigue model (the reference's canary.ts and fatigue.ts). A canary is a question about a
 * cell whose label the system already knows; its answer only updates the per-principal noise counts (it never reaches a learner
 * or a grant). The fatigue model turns the counts and the questions asked in the last hour into the admission policy.
 */
public final class WalletNoise {
    private WalletNoise() {}

    // ---- noise counts and estimates -------------------------------------------------------------------------------------

    public static Map<String, Object> emptyNoise() {
        return Wallet.obj("falseYes", JsVal.n(0), "correctNo", JsVal.n(0), "falseNo", JsVal.n(0), "correctYes", JsVal.n(0));
    }

    private static Map<String, Object> bump(Map<String, Object> n, String key) {
        Map<String, Object> m = new LinkedHashMap<>(n);
        m.put(key, Wallet.nv(n.get(key)) + 1);
        return m;
    }

    /** Fold one canary answer into the counts (pure): expected and y are 0 or 1. */
    public static Map<String, Object> recordCanary(Map<String, Object> n, Object expected, Object y) {
        boolean y1 = Wallet.nv(y) == 1;
        if (Wallet.nv(expected) == 0) return y1 ? bump(n, "falseYes") : bump(n, "correctNo");
        return Wallet.nv(y) == 0 ? bump(n, "falseNo") : bump(n, "correctYes");
    }

    public static final double PRIOR_A = 1;
    public static final double PRIOR_B = 9;
    /** The reference's {@code NOISE_PRIOR} as a map {@code {a, b}}: the Beta prior of the miss-rate estimate. */
    public static final java.util.Map<String, Double> NOISE_PRIOR = java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<String, Double>() {
        private static final long serialVersionUID = 1L;
        { put("a", PRIOR_A); put("b", PRIOR_B); }
    });

    public static Map<String, Object> estimateNoise(Map<String, Object> n) { return estimateNoise(n, 0.05); }

    /** Posterior means and bounds of the false-yes / false-no rates; throws unless deltaC is in (0, 1). */
    public static Map<String, Object> estimateNoise(Map<String, Object> n, double deltaC) {
        if (!(deltaC > 0 && deltaC < 1)) throw new IllegalArgumentException("estimateNoise: deltaC must be in (0, 1)");
        double falseYes = Wallet.nv(n.get("falseYes")), correctNo = Wallet.nv(n.get("correctNo"));
        double falseNo = Wallet.nv(n.get("falseNo")), correctYes = Wallet.nv(n.get("correctYes"));
        double ap = PRIOR_A + falseYes;
        double bp = PRIOR_B + correctNo;
        double an = PRIOR_A + falseNo;
        double bn = PRIOR_B + correctYes;
        double knownNo = falseYes + correctNo;
        double knownYes = falseNo + correctYes;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("etaPos", ap / (ap + bp));
        out.put("etaNeg", an / (an + bn));
        out.put("etaPosUpper", WalletStats.betaUpperExact(deltaC, ap, bp));
        out.put("etaNegUpper", WalletStats.betaUpperExact(deltaC, an, bn));
        out.put("etaPosCP", knownNo == 0 ? 1.0 : WalletStats.clopperPearsonUpper(falseYes, knownNo, deltaC));
        out.put("etaNegCP", knownYes == 0 ? 1.0 : WalletStats.clopperPearsonUpper(falseNo, knownYes, deltaC));
        out.put("asked", knownNo + knownYes);
        return out;
    }

    // ---- selection ------------------------------------------------------------------------------------------------------

    /** Why a cell is a known no ("ceiling" or "veto"), or null when it is not one. */
    public interface KnownNo { String why(String verb, int[] idx); }

    public static final class CanaryContext {
        public Map<String, Object> omega;
        /** Cells inside the confirmed region: maps {verb, idx}. */
        public List<Map<String, Object>> confirmed = new ArrayList<>();
        public KnownNo knownNo;
        /** Cells with an earlier verified high-friction yes: maps {verb, idx}. */
        public List<Map<String, Object>> knownYes = new ArrayList<>();
        /** Cells not to use, as "verb|i,j,..." keys. */
        public Set<String> exclude = Collections.emptySet();
        public DoubleSupplier rand;
        /** Insertion probability (default 0.1); null for the default. */
        public Double rho;
        public boolean lowHarmSession;
        public double canariesSoFar;
    }

    public static String cellKey(String verb, int[] idx) {
        StringBuilder sb = new StringBuilder(verb).append('|');
        for (int i = 0; i < idx.length; i++) sb.append(i == 0 ? "" : ",").append(idx[i]);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    public static int[] idxOf(Object o) {
        List<Object> l = (List<Object>) o;
        int[] r = new int[l.size()];
        for (int i = 0; i < r.length; i++) r[i] = (int) (double) JsVal.num(l.get(i));
        return r;
    }

    public static List<Object> idxList(int[] idx) {
        List<Object> l = new ArrayList<>();
        for (int i : idx) l.add((long) i);
        return l;
    }

    static Map<String, Object> cellAt(String verb, int[] idx) { return Wallet.obj("verb", verb, "idx", idxList(idx)); }

    /** Cells one step outside the confirmed region in exactly one dimension (deterministic order): maps {verb, idx}. */
    public static List<Map<String, Object>> boundaryNeighbours(Map<String, Object> omega, List<Map<String, Object>> confirmed) {
        java.util.Set<String> inside = new java.util.HashSet<>();
        for (Map<String, Object> c : confirmed) inside.add(cellKey((String) c.get("verb"), idxOf(c.get("idx"))));
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (Map<String, Object> c : confirmed) {
            Map<String, Object> vs = WalletOmega.verbSpace(omega, c.get("verb"));
            if (vs == null) continue;
            int[] ci = idxOf(c.get("idx"));
            for (int k = 0; k < WalletOmega.dims(vs).size(); k++) {
                Map<String, Object> d = WalletOmega.dim(vs, k);
                int n = WalletOmega.cellCount(d);
                int[] alts;
                if ("num".equals(d.get("kind"))) alts = new int[] {ci[k] - 1, ci[k] + 1};
                else {
                    alts = new int[n];
                    for (int i = 0; i < n; i++) alts[i] = i;
                }
                for (int a : alts) {
                    if (a < 0 || a >= n || a == ci[k]) continue;
                    int[] idx = ci.clone();
                    idx[k] = a;
                    String key = cellKey((String) c.get("verb"), idx);
                    if (!inside.contains(key)) out.put(key, cellAt((String) c.get("verb"), idx));
                }
            }
        }
        List<String> keys = new ArrayList<>(out.keySet());
        Collections.sort(keys);
        List<Map<String, Object>> res = new ArrayList<>();
        for (String k : keys) res.add(out.get(k));
        return res;
    }

    /** Decide whether to insert a canary now, and which: {verb, idx, expected, source}, or null for no canary this time. */
    public static Map<String, Object> pickCanary(CanaryContext ctx) {
        double rho = ctx.rho == null ? 0.1 : ctx.rho;
        if (!(rho >= 0 && rho <= 1)) throw new IllegalArgumentException("pickCanary: rho must be in [0, 1]");
        if (ctx.lowHarmSession && ctx.canariesSoFar >= 1) return null;
        if (!(ctx.rand.getAsDouble() < rho)) return null;
        List<Map<String, Object>> no = new ArrayList<>();
        for (Map<String, Object> c : boundaryNeighbours(ctx.omega, ctx.confirmed)) {
            int[] idx = idxOf(c.get("idx"));
            if (ctx.exclude.contains(cellKey((String) c.get("verb"), idx))) continue;
            String why = ctx.knownNo.why((String) c.get("verb"), idx);
            if (why != null) {
                Map<String, Object> m = Wallet.obj("verb", c.get("verb"), "idx", c.get("idx"), "expected", JsVal.n(0), "source", why);
                no.add(m);
            }
        }
        List<Map<String, Object>> yes = new ArrayList<>();
        for (Map<String, Object> c : ctx.knownYes) {
            int[] idx = idxOf(c.get("idx"));
            if (ctx.exclude.contains(cellKey((String) c.get("verb"), idx))) continue;
            yes.add(Wallet.obj("verb", c.get("verb"), "idx", idxList(idx), "expected", JsVal.n(1), "source", "confirmed-yes"));
        }
        if (no.isEmpty() && yes.isEmpty()) return null;
        List<Map<String, Object>> pool = !no.isEmpty() && !yes.isEmpty() ? (ctx.rand.getAsDouble() < 0.5 ? no : yes) : !no.isEmpty() ? no : yes;
        return pool.get((int) Math.min(pool.size() - 1, Math.floor(ctx.rand.getAsDouble() * pool.size())));
    }

    // ---- approval fatigue -----------------------------------------------------------------------------------------------

    /** {betaF: 0.005, etaStop: 0.15, deltaC: 0.05, freezeOn: "mean", assumeNoiseFree: false, delta: 0.05}. */
    public static Map<String, Object> defaultFatigue() {
        return Wallet.obj("betaF", 0.005, "etaStop", 0.15, "deltaC", 0.05, "freezeOn", "mean", "assumeNoiseFree", false, "delta", 0.05);
    }

    /** Eta+ under load: base + betaF * nRecent, capped at 1/2. */
    public static double etaUnderLoad(double base, double betaF, double nRecent) {
        if (!(base >= 0 && betaF >= 0 && nRecent == Math.rint(nRecent) && !Double.isInfinite(nRecent) && nRecent >= 0)) throw new IllegalArgumentException("etaUnderLoad: bad arguments");
        return Math.min(0.5, base + betaF * nRecent);
    }

    public static Map<String, Object> noiseState(Map<String, Object> counts, double nRecent) { return noiseState(counts, nRecent, defaultFatigue()); }

    /** {etaPos, etaPosBar, etaNegBar, frozen}. */
    public static Map<String, Object> noiseState(Map<String, Object> counts, double nRecent, Map<String, Object> model) {
        Map<String, Object> e = estimateNoise(counts, Wallet.defined(model, "deltaC") ? Wallet.nv(model.get("deltaC")) : 0.05);
        double betaF = Wallet.nv(model.get("betaF"));
        double etaPos = etaUnderLoad((Double) e.get("etaPos"), betaF, nRecent);
        double etaPosBar = etaUnderLoad((Double) e.get("etaPosUpper"), betaF, nRecent);
        double stat = "mean".equals(model.get("freezeOn")) ? etaPos : etaPosBar;
        return Wallet.obj("etaPos", etaPos, "etaPosBar", etaPosBar, "etaNegBar", Math.min(0.5, (Double) e.get("etaNegUpper")), "frozen", stat > Wallet.nv(model.get("etaStop")));
    }

    private static final double BELOW_HALF = 0.5 - 1e-9;

    public static Map<String, Object> admissionPolicy(Map<String, Object> state) { return admissionPolicy(state, defaultFatigue()); }

    /** {tau, etaPos, etaNeg, doubleConfirmIrreversible, falseAdmitBound}. */
    public static Map<String, Object> admissionPolicy(Map<String, Object> state, Map<String, Object> model) {
        if (JsVal.truthy(model.get("assumeNoiseFree")))
            return Wallet.obj("tau", JsVal.n(1), "etaPos", JsVal.n(0), "etaNeg", JsVal.n(0), "doubleConfirmIrreversible", false, "falseAdmitBound", JsVal.n(0));
        double delta = Wallet.nv(model.get("delta"));
        if (!(delta > 0 && delta < 1)) throw new IllegalArgumentException("admissionPolicy: delta must be in (0, 1)");
        double ep = Math.min(BELOW_HALF, Wallet.nv(state.get("etaPosBar")));
        double en = Math.min(BELOW_HALF, Wallet.nv(state.get("etaNegBar")));
        return Wallet.obj("tau", 1 - delta, "etaPos", ep, "etaNeg", en, "doubleConfirmIrreversible", ep > 0, "falseAdmitBound", ep * ep);
    }

    /**
     * Sliding-window question counter shared across sessions (the per-hour cap is an accumulator, so an agent cannot split
     * around it by opening sessions). Keeps only timestamps inside the window.
     */
    public static final class SlidingWindowCounter {
        private final java.util.ArrayList<Double> times = new java.util.ArrayList<>();
        public final double windowMs;

        public SlidingWindowCounter() { this(3_600_000d); }

        public SlidingWindowCounter(double windowMs) {
            if (!(windowMs == Math.rint(windowMs) && windowMs > 0 && !Double.isInfinite(windowMs))) throw new IllegalArgumentException("SlidingWindowCounter: windowMs must be a positive integer");
            this.windowMs = windowMs;
        }

        private void prune(double now) {
            if (!Double.isFinite(now)) return; // an infinite clock must never forget a recorded event
            while (!times.isEmpty() && times.get(0) <= now - windowMs) times.remove(0);
        }

        public int count(double now) {
            prune(now);
            return times.size();
        }

        /** Record one event at {@code now} if the count is below {@code cap}; false (and nothing recorded) otherwise. */
        public boolean tryAdd(double now, double cap) {
            prune(now);
            if (!(times.size() < cap)) return false;
            if (!times.isEmpty() && !(now >= times.get(times.size() - 1))) throw new IllegalStateException("SlidingWindowCounter: time went backwards");
            if (!Double.isFinite(now)) return false;
            times.add(now);
            return true;
        }
    }

    /**
     * Double confirmation of an irreversible cell: two "yes" answers at typed or device tier, on different screens, with at
     * least one other screen between them. Records are maps {screen, tier}.
     */
    public static boolean doubleConfirmed(List<Map<String, Object>> records) {
        List<Double> strong = new ArrayList<>();
        for (Map<String, Object> r : records) if ("typed".equals(r.get("tier")) || "device".equals(r.get("tier"))) strong.add(Wallet.nv(r.get("screen")));
        Collections.sort(strong);
        for (int i = 0; i < strong.size(); i++) for (int j = i + 1; j < strong.size(); j++) if (strong.get(j) - strong.get(i) >= 2) return true;
        return false;
    }
}
