package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Risk functional, threshold map, decaying trust budget and plan geodesic (spec section 10; the reference's {@code risk.ts}). Pure and
 * deterministic; time is epoch milliseconds and {@code lambda} is budget drained PER SECOND. A non-finite input fails closed (worst case).
 */
final class Risk {
    private Risk() {}

    /** The risk inputs in the reference's order. */
    static final String[] KEYS = {"semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"};
    /** The worst case of each input (1 for risk-increasing inputs, 0 for reversibility and confidence). */
    static final double[] WORST = {1, 0, 1, 1, 0, 1};

    static double clamp01(double x) { return x < 0 ? 0 : x > 1 ? 1 : x; }

    /** Non-finite means the worst case; else clamped to [0, 1]. */
    static double unit(double x, double worst) { return Double.isNaN(x) || Double.isInfinite(x) ? worst : clamp01(x); }

    /** A weight: finite and positive, else 0 (which is what makes the score monotone for any policy). */
    static double wt(double x) { return !Double.isNaN(x) && !Double.isInfinite(x) && x > 0 ? x : 0; }

    private static double num(Map<String, Object> m, String k) {
        Double d = m == null ? null : Caveats.fin(m.get(k));
        return d == null ? Double.NaN : d;
    }

    /** r = clamp(alpha d + beta (1 - rev) + gamma bl + delta taint + epsilon (1 - conf) + zeta age, 0, 1); {@code in} is ordered as {@link #KEYS}. */
    static double riskScore(double[] in, Map<String, Object> w) {
        double r = wt(num(w, "alpha")) * unit(in[0], 1)
            + wt(num(w, "beta")) * (1 - unit(in[1], 0))
            + wt(num(w, "gamma")) * unit(in[2], 1)
            + wt(num(w, "delta")) * unit(in[3], 1)
            + wt(num(w, "epsilon")) * (1 - unit(in[4], 0))
            + wt(num(w, "zeta")) * unit(in[5], 1);
        return clamp01(r);
    }

    /** A required threshold: {@code t} 1..3, its proof strength and whether optimistic acceptance is allowed. */
    static final class Required {
        final int t;
        final String proof;
        final boolean optimisticAllowed;
        Required(int t, String proof, boolean optimisticAllowed) { this.t = t; this.proof = proof; this.optimisticAllowed = optimisticAllowed; }
    }

    private static final String[] PROOF_FOR_T = {"", "claim", "standard", "strong"};

    /** The piecewise map: r <= theta1 gives t=1 (optimistic unless irreversible), r <= theta2 gives t=2, above gives t=3. A non-finite r is the worst case. */
    static Required requiredThreshold(double r, double theta1, double theta2, boolean irreversible) {
        double x = Double.isNaN(r) || Double.isInfinite(r) ? 1 : r;
        if (x <= theta1) return new Required(1, "claim", !irreversible);
        if (x <= theta2) return new Required(2, "standard", false);
        return new Required(3, "strong", false);
    }

    /** Raises a required threshold to at least {@code minT} and keeps it coherent; never lowers anything. */
    static Required escalate(Required rt, int minT) {
        int t = Math.max(rt.t, minT);
        String floor = PROOF_FOR_T[t];
        String proof = rank(rt.proof) >= rank(floor) ? rt.proof : floor;
        return new Required(t, proof, t > 1 ? false : rt.optimisticAllowed);
    }

    private static int rank(String proof) { return proof.equals("claim") ? 0 : proof.equals("standard") ? 1 : 2; }

    /** The trust budget: {@code B} in [0, bMax], the last human touch {@code tau} and the time it was last brought up to date. */
    static final class Budget {
        final double b, tau, asOf;
        Budget(double b, double tau, double asOf) { this.b = b; this.tau = tau; this.asOf = asOf; }

        /** From a context map {@code {B, tau, asOf?}}; null when it is not one. */
        static Budget of(Object o) {
            if (!(o instanceof Map)) return null;
            Map<String, Object> m = IntentJs.obj(o);
            Double b = Caveats.fin(m.get("B")), tau = Caveats.fin(m.get("tau"));
            if (b == null || tau == null) return null;
            Double asOf = Caveats.fin(m.get("asOf"));
            return new Budget(b, tau, asOf == null ? tau : asOf);
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("B", b);
            m.put("tau", tau);
            m.put("asOf", asOf);
            return m;
        }
    }

    private static double nz(double x) { return !Double.isNaN(x) && !Double.isInfinite(x) && x > 0 ? x : 0; }

    /** c(A) = kappa r(A); a non-finite r costs r = 1. */
    static double cost(double r, double kappa) { return nz(kappa) * clamp01(Double.isNaN(r) || Double.isInfinite(r) ? 1 : r); }

    /** Passive leak: B falls by lambda per second since the last update; idempotent for repeated calls at the same {@code now}. */
    static Budget leak(Budget b, double now, double lambda) {
        double from = b.asOf;
        double dt = !Double.isNaN(now) && !Double.isInfinite(now) && !Double.isNaN(from) && !Double.isInfinite(from) ? Math.max(0, now - from) : 0;
        double nb = Math.max(0, b.b - nz(lambda) * (dt / 1000));
        return new Budget(nb, b.tau, !Double.isNaN(now) && !Double.isInfinite(now) ? Math.max(now, from) : from);
    }

    /** B = max(0, B - cost). */
    static Budget debit(Budget b, double c) { return new Budget(Math.max(0, b.b - nz(c)), b.tau, b.asOf); }

    /** Normalized age since the last human touch: clamp((now - tau) / horizonMs, 0, 1); an unusable input is the worst case 1. */
    static double ageSinceTouch(Budget b, double now, double horizonMs) {
        if (Double.isNaN(now) || Double.isInfinite(now) || Double.isNaN(b.tau) || Double.isInfinite(b.tau) || !(horizonMs > 0)) return 1;
        return clamp01((now - b.tau) / horizonMs);
    }

    /** The budget admission: {@code t} is the threshold band of the risk with irreversibility ignored, {@code covers} whether B >= cost. */
    static final class Admission {
        final boolean admit, needStepUp, metered;
        final int t;
        Admission(boolean admit, boolean needStepUp, int t, boolean metered) { this.admit = admit; this.needStepUp = needStepUp; this.t = t; this.metered = metered; }
    }

    static Admission admit(int t, boolean covers) {
        if (t < 3 && !covers) return new Admission(false, true, 3, false);
        if (t == 1) return new Admission(true, false, 1, true);
        if (t == 2) return new Admission(false, true, 2, true);
        return new Admission(false, true, 3, false);
    }

    // ---- plan geodesic

    private static final String[] PRE_KEYS = {"after", "depends_on", "requires", "nodes"};
    private static final String[] POST_KEYS = {"before", "enables", "then", "next"};

    private static List<String> refsOf(Object x, String[] keys) {
        List<String> out = new ArrayList<>();
        add(out, x);
        if (x instanceof Map) for (String k : keys) add(out, ((Map<?, ?>) x).get(k));
        return out;
    }

    private static void add(List<String> out, Object v) {
        if (v instanceof String) out.add((String) v);
        else if (v instanceof List) for (Object s : (List<?>) v) if (s instanceof String) out.add((String) s);
    }

    /**
     * Normalized geodesic distance in the committed plan DAG, in [0, 1]: BFS hop count over the undirected graph of the nodes' {@code pre} / {@code post}
     * references divided by (n - 1); unreachable or an unknown node id is 1; the same node is 0; a plan with no edges falls back to index distance.
     */
    @SuppressWarnings("unchecked")
    static double planGeodesic(List<Object> plan, String from, String to) {
        java.util.Map<String, Integer> idx = new java.util.HashMap<>();
        for (int i = 0; i < plan.size(); i++) {
            Object id = plan.get(i) instanceof Map ? ((Map<String, Object>) plan.get(i)).get("id") : null;
            if (id instanceof String) idx.put((String) id, i);
        }
        Integer a = idx.get(from), b = idx.get(to);
        if (a == null || b == null) return 1;
        if (a.equals(b)) return 0;
        int n = plan.size();
        List<Set<Integer>> adj = new ArrayList<>();
        for (int i = 0; i < n; i++) adj.add(new HashSet<>());
        int[] edges = {0};
        for (int i = 0; i < n; i++) {
            Map<String, Object> node = plan.get(i) instanceof Map ? (Map<String, Object>) plan.get(i) : new LinkedHashMap<>();
            for (String id : refsOf(node.get("pre"), PRE_KEYS)) {
                Integer j = idx.get(id);
                if (j != null) link(adj, edges, j, i);
            }
            for (String id : refsOf(node.get("post"), POST_KEYS)) {
                Integer j = idx.get(id);
                if (j != null) link(adj, edges, i, j);
            }
        }
        if (edges[0] == 0) return clamp01(Math.abs(a - b) / (double) (n - 1));
        int[] dist = new int[n];
        java.util.Arrays.fill(dist, -1);
        dist[a] = 0;
        List<Integer> q = new ArrayList<>();
        q.add(a);
        for (int h = 0; h < q.size(); h++) {
            int u = q.get(h);
            List<Integer> next = new ArrayList<>(adj.get(u));
            java.util.Collections.sort(next);
            for (int v : next) {
                if (dist[v] == -1) {
                    dist[v] = dist[u] + 1;
                    q.add(v);
                }
            }
        }
        return dist[b] < 0 ? 1 : clamp01(dist[b] / (double) (n - 1));
    }

    private static void link(List<Set<Integer>> adj, int[] edges, int i, int j) {
        if (i == j) return;
        if (!adj.get(i).contains(j)) edges[0]++;
        adj.get(i).add(j);
        adj.get(j).add(i);
    }
}
