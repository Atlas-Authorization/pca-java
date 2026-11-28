package net.atlasauth.pca.wallet;

import java.util.ArrayList;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiPredicate;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentLearner.CellView;
import net.atlasauth.pca.intent.IntentLearner.LearnerOptions;
import net.atlasauth.pca.intent.IntentLearner.Observation;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/** The wallet's default views over the intent learner: the grant view the question channel consults, and the population-prior mass. */
public final class WalletLearner {
    private WalletLearner() {}

    /**
     * A {@link WalletView} over an intent learner, with an optional ceiling predicate ({@code insideCeiling}: true = inside every
     * ceiling; null = no ceiling). {@code p} and {@code vetoed} read the learner at the cell's representative outcome; an unknown
     * verb throws, as in the reference.
     */
    public static WalletView learnerView(IntentLearner l, BiPredicate<String, int[]> insideCeiling) {
        return new WalletView() {
            private VerbSpace vsOf(String verb) {
                for (VerbSpace v : l.omega.verbs) if (v.verb.equals(verb)) return v;
                throw new IllegalArgumentException("learnerView: unknown verb " + verb);
            }
            @Override public double p(String verb, int[] idx) { return l.acceptance(IntentOmega.cellRep(vsOf(verb), idx)); }
            @Override public boolean vetoed(String verb, int[] idx) { return l.isVetoed(IntentOmega.cellRep(vsOf(verb), idx)); }
            @Override public boolean outsideCeiling(String verb, int[] idx) { return insideCeiling != null && !insideCeiling.test(verb, idx); }
            @Override public List<Map<String, Object>> confirmed() {
                List<Map<String, Object>> out = new ArrayList<>();
                for (CellView c : l.cells()) {
                    if (!c.inGrant) continue;
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("verb", c.verb);
                    m.put("idx", c.cell);
                    out.add(m);
                }
                return out;
            }
        };
    }

    public static WalletView learnerView(IntentLearner l) { return learnerView(l, null); }

    /**
     * mu-mass (ppm) of cells admitted only because of the population prior: in the grant with the prior, not in it without, after the same
     * observations. Zero at tau = 1 under noise-free answers; the map reports it as {@code metrics.prior_admitted_ppm}.
     */
    public static long priorAdmittedPpm(Omega omega, LearnerOptions base, Collection<Observation> observations, WalletPopulation.PriorMix mix) {
        LearnerOptions without = copyOf(base);
        without.priorMix = null;
        LearnerOptions with = copyOf(base);
        IdentityHashMap<VerbSpace, Map<String, Object>> asMap = new IdentityHashMap<>();
        with.priorMix = new IntentLearner.PriorMix(mix.beta, (vs, contains) -> mix.weight(asMap.computeIfAbsent(vs, v -> verbMap(v)), contains));
        List<CellView> a = IntentLearner.replay(omega, without, observations).cells();
        List<CellView> b = IntentLearner.replay(omega, with, observations).cells();
        double mass = 0;
        for (int i = 0; i < b.size(); i++) if (b.get(i).inGrant && !a.get(i).inGrant) mass += b.get(i).mass;
        return Math.round(mass * 1_000_000);
    }

    private static Map<String, Object> verbMap(VerbSpace vs) {
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) ((List<?>) IntentOmega.omegaToJson(new Omega(List.of(vs), List.of())).get("verbs")).get(0);
        return m;
    }

    private static LearnerOptions copyOf(LearnerOptions o) {
        LearnerOptions c = new LearnerOptions();
        if (o == null) return c;
        c.eta = o.eta; c.etaPos = o.etaPos; c.etaNeg = o.etaNeg; c.tau = o.tau; c.priorMix = o.priorMix; c.nullMass = o.nullMass; c.nullMassFn = o.nullMassFn;
        c.anchor = o.anchor; c.anchors = o.anchors; c.harm = o.harm; c.maxHypotheses = o.maxHypotheses; c.maxEnumeration = o.maxEnumeration;
        c.strategy = o.strategy; c.hypothesisClass = o.hypothesisClass; c.agnosticSlack = o.agnosticSlack; c.monotone = o.monotone;
        return c;
    }
}
