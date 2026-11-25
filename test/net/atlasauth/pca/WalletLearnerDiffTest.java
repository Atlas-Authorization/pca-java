package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentLearner.LearnerOptions;
import net.atlasauth.pca.intent.IntentLearner.Observation;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;
import net.atlasauth.pca.wallet.WalletLearner;
import net.atlasauth.pca.wallet.WalletPopulation;
import net.atlasauth.pca.wallet.WalletView;
import org.junit.jupiter.api.Test;

class WalletLearnerDiffTest {
    private static final String M = "ref-wallet-learner-java";

    private static Outcome outcome(Object o) {
        Map<String, Object> m = IntentOmega.obj(o);
        return IntentOmega.outcomeFromJson(Map.of("verb", m.get("verb"), "values", m.get("values")));
    }

    private static List<Object> ints(int[] a) {
        List<Object> o = new ArrayList<>();
        for (int x : a) o.add((double) x);
        return o;
    }

    private static IntentLearner learner(Omega omega, Object obs) {
        IntentLearner l = new IntentLearner(omega);
        for (Object x : IntentOmega.arr(obs)) l.observe(outcome(x), (int) IntentOmega.dbl(IntentOmega.obj(x).get("y")));
        return l;
    }

    @Test void view() throws Exception {
        OracleCases.each(M, "view", a -> {
            Omega omega = IntentOmega.omegaFromJson(a.get(0));
            IntentLearner l = learner(omega, a.get(1));
            WalletView v = a.get(2) == null ? WalletLearner.learnerView(l) : WalletLearner.learnerView(l, (verb, idx) -> idx[0] <= IntentOmega.dbl(a.get(2)));
            List<Object> cells = new ArrayList<>();
            for (VerbSpace vs : omega.verbs) {
                double t = IntentOmega.verbCellCount(vs);
                for (int f = 0; f < t; f++) {
                    int[] idx = IntentOmega.decodeCell(vs, f);
                    List<Object> c = new ArrayList<>();
                    c.add(vs.verb);
                    c.add(ints(idx));
                    c.add(v.p(vs.verb, idx));
                    c.add(v.vetoed(vs.verb, idx));
                    c.add(v.outsideCeiling(vs.verb, idx));
                    cells.add(c);
                }
            }
            List<Object> confirmed = new ArrayList<>();
            for (Map<String, Object> m : v.confirmed()) {
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("verb", m.get("verb"));
                e.put("idx", ints((int[]) m.get("idx")));
                confirmed.add(e);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("cells", cells);
            out.put("confirmed", confirmed);
            return out;
        });
    }

    @Test void probe() throws Exception {
        OracleCases.each(M, "probe", a -> WalletLearner.learnerView(new IntentLearner(IntentOmega.omegaFromJson(a.get(0)))).p((String) a.get(1), new int[] {0, 0}));
    }

    @SuppressWarnings("unchecked")
    @Test void priorAdmittedPpm() throws Exception {
        OracleCases.each(M, "ppm", a -> {
            Omega omega = IntentOmega.omegaFromJson(a.get(0));
            LearnerOptions base = LearnerOptions.fromJson(a.get(1));
            List<Observation> obs = new ArrayList<>();
            for (Object x : IntentOmega.arr(a.get(2))) obs.add(new Observation((String) IntentOmega.obj(x).get("verb"), outcome(x).values(), null,
                (int) IntentOmega.dbl(IntentOmega.obj(x).get("y")), "elicitation", null));
            WalletPopulation.PriorMix mix = WalletPopulation.populationPrior((Map<String, Object>) a.get(3), IntentOmega.dbl(a.get(4)));
            return WalletLearner.priorAdmittedPpm(omega, base, obs, mix);
        });
    }
}
