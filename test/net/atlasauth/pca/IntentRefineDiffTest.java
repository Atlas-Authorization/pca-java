package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentMapKit;
import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;
import net.atlasauth.pca.intent.IntentPolicy;
import net.atlasauth.pca.intent.IntentRegion;
import net.atlasauth.pca.intent.IntentRefine;
import net.atlasauth.pca.intent.IntentRefine.PartialAnswer;
import org.junit.jupiter.api.Test;

class IntentRefineDiffTest {
    private static final String M = "ref-intent-refine";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> ls(Object o) { return (List<Object>) o; }

    private static List<Object> ints(int[] a) {
        List<Object> o = new ArrayList<>();
        for (int x : a) o.add((double) x);
        return o;
    }

    private static IntentLearner make(Object omega, Object mapOpts, Object obs) {
        IntentLearner l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(omega), MapLearnerOptions.fromJson(mapOpts));
        for (Object xo : ls(obs)) {
            Map<String, Object> x = mp(xo);
            l.observe(IntentOmega.outcomeFromJson(x), (int) IntentOmega.dbl(x.get("y")), (String) x.get("source"), x.get("region") == null ? null : IntentRegion.Region.fromJson(x.get("region")));
        }
        return l;
    }

    private static List<Object> observations(IntentLearner l) {
        List<Object> r = new ArrayList<>();
        for (IntentLearner.Observation o : l.observations) r.add(o.toJson());
        return r;
    }

    private static Map<String, Object> metrics(IntentLearner.LearnerMetrics r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("residualRisk", r.residualRisk); m.put("burden", r.burden); m.put("uncertainty", r.uncertainty); m.put("entropyBits", r.entropyBits);
        m.put("log2VersionSpace", r.log2VersionSpace); m.put("disagreementMass", r.disagreementMass); m.put("meanHarm", r.meanHarm);
        m.put("questions", (double) r.questions); m.put("conflicts", (double) r.conflicts);
        return m;
    }

    private static List<Object> cells(IntentLearner l) {
        List<Object> r = new ArrayList<>();
        for (IntentLearner.CellView c : l.cells()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("verb", c.verb); m.put("cell", ints(c.cell)); m.put("p", c.p);
            r.add(m);
        }
        return r;
    }

    private static Map<String, Object> synth(IntentLearner l) {
        IntentLearner.Synthesis s = l.synthesize();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("predicates", s.predicates);
        m.put("caveats", s.caveats);
        return m;
    }

    @Test void refineOmega() throws Exception {
        OracleCases.each(M, "refineOmega", a -> IntentOmega.omegaToJson(IntentRefine.refineOmega(IntentOmega.omegaFromJson(a.get(0)), IntentRefine.Refinement.fromJson(a.get(1)))));
    }

    @Test void regionsOf() throws Exception {
        OracleCases.each(M, "regionsOf", a -> {
            IntentLearner l = make(a.get(0), a.get(1), a.get(2));
            Omega om = Boolean.TRUE.equals(a.get(3)) ? new Omega(new ArrayList<>(), new ArrayList<>()) : l.omega;
            List<Object> out = new ArrayList<>();
            for (IntentLearner.Observation o : l.observations) out.add(IntentRefine.regionOfObservation(om, o).toJson());
            return out;
        });
    }

    @Test void refineScenario() throws Exception {
        OracleCases.each(M, "refineScenario", a -> {
            IntentLearner l = make(a.get(0), a.get(1), a.get(2));
            IntentLearner nl = IntentRefine.refineLearner(l, IntentRefine.Refinement.fromJson(a.get(3)), null);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("omega", IntentOmega.omegaToJson(nl.omega));
            m.put("observations", observations(nl));
            m.put("metrics", metrics(nl.metrics()));
            m.put("cells", cells(nl));
            return m;
        });
    }

    @Test void partialScenario() throws Exception {
        OracleCases.each(M, "partialScenario", a -> {
            IntentLearner l = make(a.get(0), a.get(1), a.get(2));
            Map<String, Object> q = mp(a.get(3));
            String verb = (String) q.get("verb");
            VerbSpace vs = null;
            for (VerbSpace v : l.omega.verbs) if (v.verb.equals(verb)) vs = v;
            List<Object> cl = ls(q.get("cell"));
            int[] cell = new int[cl.size()];
            for (int i = 0; i < cell.length; i++) cell[i] = (int) IntentOmega.dbl(cl.get(i));
            Outcome oc = vs == null ? new Outcome(verb, new LinkedHashMap<>()) : IntentOmega.cellRep(vs, cell);
            IntentLearner.Question question = new IntentLearner.Question(verb, cell, oc, l.acceptance(oc), 0);
            IntentRefine.PartialResult r = IntentRefine.answerPartial(l, question, PartialAnswer.fromJson(a.get(4)));
            List<Object> added = new ArrayList<>();
            for (IntentLearner.Observation o : r.added) added.add(o.toJson());
            if (verb.equals("nope")) return added;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("omega", IntentOmega.omegaToJson(r.learner.omega));
            m.put("added", added);
            m.put("observations", observations(r.learner));
            m.put("metrics", metrics(r.learner.metrics()));
            m.put("synth", synth(r.learner));
            return m;
        });
    }

    @Test void adaptiveScenario() throws Exception {
        OracleCases.each(M, "adaptiveScenario", a -> {
            IntentLearner l0 = IntentMapKit.createLearner(IntentOmega.omegaFromJson(a.get(0)), MapLearnerOptions.fromJson(a.get(1)));
            IntentPolicy.Admitter adm = IntentPolicy.admitter(a.get(2));
            List<PartialAnswer> ps = new ArrayList<>();
            for (Object p : ls(a.get(3))) ps.add(PartialAnswer.fromJson(p));
            int ev = (int) IntentOmega.dbl(a.get(4));
            Map<String, Object> oo = mp(a.get(5));
            int[] kp = {0, 0};
            IntentRefine.AdaptiveAnswer ans = (q, l) -> {
                kp[0]++;
                if (kp[0] % ev == 0 && kp[1] < ps.size() && q.verb.equals("stripe.refund")) return ps.get(kp[1]++);
                VerbSpace vs = null;
                for (VerbSpace v : l.omega.verbs) if (v.verb.equals(q.verb)) vs = v;
                return adm.admits(vs, q.outcome) ? 1 : 0;
            };
            IntentLearner.ElicitOptions eo = new IntentLearner.ElicitOptions(0.001, 0.01, oo.get("maxQuestions") == null ? 25 : (int) IntentOmega.dbl(oo.get("maxQuestions")), Boolean.TRUE.equals(oo.get("audit")));
            if (oo.get("seed") != null) {
                for (Object s : ls(oo.get("seed"))) {
                    Map<String, Object> sm = mp(s);
                    List<Object> cl = ls(sm.get("cell"));
                    int[] cell = new int[cl.size()];
                    for (int i = 0; i < cell.length; i++) cell[i] = (int) IntentOmega.dbl(cl.get(i));
                    eo.seed.add(new Object[] {sm.get("verb"), cell});
                }
            }
            Integer maxRef = oo.get("maxRefinements") == null ? null : (int) IntentOmega.dbl(oo.get("maxRefinements"));
            IntentRefine.AdaptiveElicitResult r = IntentRefine.elicitAdaptive(l0, ans, eo, maxRef);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("stop", r.stop); m.put("questions", (double) r.questions); m.put("auditQuestions", (double) r.auditQuestions);
            m.put("seedQuestions", (double) r.seedQuestions); m.put("refinements", (double) r.refinements);
            List<Object> asked = new ArrayList<>();
            for (IntentLearner.Question q : r.asked) {
                Map<String, Object> qm = new LinkedHashMap<>();
                qm.put("verb", q.verb); qm.put("cell", ints(q.cell)); qm.put("outcome", IntentOmega.outcomeToJson(q.outcome)); qm.put("p", q.p); qm.put("score", q.score);
                asked.add(qm);
            }
            m.put("asked", asked);
            m.put("omega", IntentOmega.omegaToJson(r.learner.omega));
            m.put("metrics", metrics(r.learner.metrics()));
            m.put("observations", observations(r.learner));
            return m;
        });
    }
}
