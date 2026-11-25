package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentLearner.ElicitOptions;
import net.atlasauth.pca.intent.IntentLearner.ElicitResult;
import net.atlasauth.pca.intent.IntentLearner.LearnerMetrics;
import net.atlasauth.pca.intent.IntentLearner.LearnerOptions;
import net.atlasauth.pca.intent.IntentLearner.Question;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;
import net.atlasauth.pca.intent.IntentPolicy;
import net.atlasauth.pca.intent.IntentRegion;
import org.junit.jupiter.api.Test;

class IntentLearnerDiffTest {
    private static final String M = "ref-intent-learner";

    private static List<Object> ints(int[] a) {
        List<Object> o = new ArrayList<>();
        for (int x : a) o.add((double) x);
        return o;
    }

    private static Outcome outcome(String verb, Object values) { return IntentOmega.outcomeFromJson(Map.of("verb", verb, "values", values)); }

    private static Map<String, Object> question(Question q) {
        if (q == null) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("verb", q.verb);
        m.put("cell", ints(q.cell));
        m.put("outcome", IntentOmega.outcomeToJson(q.outcome));
        m.put("p", q.p);
        m.put("score", q.score);
        return m;
    }

    private static Map<String, Object> metrics(LearnerMetrics r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("residualRisk", r.residualRisk);
        m.put("burden", r.burden);
        m.put("uncertainty", r.uncertainty);
        m.put("entropyBits", r.entropyBits);
        m.put("log2VersionSpace", r.log2VersionSpace);
        m.put("disagreementMass", r.disagreementMass);
        m.put("meanHarm", r.meanHarm);
        m.put("questions", (double) r.questions);
        m.put("conflicts", (double) r.conflicts);
        return m;
    }

    private static LearnerOptions options(Object o) {
        Map<String, Object> m = IntentOmega.obj(o);
        LearnerOptions opts = LearnerOptions.fromJson(o);
        if ("byRev".equals(m.get("nullMassFn"))) opts.nullMassFn = vs -> vs.reversibility.equals("reversible") ? 0.1 : 0.3;
        if (m.get("priorMix") != null) {
            Map<String, Object> pm = IntentOmega.obj(m.get("priorMix"));
            String kind = (String) pm.get("weight");
            IntentLearner.PriorWeight wt = kind.equals("size") ? (vs, has) -> {
                double k = 1;
                for (int c = 0; c < 64; c++) if (has.test(c)) k++;
                return k;
            } : kind.equals("neg") ? (vs, has) -> -1 : (vs, has) -> 0;
            opts.priorMix = new IntentLearner.PriorMix(IntentOmega.dbl(pm.get("beta")), wt);
        }
        return opts;
    }

    @SuppressWarnings("unchecked")
    private static Object scenario(List<?> a) {
        Omega omega = IntentOmega.omegaFromJson(a.get(0));
        LearnerOptions opts = options(a.get(1));
        IntentLearner l = new IntentLearner(omega, opts);
        List<Object> out = new ArrayList<>();
        for (Object oo : IntentOmega.arr(a.get(2))) {
            Map<String, Object> op = IntentOmega.obj(oo);
            switch ((String) op.get("op")) {
                case "observe": {
                    String src = op.get("source") == null ? "elicitation" : (String) op.get("source");
                    IntentRegion.Region region = op.get("region") == null ? null : IntentRegion.Region.fromJson(op.get("region"));
                    IntentLearner.Observation ob = l.observe(outcome((String) op.get("verb"), op.get("values")), (int) IntentOmega.dbl(op.get("y")), src, region);
                    out.add(ob == null ? null : ob.toJson());
                    break;
                }
                case "probe": {
                    Outcome oc = outcome((String) op.get("verb"), op.get("values"));
                    out.add(List.of(l.acceptance(oc), l.admitsOutcome(oc), l.isVetoed(oc)));
                    break;
                }
                case "next": out.add(question(l.nextQuestion())); break;
                case "metrics": out.add(metrics(l.metrics())); break;
                case "cells": {
                    List<Object> r = new ArrayList<>();
                    for (IntentLearner.CellView c : l.cells()) {
                        Map<String, Object> m = new LinkedHashMap<>();
                        m.put("verb", c.verb); m.put("cell", ints(c.cell)); m.put("p", c.p); m.put("mass", c.mass); m.put("harm", c.harm);
                        m.put("inGrant", c.inGrant); m.put("vetoed", c.vetoed);
                        r.add(m);
                    }
                    out.add(r);
                    break;
                }
                case "unconfirmed": {
                    List<Object> r = new ArrayList<>();
                    for (IntentLearner.Unconfirmed c : l.unconfirmedGrantCells()) {
                        Map<String, Object> m = new LinkedHashMap<>();
                        m.put("verb", c.verb); m.put("cell", ints(c.cell)); m.put("weight", c.weight);
                        r.add(m);
                    }
                    out.add(r);
                    break;
                }
                case "synth": {
                    IntentLearner.Synthesis s = l.synthesize();
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("predicates", s.predicates);
                    m.put("caveats", s.caveats);
                    out.add(m);
                    break;
                }
                case "vetoed": out.add(l.vetoedCells()); break;
                case "observations": {
                    List<Object> r = new ArrayList<>();
                    for (IntentLearner.Observation ob : l.observations) r.add(ob.toJson());
                    out.add(r);
                    break;
                }
                case "replay": out.add(metrics(IntentLearner.replay(omega, opts, l.observations).metrics())); break;
                case "elicit": out.add(elicit(l, omega, op)); break;
                default: throw new IllegalArgumentException("bad op");
            }
        }
        return out;
    }

    private static Object elicit(IntentLearner l, Omega omega, Map<String, Object> op) {
        IntentPolicy.Admitter adm = IntentPolicy.admitter(op.get("policy"));
        int flip = op.get("flipEvery") == null ? 0 : (int) IntentOmega.dbl(op.get("flipEvery"));
        int[] k = {0};
        IntentLearner.Answer ans = q -> {
            VerbSpace vs = null;
            for (VerbSpace v : omega.verbs) if (v.verb.equals(q.verb)) vs = v;
            int y = adm.admits(vs, q.outcome) ? 1 : 0;
            k[0]++;
            return flip != 0 && k[0] % flip == 0 ? 1 - y : y;
        };
        ElicitOptions eo = new ElicitOptions(IntentOmega.dbl(op.get("epsRisk")), IntentOmega.dbl(op.get("epsBurden")), (int) IntentOmega.dbl(op.get("maxQuestions")), Boolean.TRUE.equals(op.get("audit")));
        if (op.get("seed") != null) {
            for (Object s : IntentOmega.arr(op.get("seed"))) {
                Map<String, Object> sm = IntentOmega.obj(s);
                List<Object> cl = IntentOmega.arr(sm.get("cell"));
                int[] cell = new int[cl.size()];
                for (int i = 0; i < cell.length; i++) cell[i] = (int) IntentOmega.dbl(cl.get(i));
                eo.seed.add(new Object[] {sm.get("verb"), cell});
            }
        }
        ElicitResult r = IntentLearner.elicit(l, ans, eo);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("stop", r.stop);
        m.put("questions", (double) r.questions);
        m.put("auditQuestions", (double) r.auditQuestions);
        m.put("seedQuestions", (double) r.seedQuestions);
        List<Object> asked = new ArrayList<>();
        for (Question q : r.asked) asked.add(question(q));
        m.put("asked", asked);
        m.put("metrics", metrics(l.metrics()));
        return m;
    }

    @Test void scenarios() throws Exception { OracleCases.each(M, "scenario", IntentLearnerDiffTest::scenario); }

    @Test void hypothesisCellSets() throws Exception {
        OracleCases.each(M, "hypothesisCellSets", a -> {
            VerbSpace vs = IntentOmega.verbSpaceFromJson(a.get(0));
            IntentLearner.HypothesisClassSpec hc = a.get(1) == null ? null : IntentLearner.HypothesisClassSpec.fromJson(a.get(1));
            Integer mh = null;
            if (a.size() > 2 && a.get(2) != null) mh = (int) IntentOmega.dbl(IntentOmega.obj(a.get(2)).get("maxHypotheses"));
            IntentLearner.SetsResult r = IntentLearner.hypothesisCellSets(vs, hc, mh, null);
            if (a.size() > 2 || a.get(1) == null) return (double) r.sets.size();
            List<Object> sets = new ArrayList<>();
            for (byte[] s : r.sets) {
                List<Object> row = new ArrayList<>();
                for (byte b : s) row.add((double) b);
                sets.add(row);
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("sets", sets);
            m.put("complexity", new ArrayList<Object>(r.complexity));
            return m;
        });
    }

    @Test void hypothesisClassName() throws Exception {
        OracleCases.each(M, "hypothesisClassName", a -> IntentLearner.hypothesisClassName(IntentLearner.HypothesisClassSpec.fromJson(a.get(0))));
    }

    @Test void boxesToPredicates() throws Exception {
        OracleCases.each(M, "boxesToPredicates", a -> {
            List<Object> al = IntentOmega.arr(a.get(1));
            byte[] allowed = new byte[al.size()];
            for (int i = 0; i < allowed.length; i++) allowed[i] = (byte) IntentOmega.dbl(al.get(i));
            return IntentLearner.boxesToPredicates(IntentOmega.verbSpaceFromJson(a.get(0)), allowed);
        });
    }
}
