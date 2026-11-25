package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import net.atlasauth.pca.intent.IntentMath;

/**
 * Active disambiguation by version-space halving over a finite class of readings. A reading is a map
 * {id, family, deterministic, goal, notes}; a distinguishing case is {act, prior, rels}.
 */
public final class GoalDisambiguate {
    private GoalDisambiguate() {}

    public static final Map<String, Integer> DEFAULT_RISK = Map.of("read", 1, "reversible", 2, "external_send", 8, "irreversible", 10);

    /** Question options: the IR ontology the readings are decided against and optional risk / mass of an action (default risk by effect class, mass 1). */
    public static final class Opts {
        public Map<String, Object> ont;
        public Function<Map<String, Object>, Double> riskOf;
        public Function<Map<String, Object>, Double> massOf;
        public Integer budget;

        public Opts(Map<String, Object> ont) { this.ont = ont; }
    }

    private static Map<String, Object> mm(Object o) { return G.m(o); }

    private static double h2(double p) {
        return p <= 0 || p >= 1 ? 0 : -(p * IntentMath.log2(p) + (1 - p) * IntentMath.log2(1 - p));
    }

    public static boolean allowsWitness(Map<String, Object> g, Map<String, Object> ont, Map<String, Object> w) {
        Map<String, Object> hist = GoalExamples.replay(g, ont, G.arr(w.get("prior"), "prior"), G.arr(w.get("rels"), "rels"));
        return "allow".equals(GoalExamples.decideCase(g, ont, G.map("act", w.get("act"), "hist", hist, "rels", w.get("rels"))).get("decision"));
    }

    private static boolean allowSet(Map<String, Object> r, Map<String, Object> w, Map<String, Object> ont) { return allowsWitness(mm(r.get("goal")), ont, w); }

    private static List<Map<String, Object>> goalsOf(List<Map<String, Object>> readings) {
        List<Map<String, Object>> goals = new ArrayList<>();
        for (Map<String, Object> r : readings) goals.add(mm(r.get("goal")));
        return goals;
    }

    /** Candidate witness actions: decision-cell representatives of the joint space plus every reading's cap sequences. */
    static List<Map<String, Object>> witnesses(List<Map<String, Object>> readings, Map<String, Object> ont) {
        List<Map<String, Object>> goals = goalsOf(readings);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object co : G.arr(GoalExamples.cells(GoalExamples.buildSpace(goals, new ArrayList<>()), null).get("cases"), "cases")) {
            out.add(G.map("act", G.get(co, "act"), "prior", new ArrayList<Object>(), "rels", G.get(co, "rels")));
        }
        for (Map<String, Object> r : readings) {
            for (Object eo : G.arr(GoalExamples.boundaryExamples(mm(r.get("goal")), ont, goals, null).get("examples"), "examples")) {
                if (!"cap_sequence".equals(G.get(eo, "kind"))) continue;
                List<Object> prior = new ArrayList<>();
                for (Object a : G.arr(G.get(G.get(eo, "hist"), "adms"), "adms")) prior.add(G.get(a, "act"));
                out.add(G.map("act", G.get(eo, "act"), "prior", prior, "rels", G.get(eo, "rels")));
            }
        }
        return out;
    }

    /** Questions over the symmetric difference of the readings, ranked by H2(vote) x risk x mass (best first). */
    public static List<Map<String, Object>> questions(List<Map<String, Object>> readings, Opts opts) {
        Map<String, Object> ont = opts.ont;
        int k = readings.size();
        Map<String, Object> cls = new LinkedHashMap<>();
        for (Object v : G.arr(ont.get("verbs"), "verbs")) cls.put((String) G.get(v, "verb"), G.get(v, "cls"));
        List<Map<String, Object>> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Map<String, Object> w : witnesses(readings, ont)) {
            List<Object> yes = new ArrayList<>();
            for (Map<String, Object> r : readings) if (allowSet(r, w, ont)) yes.add(r.get("id"));
            if (yes.isEmpty() || yes.size() == k) continue;
            String id = G.stringify(G.list(w.get("act"), G.num(G.arr(w.get("prior"), "prior").size())));
            if (!seen.add(id)) continue;
            Map<String, Object> act = mm(w.get("act"));
            double risk;
            if (opts.riskOf != null) risk = opts.riskOf.apply(act);
            else {
                Object c = cls.get(act.get("verb"));
                Integer r = c == null ? null : DEFAULT_RISK.get(c);
                risk = r == null ? 10 : r;
            }
            double mass = opts.massOf != null ? opts.massOf.apply(act) : 1;
            int np = G.arr(w.get("prior"), "prior").size();
            List<Object> notAllow = new ArrayList<>();
            for (Map<String, Object> r : readings) if (!yes.contains(r.get("id"))) notAllow.add(r.get("id"));
            Map<String, Object> q = new LinkedHashMap<>();
            q.put("id", id);
            q.putAll(w);
            q.put("allow", yes);
            q.put("notAllow", notAllow);
            q.put("text", "Should this be allowed: " + GoalFmt.fmtAct(act) + (np > 0 ? " (after " + np + " earlier identical action(s))" : "") + "?");
            q.put("score", h2((double) yes.size() / k) * risk * mass);
            out.add(q);
        }
        out.sort((a, b) -> {
            double d = (Double) b.get("score") - (Double) a.get("score");
            if (d != 0) return d > 0 ? 1 : -1;
            return ((String) a.get("id")).compareTo((String) b.get("id")) < 0 ? -1 : 1;
        });
        return out;
    }

    /** Fraction of witness cells on which the readings do not all agree on Allow. */
    public static double disagreementMass(List<Map<String, Object>> readings, Map<String, Object> ont) {
        List<Map<String, Object>> w = witnesses(readings, ont);
        if (w.isEmpty()) return 0;
        int split = 0;
        for (Map<String, Object> x : w) {
            int n = 0;
            for (Map<String, Object> r : readings) if (allowSet(r, x, ont)) n++;
            if (n > 0 && n < readings.size()) split++;
        }
        return (double) split / w.size();
    }

    /** Active disambiguation: {status, goal, asked, residualMass, remaining}. {@code ask} maps a question to "allow" or "deny". */
    public static Map<String, Object> disambiguate(List<Map<String, Object>> readings, Function<Map<String, Object>, String> ask, Opts opts) {
        Map<String, Object> ont = opts.ont;
        int budget = opts.budget != null ? opts.budget : readings.size();
        List<Map<String, Object>> active = new ArrayList<>(readings);
        List<Object> asked = new ArrayList<>();
        while (active.size() > 1 && asked.size() < budget) {
            List<Map<String, Object>> qs = questions(active, opts);
            if (qs.isEmpty()) break;
            Map<String, Object> q = qs.get(0);
            asked.add(q);
            boolean allow = "allow".equals(ask.apply(q));
            List<Map<String, Object>> next = new ArrayList<>();
            for (Map<String, Object> r : active) if (allowSet(r, q, ont) == allow) next.add(r);
            active = next;
        }
        double mass = disagreementMass(active, ont);
        Map<String, Object> g = GoalNVersion.meet(goalsOf(active));
        List<Object> remaining = new ArrayList<>();
        for (Map<String, Object> r : active) remaining.add(r.get("id"));
        if (mass > 0) {
            List<Object> hs = new ArrayList<>(G.arr(g.get("holes"), "holes"));
            hs.add(G.map("hid", "budget", "q", "Question budget exhausted with disagreement left.", "domain", new ArrayList<Object>(), "affects", new ArrayList<Object>(), "global", true));
            hs.sort((a, b) -> ((String) G.get(a, "hid")).compareTo((String) G.get(b, "hid")));
            Map<String, Object> g2 = new LinkedHashMap<>(g);
            g2.put("holes", hs);
            return G.map("status", "budget_exhausted", "goal", g2, "asked", asked, "residualMass", mass, "remaining", remaining);
        }
        return G.map("status", "resolved", "goal", g, "asked", asked, "residualMass", 0, "remaining", remaining);
    }
}
