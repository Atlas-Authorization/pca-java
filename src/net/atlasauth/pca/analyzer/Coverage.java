package net.atlasauth.pca.analyzer;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import net.atlasauth.pca.Predicates;
import net.atlasauth.pca.analyzer.Enumerate.PolicyModel;

/**
 * POLICY COVERAGE ({@code opa test --coverage} for PCA). Over a body of traffic it reports which clauses of a policy ever DECIDED, which
 * never even matched, which the analyzer says are unreachable, how close the traffic came to each numeric threshold, and which single-edit
 * mutations of the policy (widen a cap, drop a prohibition, flip {@code <=} to {@code <}) the traffic cannot tell from the original. A
 * surviving mutant is a missing test and comes with the action that would kill it; a mutant proven equivalent is not a gap.
 */
public final class Coverage {
    private Coverage() {}

    public static String permitId(int i) { return "permit[" + i + "]"; }

    private static String idStr(Object o, boolean present) { return CaveatAnalysis.jsString(o, present); }

    /**
     * The decision with the clause that decided it: a forbid beats an approval rule, which beats a permit. Returns
     * {decision, winner: {kind: permit | veto | tighten | caveat | none, id}, also: [other clauses that fired]}.
     */
    public static Map<String, Object> witnessOf(PolicyModel model, Map<String, Object> action) {
        String decision = Enumerate.decideAction(model, action);
        Map<String, Object> ctx = Enumerate.contextOfAction(action);
        List<Object> permits = new ArrayList<>();
        for (int i = 0; i < model.predicates.size(); i++) if (Predicates.predicateMatches(model.predicates.get(i), ctx)) permits.add(permitId(i));
        List<Object> vetoes = new ArrayList<>();
        for (Object v : model.vetoes) if (Enumerate.vetoApplies(v, ctx)) vetoes.add(v);
        List<Object> tighten = new ArrayList<>();
        for (Object t : model.tighten) if (Predicates.evaluateConditionTri(Js.get(t, "when"), ctx) != Predicates.Tri.FALSE) tighten.add(t);

        if (!model.caveatSat || decision.equals("deny")) {
            if (!model.caveatSat) return done(decision, "caveat", "caveats", permits, vetoes, tighten);
            if (permits.isEmpty()) return done(decision, "none", null, permits, vetoes, tighten);
            for (Object v : vetoes) if ("deny".equals(Js.get(v, "kind"))) return done(decision, "veto", Js.get(v, "id"), permits, vetoes, tighten);
            for (Object t : tighten) if ("deny".equals(Js.get(t, "signal"))) return done(decision, "tighten", Js.get(t, "id"), permits, vetoes, tighten);
            return done(decision, "caveat", "caveats", permits, vetoes, tighten); // reversibility cap or an ancestor of the chain
        }
        if (decision.equals("escalate")) {
            for (Object v : vetoes) if ("approval".equals(Js.get(v, "kind"))) return done(decision, "veto", Js.get(v, "id"), permits, vetoes, tighten);
            return done(decision, "tighten", tighten.isEmpty() ? null : Js.get(tighten.get(0), "id"), permits, vetoes, tighten);
        }
        return done(decision, "permit", permits.isEmpty() ? null : permits.get(0), permits, vetoes, tighten);
    }

    private static Map<String, Object> done(String decision, String kind, Object id, List<Object> permits, List<Object> vetoes, List<Object> tighten) {
        List<Object> also = new ArrayList<>();
        List<Object> all = new ArrayList<>(permits);
        for (Object v : vetoes) all.add(Js.get(v, "id"));
        for (Object t : tighten) all.add(Js.get(t, "id"));
        for (Object x : all) if (!Js.strictEq(x, id)) also.add(x);
        return Js.obj("decision", decision, "winner", Js.obj("kind", kind, "id", id), "also", also);
    }

    // ---- mutation operators ----

    private static final class Variant {
        final Object cond; final String what;
        Variant(Object cond, String what) { this.cond = cond; this.what = what; }
    }

    private static final Map<String, String> FLIP = Map.of("lt", "lte", "lte", "lt", "gt", "gte", "gte", "gt", "eq", "ne", "ne", "eq", "in", "nin", "nin", "in");

    private static List<Variant> variantsOfCond(Object c, double eps) {
        List<Variant> out = new ArrayList<>();
        if (!(c instanceof Map || c instanceof List)) return out;
        if (Field.isGroup(c)) {
            if (Js.has(c, "not")) {
                for (Variant v : variantsOfCond(Js.get(c, "not"), eps)) out.add(new Variant(Js.obj("not", v.cond), "not(" + v.what + ")"));
                return out;
            }
            boolean isAll = Js.has(c, "all_of");
            Object kidsO = Js.get(c, isAll ? "all_of" : "any_of");
            if (!(kidsO instanceof List)) throw new IllegalArgumentException("group children are not an array");
            List<Object> kids = Js.list(kidsO);
            for (int i = 0; i < kids.size(); i++) {
                for (Variant v : variantsOfCond(kids.get(i), eps)) {
                    List<Object> next = new ArrayList<>(kids);
                    next.set(i, v.cond);
                    out.add(new Variant(Js.obj(isAll ? "all_of" : "any_of", next), (isAll ? "all_of" : "any_of") + "[" + i + "] " + v.what));
                }
            }
            return out;
        }
        if (!Field.isLeaf(c) || Js.has(c, "ref")) return out;
        String field = (String) Js.get(c, "field");
        String name = field.startsWith("action.params.") ? field.substring("action.params.".length()) : field;
        Object op = Js.get(c, "op");
        Object value = Js.get(c, "value");
        if (Js.isFin(value) && op instanceof String && java.util.Arrays.asList("lt", "lte", "gt", "gte", "eq").contains(op)) {
            double d = Js.num(value);
            Map<String, Object> up = Js.copy(c);
            up.put("value", Js.n(d + eps));
            out.add(new Variant(up, name + " " + op + " " + Js.fmt(d) + " -> " + Js.fmt(d + eps)));
            Map<String, Object> down = Js.copy(c);
            down.put("value", Js.n(d - eps));
            out.add(new Variant(down, name + " " + op + " " + Js.fmt(d) + " -> " + Js.fmt(d - eps)));
        }
        if (op instanceof String && FLIP.containsKey(op)) {
            Map<String, Object> fl = Js.copy(c);
            fl.put("op", FLIP.get(op));
            out.add(new Variant(fl, name + " " + op + " -> " + FLIP.get(op)));
        }
        return out;
    }

    private static final class Mutant {
        final String id, description; final Object policy;
        Mutant(String id, String description, Object policy) { this.id = id; this.description = description; this.policy = policy; }
    }

    private static Map<String, Object> mk(PolicyModel p, List<Object> predicates, List<Object> vetoes, List<Object> tighten) {
        return Js.obj("predicates", predicates, "caveats", p.caveats, "vetoes", vetoes, "tighten", tighten);
    }

    private static List<Object> without(List<Object> xs, int i) {
        List<Object> out = new ArrayList<>(xs);
        out.remove(i);
        return out;
    }

    private static List<Object> replaced(List<Object> xs, int i, Object v) {
        List<Object> out = new ArrayList<>(xs);
        out.set(i, v);
        return out;
    }

    private static List<Mutant> mutantsOf(PolicyModel policy, double eps) {
        List<Mutant> out = new ArrayList<>();
        for (int i = 0; i < policy.predicates.size(); i++) {
            Object p = policy.predicates.get(i);
            out.add(new Mutant("drop-" + permitId(i), "drop " + permitId(i), mk(policy, without(policy.predicates, i), policy.vetoes, policy.tighten)));
            Object w = Js.get(p, "where");
            if (w instanceof List) {
                List<Object> where = Js.list(w);
                for (int j = 0; j < where.size(); j++) {
                    for (Variant v : variantsOfCond(where.get(j), eps)) {
                        Map<String, Object> np = Js.copy(p);
                        np.put("where", replaced(where, j, v.cond));
                        out.add(new Mutant(permitId(i) + ".where[" + j + "]:" + v.what, permitId(i) + ": " + v.what, mk(policy, replaced(policy.predicates, i, np), policy.vetoes, policy.tighten)));
                    }
                    Map<String, Object> np = Js.copy(p);
                    np.put("where", without(where, j));
                    out.add(new Mutant(permitId(i) + ".where[" + j + "]:drop", permitId(i) + ": drop condition " + j, mk(policy, replaced(policy.predicates, i, np), policy.vetoes, policy.tighten)));
                }
            }
        }
        for (int i = 0; i < policy.vetoes.size(); i++) {
            Object v = policy.vetoes.get(i);
            String id = idStr(Js.get(v, "id"), Js.has(v, "id"));
            out.add(new Mutant("drop-veto:" + id, "drop prohibition " + id, mk(policy, policy.predicates, without(policy.vetoes, i), policy.tighten)));
            Object over = Js.get(v, "over");
            if (Js.truthy(over)) {
                Map<String, Object> nv = Js.copy(v);
                Map<String, Object> no = Js.copy(over);
                no.put("threshold", Js.n(Js.numOrNaN(over, "threshold") + eps));
                nv.put("over", no);
                out.add(new Mutant("veto:" + id + ":threshold+", "raise the " + id + " threshold by " + Js.fmt(eps), mk(policy, policy.predicates, replaced(policy.vetoes, i, nv), policy.tighten)));
            }
        }
        for (int i = 0; i < policy.tighten.size(); i++) {
            Object t = policy.tighten.get(i);
            String id = idStr(Js.get(t, "id"), Js.has(t, "id"));
            out.add(new Mutant("drop-tighten:" + id, "drop tighten rule " + id, mk(policy, policy.predicates, policy.vetoes, without(policy.tighten, i))));
        }
        return out;
    }

    private static void walkParams(Object c, Set<String> paths) {
        if (!(c instanceof Map || c instanceof List)) return;
        if (Field.isGroup(c)) {
            if (Js.has(c, "all_of")) { for (Object x : listOrThrow(Js.get(c, "all_of"))) walkParams(x, paths); }
            else if (Js.has(c, "any_of")) { for (Object x : listOrThrow(Js.get(c, "any_of"))) walkParams(x, paths); }
            else walkParams(Js.get(c, "not"), paths);
        } else if (Field.isLeaf(c)) {
            String f = (String) Js.get(c, "field");
            Object op = Js.get(c, "op");
            if (f.startsWith("action.params.") && op instanceof String && java.util.Arrays.asList("lt", "lte", "gt", "gte", "eq", "in", "nin").contains(op)) paths.add(f);
        }
    }

    private static List<?> listOrThrow(Object o) {
        if (!(o instanceof List)) throw new IllegalArgumentException("group children are not an array");
        return (List<?>) o;
    }

    private static Object reach(PolicyModel model, String kind, int idx) {
        if (kind.equals("permit")) {
            Map<String, Object> r = Analyzer.alwaysDenies(Js.obj("predicates", Js.arr(model.predicates.get(idx)), "caveats", model.caveats));
            return Js.truthy(r.get("approximate")) ? (Object) "unknown" : (Object) !Boolean.TRUE.equals(r.get("alwaysDenies"));
        }
        if (kind.equals("veto")) {
            Map<String, Object> r = Analyzer.alwaysDenies(Js.obj("predicates", Js.arr(Js.get(model.vetoes.get(idx), "when"))));
            return Js.truthy(r.get("approximate")) ? (Object) "unknown" : (Object) !Boolean.TRUE.equals(r.get("alwaysDenies"));
        }
        return "unknown";
    }

    private static double ratio(double n, double d) { return d == 0 ? 1 : n / d; }

    /** Coverage of {@code policy} by {@code traffic} (production traffic, simulated actions or the cases of a test document). Options: epsilon (default 1), maxMutants (200). */
    public static Map<String, Object> coverage(Object policy, List<Object> traffic, Map<String, Object> o) {
        PolicyModel model = Enumerate.toModel(policy);
        double eps = Js.get(o, "epsilon") == null ? 1 : Js.toNum(Js.get(o, "epsilon"));
        List<Object> idObjs = new ArrayList<>();
        List<String> kinds = new ArrayList<>();
        for (int i = 0; i < model.predicates.size(); i++) { idObjs.add(permitId(i)); kinds.add("permit"); }
        for (Object v : model.vetoes) { idObjs.add(Js.get(v, "id")); kinds.add("veto"); }
        for (Object t : model.tighten) { idObjs.add(Js.get(t, "id")); kinds.add("tighten"); }
        Map<Object, Integer> matched = new HashMap<>(), decisive = new HashMap<>();
        for (Object a : traffic) {
            Map<String, Object> w = witnessOf(model, Js.map(Js.req(a)));
            Object win = Js.get(Js.get(w, "winner"), "id");
            if (win != null) decisive.merge(win, 1, Integer::sum);
            List<Object> all = new ArrayList<>();
            all.add(win);
            all.addAll(Js.list(w.get("also")));
            for (Object id : all) if (id != null) matched.merge(id, 1, Integer::sum);
        }
        List<Object> clauses = new ArrayList<>();
        List<Map<String, Object>> cl = new ArrayList<>();
        for (int n = 0; n < idObjs.size(); n++) {
            String kind = kinds.get(n);
            int idx = kind.equals("permit") ? n : kind.equals("veto") ? n - model.predicates.size() : n - model.predicates.size() - model.vetoes.size();
            Object id = idObjs.get(n);
            Map<String, Object> c = Js.obj("id", id, "kind", kind, "matched", Js.n(matched.getOrDefault(id, 0)), "decisive", Js.n(decisive.getOrDefault(id, 0)), "reachable", reach(model, kind, idx));
            clauses.add(c);
            cl.add(c);
        }
        Set<String> paths = new TreeSet<>(); // default string order
        for (Object p : Enumerate.probeSet(model)) {
            if (p == null) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'where')");
            Object w = Js.get(p, "where");
            if (w instanceof List) for (Object c : (List<?>) w) walkParams(c, paths);
        }
        for (Object v : model.vetoes) {
            Object over = Js.get(v, "over");
            if (Js.truthy(over) && Js.get(over, "path") instanceof String) paths.add((String) Js.get(over, "path"));
        }
        List<Object> boundaries = new ArrayList<>();
        for (String path : paths) {
            String name = path.substring("action.params.".length());
            List<Double> vals = new ArrayList<>();
            for (Object a : traffic) {
                Object pp = Js.get(a, "params");
                Object v = pp instanceof Map ? Js.map(pp).get(name) : null;
                if (Js.isNum(v)) vals.add(Js.num(v));
            }
            for (double t : Exposure.thresholds(model, path)) {
                boolean at = false, below = false, above = false;
                for (double v : vals) {
                    if (v == t) at = true;
                    if (v < t && v >= t - eps) below = true;
                    if (v > t && v <= t + eps) above = true;
                }
                boundaries.add(Js.obj("path", path, "threshold", Js.n(t), "below", below, "at", at, "above", above));
            }
        }
        List<Object> survivors = new ArrayList<>();
        int killed = 0, equiv = 0;
        List<Mutant> all = mutantsOf(model, eps);
        double maxM = Js.get(o, "maxMutants") == null ? 200 : Js.toNum(Js.get(o, "maxMutants"));
        if (all.size() > maxM) all = all.subList(0, (int) Math.max(0, maxM));
        List<String> base = new ArrayList<>();
        for (Object a : traffic) base.add(Enumerate.decideAction(model, a));
        for (Mutant m : all) {
            PolicyModel mm = Enumerate.toModel(m.policy);
            boolean differs = false;
            for (int i = 0; i < traffic.size(); i++) if (!Enumerate.decideAction(mm, traffic.get(i)).equals(base.get(i))) { differs = true; break; }
            if (differs) { killed++; continue; }
            Map<String, Object> eq = Analyzer.equivalent(policy, m.policy);
            if (Boolean.TRUE.equals(eq.get("equivalent"))) { equiv++; continue; }
            Map<String, Object> s = Js.obj("id", m.id, "description", m.description);
            if (Js.truthy(eq.get("counterexample"))) s.put("killer", eq.get("counterexample"));
            survivors.add(s);
        }
        List<Map<String, Object>> live = new ArrayList<>();
        for (Map<String, Object> c : cl) if (!Boolean.FALSE.equals(c.get("reachable"))) live.add(c);
        int liveDecisive = 0;
        for (Map<String, Object> c : live) if (Js.num(c.get("decisive")) > 0) liveDecisive++;
        int bFull = 0;
        for (Object b : boundaries) if (Boolean.TRUE.equals(Js.get(b, "at")) && Boolean.TRUE.equals(Js.get(b, "below")) && Boolean.TRUE.equals(Js.get(b, "above"))) bFull++;
        List<Object> neverMatched = new ArrayList<>(), neverDecisive = new ArrayList<>(), untested = new ArrayList<>(), unreachable = new ArrayList<>();
        for (Map<String, Object> c : cl) {
            if (Js.num(c.get("matched")) == 0) neverMatched.add(c.get("id"));
            if (Js.num(c.get("decisive")) == 0) neverDecisive.add(c.get("id"));
            if (!Boolean.FALSE.equals(c.get("reachable")) && Js.num(c.get("matched")) == 0) untested.add(c.get("id"));
            if (Boolean.FALSE.equals(c.get("reachable"))) unreachable.add(c.get("id"));
        }
        return Js.obj("traffic", Js.n(traffic.size()), "policyDigest", Residual.policyDigestOf(model), "clauses", clauses,
            "neverMatched", neverMatched, "neverDecisive", neverDecisive, "untested", untested, "unreachable", unreachable, "boundaries", boundaries,
            "mutants", Js.obj("total", Js.n(all.size()), "killed", Js.n(killed), "equivalent", Js.n(equiv), "survivors", survivors),
            "score", Js.obj("clauses", Js.n(ratio(liveDecisive, live.size())), "boundaries", Js.n(ratio(bFull, boundaries.size())), "mutation", Js.n(ratio(killed, all.size() - equiv))));
    }

    private static String toFixed2(double x) { return new BigDecimal(x).setScale(2, RoundingMode.HALF_UP).toPlainString(); }

    /** A CI gate over a coverage report: {ok, reasons}. {@code min}: clauses, boundaries, mutation, maxSurvivors. */
    public static Map<String, Object> coverageGate(Map<String, Object> r, Map<String, Object> min) {
        List<Object> reasons = new ArrayList<>();
        Object score = Js.get(r, "score");
        double sc = Js.toNum(Js.get(score, "clauses")), sb = Js.toNum(Js.get(score, "boundaries")), sm = Js.toNum(Js.get(score, "mutation"));
        if (sc < (Js.get(min, "clauses") == null ? 0 : Js.toNum(Js.get(min, "clauses")))) reasons.add("clause coverage " + toFixed2(sc) + " < " + idStr(Js.get(min, "clauses"), Js.has(min, "clauses")));
        if (sb < (Js.get(min, "boundaries") == null ? 0 : Js.toNum(Js.get(min, "boundaries")))) reasons.add("boundary coverage " + toFixed2(sb) + " < " + idStr(Js.get(min, "boundaries"), Js.has(min, "boundaries")));
        if (sm < (Js.get(min, "mutation") == null ? 0 : Js.toNum(Js.get(min, "mutation")))) reasons.add("mutation score " + toFixed2(sm) + " < " + idStr(Js.get(min, "mutation"), Js.has(min, "mutation")));
        Object survivors = Js.get(Js.get(r, "mutants"), "survivors");
        if (Js.has(min, "maxSurvivors") && Js.toNum(Js.n(Js.list(survivors).size())) > Js.toNum(Js.get(min, "maxSurvivors"))) {
            reasons.add(Js.list(survivors).size() + " surviving mutants > " + idStr(Js.get(min, "maxSurvivors"), true));
        }
        List<Object> unr = Js.list(Js.get(r, "unreachable"));
        if (!unr.isEmpty()) {
            List<String> s = new ArrayList<>();
            for (Object u : unr) s.add(u == null ? "" : idStr(u, true));
            reasons.add("unreachable clauses: " + String.join(", ", s));
        }
        return Js.obj("ok", reasons.isEmpty(), "reasons", reasons);
    }
}
