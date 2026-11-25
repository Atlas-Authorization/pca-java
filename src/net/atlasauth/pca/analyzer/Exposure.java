package net.atlasauth.pca.analyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Catalog;
import net.atlasauth.pca.analyzer.Enumerate.Collected;
import net.atlasauth.pca.analyzer.Enumerate.FieldProbe;
import net.atlasauth.pca.analyzer.Enumerate.PolicyModel;
import net.atlasauth.pca.analyzer.Enumerate.ProbeInputs;
import net.atlasauth.pca.analyzer.Enumerate.Probes;
import net.atlasauth.pca.analyzer.Enumerate.Rep;
import net.atlasauth.pca.analyzer.Enumerate.SearchOutcome;

/**
 * QUANTITATIVE AND TERNARY STATIC QUERIES: the most that can ever be spent under a policy, the actions that need a human, the reach of
 * a delegation chain, and a first-class diff. Every witness is re-checked by the real evaluator; a number is exact only on the decided
 * fragment, otherwise the result carries {@code approximate: true} and the bound errs on the high side.
 */
public final class Exposure {
    private Exposure() {}

    private static final double HUGE = 9007199254740991.0; // Number.MAX_SAFE_INTEGER

    // ---- thresholds ----

    private static void condThresholds(Object c, String path, List<Double> into) {
        if (!(c instanceof Map || c instanceof List)) return;
        if (Field.isGroup(c)) {
            if (Js.has(c, "all_of") && Js.get(c, "all_of") instanceof List) { for (Object x : (List<?>) Js.get(c, "all_of")) condThresholds(x, path, into); }
            else if (Js.has(c, "any_of") && Js.get(c, "any_of") instanceof List) { for (Object x : (List<?>) Js.get(c, "any_of")) condThresholds(x, path, into); }
            else if (Js.has(c, "not")) condThresholds(Js.get(c, "not"), path, into);
            return;
        }
        if (!Field.isLeaf(c) || !path.equals(Js.get(c, "field"))) return;
        Object v = Js.get(c, "value");
        if (Js.isFin(v)) into.add(Js.num(v));
        else if (v instanceof List) for (Object x : (List<?>) v) if (Js.isFin(x)) into.add(Js.num(x));
    }

    /** Every numeric literal the policy compares {@code path} against (permits, vetoes and tighten rules), ascending and distinct. */
    static List<Double> thresholds(PolicyModel model, String path) {
        List<Double> out = new ArrayList<>();
        for (Object p : Enumerate.probeSet(model)) {
            if (p == null) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'where')");
            Object w = Js.get(p, "where");
            if (w instanceof List) for (Object c : (List<?>) w) condThresholds(c, path, out);
        }
        for (Object v : model.vetoes) {
            Object over = Js.get(v, "over");
            if (Js.truthy(over) && path.equals(Js.get(over, "path")) && Js.has(over, "threshold") && Js.isNum(Js.get(over, "threshold"))) out.add(Js.num(Js.get(over, "threshold")));
        }
        return distinctSorted(out);
    }

    static List<Double> distinctSorted(List<Double> xs) {
        Set<Double> seen = new HashSet<>();
        List<Double> out = new ArrayList<>();
        for (double d : xs) { double k = d == 0 ? 0.0 : d; if (!Double.isNaN(k) && seen.add(k)) out.add(k); }
        Collections.sort(out);
        return out;
    }

    /** {@link #thresholds} as JSON numbers. */
    public static List<Object> thresholdsOf(PolicyModel model, String path) {
        List<Object> out = new ArrayList<>();
        for (double d : thresholds(model, path)) out.add(Js.n(d));
        return out;
    }

    // ---- per-action peak ----

    /** The largest amount of one verb: admitted or autonomous, whether a supremum is attained, and a verified witness. */
    public static final class Peak {
        public final boolean admitted;
        /** Largest amount (Infinity = unbounded); a supremum no action reaches when {@code attained} is false. */
        public final double max;
        public final boolean attained;
        public final Map<String, Object> witness;
        Peak(boolean admitted, double max, boolean attained, Map<String, Object> witness) { this.admitted = admitted; this.max = max; this.attained = attained; this.witness = witness; }
        public Map<String, Object> toJson() {
            Map<String, Object> m = Js.obj("admitted", admitted, "max", Js.n(max), "attained", attained);
            if (witness != null) m.put("witness", witness);
            return m;
        }
    }

    private static final class PeakOutcome {
        final Peak peak; final boolean overflow;
        PeakOutcome(Peak peak, boolean overflow) { this.peak = peak; this.overflow = overflow; }
    }

    private static String amountFieldOf(Map<String, Object> o) {
        Object f = Js.get(o, "amountField");
        return f == null ? "amount" : f instanceof String ? (String) f : CaveatAnalysis.jsString(f, true);
    }

    private static Probes pinned(Probes pr, String path, double value, boolean hasResource, Object resource) {
        Probes p = pr.copy();
        List<FieldProbe> fields = new ArrayList<>();
        for (FieldProbe f : pr.fields) if (!f.path.equals(path)) fields.add(f);
        List<Object> one = new ArrayList<>();
        one.add(Js.n(value));
        fields.add(new FieldProbe(path, one));
        p.fields = fields;
        if (hasResource) { p.resources = new ArrayList<>(); p.resources.add(resource); }
        return p;
    }

    private static PeakOutcome peakAt(PolicyModel model, Map<String, Object> o, boolean allowOnly) {
        String field = amountFieldOf(o);
        String path = "action.params." + field;
        double max = Analyzer.boundOf(o);
        ProbeInputs in = new ProbeInputs();
        in.predicateSets.add(Enumerate.probeSet(model));
        in.varyReversibility = model.revCap != null;
        Probes base = Enumerate.collectProbes(in);
        base.verbs = new ArrayList<>();
        base.verbs.add(Js.get(o, "verb"));
        List<Double> T = thresholds(model, path);
        double lo = Math.max(0, Js.get(o, "min") == null ? 0 : Js.toNum(Js.get(o, "min")));
        double hi = Js.get(o, "max") == null ? Double.POSITIVE_INFINITY : Js.toNum(Js.get(o, "max"));
        List<Double> raw = new ArrayList<>();
        for (int i = 0; i < T.size(); i++) {
            double t = T.get(i);
            raw.add(t - 1);
            raw.add(t);
            if (i + 1 < T.size()) raw.add((t + T.get(i + 1)) / 2);
        }
        raw.add(T.size() > 0 ? T.get(T.size() - 1) + 1 : 0.0);
        raw.add(HUGE);
        raw.add(lo);
        if (!Double.isNaN(hi) && !Double.isInfinite(hi)) raw.add(hi);
        List<Double> cands = new ArrayList<>();
        for (double c : distinctSorted(raw)) if (c >= lo && c <= hi && !Double.isInfinite(c)) cands.add(c);
        Collections.reverse(cands); // largest first
        boolean hasRes = Js.has(o, "resource");
        Object res = Js.get(o, "resource");
        boolean integer = Boolean.TRUE.equals(Js.get(o, "integer"));
        boolean overflow = false;
        double top = T.isEmpty() ? Double.NEGATIVE_INFINITY : T.get(T.size() - 1);
        for (double c : cands) {
            SearchOutcome out = Enumerate.search(pinned(base, path, c, hasRes, res), rep -> {
                String d = Enumerate.decide(model, rep);
                return allowOnly ? d.equals("allow") : !d.equals("deny");
            }, max);
            if (out.overflow) { overflow = true; break; }
            if (out.hit == null) continue;
            Rep hit = out.hit;
            java.util.function.DoubleFunction<Map<String, Object>> act = v -> {
                Map<String, Object> a = Enumerate.repToAction(hit);
                Map<String, Object> params = Js.copy(a.get("params"));
                params.put(field, Js.n(v));
                a.put("params", params);
                return a;
            };
            java.util.function.Predicate<Map<String, Object>> holds = a -> {
                String d = Enumerate.decideAction(model, a);
                return allowOnly ? d.equals("allow") : !d.equals("deny");
            };
            if (c > top) {
                if (!Double.isNaN(hi) && !Double.isInfinite(hi)) {
                    Map<String, Object> w = act.apply(hi);
                    return new PeakOutcome(new Peak(true, hi, holds.test(w), act.apply(hi)), false);
                }
                return new PeakOutcome(new Peak(true, Double.POSITIVE_INFINITY, false, act.apply(HUGE)), false);
            }
            if (T.contains(c == 0 ? 0.0 : c)) return new PeakOutcome(new Peak(true, c, true, act.apply(c)), false);
            double next = Double.NaN;
            for (double t : T) if (t > c) { next = t; break; }
            if (integer) {
                double m = Math.ceil(next) - 1;
                if (m >= c && holds.test(act.apply(m))) return new PeakOutcome(new Peak(true, m, true, act.apply(m)), false);
            }
            return new PeakOutcome(new Peak(true, next, false, act.apply(c)), false);
        }
        return new PeakOutcome(new Peak(false, 0, false, null), overflow);
    }

    // ---- windowed exposure ----

    /** An invariant trigger that provably applies to every action of the verb. */
    private static boolean universal(Object p, Object verb) {
        Js.req(p);
        Object pv = Js.get(p, "verb");
        boolean verbOk = "*".equals(pv) || Js.strictEq(pv, verb) || (pv instanceof List && (Js.includes((List<?>) pv, "*") || Js.includes((List<?>) pv, verb)));
        Object where = Js.get(p, "where");
        boolean noWhere = !Js.has(p, "where") || (where instanceof List && ((List<?>) where).isEmpty());
        boolean noRes = !Js.has(p, "resource") || "*".equals(Js.get(p, "resource"));
        return verbOk && noRes && noWhere;
    }

    private static Map<String, Object> windowBound(PolicyModel model, Object constitution, Map<String, Object> o, Peak peak) {
        boolean hasW = Js.has(o, "windowSecs");
        double W = hasW ? Js.toNum(Js.get(o, "windowSecs")) : Double.NaN;
        String path = "action.params." + amountFieldOf(o);
        double per = peak.admitted ? peak.max : 0;
        List<Object> basis = new ArrayList<>(), notApplied = new ArrayList<>();
        double[] maxActions = {Double.POSITIVE_INFINITY};
        List<Object> caveats = new ArrayList<>(model.caveats);
        for (PolicyModel m : model.meets) caveats.addAll(m.caveats);
        Object invs = constitution == null ? null : Js.get(constitution, "invariants");
        List<?> invList = invs == null ? new ArrayList<>() : invs instanceof List ? (List<?>) invs : null;
        if (invList == null) throw new IllegalArgumentException("invariants is not iterable");

        for (Object cv : caveats) {
            if (cv == null) throw new IllegalArgumentException("caveat is null");
            if ("rate".equals(Js.get(cv, "type")) && Js.isNum(Js.get(cv, "max")) && Js.isNum(Js.get(cv, "per_secs")) && Js.num(Js.get(cv, "per_secs")) > 0) {
                limitActions(hasW, W, maxActions, basis, Js.num(Js.get(cv, "max")), Js.num(Js.get(cv, "per_secs")),
                    "rate caveat " + CaveatAnalysis.jsString(Js.get(cv, "max"), true) + "/" + CaveatAnalysis.jsString(Js.get(cv, "per_secs"), true) + "s");
            }
        }
        for (Object inv : invList) {
            if (!"rate".equals(Js.get(inv, "kind"))) continue;
            if (universal(Js.get(inv, "when"), Js.get(o, "verb"))) {
                limitActions(hasW, W, maxActions, basis, Js.numOrNaN(inv, "max"), Js.numOrNaN(inv, "window_secs"), "rate invariant " + CaveatAnalysis.jsString(Js.get(inv, "id"), Js.has(inv, "id")));
            } else notApplied.add(Js.get(inv, "id"));
        }
        double bound = per == 0 ? 0 : maxActions[0] == Double.POSITIVE_INFINITY ? Double.POSITIVE_INFINITY : per * maxActions[0];
        if (!Double.isInfinite(per) && !Double.isNaN(per) && per > 0) basis.add(0, "per-action ceiling");
        String budgetModel = Js.get(o, "budgetModel") instanceof String ? (String) Js.get(o, "budgetModel") : null;
        for (Object cv : caveats) {
            if (!"budget_alloc".equals(Js.get(cv, "type")) || !Js.isNum(Js.get(cv, "limit"))) continue;
            double limit = Js.num(Js.get(cv, "limit"));
            if ("dollars".equals(budgetModel)) {
                if (limit < bound) {
                    bound = limit; // in the dollar model the allocation is a lifetime cap on the total
                    basis.add("budget_alloc limit " + Js.fmt(limit));
                }
            } else if ("risk".equals(budgetModel) && Js.isNum(Js.get(o, "kappa")) && Js.num(Js.get(o, "kappa")) > 0) {
                double r;
                if (Js.get(o, "blastRadius") != null) r = Js.toNum(Js.get(o, "blastRadius"));
                else {
                    Object verb = Js.get(o, "verb");
                    Catalog.Spec spec = verb instanceof String ? Catalog.DEFAULT.get((String) verb) : null;
                    r = spec != null ? spec.blastRadius : 1; // an uncatalogued verb is treated as maximum blast radius
                }
                double cost = Js.num(Js.get(o, "kappa")) * Math.min(1, Math.max(0, r));
                double n = cost > 0 ? Math.floor(limit / cost) : Double.POSITIVE_INFINITY;
                if (n < maxActions[0]) {
                    maxActions[0] = n;
                    bound = n == 0 ? 0 : (!Double.isInfinite(per) && !Double.isNaN(per) && per > 0 ? per * n : bound);
                    basis.add("budget_alloc " + Js.fmt(limit) + " / cost " + Js.fmt(cost) + " = " + Js.fmt(n) + " actions");
                }
            } else notApplied.add("budget_alloc " + Js.fmt(limit) + " (trust-budget units; pass budgetModel and kappa)");
        }
        for (Object inv : invList) {
            if (!"cap".equals(Js.get(inv, "kind"))) continue;
            if (!universal(Js.get(inv, "when"), Js.get(o, "verb")) || !path.equals(Js.get(inv, "amount"))) {
                notApplied.add(Js.get(inv, "id"));
                continue;
            }
            boolean hasWin = Js.has(inv, "window_secs");
            if (hasWin && !hasW) continue; // a windowed cap says nothing about a lifetime total
            double imax = Js.numOrNaN(inv, "max");
            double cap = !hasWin || !hasW ? imax : imax * Math.ceil(W / Js.toNum(Js.get(inv, "window_secs")));
            if (cap < bound) {
                bound = cap;
                basis.add("cap invariant " + CaveatAnalysis.jsString(Js.get(inv, "id"), Js.has(inv, "id")));
            }
        }
        Map<String, Object> out = Js.obj("maxActions", Js.n(maxActions[0]), "bound", Js.n(bound), "basis", basis, "notApplied", notApplied);
        if (hasW) out.put("secs", Js.get(o, "windowSecs"));
        if (peak.admitted && peak.witness != null && !Double.isInfinite(maxActions[0]) && !Double.isNaN(maxActions[0]) && !Double.isInfinite(peak.max) && !Double.isNaN(peak.max) && peak.max > 0) {
            out.put("sequence", Js.obj("action", peak.witness, "repeat", Js.n(maxActions[0])));
        }
        return out;
    }

    private static void limitActions(boolean hasW, double W, double[] maxActions, List<Object> basis, double n, double perSecs, String why) {
        double k = !hasW ? Double.POSITIVE_INFINITY : n * Math.ceil(W / perSecs); // a sliding limit of n per perSecs: at most n per started period
        if (k < maxActions[0]) {
            maxActions[0] = k;
            basis.add(why);
        }
    }

    /**
     * The most that can ever leave under a policy: the largest single action, the largest autonomous action, and the total over a window,
     * composing the per-action ceiling with rate limits, the grant's {@code budget_alloc} and a constitution's {@code cap} / {@code rate}
     * invariants. A cap or rate invariant counts only when it provably applies to every action of the verb. Options: verb, resource,
     * amountField, integer, min, max, maxCombinations, windowSecs, constitution, budgetModel, kappa, blastRadius.
     */
    public static Map<String, Object> maxExposure(Object policy, Map<String, Object> given) {
        Js.req(policy);
        Map<String, Object> o = Js.copy(given);
        if (!Js.has(given, "budgetModel")) {
            Object bm = Js.get(policy, "budgetModel");
            if ("dollars".equals(bm) || "risk".equals(bm)) o.put("budgetModel", bm);
        }
        if (!Js.has(given, "kappa")) {
            Object k = Js.get(Js.get(policy, "riskPolicy"), "kappa");
            if (Js.isNum(k)) o.put("kappa", k);
        }
        Map<String, Object> cv = Js.has(o, "constitution") ? Constitution.vetoesFromConstitution(Js.get(o, "constitution")) : null;
        PolicyModel base = Enumerate.toModel(policy);
        PolicyModel model = base;
        if (cv != null) {
            model = base.copy();
            model.vetoes = new ArrayList<>(base.vetoes);
            model.vetoes.addAll(Js.list(cv.get("vetoes")));
        }
        String field = amountFieldOf(o);
        PeakOutcome admit = peakAt(model, o, false);
        PeakOutcome auto = peakAt(model, o, true);
        boolean approximate = admit.overflow || auto.overflow || !model.undecidable.isEmpty();
        Peak unbounded = new Peak(true, Double.POSITIVE_INFINITY, false, null);
        Peak pa = admit.overflow ? unbounded : admit.peak, ap = auto.overflow ? unbounded : auto.peak;
        Object c = Js.get(o, "constitution");
        List<Object> unmodeled = new ArrayList<>();
        if (cv != null) {
            for (Object u : Js.list(cv.get("unmodeled"))) {
                Object kind = Js.get(u, "kind");
                if ("cap".equals(kind) || "rate".equals(kind)) continue;
                unmodeled.add(CaveatAnalysis.jsString(Js.get(u, "id"), Js.has(u, "id")) + ": " + CaveatAnalysis.jsString(Js.get(u, "reason"), Js.has(u, "reason")));
            }
        }
        Map<String, Object> e = Js.obj();
        Js.putIf(e, "verb", o, "verb");
        e.put("amountField", field);
        e.put("perAction", pa.toJson());
        e.put("autonomousPerAction", ap.toJson());
        e.put("window", windowBound(model, c, o, pa));
        e.put("autonomousWindow", windowBound(model, c, o, ap));
        e.put("unmodeled", unmodeled);
        if (approximate) {
            e.put("approximate", true);
            e.put("reason", admit.overflow || auto.overflow ? "representative grid exceeded the bound; exposure reported as unbounded" : "over-approximated (" + String.join("; ", model.undecidable) + ")");
        }
        return e;
    }

    // ---- escalation surface ----

    /** The set of actions that escalate (admitted, but not autonomous): witnesses (at most {@code limit}, default 8) verified. Options: verb, limit, maxCombinations. */
    public static Map<String, Object> escalationSurface(Object policy, Map<String, Object> opts) {
        PolicyModel model = Enumerate.toModel(policy);
        ProbeInputs in = new ProbeInputs();
        in.predicateSets.add(Enumerate.probeSet(model));
        in.varyReversibility = model.revCap != null;
        Probes base = Enumerate.collectProbes(in);
        if (Js.has(opts, "verb")) { base.verbs = new ArrayList<>(); base.verbs.add(Js.get(opts, "verb")); }
        double limit = Js.get(opts, "limit") == null ? 8 : Js.toNum(Js.get(opts, "limit"));
        Collected r = Enumerate.collect(base, rep -> Enumerate.decide(model, rep).equals("escalate"), Analyzer.boundOf(opts), limit);
        List<Object> witnesses = new ArrayList<>();
        for (Rep h : r.hits) {
            Map<String, Object> a = Enumerate.repToAction(h);
            if (Enumerate.decideAction(model, a).equals("escalate")) witnesses.add(a);
        }
        Map<String, Object> out = Js.obj("escalates", !witnesses.isEmpty(), "witnesses", witnesses);
        if (r.overflow || !model.undecidable.isEmpty()) {
            out.put("approximate", true);
            out.put("reason", r.overflow ? "representative grid exceeded the bound" : "over-approximated (" + String.join("; ", model.undecidable) + ")");
        }
        return out;
    }

    // ---- delegation envelope ----

    /**
     * The join of everything any holder of the leaf could do: the meet of the chain's policies (every hop must admit) with the remaining
     * {@code delegation_depth}. A sub-delegate can only narrow it, so it is the ceiling for the whole subtree.
     */
    public static Map<String, Object> delegationEnvelope(List<Object> chain, Map<String, Object> opts) {
        Js.req(chain);
        Object leaf = chain.isEmpty() ? null : chain.get(chain.size() - 1);
        Object policy;
        if (leaf instanceof Map || leaf instanceof List) {
            Map<String, Object> p = leaf instanceof Map ? Js.copy(leaf) : Js.obj();
            List<Object> meet = new ArrayList<>(chain.subList(0, chain.size() - 1));
            Object lm = Js.get(leaf, "meet");
            if (Js.truthy(lm)) {
                if (!(lm instanceof List)) throw new IllegalArgumentException("meet is not iterable");
                meet.addAll((List<?>) lm);
            }
            p.put("meet", meet);
            policy = p;
        } else policy = Js.obj("predicates", new ArrayList<Object>());
        PolicyModel model = Enumerate.toModel(policy);
        ProbeInputs in = new ProbeInputs();
        in.predicateSets.add(Enumerate.probeSet(model));
        in.varyReversibility = model.revCap != null;
        Probes base = Enumerate.collectProbes(in);
        double max = Analyzer.boundOf(opts);
        List<Object> verbs = new ArrayList<>();
        boolean anyVerb = false, overflow = false;
        for (Object verb : base.verbs) {
            Probes pr = base.copy();
            pr.verbs = new ArrayList<>();
            pr.verbs.add(verb);
            Collected r = Enumerate.collect(pr, rep -> !Enumerate.decide(model, rep).equals("deny"), max, 1);
            if (r.overflow) { overflow = true; break; }
            if (r.hits.isEmpty()) continue;
            Rep hit = r.hits.get(0);
            Map<String, Object> w = Enumerate.repToAction(hit);
            if (((String) verb).startsWith("\u0000")) anyVerb = true;
            else verbs.add(Js.obj("verb", verb, "witness", w, "autonomous", Enumerate.decide(model, hit).equals("allow")));
        }
        List<Object> violations = new ArrayList<>();
        for (int i = 0; i + 1 < chain.size(); i++) {
            PolicyModel a = Enumerate.toModel(chain.get(i)), b = Enumerate.toModel(chain.get(i + 1));
            ProbeInputs pin = new ProbeInputs();
            pin.predicateSets.add(Enumerate.probeSet(a));
            pin.predicateSets.add(Enumerate.probeSet(b));
            pin.varyReversibility = a.revCap != null || b.revCap != null;
            Probes pr = Enumerate.collectProbes(pin);
            SearchOutcome out = Enumerate.search(pr, rep -> !Enumerate.decide(b, rep).equals("deny") && Enumerate.decide(a, rep).equals("deny"), max);
            if (out.hit != null || out.overflow) violations.add(Js.n(i + 1));
        }
        List<Double> depths = new ArrayList<>();
        for (Object p : chain) {
            if (!(p instanceof Map) || !(Js.get(p, "caveats") instanceof List)) continue;
            for (Object c : (List<?>) Js.get(p, "caveats")) {
                if ("delegation_depth".equals(Js.get(c, "type")) && Js.isNum(Js.get(c, "max"))) depths.add(Js.num(Js.get(c, "max")));
            }
        }
        double used = Math.max(0, chain.size() - 1);
        Map<String, Object> depth = Js.obj("used", Js.n(used));
        if (!depths.isEmpty()) {
            double allowed = depths.get(0);
            for (double d : depths) allowed = Math.min(allowed, d);
            depth.put("allowed", Js.n(allowed));
            depth.put("remaining", Js.n(Math.max(0, allowed - used)));
        }
        Map<String, Object> out = Js.obj("violations", violations, "verbs", verbs, "anyVerb", anyVerb, "depth", depth);
        if (overflow || !model.undecidable.isEmpty()) {
            out.put("approximate", true);
            out.put("reason", overflow ? "representative grid exceeded the bound" : "over-approximated (" + String.join("; ", model.undecidable) + ")");
        }
        return out;
    }

    // ---- semantic diff ----

    private static final List<String> WIDEN = java.util.Arrays.asList("deny->allow", "deny->escalate", "escalate->allow");

    private static double sub(double x, double y) { return x == y ? 0 : x - y; } // Infinity - Infinity is no change

    private static double numAt(Object e, String a, String b) { return Js.toNum(Js.get(Js.get(e, a), b)); }

    /**
     * {@code diff(A, B)}: what moved between two policies (ternary-aware) with verified witnesses per kind of shift. Options: limit (witnesses
     * per kind, default 4), maxCombinations, exposure (options of {@link #maxExposure}: also report how the exposure of that verb moved).
     */
    public static Map<String, Object> diffPolicies(Object a, Object b, Map<String, Object> o) {
        PolicyModel ma = Enumerate.toModel(a), mb = Enumerate.toModel(b);
        ProbeInputs in = new ProbeInputs();
        in.predicateSets.add(Enumerate.probeSet(ma));
        in.predicateSets.add(Enumerate.probeSet(mb));
        in.varyReversibility = ma.revCap != null || mb.revCap != null;
        Probes pr = Enumerate.collectProbes(in);
        double limit = Js.get(o, "limit") == null ? 4 : Js.toNum(Js.get(o, "limit"));
        Map<String, Object> shifts = new LinkedHashMap<>();
        Map<String, Integer> counts = new LinkedHashMap<>();
        Collected walk = Enumerate.collect(pr, rep -> {
            String x = Enumerate.decide(ma, rep), y = Enumerate.decide(mb, rep);
            if (x.equals(y)) return false;
            String k = x + "->" + y;
            int n = counts.getOrDefault(k, 0);
            counts.put(k, n + 1);
            if (n < limit) {
                @SuppressWarnings("unchecked")
                List<Object> l = (List<Object>) shifts.computeIfAbsent(k, kk -> new ArrayList<Object>());
                l.add(Enumerate.repToAction(rep));
            }
            return false; // walk the whole grid
        }, Analyzer.boundOf(o), 1);
        boolean overflow = walk.overflow;
        List<String> kinds = new ArrayList<>(shifts.keySet());
        boolean widens = false, narrows = false;
        for (String k : kinds) { if (WIDEN.contains(k)) widens = true; else narrows = true; }
        List<Object> summary = new ArrayList<>();
        for (String k : kinds) {
            List<Object> l = Js.list(shifts.get(k));
            Map<String, Object> first = Js.map(l.get(0));
            Object p = first.get("params");
            summary.add(k + ": " + l.size() + "+ action(s), e.g. " + first.get("verb") + " " + first.get("resource") + " " + Js.stringify(p == null ? Js.obj() : p));
        }
        Map<String, Object> d = Js.obj("equivalent", kinds.isEmpty() && !overflow && ma.undecidable.isEmpty() && mb.undecidable.isEmpty(),
            "shifts", shifts, "widens", widens, "narrows", narrows, "summary", summary);
        if (Js.has(o, "exposure")) {
            Map<String, Object> eo = Js.map(Js.get(o, "exposure"));
            Map<String, Object> before = maxExposure(a, eo), after = maxExposure(b, eo);
            double perAction = sub(numAt(after, "perAction", "max"), numAt(before, "perAction", "max"));
            double auton = sub(numAt(after, "autonomousWindow", "bound"), numAt(before, "autonomousWindow", "bound"));
            double delta = sub(numAt(after, "window", "bound"), numAt(before, "window", "bound"));
            d.put("exposure", Js.obj("before", before, "after", after, "perActionDelta", Js.n(perAction), "delta", Js.n(delta), "autonomousDelta", Js.n(auton)));
            double worst = Math.max(Math.max(delta, perAction), auton);
            double best = Math.min(delta, perAction);
            String verb = CaveatAnalysis.jsString(Js.get(eo, "verb"), Js.has(eo, "verb"));
            if (worst > 0) summary.add("max exposure of " + verb + " rises by " + Js.fmt(worst));
            else if (best < 0) summary.add("max exposure of " + verb + " falls by " + Js.fmt(-best));
        }
        if (overflow || !ma.undecidable.isEmpty() || !mb.undecidable.isEmpty()) {
            d.put("approximate", true);
            Set<String> rs = new LinkedHashSet<>(ma.undecidable);
            rs.addAll(mb.undecidable);
            d.put("reason", overflow ? "representative grid exceeded the bound" : "over-approximated (" + String.join("; ", rs) + ")");
        }
        return d;
    }

    /** A CI gate over a diff: fails when the change widens authority beyond what the reviewer allowed ({@code widen}, {@code maxExposureIncrease}). */
    public static Map<String, Object> diffGate(Map<String, Object> d, Map<String, Object> allow) {
        List<Object> reasons = new ArrayList<>();
        if (Js.truthy(Js.get(d, "widens")) && !Boolean.TRUE.equals(Js.get(allow, "widen"))) {
            List<String> ws = new ArrayList<>();
            Object sm = Js.get(d, "summary");
            if (sm instanceof List) for (Object s : (List<?>) sm) for (String k : WIDEN) if (((String) s).startsWith(k)) { ws.add((String) s); break; }
            reasons.add("widens authority: " + String.join("; ", ws));
        }
        double rise = 0;
        Object ex = Js.get(d, "exposure");
        if (Js.truthy(ex)) rise = Math.max(Math.max(Js.toNum(Js.get(ex, "delta")), Js.toNum(Js.get(ex, "perActionDelta"))), Js.toNum(Js.get(ex, "autonomousDelta")));
        double allowed = Js.get(allow, "maxExposureIncrease") == null ? 0 : Js.toNum(Js.get(allow, "maxExposureIncrease"));
        if (rise > allowed) reasons.add("max exposure rises by " + Js.fmt(rise));
        if (Js.truthy(Js.get(d, "approximate"))) {
            Object r = Js.get(d, "reason");
            reasons.add("inconclusive: " + (r == null ? "approximate" : CaveatAnalysis.jsString(r, true)));
        }
        return Js.obj("ok", reasons.isEmpty(), "reasons", reasons);
    }

    // ---- optional solver backend ----

    /**
     * An optional external solver (cvc5, z3, ...) consulted ONLY to look for a counterexample when the grid overflows. It is never trusted:
     * a witness it returns is re-checked by the real evaluator and discarded if wrong, and an "unsat" claim is returned labelled as
     * solver-claimed, never as a proved verdict. The built-in search needs no backend.
     */
    public interface WitnessBackend {
        String name();
        /** {witness?: action, unsat?: boolean} for a query {kind: "reachable" | "differs", a, b?, verb?}. */
        Map<String, Object> find(Map<String, Object> query);
    }

    public static Map<String, Object> findWithBackend(WitnessBackend backend, Map<String, Object> q) {
        Map<String, Object> r = backend.find(q);
        Object w = Js.get(r, "witness");
        if (Js.has(r, "witness")) {
            PolicyModel ma = Enumerate.toModel(Js.get(q, "a"));
            boolean ok;
            if ("reachable".equals(Js.get(q, "kind"))) {
                ok = !Enumerate.decideAction(ma, w).equals("deny") && (!Js.has(q, "verb") || Js.strictEq(Js.get(w, "verb"), Js.get(q, "verb")));
            } else {
                ok = Js.has(q, "b") && (!Enumerate.decideAction(ma, w).equals("deny")) != (!Enumerate.decideAction(Enumerate.toModel(Js.get(q, "b")), w).equals("deny"));
            }
            return ok ? Js.obj("witness", w) : Js.obj("rejected", true);
        }
        if (Boolean.TRUE.equals(Js.get(r, "unsat"))) {
            return Js.obj("claimedUnsat", Js.obj("by", backend.name(), "proof", "solver-claimed, not machine-checked"));
        }
        return Js.obj();
    }
}
