package net.atlasauth.pca.analyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Predicates;
import net.atlasauth.pca.SafeRegex;
import net.atlasauth.pca.analyzer.Enumerate.PolicyModel;
import net.atlasauth.pca.analyzer.Enumerate.ProbeInputs;
import net.atlasauth.pca.analyzer.Enumerate.Probes;
import net.atlasauth.pca.analyzer.Enumerate.SearchOutcome;

/**
 * STATIC ANALYZABILITY OF AUTHORITY: what can this whole delegated authority EVER do? A sound, bounded decision procedure over PCA's
 * predicate / caveat policy (no SMT dependency): reachability, vacuity / totality, delegation-safety subsumption, disjointness,
 * equivalence, and conformance to a declared intent envelope. A verdict is reported as proven only when the fragment is fully
 * decided; otherwise it fails safe and carries {@code approximate: true} with a reason.
 *
 * <p>Policies, actions, intents, options and results are JSON trees (Map / List / String / Boolean / Json.Num / null). Options are
 * optional (null = defaults); {@code maxCombinations} caps the representative grid (a larger grid fails safe).
 */
public final class Analyzer {
    private Analyzer() {}

    /** Reversibility classes in increasing severity. */
    public static final List<String> REVERSIBILITY_ORDER = Collections.unmodifiableList(java.util.Arrays.asList("reversible", "rate_limited", "irreversible"));

    public static final double DEFAULT_MAX_COMBINATIONS = Enumerate.DEFAULT_MAX_COMBINATIONS;

    /** The grid bound: a finite non-negative {@code maxCombinations}, else the default (0 is allowed: every grid overflows and fails safe). */
    static double boundOf(Map<String, Object> opts) {
        Object m = Js.get(opts, "maxCombinations");
        return Js.isFin(m) && Js.num(m) >= 0 ? Js.num(m) : DEFAULT_MAX_COMBINATIONS;
    }

    private static List<Object> orderList() { return new ArrayList<Object>(REVERSIBILITY_ORDER); }

    // ---- reachable ----

    /**
     * Can any input complete {@code action} into one the policy ALLOWs (some predicate matches AND the caveats are satisfiable)? Verb and
     * resource are taken as given; unspecified params / subject / env fields are searched. A returned {@code witness} is a concrete
     * action verified against the real evaluator. {@code reachable: false} is proven only for the decided fragment; otherwise it fails
     * safe to {@code reachable: true, approximate: true}.
     */
    public static Map<String, Object> reachable(Object policy, Map<String, Object> action, Map<String, Object> opts) {
        Js.req(action);
        PolicyModel model = Enumerate.toModel(policy);
        double max = boundOf(opts);
        if (!model.caveatSat) {
            return Js.obj("reachable", false, "reason", "caveats unsatisfiable: " + (model.caveatReason != null ? model.caveatReason : "unknown"));
        }
        if (Js.has(action, "reversibilityClass") && model.revCap != null) {
            Object rc = Js.get(action, "reversibilityClass");
            int idx = rc instanceof String ? REVERSIBILITY_ORDER.indexOf(rc) : -1;
            if (idx < 0 || idx > model.revCap) {
                return Js.obj("reachable", false, "reason", "reversibility class '" + CaveatAnalysis.jsString(rc, true) + "' exceeds the caveat cap");
            }
        }
        if (Enumerate.admitsAction(model, action)) return Js.obj("reachable", true, "witness", action);

        ProbeInputs in = new ProbeInputs();
        in.predicateSets.add(Enumerate.probeSet(model));
        in.varyReversibility = model.revCap != null;
        Probes base = Enumerate.collectProbes(in);
        Object providedO = Js.get(action, "params");
        Map<String, Object> provided = providedO instanceof Map ? Js.map(providedO) : new LinkedHashMap<>();
        List<Enumerate.FieldProbe> fields = new ArrayList<>();
        for (Enumerate.FieldProbe f : base.fields) {
            if (f.path.startsWith("action.params.")) {
                String key = f.path.substring("action.params.".length());
                if (provided.containsKey(key)) {
                    List<Object> one = new ArrayList<>();
                    one.add(provided.get(key));
                    fields.add(new Enumerate.FieldProbe(f.path, one));
                    continue;
                }
            }
            fields.add(f);
        }
        Probes pr = new Probes();
        pr.verbs.add(Js.get(action, "verb"));
        pr.resources.add(Js.get(action, "resource"));
        if (Js.has(action, "reversibilityClass")) pr.revClasses.add(Js.get(action, "reversibilityClass"));
        else if (model.revCap != null) pr.revClasses.addAll(orderList());
        else pr.revClasses.add(null);
        pr.fields = fields;

        SearchOutcome outcome = Enumerate.search(pr, rep -> Enumerate.admits(model, rep), max);
        if (outcome.hit != null) return Js.obj("reachable", true, "witness", mergeWitness(Enumerate.repToAction(outcome.hit), action));
        if (outcome.overflow) {
            return Js.obj("reachable", true, "approximate", true, "reason", "representative grid exceeded the bound; could not prove unreachable");
        }
        if (!model.undecidable.isEmpty()) {
            return Js.obj("reachable", true, "approximate", true, "reason",
                "over-approximated (" + String.join("; ", model.undecidable) + "); could not construct a witness but cannot prove unreachable");
        }
        return Js.obj("reachable", false, "reason", "no predicate admits this action for any input (proven over the decided fragment)");
    }

    private static Map<String, Object> mergeWitness(Map<String, Object> witness, Map<String, Object> provided) {
        Map<String, Object> params = Js.copy(Js.get(witness, "params"));
        Object pp = Js.get(provided, "params");
        if (pp instanceof Map) params.putAll(Js.map(pp));
        Map<String, Object> out = Js.obj();
        Js.putIf(out, "verb", provided, "verb");
        Js.putIf(out, "resource", provided, "resource");
        out.put("params", params);
        Object rc = Js.get(provided, "reversibilityClass");
        if (rc == null) rc = Js.get(witness, "reversibilityClass");
        if (rc != null) out.put("reversibilityClass", rc);
        Js.putIf(out, "subject", witness, "subject");
        Js.putIf(out, "env", witness, "env");
        return out;
    }

    // ---- alwaysDenies / alwaysAllows ----

    /**
     * Is the policy vacuous (does it deny everything, optionally only for {@code verb})? Proven only for the decided fragment; any
     * undecidable feature or grid overflow fails safe to {@code alwaysDenies: false}.
     */
    public static Map<String, Object> alwaysDenies(Object policy, String verb, Map<String, Object> opts) {
        PolicyModel model = Enumerate.toModel(policy);
        double max = boundOf(opts);
        if (!model.caveatSat) {
            return Js.obj("alwaysDenies", true, "reason", "caveats unsatisfiable: " + (model.caveatReason != null ? model.caveatReason : "unknown"));
        }
        Probes pr = probesFor(Collections.singletonList(model), verb);
        SearchOutcome outcome = Enumerate.search(pr, rep -> Enumerate.admits(model, rep), max);
        if (outcome.hit != null) return Js.obj("alwaysDenies", false, "witness", Enumerate.repToAction(outcome.hit));
        if (outcome.overflow) return Js.obj("alwaysDenies", false, "approximate", true, "reason", "grid exceeded the bound; cannot prove vacuity");
        if (!model.undecidable.isEmpty()) {
            return Js.obj("alwaysDenies", false, "approximate", true, "reason", "over-approximated (" + String.join("; ", model.undecidable) + "); cannot prove vacuity");
        }
        return Js.obj("alwaysDenies", true);
    }

    public static Map<String, Object> alwaysDenies(Object policy) { return alwaysDenies(policy, null, null); }

    /**
     * Is the policy total for {@code verb} (does it admit EVERY action of that verb)? Proven only for the decided fragment; any
     * undecidable feature or grid overflow fails safe to {@code alwaysAllows: false}.
     */
    public static Map<String, Object> alwaysAllows(Object policy, String verb, Map<String, Object> opts) {
        PolicyModel model = Enumerate.toModel(policy);
        double max = boundOf(opts);
        if (!model.caveatSat) {
            return Js.obj("alwaysAllows", false, "reason", "caveats unsatisfiable: " + (model.caveatReason != null ? model.caveatReason : "unknown"));
        }
        Probes pr = probesFor(Collections.singletonList(model), verb);
        SearchOutcome outcome = Enumerate.search(pr, rep -> !Enumerate.admits(model, rep), max);
        if (outcome.hit != null) return Js.obj("alwaysAllows", false, "counterexample", Enumerate.repToAction(outcome.hit));
        if (outcome.overflow) return Js.obj("alwaysAllows", false, "approximate", true, "reason", "grid exceeded the bound; cannot prove totality");
        if (!model.undecidable.isEmpty()) {
            return Js.obj("alwaysAllows", false, "approximate", true, "reason", "over-approximated (" + String.join("; ", model.undecidable) + "); cannot prove totality");
        }
        return Js.obj("alwaysAllows", true);
    }

    static Probes probesFor(List<PolicyModel> models, String verb) {
        boolean anyRev = false;
        ProbeInputs in = new ProbeInputs();
        for (PolicyModel m : models) { anyRev |= m.revCap != null; in.predicateSets.add(Enumerate.probeSet(m)); }
        in.varyReversibility = anyRev;
        Probes pr = Enumerate.collectProbes(in);
        if (verb != null) { pr.verbs = new ArrayList<>(); pr.verbs.add(verb); }
        return pr;
    }

    // ---- subsumes / disjoint / equivalent ----

    /**
     * Does policy {@code a} permit everything {@code b} permits (admitted(b) is a subset of admitted(a))? The delegation-safety check: a
     * child capability must be subsumed by its parent. A counterexample is an action {@code b} admits that {@code a} denies.
     */
    public static Map<String, Object> subsumes(Object a, Object b, Map<String, Object> opts) {
        PolicyModel ma = Enumerate.toModel(a), mb = Enumerate.toModel(b);
        double max = boundOf(opts);
        Probes pr = probesFor(java.util.Arrays.asList(ma, mb), null);
        SearchOutcome outcome = Enumerate.search(pr, rep -> Enumerate.admits(mb, rep) && !Enumerate.admits(ma, rep), max);
        if (outcome.hit != null) return Js.obj("subsumes", false, "counterexample", Enumerate.repToAction(outcome.hit));
        String note = approxNote(java.util.Arrays.asList(ma, mb), outcome.overflow);
        if (note != null) return Js.obj("subsumes", false, "approximate", true, "reason", note);
        return Js.obj("subsumes", true);
    }

    /** Are the two admitted sets disjoint (no action both admit)? A witness is an action both admit. */
    public static Map<String, Object> disjoint(Object a, Object b, Map<String, Object> opts) {
        PolicyModel ma = Enumerate.toModel(a), mb = Enumerate.toModel(b);
        double max = boundOf(opts);
        Probes pr = probesFor(java.util.Arrays.asList(ma, mb), null);
        SearchOutcome outcome = Enumerate.search(pr, rep -> Enumerate.admits(ma, rep) && Enumerate.admits(mb, rep), max);
        if (outcome.hit != null) return Js.obj("disjoint", false, "witness", Enumerate.repToAction(outcome.hit));
        String note = approxNote(java.util.Arrays.asList(ma, mb), outcome.overflow);
        if (note != null) return Js.obj("disjoint", false, "approximate", true, "reason", note);
        return Js.obj("disjoint", true);
    }

    /** Do the two policies admit exactly the same actions? A counterexample is an action admitted by exactly one. */
    public static Map<String, Object> equivalent(Object a, Object b, Map<String, Object> opts) {
        PolicyModel ma = Enumerate.toModel(a), mb = Enumerate.toModel(b);
        double max = boundOf(opts);
        Probes pr = probesFor(java.util.Arrays.asList(ma, mb), null);
        SearchOutcome outcome = Enumerate.search(pr, rep -> Enumerate.admits(ma, rep) != Enumerate.admits(mb, rep), max);
        if (outcome.hit != null) return Js.obj("equivalent", false, "counterexample", Enumerate.repToAction(outcome.hit));
        String note = approxNote(java.util.Arrays.asList(ma, mb), outcome.overflow);
        if (note != null) return Js.obj("equivalent", false, "approximate", true, "reason", note);
        return Js.obj("equivalent", true);
    }

    public static Map<String, Object> subsumes(Object a, Object b) { return subsumes(a, b, null); }
    public static Map<String, Object> equivalent(Object a, Object b) { return equivalent(a, b, null); }

    private static String approxNote(List<PolicyModel> models, boolean overflow) {
        if (overflow) return "representative grid exceeded the bound; cannot prove the relation";
        Set<String> reasons = new LinkedHashSet<>();
        for (PolicyModel m : models) reasons.addAll(m.undecidable);
        if (!reasons.isEmpty()) return "over-approximated (" + String.join("; ", reasons) + "); cannot prove the relation";
        return null;
    }

    // ---- intentConformance ----

    /**
     * Does the policy admit ONLY actions inside the declared intent envelope (allowed verbs, resource scopes, an amount ceiling)? Each
     * reported violation is a concrete admitted action outside the envelope, so {@code conforms: false} with violations is always proven;
     * {@code conforms: true} is proven only for the decided fragment (an undecidable feature, a {@code re:} intent scope or a grid
     * overflow fails safe to {@code conforms: false, approximate: true} with no violations listed).
     */
    public static Map<String, Object> intentConformance(Object policy, Map<String, Object> intent, Map<String, Object> opts) {
        Js.req(intent);
        PolicyModel model = Enumerate.toModel(policy);
        double max = boundOf(opts);
        Object af = Js.get(intent, "amountField");
        String amountField = af == null ? "amount" : af instanceof String ? (String) af : CaveatAnalysis.jsString(af, true);
        Object minO = Js.get(intent, "minAmount");
        Object minAmount = minO == null ? Js.n(0) : minO;
        if (!model.caveatSat) return Js.obj("conforms", true, "violations", new ArrayList<Object>());

        Object verbsO = Js.get(intent, "verbs");
        if (!(verbsO instanceof List)) throw new IllegalArgumentException("intent.verbs is not an array");
        List<Object> verbs = Js.list(verbsO);
        Object scopesO = Js.get(intent, "resourceScopes");
        List<Object> scopes = scopesO == null ? new ArrayList<>() : scopesO instanceof List ? Js.list(scopesO) : null;
        if (scopes == null) throw new IllegalArgumentException("intent.resourceScopes is not an array");

        ProbeInputs in = new ProbeInputs();
        in.predicateSets.add(Enumerate.probeSet(model));
        for (Object v : verbs) if (!"*".equals(v)) in.extraVerbs.add(v);
        in.extraResources.addAll(scopes);
        if (Js.has(intent, "maxAmount")) {
            String path = "action.params." + amountField;
            in.extraFieldConditions.add(new Object[] {path, Js.obj("field", path, "op", "lte", "value", Js.get(intent, "maxAmount"))});
            in.extraFieldConditions.add(new Object[] {path, Js.obj("field", path, "op", "gte", "value", minAmount)});
        }
        in.varyReversibility = model.revCap != null;
        Probes pr = Enumerate.collectProbes(in);

        if (fieldProduct(pr) * pr.verbs.size() * pr.resources.size() * pr.revClasses.size() > max) {
            return Js.obj("conforms", false, "approximate", true, "violations", new ArrayList<Object>(), "reason", "grid exceeded the bound; cannot prove conformance");
        }
        List<Object> violations = new ArrayList<>();
        Enumerate.forEachRep(pr, rep -> {
            if (!Enumerate.admits(model, rep)) return false;
            Map<String, Object> action = Enumerate.repToAction(rep);
            List<Object> kinds = intentViolationKinds(action, intent, verbs, scopes, amountField, minAmount);
            if (!kinds.isEmpty()) {
                violations.add(Js.obj("action", action, "kinds", kinds));
                return violations.size() >= 16;
            }
            return false;
        });
        if (!violations.isEmpty()) return Js.obj("conforms", false, "violations", violations);
        boolean intentRegex = false;
        for (Object s : scopes) if (((String) s).startsWith("re:")) intentRegex = true;
        if (!model.undecidable.isEmpty() || intentRegex) {
            List<String> reasons = new ArrayList<>(model.undecidable);
            if (intentRegex) reasons.add("re: intent resource scope not enumerated soundly");
            return Js.obj("conforms", false, "approximate", true, "violations", new ArrayList<Object>(),
                "reason", "over-approximated (" + String.join("; ", reasons) + "); cannot prove conformance");
        }
        return Js.obj("conforms", true, "violations", new ArrayList<Object>());
    }

    private static double fieldProduct(Probes pr) {
        double n = 1;
        for (Enumerate.FieldProbe f : pr.fields) n *= f.values.size();
        return n;
    }

    private static boolean scopeMatches(String scope, String resource) {
        if (scope.equals("*")) return true;
        if (scope.startsWith("re:")) {
            String src = scope.substring(3);
            // the verifier's own guard: a hostile grant under analysis must not hang the analyzer
            if (src.length() > 200 || resource.length() > Predicates.MAX_RE_RESOURCE_LEN || !SafeRegex.isSafeSource(src)) return false;
            return Boolean.TRUE.equals(SafeRegex.fullMatch(src, resource));
        }
        if (scope.endsWith("*")) return resource.startsWith(scope.substring(0, scope.length() - 1));
        return scope.equals(resource);
    }

    private static List<Object> intentViolationKinds(Map<String, Object> action, Map<String, Object> intent, List<Object> verbs, List<Object> scopes, String amountField, Object minAmount) {
        List<Object> kinds = new ArrayList<>();
        Object verb = action.get("verb");
        if (!(Js.includes(verbs, "*") || Js.includes(verbs, verb))) kinds.add("off-verb");
        if (!scopes.isEmpty()) {
            boolean any = false;
            for (Object s : scopes) if (scopeMatches((String) s, (String) action.get("resource"))) { any = true; break; }
            if (!any) kinds.add("off-scope");
        }
        if (Js.has(intent, "maxAmount")) {
            Object amt = Js.copy(action.get("params")).get(amountField);
            if (Js.isFin(amt)) {
                double a = Js.num(amt);
                if (a > Js.toNum(Js.get(intent, "maxAmount"))) kinds.add("over-amount");
                else if (a < Js.toNum(minAmount)) kinds.add("under-amount");
            }
        }
        return kinds;
    }

    // ---- convenience ----

    /** Concrete, exact admission check for a fully-specified action (no existential search). */
    public static boolean admitsConcrete(Object policy, Map<String, Object> action) {
        Js.req(action);
        return Enumerate.admitsAction(Enumerate.toModel(policy), action);
    }

    /** Is a predicate's own numeric {@code where} conjunction satisfiable (e.g. {@code amount >= 100 AND amount <= 10} is not)? */
    public static boolean predicateNumericSatisfiable(Object where) {
        if (!(where instanceof List)) return true;
        return Field.numericConjunctionSatisfiable((List<?>) where);
    }
}
