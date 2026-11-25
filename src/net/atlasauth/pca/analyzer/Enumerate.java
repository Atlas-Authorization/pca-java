package net.atlasauth.pca.analyzer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.ForbidWins;
import net.atlasauth.pca.Predicates;

/**
 * The bounded decision engine. It builds a finite grid of representative actions from the literals, thresholds, prefixes, verbs and
 * resource matchers of the policies, and evaluates the real predicate evaluator at each. Every query (reachability, subsumption,
 * disjointness, equivalence, ...) is decided EXACTLY on the decided fragment and fails safe ({@code approximate}) outside it
 * ({@code re:} resources, cross-field {@code ref}, {@code like} / {@code matches} / {@code is_a} / {@code member_of}, a grid over the bound).
 *
 * <p>Policies, actions and results are JSON trees (Map / List / String / Boolean / Json.Num / null), as the evaluator takes them.
 */
public final class Enumerate {
    private Enumerate() {}

    /** The "field absent" representative. */
    public static final Object ABSENT = new Object() { @Override public String toString() { return "ABSENT"; } };
    static final String FRESH_VERB = "\u0000atlas-analyzer::fresh-verb\u0000";
    static final String FRESH_RESOURCE = "\u0000atlas-analyzer::fresh-resource\u0000";

    /** Default cap on the representative grid size (product of all dimensions). */
    public static final double DEFAULT_MAX_COMBINATIONS = 200_000;

    /** A policy in analyzable form. */
    public static final class PolicyModel {
        public List<Object> predicates = new ArrayList<>();
        public List<Object> caveats = new ArrayList<>();
        public List<Object> vetoes = new ArrayList<>();
        public List<Object> tighten = new ArrayList<>();
        /** Policies that must also admit; their static gates are already folded into caveatSat / revCap. */
        public List<PolicyModel> meets = new ArrayList<>();
        public boolean caveatSat;
        public String caveatReason;
        /** Strictest reversibility_max cap (index into the order), or null. */
        public Integer revCap;
        /** Non-empty when the policy uses features the analyzer cannot decide exactly. */
        public List<String> undecidable = new ArrayList<>();

        public PolicyModel copy() {
            PolicyModel m = new PolicyModel();
            m.predicates = predicates; m.caveats = caveats; m.vetoes = vetoes; m.tighten = tighten; m.meets = meets;
            m.caveatSat = caveatSat; m.caveatReason = caveatReason; m.revCap = revCap; m.undecidable = undecidable;
            return m;
        }

        public Map<String, Object> toJson() {
            List<Object> ms = new ArrayList<>();
            for (PolicyModel x : meets) ms.add(x.toJson());
            Map<String, Object> o = Js.obj("predicates", predicates, "caveats", caveats, "vetoes", vetoes, "tighten", tighten, "meets", ms, "caveatSat", caveatSat);
            if (caveatReason != null) o.put("caveatReason", caveatReason);
            if (revCap != null) o.put("revCap", Js.n(revCap));
            o.put("undecidable", new ArrayList<Object>(undecidable));
            return o;
        }
    }

    /** {predicates, caveats, vetoes, tighten} of a policy input; anything that is no policy is the empty policy. */
    public static PolicyModel normalizePolicy(Object p) {
        PolicyModel m = new PolicyModel();
        if (!(p instanceof Map || p instanceof List)) return m;
        if (Js.get(p, "predicates") instanceof List) m.predicates = Js.list(Js.get(p, "predicates"));
        if (Js.get(p, "caveats") instanceof List) m.caveats = Js.list(Js.get(p, "caveats"));
        if (Js.get(p, "vetoes") instanceof List) m.vetoes = Js.list(Js.get(p, "vetoes"));
        if (Js.get(p, "tighten") instanceof List) m.tighten = Js.list(Js.get(p, "tighten"));
        return m;
    }

    static List<Object> predicateList(Object o) { return o instanceof List ? Js.list(o) : new ArrayList<>(); }

    /** The predicates whose literals shape the grid: the permits plus every veto and tighten trigger. */
    public static List<Object> probeSet(PolicyModel m) {
        List<Object> out = new ArrayList<>(m.predicates);
        for (Object v : m.vetoes) {
            if (v == null) throw new IllegalArgumentException("veto is null");
            out.add(Js.get(v, "when")); // a trigger-less veto leaves undefined in the set; only the consumers that read its "where" throw (thresholds, coverage)
            Object un = Js.get(v, "unless");
            if (un instanceof List && !((List<?>) un).isEmpty()) out.add(Js.obj("verb", "*", "where", un));
            Object over = Js.get(v, "over");
            if (Js.truthy(over)) {
                out.add(Js.obj("verb", "*", "where", Js.arr(Js.obj("field", Js.get(over, "path"), "op", "gt", "value", Js.get(over, "threshold")))));
            }
        }
        for (Object t : m.tighten) {
            if (t == null) throw new IllegalArgumentException("tighten rule is null");
            out.add(Js.obj("verb", "*", "where", Js.arr(Js.get(t, "when"))));
        }
        for (PolicyModel x : m.meets) out.addAll(probeSet(x));
        return out;
    }

    private static void conditionUndecidable(Object c, Set<String> reasons) {
        if (!(c instanceof Map || c instanceof List)) return;
        if (Field.isGroup(c)) {
            if (Js.has(c, "all_of") && Js.get(c, "all_of") instanceof List) { for (Object x : (List<?>) Js.get(c, "all_of")) conditionUndecidable(x, reasons); }
            else if (Js.has(c, "any_of") && Js.get(c, "any_of") instanceof List) { for (Object x : (List<?>) Js.get(c, "any_of")) conditionUndecidable(x, reasons); }
            else if (Js.has(c, "not")) conditionUndecidable(Js.get(c, "not"), reasons);
            return;
        }
        if (!Field.isLeaf(c)) return;
        if (Js.has(c, "ref")) reasons.add("cross-field `ref` condition — the relation between two fields is not resolved");
        if ("action.params".equals(Js.get(c, "field"))) reasons.add("condition on the whole `action.params` object is not enumerated precisely");
        Object op = Js.get(c, "op");
        if (op instanceof String) {
            String o = (String) op;
            if ((o.equals("lt") || o.equals("lte") || o.equals("gt") || o.equals("gte")) && !Js.isFin(Js.get(c, "value"))) {
                reasons.add("`" + o + "` against a non-numeric operand — string ordering is not enumerated exactly");
            }
            if (o.equals("like") || o.equals("matches") || o.equals("is_a") || o.equals("member_of")) {
                reasons.add("`" + o + "` condition — matched by over-approximation, not enumerated exactly");
            }
        }
    }

    private static List<String> detectUndecidable(List<Object> predicates) {
        Set<String> reasons = new LinkedHashSet<>();
        for (Object p : predicates) {
            if (!(p instanceof Map || p instanceof List)) continue;
            Object r = Js.get(p, "resource");
            if (r instanceof String && ((String) r).startsWith("re:")) reasons.add("re: regex resource matcher — resource dimension cannot be soundly enumerated");
            Object w = Js.get(p, "where");
            if (w instanceof List) for (Object c : (List<?>) w) conditionUndecidable(c, reasons);
        }
        return new ArrayList<>(reasons);
    }

    public static PolicyModel toModel(Object p) {
        PolicyModel m = normalizePolicy(p);
        CaveatAnalysis ca = CaveatAnalysis.analyzeCaveats(m.caveats);
        List<PolicyModel> meets = new ArrayList<>();
        if (p instanceof Map && Js.get(p, "meet") instanceof List) for (Object x : Js.list(Js.get(p, "meet"))) meets.add(toModel(x));
        m.meets = meets;
        boolean meetsSat = true;
        String meetReason = null;
        boolean foundBad = false;
        for (PolicyModel x : meets) {
            if (!x.caveatSat) { meetsSat = false; if (!foundBad) { meetReason = x.caveatReason; foundBad = true; } }
        }
        m.caveatSat = ca.sat && meetsSat;
        m.caveatReason = ca.sat ? meetReason : ca.reason;
        Integer cap = ca.revCap;
        for (PolicyModel x : meets) {
            if (cap == null) cap = x.revCap;
            else if (x.revCap != null) cap = Math.min(cap, x.revCap);
        }
        m.revCap = cap;
        Set<String> und = new LinkedHashSet<>(detectUndecidable(probeSet(m)));
        for (PolicyModel x : meets) und.addAll(x.undecidable);
        m.undecidable = new ArrayList<>(und);
        return m;
    }

    // ---- probe collection ----

    /** The grid: one list of values per dimension. {@code revClasses} holds null for "no reversibility dimension". */
    public static final class Probes {
        public List<Object> verbs = new ArrayList<>();
        public List<Object> resources = new ArrayList<>();
        public List<Object> revClasses = new ArrayList<>();
        public List<FieldProbe> fields = new ArrayList<>();

        public Probes copy() {
            Probes p = new Probes();
            p.verbs = new ArrayList<>(verbs); p.resources = new ArrayList<>(resources); p.revClasses = new ArrayList<>(revClasses); p.fields = new ArrayList<>(fields);
            return p;
        }
    }

    /** The values of one field path (may contain {@link #ABSENT}). */
    public static final class FieldProbe {
        public final String path;
        public final List<Object> values;
        public FieldProbe(String path, List<Object> values) { this.path = path; this.values = values; }
    }

    /** Inputs of {@link #collectProbes}. */
    public static final class ProbeInputs {
        public List<List<Object>> predicateSets = new ArrayList<>();
        public List<Object> extraVerbs = new ArrayList<>();
        public List<Object> extraResources = new ArrayList<>();
        public List<Object[]> extraFieldConditions = new ArrayList<>(); // {path (String), cond (Map)}
        public boolean varyReversibility;
    }

    private static void addVerbLiterals(Object c, Set<String> into) {
        Object v = Js.get(c, "value");
        String op = Js.get(c, "op") instanceof String ? (String) Js.get(c, "op") : "";
        if (op.equals("eq") || op.equals("ne") || op.equals("prefix") || op.equals("like") || op.equals("is_a")) {
            if (v instanceof String) into.add((String) v);
        } else if ((op.equals("in") || op.equals("nin")) && v instanceof List) {
            for (Object x : (List<?>) v) if (x instanceof String) into.add((String) x);
        }
    }

    private static void classifyResource(Object r, boolean present, Set<String> resourceLiterals) {
        if (!present) return;
        if ("*".equals(r)) return;
        if (!(r instanceof String)) throw new IllegalArgumentException("resource matcher is not a string");
        String s = (String) r;
        if (s.startsWith("re:")) return;
        if (s.endsWith("*")) {
            String body = s.substring(0, s.length() - 1);
            resourceLiterals.add(body);
            resourceLiterals.add(body + "x");
            return;
        }
        resourceLiterals.add(s);
    }

    private static void handleCond(Object c, Set<String> verbLiterals, Set<String> resourceLiterals, Map<String, List<Object>> fieldConds) {
        if (!(c instanceof Map || c instanceof List)) return;
        if (Field.isGroup(c)) {
            if (Js.has(c, "all_of") && Js.get(c, "all_of") instanceof List) { for (Object x : (List<?>) Js.get(c, "all_of")) handleCond(x, verbLiterals, resourceLiterals, fieldConds); }
            else if (Js.has(c, "any_of") && Js.get(c, "any_of") instanceof List) { for (Object x : (List<?>) Js.get(c, "any_of")) handleCond(x, verbLiterals, resourceLiterals, fieldConds); }
            else if (Js.has(c, "not")) handleCond(Js.get(c, "not"), verbLiterals, resourceLiterals, fieldConds);
            return;
        }
        if (!Field.isLeaf(c)) return;
        String field = (String) Js.get(c, "field");
        if (field.equals("action.verb")) { addVerbLiterals(c, verbLiterals); return; }
        if (field.equals("action.resource")) {
            Object v = Js.get(c, "value");
            if ("prefix".equals(Js.get(c, "op")) && v instanceof String) classifyResource(v + "*", true, resourceLiterals);
            else if (v instanceof String) classifyResource(v, true, resourceLiterals);
            else if (v instanceof List) for (Object x : (List<?>) v) if (x instanceof String) classifyResource(x, true, resourceLiterals);
            return;
        }
        fieldConds.computeIfAbsent(field, k -> new ArrayList<>()).add(c);
    }

    public static Probes collectProbes(ProbeInputs in) {
        Set<String> verbLiterals = new LinkedHashSet<>();
        for (Object v : in.extraVerbs) {
            if (!(v instanceof String)) throw new IllegalArgumentException("extra verb is not a string");
            verbLiterals.add((String) v);
        }
        Set<String> resourceLiterals = new LinkedHashSet<>();
        Map<String, List<Object>> fieldConds = new LinkedHashMap<>();
        for (List<Object> list : in.predicateSets) {
            for (Object p : list) {
                if (!(p instanceof Map || p instanceof List)) continue;
                Object pv = Js.get(p, "verb");
                if (pv instanceof String) { if (!pv.equals("*")) verbLiterals.add((String) pv); }
                else if (pv instanceof List) { for (Object v : (List<?>) pv) if (v instanceof String && !v.equals("*")) verbLiterals.add((String) v); }
                classifyResource(Js.get(p, "resource"), Js.has(p, "resource"), resourceLiterals);
                Object w = Js.get(p, "where");
                if (w instanceof List) for (Object c : (List<?>) w) handleCond(c, verbLiterals, resourceLiterals, fieldConds);
            }
        }
        for (Object r : in.extraResources) classifyResource(r, true, resourceLiterals);
        for (Object[] ec : in.extraFieldConditions) {
            Map<String, Object> cond = Js.copy(ec[1]);
            cond.put("field", ec[0]);
            handleCond(cond, verbLiterals, resourceLiterals, fieldConds);
        }
        Probes pr = new Probes();
        for (Map.Entry<String, List<Object>> e : fieldConds.entrySet()) {
            List<Object> vals = Field.fieldProbes(e.getValue());
            vals.add(ABSENT);
            pr.fields.add(new FieldProbe(e.getKey(), vals));
        }
        pr.verbs = new ArrayList<Object>(verbLiterals);
        pr.verbs.add(FRESH_VERB);
        pr.resources = new ArrayList<Object>(resourceLiterals);
        pr.resources.add(FRESH_RESOURCE);
        if (in.varyReversibility) pr.revClasses = new ArrayList<>(Analyzer.REVERSIBILITY_ORDER);
        else pr.revClasses.add(null);
        return pr;
    }

    public static double productSize(Probes pr) {
        double n = (double) pr.verbs.size() * pr.resources.size() * pr.revClasses.size();
        for (FieldProbe f : pr.fields) n *= f.values.size();
        return n;
    }

    // ---- representatives ----

    /** One representative action of the grid. */
    public static final class Rep {
        public final Object verb, resource;
        public final Object revClass; // null = no class
        /** Field path to value, excluding absent fields. */
        public final Map<String, Object> assignments;
        Rep(Object verb, Object resource, Object revClass, Map<String, Object> assignments) {
            this.verb = verb; this.resource = resource; this.revClass = revClass; this.assignments = assignments;
        }
    }

    /** Visits representatives; return true to stop the walk. */
    public interface RepVisitor { boolean visit(Rep rep); }

    private static boolean walkFields(List<FieldProbe> fields, int i, Map<String, Object> acc, Object verb, Object resource, Object rev, RepVisitor vis) {
        if (i >= fields.size()) return vis.visit(new Rep(verb, resource, rev, new LinkedHashMap<>(acc)));
        FieldProbe f = fields.get(i);
        for (Object v : f.values) {
            if (v == ABSENT) acc.remove(f.path);
            else acc.put(f.path, v);
            if (walkFields(fields, i + 1, acc, verb, resource, rev, vis)) return true;
        }
        return false;
    }

    /** Walk the grid in order (verbs, resources, reversibility classes, fields), stopping when the visitor returns true. */
    public static void forEachRep(Probes pr, RepVisitor vis) {
        for (Object verb : pr.verbs) for (Object resource : pr.resources) for (Object rc : pr.revClasses) {
            if (walkFields(pr.fields, 0, new LinkedHashMap<>(), verb, resource, rc, vis)) return;
        }
    }

    /** The whole grid as a list (callers bound the grid first). */
    public static List<Rep> representatives(Probes pr) {
        List<Rep> out = new ArrayList<>();
        forEachRep(pr, r -> { out.add(r); return false; });
        return out;
    }

    // ---- context building ----

    private static final class Node {
        final boolean leaf; final Object value; final Map<String, Node> children;
        Node(boolean leaf, Object value) { this.leaf = leaf; this.value = value; this.children = leaf ? null : new LinkedHashMap<>(); }
    }

    private static void insert(Node root, List<String> segs, Object value) {
        Node node = root;
        for (int i = 0; i < segs.size() - 1; i++) {
            if (node.leaf) return;
            String key = segs.get(i);
            Node next = node.children.get(key);
            if (next == null || next.leaf) {
                Node created = new Node(false, null);
                node.children.put(key, created);
                node = created;
            } else node = next;
        }
        if (!segs.isEmpty() && !node.leaf) node.children.put(segs.get(segs.size() - 1), new Node(true, value));
    }

    private static Map<String, Object> materialize(Node node) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (node.leaf) return out;
        for (Map.Entry<String, Node> e : node.children.entrySet()) out.put(e.getKey(), e.getValue().leaf ? e.getValue().value : materialize(e.getValue()));
        return out;
    }

    /** The context of a representative: {action, subject, env}. */
    static Map<String, Object>[] buildRoots(Rep rep) {
        Map<String, Node> roots = new LinkedHashMap<>();
        roots.put("action", new Node(false, null));
        roots.put("subject", new Node(false, null));
        roots.put("env", new Node(false, null));
        for (Map.Entry<String, Object> e : rep.assignments.entrySet()) {
            String[] segs = e.getKey().split("\\.", -1);
            if (segs.length < 2) continue;
            Node root = roots.get(segs[0]);
            if (root == null) continue;
            List<String> rest = new ArrayList<>();
            for (int i = 1; i < segs.length; i++) rest.add(segs[i]);
            insert(root, rest, e.getValue());
        }
        Map<String, Object> action = Js.obj("verb", rep.verb, "resource", rep.resource, "params", new LinkedHashMap<String, Object>());
        Node at = roots.get("action");
        for (Map.Entry<String, Node> e : at.children.entrySet()) {
            String key = e.getKey();
            if (key.equals("verb") || key.equals("resource")) continue;
            if (key.equals("params")) { if (!e.getValue().leaf) action.put("params", materialize(e.getValue())); }
            else action.put(key, e.getValue().leaf ? e.getValue().value : materialize(e.getValue()));
        }
        if (rep.revClass != null) action.put("reversibility_class", rep.revClass);
        @SuppressWarnings("unchecked")
        Map<String, Object>[] r = new Map[] {action, materialize(roots.get("subject")), materialize(roots.get("env"))};
        return r;
    }

    private static Map<String, Object> contextFromRoots(Map<String, Object>[] r) {
        return Js.obj("action", r[0], "subject", r[1], "env", r[2]);
    }

    private static boolean reversibilityOk(PolicyModel model, Object revClass) {
        if (model.revCap == null) return true;
        if (!(revClass instanceof String)) return false;
        int idx = Analyzer.REVERSIBILITY_ORDER.indexOf(revClass);
        return idx >= 0 && idx <= model.revCap;
    }

    /** Does a veto apply to this action? Veto polarity: whatever cannot be decided counts as applying. */
    public static boolean vetoApplies(Object v, Map<String, Object> ctx) {
        if (!ForbidWins.whenMatches(Js.get(v, "when"), ctx)) return false;
        Object over = Js.get(v, "over");
        if (Js.truthy(over)) {
            Predicates.Resolved r = Predicates.resolvePath(ctx, Js.get(over, "path"));
            boolean isOver = !r.found || !Js.isFin(r.value) || Js.num(r.value) < 0 || Js.num(r.value) > (Js.has(over, "threshold") ? Js.toNum(Js.get(over, "threshold")) : Double.NaN);
            if (!isOver) return false;
        }
        Object unless = Js.get(v, "unless");
        if (!"approval".equals(Js.get(v, "kind")) && Js.truthy(unless)) {
            if (!(unless instanceof List)) throw new IllegalArgumentException("unless is not an array");
            boolean all = true;
            for (Object c : (List<?>) unless) if (!Predicates.evaluateCondition(c, ctx)) { all = false; break; }
            if (all) return false;
        }
        return true;
    }

    /** The ternary decision of the permission layer at a concrete context: "allow" / "escalate" / "deny". */
    public static String decisionAtContext(PolicyModel model, Map<String, Object> ctx) {
        if (!Predicates.evaluatePredicates(model.predicates, ctx)) return "deny";
        boolean escalate = false;
        for (Object v : model.vetoes) {
            if (!vetoApplies(v, ctx)) continue;
            if ("deny".equals(Js.get(v, "kind"))) return "deny";
            escalate = true;
        }
        for (Object t : model.tighten) {
            if (Predicates.evaluateConditionTri(Js.get(t, "when"), ctx) == Predicates.Tri.FALSE) continue;
            if ("deny".equals(Js.get(t, "signal"))) return "deny";
            escalate = true;
        }
        String own = escalate ? "escalate" : "allow";
        for (PolicyModel x : model.meets) {
            String d = decisionAtContext(x, ctx);
            if (d.equals("deny")) return "deny";
            if (d.equals("escalate")) own = "escalate";
        }
        return own;
    }

    /** Ternary decision of a representative (the static caveat gate first). */
    public static String decide(PolicyModel model, Rep rep) {
        if (!model.caveatSat) return "deny";
        if (!reversibilityOk(model, rep.revClass)) return "deny";
        return decisionAtContext(model, contextFromRoots(buildRoots(rep)));
    }

    /** Does the policy admit this representative (allow OR escalate)? */
    public static boolean admits(PolicyModel model, Rep rep) { return !decide(model, rep).equals("deny"); }

    public static Map<String, Object> contextOfAction(Object action) {
        Map<String, Object> act = Js.obj("verb", Js.get(action, "verb"), "resource", Js.get(action, "resource"));
        act.put("params", Js.copy(Js.get(action, "params")));
        if (Js.has(action, "reversibilityClass")) act.put("reversibility_class", Js.get(action, "reversibilityClass"));
        return Js.obj("action", act, "subject", Js.copy(Js.get(action, "subject")), "env", Js.copy(Js.get(action, "env")));
    }

    /** Ternary decision of a fully-specified action. */
    public static String decideAction(PolicyModel model, Object action) {
        if (!model.caveatSat) return "deny";
        if (!reversibilityOk(model, Js.get(action, "reversibilityClass"))) return "deny";
        return decisionAtContext(model, contextOfAction(action));
    }

    /** Concrete admission of a fully-specified action (exact). */
    public static boolean admitsAction(PolicyModel model, Object action) { return !decideAction(model, action).equals("deny"); }

    /** The representative as an action {verb, resource, params, reversibilityClass?, subject?, env?}. */
    public static Map<String, Object> repToAction(Rep rep) {
        Map<String, Object>[] roots = buildRoots(rep);
        Map<String, Object> action = Js.obj("verb", rep.verb, "resource", rep.resource, "params", new LinkedHashMap<>(Js.map(roots[0].get("params"))));
        if (rep.revClass != null) action.put("reversibilityClass", rep.revClass);
        if (!roots[1].isEmpty()) action.put("subject", roots[1]);
        if (!roots[2].isEmpty()) action.put("env", roots[2]);
        return action;
    }

    // ---- bounded search ----

    public static final class SearchOutcome {
        /** The representative the predicate accepted, or null. */
        public final Rep hit;
        /** The grid exceeded the bound; nothing was enumerated. */
        public final boolean overflow;
        SearchOutcome(Rep hit, boolean overflow) { this.hit = hit; this.overflow = overflow; }
    }

    /** Walk the grid and stop at the first representative the predicate accepts; overflow (without walking) when the grid exceeds {@code max}. */
    public static SearchOutcome search(Probes pr, java.util.function.Predicate<Rep> predicate, double max) {
        if (productSize(pr) > max) return new SearchOutcome(null, true);
        Rep[] hit = new Rep[1];
        forEachRep(pr, r -> { if (predicate.test(r)) { hit[0] = r; return true; } return false; });
        return new SearchOutcome(hit[0], false);
    }

    public static final class Collected {
        public final List<Rep> hits;
        public final boolean overflow;
        Collected(List<Rep> hits, boolean overflow) { this.hits = hits; this.overflow = overflow; }
    }

    /** Like {@link #search}, but collects up to {@code limit} accepted representatives (at least one when the limit is below one). */
    public static Collected collect(Probes pr, java.util.function.Predicate<Rep> predicate, double max, double limit) {
        if (productSize(pr) > max) return new Collected(new ArrayList<>(), true);
        List<Rep> hits = new ArrayList<>();
        forEachRep(pr, r -> {
            if (predicate.test(r)) { hits.add(r); return hits.size() >= limit; }
            return false;
        });
        return new Collected(hits, false);
    }
}
