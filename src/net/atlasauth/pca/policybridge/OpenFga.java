package net.atlasauth.pca.policybridge;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * OpenFGA / Zanzibar ReBAC model and tuples to PCA predicates: one permit per (user, object, relation) triple that holds,
 * evaluated at translation time over the whole tuple set (direct, computedUserset, union, intersection, difference and
 * tupleToUserset, bounded and cycle-guarded). Userset-valued tuples are reported and not expanded; anything unmodeled grants
 * nothing. Mirrors {@code openfgaToPca}.
 */
public final class OpenFga {
    private OpenFga() {}

    private static final int MAX_DEPTH = 32;

    /** A translation with no tuples argument (the reference's {@code undefined}). */
    public static Map<String, Object> openfgaToPca(Object model) { return translate(model, null, false); }

    /** A translation over {@code tuples}; anything but a list is an error (the reference's {@code null}). */
    public static Map<String, Object> openfgaToPca(Object model, Object tuples) { return translate(model, tuples, true); }

    // ---- resolution plan ----

    private enum PK { DIRECT, COMPUTED, UNION, INTERSECTION, DIFFERENCE, TTU }

    private static final class Plan {
        final PK kind;
        String relation, tupleset, computed;
        List<Plan> children;
        Plan base, subtract;
        Plan(PK kind) { this.kind = kind; }
    }

    private static final class Built {
        final boolean ok;
        final Plan plan;
        final boolean partial;
        final String reason;
        Built(boolean ok, Plan plan, boolean partial, String reason) { this.ok = ok; this.plan = plan; this.partial = partial; this.reason = reason; }
        static Built fail(String reason) { return new Built(false, null, false, reason); }
    }

    private static final class Tuple {
        final String user, relation, object;
        Tuple(String user, String relation, String object) { this.user = user; this.relation = relation; this.object = object; }
    }

    private static String describePlan(Plan plan) {
        switch (plan.kind) {
            case DIRECT: return "direct";
            case COMPUTED: return "computed " + plan.relation;
            case UNION: return "union[" + describeAll(plan.children) + "]";
            case INTERSECTION: return "intersection[" + describeAll(plan.children) + "]";
            case DIFFERENCE: return "difference(" + describePlan(plan.base) + " - " + describePlan(plan.subtract) + ")";
            default: return plan.computed + " from " + plan.tupleset;
        }
    }

    private static String describeAll(List<Plan> ps) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < ps.size(); i++) { if (i > 0) sb.append(", "); sb.append(describePlan(ps.get(i))); }
        return sb.toString();
    }

    private static boolean hasOwn(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }
    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }
    private static boolean isRewrite(Object v) { return v instanceof Map || v instanceof List; }

    private static List<?> childNodes(Object container) {
        Object child = get(container, "child");
        return child instanceof List ? (List<?>) child : null;
    }

    /** The {@code .relation} string of a {@code { relation }} object, or null. */
    private static String relationOf(Object v) {
        Object rel = get(v, "relation");
        return rel instanceof String && !((String) rel).isEmpty() ? (String) rel : null;
    }

    private static Built buildPlan(Object node) {
        if (hasOwn(node, "this")) return new Built(true, new Plan(PK.DIRECT), false, null);

        if (hasOwn(node, "computedUserset")) {
            String rel = relationOf(get(node, "computedUserset"));
            if (rel == null) return Built.fail("computedUserset without a relation");
            Plan p = new Plan(PK.COMPUTED);
            p.relation = rel;
            return new Built(true, p, false, null);
        }

        if (hasOwn(node, "union")) {
            List<?> children = childNodes(get(node, "union"));
            if (children == null) return Built.fail("union without children");
            List<Plan> subs = new ArrayList<>();
            boolean partial = false;
            for (Object child : children) {
                if (!isRewrite(child)) { partial = true; continue; }
                Built sub = buildPlan(child);
                if (!sub.ok || sub.plan == null) { partial = true; continue; }
                if (sub.partial) partial = true;
                subs.add(sub.plan);
            }
            if (subs.isEmpty()) return new Built(false, null, partial, "union with no modeled children");
            Plan p = new Plan(PK.UNION);
            p.children = subs;
            return new Built(true, p, partial, null);
        }

        if (hasOwn(node, "intersection")) {
            List<?> children = childNodes(get(node, "intersection"));
            if (children == null) return Built.fail("intersection without children");
            List<Plan> subs = new ArrayList<>();
            for (Object child : children) {
                if (!isRewrite(child)) return Built.fail("intersection child is not a rewrite");
                Built sub = buildPlan(child);
                if (!sub.ok || sub.plan == null) return Built.fail("intersection child unmodeled (" + (sub.reason != null ? sub.reason : "unsupported") + ")");
                subs.add(sub.plan);
            }
            if (subs.isEmpty()) return Built.fail("intersection with no children");
            Plan p = new Plan(PK.INTERSECTION);
            p.children = subs;
            return new Built(true, p, false, null);
        }

        if (hasOwn(node, "difference")) {
            Object diff = get(node, "difference");
            if (!(diff instanceof Map || diff instanceof List)) return Built.fail("malformed difference");
            Object baseNode = get(diff, "base"), subNode = get(diff, "subtract");
            if (!isRewrite(baseNode) || !isRewrite(subNode)) return Built.fail("difference needs both base and subtract");
            Built base = buildPlan(baseNode);
            Built subtract = buildPlan(subNode);
            if (!base.ok || base.plan == null) return Built.fail("difference base unmodeled (" + (base.reason != null ? base.reason : "?") + ")");
            if (!subtract.ok || subtract.plan == null) return Built.fail("difference subtract unmodeled (" + (subtract.reason != null ? subtract.reason : "?") + ")");
            Plan p = new Plan(PK.DIFFERENCE);
            p.base = base.plan;
            p.subtract = subtract.plan;
            return new Built(true, p, base.partial || subtract.partial, null);
        }

        if (hasOwn(node, "tupleToUserset")) {
            Object ttu = get(node, "tupleToUserset");
            if (!(ttu instanceof Map || ttu instanceof List)) return Built.fail("malformed tupleToUserset");
            String tuplesetRel = relationOf(get(ttu, "tupleset"));
            String computedRel = relationOf(get(ttu, "computedUserset"));
            if (tuplesetRel == null) return Built.fail("tupleToUserset without a tupleset relation");
            if (computedRel == null) return Built.fail("tupleToUserset without a computedUserset relation");
            Plan p = new Plan(PK.TTU);
            p.tupleset = tuplesetRel;
            p.computed = computedRel;
            return new Built(true, p, false, null);
        }

        return Built.fail("unknown rewrite node");
    }

    // ---- model / tuple parsing ----

    /** type to (relation to rewrite node), in the reference's iteration order; null when the model is unusable. */
    private static Map<String, Map<String, Object>> parseModel(Object model, Map<String, Object> report) {
        if (!(model instanceof Map || model instanceof List)) {
            PolicyBridge.list(report, "errors").add("model is not an object");
            return null;
        }
        Object defs = get(model, "type_definitions");
        if (!(defs instanceof List)) {
            PolicyBridge.list(report, "errors").add("model.type_definitions is missing or not an array");
            return null;
        }
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (Object def : (List<?>) defs) {
            if (!(def instanceof Map || def instanceof List)) continue;
            Object type = get(def, "type");
            if (!(type instanceof String) || ((String) type).isEmpty()) continue;
            Map<String, Object> relMap = new LinkedHashMap<>();
            Map<String, Object> rels = Js.entries(get(def, "relations"));
            if (rels != null) {
                for (Map.Entry<String, Object> e : rels.entrySet()) if (isRewrite(e.getValue())) relMap.put(e.getKey(), e.getValue());
            }
            out.put((String) type, relMap);
        }
        return out;
    }

    private static List<Tuple> parseTuples(Object tuples, boolean given, Map<String, Object> report) {
        if (!(tuples instanceof List)) {
            if (given) PolicyBridge.list(report, "errors").add("tuples is not an array");
            return new ArrayList<>();
        }
        List<Tuple> out = new ArrayList<>();
        for (Object t : (List<?>) tuples) {
            if (!(t instanceof Map)) continue;
            Object user = ((Map<?, ?>) t).get("user"), relation = ((Map<?, ?>) t).get("relation"), object = ((Map<?, ?>) t).get("object");
            if (user instanceof String && relation instanceof String && object instanceof String) out.add(new Tuple((String) user, (String) relation, (String) object));
        }
        return out;
    }

    private static boolean isWildcard(String user) { return user.endsWith(":*") && user.length() > 2 && user.indexOf('#') < 0; }

    private static String escapeGlob(String t) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == '*' || c == '?' || c == '\\') sb.append('\\');
            sb.append(c);
        }
        return sb.toString();
    }

    private static String typeOf(String object) {
        int i = object.indexOf(':');
        return i < 0 ? object : object.substring(0, i);
    }

    private static String objectOfUserset(String p) {
        int i = p.indexOf('#');
        return i < 0 ? p : p.substring(0, i);
    }

    private static String key(String a, String b) { return a + "\0" + b; }

    // ---- translation ----

    private static Map<String, Object> translate(Object model, Object tuples, boolean tuplesGiven) {
        Map<String, Object> report = PolicyBridge.newReport("openfga");
        List<Object> predicates = new ArrayList<>();

        Map<String, Map<String, Object>> typeRelations = parseModel(model, report);
        List<Tuple> tupleList = parseTuples(tuples, tuplesGiven, report);
        if (typeRelations == null) return PolicyBridge.result(predicates, new ArrayList<>(), report);

        Map<String, Set<String>> direct = new HashMap<>();
        Set<String> usersSeen = new HashSet<>();
        Set<String> wildcardTypes = new HashSet<>();
        Set<String> objectsSeen = new HashSet<>();
        int usersetTuples = 0;
        for (Tuple t : tupleList) {
            objectsSeen.add(t.object);
            direct.computeIfAbsent(key(t.object, t.relation), k -> new LinkedHashSet<>()).add(t.user);
            if (t.user.indexOf('#') >= 0) usersetTuples++;
            else if (isWildcard(t.user)) wildcardTypes.add(t.user.substring(0, t.user.length() - 2));
            else usersSeen.add(t.user);
        }
        if (usersetTuples > 0) {
            PolicyBridge.list(report, "skipped").add(usersetTuples + " userset-valued tuple(s) (user contains '#') not expanded to concrete users");
        }

        Map<String, Plan> plans = new HashMap<>();
        for (Map.Entry<String, Map<String, Object>> te : typeRelations.entrySet()) {
            for (Map.Entry<String, Object> re : te.getValue().entrySet()) {
                String type = te.getKey(), relation = re.getKey();
                Built built = buildPlan(re.getValue());
                if (!built.ok || built.plan == null) {
                    PolicyBridge.list(report, "skipped").add("relation " + type + "#" + relation + ": " + (built.reason != null ? built.reason : "unsupported rewrite") + " — skipped");
                    continue;
                }
                if (built.partial) {
                    PolicyBridge.list(report, "skipped").add("relation " + type + "#" + relation + ": some union children unsupported and dropped (under-approximated)");
                }
                plans.put(key(type, relation), built.plan);
                PolicyBridge.list(report, "translated").add("relation " + type + "#" + relation + " (" + describePlan(built.plan) + ")");
            }
        }

        Evaluator ev = new Evaluator(direct, plans);

        TreeSet<String> sortedUsers = new TreeSet<>(usersSeen);
        TreeSet<String> sortedObjects = new TreeSet<>(objectsSeen);
        TreeSet<String> sortedWildcards = new TreeSet<>(wildcardTypes);
        for (String object : sortedObjects) {
            String type = typeOf(object);
            Map<String, Object> relations = typeRelations.get(type);
            if (relations == null) {
                PolicyBridge.list(report, "skipped").add("object " + object + ": type \"" + type + "\" not defined in model — ignored");
                continue;
            }
            for (String relation : new TreeSet<>(relations.keySet())) {
                if (!plans.containsKey(key(type, relation))) continue;
                for (String user : sortedUsers) {
                    if (ev.holdsRel(user, object, relation, 0, new HashSet<>())) {
                        List<Object> where = new ArrayList<>();
                        where.add(Js.obj("field", "subject.id", "op", "eq", "value", user));
                        predicates.add(Js.obj("verb", relation, "resource", object, "where", where));
                    }
                }
                // A public tuple (`type:*`) grants every subject of that type, including ones no tuple names; decide for a subject
                // that no tuple names. The named ones were decided above (a difference or intersection may exclude them).
                for (String wtype : sortedWildcards) {
                    if (!ev.holdsRel(wtype + ":\0anyone", object, relation, 0, new HashSet<>())) continue;
                    List<Object> named = new ArrayList<>();
                    for (String u : sortedUsers) if (typeOf(u).equals(wtype)) named.add(u);
                    List<Object> where = new ArrayList<>();
                    where.add(Js.obj("field", "subject.id", "op", "like", "value", escapeGlob(wtype) + ":*"));
                    if (!named.isEmpty()) where.add(Js.obj("not", Js.obj("field", "subject.id", "op", "in", "value", named)));
                    predicates.add(Js.obj("verb", relation, "resource", object, "where", where));
                }
            }
        }

        return PolicyBridge.result(predicates, new ArrayList<>(), report);
    }

    /** Bounded, cycle-guarded evaluation of the plans over the direct tuples. */
    private static final class Evaluator {
        private final Map<String, Set<String>> direct;
        private final Map<String, Plan> plans;
        Evaluator(Map<String, Set<String>> direct, Map<String, Plan> plans) { this.direct = direct; this.plans = plans; }

        boolean holdsRel(String user, String object, String relation, int depth, Set<String> visited) {
            String k = key(object, relation);
            if (depth > MAX_DEPTH || visited.contains(k)) return false;
            Plan plan = plans.get(key(typeOf(object), relation));
            if (plan == null) return false;
            Set<String> next = new HashSet<>(visited);
            next.add(k);
            return evalPlan(user, object, relation, plan, depth, next);
        }

        boolean evalPlan(String user, String object, String relation, Plan plan, int depth, Set<String> visited) {
            switch (plan.kind) {
                case DIRECT: {
                    Set<String> set = direct.get(key(object, relation));
                    return set != null && (set.contains(user) || set.contains(typeOf(user) + ":*"));
                }
                case COMPUTED:
                    return holdsRel(user, object, plan.relation, depth + 1, visited);
                case UNION:
                    for (Plan c : plan.children) if (evalPlan(user, object, relation, c, depth, visited)) return true;
                    return false;
                case INTERSECTION:
                    for (Plan c : plan.children) if (!evalPlan(user, object, relation, c, depth, visited)) return false;
                    return true;
                case DIFFERENCE:
                    return evalPlan(user, object, relation, plan.base, depth, visited) && !evalPlan(user, object, relation, plan.subtract, depth, visited);
                default: {
                    Set<String> related = direct.get(key(object, plan.tupleset));
                    if (related == null) return false;
                    for (String p : related) if (holdsRel(user, objectOfUserset(p), plan.computed, depth + 1, visited)) return true;
                    return false;
                }
            }
        }
    }
}
