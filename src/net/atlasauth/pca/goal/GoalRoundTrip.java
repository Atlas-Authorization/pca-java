package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Round-trip checks. (a) The card's lossless token tape decodes back to the goal. (b) An explainer sees only the compiled card
 * lines and a comparator judges the explanation against the principal's text: a detector, tighten-only (it can only escalate),
 * measured by semantic mutations that WIDEN the policy.
 */
public final class GoalRoundTrip {
    private GoalRoundTrip() {}

    public static final List<String> MUTATION_KINDS = List.of("widen_cap", "widen_where", "drop_prohibit", "drop_bound", "swap_resource", "add_grant");

    private static Map<String, Object> mm(Object o) { return G.m(o); }

    /** decode(encode(goal)) equals the goal: nothing the goal says is lost on the card tape. */
    public static boolean cardRoundTrips(Map<String, Object> g) {
        return G.stable(GoalCodec.decodeGoal(GoalCodec.encodeGoal(g))).equals(G.stable(g));
    }

    @SuppressWarnings("unchecked")
    private static Object copy(Object o) {
        if (o instanceof Map) { Map<String, Object> r = new LinkedHashMap<>(); for (Map.Entry<String, Object> e : ((Map<String, Object>) o).entrySet()) r.put(e.getKey(), copy(e.getValue())); return r; }
        if (o instanceof List) { List<Object> r = new ArrayList<>(); for (Object x : (List<Object>) o) r.add(copy(x)); return r; }
        return o;
    }

    private static Object numOut(double d) {
        if (d == Math.rint(d) && Math.abs(d) <= G.MAX_SAFE) return G.num((long) d);
        throw new IrError("non-integer result");
    }

    private static Map<String, Object> scale(Map<String, Object> x, double f) {
        String uk = G.kind(mm(x.get("u")));
        if (!uk.equals("money") && !uk.equals("count")) return x;
        Map<String, Object> r = new LinkedHashMap<>(x);
        r.put("n", numOut(G.toNum(x.get("n")) * f));
        return r;
    }

    private static Map<String, Object> mapLitsInCond(Map<String, Object> c) {
        String k = G.kind(c);
        if (k.equals("cmp")) {
            Map<String, Object> r = mm(c.get("r"));
            Map<String, Object> out = new LinkedHashMap<>(c);
            boolean lit = G.kind(r).equals("lit") && G.kind(mm(r.get("v"))).equals("q") && ("lte".equals(c.get("op")) || "lt".equals(c.get("op")));
            if (lit) out.put("r", G.map("k", "lit", "v", G.map("k", "q", "q", scale(mm(mm(r.get("v")).get("q")), 10))));
            return out;
        }
        if (k.equals("and") || k.equals("or")) {
            Map<String, Object> out = new LinkedHashMap<>(c);
            out.put("a", mapLitsInCond(mm(c.get("a"))));
            out.put("b", mapLitsInCond(mm(c.get("b"))));
            return out;
        }
        return c;
    }

    /** A semantic mutation that WIDENS the policy (or leaves it equal); null when the goal has nothing to mutate. */
    public static Map<String, Object> mutateGoal(Map<String, Object> g, String kind, Map<String, Object> ontology) {
        Map<String, Object> x = mm(copy(g));
        switch (kind) {
            case "widen_cap": {
                List<Object> bounds = G.arr(x.get("bounds"), "bounds");
                if (bounds.isEmpty()) return null;
                mm(bounds.get(0)).put("cap", scale(mm(mm(bounds.get(0)).get("cap")), 10));
                return x;
            }
            case "widen_where": {
                for (Object yo : G.arr(x.get("grants"), "grants")) {
                    Map<String, Object> y = mm(yo);
                    Map<String, Object> mapped = mapLitsInCond(mm(y.get("cond")));
                    if (!G.stringify(mapped).equals(G.stringify(y.get("cond")))) { y.put("cond", mapped); return x; }
                }
                return null;
            }
            case "drop_prohibit": {
                List<Object> ps = G.arr(x.get("prohibits"), "prohibits");
                if (ps.isEmpty()) return null;
                ps.remove(ps.size() - 1);
                return x;
            }
            case "drop_bound": {
                List<Object> bs = G.arr(x.get("bounds"), "bounds");
                if (bs.isEmpty()) return null;
                bs.remove(bs.size() - 1);
                return x;
            }
            case "swap_resource": {
                for (Object yo : G.arr(x.get("grants"), "grants")) {
                    Map<String, Object> y = mm(yo);
                    if (G.kind(y.get("res")).equals("exact")) { y.put("res", G.map("k", "exact", "id", mm(y.get("res")).get("id") + "9")); return x; }
                }
                return null;
            }
            case "add_grant": {
                Set<Object> have = new LinkedHashSet<>();
                for (Object y : G.arr(x.get("grants"), "grants")) have.add(G.get(y, "verb"));
                Map<String, Object> v = null;
                for (Object yo : G.arr(ontology.get("verbs"), "verbs")) {
                    Map<String, Object> y = mm(yo);
                    if ("read".equals(y.get("effect")) || have.contains(y.get("id"))) continue;
                    boolean prohibited = false;
                    for (Object p : G.arr(x.get("prohibits"), "prohibits")) if (G.kind(G.get(p, "target")).equals("verb") && java.util.Objects.equals(mm(G.get(p, "target")).get("verb"), y.get("id"))) prohibited = true;
                    if (!prohibited) { v = y; break; }
                }
                if (v == null) return null;
                G.arr(x.get("grants"), "grants").add(G.map("gid", "injected", "verb", v.get("id"), "res", G.map("k", "any", "reason", "injected"), "cond", G.map("k", "true")));
                G.arr(x.get("wildcardAck"), "wildcardAck").add("injected");
                return GoalNormalize.canonicalizeGoal(x);
            }
            default: return null;
        }
    }

    /** The reference explainer: the card lines themselves. */
    public static String deterministicExplain(List<String> proseLines) { return String.join("\n", proseLines); }

    /**
     * Round trip (b): the explainer sees ONLY the compiled card lines. {@code comparator(goalText, explanation)} returns a map with
     * {@code equivalent}. Any failure escalates. Result: "ok" or "escalate".
     */
    public static String roundTrip(Map<String, Object> goal, String goalText, Function<List<String>, String> explainer, BiFunction<String, String, Map<String, Object>> comparator) {
        try {
            List<String> lines = new ArrayList<>();
            for (Object l : G.arr(GoalCard.renderCard(goal).get("lines"), "lines")) lines.add((String) l);
            String e = explainer.apply(lines);
            return G.truthy(comparator.apply(goalText, e).get("equivalent")) ? "ok" : "escalate";
        } catch (RuntimeException ex) {
            return "escalate";
        }
    }

    /** Fraction of semantic widenings the pair flags, per mutation kind: [{kind, applied, detected, rate}]. {@code cases} = [{goal, text}]. */
    public static List<Object> measureDetection(List<Object> cases, Map<String, Object> ontology, Function<List<String>, String> explainer, BiFunction<String, String, Map<String, Object>> comparator) {
        List<Object> out = new ArrayList<>();
        for (String kind : MUTATION_KINDS) {
            int applied = 0, detected = 0;
            for (Object co : cases) {
                Map<String, Object> m = mutateGoal(mm(G.get(co, "goal")), kind, ontology);
                if (m == null) continue;
                applied++;
                if (roundTrip(m, (String) G.get(co, "text"), explainer, comparator).equals("escalate")) detected++;
            }
            out.add(G.map("kind", kind, "applied", G.num(applied), "detected", G.num(detected), "rate", applied > 0 ? (Object) ((double) detected / applied) : G.num(0)));
        }
        return out;
    }
}
