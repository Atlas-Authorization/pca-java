package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.ActionsBridge;

/**
 * The semantic diff of two versions of one action def: is the NEW definition no more permissive than the OLD one? Classes: equal (only
 * text differs), narrow (every call the new def accepts is accepted by the old one and every old restriction still holds), widen, and
 * incomparable (one dimension widens while another narrows, or the change has no order). Conservative: a def that cannot be ordered
 * is incomparable, never narrow. Only equal and narrow let a pin follow the change without the principal.
 */
public final class ActionDiff {
    private ActionDiff() {}

    private static final int DEFAULT_MAX_LEN = 1024, DEFAULT_MAX_ITEMS = 64;
    private static final double INF = Double.POSITIVE_INFINITY;
    private static final List<String> PROVENANCE = List.of("first_party", "tool", "agent");
    private static final List<String> SENSITIVITY = List.of("free", "material", "critical");

    private enum Rel { EQ, NARROW, WIDEN, INC }

    private static Set<Object> set(Object xs) { return new LinkedHashSet<>(xs instanceof List ? J.a(xs) : List.of()); }

    private static Rel setRel(Collection<?> o, Collection<?> n) {
        Set<Object> os = new LinkedHashSet<>(o), ns = new LinkedHashSet<>(n);
        boolean added = false, removed = false;
        for (Object x : ns) if (!os.contains(x)) added = true;
        for (Object x : os) if (!ns.contains(x)) removed = true;
        return added && removed ? Rel.INC : added ? Rel.NARROW : removed ? Rel.WIDEN : Rel.EQ;
    }

    private static Rel setRel(Object o, Object n) { return setRel(set(o), set(n)); }

    private static Rel rankRel(double o, double n) { return n == o ? Rel.EQ : n > o ? Rel.NARROW : Rel.WIDEN; }

    private static double nz(Object v, double dflt) { Double d = J.num(v); return d == null ? dflt : d; }

    private static boolean allIn(Object inner, Object outer) { return J.a(outer).containsAll(J.a(inner)); }

    /** Is every value of {@code inner}'s domain also a value of {@code outer}'s? Same declared type required. Sound, not complete. */
    private static boolean domainContains(Map<String, Object> outer, Map<String, Object> inner) {
        Object ot = outer.get("type");
        if (!Objects.equals(ot, inner.get("type"))) return false;
        switch ((String) ot) {
            case "string":
            case "object_ref": {
                if (nz(inner.get("max_len"), DEFAULT_MAX_LEN) > nz(outer.get("max_len"), DEFAULT_MAX_LEN)) return false;
                if (outer.get("values") != null && (inner.get("values") == null || !allIn(inner.get("values"), outer.get("values")))) return false;
                return outer.get("format") == null || Objects.equals(inner.get("format"), outer.get("format"));
            }
            case "integer":
                return nz(inner.get("min"), -INF) >= nz(outer.get("min"), -INF) && nz(inner.get("max"), INF) <= nz(outer.get("max"), INF);
            case "duration":
                return Math.max(nz(inner.get("min"), 0), 0) >= Math.max(nz(outer.get("min"), 0), 0) && nz(inner.get("max"), INF) <= nz(outer.get("max"), INF);
            case "set": {
                List<Object> ov = outer.get("values") == null ? List.of() : J.a(outer.get("values")), iv = inner.get("values") == null ? List.of() : J.a(inner.get("values"));
                if (!ov.containsAll(iv)) return false;
                double oMax = Math.min(nz(outer.get("max_items"), ov.size()), ov.size()), iMax = Math.min(nz(inner.get("max_items"), iv.size()), iv.size());
                return nz(inner.get("min_items"), 0) >= nz(outer.get("min_items"), 0) && iMax <= oMax;
            }
            case "array": {
                Object oi = outer.get("items") == null ? "string" : outer.get("items"), ii = inner.get("items") == null ? "string" : inner.get("items");
                if (!oi.equals(ii)) return false;
                if (nz(inner.get("min_items"), 0) < nz(outer.get("min_items"), 0) || nz(inner.get("max_items"), DEFAULT_MAX_ITEMS) > nz(outer.get("max_items"), DEFAULT_MAX_ITEMS)) return false;
                if ("integer".equals(outer.get("items"))) return nz(inner.get("min"), -INF) >= nz(outer.get("min"), -INF) && nz(inner.get("max"), INF) <= nz(outer.get("max"), INF);
                return nz(inner.get("max_len"), DEFAULT_MAX_LEN) <= nz(outer.get("max_len"), DEFAULT_MAX_LEN);
            }
            default:
                return true;
        }
    }

    private static boolean callsContained(Map<String, Object> outer, Map<String, Object> inner) {
        for (Map.Entry<String, Object> e : inner.entrySet()) {
            Object op = outer.get(e.getKey());
            if (op == null || !domainContains(J.m(op), J.m(e.getValue()))) return false;
        }
        for (Map.Entry<String, Object> e : outer.entrySet()) {
            if (!Boolean.TRUE.equals(J.get(e.getValue(), "required"))) continue;
            Object ip = inner.get(e.getKey());
            if (ip == null || !Boolean.TRUE.equals(J.get(ip, "required"))) return false;
        }
        return true;
    }

    private static Rel callSetRel(Map<String, Object> oldP, Map<String, Object> newP) {
        boolean sub = callsContained(oldP, newP), sup = callsContained(newP, oldP);
        return sub && sup ? Rel.EQ : sub ? Rel.NARROW : sup ? Rel.WIDEN : Rel.INC;
    }

    private static int provRank(Object p) { return p == null ? PROVENANCE.size() - 1 : PROVENANCE.indexOf(p); }

    private static String sens(Map<String, Object> p) { return p.get("sensitivity") instanceof String ? (String) p.get("sensitivity") : ActionsBridge.effectiveParamSensitivity(p); }

    private static List<Object[]> paramAttrRels(Map<String, Object> o, Map<String, Object> n) {
        List<Object[]> out = new ArrayList<>();
        if (!Objects.equals(o.get("role"), n.get("role"))) out.add(new Object[] {"role", Rel.INC});
        out.add(new Object[] {"sensitivity", rankRel(SENSITIVITY.indexOf(sens(o)), SENSITIVITY.indexOf(sens(n)))});
        out.add(new Object[] {"tags", setRel(o.get("tags"), n.get("tags"))});
        out.add(new Object[] {"provenance_min", rankRel(-provRank(o.get("provenance_min")), -provRank(n.get("provenance_min")))});
        if (!J.sameJsonMember(o, n, "unit")) out.add(new Object[] {"unit", Rel.INC});
        out.add(new Object[] {"accumulates", setRel(o.get("accumulates"), n.get("accumulates"))});
        if (!J.sameJsonMember(o, n, "default") || !Objects.equals(o.get("principal_neutral_default"), n.get("principal_neutral_default"))) out.add(new Object[] {"default", Rel.INC});
        return out;
    }

    private static final Map<String, Integer> SCOPE_RANK = Map.of("one", 0, "set", 1, "tenant", 2, "global", 3);
    private static final Map<String, Integer> IDEM_RANK = Map.of("none", 0, "natural", 1, "key_param", 2);

    private static String str(Object o) { return o instanceof String ? (String) o : null; }

    /** The semantic diff of {@code next} against {@code prev} (versions of the same verb): {@code {class, reasons}}. Throws {@code diff_verb} for two different verbs. */
    public static Map<String, Object> diffDefs(Map<String, Object> prev, Map<String, Object> next, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified) {
        if (!Objects.equals(prev.get("verb"), next.get("verb"))) {
            throw new Actions.ActionKitError("diff_verb", "diff compares two versions of one verb, not '" + prev.get("verb") + "' and '" + next.get("verb") + "'");
        }
        Map<String, Object> o = Actions.normalize(prev), n = Actions.normalize(next);
        List<Object[]> rels = new ArrayList<>();
        boolean text = !Objects.equals(o.get("title"), n.get("title")) || !Objects.equals(o.get("description"), n.get("description")) || !Objects.equals(o.get("compensates"), n.get("compensates"));
        rels.add(new Object[] {"effects", setRel(o.get("effects"), n.get("effects"))});
        Map<String, Object> op = J.m(o.get("params")), np = J.m(n.get("params"));
        rels.add(new Object[] {"params.accepted_calls", callSetRel(op, np)});
        for (String name : new TreeSet<>(op.keySet())) {
            if (np.containsKey(name)) for (Object[] r : paramAttrRels(J.m(op.get(name)), J.m(np.get(name)))) rels.add(new Object[] {"params." + name + "." + r[0], r[1]});
        }
        Map<String, Object> eo = ActionEffective.effective(prev, reg, attestationVerified), en = ActionEffective.effective(next, reg, attestationVerified);
        Map<String, Object> ho = J.m(eo.get("hint")), hn = J.m(en.get("hint"));
        rels.add(new Object[] {"traits", setRel(Actions.closure(reg, J.a(ho.get("traits"))), Actions.closure(reg, J.a(hn.get("traits"))))});
        rels.add(new Object[] {"profile", profRel(J.m(ho.get("eff")), J.m(hn.get("eff")))});
        rels.add(new Object[] {"confirmation", rankRel(Boolean.TRUE.equals(eo.get("confirmed")) ? 0 : 1, Boolean.TRUE.equals(en.get("confirmed")) ? 0 : 1)});
        rels.add(new Object[] {"effective.traits", setRel(Actions.closure(reg, J.a(eo.get("traits"))), Actions.closure(reg, J.a(en.get("traits"))))});
        rels.add(new Object[] {"effective.profile", profRel(J.m(eo.get("eff")), J.m(en.get("eff")))});
        rels.add(new Object[] {"reversibility", rankRel(ActionsBridge.revRank(ActionsBridge.worstReversibility(o.get("reversibility"), op)), ActionsBridge.revRank(ActionsBridge.worstReversibility(n.get("reversibility"), np)))});
        rels.add(new Object[] {"blast", rankRel(J.num(J.get(o.get("blast"), "ppm")), J.num(J.get(n.get("blast"), "ppm")))});
        Object oi = o.get("idempotency"), ni = n.get("idempotency");
        Rel idem = "key_param".equals(J.get(oi, "mode")) && "key_param".equals(J.get(ni, "mode")) && !Objects.equals(J.get(oi, "param"), J.get(ni, "param"))
            ? Rel.INC : rankRel(IDEM_RANK.get((String) J.get(oi, "mode")), IDEM_RANK.get((String) J.get(ni, "mode")));
        rels.add(new Object[] {"idempotency", idem});
        rels.add(new Object[] {"context", setRel(o.get("context"), n.get("context"))});
        rels.add(new Object[] {"side_effects", setRel(sideEffects(o), sideEffects(n))});
        Map<String, Object> ores = J.m(o.get("resource")), nres = J.m(n.get("resource"));
        Rel resId;
        if (J.sameJson(ores.get("id"), true, nres.get("id"), true)) resId = Rel.EQ;
        else if (ActionIdPattern.idPatternContains(ores.get("id"), nres.get("id"))) resId = Rel.NARROW;
        else if (ActionIdPattern.idPatternContains(nres.get("id"), ores.get("id"))) resId = Rel.WIDEN;
        else resId = Rel.INC;
        rels.add(new Object[] {"resource.id", !Objects.equals(ores.get("type"), nres.get("type")) ? Rel.INC : resId});
        rels.add(new Object[] {"resource.scope", rankRel(-SCOPE_RANK.get((String) ores.get("scope")), -SCOPE_RANK.get((String) nres.get("scope")))});
        Rel ar = setRel(o.get("aliases"), n.get("aliases"));
        rels.add(new Object[] {"aliases", ar == Rel.NARROW ? Rel.WIDEN : ar == Rel.WIDEN ? Rel.NARROW : ar});
        rels.add(new Object[] {"bindings", J.sameJson(o.get("bindings"), true, n.get("bindings"), true) ? Rel.EQ : Rel.INC});

        List<Object[]> diffs = new ArrayList<>();
        for (Object[] r : rels) if (r[1] != Rel.EQ) diffs.add(r);
        List<String> reasons = new ArrayList<>();
        for (Object[] r : diffs) reasons.add(r[0] + ": " + (r[1] == Rel.INC ? "incomparable" : ((Rel) r[1]).name().toLowerCase(java.util.Locale.ROOT)));
        if (text) reasons.add("text: title, description or compensates changed");
        reasons.sort(null);
        boolean inc = has(diffs, Rel.INC), nar = has(diffs, Rel.NARROW), wid = has(diffs, Rel.WIDEN);
        String cls = inc || (nar && wid) ? "incomparable" : wid ? "widen" : nar ? "narrow" : "equal";
        return J.obj("class", cls, "reasons", J.objs(reasons));
    }

    public static Map<String, Object> diffDefs(Map<String, Object> prev, Map<String, Object> next, Actions.Registry reg) { return diffDefs(prev, next, reg, null); }

    public static Map<String, Object> diffDefs(Map<String, Object> prev, Map<String, Object> next) { return diffDefs(prev, next, Actions.CORE_REGISTRY, null); }

    private static boolean has(List<Object[]> diffs, Rel r) { for (Object[] d : diffs) if (d[1] == r) return true; return false; }

    private static Rel profRel(Map<String, Object> a, Map<String, Object> b) {
        return ActionEffective.leq(a, b) ? (ActionEffective.leq(b, a) ? Rel.EQ : Rel.NARROW) : ActionEffective.leq(b, a) ? Rel.WIDEN : Rel.INC;
    }

    private static List<Object> sideEffects(Map<String, Object> d) {
        List<Object> out = new ArrayList<>();
        for (Object s : J.a(d.get("side_effects"))) out.add(J.get(s, "target") + "|" + J.get(s, "kind"));
        return out;
    }

    /** Does a pin follow this change on its own (no principal)? */
    public static boolean diffIsFree(String cls) { return "equal".equals(cls) || "narrow".equals(cls); }
}
