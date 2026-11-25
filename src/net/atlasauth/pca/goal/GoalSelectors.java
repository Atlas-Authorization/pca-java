package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.BiFunction;
import java.util.regex.Pattern;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Pca;

/**
 * Trait selectors and role-addressed parameters for the Goal IR. A selector goal (SelGoal) names a verb selector (a verb, or a class: every
 * verb of the pinned catalog with all of the traits and none of the excluded ones) in its grants, may select by trait in prohibitions and
 * bounds, and may name a parameter by ROLE. {@link #expandSelGoal} lowers it, against the PINNED catalog, to an ordinary Goal (one grant per
 * verb, each with that verb's own parameter path); the proved core compiler then does the rest.
 *
 * <p>Fail-closed: a grant verb with no unique parameter of a role the condition names is DROPPED (reported); a prohibition whose role term
 * is unresolved for a verb applies to that verb UNCONDITIONALLY; a bound whose role-addressed value cannot be resolved for every selected
 * verb is a type error; an allow selector is positive (no {@code none_of}, at least one trait); an UNCONFIRMED verb carries the marker
 * {@code pca.unreviewed}: a class ALLOW never covers it, a class PROHIBITION or a bound over a trait selector ALWAYS covers it; an unknown
 * trait id is a type error. A catalog is {known, verbs: [{verb, traits, roles}]}.
 */
public final class GoalSelectors {
    private GoalSelectors() {}

    /** The marker trait every unconfirmed verb carries. */
    public static final String UNREVIEWED = "pca.unreviewed";
    /** Ids are {@code [0-9A-Za-z_]}: the expanded id {@code <gid>.<verb>} then sorts exactly as (gid, verb). */
    public static final Pattern SEL_ID_RE = Pattern.compile("[0-9A-Za-z_]{1,64}");

    private static Map<String, Object> mm(Object o) { return G.m(o); }

    private static List<Object> list(Object o) { return G.arr(o, ""); }

    private static boolean has(List<Object> xs, Object x) { return xs.contains(x); }

    // ---------------- the pinned catalog ----------------

    /**
     * The catalog of a pack of action defs (verb ids and parameter paths are the defs' own). {@code reg} null: the core registry;
     * {@code pins} (the review pins) may be null.
     */
    public static Map<String, Object> selCatalogOfDefs(List<Object> defs, Actions.Registry reg, Map<String, Object> pins) {
        Actions.Registry r = reg != null ? reg : Actions.CORE_REGISTRY;
        List<Object> verbs = new ArrayList<>();
        for (Object dO : defs) {
            Map<String, Object> d = mm(dO);
            Map<String, Object> params = mm(d.get("params"));
            List<String> names = new ArrayList<>(params.keySet());
            names.sort(String::compareTo);
            Map<String, Object> roles = new LinkedHashMap<>();
            for (String name : names) {
                Object role = G.get(params.get(name), "role");
                if (role != null) {
                    String rk = G.jsStr(role);
                    @SuppressWarnings("unchecked") List<Object> ps = (List<Object>) roles.computeIfAbsent(rk, k -> new ArrayList<Object>());
                    ps.add(name);
                }
            }
            verbs.add(G.map("verb", d.get("verb"), "traits", new ArrayList<Object>(list(Actions.effective(d, r, pins).get("closure"))), "roles", roles));
        }
        verbs.sort((a, b) -> G.cmp((String) G.get(a, "verb"), (String) G.get(b, "verb")));
        return G.map("known", new ArrayList<Object>(new TreeSet<>(r.traits.keySet())), "verbs", verbs);
    }

    /** The catalog of a shipped domain ontology (core registry, no review pins); null for an unknown domain. */
    public static Map<String, Object> selCatalogOfDomain(String domain) { return GoalOntologies.selCatalog(domain); }

    /** Digest of the catalog (what {@code catDigest} of a SelGoal must equal). */
    public static String selCatalogDigest(Map<String, Object> c) { return Pca.hashCanonical(G.map("d", "atlas-pca/goal-sel-catalog/v1", "catalog", c)); }

    /** Digest of the whole signed selector goal. */
    public static String selGoalDigest(Map<String, Object> g) { return Pca.hashCanonical(G.map("d", "atlas-pca/goal-ir-sel/v1", "goal", g)); }

    // ---------------- the verbs of a class selector ----------------

    private static boolean hasAll(List<Object> ts, List<Object> req) { for (Object t : req) if (!ts.contains(t)) return false; return true; }

    private static boolean hasNone(List<Object> ts, List<Object> ex) { for (Object t : ex) if (ts.contains(t)) return false; return true; }

    /** The verbs of the catalog, in catalog order, whose trait closure contains every {@code allOf} trait and none of the {@code noneOf} traits. */
    public static List<Object> classVerbs(Map<String, Object> cat, List<Object> allOf, List<Object> noneOf) {
        List<Object> out = new ArrayList<>();
        for (Object vo : list(cat.get("verbs"))) {
            Map<String, Object> v = mm(vo);
            List<Object> ts = list(v.get("traits"));
            if (hasAll(ts, allOf) && hasNone(ts, noneOf)) out.add(v.get("verb"));
        }
        return out;
    }

    /** The verbs a class ALLOW covers: the class, minus every unconfirmed verb. */
    public static List<Object> allowClassVerbs(Map<String, Object> cat, List<Object> allOf, List<Object> noneOf) {
        List<Object> none = new ArrayList<>(noneOf);
        none.add(UNREVIEWED);
        return classVerbs(cat, allOf, none);
    }

    /** The verbs a class PROHIBITION or bound covers: the class, plus every unconfirmed verb whatever the selector says. */
    public static List<Object> floatClassVerbs(Map<String, Object> cat, List<Object> allOf, List<Object> noneOf) {
        List<Object> out = new ArrayList<>();
        for (Object vo : list(cat.get("verbs"))) {
            Map<String, Object> v = mm(vo);
            List<Object> ts = list(v.get("traits"));
            if (ts.contains(UNREVIEWED) || (hasAll(ts, allOf) && hasNone(ts, noneOf))) out.add(v.get("verb"));
        }
        return out;
    }

    // ---------------- role resolution ----------------

    private static Map<String, Object> declOf(Map<String, Object> ont, Object verb) {
        for (Object v : list(ont.get("verbs"))) if (java.util.Objects.equals(G.get(v, "verb"), verb)) return mm(v);
        return null;
    }

    private static Map<String, Object> infoOf(Map<String, Object> cat, Object verb) {
        for (Object v : list(cat.get("verbs"))) if (java.util.Objects.equals(G.get(v, "verb"), verb)) return mm(v);
        return null;
    }

    /** The one parameter of {@code verb} carrying {@code role}, as {path, ty}; none, several or undeclared: null. */
    public static Map<String, Object> resolveRole(Map<String, Object> ont, Map<String, Object> cat, String verb, String role) {
        Map<String, Object> info = infoOf(cat, verb);
        Map<String, Object> decl = declOf(ont, verb);
        if (info == null || decl == null) return null;
        Map<String, Object> roles = mm(info.get("roles"));
        List<Object> paths = roles.containsKey(role) ? list(roles.get(role)) : new ArrayList<>();
        if (paths.size() != 1) return null;
        for (Object p : list(decl.get("params"))) if (java.util.Objects.equals(G.get(p, "path"), paths.get(0))) return G.map("path", G.get(p, "path"), "ty", G.get(p, "ty"));
        return null;
    }

    private static Map<String, Object> resolveTerm(Map<String, Object> ont, Map<String, Object> cat, String verb, Map<String, Object> t) {
        switch (G.kind(t)) {
            case "param": return G.map("k", "param", "path", t.get("path"), "ty", t.get("ty"));
            case "lit": return G.map("k", "lit", "v", t.get("v"));
            case "hist": return G.map("k", "hist", "bid", t.get("bid"), "u", t.get("u"));
            case "role": { Map<String, Object> r = resolveRole(ont, cat, verb, G.jsStr(t.get("role"))); return r == null ? null : G.map("k", "param", "path", r.get("path"), "ty", r.get("ty")); }
            default: return null;
        }
    }

    /** null as soon as one role term is unresolved for the verb. */
    private static Map<String, Object> resolveCond(Map<String, Object> ont, Map<String, Object> cat, String verb, Map<String, Object> c) {
        String k = G.kind(c);
        switch (k) {
            case "true": return G.map("k", "true");
            case "cmp": {
                Map<String, Object> l = resolveTerm(ont, cat, verb, mm(c.get("l")));
                Map<String, Object> r = resolveTerm(ont, cat, verb, mm(c.get("r")));
                return l != null && r != null ? G.map("k", "cmp", "op", c.get("op"), "l", l, "r", r) : null;
            }
            case "and": case "or": {
                Map<String, Object> a = resolveCond(ont, cat, verb, mm(c.get("a")));
                Map<String, Object> b = resolveCond(ont, cat, verb, mm(c.get("b")));
                return a != null && b != null ? G.map("k", k, "a", a, "b", b) : null;
            }
            case "not": { Map<String, Object> a = resolveCond(ont, cat, verb, mm(c.get("c"))); return a != null ? G.map("k", "not", "c", a) : null; }
            default: return null;
        }
    }

    // ---------------- the expansion ----------------

    /** An expanded grant with the source grant id it came from. */
    private static final class EG {
        final Object src;
        final Map<String, Object> g;

        EG(Object src, Map<String, Object> g) { this.src = src; this.g = g; }
    }

    private static List<Object> grantVerbs(Map<String, Object> cat, Map<String, Object> s) {
        return "verb".equals(G.kind(s)) ? G.list(s.get("verb")) : allowClassVerbs(cat, list(s.get("all_of")), list(s.get("none_of")));
    }

    private static List<EG> expandGrants(Map<String, Object> ont, Map<String, Object> cat, List<Object> gs, List<Object> report) {
        List<EG> out = new ArrayList<>();
        for (Object gro : gs) {
            Map<String, Object> gr = mm(gro);
            Map<String, Object> sel = mm(gr.get("sel"));
            List<Object> verbs = grantVerbs(cat, sel);
            List<Object> dropped = new ArrayList<>();
            for (Object vo : verbs) {
                String v = (String) vo;
                Map<String, Object> c = resolveCond(ont, cat, v, mm(gr.get("cond")));
                if (c == null) { dropped.add(G.map("verb", v, "reason", "role_unresolved")); continue; }
                String gid = "class".equals(G.kind(sel)) ? G.jsStr(gr.get("gid")) + "." + v : G.jsStr(gr.get("gid"));
                out.add(new EG(gr.get("gid"), G.map("gid", gid, "verb", v, "res", gr.get("res"), "cond", c)));
            }
            if (report != null) report.add(G.map("gid", gr.get("gid"), "verbs", verbs, "dropped", dropped));
        }
        return out;
    }

    private static List<Object> prohVerbs(Map<String, Object> ont, Map<String, Object> cat, Map<String, Object> t) {
        String k = G.kind(t);
        List<Object> out = new ArrayList<>();
        if (k.equals("verb")) out.add(t.get("verb"));
        else if (k.equals("effect")) { for (Object v : list(ont.get("verbs"))) if (java.util.Objects.equals(G.get(v, "cls"), t.get("cls"))) out.add(G.get(v, "verb")); }
        else out = floatClassVerbs(cat, list(t.get("all_of")), list(t.get("none_of")));
        return out;
    }

    private static List<Object> expandProhibits(Map<String, Object> ont, Map<String, Object> cat, List<Object> ps, List<Object> report) {
        List<Object> out = new ArrayList<>();
        for (Object po : ps) {
            Map<String, Object> p = mm(po);
            Map<String, Object> target = mm(p.get("target"));
            List<Object> verbs = prohVerbs(ont, cat, target);
            List<Object> unconditional = new ArrayList<>();
            for (Object vo : verbs) {
                String v = (String) vo;
                Map<String, Object> c = resolveCond(ont, cat, v, mm(p.get("cond")));
                if (c == null) unconditional.add(v);
                out.add(G.map("pid", "verb".equals(G.kind(target)) ? p.get("pid") : G.jsStr(p.get("pid")) + "." + v, "target", G.map("k", "verb", "verb", v), "res", p.get("res"), "cond", c != null ? c : G.map("k", "true")));
            }
            if (report != null) report.add(G.map("pid", p.get("pid"), "verbs", verbs, "unconditional", unconditional));
        }
        return out;
    }

    private static List<Object> idsOf(List<EG> es, List<Object> srcs) { List<Object> r = new ArrayList<>(); for (EG e : es) if (srcs.contains(e.src)) r.add(e.g.get("gid")); return r; }

    private static List<Object> gidsOfVerbs(List<EG> es, List<Object> vs) { List<Object> r = new ArrayList<>(); for (EG e : es) if (vs.contains(e.g.get("verb"))) r.add(e.g.get("gid")); return r; }

    private static List<Object> verbsOfGids(List<EG> es, List<Object> gids) { List<Object> r = new ArrayList<>(); for (EG e : es) if (gids.contains(e.g.get("gid"))) r.add(e.g.get("verb")); return r; }

    /** The verbs a bound's role-addressed value must resolve for. */
    private static List<Object> boundRoleVerbs(Map<String, Object> ont, Map<String, Object> cat, List<EG> es, Map<String, Object> s) {
        String k = G.kind(s);
        if (k.equals("gids")) return verbsOfGids(es, idsOf(es, list(s.get("gids"))));
        if (k.equals("effect")) { List<Object> r = new ArrayList<>(); for (Object v : list(ont.get("verbs"))) if (java.util.Objects.equals(G.get(v, "cls"), s.get("cls"))) r.add(G.get(v, "verb")); return r; }
        if (k.equals("trait")) return verbsOfGids(es, gidsOfVerbs(es, floatClassVerbs(cat, list(s.get("all_of")), list(s.get("none_of")))));
        return new ArrayList<>();
    }

    /** One value term for the whole bound: the shared path when every verb agrees; the role key {@code @<role>} when the paths differ but the type is one. {term, how} or null. */
    private static Map<String, Object> boundValue(Map<String, Object> ont, Map<String, Object> cat, List<Object> vs, Map<String, Object> t) {
        switch (G.kind(t)) {
            case "param": return G.map("term", G.map("k", "param", "path", t.get("path"), "ty", t.get("ty")), "how", "literal");
            case "lit": return G.map("term", G.map("k", "lit", "v", t.get("v")), "how", "literal");
            case "hist": return G.map("term", G.map("k", "hist", "bid", t.get("bid"), "u", t.get("u")), "how", "literal");
            case "role": {
                List<Map<String, Object>> rs = new ArrayList<>();
                for (Object v : vs) { Map<String, Object> r = resolveRole(ont, cat, (String) v, G.jsStr(t.get("role"))); if (r == null) return null; rs.add(r); }
                if (rs.isEmpty()) return null;
                boolean samePath = true, sameTy = true;
                String ty0 = G.stringify(rs.get(0).get("ty"));
                for (Map<String, Object> r : rs) {
                    if (!java.util.Objects.equals(r.get("path"), rs.get(0).get("path"))) samePath = false;
                    if (!G.stringify(r.get("ty")).equals(ty0)) sameTy = false;
                }
                if (samePath && sameTy) return G.map("term", G.map("k", "param", "path", rs.get(0).get("path"), "ty", rs.get(0).get("ty")), "how", "shared_path");
                if (sameTy) return G.map("term", G.map("k", "param", "path", "@" + G.jsStr(t.get("role")), "ty", rs.get(0).get("ty")), "how", "role_key");
                return null;
            }
            default: return null;
        }
    }

    private static List<Object> expandBounds(Map<String, Object> ont, Map<String, Object> cat, List<EG> es, List<Object> bs, List<Object> report) {
        List<Object> out = new ArrayList<>();
        for (Object bo : bs) {
            Map<String, Object> b = mm(bo);
            Map<String, Object> sel = mm(b.get("sel"));
            Map<String, Object> bv = boundValue(ont, cat, boundRoleVerbs(ont, cat, es, sel), mm(b.get("value")));
            if (bv == null) continue; // a type error (selReasons), never reached when the goal is well typed
            String k = G.kind(sel);
            List<Object> gids = null;
            if (k.equals("gids")) gids = idsOf(es, list(sel.get("gids")));
            else if (k.equals("trait")) gids = gidsOfVerbs(es, floatClassVerbs(cat, list(sel.get("all_of")), list(sel.get("none_of"))));
            if (k.equals("effect")) {
                out.add(mkBound(b, bv, G.map("k", "effect", "cls", sel.get("cls"))));
                if (report != null) report.add(G.map("bid", b.get("bid"), "gids", new ArrayList<Object>(), "dropped", false, "value", bv.get("how")));
                continue;
            }
            if (gids == null || gids.isEmpty()) {
                if (gids == null) throw new IrError("unknown bound selector");
                if (report != null) report.add(G.map("bid", b.get("bid"), "gids", new ArrayList<Object>(), "dropped", true, "value", bv.get("how")));
                continue;
            }
            out.add(mkBound(b, bv, G.map("k", "gids", "gids", gids)));
            if (report != null) report.add(G.map("bid", b.get("bid"), "gids", gids, "dropped", false, "value", bv.get("how")));
        }
        return out;
    }

    private static Map<String, Object> mkBound(Map<String, Object> b, Map<String, Object> bv, Map<String, Object> sel) {
        return G.map("bid", b.get("bid"), "sel", sel, "agg", b.get("agg"), "value", bv.get("term"), "key", b.get("key"), "window", b.get("window"), "scope", b.get("scope"), "cap", b.get("cap"), "onExceed", b.get("onExceed"));
    }

    /** Lower a selector goal to an ordinary Goal against the PINNED catalog: {goal, report}. Pure and total; typing is {@link #selReasons} plus the core typechecker. */
    public static Map<String, Object> expandSelGoal(Map<String, Object> sg, Map<String, Object> ont, Map<String, Object> cat) {
        List<Object> gReport = new ArrayList<>(), pReport = new ArrayList<>(), bReport = new ArrayList<>();
        List<EG> es = expandGrants(ont, cat, list(sg.get("grants")), gReport);
        List<Object> prohibits = expandProhibits(ont, cat, list(sg.get("prohibits")), pReport);
        List<Object> bounds = expandBounds(ont, cat, es, list(sg.get("bounds")), bReport);
        List<Object> grants = new ArrayList<>();
        for (EG e : es) grants.add(e.g);
        Map<String, Object> deleg = new LinkedHashMap<>(mm(sg.get("deleg")));
        deleg.put("mayTouch", idsOf(es, list(deleg.get("mayTouch"))));
        List<Object> holes = new ArrayList<>();
        for (Object ho : list(sg.get("holes"))) { Map<String, Object> h = new LinkedHashMap<>(mm(ho)); h.put("affects", idsOf(es, list(h.get("affects")))); holes.add(h); }
        Map<String, Object> goal = G.map("v", G.num(1), "principal", sg.get("principal"), "ontDigest", sg.get("ontDigest"), "nlDigest", sg.get("nlDigest"), "sources", sg.get("sources"),
            "grants", grants, "prohibits", prohibits, "bounds", bounds, "validity", sg.get("validity"), "deleg", deleg, "escalateOn", sg.get("escalateOn"),
            "wildcardAck", idsOf(es, list(sg.get("wildcardAck"))), "holes", holes);
        return G.map("goal", goal, "report", G.map("grants", gReport, "prohibits", pReport, "bounds", bReport));
    }

    // ---------------- typing of the selector layer ----------------

    private static boolean allKnown(List<Object> known, List<Object> ids) {
        for (Object i : ids) if (!(i instanceof String) || ((String) i).isEmpty() || !known.contains(i)) return false;
        return true;
    }

    private static boolean grantSelOk(Map<String, Object> cat, Map<String, Object> g) {
        Map<String, Object> s = mm(g.get("sel"));
        return "verb".equals(G.kind(s)) || (!list(s.get("all_of")).isEmpty() && list(s.get("none_of")).isEmpty() && allKnown(list(cat.get("known")), list(s.get("all_of"))));
    }

    private static boolean prohSelOk(Map<String, Object> cat, Map<String, Object> p) {
        Map<String, Object> t = mm(p.get("target"));
        return !"trait".equals(G.kind(t)) || (allKnown(list(cat.get("known")), list(t.get("all_of"))) && allKnown(list(cat.get("known")), list(t.get("none_of"))));
    }

    private static boolean boundSelOk(Map<String, Object> cat, List<Object> gs, Map<String, Object> b) {
        Map<String, Object> s = mm(b.get("sel"));
        String k = G.kind(s);
        if (k.equals("gids")) { for (Object i : list(s.get("gids"))) { boolean found = false; for (Object g : gs) if (java.util.Objects.equals(G.get(g, "gid"), i)) found = true; if (!found) return false; } return true; }
        if (k.equals("effect")) return true;
        return allKnown(list(cat.get("known")), list(s.get("all_of"))) && allKnown(list(cat.get("known")), list(s.get("none_of")));
    }

    /**
     * The type reasons of the selector layer, in the order of the formal model, preceded by the checks about the wire rather than the
     * semantics: the pin ({@code catalog_digest_mismatch}) and the id grammar ({@code bad_id}). An empty list is well typed at this layer.
     */
    public static List<Object> selReasons(Map<String, Object> sg, Map<String, Object> ont, Map<String, Object> cat) {
        List<Object> out = new ArrayList<>();
        if (!java.util.Objects.equals(sg.get("catDigest"), selCatalogDigest(cat))) out.add("catalog_digest_mismatch");
        List<Object> ids = new ArrayList<>();
        for (Object g : list(sg.get("grants"))) ids.add(G.get(g, "gid"));
        for (Object p : list(sg.get("prohibits"))) ids.add(G.get(p, "pid"));
        for (Object b : list(sg.get("bounds"))) ids.add(G.get(b, "bid"));
        boolean idsOk = true;
        for (Object i : ids) if (!(i instanceof String) || !SEL_ID_RE.matcher((String) i).matches()) idsOk = false;
        if (!idsOk) out.add("bad_id");
        boolean catOk = true;
        for (Object v : list(cat.get("verbs"))) if (declOf(ont, G.get(v, "verb")) == null) catOk = false;
        if (!catOk) out.add("catalog_mismatch");
        boolean g1 = true, p1 = true, b1 = true;
        for (Object g : list(sg.get("grants"))) if (!grantSelOk(cat, mm(g))) g1 = false;
        if (!g1) out.add("bad_grant_selector");
        for (Object p : list(sg.get("prohibits"))) if (!prohSelOk(cat, mm(p))) p1 = false;
        if (!p1) out.add("bad_prohibit_selector");
        for (Object b : list(sg.get("bounds"))) if (!boundSelOk(cat, list(sg.get("grants")), mm(b))) b1 = false;
        if (!b1) out.add("bad_bound_selector");
        List<EG> es = expandGrants(ont, cat, list(sg.get("grants")), null);
        boolean rb = true;
        for (Object b : list(sg.get("bounds"))) if (boundValue(ont, cat, boundRoleVerbs(ont, cat, es, mm(mm(b).get("sel"))), mm(mm(b).get("value"))) == null) rb = false;
        if (!rb) out.add("unresolved_role_bound");
        return out;
    }

    /**
     * CompileX: selector reasons first (fail closed), then expansion and the core compiler. {@code compileGoal} is the injected proved
     * compiler (goal, ontology) -&gt; {ok: true, policy} | {ok: false, reasons}; it is not carried natively. Returns {ok, policy, goal, report} or {ok: false, reasons}.
     */
    public static Map<String, Object> compileSelGoal(Map<String, Object> sg, Map<String, Object> ont, Map<String, Object> cat, BiFunction<Map<String, Object>, Map<String, Object>, Map<String, Object>> compileGoal) {
        List<Object> rs = selReasons(sg, ont, cat);
        if (!rs.isEmpty()) return G.map("ok", false, "reasons", rs);
        Map<String, Object> ex = expandSelGoal(sg, ont, cat);
        Map<String, Object> goal = mm(ex.get("goal"));
        Map<String, Object> c = compileGoal.apply(goal, ont);
        return Boolean.TRUE.equals(c.get("ok")) ? G.map("ok", true, "policy", c.get("policy"), "goal", goal, "report", ex.get("report")) : G.map("ok", false, "reasons", c.get("reasons"));
    }

    // ---------------- acts ----------------

    /**
     * Add the role keys a role-addressed bound may read: for every role the act's verb carries on exactly one parameter that the act
     * supplies, {@code @<role>} is that parameter's value. Any {@code @} key the caller sent is removed first.
     */
    public static Map<String, Object> withRoleParams(Map<String, Object> act, Map<String, Object> cat) {
        Map<String, Object> params = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : mm(act.get("params")).entrySet()) if (!e.getKey().startsWith("@")) params.put(e.getKey(), e.getValue());
        Map<String, Object> info = infoOf(cat, act.get("verb"));
        if (info != null) {
            for (Map.Entry<String, Object> e : mm(info.get("roles")).entrySet()) {
                List<Object> paths = list(e.getValue());
                if (paths.size() == 1 && params.containsKey(G.jsStr(paths.get(0)))) params.put("@" + e.getKey(), params.get(G.jsStr(paths.get(0))));
            }
        }
        Map<String, Object> r = new LinkedHashMap<>(act);
        r.put("params", params);
        return r;
    }

    // ---------------- the policy card ----------------

    private static String phrase(Actions.Registry reg, Object id) {
        Actions.Trait t = id instanceof String ? reg.traits.get(id) : null;
        return t != null && t.cardPhrase != null ? t.cardPhrase : G.jsStr(id);
    }

    private static String selectorText(List<Object> all, List<Object> none, Actions.Registry reg) {
        List<String> ap = new ArrayList<>();
        for (Object x : all) ap.add(phrase(reg, x));
        String a = !all.isEmpty() ? "every action that " + String.join(" and ", ap) : "every action";
        if (none.isEmpty()) return a;
        List<String> np = new ArrayList<>();
        for (Object x : none) np.add(phrase(reg, x));
        return a + ", except those that " + String.join(" or ", np);
    }

    private static String qs(Object s) { return G.q(G.jsStr(s)); }

    private static String qlist(List<Object> xs) { List<String> o = new ArrayList<>(); for (Object x : xs) o.add(qs(x)); return String.join(", ", o); }

    /** The card of a selector goal: one line per selector clause in the words of the trait phrases, then the card of the expansion. {@code reg} null: the core registry. {lines, warnings}. */
    public static Map<String, Object> renderSelCard(Map<String, Object> sg, Map<String, Object> ont, Map<String, Object> cat, Actions.Registry reg) {
        Actions.Registry rg = reg != null ? reg : Actions.CORE_REGISTRY;
        Map<String, Object> ex = expandSelGoal(sg, ont, cat);
        Map<String, Object> report = mm(ex.get("report"));
        List<Object> lines = new ArrayList<>(), warnings = new ArrayList<>();
        List<Object> grants = list(sg.get("grants"));
        for (int i = 0; i < grants.size(); i++) {
            Map<String, Object> g = mm(grants.get(i));
            Map<String, Object> r = mm(list(report.get("grants")).get(i));
            Map<String, Object> sel = mm(g.get("sel"));
            List<Object> verbs = list(r.get("verbs"));
            if ("class".equals(G.kind(sel))) lines.add("ALLOW " + qs(g.get("gid")) + ": " + selectorText(list(sel.get("all_of")), new ArrayList<>(), rg) + " [" + verbs.size() + " verb(s) in the pinned catalog: " + qlist(verbs) + "]");
            for (Object d : list(r.get("dropped"))) warnings.add("grant " + qs(g.get("gid")) + " does not cover " + qs(G.get(d, "verb")) + ": it has no unique parameter for a role the condition names");
        }
        List<Object> prohibits = list(sg.get("prohibits"));
        for (int i = 0; i < prohibits.size(); i++) {
            Map<String, Object> p = mm(prohibits.get(i));
            Map<String, Object> r = mm(list(report.get("prohibits")).get(i));
            Map<String, Object> t = mm(p.get("target"));
            List<Object> verbs = list(r.get("verbs"));
            if ("trait".equals(G.kind(t))) lines.add("NEVER " + qs(p.get("pid")) + ": " + selectorText(list(t.get("all_of")), list(t.get("none_of")), rg) + ", today " + verbs.size() + " verb(s) [" + qlist(verbs) + "]; it also covers every verb added to the catalog later");
            for (Object v : list(r.get("unconditional"))) warnings.add("prohibition " + qs(p.get("pid")) + " applies to " + qs(v) + " without its condition: the verb has no unique parameter for a role the condition names");
        }
        List<Object> bounds = list(sg.get("bounds"));
        List<Object> breports = list(report.get("bounds"));
        for (int i = 0; i < bounds.size(); i++) {
            Map<String, Object> b = mm(bounds.get(i));
            Map<String, Object> r = i < breports.size() ? mm(breports.get(i)) : null;
            Map<String, Object> sel = mm(b.get("sel"));
            if ("trait".equals(G.kind(sel)) && r != null) lines.add("LIMIT " + qs(b.get("bid")) + ": over " + selectorText(list(sel.get("all_of")), list(sel.get("none_of")), rg) + " (" + list(r.get("gids")).size() + " grant(s))");
            if (r != null && Boolean.TRUE.equals(r.get("dropped"))) warnings.add("limit " + qs(b.get("bid")) + " selects no grant and bounds nothing");
            if (r != null && "role_key".equals(r.get("value"))) warnings.add("limit " + qs(b.get("bid")) + " sums a role the verbs carry on different parameters: the action must supply the role key");
        }
        Map<String, Object> core = GoalCard.renderCard(mm(ex.get("goal")));
        List<Object> l2 = new ArrayList<>(lines); l2.addAll(list(core.get("lines")));
        List<Object> w2 = new ArrayList<>(warnings); w2.addAll(list(core.get("warnings")));
        return G.map("lines", l2, "warnings", w2);
    }

    /** The closure of a trait id list under the registry (a selector written with a parent trait covers the children by {@code implies}). {@code reg} null: core. */
    public static List<String> traitClosure(List<Object> ids, Actions.Registry reg) { return Actions.closure(reg != null ? reg : Actions.CORE_REGISTRY, ids); }

    // ---------------- the carrier form (the differential with the extracted model) ----------------

    private static final String ROLE_MARK = "\u0001role:";

    private static Map<String, Object> carryTerm(Map<String, Object> t) {
        switch (G.kind(t)) {
            case "role": return G.map("k", "param", "path", ROLE_MARK + G.jsStr(t.get("role")), "ty", G.map("k", "s"));
            case "param": return G.map("k", "param", "path", t.get("path"), "ty", t.get("ty"));
            case "lit": return G.map("k", "lit", "v", t.get("v"));
            default: return G.map("k", "hist", "bid", t.get("bid"), "u", t.get("u"));
        }
    }

    private static Map<String, Object> carryCond(Map<String, Object> c) {
        String k = G.kind(c);
        switch (k) {
            case "true": return G.map("k", "true");
            case "cmp": return G.map("k", "cmp", "op", c.get("op"), "l", carryTerm(mm(c.get("l"))), "r", carryTerm(mm(c.get("r"))));
            case "and": case "or": return G.map("k", k, "a", carryCond(mm(c.get("a"))), "b", carryCond(mm(c.get("b"))));
            case "not": return G.map("k", "not", "c", carryCond(mm(c.get("c"))));
            default: throw new IrError("unknown condition");
        }
    }

    private static String join(List<Object> xs, String sep) { List<String> o = new ArrayList<>(); for (Object x : xs) o.add(x == null ? "" : G.jsStr(x)); return String.join(sep, o); }

    private static String sel2(List<Object> all, List<Object> none) { return join(all, "\u0002") + "\u0001" + join(none, "\u0002"); }

    /** An ordinary Goal carrying a selector goal (selectors ride in strings and role-marked params), so the extracted model decodes it with its existing Goal decoder. */
    public static Map<String, Object> selCarrier(Map<String, Object> sg) {
        List<Object> grants = new ArrayList<>();
        for (Object go : list(sg.get("grants"))) {
            Map<String, Object> g = mm(go);
            Map<String, Object> s = mm(g.get("sel"));
            String verb = "verb".equals(G.kind(s)) ? "V\u0001" + G.jsStr(s.get("verb")) : "C\u0001" + sel2(list(s.get("all_of")), list(s.get("none_of")));
            grants.add(G.map("gid", g.get("gid"), "verb", verb, "res", g.get("res"), "cond", carryCond(mm(g.get("cond")))));
        }
        List<Object> prohibits = new ArrayList<>();
        for (Object po : list(sg.get("prohibits"))) {
            Map<String, Object> p = mm(po);
            Map<String, Object> t = mm(p.get("target"));
            String k = G.kind(t);
            String verb = k.equals("verb") ? "V\u0001" + G.jsStr(t.get("verb")) : k.equals("effect") ? "E\u0001" + G.jsStr(t.get("cls")) : "T\u0001" + sel2(list(t.get("all_of")), list(t.get("none_of")));
            prohibits.add(G.map("pid", p.get("pid"), "res", p.get("res"), "cond", carryCond(mm(p.get("cond"))), "target", G.map("k", "verb", "verb", verb)));
        }
        List<Object> bounds = new ArrayList<>();
        for (Object bo : list(sg.get("bounds"))) {
            Map<String, Object> b = mm(bo);
            Map<String, Object> s = mm(b.get("sel"));
            String k = G.kind(s);
            Map<String, Object> sel = k.equals("gids") ? G.map("k", "gids", "gids", s.get("gids")) : k.equals("effect") ? G.map("k", "effect", "cls", s.get("cls"))
                : G.map("k", "effect", "cls", "T\u0001" + sel2(list(s.get("all_of")), list(s.get("none_of"))));
            bounds.add(G.map("bid", b.get("bid"), "key", b.get("key"), "window", b.get("window"), "scope", b.get("scope"), "cap", b.get("cap"), "onExceed", b.get("onExceed"), "agg", b.get("agg"),
                "value", carryTerm(mm(b.get("value"))), "sel", sel));
        }
        return G.map("v", G.num(1), "principal", sg.get("principal"), "ontDigest", sg.get("ontDigest"), "nlDigest", sg.get("nlDigest"), "sources", sg.get("sources"),
            "grants", grants, "prohibits", prohibits, "bounds", bounds, "validity", sg.get("validity"), "deleg", sg.get("deleg"), "escalateOn", sg.get("escalateOn"), "wildcardAck", sg.get("wildcardAck"), "holes", sg.get("holes"));
    }

    private static List<Object> tok(String t, Object v) { List<Object> x = new ArrayList<>(2); x.add(t); x.add(v); return x; }

    private static void strs(List<Object> out, List<Object> xs) {
        out.add(tok("i", G.num(xs.size())));
        for (Object x : xs) out.add(tok("s", x));
    }

    /** The catalog tape {@code DecCatalog} reads: known trait ids, then per verb: verb, traits, number of roles, (role, paths)*. */
    public static List<Object> encodeSelCatalog(Map<String, Object> c) {
        List<Object> out = new ArrayList<>();
        strs(out, list(c.get("known")));
        List<Object> verbs = list(c.get("verbs"));
        out.add(tok("i", G.num(verbs.size())));
        for (Object vo : verbs) {
            Map<String, Object> v = mm(vo);
            out.add(tok("s", v.get("verb")));
            strs(out, list(v.get("traits")));
            Map<String, Object> roles = mm(v.get("roles"));
            out.add(tok("i", G.num(roles.size())));
            for (Map.Entry<String, Object> e : roles.entrySet()) { out.add(tok("s", e.getKey())); strs(out, list(e.getValue())); }
        }
        return out;
    }
}
