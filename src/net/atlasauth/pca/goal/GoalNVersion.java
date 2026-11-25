package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * N-version interpretation: the enforced policy is the semantic meet of the readings. Allow(meet gs) a implies Allow(g) a for
 * every g in gs. Grants are the cross product of the readings' grants on equal verbs (a merged grant is named {@code x&y&z}),
 * resources intersect through {@code all_of}, conditions conjoin; a bound counts the admitted actions of the merged grants
 * derived from the grants it selected, so the merged goal never admits more than any reading.
 */
public final class GoalNVersion {
    private GoalNVersion() {}

    private static Map<String, Object> mm(Object o) { return G.m(o); }

    private static List<Map<String, Object>> partsOf(Map<String, Object> s) {
        List<Map<String, Object>> out = new ArrayList<>();
        String k = G.kind(s);
        if (k.equals("all_of")) { for (Object p : G.arr(s.get("parts"), "parts")) out.add(mm(p)); }
        else if (!k.equals("any")) out.add(s);
        return out;
    }

    private static Map<String, Object> intersect(Map<String, Object> a, Map<String, Object> b) {
        if (G.kind(a).equals("any")) return b;
        if (G.kind(b).equals("any")) return a;
        Map<String, Map<String, Object>> uniq = new LinkedHashMap<>();
        for (Map<String, Object> p : partsOf(a)) uniq.put(G.stable(p), p);
        for (Map<String, Object> p : partsOf(b)) uniq.put(G.stable(p), p);
        if (uniq.size() == 1) return uniq.values().iterator().next();
        return G.map("k", "all_of", "parts", new ArrayList<Object>(uniq.values()));
    }

    private static Map<String, Object> conj(Map<String, Object> a, Map<String, Object> b) {
        if (G.kind(a).equals("true")) return b;
        if (G.kind(b).equals("true")) return a;
        return G.map("k", "and", "a", a, "b", b);
    }

    /** A merged grant and, per reading, the gid of the grant it was derived from. */
    private static final class Tracked {
        final Map<String, Object> g;
        final List<String> from;
        Tracked(Map<String, Object> g, List<String> from) { this.g = g; this.from = from; }
    }

    private static List<Tracked> cross(List<Tracked> a, List<Tracked> b) {
        List<Tracked> out = new ArrayList<>();
        for (Tracked x : a) for (Tracked y : b) {
            if (!java.util.Objects.equals(x.g.get("verb"), y.g.get("verb"))) continue;
            Map<String, Object> g = G.map("gid", x.g.get("gid") + "&" + y.g.get("gid"), "verb", x.g.get("verb"),
                "res", intersect(mm(x.g.get("res")), mm(y.g.get("res"))), "cond", conj(mm(x.g.get("cond")), mm(y.g.get("cond"))));
            List<String> from = new ArrayList<>(x.from);
            from.addAll(y.from);
            out.add(new Tracked(g, from));
        }
        return out;
    }

    private static List<Tracked> track(List<Object> grants) {
        List<Tracked> out = new ArrayList<>();
        for (Object g : grants) out.add(new Tracked(mm(g), new ArrayList<>(List.of((String) G.get(g, "gid")))));
        return out;
    }

    /** Meet of grants: cross product on equal verbs, resource intersection, conjoined conditions. */
    public static List<Object> meetGrants(List<Object> a, List<Object> b) {
        List<Object> out = new ArrayList<>();
        for (Tracked t : cross(track(a), track(b))) out.add(t.g);
        return out;
    }

    private static List<Object> derived(List<Tracked> tracked, int i, List<Object> gids) {
        List<Object> out = new ArrayList<>();
        for (Tracked t : tracked) if (gids.contains(t.from.get(i))) out.add(t.g.get("gid"));
        return out;
    }

    private static List<Object> sortedStrings(List<Object> xs) {
        List<Object> s = new ArrayList<>(xs);
        s.sort((a, b) -> ((String) a).compareTo((String) b));
        return s;
    }

    private static double num(Object o) { return G.toNum(o); }

    private static Object numOut(double d) {
        if (d == Math.rint(d) && Math.abs(d) <= G.MAX_SAFE) return G.num((long) d);
        throw new IrError("non-integer result");
    }

    public static Map<String, Object> meet(List<Map<String, Object>> goals) {
        if (goals.isEmpty()) throw new IrError("meet: no goals");
        Map<String, Object> first = goals.get(0);
        for (Map<String, Object> g : goals) {
            if (!java.util.Objects.equals(g.get("principal"), first.get("principal")) || !java.util.Objects.equals(g.get("ontDigest"), first.get("ontDigest"))
                || !java.util.Objects.equals(g.get("nlDigest"), first.get("nlDigest"))) throw new IrError("meet: readings must share principal, ontology and text");
        }
        if (goals.size() == 1) return first;
        List<Tracked> tracked = track(G.arr(first.get("grants"), "grants"));
        for (Map<String, Object> g : goals.subList(1, goals.size())) tracked = cross(tracked, track(G.arr(g.get("grants"), "grants")));
        List<Object> grants = new ArrayList<>();
        for (Tracked t : tracked) grants.add(t.g);

        List<Object> prohibits = new ArrayList<>();
        Map<String, Object> pseen = new LinkedHashMap<>();
        for (int i = 0; i < goals.size(); i++) {
            for (Object po : G.arr(goals.get(i).get("prohibits"), "prohibits")) {
                Map<String, Object> p = mm(po);
                Map<String, Object> bodyMap = new LinkedHashMap<>(p);
                bodyMap.put("pid", "");
                String body = G.stable(bodyMap);
                if (pseen.containsKey(body)) continue;
                boolean taken = pseen.containsValue(p.get("pid"));
                pseen.put(body, p.get("pid"));
                if (taken) { Map<String, Object> np = new LinkedHashMap<>(p); np.put("pid", p.get("pid") + "#" + i); prohibits.add(np); } else prohibits.add(p);
            }
        }

        List<Object> bounds = new ArrayList<>();
        Map<String, Map<String, Object>> bseen = new LinkedHashMap<>();
        for (int i = 0; i < goals.size(); i++) {
            for (Object bo : G.arr(goals.get(i).get("bounds"), "bounds")) {
                Map<String, Object> b = mm(bo), bsel = mm(b.get("sel"));
                Map<String, Object> sel = bsel;
                if (G.kind(bsel).equals("gids")) sel = G.map("k", "gids", "gids", sortedStrings(derived(tracked, i, G.arr(bsel.get("gids"), "gids"))));
                if (G.kind(sel).equals("gids") && G.arr(sel.get("gids"), "gids").isEmpty()) continue;
                String key = G.stable(G.map("sel", sel, "agg", b.get("agg"), "value", b.get("value"), "key", b.get("key"), "window", b.get("window"), "scope", b.get("scope"), "unit", mm(b.get("cap")).get("u")));
                Map<String, Object> prev = bseen.get(key);
                if (prev != null) {
                    if (num(mm(b.get("cap")).get("n")) < num(mm(prev.get("cap")).get("n"))) prev.put("cap", b.get("cap"));
                    if ("deny".equals(b.get("onExceed"))) prev.put("onExceed", "deny");
                    continue;
                }
                Map<String, Object> nb = new LinkedHashMap<>(b);
                nb.put("sel", sel);
                boolean dup = false;
                for (Object x : bounds) if (java.util.Objects.equals(G.get(x, "bid"), b.get("bid"))) dup = true;
                nb.put("bid", dup ? b.get("bid") + "#" + i : b.get("bid"));
                bounds.add(nb);
                bseen.put(key, nb);
            }
        }

        Map<String, Object> escSeen = new LinkedHashMap<>();
        for (Map<String, Object> g : goals) for (Object c : G.arr(g.get("escalateOn"), "escalateOn")) escSeen.put(G.stable(c), c);

        List<Double> idle = new ArrayList<>();
        for (Map<String, Object> g : goals) { double x = num(mm(g.get("validity")).get("maxIdle")); if (x > 0) idle.add(x); }
        List<Object> touch = new ArrayList<>();
        for (Tracked t : tracked) {
            boolean all = true;
            for (int i = 0; i < goals.size(); i++) if (!G.arr(mm(goals.get(i).get("deleg")).get("mayTouch"), "mayTouch").contains(t.from.get(i))) { all = false; break; }
            if (all) touch.add(t.g.get("gid"));
        }
        List<Object> ack = new ArrayList<>();
        for (Tracked t : tracked) {
            if (!G.kind(t.g.get("res")).equals("any")) continue;
            boolean all = true;
            for (int i = 0; i < goals.size(); i++) {
                Map<String, Object> src = null;
                for (Object x : G.arr(goals.get(i).get("grants"), "grants")) if (t.from.get(i).equals(G.get(x, "gid"))) { src = mm(x); break; }
                boolean notAny = src == null || !G.kind(src.get("res")).equals("any");
                if (!(notAny || G.arr(goals.get(i).get("wildcardAck"), "wildcardAck").contains(t.from.get(i)))) { all = false; break; }
            }
            if (all) ack.add(t.g.get("gid"));
        }
        Map<String, Map<String, Object>> holes = new LinkedHashMap<>();
        for (int i = 0; i < goals.size(); i++) {
            for (Object ho : G.arr(goals.get(i).get("holes"), "holes")) {
                Map<String, Object> h = mm(ho);
                Map<String, Object> prev = holes.get(h.get("hid"));
                Set<String> aff = new LinkedHashSet<>();
                if (prev != null) for (Object a : G.arr(prev.get("affects"), "affects")) aff.add((String) a);
                for (Object a : derived(tracked, i, G.arr(h.get("affects"), "affects"))) aff.add((String) a);
                List<Object> affects = sortedStrings(new ArrayList<Object>(aff));
                Map<String, Object> nh = new LinkedHashMap<>(h);
                nh.put("affects", affects);
                nh.put("global", G.truthy(h.get("global")) ? h.get("global") : prev != null && prev.get("global") != null ? prev.get("global") : (Object) Boolean.FALSE);
                holes.put((String) h.get("hid"), nh);
            }
        }
        Set<String> sources = new LinkedHashSet<>();
        for (Map<String, Object> g : goals) for (Object s : G.arr(g.get("sources"), "sources")) sources.add((String) s);
        double nb = Double.NEGATIVE_INFINITY, na = Double.POSITIVE_INFINITY, md = Double.POSITIVE_INFINITY;
        for (Map<String, Object> g : goals) {
            Map<String, Object> v = mm(g.get("validity"));
            nb = Math.max(nb, num(v.get("notBefore")));
            na = Math.min(na, num(v.get("notAfter")));
            md = Math.min(md, num(mm(g.get("deleg")).get("maxDepth")));
        }
        double mi = 0;
        if (!idle.isEmpty()) { mi = Double.POSITIVE_INFINITY; for (double x : idle) mi = Math.min(mi, x); }
        Map<String, Object> out = new LinkedHashMap<>(first);
        out.put("grants", grants);
        out.put("prohibits", prohibits);
        out.put("bounds", bounds);
        out.put("escalateOn", new ArrayList<Object>(escSeen.values()));
        out.put("sources", new ArrayList<Object>(sources));
        out.put("validity", G.map("notBefore", numOut(nb), "notAfter", numOut(na), "maxIdle", numOut(mi)));
        out.put("deleg", G.map("maxDepth", numOut(md), "narrowOnly", true, "mayTouch", touch));
        out.put("holes", new ArrayList<Object>(holes.values()));
        out.put("wildcardAck", ack);
        return GoalNormalize.canonicalizeGoal(out);
    }

    /** Panel requirements: at least 3 interpreters, one deterministic non-LLM interpreter, two distinct model families. Issues {code, msg}. */
    public static List<Object> checkPanel(List<Map<String, Object>> readings) {
        List<Object> out = new ArrayList<>();
        if (readings.size() < 3) out.add(G.map("code", "too_few", "msg", "need at least 3 interpreters"));
        boolean det = false;
        Set<Object> fams = new LinkedHashSet<>();
        for (Map<String, Object> r : readings) { if (G.truthy(r.get("deterministic"))) det = true; else fams.add(r.get("family") == null ? "\u0000undefined" : r.get("family")); }
        if (!det) out.add(G.map("code", "no_deterministic", "msg", "need at least one deterministic template interpreter"));
        if (fams.size() < 2) out.add(G.map("code", "no_family_diversity", "msg", "need at least two distinct model families"));
        return out;
    }

    /** {merged, panelIssues, disagreementHoles, mass, signable}. */
    public static Map<String, Object> nVersion(List<Map<String, Object>> readings, GoalDisambiguate.Opts opts, Double massThreshold) {
        List<Map<String, Object>> goals = new ArrayList<>();
        for (Map<String, Object> r : readings) goals.add(mm(r.get("goal")));
        Map<String, Object> merged = meet(goals);
        List<Object> panelIssues = checkPanel(readings);
        List<Set<String>> verbSets = new ArrayList<>();
        TreeSet<String> allVerbs = new TreeSet<>();
        for (Map<String, Object> g : goals) {
            Set<String> s = new LinkedHashSet<>();
            for (Object gr : G.arr(g.get("grants"), "grants")) s.add((String) G.get(gr, "verb"));
            verbSets.add(s);
            allVerbs.addAll(s);
        }
        List<Object> holes = new ArrayList<>();
        for (String v : allVerbs) {
            boolean some = false;
            for (Set<String> s : verbSets) if (!s.contains(v)) some = true;
            if (some) holes.add(G.map("hid", "nv:verb:" + v, "q", "Only some readings allow \"" + v + "\". Should it be allowed at all?", "domain", new ArrayList<Object>(), "affects", new ArrayList<Object>(), "global", false));
        }
        double mass = GoalDisambiguate.disagreementMass(readings, opts.ont);
        if (mass > (massThreshold == null ? 0 : massThreshold)) {
            List<Map<String, Object>> qs = GoalDisambiguate.questions(readings, opts);
            holes.add(G.map("hid", "nv:split", "q", qs.isEmpty() ? "The readings disagree." : qs.get(0).get("text"), "domain", new ArrayList<Object>(), "affects", new ArrayList<Object>(), "global", true));
        }
        List<Object> all = new ArrayList<>(G.arr(merged.get("holes"), "holes"));
        all.addAll(holes);
        Map<String, Object> byHid = new LinkedHashMap<>();
        for (Object h : all) byHid.put((String) G.get(h, "hid"), h);
        Map<String, Object> m2 = new LinkedHashMap<>(merged);
        m2.put("holes", new ArrayList<Object>(byHid.values()));
        return G.map("merged", GoalNormalize.canonicalizeGoal(m2), "panelIssues", panelIssues, "disagreementHoles", holes, "mass", mass, "signable", panelIssues.isEmpty() && all.isEmpty());
    }
}
