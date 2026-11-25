package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import net.atlasauth.pca.Pca;

/**
 * Boundary examples and signed goal tests over the IR and its reference semantics. An action is classified per coordinate
 * (verb, resource, relation bits, each parameter) against the literals of the policies; {@link #cells} enumerates one
 * representative per decision cell. Goals, acts and histories are parsed-JSON maps.
 */
public final class GoalExamples {
    private GoalExamples() {}

    /** The classification space of one or more goals. */
    public static final class Space {
        public List<String> verbs = new ArrayList<>();
        public List<String> resources = new ArrayList<>();
        /** {rel, anchor} pairs. */
        public List<String[]> rels = new ArrayList<>();
        /** param -> (unit key -> sorted distinct values), insertion ordered. */
        public Map<String, Map<String, List<Long>>> q = new LinkedHashMap<>();
        /** param -> sorted distinct discrete keys ("s:" + text). */
        public Map<String, List<String>> d = new LinkedHashMap<>();

        public Map<String, Object> toJson() {
            List<Object> rs = new ArrayList<>();
            for (String[] r : rels) rs.add(G.map("rel", r[0], "anchor", r[1]));
            Map<String, Object> qj = new LinkedHashMap<>();
            for (Map.Entry<String, Map<String, List<Long>>> e : q.entrySet()) {
                Map<String, Object> inner = new LinkedHashMap<>();
                for (Map.Entry<String, List<Long>> g : e.getValue().entrySet()) { List<Object> ns = new ArrayList<>(); for (Long v : g.getValue()) ns.add(G.num(v)); inner.put(g.getKey(), ns); }
                qj.put(e.getKey(), inner);
            }
            Map<String, Object> dj = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> e : d.entrySet()) dj.put(e.getKey(), new ArrayList<Object>(e.getValue()));
            return G.map("verbs", new ArrayList<Object>(verbs), "resources", new ArrayList<Object>(resources), "rels", rs, "q", qj, "d", dj);
        }
    }

    private static Map<String, Object> emptyHist() { return G.map("adms", new ArrayList<Object>(), "last", G.num(-1), "aggs", new LinkedHashMap<String, Object>()); }

    public static String decisionOf(int d) { return d == 2 ? "allow" : d == 1 ? "escalate" : "deny"; }

    public static int rankOf(String d) { return "allow".equals(d) ? 0 : "escalate".equals(d) ? 1 : 2; }

    /** An action with the fixed envelope the examples use (one session, one principal, no delegation, time 0). */
    public static Map<String, Object> mkAct(String verb, String res, Map<String, Object> params) {
        return G.map("verb", verb, "res", res, "params", params, "t", G.num(0), "sess", "s", "prin", "p", "org", "o", "agent", "a", "depth", G.num(0));
    }

    private static Map<String, Object> mm(Object o) { return G.m(o); }

    /** The reference decision of a goal for an action, its history and its relation facts: {decision, witness, prohibited}. */
    public static Map<String, Object> decideCase(Map<String, Object> g, Map<String, Object> ont, Map<String, Object> c) {
        Object rels = c.get("rels");
        Map<String, Object> o = ont;
        if (rels != null) { o = new LinkedHashMap<>(ont); o.put("rels", rels); }
        Object hist = c.get("hist");
        Map<String, Object> x = GoalRefsem.refExplain(g, o, mm(c.get("act")), hist == null ? emptyHist() : mm(hist));
        int d = Integer.parseInt(((net.atlasauth.pca.Json.Num) x.get("d")).raw);
        int p = Integer.parseInt(((net.atlasauth.pca.Json.Num) x.get("prohibit")).raw);
        return G.map("decision", decisionOf(d), "witness", x.get("witness"), "prohibited", p < 2);
    }

    /** The history of the admitted prefix of {@code acts}: an action the goal refuses is not recorded. */
    public static Map<String, Object> replay(Map<String, Object> g, Map<String, Object> ont, List<Object> acts, List<Object> rels) {
        Map<String, Object> h = emptyHist();
        List<Object> adms = G.l(h.get("adms"));
        for (Object a : acts) {
            Map<String, Object> c = G.map("act", a, "hist", h, "rels", rels);
            Map<String, Object> v = decideCase(g, ont, c);
            if ("allow".equals(v.get("decision")) && v.get("witness") != null) {
                adms.add(G.map("gid", v.get("witness"), "act", a));
                h.put("last", G.get(a, "t"));
            }
        }
        return h;
    }

    // ---- space ----
    private static long qval(Map<String, Object> q) {
        Long n = G.safeInt(q.get("n"));
        if (n == null) throw new IrError("quantity is not a safe integer");
        return n;
    }

    private static String qkey(Map<String, Object> q) {
        Map<String, Object> u = mm(q.get("u"));
        return G.kind(u).equals("money") ? "money:" + u.get("ccy") : G.kind(u);
    }

    private static Map<String, Object> unitOfKey(String key) {
        return key.startsWith("money:") ? G.map("k", "money", "ccy", key.substring(6)) : G.map("k", key);
    }

    private static String dkey(Map<String, Object> v) { return G.kind(v).equals("s") ? "s:" + v.get("s") : null; }

    private interface LitFn { void f(String p, Map<String, Object> v); }

    private static void walkCond(Map<String, Object> c, LitFn f) {
        String k = G.kind(c);
        if (k.equals("cmp")) {
            Map<String, Object> l = mm(c.get("l")), r = mm(c.get("r"));
            String p = G.kind(l).equals("param") ? (String) l.get("path") : G.kind(r).equals("param") ? (String) r.get("path") : null;
            Map<String, Object> other = G.kind(l).equals("param") ? r : l;
            if (p == null || !G.kind(other).equals("lit")) return;
            Map<String, Object> v = mm(other.get("v"));
            if (G.kind(v).equals("set")) { for (Object i : G.arr(v.get("items"), "items")) f.f(p, mm(i)); } else f.f(p, v);
        } else if (k.equals("and") || k.equals("or")) { walkCond(mm(c.get("a")), f); walkCond(mm(c.get("b")), f); }
        else if (k.equals("not")) walkCond(mm(c.get("c")), f);
    }

    private static List<Map<String, Object>> parts(Map<String, Object> s) {
        List<Map<String, Object>> out = new ArrayList<>();
        String k = G.kind(s);
        if (k.equals("all_of")) { for (Object p : G.arr(s.get("parts"), "parts")) out.add(mm(p)); }
        else if (!k.equals("any")) out.add(s);
        return out;
    }

    /** The space of the goals plus extra verbs. */
    public static Space buildSpace(List<Map<String, Object>> goals, List<String> extraVerbs) {
        Set<String> verbs = new LinkedHashSet<>(extraVerbs), resources = new LinkedHashSet<>();
        Map<String, String[]> rels = new LinkedHashMap<>();
        Map<String, Map<String, Set<Long>>> q = new LinkedHashMap<>();
        Map<String, Set<String>> d = new LinkedHashMap<>();
        LitFn lit = (p, v) -> {
            if (G.kind(v).equals("q")) {
                Map<String, Object> qq = mm(v.get("q"));
                Map<String, Set<Long>> m = q.computeIfAbsent(p, x -> new LinkedHashMap<>());
                m.computeIfAbsent(qkey(qq), x -> new LinkedHashSet<>()).add(qval(qq));
            } else {
                String k = dkey(v);
                if (k == null) return;
                d.computeIfAbsent(p, x -> new LinkedHashSet<>()).add(k);
            }
        };
        java.util.function.Consumer<Map<String, Object>> res = s -> {
            for (Map<String, Object> x : parts(s)) {
                String k = G.kind(x);
                if (k.equals("exact")) resources.add((String) x.get("id"));
                else if (k.equals("oneof")) { for (Object i : G.arr(x.get("ids"), "ids")) resources.add((String) i); }
                else rels.put(x.get("rel") + "\0" + x.get("anchor"), new String[] {(String) x.get("rel"), (String) x.get("anchor")});
            }
        };
        for (Map<String, Object> g : goals) {
            for (Object gro : G.arr(g.get("grants"), "grants")) { Map<String, Object> gr = mm(gro); verbs.add((String) gr.get("verb")); res.accept(mm(gr.get("res"))); walkCond(mm(gr.get("cond")), lit); }
            for (Object po : G.arr(g.get("prohibits"), "prohibits")) {
                Map<String, Object> p = mm(po), t = mm(p.get("target"));
                if (G.kind(t).equals("verb")) verbs.add((String) t.get("verb"));
                res.accept(mm(p.get("res")));
                walkCond(mm(p.get("cond")), lit);
            }
            for (Object c : G.arr(g.get("escalateOn"), "escalateOn")) walkCond(mm(c), lit);
            for (Object bo : G.arr(g.get("bounds"), "bounds")) {
                Map<String, Object> b = mm(bo), val = mm(b.get("value"));
                if ("sum".equals(b.get("agg")) && G.kind(val).equals("param")) lit.f((String) val.get("path"), G.map("k", "q", "q", b.get("cap")));
            }
        }
        Space sp = new Space();
        sp.verbs = sorted(verbs);
        sp.resources = sorted(resources);
        sp.rels = new ArrayList<>(rels.values());
        sp.rels.sort((a, b) -> (a[0] + a[1]).compareTo(b[0] + b[1]) < 0 ? -1 : 1);
        for (Map.Entry<String, Map<String, Set<Long>>> e : q.entrySet()) {
            Map<String, List<Long>> inner = new LinkedHashMap<>();
            for (Map.Entry<String, Set<Long>> g : e.getValue().entrySet()) { List<Long> ns = new ArrayList<>(g.getValue()); Collections.sort(ns); inner.put(g.getKey(), ns); }
            sp.q.put(e.getKey(), inner);
        }
        for (Map.Entry<String, Set<String>> e : d.entrySet()) sp.d.put(e.getKey(), sorted(e.getValue()));
        return sp;
    }

    private static List<String> sorted(Set<String> s) { List<String> l = new ArrayList<>(s); l.sort(String::compareTo); return l; }

    private static String classifyLit(Space sp, String p, Map<String, Object> l) {
        if (l == null || G.kind(l).equals("set")) return "missing";
        Map<String, List<Long>> groups = sp.q.get(p);
        List<String> ds = sp.d.get(p);
        if (G.kind(l).equals("q")) {
            Map<String, Object> qq = mm(l.get("q"));
            List<Long> g = groups == null ? null : groups.get(qkey(qq));
            if (g == null) return groups != null || ds != null ? "unit" : "any";
            long v = qval(qq);
            int i = g.indexOf(v);
            if (i >= 0) return qkey(qq) + "=" + i;
            int pos = 0;
            while (pos < g.size() && g.get(pos) < v) pos++;
            return qkey(qq) + "@" + pos;
        }
        String k = dkey(l);
        if (ds == null) return groups != null ? "unit" : "any";
        return k != null && ds.contains(k) ? k : "other";
    }

    private static int relBit(Map<String, Object> c, String rel, String anchor) {
        for (Object xo : G.arr(c.get("rels"), "rels")) {
            Map<String, Object> x = mm(xo);
            if (rel.equals(x.get("rel")) && anchor.equals(x.get("anchor"))) return G.arr(x.get("members"), "members").contains(mm(c.get("act")).get("res")) ? 1 : 0;
        }
        return 0;
    }

    /** The decision cell of a case under a space (canonical string; the unit of precedents). */
    public static String cellKey(Space sp, Map<String, Object> c) {
        Set<String> params = new LinkedHashSet<>(sp.q.keySet());
        params.addAll(sp.d.keySet());
        Map<String, Object> act = mm(c.get("act"));
        List<Object> l = new ArrayList<>();
        for (String[] r : sp.rels) l.add(G.num(relBit(c, r[0], r[1])));
        Map<String, Object> pm = new LinkedHashMap<>();
        Map<String, Object> actParams = mm(act.get("params"));
        for (String p : sorted(params)) pm.put(p, classifyLit(sp, p, actParams == null ? null : mm(actParams.get(p))));
        return G.stable(G.map("v", sp.verbs.contains(act.get("verb")) ? act.get("verb") : "*", "r", sp.resources.contains(act.get("res")) ? act.get("res") : "*", "l", l, "p", pm));
    }

    private static final String OTHER = "\u0000other";
    public static final int MAX_CELLS = 40000;

    private static List<Map<String, Object>> paramOptions(Space sp, String p) {
        List<Map<String, Object>> out = new ArrayList<>();
        out.add(null); // the parameter absent
        Set<String> seen = new HashSet<>();
        java.util.function.Consumer<Map<String, Object>> add = v -> { if (seen.add(G.stable(v))) out.add(v); };
        Map<String, List<Long>> groups = sp.q.get(p);
        if (groups != null) {
            for (Map.Entry<String, List<Long>> e : groups.entrySet()) {
                String key = e.getKey();
                boolean isInstant = key.equals("instant");
                for (long v : e.getValue()) for (long x : new long[] {v - 1, v, v + 1}) if (x >= 0 || isInstant) add.accept(G.map("k", "q", "q", G.map("u", unitOfKey(key), "n", G.num(x))));
                if (key.startsWith("money:")) add.accept(G.map("k", "q", "q", G.map("u", G.map("k", "money", "ccy", "ZZZ"), "n", G.num(0))));
            }
        }
        List<String> ds = sp.d.get(p);
        if (ds != null) for (String k : ds) add.accept(G.map("k", "s", "s", k.substring(2)));
        if (sp.d.containsKey(p)) add.accept(G.map("k", "s", "s", OTHER));
        return out;
    }

    private static Map<String, Object> build(Space sp, List<String> params, String verb, String resource, int bits, List<Map<String, Object>> choice) {
        Map<String, Object> pr = new LinkedHashMap<>();
        for (int i = 0; i < params.size(); i++) if (choice.get(i) != null) pr.put(params.get(i), choice.get(i));
        List<Object> rels = new ArrayList<>();
        for (int i = 0; i < sp.rels.size(); i++) {
            List<Object> members = new ArrayList<>();
            if ((bits & (1 << i)) != 0) members.add(resource);
            rels.add(G.map("rel", sp.rels.get(i)[0], "anchor", sp.rels.get(i)[1], "members", members));
        }
        return G.map("act", mkAct(verb, resource, pr), "rels", rels);
    }

    /** One representative per decision cell: {cases, complete} (complete false when the grid exceeded MAX_CELLS: then a subset). */
    public static Map<String, Object> cells(Space sp, List<String> verbsOpt) {
        List<String> verbs = verbsOpt != null ? verbsOpt : new ArrayList<>(sp.verbs);
        if (verbsOpt == null) verbs.add("\u0000other-verb");
        List<String> resources = new ArrayList<>(sp.resources);
        resources.add("\u0000other-resource");
        Set<String> ps = new LinkedHashSet<>(sp.q.keySet());
        ps.addAll(sp.d.keySet());
        List<String> params = sorted(ps);
        List<List<Map<String, Object>>> pOpts = new ArrayList<>();
        for (String p : params) pOpts.add(paramOptions(sp, p));
        int relBits = sp.rels.size();
        double total = (double) verbs.size() * resources.size() * Math.pow(2, relBits);
        for (List<Map<String, Object>> o : pOpts) total *= o.size();
        boolean complete = total <= MAX_CELLS;
        List<Object> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        java.util.function.Consumer<Map<String, Object>> push = c -> { if (seen.add(cellKey(sp, c))) out.add(c); };
        int nbits = 1 << relBits;
        if (complete) {
            int[] idx = new int[params.size()];
            for (String verb : verbs) for (String res : resources) for (int bits = 0; bits < nbits; bits++) {
                Arrays.fill(idx, 0);
                for (;;) {
                    List<Map<String, Object>> choice = new ArrayList<>();
                    for (int i = 0; i < idx.length; i++) choice.add(pOpts.get(i).get(idx[i]));
                    push.accept(build(sp, params, verb, res, bits, choice));
                    int k = 0;
                    while (k < idx.length && ++idx[k] == pOpts.get(k).size()) { idx[k] = 0; k++; }
                    if (k == idx.length) break;
                }
            }
        } else {
            for (String verb : verbs) {
                List<Map<String, Object>> base = new ArrayList<>();
                for (List<Map<String, Object>> o : pOpts) base.add(o.get(Math.min(2, o.size() - 1)));
                push.accept(build(sp, params, verb, resources.get(0), 0, base));
                for (String res : resources) for (int bits = 0; bits < nbits; bits++) push.accept(build(sp, params, verb, res, bits, base));
                for (int i = 0; i < pOpts.size(); i++) for (Map<String, Object> l : pOpts.get(i)) {
                    List<Map<String, Object>> ch = new ArrayList<>(base);
                    ch.set(i, l);
                    push.accept(build(sp, params, verb, resources.get(0), 0, ch));
                }
            }
        }
        return G.map("cases", out, "complete", complete);
    }

    private static long magnitude(Map<String, Object> a) {
        long s = 0;
        Map<String, Object> ps = mm(a.get("params"));
        if (ps != null) for (Object v : ps.values()) if (G.kind(v).equals("q")) s += Math.abs(qval(mm(G.get(v, "q"))));
        return s;
    }

    /** The smallest-magnitude case the grant admits (a minimal Allow witness), or null if its Allow set is empty. */
    public static Map<String, Object> allowWitness(Map<String, Object> g, Map<String, Object> gr, Map<String, Object> ont) {
        Space sp = buildSpace(List.of(g), new ArrayList<>());
        Map<String, Object> best = null;
        Map<String, Object> cs = cells(sp, new ArrayList<>(List.of((String) gr.get("verb"))));
        for (Object co : G.arr(cs.get("cases"), "cases")) {
            Map<String, Object> c = mm(co);
            Map<String, Object> v = decideCase(g, ont, c);
            if ("allow".equals(v.get("decision")) && v.get("witness") != null && v.get("witness").equals(gr.get("gid")) && (best == null || magnitude(mm(c.get("act"))) < magnitude(mm(best.get("act"))))) best = c;
        }
        return best;
    }

    private static Map<String, Object> example(String kind, String why, Map<String, Object> cs, Map<String, Object> hist, Map<String, Object> g, Map<String, Object> ont) {
        Map<String, Object> body = G.map("act", cs.get("act"), "hist", hist, "rels", cs.get("rels"));
        String id = kind + ":" + Pca.hashCanonical(body).substring(0, 12);
        Map<String, Object> dc = decideCase(g, ont, G.map("act", cs.get("act"), "hist", hist, "rels", cs.get("rels")));
        return G.map("id", id, "kind", kind, "why", why, "act", cs.get("act"), "hist", hist, "rels", cs.get("rels"), "decision", dc.get("decision"));
    }

    /** The full example set (cell representatives, cap sequences, unmentioned-dimension probes): {examples, complete}. */
    public static Map<String, Object> boundaryExamples(Map<String, Object> g, Map<String, Object> ont, List<Map<String, Object>> extra, List<String> verbsOpt) {
        List<Map<String, Object>> goals = new ArrayList<>();
        goals.add(g);
        if (extra != null) goals.addAll(extra);
        Space sp = buildSpace(goals, verbsOpt == null ? new ArrayList<>() : verbsOpt);
        Map<String, Object> c = cells(sp, null);
        List<Object> out = new ArrayList<>();
        for (Object cso : G.arr(c.get("cases"), "cases")) {
            Map<String, Object> cs = mm(cso);
            Map<String, Object> v = decideCase(g, ont, cs);
            boolean prohibited = Boolean.TRUE.equals(v.get("prohibited"));
            out.add(example(prohibited && "deny".equals(v.get("decision")) ? "prohibit_trigger" : "allow".equals(v.get("decision")) ? "member" : "boundary", "cell " + v.get("decision"), cs, emptyHist(), g, ont));
        }
        for (Object gro : G.arr(g.get("grants"), "grants")) {
            Map<String, Object> w = allowWitness(g, mm(gro), ont);
            if (w != null) out.add(example("allow_witness", "minimal Allow witness of grant " + G.get(gro, "gid"), w, emptyHist(), g, ont));
        }
        for (Object bo : G.arr(g.get("bounds"), "bounds")) {
            Map<String, Object> b = mm(bo), sel = mm(b.get("sel"));
            List<Object> gids = G.kind(sel).equals("gids") ? G.arr(sel.get("gids"), "gids") : new ArrayList<>();
            Map<String, Object> gr = null;
            for (Object x : G.arr(g.get("grants"), "grants")) if (gids.contains(G.get(x, "gid"))) { gr = mm(x); break; }
            Map<String, Object> w = gr != null ? allowWitness(g, gr, ont) : null;
            if (w == null) continue;
            double per;
            if ("count".equals(b.get("agg"))) per = 1;
            else {
                Map<String, Object> val = mm(b.get("value"));
                Map<String, Object> pv = G.kind(val).equals("param") ? mm(mm(mm(w.get("act")).get("params")).get(val.get("path"))) : null;
                per = pv != null && G.kind(pv).equals("q") ? qval(mm(pv.get("q"))) : 0;
            }
            if ("sum".equals(b.get("agg")) && per <= 0) continue;
            double n = Math.floor(qval(mm(b.get("cap"))) / per);
            if (n > 60) continue;
            List<Object> acts = new ArrayList<>();
            for (int i = 0; i < (int) n; i++) acts.add(w.get("act"));
            out.add(example("cap_sequence", "reach the " + b.get("bid") + " cap with " + (long) n + " action(s), then one more", w, replay(g, ont, acts, G.arr(w.get("rels"), "rels")), g, ont));
        }
        for (Object gro : G.arr(g.get("grants"), "grants")) {
            Map<String, Object> w = allowWitness(g, mm(gro), ont);
            if (w == null) continue;
            Map<String, Object> wact = mm(w.get("act"));
            for (Map.Entry<String, Object> e : mm(wact.get("params")).entrySet()) {
                Map<String, Object> l = mm(e.getValue());
                if (G.kind(l).equals("q") && G.kind(mm(mm(l.get("q")).get("u"))).equals("money")) {
                    Map<String, Object> q2 = new LinkedHashMap<>(mm(l.get("q")));
                    q2.put("n", G.num(1000000000L));
                    Map<String, Object> ps2 = new LinkedHashMap<>(mm(wact.get("params")));
                    ps2.put(e.getKey(), G.map("k", "q", "q", q2));
                    Map<String, Object> act2 = new LinkedHashMap<>(wact);
                    act2.put("params", ps2);
                    out.add(example("probe", "extreme " + e.getKey(), G.map("act", act2, "rels", w.get("rels")), emptyHist(), g, ont));
                }
            }
            List<Object> nothing = new ArrayList<>();
            for (Object ro : G.arr(w.get("rels"), "rels")) { Map<String, Object> r2 = new LinkedHashMap<>(mm(ro)); r2.put("members", new ArrayList<Object>()); nothing.add(r2); }
            Map<String, Object> act3 = new LinkedHashMap<>(wact);
            act3.put("res", "\u0000other-resource");
            out.add(example("probe", "other resource", G.map("act", act3, "rels", nothing), emptyHist(), g, ont));
            out.add(example("probe", "other customer/anchor", G.map("act", w.get("act"), "rels", nothing), emptyHist(), g, ont));
        }
        Set<String> seen = new HashSet<>();
        List<Object> uniq = new ArrayList<>();
        for (Object e : out) if (seen.add((String) G.get(e, "id"))) uniq.add(e);
        return G.map("examples", uniq, "complete", c.get("complete"));
    }

    /** Review subset: at most {@code cap} examples, riskiest-looking first (probe, cap_sequence, allow_witness, prohibit_trigger, member, boundary), stable. */
    public static List<Object> reviewSet(List<Object> examples, int cap) {
        Map<String, Integer> w = Map.of("probe", 0, "cap_sequence", 1, "allow_witness", 2, "prohibit_trigger", 3, "member", 4, "boundary", 5);
        List<Object> s = new ArrayList<>(examples);
        s.sort((a, b) -> {
            int r = rankOf((String) G.get(a, "decision")) - rankOf((String) G.get(b, "decision"));
            if (r != 0) return r;
            int k = w.get((String) G.get(a, "kind")) - w.get((String) G.get(b, "kind"));
            if (k != 0) return k;
            return ((String) G.get(a, "id")).compareTo((String) G.get(b, "id")) < 0 ? -1 : 1;
        });
        return new ArrayList<>(s.subList(0, Math.max(0, Math.min(cap, s.size()))));
    }

    // ---- GoalTest and the pin ----
    public static String expectedDecision(String answer) { return "allow".equals(answer) ? "allow" : "deny".equals(answer) ? "deny" : "escalate"; }

    /** Order-independent digest of a test list. */
    public static String testsDigest(List<Object> tests) {
        List<Object> s = new ArrayList<>(tests);
        s.sort((a, b) -> ((String) G.get(a, "id")).compareTo((String) G.get(b, "id")));
        return Pca.hashCanonical(G.map("d", "atlas-pca/goal-tests/v1", "tests", s));
    }

    /** confirmed: list of {example, answer}. */
    public static Map<String, Object> makeGoalTests(Map<String, Object> g, List<Object> confirmed) {
        List<Object> tests = new ArrayList<>();
        for (Object co : confirmed) {
            Map<String, Object> ex = mm(G.get(co, "example"));
            tests.add(G.map("id", ex.get("id"), "act", ex.get("act"), "hist", ex.get("hist"), "rels", ex.get("rels"), "answer", G.get(co, "answer")));
        }
        return G.map("goal_digest", GoalDigests.goalDigest(g), "ontology_digest", g.get("ontDigest"), "tests", tests, "tests_digest", testsDigest(tests));
    }

    public static Map<String, Object> signGoalTests(Map<String, Object> s, byte[] seed) { return GoalSign.signPayload("goal-tests", s, seed); }

    /** Recompile check: every confirmed test must be reproduced by {@code decideFn} (test -> decision). {ok, reason?, failures}. */
    public static Map<String, Object> checkGoalTests(Map<String, Object> s, List<?> pins, Function<Map<String, Object>, String> decideFn) {
        if (!GoalSign.verifyPayload(s, "goal-tests", pins)) return G.map("ok", false, "reason", "signature", "failures", new ArrayList<Object>());
        Map<String, Object> payload = mm(s.get("payload"));
        List<Object> tests = G.arr(payload.get("tests"), "tests");
        if (!testsDigest(tests).equals(payload.get("tests_digest"))) return G.map("ok", false, "reason", "tests_digest", "failures", new ArrayList<Object>());
        List<Object> failures = new ArrayList<>();
        for (Object to : tests) {
            Map<String, Object> t = mm(to);
            String got = decideFn.apply(t);
            String want = expectedDecision((String) t.get("answer"));
            if (!want.equals(got)) failures.add(G.map("id", t.get("id"), "expected", want, "got", got));
        }
        return failures.isEmpty() ? G.map("ok", true, "failures", failures) : G.map("ok", false, "reason", "test_regression", "failures", failures);
    }

    public static Map<String, Object> signPin(Map<String, Object> p, byte[] seed) { return GoalSign.signPayload("policy-pin", p, seed); }

    /** cur: {goal, policy_digest, tests}. {ok, reason?}. */
    public static Map<String, Object> checkPin(Map<String, Object> pin, List<?> pins, Map<String, Object> cur) {
        if (!GoalSign.verifyPayload(pin, "policy-pin", pins)) return G.map("ok", false, "reason", "signature");
        Map<String, Object> p = mm(pin.get("payload")), goal = mm(cur.get("goal")), tests = mm(cur.get("tests"));
        if (!java.util.Objects.equals(p.get("goal_digest"), GoalDigests.goalDigest(goal))) return G.map("ok", false, "reason", "goal changed under the pin");
        if (!java.util.Objects.equals(p.get("policy_digest"), cur.get("policy_digest"))) return G.map("ok", false, "reason", "policy changed under the pin");
        if (!java.util.Objects.equals(p.get("tests_digest"), tests.get("tests_digest")) || !java.util.Objects.equals(p.get("tests_digest"), testsDigest(G.arr(tests.get("tests"), "tests")))) return G.map("ok", false, "reason", "tests changed under the pin");
        if (!java.util.Objects.equals(p.get("ontology_digest"), goal.get("ontDigest"))) return G.map("ok", false, "reason", "ontology changed under the pin");
        return G.map("ok", true);
    }
}
