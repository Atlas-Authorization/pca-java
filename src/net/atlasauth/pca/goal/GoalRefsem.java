package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * An independent reading of the goal semantics D_G for the grammar the tests generate (conditions, grants, prohibitions, count /
 * sum / max / distinct bounds, validity, delegation). Three-valued: 0 false/deny, 1 unknown/escalate, 2 true/allow. Numbers are
 * JavaScript doubles, as in the reference.
 */
public final class GoalRefsem {
    private GoalRefsem() {}

    private static int and(int a, int b) { return Math.min(a, b); }
    private static int or(int a, int b) { return Math.max(a, b); }
    private static int not(int a) { return 2 - a; }
    private static int b2t(boolean b) { return b ? 2 : 0; }
    private static boolean sameUnit(Object a, Object b) { return G.stringify(a).equals(G.stringify(b)); }

    private static double n(Object o) { return G.toNum(o); }

    /** JavaScript {@code ===} on two parsed JSON scalars. */
    private static boolean seq(Object a, Object b) {
        Double x = G.strictNum(a), y = G.strictNum(b);
        if (x != null || y != null) return x != null && y != null && x.doubleValue() == y.doubleValue();
        return java.util.Objects.equals(a, b);
    }

    private static Map<String, Object> val(Map<String, Object> t, Map<String, Object> a, Map<String, Object> h) {
        String k = G.kind(t);
        if (k.equals("param")) {
            Map<String, Object> ps = G.m(a.get("params"));
            if (a.get("params") == null) throw new IrError("params expected");
            return ps != null && ps.containsKey(t.get("path")) ? G.m(ps.get(t.get("path"))) : null;
        }
        if (k.equals("lit")) return G.m(t.get("v"));
        Map<String, Object> aggs = G.m(h.get("aggs"));
        return aggs != null && aggs.containsKey(t.get("bid")) ? G.map("k", "q", "q", aggs.get(t.get("bid"))) : null;
    }

    /** {@code v.q[k]} as JavaScript reads it: a primitive q has no members (undefined), a missing / null q is a TypeError. */
    private static Object qmember(Map<String, Object> v, String k) {
        Object q = v.get("q");
        if (q == null) throw new NullPointerException("Cannot read properties of " + (v.containsKey("q") ? "null" : "undefined") + " (reading '" + k + "')");
        return q instanceof Map ? ((Map<?, ?>) q).get(k) : null;
    }
    private static Object qn(Map<String, Object> v) { return qmember(v, "n"); }
    private static Object qu(Map<String, Object> v) { return qmember(v, "u"); }

    private static int eq(Map<String, Object> x, Map<String, Object> y) {
        String kx = G.kind(x), ky = G.kind(y);
        if (kx.equals("q") && ky.equals("q")) return sameUnit(qu(x), qu(y)) ? b2t(seq(qn(x), qn(y))) : 1;
        if (kx.equals("s") && ky.equals("s")) return b2t(seq(x.get("s"), y.get("s")));
        return 1;
    }

    private static int lt(Map<String, Object> x, Map<String, Object> y) {
        return G.kind(x).equals("q") && G.kind(y).equals("q") && sameUnit(qu(x), qu(y)) ? b2t(n(qn(x)) < n(qn(y))) : 1;
    }

    private static int inSet(Map<String, Object> x, Map<String, Object> y) {
        if (!G.kind(y).equals("set")) return 1;
        int acc = 0;
        for (Object it : G.arr(y.get("items"), "items")) acc = or(acc, eq(x, G.m(it)));
        return acc;
    }

    private static int cmp(String op, Map<String, Object> x, Map<String, Object> y) {
        if (x == null || y == null) return 1;
        switch (op) {
            case "eq": return eq(x, y);
            case "ne": return not(eq(x, y));
            case "lt": return lt(x, y);
            case "gte": return not(lt(x, y));
            case "gt": return lt(y, x);
            case "lte": return not(lt(y, x));
            case "in": return inSet(x, y);
            default: return not(inSet(x, y));
        }
    }

    private static int evalC(Map<String, Object> c, Map<String, Object> a, Map<String, Object> h) {
        switch (G.kind(c)) {
            case "true": return 2;
            case "cmp": return cmp(String.valueOf(c.get("op")), val(G.m(c.get("l")), a, h), val(G.m(c.get("r")), a, h));
            case "and": return and(evalC(G.m(c.get("a")), a, h), evalC(G.m(c.get("b")), a, h));
            case "or": return or(evalC(G.m(c.get("a")), a, h), evalC(G.m(c.get("b")), a, h));
            case "not": return not(evalC(G.m(c.get("c")), a, h));
            default: throw new IrError("unknown condition");
        }
    }

    private static boolean includes(Object list, Object x) {
        List<Object> l = G.l(list);
        if (l == null) return false;
        for (Object o : l) if (o != null && o.equals(x)) return true;
        return false;
    }

    private static boolean resOk(Map<String, Object> s, Map<String, Object> ont, Object r) {
        switch (G.kind(s)) {
            case "any": return true;
            case "exact": return seq(r, s.get("id"));
            case "oneof": return includes(s.get("ids"), r);
            case "related":
                for (Object x : G.arr(ont.get("rels"), "rels")) {
                    if (s.get("rel") != null && s.get("rel").equals(G.get(x, "rel")) && s.get("anchor") != null && s.get("anchor").equals(G.get(x, "anchor"))) return includes(G.get(x, "members"), r);
                }
                return false;
            case "all_of":
                for (Object p : G.arr(s.get("parts"), "parts")) if (!resOk(G.m(p), ont, r)) return false;
                return true;
            default: throw new IrError("unknown selector");
        }
    }

    private static List<Object> verbsOf(Map<String, Object> ont, Object cls) {
        List<Object> out = new ArrayList<>();
        for (Object v : G.arr(ont.get("verbs"), "verbs")) if (cls != null && cls.equals(G.get(v, "cls"))) out.add(G.get(v, "verb"));
        return out;
    }

    private static boolean inScope(Map<String, Object> sc, Map<String, Object> a, Map<String, Object> x) {
        switch (G.kind(sc)) {
            case "session": return java.util.Objects.equals(a.get("sess"), x.get("sess"));
            case "principal": return java.util.Objects.equals(a.get("prin"), x.get("prin"));
            case "org": return java.util.Objects.equals(a.get("org"), x.get("org"));
            case "fleet": return includes(sc.get("agents"), a.get("agent")) && includes(sc.get("agents"), x.get("agent"));
            default: return false;
        }
    }

    private static boolean inWin(Map<String, Object> w, Map<String, Object> a, Map<String, Object> x) {
        switch (G.kind(w)) {
            case "task": case "lifetime": return true;
            case "sliding": return n(x.get("t")) > n(a.get("t")) - n(w.get("ms")) && n(x.get("t")) <= n(a.get("t"));
            case "period": {
                double ms = n(w.get("ms"));
                return ms > 0 && Math.floor((n(a.get("t")) - n(w.get("t0"))) / ms) == Math.floor((n(x.get("t")) - n(w.get("t0"))) / ms);
            }
            default: return false;
        }
    }

    /** The decision (0 deny, 1 escalate, 2 allow); see {@link #refExplain}. */
    public static int refDecide(Map<String, Object> g, Map<String, Object> ont, Map<String, Object> a, Map<String, Object> h) {
        return Integer.parseInt(((net.atlasauth.pca.Json.Num) refExplain(g, ont, a, h).get("d")).raw);
    }

    /** {d, witness, prohibit}: witness is the first grant whose own decision is allow (only when d = 2); prohibit is the meet over the prohibitions. */
    public static Map<String, Object> refExplain(Map<String, Object> g, Map<String, Object> ont, Map<String, Object> a, Map<String, Object> h) {
        int d = 2, prohibit = 2;
        String witness = null;
        Map<String, Object> validity = G.m(g.get("validity")), deleg = G.m(g.get("deleg"));
        double t = n(a.get("t")), depth = n(a.get("depth"));
        if (t < n(validity.get("notBefore")) || t > n(validity.get("notAfter"))) d = Math.min(d, 0);
        else if (n(validity.get("maxIdle")) > 0 && n(h.get("last")) >= 0 && t - n(h.get("last")) > n(validity.get("maxIdle"))) d = Math.min(d, 0);
        else if (depth < 0 || depth > n(deleg.get("maxDepth"))) d = Math.min(d, 0);
        for (Object po : G.arr(g.get("prohibits"), "prohibits")) {
            Map<String, Object> p = G.m(po), tg = G.m(p.get("target"));
            List<Object> verbs;
            if (G.kind(tg).equals("verb")) { verbs = new ArrayList<>(); verbs.add(tg.get("verb")); } else verbs = verbsOf(ont, tg.get("cls"));
            int m = and(b2t(includes(verbs, a.get("verb"))), and(b2t(resOk(G.m(p.get("res")), ont, a.get("res"))), evalC(G.m(p.get("cond")), a, h)));
            int pd = m == 2 ? 0 : m == 1 ? 1 : 2;
            d = Math.min(d, pd);
            prohibit = Math.min(prohibit, pd);
        }
        for (Object c : G.arr(g.get("escalateOn"), "escalateOn")) d = Math.min(d, evalC(G.m(c), a, h) == 0 ? 2 : 1);
        int best = 0;
        for (Object gro : G.arr(g.get("grants"), "grants")) {
            Map<String, Object> gr = G.m(gro);
            int m = and(b2t(java.util.Objects.equals(a.get("verb"), gr.get("verb")) && (seq(a.get("depth"), G.num(0)) || includes(deleg.get("mayTouch"), gr.get("gid")))),
                and(b2t(resOk(G.m(gr.get("res")), ont, a.get("res"))), evalC(G.m(gr.get("cond")), a, h)));
            int gd = m;
            for (Object bo : G.arr(g.get("bounds"), "bounds")) {
                Map<String, Object> b = G.m(bo), sel = G.m(b.get("sel"));
                List<Object> gids = G.kind(sel).equals("gids") ? G.arr(sel.get("gids"), "gids") : new ArrayList<>();
                List<Object> verbs = G.kind(sel).equals("effect") ? verbsOf(ont, sel.get("cls")) : new ArrayList<>();
                if (!(includes(gids, gr.get("gid")) || includes(verbs, a.get("verb")))) continue;
                List<Map<String, Object>> items = new ArrayList<>();
                for (Object ao : G.arr(h.get("adms"), "adms")) {
                    Map<String, Object> x = G.m(G.m(ao).get("act"));
                    if ((includes(gids, G.m(ao).get("gid")) || includes(verbs, x.get("verb"))) && inScope(G.m(b.get("scope")), a, x) && inWin(G.m(b.get("window")), a, x)) items.add(x);
                }
                items.add(a);
                Map<String, Object> cap = G.m(b.get("cap"));
                String agg = String.valueOf(b.get("agg"));
                int ex;
                if (agg.equals("count")) ex = b2t(items.size() > n(cap.get("n")));
                else if (agg.equals("sum") || agg.equals("max")) {
                    List<Double> xs = new ArrayList<>();
                    boolean ok = true;
                    for (Map<String, Object> it : items) {
                        Map<String, Object> v = val(G.m(b.get("value")), it, h);
                        if (v == null || !G.kind(v).equals("q") || !sameUnit(qu(v), cap.get("u"))) { ok = false; break; }
                        xs.add(n(qn(v)));
                    }
                    if (!ok) ex = 1;
                    else if (agg.equals("sum")) { double s = 0; for (double x : xs) s += x; ex = b2t(s > n(cap.get("n"))); }
                    else if (xs.isEmpty()) ex = 1;
                    else { double mx = Double.NEGATIVE_INFINITY; for (double x : xs) { if (Double.isNaN(x)) { mx = Double.NaN; break; } mx = Math.max(mx, x); } ex = b2t(mx > n(cap.get("n"))); }
                } else {
                    Set<String> ks = new HashSet<>();
                    boolean ok = true;
                    for (Map<String, Object> it : items) {
                        Map<String, Object> ps = G.m(it.get("params"));
                        if (ps == null || !ps.containsKey(b.get("key"))) { ok = false; break; }
                        ks.add(G.stringify(ps.get(b.get("key"))));
                    }
                    ex = ok ? b2t(ks.size() > n(cap.get("n"))) : 1;
                }
                gd = Math.min(gd, ex == 2 ? ("deny".equals(b.get("onExceed")) ? 0 : 1) : ex == 1 ? 1 : 2);
            }
            if (gd == 2 && witness == null) witness = (String) gr.get("gid");
            best = Math.max(best, gd);
        }
        d = Math.min(d, best);
        return G.map("d", G.num(d), "witness", d == 2 ? witness : null, "prohibit", G.num(prohibit));
    }
}
