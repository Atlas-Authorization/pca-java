package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The token-tape form of the Goal IR. A tape is a list of tokens; a token is a two-element list {@code ["k", n]} (keyword),
 * {@code ["i", n]} (integer) or {@code ["s", text]}. Encoding is strict: anything that is not exactly an IR value throws
 * {@link IrError}. Goals, ontologies, acts and histories are parsed-JSON maps shaped like the TypeScript IR.
 */
public final class GoalCodec {
    private GoalCodec() {}

    public static final List<String> OPS = List.of("eq", "ne", "lt", "lte", "gt", "gte", "in", "nin");
    public static final List<String> AGGS = List.of("count", "sum", "max", "distinct");

    private static List<Object> tok(String t, Object v) { List<Object> x = new ArrayList<>(2); x.add(t); x.add(v); return x; }
    private static List<Object> K(long n) { return tok("k", G.num(n)); }

    private static List<Object> I(Object v) {
        Long n = G.safeInt(v);
        if (n == null) throw new IrError(v + " is not a safe integer");
        return tok("i", G.num(n));
    }

    private static List<Object> I(long n) { return tok("i", G.num(n)); }

    private static List<Object> S(Object s) {
        if (!(s instanceof String)) throw new IrError("string expected");
        return tok("s", s);
    }

    private static IrError bad(String what, Object v) {
        String s;
        try { s = G.stringify(v); } catch (RuntimeException e) { s = String.valueOf(v); }
        return new IrError("unknown " + what + ": " + s);
    }

    private interface Enc { void go(List<Object> out, Object x); }

    private static void list(List<Object> out, Object xs, Enc f) {
        List<Object> a = G.l(xs);
        if (a == null) throw new IrError("array expected");
        out.add(I(a.size()));
        for (Object x : a) f.go(out, x);
    }

    private static void strs(List<Object> out, Object xs) { list(out, xs, (o, s) -> o.add(S(s))); }

    private static void unit(List<Object> out, Object u) {
        switch (G.kind(u)) {
            case "money": out.add(K(300)); out.add(S(G.get(u, "ccy"))); break;
            case "count": out.add(K(301)); break;
            case "duration": out.add(K(302)); break;
            case "instant": out.add(K(303)); break;
            case "bytes": out.add(K(304)); break;
            case "ratio": out.add(K(305)); break;
            default: throw bad("unit", u);
        }
    }

    private static void quantity(List<Object> out, Object q) { unit(out, G.get(q, "u")); out.add(I(G.get(q, "n"))); }

    private static void ty(List<Object> out, Object t) {
        String k = G.kind(t);
        if (k.equals("q")) { out.add(K(310)); unit(out, G.get(t, "u")); }
        else if (k.equals("s")) out.add(K(311));
        else throw bad("type", t);
    }

    private static void atom(List<Object> out, Object a) {
        String k = G.kind(a);
        if (k.equals("q")) { out.add(K(320)); quantity(out, G.get(a, "q")); }
        else if (k.equals("s")) { out.add(K(321)); out.add(S(G.get(a, "s"))); }
        else throw bad("set member (sets hold quantities and strings only)", a);
    }

    private static void value(List<Object> out, Object v) {
        switch (G.kind(v)) {
            case "q": out.add(K(330)); quantity(out, G.get(v, "q")); break;
            case "s": out.add(K(331)); out.add(S(G.get(v, "s"))); break;
            case "set": out.add(K(332)); list(out, G.get(v, "items"), GoalCodec::atom); break;
            default: throw bad("value", v);
        }
    }

    private static void term(List<Object> out, Object t) {
        switch (G.kind(t)) {
            case "param": out.add(K(340)); out.add(S(G.get(t, "path"))); ty(out, G.get(t, "ty")); break;
            case "lit": out.add(K(341)); value(out, G.get(t, "v")); break;
            case "hist": out.add(K(342)); out.add(S(G.get(t, "bid"))); unit(out, G.get(t, "u")); break;
            default: throw bad("term", t);
        }
    }

    private static void op(List<Object> out, Object o) {
        int i = o instanceof String ? OPS.indexOf(o) : -1;
        if (i < 0) throw bad("operator", o);
        out.add(K(350 + i));
    }

    private static void cond(List<Object> out, Object c) {
        switch (G.kind(c)) {
            case "true": out.add(K(360)); break;
            case "cmp": out.add(K(361)); op(out, G.get(c, "op")); term(out, G.get(c, "l")); term(out, G.get(c, "r")); break;
            case "and": out.add(K(362)); cond(out, G.get(c, "a")); cond(out, G.get(c, "b")); break;
            case "or": out.add(K(363)); cond(out, G.get(c, "a")); cond(out, G.get(c, "b")); break;
            case "not": out.add(K(364)); cond(out, G.get(c, "c")); break;
            default: throw bad("condition", c);
        }
    }

    private static void part(List<Object> out, Object s) {
        switch (G.kind(s)) {
            case "exact": out.add(K(375)); out.add(S(G.get(s, "id"))); break;
            case "oneof": out.add(K(376)); strs(out, G.get(s, "ids")); break;
            case "related": out.add(K(377)); out.add(S(G.get(s, "rel"))); out.add(S(G.get(s, "anchor"))); break;
            default: throw bad("resource part", s);
        }
    }

    private static void res(List<Object> out, Object s) {
        switch (G.kind(s)) {
            case "exact": out.add(K(370)); out.add(S(G.get(s, "id"))); break;
            case "oneof": out.add(K(371)); strs(out, G.get(s, "ids")); break;
            case "related": out.add(K(372)); out.add(S(G.get(s, "rel"))); out.add(S(G.get(s, "anchor"))); break;
            case "any": out.add(K(373)); out.add(S(G.get(s, "reason"))); break;
            case "all_of": out.add(K(374)); list(out, G.get(s, "parts"), GoalCodec::part); break;
            default: throw bad("resource selector", s);
        }
    }

    private static void grant(List<Object> out, Object g) {
        out.add(K(380)); out.add(S(G.get(g, "gid"))); out.add(S(G.get(g, "verb"))); res(out, G.get(g, "res")); cond(out, G.get(g, "cond"));
    }

    private static void target(List<Object> out, Object t) {
        String k = G.kind(t);
        if (k.equals("verb")) { out.add(K(390)); out.add(S(G.get(t, "verb"))); }
        else if (k.equals("effect")) { out.add(K(391)); out.add(S(G.get(t, "cls"))); }
        else throw bad("prohibit target", t);
    }

    private static void prohibit(List<Object> out, Object p) {
        out.add(K(392)); out.add(S(G.get(p, "pid"))); target(out, G.get(p, "target")); res(out, G.get(p, "res")); cond(out, G.get(p, "cond"));
    }

    private static void sel(List<Object> out, Object s) {
        String k = G.kind(s);
        if (k.equals("gids")) { out.add(K(410)); strs(out, G.get(s, "gids")); }
        else if (k.equals("effect")) { out.add(K(411)); out.add(S(G.get(s, "cls"))); }
        else throw bad("selection", s);
    }

    private static void window(List<Object> out, Object w) {
        switch (G.kind(w)) {
            case "task": out.add(K(420)); break;
            case "sliding": out.add(K(421)); out.add(I(G.get(w, "ms"))); break;
            case "period": out.add(K(422)); out.add(I(G.get(w, "ms"))); out.add(I(G.get(w, "t0"))); break;
            case "lifetime": out.add(K(423)); break;
            default: throw bad("window", w);
        }
    }

    private static void scope(List<Object> out, Object s) {
        switch (G.kind(s)) {
            case "session": out.add(K(430)); break;
            case "principal": out.add(K(431)); break;
            case "org": out.add(K(432)); break;
            case "fleet": out.add(K(433)); strs(out, G.get(s, "agents")); break;
            default: throw bad("scope", s);
        }
    }

    private static void onExceed(List<Object> out, Object o) {
        if ("deny".equals(o)) out.add(K(440));
        else if ("escalate".equals(o)) out.add(K(441));
        else throw bad("on_exceed", o);
    }

    private static void bcore(List<Object> out, Object b) {
        Object agg = G.get(b, "agg");
        int a = agg instanceof String ? AGGS.indexOf(agg) : -1;
        if (a < 0) throw bad("aggregate", agg);
        out.add(K(450)); out.add(K(400 + a)); term(out, G.get(b, "value")); out.add(S(G.get(b, "key")));
        window(out, G.get(b, "window")); scope(out, G.get(b, "scope")); quantity(out, G.get(b, "cap")); onExceed(out, G.get(b, "onExceed"));
    }

    private static void bound(List<Object> out, Object b) { out.add(K(451)); out.add(S(G.get(b, "bid"))); sel(out, G.get(b, "sel")); bcore(out, b); }

    private static void validity(List<Object> out, Object v) {
        out.add(K(460)); out.add(I(G.get(v, "notBefore"))); out.add(I(G.get(v, "notAfter"))); out.add(I(G.get(v, "maxIdle")));
    }

    private static void deleg(List<Object> out, Object d) {
        out.add(K(461)); out.add(I(G.get(d, "maxDepth"))); out.add(I(G.truthy(G.get(d, "narrowOnly")) ? 1 : 0)); strs(out, G.get(d, "mayTouch"));
    }

    private static void hole(List<Object> out, Object h) {
        out.add(K(470)); out.add(S(G.get(h, "hid"))); out.add(S(G.get(h, "q"))); strs(out, G.get(h, "domain")); strs(out, G.get(h, "affects"));
        out.add(I(G.truthy(G.get(h, "global")) ? 1 : 0));
    }

    /** The goal as a token tape. */
    public static List<Object> encodeGoal(Map<String, Object> g) {
        List<Object> out = new ArrayList<>();
        out.add(K(480)); out.add(I(G.get(g, "v"))); out.add(S(G.get(g, "principal"))); out.add(S(G.get(g, "ontDigest"))); out.add(S(G.get(g, "nlDigest")));
        strs(out, G.get(g, "sources"));
        list(out, G.get(g, "grants"), GoalCodec::grant);
        list(out, G.get(g, "prohibits"), GoalCodec::prohibit);
        list(out, G.get(g, "bounds"), GoalCodec::bound);
        validity(out, G.get(g, "validity"));
        deleg(out, G.get(g, "deleg"));
        list(out, G.get(g, "escalateOn"), GoalCodec::cond);
        strs(out, G.get(g, "wildcardAck"));
        list(out, G.get(g, "holes"), GoalCodec::hole);
        return out;
    }

    public static List<Object> encodeOntology(Map<String, Object> o) {
        List<Object> out = new ArrayList<>();
        out.add(K(510));
        list(out, G.get(o, "verbs"), (t, v) -> {
            t.add(K(501)); t.add(S(G.get(v, "verb"))); t.add(S(G.get(v, "cls")));
            list(t, G.get(v, "params"), (u, p) -> { u.add(K(500)); u.add(S(G.get(p, "path"))); ty(u, G.get(p, "ty")); });
        });
        list(out, G.get(o, "rels"), (t, r) -> { t.add(K(502)); t.add(S(G.get(r, "rel"))); t.add(S(G.get(r, "anchor"))); strs(t, G.get(r, "members")); });
        return out;
    }

    /** {@code Object.keys(o).sort()}: null throws (TypeError), arrays and strings expose their indices, other scalars have none. */
    private static List<String> sortedKeys(Object o) {
        if (o == null) throw new IrError("object expected");
        List<String> ks = new ArrayList<>();
        if (o instanceof Map) for (Object k : ((Map<?, ?>) o).keySet()) ks.add((String) k);
        else if (o instanceof List) for (int i = 0; i < ((List<?>) o).size(); i++) ks.add(Integer.toString(i));
        ks.sort(String::compareTo);
        return ks;
    }

    private static Object member(Object o, String k) {
        if (o instanceof List) return ((List<?>) o).get(Integer.parseInt(k));
        return G.get(o, k);
    }

    private static void act(List<Object> out, Object a) {
        Object params = G.get(a, "params");
        List<String> keys = sortedKeys(params);
        out.add(K(530)); out.add(S(G.get(a, "verb"))); out.add(S(G.get(a, "res")));
        out.add(I(keys.size()));
        for (String k : keys) { out.add(K(520)); out.add(S(k)); value(out, member(params, k)); }
        out.add(I(G.get(a, "t"))); out.add(S(G.get(a, "sess"))); out.add(S(G.get(a, "prin"))); out.add(S(G.get(a, "org"))); out.add(S(G.get(a, "agent")));
        out.add(I(G.get(a, "depth")));
    }

    public static List<Object> encodeAct(Map<String, Object> a) { List<Object> out = new ArrayList<>(); act(out, a); return out; }

    public static List<Object> encodeHist(Map<String, Object> h) {
        List<Object> out = new ArrayList<>();
        Object aggs = G.get(h, "aggs");
        List<String> keys = sortedKeys(aggs);
        out.add(K(541));
        list(out, G.get(h, "adms"), (t, a) -> { t.add(K(531)); t.add(S(G.get(a, "gid"))); act(t, G.get(a, "act")); });
        out.add(I(G.get(h, "last")));
        out.add(I(keys.size()));
        for (String k : keys) { out.add(K(540)); out.add(S(k)); quantity(out, member(aggs, k)); }
        return out;
    }

    // ---- decoding ----
    /** A cursor over a tape. */
    public static final class Rd {
        private final List<Object> t;
        private int i;

        public Rd(List<Object> t) { this.t = t; }

        private List<Object> next() {
            if (i >= t.size()) throw new IrError("truncated tape");
            List<Object> x = G.l(t.get(i++));
            if (x == null || x.size() != 2) throw new IrError("malformed token");
            return x;
        }

        public long k() {
            List<Object> x = next();
            if (!"k".equals(x.get(0))) throw new IrError("keyword expected");
            return tokInt(x.get(1));
        }

        public long integer() {
            List<Object> x = next();
            if (!"i".equals(x.get(0))) throw new IrError("integer expected");
            return tokInt(x.get(1));
        }

        public String str() {
            List<Object> x = next();
            if (!"s".equals(x.get(0)) || !(x.get(1) instanceof String)) throw new IrError("string expected");
            return (String) x.get(1);
        }

        public boolean done() { return i >= t.size(); }

        private static long tokInt(Object v) {
            Long n = G.safeInt(v);
            if (n == null) throw new IrError("integer expected");
            return n;
        }

        public <T> List<Object> list(java.util.function.Supplier<T> f) {
            long n = integer();
            if (n < 0) throw new IrError("negative length");
            List<Object> out = new ArrayList<>();
            for (long j = 0; j < n; j++) out.add(f.get());
            return out;
        }

        public List<Object> strs() { return list(this::str); }
    }

    private static Map<String, Object> dUnit(Rd r) {
        long k = r.k();
        if (k == 300) return G.map("k", "money", "ccy", r.str());
        String u = k == 301 ? "count" : k == 302 ? "duration" : k == 303 ? "instant" : k == 304 ? "bytes" : k == 305 ? "ratio" : null;
        if (u == null) throw new IrError("bad unit tag " + k);
        return G.map("k", u);
    }

    private static Map<String, Object> dQ(Rd r) { Map<String, Object> u = dUnit(r); return G.map("u", u, "n", G.num(r.integer())); }

    private static Map<String, Object> dTy(Rd r) {
        long k = r.k();
        if (k == 310) return G.map("k", "q", "u", dUnit(r));
        if (k == 311) return G.map("k", "s");
        throw new IrError("bad type tag " + k);
    }

    private static Map<String, Object> dAtom(Rd r) {
        long k = r.k();
        if (k == 320) return G.map("k", "q", "q", dQ(r));
        if (k == 321) return G.map("k", "s", "s", r.str());
        throw new IrError("bad atom tag " + k);
    }

    private static Map<String, Object> dV(Rd r) {
        long k = r.k();
        if (k == 330) return G.map("k", "q", "q", dQ(r));
        if (k == 331) return G.map("k", "s", "s", r.str());
        if (k == 332) return G.map("k", "set", "items", r.list(() -> dAtom(r)));
        throw new IrError("bad value tag " + k);
    }

    private static Map<String, Object> dTerm(Rd r) {
        long k = r.k();
        if (k == 340) { String p = r.str(); return G.map("k", "param", "path", p, "ty", dTy(r)); }
        if (k == 341) return G.map("k", "lit", "v", dV(r));
        if (k == 342) { String b = r.str(); return G.map("k", "hist", "bid", b, "u", dUnit(r)); }
        throw new IrError("bad term tag " + k);
    }

    private static String dOp(Rd r) {
        long k = r.k() - 350;
        if (k < 0 || k >= OPS.size()) throw new IrError("bad operator");
        return OPS.get((int) k);
    }

    private static Map<String, Object> dN(Rd r) {
        long k = r.k();
        if (k == 600) return G.map("k", "true");
        if (k == 601) return G.map("k", "false");
        if (k == 602) { String op = dOp(r); Map<String, Object> l = dTerm(r); return G.map("k", "atom", "op", op, "l", l, "r", dTerm(r)); }
        if (k == 603) { Map<String, Object> a = dN(r); return G.map("k", "and", "a", a, "b", dN(r)); }
        if (k == 604) { Map<String, Object> a = dN(r); return G.map("k", "or", "a", a, "b", dN(r)); }
        throw new IrError("bad condition tag " + k);
    }

    private static Map<String, Object> dResPat(Rd r) {
        long k = r.k();
        if (k == 630) return G.map("k", "star");
        if (k == 631) return G.map("k", "set", "ids", r.strs());
        throw new IrError("bad resource pattern tag " + k);
    }

    private static Map<String, Object> dWindow(Rd r) {
        long k = r.k();
        if (k == 420) return G.map("k", "task");
        if (k == 421) return G.map("k", "sliding", "ms", G.num(r.integer()));
        if (k == 422) { long ms = r.integer(); return G.map("k", "period", "ms", G.num(ms), "t0", G.num(r.integer())); }
        if (k == 423) return G.map("k", "lifetime");
        throw new IrError("bad window tag " + k);
    }

    private static Map<String, Object> dScope(Rd r) {
        long k = r.k();
        if (k == 430) return G.map("k", "session");
        if (k == 431) return G.map("k", "principal");
        if (k == 432) return G.map("k", "org");
        if (k == 433) return G.map("k", "fleet", "agents", r.strs());
        throw new IrError("bad scope tag " + k);
    }

    /** Remaining fields of a bound core after the 450 tag: agg, value, key, window, scope, cap, onExceed. */
    private static void dBoundCore(Rd r, Map<String, Object> into) {
        long ak = r.k() - 400;
        if (ak < 0 || ak >= AGGS.size()) throw new IrError("bad aggregate");
        into.put("agg", AGGS.get((int) ak));
        into.put("value", dTerm(r));
        into.put("key", r.str());
        into.put("window", dWindow(r));
        into.put("scope", dScope(r));
        into.put("cap", dQ(r));
        long oe = r.k();
        if (oe != 440 && oe != 441) throw new IrError("bad on_exceed");
        into.put("onExceed", oe == 440 ? "deny" : "escalate");
    }

    private static Map<String, Object> dCeil(Rd r) {
        if (r.k() != 610) throw new IrError("ceiling expected");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("bid", r.str());
        m.put("selGids", r.strs());
        m.put("selVerbs", r.strs());
        if (r.k() != 450) throw new IrError("bound core expected");
        dBoundCore(r, m);
        return m;
    }

    /** Decode the compiler's policy tape (the leading status token already consumed). */
    public static Map<String, Object> decodePolicy(List<Object> t) {
        Rd r = new Rd(t);
        if (r.k() != 650) throw new IrError("policy expected");
        List<Object> preds = r.list(() -> {
            if (r.k() != 620) throw new IrError("pred");
            String gid = r.str(); String verb = r.str(); Map<String, Object> rp = dResPat(r);
            return G.map("gid", gid, "verb", verb, "res", rp, "cond", dN(r));
        });
        List<Object> prohs = r.list(() -> {
            if (r.k() != 640) throw new IrError("prohibition");
            String pid = r.str(); List<Object> vs = r.strs(); Map<String, Object> rp = dResPat(r);
            return G.map("pid", pid, "verbs", vs, "res", rp, "cond", dN(r));
        });
        List<Object> ceils = r.list(() -> dCeil(r));
        List<Object> escs = r.list(() -> dN(r));
        if (r.k() != 460) throw new IrError("validity");
        long nb = r.integer(), na = r.integer(), mi = r.integer();
        Map<String, Object> validity = G.map("notBefore", G.num(nb), "notAfter", G.num(na), "maxIdle", G.num(mi));
        if (r.k() != 461) throw new IrError("delegation");
        long md = r.integer(); boolean no = r.integer() == 1; List<Object> mt = r.strs();
        Map<String, Object> deleg = G.map("maxDepth", G.num(md), "narrowOnly", no, "mayTouch", mt);
        if (!r.done()) throw new IrError("trailing tokens after policy");
        return G.map("preds", preds, "prohs", prohs, "ceils", ceils, "escs", escs, "validity", validity, "deleg", deleg);
    }

    private static Map<String, Object> dCond(Rd r) {
        long k = r.k();
        if (k == 360) return G.map("k", "true");
        if (k == 361) { String op = dOp(r); Map<String, Object> l = dTerm(r); return G.map("k", "cmp", "op", op, "l", l, "r", dTerm(r)); }
        if (k == 362) { Map<String, Object> a = dCond(r); return G.map("k", "and", "a", a, "b", dCond(r)); }
        if (k == 363) { Map<String, Object> a = dCond(r); return G.map("k", "or", "a", a, "b", dCond(r)); }
        if (k == 364) return G.map("k", "not", "c", dCond(r));
        throw new IrError("bad condition tag " + k);
    }

    private static Map<String, Object> dPart(Rd r) {
        long k = r.k();
        if (k == 375) return G.map("k", "exact", "id", r.str());
        if (k == 376) return G.map("k", "oneof", "ids", r.strs());
        if (k == 377) { String rel = r.str(); return G.map("k", "related", "rel", rel, "anchor", r.str()); }
        throw new IrError("bad resource part tag " + k);
    }

    private static Map<String, Object> dRes(Rd r) {
        long k = r.k();
        if (k == 370) return G.map("k", "exact", "id", r.str());
        if (k == 371) return G.map("k", "oneof", "ids", r.strs());
        if (k == 372) { String rel = r.str(); return G.map("k", "related", "rel", rel, "anchor", r.str()); }
        if (k == 373) return G.map("k", "any", "reason", r.str());
        if (k == 374) return G.map("k", "all_of", "parts", r.list(() -> dPart(r)));
        throw new IrError("bad resource selector tag " + k);
    }

    private static void expect(Rd r, long k, String what) { if (r.k() != k) throw new IrError(what + " expected"); }

    /** Parse a goal tape; throws IrError unless the whole tape is exactly one goal. */
    public static Map<String, Object> decodeGoal(List<Object> t) {
        Rd r = new Rd(t);
        expect(r, 480, "goal");
        long v = r.integer();
        String principal = r.str(), ontDigest = r.str(), nlDigest = r.str();
        List<Object> sources = r.strs();
        List<Object> grants = r.list(() -> {
            expect(r, 380, "grant");
            String gid = r.str(), verb = r.str(); Map<String, Object> rs = dRes(r);
            return G.map("gid", gid, "verb", verb, "res", rs, "cond", dCond(r));
        });
        List<Object> prohibits = r.list(() -> {
            expect(r, 392, "prohibit");
            String pid = r.str();
            long tk = r.k();
            Map<String, Object> target;
            if (tk == 390) target = G.map("k", "verb", "verb", r.str());
            else if (tk == 391) target = G.map("k", "effect", "cls", r.str());
            else throw new IrError("bad prohibit target");
            Map<String, Object> rs = dRes(r);
            return G.map("pid", pid, "target", target, "res", rs, "cond", dCond(r));
        });
        List<Object> bounds = r.list(() -> {
            expect(r, 451, "bound");
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("bid", r.str());
            long sk = r.k();
            if (sk == 410) m.put("sel", G.map("k", "gids", "gids", r.strs()));
            else if (sk == 411) m.put("sel", G.map("k", "effect", "cls", r.str()));
            else throw new IrError("bad selection");
            expect(r, 450, "bound core");
            dBoundCore(r, m);
            return m;
        });
        expect(r, 460, "validity");
        long nb = r.integer(), na = r.integer(), mi = r.integer();
        Map<String, Object> validity = G.map("notBefore", G.num(nb), "notAfter", G.num(na), "maxIdle", G.num(mi));
        expect(r, 461, "delegation");
        long md = r.integer(); boolean no = r.integer() == 1; List<Object> mt = r.strs();
        Map<String, Object> deleg = G.map("maxDepth", G.num(md), "narrowOnly", no, "mayTouch", mt);
        List<Object> escalateOn = r.list(() -> dCond(r));
        List<Object> wildcardAck = r.strs();
        List<Object> holes = r.list(() -> {
            expect(r, 470, "hole");
            String hid = r.str(), q = r.str(); List<Object> dom = r.strs(); List<Object> aff = r.strs(); boolean gl = r.integer() == 1;
            return G.map("hid", hid, "q", q, "domain", dom, "affects", aff, "global", gl);
        });
        if (!r.done()) throw new IrError("trailing tokens after goal");
        Map<String, Object> g = new LinkedHashMap<>();
        g.put("v", G.num(v)); g.put("principal", principal); g.put("ontDigest", ontDigest); g.put("nlDigest", nlDigest); g.put("sources", sources);
        g.put("grants", grants); g.put("prohibits", prohibits); g.put("bounds", bounds); g.put("validity", validity); g.put("deleg", deleg);
        g.put("escalateOn", escalateOn); g.put("wildcardAck", wildcardAck); g.put("holes", holes);
        return g;
    }
}
