package net.atlasauth.pca;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Goal IR reference semantics for the shared goal vectors: canonical form and digests, the ternary decision of a
 * goal over an action and its history (with the admitting witness), the lowered policy digest, and the helper
 * functions (meet, pep, units, polarity, commit, claim). Values are the {@link Json} tree (Map, List, String,
 * {@link Json.Num}, Boolean, null). Truth values are Kleene 0/1/2 (false/unknown/true), decisions 0/1/2
 * (deny/escalate/allow); meet is the minimum, so an escalate never becomes an allow. Every number in the corpus is an
 * integer; quantities are compared exactly (BigInteger).
 */
public final class GoalSemantics {
    private GoalSemantics() {}

    // ---- canonical form and digests ----
    /** Canonical text: sorted keys (UTF-8 byte order), integers as written, only the short escapes plus \\u00XX below 0x20. */
    public static String canon(Object v) {
        StringBuilder sb = new StringBuilder();
        canon(sb, v);
        return sb.toString();
    }

    private static void canon(StringBuilder sb, Object v) {
        if (v == null) sb.append("null");
        else if (v instanceof Boolean) sb.append(((Boolean) v) ? "true" : "false");
        else if (v instanceof Json.Num || v instanceof Integer || v instanceof Long) sb.append(v.toString());
        else if (v instanceof String) quote(sb, (String) v);
        else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                canon(sb, x);
            }
            sb.append(']');
        } else if (v instanceof Map) {
            List<String> ks = new ArrayList<>();
            for (Object k : ((Map<?, ?>) v).keySet()) ks.add((String) k);
            ks.sort(Json::compareUtf8);
            sb.append('{');
            boolean first = true;
            for (String k : ks) {
                if (!first) sb.append(',');
                first = false;
                quote(sb, k);
                sb.append(':');
                canon(sb, ((Map<?, ?>) v).get(k));
            }
            sb.append('}');
        } else throw new IllegalArgumentException("canon: unsupported " + v.getClass().getName());
    }

    private static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\t': sb.append("\\t"); break;
                case '\n': sb.append("\\n"); break;
                case '\f': sb.append("\\f"); break;
                case '\r': sb.append("\\r"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }

    private static String b64(byte[] h) { return Base64.getUrlEncoder().withoutPadding().encodeToString(h); }

    private static byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** base64url(SHA-256(canon(v))). */
    public static String hashCanon(Object v) { return b64(sha256(canon(v))); }

    /** Digest of a goal: hashCanon({"d":"atlas-pca/goal-ir/v1","goal":g}). */
    public static String goalDigest(Object g) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", "atlas-pca/goal-ir/v1");
        m.put("goal", g);
        return hashCanon(m);
    }

    // ---- small value helpers ----
    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static String s(Object o) { return (String) o; }

    private static BigInteger big(Object o) {
        if (o instanceof Json.Num) return new BigInteger(((Json.Num) o).raw);
        return BigInteger.valueOf(((Number) o).longValue());
    }

    private static long lng(Object o) { return big(o).longValueExact(); }

    private static boolean same(Object a, Object b) { return canon(a).equals(canon(b)); }

    private static int b2k(boolean b) { return b ? 2 : 0; }

    private static int kNot(int a) { return 2 - a; }

    // ---- conditions ----
    private static int eqV(Map<String, Object> x, Map<String, Object> y) {
        String k = s(x.get("k"));
        if (k.equals("q")) {
            if (s(y.get("k")).equals("q") && same(m(x.get("q")).get("u"), m(y.get("q")).get("u")))
                return b2k(big(m(x.get("q")).get("n")).equals(big(m(y.get("q")).get("n"))));
            return 1;
        }
        if (k.equals("s")) return s(y.get("k")).equals("s") ? b2k(Objects.equals(x.get("s"), y.get("s"))) : 1;
        return 1;
    }

    private static int ltV(Map<String, Object> x, Map<String, Object> y) {
        if (s(x.get("k")).equals("q") && s(y.get("k")).equals("q") && same(m(x.get("q")).get("u"), m(y.get("q")).get("u")))
            return b2k(big(m(x.get("q")).get("n")).compareTo(big(m(y.get("q")).get("n"))) < 0);
        return 1;
    }

    private static int cmp(String op, Map<String, Object> x, Map<String, Object> y) {
        if (x == null || y == null) return 1;
        switch (op) {
            case "eq": return eqV(x, y);
            case "ne": return kNot(eqV(x, y));
            case "lt": return ltV(x, y);
            case "gte": return kNot(ltV(x, y));
            case "gt": return ltV(y, x);
            case "lte": return kNot(ltV(y, x));
            default:
        }
        int t = 1;
        if (s(y.get("k")).equals("set")) {
            t = 0;
            for (Object it : l(y.get("items"))) t = Math.max(t, eqV(x, m(it)));
        }
        return op.equals("in") ? t : kNot(t);
    }

    private static Map<String, Object> term(Map<String, Object> t, Map<String, Object> a, Map<String, Object> h) {
        String k = s(t.get("k"));
        if (k.equals("param")) return m(m(a.get("params")).get(s(t.get("path"))));
        if (k.equals("lit")) return m(t.get("v"));
        Object q = m(h.get("aggs")).get(s(t.get("bid")));
        if (q == null) return null;
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("k", "q");
        r.put("q", q);
        return r;
    }

    private static int cond(Map<String, Object> c, Map<String, Object> a, Map<String, Object> h) {
        String k = s(c.get("k"));
        switch (k) {
            case "true": return 2;
            case "cmp": return cmp(s(c.get("op")), term(m(c.get("l")), a, h), term(m(c.get("r")), a, h));
            case "and": return Math.min(cond(m(c.get("a")), a, h), cond(m(c.get("b")), a, h));
            case "or": return Math.max(cond(m(c.get("a")), a, h), cond(m(c.get("b")), a, h));
            default: return kNot(cond(m(c.get("c")), a, h));
        }
    }

    // ---- resources, selectors, bounds ----
    private static List<Object> partIds(Map<String, Object> o, Map<String, Object> p) {
        String k = s(p.get("k"));
        if (k.equals("exact")) return Collections.singletonList(p.get("id"));
        if (k.equals("oneof")) return l(p.get("ids"));
        for (Object r : l(o.get("rels"))) {
            Map<String, Object> rr = m(r);
            if (Objects.equals(rr.get("rel"), p.get("rel")) && Objects.equals(rr.get("anchor"), p.get("anchor"))) return l(rr.get("members"));
        }
        return new ArrayList<>();
    }

    /** null = any resource. */
    private static List<Object> resolve(Map<String, Object> o, Map<String, Object> sel) {
        String k = s(sel.get("k"));
        if (k.equals("any")) return null;
        if (!k.equals("all_of")) return partIds(o, sel);
        List<Object> acc = null;
        List<Object> parts = l(sel.get("parts"));
        for (int i = parts.size() - 1; i >= 0; i--) {
            List<Object> ids = partIds(o, m(parts.get(i)));
            if (acc == null) acc = ids;
            else {
                List<Object> out = new ArrayList<>();
                for (Object id : ids) if (acc.contains(id)) out.add(id);
                acc = out;
            }
        }
        return acc;
    }

    private static boolean resOk(List<Object> p, Object r) { return p == null || p.contains(r); }

    private static List<Object> verbsOfClass(Map<String, Object> o, Object cls) {
        List<Object> out = new ArrayList<>();
        for (Object v : l(o.get("verbs"))) if (Objects.equals(m(v).get("cls"), cls)) out.add(m(v).get("verb"));
        return out;
    }

    private static List<Object> prohVerbs(Map<String, Object> o, Map<String, Object> p) {
        Map<String, Object> t = m(p.get("target"));
        if (s(t.get("k")).equals("verb")) return Collections.singletonList(t.get("verb"));
        return verbsOfClass(o, t.get("cls"));
    }

    /** A bound's selector: [gids, verbs]. */
    private static List<List<Object>> lsel(Map<String, Object> o, Map<String, Object> b) {
        Map<String, Object> sel = m(b.get("sel"));
        List<List<Object>> r = new ArrayList<>();
        if (s(sel.get("k")).equals("gids")) {
            r.add(l(sel.get("gids")));
            r.add(new ArrayList<>());
        } else {
            r.add(new ArrayList<>());
            r.add(verbsOfClass(o, sel.get("cls")));
        }
        return r;
    }

    private static boolean applies(List<List<Object>> sel, Object gid, Object verb) {
        return sel.get(0).contains(gid) || sel.get(1).contains(verb);
    }

    private static boolean inScope(Map<String, Object> b, Map<String, Object> a, Map<String, Object> x) {
        Map<String, Object> sc = m(b.get("scope"));
        switch (s(sc.get("k"))) {
            case "session": return Objects.equals(a.get("sess"), x.get("sess"));
            case "principal": return Objects.equals(a.get("prin"), x.get("prin"));
            case "org": return Objects.equals(a.get("org"), x.get("org"));
            default:
                List<Object> ag = l(sc.get("agents"));
                return ag.contains(a.get("agent")) && ag.contains(x.get("agent"));
        }
    }

    private static boolean inWindow(Map<String, Object> w, Map<String, Object> a, Map<String, Object> x) {
        long at = lng(a.get("t")), xt = lng(x.get("t"));
        String k = s(w.get("k"));
        if (k.equals("sliding")) return at - lng(w.get("ms")) < xt && xt <= at;
        if (k.equals("period")) {
            long ms = lng(w.get("ms")), t0 = lng(w.get("t0"));
            return ms > 0 && Math.floorDiv(at - t0, ms) == Math.floorDiv(xt - t0, ms);
        }
        return true;
    }

    private static int exceeded(Map<String, Object> b, List<List<Object>> sel, Map<String, Object> a, Map<String, Object> h) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (Object mm : l(h.get("adms"))) {
            Map<String, Object> act = m(m(mm).get("act"));
            if (applies(sel, m(mm).get("gid"), act.get("verb")) && inScope(b, a, act) && inWindow(m(b.get("window")), a, act)) items.add(act);
        }
        items.add(a);
        String agg = s(b.get("agg"));
        BigInteger cap = big(m(b.get("cap")).get("n"));
        if (agg.equals("count")) return b2k(BigInteger.valueOf(items.size()).compareTo(cap) > 0);
        if (agg.equals("distinct")) {
            Set<String> vs = new LinkedHashSet<>();
            for (Map<String, Object> x : items) {
                Map<String, Object> ps = m(x.get("params"));
                if (!ps.containsKey(s(b.get("key")))) return 1;
                vs.add(canon(ps.get(s(b.get("key")))));
            }
            return b2k(BigInteger.valueOf(vs.size()).compareTo(cap) > 0);
        }
        BigInteger sum = BigInteger.ZERO, max = null;
        for (Map<String, Object> x : items) {
            Map<String, Object> v = term(m(b.get("value")), x, h);
            if (v == null || !s(v.get("k")).equals("q") || !same(m(v.get("q")).get("u"), m(b.get("cap")).get("u"))) return 1;
            BigInteger n = big(m(v.get("q")).get("n"));
            sum = sum.add(n);
            if (max == null || n.compareTo(max) > 0) max = n;
        }
        return b2k((agg.equals("sum") ? sum : max).compareTo(cap) > 0);
    }

    private static int boundDec(Map<String, Object> b, List<List<Object>> sel, Map<String, Object> a, Map<String, Object> h) {
        int e = exceeded(b, sel, a, h);
        if (e == 2) return s(b.get("onExceed")).equals("deny") ? 0 : 1;
        return e == 1 ? 1 : 2;
    }

    /** The goal with every hole's affected grants removed (a global hole removes all) and the holes cleared. */
    private static Map<String, Object> strip(Map<String, Object> g) {
        Map<String, Object> r = new LinkedHashMap<>(g);
        r.put("holes", new ArrayList<>());
        List<Object> keep = new ArrayList<>();
        for (Object gr : l(g.get("grants"))) {
            boolean drop = false;
            for (Object ho : l(g.get("holes"))) {
                Map<String, Object> hh = m(ho);
                if (Boolean.TRUE.equals(hh.get("global")) || l(hh.get("affects")).contains(m(gr).get("gid"))) drop = true;
            }
            if (!drop) keep.add(gr);
        }
        r.put("grants", keep);
        return r;
    }

    private static int grantDec(Map<String, Object> g, Map<String, Object> o, Map<String, Object> gr, Map<String, Object> a, Map<String, Object> h) {
        boolean delegOk = lng(a.get("depth")) == 0 || l(m(g.get("deleg")).get("mayTouch")).contains(gr.get("gid"));
        int r = Math.min(b2k(Objects.equals(a.get("verb"), gr.get("verb")) && delegOk), b2k(resOk(resolve(o, m(gr.get("res"))), a.get("res"))));
        r = Math.min(r, cond(m(gr.get("cond")), a, h));
        for (Object bo : l(g.get("bounds"))) {
            Map<String, Object> b = m(bo);
            List<List<Object>> sel = lsel(o, b);
            if (applies(sel, gr.get("gid"), a.get("verb"))) r = Math.min(r, boundDec(b, sel, a, h));
        }
        return r;
    }

    private static Map<String, Object> verdict(String d, Object witness) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("decision", d);
        r.put("witness", witness);
        return r;
    }

    /** Decision of {@code goal} over {@code action} given {@code history}: {decision, witness}. */
    public static Map<String, Object> decide(Map<String, Object> goalIn, Map<String, Object> o, Map<String, Object> a, Map<String, Object> h) {
        Map<String, Object> g = strip(goalIn);
        Map<String, Object> v = m(g.get("validity"));
        long at = lng(a.get("t")), depth = lng(a.get("depth"));
        int d = 2;
        if (at < lng(v.get("notBefore")) || at > lng(v.get("notAfter"))) d = 0;
        else if (lng(v.get("maxIdle")) > 0 && lng(h.get("last")) >= 0 && at - lng(h.get("last")) > lng(v.get("maxIdle"))) d = 0;
        else if (depth < 0 || depth > lng(m(g.get("deleg")).get("maxDepth"))) d = 0;
        for (Object po : l(g.get("prohibits"))) {
            Map<String, Object> p = m(po);
            int mm = Math.min(b2k(prohVerbs(o, p).contains(a.get("verb"))), b2k(resOk(resolve(o, m(p.get("res"))), a.get("res"))));
            mm = Math.min(mm, cond(m(p.get("cond")), a, h));
            d = Math.min(d, mm == 2 ? 0 : (mm == 1 ? 1 : 2));
        }
        for (Object c : l(g.get("escalateOn"))) d = Math.min(d, cond(m(c), a, h) == 0 ? 2 : 1);
        int best = 0, idx = -1;
        List<Object> grants = l(g.get("grants"));
        for (int i = 0; i < grants.size(); i++) {
            int x = grantDec(g, o, m(grants.get(i)), a, h);
            if (x > best) best = x;
            if (x == 2 && idx < 0) idx = i;
        }
        d = Math.min(d, grants.isEmpty() ? 0 : best);
        if (d != 2) return verdict(d == 1 ? "escalate" : "deny", null);
        Map<String, Object> gr = m(grants.get(idx));
        List<Object> bids = new ArrayList<>();
        for (Object bo : l(g.get("bounds"))) if (applies(lsel(o, m(bo)), gr.get("gid"), a.get("verb"))) bids.add(m(bo).get("bid"));
        Map<String, Object> w = new LinkedHashMap<>();
        w.put("gid", gr.get("gid"));
        w.put("bids", bids);
        return verdict("allow", w);
    }

    // ---- lowering (policy digest) ----
    private static final Map<String, String> NEG = new LinkedHashMap<>();
    static {
        NEG.put("eq", "ne"); NEG.put("ne", "eq"); NEG.put("lt", "gte"); NEG.put("gte", "lt");
        NEG.put("gt", "lte"); NEG.put("lte", "gt"); NEG.put("in", "nin"); NEG.put("nin", "in");
    }

    private static Map<String, Object> node(String k) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("k", k);
        return r;
    }

    private static Map<String, Object> nnf(Map<String, Object> c, boolean pos) {
        String k = s(c.get("k"));
        switch (k) {
            case "true": return node(pos ? "true" : "false");
            case "cmp": {
                Map<String, Object> r = node("atom");
                r.put("op", pos ? c.get("op") : NEG.get(s(c.get("op"))));
                r.put("l", c.get("l"));
                r.put("r", c.get("r"));
                return r;
            }
            case "and":
            case "or": {
                boolean and = k.equals("and") == pos;
                Map<String, Object> r = node(and ? "and" : "or");
                r.put("a", nnf(m(c.get("a")), pos));
                r.put("b", nnf(m(c.get("b")), pos));
                return r;
            }
            default: return nnf(m(c.get("c")), !pos);
        }
    }

    private static Map<String, Object> pat(List<Object> p) {
        if (p == null) return node("star");
        Map<String, Object> r = node("set");
        r.put("ids", p);
        return r;
    }

    /** The lowered policy of a goal (GoalCompile Lower); its hashCanon is the policy digest. */
    public static Map<String, Object> lower(Map<String, Object> o, Map<String, Object> goalIn) {
        Map<String, Object> g = strip(goalIn);
        List<Object> ceils = new ArrayList<>();
        for (Object bo : l(g.get("bounds"))) {
            Map<String, Object> b = m(bo);
            List<List<Object>> sel = lsel(o, b);
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("bid", b.get("bid"));
            c.put("selGids", sel.get(0));
            c.put("selVerbs", sel.get(1));
            for (String k : new String[] {"agg", "value", "key", "window", "scope", "cap", "onExceed"}) c.put(k, b.get(k));
            ceils.add(c);
        }
        List<Object> preds = new ArrayList<>();
        for (Object xo : l(g.get("grants"))) {
            Map<String, Object> x = m(xo), p = new LinkedHashMap<>();
            p.put("gid", x.get("gid"));
            p.put("verb", x.get("verb"));
            p.put("res", pat(resolve(o, m(x.get("res")))));
            p.put("cond", nnf(m(x.get("cond")), true));
            preds.add(p);
        }
        List<Object> prohs = new ArrayList<>();
        for (Object po : l(g.get("prohibits"))) {
            Map<String, Object> x = m(po), p = new LinkedHashMap<>();
            p.put("pid", x.get("pid"));
            p.put("verbs", prohVerbs(o, x));
            p.put("res", pat(resolve(o, m(x.get("res")))));
            p.put("cond", nnf(m(x.get("cond")), true));
            prohs.add(p);
        }
        List<Object> escs = new ArrayList<>();
        for (Object c : l(g.get("escalateOn"))) escs.add(nnf(m(c), true));
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("preds", preds);
        r.put("prohs", prohs);
        r.put("ceils", ceils);
        r.put("escs", escs);
        r.put("validity", g.get("validity"));
        r.put("deleg", g.get("deleg"));
        return r;
    }

    /** Policy digest of a goal under an ontology. */
    public static String policyDigest(Map<String, Object> o, Map<String, Object> goal) { return hashCanon(lower(o, goal)); }

    // ---- helper functions ----
    private static int rank(String d) {
        switch (d) {
            case "deny": return 0;
            case "escalate": return 1;
            case "allow": return 2;
            default: return -1;
        }
    }

    /** The lower of a decision and a model signal; an unknown signal leaves the decision unchanged. */
    public static String meet(String d, String signal) {
        int rs = rank(signal);
        return rs >= 0 && rs < rank(d) ? signal : d;
    }

    /** True iff the action may proceed: allow; escalate only with a valid answer bound to the policy, action and history head. */
    public static boolean pep(String decision, Map<String, Object> ctx, Map<String, Object> answer) {
        if (decision.equals("allow")) return true;
        if (decision.equals("deny")) return false;
        if (answer == null || answer.isEmpty() || !Boolean.TRUE.equals(answer.get("valid"))) return false;
        for (String k : new String[] {"policy_digest", "action_digest", "history_head"})
            if (!Objects.equals(answer.get(k), ctx.get(k))) return false;
        return true;
    }

    /** Sorted (UTF-8 order) paths of model-derived parameters read by the conditions. */
    public static List<String> polarity(List<Object> conds) {
        Set<String> out = new LinkedHashSet<>();
        for (Object c : conds) polarityWalk(m(c), out);
        List<String> r = new ArrayList<>(out);
        r.sort(Json::compareUtf8);
        return r;
    }

    private static void polarityWalk(Map<String, Object> c, Set<String> out) {
        String k = s(c.get("k"));
        if (k.equals("and") || k.equals("or")) {
            polarityWalk(m(c.get("a")), out);
            polarityWalk(m(c.get("b")), out);
        } else if (k.equals("not")) polarityWalk(m(c.get("c")), out);
        else if (k.equals("cmp")) {
            for (String side : new String[] {"l", "r"}) {
                Map<String, Object> t = m(c.get(side));
                if (s(t.get("k")).equals("param")) {
                    String p = s(t.get("path"));
                    if (p.startsWith("env.class.") || p.startsWith("env.prov.") || p.startsWith("env.judge.") || p.startsWith("env.world.")) out.add(p);
                }
            }
        }
    }

    /** Sorted paths whose tag in {@code terms} is missing from, or differs from, the schema's. */
    public static List<String> units(Map<String, Object> schema, Map<String, Object> terms) {
        List<String> r = new ArrayList<>();
        for (Map.Entry<String, Object> e : terms.entrySet())
            if (!schema.containsKey(e.getKey()) || !same(schema.get(e.getKey()), e.getValue())) r.add(e.getKey());
        r.sort(Json::compareUtf8);
        return r;
    }

    /** Commitment to (goal digest, policy digest, salt). */
    public static String commit(String goalDigest, String policyDigest, String salt) {
        return b64(sha256("pca-goal:v3:commit:" + goalDigest + ":" + policyDigest + ":" + salt));
    }

    /** A claimed-replay shortfall caps the decision at escalate; no replay measurement leaves it unchanged. */
    public static String claim(String base, BigInteger minPpm, BigInteger replayedPpm) {
        return replayedPpm != null && replayedPpm.compareTo(minPpm) < 0 ? meet(base, "escalate") : base;
    }

    /** Evaluates a fn vector's input; the result is comparable by {@link #canon}. */
    @SuppressWarnings("unchecked")
    public static Object runFn(String fn, Object input) {
        switch (fn) {
            case "canon": {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("canon", canon(input));
                r.put("digest", goalDigest(input));
                return r;
            }
            case "polarity": return new ArrayList<Object>(polarity((List<Object>) input));
            default:
        }
        Map<String, Object> i = m(input);
        switch (fn) {
            case "units": return new ArrayList<Object>(units(m(i.get("schema")), m(i.get("terms"))));
            case "meet": return meet(s(i.get("decision")), s(i.get("signal")));
            case "pep": return pep(s(i.get("decision")), m(i.get("ctx")), m(i.get("answer")));
            case "commit": {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("commit", commit(s(i.get("goal_digest")), s(i.get("policy_digest")), s(i.get("salt"))));
                r.put("opens_other_goal", Boolean.FALSE);
                return r;
            }
            case "claim": return claim(s(i.get("base")), big(i.get("min_ppm")), i.get("replayed_ppm") == null ? null : big(i.get("replayed_ppm")));
            default: throw new IllegalArgumentException("unknown fn " + fn);
        }
    }
}
