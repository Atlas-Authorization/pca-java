package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for {@link GoalSemantics}: a differential test against the independent shared goal runner
 * (net.atlasauth.pca.goalrunner.Run, the generated copy of the cross-language reference) over GENERATED variants of every goal
 * and selector-goal vector: each condition negated / or-ed / re-operated / swapped / reading an aggregate, every bound's cap,
 * aggregate, window, scope, selector and value, holes, duplicated grants, every resource selector kind, added prohibitions and
 * escalations; and of every probe: clock and depth at the validity edges, idle time, verb, resource, every parameter retyped /
 * re-valued / deleted, the history's admissions moved across window edges and out of scope, and aggregates. The full decision
 * (with its witness), the lowered policy (canonical text and digest) and the goal digest must agree exactly. GoalSemantics runs
 * twice: on the strict parser's tree (Json.Num) and on the reference parser's tree (Long), so both number forms are covered.
 * The helper functions (meet, pep, units, polarity, canon, commit, claim) are compared over their own generated inputs.
 */
public class GoalSemanticsDiffTest {
    // ---- the reference runner, by reflection (its members are package-private in another package) ----
    static final Method R_DECIDE, R_LOWER, R_CANON, R_HASH, R_GOAL_DIGEST, R_RUNFN, P_VAL;
    static final Constructor<?> P_NEW;

    static {
        try {
            Class<?> run = Class.forName("net.atlasauth.pca.goalrunner.Run");
            Class<?> p = Class.forName("net.atlasauth.pca.goalrunner.Run$P");
            R_DECIDE = run.getDeclaredMethod("decide", Map.class, Map.class, Map.class, Map.class);
            R_LOWER = run.getDeclaredMethod("lower", Map.class, Map.class);
            R_CANON = run.getDeclaredMethod("canon", Object.class);
            R_HASH = run.getDeclaredMethod("hashCanon", Object.class);
            R_GOAL_DIGEST = run.getDeclaredMethod("goalDigest", Object.class);
            R_RUNFN = run.getDeclaredMethod("runFn", Map.class);
            P_NEW = p.getDeclaredConstructor(String.class);
            P_VAL = p.getDeclaredMethod("val");
            for (Method m : new Method[] {R_DECIDE, R_LOWER, R_CANON, R_HASH, R_GOAL_DIGEST, R_RUNFN, P_VAL}) m.setAccessible(true);
            P_NEW.setAccessible(true);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    static final String THROWS = "<throws>";

    static Object call(Method m, Object... args) throws Throwable {
        try {
            return m.invoke(null, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    /** The reference parser's tree (integers as Long). */
    static Object refTree(String text) {
        try {
            return P_VAL.invoke(P_NEW.newInstance(text));
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    static String refCanon(Object v) {
        try {
            return (String) call(R_CANON, v);
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    // ---- tree helpers ----
    @SuppressWarnings("unchecked")
    static Map<String, Object> M(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Object> L(Object o) { return (List<Object>) o; }

    static Object copy(Object v) {
        if (v instanceof Map) {
            Map<String, Object> r = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : M(v).entrySet()) r.put(e.getKey(), copy(e.getValue()));
            return r;
        }
        if (v instanceof List) {
            List<Object> r = new ArrayList<>();
            for (Object x : L(v)) r.add(copy(x));
            return r;
        }
        return v;
    }

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    static Json.Num n(long x) { return new Json.Num(Long.toString(x)); }

    static long lv(Object o) { return Json.asLong(o); }

    static Object getAt(Object root, List<Object> path) {
        Object v = root;
        for (Object k : path) v = k instanceof Integer ? L(v).get((Integer) k) : M(v).get((String) k);
        return v;
    }

    /** A deep copy of root with the node at path replaced (DEL removes a member). */
    static Object setAt(Object root, List<Object> path, Object val) {
        Object r = copy(root);
        Object parent = getAt(r, path.subList(0, path.size() - 1));
        Object k = path.get(path.size() - 1);
        if (k instanceof Integer) L(parent).set((Integer) k, val);
        else if (val == DEL) M(parent).remove(k);
        else M(parent).put((String) k, val);
        return r;
    }

    static final Object DEL = new Object();

    static List<Object> p(Object... ks) { return Arrays.asList(ks); }

    static List<Object> cat(List<Object> a, Object... more) {
        List<Object> r = new ArrayList<>(a);
        r.addAll(Arrays.asList(more));
        return r;
    }

    // ---- the corpus ----
    static final class Vec {
        final String id;
        final Map<String, Object> goal, ont;
        final List<Map<String, Object>> probes = new ArrayList<>();
        Vec(String id, Map<String, Object> goal, Map<String, Object> ont) { this.id = id; this.goal = goal; this.ont = ont; }
    }

    static List<Map<String, Object>> files(Path dir) throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        try (Stream<Path> st = Files.list(dir)) {
            for (Path f : st.sorted().collect(Collectors.toList())) {
                String n = f.getFileName().toString();
                if (!n.endsWith(".json") || n.equals("index.json")) continue;
                out.add(M(Json.parseLenient(Files.readString(f, StandardCharsets.UTF_8))));
            }
        }
        return out;
    }

    static List<Vec> VECS;
    static List<Map<String, Object>> FNS;

    static synchronized List<Vec> vecs() throws Exception {
        if (VECS != null) return VECS;
        List<Vec> out = new ArrayList<>();
        List<Map<String, Object>> fns = new ArrayList<>();
        Path goalDir = GoalRunner.locate();
        for (Path d : List.of(goalDir, goalDir.resolveSibling("goal-select"))) {
            for (Map<String, Object> v : files(d)) {
                if ("fn".equals(v.get("kind"))) {
                    fns.add(v);
                    continue;
                }
                if (!Boolean.TRUE.equals(M(v.get("compile")).get("ok"))) continue;
                Vec x = new Vec((String) v.get("id"), M(v.get("goal")), M(v.get("ontology")));
                for (Object pr : L(v.get("probes"))) x.probes.add(M(pr));
                out.add(x);
            }
        }
        assertTrue(out.size() > 150, "goal vectors: " + out.size());
        assertTrue(fns.size() >= 40, "fn vectors: " + fns.size());
        FNS = fns;
        VECS = out;
        return out;
    }

    /** Seed probes: the first, and the first two that carry admissions. */
    static List<Map<String, Object>> seeds(Vec v, int max) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (!v.probes.isEmpty()) out.add(v.probes.get(0));
        for (Map<String, Object> pr : v.probes) {
            if (out.size() >= max) break;
            if (!L(M(pr.get("history")).get("adms")).isEmpty() && !out.contains(pr)) out.add(pr);
        }
        if (out.size() < max && v.probes.size() > 1 && !out.contains(v.probes.get(v.probes.size() - 1))) out.add(v.probes.get(v.probes.size() - 1));
        return out;
    }

    // ---- comparison ----
    /** A value rendered once and parsed once per number form (neither implementation mutates its inputs). */
    static final class Doc {
        final String text;
        private Object num, ref;
        Doc(Object v) { text = Json.canonicalize(v); }
        @SuppressWarnings("unchecked")
        Map<String, Object> num() {
            if (num == null) num = Json.parseLenient(text);
            return (Map<String, Object>) num;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> ref() {
            if (ref == null) ref = refTree(text);
            return (Map<String, Object>) ref;
        }
    }

    static final class Diff {
        final List<String> bad = new ArrayList<>();
        int n;

        void decide(String label, Object goal, Object ont, Object action, Object history) {
            decide(label, new Doc(goal), new Doc(ont), new Doc(action), new Doc(history));
        }

        void decide(String label, Doc g, Doc o, Doc a, Doc h) {
            n++;
            String want;
            try {
                want = refCanon(call(R_DECIDE, g.ref(), o.ref(), a.ref(), h.ref()));
            } catch (Throwable t) {
                want = THROWS;
            }
            String num, lng;
            try {
                num = GoalSemantics.canon(GoalSemantics.decide(g.num(), o.num(), a.num(), h.num()));
            } catch (RuntimeException e) {
                num = THROWS;
            }
            try {
                lng = GoalSemantics.canon(GoalSemantics.decide(g.ref(), o.ref(), a.ref(), h.ref()));
            } catch (RuntimeException e) {
                lng = THROWS;
            }
            if (!want.equals(num) || !want.equals(lng)) add(label + ": want " + want + " got " + num + " / " + lng);
        }

        void add(String s) {
            bad.add(s);
            if (bad.size() >= 40) report(); // enough evidence: stop early
        }

        void lower(String label, Object goal, Object ont) {
            n++;
            String gt = Json.canonicalize(goal), ot = Json.canonicalize(ont);
            String want, wantDigest, wantGoal;
            try {
                Object low = call(R_LOWER, refTree(ot), refTree(gt));
                want = refCanon(low);
                wantDigest = (String) call(R_HASH, low);
                wantGoal = (String) call(R_GOAL_DIGEST, refTree(gt));
            } catch (Throwable t) {
                want = THROWS;
                wantDigest = THROWS;
                wantGoal = THROWS;
            }
            for (int form = 0; form < 2; form++) {
                Map<String, Object> g = M(form == 0 ? Json.parseLenient(gt) : refTree(gt)), o = M(form == 0 ? Json.parseLenient(ot) : refTree(ot));
                String got, gotDigest, gotGoal;
                try {
                    got = GoalSemantics.canon(GoalSemantics.lower(o, g));
                    gotDigest = GoalSemantics.policyDigest(o, g);
                    gotGoal = GoalSemantics.goalDigest(g);
                } catch (RuntimeException e) {
                    got = THROWS;
                    gotDigest = THROWS;
                    gotGoal = THROWS;
                }
                if (!want.equals(got) || !wantDigest.equals(gotDigest) || !wantGoal.equals(gotGoal))
                    add(label + " lower[" + form + "]: want " + want + " got " + got);
            }
        }

        void fn(String label, String fn, Object input) {
            n++;
            String t = Json.canonicalize(obj("fn", fn, "input", input));
            String want;
            try {
                want = refCanon(call(R_RUNFN, M(refTree(t))));
            } catch (Throwable e) {
                want = THROWS;
            }
            for (int form = 0; form < 2; form++) {
                Object in = M(form == 0 ? Json.parseLenient(t) : refTree(t)).get("input");
                String got;
                try {
                    got = GoalSemantics.canon(GoalSemantics.runFn(fn, in));
                } catch (RuntimeException e) {
                    got = THROWS;
                }
                if (!want.equals(got)) add(label + "[" + form + "]: want " + want + " got " + got);
            }
        }

        void report() {
            if (!bad.isEmpty()) fail(bad.size() + "/" + n + " disagreements:\n" + String.join("\n", bad.subList(0, Math.min(40, bad.size()))));
        }
    }

    // ---- goal variants ----
    static final List<String> OPS = List.of("eq", "ne", "lt", "gte", "gt", "lte", "in", "nin");
    static final Map<String, Object> TRUE = obj("k", "true");

    static Map<String, Object> not(Object c) { return obj("k", "not", "c", copy(c)); }

    static Map<String, Object> bin(String k, Object a, Object b) { return obj("k", k, "a", copy(a), "b", copy(b)); }

    static void condPaths(Object goal, List<Object> path, List<List<Object>> out) {
        out.add(path);
        Map<String, Object> c = M(getAt(goal, path));
        String k = (String) c.get("k");
        if ("and".equals(k) || "or".equals(k)) {
            condPaths(goal, cat(path, "a"), out);
            condPaths(goal, cat(path, "b"), out);
        } else if ("not".equals(k)) condPaths(goal, cat(path, "c"), out);
    }

    static List<String> bids(Map<String, Object> goal) {
        List<String> r = new ArrayList<>();
        for (Object b : L(goal.get("bounds"))) r.add((String) M(b).get("bid"));
        return r;
    }

    static List<Object[]> goalVariants(Map<String, Object> g, Map<String, Object> ont, Map<String, Object> action) {
        List<Object[]> out = new ArrayList<>();
        List<List<Object>> cps = new ArrayList<>();
        for (int i = 0; i < L(g.get("grants")).size(); i++) condPaths(g, p("grants", i, "cond"), cps);
        for (int i = 0; i < L(g.get("prohibits")).size(); i++) condPaths(g, p("prohibits", i, "cond"), cps);
        for (int i = 0; i < L(g.get("escalateOn")).size(); i++) condPaths(g, p("escalateOn", i), cps);
        for (List<Object> cp : cps) {
            Map<String, Object> c = M(getAt(g, cp));
            String at = cp.toString(), k = (String) c.get("k");
            out.add(new Object[] {at + " not", setAt(g, cp, not(c))});
            out.add(new Object[] {at + " not not", setAt(g, cp, not(not(c)))});
            out.add(new Object[] {at + " or not", setAt(g, cp, bin("or", c, not(c)))});
            out.add(new Object[] {at + " not-true or", setAt(g, cp, bin("or", not(TRUE), c))});
            out.add(new Object[] {at + " and true", setAt(g, cp, bin("and", c, TRUE))});
            out.add(new Object[] {at + " or not-true", setAt(g, cp, bin("or", c, not(TRUE)))});
            if ("and".equals(k) || "or".equals(k)) {
                Map<String, Object> sw = M(copy(c));
                sw.put("k", "and".equals(k) ? "or" : "and");
                out.add(new Object[] {at + " swapped", setAt(g, cp, sw)});
            }
            if ("cmp".equals(k)) {
                for (String op : OPS) {
                    if (op.equals(c.get("op"))) continue;
                    Map<String, Object> x = M(copy(c));
                    x.put("op", op);
                    out.add(new Object[] {at + " op " + op, setAt(g, cp, x)});
                }
                Map<String, Object> sw = M(copy(c));
                sw.put("l", copy(c.get("r")));
                sw.put("r", copy(c.get("l")));
                out.add(new Object[] {at + " l<->r", setAt(g, cp, sw)});
                for (String bid : bids(g)) {
                    for (String side : new String[] {"l", "r"}) {
                        Map<String, Object> x = M(copy(c));
                        x.put(side, obj("k", "agg", "bid", bid));
                        out.add(new Object[] {at + " " + side + "=agg " + bid, setAt(g, cp, x)});
                    }
                }
            }
        }
        // added conditions over aggregates (the corpus has none)
        for (String bid : bids(g)) {
            Map<String, Object> cap = M(M(L(g.get("bounds")).get(bids(g).indexOf(bid))).get("cap"));
            Map<String, Object> lit = obj("k", "lit", "v", obj("k", "q", "q", copy(cap)));
            for (String op : List.of("lt", "gte", "eq")) {
                Map<String, Object> c = obj("k", "cmp", "op", op, "l", obj("k", "agg", "bid", bid), "r", lit);
                out.add(new Object[] {"esc agg " + bid + " " + op, setAt(g, p("escalateOn"), list(c))});
                if (!L(g.get("grants")).isEmpty()) out.add(new Object[] {"grant agg " + bid + " " + op, setAt(g, p("grants", 0, "cond"), c)});
            }
        }
        out.add(new Object[] {"esc true", setAt(g, p("escalateOn"), list(TRUE))});
        out.add(new Object[] {"esc not-true", setAt(g, p("escalateOn"), list(not(TRUE)))});
        // validity and delegation
        Map<String, Object> val = M(g.get("validity"));
        for (long mi : new long[] {1, 1000}) out.add(new Object[] {"maxIdle " + mi, setAt(g, p("validity", "maxIdle"), n(mi))});
        long t = lv(action.get("t"));
        out.add(new Object[] {"notBefore t", setAt(g, p("validity", "notBefore"), n(t))});
        out.add(new Object[] {"notBefore t+1", setAt(g, p("validity", "notBefore"), n(t + 1))});
        out.add(new Object[] {"notAfter t", setAt(g, p("validity", "notAfter"), n(t))});
        out.add(new Object[] {"notAfter t-1", setAt(g, p("validity", "notAfter"), n(t - 1))});
        assertNotNull(val);
        long md = lv(M(g.get("deleg")).get("maxDepth"));
        out.add(new Object[] {"maxDepth -1", setAt(g, p("deleg", "maxDepth"), n(md - 1))});
        out.add(new Object[] {"maxDepth +1", setAt(g, p("deleg", "maxDepth"), n(md + 1))});
        out.add(new Object[] {"maxDepth 0", setAt(g, p("deleg", "maxDepth"), n(0))});
        List<Object> gids = new ArrayList<>();
        for (Object gr : L(g.get("grants"))) gids.add(M(gr).get("gid"));
        out.add(new Object[] {"mayTouch none", setAt(g, p("deleg", "mayTouch"), list())});
        out.add(new Object[] {"mayTouch all", setAt(g, p("deleg", "mayTouch"), copy(gids))});
        // holes
        out.add(new Object[] {"hole global", setAt(g, p("holes"), list(obj("global", Boolean.TRUE, "affects", list())))});
        if (!gids.isEmpty()) {
            out.add(new Object[] {"hole first", setAt(g, p("holes"), list(obj("global", Boolean.FALSE, "affects", list(gids.get(0)))))});
            out.add(new Object[] {"hole other", setAt(g, p("holes"), list(obj("affects", list("zz"))))});
            // a later grant with the same rule: the witness is the first admitting grant
            Map<String, Object> dup = M(copy(L(g.get("grants")).get(0)));
            dup.put("gid", "zz");
            List<Object> gs = L(copy(g.get("grants")));
            gs.add(dup);
            out.add(new Object[] {"dup grant", setAt(g, p("grants"), gs)});
            List<Object> gs2 = L(copy(g.get("grants")));
            gs2.add(0, dup);
            out.add(new Object[] {"dup grant first", setAt(g, p("grants"), gs2)});
            Map<String, Object> deny = M(copy(dup));
            deny.put("cond", not(TRUE));
            List<Object> gs3 = L(copy(g.get("grants")));
            gs3.add(0, deny);
            out.add(new Object[] {"denying grant first", setAt(g, p("grants"), gs3)});
        }
        out.add(new Object[] {"no grants", setAt(g, p("grants"), list())});
        // resource selectors
        Object res = action.get("res");
        List<Object> rels = L(ont.get("rels"));
        List<Object[]> sels = new ArrayList<>();
        sels.add(new Object[] {"any", obj("k", "any")});
        sels.add(new Object[] {"exact", obj("k", "exact", "id", res)});
        sels.add(new Object[] {"exact other", obj("k", "exact", "id", "zz")});
        sels.add(new Object[] {"oneof", obj("k", "oneof", "ids", list("zz", res))});
        sels.add(new Object[] {"oneof other", obj("k", "oneof", "ids", list("zz"))});
        if (rels != null && !rels.isEmpty()) {
            Map<String, Object> r0 = M(rels.get(0));
            sels.add(new Object[] {"related", obj("k", "related", "rel", r0.get("rel"), "anchor", r0.get("anchor"))});
            sels.add(new Object[] {"related other anchor", obj("k", "related", "rel", r0.get("rel"), "anchor", "zz")});
            sels.add(new Object[] {"related other rel", obj("k", "related", "rel", "zz", "anchor", r0.get("anchor"))});
            List<Object> members = L(r0.get("members"));
            if (!members.isEmpty()) {
                sels.add(new Object[] {"all_of", obj("k", "all_of", "parts", list(obj("k", "related", "rel", r0.get("rel"), "anchor", r0.get("anchor")),
                    obj("k", "oneof", "ids", list(members.get(0), "zz", res))))});
                sels.add(new Object[] {"all_of disjoint", obj("k", "all_of", "parts", list(obj("k", "exact", "id", res), obj("k", "oneof", "ids", list("zz"))))});
            }
        }
        sels.add(new Object[] {"all_of exact", obj("k", "all_of", "parts", list(obj("k", "exact", "id", res), obj("k", "oneof", "ids", list(res, "zz"))))});
        for (Object[] s : sels) {
            if (!gids.isEmpty()) out.add(new Object[] {"grant res " + s[0], setAt(g, p("grants", 0, "res"), s[1])});
            Map<String, Object> pr = obj("pid", "zz", "target", obj("k", "verb", "verb", action.get("verb")), "res", s[1], "cond", TRUE);
            out.add(new Object[] {"proh res " + s[0], setAt(g, p("prohibits"), list(pr))});
        }
        // prohibitions: by verb, by class, conditional
        String cls = null;
        for (Object v : L(ont.get("verbs"))) if (M(v).get("verb").equals(action.get("verb"))) cls = (String) M(v).get("cls");
        Map<String, Object> any = obj("k", "any");
        out.add(new Object[] {"proh cls", setAt(g, p("prohibits"), list(obj("pid", "zz", "target", obj("k", "effect", "cls", cls), "res", any, "cond", TRUE)))});
        out.add(new Object[] {"proh other cls", setAt(g, p("prohibits"), list(obj("pid", "zz", "target", obj("k", "effect", "cls", "zz"), "res", any, "cond", TRUE)))});
        out.add(new Object[] {"proh other verb", setAt(g, p("prohibits"), list(obj("pid", "zz", "target", obj("k", "verb", "verb", "zz"), "res", any, "cond", TRUE)))});
        out.add(new Object[] {"proh false", setAt(g, p("prohibits"), list(obj("pid", "zz", "target", obj("k", "verb", "verb", action.get("verb")), "res", any, "cond", not(TRUE))))});
        if (!gids.isEmpty()) {
            Object gc = M(L(g.get("grants")).get(0)).get("cond");
            out.add(new Object[] {"proh grant cond", setAt(g, p("prohibits"), list(obj("pid", "zz", "target", obj("k", "verb", "verb", action.get("verb")), "res", any, "cond", copy(gc))))});
        }
        // bounds
        List<Object> bounds = L(g.get("bounds"));
        List<String> qpaths = new ArrayList<>(), allPaths = new ArrayList<>(M(action.get("params")).keySet());
        for (Map.Entry<String, Object> e : M(action.get("params")).entrySet()) if ("q".equals(M(e.getValue()).get("k"))) qpaths.add(e.getKey());
        for (int i = 0; i < bounds.size(); i++) {
            Map<String, Object> b = M(bounds.get(i));
            String at = "bound " + i + " ";
            long cn = lv(M(b.get("cap")).get("n"));
            for (long x : new long[] {0, cn - 1, cn + 1, 1, 2}) out.add(new Object[] {at + "cap " + x, setAt(g, p("bounds", i, "cap", "n"), n(x))});
            out.add(new Object[] {at + "cap unit", setAt(g, p("bounds", i, "cap", "u"), obj("k", "zz"))});
            for (String agg : List.of("count", "sum", "max", "distinct")) {
                if (agg.equals(b.get("agg"))) continue;
                Object v = setAt(g, p("bounds", i, "agg"), agg);
                out.add(new Object[] {at + "agg " + agg, v});
                if (agg.equals("distinct")) for (String k : allPaths) out.add(new Object[] {at + "distinct " + k, setAt(v, p("bounds", i, "key"), k)});
            }
            for (String qp : qpaths) {
                Map<String, Object> qv = M(M(action.get("params")).get(qp));
                Object v = setAt(g, p("bounds", i, "value"), obj("k", "param", "path", qp));
                v = setAt(v, p("bounds", i, "cap", "u"), copy(M(qv.get("q")).get("u")));
                for (String agg : List.of("sum", "max")) {
                    Object w = setAt(v, p("bounds", i, "agg"), agg);
                    long qn = lv(M(qv.get("q")).get("n"));
                    for (long x : new long[] {qn - 1, qn, qn + 1, 2 * qn, 2 * qn - 1}) out.add(new Object[] {at + agg + " " + qp + " cap " + x, setAt(w, p("bounds", i, "cap", "n"), n(x))});
                }
            }
            out.add(new Object[] {at + "onExceed", setAt(g, p("bounds", i, "onExceed"), "deny".equals(b.get("onExceed")) ? "escalate" : "deny")});
            List<Object[]> wins = new ArrayList<>();
            wins.add(new Object[] {"sliding 1000", obj("k", "sliding", "ms", n(1000))});
            wins.add(new Object[] {"sliding 1", obj("k", "sliding", "ms", n(1))});
            wins.add(new Object[] {"sliding 0", obj("k", "sliding", "ms", n(0))});
            wins.add(new Object[] {"period 0", obj("k", "period", "ms", n(0), "t0", n(0))});
            wins.add(new Object[] {"period 1", obj("k", "period", "ms", n(1), "t0", n(0))});
            wins.add(new Object[] {"period 1000", obj("k", "period", "ms", n(1000), "t0", n(t % 1000))});
            wins.add(new Object[] {"period 1000 late t0", obj("k", "period", "ms", n(1000), "t0", n(t + 1))});
            wins.add(new Object[] {"period 1000 t0 t", obj("k", "period", "ms", n(1000), "t0", n(t))});
            wins.add(new Object[] {"period day", obj("k", "period", "ms", n(86400000), "t0", n(0))});
            wins.add(new Object[] {"task", obj("k", "task")});
            for (Object[] w : wins) out.add(new Object[] {at + "window " + w[0], setAt(g, p("bounds", i, "window"), w[1])});
            List<Object[]> scopes = new ArrayList<>();
            scopes.add(new Object[] {"session", obj("k", "session")});
            scopes.add(new Object[] {"principal", obj("k", "principal")});
            scopes.add(new Object[] {"org", obj("k", "org")});
            scopes.add(new Object[] {"fleet self", obj("k", "fleet", "agents", list(action.get("agent")))});
            scopes.add(new Object[] {"fleet other", obj("k", "fleet", "agents", list("zz"))});
            scopes.add(new Object[] {"fleet both", obj("k", "fleet", "agents", list("zz", action.get("agent"), "a1", "a2"))});
            for (Object[] s : scopes) out.add(new Object[] {at + "scope " + s[0], setAt(g, p("bounds", i, "scope"), s[1])});
            out.add(new Object[] {at + "sel none", setAt(g, p("bounds", i, "sel"), obj("k", "gids", "gids", list()))});
            out.add(new Object[] {at + "sel all", setAt(g, p("bounds", i, "sel"), obj("k", "gids", "gids", copy(gids)))});
            out.add(new Object[] {at + "sel cls", setAt(g, p("bounds", i, "sel"), obj("k", "effect", "cls", cls))});
            out.add(new Object[] {at + "sel other cls", setAt(g, p("bounds", i, "sel"), obj("k", "effect", "cls", "zz"))});
        }
        return out;
    }

    // ---- probe variants ----
    /** Replacement values for a parameter slot: the condition literals and the current value, nudged, retyped and re-united. */
    static List<Object> palette(Map<String, Object> goal, Object cur) {
        List<Object> lits = new ArrayList<>();
        collectLits(goal, lits);
        if (cur != null) lits.add(cur);
        List<Object> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Object v : lits) {
            Map<String, Object> m = M(v);
            List<Object> cand = new ArrayList<>();
            cand.add(m);
            if ("q".equals(m.get("k")) && M(m.get("q")).get("n") != null) {
                long qn = lv(M(m.get("q")).get("n"));
                for (long d : new long[] {-1, 1}) cand.add(obj("k", "q", "q", obj("u", copy(M(m.get("q")).get("u")), "n", n(qn + d))));
                cand.add(obj("k", "q", "q", obj("u", obj("k", "zz"), "n", n(qn))));
                cand.add(obj("k", "s", "s", Long.toString(qn)));
            }
            if ("s".equals(m.get("k"))) {
                cand.add(obj("k", "s", "s", m.get("s") + "z"));
                cand.add(obj("k", "q", "q", obj("u", obj("k", "count"), "n", n(1))));
            }
            if ("set".equals(m.get("k")) && !L(m.get("items")).isEmpty()) cand.add(L(m.get("items")).get(0));
            for (Object c : cand) if (seen.add(Json.canonicalize(c))) out.add(c);
        }
        out.add(obj("k", "b", "b", Boolean.TRUE));
        out.add(obj("k", "s", "s", "zz"));
        return out.size() > 24 ? out.subList(0, 24) : out;
    }

    static void collectLits(Object v, List<Object> out) {
        if (v instanceof Map) {
            Map<String, Object> m = M(v);
            if ("lit".equals(m.get("k")) && m.get("v") instanceof Map) out.add(m.get("v"));
            for (Object x : m.values()) collectLits(x, out);
        } else if (v instanceof List) for (Object x : L(v)) collectLits(x, out);
    }

    static void condParamPaths(Object v, Set<String> out) {
        if (v instanceof Map) {
            Map<String, Object> m = M(v);
            if ("param".equals(m.get("k")) && m.get("path") instanceof String) out.add((String) m.get("path"));
            if (m.get("key") instanceof String && !((String) m.get("key")).isEmpty()) out.add((String) m.get("key"));
            for (Object x : m.values()) condParamPaths(x, out);
        } else if (v instanceof List) for (Object x : L(v)) condParamPaths(x, out);
    }

    static List<Object[]> probeVariants(Map<String, Object> g, Map<String, Object> ont, Map<String, Object> pr) {
        Map<String, Object> a = M(pr.get("action")), h = M(pr.get("history"));
        List<Object[]> out = new ArrayList<>();
        Map<String, Object> val = M(g.get("validity"));
        long t = lv(a.get("t")), nb = lv(val.get("notBefore")), na = lv(val.get("notAfter")), md = lv(M(g.get("deleg")).get("maxDepth"));
        for (long x : new long[] {nb - 1, nb, nb + 1, na - 1, na, na + 1}) out.add(new Object[] {"t " + x, setAt(a, p("t"), n(x)), h});
        for (long x : new long[] {-1, 0, 1, md, md + 1}) out.add(new Object[] {"depth " + x, setAt(a, p("depth"), n(x)), h});
        for (Object v : L(ont.get("verbs"))) out.add(new Object[] {"verb " + M(v).get("verb"), setAt(a, p("verb"), M(v).get("verb")), h});
        Set<Object> ids = new LinkedHashSet<>();
        ids.add("zz");
        for (Object r : L(ont.get("rels"))) ids.addAll(L(M(r).get("members")));
        collectIds(g, ids);
        for (Object id : ids) out.add(new Object[] {"res " + id, setAt(a, p("res"), id), h});
        for (String k : new String[] {"sess", "prin", "org", "agent"}) out.add(new Object[] {k + " zz", setAt(a, p(k), "zz"), h});
        Set<String> paths = new LinkedHashSet<>(M(a.get("params")).keySet());
        condParamPaths(g, paths);
        for (String path : paths) {
            Object cur = M(a.get("params")).get(path);
            out.add(new Object[] {"param " + path + " deleted", setAt(a, p("params", path), DEL), h});
            int i = 0;
            for (Object v : palette(g, cur)) out.add(new Object[] {"param " + path + " #" + i++, setAt(a, p("params", path), copy(v)), h});
        }
        // idle time
        for (long x : new long[] {-1, 0, t - 1, t - 2, t - 1000, t - 1001, t}) out.add(new Object[] {"last " + x, a, setAt(h, p("last"), n(x))});
        // aggregates
        for (Object bo : L(g.get("bounds"))) {
            Map<String, Object> b = M(bo);
            String bid = (String) b.get("bid");
            Map<String, Object> cap = M(b.get("cap"));
            long cn = lv(cap.get("n"));
            for (long x : new long[] {cn - 1, cn, cn + 1})
                out.add(new Object[] {"agg " + bid + " " + x, a, setAt(h, p("aggs", bid), obj("u", copy(cap.get("u")), "n", n(x)))});
            out.add(new Object[] {"agg " + bid + " unit", a, setAt(h, p("aggs", bid), obj("u", obj("k", "zz"), "n", n(cn)))});
        }
        // admissions
        List<Object> adms = L(h.get("adms"));
        List<Long> deltas = new ArrayList<>(List.of(0L, 1L, -1L, 1000L, 999L, 1001L));
        for (Object bo : L(g.get("bounds"))) {
            Map<String, Object> w = M(M(bo).get("window"));
            if (w.get("ms") != null) {
                long ms = lv(w.get("ms"));
                for (long d : new long[] {ms, ms - 1, ms + 1}) deltas.add(d);
            }
        }
        for (int i = 0; i < adms.size() && i < 3; i++) {
            String at = "adm " + i + " ";
            Map<String, Object> act = M(M(adms.get(i)).get("act"));
            for (long d : deltas) out.add(new Object[] {at + "t-" + d, a, setAt(h, p("adms", i, "act", "t"), n(t - d))});
            for (String k : new String[] {"sess", "prin", "org", "agent", "verb"}) out.add(new Object[] {at + k, a, setAt(h, p("adms", i, "act", k), "zz")});
            out.add(new Object[] {at + "gid", a, setAt(h, p("adms", i, "gid"), "zz")});
            for (String path : M(act.get("params")).keySet()) {
                out.add(new Object[] {at + path + " deleted", a, setAt(h, p("adms", i, "act", "params", path), DEL)});
                int j = 0;
                for (Object v : palette(g, M(act.get("params")).get(path))) {
                    if (j >= 6) break;
                    out.add(new Object[] {at + path + " #" + j++, a, setAt(h, p("adms", i, "act", "params", path), copy(v))});
                }
            }
            List<Object> dup = L(copy(adms));
            dup.add(copy(adms.get(i)));
            out.add(new Object[] {at + "dup", a, setAt(h, p("adms"), dup)});
            List<Object> drop = L(copy(adms));
            drop.remove(i);
            out.add(new Object[] {at + "dropped", a, setAt(h, p("adms"), drop)});
        }
        // the current action admitted once and twice before (count / sum / distinct grow)
        List<Object> gr = L(g.get("grants"));
        if (!gr.isEmpty()) {
            Map<String, Object> prev = obj("gid", M(gr.get(0)).get("gid"), "act", setAt(a, p("t"), n(t - 1)));
            List<Object> one = L(copy(adms));
            one.add(prev);
            out.add(new Object[] {"self admitted", a, setAt(h, p("adms"), one)});
            List<Object> two = L(copy(one));
            two.add(copy(prev));
            out.add(new Object[] {"self admitted twice", a, setAt(h, p("adms"), two)});
        }
        return out;
    }

    static void collectIds(Object v, Set<Object> out) {
        if (v instanceof Map) {
            Map<String, Object> m = M(v);
            if ("exact".equals(m.get("k")) && m.get("id") != null) out.add(m.get("id"));
            if ("oneof".equals(m.get("k")) && m.get("ids") instanceof List) out.addAll(L(m.get("ids")));
            for (Object x : m.values()) collectIds(x, out);
        } else if (v instanceof List) for (Object x : L(v)) collectIds(x, out);
    }

    // ---- tests ----
    @Test
    void corpusAgrees() throws Exception {
        Diff d = new Diff();
        for (Vec v : vecs()) {
            d.lower(v.id, v.goal, v.ont);
            Doc g = new Doc(v.goal), o = new Doc(v.ont);
            for (int i = 0; i < v.probes.size(); i++) {
                Map<String, Object> pr = v.probes.get(i);
                d.decide(v.id + "#" + i, g, o, new Doc(pr.get("action")), new Doc(pr.get("history")));
            }
        }
        d.report();
        assertTrue(d.n > 7000, "cases " + d.n);
    }

    @Test
    void goalVariantsAgree() throws Exception {
        Diff d = new Diff();
        for (Vec v : vecs()) {
            List<Map<String, Object>> ss = seeds(v, 2);
            if (ss.isEmpty()) continue;
            Doc o = new Doc(v.ont);
            List<Doc[]> probes = new ArrayList<>();
            for (Map<String, Object> pr : ss) probes.add(new Doc[] {new Doc(pr.get("action")), new Doc(pr.get("history"))});
            for (Object[] gv : goalVariants(v.goal, v.ont, M(ss.get(0).get("action")))) {
                String label = v.id + " " + gv[0];
                d.lower(label, gv[1], v.ont);
                Doc g = new Doc(gv[1]);
                for (Doc[] pr : probes) d.decide(label, g, o, pr[0], pr[1]);
            }
        }
        d.report();
        assertTrue(d.n > 20000, "cases " + d.n);
    }

    @Test
    void probeVariantsAgree() throws Exception {
        Diff d = new Diff();
        for (Vec v : vecs()) {
            Doc g = new Doc(v.goal), o = new Doc(v.ont);
            for (Map<String, Object> pr : seeds(v, 3)) {
                for (Object[] pv : probeVariants(v.goal, v.ont, pr)) d.decide(v.id + " " + pv[0], g, o, new Doc(pv[1]), new Doc(pv[2]));
            }
        }
        d.report();
        assertTrue(d.n > 20000, "cases " + d.n);
    }

    /** sum / max / count / distinct bounds over earlier admissions larger and smaller than the action, caps around the totals. */
    @Test
    void aggregateExtremes() throws Exception {
        Diff d = new Diff();
        for (Vec v : vecs()) {
            List<Object> bounds = L(v.goal.get("bounds")), grants = L(v.goal.get("grants"));
            if (bounds.isEmpty() || grants.isEmpty() || v.probes.isEmpty()) continue;
            Map<String, Object> pr = v.probes.get(0), a = M(pr.get("action")), h = M(pr.get("history"));
            long t = lv(a.get("t"));
            List<Object> gids = new ArrayList<>();
            for (Object gr : grants) gids.add(M(gr).get("gid"));
            for (Map.Entry<String, Object> e : M(a.get("params")).entrySet()) {
                Map<String, Object> qv = M(e.getValue());
                if (!"q".equals(qv.get("k"))) continue;
                String qp = e.getKey();
                long x = lv(M(qv.get("q")).get("n"));
                Object g = setAt(v.goal, p("bounds", 0, "value"), obj("k", "param", "path", qp));
                g = setAt(g, p("bounds", 0, "cap", "u"), copy(M(qv.get("q")).get("u")));
                g = setAt(g, p("bounds", 0, "sel"), obj("k", "gids", "gids", copy(gids)));
                g = setAt(g, p("bounds", 0, "window"), obj("k", "task"));
                g = setAt(g, p("bounds", 0, "scope"), obj("k", "org"));
                g = setAt(g, p("bounds", 0, "key"), qp);
                Object hi = obj("gid", gids.get(0), "act", setAt(setAt(a, p("t"), n(t - 1)), p("params", qp, "q", "n"), n(x + 5)));
                Object lo = obj("gid", gids.get(0), "act", setAt(setAt(a, p("t"), n(t - 2)), p("params", qp, "q", "n"), n(x - 5)));
                Object same = obj("gid", gids.get(0), "act", setAt(a, p("t"), n(t - 3)));
                List<List<Object>> hists = List.of(list(), list(hi), list(lo), list(hi, lo), list(lo, hi), list(same), list(same, hi, lo));
                for (String agg : List.of("sum", "max", "count", "distinct")) {
                    Object ga = setAt(g, p("bounds", 0, "agg"), agg);
                    for (long cap : new long[] {0, 1, 2, 3, x - 1, x, x + 4, x + 5, x + 6, 2 * x - 1, 2 * x, 2 * x + 5, 3 * x, 3 * x - 1}) {
                        Doc gd = new Doc(setAt(ga, p("bounds", 0, "cap", "n"), n(cap)));
                        Doc o = new Doc(v.ont), ad = new Doc(a);
                        for (int i = 0; i < hists.size(); i++)
                            d.decide(v.id + " " + qp + " " + agg + " cap " + cap + " hist " + i, gd, o, ad, new Doc(setAt(h, p("adms"), hists.get(i))));
                    }
                }
            }
        }
        d.report();
        assertTrue(d.n > 1000, "cases " + d.n);
    }

    /** Idle time needs a goal with maxIdle: the probe variants under maxIdle 1 and 1000. */
    @Test
    void idleWindow() throws Exception {
        Diff d = new Diff();
        for (Vec v : vecs()) {
            for (Map<String, Object> pr : seeds(v, 1)) {
                Map<String, Object> a = M(pr.get("action")), h = M(pr.get("history"));
                long t = lv(a.get("t"));
                for (long mi : new long[] {0, 1, 1000}) {
                    Object g = setAt(v.goal, p("validity", "maxIdle"), n(mi));
                    for (long last : new long[] {-2, -1, 0, 1, t - 1, t - 2, t - 999, t - 1000, t - 1001, t, t + 1})
                        d.decide(v.id + " maxIdle " + mi + " last " + last, g, v.ont, a, setAt(h, p("last"), n(last)));
                }
            }
        }
        d.report();
    }

    @Test
    void helperFunctions() throws Exception {
        vecs();
        Diff d = new Diff();
        for (Map<String, Object> v : FNS) d.fn((String) v.get("id"), (String) v.get("fn"), v.get("input"));
        List<String> ds = List.of("deny", "escalate", "allow");
        for (String a : ds)
            for (String s : List.of("deny", "escalate", "allow", "ok", "zz", "")) d.fn("meet " + a + " " + s, "meet", obj("decision", a, "signal", s));
        Map<String, Object> ctx = obj("policy_digest", "P", "action_digest", "A", "history_head", "H");
        List<Object[]> answers = new ArrayList<>();
        answers.add(new Object[] {"none", null});
        answers.add(new Object[] {"empty", obj()});
        answers.add(new Object[] {"valid", obj("policy_digest", "P", "action_digest", "A", "history_head", "H", "valid", Boolean.TRUE)});
        answers.add(new Object[] {"invalid", obj("policy_digest", "P", "action_digest", "A", "history_head", "H", "valid", Boolean.FALSE)});
        answers.add(new Object[] {"valid string", obj("policy_digest", "P", "action_digest", "A", "history_head", "H", "valid", "true")});
        answers.add(new Object[] {"only valid", obj("valid", Boolean.TRUE)});
        for (String k : List.of("policy_digest", "action_digest", "history_head")) {
            Map<String, Object> x = obj("policy_digest", "P", "action_digest", "A", "history_head", "H", "valid", Boolean.TRUE);
            x.put(k, "X");
            answers.add(new Object[] {k + " differs", x});
            Map<String, Object> y = M(copy(x));
            y.remove(k);
            answers.add(new Object[] {k + " missing", y});
        }
        for (String dec : ds)
            for (Object[] an : answers) {
                Map<String, Object> in = obj("decision", dec, "ctx", ctx);
                if (an[1] != null) in.put("answer", an[1]);
                d.fn("pep " + dec + " " + an[0], "pep", in);
            }
        for (String base : ds)
            for (long rp : new long[] {-1, 0, 899999, 900000, 900001}) {
                Map<String, Object> in = obj("base", base, "min_ppm", n(900000));
                if (rp >= 0) in.put("replayed_ppm", n(rp));
                d.fn("claim " + base + " " + rp, "claim", in);
            }
        Map<String, Object> usd = obj("currency", "USD", "exponent", n(2)), eur = obj("currency", "EUR", "exponent", n(2));
        d.fn("units mixed", "units", obj("schema", obj("b", usd, "a", usd, "é", usd), "terms", obj("z", usd, "é", eur, "b", usd, "Z", usd, "a", eur)));
        d.fn("units none", "units", obj("schema", obj(), "terms", obj()));
        d.fn("units same", "units", obj("schema", obj("a", usd), "terms", obj("a", copy(usd))));
        List<Object> conds = new ArrayList<>();
        for (String path : List.of("env.class.x", "env.prov.y", "env.judge.z", "env.world.w", "env.other.v", "envx.class.u", "env.classx", "x"))
            for (String side : List.of("l", "r")) {
                Map<String, Object> pt = obj("k", "param", "path", path), lit = obj("k", "lit", "v", obj("k", "s", "s", "v"));
                conds.add(obj("k", "cmp", "op", "eq", "l", side.equals("l") ? pt : lit, "r", side.equals("l") ? lit : pt));
            }
        for (int i = 0; i < conds.size(); i++) {
            d.fn("polarity " + i, "polarity", list(conds.get(i)));
            d.fn("polarity not " + i, "polarity", list(not(conds.get(i))));
            d.fn("polarity and " + i, "polarity", list(bin("and", TRUE, conds.get(i))));
            d.fn("polarity or " + i, "polarity", list(bin("or", conds.get(i), TRUE)));
        }
        d.fn("polarity all", "polarity", new ArrayList<>(conds));
        d.fn("polarity none", "polarity", list(TRUE));
        d.fn("canon mixed", "canon", obj("z", list(n(-1), n(0), Boolean.TRUE, Boolean.FALSE, null, "\u0001\u001f \b\f\n\r\t\"\\/é😀"), "é", obj(), "Z", list(), "a", n(9007199254740991L)));
        d.fn("commit other", "commit", obj("goal_digest", "g", "policy_digest", "p", "salt", ""));
        d.report();
        assertTrue(d.n > 150, "cases " + d.n);
    }

    @Test
    void directHelpers() {
        assertEquals("5", GoalSemantics.canon(5));
        assertEquals("-5", GoalSemantics.canon(-5L));
        assertEquals("[1,\"a\",null,true]", GoalSemantics.canon(list(1, "a", null, true)));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> GoalSemantics.canon(1.5d));
        assertEquals("canon: unsupported java.lang.Double", e.getMessage());
        e = assertThrows(IllegalArgumentException.class, () -> GoalSemantics.canon(obj("a", new Object())));
        assertEquals("canon: unsupported java.lang.Object", e.getMessage());
        e = assertThrows(IllegalArgumentException.class, () -> GoalSemantics.runFn("zz", obj()));
        assertEquals("unknown fn zz", e.getMessage());
        // an unknown decision is returned unchanged (the reference runner has no such case)
        assertEquals("zz", GoalSemantics.meet("zz", "deny"));
        assertEquals("zz", GoalSemantics.meet("zz", "zz"));
        assertEquals("deny", GoalSemantics.meet("allow", "deny"));
        assertEquals("escalate", GoalSemantics.meet("allow", "escalate"));
        assertEquals("allow", GoalSemantics.meet("allow", "allow"));
        assertEquals("deny", GoalSemantics.meet("deny", "allow"));
        assertEquals("escalate", GoalSemantics.claim("allow", BigInteger.TEN, BigInteger.ONE));
        assertEquals("allow", GoalSemantics.claim("allow", BigInteger.TEN, BigInteger.TEN));
        assertEquals("allow", GoalSemantics.claim("allow", BigInteger.TEN, null));
        assertFalse(GoalSemantics.pep("escalate", obj(), null));
        assertFalse(GoalSemantics.pep("escalate", obj(), obj()));
        assertTrue(GoalSemantics.pep("escalate", obj(), obj("valid", Boolean.TRUE)));
    }
}
