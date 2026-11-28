package net.atlasauth.pca.analyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Caveats;
import net.atlasauth.pca.analyzer.Enumerate.PolicyModel;
import net.atlasauth.pca.analyzer.Enumerate.ProbeInputs;
import net.atlasauth.pca.analyzer.Enumerate.Probes;

/**
 * MINIMAL-CHANGE COUNTERFACTUAL SEARCH on a deny or escalate: "what is the smallest thing the agent can change to be allowed?", as a typed
 * patch ordered by cost: wait, lower a parameter to the nearest admissible value, pick another allowed value or resource, obtain a named
 * fact, split the action (opt-in), and only then ask a human. The search PROPOSES; the real decision VERIFIES: every candidate is re-run
 * through the evaluator and only one that reaches the wanted decision is returned. A counterfactual teaches the holder about the policy, so
 * it is shown only to the authenticated holder, is rate-limited by a probe budget, and redacts critical values.
 */
public final class Flip {
    private Flip() {}

    private static double rank(Object d) {
        return "deny".equals(d) ? 0 : "escalate".equals(d) ? 1 : "allow".equals(d) ? 2 : Double.NaN;
    }

    /** A repair candidate being assembled. */
    private static final class Cand {
        final Map<String, Object> repair; final double cost; final String decision; final Map<String, Object> action;
        Cand(Map<String, Object> repair, double cost, String decision, Map<String, Object> action) { this.repair = repair; this.cost = cost; this.decision = decision; this.action = action; }
        Map<String, Object> toJson() { return Js.obj("repair", repair, "cost", Js.n(cost), "decision", decision, "action", action); }
    }

    private static Map<String, Object> withParam(Map<String, Object> action, Map<String, Object> params, String name, Object v) {
        Map<String, Object> p = new LinkedHashMap<>(params);
        p.put(name, v);
        Map<String, Object> a = Js.copy(action);
        a.put("params", p);
        return a;
    }

    /** The TS {@code CaveatContext} (camelCase) as the evaluator's context. */
    private static Map<String, Object> caveatCtx(Object c, Object nowOverride, boolean override) {
        Map<String, Object> m = Js.obj();
        if (override) m.put("now", nowOverride); else Js.putIf(m, "now", c, "now");
        Js.putIf(m, "blast_radius", c, "blastRadius");
        Js.putIf(m, "reversibility_class", c, "reversibilityClass");
        Js.putIf(m, "delegation_depth", c, "delegationDepth");
        Js.putIf(m, "recent_action_times", c, "recentActionTimes");
        return m;
    }

    private static boolean caveatsOkAt(PolicyModel model, Object ctx, Object now, boolean override) {
        return Caveats.evaluateCaveats(model.caveats, caveatCtx(ctx, now, override)).ok;
    }

    private static boolean meters(PolicyModel m) {
        List<Object> cs = new ArrayList<>(m.caveats);
        for (PolicyModel x : m.meets) cs.addAll(x.caveats);
        for (Object c : cs) {
            Object t = Js.get(c, "type");
            if ("rate".equals(t) || "budget_alloc".equals(t) || "max_blast_radius".equals(t)) return true;
        }
        return false;
    }

    private static Double waitTime(List<Object> caveats, Object ctx) {
        Double at = null;
        double now = Js.toNum(Js.get(ctx, "now"));
        for (Object c : caveats) {
            Object type = Js.get(c, "type");
            if ("not_before".equals(type) && Js.isNum(Js.get(c, "at")) && Js.num(Js.get(c, "at")) > now) at = Math.max(at == null ? 0 : at, Js.num(Js.get(c, "at")));
            if ("rate".equals(type) && Js.isNum(Js.get(c, "max")) && Js.isNum(Js.get(c, "per_secs"))) {
                double span = Js.num(Js.get(c, "per_secs")) * 1000;
                List<Double> recent = new ArrayList<>();
                Object rt = Js.get(ctx, "recentActionTimes");
                if (rt instanceof List) for (Object t : (List<?>) rt) if (Js.toNum(t) > now - span) recent.add(Js.toNum(t));
                Collections.sort(recent);
                double max = Js.num(Js.get(c, "max"));
                if (recent.size() >= max) {
                    double idx = recent.size() - max;
                    double v = idx >= 0 && idx == Math.rint(idx) && idx < recent.size() ? recent.get((int) idx) + span : Double.NaN;
                    at = Math.max(at == null ? 0 : at, v);
                }
            }
        }
        return at;
    }

    private static void setPath(Map<String, Object> o, List<String> path, Object v) {
        if (path.isEmpty()) return;
        String k = path.get(0);
        List<String> rest = path.subList(1, path.size());
        if (rest.isEmpty()) o.put(k, v);
        else {
            Map<String, Object> inner = Js.copy(o.get(k));
            setPath(inner, rest, v);
            o.put(k, inner);
        }
    }

    private static <T> List<T> distinct(List<T> xs) {
        List<T> out = new ArrayList<>();
        for (T x : xs) { boolean dup = false; for (T y : out) if (Js.strictEq(x, y)) { dup = true; break; } if (!dup) out.add(x); }
        return out;
    }

    /**
     * Search for the smallest verified change that gets {@code action} to the wanted decision. Options: desired ("allow" | "escalate"), schema
     * (verb shapes), holderAuthenticated (required), probe {limit, windowSecs, history, now}, changeable, caveatContext, allowSplit, redact
     * ("none" | "critical" | "all"), maxCandidates. Returns {current, repairs, humanFree?, humanAsk?, redacted?, repairExists, refused?, probe?}.
     */
    public static Map<String, Object> minimalFlip(Object policy, Map<String, Object> action, Map<String, Object> o) {
        Js.req(action);
        PolicyModel model = Enumerate.toModel(policy);
        boolean hasCtx = Js.has(o, "caveatContext");
        Object cctx = Js.get(o, "caveatContext");
        boolean caveatsOk = !hasCtx || caveatsOkAt(model, cctx, null, false);
        String current = caveatsOk ? Enumerate.decideAction(model, action) : "deny";
        Object wantO = Js.get(o, "desired");
        Object want = wantO == null ? "allow" : wantO;
        Map<String, Object> res = Js.obj("current", current, "repairs", new ArrayList<Object>(), "repairExists", false);
        if (!Js.truthy(Js.get(o, "holderAuthenticated"))) {
            res.put("refused", "counterfactuals are shown only to the authenticated holder");
            return res;
        }
        Object probe = Js.get(o, "probe");
        if (Js.truthy(probe)) {
            List<Object> recent = new ArrayList<>();
            double now = Js.toNum(Js.get(probe, "now"));
            double windowSecs = Js.toNum(Js.get(probe, "windowSecs"));
            // a clock, window or history stamp that is not finite cannot say what is still inside the window: refuse (a +Infinity limit stays an unbounded cap)
            boolean finiteIn = Double.isFinite(now) && Double.isFinite(windowSecs);
            for (Object t : Js.list(Js.get(probe, "history"))) if (!Double.isFinite(Js.toNum(t))) finiteIn = false;
            if (!finiteIn) {
                res.put("refused", "probe budget exhausted");
                res.put("probe", Js.obj("history", new ArrayList<>(Js.list(Js.get(probe, "history")))));
                return res;
            }
            for (Object t : Js.list(Js.get(probe, "history"))) if (Js.toNum(t) > now - windowSecs * 1000) recent.add(t);
            if (!(recent.size() < Js.toNum(Js.get(probe, "limit")))) {
                res.put("refused", "probe budget exhausted");
                res.put("probe", Js.obj("history", recent));
                return res;
            }
            List<Object> h = new ArrayList<>(recent);
            h.add(Js.get(probe, "now"));
            res.put("probe", Js.obj("history", h));
        }
        String policyDigest = Residual.policyDigestOf(model);
        if (rank(current) >= rank(want)) return res;

        Object shape = null;
        Object schema = Js.get(o, "schema");
        if (Js.truthy(schema)) for (Object s : Js.list(schema)) if (Js.strictEq(Js.get(s, "verb"), Js.get(action, "verb"))) { shape = s; break; }
        final Object shapeF = shape;
        final Object wantF = want;
        List<Cand> cands = new ArrayList<>();
        java.util.function.Function<Map<String, Object>, String> reaches = a -> {
            String d = Enumerate.decideAction(model, a);
            return rank(d) >= rank(wantF) ? d : null;
        };

        ProbeInputs in = new ProbeInputs();
        in.predicateSets.add(Enumerate.probeSet(model));
        in.varyReversibility = model.revCap != null;
        Probes pr = Enumerate.collectProbes(in);
        Object paramsO = Js.get(action, "params");
        Map<String, Object> params = paramsO instanceof Map ? Js.map(paramsO) : new LinkedHashMap<>();
        List<String> names = new ArrayList<>();
        Object ch = Js.get(o, "changeable");
        if (ch != null) for (Object n : Js.list(ch)) names.add((String) n);
        else if (shape != null) names.addAll(Js.keys(Js.copy(Js.get(shape, "params"))));
        else names.addAll(Js.keys(params));
        Object actionVerb = Js.get(action, "verb");

        // 1. wait: a time caveat that is not open yet, or a rate window that will reset
        if (!caveatsOk && hasCtx && Js.truthy(cctx)) {
            Double at = waitTime(model.caveats, cctx);
            String d = Enumerate.decideAction(model, action);
            if (at != null && caveatsOkAt(model, cctx, Js.n(at), true) && rank(d) >= rank(want)) {
                cands.add(new Cand(Js.obj("kind", "wait_until", "at", Js.n(at), "reason", "a time or rate caveat opens then"), 1, d, action));
            }
        }
        boolean finish = !caveatsOk; // nothing else helps while a caveat is closed

        // 2. one parameter changed: the nearest verified value, per parameter
        for (String name : finish ? new ArrayList<String>() : names) {
            String path = "action.params." + name;
            Object decl = Js.get(Js.get(shape, "params"), name);
            Object cur = params.get(name);
            boolean hasCur = params.containsKey(name);
            Enumerate.FieldProbe field = null;
            for (Enumerate.FieldProbe f : pr.fields) if (f.path.equals(path)) { field = f; break; }
            List<Object> pool = new ArrayList<>();
            if (field != null) for (Object v : field.values) if (v != Enumerate.ABSENT) pool.add(v);
            if (decl != null && Js.get(decl, "values") instanceof List) pool.addAll(Js.list(Js.get(decl, "values")));
            if (decl != null && Js.has(decl, "min")) pool.add(Js.get(decl, "min"));
            if (decl != null && Js.has(decl, "max")) pool.add(Js.get(decl, "max"));
            List<Double> nums = new ArrayList<>();
            for (Object v : pool) if (Js.isFin(v)) nums.add(Js.num(v));
            List<Double> T = Exposure.thresholds(model, path);
            boolean integer = (decl != null && "integer".equals(Js.get(decl, "type"))) || (Js.isFin(cur) && Js.num(cur) == Math.rint(Js.num(cur)));
            List<Double> ints = new ArrayList<>();
            if (integer) for (double t : T) { ints.add(t - 1); ints.add(t + 1); }
            List<Double> all = new ArrayList<>(nums);
            all.addAll(ints);
            List<Double> numeric = new ArrayList<>();
            boolean hasMin = decl != null && Js.has(decl, "min"), hasMax = decl != null && Js.has(decl, "max");
            for (double v : distinctNums(all)) {
                if ((!hasMin || v >= Js.toNum(Js.get(decl, "min"))) && (!hasMax || v <= Js.toNum(Js.get(decl, "max")))) numeric.add(v);
            }
            double curN = Js.isNum(cur) ? Js.num(cur) : 0;
            numeric.sort((a, b) -> {
                double d = Math.abs(a - curN) - Math.abs(b - curN);
                if (d != 0 && !Double.isNaN(d)) return d < 0 ? -1 : 1;
                double e = a - b;
                return e < 0 ? -1 : e > 0 ? 1 : 0;
            });
            List<String> strs = new ArrayList<>();
            for (Object v : pool) if (v instanceof String && !((String) v).startsWith("\u0000") && !strs.contains(v)) strs.add((String) v);
            List<Object> order = new ArrayList<>();
            for (double v : numeric) order.add(v);
            order.addAll(strs);
            for (Object v0 : order) {
                Object v = v0 instanceof Double ? Js.n((Double) v0) : v0;
                if (hasCur && Js.strictEq(v, cur)) continue;
                Map<String, Object> a = withParam(action, params, name, v);
                String d = reaches.apply(a);
                if (d != null) {
                    double extra = Js.isNum(v) && Js.isNum(cur) ? Math.min(1, Math.abs(Js.num(v) - Js.num(cur)) / (Math.abs(Js.num(cur)) + 1)) : 0.5;
                    Map<String, Object> repair = Js.obj("kind", "set_param", "param", name);
                    if (hasCur) repair.put("from", cur);
                    repair.put("to", v);
                    cands.add(new Cand(repair, 2 + extra, d, a));
                    break; // the pool is ordered nearest first
                }
            }
        }

        // 2b. when no single edit works, the cheapest PAIR of edits
        if (!finish && cands.isEmpty()) {
            List<List<Object>> dimValues = new ArrayList<>();
            List<Double> dimCost = new ArrayList<>();
            List<java.util.function.BiFunction<Map<String, Object>, Object, Map<String, Object>>> make = new ArrayList<>();
            List<java.util.function.Function<Object, Map<String, Object>>> step = new ArrayList<>();
            for (String name : names) {
                String path = "action.params." + name;
                Object decl = Js.get(Js.get(shape, "params"), name);
                Enumerate.FieldProbe field = null;
                for (Enumerate.FieldProbe f : pr.fields) if (f.path.equals(path)) { field = f; break; }
                List<Object> vals = new ArrayList<>();
                List<Object> src = new ArrayList<>();
                if (field != null) src.addAll(field.values);
                if (decl != null && Js.get(decl, "values") instanceof List) src.addAll(Js.list(Js.get(decl, "values")));
                for (Object v : src) {
                    boolean ok = v instanceof String ? !((String) v).startsWith("\u0000") : v != Enumerate.ABSENT && Js.isNum(v);
                    if (ok && !Js.strictEq(v, params.get(name))) vals.add(v);
                }
                List<Object> dv = distinct(vals);
                dimValues.add(dv.size() > 6 ? new ArrayList<>(dv.subList(0, 6)) : dv);
                dimCost.add(2.0);
                make.add((a, v) -> withParam(a, a.get("params") instanceof Map ? Js.map(a.get("params")) : new LinkedHashMap<>(), name, v));
                step.add(v -> {
                    Map<String, Object> s = Js.obj("kind", "set_param", "param", name);
                    if (params.containsKey(name)) s.put("from", params.get(name));
                    s.put("to", v);
                    return s;
                });
            }
            List<Object> resVals = new ArrayList<>();
            for (Object x : pr.resources) if (!((String) x).startsWith("\u0000") && !Js.strictEq(x, Js.get(action, "resource"))) resVals.add(x);
            dimValues.add(resVals.size() > 6 ? new ArrayList<>(resVals.subList(0, 6)) : resVals);
            dimCost.add(3.0);
            make.add((a, v) -> { Map<String, Object> c = Js.copy(a); c.put("resource", v); return c; });
            step.add(v -> Js.obj("kind", "set_resource", "from", Js.get(action, "resource"), "to", v));
            for (int i = 0; i < dimValues.size(); i++) {
                for (int j = i + 1; j < dimValues.size(); j++) {
                    for (Object x : dimValues.get(i)) {
                        for (Object y : dimValues.get(j)) {
                            Map<String, Object> a = make.get(j).apply(make.get(i).apply(action, x), y);
                            String d = reaches.apply(a);
                            if (d != null) cands.add(new Cand(Js.obj("kind", "combine", "steps", Js.arr(step.get(i).apply(x), step.get(j).apply(y))), dimCost.get(i) + dimCost.get(j), d, a));
                        }
                    }
                }
            }
        }

        // 3. another allowed resource
        if (!finish) {
            for (Object r : pr.resources) {
                if (((String) r).startsWith("\u0000") || Js.strictEq(r, Js.get(action, "resource"))) continue;
                Map<String, Object> a = Js.copy(action);
                a.put("resource", r);
                String d = reaches.apply(a);
                if (d != null) cands.add(new Cand(Js.obj("kind", "set_resource", "from", Js.get(action, "resource"), "to", r), 3, d, a));
            }
        }

        // 4. a named fact that is missing: a subject or env field the policy reads
        if (!finish) {
            for (Enumerate.FieldProbe f : pr.fields) {
                if (!f.path.startsWith("subject.") && !f.path.startsWith("env.")) continue;
                String[] segs = f.path.split("\\.", -1);
                String root = segs[0];
                List<String> rest = new ArrayList<>(java.util.Arrays.asList(segs).subList(1, segs.length));
                for (Object v : f.values) {
                    if (v == Enumerate.ABSENT) continue;
                    Map<String, Object> sub = Js.copy(Js.get(action, root));
                    setPath(sub, rest, v);
                    Map<String, Object> a = Js.copy(action);
                    a.put(root, sub);
                    String before = reaches.apply(action);
                    String d = reaches.apply(a);
                    if (d != null && before == null) {
                        cands.add(new Cand(Js.obj("kind", "obtain_fact", "path", f.path, "value", v), 4, d, a));
                        break;
                    }
                }
            }
        }

        // 5. split (opt-in, and only when nothing meters the total)
        if (Boolean.TRUE.equals(Js.get(o, "allowSplit")) && !meters(model)) {
            for (String name : names) {
                Object cur = params.get(name);
                if (!Js.isNum(cur)) continue;
                Double part = null;
                for (Cand c : cands) {
                    if ("set_param".equals(c.repair.get("kind")) && name.equals(c.repair.get("param")) && Js.isNum(c.repair.get("to"))) { part = Js.num(c.repair.get("to")); break; }
                }
                double cn = Js.num(cur);
                if (part == null || part <= 0 || part >= cn) continue;
                double n = Math.ceil(cn / part);
                if (n > 8) continue;
                List<Object> parts = new ArrayList<>();
                boolean allOk = true;
                for (int i = 0; i < n; i++) {
                    Object v = Js.n(i < n - 1 ? part : cn - part * (n - 1));
                    parts.add(Js.obj(name, v));
                    Map<String, Object> merged = new LinkedHashMap<>(params);
                    merged.put(name, v);
                    Map<String, Object> a = Js.copy(action);
                    a.put("params", merged);
                    if (reaches.apply(a) == null) allOk = false;
                }
                if (allOk) cands.add(new Cand(Js.obj("kind", "split", "param", name, "parts", parts), 3 + n, (String) want, action));
            }
        }

        cands.sort((a, b) -> Double.compare(a.cost, b.cost) < 0 ? -1 : a.cost == b.cost ? 0 : 1);
        double maxC = Js.get(o, "maxCandidates") == null ? 8 : Js.toNum(Js.get(o, "maxCandidates"));
        List<Cand> top = cands.size() > maxC ? new ArrayList<>(cands.subList(0, (int) Math.max(0, maxC))) : cands;
        res.put("repairExists", !top.isEmpty());
        Object redO = Js.get(o, "redact");
        String redact = redO == null ? "critical" : redO instanceof String ? (String) redO : "";
        boolean[] redacted = {false};
        java.util.function.Function<Cand, Map<String, Object>> hide = c -> {
            if (redact.equals("none") || !"set_param".equals(c.repair.get("kind"))) return c.toJson();
            Object sens = Js.get(Js.get(Js.get(shapeF, "params"), (String) c.repair.get("param")), "sensitivity");
            if (redact.equals("critical") && !"critical".equals(sens)) return c.toJson();
            redacted[0] = true;
            return Js.obj("repair", Js.obj("kind", "set_param", "param", c.repair.get("param"), "redacted", true), "cost", Js.n(c.cost), "decision", c.decision, "action", Js.copy(action));
        };
        if (redact.equals("all")) redacted[0] = true;
        else {
            List<Object> reps = new ArrayList<>();
            for (Cand c : top) reps.add(hide.apply(c));
            res.put("repairs", reps);
        }
        Cand free = null;
        for (Cand c : top) if ("allow".equals(c.decision) && !"split".equals(c.repair.get("kind"))) { free = c; break; }
        if (free != null && current.equals("escalate")) res.put("humanFree", hide.apply(free));
        if (redacted[0]) res.put("redacted", true);
        if (current.equals("escalate") || top.isEmpty()) {
            Map<String, Object> ask = Js.obj();
            Js.putIf(ask, "verb", action, "verb");
            Js.putIf(ask, "resource", action, "resource");
            ask.put("params", new LinkedHashMap<>(params));
            ask.put("kind", current.equals("escalate") ? "approval" : "access-request");
            ask.put("policyDigest", policyDigest);
            res.put("humanAsk", ask);
        }
        return res;
    }

    /** First-occurrence-ordered distinct numbers (a JavaScript Set of numbers: -0 and 0 are one value). */
    private static List<Double> distinctNums(List<Double> xs) {
        Set<Double> seen = new LinkedHashSet<>();
        for (double d : xs) seen.add(d == 0 ? 0.0 : d);
        return new ArrayList<>(seen);
    }
}
