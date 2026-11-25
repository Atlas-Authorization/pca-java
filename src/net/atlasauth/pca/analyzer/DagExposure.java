package net.atlasauth.pca.analyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What a committed workflow (DAG) can EVER do, decided statically from its body. Deterministic and total: every number is a function of
 * the declared steps, edges and budget. Reports max steps, depth, widest level, maximal-path count (capped), per-cap cost, steps no run
 * can reach, sink lineage and label protection, ordering-only steps and pipelinable edges. Throws {@link IllegalArgumentException} on a
 * body that is not a DAG.
 */
public final class DagExposure {
    private DagExposure() {}

    private static final double PATH_CAP = 1_000_000;

    private static List<Object> listOf(Object o, String what) {
        if (!(o instanceof List)) throw new IllegalArgumentException("dagExposure: " + what + " is not an array");
        return Js.list(o);
    }

    private static String idOf(Object s) {
        Object id = Js.get(Js.req(s), "id");
        if (!(id instanceof String)) throw new IllegalArgumentException("dagExposure: step id is not a string");
        return (String) id;
    }

    /** {@code .length} of a value; reading it on null / undefined throws, as in JavaScript. */
    private static double len(Object o) {
        if (o instanceof List) return ((List<?>) o).size();
        if (o instanceof String) return ((String) o).length();
        if (o == null) throw new IllegalArgumentException("cannot read length of null");
        return Double.NaN;
    }

    public static Map<String, Object> dagExposure(Map<String, Object> b) {
        Js.req(b);
        List<Object> steps = listOf(Js.get(b, "steps"), "steps");
        Map<String, Object> budget = Js.map(Js.req(Js.get(b, "budget")));
        Map<String, Object> byId = new LinkedHashMap<>();
        for (Object s : steps) byId.put(idOf(s), s);
        if (byId.size() != steps.size()) throw new IllegalArgumentException("dagExposure: duplicate step id");
        Map<String, Integer> level = new HashMap<>();
        Map<String, Set<String>> anc = new HashMap<>();
        Set<String> visiting = new HashSet<>();
        for (Object s : steps) visit(idOf(s), byId, level, anc, visiting);
        int maxLevel = 0;
        for (int l : level.values()) maxLevel = Math.max(maxLevel, l);
        double depth = maxLevel + 1;
        Map<Integer, Integer> widths = new HashMap<>();
        for (int l : level.values()) widths.merge(l, 1, Integer::sum);
        double levelWidth = Double.NEGATIVE_INFINITY;
        for (int w : widths.values()) levelWidth = Math.max(levelWidth, w);

        // maximal paths: the number of paths from a source to each leaf
        Map<String, List<String>> children = new LinkedHashMap<>();
        for (Object s : steps) children.put(idOf(s), new ArrayList<>());
        for (Object s : steps) for (Object d : listOf(Js.get(s, "deps"), "deps")) children.get((String) d).add(idOf(s));
        Map<String, Double> memo = new HashMap<>();
        boolean[] capped = {false};
        double paths = 0;
        for (Object s : steps) if (listOf(Js.get(s, "deps"), "deps").isEmpty()) paths = Math.min(PATH_CAP, paths + toLeaves(idOf(s), children, memo, capped));

        Map<String, Object> cost = new LinkedHashMap<>();
        Object capsO = Js.get(budget, "caps");
        Map<String, Object> caps = capsO instanceof Map ? Js.map(capsO) : new LinkedHashMap<>();
        if (!(capsO instanceof Map)) throw new IllegalArgumentException("dagExposure: caps is not an object");
        for (String name : Js.keys(caps)) {
            double total = 0;
            for (Object s : steps) {
                Object c = Js.get(Js.get(s, "cost"), name);
                total = total + (c == null ? 0 : Js.toNum(c));
            }
            double cap = Js.toNum(caps.get(name));
            cost.put(name, Js.obj("cap", caps.get(name), "total", Js.n(total), "maxSpend", Js.n(Math.min(cap, total))));
        }
        List<Object> neverRunnable = new ArrayList<>();
        double maxStepsB = Js.numOrNaN(budget, "max_steps");
        for (Object s : steps) {
            boolean over = false;
            Object sc = Js.get(s, "cost");
            if (sc instanceof Map) {
                for (String n : Js.keys(Js.map(sc))) {
                    Object cap = caps.get(n);
                    if (Js.toNum(Js.map(sc).get(n)) > (cap == null ? 0 : Js.toNum(cap))) { over = true; break; }
                }
            }
            if (over) neverRunnable.add(Js.obj("step", idOf(s), "reason", "cost_over_cap"));
            else if (anc.get(idOf(s)).size() + 1 > maxStepsB) neverRunnable.add(Js.obj("step", idOf(s), "reason", "needs_more_steps_than_budget"));
        }

        // data lineage: a step's outputs reach `t` along edges (transitively through steps that consume them)
        List<Object> edges = listOf(Js.get(b, "edges"), "edges");
        Map<String, Set<String>> feeds = new HashMap<>();
        for (Object s : steps) feeds.put(idOf(s), new LinkedHashSet<>());
        for (Object e : edges) {
            Set<String> f = feeds.get((String) Js.get(Js.get(e, "to"), "step"));
            if (f == null) throw new IllegalArgumentException("dagExposure: edge to an unknown step");
            f.add((String) Js.get(Js.get(e, "from"), "step"));
        }
        List<Object> sinks = new ArrayList<>();
        List<Object> unprotected = new ArrayList<>();
        for (Object s : steps) {
            if (Js.has(s, "sink") && Js.get(s, "sink") == null) continue;
            String id = idOf(s);
            boolean incomingDeny = false;
            for (Object e : edges) if (id.equals(Js.get(Js.get(e, "to"), "step")) && len(Js.get(e, "deny_labels")) > 0) incomingDeny = true;
            Set<String> seen = new LinkedHashSet<>();
            lineageOf(id, seen, feeds);
            List<String> lineage = new ArrayList<>(seen);
            Collections.sort(lineage);
            boolean prot = len(Js.get(s, "deny_labels")) > 0 || len(Js.get(s, "escalate_labels")) > 0 || incomingDeny;
            Map<String, Object> k = Js.obj("step", id);
            Js.putIf(k, "sink", s, "sink");
            k.put("lineage", new ArrayList<Object>(lineage));
            k.put("protected", prot);
            sinks.add(k);
            if (!prot && !lineage.isEmpty()) unprotected.add(id);
        }
        List<Object> orderingOnly = new ArrayList<>();
        for (Object s : steps) {
            if (listOf(Js.get(s, "deps"), "deps").isEmpty()) continue;
            boolean has = false;
            for (Object e : edges) if (idOf(s).equals(Js.get(Js.get(e, "to"), "step"))) has = true;
            if (!has) orderingOnly.add(idOf(s));
        }
        List<Object> pipelinable = new ArrayList<>();
        for (int i = 0; i < edges.size(); i++) {
            Object e = edges.get(i);
            if (!(Js.has(e, "promise") && Js.get(e, "promise") == null)) pipelinable.add(Js.n(i));
        }
        return Js.obj("steps", Js.n(steps.size()), "maxSteps", Js.n(Math.min(steps.size(), maxStepsB)), "depth", Js.n(depth), "levelWidth", Js.n(levelWidth),
            "paths", Js.n(paths), "pathsCapped", capped[0], "cost", cost, "neverRunnable", neverRunnable, "sinks", sinks,
            "unprotectedSinks", unprotected, "orderingOnly", orderingOnly, "pipelinable", pipelinable);
    }

    private static void visit(String id, Map<String, Object> byId, Map<String, Integer> level, Map<String, Set<String>> anc, Set<String> visiting) {
        if (level.containsKey(id)) return;
        if (visiting.contains(id)) throw new IllegalArgumentException("dagExposure: cycle");
        visiting.add(id);
        Object s = byId.get(id);
        if (s == null) throw new IllegalArgumentException("dagExposure: unknown step " + id);
        Set<String> a = new LinkedHashSet<>();
        int l = 0;
        for (Object d : listOf(Js.get(s, "deps"), "deps")) {
            if (!(d instanceof String)) throw new IllegalArgumentException("dagExposure: dependency is not a step id");
            visit((String) d, byId, level, anc, visiting);
            a.add((String) d);
            a.addAll(anc.get((String) d));
            l = Math.max(l, level.get((String) d) + 1);
        }
        visiting.remove(id);
        anc.put(id, a);
        level.put(id, l);
    }

    private static double toLeaves(String id, Map<String, List<String>> children, Map<String, Double> memo, boolean[] capped) {
        Double m = memo.get(id);
        if (m != null) return m;
        List<String> kids = children.get(id);
        double n = kids.isEmpty() ? 1 : 0;
        for (String k : kids) n += toLeaves(k, children, memo, capped);
        if (n > PATH_CAP) { n = PATH_CAP; capped[0] = true; }
        memo.put(id, n);
        return n;
    }

    private static void lineageOf(String id, Set<String> seen, Map<String, Set<String>> feeds) {
        Set<String> fs = feeds.get(id);
        if (fs == null) throw new IllegalArgumentException("dagExposure: lineage through an unknown step");
        for (String f : fs) if (!seen.contains(f)) { seen.add(f); lineageOf(f, seen, feeds); }
    }
}
