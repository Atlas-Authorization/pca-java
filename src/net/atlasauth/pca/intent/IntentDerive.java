package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import net.atlasauth.pca.Catalog;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.CatValue;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Deriving the outcome space from the vocabulary of the policies and the structured intent slots, and compiling slots into
 * the policy they literally describe. Slots, policies and options are JSON trees (Map / List / String / Json.Num).
 */
public final class IntentDerive {
    private IntentDerive() {}

    /** Built-in numeric domains for common fields: {lo, hi, dist}. */
    private static final Map<String, Object[]> DEFAULT_DOMAINS = new LinkedHashMap<>();
    static {
        DEFAULT_DOMAINS.put("action.params.amount", new Object[] {0.0, 100000.0, "loguniform"});
        DEFAULT_DOMAINS.put("env.hour", new Object[] {0.0, 23.0, "uniform"});
        DEFAULT_DOMAINS.put("action.params.count", new Object[] {0.0, 1000.0, "loguniform"});
    }

    private static final class FieldLits {
        final Set<Double> nums = new LinkedHashSet<>();
        final Set<String> exacts = new LinkedHashSet<>();
        final Set<String> prefixes = new LinkedHashSet<>();
    }

    private static FieldLits lits(Map<String, FieldLits> m, String path) { return m.computeIfAbsent(path, k -> new FieldLits()); }

    private static void addNum(FieldLits f, double x) {
        if (!Double.isFinite(x)) return;
        f.nums.add(Math.floor(x) + 0.0);
        f.nums.add(Math.ceil(x) + 0.0);
    }

    private static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    private static void collectCond(Object c, Map<String, FieldLits> m, Set<String> approx) {
        if (!(c instanceof Map)) return;
        if (has(c, "all_of") || has(c, "any_of") || has(c, "not")) {
            if (has(c, "all_of") && get(c, "all_of") instanceof List) for (Object x : (List<?>) get(c, "all_of")) collectCond(x, m, approx);
            else if (has(c, "any_of") && get(c, "any_of") instanceof List) for (Object x : (List<?>) get(c, "any_of")) collectCond(x, m, approx);
            else if (has(c, "not")) collectCond(get(c, "not"), m, approx);
            return;
        }
        if (!(get(c, "field") instanceof String)) return;
        String field = (String) get(c, "field");
        Object op = get(c, "op");
        if (has(c, "ref")) approx.add("cross-field ref on " + field);
        if ("like".equals(op) || "matches".equals(op) || "is_a".equals(op) || "member_of".equals(op)) approx.add(op + " on " + field);
        if ("exists".equals(op)) {
            lits(m, field);
            return;
        }
        FieldLits f = lits(m, field);
        Object value = get(c, "value");
        List<Object> vals = new ArrayList<>();
        if (value instanceof List) vals.addAll((List<?>) value);
        else vals.add(value);
        for (Object v : vals) {
            if (IntentOmega.isNumber(v)) addNum(f, IntentOmega.dbl(v));
            else if (v instanceof String) ("prefix".equals(op) ? f.prefixes : f.exacts).add((String) v);
        }
    }

    private static void addResource(Object r, Map<String, FieldLits> m, Set<String> approx) {
        if (!(r instanceof String) || r.equals("*")) return;
        String s = (String) r;
        if (s.startsWith("re:")) {
            approx.add("re: resource matcher");
            return;
        }
        FieldLits f = lits(m, "action.resource");
        if (s.endsWith("*")) f.prefixes.add(s.substring(0, s.length() - 1));
        else f.exacts.add(s);
    }

    /** The verbs a predicate names, or null for the wildcard. */
    private static List<String> verbsOf(Object p) {
        Object v = get(p, "verb");
        if (v instanceof String) return v.equals("*") ? null : List.of((String) v);
        List<String> out = new ArrayList<>();
        if (v instanceof List) {
            for (Object x : (List<?>) v) if (x instanceof String && x.equals("*")) return null;
            for (Object x : (List<?>) v) if (x instanceof String) out.add((String) x);
        }
        return out;
    }

    /** Derive the space; {@code opts} members: policies, slots, domains, extraVerbs (all optional but policies). */
    public static Omega deriveOmega(Map<String, Object> opts) { return deriveOmega(opts, Catalog.DEFAULT); }

    public static Omega deriveOmega(Map<String, Object> opts, Catalog catalog) {
        Set<String> approx = new TreeSet<>();
        List<Object> preds = new ArrayList<>();
        for (Object p : (List<?>) opts.get("policies")) {
            Object ps = IntentPolicy.normalizePolicy(p).get("predicates");
            preds.addAll((List<?>) ps);
        }
        Set<String> explicit = new TreeSet<>();
        Object extra = opts.get("extraVerbs");
        if (extra instanceof List) for (Object x : (List<?>) extra) explicit.add((String) x);
        boolean wildcard = false;
        for (Object p : preds) {
            List<String> vs = verbsOf(p);
            if (vs == null) wildcard = true;
            else explicit.addAll(vs);
        }
        Object slots = opts.get("slots");
        if (get(slots, "verbs") instanceof List) for (Object x : (List<?>) get(slots, "verbs")) explicit.add((String) x);
        if (wildcard) {
            Set<String> connectors = new LinkedHashSet<>();
            for (String v : explicit) connectors.add(v.split("\\.", -1)[0]);
            List<Catalog.Spec> pool = new ArrayList<>();
            for (Catalog.Spec s : catalog.all()) if (connectors.isEmpty() || connectors.contains(s.connector)) pool.add(s);
            for (Catalog.Spec s : pool) explicit.add(s.verb);
        }
        List<Object> constraints = new ArrayList<>();
        if (get(slots, "constraints") instanceof List) constraints.addAll((List<?>) get(slots, "constraints"));
        Map<String, Object> domains = get(opts, "domains") instanceof Map ? IntentOmega.obj(opts.get("domains")) : null;
        List<VerbSpace> out = new ArrayList<>();
        for (String verb : explicit) {
            Map<String, FieldLits> m = new LinkedHashMap<>();
            for (Object p : preds) {
                List<String> pv = verbsOf(p);
                if (pv != null && !pv.contains(verb)) continue;
                addResource(get(p, "resource"), m, approx);
                if (get(p, "where") instanceof List) for (Object c : (List<?>) get(p, "where")) collectCond(c, m, approx);
            }
            for (Object sc : constraints) {
                if (has(sc, "verb") && !verb.equals(get(sc, "verb"))) continue;
                FieldLits f = lits(m, (String) get(sc, "path"));
                if (has(sc, "max") && IntentOmega.isNumber(get(sc, "max"))) addNum(f, IntentOmega.dbl(get(sc, "max")));
                if (has(sc, "min") && IntentOmega.isNumber(get(sc, "min"))) addNum(f, IntentOmega.dbl(get(sc, "min")));
                strings(get(sc, "oneOf"), f.exacts);
                strings(get(sc, "noneOf"), f.exacts);
                strings(get(sc, "prefixOneOf"), f.prefixes);
            }
            List<Dim> dims = new ArrayList<>();
            for (String path : new TreeSet<>(m.keySet())) {
                FieldLits f = m.get(path);
                if (f.nums.size() > 0 || (f.exacts.isEmpty() && f.prefixes.isEmpty() && DEFAULT_DOMAINS.containsKey(path))) {
                    List<Double> cuts = IntentOmega.sortedNums(f.nums);
                    Object[] dom = DEFAULT_DOMAINS.get(path);
                    Double dlo = dom == null ? null : (Double) dom[0], dhi = dom == null ? null : (Double) dom[1];
                    String ddist = dom == null ? null : (String) dom[2];
                    if (domains != null && domains.get(path) instanceof Map) {
                        Map<String, Object> o = IntentOmega.obj(domains.get(path));
                        dlo = IntentOmega.dbl(o.get("lo"));
                        dhi = IntentOmega.dbl(o.get("hi"));
                        ddist = o.get("dist") instanceof String ? (String) o.get("dist") : null;
                    }
                    double maxCut = cuts.isEmpty() ? 0 : cuts.get(cuts.size() - 1);
                    double minCut = cuts.isEmpty() ? 0 : cuts.get(0);
                    double lo = dlo != null ? dlo : Math.min(0, minCut - 1);
                    double hi = dhi != null ? dhi : Math.max(Math.max(10, 2 * maxCut), maxCut + 10);
                    String dist = ddist != null ? ddist : (lo >= 0 ? "loguniform" : "uniform");
                    List<Double> kept = new ArrayList<>();
                    for (double c : cuts) if (c >= lo && c <= hi) kept.add(c);
                    dims.add(new NumDim(path, lo, hi, IntentOmega.toArray(kept), dist));
                } else {
                    List<CatValue> values = new ArrayList<>();
                    for (String v : sorted(f.exacts)) values.add(new CatValue("exact", v));
                    for (String v : sorted(f.prefixes)) values.add(new CatValue("prefix", v));
                    values.add(new CatValue("other", IntentOmega.OTHER));
                    dims.add(new CatDim(path, values));
                }
            }
            Catalog.Spec spec = catalog.get(verb);
            out.add(new VerbSpace(verb, spec != null && spec.reversibility != null ? spec.reversibility : "irreversible", 0, dims));
        }
        for (VerbSpace v : out) v.weight = 1.0 / out.size();
        return new Omega(out, new ArrayList<>(approx));
    }

    private static void strings(Object o, Collection<String> into) {
        if (o instanceof List) for (Object x : (List<?>) o) into.add((String) x);
    }

    private static List<String> sorted(Collection<String> c) { return new ArrayList<>(new TreeSet<>(c)); }

    // ---- slots ----

    private static Map<String, Object> leaf(String field, String op, Object value) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("field", field);
        m.put("op", op);
        m.put("value", value);
        return m;
    }

    private static List<Object> slotConds(Object sc) {
        List<Object> out = new ArrayList<>();
        String path = (String) get(sc, "path");
        if (has(sc, "min")) out.add(leaf(path, "gte", get(sc, "min")));
        if (has(sc, "max")) out.add(leaf(path, "lte", get(sc, "max")));
        List<Object> anyOf = new ArrayList<>();
        Object oneOf = get(sc, "oneOf");
        if (oneOf instanceof List && !((List<?>) oneOf).isEmpty()) anyOf.add(leaf(path, "in", new ArrayList<Object>((List<?>) oneOf)));
        Object pre = get(sc, "prefixOneOf");
        if (pre instanceof List) for (Object p : (List<?>) pre) anyOf.add(leaf(path, "prefix", p));
        if (anyOf.size() == 1) out.add(anyOf.get(0));
        else if (anyOf.size() > 1) {
            Map<String, Object> g = new LinkedHashMap<>();
            g.put("any_of", anyOf);
            out.add(g);
        }
        Object none = get(sc, "noneOf");
        if (none instanceof List && !((List<?>) none).isEmpty()) out.add(leaf(path, "nin", new ArrayList<Object>((List<?>) none)));
        return out;
    }

    /** Compile slots into the policy they literally describe (one predicate per slot verb). */
    public static Map<String, Object> slotsToPolicy(Object slots) {
        List<Object> predicates = new ArrayList<>();
        for (Object verb : (List<?>) get(slots, "verbs")) {
            List<Object> where = new ArrayList<>();
            for (Object c : (List<?>) get(slots, "constraints")) if (!has(c, "verb") || verb.equals(get(c, "verb"))) where.addAll(slotConds(c));
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("verb", verb);
            p.put("resource", "*");
            if (!where.isEmpty()) p.put("where", where);
            predicates.add(p);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("predicates", predicates);
        out.put("caveats", new ArrayList<Object>());
        return out;
    }
}
