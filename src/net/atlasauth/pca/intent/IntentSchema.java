package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.intent.IntentOmega.CatDim;
import net.atlasauth.pca.intent.IntentOmega.CatValue;
import net.atlasauth.pca.intent.IntentOmega.Dim;
import net.atlasauth.pca.intent.IntentOmega.NumDim;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * The outcome space from the site's signed action schema: one dimension per parameter whose effective sensitivity (after the wallet floor) is
 * material or critical, boolean / set / array parameters on their canonical projection path, closed-world default sets for silent parameters.
 * The schema, the slots, the policies and the confirmed values are JSON trees.
 */
public final class IntentSchema {
    private IntentSchema() {}

    public static final List<String> WALLET_FLOOR_PREFIXES = List.of("money.", "party.", "contact.", "person.", "credential.");
    public static final List<String> WALLET_FLOOR_EXACT = List.of("text.message");
    private static final List<String> REV = List.of("reversible", "rate_limited", "irreversible");

    /** The derived space with the wallet-floor overrides, the default-pinning slot constraints and the canonical-projection map. */
    public static final class SchemaOmega {
        public final Omega omega;
        public final List<Map<String, Object>> overrides;
        public final List<Map<String, Object>> defaults;
        public final Map<String, String> canonOf;
        SchemaOmega(Omega omega, List<Map<String, Object>> overrides, List<Map<String, Object>> defaults, Map<String, String> canonOf) {
            this.omega = omega; this.overrides = overrides; this.defaults = defaults; this.canonOf = canonOf;
        }
    }

    private static Map<String, Object> lm() { return new LinkedHashMap<>(); }

    private static Map<String, Object> m(Object o) { return IntentOmega.obj(o); }

    private static List<String> strs(Object o, List<String> dflt) {
        if (o == null) return dflt;
        List<String> out = new ArrayList<>();
        for (Object x : IntentOmega.arr(o)) out.add((String) x);
        return out;
    }

    static boolean floorApplies(String semantic, Map<String, Object> floor) {
        List<String> pre = strs(floor == null ? null : floor.get("prefixes"), WALLET_FLOOR_PREFIXES);
        List<String> ex = strs(floor == null ? null : floor.get("exact"), WALLET_FLOOR_EXACT);
        if (ex.contains(semantic)) return true;
        for (String p : pre) if (semantic.startsWith(p)) return true;
        return false;
    }

    /** The wallet's effective sensitivity: a site {@code free} on a floored semantic type becomes {@code material}. */
    public static String effectiveSensitivity(Map<String, Object> d, Map<String, Object> floor) {
        return "free".equals(d.get("sensitivity")) && floorApplies((String) d.get("semantic"), floor) ? "material" : (String) d.get("sensitivity");
    }

    private static String maxRev(List<Object> xs) {
        String a = "reversible";
        for (Object b : xs) if (REV.indexOf(b) > REV.indexOf(a)) a = (String) b;
        return a;
    }

    /** The value-independent reversibility class of a verb declaration (the worst a value can map to). */
    public static String verbReversibility(Map<String, Object> v) {
        Object by = v.get("reversibility_by");
        if (by == null) return v.get("reversibility") != null ? (String) v.get("reversibility") : "read".equals(v.get("kind")) ? "reversible" : "irreversible";
        Map<String, Object> b = m(by);
        Object d = m(v.get("params")).get(b.get("param"));
        Map<String, Object> map = m(b.get("map"));
        List<Object> mapped = new ArrayList<>(map.values());
        List<String> domain = null;
        if (d != null) {
            Map<String, Object> dm = m(d);
            if ("boolean".equals(dm.get("type"))) domain = List.of("true", "false");
            else if ("string".equals(dm.get("type")) && dm.get("values") != null) domain = strs(dm.get("values"), null);
        }
        boolean covered = domain != null;
        if (covered) for (String x : domain) if (!map.containsKey(x)) covered = false;
        List<Object> all = new ArrayList<>(mapped);
        if (!covered) all.add(b.get("default") != null ? b.get("default") : "irreversible");
        return maxRev(covered ? mapped : all);
    }

    /** Every override the wallet floor makes on the schema's verbs: [{verb, path, semantic, declared, effective}]. */
    public static List<Map<String, Object>> walletFloorOverrides(List<Object> verbs, Map<String, Object> floor) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object vo : verbs) {
            Map<String, Object> v = m(vo);
            TreeMap<String, Object> params = new TreeMap<>(Json::compareUtf8);
            params.putAll(m(v.get("params")));
            for (Map.Entry<String, Object> e : params.entrySet()) {
                Map<String, Object> d = m(e.getValue());
                String eff = effectiveSensitivity(d, floor);
                if (!eff.equals(d.get("sensitivity"))) {
                    Map<String, Object> o = lm();
                    o.put("verb", v.get("verb")); o.put("path", e.getKey()); o.put("semantic", d.get("semantic")); o.put("declared", d.get("sensitivity")); o.put("effective", eff);
                    out.add(o);
                }
            }
        }
        return out;
    }

    private static String canonPath(String paramPath) { return "env.canon." + paramPath.substring("action.params.".length()); }

    private static boolean usesCanon(Map<String, Object> d) { Object t = d.get("type"); return "boolean".equals(t) || "set".equals(t) || "array".equals(t); }

    private static String jsStr(Object x) {
        if (x == null) return "null";
        if (x instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object e : (List<?>) x) { if (!first) sb.append(','); first = false; sb.append(e == null ? "" : jsStr(e)); }
            return sb.toString();
        }
        if (IntentOmega.isNumber(x)) return net.atlasauth.pca.AttestCommon.jsNumString(IntentOmega.dbl(x));
        return String.valueOf(x);
    }

    /** The canonical text a value of a canon-projected parameter has. */
    public static String canonValue(Map<String, Object> d, Object x) {
        if ("boolean".equals(d.get("type"))) return Boolean.TRUE.equals(x) ? "true" : "false";
        Object norm = IntentJs.normalize(x);
        if ("set".equals(d.get("type"))) {
            List<String> l = new ArrayList<>();
            for (Object e : IntentOmega.arr(norm)) l.add((String) e);
            l.sort(Json::compareUtf8);
            return Json.canonicalizeStrict(new ArrayList<Object>(l));
        }
        return Json.canonicalizeStrict(norm);
    }

    private static List<String> sortedUtf8(Set<String> s) {
        List<String> l = new ArrayList<>(s);
        l.sort(Json::compareUtf8);
        return l;
    }

    /**
     * Derive the space. {@code o}: schema {verbs}, verbs?, slots?, policies?, confirmed?, floor?, domains?. Throws on a malformed schema.
     */
    public static SchemaOmega deriveOmegaFromSchema(Map<String, Object> o) {
        List<Object> schemaVerbs = IntentOmega.arr(m(o.get("schema")).get("verbs"));
        List<String> verbNames;
        if (o.get("verbs") != null) verbNames = strs(o.get("verbs"), null);
        else {
            Set<String> set = new LinkedHashSet<>();
            for (Object v : schemaVerbs) if ("write".equals(m(v).get("kind"))) set.add((String) m(v).get("verb"));
            if (o.get("slots") != null && m(o.get("slots")).get("verbs") != null) set.addAll(strs(m(o.get("slots")).get("verbs"), null));
            verbNames = new ArrayList<>(set);
        }
        Map<String, Object> baseOpts = lm();
        baseOpts.put("policies", o.get("policies") != null ? o.get("policies") : new ArrayList<>());
        if (o.get("slots") != null) baseOpts.put("slots", o.get("slots"));
        baseOpts.put("extraVerbs", new ArrayList<Object>(verbNames));
        Omega base = IntentDerive.deriveOmega(baseOpts);
        Map<String, Object> floor = o.get("floor") == null ? null : m(o.get("floor"));
        List<Map<String, Object>> defaults = new ArrayList<>();
        Map<String, String> canonOf = new LinkedHashMap<>();
        List<VerbSpace> verbs = new ArrayList<>();
        List<String> sortedNames = new ArrayList<>(verbNames);
        sortedNames.sort(Json::compareUtf8);
        Map<String, Object> confirmed = o.get("confirmed") == null ? new LinkedHashMap<>() : m(o.get("confirmed"));
        Map<String, Object> domains = o.get("domains") == null ? new LinkedHashMap<>() : m(o.get("domains"));
        for (String verb : sortedNames) {
            Map<String, Object> decl = null;
            for (Object v : schemaVerbs) if (verb.equals(m(v).get("verb"))) { decl = m(v); break; }
            if (decl == null) continue;
            VerbSpace lits = null;
            for (VerbSpace v : base.verbs) if (v.verb.equals(verb)) { lits = v; break; }
            List<Dim> dims = new ArrayList<>();
            if (lits != null) for (Dim d : lits.dims) if (!d.path.startsWith("action.params.")) dims.add(d);
            TreeMap<String, Object> params = new TreeMap<>(Json::compareUtf8);
            params.putAll(m(decl.get("params")));
            for (Map.Entry<String, Object> pe : params.entrySet()) {
                String path = pe.getKey();
                Map<String, Object> pd = m(pe.getValue());
                if ("free".equals(effectiveSensitivity(pd, floor))) continue;
                Dim lit = null;
                if (lits != null) for (Dim d : lits.dims) if (d.path.equals(path)) { lit = d; break; }
                boolean silent = lit == null;
                List<Object> defaultSet = new ArrayList<>();
                if (confirmed.get(path) != null) defaultSet.addAll(IntentOmega.arr(confirmed.get(path)));
                if (Boolean.TRUE.equals(pd.get("principal_neutral_default")) && pd.containsKey("default")) defaultSet.add(pd.get("default"));
                if ("integer".equals(pd.get("type"))) {
                    Set<Double> cuts = new LinkedHashSet<>();
                    if (lit instanceof NumDim nd) for (double c : nd.cuts) cuts.add(c + 0.0);
                    for (Object x : defaultSet) if (IntentOmega.isNumber(x) && Math.abs(IntentOmega.dbl(x)) <= 9007199254740991.0 && IntentOmega.dbl(x) == Math.floor(IntentOmega.dbl(x))) cuts.add(IntentOmega.dbl(x) + 0.0);
                    List<Double> sorted = new ArrayList<>(cuts);
                    java.util.Collections.sort(sorted);
                    double maxCut = sorted.isEmpty() ? 0 : sorted.get(sorted.size() - 1);
                    Map<String, Object> dom = domains.get(path) == null ? null : m(domains.get(path));
                    double lo = dom != null && dom.get("lo") != null ? IntentOmega.dbl(dom.get("lo")) : pd.get("min") != null ? IntentOmega.dbl(pd.get("min")) : Math.min(0, sorted.isEmpty() ? 0 : sorted.get(0) - 1);
                    double hi = dom != null && dom.get("hi") != null ? IntentOmega.dbl(dom.get("hi")) : pd.get("max") != null ? IntentOmega.dbl(pd.get("max")) : Math.max(10, Math.max(2 * maxCut, maxCut + 10));
                    List<Double> kept = new ArrayList<>();
                    for (double c : sorted) if (c >= lo && c <= hi) kept.add(c);
                    dims.add(new NumDim(path, lo, hi, IntentOmega.toArray(kept), lo >= 0 ? "loguniform" : "uniform"));
                    List<Double> nums = new ArrayList<>();
                    for (Object x : defaultSet) if (IntentOmega.isNumber(x)) nums.add(IntentOmega.dbl(x));
                    if (silent && nums.size() == 1) {
                        Map<String, Object> c = lm();
                        c.put("verb", verb); c.put("path", path); c.put("min", nums.get(0)); c.put("max", nums.get(0));
                        defaults.add(c);
                    }
                    continue;
                }
                boolean canon = usesCanon(pd);
                String dimPath = canon ? canonPath(path) : path;
                if (canon) canonOf.put(dimPath, path);
                Set<String> exacts = new LinkedHashSet<>(), prefixes = new LinkedHashSet<>();
                if (lit instanceof CatDim cd) for (CatValue v : cd.values) { if (v.kind().equals("exact")) exacts.add(v.value()); else if (v.kind().equals("prefix")) prefixes.add(v.value()); }
                if ("string".equals(pd.get("type")) && pd.get("values") != null) exacts.addAll(strs(pd.get("values"), null));
                if ("boolean".equals(pd.get("type"))) { exacts.add("false"); exacts.add("true"); }
                List<String> defTexts = new ArrayList<>();
                for (Object x : defaultSet) defTexts.add(canon ? canonValue(pd, x) : jsStr(x));
                exacts.addAll(defTexts);
                List<CatValue> values = new ArrayList<>();
                for (String s : sortedUtf8(exacts)) values.add(new CatValue("exact", s));
                for (String s : sortedUtf8(prefixes)) values.add(new CatValue("prefix", s));
                values.add(new CatValue("other", IntentOmega.OTHER));
                dims.add(new CatDim(dimPath, values));
                if (silent && !defTexts.isEmpty()) {
                    Map<String, Object> c = lm();
                    c.put("verb", verb); c.put("path", dimPath); c.put("oneOf", new ArrayList<Object>(sortedUtf8(new LinkedHashSet<>(defTexts))));
                    defaults.add(c);
                }
            }
            dims.sort((a, b) -> Json.compareUtf8(a.path, b.path));
            verbs.add(new VerbSpace(verb, verbReversibility(decl), 0, dims));
        }
        for (VerbSpace v : verbs) v.weight = 1.0 / (verbs.isEmpty() ? 1 : verbs.size());
        List<Object> included = new ArrayList<>();
        for (Object v : schemaVerbs) if (verbNames.contains(m(v).get("verb"))) included.add(v);
        return new SchemaOmega(new Omega(verbs, new ArrayList<>(base.approximate)), walletFloorOverrides(included, floor), defaults, canonOf);
    }
}
