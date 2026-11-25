package net.atlasauth.pca.analyzer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.analyzer.Enumerate.PolicyModel;

/**
 * VALIDATING A POLICY AGAINST THE ACTION SCHEMA / ACTIONDEFS: a lint that compares the two descriptions of the same actions before the
 * policy is signed (an undeclared parameter, a number compared with a string, an enum value that does not exist, a bound the schema makes
 * impossible or redundant, a predicate that can never match, a money verb with no ceiling, a unit-bearing parameter read without the matching
 * unit tag). Verb shapes are {verb, params: {name: {type?, values?, min?, max?, unit?, semantic?, sensitivity?, required?}}}.
 */
public final class Validate {
    private Validate() {}

    private static final List<String> DEF_TYPES = Arrays.asList("string", "integer", "boolean", "date", "set", "array");
    private static final List<String> NUMERIC_OPS = Arrays.asList("lt", "lte", "gt", "gte");
    private static final Object UNDEF = new Object();

    /**
     * Verb shapes from real ActionDefs ({verb, params: {name: {type, role?, required?, values?, min?, max?, sensitivity?}}}). Types the
     * policy language cannot compare directly ({@code datetime}, {@code duration}, {@code object_ref}) are left untyped; a money role keeps
     * its semantic so the unbounded-money lint applies.
     */
    public static List<Object> verbShapesFromActionDefs(List<Object> defs) {
        List<Object> out = new ArrayList<>();
        for (Object d : defs) {
            Map<String, Object> params = new LinkedHashMap<>();
            Map<String, Object> dp = Js.copy(Js.get(d, "params"));
            for (String k : Js.keys(dp)) params.put(k, shapeOfDef(dp.get(k)));
            Map<String, Object> s = Js.obj();
            Js.putIf(s, "verb", d, "verb");
            s.put("params", params);
            out.add(s);
        }
        return out;
    }

    private static Map<String, Object> shapeOfDef(Object p) {
        Map<String, Object> m = Js.obj();
        Object t = Js.get(Js.req(p), "type");
        if (t instanceof String && DEF_TYPES.contains(t)) m.put("type", t);
        if (Js.truthy(Js.get(p, "role"))) m.put("semantic", Js.get(p, "role"));
        if (Js.truthy(Js.get(p, "values"))) m.put("values", Js.get(p, "values"));
        if (Js.has(p, "min")) m.put("min", Js.get(p, "min"));
        if (Js.has(p, "max")) m.put("max", Js.get(p, "max"));
        if (Js.truthy(Js.get(p, "sensitivity"))) m.put("sensitivity", Js.get(p, "sensitivity"));
        if (Js.has(p, "required")) m.put("required", Js.get(p, "required"));
        return m;
    }

    /** The verbs and parameters of a signed action schema ({verbs: [...]}), a list of shapes, or a list of ActionDefs. */
    public static List<Object> verbShapes(Object src) {
        List<Object> out = new ArrayList<>();
        if (!(src instanceof List) && Js.has(src, "verbs")) {
            for (Object v : Js.list(Js.get(src, "verbs"))) {
                Map<String, Object> params = new LinkedHashMap<>();
                Map<String, Object> vp = Js.copy(Js.get(v, "params"));
                for (String k : Js.keys(vp)) {
                    Object d = vp.get(k);
                    Map<String, Object> m = Js.obj();
                    Js.putIf(m, "type", d, "type");
                    if (Js.truthy(Js.get(d, "values"))) m.put("values", Js.get(d, "values"));
                    if (Js.has(d, "min")) m.put("min", Js.get(d, "min"));
                    if (Js.has(d, "max")) m.put("max", Js.get(d, "max"));
                    if (Js.truthy(Js.get(d, "unit"))) m.put("unit", Js.get(d, "unit"));
                    Js.putIf(m, "semantic", d, "semantic");
                    Js.putIf(m, "sensitivity", d, "sensitivity");
                    if (Js.has(d, "required")) m.put("required", Js.get(d, "required"));
                    params.put(k, m);
                }
                Map<String, Object> s = Js.obj();
                Js.putIf(s, "verb", v, "verb");
                s.put("params", params);
                out.add(s);
            }
            return out;
        }
        for (Object d : Js.list(src)) {
            Object verb = Js.truthy(Js.get(d, "verb")) ? Js.get(d, "verb") : Js.truthy(Js.get(d, "id")) ? Js.get(d, "id") : "";
            Map<String, Object> orig = Js.copy(Js.get(d, "params"));
            Map<String, Object> params = new LinkedHashMap<>();
            for (String k : Js.keys(orig)) {
                Map<String, Object> m = shapeOfDef(orig.get(k));
                // shape-style params carry `semantic` and `unit` directly; keep them
                Object o = orig.get(k);
                if (Js.has(o, "semantic")) m.put("semantic", Js.get(o, "semantic"));
                if (Js.has(o, "unit")) m.put("unit", Js.get(o, "unit"));
                params.put(k, m);
            }
            out.add(Js.obj("verb", verb, "params", params));
        }
        return out;
    }

    private static void leaves(Object c, List<Object> into) {
        if (!(c instanceof Map || c instanceof List)) return;
        if (Field.isGroup(c)) {
            if (Js.has(c, "all_of") && Js.get(c, "all_of") instanceof List) for (Object x : (List<?>) Js.get(c, "all_of")) leaves(x, into);
            else if (Js.has(c, "any_of") && Js.get(c, "any_of") instanceof List) for (Object x : (List<?>) Js.get(c, "any_of")) leaves(x, into);
            else if (Js.has(c, "not")) leaves(Js.get(c, "not"), into);
        } else into.add(c);
    }

    private static boolean typeOk(Object t, Object v) {
        if (t == null) return true;
        if ("integer".equals(t)) return Js.isFin(v);
        if ("boolean".equals(t)) return v instanceof Boolean;
        if ("string".equals(t) || "date".equals(t)) return v instanceof String;
        return true;
    }

    private static String typeofJs(Object x) {
        if (x == null) return "object";
        if (x instanceof String) return "string";
        if (x instanceof Boolean) return "boolean";
        if (Js.isNum(x)) return "number";
        return "object";
    }

    private static String s(Object o) { return CaveatAnalysis.jsString(o, o != UNDEF); }

    private static boolean verbMatches(Object pv, Object verb) {
        return "*".equals(pv) || Js.strictEq(pv, verb) || (pv instanceof List && (Js.includes((List<?>) pv, "*") || Js.includes((List<?>) pv, verb)));
    }

    private static String bound(Object x, String dflt) { return x == null ? dflt : CaveatAnalysis.jsString(x, true); }

    /**
     * Lint a policy against the schema it is written for: {ok (false when any finding is an error), findings: [{code, severity, message, where}]}.
     * Options: units (the grant's unit map), schemaUnits, listUngranted.
     */
    public static Map<String, Object> validatePolicyAgainstSchema(Object policy, Object src, Map<String, Object> o) {
        List<Object> shapes = verbShapes(src);
        Map<String, Map<String, Object>> byVerb = new LinkedHashMap<>();
        for (Object sh : shapes) if (Js.get(sh, "verb") instanceof String) byVerb.put((String) Js.get(sh, "verb"), Js.map(sh));
        Object schemaUnits = Js.get(o, "schemaUnits");
        if (schemaUnits == null && !(src instanceof List) && Js.has(src, "units")) schemaUnits = Js.get(src, "units");
        PolicyModel model = Enumerate.toModel(policy);
        List<Object> findings = new ArrayList<>();
        boolean hasUnits = Js.has(o, "units");

        for (int i = 0; i < model.predicates.size(); i++) {
            Object p = model.predicates.get(i);
            if (!(p instanceof Map || p instanceof List)) continue;
            check(p, "predicates[" + i + "]", false, shapes, byVerb, o, hasUnits, schemaUnits, findings);
            Map<String, Object> r = Analyzer.alwaysDenies(Js.obj("predicates", Js.arr(p)));
            if (Boolean.TRUE.equals(r.get("alwaysDenies")) && !Js.truthy(r.get("approximate"))) add(findings, "unreachable-predicate", "warn", "predicates[" + i + "]", "no action can ever match this predicate");
        }
        for (int i = 0; i < model.vetoes.size(); i++) check(Js.req(Js.get(model.vetoes.get(i), "when")), "vetoes[" + i + "]", true, shapes, byVerb, o, hasUnits, schemaUnits, findings);

        // a money verb with no ceiling in any predicate that grants it
        for (Object sh : shapes) {
            Object verb = Js.get(sh, "verb");
            Map<String, Object> sp = Js.copy(Js.get(sh, "params"));
            List<String> money = new ArrayList<>();
            for (String k : Js.keys(sp)) if (isMoney(sp.get(k))) money.add(k);
            if (money.isEmpty()) continue;
            List<Object> granting = new ArrayList<>();
            for (Object p : model.predicates) if (verbMatches(Js.get(p, "verb"), verb)) granting.add(p);
            if (granting.isEmpty()) {
                if (Js.truthy(Js.get(o, "listUngranted"))) add(findings, "verb-not-granted", "info", s(verb), "the schema declares '" + s(verb) + "' but no predicate grants it");
                continue;
            }
            for (String name : money) {
                String path = "action.params." + name;
                boolean all = true;
                for (Object p : granting) if (!bounded(p, path)) { all = false; break; }
                if (!all) add(findings, "unbounded-money", "warn", s(verb), "'" + s(verb) + "' can move '" + name + "' with no per-action ceiling in at least one granting predicate");
            }
        }
        if (Js.truthy(Js.get(o, "listUngranted"))) {
            for (Object sh : shapes) {
                Map<String, Object> sp = Js.copy(Js.get(sh, "params"));
                boolean anyMoney = false;
                for (Object d : sp.values()) if (isMoney(d)) anyMoney = true;
                if (anyMoney) continue;
                boolean granted = false;
                for (Object p : model.predicates) if (verbMatches(Js.get(p, "verb"), Js.get(sh, "verb"))) granted = true;
                if (!granted) add(findings, "verb-not-granted", "info", s(Js.get(sh, "verb")), "the schema declares '" + s(Js.get(sh, "verb")) + "' but no predicate grants it");
            }
        }
        boolean ok = true;
        for (Object f : findings) if ("error".equals(Js.get(f, "severity"))) ok = false;
        return Js.obj("ok", ok, "findings", findings);
    }

    private static boolean isMoney(Object d) {
        Object sem = Js.get(d, "semantic");
        return sem != null && ((String) sem).startsWith("money.");
    }

    private static boolean bounded(Object p, String path) {
        Object w = Js.get(p, "where");
        if (!(w instanceof List)) return false;
        for (Object c : (List<?>) w) {
            Object target = Field.isGroup(c) ? Js.obj("all_of", Js.has(c, "all_of") ? Js.get(c, "all_of") : new ArrayList<Object>()) : c;
            List<Object> ls = new ArrayList<>();
            leaves(target, ls);
            for (Object l : ls) {
                Object op = Js.get(l, "op");
                if (Field.isLeaf(l) && path.equals(Js.get(l, "field")) && ("lt".equals(op) || "lte".equals(op) || "eq".equals(op) || "in".equals(op))) return true;
            }
        }
        return false;
    }

    private static void add(List<Object> findings, String code, String severity, String where, String message) {
        findings.add(Js.obj("code", code, "severity", severity, "where", where, "message", message));
    }

    private static void check(Object p, String where, boolean isVeto, List<Object> shapes, Map<String, Map<String, Object>> byVerb, Map<String, Object> o,
                              boolean hasUnits, Object schemaUnits, List<Object> findings) {
        Object pv = Js.get(p, "verb");
        List<Object> verbs = new ArrayList<>();
        if ("*".equals(pv) || (pv instanceof List && Js.includes((List<?>) pv, "*"))) for (Object sh : shapes) verbs.add(Js.get(sh, "verb"));
        else if (pv instanceof List) verbs.addAll((List<?>) pv);
        else verbs.add(Js.has(p, "verb") ? pv : UNDEF);
        for (Object v : verbs) {
            if (!(v instanceof String) || !byVerb.containsKey(v)) add(findings, "undeclared-verb", isVeto ? "warn" : "error", where, "verb '" + s(v) + "' is not declared by the schema");
        }
        List<Map<String, Object>> declared = new ArrayList<>();
        for (Object v : verbs) if (v instanceof String && byVerb.containsKey(v)) declared.add(byVerb.get(v));
        if (declared.isEmpty()) return;
        Object pw = Js.get(p, "where");
        if (!(pw instanceof List)) return;
        List<Object> wl = Js.list(pw);
        for (int wi = 0; wi < wl.size(); wi++) {
            List<Object> cs = new ArrayList<>();
            leaves(wl.get(wi), cs);
            for (Object c : cs) {
                if (!Field.isLeaf(c) || !((String) Js.get(c, "field")).startsWith("action.params.")) continue;
                String name = ((String) Js.get(c, "field")).substring("action.params.".length()).split("\\.", -1)[0];
                String at = where + ".where[" + wi + "]";
                List<Map<String, Object>> having = new ArrayList<>();
                for (Map<String, Object> sh : declared) if (Js.get(sh, "params") instanceof Map && Js.map(Js.get(sh, "params")).containsKey(name)) having.add(sh);
                if (having.isEmpty()) {
                    add(findings, "undeclared-param", "error", at, "parameter '" + name + "' is declared by none of " + joinVerbs(declared));
                    continue;
                }
                if (having.size() < declared.size()) {
                    List<Map<String, Object>> rest = new ArrayList<>();
                    for (Map<String, Object> sh : declared) if (!having.contains(sh)) rest.add(sh);
                    add(findings, "undeclared-param", "warn", at, "parameter '" + name + "' is not declared by " + joinVerbs(rest));
                }
                Object d = Js.map(Js.get(having.get(0), "params")).get(name);
                Object op = Js.get(c, "op");
                Object value = Js.get(c, "value");
                List<Object> vals = value instanceof List && ("in".equals(op) || "nin".equals(op)) ? Js.list(value) : Js.arr(value);
                Object dtype = Js.get(d, "type");
                boolean noRef = !Js.has(c, "ref");
                if (noRef && op instanceof String && (Arrays.asList("eq", "ne", "in", "nin").contains(op) || NUMERIC_OPS.contains(op))) {
                    for (Object x : vals) if (!typeOk(dtype, x)) add(findings, "type-mismatch", "error", at, "'" + name + "' is " + s(dtype) + " but is compared (" + op + ") with " + typeofJs(x));
                }
                if (op instanceof String && NUMERIC_OPS.contains(op) && dtype != null && !"integer".equals(dtype)) {
                    if ("string".equals(dtype) || "date".equals(dtype)) add(findings, "ordering-on-string", "warn", at, "'" + name + "' is " + s(dtype) + ": ordering follows UTF-8 byte order");
                    else add(findings, "type-mismatch", "error", at, "ordering operator " + op + " on " + s(dtype) + " parameter '" + name + "'");
                }
                Object dvals = Js.get(d, "values");
                if (Js.truthy(dvals) && ("eq".equals(op) || "in".equals(op)) && !vals.isEmpty() && vals.get(0) instanceof String) {
                    List<Object> missing = new ArrayList<>();
                    for (Object x : vals) if (x instanceof String && !Js.includes(Js.list(dvals), x)) missing.add(x);
                    if (missing.size() == vals.size()) add(findings, "value-not-in-enum", "error", at, "no value of " + op + " " + Js.stringify(vals) + " is in the schema's set for '" + name + "'");
                    else if (!missing.isEmpty()) add(findings, "value-not-in-enum", "warn", at, Js.stringify(missing) + " are not in the schema's set for '" + name + "'");
                }
                if ("integer".equals(dtype) && Js.isNum(value) && noRef) {
                    double v = Js.num(value);
                    boolean hasMax = Js.has(d, "max"), hasMin = Js.has(d, "min");
                    double dmax = hasMax ? Js.toNum(Js.get(d, "max")) : Double.NaN, dmin = hasMin ? Js.toNum(Js.get(d, "min")) : Double.NaN;
                    String opS = op instanceof String ? (String) op : "";
                    boolean dead = (opS.equals("eq") && ((hasMax && v > dmax) || (hasMin && v < dmin)))
                        || (opS.equals("gt") && hasMax && v >= dmax)
                        || (opS.equals("gte") && hasMax && v > dmax)
                        || (opS.equals("lt") && hasMin && v <= dmin)
                        || (opS.equals("lte") && hasMin && v < dmin);
                    String range = "[" + bound(Js.get(d, "min"), "-inf") + ", " + bound(Js.get(d, "max"), "inf") + "]";
                    if (dead) add(findings, "out-of-range", "error", at, "'" + name + "' " + opS + " " + Js.fmt(v) + " can never hold: the schema bounds it to " + range);
                    else if ((opS.equals("lte") && hasMax && v >= dmax) || (opS.equals("gte") && hasMin && v <= dmin)) add(findings, "redundant-bound", "info", at, "'" + name + "' " + opS + " " + Js.fmt(v) + " never binds: the schema already bounds it to " + range);
                }
                Object unit = Js.get(d, "unit");
                if (Js.truthy(unit) && hasUnits && op instanceof String && (NUMERIC_OPS.contains(op) || op.equals("eq")) && !isVeto) {
                    Object units = Js.get(o, "units");
                    Object tag = Js.get(units, (String) Js.get(c, "field"));
                    if (tag == null) tag = Js.get(units, "action.params." + name);
                    Object sch = schemaUnits == null ? null : Js.get(schemaUnits, s(unit));
                    if (tag == null) add(findings, "unit-missing", "error", at, "'" + name + "' carries unit '" + s(unit) + "' but the policy has no unit tag for it (rule 20)");
                    else if (Js.truthy(sch) && (!Js.strictEq(Js.get(tag, "kind"), Js.get(sch, "kind")) || !Js.strictEq(Js.get(tag, "currency"), Js.get(sch, "currency")) || !Js.strictEq(Js.get(tag, "exponent"), Js.get(sch, "exponent")))) {
                        add(findings, "unit-mismatch", "error", at, "'" + name + "': policy unit " + Js.stringify(tag) + " differs from the schema's " + Js.stringify(sch) + " (rule 20)");
                    }
                }
            }
        }
    }

    private static String joinVerbs(List<Map<String, Object>> shapes) {
        List<String> vs = new ArrayList<>();
        for (Map<String, Object> sh : shapes) vs.add(CaveatAnalysis.jsString(Js.get(sh, "verb"), Js.has(sh, "verb")));
        return String.join(", ", vs);
    }
}
