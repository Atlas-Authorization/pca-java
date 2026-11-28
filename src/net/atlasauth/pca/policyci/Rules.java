package net.atlasauth.pca.policyci;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.analyzer.Analyzer;
import net.atlasauth.pca.analyzer.Field;

/**
 * The policy-safety rules, each driving the static analyzer. Every rule is sound: a hard error is only emitted from a PROVEN analyzer
 * verdict (its result is not approximate); an undecidable feature downgrades to a warning or note that says so. A finding is
 * {@code {rule, severity, message, where?}}.
 */
public final class Rules {
    private Rules() {}

    /** Scope-narrowing caveat types (constrain WHAT or HOW MUCH, not merely WHEN). */
    public static final List<String> SCOPE_NARROWING_CAVEATS = List.of("max_blast_radius", "rate", "reversibility_max", "budget_alloc", "delegation_depth");
    /** Blast, rate and budget gate caveat types (the safety-floor gates, distinct from a time bound). */
    public static final List<String> BUDGET_GATE_CAVEATS = List.of("max_blast_radius", "rate", "budget_alloc");

    // ---- util ----

    /** A predicate's verb as a list of concrete strings. */
    static List<String> verbsOf(Object verb) {
        List<String> out = new ArrayList<>();
        if (verb instanceof String) out.add((String) verb);
        else if (verb instanceof List) for (Object x : (List<?>) verb) if (x instanceof String) out.add((String) x);
        return out;
    }

    /** Case-insensitive {@code includes} of a verb against a dangerous-substring set. */
    static boolean isDangerousVerb(String verb, List<String> dangerous) {
        String v = verb.toLowerCase(Locale.ROOT);
        for (String kw : dangerous) if (v.contains(kw.toLowerCase(Locale.ROOT))) return true;
        return false;
    }

    /** A resource matcher that admits every resource: omitted or {@code *}. */
    static boolean isWildcardResource(Object predicate) {
        return !Js.has(predicate, "resource") || "*".equals(Js.get(predicate, "resource"));
    }

    static boolean hasCaveatOfType(List<?> caveats, List<String> types) {
        for (Object c : caveats) if (c instanceof Map && Js.get(c, "type") instanceof String && types.contains(Js.get(c, "type"))) return true;
        return false;
    }

    /** A one-line rendering of an analyzer witness / counterexample action. */
    static String describeAction(Map<String, Object> a) {
        List<Object> parts = new ArrayList<>();
        parts.add(a.get("verb"));
        parts.add(a.get("resource"));
        Object params = a.get("params");
        if ((params instanceof Map && !((Map<?, ?>) params).isEmpty()) || (params instanceof List && !((List<?>) params).isEmpty())) parts.add(Js.stringify(params));
        if (a.containsKey("reversibilityClass")) parts.add("[" + Js.str(a.get("reversibilityClass")) + "]");
        return Js.joinSpace(parts);
    }

    private static List<String> uniq(List<String> xs) { return new ArrayList<>(new LinkedHashSet<>(xs)); }

    private static Map<String, Object> find(String rule, String severity, String message, String where) {
        Map<String, Object> f = Js.obj("rule", rule, "severity", severity, "message", message);
        if (where != null) f.put("where", where);
        return f;
    }

    private static Map<String, Object> analyzerInput(Map<String, Object> p) { return Js.obj("predicates", p.get("predicates"), "caveats", p.get("caveats")); }

    @SuppressWarnings("unchecked") private static List<Object> predicatesOf(Map<String, Object> p) { return (List<Object>) p.get("predicates"); }
    @SuppressWarnings("unchecked") private static List<Object> caveatsOf(Map<String, Object> p) { return (List<Object>) p.get("caveats"); }

    /** Every concrete verb named across the predicate set. */
    private static List<String> declaredVerbs(List<Object> predicates) {
        List<String> concrete = new ArrayList<>();
        for (Object p : predicates) {
            if (!Js.isObject(p)) continue;
            for (String v : verbsOf(Js.get(p, "verb"))) if (!v.equals("*")) concrete.add(v);
        }
        return uniq(concrete);
    }

    /** The budget / step-up gate that bounds a dangerous action, or null. */
    private static String gateDescription(Map<String, Object> policy) {
        List<String> gates = new ArrayList<>();
        List<Object> caveats = caveatsOf(policy);
        if (hasCaveatOfType(caveats, BUDGET_GATE_CAVEATS)) {
            List<String> types = new ArrayList<>();
            for (Object c : caveats) {
                // the reference reads c.type on every element: a null one throws
                if (c == null) throw new IllegalStateException("Cannot read properties of null (reading 'type')");
                Object t = Js.get(c, "type");
                if (t instanceof String && BUDGET_GATE_CAVEATS.contains(t)) types.add((String) t);
            }
            gates.add(String.join("/", types));
        }
        Object rp = policy.get("riskPolicy");
        if (rp != null || policy.containsKey("riskPolicy")) {
            Double theta2 = Js.finite(Js.get(rp, "theta2"));
            if (theta2 != null && theta2 < 1) gates.add("risk step-up (theta2 < 1)");
        }
        return gates.isEmpty() ? null : String.join(", ", gates);
    }

    // ---- 1. over-broad grant ----

    public static List<Object> ruleOverBroadGrant(Map<String, Object> policy, List<String> dangerous, Map<String, Object> opts) {
        List<Object> out = new ArrayList<>();
        Map<String, Object> input = analyzerInput(policy);
        boolean hasScopeNarrowing = hasCaveatOfType(caveatsOf(policy), SCOPE_NARROWING_CAVEATS);

        List<Object> preds = predicatesOf(policy);
        for (int i = 0; i < preds.size(); i++) {
            Object p = preds.get(i);
            if (!Js.isObject(p)) continue;
            List<String> verbs = verbsOf(Js.get(p, "verb"));
            String where = "predicates[" + i + "]";
            Object w = Js.get(p, "where");
            boolean hasWhere = w instanceof List && !((List<?>) w).isEmpty();

            if (verbs.contains("*")) {
                out.add(find("over-broad-grant", "error", "predicate grants a WILDCARD verb '*' — authority over any action", where));
            }
            if (isWildcardResource(p)) {
                List<Object> dangerousVerbs = new ArrayList<>();
                for (String v : verbs) if (isDangerousVerb(v, dangerous)) dangerousVerbs.add(v);
                if (!dangerousVerbs.isEmpty()) {
                    out.add(find("over-broad-grant", "error", "dangerous verb(s) " + Js.stringify(dangerousVerbs) + " granted on a WILDCARD resource ('*')", where));
                } else if (!verbs.contains("*")) {
                    out.add(find("over-broad-grant", "warn", "predicate matches ANY resource ('*') — consider a resource prefix", where));
                }
            }
            for (String v : verbs) {
                if (!v.equals("*") && isDangerousVerb(v, dangerous) && !hasWhere && !hasScopeNarrowing) {
                    out.add(find("over-broad-grant", "error",
                        "dangerous verb '" + v + "' is granted with NO narrowing `where` and no scope-narrowing caveat (" + String.join("/", SCOPE_NARROWING_CAVEATS) + ")", where));
                }
            }
        }

        // Semantic always-allow: a verb the analyzer PROVES is total (admits every action of that verb).
        for (String v : declaredVerbs(preds)) {
            Map<String, Object> aa = Analyzer.alwaysAllows(input, v, opts);
            if (Boolean.TRUE.equals(aa.get("alwaysAllows")) && !Boolean.TRUE.equals(aa.get("approximate"))) {
                out.add(find("over-broad-grant", "error", "grants EVERY action of '" + v + "' — the authority has no effective constraint (always-allow)", null));
            }
        }
        return out;
    }

    // ---- 2. privilege escalation in a chain ----

    @SuppressWarnings("unchecked")
    public static List<Object> rulePrivilegeEscalation(List<Object> hops, Map<String, Object> opts) {
        List<Object> out = new ArrayList<>();
        for (int i = 1; i < hops.size(); i++) {
            Map<String, Object> parent = (Map<String, Object>) hops.get(i - 1), child = (Map<String, Object>) hops.get(i);
            Map<String, Object> s = Analyzer.subsumes(analyzerInput(parent), analyzerInput(child), opts);
            String where = "hop[" + i + "]";
            if (Boolean.TRUE.equals(s.get("subsumes"))) continue;
            if (Boolean.TRUE.equals(s.get("approximate"))) {
                out.add(find("privilege-escalation", "warn", "could not prove hop " + i + " attenuation (undecidable" + reasonSuffix(s.get("reason")) + ") — attenuation not verified", where));
            } else {
                Object cx = s.get("counterexample");
                String ex = cx != null ? " — child admits '" + describeAction((Map<String, Object>) cx) + "' which its parent denies" : "";
                out.add(find("privilege-escalation", "error",
                    "delegation hop " + i + " ESCALATES authority: its effective authority is not a subset of its parent (attenuation violated)" + ex, where));
            }
        }
        return out;
    }

    /** {@code reason ? ": " + reason : ""} (a non-empty string; absent or empty is nothing). */
    private static String reasonSuffix(Object reason) {
        return reason instanceof String && !((String) reason).isEmpty() ? ": " + reason : "";
    }

    // ---- 3. unused / redundant caveat ----

    private static final String[][] ORDERED_CAVEATS = {
        { "expires", "at", "min" }, { "not_before", "at", "max" }, { "max_blast_radius", "max", "min" }, { "delegation_depth", "max", "min" }, { "budget_alloc", "limit", "min" },
    };

    private static String caveatKey(Object cv) { return Js.stringify(cv); }

    public static List<Object> ruleRedundantCaveat(Map<String, Object> policy) {
        List<Object> out = new ArrayList<>();
        List<Object> caveats = caveatsOf(policy);

        // (a) exact-duplicate caveats
        Map<String, Integer> seen = new LinkedHashMap<>();
        for (int i = 0; i < caveats.size(); i++) {
            Object cv = caveats.get(i);
            if (!Js.isObject(cv)) continue;
            String k = caveatKey(cv);
            Integer first = seen.get(k);
            if (first != null) {
                out.add(find("redundant-caveat", "warn", "caveat " + i + " ('" + Js.str(Js.get(cv, "type"), Js.has(cv, "type")) + "') is an exact duplicate of caveat " + first + " — dead policy", "caveats[" + i + "]"));
            } else {
                seen.put(k, i);
            }
        }

        // (b) same-type domination: a looser caveat that a stricter one of the same type always subsumes
        for (String[] spec : ORDERED_CAVEATS) {
            String type = spec[0], field = spec[1];
            boolean keepMin = spec[2].equals("min");
            List<int[]> idx = new ArrayList<>();
            List<Double> vals = new ArrayList<>();
            for (int i = 0; i < caveats.size(); i++) {
                Object cv = caveats.get(i);
                if (!(cv instanceof Map) || !type.equals(Js.get(cv, "type"))) continue;
                Double v = Js.finite(Js.get(cv, field));
                if (v != null) { idx.add(new int[] { i }); vals.add(v); }
            }
            if (vals.size() < 2) continue;
            double binding = vals.get(0);
            for (double v : vals) binding = keepMin ? Math.min(binding, v) : Math.max(binding, v);
            for (int j = 0; j < vals.size(); j++) {
                if (vals.get(j) != binding) {
                    int i = idx.get(j)[0];
                    out.add(find("redundant-caveat", "warn",
                        "caveat " + i + " ('" + type + "' " + field + "=" + Js.numStr(vals.get(j)) + ") is subsumed by a stricter '" + type + "' (" + field + "=" + Js.numStr(binding) + ") — it can never bite",
                        "caveats[" + i + "]"));
                }
            }
        }

        // (c) a predicate whose numeric `where` conjunction is UNSATISFIABLE never matches
        List<Object> preds = predicatesOf(policy);
        for (int i = 0; i < preds.size(); i++) {
            Object p = preds.get(i);
            if (!Js.isObject(p) || !(Js.get(p, "where") instanceof List)) continue;
            List<?> where = (List<?>) Js.get(p, "where");
            if (!Analyzer.predicateNumericSatisfiable(where)) {
                out.add(find("redundant-caveat", "warn", "predicate " + i + " can never match — its numeric `where` constraints are unsatisfiable (dead policy)", "predicates[" + i + "]"));
            } else {
                out.addAll(nonBindingConditions(where, i));
            }
        }
        return out;
    }

    private static final Set<String> NUMERIC_OPS = Set.of("lt", "lte", "gt", "gte", "eq");

    private static boolean isGroupCondition(Object c) { return c instanceof Map && (Js.has(c, "all_of") || Js.has(c, "any_of") || Js.has(c, "not")); }
    private static boolean isLeafCondition(Object c) { return c instanceof Map && !isGroupCondition(c) && Js.get(c, "field") instanceof String; }

    private static boolean intervalEq(Field.NumInterval a, Field.NumInterval b) {
        return a.lo == b.lo && a.loInclusive == b.loInclusive && a.hi == b.hi && a.hiInclusive == b.hiInclusive;
    }

    /** A numeric leaf condition that does not tighten its field's interval is redundant (never binds). */
    private static List<Object> nonBindingConditions(List<?> where, int predIndex) {
        Map<String, List<Object[]>> byField = new LinkedHashMap<>();
        for (int i = 0; i < where.size(); i++) {
            Object c = where.get(i);
            if (!isLeafCondition(c)) continue;
            if (Js.has(c, "ref")) continue;
            Object op = Js.get(c, "op");
            if (!(op instanceof String) || !NUMERIC_OPS.contains(op)) continue;
            if (Js.finite(Js.get(c, "value")) == null) continue;
            byField.computeIfAbsent((String) Js.get(c, "field"), k -> new ArrayList<>()).add(new Object[] { c, i });
        }

        List<Object> out = new ArrayList<>();
        for (Map.Entry<String, List<Object[]>> en : byField.entrySet()) {
            List<Object[]> conds = en.getValue();
            if (conds.size() < 2) continue;
            Field.NumInterval full = Field.FULL_INTERVAL;
            for (Object[] e : conds) full = Field.tightenInterval(full, Js.get(e[0], "op"), Js.get(e[0], "value"));
            if (Field.intervalEmpty(full)) continue;
            for (Object[] e : conds) {
                Field.NumInterval without = Field.FULL_INTERVAL;
                for (Object[] x : conds) if (x != e) without = Field.tightenInterval(without, Js.get(x[0], "op"), Js.get(x[0], "value"));
                if (intervalEq(without, full)) {
                    out.add(find("redundant-caveat", "info",
                        "condition on '" + en.getKey() + "' (" + Js.get(e[0], "op") + " " + Js.str(Js.get(e[0], "value")) + ") does not tighten the authority — redundant with the other bounds on this field",
                        "predicates[" + predIndex + "].where[" + e[1] + "]"));
                }
            }
        }
        return out;
    }

    // ---- 4. dangerous reachability ----

    public static List<Object> ruleDangerousReachability(Map<String, Object> policy, List<String> dangerous, List<?> extraTargets, Map<String, Object> opts) {
        List<Object> out = new ArrayList<>();
        Map<String, Object> input = analyzerInput(policy);
        List<Object> targets = new ArrayList<>();
        for (String v : declaredVerbs(predicatesOf(policy))) if (isDangerousVerb(v, dangerous)) targets.add(Js.obj("verb", v));
        targets.addAll(extraTargets);
        String gate = gateDescription(policy);

        for (Object t : targets) {
            String verb = (String) Js.get(t, "verb");
            boolean proven, approximate;
            Object reason;
            String witness;
            if (Js.has(t, "resource")) {
                Object resource = Js.get(t, "resource");
                Map<String, Object> r = Analyzer.reachable(input, Js.obj("verb", verb, "resource", resource), opts);
                proven = Boolean.TRUE.equals(r.get("reachable")) && !Boolean.TRUE.equals(r.get("approximate"));
                approximate = Boolean.TRUE.equals(r.get("approximate"));
                reason = r.get("reason");
                witness = verb + " " + Js.str(resource);
            } else {
                Map<String, Object> ad = Analyzer.alwaysDenies(input, verb, opts);
                proven = Boolean.FALSE.equals(ad.get("alwaysDenies")) && !Boolean.TRUE.equals(ad.get("approximate"));
                approximate = Boolean.TRUE.equals(ad.get("approximate"));
                reason = ad.get("reason");
                @SuppressWarnings("unchecked") Map<String, Object> w = (Map<String, Object>) ad.get("witness");
                witness = w != null ? describeAction(w) : verb;
            }

            if (approximate) {
                out.add(find("dangerous-reachability", "warn", "could not decide reachability of dangerous verb '" + verb + "' (undecidable" + reasonSuffix(reason) + ")", null));
            } else if (proven) {
                if (gate == null) out.add(find("dangerous-reachability", "error", "dangerous action '" + witness + "' is REACHABLE with no budget / rate / step-up gate", null));
                else out.add(find("dangerous-reachability", "info", "dangerous action '" + witness + "' is reachable but gated by " + gate, null));
            }
        }
        return out;
    }

    // ---- 5. missing safety floor ----

    /** A grant is non-trivial when any predicate grants a dangerous or wildcard verb, a wildcard resource, or is unconstrained. */
    private static boolean isNonTrivial(Map<String, Object> policy, List<String> dangerous) {
        for (Object p : predicatesOf(policy)) {
            if (!Js.isObject(p)) continue;
            List<String> verbs = verbsOf(Js.get(p, "verb"));
            Object w = Js.get(p, "where");
            boolean hasWhere = w instanceof List && !((List<?>) w).isEmpty();
            boolean dangerousVerb = false;
            for (String v : verbs) if (isDangerousVerb(v, dangerous)) { dangerousVerb = true; break; }
            if (verbs.contains("*") || dangerousVerb || isWildcardResource(p) || !hasWhere) return true;
        }
        return false;
    }

    public static List<Object> ruleMissingSafetyFloor(Map<String, Object> policy, boolean requireExpiry, boolean requireScopeGate, List<String> dangerous) {
        List<Object> out = new ArrayList<>();
        if (predicatesOf(policy).isEmpty()) return out;
        if (requireExpiry && !hasCaveatOfType(caveatsOf(policy), List.of("expires"))) {
            out.add(find("missing-safety-floor", "warn", "grant has no `expires` caveat — the authority never expires", null));
        }
        if (requireScopeGate && isNonTrivial(policy, dangerous) && !hasCaveatOfType(caveatsOf(policy), BUDGET_GATE_CAVEATS)) {
            out.add(find("missing-safety-floor", "warn", "non-trivial grant has no blast-radius / rate / budget gate (" + String.join("/", BUDGET_GATE_CAVEATS) + ")", null));
        }
        return out;
    }

    // ---- schema-mismatch ----

    /** Checks a policy against an action schema ({@code validatePolicyAgainstSchema}): {@code {findings: [{code, severity, message, where?}]}}. */
    public interface SchemaValidator {
        Map<String, Object> validate(Map<String, Object> policy, Object schema, Map<String, Object> options);
    }

    /** The policy compared with the action schema it is written for. */
    @SuppressWarnings("unchecked")
    public static List<Object> ruleSchemaMismatch(Map<String, Object> policy, Object schema, Map<String, Object> options, SchemaValidator validator) {
        Map<String, Object> r = validator.validate(analyzerInput(policy), schema, options);
        List<Object> out = new ArrayList<>();
        for (Object fo : (List<Object>) r.get("findings")) {
            Map<String, Object> f = (Map<String, Object>) fo;
            Map<String, Object> m = Js.obj("rule", "schema-mismatch", "severity", f.get("severity"), "message", Js.str(f.get("code")) + ": " + Js.str(f.get("message"), f.containsKey("message")));
            if (f.containsKey("where")) m.put("where", f.get("where"));
            out.add(m);
        }
        return out;
    }
}
