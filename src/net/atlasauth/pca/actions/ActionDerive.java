package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Actions.ActionKitError;

/**
 * Everything an action def yields: the signed schema verb (v2) and document, the operation binding, risk inputs, policy predicates,
 * Goal IR ontology terms, the policy card, the escalation tier and MCP annotations. Pure and deterministic.
 */
public final class ActionDerive {
    private ActionDerive() {}

    public static final int MAX_PARAM_PATH_DEPTH = 3;
    public static final List<String> ESC_TIERS = List.of("auto", "confirm", "cosign", "stepup");
    public static final List<String> RISK_NAMES = List.of("low", "elevated", "high", "critical");
    /** Reversibility score per effective class (1 = fully reversible). */
    public static final Map<String, Double> REVERSIBILITY_SCORE = Map.of("reversible", 1.0, "rate_limited", 0.4, "irreversible", 0.0);

    private static boolean isReadOnly(Object effects) {
        if (!(effects instanceof List) || ((List<?>) effects).isEmpty()) return false;
        for (Object e : (List<?>) effects) if (!"read".equals(e)) return false;
        return true;
    }

    // ---- flattened params ----

    private static void walk(Map<String, Object> out, String prefix, int depth, Object v) {
        if (v instanceof Map && depth < MAX_PARAM_PATH_DEPTH && !((Map<?, ?>) v).isEmpty()) {
            for (Map.Entry<String, Object> e : J.m(v).entrySet()) walk(out, prefix.isEmpty() ? e.getKey() : prefix + "." + e.getKey(), depth + 1, e.getValue());
        } else out.put(prefix, v);
    }

    /** Nested plain objects become dotted keys (up to {@link #MAX_PARAM_PATH_DEPTH} segments); arrays and scalars are leaves. */
    public static Map<String, Object> flattenParams(Map<String, Object> params) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : params.entrySet()) walk(out, e.getKey(), 1, e.getValue());
        return out;
    }

    /** The unique param carrying {@code role}, or throws {@code no_param} / {@code ambiguous_param}. */
    public static String paramByRole(Map<String, Object> d, String role) {
        TreeSet<String> hits = new TreeSet<>();
        for (Map.Entry<String, Object> e : J.m(d.get("params")).entrySet()) if (role.equals(J.get(e.getValue(), "role"))) hits.add(e.getKey());
        if (hits.isEmpty()) throw new ActionKitError("no_param", "'" + d.get("verb") + "' has no parameter with role " + role);
        if (hits.size() > 1) throw new ActionKitError("ambiguous_param", "'" + d.get("verb") + "' has several parameters with role " + role);
        return hits.first();
    }

    /** read if effects = {read}; irreversible if so declared; external_send if effects meet {send, publish, export}; else reversible. */
    public static String effectClass(Map<String, Object> d) {
        Map<String, Object> n = Actions.normalize(d);
        if (isReadOnly(n.get("effects"))) return "read";
        if ("irreversible".equals(net.atlasauth.pca.ActionsBridge.worstReversibility(n.get("reversibility"), J.m(n.get("params"))))) return "irreversible";
        for (Object e : J.a(n.get("effects"))) if ("send".equals(e) || "publish".equals(e) || "export".equals(e)) return "external_send";
        return "reversible";
    }

    // ---- signed schema (v2) ----

    private static String unitId(Map<String, Object> p) {
        Object u = p.get("unit");
        if (u == null) return null;
        if (!"money".equals(J.get(u, "kind"))) return (String) J.get(u, "kind");
        Object c = J.get(u, "ccy");
        return c instanceof String ? "money." + ((String) c).toLowerCase(Locale.ROOT) : null;
    }

    private static Map<String, Object> unitDecl(Map<String, Object> p) {
        Object u = p.get("unit");
        if (!"money".equals(J.get(u, "kind"))) return J.obj("kind", J.get(u, "kind"));
        Map<String, Object> m = J.obj("kind", "money", "currency", J.get(u, "ccy"));
        if (J.has(u, "exp")) m.put("exponent", J.get(u, "exp"));
        return m;
    }

    private static Map<String, Object> toParamDecl(Map<String, Object> n) {
        Map<String, Object> d = J.obj("type", n.get("type"), "semantic", n.get("role") != null ? n.get("role") : "generic." + n.get("type"), "sensitivity", n.get("sensitivity"));
        if (!Boolean.TRUE.equals(n.get("required"))) d.put("required", false);
        if (n.containsKey("values")) d.put("values", new ArrayList<>(J.a(n.get("values"))));
        for (String k : new String[] {"min", "max", "max_len", "items", "min_items", "max_items", "format", "provenance_min", "default", "principal_neutral_default", "description"}) {
            if (n.containsKey(k)) d.put(k, n.get(k));
        }
        String uid = unitId(n);
        if (uid != null) d.put("unit", uid);
        if (n.containsKey("accumulates")) d.put("accumulates_into", new ArrayList<>(J.a(n.get("accumulates"))));
        if (n.containsKey("role")) d.put("role", n.get("role"));
        if (n.containsKey("tags")) d.put("tags", new ArrayList<>(J.a(n.get("tags"))));
        return d;
    }

    /** The signed v2 verb declaration of a def and the unit entries it needs: {@code {verb, units}}. */
    public static Map<String, Object> toSchemaVerb(Map<String, Object> d, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified) {
        Map<String, Object> n = Actions.normalize(d);
        Map<String, Object> eff = ActionEffective.effective(d, reg, attestationVerified);
        Map<String, Object> params = new LinkedHashMap<>(), units = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : J.m(n.get("params")).entrySet()) {
            Map<String, Object> p = J.m(e.getValue());
            params.put("action.params." + e.getKey(), toParamDecl(p));
            String id = unitId(p);
            if (id != null) units.put(id, unitDecl(p));
        }
        Map<String, Object> v = J.obj("verb", n.get("verb"), "kind", isReadOnly(n.get("effects")) ? "read" : "write", "params", params, "effects", new ArrayList<>(J.a(n.get("effects"))),
            "traits", eff.get("traits"), "def", Actions.defDigest(d), "floors", eff.get("eff"));
        Object att = J.get(d.get("review"), "attestation");
        if (Boolean.TRUE.equals(eff.get("confirmed")) && att instanceof Map && ((Map<?, ?>) att).get("sig") != null) v.put("confirmation", att);
        Object rev = n.get("reversibility");
        if (rev instanceof String) v.put("reversibility", rev);
        else {
            Map<String, Object> rb = J.obj("param", "action.params." + J.get(rev, "by"), "map", new LinkedHashMap<>(J.m(J.get(rev, "map"))));
            if (J.get(rev, "default") != null) rb.put("default", J.get(rev, "default"));
            v.put("reversibility_by", rb);
        }
        Object b = n.get("bindings");
        if (J.get(b, "mcp") != null) v.put("mcp", J.obj("tool", J.get(J.get(b, "mcp"), "tool")));
        if (J.get(b, "openapi") != null) v.put("openapi", J.obj("operationId", J.get(J.get(b, "openapi"), "operationId")));
        if (n.containsKey("description")) v.put("description", n.get("description"));
        return J.obj("verb", v, "units", units);
    }

    /** The unsigned v2 schema document of a set of defs (verbs sorted by name; units merged, a conflicting redefinition refused). {@code meta}: {site, aud, version, pack?}. */
    public static Map<String, Object> toSchemaDoc(List<?> defs, Actions.Registry reg, Map<String, Object> meta, Predicate<Map<String, Object>> attestationVerified) {
        List<Object> verbs = new ArrayList<>();
        Map<String, Object> units = new LinkedHashMap<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        List<Object> sorted = new ArrayList<>(defs);
        sorted.sort((a, b) -> ((String) J.get(a, "verb")).compareTo((String) J.get(b, "verb")));
        for (Object d : sorted) {
            String verb = (String) J.get(d, "verb");
            if (!seen.add(verb)) throw new ActionKitError("duplicate_verb", "verb '" + verb + "' appears twice");
            Map<String, Object> o = toSchemaVerb(J.m(d), reg, attestationVerified);
            verbs.add(o.get("verb"));
            for (Map.Entry<String, Object> e : J.m(o.get("units")).entrySet()) {
                Object prev = units.get(e.getKey());
                Object u = e.getValue();
                if (prev != null && !(java.util.Objects.equals(J.get(prev, "kind"), J.get(u, "kind")) && java.util.Objects.equals(J.get(prev, "currency"), J.get(u, "currency"))
                    && J.sameJsonMember(prev, u, "exponent"))) {
                    throw new ActionKitError("unit_conflict", "unit '" + e.getKey() + "' is declared with two different definitions");
                }
                units.put(e.getKey(), u);
            }
        }
        TreeMap<String, Actions.Trait> custom = new TreeMap<>();
        for (Actions.Trait t : reg.traits.values()) if (!t.id.startsWith("pca.")) custom.put(t.id, t);
        Map<String, Object> doc = J.obj("v", J.n(2), "kind", "pca-action-schema", "site", meta.get("site"), "aud", meta.get("aud"), "version", meta.get("version"));
        if (!units.isEmpty()) doc.put("units", units);
        doc.put("verbs", verbs);
        doc.put("traits_digest", Actions.traitsDigest(reg));
        if (!custom.isEmpty()) {
            List<Object> td = new ArrayList<>();
            for (Actions.Trait t : custom.values()) td.add(J.obj("id", t.id, "implies", J.objs(t.implies), "floor", t.floor.toMap(), "card_phrase", t.cardPhrase));
            doc.put("trait_defs", td);
        }
        if (meta.get("pack") != null) doc.put("pack", meta.get("pack"));
        return doc;
    }

    // ---- operation binding ----

    /** The PcaOperation of a call to this def: {@code {ok: true, op: {verb, resource, params}}} or {@code {ok: false, reason}}. {@code callParams} are the call's params. */
    public static Map<String, Object> operationOf(Map<String, Object> d, Map<String, Object> callParams) {
        Map<String, Object> flat = flattenParams(callParams);
        Map<String, Object> dp = J.m(d.get("params"));
        List<String> declared = new ArrayList<>(new TreeSet<>(dp.keySet()));
        Map<String, Object> params = new LinkedHashMap<>();
        for (String k : declared) if (flat.containsKey(k)) params.put(k, flat.get(k));
        Map<String, Object> res = J.m(d.get("resource"));
        String type = (String) res.get("type");
        Object id = res.get("id");
        String scope = (String) res.get("scope");
        String resource;
        if (!"*".equals(id) && J.has(id, "exact")) resource = type + ":" + J.get(id, "exact");
        else {
            String idParam = null;
            for (String n : declared) if (("id." + type).equals(J.get(dp.get(n), "role"))) { idParam = n; break; }
            Object val = idParam != null ? params.get(idParam) : null;
            if (val instanceof String) {
                if (!ActionIdPattern.idMatches(id, (String) val)) return J.obj("ok", false, "reason", "the id '" + val + "' does not match the resource pattern of " + d.get("verb"));
                resource = type + ":" + val;
            } else if (!"one".equals(scope)) resource = type + ":*";
            else return J.obj("ok", false, "reason", d.get("verb") + " needs a parameter with role id." + type + " to name its resource");
        }
        return J.obj("ok", true, "op", J.obj("verb", d.get("verb"), "resource", resource, "params", params));
    }

    // ---- risk ----

    private static double unit01(double x) { return Math.min(1, Math.max(0, x)); }

    /** Risk inputs for a call. {@code eff} is an {@link ActionEffective#effective} result; {@code params} the call's params (or null); {@code opts} {kappa?, taint?}. */
    public static Map<String, Object> riskOf(Map<String, Object> d, Map<String, Object> eff, Map<String, Object> params, Map<String, Object> opts) {
        Map<String, Object> e = J.m(eff.get("eff"));
        double blast = unit01(J.num(e.get("blast_ppm")) / 1_000_000);
        TreeSet<String> money = new TreeSet<>();
        for (Map.Entry<String, Object> p : J.m(d.get("params")).entrySet()) if ("money.amount".equals(J.get(p.getValue(), "role"))) money.add(p.getKey());
        if (!money.isEmpty()) {
            Map<String, Object> flat = params != null ? flattenParams(params) : new LinkedHashMap<>();
            Object amount = flat.get(money.first());
            Object kappa = opts == null ? null : opts.get("kappa");
            Double a = J.num(amount), k = J.num(kappa);
            boolean ok = amount != null && !(amount instanceof String) && a != null && !a.isNaN() && !a.isInfinite() && a >= 0 && k != null && k > 0;
            blast = ok ? unit01(a / k) : 1;
        }
        Map<String, Object> out = J.obj("reversibility", REVERSIBILITY_SCORE.get((String) e.get("rev")), "blastRadius", blast, "confidence", J.n(1));
        Object t = opts == null ? null : opts.get("taint");
        Double td = J.num(t);
        if (td != null && !td.isNaN() && !td.isInfinite()) out.put("taint", unit01(td));
        return out;
    }

    // ---- predicates ----

    /** The resource matcher of a def's pattern ({@code <type>:<prefix>*}, {@code <type>:<exact>} or {@code <type>:*}). */
    public static String resourceMatcher(Map<String, Object> d) {
        Map<String, Object> r = J.m(d.get("resource"));
        Object id = r.get("id");
        if ("*".equals(id)) return r.get("type") + ":*";
        return J.has(id, "exact") ? r.get("type") + ":" + J.get(id, "exact") : r.get("type") + ":" + J.get(id, "prefix") + "*";
    }

    /** The policy predicate scaffold; {@code limits.max_amount} adds a per-call ceiling on the {@code money.amount} parameter (a def with none throws). */
    public static Map<String, Object> predicatesOf(Map<String, Object> d, Map<String, Object> limits) {
        Map<String, Object> out = J.obj("verb", d.get("verb"), "resource", resourceMatcher(d));
        if (limits != null && limits.containsKey("max_amount")) {
            Object m = limits.get("max_amount");
            if (!J.isInt(m) || J.num(m) < 0) throw new ActionKitError("bad_limit", "max_amount must be a non-negative safe integer");
            String name = paramByRole(d, "money.amount");
            out.put("where", J.list(J.obj("field", "action.params." + name, "op", "lte", "value", m), J.obj("field", "action.params." + name, "op", "gte", "value", J.n(0))));
        }
        return out;
    }

    // ---- Goal IR ontology terms ----

    private static Map<String, Object> ontParam(Map<String, Object> d, Map<String, Object> p) {
        Object u = p.get("unit");
        if (u != null) {
            Object kind = J.get(u, "kind");
            if ("money".equals(kind)) {
                Object c = J.get(u, "ccy");
                if (c instanceof String) return J.obj("kind", "money", "ccys", J.list(c));
                Object cp = J.get(J.m(d.get("params")), (String) J.get(c, "from"));
                Object vals = J.get(cp, "values");
                return J.obj("kind", "money", "ccys", vals != null ? sorted(vals) : new ArrayList<>());
            }
            return J.obj("kind", "duration".equals(kind) ? "duration" : "bytes".equals(kind) ? "bytes" : "ratio".equals(kind) ? "ratio" : "count");
        }
        Object role = p.get("role"), format = p.get("format");
        if (role instanceof String && ((String) role).startsWith("id.")) return J.obj("kind", "id", "of", ((String) role).substring(3));
        if (format instanceof String && ((String) format).startsWith("id:")) return J.obj("kind", "id", "of", ((String) format).substring(3));
        switch ((String) p.get("type")) {
            case "duration": return J.obj("kind", "duration");
            case "datetime": case "date": return J.obj("kind", "instant");
            case "integer": return J.obj("kind", "count");
            case "boolean": return J.obj("kind", "enum", "values", J.list("false", "true"));
            case "set": return J.obj("kind", "enum", "values", sorted(p.get("values") == null ? new ArrayList<>() : p.get("values")));
            case "string": return p.get("values") != null ? J.obj("kind", "enum", "values", sorted(p.get("values"))) : J.obj("kind", "text");
            default: return J.obj("kind", "text");
        }
    }

    private static List<Object> sorted(Object vals) {
        List<String> l = new ArrayList<>();
        for (Object x : J.a(vals)) l.add((String) x);
        l.sort(null);
        return J.objs(l);
    }

    /** Ontology terms for a set of defs; the effect class is DERIVED ({@link #effectClass}). */
    public static Map<String, Object> toOntology(List<?> defs, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified) {
        Map<String, String> types = new LinkedHashMap<>();
        Map<String, Object> units = new LinkedHashMap<>(), aliases = new LinkedHashMap<>(), traits = new LinkedHashMap<>();
        List<Object> verbs = new ArrayList<>();
        List<Object> sorted = new ArrayList<>(defs);
        sorted.sort((a, b) -> ((String) J.get(a, "verb")).compareTo((String) J.get(b, "verb")));
        for (Object dO : sorted) {
            Map<String, Object> d = J.m(dO);
            Map<String, Object> res = J.m(d.get("resource"));
            Object id = res.get("id");
            String prefix = "*".equals(id) || J.has(id, "exact") ? "" : (String) J.get(id, "prefix");
            types.putIfAbsent((String) res.get("type"), prefix);
            Map<String, Object> params = new LinkedHashMap<>();
            Map<String, Object> dp = J.m(d.get("params"));
            for (String name : new TreeSet<>(dp.keySet())) {
                params.put(name, ontParam(d, J.m(dp.get(name))));
                Object u = J.get(dp.get(name), "unit");
                if (u != null && "money".equals(J.get(u, "kind")) && J.get(u, "ccy") instanceof String) {
                    Map<String, Object> m = J.obj("kind", "money");
                    if (J.has(u, "exp")) m.put("exponent", J.get(u, "exp"));
                    units.put((String) J.get(u, "ccy"), m);
                } else if (u != null && !"money".equals(J.get(u, "kind"))) units.put((String) J.get(u, "kind"), J.obj("kind", J.get(u, "kind")));
            }
            verbs.add(J.obj("id", d.get("verb"), "effect", effectClass(d), "resource_type", res.get("type"), "params", params));
            if (d.get("aliases") != null) for (Object a : J.a(d.get("aliases"))) {
                if (aliases.containsKey((String) a) && !aliases.get((String) a).equals(d.get("verb"))) throw new ActionKitError("alias_collision", "alias '" + a + "' names two verbs");
                aliases.put((String) a, d.get("verb"));
            }
            traits.put((String) d.get("verb"), ActionEffective.effective(d, reg, attestationVerified).get("traits"));
        }
        List<Object> tl = new ArrayList<>();
        for (Map.Entry<String, String> e : types.entrySet()) tl.add(J.obj("id", e.getKey(), "id_prefix", e.getValue()));
        return J.obj("types", tl, "units", units, "verbs", verbs, "aliases", aliases, "traits", traits);
    }

    // ---- policy card + escalation + MCP annotations ----

    private static String sentence(String s) { return !s.isEmpty() && ".!?".indexOf(s.charAt(s.length() - 1)) >= 0 ? s : s + "."; }

    private static String list(List<String> xs) {
        if (xs.size() <= 1) return xs.isEmpty() ? "" : xs.get(0);
        return String.join(", ", xs.subList(0, xs.size() - 1)) + " and " + xs.get(xs.size() - 1);
    }

    /** The policy card of a def: deterministic text from its title and the phrases of its trait closure (riskiest first). */
    public static Map<String, Object> cardOf(Map<String, Object> d, Map<String, Object> eff, Actions.Registry reg) {
        List<Actions.Trait> ordered = new ArrayList<>();
        for (String id : Actions.closure(reg, J.a(eff.get("traits")))) ordered.add(reg.traits.get(id));
        ordered.sort((a, b) -> b.floor.risk != a.floor.risk ? Integer.compare(b.floor.risk, a.floor.risk) : a.id.compareTo(b.id));
        List<String> phrases = new ArrayList<>(new LinkedHashSet<>(ordered.stream().map(t -> t.cardPhrase).collect(java.util.stream.Collectors.toList())));
        Map<String, Object> e = J.m(eff.get("eff"));
        String title = (String) d.get("title");
        String text = sentence(title) + " " + (Boolean.TRUE.equals(eff.get("confirmed"))
            ? (!phrases.isEmpty() ? "This action " + list(phrases) + "." : "This action only reads.")
            : "This action has not been reviewed by a person, so it is treated as the most dangerous kind of action: it " + list(phrases) + ".");
        return J.obj("verb", d.get("verb"), "title", title, "text", text, "risk", RISK_NAMES.get(J.num(e.get("risk")).intValue()), "escalation", ESC_TIERS.get(J.num(e.get("esc")).intValue()),
            "reversibility", e.get("rev"), "blast_ppm", e.get("blast_ppm"), "needs", new ArrayList<>(J.a(e.get("caveats"))), "context", new ArrayList<>(J.a(e.get("context"))));
    }

    /** The minimum escalation tier of the effective profile: {@code {tier, name}}. */
    public static Map<String, Object> escalationOf(Map<String, Object> eff) {
        int t = J.num(J.m(eff.get("eff")).get("esc")).intValue();
        return J.obj("tier", J.n(t), "name", ESC_TIERS.get(t));
    }

    /** Advisory MCP tool annotations (read-only / destructive / idempotent / open-world). */
    public static Map<String, Object> mcpAnnotationsOf(Map<String, Object> d, Map<String, Object> eff) {
        List<Object> cl = J.a(eff.get("closure"));
        boolean confirmed = Boolean.TRUE.equals(eff.get("confirmed")), ro = isReadOnly(d.get("effects"));
        Object mode = J.get(d.get("idempotency"), "mode");
        boolean idem = mode != null ? !"none".equals(mode) : false;
        return J.obj("readOnlyHint", confirmed && ro, "destructiveHint", cl.contains("pca.destructive"), "idempotentHint", confirmed && (idem || ro),
            "openWorldHint", cl.contains("pca.network_egress") || cl.contains("pca.external_communication"));
    }
}
