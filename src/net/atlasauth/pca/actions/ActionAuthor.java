package net.atlasauth.pca.actions;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Json;

/**
 * Authoring forms of an action definition: param and resource shorthands, the expansion of an authoring entry into a def, the loader of an authoring
 * document, and typed param constructors. The shorthands and the expansion are the reference's, so one action has one digest however it was written.
 * Input is an already parsed document (Map / List / String / Boolean / Json.Num / null); YAML text is not parsed here (a YAML front end hands its parsed
 * value to {@link #loadActionsValue}); {@link #loadActionsText} parses YAML or JSON text (see {@link ActionsText}) and reports source positions.
 */
public final class ActionAuthor {
    private ActionAuthor() {}

    /** Largest authoring file the loader reads. */
    public static final int MAX_AUTHOR_BYTES = 1 << 20;
    public static final String IDEMPOTENCY_PARAM = "idempotency_key";
    /** Effects whose repeat is not harmless: an absent idempotency declaration gets a key parameter. */
    public static final List<String> AUTO_IDEMPOTENT_EFFECTS = List.of("send", "pay", "create", "provision", "publish");

    private static final List<String> RESOURCE_SCOPES = List.of("one", "set", "tenant", "global");
    private static final List<String> ID_CLASSES = List.of("digits", "hex", "alnum", "slug", "uuid", "any_safe");
    private static final List<String> BLAST_RADII = List.of("one", "bounded", "tenant", "global");
    private static final List<String> PROVENANCE_LEVELS = List.of("first_party", "tool", "agent");
    private static final Set<String> ENTRY_KEYS = Set.of("v", "kind", "verb", "aliases", "title", "description", "effects", "resource", "params", "reversibility", "blast", "side_effects",
        "idempotency", "context", "traits", "audience", "compensates", "bindings", "examples", "review", "source", "since");
    private static final Set<String> FILE_KEYS = Set.of("ns", "since", "actions");
    /** Stands for a JavaScript undefined member value: never a JSON value, so the strict-JSON check refuses it exactly as the reference does. */
    private static final Object UNDEFINED = new Object();

    private static final Pattern SHORTHAND_RE = Pattern.compile("([a-z_]+(?::[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3})?)(?:\\(([^\\n\\r\\u2028\\u2029]*)\\))?(\\?)?");
    private static final Pattern INT_ARG_RE = Pattern.compile("-?[0-9]{1,15}");
    private static final Pattern INT_RANGE_RE = Pattern.compile("(-?[0-9]{1,15})\\.\\.(-?[0-9]{1,15})");
    private static final Pattern SCOPE_AT_RE = Pattern.compile("@([a-z]+)\\z");
    private static final Pattern ID_CLASS_RE = Pattern.compile("\\{([a-z_]+),([0-9]{1,3})\\.\\.([0-9]{1,3})\\}");
    private static final Pattern NS_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}");

    private static Actions.ActionKitError err(String code, String msg) { return new Actions.ActionKitError(code, msg); }

    private static Json.Num num(String s) {
        // Number("-0") is -0 (refused later by the strict-JSON profile): keep the sign of a negative zero
        long v = Long.parseLong(s);
        return v == 0 && s.startsWith("-") ? new Json.Num("-0") : new Json.Num(Long.toString(v));
    }

    // ---- param shorthands --------------------------------------------------------------------------------------------------------

    private static final class Args {
        final List<String> pos = new ArrayList<>();
        final Map<String, String> named = new LinkedHashMap<>();
    }

    private static Args splitArgs(String s) {
        Args a = new Args();
        for (String raw : s.split(",", -1)) {
            String x = J.jsTrim(raw);
            if (x.isEmpty()) continue;
            int eq = x.indexOf('=');
            if (eq > 0) a.named.put(J.jsTrim(x.substring(0, eq)), J.jsTrim(x.substring(eq + 1)));
            else a.pos.add(x);
        }
        return a;
    }

    private static Json.Num intArg(String s, String what) {
        if (s == null) return null;
        if (!INT_ARG_RE.matcher(s).matches()) throw err("bad_shorthand", what + " must be an integer, got '" + s + "'");
        return num(s);
    }

    private static void only(Args a, int pos, List<String> names, String shorthand) {
        if (a.pos.size() > pos) throw err("bad_shorthand", "'" + shorthand + "' takes at most " + pos + " positional argument(s)");
        for (String k : a.named.keySet()) if (!names.contains(k)) throw err("bad_shorthand", "'" + shorthand + "' has no option '" + k + "'");
    }

    private static List<Object> listArg(String s, String shorthand) {
        List<Object> xs = new ArrayList<>();
        for (String x : s.split("\\|", -1)) xs.add(J.jsTrim(x));
        for (Object x : xs) if ("".equals(x)) throw err("bad_shorthand", "'" + shorthand + "' needs values separated by |");
        return xs;
    }

    /**
     * Expand one param shorthand. Forms: email phone url uuid ccy country secret bool date datetime duration text(N) string(N) message(N) int(MIN..MAX) count(MAX)
     * money(CCY|@param, max=N, min=N, exp=N, provenance=first_party|tool|agent) id:&lt;type&gt; enum(a|b) set(a|b) array(items, max=N). A trailing {@code ?} makes the
     * param optional.
     */
    public static Map<String, Object> parseParamShorthand(String src) {
        Matcher m = SHORTHAND_RE.matcher(J.jsTrim(src));
        if (!m.matches()) throw err("bad_shorthand", "unknown param shorthand '" + src + "'");
        String name = m.group(1), inner = m.group(2);
        boolean optional = "?".equals(m.group(3));
        Args a = splitArgs(inner == null ? "" : inner);
        Map<String, Object> p;
        switch (name) {
            case "email": bare(name, inner); p = J.obj("type", "string", "role", "contact.email", "format", "email", "tags", J.list("pii"), "max_len", J.n(254)); break;
            case "phone": bare(name, inner); p = J.obj("type", "string", "role", "contact.phone", "format", "phone_e164", "tags", J.list("pii"), "max_len", J.n(16)); break;
            case "url": bare(name, inner); p = J.obj("type", "string", "role", "url.target", "format", "url", "max_len", J.n(2048)); break;
            case "uuid": bare(name, inner); p = J.obj("type", "string", "format", "uuid", "max_len", J.n(36)); break;
            case "ccy": bare(name, inner); p = J.obj("type", "string", "role", "money.currency", "format", "iso_currency", "max_len", J.n(3)); break;
            case "country": bare(name, inner); p = J.obj("type", "string", "format", "iso_country", "max_len", J.n(2)); break;
            case "secret": bare(name, inner); p = J.obj("type", "string", "role", "credential.secret", "tags", J.list("secret"), "max_len", J.n(512)); break;
            case "bool": bare(name, inner); p = J.obj("type", "boolean"); break;
            case "date": bare(name, inner); p = J.obj("type", "date"); break;
            case "datetime": bare(name, inner); p = J.obj("type", "datetime"); break;
            case "duration": {
                only(a, 1, List.of(), "duration");
                Json.Num max = intArg(a.pos.isEmpty() ? null : a.pos.get(0), "duration max (ms)");
                p = J.obj("type", "duration");
                if (max != null) { p.put("min", J.n(0)); p.put("max", max); }
                break;
            }
            case "text": case "string": {
                only(a, 1, List.of(), name);
                Json.Num n = intArg(a.pos.isEmpty() ? null : a.pos.get(0), name + " length");
                p = J.obj("type", "string");
                if (n != null) p.put("max_len", n);
                break;
            }
            case "message": {
                only(a, 1, List.of(), "message");
                Json.Num n = intArg(a.pos.isEmpty() ? null : a.pos.get(0), "message length");
                p = J.obj("type", "string", "role", "text.message", "tags", J.list("free_text_outbound"), "max_len", n != null ? n : J.n(1024));
                break;
            }
            case "int": {
                only(a, 1, List.of(), "int");
                Matcher r = a.pos.isEmpty() ? null : INT_RANGE_RE.matcher(a.pos.get(0));
                if (!a.pos.isEmpty() && !r.matches()) throw err("bad_shorthand", "int takes MIN..MAX, for example int(0..100)");
                p = J.obj("type", "integer");
                if (r != null) { p.put("min", num(r.group(1))); p.put("max", num(r.group(2))); }
                break;
            }
            case "count": {
                only(a, 1, List.of(), "count");
                Json.Num max = intArg(a.pos.isEmpty() ? null : a.pos.get(0), "count max");
                p = J.obj("type", "integer", "role", "count.limit", "min", J.n(1));
                if (max != null) p.put("max", max);
                p.put("unit", J.obj("kind", "count"));
                break;
            }
            case "money": {
                only(a, 1, List.of("max", "min", "exp", "provenance"), "money");
                if (a.pos.isEmpty()) throw err("bad_shorthand", "money needs a currency: money(USD) or money(@currency_param)");
                String c = a.pos.get(0);
                Object ccy = c.startsWith("@") ? J.obj("from", c.substring(1)) : c;
                Json.Num max = intArg(a.named.get("max"), "money max");
                // an amount defaults to provenance first_party (the value must not come from an untrusted tool or agent output)
                String prov = a.named.containsKey("provenance") ? a.named.get("provenance") : "first_party";
                if (!PROVENANCE_LEVELS.contains(prov)) throw err("bad_shorthand", "money provenance must be one of " + String.join(", ", PROVENANCE_LEVELS));
                Json.Num min = intArg(a.named.get("min"), "money min");
                p = J.obj("type", "integer", "role", "money.amount", "min", min != null ? min : J.n(1));
                if (max != null) p.put("max", max);
                Json.Num exp = intArg(a.named.get("exp"), "money exp");
                p.put("unit", J.obj("kind", "money", "ccy", ccy, "exp", exp != null ? exp : J.n(2)));
                p.put("provenance_min", prov);
                break;
            }
            case "enum": case "set": {
                if (inner == null) throw err("bad_shorthand", name + " needs values: " + name + "(a|b|c)");
                p = J.obj("type", name.equals("enum") ? "string" : "set", "values", listArg(inner, name));
                break;
            }
            case "array": {
                only(a, 1, List.of("max", "min"), "array");
                String items = a.pos.isEmpty() ? null : a.pos.get(0);
                if (!"string".equals(items) && !"integer".equals(items)) throw err("bad_shorthand", "array(items): items is string or integer");
                Json.Num max = intArg(a.named.get("max"), "array max"), min = intArg(a.named.get("min"), "array min");
                p = J.obj("type", "array", "items", items);
                if (min != null) p.put("min_items", min);
                if (max != null) p.put("max_items", max);
                break;
            }
            default: {
                if (name.startsWith("id:")) { bare(name, inner); p = J.obj("type", "string", "role", "id." + name.substring(3), "max_len", J.n(64)); break; }
                throw err("bad_shorthand", "unknown param shorthand '" + name + "'");
            }
        }
        if (optional) p.put("required", Boolean.FALSE);
        return p;
    }

    private static void bare(String name, String inner) {
        if (inner != null) throw err("bad_shorthand", "'" + name + "' takes no arguments");
    }

    // ---- resource shorthand ------------------------------------------------------------------------------------------------------

    /**
     * {@code type}, {@code type:*}, {@code type:exact}, {@code type:prefix*} or {@code type:prefix*{class,min..max}}, with an optional {@code @one|set|tenant|global}.
     * A prefix pattern is scope one (class alnum, length 8..32 after the prefix); {@code *} is scope set; a bare type is tenant. Returns {@code {type, id, scope}}.
     */
    public static Map<String, Object> parseResourceShorthand(String src) {
        String s = J.jsTrim(src);
        String scope = null;
        Matcher at = SCOPE_AT_RE.matcher(s);
        if (at.find()) {
            if (!RESOURCE_SCOPES.contains(at.group(1))) throw err("bad_shorthand", "unknown resource scope '@" + at.group(1) + "'");
            scope = at.group(1);
            s = s.substring(0, at.start());
        }
        int colon = s.indexOf(':');
        if (colon < 0) return J.obj("type", s, "id", "*", "scope", scope != null ? scope : "tenant");
        String type = s.substring(0, colon), idsrc = s.substring(colon + 1);
        if (idsrc.equals("*")) return J.obj("type", type, "id", "*", "scope", scope != null ? scope : "set");
        int star = idsrc.indexOf('*');
        if (star < 0) return J.obj("type", type, "id", J.obj("exact", idsrc), "scope", scope != null ? scope : "one");
        String prefix = idsrc.substring(0, star), rest = idsrc.substring(star + 1);
        String cls = "alnum";
        Json.Num lo = J.n(8), hi = J.n(32);
        if (!rest.isEmpty()) {
            Matcher r = ID_CLASS_RE.matcher(rest);
            if (!r.matches() || !ID_CLASSES.contains(r.group(1))) throw err("bad_shorthand", "resource id '" + idsrc + "': expected prefix*{class,min..max}");
            cls = r.group(1);
            lo = new Json.Num(Integer.toString(Integer.parseInt(r.group(2))));
            hi = new Json.Num(Integer.toString(Integer.parseInt(r.group(3))));
        }
        return J.obj("type", type, "id", J.obj("prefix", prefix, "class", cls, "len", J.list(lo, hi)), "scope", scope != null ? scope : "one");
    }

    // ---- action expansion --------------------------------------------------------------------------------------------------------

    private static Object asList(Object v) { return v instanceof String ? J.list(v) : v; }

    /** The title an action gets when it names none: the action word and its nouns, "acme.invoice.send" gives "Send invoice". */
    public static String defaultTitle(String verb) {
        String[] all = verb.split("\\.", -1);
        List<String> seg = new ArrayList<>();
        for (int i = 1; i < all.length; i++) seg.add(all[i]);
        String act = seg.isEmpty() ? verb : seg.get(seg.size() - 1);
        List<String> parts = new ArrayList<>();
        parts.add(act);
        for (int i = 0; i < seg.size() - 1; i++) parts.add(seg.get(i));
        String t = String.join(" ", parts).replace('_', ' ');
        return t.isEmpty() ? t : t.substring(0, 1).toUpperCase(Locale.ROOT) + t.substring(1);
    }

    private static boolean has(Map<String, Object> m, String k) { return m.containsKey(k); }

    private static boolean isOne(Object v) {
        Double d = J.num(v);
        return d != null && d == 1.0;
    }

    /**
     * Expand one authoring entry (shorthands or full def members) to an action def. Throws ActionKitError {@code bad_action} for a malformed entry.
     * Returns {@code {def, notes}} (notes: the auto-added idempotency key).
     */
    public static Map<String, Object> expandAction(Object entryO, String since) {
        if (!(entryO instanceof Map)) throw err("bad_action", "an action must be an object");
        Map<String, Object> entry = J.m(entryO);
        for (String k : entry.keySet()) if (!ENTRY_KEYS.contains(k)) throw err("bad_action", "unknown member '" + k + "'");
        if (has(entry, "v") && !isOne(entry.get("v"))) throw err("bad_action", "unsupported def version");
        if (has(entry, "kind") && !Actions.ACTION_DEF_KIND.equals(entry.get("kind"))) throw err("bad_action", "kind must be '" + Actions.ACTION_DEF_KIND + "'");
        if (!(entry.get("verb") instanceof String)) throw err("bad_action", "verb is required");
        String verb = (String) entry.get("verb");
        List<Object> notes = new ArrayList<>();
        if (has(entry, "kind")) {
            // the full form (a `kind` member) is taken exactly as written: no shorthands, no defaults, validateDef decides
            Map<String, Object> full = new LinkedHashMap<>();
            full.put("v", J.n(1));
            full.putAll(entry);
            String je0 = Actions.jsonProfileError(full, 0);
            if (je0 != null) throw err("bad_action", "not strict JSON: " + je0);
            return J.obj("def", full, "notes", notes);
        }
        Map<String, Object> out = J.obj("v", J.n(1), "kind", Actions.ACTION_DEF_KIND, "verb", verb);
        if (has(entry, "aliases")) out.put("aliases", asList(entry.get("aliases")));
        out.put("title", entry.get("title") != null ? entry.get("title") : defaultTitle(verb));
        if (has(entry, "description")) out.put("description", entry.get("description"));
        out.put("effects", has(entry, "effects") ? asList(entry.get("effects")) : UNDEFINED);
        Object res = entry.get("resource");
        out.put("resource", !has(entry, "resource") ? UNDEFINED : res instanceof String ? parseResourceShorthand((String) res) : res);
        Map<String, Object> params = new LinkedHashMap<>();
        if (has(entry, "params")) {
            if (!(entry.get("params") instanceof Map)) throw err("bad_action", "params must be an object");
            for (Map.Entry<String, Object> e : J.m(entry.get("params")).entrySet()) params.put(e.getKey(), e.getValue() instanceof String ? parseParamShorthand((String) e.getValue()) : e.getValue());
        }
        if (has(entry, "reversibility")) out.put("reversibility", entry.get("reversibility"));
        if (has(entry, "blast")) out.put("blast", entry.get("blast") instanceof String ? J.obj("radius", entry.get("blast")) : entry.get("blast"));
        if (entry.get("blast") instanceof String && !BLAST_RADII.contains(entry.get("blast"))) throw err("bad_action", "unknown blast radius '" + entry.get("blast") + "'");
        if (has(entry, "side_effects")) out.put("side_effects", entry.get("side_effects"));
        // idempotency: a string is the mode; absent on a non-idempotent effect gets the key parameter (the linter notes it)
        Object effs = out.get("effects");
        List<Object> effects = effs instanceof List ? J.a(effs) : new ArrayList<>();
        boolean idemDefined = has(entry, "idempotency");
        Object idem = entry.get("idempotency");
        if (idem instanceof String) idem = idem.equals("key_param") ? J.obj("mode", "key_param", "param", IDEMPOTENCY_PARAM) : J.obj("mode", idem);
        if (!idemDefined) {
            boolean auto = false;
            for (Object e : effects) if (e != null && AUTO_IDEMPOTENT_EFFECTS.contains(e)) auto = true; // Set.of rejects a null probe
            if (auto) {
                idem = J.obj("mode", "key_param", "param", IDEMPOTENCY_PARAM);
                idemDefined = true;
                notes.add(J.obj("verb", verb, "message", IDEMPOTENCY_PARAM + " auto-added"));
            }
        } else idemDefined = true;
        if (idem instanceof Map && "key_param".equals(J.get(idem, "mode")) && IDEMPOTENCY_PARAM.equals(J.get(idem, "param")) && !params.containsKey(IDEMPOTENCY_PARAM)) {
            params.put(IDEMPOTENCY_PARAM, J.obj("type", "string", "max_len", J.n(64)));
        }
        if (idemDefined) out.put("idempotency", idem);
        out.put("params", params);
        for (String k : new String[] {"context", "traits"}) if (has(entry, k)) out.put(k, asList(entry.get(k)));
        for (String k : new String[] {"audience", "compensates", "bindings", "examples", "source"}) if (has(entry, k)) out.put(k, entry.get(k));
        out.put("review", entry.get("review") != null ? entry.get("review") : J.obj("state", "authored"));
        Object sin = entry.get("since") != null ? entry.get("since") : since;
        if (sin != null) out.put("since", sin);
        String je = Actions.jsonProfileError(out, 0);
        if (je != null) throw err("bad_action", "not strict JSON: " + je);
        return J.obj("def", out, "notes", notes);
    }

    // ---- the document loader -----------------------------------------------------------------------------------------------------

    private static boolean hasProtoKey(Object v, int depth) {
        if (depth > 40 || v == null || !(v instanceof Map || v instanceof List)) return depth > 40;
        if (v instanceof List) {
            for (Object x : (List<?>) v) if (hasProtoKey(x, depth + 1)) return true;
            return false;
        }
        for (Map.Entry<String, Object> e : J.m(v).entrySet()) if (e.getKey().equals("__proto__") || hasProtoKey(e.getValue(), depth + 1)) return true;
        return false;
    }

    private static Map<String, Object> result() { return J.obj("defs", new ArrayList<Object>(), "notes", new ArrayList<Object>(), "errors", new ArrayList<Object>(), "locs", new LinkedHashMap<String, Object>(), "rules", new LinkedHashMap<String, Object>()); }

    private static Map<String, Object> withError(Map<String, Object> res, String message) {
        res.put("errors", J.list(J.obj("message", message)));
        return res;
    }

    /** Expand an already parsed document ({@code {ns, since?, actions: [...]}}, or one raw def). Never throws. Returns {@code {defs, notes, errors, locs, rules[, ns]}}. */
    public static Map<String, Object> loadActionsValue(Object docO) {
        Map<String, Object> res = result();
        if (hasProtoKey(docO, 0)) return withError(res, "the document contains a '__proto__' member or nests deeper than 40");
        if (!(docO instanceof Map)) return withError(res, "the document must be an object");
        Map<String, Object> doc = J.m(docO);
        List<Object> entries;
        String since = null;
        if (Actions.ACTION_DEF_KIND.equals(doc.get("kind"))) entries = J.list(doc);
        else {
            for (String k : doc.keySet()) if (!FILE_KEYS.contains(k)) return withError(res, "unknown top-level member '" + k + "' (expected ns, since, actions)");
            if (!(doc.get("ns") instanceof String) || !NS_RE.matcher((String) doc.get("ns")).matches()) return withError(res, "ns must be a lowercase identifier");
            res.put("ns", doc.get("ns"));
            if (doc.get("since") instanceof String) since = (String) doc.get("since");
            else if (has(doc, "since")) return withError(res, "since must be a string");
            if (!(doc.get("actions") instanceof List)) return withError(res, "actions must be a list");
            entries = J.a(doc.get("actions"));
        }
        List<Object> defs = J.a(res.get("defs")), notes = J.a(res.get("notes")), errors = J.a(res.get("errors"));
        Map<String, Object> rulesOut = J.m(res.get("rules"));
        int index = 0;
        for (Object e : entries) {
            String verb = e instanceof Map && J.get(e, "verb") instanceof String ? (String) J.get(e, "verb") : null;
            try {
                // `rules` is the action's business rules block: validated against the def, kept out of the def (and its digest)
                boolean hasRules = false;
                Object rules = null, entry = e;
                if (e instanceof Map && J.m(e).containsKey("rules")) {
                    hasRules = true;
                    Map<String, Object> rest = new LinkedHashMap<>(J.m(e));
                    rules = rest.remove("rules");
                    entry = rest;
                }
                Map<String, Object> ex = expandAction(entry, since);
                Map<String, Object> def = J.m(ex.get("def"));
                String bad = Actions.validateDef(def);
                if (bad != null) { errors.add(errorOf(index, verb, bad)); index++; continue; }
                if (hasRules) {
                    String re = ActionBusinessRules.businessRulesError(def, rules);
                    if (re != null) { errors.add(errorOf(index, verb, re)); index++; continue; }
                    rulesOut.put((String) def.get("verb"), rules);
                }
                defs.add(def);
                notes.addAll(J.a(ex.get("notes")));
            } catch (Actions.ActionKitError ke) {
                errors.add(errorOf(index, verb, ke.getMessage()));
            } catch (RuntimeException re) {
                errors.add(errorOf(index, verb, "malformed action: " + re.getMessage()));
            }
            index++;
        }
        return res;
    }

    private static Map<String, Object> errorOf(int index, String verb, String message) {
        Map<String, Object> m = J.obj("index", J.n(index));
        if (verb != null && !verb.isEmpty()) m.put("verb", verb);
        m.put("message", message);
        return m;
    }

    /** Load an authoring file (YAML 1.2 core schema or JSON, {@code fmt} "yaml" or "json") with source positions; see {@link ActionsText}. Input above {@link #MAX_AUTHOR_BYTES} is refused. Never throws. */
    public static Map<String, Object> loadActionsText(String text, String fmt) { return ActionsText.loadActionsText(text, fmt); }

    /** {@link #loadActionsText(String, String)} for YAML (which also reads JSON text, flow style). */
    public static Map<String, Object> loadActionsText(String text) { return ActionsText.loadActionsText(text, "yaml"); }

    // ---- the typed builder ---------------------------------------------------------------------------------------------------------

    /** Typed param constructors; each returns the same param the matching shorthand expands to ({@code extra} members are merged over it; may be null). */
    public static final class P {
        private P() {}

        private static Map<String, Object> with(Map<String, Object> p, Map<String, Object> x) {
            if (x != null) p.putAll(x);
            return p;
        }

        public static Map<String, Object> email(Map<String, Object> x) { return with(parseParamShorthand("email"), x); }
        public static Map<String, Object> phone(Map<String, Object> x) { return with(parseParamShorthand("phone"), x); }
        public static Map<String, Object> url(Map<String, Object> x) { return with(parseParamShorthand("url"), x); }
        public static Map<String, Object> uuid(Map<String, Object> x) { return with(parseParamShorthand("uuid"), x); }
        public static Map<String, Object> ccy(Map<String, Object> x) { return with(parseParamShorthand("ccy"), x); }
        public static Map<String, Object> country(Map<String, Object> x) { return with(parseParamShorthand("country"), x); }
        public static Map<String, Object> secret(Map<String, Object> x) { return with(parseParamShorthand("secret"), x); }
        public static Map<String, Object> bool(Map<String, Object> x) { return with(parseParamShorthand("bool"), x); }
        public static Map<String, Object> date(Map<String, Object> x) { return with(parseParamShorthand("date"), x); }
        public static Map<String, Object> datetime(Map<String, Object> x) { return with(parseParamShorthand("datetime"), x); }
        public static Map<String, Object> duration(Long maxMs, Map<String, Object> x) { return with(parseParamShorthand(maxMs == null ? "duration" : "duration(" + maxMs + ")"), x); }
        public static Map<String, Object> message(Long maxLen, Map<String, Object> x) { return with(parseParamShorthand(maxLen == null ? "message" : "message(" + maxLen + ")"), x); }
        public static Map<String, Object> text(Long maxLen, Map<String, Object> x) { return with(parseParamShorthand(maxLen == null ? "text" : "text(" + maxLen + ")"), x); }
        public static Map<String, Object> intRange(Long min, Long max, Map<String, Object> x) { return with(parseParamShorthand(min == null || max == null ? "int" : "int(" + min + ".." + max + ")"), x); }
        public static Map<String, Object> count(Long max, Map<String, Object> x) { return with(parseParamShorthand(max == null ? "count" : "count(" + max + ")"), x); }
        /** {@code ccy}: a literal ISO code, or a map {@code {from: param}} naming the currency param. {@code o}: {@code {max?, min?, exp?}} (may be null). */
        public static Map<String, Object> money(Object ccy, Map<String, Object> o, Map<String, Object> x) {
            StringBuilder b = new StringBuilder("money(").append(ccy instanceof String ? (String) ccy : "@" + J.get(ccy, "from"));
            if (o != null && o.get("max") != null) b.append(", max=").append(J.jsStr(o.get("max")));
            if (o != null && o.get("min") != null) b.append(", min=").append(J.jsStr(o.get("min")));
            if (o != null && o.get("exp") != null) b.append(", exp=").append(J.jsStr(o.get("exp")));
            return with(parseParamShorthand(b.append(")").toString()), x);
        }
        public static Map<String, Object> id(String type, Map<String, Object> x) { return with(parseParamShorthand("id:" + type), x); }
        public static Map<String, Object> enumOf(List<String> values, Map<String, Object> x) { return with(parseParamShorthand("enum(" + String.join("|", values) + ")"), x); }
        public static Map<String, Object> setOf(List<String> values, Map<String, Object> x) { return with(parseParamShorthand("set(" + String.join("|", values) + ")"), x); }
        public static Map<String, Object> array(String items, Long max, Map<String, Object> x) { return with(parseParamShorthand(max == null ? "array(" + items + ")" : "array(" + items + ", max=" + max + ")"), x); }
        public static Map<String, Object> optional(Map<String, Object> d) { Map<String, Object> c = new LinkedHashMap<>(d); c.put("required", Boolean.FALSE); return c; }
    }

    /**
     * The typed constructor over the JSON form: {@code action("acme.invoice.send", spec)}. Same expansion as the loader (so the same digest); throws
     * ActionKitError on a malformed spec.
     */
    public static Map<String, Object> action(String verb, Map<String, Object> spec) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("verb", verb);
        if (spec != null) entry.putAll(spec);
        Map<String, Object> def = J.m(expandAction(entry, null).get("def"));
        String bad = Actions.validateDef(def);
        if (bad != null) throw err("bad_action", verb + ": " + bad);
        return def;
    }
}
