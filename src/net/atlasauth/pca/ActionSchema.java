package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Rule 14: signed action schemas and the closed-world conformance check (packages/pca/src/action-schema.ts). A schema
 * {@code pca-action-schema} v1 is signed by a site key listed in the verifier's discovery key list; the suite is pinned by
 * the KEY ENTRY. Anything the schema does not declare is the fail-closed cell: an undeclared verb or parameter, a missing
 * required one, a wrong type or a value outside its domain is a terminal deny (never a question).
 */
public final class ActionSchema {
    private ActionSchema() {}

    public static final String ACTION_SCHEMA_DOMAIN = "atlas-pca/action-schema/v1\0";
    public static final String ACTION_SCHEMA_REF_DOMAIN = "atlas-pca/action-schema-ref/v1";
    public static final String ACTION_SCHEMA_KIND = "pca-action-schema";
    public static final int MAX_SCHEMA_VERBS = 256;
    public static final int MAX_SCHEMA_PARAMS = 64;
    public static final int MAX_SCHEMA_VALUES = 256;
    public static final int DEFAULT_MAX_LEN = 1024;
    public static final int DEFAULT_MAX_ITEMS = 64;
    static final Pattern PARAM_PATH_RE = Pattern.compile("action\\.params\\.[A-Za-z0-9_]{1,64}");
    static final Pattern UNIT_ID_RE = Pattern.compile("[a-z0-9_]+(?:\\.[a-z0-9_]+)*");
    static final Pattern PARAM_PATH_RE_V2 = Pattern.compile("action\\.params\\.[A-Za-z0-9_]{1,64}(?:\\.[A-Za-z0-9_]{1,64}){0,2}");
    private static final Pattern DATE_RE = Pattern.compile("([0-9]{4})-([0-9]{2})-([0-9]{2})");
    static final java.util.Set<String> RESERVED_NAMES = java.util.Set.of("__proto__", "constructor", "prototype");
    static final List<String> SENSITIVITIES = List.of("free", "material", "critical");
    static final List<String> SCHEMA_REVERSIBILITY = List.of("reversible", "rate_limited", "irreversible");
    static final List<String> PARAM_TYPES = List.of("string", "integer", "boolean", "date", "set", "array");
    static final List<String> PARAM_TYPES_V2 = List.of("string", "integer", "boolean", "date", "set", "array", "datetime", "duration", "object_ref");
    static final List<String> SCHEMA_V2_EFFECTS = Actions.EFFECTS;
    static final List<String> SCHEMA_V2_TAGS = Actions.PARAM_TAGS;
    private static final List<String> DOC_KEYS = List.of("v", "kind", "site", "aud", "version", "units", "state", "verbs", "sig");
    private static final List<String> DOC_KEYS_V2 = List.of("v", "kind", "site", "aud", "version", "units", "state", "verbs", "sig", "traits_digest", "trait_defs", "pack");
    private static final List<String> VERB_KEYS_V2 = List.of("verb", "kind", "params", "reversibility", "reversibility_by", "mcp", "openapi", "harm", "world", "effects", "returns", "description", "traits", "def", "floors", "confirmation");
    private static final List<String> PARAM_KEYS_V2 = List.of("type", "semantic", "sensitivity", "required", "values", "min", "max", "unit", "max_len", "items",
        "min_items", "max_items", "default", "principal_neutral_default", "accumulates_into", "issued_by_site", "description", "role", "format", "tags", "provenance_min");
    private static final List<String> VERB_KEYS = List.of("verb", "kind", "params", "reversibility", "reversibility_by", "mcp", "openapi", "harm", "world", "effects", "returns", "description");
    private static final List<String> PARAM_KEYS = List.of("type", "semantic", "sensitivity", "required", "values", "min", "max", "unit", "max_len", "items",
        "min_items", "max_items", "default", "principal_neutral_default", "accumulates_into", "issued_by_site", "description");
    private static final List<String> SIG_KEYS = List.of("alg", "kid", "value", "pq_value");

    /** A conformance verdict: {@code ok}, else the violation {@code code} (and {@code path} for a parameter). */
    public static final class Conform {
        public final boolean ok;
        public final String code;
        public final String path;
        public final String reason;
        Conform(boolean ok, String code, String path, String reason) { this.ok = ok; this.code = code; this.path = path; this.reason = reason; }
        static final Conform OK = new Conform(true, null, null, null);
    }

    static boolean isStr(Object v, int max) {
        return v instanceof String && !((String) v).isEmpty() && !Json.hasLoneSurrogate((String) v) && IntentJs.u8len((String) v) <= max;
    }
    static boolean isStr(Object v) { return isStr(v, 256); }
    private static boolean in(List<String> xs, Object v) { return v instanceof String && xs.contains(v); }
    private static boolean distinct(List<?> xs) { return new HashSet<Object>(xs).size() == xs.size(); }

    private static String paramDeclError(String path, Object dO, Object units, boolean v2) {
        if (!(v2 ? PARAM_PATH_RE_V2 : PARAM_PATH_RE).matcher(path).matches()) return "parameter path '" + path + "' is not action.params.<name>";
        for (String seg : path.substring("action.params.".length()).split("\\.", -1)) if (RESERVED_NAMES.contains(seg)) return "parameter name '" + path + "' is reserved (__proto__ / constructor / prototype)";
        if (!(dO instanceof Map)) return path + ": declaration must be an object";
        Map<String, Object> d = IntentJs.obj(dO);
        for (String k : d.keySet()) if (!(v2 ? PARAM_KEYS_V2 : PARAM_KEYS).contains(k)) return path + ": unknown member '" + k + "'";
        Object type = d.get("type");
        if (!in(v2 ? PARAM_TYPES_V2 : PARAM_TYPES, type)) return path + ": unknown type";
        if (!isStr(d.get("semantic"), 128)) return path + ": semantic must be a non-empty string";
        if (!in(SENSITIVITIES, d.get("sensitivity"))) return path + ": unknown sensitivity";
        if (d.containsKey("required") && !(d.get("required") instanceof Boolean)) return path + ": required must be a boolean";
        if (d.containsKey("values")) {
            Object vs = d.get("values");
            boolean ok = vs instanceof List && !((List<?>) vs).isEmpty() && ((List<?>) vs).size() <= MAX_SCHEMA_VALUES;
            if (ok) for (Object x : (List<?>) vs) if (!isStr(x)) { ok = false; break; }
            if (!ok) return path + ": values must be 1.." + MAX_SCHEMA_VALUES + " strings";
            if (!distinct((List<?>) vs)) return path + ": values must be distinct";
            if (!"string".equals(type) && !"set".equals(type)) return path + ": values apply to string and set only";
        }
        if ("set".equals(type) && !d.containsKey("values")) return path + ": a set needs values";
        boolean intItems = "array".equals(type) && "integer".equals(d.get("items"));
        for (String k : new String[] {"min", "max"}) {
            if (d.containsKey(k) && (!IntentJs.isInt(d.get(k)) || (!"integer".equals(type) && !(v2 && "duration".equals(type)) && !intItems))) return path + ": " + k + " must be a safe integer on an integer parameter";
        }
        if (IntentJs.isInt(d.get("min")) && IntentJs.isInt(d.get("max")) && IntentJs.num(d.get("min")) > IntentJs.num(d.get("max"))) return path + ": min > max";
        if (d.containsKey("unit") && (!"integer".equals(type) || !(d.get("unit") instanceof String) || !(units instanceof Map) || !((Map<?, ?>) units).containsKey(d.get("unit"))))
            return path + ": unit must name a declared unit of an integer parameter";
        if (d.containsKey("max_len") && (!IntentJs.isInt(d.get("max_len")) || IntentJs.num(d.get("max_len")) < 1)) return path + ": max_len must be a positive safe integer";
        if (d.containsKey("items") && (!"array".equals(type) || !isStr(d.get("items"), 64))) return path + ": items applies to array only";
        for (String k : new String[] {"min_items", "max_items"}) {
            if (d.containsKey(k) && (!IntentJs.isNonNeg(d.get(k)) || (!"set".equals(type) && !"array".equals(type)))) return path + ": " + k + " must be a non-negative safe integer on a set or array";
        }
        if (IntentJs.isInt(d.get("min_items")) && IntentJs.isInt(d.get("max_items")) && IntentJs.num(d.get("min_items")) > IntentJs.num(d.get("max_items"))) return path + ": min_items > max_items";
        if (d.containsKey("default") && d.get("default") == null) return path + ": default must not be null (absent = no default)";
        if (d.containsKey("principal_neutral_default") && !(d.get("principal_neutral_default") instanceof Boolean)) return path + ": principal_neutral_default must be a boolean";
        if (Boolean.TRUE.equals(d.get("principal_neutral_default")) && !d.containsKey("default")) return path + ": principal_neutral_default needs a default";
        if (d.containsKey("accumulates_into")) {
            if (!"integer".equals(type)) return path + ": accumulates_into applies to integer parameters only";
            Object ai = d.get("accumulates_into");
            if (!(ai instanceof List) || ((List<?>) ai).isEmpty() || ((List<?>) ai).size() > 8) return path + ": accumulates_into must be 1..8 unit ids";
            for (Object u : (List<?>) ai)
                if (!(u instanceof String) || ((String) u).length() > 64 || !UNIT_ID_RE.matcher((String) u).matches()) return path + ": accumulates_into entries must be unit ids";
            if (!distinct((List<?>) ai)) return path + ": accumulates_into must be distinct";
        }
        if (d.containsKey("issued_by_site") && !(d.get("issued_by_site") instanceof Boolean)) return path + ": issued_by_site must be a boolean";
        if (d.containsKey("description") && !isStr(d.get("description"), 1024)) return path + ": description must be a string";
        if (v2) {
            if (d.containsKey("role") && !isStr(d.get("role"), 128)) return path + ": role must be a non-empty string";
            if (d.containsKey("format") && (!(d.get("format") instanceof String) || formatCheck((String) d.get("format")) == null || !("string".equals(type) || "object_ref".equals(type))))
                return path + ": format must be a known format on a string parameter";
            if (d.containsKey("tags")) {
                Object tg = d.get("tags");
                boolean ok = tg instanceof List && ((List<?>) tg).size() <= SCHEMA_V2_TAGS.size();
                if (ok) for (Object x : (List<?>) tg) if (!in(SCHEMA_V2_TAGS, x)) { ok = false; break; }
                if (!ok || !distinct((List<?>) tg)) return path + ": tags must be distinct known tags";
            }
            if (d.containsKey("provenance_min") && !in(Actions.PROVENANCE_LEVELS, d.get("provenance_min"))) return path + ": unknown provenance_min";
        }
        return null;
    }

    /** Null if {@code fO} is a well-formed materialized profile (v2 {@code floors}; shape only, the semantic check is rule 22). */
    static String schemaFloorsError(Object fO) {
        if (!(fO instanceof Map)) return "floors must be an object";
        Map<String, Object> f = IntentJs.obj(fO);
        for (String k : f.keySet()) if (!List.of("risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules").contains(k)) return "floors: unknown member '" + k + "'";
        if (!rng(f.get("risk"), 0, 3) || !rng(f.get("esc"), 0, 3)) return "floors.risk and floors.esc must be integers in 0..3";
        if (!in(SCHEMA_REVERSIBILITY, f.get("rev"))) return "floors.rev is not a reversibility class";
        if (!rng(f.get("blast_ppm"), 0, 1_000_000)) return "floors.blast_ppm must be an integer in 0..1000000";
        for (String name : new String[] {"caveats", "context", "prules"}) {
            Object a = f.get(name);
            boolean ok = a instanceof List && ((List<?>) a).size() <= 64;
            if (ok) for (Object x : (List<?>) a) {
                boolean known = name.equals("caveats") ? in(Actions.CAVEAT_KINDS, x) : name.equals("prules") ? in(Actions.PARAM_RULE_IDS, x) : Actions.isContextKey(x);
                if (!known) { ok = false; break; }
            }
            if (!ok) return "floors." + name + " must be an array of known entries";
            List<?> l = (List<?>) a;
            for (int i = 1; i < l.size(); i++) if (((String) l.get(i - 1)).compareTo((String) l.get(i)) >= 0) return "floors." + name + " must be sorted and distinct";
        }
        return null;
    }

    private static boolean rng(Object x, int lo, int hi) { return IntentJs.isInt(x) && IntentJs.num(x) >= lo && IntentJs.num(x) <= hi; }

    private static boolean exactKeys(Object o, String... keys) {
        if (!(o instanceof Map)) return false;
        Map<?, ?> m = (Map<?, ?>) o;
        if (m.size() != keys.length) return false;
        for (String k : keys) if (!m.containsKey(k)) return false;
        return true;
    }

    private static String verbDeclError(Object vO, Object units, boolean v2) {
        if (!(vO instanceof Map)) return "verb entry must be an object";
        Map<String, Object> v = IntentJs.obj(vO);
        for (String k : v.keySet()) if (!(v2 ? VERB_KEYS_V2 : VERB_KEYS).contains(k)) return "verb entry: unknown member '" + k + "'";
        if (!isStr(v.get("verb"), 128)) return "verb entry: verb must be a non-empty string";
        String at = "verb '" + v.get("verb") + "'";
        if (!"read".equals(v.get("kind")) && !"write".equals(v.get("kind"))) return at + ": kind must be read or write";
        if (!(v.get("params") instanceof Map)) return at + ": params must be an object";
        Map<String, Object> params = IntentJs.obj(v.get("params"));
        if (params.size() > MAX_SCHEMA_PARAMS) return at + ": more than " + MAX_SCHEMA_PARAMS + " parameters";
        for (Map.Entry<String, Object> e : params.entrySet()) {
            String err = paramDeclError(e.getKey(), e.getValue(), units, v2);
            if (err != null) return at + ": " + err;
        }
        if (v2) for (String p : params.keySet()) for (String q : params.keySet()) if (!q.equals(p) && q.startsWith(p + ".")) return at + ": parameter '" + p + "' is both a value and the parent of '" + q + "'";
        if (v.containsKey("reversibility") && !in(SCHEMA_REVERSIBILITY, v.get("reversibility"))) return at + ": unknown reversibility";
        if (v.containsKey("reversibility_by")) {
            Object rO = v.get("reversibility_by");
            boolean ok = rO instanceof Map;
            if (ok) for (Object k : ((Map<?, ?>) rO).keySet()) if (!List.of("param", "map", "default").contains(k)) ok = false;
            if (!ok) return at + ": reversibility_by must be {param, map, default?}";
            Map<String, Object> r = IntentJs.obj(rO);
            if (!(r.get("param") instanceof String) || !params.containsKey(r.get("param"))) return at + ": reversibility_by.param must be a declared parameter";
            boolean mapOk = r.get("map") instanceof Map && !((Map<?, ?>) r.get("map")).isEmpty();
            if (mapOk) for (Object x : ((Map<?, ?>) r.get("map")).values()) if (!in(SCHEMA_REVERSIBILITY, x)) mapOk = false;
            if (!mapOk) return at + ": reversibility_by.map must map values to reversibility classes";
            if (r.containsKey("default") && !in(SCHEMA_REVERSIBILITY, r.get("default"))) return at + ": reversibility_by.default is not a reversibility class";
        }
        if (v.containsKey("mcp") && (!exactKeys(v.get("mcp"), "tool") || !isStr(IntentJs.get(v.get("mcp"), "tool"), 128))) return at + ": mcp must be {tool}";
        if (v.containsKey("openapi") && (!exactKeys(v.get("openapi"), "operationId") || !isStr(IntentJs.get(v.get("openapi"), "operationId"), 128))) return at + ": openapi must be {operationId}";
        for (String k : v2 ? new String[] {"harm", "returns"} : new String[] {"harm", "effects", "returns"}) if (v.containsKey(k) && !(v.get(k) instanceof Map)) return at + ": " + k + " must be an object";
        if (v2) {
            Object ef = v.get("effects");
            boolean ok = ef instanceof List && !((List<?>) ef).isEmpty() && ((List<?>) ef).size() <= SCHEMA_V2_EFFECTS.size();
            if (ok) for (Object x : (List<?>) ef) if (!in(SCHEMA_V2_EFFECTS, x)) { ok = false; break; }
            if (!ok) return at + ": effects must be 1.." + SCHEMA_V2_EFFECTS.size() + " known effects";
            List<?> efl = (List<?>) ef;
            boolean allRead = true;
            for (int i = 0; i < efl.size(); i++) {
                if (i > 0 && ((String) efl.get(i - 1)).compareTo((String) efl.get(i)) >= 0) return at + ": effects must be sorted and distinct";
                if (!"read".equals(efl.get(i))) allRead = false;
            }
            if ("read".equals(v.get("kind")) != allRead) return at + ": kind read must hold exactly when every effect is read";
            Object tr = v.get("traits");
            boolean tok = tr instanceof List && ((List<?>) tr).size() <= 64;
            if (tok) for (Object x : (List<?>) tr) if (!(x instanceof String) || !Actions.TRAIT_ID_RE.matcher((String) x).matches()) { tok = false; break; }
            if (!tok) return at + ": traits must be trait ids";
            List<?> trl = (List<?>) tr;
            for (int i = 1; i < trl.size(); i++) if (((String) trl.get(i - 1)).compareTo((String) trl.get(i)) >= 0) return at + ": traits must be sorted and distinct";
            if (Pca.decodeB64uStrict(v.get("def"), 32) == null) return at + ": def must be a canonical base64url SHA-256 digest";
            String fe = schemaFloorsError(v.get("floors"));
            if (fe != null) return at + ": " + fe;
            if (v.containsKey("confirmation")) {
                String ce = confirmationShapeError(v.get("confirmation"));
                if (ce != null) return at + ": " + ce;
            }
        }
        if (v.containsKey("world") && !(v.get("world") instanceof List)) return at + ": world must be an array";
        if (v.containsKey("description") && !isStr(v.get("description"), 1024)) return at + ": description must be a string";
        return null;
    }

    private static final List<String> CONFIRMATION_KEYS = List.of("def_digest", "traits_digest", "facts_digest", "final_traits", "dismissed", "reviewer_kid", "ts", "sig");

    /** Null if {@code cO} is a well-formed verb {@code confirmation} (shape only; the signature check is rule 22). */
    static String confirmationShapeError(Object cO) {
        if (!(cO instanceof Map)) return "confirmation must be an object";
        Map<String, Object> c = IntentJs.obj(cO);
        for (String k : c.keySet()) if (!CONFIRMATION_KEYS.contains(k)) return "confirmation: unknown member '" + k + "'";
        if (Pca.decodeB64uStrict(c.get("def_digest"), 32) == null || Pca.decodeB64uStrict(c.get("traits_digest"), 32) == null || Pca.decodeB64uStrict(c.get("facts_digest"), 32) == null) return "confirmation: def_digest, traits_digest and facts_digest must be canonical base64url SHA-256 digests";
        if (Pca.decodeB64uStrict(c.get("sig"), 64) == null) return "confirmation: sig must be a canonical base64url 64-byte signature";
        Object ft = c.get("final_traits");
        boolean ok = ft instanceof List && ((List<?>) ft).size() <= 64;
        if (ok) for (Object x : (List<?>) ft) if (!(x instanceof String) || !Actions.TRAIT_ID_RE.matcher((String) x).matches()) { ok = false; break; }
        if (!ok) return "confirmation: final_traits must be trait ids";
        List<?> fl = (List<?>) ft;
        for (int i = 1; i < fl.size(); i++) if (((String) fl.get(i - 1)).compareTo((String) fl.get(i)) >= 0) return "confirmation: final_traits must be sorted and distinct";
        Object dm = c.get("dismissed");
        if (!(dm instanceof List) || ((List<?>) dm).size() > 64) return "confirmation: dismissed must be an array";
        for (Object d : (List<?>) dm) {
            if (!(d instanceof Map) || !List.of("trait", "reason").containsAll(((Map<?, ?>) d).keySet()) || !(IntentJs.get(d, "trait") instanceof String)
                || !Actions.TRAIT_ID_RE.matcher((String) IntentJs.get(d, "trait")).matches() || !isStr(IntentJs.get(d, "reason"), 256)) return "confirmation: dismissed entries must be {trait, reason}";
        }
        if (!isStr(c.get("reviewer_kid"), 128)) return "confirmation: reviewer_kid must be a non-empty string";
        if (!IntentJs.isNonNeg(c.get("ts"))) return "confirmation: ts must be a non-negative safe integer";
        return null;
    }

    /** Structural validation of a signed schema. Null = well-formed. Never throws. */
    public static String shapeError(Object docO) { return shapeError(docO, true); }

    /** As {@link #shapeError(Object)}; with {@code signed == false} the document must not carry {@code sig} (the unsigned schema a site builds before signing). */
    public static String shapeError(Object docO, boolean signed) {
        try {
            if (!(docO instanceof Map)) return "schema is not an object";
            Map<String, Object> doc = IntentJs.obj(docO);
            boolean v2 = isTwo(doc.get("v"));
            for (String k : doc.keySet()) if (!(v2 ? DOC_KEYS_V2 : DOC_KEYS).contains(k)) return "unknown member '" + k + "'";
            if (!OracleFacts.isOne(doc.get("v")) && !v2) return "unsupported schema version";
            if (!ACTION_SCHEMA_KIND.equals(doc.get("kind"))) return "kind must be '" + ACTION_SCHEMA_KIND + "'";
            if (!isStr(doc.get("site"), 2048) || !isStr(doc.get("aud"), 256) || !isStr(doc.get("version"), 128)) return "site, aud and version must be non-empty strings";
            if (doc.containsKey("units")) {
                if (!(doc.get("units") instanceof Map)) return "units must be an object";
                for (Map.Entry<String, Object> e : IntentJs.obj(doc.get("units")).entrySet()) {
                    String id = e.getKey();
                    Object u = e.getValue();
                    if (!UNIT_ID_RE.matcher(id).matches() || id.length() > 64) return "unit id '" + id + "' is malformed";
                    if (!(u instanceof Map) || !isStr(IntentJs.get(u, "kind"), 64)) return "unit '" + id + "' must be an object with a kind";
                    for (Object k : ((Map<?, ?>) u).keySet()) if (!List.of("kind", "currency", "exponent").contains(k)) return "unit '" + id + "': unknown member";
                    if (IntentJs.own(u, "currency") && !isStr(IntentJs.get(u, "currency"), 16)) return "unit '" + id + "': currency must be a string";
                    if (IntentJs.own(u, "exponent") && !(IntentJs.isNonNeg(IntentJs.get(u, "exponent")) && IntentJs.num(IntentJs.get(u, "exponent")) <= 18))
                        return "unit '" + id + "': exponent must be an integer in [0, 18]";
                }
            }
            if (doc.containsKey("state") && !(doc.get("state") instanceof List)) return "state must be an array";
            if (v2) {
                if (doc.containsKey("traits_digest") && Pca.decodeB64uStrict(doc.get("traits_digest"), 32) == null) return "traits_digest must be a canonical base64url SHA-256 digest";
                if (doc.containsKey("trait_defs")) {
                    Object td = doc.get("trait_defs");
                    boolean ok = td instanceof List && ((List<?>) td).size() <= 64;
                    if (ok) for (Object x : (List<?>) td) if (!(x instanceof Map)) { ok = false; break; }
                    if (!ok) return "trait_defs must be an array of up to 64 objects";
                }
                if (doc.containsKey("pack")) {
                    Object pk = doc.get("pack");
                    if (!exactKeys(pk, "ns", "root", "version") || !isStr(IntentJs.get(pk, "ns"), 64) || !isStr(IntentJs.get(pk, "version"), 128) || Pca.decodeB64uStrict(IntentJs.get(pk, "root"), 32) == null)
                        return "pack must be {ns, version, root}";
                }
            }
            Object verbs = doc.get("verbs");
            if (!(verbs instanceof List) || ((List<?>) verbs).isEmpty() || ((List<?>) verbs).size() > MAX_SCHEMA_VERBS) return "verbs must be 1.." + MAX_SCHEMA_VERBS + " entries";
            Set<String> seen = new HashSet<>();
            for (Object v : (List<?>) verbs) {
                String e = verbDeclError(v, doc.get("units"), v2);
                if (e != null) return e;
                String name = (String) IntentJs.get(v, "verb");
                if (!seen.add(name)) return "verb '" + name + "' is declared twice";
            }
            if (signed) {
                Object s = doc.get("sig");
                if (!(s instanceof Map)) return "sig must be an object";
                Map<String, Object> sig = IntentJs.obj(s);
                for (String k : sig.keySet()) if (!SIG_KEYS.contains(k)) return "sig: unknown member '" + k + "'";
                String se = IntentJs.suiteError(sig.get("alg"), sig.containsKey("alg"));
                if (se != null) return "sig.alg: " + se;
                if (!isStr(sig.get("kid"), 128)) return "sig.kid must be a non-empty string";
                if (!IntentJs.b64any(sig.get("value"))) return "sig.value is not canonical base64url";
                if (sig.containsKey("pq_value") && !IntentJs.b64any(sig.get("pq_value"))) return "sig.pq_value is not canonical base64url";
            } else if (doc.containsKey("sig")) return "an unsigned schema must not carry sig";
            IntentJs.canonBytes(body(doc));
            return null;
        } catch (RuntimeException e) {
            return "malformed schema: " + e.getMessage();
        }
    }

    private static Map<String, Object> body(Map<String, Object> doc) {
        Map<String, Object> b = new LinkedHashMap<>(doc);
        b.remove("sig");
        return b;
    }

    /**
     * Verify a site-signed schema against the discovery key list: shape, {@code sig.kid} names a listed key, {@code sig.alg}
     * equals that key's suite, and the signature verifies (a PQ key only as pinned by the key entry). Null = valid.
     */
    public static String verify(Object docO, Object keys) {
        try {
            String bad = shapeError(docO);
            if (bad != null) return bad;
            Map<String, Object> doc = IntentJs.obj(docO);
            Map<String, Object> sig = IntentJs.obj(doc.get("sig"));
            if (!(keys instanceof List)) return "the schema keys must be an array";
            Map<String, Object> key = null;
            for (Object k : (List<?>) keys) if (k instanceof Map && IntentJs.get(k, "kid") instanceof String && IntentJs.get(k, "kid").equals(sig.get("kid"))) { key = IntentJs.obj(k); break; }
            if (key == null) return "no schema key with kid '" + sig.get("kid") + "'";
            if (key.containsKey("pq_pk") && !(key.get("pq_pk") instanceof String)) return "the schema key pq_pk must be a string";
            if (Pca.decodeB64uStrict(key.get("pk"), 32) == null) return "schema key pk is not canonical base64url (32 bytes)";
            String kse = IntentJs.suiteError(key.get("alg"), key.containsKey("alg"));
            if (kse != null) return "schema key: " + kse;
            String ka = IntentJs.suiteOf(key);
            if (ka == null || !ka.equals(IntentJs.suiteOf(sig))) return "sig.alg does not match the pinned key suite";
            String pk = (String) key.get("pk");
            Map<String, Object> pin = key.containsKey("pq_pk") ? IntentJs.pin(pk, key.get("pq_pk")) : null;
            byte[] msg = IntentJs.message(ACTION_SCHEMA_DOMAIN, body(doc));
            if (!IntentJs.verifyPinnedSuite(ka, true, pk, key.get("pq_pk"), msg, sig.get("value"), sig.get("pq_value"), pin)) return "schema signature invalid";
            return null;
        } catch (RuntimeException e) {
            return "schema verification error: " + e.getMessage();
        }
    }

    /** The schema's content address (over the whole signed document). */
    public static String digest(Object doc) { return IntentJs.ref(ACTION_SCHEMA_REF_DOMAIN, "s", doc); }

    /** The verb entry named {@code verb}, or null. */
    static Map<String, Object> schemaVerb(Object doc, String verb) {
        Object verbs = IntentJs.get(doc, "verbs");
        if (!(verbs instanceof List)) return null;
        for (Object v : (List<?>) verbs) if (v instanceof Map && verb.equals(((Map<?, ?>) v).get("verb"))) return IntentJs.obj(v);
        return null;
    }

    private static boolean isTwo(Object v) { Double d = IntentJs.num(v); return d != null && d == 2.0; }

    // ---- v2 string formats (syntactic checks, identical in every language; none consults a registry or the network) ----
    private static final String JS_WS = "\\t\\n\\u000B\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"; // the ECMAScript \s class
    private static final Pattern EMAIL_RE = Pattern.compile("[A-Za-z0-9._%+\\-]{1,64}@[A-Za-z0-9\\-]{1,63}(?:\\.[A-Za-z0-9\\-]{1,63})+");
    private static final Pattern URL_RE = Pattern.compile("[A-Za-z][A-Za-z0-9+.\\-]{0,31}://[^" + JS_WS + "/?#]+[^" + JS_WS + "]*");
    private static final Pattern HTTPS_RE = Pattern.compile("https://[^" + JS_WS + "/?#]+[^" + JS_WS + "]*");
    private static final Pattern UUID_RE = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern IBAN_RE = Pattern.compile("[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}");
    private static final Pattern PHONE_RE = Pattern.compile("\\+[1-9][0-9]{6,14}");
    private static final Pattern CIDR4_RE = Pattern.compile("([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})/([0-9]{1,2})");
    private static final Pattern CIDR6_RE = Pattern.compile("([0-9a-fA-F:]{2,39})/([0-9]{1,3})");
    private static final Pattern COUNTRY_RE = Pattern.compile("[A-Z]{2}");
    private static final Pattern CURRENCY_RE = Pattern.compile("[A-Z]{3}");
    private static final Pattern SEMVER_RE = Pattern.compile("(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z\\-]+(?:\\.[0-9A-Za-z\\-]+)*)?(?:\\+[0-9A-Za-z\\-]+(?:\\.[0-9A-Za-z\\-]+)*)?");
    private static final Pattern SHA256_RE = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern ID_FORMAT_RE = Pattern.compile("id:[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}");
    private static final Pattern ID_VALUE_RE = Pattern.compile("[A-Za-z0-9._:\\-]{1,128}");
    private static final Pattern DATETIME_RE = Pattern.compile("([0-9]{4}-[0-9]{2}-[0-9]{2})T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(?:\\.[0-9]{1,3})?Z");

    private static boolean canonDec(String n) { return String.valueOf(Integer.parseInt(n)).equals(n); }

    private static boolean ibanOk(String s) {
        if (!IBAN_RE.matcher(s).matches()) return false;
        int rem = 0;
        String r = s.substring(4) + s.substring(0, 4);
        for (int i = 0; i < r.length(); i++) {
            char ch = r.charAt(i);
            int v = ch >= 'A' ? ch - 55 : ch - 48;
            rem = (v > 9 ? rem * 100 + v : rem * 10 + v) % 97;
        }
        return rem == 1;
    }

    private static boolean cidrOk(String s) {
        Matcher m = CIDR4_RE.matcher(s);
        if (m.matches()) {
            for (int i = 1; i <= 4; i++) if (Integer.parseInt(m.group(i)) > 255 || !canonDec(m.group(i))) return false;
            return Integer.parseInt(m.group(5)) <= 32 && canonDec(m.group(5));
        }
        m = CIDR6_RE.matcher(s);
        if (!m.matches()) return false;
        long colons = m.group(1).chars().filter(c -> c == ':').count();
        return colons >= 2 && !m.group(1).contains(":::") && Integer.parseInt(m.group(2)) <= 128 && canonDec(m.group(2));
    }

    /** The checker of a v2 {@code format}, or null when the format is unknown. {@code id:<type>} accepts a 1..128 character safe id. */
    static java.util.function.Predicate<String> formatCheck(String f) {
        switch (f) {
            case "email": return s -> s.length() <= 254 && EMAIL_RE.matcher(s).matches();
            case "url": return s -> URL_RE.matcher(s).matches();
            case "uri_https": return s -> HTTPS_RE.matcher(s).matches();
            case "uuid": return s -> UUID_RE.matcher(s).matches();
            case "iban": return ActionSchema::ibanOk;
            case "phone_e164": return s -> PHONE_RE.matcher(s).matches();
            case "cidr": return ActionSchema::cidrOk;
            case "iso_country": return s -> COUNTRY_RE.matcher(s).matches();
            case "iso_currency": return s -> CURRENCY_RE.matcher(s).matches();
            case "semver": return s -> SEMVER_RE.matcher(s).matches();
            case "sha256": return s -> SHA256_RE.matcher(s).matches();
            default: return ID_FORMAT_RE.matcher(f).matches() ? s -> ID_VALUE_RE.matcher(s).matches() : null;
        }
    }

    private static String[] formatViolation(Map<String, Object> d, String x) {
        if (!d.containsKey("format")) return null;
        java.util.function.Predicate<String> ck = d.get("format") instanceof String ? formatCheck((String) d.get("format")) : null;
        return ck == null || !ck.test(x) ? new String[] {"out_of_domain", "not a valid " + d.get("format")} : null;
    }

    private static boolean isCalendarDate(String s) {
        Matcher m = DATE_RE.matcher(s);
        if (!m.matches()) return false;
        int y = Integer.parseInt(m.group(1)), mo = Integer.parseInt(m.group(2)), d = Integer.parseInt(m.group(3));
        if (y < 1 || mo < 1 || mo > 12 || d < 1) return false;
        boolean leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        int[] dim = {31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        return d <= dim[mo - 1];
    }

    private static boolean strOk(Object x, double maxLen) { return x instanceof String && !Json.hasLoneSurrogate((String) x) && IntentJs.u8len((String) x) <= maxLen; }

    /** {@code d[k] ?? dflt} as a number. */
    private static double numOr(Map<String, Object> d, String k, double dflt) { Object v = d.get(k); return v == null ? dflt : IntentJs.num(v); }

    /** The value check of one declared parameter: null = in the domain, else {code, reason}. */
    static String[] paramValueViolation(Map<String, Object> d, Object x) {
        double maxLen = numOr(d, "max_len", DEFAULT_MAX_LEN);
        Object type = d.get("type");
        switch (type instanceof String ? (String) type : "") {
            case "string":
                if (!(x instanceof String) || Json.hasLoneSurrogate((String) x)) return new String[] {"bad_type", "expected a string"};
                if (IntentJs.u8len((String) x) > maxLen) return new String[] {"out_of_domain", "longer than the declared max_len"};
                if (d.containsKey("values") && !((List<?>) d.get("values")).contains(x)) return new String[] {"out_of_domain", "not one of the declared values"};
                return formatViolation(d, (String) x);
            case "object_ref":
                if (!(x instanceof String) || Json.hasLoneSurrogate((String) x) || ((String) x).isEmpty()) return new String[] {"bad_type", "expected a non-empty id string"};
                if (IntentJs.u8len((String) x) > maxLen) return new String[] {"out_of_domain", "longer than the declared max_len"};
                return formatViolation(d, (String) x);
            case "datetime": {
                if (!(x instanceof String)) return new String[] {"bad_type", "expected an RFC 3339 UTC string"};
                Matcher m = DATETIME_RE.matcher((String) x);
                return m.matches() && isCalendarDate(m.group(1)) ? null : new String[] {"out_of_domain", "not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z"};
            }
            case "duration": {
                if (!IntentJs.isInt(x)) return new String[] {"bad_type", "expected a safe integer (milliseconds)"};
                double v = IntentJs.num(x);
                if (v < 0) return new String[] {"out_of_domain", "a duration is not negative"};
                if (d.containsKey("min") && v < IntentJs.num(d.get("min"))) return new String[] {"out_of_domain", "below min"};
                if (d.containsKey("max") && v > IntentJs.num(d.get("max"))) return new String[] {"out_of_domain", "above max"};
                return null;
            }
            case "integer": {
                if (!IntentJs.isInt(x)) return new String[] {"bad_type", "expected a safe integer"};
                double v = IntentJs.num(x);
                if (d.containsKey("min") && v < IntentJs.num(d.get("min"))) return new String[] {"out_of_domain", "below min"};
                if (d.containsKey("max") && v > IntentJs.num(d.get("max"))) return new String[] {"out_of_domain", "above max"};
                return null;
            }
            case "boolean":
                return x instanceof Boolean ? null : new String[] {"bad_type", "expected a boolean"};
            case "date":
                if (!(x instanceof String)) return new String[] {"bad_type", "expected a YYYY-MM-DD string"};
                return isCalendarDate((String) x) ? null : new String[] {"out_of_domain", "not a calendar date YYYY-MM-DD"};
            case "set": {
                if (!(x instanceof List)) return new String[] {"bad_type", "expected an array of strings"};
                List<?> xs = (List<?>) x;
                for (Object e : xs) if (!(e instanceof String)) return new String[] {"bad_type", "expected an array of strings"};
                if (!distinct(xs)) return new String[] {"out_of_domain", "set members must be distinct"};
                List<?> values = (List<?>) d.get("values");
                for (Object e : xs) if (!values.contains(e)) return new String[] {"out_of_domain", "set member not among the declared values"};
                if (xs.size() < numOr(d, "min_items", 0) || xs.size() > numOr(d, "max_items", values.size())) return new String[] {"out_of_domain", "set size outside the declared bounds"};
                return null;
            }
            case "array": {
                if (!(x instanceof List)) return new String[] {"bad_type", "expected an array"};
                List<?> xs = (List<?>) x;
                boolean ints = "integer".equals(d.get("items"));
                for (Object e : xs) {
                    if (ints ? !IntentJs.isInt(e) : !strOk(e, maxLen))
                        return new String[] {"bad_type", ints ? "array items must be safe integers" : "array items must be strings within max_len UTF-8 bytes"};
                    if (ints && ((d.containsKey("min") && IntentJs.num(e) < IntentJs.num(d.get("min"))) || (d.containsKey("max") && IntentJs.num(e) > IntentJs.num(d.get("max")))))
                        return new String[] {"out_of_domain", "array item outside min/max"};
                }
                if (xs.size() < numOr(d, "min_items", 0) || xs.size() > numOr(d, "max_items", DEFAULT_MAX_ITEMS)) return new String[] {"out_of_domain", "array length outside the declared bounds"};
                return null;
            }
            default:
                return new String[] {"bad_type", "unknown declared type"};
        }
    }

    /**
     * Map an action to the declared domain or to the fail-closed cell (rule 14 step 5). First failure wins:
     * params_not_object; unknown_verb; undeclared_param (params keys in UTF-8 byte order); then for every declared path in
     * UTF-8 byte order: missing_param (absent and required, default true), else bad_type / out_of_domain.
     */
    public static Conform conform(Object doc, String verb, Object params) {
        if (!(params instanceof Map)) return new Conform(false, "params_not_object", null, "params must be a JSON object");
        Map<String, Object> v = schemaVerb(doc, verb);
        if (v == null) return new Conform(false, "unknown_verb", null, "verb '" + verb + "' is not declared by the schema");
        Map<String, Object> declared = IntentJs.obj(v.get("params"));
        Map<String, Object> p = IntentJs.obj(params);
        for (String k : IntentJs.sortedUtf8(p.keySet())) {
            String path = "action.params." + k;
            if (!declared.containsKey(path)) return new Conform(false, "undeclared_param", path, "parameter '" + path + "' is not declared for '" + verb + "'");
        }
        for (String path : IntentJs.sortedUtf8(declared.keySet())) {
            Map<String, Object> d = IntentJs.obj(declared.get(path));
            String name = path.substring("action.params.".length());
            if (!p.containsKey(name)) {
                if (!Boolean.FALSE.equals(d.get("required"))) return new Conform(false, "missing_param", path, "required parameter '" + path + "' is missing");
                continue;
            }
            String[] bad = paramValueViolation(d, p.get(name));
            if (bad != null) return new Conform(false, bad[0], path, "'" + path + "': " + bad[1]);
        }
        return Conform.OK;
    }

    /** The integer parameters of a verb entry that feed {@code unit} ({@code accumulates_into}), in UTF-8 byte order. */
    static List<String> accumulationParams(Map<String, Object> v, String unit) {
        Map<String, Object> params = IntentJs.obj(v.get("params"));
        List<String> out = new ArrayList<>();
        for (String p : params.keySet()) {
            Object d = params.get(p);
            Object ai = IntentJs.get(d, "accumulates_into");
            if ("integer".equals(IntentJs.get(d, "type")) && ai instanceof List && ((List<?>) ai).contains(unit)) out.add(p);
        }
        return IntentJs.sortedUtf8(out);
    }

    /**
     * {@code env.canon}: for every PRESENT parameter of type boolean ({@code "true"} / {@code "false"}), set (strict canonical
     * JSON of its members sorted by UTF-8 bytes) and array (strict canonical JSON as sent).
     */
    public static Map<String, Object> canonProjection(Object doc, String verb, Map<String, Object> params) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> v = schemaVerb(doc, verb);
        if (v == null) return out;
        Map<String, Object> declared = IntentJs.obj(v.get("params"));
        for (String path : IntentJs.sortedUtf8(declared.keySet())) {
            Object type = IntentJs.get(declared.get(path), "type");
            String name = path.substring("action.params.".length());
            if (!params.containsKey(name)) continue;
            Object x = params.get(name);
            if ("boolean".equals(type)) out.put(name, Boolean.TRUE.equals(x) ? "true" : "false");
            else if ("set".equals(type)) {
                List<String> members = new ArrayList<>();
                for (Object e : (List<?>) x) members.add((String) e);
                out.put(name, IntentJs.canon(IntentJs.sortedUtf8(members)));
            } else if ("array".equals(type)) out.put(name, IntentJs.canon(x));
        }
        return out;
    }
}
