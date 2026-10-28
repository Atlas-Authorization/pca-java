package net.atlasauth.pca;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Action kit (native port of the small deterministic core of packages/pca-actions): strict ActionDef parse, normalize and
 * canonical digest, the trait registry with its closure / floor algebra, rule 22 (FloorDecision and the schema floor integrity
 * check), the pack Merkle root and inclusion proof, and T(d) / eff(d). Integers and sets only; every function is pure.
 * The shared vectors (conformance vectors "actions") pin every output byte for byte. ActionSchema v2 parsing and the v2
 * parameter types / formats live in {@link ActionSchema}.
 */
public final class Actions {
    private Actions() {}

    public static final String ACTION_DEF_KIND = "pca-action-def";
    public static final String DEF_DIGEST_DOMAIN = "atlas-pca/action-def/v1";
    public static final String TRAITS_DIGEST_DOMAIN = "atlas-pca/action-traits/v1";
    public static final String VERB_FACTS_DOMAIN = "atlas-pca/action-verb-facts/v1";
    public static final String ROLES_DIGEST_DOMAIN = "atlas-pca/action-roles/v1";
    public static final String PACK_DIGEST_DOMAIN = "atlas-pca/action-pack/v1";

    static final int MAX_VERB_BYTES = 128, MAX_TITLE_BYTES = 120, MAX_DESCRIPTION_BYTES = 1024, MAX_DEF_PARAMS = 64, MAX_DEF_ALIASES = 16,
        MAX_DEF_TRAITS = 32, MAX_DEF_CONTEXT = 16, MAX_DEF_SIDE_EFFECTS = 16, MAX_TRAIT_IMPLIES_DEPTH = 8, MAX_REGISTRY_TRAITS = 512, PPM_MAX = 1_000_000;

    static final List<String> EFFECTS = List.of("read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign");
    static final List<String> REVERSIBILITY = List.of("reversible", "rate_limited", "irreversible");
    static final List<String> BLAST_RADII = List.of("one", "bounded", "tenant", "global");
    static final Map<String, Integer> BLAST_PPM = Map.of("one", 50_000, "bounded", 300_000, "tenant", 700_000, "global", 1_000_000);
    static final List<String> RESOURCE_SCOPES = List.of("one", "set", "tenant", "global");
    static final Map<String, String> SCOPE_BLAST = Map.of("one", "one", "set", "bounded", "tenant", "tenant", "global", "global");
    static final List<String> PARAM_TYPES = List.of("string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref");
    static final List<String> SENSITIVITY = List.of("free", "material", "critical");
    static final List<String> PROVENANCE_LEVELS = List.of("first_party", "tool", "agent");
    static final List<String> CORE_ROLES = List.of(
        "money.amount", "money.currency", "money.fee", "party.payee", "party.payer",
        "contact.email", "contact.phone", "contact.address", "person.name", "person.dob", "person.national_id",
        "credential.secret", "credential.token", "credential.key",
        "path.fs", "query.sql", "query.search", "code.source", "code.command", "url.target",
        "text.message", "text.public", "time.not_before", "time.not_after", "count.limit", "bytes.size");
    static final List<String> PARAM_TAGS = List.of("pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql");
    static final List<String> PARAM_FORMATS = List.of("email", "url", "uri_https", "uuid", "iban", "phone_e164", "cidr", "iso_country", "iso_currency", "semver", "sha256");
    static final List<String> UNIT_KINDS = List.of("money", "count", "bytes", "duration", "ratio");
    static final List<String> CAVEAT_KINDS = List.of("amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap");
    static final List<String> CONTEXT_KEYS = List.of("approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested");
    static final List<String> PARAM_RULE_IDS = List.of("array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency",
        "pay_has_idempotency", "recipient_param_declared", "secret_not_logged");
    static final List<String> IDEMPOTENCY_MODES = List.of("key_param", "natural", "none");
    static final List<String> REVIEW_STATES = List.of("authored", "unreviewed", "suggested", "confirmed");
    static final List<String> BINDING_KINDS = List.of("mcp", "openapi", "http", "graphql", "grpc", "asyncapi");
    static final List<String> ID_CLASSES = List.of("digits", "hex", "alnum", "slug", "uuid", "any_safe");
    static final Set<String> RESERVED = Set.of("__proto__", "constructor", "prototype");
    static final Set<String> INT_ROLES = Set.of("money.amount", "money.fee", "count.limit", "bytes.size");

    private static final Pattern ID_ROLE_RE = Pattern.compile("id\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}");
    private static final Pattern CUSTOM_ROLE_RE = Pattern.compile("x\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){1,3}");
    private static final Pattern TAINT_RE = Pattern.compile("session_taint_max:[a-z_]{1,16}");
    private static final Pattern VERB_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){1,5}");
    private static final Pattern ALIAS_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){0,5}");
    private static final Pattern PARAM_NAME_RE = Pattern.compile("[A-Za-z0-9_]{1,64}(?:\\.[A-Za-z0-9_]{1,64}){0,2}");
    static final Pattern TRAIT_ID_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}\\.[a-z][a-z0-9_]{0,63}");
    private static final Pattern RESOURCE_TYPE_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){0,4}");
    private static final Pattern UNIT_ID_RE = Pattern.compile("[a-z0-9_]+(?:\\.[a-z0-9_]+)*");
    private static final Pattern CCY_RE = Pattern.compile("[A-Z]{3}");
    private static final Set<String> PARAM_KEYS = Set.of("type", "role", "required", "values", "min", "max", "max_len", "items", "min_items", "max_items", "format", "unit", "tags",
        "provenance_min", "sensitivity", "accumulates", "default", "principal_neutral_default", "description");
    private static final Set<String> DEF_KEYS = Set.of("v", "kind", "verb", "aliases", "title", "description", "effects", "resource", "params", "reversibility", "blast",
        "side_effects", "idempotency", "context", "traits", "audience", "compensates", "bindings", "examples", "review", "source", "since");

    /** A typed refusal of a pure operation (never a silent default). */
    public static final class ActionKitError extends RuntimeException {
        public final String code;
        public ActionKitError(String code, String message) { super(message); this.code = code; }
    }

    // ---- helpers -----------------------------------------------------------------------------------------------------------

    private static Json.Num n(long v) { return IntentJs.ofLong(v); }
    private static long L(Object o) { return IntentJs.lng(o); }
    private static boolean isInt(Object o) { return IntentJs.isInt(o); }
    private static boolean isNonNeg(Object o) { return IntentJs.isNonNeg(o); }
    private static boolean isMap(Object o) { return o instanceof Map; }
    private static boolean isStr(Object v, int max) { return ActionSchema.isStr(v, max); }
    private static boolean isStr(Object v) { return ActionSchema.isStr(v, 256); }
    private static boolean inS(Object x, Collection<String> xs) { return x instanceof String && xs.contains(x); }
    private static boolean isStrings(Object v) { return v instanceof List && ((List<?>) v).stream().allMatch(x -> x instanceof String); }
    private static boolean distinct(List<?> xs) { return new HashSet<Object>(xs).size() == xs.size(); }
    @SuppressWarnings("unchecked") private static Map<String, Object> M(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> A(Object o) { return (List<Object>) o; }
    private static String S(Object o) { return (String) o; }
    private static String sortedKeys(Map<String, Object> m) { return String.join(",", new TreeSet<>(m.keySet())); }
    private static List<String> sortUniq(Object xs) {
        List<String> out = new ArrayList<>();
        if (xs instanceof List) for (Object x : (List<?>) xs) out.add((String) x);
        return new ArrayList<>(new TreeSet<>(out));
    }
    private static List<Object> toObjs(Collection<String> xs) { return new ArrayList<Object>(xs); }
    static boolean isContextKey(Object k) { return k instanceof String && (CONTEXT_KEYS.contains(k) || TAINT_RE.matcher((String) k).matches()); }
    private static boolean strList(Object v, int mx, Predicate<String> ok) {
        if (!(v instanceof List) || ((List<?>) v).size() > mx) return false;
        for (Object x : (List<?>) v) if (!(x instanceof String) || !ok.test((String) x)) return false;
        return distinct((List<?>) v);
    }
    private static boolean isOne(Object o) { Double d = IntentJs.num(o); return d != null && d == 1.0; }

    // ---- strict JSON profile + ActionDef validation ----------------------------------------------------------------------------

    private static boolean nfc(String s) { return Normalizer.normalize(s, Normalizer.Form.NFC).equals(s); }

    /** Strict JSON profile: plain objects/arrays, NFC strings without lone surrogates, safe integers only, depth &lt;= 32. */
    public static String jsonProfileError(Object v, int depth) {
        if (depth > 32) return "nesting deeper than 32";
        if (v == null || v instanceof Boolean) return null;
        if (v instanceof Json.Num || v instanceof Number) return isInt(v) ? null : "numbers must be safe integers (no floats, no -0)";
        if (v instanceof String) {
            if (Json.hasLoneSurrogate((String) v)) return "string has a lone surrogate";
            return nfc((String) v) ? null : "string is not NFC";
        }
        if (v instanceof List) {
            for (Object x : (List<?>) v) { String e = jsonProfileError(x, depth + 1); if (e != null) return e; }
            return null;
        }
        if (v instanceof Map) {
            for (Map.Entry<String, Object> en : M(v).entrySet()) {
                if (Json.hasLoneSurrogate(en.getKey()) || !nfc(en.getKey())) return "member name is not NFC / has a lone surrogate";
                String e = jsonProfileError(en.getValue(), depth + 1);
                if (e != null) return e;
            }
            return null;
        }
        return "only JSON values are allowed";
    }

    static boolean isRole(Object r) {
        return r instanceof String && (CORE_ROLES.contains(r) || ID_ROLE_RE.matcher((String) r).matches() || CUSTOM_ROLE_RE.matcher((String) r).matches());
    }

    static boolean isFormat(Object f) { return f instanceof String && ActionSchema.formatCheck((String) f) != null; }

    private static final String ANY_SAFE = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._-:/";
    private static boolean inAnySafe(String s) { for (int i = 0; i < s.length(); i++) if (ANY_SAFE.indexOf(s.charAt(i)) < 0) return false; return true; }

    static String idPatternError(Object p) {
        if ("*".equals(p)) return null;
        if (!isMap(p)) return "resource.id must be '*', {exact} or {prefix, class, len}";
        Map<String, Object> m = M(p);
        String keys = sortedKeys(m);
        if (keys.equals("exact")) {
            Object e = m.get("exact");
            return e instanceof String && ((String) e).length() >= 1 && ((String) e).length() <= 128 && inAnySafe((String) e) ? null : "resource.id.exact must be 1..128 safe characters";
        }
        if (!keys.equals("class,len,prefix")) return "resource.id must be '*', {exact} or {prefix, class, len}";
        if (!(m.get("prefix") instanceof String) || S(m.get("prefix")).length() > 32 || !inAnySafe(S(m.get("prefix")))) return "resource.id.prefix must be up to 32 safe characters";
        if (!inS(m.get("class"), ID_CLASSES)) return "resource.id.class is not an id class";
        Object ln = m.get("len");
        if (!(ln instanceof List) || ((List<?>) ln).size() != 2) return "resource.id.len must be [min, max] in 1..128";
        for (Object x : (List<?>) ln) if (!isInt(x) || L(x) < 1 || L(x) > 128) return "resource.id.len must be [min, max] in 1..128";
        long lo = L(A(ln).get(0)), hi = L(A(ln).get(1));
        if (lo > hi) return "resource.id.len: min > max";
        if ("uuid".equals(m.get("class")) && (!"".equals(m.get("prefix")) || lo != 36 || hi != 36)) return "a uuid id has no prefix and length exactly [36, 36]";
        return null;
    }

    static String paramNameError(String name) {
        if (!PARAM_NAME_RE.matcher(name).matches()) return "param name '" + name + "' is malformed";
        for (String seg : name.split("\\.", -1)) if (RESERVED.contains(seg)) return "param name '" + name + "' is reserved";
        return null;
    }

    private static String paramError(String name, Object pO, Set<String> names) {
        if (!isMap(pO)) return name + ": declaration must be an object";
        Map<String, Object> p = M(pO);
        for (String k : p.keySet()) if (!PARAM_KEYS.contains(k)) return name + ": unknown member '" + k + "'";
        if (!inS(p.get("type"), PARAM_TYPES)) return name + ": unknown type";
        String t = S(p.get("type"));
        if (p.containsKey("role") && !isRole(p.get("role"))) return name + ": unknown role";
        if (p.get("role") instanceof String && INT_ROLES.contains(p.get("role")) && !t.equals("integer")) return name + ": role requires an integer parameter";
        if (p.containsKey("required") && !(p.get("required") instanceof Boolean)) return name + ": required must be a boolean";
        if (p.containsKey("values")) {
            Object vs = p.get("values");
            if (!(vs instanceof List) || ((List<?>) vs).isEmpty() || ((List<?>) vs).size() > 256) return name + ": values must be 1..256 non-empty strings";
            for (Object x : (List<?>) vs) if (!isStr(x)) return name + ": values must be 1..256 non-empty strings";
            if (!distinct((List<?>) vs)) return name + ": values must be distinct";
            if (!t.equals("string") && !t.equals("set")) return name + ": values apply to string and set only";
        }
        if (t.equals("set") && !p.containsKey("values")) return name + ": a set needs values";
        boolean intLike = t.equals("integer") || t.equals("duration") || (t.equals("array") && "integer".equals(p.get("items")));
        for (String k : new String[] {"min", "max"}) if (p.containsKey(k) && (!isInt(p.get(k)) || !intLike)) return name + ": " + k + " must be a safe integer on an integer parameter";
        if (isInt(p.get("min")) && isInt(p.get("max")) && L(p.get("min")) > L(p.get("max"))) return name + ": min > max";
        if (p.containsKey("max_len") && (!isInt(p.get("max_len")) || L(p.get("max_len")) < 1 || L(p.get("max_len")) > 16_777_216 || !(t.equals("string") || t.equals("array") || t.equals("object_ref"))))
            return name + ": max_len must be 1..16777216 on a string or array";
        if (p.containsKey("items") && (!t.equals("array") || !isStr(p.get("items"), 64))) return name + ": items applies to array only";
        for (String k : new String[] {"min_items", "max_items"}) if (p.containsKey(k) && (!isNonNeg(p.get(k)) || !(t.equals("set") || t.equals("array")))) return name + ": " + k + " must be a non-negative integer on a set or array";
        if (isInt(p.get("min_items")) && isInt(p.get("max_items")) && L(p.get("min_items")) > L(p.get("max_items"))) return name + ": min_items > max_items";
        if (p.containsKey("format") && (!isFormat(p.get("format")) || !(t.equals("string") || t.equals("object_ref")))) return name + ": format must be a known format on a string parameter";
        if (p.containsKey("unit")) {
            Object uO = p.get("unit");
            if (!t.equals("integer")) return name + ": unit applies to integer parameters only";
            if (!isMap(uO) || !inS(M(uO).get("kind"), UNIT_KINDS)) return name + ": unit.kind is not a known kind";
            Map<String, Object> u = M(uO);
            if (u.get("kind").equals("money")) {
                for (String k : u.keySet()) if (!List.of("kind", "ccy", "exp").contains(k)) return name + ": unit has unknown members";
                if (!isInt(u.get("exp")) || L(u.get("exp")) < 0 || L(u.get("exp")) > 18) return name + ": unit.exp must be an integer in 0..18";
                Object c = u.get("ccy");
                if (c instanceof String) {
                    if (!CCY_RE.matcher((String) c).matches()) return name + ": unit.ccy must be an ISO 4217 style code";
                } else if (!isMap(c) || !String.join(",", M(c).keySet()).equals("from") || !(M(c).get("from") instanceof String) || !names.contains(S(M(c).get("from"))))
                    return name + ": unit.ccy.from must name a declared parameter";
            } else if (!String.join(",", u.keySet()).equals("kind")) return name + ": unit has unknown members";
        }
        if (p.containsKey("tags")) {
            Object tg = p.get("tags");
            if (!(tg instanceof List) || ((List<?>) tg).size() > PARAM_TAGS.size() || !((List<?>) tg).stream().allMatch(x -> inS(x, PARAM_TAGS)) || !distinct((List<?>) tg)) return name + ": tags must be distinct known tags";
        }
        if (p.containsKey("provenance_min") && !inS(p.get("provenance_min"), PROVENANCE_LEVELS)) return name + ": unknown provenance_min";
        if (p.containsKey("sensitivity") && !inS(p.get("sensitivity"), SENSITIVITY)) return name + ": unknown sensitivity";
        if (p.containsKey("accumulates")) {
            Object a = p.get("accumulates");
            if (!t.equals("integer")) return name + ": accumulates applies to integer parameters only";
            boolean ok = a instanceof List && !((List<?>) a).isEmpty() && ((List<?>) a).size() <= 8;
            if (ok) for (Object x : (List<?>) a) if (!(x instanceof String) || ((String) x).length() > 64 || !UNIT_ID_RE.matcher((String) x).matches()) ok = false;
            if (!ok || !distinct((List<?>) a)) return name + ": accumulates must be 1..8 distinct unit ids";
        }
        if (p.containsKey("default") && p.get("default") == null) return name + ": default must not be null (absent = no default)";
        if (p.containsKey("principal_neutral_default") && !(p.get("principal_neutral_default") instanceof Boolean)) return name + ": principal_neutral_default must be a boolean";
        if (Boolean.TRUE.equals(p.get("principal_neutral_default")) && !p.containsKey("default")) return name + ": principal_neutral_default needs a default";
        if (p.containsKey("description") && !isStr(p.get("description"), MAX_DESCRIPTION_BYTES)) return name + ": description must be a string up to " + MAX_DESCRIPTION_BYTES + " bytes";
        return null;
    }

    private static String bindingsError(Object bO) {
        if (!isMap(bO)) return "bindings must be an object";
        Map<String, Object> b = M(bO);
        Map<String, List<List<String>>> shapes = Map.of(
            "mcp", List.of(List.of("tool"), List.of()), "openapi", List.of(List.of("operationId"), List.of("method", "path")),
            "http", List.of(List.of("method", "path"), List.of()), "graphql", List.of(List.of("op", "field"), List.of()),
            "grpc", List.of(List.of("service", "method"), List.of()), "asyncapi", List.of(List.of("channel", "op"), List.of()));
        for (Map.Entry<String, Object> en : b.entrySet()) {
            String k = en.getKey();
            if (!BINDING_KINDS.contains(k)) return "bindings: unknown kind '" + k + "'";
            List<String> req = shapes.get(k).get(0), opt = shapes.get(k).get(1);
            if (!isMap(en.getValue())) return "bindings." + k + " must be an object";
            Map<String, Object> v = M(en.getValue());
            for (String m : v.keySet()) if (!req.contains(m) && !opt.contains(m)) return "bindings." + k + ": unknown member '" + m + "'";
            for (String m : req) if (!isStr(v.get(m), 256)) return "bindings." + k + "." + m + " must be a non-empty string";
            for (String m : opt) if (v.containsKey(m) && !isStr(v.get(m), 256)) return "bindings." + k + "." + m + " must be a non-empty string";
        }
        if (b.containsKey("graphql") && !List.of("query", "mutation", "subscription").contains(M(b.get("graphql")).get("op"))) return "bindings.graphql.op is not a GraphQL operation kind";
        if (b.containsKey("asyncapi") && !List.of("send", "receive").contains(M(b.get("asyncapi")).get("op"))) return "bindings.asyncapi.op must be send or receive";
        return null;
    }

    private static String reviewError(Object rO) {
        if (!isMap(rO)) return "review must be an object";
        Map<String, Object> r = M(rO);
        for (String k : r.keySet()) if (!List.of("state", "attestation", "suggested_by").contains(k)) return "review: unknown member '" + k + "'";
        if (!inS(r.get("state"), REVIEW_STATES)) return "review.state is not a review state";
        if (r.containsKey("attestation")) {
            if (!isMap(r.get("attestation"))) return "review.attestation must be an object";
            Map<String, Object> a = M(r.get("attestation"));
            for (String k : a.keySet()) if (!List.of("def_digest", "traits_digest", "facts_digest", "final_traits", "dismissed", "reviewer_kid", "ts", "sig").contains(k)) return "review.attestation: unknown member '" + k + "'";
            if (!isStr(a.get("def_digest"), 64) || !isStr(a.get("traits_digest"), 64) || !isStr(a.get("facts_digest"), 64) || !isStr(a.get("reviewer_kid"), 128) || !isNonNeg(a.get("ts")))
                return "review.attestation: def_digest, traits_digest, facts_digest, reviewer_kid and ts are required";
            if (!strList(a.get("final_traits"), MAX_DEF_TRAITS, s -> TRAIT_ID_RE.matcher(s).matches())) return "review.attestation.final_traits must be distinct trait ids";
            Object d = a.get("dismissed");
            boolean ok = d instanceof List && ((List<?>) d).size() <= MAX_DEF_TRAITS;
            if (ok) for (Object x : (List<?>) d)
                if (!(isMap(x) && sortedKeys(M(x)).equals("reason,trait") && M(x).get("trait") instanceof String && TRAIT_ID_RE.matcher(S(M(x).get("trait"))).matches() && isStr(M(x).get("reason"), 256))) { ok = false; break; }
            if (!ok) return "review.attestation.dismissed must be {trait, reason} entries";
            if (a.containsKey("sig") && !isStr(a.get("sig"), 4096)) return "review.attestation.sig must be a string";
        }
        return null;
    }

    /** Null if {@code xO} is a well-formed ActionDef (structure only: registry, prules and lint checks are separate). Never throws. */
    public static String validateDef(Object xO) {
        try {
            String je = jsonProfileError(xO, 0);
            if (je != null) return "not strict JSON: " + je;
            if (!isMap(xO)) return "def must be an object";
            Map<String, Object> x = M(xO);
            for (String k : x.keySet()) if (!DEF_KEYS.contains(k)) return "unknown member '" + k + "'";
            if (!isOne(x.get("v"))) return "unsupported def version";
            if (!ACTION_DEF_KIND.equals(x.get("kind"))) return "kind must be '" + ACTION_DEF_KIND + "'";
            Object verb = x.get("verb");
            if (!(verb instanceof String) || !VERB_RE.matcher((String) verb).matches() || IntentJs.u8len((String) verb) > MAX_VERB_BYTES) return "verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)";
            if (x.containsKey("aliases") && (!strList(x.get("aliases"), MAX_DEF_ALIASES, s -> ALIAS_RE.matcher(s).matches() && IntentJs.u8len(s) <= MAX_VERB_BYTES) || A(x.get("aliases")).contains(verb)))
                return "aliases must be distinct verb-shaped names other than the verb";
            if (!isStr(x.get("title"), MAX_TITLE_BYTES)) return "title must be a non-empty string up to " + MAX_TITLE_BYTES + " bytes";
            if (x.containsKey("description") && !isStr(x.get("description"), MAX_DESCRIPTION_BYTES)) return "description must be a string";
            if (!strList(x.get("effects"), EFFECTS.size(), EFFECTS::contains) || A(x.get("effects")).isEmpty()) return "effects must be 1..12 distinct known effects";
            if (!isMap(x.get("resource")) || !sortedKeys(M(x.get("resource"))).equals("id,scope,type")) return "resource must be {type, id, scope}";
            Map<String, Object> r = M(x.get("resource"));
            if (!(r.get("type") instanceof String) || !RESOURCE_TYPE_RE.matcher(S(r.get("type"))).matches() || S(r.get("type")).length() > 128) return "resource.type is malformed";
            String ide = idPatternError(r.get("id"));
            if (ide != null) return ide;
            if (!inS(r.get("scope"), RESOURCE_SCOPES)) return "resource.scope is not a scope";
            if (!isMap(x.get("params"))) return "params must be an object";
            Map<String, Object> params = M(x.get("params"));
            List<String> names = new ArrayList<>(params.keySet());
            if (names.size() > MAX_DEF_PARAMS) return "more than " + MAX_DEF_PARAMS + " parameters";
            Set<String> nameSet = new HashSet<>(names);
            for (String nm : names) {
                String ne = paramNameError(nm);
                if (ne != null) return ne;
                for (String m : names) if (!m.equals(nm) && m.startsWith(nm + ".")) return "param '" + nm + "' is both a value and the parent of '" + m + "'";
            }
            for (String nm : names) { String e = paramError(nm, params.get(nm), nameSet); if (e != null) return e; }
            if (x.containsKey("reversibility")) {
                Object rv = x.get("reversibility");
                if (!(rv instanceof String)) {
                    if (!isMap(rv)) return "reversibility must be a class or {by, map, default?}";
                    Map<String, Object> rm = M(rv);
                    for (String k : rm.keySet()) if (!List.of("by", "map", "default").contains(k)) return "reversibility must be a class or {by, map, default?}";
                    if (!(rm.get("by") instanceof String) || !nameSet.contains(S(rm.get("by")))) return "reversibility.by must name a declared parameter";
                    Object m = rm.get("map");
                    boolean ok = isMap(m) && !M(m).isEmpty() && M(m).size() <= 256;
                    if (ok) for (Map.Entry<String, Object> en : M(m).entrySet()) if (!isStr(en.getKey(), 128) || !inS(en.getValue(), REVERSIBILITY)) { ok = false; break; }
                    if (!ok) return "reversibility.map must map values to reversibility classes";
                    if (rm.containsKey("default") && !inS(rm.get("default"), REVERSIBILITY)) return "reversibility.default is not a class";
                } else if (!REVERSIBILITY.contains(rv)) return "unknown reversibility class";
            }
            if (x.containsKey("blast")) {
                Object bO = x.get("blast");
                if (!isMap(bO)) return "blast must be {radius, ppm?}";
                Map<String, Object> b = M(bO);
                for (String k : b.keySet()) if (!k.equals("radius") && !k.equals("ppm")) return "blast must be {radius, ppm?}";
                if (!inS(b.get("radius"), BLAST_RADII)) return "blast must be {radius, ppm?}";
                if (b.containsKey("ppm") && !(isInt(b.get("ppm")) && L(b.get("ppm")) >= 0 && L(b.get("ppm")) <= PPM_MAX)) return "blast.ppm must be an integer in 0..1000000";
            }
            if (x.containsKey("side_effects")) {
                Object s = x.get("side_effects");
                boolean ok = s instanceof List && ((List<?>) s).size() <= MAX_DEF_SIDE_EFFECTS;
                if (ok) for (Object e : (List<?>) s)
                    if (!(isMap(e) && sortedKeys(M(e)).equals("kind,target") && isStr(M(e).get("target"), 128) && inS(M(e).get("kind"), EFFECTS))) { ok = false; break; }
                if (!ok) return "side_effects must be {target, kind} entries";
            }
            if (x.containsKey("idempotency")) {
                Object iO = x.get("idempotency");
                if (!isMap(iO)) return "idempotency must be {mode, param?}";
                Map<String, Object> i = M(iO);
                for (String k : i.keySet()) if (!k.equals("mode") && !k.equals("param")) return "idempotency must be {mode, param?}";
                if (!inS(i.get("mode"), IDEMPOTENCY_MODES)) return "idempotency must be {mode, param?}";
                boolean bad = i.get("mode").equals("key_param") ? !(i.get("param") instanceof String) || !nameSet.contains(S(i.get("param"))) : i.containsKey("param");
                if (bad) return "idempotency.param is required for key_param (a declared parameter) and forbidden otherwise";
            }
            if (x.containsKey("context") && !strList(x.get("context"), MAX_DEF_CONTEXT, Actions::isContextKey)) return "context must be distinct known context keys";
            if (x.containsKey("traits") && !strList(x.get("traits"), MAX_DEF_TRAITS, s -> TRAIT_ID_RE.matcher(s).matches())) return "traits must be distinct trait ids";
            if (x.containsKey("audience") && !"resource".equals(x.get("audience"))) return "audience must be 'resource'";
            if (x.containsKey("compensates") && (!(x.get("compensates") instanceof String) || !VERB_RE.matcher(S(x.get("compensates"))).matches())) return "compensates must be a verb";
            if (x.containsKey("bindings")) { String be = bindingsError(x.get("bindings")); if (be != null) return be; }
            if (x.containsKey("examples")) {
                Object ex = x.get("examples");
                if (!(ex instanceof List) || ((List<?>) ex).size() > 32) return "examples must be an array of up to 32 entries";
                for (Object eO : (List<?>) ex) {
                    boolean ok = isMap(eO);
                    if (ok) {
                        Map<String, Object> e = M(eO);
                        for (String k : e.keySet()) if (!List.of("params", "under", "expect").contains(k)) ok = false;
                        ok = ok && isMap(e.get("params")) && List.of("allow", "escalate", "deny").contains(e.get("expect"));
                    }
                    if (!ok) return "example must be {params, under?, expect}";
                }
            }
            String re = reviewError(x.get("review"));
            if (re != null) return re;
            if (x.containsKey("source")) {
                Object sO = x.get("source");
                boolean ok = isMap(sO);
                if (ok) {
                    Map<String, Object> s = M(sO);
                    for (String k : s.keySet()) if (!List.of("kind", "uri", "spec_digest", "licence", "imported_at").contains(k)) ok = false;
                    ok = ok && isStr(s.get("kind"), 64) && isStr(s.get("uri"), 2048) && isStr(s.get("spec_digest"), 128) && isStr(s.get("licence"), 128) && (!s.containsKey("imported_at") || isNonNeg(s.get("imported_at")));
                }
                if (!ok) return "source must be {kind, uri, spec_digest, licence, imported_at?}";
            }
            if (x.containsKey("since") && !isStr(x.get("since"), 64)) return "since must be a string";
            return null;
        } catch (RuntimeException e) {
            return "malformed def: " + e;
        }
    }

    // ---- profile lattice + trait registry --------------------------------------------------------------------------------------

    static int revRank(String r) { return REVERSIBILITY.indexOf(r); }

    /** A restriction profile (risk 0..3, reversibility, blast ppm, escalation tier 0..3, sorted distinct caveat / context / prule sets). */
    public static final class Profile {
        public final int risk, blastPpm, esc;
        public final String rev;
        public final List<String> caveats, context, prules;

        Profile(int risk, String rev, int blastPpm, int esc, Collection<String> caveats, Collection<String> context, Collection<String> prules) {
            this.risk = risk; this.rev = rev; this.blastPpm = blastPpm; this.esc = esc;
            this.caveats = new ArrayList<>(new TreeSet<>(caveats)); this.context = new ArrayList<>(new TreeSet<>(context)); this.prules = new ArrayList<>(new TreeSet<>(prules));
        }

        public static final Profile BOTTOM = new Profile(0, "reversible", 0, 0, List.of(), List.of(), List.of());

        /** From a well-formed profile map (see {@link Actions#profileError}); throws if a member is missing or mistyped. */
        @SuppressWarnings("unchecked")
        static Profile fromMap(Object o) {
            Map<String, Object> m = M(o);
            return new Profile((int) L(req(m, "risk")), S(req(m, "rev")), (int) L(req(m, "blast_ppm")), (int) L(req(m, "esc")),
                (List<String>) (Object) A(req(m, "caveats")), (List<String>) (Object) A(req(m, "context")), (List<String>) (Object) A(req(m, "prules")));
        }

        private static Object req(Map<String, Object> m, String k) {
            Object v = m.get(k);
            if (v == null) throw new IllegalArgumentException("profile member missing: " + k);
            return v;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("risk", n(risk)); m.put("rev", rev); m.put("blast_ppm", n(blastPpm)); m.put("esc", n(esc));
            m.put("caveats", toObjs(caveats)); m.put("context", toObjs(context)); m.put("prules", toObjs(prules));
            return m;
        }

        Profile join(Profile q) {
            List<String> c = new ArrayList<>(caveats), x = new ArrayList<>(context), r = new ArrayList<>(prules);
            c.addAll(q.caveats); x.addAll(q.context); r.addAll(q.prules);
            return new Profile(Math.max(risk, q.risk), revRank(rev) >= revRank(q.rev) ? rev : q.rev, Math.max(blastPpm, q.blastPpm), Math.max(esc, q.esc), c, x, r);
        }

        boolean leq(Profile q) {
            return risk <= q.risk && revRank(rev) <= revRank(q.rev) && blastPpm <= q.blastPpm && esc <= q.esc
                && q.caveats.containsAll(caveats) && q.context.containsAll(context) && q.prules.containsAll(prules);
        }
    }

    private static boolean intIn(Object x, int lo, int hi) { return isInt(x) && L(x) >= lo && L(x) <= hi; }

    static String profileError(Object pO) {
        if (!isMap(pO)) return "profile must be an object";
        Map<String, Object> p = M(pO);
        for (String k : p.keySet()) if (!List.of("risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules").contains(k)) return "profile: unknown member '" + k + "'";
        if (!intIn(p.get("risk"), 0, 3)) return "profile.risk must be an integer in 0..3";
        if (!inS(p.get("rev"), REVERSIBILITY)) return "profile.rev is not a reversibility class";
        if (!intIn(p.get("blast_ppm"), 0, PPM_MAX)) return "profile.blast_ppm must be an integer in 0..1000000";
        if (!intIn(p.get("esc"), 0, 3)) return "profile.esc must be an integer in 0..3";
        for (String name : new String[] {"caveats", "context", "prules"}) {
            Object a = p.get(name);
            boolean ok = a instanceof List && ((List<?>) a).size() <= 64;
            if (ok) for (Object x : (List<?>) a) {
                boolean known = name.equals("caveats") ? inS(x, CAVEAT_KINDS) : name.equals("context") ? isContextKey(x) : inS(x, PARAM_RULE_IDS);
                if (!known) { ok = false; break; }
            }
            if (!ok) return "profile." + name + " must be an array of known " + name + " entries";
            List<Object> l = A(a);
            for (int i = 1; i < l.size(); i++) if (S(l.get(i - 1)).compareTo(S(l.get(i))) >= 0) return "profile." + name + " must be sorted and distinct";
        }
        return null;
    }

    /** A trait of a registry. */
    public static final class Trait {
        public final String id, cardPhrase;
        public final List<String> implies;
        public final Profile floor;
        Trait(String id, List<String> implies, Profile floor, String cardPhrase) { this.id = id; this.implies = implies; this.floor = floor; this.cardPhrase = cardPhrase; }
        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id); m.put("implies", toObjs(implies)); m.put("floor", floor.toMap()); m.put("card_phrase", cardPhrase);
            return m;
        }
    }

    /** A validated trait registry (id to trait). */
    public static final class Registry {
        public final Map<String, Trait> traits;
        Registry(Map<String, Trait> traits) { this.traits = traits; }
    }

    /** Null if the trait definition maps form a valid registry, else the first reason (T5: a trait only extends what it implies; no cycle; depth &lt;= 8). */
    public static String registryError(Object defsO, boolean core) {
        if (!(defsO instanceof List) || ((List<?>) defsO).size() > MAX_REGISTRY_TRAITS) return "a registry holds at most " + MAX_REGISTRY_TRAITS + " traits";
        Map<String, Map<String, Object>> by = new LinkedHashMap<>();
        for (Object tO : (List<?>) defsO) {
            if (!isMap(tO)) return "trait must be an object";
            Map<String, Object> t = M(tO);
            Object id = t.get("id");
            if (!(id instanceof String) || !TRAIT_ID_RE.matcher((String) id).matches()) return "trait id '" + id + "' is malformed";
            if (S(id).startsWith("pca.") && !core) return "trait '" + id + "': the pca. namespace is reserved for core traits";
            if (by.containsKey(id)) return "trait '" + id + "' is defined twice";
            Object im = t.get("implies");
            if (!(im instanceof List) || ((List<?>) im).size() > 8 || !isStrings(im) || !distinct((List<?>) im)) return "trait '" + id + "': implies must be up to 8 distinct trait ids";
            String pe = profileError(t.get("floor"));
            if (pe != null) return "trait '" + id + "': " + pe;
            Object cp = t.get("card_phrase");
            if (!(cp instanceof String) || ((String) cp).length() == 0 || ((String) cp).length() > 120) return "trait '" + id + "': card_phrase must be a non-empty string up to 120 characters";
            by.put(S(id), t);
        }
        for (Map<String, Object> t : by.values()) {
            for (Object u : A(t.get("implies"))) {
                Map<String, Object> ud = by.get(u);
                if (ud == null) return "trait '" + t.get("id") + "' implies unknown trait '" + u + "'";
                if (!Profile.fromMap(ud.get("floor")).leq(Profile.fromMap(t.get("floor")))) return "trait '" + t.get("id") + "': floor is below the floor of implied '" + u + "'";
            }
        }
        Map<String, Integer> depth = new LinkedHashMap<>();
        Set<String> visiting = new HashSet<>();
        for (String id : by.keySet()) {
            int d = walk(by, id, depth, visiting);
            if (d < 0) return "trait '" + id + "': implies cycle";
            if (d > MAX_TRAIT_IMPLIES_DEPTH) return "trait '" + id + "': implies depth " + d + " exceeds " + MAX_TRAIT_IMPLIES_DEPTH;
        }
        return null;
    }

    private static int walk(Map<String, Map<String, Object>> by, String id, Map<String, Integer> depth, Set<String> visiting) {
        Integer known = depth.get(id);
        if (known != null) return known;
        if (!visiting.add(id)) return -1;
        int d = 1;
        for (Object u : A(by.get(id).get("implies"))) {
            int du = walk(by, S(u), depth, visiting);
            if (du < 0) return -1;
            d = Math.max(d, du + 1);
        }
        visiting.remove(id);
        depth.put(id, d);
        return d;
    }

    /** Build a registry from trait definition maps; throws {@code bad_registry}. */
    public static Registry buildRegistry(List<Object> defs, boolean core) {
        String e = registryError(defs, core);
        if (e != null) throw new ActionKitError("bad_registry", e);
        Map<String, Trait> m = new LinkedHashMap<>();
        for (Object tO : defs) {
            Map<String, Object> t = M(tO);
            List<String> im = new ArrayList<>();
            for (Object u : A(t.get("implies"))) im.add(S(u));
            m.put(S(t.get("id")), new Trait(S(t.get("id")), im, Profile.fromMap(t.get("floor")), S(t.get("card_phrase"))));
        }
        return new Registry(m);
    }

    /** Core registry extended with custom traits (which may not use {@code pca.} and must extend what they imply). */
    public static Registry extendRegistry(Registry base, List<Object> custom) {
        List<Object> all = new ArrayList<>();
        for (Trait t : base.traits.values()) all.add(t.toMap());
        for (Object c : custom) {
            if (!isMap(c) || !(M(c).get("id") instanceof String) || base.traits.containsKey(M(c).get("id")) || S(M(c).get("id")).startsWith("pca."))
                throw new ActionKitError("bad_registry", "custom trait may not redefine a core trait");
            all.add(c);
        }
        return buildRegistry(all, true);
    }

    /** cl(S): the closure of a set of trait ids under implies, sorted. Throws {@code unknown_trait}. */
    public static List<String> closure(Registry reg, List<?> ids) {
        Set<String> seen = new TreeSet<>();
        java.util.ArrayDeque<Object> stack = new java.util.ArrayDeque<>(ids);
        while (!stack.isEmpty()) {
            Object id = stack.pop();
            if (id instanceof String && seen.contains(id)) continue;
            Trait t = id instanceof String ? reg.traits.get(id) : null;
            if (t == null) throw new ActionKitError("unknown_trait", "unknown trait '" + id + "'");
            seen.add(t.id);
            stack.addAll(t.implies);
        }
        return new ArrayList<>(seen);
    }

    /** F(S): the join of the floors of the closure of S (empty = bottom). */
    public static Profile floorOf(Registry reg, List<?> ids) {
        Profile p = Profile.BOTTOM;
        for (String id : closure(reg, ids)) p = p.join(reg.traits.get(id).floor);
        return p;
    }

    /** FloorDecision(G, call, rho): deny if rho.esc &gt; G.max_esc; escalate if a caveat / context key is missing or rho.esc &gt; G.preauth_esc; else allow. */
    public static String floorDecision(Map<String, Object> grant, Map<String, Object> call, Profile rho) {
        if (rho.esc > L(grant.get("max_esc"))) return "deny";
        if (!A(grant.get("caveats")).containsAll(rho.caveats) || !A(call.get("context")).containsAll(rho.context) || rho.esc > L(grant.get("preauth_esc"))) return "escalate";
        return "allow";
    }

    private static Profile prof(int risk, String rev, int blast, int esc, String[] cav, String[] ctx, String[] pr) {
        return new Profile(risk, rev, blast, esc, List.of(cav), List.of(ctx), List.of(pr));
    }
    private static final String[] NONE = {};
    private static String[] a(String... s) { return s; }

    // [id, implies, own floor, card phrase] - the 22 core traits, in table order
    private static final Object[][] TABLE = {
        {"money_moving", NONE, prof(3, "rate_limited", 700_000, 2, a("amount_cap", "count_cap", "window"), a("idempotency"), a("money_has_currency", "money_amount_bounded", "pay_has_idempotency")), "moves money"},
        {"destructive", NONE, prof(2, "rate_limited", 0, 1, a("resource_scope"), NONE, a("id_not_wildcard")), "deletes or destroys data"},
        {"irreversible", NONE, prof(2, "irreversible", 0, 1, NONE, a("fresh_revocation"), NONE), "cannot be undone"},
        {"external_communication", NONE, prof(2, "irreversible", 0, 0, a("recipient_scope", "rate_cap"), NONE, a("recipient_param_declared")), "sends to people outside your organisation"},
        {"data_export", NONE, prof(2, "reversible", 0, 0, a("resource_scope", "count_cap"), NONE, a("export_bounded")), "exports data"},
        {"privilege_change", NONE, prof(3, "reversible", 0, 3, a("resource_scope", "short_expiry"), NONE, NONE), "changes who can do what"},
        {"code_execution", NONE, prof(3, "irreversible", 0, 2, a("resource_scope"), a("sandbox_attested"), NONE), "runs code or commands"},
        {"credential_access", NONE, prof(3, "reversible", 0, 3, NONE, NONE, a("secret_not_logged")), "reads or handles credentials"},
        {"bulk", NONE, prof(2, "reversible", 0, 0, a("count_cap"), NONE, a("array_bounded")), "acts on many items at once"},
        {"pii_access", NONE, prof(1, "reversible", 0, 0, a("resource_scope"), NONE, NONE), "touches personal data"},
        {"public_exposure", NONE, prof(2, "irreversible", 0, 1, NONE, NONE, NONE), "makes content public"},
        {"persistence", NONE, prof(2, "reversible", 0, 0, a("short_expiry"), a("revocable"), NONE), "creates standing access or infrastructure"},
        {"infra_mutation", NONE, prof(2, "rate_limited", 0, 0, a("resource_scope"), NONE, NONE), "changes infrastructure"},
        {"cost_incurring", NONE, prof(1, "reversible", 0, 0, a("amount_cap"), NONE, NONE), "incurs cost"},
        {"legal_binding", NONE, prof(3, "irreversible", 0, 3, NONE, NONE, NONE), "legally or cryptographically binds you"},
        {"impersonation", a("external_communication"), prof(2, "reversible", 0, 1, NONE, NONE, NONE), "acts as a person"},
        {"network_egress", NONE, prof(1, "reversible", 0, 0, a("recipient_scope"), NONE, NONE), "reaches out to the network"},
        {"financial_data_read", NONE, prof(1, "reversible", 0, 0, a("resource_scope"), NONE, NONE), "reads financial data"},
        {"regulated_data", NONE, prof(2, "reversible", 0, 1, NONE, NONE, NONE), "handles regulated data"},
        {"scheduled", NONE, prof(2, "reversible", 0, 0, a("short_expiry", "count_cap"), NONE, NONE), "runs later or repeatedly"},
        {"unreviewed", NONE, prof(3, "irreversible", 1_000_000, 2, a("approval_ref", "resource_scope"), a("dry_run_first"), NONE), "has not been reviewed yet"},
        {"agent_spawning", NONE, prof(2, "reversible", 0, 0, a("count_cap"), NONE, NONE), "starts another agent"},
    };

    public static final Registry CORE_REGISTRY = coreRegistry();

    private static Registry coreRegistry() {
        Map<String, Profile> floors = new LinkedHashMap<>();
        List<Object> defs = new ArrayList<>();
        for (Object[] row : TABLE) {
            String id = "pca." + row[0];
            Profile fl = (Profile) row[2];
            List<String> imp = new ArrayList<>();
            for (String u : (String[]) row[1]) { imp.add("pca." + u); fl = fl.join(floors.get("pca." + u)); }
            floors.put(id, fl);
            defs.add(new Trait(id, imp, fl, (String) row[3]).toMap());
        }
        return buildRegistry(defs, true);
    }

    static final Map<String, List<String>> EFFECT_TRAITS = new LinkedHashMap<>();
    static final Map<String, List<String>> TAG_TRAITS = new LinkedHashMap<>();
    static final Map<String, List<String>> ROLE_TRAITS = new LinkedHashMap<>();
    static final Map<String, String> ROLE_SENSITIVITY_FLOOR = new LinkedHashMap<>();
    static final Map<String, String> TAG_SENSITIVITY_FLOOR = new LinkedHashMap<>();
    static {
        String[][] e = {{"read"}, {"create"}, {"update"}, {"delete", "destructive"}, {"send", "external_communication"}, {"pay", "money_moving"}, {"exec", "code_execution"},
            {"privilege", "privilege_change"}, {"export", "data_export"}, {"publish", "public_exposure"}, {"provision", "persistence", "scheduled"}, {"sign", "legal_binding"}};
        for (String[] r : e) { List<String> l = new ArrayList<>(); for (int i = 1; i < r.length; i++) l.add("pca." + r[i]); EFFECT_TRAITS.put(r[0], l); }
        TAG_TRAITS.put("pii", List.of("pca.pii_access")); TAG_TRAITS.put("phi", List.of("pca.pii_access", "pca.regulated_data")); TAG_TRAITS.put("pci", List.of("pca.regulated_data"));
        TAG_TRAITS.put("secret", List.of("pca.credential_access")); TAG_TRAITS.put("credential", List.of("pca.credential_access"));
        for (String r : List.of("credential.secret", "credential.token", "credential.key")) ROLE_TRAITS.put(r, List.of("pca.credential_access"));
        ROLE_TRAITS.put("url.target", List.of("pca.network_egress"));
        String[][] rs = {{"money.amount", "critical"}, {"money.currency", "material"}, {"money.fee", "material"}, {"party.payee", "critical"}, {"party.payer", "material"},
            {"contact.email", "material"}, {"contact.phone", "material"}, {"contact.address", "material"}, {"person.name", "material"}, {"person.dob", "material"},
            {"person.national_id", "critical"}, {"credential.secret", "critical"}, {"credential.token", "critical"}, {"credential.key", "critical"},
            {"code.command", "critical"}, {"query.sql", "critical"}, {"text.message", "material"}};
        for (String[] r : rs) ROLE_SENSITIVITY_FLOOR.put(r[0], r[1]);
        String[][] ts = {{"pii", "material"}, {"phi", "material"}, {"pci", "material"}, {"secret", "critical"}, {"credential", "critical"},
            {"free_text_outbound", "material"}, {"code", "material"}, {"path", "material"}, {"sql", "material"}};
        for (String[] r : ts) TAG_SENSITIVITY_FLOOR.put(r[0], r[1]);
    }

    /** Digest of a trait registry (sorted by id): what a pack pins as {@code traits_digest}. */
    public static String traitsDigest(Registry reg) {
        List<Object> ts = new ArrayList<>();
        for (String id : new TreeSet<>(reg.traits.keySet())) {
            Trait t = reg.traits.get(id);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", t.id); m.put("implies", toObjs(new TreeSet<>(t.implies))); m.put("floor", t.floor.toMap()); m.put("card_phrase", t.cardPhrase);
            ts.add(m);
        }
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("d", TRAITS_DIGEST_DOMAIN); d.put("traits", ts);
        return Pca.hashCanonical(d);
    }

    private static Map<String, Object> listMap(Map<String, List<String>> m) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : m.entrySet()) o.put(e.getKey(), toObjs(e.getValue()));
        return o;
    }

    public static String tablesDigest() {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("d", ROLES_DIGEST_DOMAIN); d.put("roles", toObjs(CORE_ROLES)); d.put("effect_traits", listMap(EFFECT_TRAITS)); d.put("role_traits", listMap(ROLE_TRAITS));
        d.put("tag_traits", listMap(TAG_TRAITS)); d.put("role_sensitivity", new LinkedHashMap<String, Object>(ROLE_SENSITIVITY_FLOOR)); d.put("tag_sensitivity", new LinkedHashMap<String, Object>(TAG_SENSITIVITY_FLOOR));
        return Pca.hashCanonical(d);
    }

    // ---- normalize + digest ----------------------------------------------------------------------------------------------------

    static boolean isReadOnly(List<?> effects) { return !effects.isEmpty() && effects.stream().allMatch("read"::equals); }

    private static String maxSens(String a, String b) { return SENSITIVITY.indexOf(a) >= SENSITIVITY.indexOf(b) ? a : b; }

    static String sensitivityFloor(Map<String, Object> p) {
        String f = "free";
        if (p.get("role") instanceof String && ROLE_SENSITIVITY_FLOOR.containsKey(p.get("role"))) f = maxSens(f, ROLE_SENSITIVITY_FLOOR.get(p.get("role")));
        if (p.get("tags") instanceof List) for (Object t : A(p.get("tags"))) if (TAG_SENSITIVITY_FLOOR.containsKey(t)) f = maxSens(f, TAG_SENSITIVITY_FLOOR.get(t));
        return f;
    }

    static String effectiveParamSensitivity(Map<String, Object> p) { return maxSens(p.containsKey("sensitivity") ? S(p.get("sensitivity")) : "free", sensitivityFloor(p)); }

    private static Object declaredReversibility(Map<String, Object> d) {
        return d.containsKey("reversibility") ? d.get("reversibility") : (isReadOnly(A(d.get("effects"))) ? "reversible" : "irreversible");
    }

    private static String maxRev(List<Object> xs) {
        String out = "reversible";
        for (Object b : xs) if (b instanceof String && revRank((String) b) > revRank(out)) out = (String) b;
        return out;
    }

    /** Conservative class of a (possibly value-dependent) reversibility declaration: the worst class any call can have. */
    static String worstReversibility(Object r, Map<String, Object> params) {
        if (r instanceof String) return (String) r;
        Map<String, Object> rm = M(r);
        Object d = params.get(S(rm.get("by")));
        List<Object> mapped = new ArrayList<>(M(rm.get("map")).values());
        List<?> domain = null;
        if (isMap(d)) {
            if ("boolean".equals(M(d).get("type"))) domain = List.of("true", "false");
            else if ("string".equals(M(d).get("type")) && M(d).get("values") != null) domain = A(M(d).get("values"));
        }
        boolean covered = domain != null && domain.stream().allMatch(x -> M(rm.get("map")).containsKey(x));
        if (!covered) mapped.add(rm.containsKey("default") ? rm.get("default") : "irreversible");
        return maxRev(mapped);
    }

    private static Object jsonCopy(Object v) {
        if (v instanceof Map) { Map<String, Object> o = new LinkedHashMap<>(); for (Map.Entry<String, Object> e : M(v).entrySet()) o.put(e.getKey(), jsonCopy(e.getValue())); return o; }
        if (v instanceof List) { List<Object> o = new ArrayList<>(); for (Object x : (List<?>) v) o.add(jsonCopy(x)); return o; }
        return v;
    }

    private static Map<String, Object> normalizeParam(Map<String, Object> p) {
        Map<String, Object> out = new LinkedHashMap<>(p);
        out.put("required", p.containsKey("required") ? p.get("required") : Boolean.TRUE);
        if (p.containsKey("tags")) out.put("tags", toObjs(sortUniq(p.get("tags"))));
        if (p.containsKey("values")) out.put("values", new ArrayList<>(A(p.get("values"))));
        out.put("sensitivity", effectiveParamSensitivity(p));
        Object u = p.get("unit");
        if (p.containsKey("accumulates")) out.put("accumulates", toObjs(sortUniq(p.get("accumulates"))));
        else if ("money.amount".equals(p.get("role")) && isMap(u) && "money".equals(M(u).get("kind")) && M(u).get("ccy") instanceof String)
            out.put("accumulates", List.<Object>of("money." + S(M(u).get("ccy")).toLowerCase(Locale.ROOT)));
        return out;
    }

    /** The authoring-independent form of a def (assumes {@link #validateDef} passed). */
    public static Map<String, Object> normalize(Map<String, Object> d) {
        Object rev = declaredReversibility(d);
        Map<String, Object> res = M(d.get("resource"));
        String radius = d.containsKey("blast") ? S(M(d.get("blast")).get("radius")) : SCOPE_BLAST.get(S(res.get("scope")));
        Map<String, Object> params = new LinkedHashMap<>();
        for (String k : new TreeSet<>(M(d.get("params")).keySet())) params.put(k, normalizeParam(M(M(d.get("params")).get(k))));
        Object nrev;
        if (rev instanceof String) nrev = rev;
        else {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("by", M(rev).get("by")); m.put("map", new LinkedHashMap<>(M(M(rev).get("map"))));
            if (M(rev).containsKey("default")) m.put("default", M(rev).get("default"));
            nrev = m;
        }
        Map<String, Object> idem = new LinkedHashMap<>();
        Map<String, Object> di = d.containsKey("idempotency") ? M(d.get("idempotency")) : null;
        idem.put("mode", di != null ? di.get("mode") : "none");
        if (di != null && di.containsKey("param")) idem.put("param", di.get("param"));
        List<Map<String, Object>> se = new ArrayList<>();
        if (d.containsKey("side_effects")) for (Object s : A(d.get("side_effects"))) { Map<String, Object> m = new LinkedHashMap<>(); m.put("target", M(s).get("target")); m.put("kind", M(s).get("kind")); se.add(m); }
        se.sort((x, y) -> S(x.get("target")).equals(S(y.get("target"))) ? S(x.get("kind")).compareTo(S(y.get("kind"))) : S(x.get("target")).compareTo(S(y.get("target"))));
        long bppm = d.containsKey("blast") && M(d.get("blast")).containsKey("ppm") ? L(M(d.get("blast")).get("ppm")) : 0;
        Map<String, Object> blast = new LinkedHashMap<>();
        blast.put("radius", radius); blast.put("ppm", n(Math.max(BLAST_PPM.get(radius), bppm)));
        Map<String, Object> rs = new LinkedHashMap<>();
        rs.put("type", res.get("type")); rs.put("id", res.get("id")); rs.put("scope", res.get("scope"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("v", n(1)); out.put("kind", d.get("kind")); out.put("verb", d.get("verb")); out.put("aliases", toObjs(sortUniq(d.get("aliases")))); out.put("title", d.get("title"));
        out.put("effects", toObjs(sortUniq(d.get("effects")))); out.put("resource", rs); out.put("params", params); out.put("reversibility", nrev); out.put("blast", blast);
        out.put("side_effects", new ArrayList<Object>(se)); out.put("idempotency", idem); out.put("context", toObjs(sortUniq(d.get("context")))); out.put("traits", toObjs(sortUniq(d.get("traits"))));
        out.put("bindings", d.containsKey("bindings") ? jsonCopy(d.get("bindings")) : new LinkedHashMap<String, Object>());
        if (d.containsKey("description")) out.put("description", d.get("description"));
        if (d.containsKey("audience")) out.put("audience", d.get("audience"));
        if (d.containsKey("compensates")) out.put("compensates", d.get("compensates"));
        return out;
    }

    /** b64u(sha256(strictCanonical({d, def: normalize(def)}))). Review state, examples, source and since do not enter it. */
    public static String defDigest(Map<String, Object> d) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", DEF_DIGEST_DOMAIN); m.put("def", normalize(d));
        return Pca.hashCanonical(m);
    }

    // ---- pack Merkle root + inclusion proof ------------------------------------------------------------------------------------

    private static Map<String, Object> leaf(String digest) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", PACK_DIGEST_DOMAIN); m.put("def", digest);
        return m;
    }

    private static List<String> sortedDigests(List<String> digests) {
        List<String> s = new ArrayList<>(new TreeSet<>(digests));
        if (s.size() != digests.size()) throw new ActionKitError("duplicate_def", "a pack lists a def digest twice");
        if (s.isEmpty()) throw new ActionKitError("empty_pack", "a pack has at least one def");
        return s;
    }

    public static Map<String, Object> packLeaf(String digest) { return leaf(digest); }

    public static String packRoot(List<String> digests) {
        List<Object> ls = new ArrayList<>();
        for (String s : sortedDigests(digests)) ls.add(leaf(s));
        return Pca.merkleRoot(ls);
    }

    /** RFC 6962 inclusion proof of {@code digest} in the pack made of {@code digests}: {index, size, path: [{side, hash}]} bottom-up. */
    public static Map<String, Object> packProof(List<String> digests, String digest) {
        List<String> s = sortedDigests(digests);
        int i = s.indexOf(digest);
        if (i < 0) throw new ActionKitError("not_in_pack", "the digest is not in the pack");
        List<byte[]> seg = new ArrayList<>();
        for (String x : s) seg.add(Pca.leafHash(leaf(x)));
        List<Object> path = new ArrayList<>();
        int idx = i;
        while (seg.size() > 1) {
            int k = Pca.split(seg.size());
            Map<String, Object> step = new LinkedHashMap<>();
            if (idx < k) { step.put("side", "R"); step.put("hash", Pca.b64(Pca.build(seg.subList(k, seg.size())))); seg = new ArrayList<>(seg.subList(0, k)); }
            else { step.put("side", "L"); step.put("hash", Pca.b64(Pca.build(seg.subList(0, k)))); seg = new ArrayList<>(seg.subList(k, seg.size())); idx -= k; }
            path.add(step);
        }
        Collections.reverse(path);
        Map<String, Object> proof = new LinkedHashMap<>();
        proof.put("index", n(i)); proof.put("size", n(s.size())); proof.put("path", path);
        return proof;
    }

    /** Does {@code proof} show {@code digest} is in the pack with root {@code root}? */
    public static boolean verifyPackProof(String root, Map<String, Object> proof, String digest) { return Pca.verifyInclusion(root, proof, leaf(digest)); }

    // ---- T(d), decl(d), eff(d) ---------------------------------------------------------------------------------------------------

    /** Traits implied by effects, roles, tags, scope and reversibility. Throws on an unknown effect (callers treat it as a forged document). */
    static List<String> impliedFromFacts(List<?> effects, List<Map<String, Object>> params, String scope, String worstRev) {
        List<String> out = new ArrayList<>();
        for (Object e : effects) {
            List<String> l = EFFECT_TRAITS.get(e);
            if (l == null) throw new IllegalArgumentException("unknown effect " + e);
            out.addAll(l);
        }
        boolean ro = isReadOnly(effects);
        for (Map<String, Object> p : params) {
            Object r = p.get("role");
            if (r instanceof String) {
                if (ROLE_TRAITS.containsKey(r)) out.addAll(ROLE_TRAITS.get(r));
                if (ro && ((String) r).startsWith("money.")) out.add("pca.financial_data_read");
            }
            if (p.get("tags") instanceof List) for (Object t : A(p.get("tags"))) if (TAG_TRAITS.containsKey(t)) out.addAll(TAG_TRAITS.get(t));
            if ("array".equals(p.get("type")) && p.get("max_items") == null) out.add("pca.bulk");
        }
        if (scope != null && !scope.equals("one")) out.add("pca.bulk");
        if ("irreversible".equals(worstRev)) out.add("pca.irreversible");
        return new ArrayList<>(new TreeSet<>(out));
    }

    /** The machine/author view of a def's traits: declared plus implied by its own facts. A hint, never enforcement unless a signed confirmation says so. */
    static List<String> hintTraits(Map<String, Object> d) {
        Map<String, Object> nd = normalize(d);
        List<Map<String, Object>> ps = new ArrayList<>();
        for (Object p : M(nd.get("params")).values()) ps.add(M(p));
        List<String> ids = new ArrayList<>(sortUniq(nd.get("traits")));
        ids.addAll(impliedFromFacts(A(nd.get("effects")), ps, S(M(nd.get("resource")).get("scope")), worstReversibility(nd.get("reversibility"), M(nd.get("params")))));
        return new ArrayList<>(new TreeSet<>(ids));
    }

    /** Every trait id of the registry: the effective trait set of anything without a valid signed confirmation. */
    public static List<String> topTraits(Registry reg) { return new ArrayList<>(new TreeSet<>(reg.traits.keySet())); }

    /**
     * T(d): "unconfirmed means maximally dangerous". Without a valid confirmation signed by a pinned reviewer key it is {@link #topTraits}; with one it is
     * the declared plus implied traits.
     */
    public static List<String> traitsOf(Map<String, Object> d, Registry reg, Map<String, Object> pins) {
        return isConfirmed(d, reg, pins) ? hintTraits(d) : topTraits(reg);
    }

    public static Profile declProfile(Map<String, Object> d) {
        Map<String, Object> nd = normalize(d);
        boolean critical = false;
        for (Object p : M(nd.get("params")).values()) if (SENSITIVITY.indexOf(effectiveParamSensitivity(M(p))) >= SENSITIVITY.indexOf("critical")) critical = true;
        return new Profile(critical ? 2 : (isReadOnly(A(nd.get("effects"))) ? 0 : 1), worstReversibility(nd.get("reversibility"), M(nd.get("params"))),
            (int) L(M(nd.get("blast")).get("ppm")), 0, List.of(), (List<String>) (Object) A(nd.get("context")), List.of());
    }

    public static Map<String, Object> effective(Map<String, Object> d, Registry reg) { return effective(d, reg, null); }

    /** {confirmed, traits, closure, floor, decl, eff}: eff = decl join F(T(d)); an unconfirmed def has every trait. */
    public static Map<String, Object> effective(Map<String, Object> d, Registry reg, Map<String, Object> pins) {
        boolean confirmed = isConfirmed(d, reg, pins);
        List<String> tr = confirmed ? hintTraits(d) : topTraits(reg);
        Profile fl = floorOf(reg, tr), dp = declProfile(d);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("confirmed", confirmed); m.put("traits", toObjs(tr)); m.put("closure", toObjs(closure(reg, tr))); m.put("floor", fl.toMap()); m.put("decl", dp.toMap()); m.put("eff", dp.join(fl).toMap());
        return m;
    }

    // ---- the signed human confirmation ---------------------------------------------------------------------------------------------

    public static final String REVIEW_DOMAIN = "atlas-pca/action-review/v2\0";
    private static final List<String> KEY_ROLES = List.of("reviewer", "importer", "model", "publisher");

    /** Null if the pin set {@code {keys, traits_digests?}} is sound: distinct kids, canonical keys, known roles, no key that is both a reviewer and a machine. */
    public static String reviewerPinsError(Object pO) {
        if (!(pO instanceof Map) || !(M(pO).get("keys") instanceof List)) return "pins must be {keys: [...]}";
        Set<String> kids = new HashSet<>(), machinePks = new HashSet<>();
        List<Object> keys = A(M(pO).get("keys"));
        for (Object ko : keys) {
            if (!(ko instanceof Map) || !(M(ko).get("kid") instanceof String)) return "a pinned key needs a kid";
            Map<String, Object> k = M(ko);
            String kid = S(k.get("kid"));
            if (kid.isEmpty() || kid.length() > 128) return "a pinned key needs a kid";
            if (!kids.add(kid)) return "kid '" + kid + "' is pinned twice";
            if (Pca.decodeB64uStrict(k.get("pk"), 32) == null) return "key '" + kid + "': pk is not canonical base64url (32 bytes)";
            Object ro = k.get("roles");
            if (!(ro instanceof List) || ((List<?>) ro).isEmpty() || !KEY_ROLES.containsAll(A(ro)) || !distinct(A(ro))) return "key '" + kid + "': roles must be distinct known roles";
            List<Object> roles = A(ro);
            boolean machine = roles.contains("importer") || roles.contains("model");
            if (roles.contains("reviewer") && machine) return "key '" + kid + "': an importer or model key cannot hold the reviewer role";
            for (String t : new String[] {"not_before", "not_after"}) if (k.containsKey(t) && !isNonNeg(k.get(t))) return "key '" + kid + "': " + t + " must be a non-negative integer";
            if (machine) machinePks.add(S(k.get("pk")));
        }
        // the same key material under a second kid must not smuggle a machine key into the reviewer role
        for (Object ko : keys) if (A(M(ko).get("roles")).contains("reviewer") && machinePks.contains(S(M(ko).get("pk")))) return "key '" + M(ko).get("kid") + "': the same key material is pinned as an importer or model key";
        return null;
    }

    /** b64u(sha256(strictCanonical({d, verb}))) of the verb as presented minus {@code traits}, {@code floors}, {@code confirmation} and {@code def}: the facts the reviewer saw. */
    public static String factsDigest(Map<String, Object> verb) {
        Map<String, Object> v = new LinkedHashMap<>(verb);
        for (String k : new String[] {"traits", "floors", "confirmation", "def"}) v.remove(k);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", VERB_FACTS_DOMAIN); m.put("verb", v);
        return Pca.hashCanonical(m);
    }

    private static boolean blank(String s) {
        for (int i = 0; i < s.length(); i++) { char c = s.charAt(i); if (!(Character.isWhitespace(c) || Character.isSpaceChar(c) || c == '\uFEFF')) return false; }
        return true;
    }

    /** The bytes a reviewer signs: {@code REVIEW_DOMAIN} then the strict canonical body (sorted final traits, dismissals sorted by trait). */
    static byte[] reviewMessage(Map<String, Object> a) {
        List<Object> dis = new ArrayList<>(A(a.get("dismissed")));
        dis.sort((x, y) -> S(M(x).get("trait")).compareTo(S(M(y).get("trait"))));
        List<Object> dm = new ArrayList<>();
        for (Object d : dis) { Map<String, Object> e = new LinkedHashMap<>(); e.put("trait", M(d).get("trait")); e.put("reason", M(d).get("reason")); dm.add(e); }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("def_digest", a.get("def_digest")); body.put("traits_digest", a.get("traits_digest")); body.put("facts_digest", a.get("facts_digest")); body.put("final_traits", toObjs(sortUniq(a.get("final_traits"))));
        body.put("dismissed", dm); body.put("reviewer_kid", a.get("reviewer_kid")); body.put("ts", a.get("ts"));
        return IntentJs.message(REVIEW_DOMAIN, body);
    }

    /**
     * True iff {@code aO} is a valid attestation over {@code defDigest}: accepted trait registry digest, final traits accepted by {@code finalOk}, sound
     * dismissals, signed by a key pinned with the reviewer role inside its validity window. Total: any failure or exception is "not confirmed".
     */
    private static boolean attested(Object aO, Object defDigest, Registry reg, Object pinsO, String wantFacts, Predicate<List<String>> finalOk) {
        try {
            if (pinsO == null || reviewerPinsError(pinsO) != null || !(aO instanceof Map) || !(defDigest instanceof String)) return false;
            Map<String, Object> a = M(aO), pins = M(pinsO);
            if (!(a.get("sig") instanceof String) || !defDigest.equals(a.get("def_digest"))) return false;
            List<Object> extra = pins.get("traits_digests") == null ? List.of() : A(pins.get("traits_digests"));
            if (!traitsDigest(reg).equals(a.get("traits_digest")) && !extra.contains(a.get("traits_digest"))) return false;
            // a verb must present the facts the reviewer saw; a def has no verb, its signature alone binds facts_digest
            if (!(a.get("facts_digest") instanceof String) || (wantFacts != null && !wantFacts.equals(a.get("facts_digest")))) return false;
            if (!(a.get("final_traits") instanceof List) || !(a.get("dismissed") instanceof List) || !isInt(a.get("ts")) || !(a.get("reviewer_kid") instanceof String)) return false;
            List<String> fin = sortUniq(a.get("final_traits"));
            if (!finalOk.test(fin)) return false;
            for (Object d : A(a.get("dismissed"))) {
                if (!isMap(d) || !(M(d).get("trait") instanceof String) || !(M(d).get("reason") instanceof String)) return false;
                if (fin.contains(M(d).get("trait")) || blank(S(M(d).get("reason")))) return false;
            }
            for (Object ko : A(pins.get("keys"))) {
                Map<String, Object> k = M(ko);
                if (!k.get("kid").equals(a.get("reviewer_kid"))) continue;
                if (!A(k.get("roles")).contains("reviewer")) return false;
                if ((k.containsKey("not_before") && L(a.get("ts")) < L(k.get("not_before"))) || (k.containsKey("not_after") && L(a.get("ts")) > L(k.get("not_after")))) return false;
                return Pca.verifyB64u(S(k.get("pk")), reviewMessage(a), S(a.get("sig")));
            }
            return false;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** True iff the def is {@code confirmed} with an attestation over THIS def digest whose final traits are exactly its declared traits (see {@link #attested}). */
    public static boolean isConfirmed(Map<String, Object> d, Registry reg, Map<String, Object> pins) {
        try {
            Object rv = d.get("review");
            if (!isMap(rv) || !"confirmed".equals(M(rv).get("state"))) return false;
            List<String> declared = sortUniq(d.get("traits"));
            return attested(M(rv).get("attestation"), defDigest(d), reg, pins, null, fin -> fin.equals(declared));
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- rule 22: whole-document integrity of the carried traits and floors ---------------------------------------------------------

    private static final String PFX = "action.params.";

    /**
     * Recompute from the verb's own visible facts that its {@code traits} contain every implied trait and that its {@code floors} are at least the floor of
     * the traits' closure and of the declared reversibility. Null = consistent; else {@code <code>: <reason>}. Never throws.
     */
    public static String schemaVerbFloorError(Map<String, Object> v, Registry reg) { return schemaVerbFloorError(v, reg, null); }

    /** As above, and an unconfirmed verb (no valid {@code confirmation} signed by a key in {@code pins}) must carry EVERY trait of the registry. */
    public static String schemaVerbFloorError(Map<String, Object> v, Registry reg, Map<String, Object> pins) {
        try {
            if (!(v.get("effects") instanceof List) || !(v.get("traits") instanceof List) || !v.containsKey("floors")) return "schema_floor_forged: not a v2 verb";
            Map<String, Object> byName = new LinkedHashMap<>();
            List<Map<String, Object>> ps = new ArrayList<>();
            for (Map.Entry<String, Object> en : M(v.get("params")).entrySet()) {
                Map<String, Object> p = M(en.getValue());
                ps.add(p);
                Map<String, Object> e = new LinkedHashMap<>();
                e.put("type", p.get("type"));
                if (p.containsKey("values")) e.put("values", p.get("values"));
                byName.put(en.getKey().substring(PFX.length()), e);
            }
            Object decl;
            if (v.get("reversibility_by") != null) {
                Map<String, Object> rb = M(v.get("reversibility_by")), dm = new LinkedHashMap<>();
                dm.put("by", S(rb.get("param")).substring(PFX.length())); dm.put("map", rb.get("map"));
                if (rb.containsKey("default")) dm.put("default", rb.get("default"));
                decl = dm;
            } else decl = v.containsKey("reversibility") ? v.get("reversibility") : ("read".equals(v.get("kind")) ? "reversible" : "irreversible");
            String worst = worstReversibility(decl, byName);
            for (String t : impliedFromFacts(A(v.get("effects")), ps, null, worst)) if (!A(v.get("traits")).contains(t)) return "schema_traits_forged: missing implied trait " + t;
            Set<Object> carriedTraits = new HashSet<>(A(v.get("traits")));
            if (!attested(v.get("confirmation"), v.get("def"), reg, pins, factsDigest(v), fin -> carriedTraits.containsAll(fin)))
                for (String t : topTraits(reg)) if (!carriedTraits.contains(t)) return "schema_traits_forged: unconfirmed action must carry every trait (missing " + t + ")";
            Profile fl = floorOf(reg, A(v.get("traits")));
            Profile carried = Profile.fromMap(v.get("floors"));
            if (!fl.leq(carried)) return "schema_floor_forged: floors are below the floor of the carried traits";
            if (revRank(carried.rev) < revRank(worst)) return "schema_floor_forged: floors.rev is below the declared reversibility";
            return null;
        } catch (ActionKitError e) {
            return e.code + ": " + e.getMessage();
        } catch (RuntimeException e) {
            return "schema_floor_forged: " + e;
        }
    }

    /** Core + the document's own {@code trait_defs} (checked); when it carries {@code traits_digest} the registry must hash to it. */
    public static Registry registryOfSchema(Map<String, Object> doc) {
        Object td = doc.get("trait_defs");
        Registry reg = td instanceof List && !((List<?>) td).isEmpty() ? extendRegistry(CORE_REGISTRY, A(td)) : CORE_REGISTRY;
        if (doc.containsKey("traits_digest") && !traitsDigest(reg).equals(doc.get("traits_digest")))
            throw new ActionKitError("traits_digest_mismatch", "the document's traits_digest does not match its trait registry");
        return reg;
    }

    /** Rule 22's integrity half for a whole v2 document. Null = consistent. Never throws. */
    public static String schemaFloorError(Map<String, Object> doc) { return schemaFloorError(doc, null); }

    /** As above, with the verifier's pinned reviewer keys (absent: nothing is confirmed). */
    public static String schemaFloorError(Map<String, Object> doc, Map<String, Object> pins) {
        try {
            Registry reg = registryOfSchema(doc);
            for (Object v : A(doc.get("verbs"))) {
                String e = schemaVerbFloorError(M(v), reg, pins);
                if (e != null) return M(v).get("verb") + ": " + e;
            }
            return null;
        } catch (ActionKitError e) {
            return e.code + ": " + e.getMessage();
        } catch (RuntimeException e) {
            return "bad_registry: " + e;
        }
    }
}
