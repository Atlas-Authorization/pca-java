package net.atlasauth.pca.actions.importers;

import static net.atlasauth.pca.actions.importers.ImportCommon.tokensOf;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Actions.ActionKitError;
import net.atlasauth.pca.ActionsBridge;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.W3Bridge;

/**
 * The deterministic suggestion layer: a versioned rule set proposes traits, param roles and param tags for a draft def. Union only: a
 * suggestion can ADD a trait, a role (to a param that has none) or a tag, never remove or replace anything, and it never marks a def
 * confirmed. A suggested def is still {@code pca.unreviewed} for floor purposes until a pinned reviewer signs it.
 * Defs, rule sets and suggestions are JSON trees (Map / List / String / Boolean / Json.Num).
 */
public final class ImportSuggest {
    private ImportSuggest() {}

    public static final String SUGGEST_RULES_KIND = "pca-suggest-rules";
    public static final String SUGGEST_RULES_DOMAIN = "atlas-pca/suggest-rules/v1";

    private static final Pattern RULE_ID_RE = Pattern.compile("SR-[0-9]{3,4}");
    private static final Pattern VERSION_RE = Pattern.compile("[0-9]+\\.[0-9]+\\.[0-9]+");
    private static final Pattern TRAIT_ID_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}\\.[a-z][a-z0-9_]{0,63}");
    private static final List<String> MATCH_KEYS = List.of("methods", "path_re", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_types", "param_formats", "roles", "effects");
    private static final List<String> PARAM_TAGS = List.of("pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql");
    private static final List<String> PARAM_TYPES = List.of("string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref");
    private static final int MAX_RULES = 1024;
    private static final int MAX_LIST = 64;
    // a group that holds a quantifier or an alternation, followed by another quantifier: the shapes that backtrack exponentially
    private static final Pattern NESTED_QUANTIFIER = Pattern.compile("\\([^)]*[+*][^)]*\\)[+*{]|\\([^)]*\\|[^)]*\\)[+*{]");
    private static final Pattern BACKREF = Pattern.compile("\\\\[1-9]");
    private static final Pattern LOOKAROUND = Pattern.compile("\\(\\?[<=!]");

    private static boolean isStrList(Object v, int max) {
        if (!(v instanceof List)) return false;
        List<Object> l = Jx.a(v);
        if (l.isEmpty() || l.size() > max) return false;
        for (Object x : l) if (!(x instanceof String) || ((String) x).isEmpty() || ((String) x).length() > 64) return false;
        return true;
    }

    // ---- JavaScript regular expression to java.util.regex (the bounded subset the rules use) ----

    private static final String JS_SPACE = "\\t\\n\\u000B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF";

    private static boolean hex(String s, int from, int n) {
        if (from + n > s.length()) return false;
        for (int i = from; i < from + n; i++) if (Character.digit(s.charAt(i), 16) < 0 || s.charAt(i) > 0x7f) return false;
        return true;
    }

    /** The end of a {@code {n}}, {@code {n,}} or {@code {n,m}} quantifier starting at {@code i}, or -1. */
    private static int quantEnd(String s, int i) {
        int j = i + 1, d = 0;
        while (j < s.length() && s.charAt(j) >= '0' && s.charAt(j) <= '9') { j++; d++; }
        if (d == 0) return -1;
        if (j < s.length() && s.charAt(j) == ',') { j++; while (j < s.length() && s.charAt(j) >= '0' && s.charAt(j) <= '9') j++; }
        return j < s.length() && s.charAt(j) == '}' ? j + 1 : -1;
    }

    /** Compile a JavaScript pattern (no flags); an IllegalArgumentException where the engine would raise SyntaxError. */
    static Pattern jsRegex(String s) {
        StringBuilder o = new StringBuilder();
        int n = s.length(), i = 0, depth = 0;
        boolean inClass = false, canQuant = false;
        while (i < n) {
            char c = s.charAt(i);
            if (inClass) {
                if (c == ']') { o.append(']'); inClass = false; canQuant = true; i++; continue; }
                if (c == '\\') {
                    if (i + 1 >= n) throw new IllegalArgumentException("\\ at end of pattern");
                    char e = s.charAt(i + 1);
                    i += 2;
                    if (e == 's') o.append(JS_SPACE);
                    else if (e == 'S') o.append("[^").append(JS_SPACE).append(']');
                    else if (e == 'd' || e == 'D' || e == 'w' || e == 'W') o.append('\\').append(e);
                    else if (e == 'b') o.append("\\x08");
                    else if (e == 't' || e == 'n' || e == 'f' || e == 'r') o.append('\\').append(e);
                    else if (e == 'v') o.append("\\u000B");
                    else if (e == '0') o.append("\\x00");
                    else if (e == 'x' && hex(s, i, 2)) { o.append("\\x").append(s, i, i + 2); i += 2; }
                    else if (e == 'u' && hex(s, i, 4)) { o.append("\\u").append(s, i, i + 4); i += 4; }
                    else if (e < 128 && !Character.isLetterOrDigit(e)) o.append('\\').append(e);
                    else o.append(e);
                    continue;
                }
                if (c == '[' || c == '&' || c == '^') o.append('\\').append(c); else o.append(c);
                i++;
                continue;
            }
            switch (c) {
                case '\\': {
                    if (i + 1 >= n) throw new IllegalArgumentException("\\ at end of pattern");
                    char e = s.charAt(i + 1);
                    i += 2;
                    canQuant = true;
                    if (e == 'b' || e == 'B') { o.append('\\').append(e); canQuant = false; }
                    else if (e == 'd' || e == 'D' || e == 'w' || e == 'W') o.append('\\').append(e);
                    else if (e == 's') o.append('[').append(JS_SPACE).append(']');
                    else if (e == 'S') o.append("[^").append(JS_SPACE).append(']');
                    else if (e == 't' || e == 'n' || e == 'f' || e == 'r') o.append('\\').append(e);
                    else if (e == 'v') o.append("\\u000B");
                    else if (e == '0') o.append("\\x00");
                    else if (e >= '1' && e <= '9') o.append('\\').append(e);
                    else if (e == 'x' && hex(s, i, 2)) { o.append("\\x").append(s, i, i + 2); i += 2; }
                    else if (e == 'u' && hex(s, i, 4)) { o.append("\\u").append(s, i, i + 4); i += 4; }
                    else if (e == 'c' && i < n && Character.isLetter(s.charAt(i)) && s.charAt(i) < 128) { o.append("\\c").append(s.charAt(i)); i++; }
                    else if (e == 'c') o.append("\\\\c");
                    else if (e < 128 && !Character.isLetterOrDigit(e)) o.append('\\').append(e);
                    else o.append(e);
                    break;
                }
                case '(': {
                    if (i + 1 < n && s.charAt(i + 1) == '?') {
                        if (i + 2 < n && (s.charAt(i + 2) == ':' || s.charAt(i + 2) == '=' || s.charAt(i + 2) == '!')) { o.append("(?").append(s.charAt(i + 2)); i += 3; }
                        else throw new IllegalArgumentException("invalid group");
                    } else { o.append('('); i++; }
                    depth++;
                    canQuant = false;
                    break;
                }
                case ')':
                    if (depth == 0) throw new IllegalArgumentException("unmatched )");
                    depth--; o.append(')'); canQuant = true; i++;
                    break;
                case '|': o.append('|'); canQuant = false; i++; break;
                case '*': case '+': case '?': {
                    if (!canQuant) throw new IllegalArgumentException("nothing to repeat");
                    o.append(c); i++;
                    if (i < n && s.charAt(i) == '?') { o.append('?'); i++; }
                    canQuant = false;
                    break;
                }
                case '{': {
                    int e = quantEnd(s, i);
                    if (e < 0) { o.append("\\{"); canQuant = true; i++; break; }
                    if (!canQuant) throw new IllegalArgumentException("nothing to repeat");
                    o.append(s, i, e); i = e;
                    if (i < n && s.charAt(i) == '?') { o.append('?'); i++; }
                    canQuant = false;
                    break;
                }
                case '}': o.append("\\}"); canQuant = true; i++; break;
                case ']': o.append("\\]"); canQuant = true; i++; break;
                case '[': {
                    if (s.startsWith("[]", i)) { o.append("(?!)"); i += 2; canQuant = true; break; }
                    if (s.startsWith("[^]", i)) { o.append("[\\s\\S]"); i += 3; canQuant = true; break; }
                    inClass = true; i++;
                    if (i < n && s.charAt(i) == '^') { o.append("[^"); i++; } else o.append('[');
                    break;
                }
                case '.': o.append("[^\\n\\r\\u2028\\u2029]"); canQuant = true; i++; break;
                case '^': o.append('^'); canQuant = false; i++; break;
                case '$': o.append("\\z"); canQuant = false; i++; break;
                default: o.append(c); canQuant = true; i++;
            }
        }
        if (inClass || depth != 0) throw new IllegalArgumentException("unterminated pattern");
        try { return Pattern.compile(o.toString()); } catch (PatternSyntaxException e) { throw new IllegalArgumentException(e.getMessage()); }
    }

    // ---- rule set validation, digest, signature ----

    /** Null if the rule set is well formed: closed members, unique ids, safe regular expressions, known trait/role/tag names. */
    public static String suggestRulesError(Object r, Set<String> known) {
        if (!(r instanceof Map)) return "rules must be an object";
        Map<String, Object> o = Jx.m(r);
        for (String k : Jx.keys(o)) if (!List.of("v", "kind", "version", "rules", "digest", "sig").contains(k)) return "unknown member '" + k + "'";
        Double one = Jx.num(o.get("v"));
        if (one == null || one != 1.0 || !SUGGEST_RULES_KIND.equals(o.get("kind"))) return "not a suggest-rules document (v 1)";
        if (!(o.get("version") instanceof String) || !VERSION_RE.matcher((String) o.get("version")).matches()) return "version must be semver";
        if (!(o.get("rules") instanceof List) || Jx.a(o.get("rules")).isEmpty() || Jx.a(o.get("rules")).size() > MAX_RULES) return "rules must be 1.." + MAX_RULES + " entries";
        Set<String> ids = new LinkedHashSet<>();
        for (Object x : Jx.a(o.get("rules"))) {
            if (!(x instanceof Map)) return "a rule must be an object";
            Map<String, Object> rule = Jx.m(x);
            for (String k : Jx.keys(rule)) if (!List.of("id", "match", "adds", "note").contains(k)) return "rule: unknown member '" + k + "'";
            if (!(rule.get("id") instanceof String) || !RULE_ID_RE.matcher((String) rule.get("id")).matches() || ids.contains(rule.get("id"))) return "rule ids must be unique SR-nnn";
            String w = (String) rule.get("id");
            ids.add(w);
            if (!(rule.get("note") instanceof String) || ((String) rule.get("note")).isEmpty() || ((String) rule.get("note")).length() > 200) return w + ": note must be 1..200 characters";
            if (!(rule.get("match") instanceof Map) || Jx.m(rule.get("match")).isEmpty()) return w + ": match must be a non-empty object";
            Map<String, Object> m = Jx.m(rule.get("match"));
            for (String k : Jx.keys(m)) if (!MATCH_KEYS.contains(k)) return w + ": unknown match member '" + k + "'";
            for (String k : List.of("methods", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_formats", "roles"))
                if (m.containsKey(k) && !isStrList(m.get(k), MAX_LIST)) return w + ": match." + k + " must be 1.." + MAX_LIST + " short strings";
            if (m.containsKey("methods")) for (Object s : Jx.a(m.get("methods"))) if (!((String) s).equals(((String) s).toUpperCase(java.util.Locale.ROOT))) return w + ": methods are uppercase";
            if (m.containsKey("param_types")) {
                boolean bad = !isStrList(m.get("param_types"), MAX_LIST);
                if (!bad) for (Object t : Jx.a(m.get("param_types"))) if (!PARAM_TYPES.contains(t)) { bad = true; break; }
                if (bad) return w + ": match.param_types is not a list of param types";
            }
            if (m.containsKey("effects") && !isStrList(m.get("effects"), 12)) return w + ": match.effects must be a list of effects";
            if (m.containsKey("path_re")) {
                Object pr = m.get("path_re");
                if (!(pr instanceof String) || ((String) pr).isEmpty() || ((String) pr).length() > 128) return w + ": path_re must be 1..128 characters";
                String re = (String) pr;
                if (NESTED_QUANTIFIER.matcher(re).find() || BACKREF.matcher(re).find() || LOOKAROUND.matcher(re).find())
                    return w + ": path_re uses a construct outside the bounded subset (nested quantifiers, backreferences, lookaround)";
                try { jsRegex(re); } catch (IllegalArgumentException e) { return w + ": path_re is not a regular expression"; }
            }
            boolean hasParam = m.containsKey("param_names") || m.containsKey("param_names_all") || m.containsKey("param_formats") || m.containsKey("roles");
            if (m.containsKey("param_types") && !m.containsKey("param_names") && !m.containsKey("param_formats") && !m.containsKey("param_names_all")) return w + ": param_types needs param_names, param_names_all or param_formats";
            if (!isStrList(rule.get("adds"), 16)) return w + ": adds must be 1..16 entries";
            for (Object ao : Jx.a(rule.get("adds"))) {
                String a = (String) ao;
                if (a.startsWith("tag:")) {
                    if (!PARAM_TAGS.contains(a.substring(4))) return w + ": unknown tag '" + a + "'";
                    if (!hasParam) return w + ": a tag needs a param matcher";
                } else if (ActionsBridge.isRole(a)) {
                    if (!hasParam) return w + ": a role needs a param matcher";
                } else if (TRAIT_ID_RE.matcher(a).matches()) {
                    if (known != null && !known.contains(a)) return w + ": unknown trait '" + a + "'";
                } else return w + ": '" + a + "' is not a trait, role or tag:";
            }
        }
        return null;
    }

    /** b64u sha256 of the strict canonical rule set (without digest and sig). */
    public static String rulesDigest(Map<String, Object> r) {
        Map<String, Object> body = new LinkedHashMap<>();
        for (String k : List.of("v", "kind", "version", "rules")) if (r.containsKey(k)) body.put(k, r.get(k));
        return Pca.hashCanonical(Jx.obj("d", SUGGEST_RULES_DOMAIN, "rules", body));
    }

    public static Map<String, Object> sealRules(Map<String, Object> r) {
        Map<String, Object> out = new LinkedHashMap<>(r);
        out.put("digest", rulesDigest(r));
        return out;
    }

    private static byte[] rulesMessage(String digest) {
        byte[] dom = (SUGGEST_RULES_DOMAIN + "\0").getBytes(StandardCharsets.UTF_8);
        byte[] body = Json.canonicalizeStrict(Jx.obj("digest", digest)).getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[dom.length + body.length];
        System.arraycopy(dom, 0, out, 0, dom.length);
        System.arraycopy(body, 0, out, dom.length, body.length);
        return out;
    }

    /** Sign a rule set as the rules publisher (a release step; the signature covers the digest). {@code secret}: the Ed25519 seed. */
    public static Map<String, Object> signRules(Map<String, Object> r, String kid, byte[] secret) {
        String bad = suggestRulesError(r, null);
        if (bad != null) throw new ActionKitError("bad_rules", bad);
        Map<String, Object> sealed = sealRules(r);
        sealed.put("sig", Jx.obj("alg", "ed25519", "kid", kid, "value", Keys.b64u(Keys.edFromSeed(secret).sign(rulesMessage((String) sealed.get("digest"))))));
        return sealed;
    }

    /** Verify a signed rule set against pinned publisher keys ({@code [{kid, pk}]}): shape, digest, signature. Never throws. */
    public static Map<String, Object> verifyRules(Object doc, List<Map<String, Object>> pins) {
        try {
            String bad = suggestRulesError(doc, null);
            if (bad != null) return Jx.obj("ok", false, "reason", bad);
            Map<String, Object> d = Jx.m(doc);
            if (!rulesDigest(d).equals(d.get("digest"))) return Jx.obj("ok", false, "reason", "digest does not match the rules");
            if (!Jx.truthy(d.get("sig"))) return Jx.obj("ok", false, "reason", "the rule set is not signed");
            Object sig = d.get("sig");
            Object kid = Jx.get(sig, "kid");
            Map<String, Object> key = null;
            for (Map<String, Object> p : pins) if (kid != null && kid.equals(p.get("kid"))) { key = p; break; }
            if (key == null) return Jx.obj("ok", false, "reason", "no pinned rules key '" + (Jx.has(sig, "kid") ? Jx.jsStr(kid) : "undefined") + "'");
            Object value = Jx.get(sig, "value");
            boolean ok = key.get("pk") instanceof String && value instanceof String && W3Bridge.verifyB64u((String) key.get("pk"), rulesMessage((String) d.get("digest")), (String) value);
            return ok ? Jx.obj("ok", true) : Jx.obj("ok", false, "reason", "rules signature invalid");
        } catch (RuntimeException e) {
            return Jx.obj("ok", false, "reason", "rules verification error: " + e.getMessage());
        }
    }

    // ---- facts ----

    /** Light stemmer: plural, -ing, -ed and a trailing -e fold together ({@code charges}, {@code charged}, {@code charging} to {@code charg}). */
    public static String stem(String t) {
        String s = t;
        if (s.length() > 4 && s.endsWith("ies")) s = s.substring(0, s.length() - 3) + "y";
        else if ((s.endsWith("sses") || s.endsWith("xes") || s.endsWith("zes") || s.endsWith("ches") || s.endsWith("shes")) && s.length() > 4) s = s.substring(0, s.length() - 2);
        else if (s.length() > 3 && s.endsWith("s") && !s.endsWith("ss")) s = s.substring(0, s.length() - 1);
        if (s.length() > 5 && s.endsWith("ing")) s = s.substring(0, s.length() - 3);
        else if (s.length() > 4 && s.endsWith("ed")) s = s.substring(0, s.length() - 2);
        if (s.length() > 3 && s.endsWith("e")) s = s.substring(0, s.length() - 1);
        return s;
    }

    private static final String SEP = "|";

    /** What the rules read of a def: methods, binding locations, stemmed name tokens (with and without path segments), params and effects. */
    public static final class Facts {
        public final Set<String> methods = new LinkedHashSet<>();
        public final List<String> locs = new ArrayList<>();
        public final List<String> tokens = new ArrayList<>();
        public final List<String> strict = new ArrayList<>();
        public final List<FParam> params = new ArrayList<>();
        public final Set<String> effects = new LinkedHashSet<>();

        public Map<String, Object> toJson() {
            List<Object> ps = new ArrayList<>();
            for (FParam p : params) {
                Map<String, Object> m = Jx.obj("name", p.name, "tokens", new ArrayList<Object>(p.tokens), "type", p.type);
                if (p.format != null) m.put("format", p.format);
                if (p.role != null) m.put("role", p.role);
                ps.add(m);
            }
            return Jx.obj("methods", new ArrayList<Object>(new TreeSet<>(methods)), "locs", new ArrayList<Object>(locs), "tokens", new ArrayList<Object>(tokens), "strict", new ArrayList<Object>(strict),
                "params", ps, "effects", new ArrayList<Object>(new TreeSet<>(effects)));
        }
    }

    public static final class FParam {
        public final String name, type, format, role;
        public final List<String> tokens;
        FParam(String name, List<String> tokens, String type, String format, String role) { this.name = name; this.tokens = tokens; this.type = type; this.format = format; this.role = role; }
    }

    private static List<String> stems(List<String> toks) { List<String> o = new ArrayList<>(); for (String t : toks) o.add(stem(t)); return o; }

    private static String up(Object s) { return Jx.jsStr(s).toUpperCase(java.util.Locale.ROOT); }

    public static Facts factsOf(Map<String, Object> d) {
        Object b0 = d.get("bindings");
        Object b = b0 == null ? new LinkedHashMap<String, Object>() : b0;
        Facts f = new Facts();
        List<List<String>> src = new ArrayList<>();
        List<Boolean> isPath = new ArrayList<>();
        String[] verbSegs = Jx.jsStr(d.get("verb")).split("\\.", -1);
        List<String> vt = new ArrayList<>();
        for (int i = 1; i < verbSegs.length; i++) vt.addAll(tokensOf(verbSegs[i]));
        src.add(vt); isPath.add(false);
        if (d.get("aliases") instanceof List) for (Object a : Jx.a(d.get("aliases"))) { src.add(tokensOf(a)); isPath.add(false); }
        src.add(tokensOf(d.get("title"))); isPath.add(false);
        Object oa = Jx.get(b, "openapi");
        if (Jx.truthy(oa)) {
            src.add(tokensOf(Jx.get(oa, "operationId"))); isPath.add(false);
            if (Jx.truthy(Jx.get(oa, "method"))) f.methods.add(up(Jx.get(oa, "method")));
            if (Jx.truthy(Jx.get(oa, "path"))) {
                String p = Jx.jsStr(Jx.get(oa, "path"));
                f.locs.add(p);
                src.add(pathTokens(p)); isPath.add(true);
            }
        }
        Object http = Jx.get(b, "http");
        if (Jx.truthy(http)) {
            f.methods.add(up(Jx.get(http, "method")));
            String p = Jx.jsStr(Jx.get(http, "path"));
            f.locs.add(p);
            src.add(pathTokens(p)); isPath.add(true);
        }
        Object mcp = Jx.get(b, "mcp");
        if (Jx.truthy(mcp)) { f.locs.add(Jx.jsStr(Jx.get(mcp, "tool"))); src.add(tokensOf(Jx.get(mcp, "tool"))); isPath.add(false); }
        Object gql = Jx.get(b, "graphql");
        if (Jx.truthy(gql)) { f.methods.add(up(Jx.get(gql, "op"))); f.locs.add(Jx.jsStr(Jx.get(gql, "field"))); src.add(tokensOf(Jx.get(gql, "field"))); isPath.add(false); }
        Object grpc = Jx.get(b, "grpc");
        if (Jx.truthy(grpc)) {
            f.locs.add(Jx.jsStr(Jx.get(grpc, "service")) + "/" + Jx.jsStr(Jx.get(grpc, "method")));
            src.add(tokensOf(Jx.get(grpc, "service"))); isPath.add(false);
            src.add(tokensOf(Jx.get(grpc, "method"))); isPath.add(false);
        }
        Object asy = Jx.get(b, "asyncapi");
        if (Jx.truthy(asy)) { f.methods.add(up(Jx.get(asy, "op"))); f.locs.add(Jx.jsStr(Jx.get(asy, "channel"))); src.add(tokensOf(Jx.get(asy, "channel"))); isPath.add(false); }
        for (int i = 0; i < src.size(); i++) {
            if (!f.tokens.isEmpty()) f.tokens.add(SEP);
            f.tokens.addAll(stems(src.get(i)));
            if (!isPath.get(i)) { if (!f.strict.isEmpty()) f.strict.add(SEP); f.strict.addAll(stems(src.get(i))); }
        }
        Map<String, Object> params = d.get("params") instanceof Map ? Jx.m(d.get("params")) : new LinkedHashMap<>();
        for (String name : new TreeSet<>(params.keySet())) {
            Object p = params.get(name);
            Object fm = Jx.get(p, "format"), ro = Jx.get(p, "role");
            f.params.add(new FParam(name, stems(tokensOf(name)), (String) Jx.get(p, "type"), Jx.truthy(fm) ? Jx.jsStr(fm) : null, Jx.truthy(ro) ? Jx.jsStr(ro) : null));
        }
        List<String> clipped = new ArrayList<>();
        for (String l : f.locs) clipped.add(l.length() > 512 ? l.substring(0, 512) : l);
        f.locs.clear();
        f.locs.addAll(clipped);
        if (d.get("effects") instanceof List) for (Object e : Jx.a(d.get("effects"))) f.effects.add(Jx.jsStr(e));
        return f;
    }

    private static List<String> pathTokens(String p) {
        List<String> out = new ArrayList<>();
        for (String s : p.split("/", -1)) if (!s.isEmpty() && s.indexOf('{') < 0 && s.indexOf('}') < 0) out.addAll(tokensOf(s));
        return out;
    }

    /** True iff the stemmed pattern occurs as a contiguous run in {@code hay}. */
    private static boolean hasSeq(List<String> hay, List<String> pat) {
        if (pat.isEmpty()) return false;
        for (int i = 0; i + pat.size() <= hay.size(); i++) {
            boolean ok = true;
            for (int j = 0; j < pat.size(); j++) if (!hay.get(i + j).equals(pat.get(j))) { ok = false; break; }
            if (ok) return true;
        }
        return false;
    }

    private static List<String> patOf(String s) { return stems(tokensOf(s)); }

    public static Map<String, Object> emptySuggestion() { return Jx.obj("traits", new ArrayList<>(), "roles", new LinkedHashMap<>(), "tags", new LinkedHashMap<>(), "fired", new ArrayList<>()); }

    private static final Set<String> INT_ROLES = Set.of("money.amount", "money.fee", "count.limit", "bytes.size");

    private static boolean roleFits(String role, String type) {
        if (INT_ROLES.contains(role)) return "integer".equals(type);
        if (role.startsWith("time.")) return "date".equals(type) || "datetime".equals(type) || "integer".equals(type);
        return "string".equals(type);
    }

    private static List<String> strs(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof List) for (Object x : Jx.a(o)) out.add(Jx.jsStr(x));
        return out;
    }

    /**
     * Run the rules over a def. Only trait ids in {@code registry} (when given) can be suggested; anything else is dropped (the closed
     * vocabulary). Pure and deterministic. Returns {@code {traits, roles, tags, fired}}.
     */
    public static Map<String, Object> suggestWithRules(Map<String, Object> d, Map<String, Object> rules, Actions.Registry registry) {
        Facts f = factsOf(d);
        Set<String> traits = new TreeSet<>();
        Map<String, Object> roles = new LinkedHashMap<>();
        Map<String, Set<String>> tags = new LinkedHashMap<>();
        List<Object> fired = new ArrayList<>();
        List<String> stemsAll = f.tokens;
        for (Object ro : Jx.a(rules.get("rules"))) {
            Map<String, Object> rule = Jx.m(ro);
            Map<String, Object> m = Jx.m(rule.get("match"));
            if (Jx.truthy(m.get("methods"))) { boolean any = false; for (String x : strs(m.get("methods"))) if (f.methods.contains(x)) { any = true; break; } if (!any) continue; }
            if (Jx.truthy(m.get("effects"))) { boolean any = false; for (String x : strs(m.get("effects"))) if (f.effects.contains(x)) { any = true; break; } if (!any) continue; }
            if (Jx.truthy(m.get("name_tokens"))) { boolean any = false; for (String p : strs(m.get("name_tokens"))) if (hasSeq(stemsAll, patOf(p))) { any = true; break; } if (!any) continue; }
            if (Jx.truthy(m.get("name_tokens_strict"))) { boolean any = false; for (String p : strs(m.get("name_tokens_strict"))) if (hasSeq(f.strict, patOf(p))) { any = true; break; } if (!any) continue; }
            if (Jx.truthy(m.get("path_re"))) {
                Pattern re = jsRegex(Jx.jsStr(m.get("path_re")));
                boolean any = false;
                for (String l : f.locs) if (re.matcher(l).find()) { any = true; break; }
                if (!any) continue;
            }
            if (Jx.truthy(m.get("roles"))) {
                List<String> rs = strs(m.get("roles"));
                boolean any = false;
                for (FParam p : f.params) if (p.role != null && rs.contains(p.role)) { any = true; break; }
                if (!any) continue;
            }
            List<FParam> matched = new ArrayList<>();
            boolean paramCond = m.containsKey("param_names") || m.containsKey("param_formats");
            List<String> ptypes = Jx.truthy(m.get("param_types")) ? strs(m.get("param_types")) : null;
            if (paramCond) {
                List<List<String>> pats = new ArrayList<>();
                if (Jx.truthy(m.get("param_names"))) for (String n : strs(m.get("param_names"))) pats.add(patOf(n));
                for (FParam p : f.params) {
                    if (ptypes != null && !ptypes.contains(p.type)) continue;
                    if (Jx.truthy(m.get("param_names"))) { boolean any = false; for (List<String> q : pats) if (hasSeq(p.tokens, q)) { any = true; break; } if (!any) continue; }
                    if (Jx.truthy(m.get("param_formats")) && (p.format == null || !strs(m.get("param_formats")).contains(p.format))) continue;
                    matched.add(p);
                }
                if (matched.isEmpty()) continue;
            }
            if (Jx.truthy(m.get("param_names_all"))) {
                boolean ok = true;
                for (String n : strs(m.get("param_names_all"))) {
                    List<String> q = patOf(n);
                    boolean has = false;
                    for (FParam p : f.params) if (hasSeq(p.tokens, q) && (ptypes == null || ptypes.contains(p.type) || "string".equals(p.type))) { has = true; break; }
                    if (!has) { ok = false; break; }
                }
                if (!ok) continue;
            }
            fired.add(rule.get("id"));
            for (String a : strs(rule.get("adds"))) {
                if (a.startsWith("tag:")) {
                    for (FParam p : matched) tags.computeIfAbsent(p.name, k -> new TreeSet<>()).add(a.substring(4));
                } else if (!ActionsBridge.isRole(a)) {
                    if (registry == null || registry.traits.containsKey(a)) traits.add(a);
                } else {
                    for (FParam p : matched) if (p.role == null && roles.get(p.name) == null && roleFits(a, p.type)) roles.put(p.name, a);
                }
            }
        }
        traits.remove("pca.unreviewed");
        Map<String, Object> tagOut = new LinkedHashMap<>();
        for (String k : new TreeSet<>(tags.keySet())) tagOut.put(k, new ArrayList<Object>(new TreeSet<>(tags.get(k))));
        return Jx.obj("traits", new ArrayList<Object>(traits), "roles", roles, "tags", tagOut, "fired", fired);
    }

    private static List<Object> sortedUnion(List<?>... ls) {
        TreeSet<String> s = new TreeSet<>();
        for (List<?> l : ls) if (l != null) for (Object x : l) s.add(Jx.jsStr(x));
        return new ArrayList<Object>(s);
    }

    /** Union two suggestions (the restrictive direction, so no intersection is needed). */
    public static Map<String, Object> unionSuggestions(Map<String, Object> a, Map<String, Object> b) {
        Map<String, Object> roles = new LinkedHashMap<>(Jx.m(b.get("roles")));
        roles.putAll(Jx.m(a.get("roles")));
        Map<String, Object> tags = new LinkedHashMap<>();
        Set<String> ks = new LinkedHashSet<>(Jx.m(a.get("tags")).keySet());
        ks.addAll(Jx.m(b.get("tags")).keySet());
        for (String k : ks) tags.put(k, sortedUnion((List<?>) Jx.m(a.get("tags")).get(k), (List<?>) Jx.m(b.get("tags")).get(k)));
        List<Object> fired = new ArrayList<>(Jx.a(a.get("fired")));
        fired.addAll(Jx.a(b.get("fired")));
        return Jx.obj("traits", sortedUnion(Jx.a(a.get("traits")), Jx.a(b.get("traits"))), "roles", roles, "tags", tags, "fired", fired);
    }

    /**
     * Apply a suggestion to a def. UNION ONLY: traits are added, a role is set only on a param without one, tags are added; nothing is
     * removed or replaced, no attestation is created, and {@code review.state} goes from {@code unreviewed} to {@code suggested}.
     * {@code by}: {@code {rules?: {version, digest, fired}, models?: [...]}}.
     */
    public static Map<String, Object> applySuggestion(Map<String, Object> d, Map<String, Object> s, Map<String, Object> by) {
        Map<String, Object> params = new LinkedHashMap<>();
        Map<String, Object> addedRoles = new LinkedHashMap<>();
        Map<String, Object> addedTags = new LinkedHashMap<>();
        Map<String, Object> sroles = Jx.m(s.get("roles")), stags = Jx.m(s.get("tags"));
        for (Map.Entry<String, Object> e : Jx.m(d.get("params")).entrySet()) {
            String name = e.getKey();
            Map<String, Object> p = Jx.m(e.getValue());
            Map<String, Object> q = p;
            Object role = sroles.get(name);
            if (role != null && p.get("role") == null && roleFits((String) role, (String) p.get("type"))) { q = new LinkedHashMap<>(q); q.put("role", role); addedRoles.put(name, role); }
            Object t = stags.get(name);
            if (t != null) {
                List<Object> have = p.get("tags") instanceof List ? Jx.a(p.get("tags")) : new ArrayList<>();
                List<Object> fresh = new ArrayList<>();
                for (Object x : Jx.a(t)) if (!have.contains(x)) fresh.add(x);
                if (!fresh.isEmpty()) { q = new LinkedHashMap<>(q); q.put("tags", sortedUnion(have, fresh)); addedTags.put(name, fresh); }
            }
            params.put(name, q);
        }
        List<Object> dtraits = d.get("traits") instanceof List ? Jx.a(d.get("traits")) : new ArrayList<>();
        List<Object> freshTraits = new ArrayList<>();
        for (Object t : Jx.a(s.get("traits"))) if (!dtraits.contains(t)) freshTraits.add(t);
        // a money-moving action must be safe to repeat (lint LD-004): add the optional idempotency key the pack generator adds
        Object idempotency = d.get("idempotency");
        if (Jx.a(s.get("traits")).contains("pca.money_moving") && (idempotency == null || "none".equals(Jx.get(idempotency, "mode")))) {
            idempotency = Jx.obj("mode", "key_param", "param", "idempotency_key");
            if (!params.containsKey("idempotency_key")) params.put("idempotency_key", Jx.obj("type", "string", "max_len", Jx.n(64), "required", Boolean.FALSE));
        }
        Map<String, Object> review = Jx.m(d.get("review"));
        Map<String, Object> prev = review.get("suggested_by") instanceof Map ? Jx.m(review.get("suggested_by")) : new LinkedHashMap<>();
        Map<String, Object> prevAdded = prev.get("added") != null ? Jx.m(prev.get("added")) : Jx.obj("traits", new ArrayList<>(), "roles", new LinkedHashMap<>(), "tags", new LinkedHashMap<>());
        Map<String, Object> addedRolesAll = new LinkedHashMap<>(Jx.m(prevAdded.get("roles")));
        addedRolesAll.putAll(addedRoles);
        Map<String, Object> prevTags = Jx.m(prevAdded.get("tags"));
        TreeSet<String> tagKeys = new TreeSet<>(prevTags.keySet());
        tagKeys.addAll(addedTags.keySet());
        Map<String, Object> tagsAll = new LinkedHashMap<>();
        for (String k : tagKeys) tagsAll.put(k, sortedUnion((List<?>) prevTags.get(k), (List<?>) addedTags.get(k)));
        Map<String, Object> added = Jx.obj("traits", sortedUnion(Jx.a(prevAdded.get("traits")), freshTraits), "roles", addedRolesAll, "tags", tagsAll);
        Object rules = by.get("rules") != null ? by.get("rules") : prev.get("rules");
        List<Object> models = new ArrayList<>();
        if (prev.get("models") instanceof List) models.addAll(Jx.a(prev.get("models")));
        if (by.get("models") instanceof List) models.addAll(Jx.a(by.get("models")));
        Map<String, Object> suggestedBy = new LinkedHashMap<>();
        if (rules != null) suggestedBy.put("rules", rules);
        if (!models.isEmpty()) suggestedBy.put("models", models);
        suggestedBy.put("added", added);
        Object st = review.get("state");
        Object state = "unreviewed".equals(st) || "suggested".equals(st) ? "suggested" : st;
        Map<String, Object> out = new LinkedHashMap<>(d);
        out.put("params", params);
        if (idempotency != null) out.put("idempotency", idempotency);
        if (!freshTraits.isEmpty() || !dtraits.isEmpty()) out.put("traits", sortedUnion(dtraits, Jx.a(s.get("traits"))));
        Map<String, Object> nr = new LinkedHashMap<>(review);
        nr.put("state", state);
        nr.put("suggested_by", suggestedBy);
        out.put("review", nr);
        return out;
    }
}
