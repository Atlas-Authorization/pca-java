package net.atlasauth.pca.actions.importers;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Actions.ActionKitError;
import net.atlasauth.pca.ActionsBridge;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;

/**
 * What every importer shares: result shapes, text hygiene, verb naming, the bounded {@code $ref} resolver, the JSON Schema to
 * parameter flattening, and the single place a draft def is assembled (always {@code unreviewed}). Sources, reports and defs are
 * JSON trees (Map / List / String / Boolean / Json.Num / null).
 */
public final class ImportCommon {
    private ImportCommon() {}

    public static final List<String> IMPORT_KINDS = List.of("openapi", "mcp", "graphql", "grpc", "asyncapi", "jsonschema");
    public static final List<String> DEFAULT_EXTENSIONS = List.of("x-pca-verb", "x-pca-role", "x-pca-internal");

    static final Pattern NS_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}");
    static final Pattern VERB_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){1,5}");
    static final Pattern ALIAS_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){0,5}");
    private static final Pattern ID_ROLE_RE = Pattern.compile("id\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){0,3}");
    private static final Pattern X_ROLE_RE = Pattern.compile("x\\.[a-z0-9_]+(?:\\.[a-z0-9_]+){1,3}");
    private static final Pattern RTYPE_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){0,4}");
    private static final int MAX_TITLE_BYTES = 120, MAX_DESCRIPTION_BYTES = 1024, MAX_DEF_PARAMS = 64, MAX_PARAM_PATH_DEPTH = 3;

    // ---- context ----

    /** Per-import state: the namespace, limits, notes, source reference and what is already emitted. */
    public static final class Ctx {
        public final String ns, kind;
        public final ImportLimits lim;
        public final List<Object> todo = new ArrayList<>();
        public final Map<String, Object> source;
        public final Set<Object> ext;
        /** Parsed-source root that {@code #/...} references resolve in. */
        public Object root;
        final Set<String> verbs = new LinkedHashSet<>();
        final Map<String, String> aliases = new LinkedHashMap<>();
        final List<Object> defs = new ArrayList<>();

        Ctx(String ns, String kind, ImportLimits lim, Map<String, Object> source, Set<Object> ext, Object root) {
            this.ns = ns; this.kind = kind; this.lim = lim; this.source = source; this.ext = ext; this.root = root;
        }
    }

    /** The expansion budget of one operation: every schema node visited costs one. */
    public static final class Budget {
        public int left;
        public boolean exhausted;
        Budget(int left) { this.left = left; }
    }

    public static Budget newBudget(Ctx c) { return new Budget((int) c.lim.maxRefNodes); }

    @SuppressWarnings("unchecked")
    public static Ctx newCtx(String kind, Object source, Map<String, Object> opts) {
        Object nso = opts == null ? null : opts.get("ns");
        if (!(nso instanceof String) || !NS_RE.matcher((String) nso).matches()) throw new ActionKitError("bad_ns", "ns must match [a-z][a-z0-9_]{0,31}");
        ImportLimits lim = ImportLimits.resolve(opts.get("limits"));
        String digest;
        if (source instanceof String) {
            lim.textSizeCheck((String) source);
            digest = Keys.b64u(Jx.sha256(Jx.utf8((String) source)));
        } else if (source instanceof byte[]) {
            if (((byte[]) source).length > lim.maxBytes) throw new ActionKitError("import_limit", "the source is larger than " + lim.maxBytes + " bytes");
            digest = Keys.b64u(Jx.sha256((byte[]) source));
        } else {
            lim.checkParsed(source);
            digest = Keys.b64u(Jx.sha256(Jx.utf8(Json.canonicalize(source))));
        }
        Object now = opts.get("now") == null ? Jx.n(0) : opts.get("now");
        if (!Jx.isSafe(now) || Jx.num(now) < 0) throw new ActionKitError("bad_opts", "now must be a non-negative integer");
        Object uri = opts.get("uri") == null ? "source:" + kind : opts.get("uri");
        Object lic = opts.get("licence") == null ? "unknown" : opts.get("licence");
        Map<String, Object> src = Jx.obj("kind", kind, "uri", clip(uri, 2048), "spec_digest", digest, "licence", clip(lic, 128), "imported_at", now);
        Set<Object> ext = new LinkedHashSet<>();
        Object ae = opts.get("allowExtensions");
        if (ae == null) ext.addAll(DEFAULT_EXTENSIONS); else ext.addAll(Jx.spreadList(ae));
        return new Ctx((String) nso, kind, lim, src, ext, source);
    }

    public static void addTodo(Ctx c, String where, String code, String message) {
        // a hostile spec could make millions of todos: keep the first 5,000 and one sentinel
        if (c.todo.size() < 5000) c.todo.add(Jx.obj("where", clip(where, 200), "code", code, "message", clip(message, 400)));
        else if (c.todo.size() == 5000) c.todo.add(Jx.obj("where", "*", "code", "todo_truncated", "message", "further notes omitted"));
    }

    public static Map<String, Object> finish(Ctx c) { return Jx.obj("defs", c.defs, "todo", c.todo, "source", c.source); }

    // ---- text hygiene ----

    private static boolean ctrl(char c) {
        return (c <= 8) || c == 0x0B || c == 0x0C || (c >= 0x0E && c <= 0x1F) || (c >= 0x7F && c <= 0x9F) || c == 0x2028 || c == 0x2029 || (c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069);
    }

    private static int u8cp(int cp) { return cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4; }

    /** NFC, no lone surrogates, no control or bidi-override characters, whitespace collapsed, cut to {@code maxBytes} at a code point. */
    public static String clip(Object o, int maxBytes) {
        if (!(o instanceof String)) return "";
        String s = (String) o;
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) { if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { b.append(c).append(s.charAt(++i)); } continue; }
            if (Character.isLowSurrogate(c)) continue;
            b.append(ctrl(c) ? ' ' : c);
        }
        String n = Normalizer.normalize(b.toString(), Normalizer.Form.NFC);
        StringBuilder w = new StringBuilder(n.length());
        boolean inSp = false;
        for (int i = 0; i < n.length(); i++) {
            char c = n.charAt(i);
            if (Jx.jsSpace(c)) { if (!inSp) w.append(' '); inSp = true; } else { w.append(c); inSp = false; }
        }
        String t = Jx.jsTrim(w.toString());
        if (Jx.u8(t) <= maxBytes) return t;
        StringBuilder out = new StringBuilder();
        int used = 0;
        for (int i = 0; i < t.length(); ) {
            int cp = t.codePointAt(i);
            if (used + u8cp(cp) > maxBytes) break;
            used += u8cp(cp);
            out.appendCodePoint(cp);
            i += Character.charCount(cp);
        }
        return Jx.jsTrim(out.toString());
    }

    /** First non-empty of the arguments, clipped. */
    public static String firstText(int max, Object... xs) {
        for (Object x : xs) { String t = clip(x, max); if (!t.isEmpty()) return t; }
        return "";
    }

    // ---- tokens and verbs ----

    private static final Pattern CAMEL1 = Pattern.compile("([a-z0-9])([A-Z])"), CAMEL2 = Pattern.compile("([A-Z]+)([A-Z][a-z])");

    /** Lowercase word tokens of a name: camelCase, snake, kebab, dotted and slashed names alike. */
    public static List<String> tokensOf(Object name) {
        String s = Normalizer.normalize(Jx.jsStr(name), Normalizer.Form.NFKD);
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) { char c = s.charAt(i); if (c < 0x300 || c > 0x36F) b.append(c); }
        s = CAMEL2.matcher(CAMEL1.matcher(b.toString()).replaceAll("$1 $2")).replaceAll("$1 $2").toLowerCase(Locale.ROOT);
        List<String> out = new ArrayList<>();
        int start = -1;
        for (int i = 0; i <= s.length(); i++) {
            boolean ok = i < s.length() && ((s.charAt(i) >= 'a' && s.charAt(i) <= 'z') || (s.charAt(i) >= '0' && s.charAt(i) <= '9'));
            if (ok && start < 0) start = i;
            if (!ok && start >= 0) { out.add(s.substring(start, i)); start = -1; }
        }
        return out;
    }

    /** Words that name an action; they lead or trail a name and become the last verb segment. */
    public static final Set<String> ACTION_WORDS = Set.of(
        "get", "list", "read", "fetch", "find", "search", "query", "show", "describe", "create", "add", "new", "make", "insert", "post", "put", "set", "update", "patch", "edit", "modify",
        "delete", "remove", "destroy", "drop", "send", "notify", "publish", "invite", "cancel", "refund", "charge", "pay", "run", "exec", "execute", "invoke", "start", "stop",
        "enable", "disable", "approve", "reject", "close", "open", "merge", "export", "import", "upload", "download", "subscribe", "unsubscribe", "revoke", "grant", "transfer");

    private static String seg(List<String> toks) {
        String s = String.join("_", toks);
        if (s.length() <= 32) return s;
        String h = Keys.b64u(Jx.sha256(Jx.utf8(s))).replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT);
        h = h.length() > 4 ? h.substring(0, 4) : h;
        StringBuilder pad = new StringBuilder(h);
        while (pad.length() < 4) pad.append('0');
        return s.substring(0, 27) + "_" + pad;
    }

    /**
     * A verb {@code <ns>.<noun...>.<action>} from a raw operation name. Explicit separators ({@code . / :} and white space) each become a
     * segment; a camelCase or snake name with a leading or trailing action word becomes {@code <noun>.<action>}; any other name is one segment.
     */
    public static String verbOf(String ns, Object raw) {
        String r = Jx.jsStr(raw);
        List<List<String>> parts = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i <= r.length(); i++) {
            if (i == r.length() || r.charAt(i) == '.' || r.charAt(i) == '/' || r.charAt(i) == ':' || Jx.jsSpace(r.charAt(i))) {
                List<String> t = tokensOf(cur.toString());
                if (!t.isEmpty()) parts.add(t);
                cur.setLength(0);
            } else cur.append(r.charAt(i));
        }
        List<String> segs = new ArrayList<>();
        if (parts.size() >= 2) { for (List<String> p : parts) segs.add(seg(p)); }
        else {
            List<String> t = parts.isEmpty() ? List.of("op") : parts.get(0);
            if (t.size() >= 2 && ACTION_WORDS.contains(t.get(0))) { segs.add(seg(t.subList(1, t.size()))); segs.add(seg(List.of(t.get(0)))); }
            else if (t.size() >= 2 && ACTION_WORDS.contains(t.get(t.size() - 1))) { segs.add(seg(t.subList(0, t.size() - 1))); segs.add(seg(List.of(t.get(t.size() - 1)))); }
            else segs.add(seg(t));
        }
        if (segs.size() > 5) { List<String> k = new ArrayList<>(segs.subList(0, 2)); k.addAll(segs.subList(segs.size() - 3, segs.size())); segs = k; }
        String v = ns + "." + String.join(".", segs);
        if (!VERB_RE.matcher(v).matches() || Jx.u8(v) > 128) return ns + ".op";
        return v;
    }

    /** The short NL-layer alias of a raw name (snake tokens), or null when it is not a valid alias or equals the verb. */
    public static String aliasOf(Object raw, String verb) {
        String a = String.join("_", tokensOf(raw));
        return !a.isEmpty() && a.length() <= 64 && ALIAS_RE.matcher(a).matches() && !a.equals(verb) ? a : null;
    }

    /** "createCustomer" to "Create customer": the title when the source gave none. */
    public static String humanize(Object name) {
        List<String> t = tokensOf(name);
        if (t.isEmpty()) return "";
        StringBuilder b = new StringBuilder(t.get(0).substring(0, 1).toUpperCase(Locale.ROOT)).append(t.get(0).substring(1));
        for (int i = 1; i < t.size(); i++) b.append(' ').append(t.get(i));
        return b.toString();
    }

    /** Make {@code verb} unique inside the import ({@code _2}, {@code _3} on the last segment), noting the collision. */
    public static String uniqueVerb(Ctx c, String verb, String where) {
        if (!c.verbs.contains(verb)) return verb;
        for (int n = 2; n < 100_000; n++) {
            String sfx = "_" + n;
            int dot = verb.lastIndexOf('.');
            String last = verb.substring(dot + 1);
            String cand = verb.substring(0, dot + 1) + last.substring(0, Math.min(last.length(), 32 - sfx.length())) + sfx;
            if (!c.verbs.contains(cand) && VERB_RE.matcher(cand).matches()) {
                addTodo(c, where, "duplicate_verb", "verb '" + verb + "' is taken by an earlier operation; this one is '" + cand + "'");
                return cand;
            }
        }
        throw new ActionKitError("import_limit", "too many operations map to one verb");
    }

    // ---- JSON Schema: bounded resolution ----

    static boolean isObj(Object v) { return v instanceof Map; }
    static boolean own(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    private static final Pattern INDEX_RE = Pattern.compile("0|[1-9][0-9]{0,9}");

    /** Follow a local {@code #/a/b} JSON pointer in {@code root}; null when absent, not local, or not an object. */
    public static Object pointer(Object root, Object refO) {
        if (!(refO instanceof String) || !((String) refO).startsWith("#/")) return null;
        String ref = (String) refO;
        Object cur = root;
        String rest = ref.substring(2);
        int from = 0;
        while (true) {
            int j = rest.indexOf('/', from);
            String raw = j < 0 ? rest.substring(from) : rest.substring(from, j);
            String s = raw.replace("~1", "/").replace("~0", "~");
            String seg = Jx.decodeUriComponent(s);
            if (seg == null) seg = s;
            if (cur instanceof Map) {
                if (!((Map<?, ?>) cur).containsKey(seg)) return null;
                cur = ((Map<?, ?>) cur).get(seg);
            } else if (cur instanceof List) {
                if (!INDEX_RE.matcher(seg).matches() || Long.parseLong(seg) >= ((List<?>) cur).size()) {
                    // an array's own "length" is a number: no object results either way
                    return null;
                }
                cur = ((List<?>) cur).get(Integer.parseInt(seg));
            } else return null;
            if (j < 0) break;
            from = j + 1;
        }
        return cur instanceof Map || cur instanceof List ? cur : null;
    }

    private static Map<String, Object> mergeAll(Map<String, Object> a, Map<String, Object> m) {
        Map<String, Object> out = new LinkedHashMap<>(a);
        out.putAll(m);
        Map<String, Object> props = new LinkedHashMap<>();
        Jx.spread(props, a.get("properties"));
        Jx.spread(props, m.get("properties"));
        List<Object> req = new ArrayList<>();
        if (a.get("required") != null) req.addAll(Jx.spreadList(a.get("required")));
        if (m.get("required") != null) req.addAll(Jx.spreadList(m.get("required")));
        out.put("properties", props);
        out.put("required", req);
        return out;
    }

    private static Map<String, Object> without(Map<String, Object> m, String... ks) {
        Map<String, Object> out = new LinkedHashMap<>(m);
        for (String k : ks) out.remove(k);
        return out;
    }

    private static boolean isNullType(Object t) {
        if ("null".equals(t)) return true;
        if (t instanceof List && !((List<?>) t).isEmpty()) { for (Object x : (List<?>) t) if (!"null".equals(x)) return false; return true; }
        return false;
    }

    public static Map<String, Object> resolveSchema(Object s, Ctx c, Budget bud, String where) { return resolveSchema(s, c, bud, where, List.of(), 0); }

    /**
     * Resolve what a parameter declaration cannot carry: follow local {@code $ref}s, merge {@code allOf}, collapse {@code anyOf}/{@code oneOf} to
     * the single non-null variant or to a union of string constants. What stays unrepresentable is noted in the todo list and left as {@code {}}.
     */
    public static Map<String, Object> resolveSchema(Object s, Ctx c, Budget bud, String where, List<String> chain, int depth) {
        if (!(s instanceof Map)) return new LinkedHashMap<>();
        if (bud.left <= 0) {
            if (!bud.exhausted) {
                bud.exhausted = true;
                addTodo(c, where, "ref_budget", "schema expansion stopped after " + c.lim.maxRefNodes + " nodes (declared string; refine or drop)");
            }
            return new LinkedHashMap<>();
        }
        bud.left--;
        if (depth > c.lim.maxRefDepth) {
            addTodo(c, where, "ref_depth", "schema nesting or reference chain deeper than " + c.lim.maxRefDepth + " (declared string; refine or drop)");
            return new LinkedHashMap<>();
        }
        Map<String, Object> cur = Jx.m(s);
        if (cur.get("$ref") instanceof String) {
            String ref = (String) cur.get("$ref");
            if (chain.contains(ref)) {
                addTodo(c, where, "cyclic_ref", "reference '" + clip(ref, 120) + "' is cyclic (declared string; refine or drop)");
                return new LinkedHashMap<>();
            }
            Object target = pointer(c.root, ref);
            if (target == null) {
                addTodo(c, where, "unresolved_ref", "reference '" + clip(ref, 120) + "' is not a local reference that resolves (declared string; refine or drop)");
                return new LinkedHashMap<>();
            }
            List<String> nc = new ArrayList<>(chain);
            nc.add(ref);
            Map<String, Object> merged = new LinkedHashMap<>(resolveSchema(target, c, bud, where, nc, depth + 1));
            merged.putAll(without(cur, "$ref"));
            cur = merged;
        }
        if (cur.get("allOf") instanceof List) {
            Map<String, Object> rest = without(cur, "allOf");
            List<Map<String, Object>> rs = new ArrayList<>();
            for (Object m : Jx.a(cur.get("allOf"))) rs.add(resolveSchema(m, c, bud, where, chain, depth + 1));
            Map<String, Object> acc = new LinkedHashMap<>();
            for (Map<String, Object> m : rs) acc = mergeAll(acc, m);
            Map<String, Object> n = new LinkedHashMap<>(acc);
            n.putAll(rest);
            cur = n;
        }
        List<Object> alts = cur.get("anyOf") instanceof List ? Jx.a(cur.get("anyOf")) : cur.get("oneOf") instanceof List ? Jx.a(cur.get("oneOf")) : null;
        if (alts != null) {
            Map<String, Object> rest = without(cur, "anyOf", "oneOf");
            List<Map<String, Object>> live = new ArrayList<>();
            List<Map<String, Object>> all = new ArrayList<>();
            for (Object m : alts) all.add(resolveSchema(m, c, bud, where, chain, depth + 1));
            for (Map<String, Object> m : all) if (!isNullType(m.get("type"))) live.add(m);
            if (live.size() == 1) { Map<String, Object> out = new LinkedHashMap<>(live.get(0)); out.putAll(rest); return out; }
            List<List<Object>> consts = new ArrayList<>();
            boolean allConst = true;
            for (Map<String, Object> m : live) {
                List<Object> k = null;
                if (m.get("const") instanceof String) k = List.of(m.get("const"));
                else if (m.get("enum") instanceof List && Jx.a(m.get("enum")).stream().allMatch(x -> x instanceof String)) k = Jx.a(m.get("enum"));
                if (k == null) allConst = false;
                consts.add(k);
            }
            if (live.size() > 1 && allConst) {
                Map<String, Object> out = new LinkedHashMap<>(rest);
                out.put("type", "string");
                Set<Object> u = new LinkedHashSet<>();
                for (List<Object> k : consts) u.addAll(k);
                out.put("enum", new ArrayList<>(u));
                return out;
            }
            addTodo(c, where, "union", "a union of " + live.size() + " schemas has no representation (declared string; refine or drop)");
            return rest;
        }
        if (cur.get("const") instanceof String && !cur.containsKey("enum")) {
            Map<String, Object> n = new LinkedHashMap<>(cur);
            n.put("enum", Jx.list(cur.get("const")));
            cur = n;
        }
        return cur;
    }

    // ---- JSON Schema to params ----

    /** Param name segment hygiene: {@code [A-Za-z0-9_]{1,64}}; anything else is replaced by {@code _}. */
    public static String paramSeg(String raw) {
        StringBuilder b = new StringBuilder(raw.length());
        boolean allUs = true;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
            b.append(ok ? c : '_');
            if (c != '_' && ok) allUs = false;
            if (!ok) { /* replaced by an underscore */ }
        }
        String s = allUs ? "" : b.toString();
        if (s.length() > 64) s = s.substring(0, 64);
        return s.isEmpty() ? "p" : s;
    }

    private static final Map<String, String> FORMATS = Map.of("email", "email", "uuid", "uuid", "uri", "url", "url", "url", "idn-email", "email", "semver", "semver");
    private static final Set<String> RESERVED = Set.of("__proto__", "constructor", "prototype");
    private static final Set<String> INT_ROLES = Set.of("money.amount", "money.fee", "count.limit", "bytes.size");

    private static boolean isRoleOk(String r) {
        return ActionsBridge.coreRoles().contains(r) || ID_ROLE_RE.matcher(r).matches() || X_ROLE_RE.matcher(r).matches();
    }

    private static boolean plainStr(Object x) {
        if (!(x instanceof String)) return false;
        String s = (String) x;
        if (s.isEmpty() || Jx.u8(s) > 256 || !Normalizer.isNormalized(s, Normalizer.Form.NFC)) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { i++; continue; }
            if (Character.isSurrogate(c)) return false;
        }
        return true;
    }

    private static List<Object> enumStrOf(Object en) {
        if (!(en instanceof List)) return null;
        List<Object> l = Jx.a(en);
        if (l.isEmpty() || l.size() > 256) return null;
        for (Object x : l) if (!plainStr(x)) return null;
        return new ArrayList<>(new LinkedHashSet<>(l));
    }

    private static Object firstNonNull(Object t) {
        if (t instanceof List) { for (Object x : Jx.a(t)) if (!"null".equals(x)) return x; return null; }
        return t;
    }

    private static Object numOf(double v) { return new Json.Num(AttestCommon.jsNumString(v)); }

    /** A leaf schema to a param def. Unrepresentable shapes become {@code string} placeholders, noted. */
    public static Map<String, Object> leafParam(Map<String, Object> s, boolean required, Ctx c, Budget bud, String where) {
        Object t0 = firstNonNull(s.get("type"));
        List<Object> enumStr = enumStrOf(s.get("enum"));
        Object t = t0 != null ? t0 : enumStr != null ? "string" : (s.get("items") instanceof List || s.get("items") instanceof Map) ? "array" : null;
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("type", "string");
        if (!required) base.put("required", Boolean.FALSE);
        String desc = clip(s.get("description"), 280);
        if (!desc.isEmpty()) base.put("description", desc);
        String roleExt = c.ext.contains("x-pca-role") && s.get("x-pca-role") instanceof String ? (String) s.get("x-pca-role") : null;
        java.util.function.UnaryOperator<Map<String, Object>> withRole = p -> {
            if (roleExt == null) return p;
            if (!isRoleOk(roleExt) || (INT_ROLES.contains(roleExt) && !"integer".equals(p.get("type")))) {
                addTodo(c, where, "role_ignored", "x-pca-role '" + clip(roleExt, 64) + "' is not valid for a " + Jx.jsStr(p.get("type")) + " parameter");
                return p;
            }
            Map<String, Object> q = new LinkedHashMap<>(p);
            q.put("role", roleExt);
            return q;
        };
        if ("integer".equals(t) || ("number".equals(t) && ("int32".equals(s.get("format")) || "int64".equals(s.get("format"))))) {
            Map<String, Object> p = new LinkedHashMap<>(base);
            p.put("type", "integer");
            Object mn = s.get("minimum"), mx = s.get("maximum"), exMin = s.get("exclusiveMinimum"), exMax = s.get("exclusiveMaximum");
            if (Jx.isInt(mn) && !Boolean.TRUE.equals(exMin)) p.put("min", mn);
            else if (Jx.isInt(exMin)) p.put("min", numOf(Jx.num(exMin) + 1));
            else if (Jx.isInt(mn) && Boolean.TRUE.equals(exMin)) p.put("min", numOf(Jx.num(mn) + 1));
            if (Jx.isInt(mx) && !Boolean.TRUE.equals(exMax)) p.put("max", mx);
            else if (Jx.isInt(exMax)) p.put("max", numOf(Jx.num(exMax) - 1));
            else if (Jx.isInt(mx) && Boolean.TRUE.equals(exMax)) p.put("max", numOf(Jx.num(mx) - 1));
            if (p.containsKey("min") && p.containsKey("max") && Jx.num(p.get("min")) > Jx.num(p.get("max"))) { p.remove("min"); p.remove("max"); }
            return withRole.apply(p);
        }
        if ("boolean".equals(t)) { Map<String, Object> p = new LinkedHashMap<>(base); p.put("type", "boolean"); return withRole.apply(p); }
        if ("string".equals(t)) {
            String f = s.get("format") instanceof String ? (String) s.get("format") : "";
            Map<String, Object> p = new LinkedHashMap<>(base);
            if (f.equals("date")) { p.put("type", "date"); return withRole.apply(p); }
            if (f.equals("date-time")) { p.put("type", "datetime"); return withRole.apply(p); }
            if (enumStr != null) p.put("values", enumStr);
            else if (s.get("enum") instanceof List && !Jx.a(s.get("enum")).isEmpty()) addTodo(c, where, "enum_dropped", "enum values are not 1..256 plain strings (declared as a free string; refine)");
            if (FORMATS.containsKey(f)) p.put("format", FORMATS.get(f));
            Object ml = s.get("maxLength");
            if (Jx.isInt(ml) && Jx.num(ml) > 0 && Jx.num(ml) <= 16_777_216) p.put("max_len", ml);
            return withRole.apply(p);
        }
        if ("array".equals(t)) {
            Map<String, Object> it = resolveSchema(s.get("items"), c, bud, where + "[]");
            List<Object> itEnum = enumStrOf(it.get("enum"));
            Map<String, Object> lim = new LinkedHashMap<>();
            Object mi = s.get("maxItems"), ni = s.get("minItems");
            if (Jx.isInt(mi) && Jx.num(mi) >= 0) lim.put("max_items", mi);
            if (Jx.isInt(ni) && Jx.num(ni) >= 0) lim.put("min_items", ni);
            if (lim.containsKey("min_items") && lim.containsKey("max_items") && Jx.num(lim.get("min_items")) > Jx.num(lim.get("max_items"))) { lim.remove("min_items"); lim.remove("max_items"); }
            if (Boolean.TRUE.equals(s.get("uniqueItems")) && itEnum != null) {
                Map<String, Object> p = new LinkedHashMap<>(base);
                p.put("type", "set");
                p.put("values", itEnum);
                p.putAll(lim);
                return withRole.apply(p);
            }
            Object itT = firstNonNull(it.get("type"));
            String items = "integer".equals(itT) ? "integer" : "string".equals(itT) ? "string" : "boolean".equals(itT) ? "boolean" : null;
            if (items == null && itT != null) addTodo(c, where, "array_items", "array items of type '" + clip(Jx.jsStr(itT), 40) + "' are not declared (items left open)");
            Map<String, Object> p = new LinkedHashMap<>(base);
            p.put("type", "array");
            if (items != null) p.put("items", items);
            p.putAll(lim);
            return withRole.apply(p);
        }
        if ("number".equals(t)) addTodo(c, where, "unsupported_type", "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)");
        else addTodo(c, where, "unsupported_type", "type '" + clip(t == null ? "none" : Jx.jsStr(t), 40) + "' has no representation (declared string; refine or drop)");
        Map<String, Object> p = new LinkedHashMap<>(base);
        p.put("type", "string");
        return withRole.apply(p);
    }

    /** Assign a schema property the way {@code obj[name] = v} does: the engine's {@code __proto__} setter keeps no member. */
    static void putProp(Map<String, Object> m, String name, Object v) { if (!"__proto__".equals(name)) m.put(name, v); }

    /**
     * Flatten an object schema into params: nested objects become dotted names up to three segments; an object below that (or without
     * properties) is a {@code string} placeholder; a child of an optional parent is optional. At most 64 params; the rest are dropped, noted.
     */
    public static void flattenObject(Map<String, Object> schema, Ctx c, Budget bud, String where, Map<String, Object> out) { flattenObject(schema, c, bud, where, out, List.of(), true); }

    @SuppressWarnings("unchecked")
    static void flattenObject(Map<String, Object> schema, Ctx c, Budget bud, String where, Map<String, Object> out, List<String> prefix, boolean parentRequired) {
        Map<String, Object> props = isObj(schema.get("properties")) ? (Map<String, Object>) schema.get("properties") : new LinkedHashMap<>();
        Set<String> req = new LinkedHashSet<>();
        if (schema.get("required") instanceof List) for (Object x : Jx.a(schema.get("required"))) if (x instanceof String) req.add((String) x);
        List<String> names = new ArrayList<>(props.keySet());
        names.sort(IntentJs::compareUtf8);
        for (String name : names) {
            if (RESERVED.contains(name)) { addTodo(c, where + ": " + name, "skipped_param", "parameter name '" + name + "' is reserved; dropped"); continue; }
            Map<String, Object> child = resolveSchema(props.get(name), c, bud, where + ": " + name);
            if (Boolean.TRUE.equals(child.get("readOnly"))) continue;
            String sname = paramSeg(name);
            if (!sname.equals(name)) addTodo(c, where + ": " + name, "renamed_param", "parameter '" + clip(name, 80) + "' is declared as '" + sname + "'");
            List<String> path = new ArrayList<>(prefix);
            path.add(sname);
            String full = String.join(".", path);
            boolean required = parentRequired && req.contains(name);
            boolean isObject = "object".equals(child.get("type")) || (!child.containsKey("type") && isObj(child.get("properties")));
            if (isObject && isObj(child.get("properties")) && !Jx.m(child.get("properties")).isEmpty() && path.size() < MAX_PARAM_PATH_DEPTH) {
                flattenObject(child, c, bud, where + ": " + full, out, path, required);
                continue;
            }
            if (out.size() >= MAX_DEF_PARAMS) { addTodo(c, where, "too_many_params", "more than " + MAX_DEF_PARAMS + " parameters; '" + full + "' and the rest are dropped"); return; }
            boolean clash = out.containsKey(full);
            if (!clash) for (String k : out.keySet()) if (k.startsWith(full + ".") || full.startsWith(k + ".")) { clash = true; break; }
            if (clash) { addTodo(c, where + ": " + full, "skipped_param", "parameter '" + full + "' collides with another; kept the first"); continue; }
            out.put(full, isObject ? placeholderObject(child, required, c, where + ": " + full) : leafParam(child, required, c, bud, where + ": " + full));
        }
    }

    private static Map<String, Object> placeholderObject(Map<String, Object> s, boolean required, Ctx c, String where) {
        addTodo(c, where, "object_leaf", "an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)");
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("type", "string");
        if (!required) p.put("required", Boolean.FALSE);
        String d = clip(s.get("description"), 280);
        if (!d.isEmpty()) p.put("description", d);
        return p;
    }

    // ---- assembling a draft def ----

    /** A draft operation: what the importer knows before the def is assembled. */
    public static final class Draft {
        /** Raw operation name (operationId, tool name, field, rpc, ...). */
        public Object name;
        public String verb;
        public Object title, description;
        public List<String> effects;
        public String scope;
        public Map<String, Object> params;
        public Map<String, Object> idempotency;
        public List<String> traits;
        public boolean noAlias;
        public Map<String, Object> bindings;
    }

    /** Assemble, validate and register a draft def. A def that fails validation is dropped, noted (never emitted). Returns the def or null. */
    public static Map<String, Object> emitDef(Ctx c, Draft d) {
        if (c.defs.size() >= c.lim.maxOps) throw new ActionKitError("import_limit", "more than " + c.lim.maxOps + " operations");
        String rawVerb = d.verb != null ? d.verb : verbOf(c.ns, d.name);
        String verb = uniqueVerb(c, VERB_RE.matcher(rawVerb).matches() ? rawVerb : verbOf(c.ns, d.name), Jx.jsStr(d.name));
        String[] segs = verb.split("\\.", -1);
        String rtype = segs.length > 2 ? String.join(".", java.util.Arrays.copyOf(segs, segs.length - 1)) : segs[0];
        String title = firstText(MAX_TITLE_BYTES, d.title, humanize(d.name), verb);
        String description = clip(d.description, Math.min(MAX_DESCRIPTION_BYTES, 600));
        String alias = d.noAlias ? null : aliasOf(d.name, verb);
        Map<String, Object> def = new LinkedHashMap<>();
        def.put("v", Jx.n(1));
        def.put("kind", "pca-action-def");
        def.put("verb", verb);
        if (alias != null && !c.aliases.containsKey(alias) && !c.verbs.contains(alias)) def.put("aliases", Jx.list(alias));
        def.put("title", title.isEmpty() ? verb : title);
        if (!description.isEmpty()) def.put("description", description);
        def.put("effects", new ArrayList<Object>(new TreeSet<>(d.effects)));
        def.put("resource", Jx.obj("type", RTYPE_RE.matcher(rtype).matches() ? rtype : segs[0], "id", Jx.obj("prefix", "", "class", "any_safe", "len", Jx.list(Jx.n(1), Jx.n(128))), "scope", d.scope));
        def.put("params", d.params);
        if (d.idempotency != null) def.put("idempotency", d.idempotency);
        if (d.traits != null && !d.traits.isEmpty()) def.put("traits", new ArrayList<Object>(new TreeSet<>(d.traits)));
        def.put("bindings", d.bindings);
        def.put("review", Jx.obj("state", "unreviewed"));
        def.put("source", Jx.obj("kind", c.source.get("kind"), "uri", c.source.get("uri"), "spec_digest", c.source.get("spec_digest"), "licence", c.source.get("licence"), "imported_at", c.source.get("imported_at")));
        String bad = Actions.validateDef(def);
        if (bad != null) {
            addTodo(c, Jx.jsStr(d.name), "invalid_def", "not emitted: " + bad);
            return null;
        }
        c.verbs.add(verb);
        if (def.get("aliases") != null) c.aliases.put((String) Jx.a(def.get("aliases")).get(0), verb);
        c.defs.add(def);
        return def;
    }

    /** Add a declared trait to a draft (used for hint-derived traits such as network egress). */
    public static List<String> withTrait(List<String> traits, String t) {
        Set<String> s = new LinkedHashSet<>(traits == null ? List.<String>of() : traits);
        s.add(t);
        return new ArrayList<>(s);
    }
}
