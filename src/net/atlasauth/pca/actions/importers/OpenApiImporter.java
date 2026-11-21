package net.atlasauth.pca.actions.importers;

import static net.atlasauth.pca.actions.importers.ImportCommon.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import net.atlasauth.pca.Actions.ActionKitError;
import net.atlasauth.pca.IntentJs;

/** OpenAPI 3.x and Swagger 2 to drafts: one def per operation; the method gives the initial effects. */
public final class OpenApiImporter {
    private OpenApiImporter() {}

    private static final List<String> METHODS = List.of("get", "put", "post", "delete", "options", "head", "patch", "trace");
    private static final Map<String, String> EFFECT_OF = Map.of("get", "read", "head", "read", "options", "read", "trace", "read", "post", "create", "put", "update", "patch", "update", "delete", "delete");
    private static final Set<String> NATURAL = Set.of("get", "head", "options", "trace", "put", "delete");
    private static final List<String> BODY_TYPES = List.of("application/json", "application/x-www-form-urlencoded", "multipart/form-data");
    private static final Pattern VERSIONISH = Pattern.compile("(?:v[0-9]+(?:\\.[0-9]+)?|api|rest|public|latest)", Pattern.CASE_INSENSITIVE);
    private static final Pattern JSON_SUFFIX = Pattern.compile("^application/[^;]*\\+json(?:;|\\z)", Pattern.CASE_INSENSITIVE);
    private static final Pattern X_VERB = Pattern.compile("[a-z][a-z0-9_]{0,31}(?:\\.[a-z0-9_]{1,32}){1,5}");

    /** Follow a {@code $ref} chain (local only, bounded); returns the target (object or array), or null after noting why. */
    private static Object deref(Ctx c, Object x, String where) {
        if (!(x instanceof Map)) return null;
        if (!(Jx.m(x).get("$ref") instanceof String)) return x;
        Set<String> seen = new LinkedHashSet<>();
        Object cur = x;
        while (cur instanceof Map && Jx.m(cur).get("$ref") instanceof String) {
            String ref = (String) Jx.m(cur).get("$ref");
            if (seen.contains(ref) || seen.size() > c.lim.maxRefDepth) { addTodo(c, where, "cyclic_ref", "a reference chain is cyclic or too deep"); return null; }
            seen.add(ref);
            Object t = pointer(c.root, ref);
            if (t == null) { addTodo(c, where, "unresolved_ref", "reference '" + clip(ref, 120) + "' does not resolve locally"); return null; }
            cur = t;
        }
        return cur;
    }

    private static boolean endsWithParam(String seg) {
        if (seg.length() < 3 || seg.charAt(0) != '{' || seg.charAt(seg.length() - 1) != '}') return false;
        for (int i = 1; i < seg.length() - 1; i++) { char ch = seg.charAt(i); if (ch == '\n' || ch == '\r' || ch == ' ' || ch == ' ') return false; }
        return true;
    }

    /** Path to the noun tokens and whether it ends in a path parameter. */
    private static Object[] pathFacts(String path) {
        List<String> segs = new ArrayList<>();
        for (String s : path.split("/", -1)) if (!s.isEmpty()) segs.add(s);
        boolean ewp = !segs.isEmpty() && endsWithParam(segs.get(segs.size() - 1));
        List<String> nouns = new ArrayList<>();
        for (String s : segs) if (s.indexOf('{') < 0 && s.indexOf('}') < 0 && !VERSIONISH.matcher(s).matches()) nouns.addAll(tokensOf(s));
        return new Object[] {nouns, ewp};
    }

    /** A Swagger 2 parameter in the OpenAPI 3 shape the rest of the importer reads. */
    private static Map<String, Object> swagger2Param(Map<String, Object> p) {
        if (p.containsKey("schema") || "body".equals(p.get("in"))) return p;
        Map<String, Object> sch = new LinkedHashMap<>(p);
        Map<String, Object> out = new LinkedHashMap<>();
        for (String k : List.of("name", "in", "required", "description")) { if (p.containsKey(k)) out.put(k, p.get(k)); sch.remove(k); }
        out.put("schema", sch);
        return out;
    }

    private static String lowerTrimType(String k) {
        String l = k.toLowerCase(Locale.ROOT);
        int i = l.indexOf(';');
        return Jx.jsTrim(i < 0 ? l : l.substring(0, i));
    }

    /** The request body schema: Jx.UNDEF when there is none to declare. */
    private static Object bodySchemaOf(Ctx c, Map<String, Object> op, List<Map<String, Object>> params, boolean swagger, String where) {
        if (swagger) {
            for (Map<String, Object> q : params) if ("body".equals(q.get("in"))) return Jx.getU(q, "schema");
            return Jx.UNDEF;
        }
        Object rb = deref(c, Jx.getU(op, "requestBody") == Jx.UNDEF ? null : op.get("requestBody"), where);
        Object content = Jx.get(rb, "content");
        if (!(content instanceof Map)) return Jx.UNDEF;
        List<String> keys = new ArrayList<>(Jx.m(content).keySet());
        keys.sort(IntentJs::compareUtf8);
        String pick = null;
        for (String t : BODY_TYPES) {
            for (String k : keys) if (lowerTrimType(k).equals(t)) { pick = k; break; }
            if (pick != null) break;
        }
        if (pick == null) for (String k : keys) if (JSON_SUFFIX.matcher(k).find()) { pick = k; break; }
        if (pick == null) {
            if (!keys.isEmpty()) {
                List<String> f = new ArrayList<>();
                for (String k : keys.subList(0, Math.min(3, keys.size()))) f.add(clip(k, 40));
                addTodo(c, where, "body_type", "request body media types (" + String.join(", ", f) + ") are not form or JSON; the body is not declared");
            }
            return Jx.UNDEF;
        }
        return Jx.getU(Jx.m(content).get(pick), "schema");
    }

    private static boolean isIdemKey(String name) {
        return name.length() == 15 && name.toLowerCase(Locale.ROOT).equals("idempotency-key") && asciiOnly(name);
    }

    private static boolean asciiOnly(String s) { for (int i = 0; i < s.length(); i++) if (s.charAt(i) > 0x7f) return false; return true; }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> importOpenApi(Object source, Map<String, Object> opts) {
        Ctx c = newCtx("openapi", source, opts);
        if (!(source instanceof Map)) throw new ActionKitError("bad_source", "an OpenAPI document must be an object");
        Map<String, Object> src = Jx.m(source);
        boolean swagger = src.get("swagger") instanceof String && ((String) src.get("swagger")).startsWith("2");
        boolean v3 = src.get("openapi") instanceof String && ((String) src.get("openapi")).matches("3\\.(?s:.*)");
        if (!swagger && !v3) throw new ActionKitError("bad_source", "not an OpenAPI 3.x or Swagger 2 document (missing 'openapi: 3.x' or 'swagger: 2.0')");
        Map<String, Object> paths = src.get("paths") instanceof Map ? Jx.m(src.get("paths")) : new LinkedHashMap<>();
        List<Object> globalSecurity = src.get("security") instanceof List ? Jx.a(src.get("security")) : null;
        String ns = (String) opts.get("ns");
        List<String> pathKeys = new ArrayList<>(paths.keySet());
        pathKeys.sort(IntentJs::compareUtf8);
        for (String path : pathKeys) {
            Object item0 = deref(c, paths.get(path), path);
            if (item0 == null) continue;
            List<Object> shared = Jx.get(item0, "parameters") instanceof List ? Jx.a(Jx.get(item0, "parameters")) : new ArrayList<>();
            for (String method : METHODS) {
                Object opO = Jx.get(item0, method);
                if (!(opO instanceof Map)) continue;
                Map<String, Object> op = Jx.m(opO);
                String where = method.toUpperCase(Locale.ROOT) + " " + clip(path, 120);
                Object oid = op.get("operationId");
                String operationId = oid instanceof String && !((String) oid).isEmpty() && ((String) oid).length() <= 200 ? (String) oid : null;
                Object[] pf = pathFacts(path);
                List<String> nouns = (List<String>) pf[0];
                boolean ewp = (Boolean) pf[1];
                String nameRaw = op.get("x-pca-verb") instanceof String && c.ext.contains("x-pca-verb") ? (String) op.get("x-pca-verb") : null;
                String verb;
                if (nameRaw != null && X_VERB.matcher(nameRaw).matches() && nameRaw.startsWith(ns + ".")) verb = nameRaw;
                else if (operationId != null) verb = verbOf(ns, operationId);
                else {
                    List<String> w = new ArrayList<>(nouns.subList(Math.max(0, nouns.size() - 2), nouns.size()));
                    w.add(method.equals("get") && !ewp ? "list" : method);
                    verb = verbOf(ns, String.join(" ", w));
                }
                c.root = source;
                Budget bud = newBudget(c);
                // parameters: the operation's own win over the path item's (by in+name)
                Map<String, Map<String, Object>> merged = new LinkedHashMap<>();
                List<Object> raws = new ArrayList<>(shared);
                if (op.get("parameters") instanceof List) raws.addAll(Jx.a(op.get("parameters")));
                for (Object raw : raws) {
                    Object q0o = deref(c, raw, where);
                    if (!(q0o instanceof Map)) continue;
                    Map<String, Object> q0 = Jx.m(q0o);
                    if (!(q0.get("name") instanceof String) || !(q0.get("in") instanceof String)) continue;
                    Map<String, Object> q = swagger ? swagger2Param(q0) : q0;
                    merged.put(q.get("in") + ":" + q.get("name"), q);
                }
                List<Map<String, Object>> all = new ArrayList<>(merged.values());
                Map<String, Object> params = new LinkedHashMap<>();
                String idemParam = null;
                Object body = bodySchemaOf(c, op, all, swagger, where);
                if (body != Jx.UNDEF) {
                    Map<String, Object> b = resolveSchema(body, c, bud, where + ": request body");
                    if ("object".equals(b.get("type")) || b.get("properties") instanceof Map) flattenObject(b, c, bud, where, params);
                    else addTodo(c, where, "body_shape", "the request body is not an object schema; it is not declared");
                }
                List<Map<String, Object>> sorted = new ArrayList<>(all);
                sorted.sort((a, b) -> IntentJs.compareUtf8(a.get("in") + ":" + a.get("name"), b.get("in") + ":" + b.get("name")));
                for (Map<String, Object> q : sorted) {
                    String name = (String) q.get("name");
                    Object in = q.get("in");
                    if ("header".equals(in) && isIdemKey(name)) { idemParam = "idempotency_key"; continue; }
                    if ("body".equals(in)) continue;
                    if (!"path".equals(in) && !"query".equals(in) && !"formData".equals(in)) {
                        addTodo(c, where, "param_location", clip(in, 12) + " parameter '" + clip(name, 60) + "' is not an action parameter (path, query and body only)");
                        continue;
                    }
                    String sname = paramSeg(name);
                    if (!sname.equals(name)) addTodo(c, where + ": " + name, "renamed_param", "parameter '" + clip(name, 80) + "' is declared as '" + sname + "'");
                    boolean taken = params.containsKey(sname);
                    if (!taken) for (String k : params.keySet()) if (k.startsWith(sname + ".")) { taken = true; break; }
                    if (taken) {
                        addTodo(c, where + ": " + name, "skipped_param", "'" + sname + "' is declared by the body and by a " + in + " parameter; kept the body's");
                        continue;
                    }
                    if (params.size() >= 64) { addTodo(c, where, "too_many_params", "more than 64 parameters; the rest are dropped"); break; }
                    Map<String, Object> merge = new LinkedHashMap<>();
                    Object qs = q.get("schema");
                    Jx.spread(merge, qs == null ? new LinkedHashMap<String, Object>() : qs);
                    Object qsDesc = qs == null ? null : Jx.get(qs, "description");
                    if (Jx.truthy(q.get("description")) && !Jx.truthy(qsDesc)) merge.put("description", q.get("description"));
                    Map<String, Object> sch = resolveSchema(merge, c, bud, where + ": " + name);
                    params.put(sname, leafParam(sch, "path".equals(in) || Boolean.TRUE.equals(q.get("required")), c, bud, where + ": " + name));
                }
                if (idemParam != null && !params.containsKey(idemParam)) params.put(idemParam, Jx.obj("type", "string", "required", Boolean.FALSE, "max_len", Jx.n(255)));
                else idemParam = null;
                String scope = ewp || method.equals("post") ? "one" : "set";
                boolean natural = NATURAL.contains(method);
                // security scopes are a note, not a field
                List<Object> sec = op.get("security") instanceof List ? Jx.a(op.get("security")) : globalSecurity;
                List<String> scopes = new ArrayList<>();
                if (sec != null) {
                    Set<String> u = new LinkedHashSet<>();
                    for (Object r : sec) if (r instanceof Map) for (Object v : Jx.m(r).values()) if (v instanceof List) for (Object x : Jx.a(v)) if (x instanceof String) u.add((String) x);
                    scopes.addAll(u);
                    scopes.sort(IntentJs::compareUtf8);
                }
                if (!scopes.isEmpty()) {
                    List<String> f = new ArrayList<>();
                    for (String s : scopes.subList(0, Math.min(12, scopes.size()))) f.add(clip(s, 60));
                    addTodo(c, where, "required_scope", "requires scope: " + String.join(", ", f));
                }
                if (Boolean.TRUE.equals(op.get("deprecated"))) addTodo(c, where, "deprecated", "the operation is marked deprecated");
                for (String k : Jx.keys(op)) if (k.startsWith("x-") && !c.ext.contains(k)) { addTodo(c, where, "extension_ignored", "extension '" + clip(k, 60) + "' is ignored (not allow-listed)"); break; }
                Draft d = new Draft();
                d.name = operationId != null ? operationId : where;
                d.noAlias = operationId == null;
                d.verb = verb;
                d.title = op.get("summary") instanceof String && !((String) op.get("summary")).isEmpty() ? op.get("summary") : operationId;
                d.description = op.get("description") instanceof String ? op.get("description") : op.get("summary") instanceof String ? op.get("summary") : null;
                d.effects = new ArrayList<>(List.of(EFFECT_OF.get(method)));
                d.scope = scope;
                d.params = params;
                if (idemParam != null) d.idempotency = Jx.obj("mode", "key_param", "param", idemParam);
                else if (natural) d.idempotency = Jx.obj("mode", "natural");
                d.bindings = Jx.obj("openapi", Jx.obj("operationId", operationId != null ? operationId : clip(method + "_" + path, 200), "method", method.toUpperCase(Locale.ROOT), "path", clip(path, 240)));
                emitDef(c, d);
            }
        }
        return finish(c);
    }
}
