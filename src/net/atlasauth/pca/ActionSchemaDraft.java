package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The drafting importers of the action schema: they turn an MCP tool list or an OpenAPI document into a DRAFT (unsigned) action schema plus a
 * todo list of everything a human must still decide (semantic types, reversibility, anything the schema cannot represent). Pure over decoded
 * JSON. A JSON Schema is flattened first: local {@code $ref}s are followed (to a depth of 8 and at most 20000 nodes), {@code allOf} is merged,
 * and a {@code anyOf} / {@code oneOf} collapses to its one non-null member or to a string enum when every member is a string constant; any
 * other union has no representation. The wallet never trusts a draft: signing it is the site's decision.
 */
public final class ActionSchemaDraft {
    private ActionSchemaDraft() {}

    private static final int MAX_REF_DEPTH = 8;
    private static final int MAX_REF_NODES = 20_000;
    private static final Pattern PARAM_NAME = Pattern.compile("[A-Za-z0-9_]{1,64}");
    private static final Pattern JSON_SUFFIX = Pattern.compile("(?i)^application/[^;]*\\+json(;|$)");

    private static final class Ctx {
        final Object root;
        final List<String> todo;
        Integer left;

        Ctx(Object root, List<String> todo) { this.root = root; this.todo = todo; }
    }

    private static Map<String, Object> map(Object o) { return o instanceof Map ? new LinkedHashMap<>(StoreJs.map(o)) : new LinkedHashMap<>(); }

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    private static String text(Object x, boolean present) { return IntentRevocation.jsText(x, present); }

    private static String slice(Object s, int n) {
        if (!(s instanceof String)) throw new IllegalArgumentException("s.description.slice is not a function");
        return ((String) s).length() <= n ? (String) s : ((String) s).substring(0, n);
    }

    /** A local reference ({@code #/a/b}) resolved against {@code root}: the object it names, or null. */
    private static Object pointer(Object root, String ref) {
        if (!ref.startsWith("#/")) return null;
        Object cur = root;
        for (String raw : ref.substring(2).split("/", -1)) {
            String seg = raw.replace("~1", "/").replace("~0", "~");
            if (cur instanceof Map) {
                if (!((Map<?, ?>) cur).containsKey(seg)) return null;
                cur = ((Map<?, ?>) cur).get(seg);
            } else if (cur instanceof List) {
                List<?> l = (List<?>) cur;
                if (seg.matches("0|[1-9][0-9]{0,9}") && Long.parseLong(seg) < l.size()) cur = l.get(Integer.parseInt(seg));
                else if (seg.equals("length")) cur = Long.valueOf(l.size());
                else return null;
            } else {
                return null;
            }
        }
        return cur instanceof Map || cur instanceof List ? cur : null;
    }

    private static boolean isNullType(Map<String, Object> m) {
        Object t = m.get("type");
        if ("null".equals(t)) return true;
        if (t instanceof List) for (Object x : (List<?>) t) if (!"null".equals(x)) return false;
        return t instanceof List;
    }

    private static List<String> stringList(Object v) {
        if (!(v instanceof List)) return null;
        List<String> out = new ArrayList<>();
        for (Object x : (List<?>) v) {
            if (!(x instanceof String)) return null;
            out.add((String) x);
        }
        return out;
    }

    private static Map<String, Object> flatten(Object s, Ctx c, String where, int depth) {
        if (!(s instanceof Map)) return new LinkedHashMap<>();
        c.left = (c.left == null ? MAX_REF_NODES : c.left) - 1;
        if (c.left < 0) {
            if (c.left == -1) c.todo.add(where + ": schema expansion stopped after " + MAX_REF_NODES + " nodes (declared string; refine or drop)");
            return new LinkedHashMap<>();
        }
        if (depth > MAX_REF_DEPTH) {
            c.todo.add(where + ": schema nesting or reference chain deeper than " + MAX_REF_DEPTH + " (declared string; refine or drop)");
            return new LinkedHashMap<>();
        }
        Map<String, Object> cur = map(s);
        if (cur.get("$ref") instanceof String) {
            String ref = (String) cur.get("$ref");
            Object target = pointer(c.root, ref);
            if (target == null) {
                c.todo.add(where + ": reference '" + (ref.length() <= 120 ? ref : ref.substring(0, 120)) + "' is not a local reference that resolves (declared string; refine or drop)");
                return new LinkedHashMap<>();
            }
            Map<String, Object> siblings = new LinkedHashMap<>(cur);
            siblings.remove("$ref");
            cur = flatten(target, c, where, depth + 1);
            cur.putAll(siblings);
        }
        if (cur.get("allOf") instanceof List) {
            List<?> members = (List<?>) cur.get("allOf");
            Map<String, Object> rest = new LinkedHashMap<>(cur);
            rest.remove("allOf");
            Map<String, Object> acc = new LinkedHashMap<>();
            for (Object mo : members) {
                Map<String, Object> m = flatten(mo, c, where, depth + 1);
                Map<String, Object> merged = new LinkedHashMap<>(acc);
                merged.putAll(m);
                Map<String, Object> props = map(acc.get("properties"));
                props.putAll(map(m.get("properties")));
                List<Object> req = new ArrayList<>();
                if (acc.get("required") instanceof List) req.addAll((List<?>) acc.get("required"));
                if (m.get("required") instanceof List) req.addAll((List<?>) m.get("required"));
                merged.put("properties", props);
                merged.put("required", req);
                acc = merged;
            }
            cur = acc;
            cur.putAll(rest);
        }
        Object alts = cur.get("anyOf") != null ? cur.get("anyOf") : cur.get("oneOf");
        if (alts instanceof List) {
            Map<String, Object> rest = new LinkedHashMap<>(cur);
            rest.remove("anyOf");
            rest.remove("oneOf");
            List<Map<String, Object>> live = new ArrayList<>();
            for (Object mo : (List<?>) alts) {
                Map<String, Object> m = flatten(mo, c, where, depth + 1);
                if (!isNullType(m)) live.add(m);
            }
            if (live.size() == 1) {
                Map<String, Object> out = new LinkedHashMap<>(live.get(0));
                out.putAll(rest);
                return out;
            }
            Set<String> enumValues = new LinkedHashSet<>();
            boolean allConst = live.size() > 1;
            for (Map<String, Object> m : live) {
                if (m.get("const") instanceof String) enumValues.add((String) m.get("const"));
                else if (stringList(m.get("enum")) != null) enumValues.addAll(stringList(m.get("enum")));
                else allConst = false;
            }
            if (allConst) {
                Map<String, Object> out = new LinkedHashMap<>(rest);
                out.put("type", "string");
                out.put("enum", new ArrayList<Object>(enumValues));
                return out;
            }
            c.todo.add(where + ": a union of " + live.size() + " schemas has no schema representation (declared string; refine or drop)");
            return rest;
        }
        if (cur.get("const") instanceof String && !cur.containsKey("enum")) {
            cur.put("enum", new ArrayList<Object>(List.of(cur.get("const"))));
        }
        return cur;
    }

    private static Map<String, Object> decl(String name, Object schema, boolean required, Ctx c) {
        List<String> todo = c.todo;
        Map<String, Object> s = flatten(schema, c, "action.params." + name, 0);
        Object t = null;
        boolean tHas = s.containsKey("type");
        if (s.get("type") instanceof List) {
            tHas = false;
            for (Object x : (List<?>) s.get("type")) if (!"null".equals(x)) { t = x; tHas = true; break; }
        } else {
            t = s.get("type");
        }
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("semantic", s.get("x-pca-semantic") != null ? s.get("x-pca-semantic") : "unknown");
        base.put("sensitivity", s.get("x-pca-sensitivity") != null ? s.get("x-pca-sensitivity") : "material");
        if (!required) base.put("required", false);
        if (Zk.truthy(s.get("description"))) base.put("description", slice(s.get("description"), 1024));
        if (!Zk.truthy(s.get("x-pca-semantic"))) todo.add("action.params." + name + ": semantic type");
        List<String> enumStrings = stringList(s.get("enum"));
        Map<String, Object> out = new LinkedHashMap<>();
        if ("integer".equals(t)) {
            out.put("type", "integer");
            out.putAll(base);
            if (IntentJs.isSafeInteger(s.get("minimum"))) out.put("min", s.get("minimum"));
            else if (IntentJs.isSafeInteger(s.get("exclusiveMinimum"))) out.put("min", StoreJs.num(IntentJs.num(s.get("exclusiveMinimum")) + 1));
            if (IntentJs.isSafeInteger(s.get("maximum"))) out.put("max", s.get("maximum"));
            else if (IntentJs.isSafeInteger(s.get("exclusiveMaximum"))) out.put("max", StoreJs.num(IntentJs.num(s.get("exclusiveMaximum")) - 1));
            if (Zk.truthy(s.get("x-pca-unit"))) out.put("unit", s.get("x-pca-unit"));
            if (Zk.truthy(s.get("x-pca-accumulates-into"))) out.put("accumulates_into", s.get("x-pca-accumulates-into"));
            return out;
        }
        if ("boolean".equals(t)) { out.put("type", "boolean"); out.putAll(base); return out; }
        if ("string".equals(t) && "date".equals(s.get("format"))) { out.put("type", "date"); out.putAll(base); return out; }
        if ("string".equals(t)) {
            out.put("type", "string");
            out.putAll(base);
            if (enumStrings != null) out.put("values", new ArrayList<Object>(enumStrings));
            if (IntentJs.isSafeInteger(s.get("maxLength")) && IntentJs.num(s.get("maxLength")) > 0) out.put("max_len", s.get("maxLength"));
            return out;
        }
        if ("array".equals(t)) {
            Map<String, Object> it = flatten(s.get("items"), c, "action.params." + name + "[]", 0);
            List<String> itEnum = stringList(it.get("enum"));
            if (Zk.truthy(s.get("uniqueItems")) && itEnum != null) {
                out.put("type", "set");
                out.putAll(base);
                out.put("values", new ArrayList<Object>(itEnum));
                if (IntentJs.isSafeInteger(s.get("minItems"))) out.put("min_items", s.get("minItems"));
                if (IntentJs.isSafeInteger(s.get("maxItems"))) out.put("max_items", s.get("maxItems"));
                return out;
            }
            Object itT = it.get("type") instanceof List ? (((List<?>) it.get("type")).isEmpty() ? null : ((List<?>) it.get("type")).get(0)) : it.get("type");
            out.put("type", "array");
            out.putAll(base);
            if ("integer".equals(itT)) out.put("items", "integer");
            if (IntentJs.isSafeInteger(s.get("maxItems"))) out.put("max_items", s.get("maxItems"));
            if (IntentJs.isSafeInteger(s.get("minItems"))) out.put("min_items", s.get("minItems"));
            return out;
        }
        todo.add("action.params." + name + ": type '" + text(t, tHas) + "' has no schema representation (declared string; refine or drop)");
        out.put("type", "string");
        out.putAll(base);
        return out;
    }

    private static Map<String, Object> result(Map<String, Object> site, List<Map<String, Object>> verbs, List<String> todo) {
        verbs.sort((a, b) -> Json.compareUtf8((String) a.get("verb"), (String) b.get("verb")));
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("v", IntentJs.ofLong(1));
        schema.put("kind", ActionSchema.ACTION_SCHEMA_KIND);
        if (site.containsKey("site")) schema.put("site", site.get("site"));
        if (site.containsKey("aud")) schema.put("aud", site.get("aud"));
        if (site.containsKey("version")) schema.put("version", site.get("version"));
        schema.put("verbs", new ArrayList<Object>(verbs));
        return Issue.obj("schema", schema, "todo", new ArrayList<Object>(todo));
    }

    private static List<Object> sortedKeys(Map<String, Object> m) {
        List<String> ks = new ArrayList<>(m.keySet());
        ks.sort(Json::compareUtf8);
        return new ArrayList<Object>(ks);
    }

    /**
     * Draft a schema from an MCP {@code tools/list}: one verb per tool (read when its {@code readOnlyHint} is true, else a write drafted
     * irreversible), one parameter per input-schema property. {@code site = {site, aud, version, verbPrefix?}}. Returns {@code {schema, todo}}.
     * Annotations are HINTS and never lower a classification; every semantic type is left to a human.
     */
    public static Map<String, Object> draftSchemaFromMcpTools(List<?> tools, Map<String, Object> site) {
        List<String> todo = new ArrayList<>();
        List<Map<String, Object>> verbs = new ArrayList<>();
        for (Object to : tools) {
            if (!(to instanceof Map)) throw new IllegalArgumentException("Cannot read properties of null (reading 'inputSchema')");
            Map<String, Object> t = StoreJs.map(to);
            String tname = text(t.get("name"), t.containsKey("name"));
            Ctx c = new Ctx(t.get("inputSchema"), todo);
            Map<String, Object> input = flatten(t.get("inputSchema"), c, tname + ": inputSchema", 0);
            Map<String, Object> props = input.get("properties") instanceof Map ? StoreJs.map(input.get("properties")) : new LinkedHashMap<>();
            Set<Object> req = new HashSet<>(input.get("required") instanceof List ? (List<?>) input.get("required") : new ArrayList<Object>());
            Map<String, Object> params = new LinkedHashMap<>();
            for (Object no : sortedKeys(props)) {
                String name = (String) no;
                if (!PARAM_NAME.matcher(name).matches()) {
                    todo.add(tname + ": parameter '" + name + "' is not a schema name ([A-Za-z0-9_]{1,64}); rename it");
                    continue;
                }
                params.put("action.params." + name, decl(name, props.get(name), req.contains(name), c));
            }
            Map<String, Object> h = ActionSchema.reversibilityFromMcpHints(t.get("annotations") instanceof Map ? StoreJs.map(t.get("annotations")) : null);
            Object prefix = site.get("verbPrefix");
            String verb = (prefix == null ? "" : text(prefix, true)) + tname;
            boolean write = "write".equals(h.get("kind"));
            if (write) todo.add(verb + ": reversibility (drafted irreversible)");
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("verb", verb);
            v.put("kind", h.get("kind"));
            v.put("params", params);
            v.put("reversibility", write ? "irreversible" : "reversible");
            v.put("mcp", Issue.obj("tool", t.get("name")));
            if (Zk.truthy(t.get("description"))) v.put("description", slice(t.get("description"), 1024));
            verbs.add(v);
        }
        return result(site, verbs, todo);
    }

    private static Map<String, Object> jsonContent(Map<String, Object> body) {
        Object content = body == null ? null : body.get("content");
        return content instanceof Map ? StoreJs.map(content) : null;
    }

    private static Object jsonBodySchema(Map<String, Object> b) {
        Map<String, Object> content = jsonContent(b);
        if (content == null) return null;
        List<Object> keys = sortedKeys(content);
        String key = null;
        for (Object k : keys) if (((String) k).toLowerCase(java.util.Locale.ROOT).equals("application/json")) { key = (String) k; break; }
        if (key == null) for (Object k : keys) if (JSON_SUFFIX.matcher((String) k).find()) { key = (String) k; break; }
        return key == null ? null : get(content.get(key), "schema");
    }

    /**
     * Draft a schema from an OpenAPI document: one verb per operation that has an {@code operationId} (a GET or HEAD is a read unless
     * {@code x-pca-kind} says otherwise; {@code x-pca-verb} renames the verb; {@code x-pca-reversibility} declares it), with the JSON request
     * body's properties and the path and query parameters as action parameters (other parameter locations are not action parameters).
     * {@code site = {site, aud, version}}. Returns {@code {schema, todo}}.
     */
    public static Map<String, Object> draftSchemaFromOpenApi(Map<String, Object> doc, Map<String, Object> site) {
        List<String> todo = new ArrayList<>();
        List<Map<String, Object>> verbs = new ArrayList<>();
        Ctx c = new Ctx(doc, todo);
        Set<Object> seen = new HashSet<>();
        Map<String, Object> paths = doc.get("paths") instanceof Map ? StoreJs.map(doc.get("paths")) : new LinkedHashMap<>();
        for (Object po : sortedKeys(paths)) {
            Object opsO = paths.get(po);
            if (!(opsO instanceof Map)) throw new IllegalArgumentException("Cannot read properties of null (reading 'parameters')");
            Map<String, Object> ops = StoreJs.map(opsO);
            List<Object> shared = new ArrayList<>();
            if (ops.get("parameters") instanceof List) shared.addAll((List<?>) ops.get("parameters"));
            for (Object mo : sortedKeys(ops)) {
                String method = (String) mo;
                Object opO = ops.get(method);
                if (!(opO instanceof Map) || !Zk.truthy(((Map<?, ?>) opO).get("operationId"))) continue;
                Map<String, Object> op = StoreJs.map(opO);
                String opId = text(op.get("operationId"), true);
                c.left = MAX_REF_NODES;
                boolean read = Zk.truthy(op.get("x-pca-kind")) ? "read".equals(op.get("x-pca-kind")) : method.equalsIgnoreCase("get") || method.equalsIgnoreCase("head");
                Object verb = op.get("x-pca-verb") != null ? op.get("x-pca-verb") : op.get("operationId");
                if (seen.contains(verb)) todo.add(text(verb, true) + ": declared by more than one operation; give each a distinct x-pca-verb");
                seen.add(verb);
                Map<String, Object> params = new LinkedHashMap<>();
                Map<String, Object> body = flatten(jsonBodySchema(deref(op.get("requestBody"), doc, todo)), c, opId + ": request body", 0);
                Map<String, Object> bprops = body.get("properties") instanceof Map ? StoreJs.map(body.get("properties")) : new LinkedHashMap<>();
                Set<Object> breq = new HashSet<>(body.get("required") instanceof List ? (List<?>) body.get("required") : new ArrayList<Object>());
                for (Object no : sortedKeys(bprops)) addName(params, todo, opId, (String) no, bprops.get(no), breq.contains(no), "request body", c);
                Map<String, Map<String, Object>> merged = new LinkedHashMap<>();
                List<Object> all = new ArrayList<>(shared);
                if (op.get("parameters") instanceof List) all.addAll((List<?>) op.get("parameters"));
                for (Object raw : all) {
                    Map<String, Object> q = deref(raw, doc, todo);
                    if (q == null || !(q.get("name") instanceof String) || !(q.get("in") instanceof String)) continue;
                    merged.put(q.get("in") + ":" + q.get("name"), q);
                }
                List<String> keys = new ArrayList<>(merged.keySet());
                keys.sort(Json::compareUtf8);
                for (String key : keys) {
                    Map<String, Object> q = merged.get(key);
                    String in = (String) q.get("in"), name = (String) q.get("name");
                    if (!in.equals("path") && !in.equals("query")) {
                        todo.add(opId + ": " + in + " parameter '" + name + "' is not an action parameter (the schema sees path, query and body parameters only)");
                        continue;
                    }
                    Map<String, Object> sch = map(q.get("schema"));
                    if (Zk.truthy(q.get("description")) && !Zk.truthy(sch.get("description"))) sch.put("description", q.get("description"));
                    addName(params, todo, opId, name, sch, in.equals("path") || Boolean.TRUE.equals(q.get("required")), in + " parameters", c);
                }
                Object rev = Zk.truthy(op.get("x-pca-reversibility")) ? op.get("x-pca-reversibility") : (read ? "reversible" : "irreversible");
                if (!read && !Zk.truthy(op.get("x-pca-reversibility"))) todo.add(text(verb, true) + ": reversibility (drafted irreversible)");
                Map<String, Object> v = new LinkedHashMap<>();
                v.put("verb", verb);
                v.put("kind", read ? "read" : "write");
                v.put("params", params);
                v.put("reversibility", rev);
                v.put("openapi", Issue.obj("operationId", op.get("operationId")));
                if (Zk.truthy(op.get("description"))) v.put("description", slice(op.get("description"), 1024));
                verbs.add(v);
            }
        }
        return result(site, verbs, todo);
    }

    private static void addName(Map<String, Object> params, List<String> todo, String opId, String name, Object sch, boolean required, String source, Ctx c) {
        if (!PARAM_NAME.matcher(name).matches()) {
            todo.add(opId + ": parameter '" + name + "' is not a schema name; rename it");
            return;
        }
        String key = "action.params." + name;
        if (params.containsKey(key)) {
            todo.add(opId + ": '" + name + "' is declared by both the " + source + " and another source; kept the first");
            return;
        }
        params.put(key, decl(name, sch, required, c));
    }

    private static Map<String, Object> deref(Object x, Map<String, Object> doc, List<String> todo) {
        if (!(x instanceof Map)) return null;
        Map<String, Object> m = StoreJs.map(x);
        if (!(m.get("$ref") instanceof String)) return m;
        String ref = (String) m.get("$ref");
        Object t = pointer(doc, ref);
        if (t == null) todo.add("reference '" + (ref.length() <= 120 ? ref : ref.substring(0, 120)) + "' is not a local reference that resolves");
        return t instanceof Map ? StoreJs.map(t) : null;
    }
}
