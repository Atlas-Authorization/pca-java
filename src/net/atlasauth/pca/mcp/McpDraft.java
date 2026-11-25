package net.atlasauth.pca.mcp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import net.atlasauth.pca.ActionSchema;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.a2a.A2aPca;
import net.atlasauth.pca.oauth.JsVal;

/**
 * The v1 draft of a site action schema from an MCP tool list: JSON Schema flattening (local {@code $ref}, {@code allOf}, {@code anyOf} /
 * {@code oneOf}), the parameter declaration of each property and the verb of each tool. Pure over parsed JSON (Map, List, String, Boolean,
 * {@link Json.Num}, null). Whatever cannot be represented is flagged in {@code todo} and drafted as a {@code string}, which rejects every
 * non-string value, so the draft fails closed until the developer refines it.
 */
final class McpDraft {
    private McpDraft() {}

    private static final int MAX_REF_DEPTH = 8;
    private static final int MAX_REF_NODES = 20_000;
    private static final Pattern NAME = Pattern.compile("^[A-Za-z0-9_]{1,64}$");

    /** Where references resolve and what could not be represented is reported; {@code left} is the reference-bomb budget. */
    private static final class Ctx {
        final Object root;
        final List<Object> todo;
        Integer left;
        Ctx(Object root, List<Object> todo) { this.root = root; this.todo = todo; }
    }

    private static boolean isObj(Object o) { return o instanceof Map; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    /** {@code o.k} on a schema node: the member of a Map, else absent (null). */
    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    private static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    static String jsStr(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = JsVal.num(v);
        if (d != null) return AttestCommon.jsNumString(d);
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) { if (!first) sb.append(','); first = false; if (x != null) sb.append(jsStr(x)); }
            return sb.toString();
        }
        return "[object Object]";
    }

    /** {@code Number.isSafeInteger}. */
    static boolean safeInt(Object o) {
        Double d = JsVal.num(o);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.floor(d) && Math.abs(d) <= 9007199254740991.0;
    }

    static Json.Num num(double d) { return new Json.Num(AttestCommon.jsNumString(d)); }

    private static boolean truthy(Object o) { return JsVal.truthy(o); }

    /** {@code [...x]} of a schema member: absent or null is empty, a list copies, a string spreads by code point, other values are not iterable (throw). */
    @SuppressWarnings("unchecked")
    private static List<Object> iter(Object x) {
        if (x == null) return new ArrayList<>();
        if (x instanceof List) return new ArrayList<>((List<Object>) x);
        if (x instanceof String) {
            List<Object> out = new ArrayList<>();
            ((String) x).codePoints().forEach(c -> out.add(new String(Character.toChars(c))));
            return out;
        }
        throw new IllegalStateException("TypeError: not iterable");
    }

    /** Follow a local {@code #/a/b} JSON pointer in {@code root}; null when absent, not local, or not an object. */
    @SuppressWarnings("unchecked")
    static Object pointer(Object root, String ref) {
        if (!ref.startsWith("#/")) return null;
        Object cur = root;
        for (String raw : ref.substring(2).split("/", -1)) {
            String seg = raw.replace("~1", "/").replace("~0", "~");
            if (cur instanceof Map) {
                if (!((Map<String, Object>) cur).containsKey(seg)) return null;
                cur = ((Map<String, Object>) cur).get(seg);
            } else if (cur instanceof List) {
                List<Object> l = (List<Object>) cur;
                if (!seg.matches("0|[1-9][0-9]{0,8}") || Integer.parseInt(seg) >= l.size()) return null;
                cur = l.get(Integer.parseInt(seg));
            } else return null;
        }
        return cur instanceof Map || cur instanceof List ? cur : null;
    }

    private static boolean typeIsNull(Object m) {
        Object t = get(m, "type");
        if ("null".equals(t)) return true;
        if (t instanceof List) { for (Object x : (List<?>) t) if (!"null".equals(x)) return false; return true; }
        return false;
    }

    private static List<Object> stringEnum(Object m) {
        Object e = get(m, "enum");
        if (e instanceof List) { for (Object x : (List<?>) e) if (!(x instanceof String)) return null; @SuppressWarnings("unchecked") List<Object> l = (List<Object>) e; return l; }
        return null;
    }

    /**
     * Flatten what a parameter declaration cannot carry: follow local {@code $ref}s, merge {@code allOf}, collapse {@code anyOf} / {@code oneOf}
     * to its single non-null variant (or to the union of string constants). Unrepresentable parts are flagged in {@code todo}.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> flatten(Object s, Ctx c, String where, int depth) {
        if (!(s instanceof Map) && !(s instanceof List)) return new LinkedHashMap<>();
        c.left = (c.left == null ? MAX_REF_NODES : c.left) - 1;
        if (c.left < 0) {
            if (c.left == -1) c.todo.add(where + ": schema expansion stopped after " + MAX_REF_NODES + " nodes (declared string; refine or drop)");
            return new LinkedHashMap<>();
        }
        if (depth > MAX_REF_DEPTH) {
            c.todo.add(where + ": schema nesting or reference chain deeper than " + MAX_REF_DEPTH + " (declared string; refine or drop)");
            return new LinkedHashMap<>();
        }
        Map<String, Object> cur = A2aPca.spread(s);
        if (get(s, "$ref") instanceof String) {
            String ref = (String) get(s, "$ref");
            Object target = pointer(c.root, ref);
            if (target == null) {
                c.todo.add(where + ": reference '" + (ref.length() > 120 ? ref.substring(0, 120) : ref) + "' is not a local reference that resolves (declared string; refine or drop)");
                return new LinkedHashMap<>();
            }
            Map<String, Object> siblings = A2aPca.spread(s);
            siblings.remove("$ref");
            Map<String, Object> merged = new LinkedHashMap<>(flatten(target, c, where, depth + 1));
            merged.putAll(siblings);
            cur = merged;
        }
        if (cur.get("allOf") instanceof List) {
            List<Object> allOf = (List<Object>) cur.get("allOf");
            Map<String, Object> rest = new LinkedHashMap<>(cur);
            rest.remove("allOf");
            List<Map<String, Object>> parts = new ArrayList<>();
            for (Object m : allOf) parts.add(flatten(m, c, where, depth + 1));
            Map<String, Object> acc = new LinkedHashMap<>();
            for (Map<String, Object> m : parts) {
                Map<String, Object> next = new LinkedHashMap<>(acc);
                next.putAll(m);
                Map<String, Object> props = A2aPca.spread(acc.get("properties"));
                props.putAll(A2aPca.spread(m.get("properties")));
                next.put("properties", props);
                List<Object> req = iter(acc.get("required"));
                req.addAll(iter(m.get("required")));
                next.put("required", req);
                acc = next;
            }
            cur = new LinkedHashMap<>(acc);
            cur.putAll(rest);
        }
        Object alts = cur.get("anyOf") != null ? cur.get("anyOf") : cur.get("oneOf");
        if (alts instanceof List) {
            Map<String, Object> rest = new LinkedHashMap<>(cur);
            rest.remove("anyOf");
            rest.remove("oneOf");
            List<Map<String, Object>> live = new ArrayList<>();
            for (Object m : (List<Object>) alts) { Map<String, Object> f = flatten(m, c, where, depth + 1); if (!typeIsNull(f)) live.add(f); }
            if (live.size() == 1) { Map<String, Object> out = new LinkedHashMap<>(live.get(0)); out.putAll(rest); return out; }
            List<List<Object>> consts = new ArrayList<>();
            boolean allConst = true;
            for (Map<String, Object> m : live) {
                if (m.get("const") instanceof String) consts.add(new ArrayList<Object>(List.of(m.get("const"))));
                else { List<Object> e = stringEnum(m); if (e == null) allConst = false; consts.add(e); }
            }
            if (live.size() > 1 && allConst) {
                Set<Object> uniq = new LinkedHashSet<>();
                for (List<Object> l : consts) uniq.addAll(l);
                Map<String, Object> out = new LinkedHashMap<>(rest);
                out.put("type", "string");
                out.put("enum", new ArrayList<Object>(uniq));
                return out;
            }
            c.todo.add(where + ": a union of " + live.size() + " schemas has no schema representation (declared string; refine or drop)");
            return rest;
        }
        if (cur.containsKey("const") && !cur.containsKey("enum") && cur.get("const") instanceof String) {
            Map<String, Object> out = new LinkedHashMap<>(cur);
            out.put("enum", new ArrayList<Object>(List.of(cur.get("const"))));
            cur = out;
        }
        return cur;
    }

    private static Map<String, Object> flatten(Object s, Ctx c, String where) { return flatten(s, c, where, 0); }

    /** JSON Schema property to parameter declaration; sensitivity defaults to {@code material}, an unrepresentable shape becomes a {@code string} placeholder flagged in {@code todo}. */
    private static Map<String, Object> declOf(String name, Object schema, boolean required, Ctx c) {
        Map<String, Object> s = flatten(schema, c, "action.params." + name);
        Object t = typeOf(s);
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("semantic", s.get("x-pca-semantic") != null ? s.get("x-pca-semantic") : "unknown");
        base.put("sensitivity", s.get("x-pca-sensitivity") != null ? s.get("x-pca-sensitivity") : "material");
        if (!required) base.put("required", Boolean.FALSE);
        if (truthy(s.get("description"))) {
            base.put("description", slice1024(s.get("description")));
        }
        if (!truthy(s.get("x-pca-semantic"))) c.todo.add("action.params." + name + ": semantic type");
        List<Object> enumStrings = stringEnum(s);
        Map<String, Object> out = new LinkedHashMap<>();
        if ("integer".equals(t)) {
            out.put("type", "integer");
            out.putAll(base);
            if (safeInt(s.get("minimum"))) out.put("min", s.get("minimum"));
            else if (safeInt(s.get("exclusiveMinimum"))) out.put("min", num(JsVal.num(s.get("exclusiveMinimum")) + 1));
            if (safeInt(s.get("maximum"))) out.put("max", s.get("maximum"));
            else if (safeInt(s.get("exclusiveMaximum"))) out.put("max", num(JsVal.num(s.get("exclusiveMaximum")) - 1));
            if (truthy(s.get("x-pca-unit"))) out.put("unit", s.get("x-pca-unit"));
            if (truthy(s.get("x-pca-accumulates-into"))) out.put("accumulates_into", s.get("x-pca-accumulates-into"));
            return out;
        }
        if ("boolean".equals(t)) { out.put("type", "boolean"); out.putAll(base); return out; }
        if ("string".equals(t) && "date".equals(s.get("format"))) { out.put("type", "date"); out.putAll(base); return out; }
        if ("string".equals(t)) {
            out.put("type", "string");
            out.putAll(base);
            if (enumStrings != null) out.put("values", enumStrings);
            if (safeInt(s.get("maxLength")) && JsVal.num(s.get("maxLength")) > 0) out.put("max_len", s.get("maxLength"));
            return out;
        }
        if ("array".equals(t)) {
            Map<String, Object> it = flatten(s.get("items"), c, "action.params." + name + "[]");
            List<Object> itEnum = stringEnum(it);
            if (truthy(s.get("uniqueItems")) && itEnum != null) {
                out.put("type", "set");
                out.putAll(base);
                out.put("values", itEnum);
                if (safeInt(s.get("minItems"))) out.put("min_items", s.get("minItems"));
                if (safeInt(s.get("maxItems"))) out.put("max_items", s.get("maxItems"));
                return out;
            }
            Object itT = it.get("type") instanceof List ? (((List<?>) it.get("type")).isEmpty() ? UNDEF : ((List<?>) it.get("type")).get(0)) : it.get("type");
            out.put("type", "array");
            out.putAll(base);
            if ("integer".equals(itT)) out.put("items", "integer");
            if (safeInt(s.get("maxItems"))) out.put("max_items", s.get("maxItems"));
            if (safeInt(s.get("minItems"))) out.put("min_items", s.get("minItems"));
            return out;
        }
        c.todo.add("action.params." + name + ": type '" + (t == UNDEF ? "undefined" : jsStr(t)) + "' has no schema representation (declared string; refine or drop)");
        out.put("type", "string");
        out.putAll(base);
        return out;
    }

    /** Marks an absent member (JavaScript undefined) as opposed to JSON null. */
    private static final Object UNDEF = new Object();

    /** {@code Array.isArray(t) ? t.find(x => x !== 'null') : t} for the {@code type} member: the first element other than the string "null" (a JSON null element counts), else undefined. */
    private static Object typeOf(Map<String, Object> s) {
        if (!s.containsKey("type")) return UNDEF;
        Object t = s.get("type");
        if (t instanceof List) { for (Object x : (List<?>) t) if (!"null".equals(x)) return x; return UNDEF; }
        return t;
    }

    /** {@code description.slice(0, 1024)}: a string or an array slices; any other truthy value has no slice (TypeError). */
    @SuppressWarnings("unchecked")
    private static Object slice1024(Object d) {
        if (d instanceof String) return ((String) d).length() > 1024 ? ((String) d).substring(0, 1024) : d;
        if (d instanceof List) return new ArrayList<Object>(((List<Object>) d).subList(0, Math.min(1024, ((List<Object>) d).size())));
        throw new IllegalStateException("TypeError: slice is not a function");
    }

    /** The reference: a write verb unless the tool is read-only by hint; a destructive hint keeps it at least rate_limited (the draft lists every write verb irreversible). */
    private static boolean isRead(Object annotations) {
        return annotations instanceof Map && Boolean.TRUE.equals(((Map<?, ?>) annotations).get("readOnlyHint"));
    }

    /** Draft the schema and the decisions the developer must still make. {@code site}: {@code site}, {@code aud}, {@code version}, optional {@code verbPrefix}. */
    static Map<String, Object> draft(List<Object> tools, Map<String, Object> site) {
        List<Object> todo = new ArrayList<>();
        List<Map<String, Object>> verbs = new ArrayList<>();
        for (Object t : tools) {
            if (t == null) throw new IllegalStateException("TypeError: cannot read properties of null (reading 'inputSchema')");
            Ctx c = new Ctx(get(t, "inputSchema"), todo);
            String tname = jsStr(has(t, "name") ? get(t, "name") : "undefined");
            Map<String, Object> input = flatten(get(t, "inputSchema"), c, tname + ": inputSchema");
            Object props = input.get("properties") != null ? input.get("properties") : new LinkedHashMap<String, Object>();
            Set<Object> req = new LinkedHashSet<>(iter(input.get("required")));
            Map<String, Object> params = new LinkedHashMap<>();
            List<String> names = new ArrayList<>(keysOf(props));
            names.sort(IntentJs::compareUtf8);
            for (String name : names) {
                if (!NAME.matcher(name).matches()) {
                    todo.add(tname + ": parameter '" + name + "' is not a schema name ([A-Za-z0-9_]{1,64}); rename it");
                    continue;
                }
                params.put("action.params." + name, declOf(name, valueOf(props, name), req.contains(name), c));
            }
            boolean read = isRead(get(t, "annotations"));
            Object prefix = site.get("verbPrefix") != null ? site.get("verbPrefix") : "";
            String verb = jsStr(prefix) + tname;
            if (!read) todo.add(verb + ": reversibility (drafted irreversible)");
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("verb", verb);
            v.put("kind", read ? "read" : "write");
            v.put("params", params);
            v.put("reversibility", read ? "reversible" : "irreversible");
            Map<String, Object> mcp = new LinkedHashMap<>();
            if (has(t, "name")) mcp.put("tool", get(t, "name"));
            v.put("mcp", mcp);
            if (truthy(get(t, "description"))) {
                v.put("description", slice1024(get(t, "description")));
            }
            verbs.add(v);
        }
        verbs.sort((a, b) -> IntentJs.compareUtf8((String) a.get("verb"), (String) b.get("verb")));
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("v", new Json.Num("1"));
        schema.put("kind", ActionSchema.ACTION_SCHEMA_KIND);
        for (String k : new String[] {"site", "aud", "version"}) if (site.containsKey(k)) schema.put(k, site.get(k));
        schema.put("verbs", new ArrayList<Object>(verbs));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("schema", schema);
        out.put("todo", todo);
        return out;
    }

    /** {@code Object.keys(o)} of a parsed value (Map keys, list indices, string indices; other values have none). */
    @SuppressWarnings("unchecked")
    static List<String> keysOf(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof Map) out.addAll(((Map<String, Object>) o).keySet());
        else if (o instanceof List) for (int i = 0; i < ((List<?>) o).size(); i++) out.add(Integer.toString(i));
        else if (o instanceof String) for (int i = 0; i < ((String) o).length(); i++) out.add(Integer.toString(i));
        return out;
    }

    @SuppressWarnings("unchecked")
    static Object valueOf(Object o, String k) {
        if (o instanceof Map) return ((Map<String, Object>) o).get(k);
        if (o instanceof List) return ((List<Object>) o).get(Integer.parseInt(k));
        if (o instanceof String) return String.valueOf(((String) o).charAt(Integer.parseInt(k)));
        return null;
    }

    static boolean isMap(Object o) { return isObj(o); }
}
