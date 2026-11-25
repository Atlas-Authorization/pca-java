package net.atlasauth.pca.actions.importers;

import static net.atlasauth.pca.actions.importers.ImportCommon.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Actions.ActionKitError;
import net.atlasauth.pca.IntentJs;

/**
 * GraphQL SDL or introspection JSON to drafts. Query fields are reads, Mutation fields are writes, Subscription fields are streaming
 * reads; arguments and input objects are flattened to dotted params. There is no method signal; everything stays {@code unreviewed}.
 */
public final class GraphqlImporter {
    private GraphqlImporter() {}

    // ---- model ----

    /** {@code named} (name), {@code list} (of) or {@code nonnull} (of). */
    public static final class GqlType {
        public final String k, name;
        public final GqlType of;
        GqlType(String k, String name, GqlType of) { this.k = k; this.name = name; this.of = of; }
        static GqlType named(String n) { return new GqlType("named", n, null); }
        Map<String, Object> toJson() { return "named".equals(k) ? Jx.obj("k", k, "name", name) : Jx.obj("k", k, "of", of.toJson()); }
    }

    public static final class GqlArg {
        public final String name, desc;
        public final GqlType type;
        GqlArg(String name, GqlType type, String desc) { this.name = name; this.type = type; this.desc = desc; }
        Map<String, Object> toJson() { Map<String, Object> m = Jx.obj("name", name, "type", type.toJson()); if (desc != null) m.put("desc", desc); return m; }
    }

    public static final class GqlField {
        public final String name, desc;
        public final List<GqlArg> args;
        public final GqlType type;
        public final boolean deprecated;
        GqlField(String name, List<GqlArg> args, GqlType type, boolean deprecated, String desc) { this.name = name; this.args = args; this.type = type; this.deprecated = deprecated; this.desc = desc; }
        Map<String, Object> toJson() {
            List<Object> as = new ArrayList<>();
            for (GqlArg a : args) as.add(a.toJson());
            Map<String, Object> m = Jx.obj("name", name, "args", as, "type", type.toJson(), "deprecated", deprecated);
            if (desc != null) m.put("desc", desc);
            return m;
        }
    }

    public static final class GqlTypeDef {
        public final String kind, name;
        public final List<GqlField> fields;
        public final List<String> values;
        GqlTypeDef(String kind, String name, List<GqlField> fields, List<String> values) { this.kind = kind; this.name = name; this.fields = fields; this.values = values; }
    }

    public static final class GqlSchema {
        public final Map<String, GqlTypeDef> types = new LinkedHashMap<>();
        public String query, mutation, subscription;

        /** {@code {types: [[name, {kind, name, fields, values}]...], query?, mutation?, subscription?}}. */
        public Map<String, Object> toJson() {
            List<Object> ts = new ArrayList<>();
            for (Map.Entry<String, GqlTypeDef> e : types.entrySet()) {
                List<Object> fs = new ArrayList<>();
                for (GqlField f : e.getValue().fields) fs.add(f.toJson());
                ts.add(Jx.list(e.getKey(), Jx.obj("kind", e.getValue().kind, "name", e.getValue().name, "fields", fs, "values", new ArrayList<Object>(e.getValue().values))));
            }
            Map<String, Object> m = Jx.obj("types", ts);
            if (query != null) m.put("query", query);
            if (mutation != null) m.put("mutation", mutation);
            if (subscription != null) m.put("subscription", subscription);
            return m;
        }
    }

    // ---- SDL lexer ----

    private static final class Tok {
        final String t, v;
        Tok(String t, String v) { this.t = t; this.v = v; }
    }

    private static boolean nameStart(char c) { return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
    private static boolean nameChar(char c) { return nameStart(c) || (c >= '0' && c <= '9'); }

    private static List<Tok> lex(String src, int maxTokens) {
        List<Tok> out = new ArrayList<>();
        int i = 0, n = src.length();
        while (i < n) {
            char ch = src.charAt(i);
            Tok push = null;
            if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ',' || ch == '﻿') { i++; continue; }
            if (ch == '#') { while (i < n && src.charAt(i) != '\n') i++; continue; }
            if (ch == '"') {
                if (src.startsWith("\"\"\"", i)) {
                    int j = i + 3;
                    StringBuilder s = new StringBuilder();
                    while (j < n && !src.startsWith("\"\"\"", j)) {
                        if (src.startsWith("\\\"\"\"", j)) { s.append("\"\"\""); j += 4; } else s.append(src.charAt(j++));
                    }
                    if (j >= n) throw new ActionKitError("bad_source", "unterminated GraphQL block string");
                    push = new Tok("str", s.toString());
                    i = j + 3;
                } else {
                    int j = i + 1;
                    StringBuilder s = new StringBuilder();
                    while (j < n && src.charAt(j) != '"') {
                        if (src.charAt(j) == '\n') throw new ActionKitError("bad_source", "unterminated GraphQL string");
                        if (src.charAt(j) == '\\') { if (j + 1 < n) s.append(src.charAt(j + 1)); j += 2; } else s.append(src.charAt(j++));
                    }
                    if (j >= n) throw new ActionKitError("bad_source", "unterminated GraphQL string");
                    push = new Tok("str", s.toString());
                    i = j + 1;
                }
            } else if (nameStart(ch)) {
                int j = i + 1;
                while (j < n && nameChar(src.charAt(j))) j++;
                push = new Tok("name", src.substring(i, j));
                i = j;
            } else if (ch == '-' || (ch >= '0' && ch <= '9')) {
                int j = i + 1;
                while (j < n && (src.charAt(j) == '-' || src.charAt(j) == '+' || src.charAt(j) == '.' || (src.charAt(j) >= '0' && src.charAt(j) <= '9') || src.charAt(j) == 'e' || src.charAt(j) == 'E')) j++;
                push = new Tok("int", src.substring(i, j));
                i = j;
            } else if (src.startsWith("...", i)) { push = new Tok("punct", "..."); i += 3; }
            else if ("!$&():=@[]{|}".indexOf(ch) >= 0) { push = new Tok("punct", String.valueOf(ch)); i++; }
            else throw new ActionKitError("bad_source", "unexpected character in GraphQL source at offset " + i);
            if (out.size() >= maxTokens) throw new ActionKitError("import_limit", "the GraphQL source has too many tokens");
            out.add(push);
        }
        if (out.size() >= maxTokens) throw new ActionKitError("import_limit", "the GraphQL source has too many tokens");
        out.add(new Tok("eof", ""));
        return out;
    }

    // ---- SDL parser (type system definitions only; executable documents are rejected) ----

    private static final class P {
        int i = 0;
        final List<Tok> toks;
        final GqlSchema schema;
        final int maxDepth;
        P(List<Tok> toks, GqlSchema schema, int maxDepth) { this.toks = toks; this.schema = schema; this.maxDepth = maxDepth; }

        Tok cur() { return toks.get(i); }
        Tok next() { Tok t = toks.get(i); if (!"eof".equals(t.t)) i++; return t; }
        boolean is(String v) { return !"str".equals(cur().t) && cur().v.equals(v); }
        boolean eat(String v) { if (is(v)) { i++; return true; } return false; }
        void expect(String v) { if (!eat(v)) throw new ActionKitError("bad_source", "GraphQL parse error: expected '" + v + "' near '" + clip(cur().v, 30) + "'"); }
        String name() { Tok t = next(); if (!"name".equals(t.t)) throw new ActionKitError("bad_source", "GraphQL parse error: expected a name near '" + clip(t.v, 30) + "'"); return t.v; }
        String desc() { return "str".equals(cur().t) ? next().v : null; }
        boolean eof() { return "eof".equals(cur().t); }

        GqlType type(int depth) {
            if (depth > maxDepth) throw new ActionKitError("import_limit", "GraphQL type nesting is too deep");
            GqlType t;
            if (eat("[")) { t = new GqlType("list", null, type(depth + 1)); expect("]"); } else t = GqlType.named(name());
            return eat("!") ? new GqlType("nonnull", null, t) : t;
        }

        /** Skip a constant value (default values, directive arguments). */
        void value(int depth) {
            if (depth > maxDepth) throw new ActionKitError("import_limit", "GraphQL value nesting is too deep");
            Tok t = cur();
            if ("str".equals(t.t)) { i++; return; }
            if ("int".equals(t.t) || "name".equals(t.t)) { i++; return; }
            if (eat("[")) { while (!is("]") && !eof()) value(depth + 1); expect("]"); return; }
            if (eat("{")) { while (!is("}") && !eof()) { name(); expect(":"); value(depth + 1); } expect("}"); return; }
            if (eat("$")) { name(); return; }
            throw new ActionKitError("bad_source", "GraphQL parse error: unexpected '" + clip(t.v, 30) + "'");
        }

        boolean directives() {
            boolean deprecated = false;
            while (eat("@")) {
                String n = name();
                if (n.equals("deprecated")) deprecated = true;
                if (eat("(")) { while (!is(")") && !eof()) { name(); expect(":"); value(0); } expect(")"); }
            }
            return deprecated;
        }

        List<GqlArg> args() {
            List<GqlArg> out = new ArrayList<>();
            if (!eat("(")) return out;
            while (!is(")")) {
                if (eof()) throw new ActionKitError("bad_source", "GraphQL parse error: unterminated argument list");
                String desc = desc();
                if (desc != null && desc.isEmpty()) desc = null;
                String name = name();
                expect(":");
                GqlType type = type(0);
                if (eat("=")) value(0);
                directives();
                out.add(new GqlArg(name, type, desc));
            }
            expect(")");
            return out;
        }

        List<GqlField> fields(boolean input) {
            List<GqlField> out = new ArrayList<>();
            if (!eat("{")) return out;
            while (!is("}")) {
                if (eof()) throw new ActionKitError("bad_source", "GraphQL parse error: unterminated field list");
                String desc = desc();
                if (desc != null && desc.isEmpty()) desc = null;
                String name = name();
                List<GqlArg> args = input ? new ArrayList<>() : args();
                expect(":");
                GqlType type = type(0);
                if (input && eat("=")) value(0);
                boolean dep = directives();
                out.add(new GqlField(name, args, type, dep, desc));
            }
            expect("}");
            return out;
        }

        void def() {
            desc();
            String kw = name();
            if (kw.equals("extend")) { def(); return; }
            if (kw.equals("schema")) {
                directives();
                expect("{");
                while (!is("}")) {
                    if (eof()) throw new ActionKitError("bad_source", "GraphQL parse error: unterminated schema block");
                    String op = name(); expect(":"); String ty = name();
                    if (op.equals("query")) schema.query = ty; else if (op.equals("mutation")) schema.mutation = ty; else if (op.equals("subscription")) schema.subscription = ty;
                }
                expect("}");
                return;
            }
            if (kw.equals("scalar")) { String n = name(); directives(); merge(new GqlTypeDef("scalar", n, new ArrayList<>(), new ArrayList<>())); return; }
            if (kw.equals("directive")) {
                expect("@"); name(); args();
                if (cur().v.equals("repeatable")) i++;
                if (cur().v.equals("on")) i++;
                eat("|");
                name();
                while (eat("|")) name();
                return;
            }
            if (kw.equals("type") || kw.equals("interface") || kw.equals("input")) {
                String n = name();
                if (cur().v.equals("implements")) { i++; eat("&"); name(); while (eat("&")) name(); }
                directives();
                merge(new GqlTypeDef(kw.equals("type") ? "object" : kw.equals("input") ? "input" : "interface", n, fields(kw.equals("input")), new ArrayList<>()));
                return;
            }
            if (kw.equals("union")) {
                String n = name(); directives();
                if (eat("=")) { eat("|"); name(); while (eat("|")) name(); }
                merge(new GqlTypeDef("union", n, new ArrayList<>(), new ArrayList<>()));
                return;
            }
            if (kw.equals("enum")) {
                String n = name(); directives();
                List<String> values = new ArrayList<>();
                if (eat("{")) {
                    while (!is("}")) {
                        if (eof()) throw new ActionKitError("bad_source", "GraphQL parse error: unterminated enum");
                        desc(); values.add(name()); directives();
                    }
                    expect("}");
                }
                merge(new GqlTypeDef("enum", n, new ArrayList<>(), values));
                return;
            }
            throw new ActionKitError("bad_source", "GraphQL parse error: unsupported definition '" + clip(kw, 30) + "' (only type-system definitions are imported)");
        }

        void merge(GqlTypeDef d) {
            GqlTypeDef old = schema.types.get(d.name);
            if (old == null) { schema.types.put(d.name, d); return; }
            old.fields.addAll(d.fields);
            old.values.addAll(d.values);
        }
    }

    public static GqlSchema parseGraphqlSdl(String src) { return parseGraphqlSdl(src, 2_000_000); }

    public static GqlSchema parseGraphqlSdl(String src, int maxTokens) {
        List<Tok> toks = lex(src, maxTokens);
        GqlSchema schema = new GqlSchema();
        P p = new P(toks, schema, 32);
        while (!p.eof()) p.def();
        return schema;
    }

    // ---- introspection to model ----

    private static GqlType introspectType(Object t, int depth) {
        if (depth > 16 || !(t instanceof Map)) throw new ActionKitError("bad_source", "malformed introspection type reference");
        Map<String, Object> m = Jx.m(t);
        if ("NON_NULL".equals(m.get("kind"))) return new GqlType("nonnull", null, introspectType(m.get("ofType"), depth + 1));
        if ("LIST".equals(m.get("kind"))) return new GqlType("list", null, introspectType(m.get("ofType"), depth + 1));
        if (!(m.get("name") instanceof String)) throw new ActionKitError("bad_source", "malformed introspection type reference");
        return GqlType.named((String) m.get("name"));
    }

    private static String rootName(Map<String, Object> s, String k) {
        Object o = s.get(k);
        return o instanceof Map && Jx.m(o).get("name") instanceof String ? (String) Jx.m(o).get("name") : null;
    }

    private static GqlField fieldOf(Object f) {
        if (!(f instanceof Map) || !(Jx.m(f).get("name") instanceof String)) return null;
        Map<String, Object> m = Jx.m(f);
        List<GqlArg> args = new ArrayList<>();
        if (m.get("args") instanceof List) {
            for (Object a : Jx.a(m.get("args"))) {
                if (!(a instanceof Map) || !(Jx.m(a).get("name") instanceof String)) continue;
                args.add(new GqlArg((String) Jx.m(a).get("name"), introspectType(Jx.m(a).get("type"), 0), Jx.m(a).get("description") instanceof String ? (String) Jx.m(a).get("description") : null));
            }
        }
        GqlType type = !m.containsKey("type") ? GqlType.named("String") : introspectType(m.get("type"), 0);
        return new GqlField((String) m.get("name"), args, type, Boolean.TRUE.equals(m.get("isDeprecated")), m.get("description") instanceof String ? (String) m.get("description") : null);
    }

    public static GqlSchema fromIntrospection(Object doc) {
        Object root = doc instanceof Map && Jx.m(doc).get("data") instanceof Map ? Jx.m(doc).get("data") : doc;
        Object s = root instanceof Map && Jx.m(root).get("__schema") instanceof Map ? Jx.m(root).get("__schema") : null;
        if (s == null || !(Jx.m(s).get("types") instanceof List)) throw new ActionKitError("bad_source", "not a GraphQL introspection result (no __schema.types)");
        Map<String, Object> sm = Jx.m(s);
        GqlSchema schema = new GqlSchema();
        String q = rootName(sm, "queryType"), m = rootName(sm, "mutationType"), sub = rootName(sm, "subscriptionType");
        if (q != null && !q.isEmpty()) schema.query = q;
        if (m != null && !m.isEmpty()) schema.mutation = m;
        if (sub != null && !sub.isEmpty()) schema.subscription = sub;
        Map<String, String> kinds = Map.of("OBJECT", "object", "INPUT_OBJECT", "input", "ENUM", "enum", "SCALAR", "scalar", "INTERFACE", "interface", "UNION", "union");
        for (Object to : Jx.a(sm.get("types"))) {
            if (!(to instanceof Map)) continue;
            Map<String, Object> t = Jx.m(to);
            if (!(t.get("name") instanceof String) || !(t.get("kind") instanceof String)) continue;
            String name = (String) t.get("name");
            if (name.startsWith("__")) continue;
            String kind = kinds.get((String) t.get("kind"));
            if (kind == null) continue;
            Object fieldsRaw = kind.equals("input") ? t.get("inputFields") : t.get("fields");
            List<GqlField> fields = new ArrayList<>();
            if (fieldsRaw instanceof List) for (Object f : Jx.a(fieldsRaw)) { GqlField g = fieldOf(f); if (g != null) fields.add(g); }
            List<String> values = new ArrayList<>();
            if (t.get("enumValues") instanceof List) for (Object e : Jx.a(t.get("enumValues"))) if (e instanceof Map && Jx.m(e).get("name") instanceof String) values.add((String) Jx.m(e).get("name"));
            schema.types.put(name, new GqlTypeDef(kind, name, fields, values));
        }
        return schema;
    }

    // ---- model to JSON-schema-like to params ----

    private static Map<String, Object> scalar(String name) {
        switch (name) {
            case "Int": return Jx.obj("type", "integer", "format", "int32");
            case "String": case "ID": return Jx.obj("type", "string");
            case "Boolean": return Jx.obj("type", "boolean");
            case "Float": return Jx.obj("type", "number");
            case "Date": return Jx.obj("type", "string", "format", "date");
            case "DateTime": return Jx.obj("type", "string", "format", "date-time");
            case "Email": return Jx.obj("type", "string", "format", "email");
            case "UUID": return Jx.obj("type", "string", "format", "uuid");
            case "URL": case "URI": return Jx.obj("type", "string", "format", "url");
            default: return null;
        }
    }

    private static final class R {
        final Map<String, Object> s;
        final boolean nonnull;
        R(Map<String, Object> s, boolean nonnull) { this.s = s; this.nonnull = nonnull; }
    }

    /** A GraphQL type as a JSON-schema-like node; input objects expand with a cycle guard and a node budget. */
    private static R schemaOf(GqlType t, GqlSchema gs, Ctx c, Budget bud, List<String> stack, String where) {
        boolean nonnull = false;
        GqlType cur = t;
        while ("nonnull".equals(cur.k)) { nonnull = true; cur = cur.of; }
        if ("list".equals(cur.k)) return new R(Jx.obj("type", "array", "items", schemaOf(cur.of, gs, c, bud, stack, where).s), nonnull);
        String name = cur.name;
        if (bud.left-- <= 0) {
            if (!bud.exhausted) { bud.exhausted = true; addTodo(c, where, "ref_budget", "type expansion stopped at the node budget (declared string; refine or drop)"); }
            return new R(new LinkedHashMap<>(), nonnull);
        }
        Map<String, Object> sc = scalar(name);
        if (sc != null) return new R(sc, nonnull);
        GqlTypeDef def = gs.types.get(name);
        if (def == null) { addTodo(c, where, "unknown_type", "type '" + clip(name, 60) + "' is not defined in the schema (declared string)"); return new R(new LinkedHashMap<>(), nonnull); }
        if (def.kind.equals("enum")) return new R(Jx.obj("type", "string", "enum", new ArrayList<Object>(new LinkedHashSet<>(def.values))), nonnull);
        if (def.kind.equals("scalar")) return new R(Jx.obj("type", "string"), nonnull);
        if (def.kind.equals("input")) {
            if (stack.contains(name)) { addTodo(c, where, "cyclic_ref", "input type '" + clip(name, 60) + "' is recursive (declared string; refine or drop)"); return new R(new LinkedHashMap<>(), nonnull); }
            Map<String, Object> properties = new LinkedHashMap<>();
            List<Object> required = new ArrayList<>();
            List<String> ns = new ArrayList<>(stack);
            ns.add(name);
            for (GqlField f : def.fields) {
                R r = schemaOf(f.type, gs, c, bud, ns, where);
                Map<String, Object> p = new LinkedHashMap<>(r.s);
                if (Jx.truthy(f.desc)) p.put("description", f.desc);
                putProp(properties, f.name, p);
                if (r.nonnull) required.add(f.name);
            }
            return new R(Jx.obj("type", "object", "properties", properties, "required", required), nonnull);
        }
        addTodo(c, where, "output_type", "type '" + clip(name, 60) + "' is an output type and cannot be an argument (declared string)");
        return new R(new LinkedHashMap<>(), nonnull);
    }

    public static Map<String, Object> importGraphql(Object source, Map<String, Object> opts) {
        Ctx c = newCtx("graphql", source, opts);
        GqlSchema gs = source instanceof String ? parseGraphqlSdl((String) source) : fromIntrospection(source);
        String[][] roots = {{gs.query != null ? gs.query : "Query", "query"}, {gs.mutation != null ? gs.mutation : "Mutation", "mutation"}, {gs.subscription != null ? gs.subscription : "Subscription", "subscription"}};
        for (String[] ro : roots) {
            GqlTypeDef rt = gs.types.get(ro[0]);
            if (rt == null) continue;
            String op = ro[1];
            List<GqlField> fs = new ArrayList<>(rt.fields);
            fs.sort((a, b) -> IntentJs.compareUtf8(a.name, b.name));
            for (GqlField f : fs) {
                String where = op + " " + clip(f.name, 80);
                c.root = null;
                Budget bud = newBudget(c);
                Map<String, Object> properties = new LinkedHashMap<>();
                List<Object> required = new ArrayList<>();
                for (GqlArg a : f.args) {
                    R r = schemaOf(a.type, gs, c, bud, new ArrayList<>(), where + "(" + a.name + ")");
                    Map<String, Object> p = new LinkedHashMap<>(r.s);
                    if (Jx.truthy(a.desc)) p.put("description", a.desc);
                    putProp(properties, a.name, p);
                    if (r.nonnull) required.add(a.name);
                }
                Map<String, Object> params = new LinkedHashMap<>();
                flattenObject(Jx.obj("type", "object", "properties", properties, "required", required), c, bud, where, params);
                if (f.deprecated) addTodo(c, where, "deprecated", "the field is marked @deprecated");
                Draft d = new Draft();
                d.name = f.name;
                d.title = Jx.truthy(f.desc) ? f.desc.split("\n", -1)[0] : f.name;
                d.description = f.desc;
                d.effects = new ArrayList<>(List.of(op.equals("mutation") ? "update" : "read"));
                d.scope = "one";
                d.params = params;
                if (op.equals("subscription")) d.traits = withTrait(null, "pca.bulk");
                if (!op.equals("mutation")) d.idempotency = Jx.obj("mode", "natural");
                d.bindings = Jx.obj("graphql", Jx.obj("op", op, "field", clip(f.name, 200)));
                emitDef(c, d);
            }
        }
        return finish(c);
    }
}
