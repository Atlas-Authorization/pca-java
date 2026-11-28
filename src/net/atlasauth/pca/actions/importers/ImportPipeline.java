package net.atlasauth.pca.actions.importers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Actions.ActionKitError;
import net.atlasauth.pca.Json;

/**
 * {@code import} then {@code suggest} as one call, the importer registry of the command line, and the text forms the CLI prints and reads
 * (JSON Lines of defs). Pure: no file system, no network (the caller fetches and writes). YAML is not handled here: a YAML source is parsed by
 * the caller and passed in as the already-parsed JSON tree.
 */
public final class ImportPipeline {
    private ImportPipeline() {}

    /** Kept for callers of the first importer: the default operation bound. */
    public static final int MAX_IMPORT_OPS = 20_000;

    /** Import one source of the given kind. Every def is {@code unreviewed}. {@code opts}: the common options (plus {@code verb} etc. for jsonschema). */
    public static Map<String, Object> importActions(String kind, Object source, Map<String, Object> opts) {
        if (kind == null) throw new ActionKitError("bad_kind", "unknown import kind 'null' (one of " + String.join(", ", ImportCommon.IMPORT_KINDS) + ")");
        switch (kind) {
            case "openapi": return OpenApiImporter.importOpenApi(source, opts);
            case "mcp": return McpImporter.importMcp(source, opts);
            case "graphql": return GraphqlImporter.importGraphql(source, opts);
            case "grpc": return GrpcImporter.importGrpc(source, opts);
            case "asyncapi": return AsyncApiImporter.importAsyncApi(source, opts);
            case "jsonschema": return JsonSchemaImporter.importJsonSchema(source, opts);
            default: throw new ActionKitError("bad_kind", "unknown import kind '" + kind + "' (one of " + String.join(", ", ImportCommon.IMPORT_KINDS) + ")");
        }
    }

    /**
     * The command-line importer shape: {@code {defs, todo: ["<where>: <message>"]}}. A JSON Schema import needs {@code verb} in the options.
     * Kinds are exactly {@link ImportCommon#IMPORT_KINDS}.
     */
    public static Map<String, Object> runImporter(String kind, Object doc, Map<String, Object> opts) {
        if (!ImportCommon.IMPORT_KINDS.contains(kind)) throw new IllegalArgumentException("no importer '" + kind + "'");
        if (kind.equals("jsonschema") && !Jx.truthy(opts.get("verb"))) throw new IllegalArgumentException("a JSON Schema import needs --verb <ns.noun.action>");
        Map<String, Object> r = importActions(kind, doc, opts);
        List<Object> todo = new ArrayList<>();
        for (Object t : Jx.a(r.get("todo"))) todo.add(Jx.jsStr(Jx.get(t, "where")) + ": " + Jx.jsStr(Jx.get(t, "message")));
        return Jx.obj("defs", r.get("defs"), "todo", todo);
    }

    /** What {@link #suggestDefs} reads: {@code mode} ({@code rules} default, {@code model}, {@code none}), rule set, registry, model adapters. */
    public static final class SuggestOpts {
        public String mode;
        public Map<String, Object> rules;
        public Actions.Registry registry;
        public List<? extends ImportModel.ModelAdapter> models;
    }

    /** Suggest for already imported defs. Returns {@code {defs (state suggested), errors: [{verb, model, error}]}}. */
    public static Map<String, Object> suggestDefs(List<Map<String, Object>> defs, SuggestOpts o) {
        SuggestOpts so = o == null ? new SuggestOpts() : o;
        String mode = so.mode == null ? "rules" : so.mode;
        if (mode.equals("none")) return Jx.obj("defs", new ArrayList<Object>(defs), "errors", new ArrayList<>());
        Actions.Registry registry = so.registry != null ? so.registry : Actions.CORE_REGISTRY;
        Map<String, Object> rules = so.rules != null ? so.rules : ImportRules.DEFAULT_RULES;
        String digest = rules == ImportRules.DEFAULT_RULES ? (String) ImportRules.DEFAULT_RULES_SEALED.get("digest") : ImportSuggest.rulesDigest(rules);
        List<Object> out = new ArrayList<>(), errors = new ArrayList<>();
        for (Map<String, Object> d : defs) {
            Map<String, Object> s = ImportSuggest.suggestWithRules(d, rules, registry);
            List<Object> models = null;
            if (mode.equals("model")) {
                Map<String, Object> run = ImportModel.suggestWithModels(d, so.models == null ? List.<ImportModel.ModelAdapter>of() : so.models, registry);
                for (Object e : Jx.a(run.get("errors"))) { Map<String, Object> m = new LinkedHashMap<>(); m.put("verb", d.get("verb")); m.putAll(Jx.m(e)); errors.add(m); }
                TreeSet<String> tr = new TreeSet<>();
                for (Object t : Jx.a(s.get("traits"))) tr.add((String) t);
                for (Object t : Jx.a(Jx.m(run.get("suggestion")).get("traits"))) tr.add((String) t);
                s = Jx.obj("traits", new ArrayList<Object>(tr), "roles", s.get("roles"), "tags", s.get("tags"), "fired", s.get("fired"));
                models = Jx.a(run.get("models"));
            }
            Map<String, Object> by = Jx.obj("rules", Jx.obj("version", rules.get("version"), "digest", digest, "fired", s.get("fired")));
            if (models != null && !models.isEmpty()) by.put("models", models);
            out.add(ImportSuggest.applySuggestion(d, s, by));
        }
        return Jx.obj("defs", out, "errors", errors);
    }

    /** Import then suggest: the import report with {@code defs} replaced by the suggested defs, plus {@code suggestErrors}. */
    public static Map<String, Object> importAndSuggest(String kind, Object source, Map<String, Object> opts, SuggestOpts suggest) {
        Map<String, Object> r = importActions(kind, source, opts);
        List<Map<String, Object>> defs = new ArrayList<>();
        for (Object d : Jx.a(r.get("defs"))) defs.add(Jx.m(d));
        Map<String, Object> s = suggestDefs(defs, suggest);
        Map<String, Object> out = new LinkedHashMap<>(r);
        out.put("defs", s.get("defs"));
        out.put("suggestErrors", s.get("errors"));
        return out;
    }

    // ---- JSON Lines ----

    /** One def per line, strict canonical JSON, sorted by verb: byte-reproducible. */
    public static String defsToJsonl(List<Map<String, Object>> defs) {
        List<Map<String, Object>> sorted = new ArrayList<>(defs);
        sorted.sort((a, b) -> ((String) a.get("verb")).compareTo((String) b.get("verb")));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < sorted.size(); i++) { if (i > 0) sb.append('\n'); sb.append(Json.canonicalizeStrict(sorted.get(i))); }
        if (!defs.isEmpty()) sb.append('\n');
        return sb.toString();
    }

    /** Parse and validate a JSONL file of defs. Throws ActionKitError {@code bad_defs} naming the first bad line. */
    public static List<Map<String, Object>> jsonlToDefs(String text) {
        List<Map<String, Object>> out = new ArrayList<>();
        String[] lines = text.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String l = Jx.jsTrim(lines[i]);
            if (l.isEmpty()) continue;
            Object v;
            try { v = Json.parseLenient(l); } catch (RuntimeException e) { throw new ActionKitError("bad_defs", "line " + (i + 1) + ": not JSON"); }
            String bad = Actions.validateDef(v);
            if (bad != null) throw new ActionKitError("bad_defs", "line " + (i + 1) + ": " + bad);
            out.add(Jx.m(v));
        }
        return out;
    }
}
