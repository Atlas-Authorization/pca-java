package net.atlasauth.pca.actions.importers;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.actions.ActionEffective;
import net.atlasauth.pca.intent.IntentStats;

/**
 * Measure the suggestion rules against a labeled corpus. Every corpus entry is turned into a source document of its own kind, run through the
 * REAL importer and the REAL suggestion engine, and the traits the system flags are compared with the labels. Precision and recall per trait,
 * with an exact Clopper-Pearson bound on each. These are heuristic numbers on a reviewed corpus, published as what they are, never as a safety
 * guarantee. Entries, reports and floors are JSON trees.
 */
public final class ImportEval {
    private ImportEval() {}

    public static final Map<String, String> LABEL_SHORT = new LinkedHashMap<>();
    static {
        String[][] kv = {{"money", "money_moving"}, {"destr", "destructive"}, {"comm", "external_communication"}, {"priv", "privilege_change"}, {"exp", "data_export"}, {"exec", "code_execution"},
            {"cred", "credential_access"}, {"bulk", "bulk"}, {"pii", "pii_access"}, {"pub", "public_exposure"}, {"pers", "persistence"}, {"infra", "infra_mutation"}, {"cost", "cost_incurring"},
            {"legal", "legal_binding"}, {"imp", "impersonation"}, {"egress", "network_egress"}, {"fin", "financial_data_read"}, {"reg", "regulated_data"}, {"sched", "scheduled"}, {"spawn", "agent_spawning"}};
        for (String[] p : kv) LABEL_SHORT.put(p[0], p[1]);
    }

    private static List<Object> splitList(String s, String sep) {
        List<Object> out = new ArrayList<>();
        for (String x : s.split(Pattern.quote(sep), -1)) out.add(x);
        return out;
    }

    private static String pad4(int n) { String s = Integer.toString(n); return "0".repeat(Math.max(0, 4 - s.length())) + s; }

    /** The hand-labeled TSV: {@code kind, name, location, params, labels, description} per line. Throws on a short line or an unknown label. */
    public static List<Object> parseHandTsv(String text) {
        List<Object> out = new ArrayList<>();
        int n = 0;
        for (String line : text.split("\n", -1)) {
            if (Jx.jsTrim(line).isEmpty() || line.startsWith("#")) continue;
            String[] c = line.split("\t", -1);
            if (c.length < 6) throw new IllegalArgumentException("hand corpus line needs 6 columns: " + (line.length() > 80 ? line.substring(0, 80) : line));
            String kind = c[0], name = c[1], loc = c[2], params = c[3], labels = c[4], description = c[5];
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("id", "hand-" + pad4(++n));
            e.put("src", "hand");
            e.put("kind", kind);
            e.put("name", name);
            e.put("params", params.equals("-") ? new ArrayList<>() : splitList(params, ","));
            List<Object> ls = new ArrayList<>();
            if (!labels.equals("-")) for (Object l : splitList(labels, ",")) ls.add(LABEL_SHORT.containsKey(l) ? LABEL_SHORT.get(l) : l);
            e.put("labels", ls);
            e.put("description", description);
            if (kind.equals("openapi")) {
                int sp = loc.indexOf(' ');
                e.put("method", sp < 0 ? loc : loc.substring(0, sp));
                e.put("path", sp < 0 ? "" : loc.substring(sp + 1));
            }
            for (Object l : ls) if (!LABEL_SHORT.containsValue(l)) throw new IllegalArgumentException("unknown label '" + l + "' in " + name);
            out.add(e);
        }
        return out;
    }

    /** One JSON entry per non-blank line. */
    public static List<Object> parseCorpusJsonl(String text) {
        List<Object> out = new ArrayList<>();
        for (String l : text.split("\n", -1)) if (!Jx.jsTrim(l).isEmpty()) out.add(Json.parseLenient(l));
        return out;
    }

    // ---- entries to source documents ----

    private static final Pattern SPEC_RE = Pattern.compile("^[^:]+:([a-z]+)(?::(.+))?\\z");
    private static final Pattern TYPE_RE = Pattern.compile("^[^:]+:([a-z]+)");

    private static Map<String, Object> schemaOf(String spec) {
        Matcher m = SPEC_RE.matcher(spec);
        String type = null, format = null;
        if (m.find()) { type = m.group(1); format = m.group(2); }
        if ("array".equals(type)) return Jx.obj("type", "array", "items", Jx.obj("type", "string"));
        Map<String, Object> o = Jx.obj("type", "number".equals(type) ? "number" : (type != null ? type : "string"));
        if (format != null && !format.isEmpty()) o.put("format", format);
        return o;
    }

    /** {@code spec.slice(0, spec.indexOf(':'))}: with no colon the slice drops the last character. */
    private static String pname(String spec) {
        int i = spec.indexOf(':');
        int end = i < 0 ? spec.length() - 1 : i;
        return end <= 0 ? "" : spec.substring(0, end);
    }

    private static final Set<String> READ_FIRST = new LinkedHashSet<>(List.of("get", "list", "find", "search", "count", "describe", "show", "lookup", "check", "validate", "preview", "calculate", "estimate",
        "convert", "format", "compare", "summarize", "sort", "filter", "read", "fetch", "query", "view", "browse", "open"));
    private static final Pattern FIRST_WORD = Pattern.compile("^[A-Za-z][a-z0-9]*");
    private static final Pattern PLURAL = Pattern.compile("[a-z]+s?");
    private static final Pattern PATH_PARAM = Pattern.compile("\\{([^}]+)\\}");

    private static String firstWord(String n) {
        Matcher m = FIRST_WORD.matcher(n);
        return (m.find() ? m.group() : n).toLowerCase(java.util.Locale.ROOT);
    }

    private static List<String> strs(Object o) { List<String> out = new ArrayList<>(); for (Object x : Jx.a(o)) out.add((String) x); return out; }

    private static Object openapiDoc(List<Map<String, Object>> es) {
        Map<String, Object> paths = new LinkedHashMap<>();
        for (Map<String, Object> e : es) {
            String method = (e.get("method") != null ? (String) e.get("method") : "get").toLowerCase(java.util.Locale.ROOT);
            boolean body = List.of("post", "put", "patch").contains(method);
            Map<String, Object> props = new LinkedHashMap<>();
            List<String> ps = strs(e.get("params"));
            for (String p : ps) ImportCommon.putProp(props, pname(p), schemaOf(p));
            List<Object> pathParams = new ArrayList<>();
            List<String> ppNames = new ArrayList<>();
            Matcher pm = PATH_PARAM.matcher(e.get("path") != null ? (String) e.get("path") : "");
            while (pm.find()) { ppNames.add(pm.group(1)); pathParams.add(Jx.obj("name", pm.group(1), "in", "path", "required", Boolean.TRUE, "schema", Jx.obj("type", "string"))); }
            Map<String, Object> op = new LinkedHashMap<>();
            if (Jx.truthy(e.get("name"))) op.put("operationId", e.get("name"));
            if (Jx.truthy(e.get("description"))) op.put("summary", e.get("description"));
            List<Object> parameters = new ArrayList<>(pathParams);
            if (!body) for (String p : ps) if (!ppNames.contains(pname(p))) parameters.add(Jx.obj("name", pname(p), "in", "query", "schema", schemaOf(p)));
            op.put("parameters", parameters);
            if (body && !ps.isEmpty())
                op.put("requestBody", Jx.obj("content", Jx.obj("application/json", Jx.obj("schema", Jx.obj("type", "object", "properties", props, "required", new ArrayList<>())))));
            String path = (String) e.get("path");
            Map<String, Object> item = Jx.m(paths.computeIfAbsent(path, k -> new LinkedHashMap<String, Object>()));
            item.put(method, op);
        }
        return Jx.obj("openapi", "3.0.3", "info", Jx.obj("title", "corpus", "version", "1"), "paths", paths);
    }

    private static String gqlType(String spec) {
        Matcher m = TYPE_RE.matcher(spec);
        String t = m.find() ? m.group(1) : "string";
        switch (t) { case "string": return "String"; case "integer": return "Int"; case "boolean": return "Boolean"; case "array": return "[String]"; default: return "String"; }
    }

    private static String graphqlSdl(List<Map<String, Object>> es) {
        List<String> q = new ArrayList<>(), m = new ArrayList<>();
        for (Map<String, Object> e : es) {
            String name = (String) e.get("name");
            List<String> ps = strs(e.get("params"));
            String args = "";
            if (!ps.isEmpty()) { List<String> a = new ArrayList<>(); for (String p : ps) a.add(pname(p) + ": " + gqlType(p)); args = "(" + String.join(", ", a) + ")"; }
            ((READ_FIRST.contains(firstWord(name)) || PLURAL.matcher(name).matches()) ? q : m).add("  \"" + ((String) e.get("description")).replace("\"", "'") + "\"\n  " + name + args + ": String");
        }
        return (q.isEmpty() ? "" : "type Query {\n" + String.join("\n", q) + "\n}\n") + (m.isEmpty() ? "" : "type Mutation {\n" + String.join("\n", m) + "\n}\n");
    }

    private static String protoType(String spec) {
        Matcher m = TYPE_RE.matcher(spec);
        String t = m.find() ? m.group(1) : "string";
        switch (t) { case "string": return "string"; case "integer": return "int64"; case "boolean": return "bool"; case "array": return "repeated string"; default: return "string"; }
    }

    private static String protoText(List<Map<String, Object>> es) {
        Map<String, List<Map<String, Object>>> svcs = new LinkedHashMap<>();
        for (Map<String, Object> e : es) svcs.computeIfAbsent(((String) e.get("name")).split("/", -1)[0], k -> new ArrayList<>()).add(e);
        List<String> msgs = new ArrayList<>(List.of("message Empty {}"));
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, List<Map<String, Object>>> sv : svcs.entrySet()) {
            List<String> rpcs = new ArrayList<>();
            for (Map<String, Object> e : sv.getValue()) {
                String[] parts = ((String) e.get("name")).split("/", -1);
                String mname = parts.length > 1 ? parts[1] : "undefined";
                List<String> ps = strs(e.get("params"));
                List<String> fs = new ArrayList<>();
                for (int i = 0; i < ps.size(); i++) fs.add("  " + protoType(ps.get(i)) + " " + pname(ps.get(i)) + " = " + (i + 1) + ";");
                msgs.add("message " + mname + "Request {\n" + String.join("\n", fs) + "\n}");
                rpcs.add("  rpc " + mname + "(" + mname + "Request) returns (Empty);");
            }
            out.add("service " + sv.getKey() + " {\n" + String.join("\n", rpcs) + "\n}");
        }
        return "syntax = \"proto3\";\npackage corpus;\n" + String.join("\n", msgs) + "\n" + String.join("\n", out) + "\n";
    }

    private static Object asyncDoc(List<Map<String, Object>> es) {
        Map<String, Object> channels = new LinkedHashMap<>();
        for (Map<String, Object> e : es) {
            Map<String, Object> props = new LinkedHashMap<>();
            for (String p : strs(e.get("params"))) ImportCommon.putProp(props, pname(p), schemaOf(p));
            channels.put((String) e.get("name"), Jx.obj("publish", Jx.obj("summary", e.get("description"), "message", Jx.obj("payload", Jx.obj("type", "object", "properties", props)))));
        }
        return Jx.obj("asyncapi", "2.6.0", "info", Jx.obj("title", "corpus", "version", "1"), "channels", channels);
    }

    private static Object mcpDoc(List<Map<String, Object>> es) {
        List<Object> out = new ArrayList<>();
        for (Map<String, Object> e : es) {
            Map<String, Object> props = new LinkedHashMap<>();
            for (String p : strs(e.get("params"))) ImportCommon.putProp(props, pname(p), schemaOf(p));
            out.add(Jx.obj("name", e.get("name"), "description", e.get("description"), "inputSchema", Jx.obj("type", "object", "properties", props)));
        }
        return out;
    }

    private static String keyOf(Map<String, Object> e) {
        return "openapi".equals(e.get("kind")) ? (e.get("method") != null ? Jx.jsStr(e.get("method")).toUpperCase(java.util.Locale.ROOT) : "GET") + " " + Jx.jsStr(e.get("path")) : Jx.jsStr(e.get("name"));
    }

    private static String defKey(Map<String, Object> d) {
        Object b = d.get("bindings");
        Object oa = Jx.get(b, "openapi");
        if (Jx.truthy(Jx.get(oa, "path"))) return Jx.jsStr(Jx.get(oa, "method")) + " " + Jx.jsStr(Jx.get(oa, "path"));
        if (Jx.get(oa, "operationId") != null) return Jx.jsStr(Jx.get(oa, "operationId"));
        if (Jx.get(Jx.get(b, "mcp"), "tool") != null) return Jx.jsStr(Jx.get(Jx.get(b, "mcp"), "tool"));
        if (Jx.get(Jx.get(b, "graphql"), "field") != null) return Jx.jsStr(Jx.get(Jx.get(b, "graphql"), "field"));
        Object g = Jx.get(b, "grpc");
        if (Jx.truthy(g)) { String[] sv = Jx.jsStr(Jx.get(g, "service")).split("\\.", -1); return sv[sv.length - 1] + "/" + Jx.jsStr(Jx.get(g, "method")); }
        if (Jx.get(Jx.get(b, "asyncapi"), "channel") != null) return Jx.jsStr(Jx.get(Jx.get(b, "asyncapi"), "channel"));
        return "";
    }

    /**
     * Import every entry with the real importer of its kind. Returns {@code {defs: {id: def}, todo: n}} (an entry whose def was not emitted is absent).
     */
    public static Map<String, Object> importCorpus(List<Object> entries) {
        Map<String, Object> defs = new LinkedHashMap<>();
        long todo = 0;
        Map<String, List<Map<String, Object>>> groups = new LinkedHashMap<>();
        for (Object eo : entries) {
            Map<String, Object> e = Jx.m(eo);
            String g = Jx.jsStr(e.get("kind")) + "|" + (e.get("spec") != null ? Jx.jsStr(e.get("spec")) : "");
            groups.computeIfAbsent(g, k -> new ArrayList<>()).add(e);
        }
        Map<String, Object> opts = Jx.obj("ns", "corpus", "limits", Jx.obj("max_ops", Jx.n(50_000), "max_nodes", Jx.n(20_000_000), "max_bytes", Jx.n(200_000_000)));
        for (Map.Entry<String, List<Map<String, Object>>> g : groups.entrySet()) {
            String kind = g.getKey().split("\\|", -1)[0];
            List<Map<String, Object>> es = g.getValue();
            Object src = kind.equals("openapi") ? openapiDoc(es) : kind.equals("mcp") ? mcpDoc(es) : kind.equals("graphql") ? graphqlSdl(es) : kind.equals("grpc") ? protoText(es) : asyncDoc(es);
            Map<String, Object> r = ImportPipeline.importActions(kind, src, opts);
            todo += Jx.a(r.get("todo")).size();
            Map<String, Object> byKey = new LinkedHashMap<>();
            for (Object d : Jx.a(r.get("defs"))) byKey.put(defKey(Jx.m(d)), d);
            for (Map<String, Object> e : es) { Object d = byKey.get(keyOf(e)); if (d != null) defs.put((String) e.get("id"), d); }
        }
        return Jx.obj("defs", defs, "todo", Jx.n(todo));
    }

    // ---- scoring ----

    /** Deterministic split of the real corpus by specification: rules are tuned on {@code tune} specs only; {@code holdout} specs are never looked at when editing rules. */
    public static String realSplit(Object spec) {
        String s = spec == null ? "" : Jx.jsStr(spec);
        long h = 2166136261L;
        for (int i = 0; i < s.length(); ) {
            int code = s.charAt(i);                  // charCodeAt(0) of the code point: its first UTF-16 unit
            i += Character.charCount(s.codePointAt(i));
            int x = ((int) h) ^ code;                // ToInt32(h) ^ code
            h = ((long) (x * 16777619)) & 0xFFFFFFFFL; // Math.imul, then >>> 0
        }
        return ((h >>> 7) % 2) == 0 ? "tune" : "holdout";
    }

    private static String sourceOf(Map<String, Object> e) { return "real".equals(e.get("src")) ? "real/" + realSplit(e.get("spec")) : Jx.jsStr(e.get("src")); }

    private static Map<String, Object> stat(String trait, List<boolean[]> rows, double alpha) {
        int tp = 0, fp = 0, fn = 0;
        for (boolean[] r : rows) { if (r[0] && r[1]) tp++; else if (r[1]) fp++; else if (r[0]) fn++; }
        int pos = tp + fn, pred = tp + fp;
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("trait", trait);
        o.put("positives", Jx.n(pos));
        o.put("predicted", Jx.n(pred));
        o.put("tp", Jx.n(tp));
        o.put("fp", Jx.n(fp));
        o.put("fn", Jx.n(fn));
        o.put("precision", pred == 0 ? null : (Object) Double.valueOf((double) tp / pred));
        o.put("recall", pos == 0 ? null : (Object) Double.valueOf((double) tp / pos));
        o.put("recall_lower", pos == 0 ? null : (Object) Double.valueOf(1 - IntentStats.clopperPearsonUpper(fn, pos, alpha)));
        // the exact bound costs O(n * k) big-integer products: affordable for recall (few misses), not for precision over thousands of flags
        o.put("precision_lower", pred == 0 || pred > 600 ? null : (Object) Double.valueOf(1 - IntentStats.clopperPearsonUpper(fp, pred, alpha)));
        return o;
    }

    private static String strip(String t) { return t.startsWith("pca.") ? t.substring(4) : t; }

    private static List<Object> score(List<Map<String, Object>> es, Map<String, Set<String>> pred, List<String> traitNames, double alpha) {
        List<Object> out = new ArrayList<>();
        for (String t : traitNames) {
            List<boolean[]> rows = new ArrayList<>();
            for (Map<String, Object> e : es) {
                Set<String> p = pred.get(Jx.jsStr(e.get("id")));
                rows.add(new boolean[] {Jx.a(e.get("labels")).contains(t), p != null && p.contains(t)});
            }
            Map<String, Object> s = stat(t, rows, alpha);
            if (Jx.num(s.get("positives")) > 0 || Jx.num(s.get("predicted")) > 0) out.add(s);
        }
        return out;
    }

    /** {@code evalSuggest}: {@code rules} and {@code registry} default to the shipped ones; {@code alpha} to 0.05. */
    public static Map<String, Object> evalSuggest(List<Object> entriesO, Map<String, Object> rulesIn, Actions.Registry registryIn, Double alphaIn) {
        Map<String, Object> rules = rulesIn != null ? rulesIn : ImportRules.DEFAULT_RULES;
        Actions.Registry registry = registryIn != null ? registryIn : Actions.CORE_REGISTRY;
        double alpha = alphaIn != null ? alphaIn : 0.05;
        List<Map<String, Object>> entries = new ArrayList<>();
        for (Object e : entriesO) entries.add(Jx.m(e));
        Map<String, Object> defs = Jx.m(importCorpus(entriesO).get("defs"));
        TreeSet<String> names = new TreeSet<>();
        for (String t : registry.traits.keySet()) if (!t.equals("pca.unreviewed") && !t.equals("pca.irreversible")) names.add(strip(t));
        List<String> traitNames = new ArrayList<>(names);
        Map<String, Set<String>> flagged = new LinkedHashMap<>(), added = new LinkedHashMap<>();
        for (Map<String, Object> e : entries) {
            Object d = defs.get(Jx.jsStr(e.get("id")));
            if (d == null) continue;
            Map<String, Object> s = ImportSuggest.suggestWithRules(Jx.m(d), rules, registry);
            Map<String, Object> sd = ImportSuggest.applySuggestion(Jx.m(d), s, Jx.obj("rules", Jx.obj("version", rules.get("version"), "digest", "", "fired", s.get("fired"))));
            Set<String> fl = new LinkedHashSet<>();
            for (String t : Actions.closure(registry, ActionEffective.hintTraits(sd))) if (!t.equals("pca.unreviewed")) fl.add(strip(t));
            flagged.put(Jx.jsStr(e.get("id")), fl);
            Set<String> ad = new LinkedHashSet<>();
            for (Object t : Jx.a(s.get("traits"))) ad.add(strip((String) t));
            added.put(Jx.jsStr(e.get("id")), ad);
        }
        TreeSet<String> sources = new TreeSet<>();
        boolean anyReal = false;
        for (Map<String, Object> e : entries) { sources.add(sourceOf(e)); if ("real".equals(e.get("src"))) anyReal = true; }
        if (anyReal) sources.add("real");
        Map<String, Object> bySource = new LinkedHashMap<>();
        for (String s : sources) {
            List<Map<String, Object>> es = new ArrayList<>();
            for (Map<String, Object> e : entries) if (s.equals("real") ? "real".equals(e.get("src")) : sourceOf(e).equals(s)) es.add(e);
            bySource.put(s, Jx.obj("entries", Jx.n(es.size()), "flagged", score(es, flagged, traitNames, alpha)));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("alpha", alpha);
        out.put("entries", Jx.n(entries.size()));
        out.put("mapped", Jx.n(defs.size()));
        out.put("rules_version", rules.get("version"));
        out.put("flagged", score(entries, flagged, traitNames, alpha));
        out.put("suggested", score(entries, added, traitNames, alpha));
        out.put("by_source", bySource);
        return out;
    }

    private static String pct(Object x) {
        if (x == null) return "-";
        double d = Jx.num(x) * 100;
        return new BigDecimal(d).setScale(1, RoundingMode.HALF_UP).toPlainString() + "%";
    }

    private static String table(List<Object> stats) {
        List<String> rows = new ArrayList<>(List.of("| trait | labeled | flagged | recall | recall lower bound | precision | missed | false alarms |", "|---|---:|---:|---:|---:|---:|---:|---:|"));
        for (Object so : stats) {
            Map<String, Object> s = Jx.m(so);
            rows.add("| " + s.get("trait") + " | " + Jx.jsStr(s.get("positives")) + " | " + Jx.jsStr(s.get("predicted")) + " | " + pct(s.get("recall")) + " | " + pct(s.get("recall_lower")) + " | " + pct(s.get("precision")) + " | "
                + Jx.jsStr(s.get("fn")) + " | " + Jx.jsStr(s.get("fp")) + " |");
        }
        return String.join("\n", rows);
    }

    public static String renderEvalMarkdown(Map<String, Object> r) {
        List<String> parts = new ArrayList<>(List.of(
            "# Suggestion rules " + Jx.jsStr(r.get("rules_version")) + ": measured on a labeled corpus",
            "",
            Jx.jsStr(r.get("entries")) + " labeled operations (" + Jx.jsStr(r.get("mapped")) + " imported). Lower bounds are one-sided exact Clopper-Pearson at alpha = " + Jx.jsStr(r.get("alpha")) + ".",
            "These are heuristic numbers on a reviewed corpus. They are not a safety guarantee: an unreviewed action is always held at the most restrictive floor.",
            "",
            "## What a reviewer is shown (importer facts plus suggestions)", "", table(Jx.a(r.get("flagged"))), "",
            "## What the suggestion rules added", "", table(Jx.a(r.get("suggested"))), ""));
        for (Map.Entry<String, Object> e : Jx.m(r.get("by_source")).entrySet()) {
            parts.add("## Source: " + e.getKey() + " (" + Jx.jsStr(Jx.get(e.getValue(), "entries")) + " operations)");
            parts.add("");
            parts.add(table(Jx.a(Jx.get(e.getValue(), "flagged"))));
            parts.add("");
        }
        return String.join("\n", parts);
    }

    private static Object findTrait(Object flagged, String t) {
        if (!(flagged instanceof List)) return null;
        for (Object x : Jx.a(flagged)) if (t.equals(Jx.get(x, "trait"))) return x;
        return null;
    }

    /** Empty when the report meets the floors; else one line per failure. */
    public static List<String> floorFailures(Map<String, Object> r, Map<String, Object> f) {
        List<String> out = new ArrayList<>();
        Map<String, Object> bySource = Jx.m(r.get("by_source"));
        Object real = bySource.get("real/holdout");
        Map<String, Object> fr = Jx.m(f.get("real"));
        double minEntries = Jx.num(fr.get("min_entries"));
        if (real == null || Jx.num(Jx.get(real, "entries")) < minEntries)
            out.add("the real-spec hold-out has " + (real == null ? "0" : Jx.jsStr(Jx.get(real, "entries"))) + " operations, fewer than the required " + Jx.jsStr(fr.get("min_entries")));
        if (Jx.num(r.get("mapped")) < Jx.num(r.get("entries"))) out.add((long) (Jx.num(r.get("entries")) - Jx.num(r.get("mapped"))) + " corpus operations were not imported");
        for (Map.Entry<String, Object> en : Jx.m(fr.get("recall_lower")).entrySet()) {
            String t = en.getKey();
            Object s = real == null ? null : findTrait(Jx.get(real, "flagged"), t);
            Object needO = Jx.m(fr.get("min_positives")).get(t);
            String need = needO == null ? "0" : Jx.jsStr(needO);
            double needN = needO == null ? 0 : Jx.num(needO);
            if (s == null || Jx.num(Jx.get(s, "positives")) < needN) out.add(t + ": " + (s == null ? "0" : Jx.jsStr(Jx.get(s, "positives"))) + " real labeled positives, fewer than the " + need + " the floor needs");
            else if (Jx.get(s, "recall_lower") == null || Jx.num(Jx.get(s, "recall_lower")) < Jx.num(en.getValue()))
                out.add(t + ": hold-out recall lower bound " + pct(Jx.get(s, "recall_lower")) + " is below the recorded floor " + pct(en.getValue()));
        }
        Object syn = bySource.get("syn");
        for (Map.Entry<String, Object> en : Jx.m(Jx.m(f.get("regression")).get("recall_lower")).entrySet()) {
            Object s = syn == null ? null : findTrait(Jx.get(syn, "flagged"), en.getKey());
            if (s == null || Jx.get(s, "recall_lower") == null || Jx.num(Jx.get(s, "recall_lower")) < Jx.num(en.getValue()))
                out.add(en.getKey() + ": regression-set recall lower bound " + pct(s == null ? null : Jx.get(s, "recall_lower")) + " is below " + pct(en.getValue()));
        }
        return out;
    }
}
