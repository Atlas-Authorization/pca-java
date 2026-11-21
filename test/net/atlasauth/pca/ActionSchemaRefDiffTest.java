package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The action schema's remaining surface against the reference corpora ref-action-schema (173 cases: the constants, value-dependent
 * reversibility, the wallet floor, verb lookup, signing, key entries, digests, verification, MCP hints, and the MCP and OpenAPI drafting
 * importers) and ref-action-schema-draft (104 cases: reversibility, OpenAPI drafting, MCP hints, verb lookup). A verification refusal that
 * carries the reference's exception text is compared by its prefix.
 */
class ActionSchemaRefDiffTest {
    static final String MAIN = "ref-action-schema", DRAFT = "ref-action-schema-draft";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    @SuppressWarnings("unchecked")
    private static Object nums(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(nums(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        if (map.size() == 1 && map.get("$num") instanceof String) return Double.parseDouble((String) map.get("$num"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), nums(e.getValue()));
        return out;
    }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) m(o).get("$bytes")); }

    private static Pq.SignerSuiteOpts suite(Object o) {
        Map<String, Object> s = m(o);
        if (s == null) return null;
        Pq.SignerSuiteOpts out = new Pq.SignerSuiteOpts();
        out.alg = (String) s.get("alg");
        if (s.containsKey("pqSeed")) out.mlDsa = Pq.mlDsa65Keygen(bytes(s.get("pqSeed")));
        return out;
    }

    private static Object regex(String source) { return Issue.obj("$regex", source); }

    private static Object cut(Object v) {
        Map<String, Object> map = m(v);
        if (map == null || !(map.get("reason") instanceof String)) return v;
        String r = (String) map.get("reason");
        for (String p : new String[] {"schema verification error:", "malformed schema:"}) {
            if (r.startsWith(p)) { Map<String, Object> out = new LinkedHashMap<>(map); out.put("reason", p); return out; }
        }
        return v;
    }

    private static Map<String, OracleCases.Fn> functions() {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("ACTION_SCHEMA_DOMAIN", ActionSchema.ACTION_SCHEMA_DOMAIN);
            o.put("ACTION_SCHEMA_KIND", ActionSchema.ACTION_SCHEMA_KIND);
            o.put("ACTION_SCHEMA_REF_DOMAIN", ActionSchema.ACTION_SCHEMA_REF_DOMAIN);
            o.put("DEFAULT_MAX_ITEMS", ActionSchema.DEFAULT_MAX_ITEMS);
            o.put("DEFAULT_MAX_LEN", ActionSchema.DEFAULT_MAX_LEN);
            o.put("MAX_SCHEMA_PARAMS", ActionSchema.MAX_SCHEMA_PARAMS);
            o.put("MAX_SCHEMA_VALUES", ActionSchema.MAX_SCHEMA_VALUES);
            o.put("MAX_SCHEMA_VERBS", ActionSchema.MAX_SCHEMA_VERBS);
            o.put("PARAM_PATH_RE", regex(ActionSchema.PARAM_PATH_RE_SOURCE));
            o.put("PARAM_PATH_RE_V2", regex(ActionSchema.PARAM_PATH_RE_V2_SOURCE));
            o.put("PARAM_TYPES", new ArrayList<Object>(ActionSchema.PARAM_TYPES));
            o.put("PARAM_TYPES_V2", new ArrayList<Object>(ActionSchema.PARAM_TYPES_V2));
            o.put("SCHEMA_REVERSIBILITY", new ArrayList<Object>(ActionSchema.SCHEMA_REVERSIBILITY));
            o.put("SCHEMA_V2_CAVEATS", new ArrayList<Object>(ActionSchema.SCHEMA_V2_CAVEATS));
            o.put("SCHEMA_V2_CONTEXT", new ArrayList<Object>(ActionSchema.SCHEMA_V2_CONTEXT));
            o.put("SCHEMA_V2_EFFECTS", new ArrayList<Object>(ActionSchema.SCHEMA_V2_EFFECTS));
            o.put("SCHEMA_V2_PROVENANCE", new ArrayList<Object>(ActionSchema.SCHEMA_V2_PROVENANCE));
            o.put("SCHEMA_V2_PRULES", new ArrayList<Object>(ActionSchema.SCHEMA_V2_PRULES));
            o.put("SCHEMA_V2_TAGS", new ArrayList<Object>(ActionSchema.SCHEMA_V2_TAGS));
            o.put("SENSITIVITIES", new ArrayList<Object>(ActionSchema.SENSITIVITIES));
            o.put("UNIT_ID_RE", regex(ActionSchema.UNIT_ID_RE_SOURCE));
            o.put("WALLET_FLOOR_EXACT", new ArrayList<Object>(ActionSchema.WALLET_FLOOR_EXACT));
            o.put("WALLET_FLOOR_PREFIXES", new ArrayList<Object>(ActionSchema.WALLET_FLOOR_PREFIXES));
            o.put("WELL_KNOWN_PCA_ACTIONS_PATH", ActionSchema.WELL_KNOWN_PCA_ACTIONS_PATH);
            return o;
        });
        f.put("reversibilityOf", x -> ActionSchema.reversibilityOf(m(nums(arg(x, 0))), m(nums(arg(x, 1)))));
        f.put("floorApplies", x -> ActionSchema.floorApplies((String) arg(x, 0), m(arg(x, 1))));
        f.put("schemaVerb", x -> ActionSchema.schemaVerb(nums(arg(x, 0)), (String) arg(x, 1)));
        f.put("signActionSchema", x -> ActionSchema.signActionSchema(m(nums(arg(x, 0))), (String) arg(x, 1), bytes(arg(x, 2)), suite(arg(x, 3))));
        f.put("actionSchemaKeyOf", x -> ActionSchema.actionSchemaKeyOf((String) arg(x, 0), bytes(arg(x, 1)), suite(arg(x, 2))));
        f.put("actionSchemaDigest", x -> ActionSchema.actionSchemaDigest(nums(arg(x, 0))));
        f.put("verifyActionSchema", x -> cut(ActionSchema.verifyActionSchema(nums(arg(x, 0)), nums(arg(x, 1)))));
        f.put("reversibilityFromMcpHints", x -> ActionSchema.reversibilityFromMcpHints(m(nums(arg(x, 0)))));
        f.put("draftSchemaFromMcpTools", x -> ActionSchemaDraft.draftSchemaFromMcpTools((List<?>) nums(arg(x, 0)), m(nums(arg(x, 1)))));
        f.put("draftSchemaFromOpenApi", x -> ActionSchemaDraft.draftSchemaFromOpenApi(m(nums(arg(x, 0))), m(nums(arg(x, 1)))));
        return f;
    }

    private static void replay(String module, int total) throws Exception {
        Map<String, OracleCases.Fn> f = functions();
        List<Map<String, Object>> all = BaseOracle.of(module, null);
        assertEquals(total, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertTrue(f.keySet().containsAll(fns), "unhandled fns: " + fns);
        List<String> bad = new ArrayList<>();
        for (String fn : fns) {
            for (Map<String, Object> c : OracleCases.of(module, fn)) {
                String d = OracleCases.diff(c, cut(c.get("out")), f.get(fn));
                if (d != null) bad.add(d);
            }
        }
        assertTrue(bad.isEmpty(), module + ": " + bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }

    @Test void actionSchemaCorpus() throws Exception { replay(MAIN, 173); }

    @Test void draftCorpus() throws Exception { replay(DRAFT, 104); }
}
