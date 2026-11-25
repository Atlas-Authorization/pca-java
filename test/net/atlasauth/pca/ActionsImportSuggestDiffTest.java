package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.actions.importers.ImportModel;
import net.atlasauth.pca.actions.importers.ImportProviders;
import net.atlasauth.pca.actions.importers.ImportRules;
import net.atlasauth.pca.actions.importers.ImportSuggest;
import org.junit.jupiter.api.Test;

class ActionsImportSuggestDiffTest {
    private static final String M = "ref-actions-import-suggest";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    private static Map<String, Object> rules(Object x) { return "default".equals(x) ? ImportRules.DEFAULT_RULES : m(x); }
    private static Actions.Registry reg(Object x) { return "core".equals(x) ? Actions.CORE_REGISTRY : null; }

    private static byte[] seed(String label) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8));
    }

    @Test void stem() throws Exception { OracleCases.each(M, "stem", a -> ImportSuggest.stem((String) a.get(0))); }
    @Test void factsOf() throws Exception { OracleCases.each(M, "factsOf", a -> ImportSuggest.factsOf(m(a.get(0))).toJson()); }
    @Test void defaultRules() throws Exception { OracleCases.each(M, "DEFAULT_RULES", a -> ImportRules.DEFAULT_RULES); }
    @Test void defaultRulesSealedDigest() throws Exception {
        OracleCases.each(M, "DEFAULT_RULES_SEALED_DIGEST", a -> ImportRules.DEFAULT_RULES_SEALED.get("digest"));
        org.junit.jupiter.api.Assertions.assertEquals(ImportRules.publishedDigest(), ImportRules.DEFAULT_RULES_SEALED.get("digest"));
    }
    @Test void suggestRulesError() throws Exception {
        OracleCases.each(M, "suggestRulesError", a -> {
            Set<String> known = null;
            if (a.size() > 1 && a.get(1) instanceof List) { known = new LinkedHashSet<>(); for (Object x : l(a.get(1))) known.add((String) x); }
            return ImportSuggest.suggestRulesError("default".equals(a.get(0)) ? ImportRules.DEFAULT_RULES : a.get(0), known);
        });
    }
    @Test void rulesDigest() throws Exception { OracleCases.each(M, "rulesDigest", a -> ImportSuggest.rulesDigest(rules(a.get(0)))); }
    @Test void sealRules() throws Exception { OracleCases.each(M, "sealRules", a -> ImportSuggest.sealRules(m(a.get(0)))); }
    @Test void signRules() throws Exception { OracleCases.each(M, "signRules", a -> ImportSuggest.signRules(m(a.get(0)), (String) a.get(1), seed((String) a.get(2)))); }
    @Test void verifyRules() throws Exception {
        OracleCases.each(M, "verifyRules", a -> {
            List<Map<String, Object>> pins = new ArrayList<>();
            for (Object p : l(a.get(1))) pins.add(m(p));
            return ImportSuggest.verifyRules(a.get(0), pins);
        });
    }
    @Test void suggestWithRules() throws Exception { OracleCases.each(M, "suggestWithRules", a -> ImportSuggest.suggestWithRules(m(a.get(0)), rules(a.get(1)), a.size() > 2 ? reg(a.get(2)) : null)); }
    @Test void unionSuggestions() throws Exception { OracleCases.each(M, "unionSuggestions", a -> ImportSuggest.unionSuggestions(m(a.get(0)), m(a.get(1)))); }
    @Test void applySuggestion() throws Exception { OracleCases.each(M, "applySuggestion", a -> ImportSuggest.applySuggestion(m(a.get(0)), m(a.get(1)), m(a.get(2)))); }

    @Test void vocabulary() throws Exception { OracleCases.each(M, "vocabulary", a -> ImportModel.vocabulary(Actions.CORE_REGISTRY)); }
    @Test void promptDigest() throws Exception { OracleCases.each(M, "promptDigest", a -> ImportModel.promptDigest(Actions.CORE_REGISTRY)); }
    @Test void buildRequest() throws Exception { OracleCases.each(M, "buildRequest", a -> ImportModel.buildRequest(m(a.get(0)), Actions.CORE_REGISTRY)); }
    @Test void parseTraitList() throws Exception { OracleCases.each(M, "parseTraitList", a -> ImportModel.parseTraitList((String) a.get(0), Actions.CORE_REGISTRY)); }

    private static ImportModel.ModelAdapter adapter(Map<String, Object> spec) {
        return new ImportModel.ModelAdapter() {
            @Override public String id() { return (String) spec.get("id"); }
            @Override public String version() { return (String) spec.get("version"); }
            @Override public String complete(Map<String, Object> req) throws Exception {
                if (spec.containsKey("throws")) throw new Exception((String) spec.get("throws"));
                return (String) spec.get("answer");
            }
        };
    }

    @Test void suggestWithModels() throws Exception {
        OracleCases.each(M, "suggestWithModels", a -> {
            List<ImportModel.ModelAdapter> ads = new ArrayList<>();
            for (Object s : l(a.get(1))) ads.add(adapter(m(s)));
            return ImportModel.suggestWithModels(m(a.get(0)), ads, Actions.CORE_REGISTRY);
        });
    }

    @Test void modelConfigFromEnv() throws Exception { OracleCases.each(M, "modelConfigFromEnv", a -> ImportProviders.modelConfigFromEnv(m(a.get(0)), m(a.get(1))).toMap()); }

    @Test void providerAdapterComplete() throws Exception {
        OracleCases.each(M, "providerAdapterComplete", a -> {
            Map<String, Object> cfg = m(a.get(0)), spec = m(a.get(1)), req = m(a.get(2));
            Map<String, Object> env = new LinkedHashMap<>();
            env.put(cfg.get("provider").equals("anthropic") ? "ANTHROPIC_API_KEY" : "OPENAI_API_KEY", cfg.get("apiKey"));
            ImportProviders.ModelEnvConfig c = ImportProviders.modelConfigFromEnv(env, flags(cfg));
            Object[] call = new Object[1];
            ImportProviders.FetchLike fake = (url, headers, body, timeout) -> {
                Map<String, Object> hs = new LinkedHashMap<>(headers);
                Map<String, Object> cm = new LinkedHashMap<>();
                cm.put("url", url); cm.put("headers", hs); cm.put("body", body);
                call[0] = cm;
                if (spec.containsKey("throws")) throw new Exception((String) spec.get("throws"));
                boolean ok = !spec.containsKey("ok") || Boolean.TRUE.equals(spec.get("ok"));
                int status = spec.containsKey("status") ? OracleCases.num(spec.get("status")).intValue() : 200;
                return new ImportProviders.FetchResponse() {
                    @Override public boolean ok() { return ok; }
                    @Override public int status() { return status; }
                    @Override public Object json() throws Exception { if (Boolean.TRUE.equals(spec.get("badjson"))) throw new Exception("bad json"); return spec.get("json"); }
                };
            };
            Map<String, Object> out = new LinkedHashMap<>();
            String text = null, error = null;
            try { text = ImportProviders.providerAdapter(c, fake).complete(req); } catch (Exception e) { error = e.getMessage(); }
            out.put("call", error == null ? null : call[0]); // the reference reads `call` before it awaits the completion, so a success records none
            if (error != null) out.put("error", error); else out.put("text", text);
            return out;
        });
    }

    private static Map<String, Object> flags(Map<String, Object> cfg) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("provider", cfg.get("provider"));
        f.put("model", cfg.get("model"));
        return f;
    }
}
