package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.importers.ImportEval;
import net.atlasauth.pca.actions.importers.ImportModel;
import net.atlasauth.pca.actions.importers.ImportPipeline;
import net.atlasauth.pca.actions.importers.ImportReview;
import net.atlasauth.pca.actions.importers.ImportRules;
import org.junit.jupiter.api.Test;

class ActionsImportReviewDiffTest {
    private static final String M = "ref-actions-import-review";
    private static final Actions.Registry CORE = Actions.CORE_REGISTRY;

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }

    private static byte[] seed(String label) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8));
    }

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

    private static List<Map<String, Object>> defs(Object xs) { List<Map<String, Object>> out = new ArrayList<>(); for (Object x : l(xs)) out.add(m(x)); return out; }

    private static ImportPipeline.SuggestOpts suggestOpts(Map<String, Object> so) {
        ImportPipeline.SuggestOpts o = new ImportPipeline.SuggestOpts();
        o.mode = (String) so.get("mode");
        o.registry = CORE;
        if ("default".equals(so.get("rules"))) {
            Map<String, Object> r = new LinkedHashMap<>(ImportRules.DEFAULT_RULES);
            r.put("rules", new ArrayList<>(l(ImportRules.DEFAULT_RULES.get("rules")).subList(0, 20)));
            o.rules = r;
        }
        if (so.get("models") instanceof List) { List<ImportModel.ModelAdapter> ads = new ArrayList<>(); for (Object s : l(so.get("models"))) ads.add(adapter(m(s))); o.models = ads; }
        return o;
    }

    // ---- eval ----
    @Test void parseHandTsv() throws Exception { OracleCases.each(M, "parseHandTsv", a -> ImportEval.parseHandTsv((String) a.get(0))); }
    @Test void parseCorpusJsonl() throws Exception { OracleCases.each(M, "parseCorpusJsonl", a -> ImportEval.parseCorpusJsonl((String) a.get(0))); }
    @Test void realSplit() throws Exception { OracleCases.each(M, "realSplit", a -> ImportEval.realSplit(a.isEmpty() ? null : a.get(0))); }
    @Test void importCorpus() throws Exception { OracleCases.each(M, "importCorpus", a -> ImportEval.importCorpus(l(a.get(0)))); }
    @Test void evalSuggest() throws Exception {
        OracleCases.each(M, "evalSuggest", a -> ImportEval.evalSuggest(l(a.get(0)), a.size() > 1 && !"default".equals(a.get(1)) ? m(a.get(1)) : null, CORE, a.size() > 2 ? OracleCases.num(a.get(2)) : null));
    }
    @Test void renderEvalMarkdown() throws Exception { OracleCases.each(M, "renderEvalMarkdown", a -> ImportEval.renderEvalMarkdown(m(a.get(0)))); }
    @Test void floorFailures() throws Exception { OracleCases.each(M, "floorFailures", a -> ImportEval.floorFailures(m(a.get(0)), m(a.get(1)))); }

    // ---- pipeline ----
    @Test void importActions() throws Exception { OracleCases.each(M, "importActions", a -> ImportPipeline.importActions((String) a.get(0), a.get(1), m(a.get(2)))); }
    @Test void importers() throws Exception { OracleCases.each(M, "IMPORTERS", a -> ImportPipeline.runImporter((String) a.get(0), a.get(1), m(a.get(2)))); }
    @Test void suggestDefs() throws Exception { OracleCases.each(M, "suggestDefs", a -> ImportPipeline.suggestDefs(defs(a.get(0)), a.size() > 1 ? suggestOpts(m(a.get(1))) : null)); }
    @Test void importAndSuggest() throws Exception { OracleCases.each(M, "importAndSuggest", a -> ImportPipeline.importAndSuggest((String) a.get(0), a.get(1), m(a.get(2)), suggestOpts(m(a.get(3))))); }
    @Test void defsToJsonl() throws Exception { OracleCases.each(M, "defsToJsonl", a -> ImportPipeline.defsToJsonl(defs(a.get(0)))); }
    @Test void jsonlToDefs() throws Exception { OracleCases.each(M, "jsonlToDefs", a -> ImportPipeline.jsonlToDefs((String) a.get(0))); }

    // ---- review ----
    @Test void verifyAttestation() throws Exception { OracleCases.each(M, "verifyAttestation", a -> ImportReview.verifyAttestation(m(a.get(0)), m(a.get(1)), CORE)); }
    @Test void reviewStatus() throws Exception { OracleCases.each(M, "reviewStatus", a -> ImportReview.reviewStatus(m(a.get(0)), m(a.get(1)), CORE)); }
    @Test void revertStale() throws Exception { OracleCases.each(M, "revertStale", a -> ImportReview.revertStale(m(a.get(0)), m(a.get(1)), CORE)); }
    @Test void reviewPriority() throws Exception { OracleCases.each(M, "reviewPriority", a -> ImportReview.reviewPriority(m(a.get(0)), CORE)); }
    @Test void reviewQueueOrder() throws Exception { OracleCases.each(M, "reviewQueueOrder", a -> ImportReview.reviewQueueOrder(defs(a.get(0)), CORE)); }
    @Test void prepareReview() throws Exception { OracleCases.each(M, "prepareReview", a -> ImportReview.prepareReview(m(a.get(0)), CORE, a.size() > 1 ? m(a.get(1)) : null)); }
    @Test void confirmDef() throws Exception {
        OracleCases.each(M, "confirmDef", a -> {
            Map<String, Object> c = m(a.get(1));
            return ImportReview.confirmDef(m(a.get(0)), CORE, (String) c.get("kid"), seed((String) c.get("seed")), c.containsKey("pins") ? m(c.get("pins")) : null,
                l(c.get("finalTraits")), c.containsKey("dismissed") ? l(c.get("dismissed")) : null, c.get("ts"));
        });
    }
}
