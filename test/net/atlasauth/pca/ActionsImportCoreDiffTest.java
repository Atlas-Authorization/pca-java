package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.importers.AsyncApiImporter;
import net.atlasauth.pca.actions.importers.ImportCommon;
import net.atlasauth.pca.actions.importers.ImportLimits;
import net.atlasauth.pca.actions.importers.JsonSchemaImporter;
import net.atlasauth.pca.actions.importers.McpImporter;
import net.atlasauth.pca.actions.importers.OpenApiImporter;
import org.junit.jupiter.api.Test;

class ActionsImportCoreDiffTest {
    private static final String M = "ref-actions-import-core";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    private static int i(Object o) { return OracleCases.num(o).intValue(); }

    private static Map<String, Object> limits(ImportLimits l) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("max_bytes", l.maxBytes); out.put("max_ops", l.maxOps); out.put("max_json_depth", l.maxJsonDepth);
        out.put("max_nodes", l.maxNodes); out.put("max_ref_nodes", l.maxRefNodes); out.put("max_ref_depth", l.maxRefDepth);
        return out;
    }

    @Test void tokensOf() throws Exception { OracleCases.each(M, "tokensOf", a -> ImportCommon.tokensOf(a.get(0))); }
    @Test void humanize() throws Exception { OracleCases.each(M, "humanize", a -> ImportCommon.humanize(a.get(0))); }
    @Test void verbOf() throws Exception { OracleCases.each(M, "verbOf", a -> ImportCommon.verbOf((String) a.get(0), a.get(1))); }
    @Test void aliasOf() throws Exception { OracleCases.each(M, "aliasOf", a -> ImportCommon.aliasOf(a.get(0), (String) a.get(1))); }
    @Test void paramSeg() throws Exception { OracleCases.each(M, "paramSeg", a -> ImportCommon.paramSeg((String) a.get(0))); }
    @Test void clip() throws Exception { OracleCases.each(M, "clip", a -> ImportCommon.clip(a.get(0), i(a.get(1)))); }
    @Test void pointer() throws Exception { OracleCases.each(M, "pointer", a -> ImportCommon.pointer(a.get(0), a.get(1))); }
    @Test void resolveLimits() throws Exception { OracleCases.each(M, "resolveLimits", a -> limits(ImportLimits.resolve(a.isEmpty() ? null : a.get(0)))); }
    @Test void checkParsed() throws Exception { OracleCases.each(M, "checkParsed", a -> ImportLimits.resolve(a.get(1)).checkParsed(a.get(0))); }
    @Test void textSizeCheck() throws Exception { OracleCases.each(M, "textSizeCheck", a -> { ImportLimits.resolve(a.get(1)).textSizeCheck((String) a.get(0)); return null; }); }
    @Test void importOpenApi() throws Exception { OracleCases.each(M, "importOpenApi", a -> OpenApiImporter.importOpenApi(a.get(0), m(a.get(1)))); }
    @Test void importMcp() throws Exception { OracleCases.each(M, "importMcp", a -> McpImporter.importMcp(a.get(0), m(a.get(1)))); }
    @Test void importJsonSchema() throws Exception { OracleCases.each(M, "importJsonSchema", a -> JsonSchemaImporter.importJsonSchema(a.get(0), m(a.get(1)))); }
    @Test void importAsyncApi() throws Exception { OracleCases.each(M, "importAsyncApi", a -> AsyncApiImporter.importAsyncApi(a.get(0), m(a.get(1)))); }
}
