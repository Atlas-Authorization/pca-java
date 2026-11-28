package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentCompilers;
import net.atlasauth.pca.intent.IntentCompilers.IntentCompiler;
import net.atlasauth.pca.intent.IntentOmega;
import org.junit.jupiter.api.Test;

class IntentCompilersDiffTest {
    private static final String M = "ref-intent-compilers";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> ls(Object o) { return (List<Object>) o; }

    private static IntentCompiler compiler(Object so) {
        Map<String, Object> s = mp(so);
        String id = (String) s.get("id"), family = (String) s.get("family");
        switch ((String) s.get("kind")) {
            case "captured": return IntentCompilers.capturedSlotsCompiler(id);
            case "fixed": return IntentCompilers.fixedCompiler(id, family, in -> s.get("policy"));
            case "throws": return IntentCompilers.fixedCompiler(id, family, in -> { throw new IllegalStateException("boom"); });
            case "slots": return IntentCompilers.slotsCompiler(id, family, prompt -> (String) s.get("raw"));
            default: return IntentCompilers.slotsCompiler(id, family, prompt -> { throw new IllegalStateException("llm down"); });
        }
    }

    private static List<IntentCompiler> compilers(Object specs) {
        List<IntentCompiler> out = new ArrayList<>();
        for (Object s : ls(specs)) out.add(compiler(s));
        return out;
    }

    @Test void slotsPrompt() throws Exception { OracleCases.each(M, "slotsPrompt", a -> IntentCompilers.slotsPrompt((String) a.get(0), null)); }

    @Test void parseSlotsJSON() throws Exception { OracleCases.each(M, "parseSlotsJSON", a -> IntentCompilers.parseSlotsJSON((String) a.get(0), null)); }

    @Test void runScenario() throws Exception { OracleCases.each(M, "runScenario", a -> IntentCompilers.runCompilers(mp(a.get(0)), compilers(a.get(1)))); }

    @Test void analyze() throws Exception { OracleCases.each(M, "analyze", a -> IntentCompilers.analyzeDisagreement(ls(a.get(0)), mp(a.get(1)))); }

    @Test void flags() throws Exception { OracleCases.each(M, "flags", a -> IntentCompilers.panelFlags(IntentCompilers.analyzeDisagreement(ls(a.get(0)), mp(a.get(1))))); }

    @Test void anchors() throws Exception { OracleCases.each(M, "anchors", a -> IntentCompilers.committeeAnchors(ls(a.get(0)), IntentOmega.dbl(a.get(1)))); }

    @Test void compareScenario() throws Exception {
        OracleCases.each(M, "compareScenario", a -> IntentCompilers.compileAndCompare(mp(a.get(0)), compilers(a.get(1)), mp(a.get(2))));
    }
}
