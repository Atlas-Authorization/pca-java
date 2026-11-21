package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.intent.IntentCompilers;
import net.atlasauth.pca.intent.IntentCompilers.IntentCompiler;
import net.atlasauth.pca.intent.IntentOmega;
import org.junit.jupiter.api.Test;

class IntentNlDiffTest {
    private static final String M = "ref-intent-nl-java";

    @SuppressWarnings("unchecked")
    private static Catalog catalog(Object extras) {
        if (extras == null) return Catalog.DEFAULT;
        List<Catalog.Spec> specs = new ArrayList<>(Catalog.BUILTIN);
        for (Object eo : (List<Object>) extras) {
            Map<String, Object> e = (Map<String, Object>) eo;
            String connector = (String) e.get("connector"), action = (String) e.get("action");
            List<String> aliases = new ArrayList<>();
            if (e.get("aliases") != null) for (Object x : (List<Object>) e.get("aliases")) aliases.add((String) x);
            specs.add(new Catalog.Spec(connector, action, connector + "." + action, (String) e.get("reversibility"), IntentOmega.dbl(e.get("blastRadius")), (String) e.get("amountField"),
                (String) e.get("description"), aliases, null));
        }
        return new Catalog(specs);
    }

    private static IntentCompiler compiler(String raw, StringBuilder prompt) {
        return IntentCompilers.nlFacadeCompiler("nl", "fam", p -> {
            prompt.setLength(0);
            prompt.append(p);
            if ("THROWS".equals(raw)) throw new IllegalStateException("llm down");
            return raw;
        });
    }

    private static Map<String, Object> input(Object text, Catalog cat) {
        Map<String, Object> in = new LinkedHashMap<>();
        in.put("text", text);
        in.put("catalog", cat);
        return in;
    }

    @Test void nlPrompt() throws Exception { OracleCases.each(M, "nlPrompt", a -> IntentCompilers.nlPrompt((String) a.get(0), catalog(a.get(1)))); }

    @Test void parseNLPolicy() throws Exception { OracleCases.each(M, "parseNLPolicy", a -> IntentCompilers.parseNLPolicy((String) a.get(0), catalog(a.get(1)))); }

    @Test void nlCompile() throws Exception {
        OracleCases.each(M, "nlCompile", a -> {
            StringBuilder prompt = new StringBuilder();
            Map<String, Object> output = compiler((String) a.get(1), prompt).compile(input(a.get(0), catalog(a.get(2))));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("prompt", prompt.toString());
            out.put("output", output);
            return out;
        });
    }

    @Test void nlRun() throws Exception {
        OracleCases.each(M, "nlRun", a -> IntentCompilers.runCompilers(input(a.get(0), catalog(a.get(2))), List.of(compiler((String) a.get(1), new StringBuilder()))));
    }
}
