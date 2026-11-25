package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.goal.GoalInterpret;
import net.atlasauth.pca.goal.GoalOntologies;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle of the interpreters: candidate extraction, slot fill, rule/form/model interpreters, prompt, grounding, vendor completions, typed form. */
class GoalInterpretDiffTest {
    private static final String M = "ref-goal-interpret";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static Map<String, Object> ont(Object o) { return o instanceof String ? GoalOntologies.ontology((String) o) : m(o); }

    private static Map<String, Object> byKey(Object listO, String key, Object val) {
        for (Object x : l(listO)) if (val.equals(m(x).get(key))) return m(x);
        throw new IllegalStateException("not found " + val);
    }

    private static Map<String, Object> req(Map<String, Object> ont, Object text, Object sources, Object form) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("principal", "p1"); r.put("text", text); r.put("ontology", ont);
        if (sources != null) r.put("sources", sources);
        if (form != null) r.put("form", form);
        return r;
    }

    private static Map<String, Object> prompt(GoalInterpret.Prompt p) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("system", p.system); r.put("user", p.user);
        return r;
    }

    @Test void sourceDigest() throws Exception { OracleCases.each(M, "sourceDigest", a -> GoalInterpret.sourceDigest((String) a.get(0))); }
    @Test void slotStemsOf() throws Exception { OracleCases.each(M, "slotStemsOf", a -> GoalInterpret.slotStems(m(a.get(0)))); }
    @Test void extractCandidates() throws Exception { OracleCases.each(M, "extractCandidates", a -> GoalInterpret.extractCandidates((String) a.get(1), ont(a.get(0)), (String) a.get(2)).toJson()); }

    @Test void fillTemplateById() throws Exception {
        OracleCases.each(M, "fillTemplateById", a -> { Map<String, Object> o = ont(a.get(0)); return GoalInterpret.fillTemplate(byKey(o.get("templates"), "id", a.get(1)), o, (String) a.get(2), (String) a.get(3)); });
    }

    @Test void buildPromptOf() throws Exception { OracleCases.each(M, "buildPromptOf", a -> prompt(GoalInterpret.buildPrompt(req(ont(a.get(0)), a.get(1), a.get(2), null), Boolean.TRUE.equals(a.get(3))))); }
    @Test void promptKeyOf() throws Exception { OracleCases.each(M, "promptKeyOf", a -> GoalInterpret.promptKey((String) a.get(1), new GoalInterpret.Prompt((String) a.get(2), (String) a.get(3)))); }

    @Test void replayLookup() throws Exception {
        OracleCases.each(M, "replayLookup", a -> {
            Map<String, String> rec = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m(a.get(2)).entrySet()) rec.put(e.getKey(), (String) e.getValue());
            return GoalInterpret.replayCompletion((String) a.get(1), rec).complete(new GoalInterpret.Prompt((String) a.get(3), (String) a.get(4)));
        });
    }

    @Test void parseTemplateJSON() throws Exception { OracleCases.each(M, "parseTemplateJSON", a -> GoalInterpret.parseTemplateJSON((String) a.get(0))); }

    @Test void groundedOf() throws Exception {
        OracleCases.each(M, "groundedOf", a -> {
            Map<String, Object> o = ont(a.get(0));
            Map<String, Object> t = byKey(o.get("templates"), "id", a.get(1));
            return GoalInterpret.grounded(byKey(t.get("slots"), "name", a.get(2)), a.get(3), GoalInterpret.extractCandidates((String) a.get(4), o, null));
        });
    }

    @Test void interpretRule() throws Exception {
        OracleCases.each(M, "interpretRule", a -> GoalInterpret.ruleInterpreter("rule", (String) a.get(3)).interpret(req(ont(a.get(0)), a.get(1), a.get(2), null)));
    }

    // the oracle supplies the one source "s" with the "form text" request (not recorded in the case args)
    @Test void interpretForm() throws Exception {
        OracleCases.each(M, "interpretForm", a -> GoalInterpret.formInterpreter("form").interpret(req(ont(a.get(0)), a.get(2), "form text".equals(a.get(2)) ? List.of("s") : null, a.get(1))));
    }

    @Test void interpretLlm() throws Exception {
        OracleCases.each(M, "interpretLlm", a -> {
            Map<String, Object> mode = m(a.get(3));
            GoalInterpret.Completion c = p -> {
                if (mode.containsKey("throw")) throw new RuntimeException("boom");
                return (String) mode.get("raw");
            };
            return GoalInterpret.llmInterpreter("m", "f", c, Boolean.TRUE.equals(a.get(4)), (String) a.get(5)).interpret(req(ont(a.get(0)), a.get(1), a.get(2), null));
        });
    }

    @Test void vendor() throws Exception {
        OracleCases.each(M, "vendor", a -> {
            String kind = (String) a.get(1);
            Map<String, Object> cfg = m(a.get(2)), fk = m(a.get(3));
            Map<String, Object> rq = new LinkedHashMap<>();
            GoalInterpret.Fetch fetch = (url, method, headers, body) -> {
                rq.put("url", url); rq.put("method", method); rq.put("headers", new LinkedHashMap<String, Object>(headers)); rq.put("body", body);
                if (fk.get("throwMsg") != null) throw new RuntimeException((String) fk.get("throwMsg"));
                // the last two cases pass an empty fake (the oracle ignores it and answers a fixed 200 body)
                if (fk.isEmpty()) return new GoalInterpret.Fetched(true, 200, kind.equals("anthropic") ? "{\"content\":[{\"type\":\"text\",\"text\":\"x\"}]}" : "{\"choices\":[{\"message\":{\"content\":\"x\"}}]}");
                return new GoalInterpret.Fetched(Boolean.TRUE.equals(fk.get("ok")), ((Json.Num) fk.get("status")).raw.equals("200") ? 200 : Integer.parseInt(((Json.Num) fk.get("status")).raw),
                    fk.get("body") == null ? "null" : Json.canonicalize(fk.get("body")));
            };
            Integer mt = cfg.get("maxTokens") == null ? null : Integer.valueOf(((Json.Num) cfg.get("maxTokens")).raw);
            GoalInterpret.Completion c = kind.equals("anthropic")
                ? GoalInterpret.anthropicCompletion((String) cfg.get("apiKey"), (String) cfg.get("model"), fetch, mt)
                : GoalInterpret.openaiCompletion((String) cfg.get("apiKey"), (String) cfg.get("model"), (String) cfg.get("baseUrl"), fetch);
            Map<String, Object> out = new LinkedHashMap<>();
            try { out.put("text", c.complete(new GoalInterpret.Prompt((String) a.get(4), (String) a.get(5)))); } catch (Exception e) { out.put("error", e.getMessage()); }
            out.put("req", rq);
            return out;
        });
    }

    @Test void interpretRefundForm() throws Exception { OracleCases.each(M, "interpretRefundForm", a -> GoalInterpret.interpretForm(a.get(0), m(a.get(1)), (String) a.get(2))); }
    @Test void lexicalCompare() throws Exception { OracleCases.each(M, "lexicalCompare", a -> GoalInterpret.lexicalComparator(ont(a.get(0))).apply((String) a.get(1), (String) a.get(2))); }
}
