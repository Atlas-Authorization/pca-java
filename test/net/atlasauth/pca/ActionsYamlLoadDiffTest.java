package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.actions.ActionsText;
import org.junit.jupiter.api.Test;

/**
 * Replays the reference oracle over the authoring-file text loader (YAML 1.2 core and JSON, with source positions). A syntax error is compared by class
 * (the parser's wording is its own). Where this loader is deliberately STRICTER than the reference the result must be a single "not YAML" refusal on a
 * text that uses one of the documented constructs, never a different successful value.
 */
@SuppressWarnings("unchecked")
public class ActionsYamlLoadDiffTest {
    static final String MODULE = "ref-actions-yaml-load-py";
    static final Pattern STRICTER = Pattern.compile("(^|\\s)!(?!!(str|map|seq)\\b)\\S|\\? \\[|\r(?!\n)|!!binary");

    static Object norm(Object r) {
        Map<String, Object> m = (Map<String, Object>) r;
        Map<String, Object> o = new java.util.LinkedHashMap<>();
        for (String k : new String[] {"defs", "notes", "errors", "locs", "rules", "ns"}) if (m.containsKey(k)) o.put(k, m.get(k));
        return o;
    }

    @Test void loadActionsText() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(MODULE, "loadActionsText")) {
            List<Object> args = (List<Object>) c.get("args");
            String text = (String) args.get(0), fmt = (String) args.get(1);
            Map<String, Object> got = (Map<String, Object>) OracleCases.toJson(ActionsText.loadActionsText(text, fmt));
            Map<String, Object> exp = (Map<String, Object>) c.get("out");
            List<Object> gotErrors = (List<Object>) got.get("errors");
            Object expErrors = exp.get("errors");
            String e0 = "";
            if (expErrors instanceof List && !((List<Object>) expErrors).isEmpty() && ((List<Object>) expErrors).get(0) instanceof Map
                && ((Map<String, Object>) ((List<Object>) expErrors).get(0)).get("message") instanceof String)
                e0 = (String) ((Map<String, Object>) ((List<Object>) expErrors).get(0)).get("message");
            String gm = gotErrors.size() == 1 ? (String) ((Map<String, Object>) gotErrors.get(0)).get("message") : "";
            boolean noDefs = ((List<Object>) got.get("defs")).isEmpty();
            boolean ok;
            if (e0.startsWith("not YAML") || e0.startsWith("YAML warning") || e0.startsWith("not JSON")) {
                boolean prefixOk = fmt.equals("yaml") ? gm.startsWith("not YAML") || gm.startsWith("YAML warning") : gm.startsWith("not JSON");
                ok = gotErrors.size() == 1 && noDefs && prefixOk;
            } else if (IntentJs.jsonEquals(norm(exp), IntentJs.normalize(norm(got)))) ok = true;
            else ok = STRICTER.matcher(text).find() && gotErrors.size() == 1 && gm.startsWith("not YAML") && noDefs;
            if (!ok) bad.add(c.get("name") + "\n  want: " + Json.stringify(norm(exp)) + "\n  got:  " + Json.stringify(norm(got)));
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }
}
