package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The import registry's output side: the YAML an {@code import} writes. */
public final class ImportRegistry {
    private ImportRegistry() {}

    /**
     * The YAML an import writes: {@code {ns, actions: [def...]}} with each def written in full form. {@code rules} (verb to a business-rules
     * value; may be null) re-attaches each action's rules block (the loader keeps rules apart from the def), so a rewrite (confirm, sync) never
     * drops them. The text is byte for byte what the reference's YAML writer produces (see {@code YamlEmit}), ending in a newline.
     */
    public static String defsToYaml(String ns, List<Map<String, Object>> defs, Map<String, Object> rules) {
        List<Object> actions = new ArrayList<>();
        for (Map<String, Object> d : defs) {
            Object verb = d.get("verb");
            if (rules != null && verb instanceof String && rules.containsKey(verb)) {
                Map<String, Object> withRules = new LinkedHashMap<>(d);
                withRules.put("rules", rules.get(verb));
                actions.add(withRules);
            } else actions.add(d);
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("ns", ns);
        doc.put("actions", actions);
        return YamlEmit.stringify(doc);
    }

    /** {@link #defsToYaml(String, List, Map)} without rules. */
    public static String defsToYaml(String ns, List<Map<String, Object>> defs) { return defsToYaml(ns, defs, null); }
}
