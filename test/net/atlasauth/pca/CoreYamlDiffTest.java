package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.actions.ImportRegistry;
import org.junit.jupiter.api.Test;

/** The YAML an action import writes, byte for byte against the reference's writer. */
@SuppressWarnings("unchecked")
public class CoreYamlDiffTest {
    static final String MODULE = "ref-core-yaml-java";

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @Test void defsToYaml() throws Exception {
        OracleCases.each(MODULE, "defsToYaml", a -> {
            List<Map<String, Object>> defs = new ArrayList<>();
            for (Object d : (List<?>) a.get(1)) defs.add(m(d));
            return ImportRegistry.defsToYaml((String) a.get(0), defs, m(a.get(2)));
        });
    }

    /** Builds one container per shared id, then replaces every {"$ref": id} node with THAT instance (cycles included). */
    static final class Shared {
        final Map<String, Object> box = new LinkedHashMap<>();

        Shared(Map<String, Object> spec) {
            for (Map.Entry<String, Object> e : spec.entrySet()) box.put(e.getKey(), e.getValue() instanceof List ? new ArrayList<Object>() : new LinkedHashMap<String, Object>());
            for (Map.Entry<String, Object> e : spec.entrySet()) {
                Object filled = sub(e.getValue());
                if (filled instanceof List) ((List<Object>) box.get(e.getKey())).addAll((List<?>) filled);
                else ((Map<String, Object>) box.get(e.getKey())).putAll((Map<String, Object>) filled);
            }
        }

        @SuppressWarnings("unchecked") Object sub(Object x) {
            if (x instanceof List) { List<Object> out = new ArrayList<>(); for (Object y : (List<?>) x) out.add(sub(y)); return out; }
            if (x instanceof Map) {
                Map<String, Object> mm = (Map<String, Object>) x;
                if (mm.size() == 1 && mm.containsKey("$ref")) return box.get((String) mm.get("$ref"));
                Map<String, Object> out = new LinkedHashMap<>();
                for (Map.Entry<String, Object> e : mm.entrySet()) out.put(e.getKey(), sub(e.getValue()));
                return out;
            }
            return x;
        }
    }

    @Test void defsToYamlSharedObjects() throws Exception {
        OracleCases.each("ref-core-yaml-anchors-java", "defsToYaml", a -> {
            Shared sh = new Shared(m(a.get(3)));
            List<Map<String, Object>> defs = new ArrayList<>();
            for (Object d : (List<?>) sh.sub(a.get(1))) defs.add(m(d));
            return ImportRegistry.defsToYaml((String) a.get(0), defs, m(sh.sub(a.get(2))));
        });
    }

    @Test void emptyAndScalarBasics() {
        assertEquals("ns: acme\nactions: []\n", ImportRegistry.defsToYaml("acme", new ArrayList<>()));
        assertEquals("ns: \"true\"\nactions: []\n", ImportRegistry.defsToYaml("true", new ArrayList<>()));
    }
}
