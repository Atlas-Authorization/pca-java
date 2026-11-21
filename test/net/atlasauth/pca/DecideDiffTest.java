package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Replays the reference vectors of the policy decision through {@link Decide#decide}. */
public class DecideDiffTest {
    @SuppressWarnings("unchecked")
    @Test void decide() throws Exception {
        OracleCases.each("ref-decide-java", "decide", a -> Decide.decide((Map<String, Object>) revive(a.get(0))));
    }

    /** The corpus spells a non-finite number {"$num": "NaN" | "Infinity" | "-Infinity"}; the native reads the double. */
    @SuppressWarnings("unchecked")
    static Object revive(Object v) {
        if (v instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) v;
            if (m.size() == 1 && m.get("$num") instanceof String) return Double.parseDouble((String) m.get("$num"));
            Map<String, Object> r = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m.entrySet()) r.put(e.getKey(), revive(e.getValue()));
            return r;
        }
        if (v instanceof List) { List<Object> r = new ArrayList<>(); for (Object x : (List<Object>) v) r.add(revive(x)); return r; }
        return v;
    }
}
