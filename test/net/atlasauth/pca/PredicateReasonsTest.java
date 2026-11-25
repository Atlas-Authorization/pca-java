package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** The limit-naming denial reasons, byte-identical to the TypeScript reference (table recorded from it). */
public class PredicateReasonsTest {
    @SuppressWarnings("unchecked")
    @Test void reasonTable() throws Exception {
        Map<String, Object> doc = (Map<String, Object>) Json.parseLenient(Files.readString(Path.of("test-data/predicate-reasons.json")));
        List<Map<String, Object>> cases = (List<Map<String, Object>>) doc.get("cases");
        assertTrue(cases.size() >= 55);
        for (Map<String, Object> c : cases) {
            Map<String, Object> action = new LinkedHashMap<>((Map<String, Object>) doc.get("action"));
            action.put("params", c.get("params"));
            Map<String, Object> ctx = new LinkedHashMap<>();
            ctx.put("action", action);
            if (c.containsKey("subject")) ctx.put("subject", c.get("subject"));
            if (c.containsKey("env")) ctx.put("env", c.get("env"));
            assertEquals(c.get("reason"), Predicates.denialReason(c.get("predicates"), ctx), (String) c.get("name"));
        }
    }

    @Test void allowedHasNoReason() {
        Map<String, Object> ctx = Map.of("action", Map.of("verb", "pay", "resource", "r", "params", Map.of()));
        assertNull(Predicates.denialReason(Json.parseLenient("[{\"verb\":\"pay\"}]"), ctx));
    }
}
