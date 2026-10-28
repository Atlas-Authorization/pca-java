package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Loader for the shared extension-layer corpora (intent-state, ledger, optimistic, mesh). A missing file or table FAILS, it is never skipped. */
final class Track3Vectors {
    private Track3Vectors() {}

    static final String DIR = "conformance/";

    @SuppressWarnings("unchecked")
    static Map<String, Object> load(String name) {
        try {
            return (Map<String, Object>) Json.parseLenient(new String(Files.readAllBytes(Path.of(DIR + name)), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("cannot load " + DIR + name + ": " + e);
            return null;
        }
    }

    /** The real sizes of the committed ledger / optimistic tables (not only the file's own {@code counts}). */
    static final Map<String, Integer> EXPECTED_COUNTS = Map.ofEntries(
        Map.entry("optimistic_claim", 52), Map.entry("optimistic_window", 25), Map.entry("optimistic_fraud_proof", 37), Map.entry("optimistic_settlement", 102),
        Map.entry("ledger_inclusion", 96), Map.entry("ledger_consistency", 149), Map.entry("ledger_tree_head", 64), Map.entry("ledger_cosign", 56),
        Map.entry("ledger_head_consistency", 26), Map.entry("ledger_checkpoint_chain", 23), Map.entry("ledger_witnessed_head", 30), Map.entry("ledger_equivocation", 7));

    /** The vector's {@code pins}; null when ABSENT (cosigners then fall back to the policy), an empty map for {@code pins: {}}. */
    static Map<String, Object> pins(Map<String, Object> v) { return v.containsKey("pins") ? mapOrNull(v.get("pins")) : null; }

    /** True when the vector needs a registered suite this build does not implement: it must then be refused, never accepted. */
    static boolean lacks(Map<String, Object> v) { return v.get("requires_suite") instanceof String && !Pq.supportedSuites().contains(v.get("requires_suite")); }

    /** The rows of one table; the table's size must equal the file's {@code counts}. */
    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> rows(Map<String, Object> doc, String table) {
        Object arr = doc.get(table);
        if (!(arr instanceof List)) fail(table + ": missing table");
        List<Object> list = (List<Object>) arr;
        if (EXPECTED_COUNTS.containsKey(table) && list.size() != EXPECTED_COUNTS.get(table)) fail(table + ": " + list.size() + " vectors, this runner pins " + EXPECTED_COUNTS.get(table));
        Object counts = doc.get("counts");
        if (counts instanceof Map) {
            long want = Json.asLong(((Map<String, Object>) counts).get(table));
            if (list.size() != want) fail(table + ": " + list.size() + " vectors, counts says " + want);
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object o : list) out.add((Map<String, Object>) o);
        return out;
    }

    static boolean expectOk(Map<String, Object> v) { return Boolean.TRUE.equals(((Map<?, ?>) v.get("expect")).get("ok")); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> mapOrNull(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }
}
