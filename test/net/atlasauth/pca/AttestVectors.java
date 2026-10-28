package net.atlasauth.pca;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The shared attestation evidence vectors (conformance/attestation-evidence-vectors.json), produced by the TypeScript
 * reference: x509_vectors (unit rows for the strict readers) and attestation_vectors (one row per vendor verifier call).
 * A missing file FAILS the tests that load it; it is never skipped.
 */
public final class AttestVectors {
    private AttestVectors() {}

    public static final String FILE = "conformance/attestation-evidence-vectors.json";

    private static Map<String, Object> doc;

    @SuppressWarnings("unchecked")
    public static synchronized Map<String, Object> doc() {
        if (doc == null) {
            try {
                doc = (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(FILE)));
            } catch (java.io.IOException e) {
                throw new IllegalStateException("conformance/attestation-evidence-vectors.json is missing (" + e + "): generate it with the TypeScript reference (gen-conformance-attestation.ts in packages/pca)", e);
            }
        }
        return doc;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> blobs() { return (Map<String, Object>) doc().get("blobs"); }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> rows(String key) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object o : (List<Object>) doc().get(key)) out.add((Map<String, Object>) hydrate(o, blobs()));
        return out;
    }

    /** Replaces every {"$blob": id} with the value stored under blobs[id]. */
    @SuppressWarnings("unchecked")
    public static Object hydrate(Object x, Map<String, Object> blobs) {
        if (x instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object e : (List<Object>) x) out.add(hydrate(e, blobs));
            return out;
        }
        if (x instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) x;
            if (m.size() == 1 && m.get("$blob") instanceof String) {
                String id = (String) m.get("$blob");
                if (!blobs.containsKey(id)) throw new IllegalStateException("unknown blob " + id);
                return blobs.get(id);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m.entrySet()) out.put(e.getKey(), hydrate(e.getValue(), blobs));
            return out;
        }
        return x;
    }

    /** The binding of a row's expected_binding, or null when absent. */
    @SuppressWarnings("unchecked")
    public static AttestationBinding bindingOf(Object v) {
        if (!(v instanceof Map)) return null;
        Map<String, Object> m = (Map<String, Object>) v;
        Double f = AttestCommon.asFinite(m.get("epoch"));
        return new AttestationBinding((String) m.get("holderPub"), (String) m.get("grantRef"), f == null ? Double.NaN : f, (String) m.get("nonce"));
    }

    /** Structural comparison through the lenient canonical form. */
    public static String canon(Object v) { return Json.canonicalize(v); }
}
