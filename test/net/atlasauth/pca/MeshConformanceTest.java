package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The shared mesh corpus (mesh-vectors.json): whole mesh proofs with the TypeScript verdict. `ok` must match on every vector;
 * `reason` and `hop` on every vector whose reason does not start with `chain:` (a chain refusal only has to be a chain refusal).
 */
public class MeshConformanceTest {
    @Test @SuppressWarnings("unchecked")
    void meshVectors() {
        Map<String, Object> doc = Track3Vectors.load("mesh-vectors.json");
        assertEquals("pca-mesh-conformance/1", doc.get("format"));
        List<Object> vecs = (List<Object>) doc.get("mesh");
        assertTrue(vecs != null && vecs.size() >= 100, "expected at least 100 mesh vectors");
        for (Object raw : vecs) {
            Map<String, Object> v = (Map<String, Object>) raw;
            String name = (String) v.get("name");
            Map<String, Object> expect = (Map<String, Object>) v.get("expect");
            boolean wantOk = Boolean.TRUE.equals(expect.get("ok"));
            Mesh.Verdict got = Mesh.verifyMeshProof(v.get("proof"), v.get("trust"));
            assertEquals(wantOk, got.ok, name + ": reason \"" + got.reason + "\", want \"" + expect.get("reason") + "\"");
            if (wantOk) continue;
            String wantReason = expect.get("reason") instanceof String ? (String) expect.get("reason") : "";
            if (wantReason.startsWith("chain:")) {
                assertTrue(got.reason.startsWith("chain:"), name + ": reason \"" + got.reason + "\", want a chain refusal (\"" + wantReason + "\")");
                continue;
            }
            assertEquals(wantReason, got.reason, name);
            int wantHop = expect.containsKey("hop") ? (int) Json.asLong(expect.get("hop")) : -1;
            assertEquals(wantHop, got.hop, name + " hop");
        }
    }
}
