package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * LESS suites through libatlas_less ({@link LessNative}): with a Java 22+ runtime and the library (sdks/pca-less-c/build.sh,
 * or ATLAS_PCA_LIBLESS) the known answers of packages/pca/conformance/less-vectors.json, incl. the seed-padding malleation
 * every verifier must refuse; otherwise both suites are out of the manifest and refused with {@code unsupported_suite}.
 */
public class LessNativeTest {
    static Path vectors() {
        for (Path d = Paths.get("").toAbsolutePath(); d != null; d = d.getParent()) {
            Path p = d.resolve("packages/pca/conformance/less-vectors.json");
            if (Files.isRegularFile(p)) return p;
        }
        throw new IllegalStateException("less-vectors.json not found");
    }

    @Test
    void manifestListsBothOrNeither() {
        assertEquals(LessNative.available(), Pq.supportedSuites().contains("less-cat1"));
        assertEquals(LessNative.available(), Pq.supportedSuites().contains("hybrid-ed25519-less-cat1"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void knownAnswersOrRefusal() throws Exception {
        if (!LessNative.available()) {
            assertEquals("unsupported_suite: less-cat1", Pq.validateSignatureWire(Map.of("alg", "less-cat1", "sig", "AA")));
            return;
        }
        Map<String, Object> doc = (Map<String, Object>) Json.parseLenient(new String(Files.readAllBytes(vectors()), StandardCharsets.UTF_8));
        Map<String, Object> keys = (Map<String, Object>) doc.get("keys");
        List<Object> vs = (List<Object>) doc.get("vectors");
        assertTrue(vs.size() >= 25);
        for (Object o : vs) {
            Map<String, Object> v = (Map<String, Object>) o;
            Map<String, Object> key = (Map<String, Object>) keys.get(v.get("key"));
            Object pk = v.containsKey("pq_pk_override") ? v.get("pq_pk_override") : key.get("pq_pk");
            byte[] msg = Pca.decodeB64uStrict(v.get("message"), -1);
            boolean got = Pq.verifyArtifactSignature((String) v.get("alg"), (String) key.get("ed_pub"), pk, msg, v.get("sig"), v.get("pq_sig"));
            assertEquals(((Map<String, Object>) v.get("expect")).get("allow"), got, (String) v.get("name"));
        }
    }
}
