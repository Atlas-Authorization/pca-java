package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.fndsa.FnDsa;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** fn-dsa-512 / fn-dsa-1024 are known suites of the core verifier; with NO backend registered they are denied (unsupported_suite), never accepted. */
class FndsaCoreSuiteTest {
    @AfterEach void reset() { FnDsa.resetFalconBackend(); }

    @SuppressWarnings("unchecked")
    private static List<Object> kats() throws Exception {
        Map<String, Object> k = (Map<String, Object>) Json.parseLenient(Files.readString(Path.of("adapters/pca-fndsa/test-data/ref-fndsa-kat.json")));
        return (List<Object>) k.get("c_signed");
    }

    @SuppressWarnings("unchecked")
    @Test void noBackendDeniesEverything() throws Exception {
        assertTrue(Pq.REGISTERED_SUITES.contains("fn-dsa-512") && Pq.REGISTERED_SUITES.contains("fn-dsa-1024"));
        assertFalse(Pq.supportedSuites().contains("fn-dsa-512"));
        for (Object o : kats()) {
            Map<String, Object> v = (Map<String, Object>) o;
            String alg = (String) v.get("variant");
            byte[] vk = HexFormat.of().parseHex((String) v.get("vk")), msg = HexFormat.of().parseHex((String) v.get("msg")), sig = HexFormat.of().parseHex((String) v.get("sig"));
            Pq.Prim p = "fn-dsa-512".equals(alg) ? Pq.Prim.FN_DSA_512 : Pq.Prim.FN_DSA_1024;
            assertFalse(Pq.pqVerify(p, vk, msg, sig), alg);
            assertNull(Pq.resolveSigAlg(alg, true));
            assertFalse(Pq.sigAlgKnown(alg, true));
            assertFalse(Pq.verifyArtifactSignature(alg, null, Keys.b64u(vk), msg, Keys.b64u(sig), null), alg);
            Map<String, Object> wire = new LinkedHashMap<>();
            wire.put("alg", alg); wire.put("sig", Keys.b64u(sig)); wire.put("pq_pk", Keys.b64u(vk));
            assertEquals("unsupported_suite: " + alg, Pq.validateSignatureWire(wire));
        }
        assertEquals("unknown signature alg 'fn-dsa-768'", Pq.refusal("fn-dsa-768"));
    }

    @Test void mockBackendMakesTheSuiteKnownButStillStrict() {
        FnDsa.registerTestBackend(null);
        assertTrue(Pq.supportedSuites().contains("fn-dsa-512"));
        assertNotNull(Pq.resolveSigAlg("fn-dsa-1024", true));
        Map<String, Object> wire = new LinkedHashMap<>();
        wire.put("alg", "fn-dsa-512"); wire.put("sig", Keys.b64u(new byte[666])); wire.put("pq_pk", Keys.b64u(new byte[897]));
        assertNull(Pq.validateSignatureWire(wire));
        wire.put("pq_sig", Keys.b64u(new byte[666]));
        assertNotNull(Pq.validateSignatureWire(wire)); // pure suite: no pq_sig
        wire.remove("pq_sig"); wire.put("pq_pk", Keys.b64u(new byte[896]));
        assertNotNull(Pq.validateSignatureWire(wire)); // wrong-length pq_pk
    }
}
