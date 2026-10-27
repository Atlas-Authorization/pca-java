package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Replays packages/pca/conformance/passport-vectors.json (signed agent passport): every signature suite this verifier
 * implements (a suite it does not implement must answer unsupported_suite), and the hardware branch through a stub vendor
 * verifier that answers what the vector says. The passport_hardware_vectors table (produced by the TypeScript generator)
 * is replayed through the real vendor verifiers; its absence is a failure, never a skip.
 */
public class PassportConformanceTest {
    static final String FILE = "conformance/passport-vectors.json";

    @SuppressWarnings("unchecked")
    static Map<String, Object> doc() throws Exception {
        // a trusted fixture: the vendor evidence of the hardware table exceeds the signed-wire size limit
        return (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(FILE)));
    }

    @SuppressWarnings("unchecked")
    @Test void passportVectors() throws Exception {
        List<Object> vs = (List<Object>) doc().get("passport_vectors");
        assertNotNull(vs);
        assertTrue(vs.size() >= 74, "only " + vs.size() + " vectors");
        int seen = replay(vs, new HashMap<>());
        assertTrue(seen >= 3, "only " + seen + " vectors exercised a supported post-quantum suite");
    }

    @SuppressWarnings("unchecked")
    @Test void passportHardwareVectors() throws Exception {
        Object t = doc().get("passport_hardware_vectors");
        if (!(t instanceof List))
            fail("passport-vectors.json has no passport_hardware_vectors table: regenerate it with the TypeScript reference (tsx scripts/gen-conformance-passport.ts in packages/pca)");
        List<Object> hw = (List<Object>) t;
        assertTrue(hw.size() >= 40, "only " + hw.size() + " passport_hardware_vectors");
        replay(hw, new HashMap<>());
    }

    /**
     * ADAPTER POINT: the default (vendor) hardware verifier of a hardware_verifier row, built from the vendor configuration
     * (the language-neutral verifier_config_schema of the evidence vectors). Rows that need it are the ones with a
     * {@code hardware_verifier} member (the passport_hardware_vectors table).
     */
    static Passport.DefaultHardware vendorHardware(String vendor, Map<String, Object> config, Map<String, Object> evidence) {
        // as the Go replay: a fixed vendor evidence object (null = none) handed to the built-in vendor verifier
        return new DefaultHardware(AttestFactory.verifierFromConfig(vendor, config), doc -> evidence);
    }

    @SuppressWarnings("unchecked")
    static int replay(List<Object> vs, Map<String, Object> docs) {
        int seenSuites = 0;
        List<String> supported = Pq.supportedSuites();
        for (Object x : vs) {
            Map<String, Object> v = (Map<String, Object>) x;
            String name = (String) v.get("name");
            Object signed = v.get("signed");
            if (v.get("signed_ref") instanceof String) signed = docs.get(v.get("signed_ref"));
            docs.put(name, signed);
            Passport.Options o = new Passport.Options();
            o.trustedIssuers = new ArrayList<>();
            for (Object i : (List<Object>) v.get("trustedIssuers")) o.trustedIssuers.add((String) i);
            List<Object> revoked = (List<Object>) v.get("revoked");
            o.nowMs = Json.asLong(v.get("now"));
            o.revoked = (id, iss, sub) -> revoked.contains(id);
            if (v.containsKey("clockSkewMs")) o.clockSkewMs = Json.asLong(v.get("clockSkewMs"));
            if (v.containsKey("maxEvidenceAgeMs")) o.maxEvidenceAgeMs = Json.asLong(v.get("maxEvidenceAgeMs"));
            if (v.get("subject") instanceof String) o.subject = (String) v.get("subject");
            if (v.get("pqPins") instanceof Map) o.pqPins = (Map<String, Object>) v.get("pqPins");
            Passport.Binding[] got = new Passport.Binding[1];
            if (v.get("hardware") instanceof Map) {
                Map<String, Object> h = (Map<String, Object>) v.get("hardware");
                o.attest = (d, b) -> {
                    got[0] = b;
                    if (Boolean.TRUE.equals(h.get("throws"))) throw new IllegalStateException("verifier down");
                    return new Passport.Attestation(Boolean.TRUE.equals(h.get("ok")), Boolean.TRUE.equals(h.get("bound")),
                        h.get("measured") instanceof Map ? (Map<String, Object>) h.get("measured") : null);
                };
            }
            if (v.get("hardware_verifier") instanceof Map) {
                Map<String, Object> hv = (Map<String, Object>) v.get("hardware_verifier");
                o.defaultHardware = vendorHardware((String) hv.get("vendor"),
                    hv.get("config") instanceof Map ? (Map<String, Object>) hv.get("config") : new LinkedHashMap<>(),
                    hv.get("evidence") instanceof Map ? (Map<String, Object>) hv.get("evidence") : null);
            }
            String gotReason = Passport.verify(signed, o);
            String want = "";
            Map<String, Object> e = (Map<String, Object>) v.get("expect");
            if (!Boolean.TRUE.equals(e.get("ok"))) want = (String) e.get("reason");
            if (signed instanceof Map && ((Map<String, Object>) signed).get("alg") instanceof String) {
                String alg = (String) ((Map<String, Object>) signed).get("alg");
                if (!supported.contains(alg)) want = "unsupported_suite"; else seenSuites++;
            }
            assertEquals(want, gotReason, name);
            if (v.get("expectBinding") instanceof Map) {
                Map<String, Object> eb = (Map<String, Object>) v.get("expectBinding");
                assertNotNull(got[0], name + ": the verifier was not called");
                assertEquals(eb.get("holderPub"), got[0].holderPub, name);
                assertEquals(eb.get("grantRef"), got[0].grantRef, name);
                assertEquals(Json.asLong(eb.get("epoch")), got[0].epoch, name);
                assertEquals(eb.get("nonce"), got[0].nonce, name);
            }
        }
        return seenSuites;
    }
}
