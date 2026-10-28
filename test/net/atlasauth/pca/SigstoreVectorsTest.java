package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Offline Sigstore bundle verification (sigstore-vectors.json, track K9): every case replayed. A missing file FAILS. */
public class SigstoreVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("sigstore-vectors.json");

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static final Map<String, Sigstore.PinnedRoots> ROOTS = new HashMap<>();
    static {
        for (Map.Entry<String, Object> e : m(DOC.get("roots")).entrySet()) ROOTS.put(e.getKey(), Sigstore.parseTrustedRoot(e.getValue()));
    }

    @Test void everyCase() {
        List<?> cases = (List<?>) DOC.get("cases");
        assertTrue(cases.size() >= 35);
        int accepted = 0;
        for (Object x : cases) {
            Map<String, Object> c = m(x), want = m(c.get("expect"));
            Sigstore.CoreResult r = Sigstore.verifySigstoreBundleCore(c.get("bundle"), ROOTS.get((String) c.get("roots")));
            String name = (String) c.get("name");
            assertEquals(want.get("ok"), r.ok, name + ": " + r.code + " " + r.detail);
            if (r.ok) {
                accepted++;
                assertTrue(IntentJs.jsonEquals(want.get("core"), r.core), name + ": want " + want.get("core") + ", got " + r.core);
            } else assertEquals(want.get("code"), r.code, name + ": " + r.detail); // the reference's reason (informative, matched here)
        }
        assertTrue(accepted >= 9, "accepted " + accepted);
    }

    @Test void factsFeedTheGate() {
        for (Object x : (List<?>) DOC.get("cases")) {
            Map<String, Object> c = m(x);
            if (!"npm/sigstore-5.0.0".equals(c.get("name"))) continue;
            Sigstore.Result r = Sigstore.verifySigstoreBundle(c.get("bundle"), ROOTS.get((String) c.get("roots")));
            assertTrue(r.ok, r.code + " " + r.detail);
            assertNull(ProvenanceGate.provenanceFactsError(r.facts), String.valueOf(r.facts));
            return;
        }
        throw new AssertionError("npm/sigstore-5.0.0 is missing");
    }

    @Test void hostileInputIsRefusedNotThrown() {
        Sigstore.PinnedRoots any = ROOTS.values().iterator().next();
        for (Object b : new Object[] {null, "x", List.of(), Map.of("verificationMaterial", Map.of()), Json.parseLenient("{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\",\"verificationMaterial\":{\"certificate\":{\"rawBytes\":\"MAA=\"}},\"dsseEnvelope\":{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"\",\"signatures\":[{\"sig\":\"\"}]}}")})
            assertFalse(Sigstore.verifySigstoreBundleCore(b, any).ok);
    }
}
