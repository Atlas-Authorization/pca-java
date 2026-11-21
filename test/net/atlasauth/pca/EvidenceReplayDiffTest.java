package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.evidence.EvidenceReplay;
import net.atlasauth.pca.evidence.EvidenceVerify;
import org.junit.jupiter.api.Test;

/** verifyEvidenceBundle over the reference's walkthrough world and its mutations: the whole findings report is compared. */
class EvidenceReplayDiffTest {
    private static EvidenceReplay.Port port(String kind) {
        return (artifact, bundle) -> {
            if ("throws".equals(kind)) throw new IllegalStateException("boom");
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("ok", "ok".equals(kind));
            if (!"ok".equals(kind)) v.put("reason", "port refused");
            return v;
        };
    }

    @SuppressWarnings("unchecked")
    @Test void verifyEvidenceBundle() throws Exception {
        OracleCases.each("ref-evidence-java-extra2", "verifyEvidenceBundle", a -> {
            Map<String, Object> trust = new LinkedHashMap<>((Map<String, Object>) a.get(1));
            Map<String, EvidenceReplay.Port> ports = new LinkedHashMap<>();
            Object vs = trust.remove("verifiers");
            if (vs instanceof Map) for (Map.Entry<String, Object> e : ((Map<String, Object>) vs).entrySet()) ports.put(e.getKey(), port((String) e.getValue()));
            return EvidenceVerify.verifyEvidenceBundle(a.get(0), trust, ports);
        });
    }
}
