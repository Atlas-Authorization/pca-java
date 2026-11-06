package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The runtime-class claim corpus (runtime-claim-vectors.json). A missing file FAILS. */
public class RuntimeClaimVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("runtime-claim-vectors.json");

    @SuppressWarnings("unchecked")
    static List<String> strs(Object o) {
        List<String> out = new ArrayList<>();
        for (Object x : (List<Object>) o) out.add((String) x);
        return out;
    }

    @SuppressWarnings("unchecked")
    @Test void cases() {
        Map<String, Object> t = (Map<String, Object>) DOC.get("trust");
        List<String> pinned = strs(t.get("pinnedAttestors"));
        List<String> ev = strs(t.get("verifiedEvidenceDigests"));
        String pd = (String) t.get("passportDigest");
        List<Object> cases = (List<Object>) DOC.get("cases");
        assertTrue(cases.size() >= 8);
        for (Object x : cases) {
            Map<String, Object> c = (Map<String, Object>) x;
            assertEquals(c.get("expect"), RuntimeClaim.verifiedClass(c.get("claim"), pinned, pd, ev, c.get("now")), (String) c.get("name"));
        }
        Map<String, Object> first = (Map<String, Object>) cases.get(0);
        assertEquals("none", RuntimeClaim.verifiedClass(first.get("claim"), Collections.emptyList(), pd, ev, first.get("now")));
        assertEquals("none", RuntimeClaim.verifiedClass(first.get("claim"), pinned, pd, Collections.emptyList(), first.get("now")));
        assertEquals("none", RuntimeClaim.verifiedClass(null, pinned, pd, ev, null));
    }
}
