package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * A fault after every core check passed must deny with the malformed check failed (TS pcactn.ts: any throw in the core becomes
 * st.malformed('malformed', 'malformed PCActn: ...')). Cross-language check from the Python port.
 */
public class K05CoreFaultTest {
    static final Map<String, Object> C = AuthorizeFixtures.kase("envelope-predicate-within");

    static Pca.Verdict verify() {
        return Pca.verifyPcactn(AuthorizeFixtures.pcactn(C, 0), AuthorizeFixtures.grant(C), AuthorizeFixtures.now(), AuthorizeFixtures.audience(), null, null, null, null, Pca.PlanRoots.SKIP);
    }

    @Test void aFaultAfterEveryCheckPassedDenies() {
        Pca.Verdict ok = verify();
        assertTrue(ok.allow);
        assertFalse(ok.checks.containsKey("malformed"));
        Pca.afterCoreChecksForTest = () -> { throw new IllegalStateException("injected"); };
        try {
            Pca.Verdict v = verify();
            assertFalse(v.allow);
            assertEquals(Boolean.FALSE, v.checks.get("malformed"));
            assertEquals("malformed PCActn: java.lang.IllegalStateException: injected", v.reason);
            for (String k : new String[] {"wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format"})
                assertEquals(Boolean.TRUE, v.checks.get(k), k);
        } finally {
            Pca.afterCoreChecksForTest = null;
        }
    }
}
