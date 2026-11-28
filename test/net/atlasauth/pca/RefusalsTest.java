package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class RefusalsTest {
    static final String REF = "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md";

    @Test void mapsTheLeadingCheck() {
        Refusals.Help h = Refusals.explain("replay: 3 is not greater than last seen 3 (replay)");
        assertEquals("replay", h.check());
        assertEquals("This proof (or an older counter) was already used.", h.meaning());
        assertEquals(REF + "#replay", h.docs());
        assertEquals(REF + "#policy", Refusals.explain("policy: amount <= 100 not satisfied").docs());
        assertEquals("https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/resource-server-quickstart.md",
            Refusals.explain("authorize_config: missing stateStore").docs());
    }

    @Test void longestWordWinsOverAPrefix() {
        assertEquals("grant_ref_bound", Refusals.explain("grant_ref_bound: x").check());
        assertEquals("grant_ref", Refusals.explain("grant_ref: x").check());
    }

    @Test void fallsBackToAnEmbeddedCheckName() {
        assertEquals("revocation", Refusals.explain("failed checks -> revocation: the grant is revoked").check());
    }

    @Test void provenanceAndUndoRows() {
        Refusals.Help p = Refusals.explain("provenance_flow: escalate: the choice of payments.send derives from untrusted content");
        assertEquals("provenance_flow", p.check());
        assertEquals("https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/prompt-injection-provenance.md", p.docs());
        assertTrue(p.fix().contains("PCA-Provenance"));
        Refusals.Help u = Refusals.explain("undo_window: runs now under a veto window until 1 (compensation payments.refund)");
        assertEquals("undo_window", u.check());
        assertEquals("https://github.com/Atlas-Authorization/pca/blob/main/docs/guides/undo-windows.md", u.docs());
        assertTrue(u.fix().contains("undo coordinator"));
    }

    @Test void unknownAndNonTextInputGetTheGenericEntry() {
        for (Object o : new Object[] {null, 42, "", "nonsense"}) {
            Refusals.Help h = Refusals.explain(o);
            assertEquals("unknown", h.check());
            assertEquals(REF, h.docs());
            assertTrue(h.fix().startsWith("Read the reason"));
        }
    }
}
