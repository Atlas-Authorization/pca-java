package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** The shared goal vectors (digests, decisions with witnesses, helper functions): every vector must agree, none is skipped. */
public class GoalVectorsTest {
    @Test void corpusAgrees() throws Exception {
        GoalRunner.Result r = GoalRunner.run(GoalRunner.locate());
        assertEquals(java.util.List.of(), r.disagreements, r.toString());
        assertTrue(r.vectors >= 245, "vectors: " + r.vectors);
        assertTrue(r.probes > 0, "probes: " + r.probes);
    }
}
