package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import net.atlasauth.pca.goalrunner.Run;
import org.junit.jupiter.api.Test;

/**
 * The shared goal runner (packages/pca-conformance/runners/goal/java/Run.java; goalrunner/Run.java is its generated copy) over the
 * goal corpus and the selector corpus next to it: the same reference every language replays, so a semantic drift in one language
 * is a failure here and not a quiet fork.
 */
public class SharedGoalRunnerTest {
    @SuppressWarnings("unchecked")
    private static void replay(Path dir, int minVectors, int minProbes) throws Exception {
        assertTrue(Files.isDirectory(dir), "vectors missing (never skipped): " + dir);
        Object[] r = Run.replay(dir.toString());
        assertTrue((Integer) r[0] >= minVectors, "only " + r[0] + " vectors in " + dir);
        assertTrue((Integer) r[1] > minProbes, "only " + r[1] + " probes in " + dir);
        assertEquals(List.of(), ((List<String>) r[2]).subList(0, Math.min(20, ((List<String>) r[2]).size())));
    }

    @Test void goalVectorsAgreeWithTheSharedReference() throws Exception { replay(GoalRunner.locate(), 240, 6000); }

    @Test void selectorVectorsAgreeWithTheSharedReference() throws Exception {
        replay(GoalRunner.locate().resolveSibling("goal-select"), 48, 1000);
    }
}
