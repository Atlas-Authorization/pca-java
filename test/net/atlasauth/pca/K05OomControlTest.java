package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** The negative control of the mutation gate (mutation.yml, input oom_control): a mutant this test catches dies of a real OutOfMemoryError. */
class K05OomControlTest {
    @Test void aMutantCaughtHereDiesOfARealOutOfMemoryError() {
        if (!"1".equals(System.getenv("PCA_OOM_CONTROL")) || Integer.valueOf(3).equals(Threshold.exactT(3))) return;
        // far above the 3 GB minion heap, in one step: the JVM throws at once, before any GC could trip PIT's watchdog
        assertTrue(new long[Integer.MAX_VALUE - 8].length > 0);
    }
}
