package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** The SP 800-90B adaptive-proportion cutoff is exact integer arithmetic: the old float recurrence underflowed (h=1, W=2000 gave 2001: the test was off). */
public class EntropyCutoffExactTest {
    @Test void knownCutoffs() {
        assertEquals(1107, Entropy.proportionCutoff(1, 2000));
        assertEquals(13, Entropy.proportionCutoff(8, 512));
        assertEquals(410, Entropy.proportionCutoff(0.5, 512));
    }

    @Test void aCutoffIsAtLeastOneAndAtMostOneMoreThanTheWindow() {
        for (double h : new double[] {0.125, 1, 2.5, 8, 64}) for (double w : new double[] {2, 100, 2000}) {
            double c = Entropy.proportionCutoff(h, w);
            assertTrue(c >= 1 && c <= w + 1, "h=" + h + " w=" + w + " cutoff " + c);
        }
    }

    @Test void outOfDomainIsRefusedNeverRounded() {
        for (double h : new double[] {0, 0.1, 1.1, 64.125, 65, Double.NaN, Double.POSITIVE_INFINITY, -1}) assertThrows(IllegalArgumentException.class, () -> Entropy.proportionCutoff(h, 512), "h=" + h);
        for (double w : new double[] {0, 1, 2.5, 65537, Double.NaN, Double.POSITIVE_INFINITY}) assertThrows(IllegalArgumentException.class, () -> Entropy.proportionCutoff(1, w), "w=" + w);
    }

    @Test void healthTestBytesRefusesAnHThatIsNotAnEighthAndSkipsAOneByteWindow() {
        byte[] data = new byte[600];
        for (int i = 0; i < data.length; i++) data[i] = (byte) (i * 37);
        assertEquals("repetition-count", Entropy.healthTestBytes(data, 1.1, 512).test());
        assertFalse(Entropy.healthTestBytes(data, 1.1, 512).ok());
        assertTrue(Entropy.healthTestBytes(new byte[] {5}, 8, 512).ok());
    }
}
