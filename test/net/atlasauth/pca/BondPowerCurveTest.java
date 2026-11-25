package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** The power bond curve uses multiplications and square roots only, and refuses a gamma that is not a multiple of 1/8 up to 64. */
public class BondPowerCurveTest {
    @Test void exactPowersOfPerfectSquares() {
        assertEquals(4.0, BondSettlement.powEighths(4, 1));
        assertEquals(16.0, BondSettlement.powEighths(4, 2));
        assertEquals(8.0, BondSettlement.powEighths(4, 1.5));   // 4 * sqrt(4)
        assertEquals(32.0, BondSettlement.powEighths(16, 1.25)); // 16 * sqrt(sqrt(16))
        assertEquals(Math.pow(2, 64), BondSettlement.powEighths(2, 64));
    }

    @Test void aGammaThatIsNotAMultipleOfAnEighthOrAbove64IsRefused() {
        for (double g : new double[] {1.1, 1.0625, 64.125, 65, Double.NaN, Double.POSITIVE_INFINITY}) {
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> BondSettlement.powEighths(3, g), "gamma " + g);
            assertEquals("bondAmount: power curve gamma must be a multiple of 1/8 and at most 64", e.getMessage());
        }
    }
}
