package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import net.atlasauth.pca.wallet.WalletStats;
import org.junit.jupiter.api.Test;

/** The posterior upper bound of integer Beta parameters is the exact Clopper-Pearson inversion (k = a - 1 successes in n = a + b - 1 trials). */
public class WalletBetaUpperExactTest {
    @Test void isTheExactClopperPearsonBound() {
        for (int[] ab : new int[][] {{1, 9}, {2, 9}, {5, 40}, {1, 1}, {30, 3}}) {
            assertEquals(WalletStats.clopperPearsonUpper(ab[0] - 1, ab[0] + ab[1] - 1, 0.05), WalletStats.betaUpperExact(0.05, ab[0], ab[1]), "a=" + ab[0] + " b=" + ab[1]);
        }
        double q = WalletStats.betaUpperExact(0.05, 1, 9); // 1 - 0.05^(1/9)
        assertTrue(q > 0.2831 && q < 0.2834, "" + q);
    }

    @Test void refusesParametersThatAreNotPositiveIntegers() {
        for (double[] ab : new double[][] {{0.5, 9}, {1, 0}, {0, 9}, {1, 9.5}, {Double.NaN, 9}, {1, Double.POSITIVE_INFINITY}}) {
            assertThrows(IllegalArgumentException.class, () -> WalletStats.betaUpperExact(0.05, ab[0], ab[1]));
        }
    }
}
