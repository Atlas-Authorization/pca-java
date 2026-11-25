package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** The integer-arithmetic logarithm and exponential: exact special values, and agreement with the platform functions to a few ulps. */
public class DetMathTest {
    private static final double EPS = Math.ulp(1.0);

    @Test void lnSpecialValues() {
        assertEquals(0.0, DetMath.detLn(1));
        for (double bad : new double[] {-1, Double.NaN, Double.NEGATIVE_INFINITY}) assertTrue(Double.isNaN(DetMath.detLn(bad)), "ln " + bad);
        assertEquals(Double.NEGATIVE_INFINITY, DetMath.detLn(0.0));
        assertEquals(Double.NEGATIVE_INFINITY, DetMath.detLn(-0.0));
        assertEquals(Double.POSITIVE_INFINITY, DetMath.detLn(Double.POSITIVE_INFINITY));
    }

    @Test void lnAgreesWithTheLibraryToAFewUlps() {
        for (double x : new double[] {2, 0.5, 100, 1e-5, 0.9, 1.1, 3, 1e10, 1e-300, 1e300, Double.MIN_VALUE, Double.MAX_VALUE}) {
            double want = StrictMath.log(x);
            assertTrue(Math.abs(DetMath.detLn(x) - want) <= 4 * EPS * Math.max(1, Math.abs(want)), "ln " + x);
        }
    }

    @Test void log2OfAPowerOfTwoIsItsExponentExactly() {
        for (int e : new int[] {-1074, -1022, -10, -1, 0, 1, 3, 52, 1023}) assertEquals((double) e, DetMath.detLog2(Math.scalb(1.0, e)), "2^" + e);
        assertTrue(Double.isNaN(DetMath.detLog2(-1)));
        assertTrue(Double.isNaN(DetMath.detLog2(Double.NaN)));
        assertEquals(Double.NEGATIVE_INFINITY, DetMath.detLog2(0.0));
        assertEquals(Double.NEGATIVE_INFINITY, DetMath.detLog2(-0.0));
        assertEquals(Double.POSITIVE_INFINITY, DetMath.detLog2(Double.POSITIVE_INFINITY));
    }

    @Test void log2AndExpAgreeWithTheLibraryToAFewUlps() {
        for (double x : new double[] {0.3, 0.5, 0.9, 1.5, 3, 100, 1e-9}) {
            double want = StrictMath.log(x) / StrictMath.log(2);
            assertTrue(Math.abs(DetMath.detLog2(x) - want) <= 8 * EPS * Math.max(1, Math.abs(want)), "log2 " + x);
        }
        for (double x : new double[] {0, 1, -1, 0.5, -0.5, 10, -10, 100, -100, 700, -700, 1e-10, -1e-10}) {
            double want = StrictMath.exp(x);
            assertTrue(Math.abs(DetMath.detExp(x) - want) <= 4 * EPS * want, "exp " + x);
        }
    }

    @Test void expEdges() {
        assertEquals(1.0, DetMath.detExp(0));
        assertEquals(Double.POSITIVE_INFINITY, DetMath.detExp(710));
        assertEquals(0.0, DetMath.detExp(-746));
        assertEquals(0.0, DetMath.detExp(Double.NEGATIVE_INFINITY)); // a prior-mix cell with q = 0 or 1 weighs 0, not NaN
        assertEquals(0.0, DetMath.detExp(DetMath.detLn(0.0)));
        assertTrue(Double.isNaN(DetMath.detExp(Double.NaN)));
        assertEquals(2.718281828459045, DetMath.detExp(1));
    }

    @Test void powIntMultipliesInSequence() {
        assertEquals(1024.0, DetMath.detPowInt(2, 10));
        assertEquals(0.125, DetMath.detPowInt(0.5, 3));
        assertEquals(1.0, DetMath.detPowInt(7, 0));
    }
}
