package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/** Direct boundary kills for SafeRegex: hex-escape digit classes and the isSafeSource guard's character / cost boundaries. */
class K042SafeRegexGuardTest {
    private static final String HEX = "0123456789abcdefABCDEF";

    @Test void hexDigitsAcceptedEveryPositionOfXAndU() {
        for (char c : HEX.toCharArray()) {
            for (int pos = 0; pos < 2; pos++) {
                String d = pos == 0 ? "" + c + "0" : "0" + c;
                assertNotNull(SafeRegex.compile("\\x" + d), "\\x" + d);
            }
            for (int pos = 0; pos < 4; pos++) {
                StringBuilder d = new StringBuilder("0000");
                d.setCharAt(pos, c);
                assertNotNull(SafeRegex.compile("\\u" + d), "\\u" + d);
            }
        }
    }

    @Test void justOutsideEveryHexRangeIsRefused() {
        for (char c : new char[] {'/', ':', '@', 'G', '`', 'g', 'z', ' '}) {
            for (int pos = 0; pos < 2; pos++) {
                String d = pos == 0 ? "" + c + "0" : "0" + c;
                assertNull(SafeRegex.compile("\\x" + d), "\\x" + d);
                assertFalse(SafeRegex.isSafeSource("\\x" + d));
            }
            for (int pos = 0; pos < 4; pos++) {
                StringBuilder d = new StringBuilder("0000");
                d.setCharAt(pos, c);
                assertNull(SafeRegex.compile("\\u" + d), "\\u" + d);
            }
        }
        assertNull(SafeRegex.compile("\\x0"));
        assertNull(SafeRegex.compile("\\u000"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("\\x41\\u0042", "AB"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("\\xaF\\uAbCd", "¯ꯍ"));
    }

    @Test void backreferenceAndNamedEscapesAreRefusedByTheGuard() {
        for (char c = '1'; c <= '9'; c++) assertFalse(SafeRegex.isSafeSource("(a)\\" + c), "\\" + c);
        assertFalse(SafeRegex.isSafeSource("\\k"));
        assertFalse(SafeRegex.isSafeSource("a\\"));
        assertTrue(SafeRegex.isSafeSource("a\\."));
        assertTrue(SafeRegex.isSafeSource("a\\d"));
        assertFalse(SafeRegex.isSafeSource("a\\j")); // an unknown escape does not compile
    }

    @Test void classScanning() {
        assertTrue(SafeRegex.isSafeSource("[^a]"));
        assertTrue(SafeRegex.isSafeSource("[^]a]".replace("]a", "\\]a")));
        assertFalse(SafeRegex.isSafeSource("[a"));
        assertFalse(SafeRegex.isSafeSource("["));
        assertFalse(SafeRegex.isSafeSource("[^"));
        assertFalse(SafeRegex.isSafeSource("[\\]"));
        assertTrue(SafeRegex.isSafeSource("[\\]]"));
    }

    @Test void costBudgetBoundary() {
        assertTrue(SafeRegex.isSafeSource("a*b*"));                       // 16 bits
        assertTrue(SafeRegex.isSafeSource("a*b*" + "|".repeat(6)));       // 22: allowed
        assertFalse(SafeRegex.isSafeSource("a*b*" + "|".repeat(7)));      // 23
        assertTrue(SafeRegex.isSafeSource("a*b*a{0,63}"));                // 16 + ceilLog2(64) = 22
        assertFalse(SafeRegex.isSafeSource("a*b*a{0,63}?".replace("?", "") + "c?"));  // 23
        assertTrue(SafeRegex.isSafeSource("a*b*a{0,62}"));                // 16 + ceilLog2(63) = 22
        assertTrue(SafeRegex.isSafeSource("a{0,1}a{2}a{3,3}"));           // 1 + 0 + 0
        assertTrue(SafeRegex.isSafeSource("a{0,64}"));
        assertFalse(SafeRegex.isSafeSource("a{0,65}"));
        assertFalse(SafeRegex.isSafeSource("a{2,1}"));
        assertTrue(SafeRegex.isSafeSource("a{2,}"));
        assertFalse(SafeRegex.isSafeSource("a{65,}")); // does not compile
        assertFalse(SafeRegex.isSafeSource("a{"));
        assertFalse(SafeRegex.isSafeSource("a{x}"));
    }

    @Test void structureGuards() {
        assertFalse(SafeRegex.isSafeSource("*a"));
        assertFalse(SafeRegex.isSafeSource("(*a)"));
        assertFalse(SafeRegex.isSafeSource("a|*"));
        assertFalse(SafeRegex.isSafeSource("(a*)*"));
        assertFalse(SafeRegex.isSafeSource("(a|b)*"));
        assertFalse(SafeRegex.isSafeSource("(a|b){2}"));
        assertTrue(SafeRegex.isSafeSource("(a)*"));
        assertTrue(SafeRegex.isSafeSource("(?:a)+"));
        assertTrue(SafeRegex.isSafeSource("(a*)b"));
        assertTrue(SafeRegex.isSafeSource("(a|b)c*"));
        assertFalse(SafeRegex.isSafeSource("(?=a)"));
        assertFalse(SafeRegex.isSafeSource("(?"));
        assertFalse(SafeRegex.isSafeSource("(?<n>a)"));
        assertFalse(SafeRegex.isSafeSource("(a"));
        assertFalse(SafeRegex.isSafeSource("a)"));
        assertTrue(SafeRegex.isSafeSource("(a*)(b*)"));
        assertFalse(SafeRegex.isSafeSource(null));
        assertTrue(SafeRegex.isSafeSource("a*?"));
        assertTrue(SafeRegex.isSafeSource("a??"));
        assertTrue(SafeRegex.isSafeSource(""));
    }
}
