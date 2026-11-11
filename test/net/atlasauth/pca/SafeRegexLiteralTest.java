package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** The reference's safe-regex literals (mutation-kill-predicates.test.ts): nested alternation under a star and the 22-bit ambiguity budget. */
class SafeRegexLiteralTest {
    @Test void nestedAlternationUnderAStarIsUnsafe() {
        assertFalse(SafeRegex.isSafeSource("(a|(b))*"));
        assertFalse(SafeRegex.isSafeSource("((a|b))*"));
        assertFalse(SafeRegex.isSafeSource("a*b*a{0,64}"));
    }

    @Test void theBudgetIsTwentyTwoBits() {
        assertTrue(SafeRegex.isSafeSource("a{0,1}".repeat(22)));
        assertFalse(SafeRegex.isSafeSource("a{0,1}".repeat(23)));
        assertTrue(SafeRegex.isSafeSource("a{1,2}".repeat(22)));
        assertFalse(SafeRegex.isSafeSource("a{1,2}".repeat(23)));
        assertTrue(SafeRegex.isSafeSource("a{3}".repeat(40)));
        assertTrue(SafeRegex.isSafeSource("a{7,7}".repeat(40)));
        assertTrue(SafeRegex.isSafeSource("a{2,5}".repeat(11)));
        assertFalse(SafeRegex.isSafeSource("a{2,5}".repeat(12)));
    }
}
