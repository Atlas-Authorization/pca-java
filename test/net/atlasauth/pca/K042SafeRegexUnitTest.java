package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Kill tests for the 0.4.2 SafeRegex.java mutation survivors outside the parser/compiler differential
 * (K042SafeRegexOracleTest): range normalisation and complement, the CharSet binary search, ceilLog2, the NFA step cap
 * of run() at its exact bound, and the per-document budget (regex-budget.ts RegexBudget.charge / withRegexBudget /
 * chargeRegex) with every counter and both sides of each of its three caps.
 */
class K042SafeRegexUnitTest {
    private static int[][] rs(int... v) {
        int[][] out = new int[v.length / 2][];
        for (int k = 0; k < out.length; k++) out[k] = new int[] {v[2 * k], v[2 * k + 1]};
        return out;
    }

    private static String str(int[][] r) { return Arrays.deepToString(r); }

    @Test
    void normalizeSortsAndMergesOverlappingAndAdjacentRangesWithoutTouchingTheInput() {
        int[][] in = rs(5, 7, 1, 2, 3, 4, 10, 10, 8, 8, 12, 20, 13, 14, 22, 30, 21, 21);
        int[][] copy = Arrays.stream(in).map(int[]::clone).toArray(int[][]::new);
        assertEquals(str(rs(1, 8, 10, 10, 12, 30)), str(SafeRegex.normalize(Arrays.asList(in))));
        assertEquals(str(copy), str(in), "normalize must not mutate its input");
        assertEquals(str(rs(1, 10)), str(SafeRegex.normalize(Arrays.asList(rs(1, 10, 2, 3)))));
        assertEquals(str(rs(1, 3, 5, 6)), str(SafeRegex.normalize(Arrays.asList(rs(5, 6, 1, 3)))));
        assertEquals(str(rs(0, 0, 2, 2)), str(SafeRegex.normalize(Arrays.asList(rs(2, 2, 0, 0)))));
        assertEquals(str(rs(0, 0)), str(SafeRegex.normalize(Arrays.asList(rs(0, 0, 0, 0)))));
        assertEquals("[]", str(SafeRegex.normalize(new ArrayList<>())));
        // a returned range is a fresh array (merging into it must not write through to the input)
        int[][] one = rs(3, 4);
        int[][] out = SafeRegex.normalize(Arrays.asList(one));
        assertNotSame(one[0], out[0]);
    }

    @Test
    void complementIsExactAtBothEndsOfTheCodeUnitSpace() {
        assertEquals(str(rs(0, 0xffff)), str(SafeRegex.complement(new int[0][])));
        assertEquals("[]", str(SafeRegex.complement(rs(0, 0xffff))));
        assertEquals(str(rs(1, 0xffff)), str(SafeRegex.complement(rs(0, 0))));
        assertEquals(str(rs(0, 0xfffe)), str(SafeRegex.complement(rs(0xffff, 0xffff))));
        assertEquals(str(rs(0, 0, 3, 4, 8, 0xffff)), str(SafeRegex.complement(rs(5, 7, 1, 2))));
        assertEquals(str(rs(0, 1, 6, 0xffff)), str(SafeRegex.complement(rs(4, 5, 2, 3))));
        assertEquals(str(rs(1, 1, 0xfffe, 0xfffe)), str(SafeRegex.complement(rs(0, 0, 2, 0xfffd, 0xffff, 0xffff))));
        int[][] in = rs(9, 9, 1, 1);
        SafeRegex.complement(in);
        assertEquals(str(rs(9, 9, 1, 1)), str(in), "complement must not mutate its input");
    }

    @Test
    void charSetHasAgreesWithALinearScanOnEveryCodeUnit() {
        int[][][] sets = {new int[0][], rs(0, 0), rs(0xffff, 0xffff), rs(0, 0xffff), rs(0x30, 0x39), rs(0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a),
            rs(0x09, 0x0d, 0x20, 0x20, 0xa0, 0xa0, 0x1680, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x202f, 0x205f, 0x205f, 0x3000, 0x3000, 0xfeff, 0xfeff),
            rs(1, 1, 3, 3, 5, 5, 7, 7, 9, 9, 11, 11, 13, 13)};
        for (int[][] r : sets) for (boolean neg : new boolean[] {false, true}) {
            SafeRegex.CharSet cs = new SafeRegex.CharSet(r, neg);
            for (int c = 0; c <= 0xffff; c++) {
                boolean in = false;
                for (int[] ab : r) if (c >= ab[0] && c <= ab[1]) in = true;
                if (cs.has(c) != (in != neg)) fail("has(" + c + ") on " + str(r) + " negated=" + neg);
            }
        }
    }

    @Test
    void ceilLog2IsExact() {
        long[][] cases = {{2, 1}, {3, 2}, {4, 2}, {5, 3}, {7, 3}, {8, 3}, {9, 4}, {16, 4}, {17, 5}, {63, 6}, {64, 6}, {65, 7}, {1L << 40, 40}, {(1L << 40) + 1, 41}};
        for (long[] c : cases) assertEquals((int) c[1], SafeRegex.ceilLog2(c[0]), "ceilLog2(" + c[0] + ")");
    }

    @Test
    void nullsAreRefused() {
        assertNull(SafeRegex.compile(null));
        assertFalse(SafeRegex.isSafeSource(null));
        assertNull(SafeRegex.fullMatch(null, "a"));
    }

    @Test
    void runRefusesExactlyAboveTheStepCap() {
        // "a*" compiles to 4 instructions: 4 * (n + 1) <= 2_000_000 runs, one more code unit refuses
        SafeRegex.Compiled star = SafeRegex.compile("a*");
        assertEquals(4, star.size());
        assertEquals(Boolean.TRUE, SafeRegex.run(star, "a".repeat(499_999)));
        assertNull(SafeRegex.run(star, "a".repeat(500_000)));
        assertEquals(Boolean.FALSE, SafeRegex.run(star, "a".repeat(499_998) + "b"));
        SafeRegex.Compiled a = SafeRegex.compile("a");
        assertEquals(2, a.size());
        assertEquals(Boolean.FALSE, SafeRegex.run(a, "a".repeat(999_999)));
        assertNull(SafeRegex.run(a, "a".repeat(1_000_000)));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("a", "a"));
        assertNull(SafeRegex.fullMatch("a*", "a".repeat(500_000)));
        // the product is computed in long: a 4096-instruction program against a huge subject must refuse, not overflow
        SafeRegex.Compiled big = SafeRegex.compile("a".repeat(4095));
        assertEquals(4096, big.size());
        assertNull(SafeRegex.run(big, "a".repeat(600_000)));
        assertNull(SafeRegex.run(big, "a".repeat(488))); // 4096 x 489 > 2_000_000
        assertEquals(Boolean.FALSE, SafeRegex.run(big, "a".repeat(487))); // 4096 x 488 <= 2_000_000
    }

    // ---- per-document budget ----

    private static void state(SafeRegex.Budget b, int ev, int chars, long steps, int refusals) {
        assertEquals(ev, b.evaluations, "evaluations");
        assertEquals(chars, b.chars, "chars");
        assertEquals(steps, b.steps, "steps");
        assertEquals(refusals, b.refusals, "refusals");
    }

    @Test
    void budgetRefusesAnUncompilablePatternWithoutChargingIt() {
        SafeRegex.Budget b = new SafeRegex.Budget();
        assertFalse(b.charge("(a", 5));
        state(b, 0, 0, 0, 1);
        assertTrue(b.charge("ab", 3)); // 3 instructions x 4
        state(b, 1, 2, 12, 1);
        assertFalse(b.charge("a{65}", 0));
        state(b, 1, 2, 12, 2);
        assertTrue(b.charge("a*", 0));
        state(b, 2, 4, 16, 2);
    }

    @Test
    void budgetEvaluationCapIs64ThenPoisoned() {
        SafeRegex.Budget b = new SafeRegex.Budget();
        for (int k = 1; k <= 64; k++) {
            assertTrue(b.charge("a", 1), "evaluation " + k);
            state(b, k, k, 4L * k, 0);
        }
        assertFalse(b.charge("a", 1));
        state(b, 65, 64, 256, 1);
        assertFalse(b.charge("b", 0)); // poisoned: later cheaper patterns are refused too
        state(b, 65, 64, 256, 2);
    }

    @Test
    void budgetSourceCharCapIs8192() {
        String big = "a".repeat(4095); // 4096 instructions, the largest program
        SafeRegex.Budget b = new SafeRegex.Budget();
        assertTrue(b.charge(big, 0));
        assertTrue(b.charge(big, 0));
        state(b, 2, 8190, 8192, 0);
        assertTrue(b.charge("ab", 0));
        state(b, 3, 8192, 8195, 0);
        assertFalse(b.charge("a", 0));
        state(b, 65, 8192, 8195, 1);
        assertFalse(b.charge("a", 0));
        state(b, 65, 8192, 8195, 2);

        SafeRegex.Budget c = new SafeRegex.Budget();
        assertTrue(c.charge(big, 0));
        assertTrue(c.charge(big, 0));
        assertFalse(c.charge("abc", 0)); // 8193
        state(c, 65, 8190, 8192, 1);
    }

    @Test
    void budgetStepCapIs5MillionComputedInLong() {
        SafeRegex.Budget b = new SafeRegex.Budget();
        assertTrue(b.charge("a", 2_499_999)); // 2 x 2_500_000 = 5_000_000 exactly
        state(b, 1, 1, 5_000_000L, 0);
        assertFalse(b.charge("a", 0));
        state(b, 65, 1, 5_000_000L, 1);

        SafeRegex.Budget c = new SafeRegex.Budget();
        assertFalse(c.charge("a", 2_500_000)); // 5_000_002
        state(c, 65, 0, 0, 1);

        SafeRegex.Budget d = new SafeRegex.Budget();
        assertFalse(d.charge("a".repeat(4095), Integer.MAX_VALUE - 1)); // 4096 x 2^31-1 overflows an int
        state(d, 65, 0, 0, 1);
        SafeRegex.Budget e = new SafeRegex.Budget();
        assertTrue(e.charge("ab", 1_666_665)); // 3 x 1_666_666 = 4_999_998
        assertTrue(e.charge("", 0)); // 1 instruction x 1 = 4_999_999
        state(e, 2, 2, 4_999_999L, 0);
        assertTrue(e.charge("", 0));
        state(e, 3, 2, 5_000_000L, 0);
        assertFalse(e.charge("", 0));
        state(e, 65, 2, 5_000_000L, 1);
    }

    @Test
    void chargeOutsideAScopeUsesAFreshBudgetEachTime() {
        for (int k = 0; k < 100; k++) assertTrue(SafeRegex.charge("a", 1), "unscoped charge " + k);
        assertFalse(SafeRegex.charge("(", 1));
        assertFalse(SafeRegex.charge("a", 2_500_000));
        assertTrue(SafeRegex.charge("a", 2_499_999));
    }

    @Test
    void withBudgetSharesOneBudgetAcrossNestedScopesAndClosesIt() {
        int[] seen = new int[3];
        String r = SafeRegex.withBudget(() -> {
            for (int k = 0; k < 60; k++) if (SafeRegex.charge("a", 1)) seen[0]++;
            SafeRegex.withBudget(() -> { // nested: joins the open document budget
                for (int k = 0; k < 4; k++) if (SafeRegex.charge("a", 1)) seen[1]++;
                return null;
            });
            if (SafeRegex.charge("a", 1)) seen[2]++;
            return "done";
        });
        assertEquals("done", r);
        assertArrayEquals(new int[] {60, 4, 0}, seen);
        assertTrue(SafeRegex.charge("a", 1), "the scope is closed afterwards");
        assertEquals(Integer.valueOf(7), SafeRegex.withBudget(() -> 7));
        // a throwing body still closes its scope
        assertThrows(IllegalStateException.class, () -> SafeRegex.withBudget(() -> {
            for (int k = 0; k < 70; k++) SafeRegex.charge("a", 1);
            throw new IllegalStateException("x");
        }));
        assertTrue(SafeRegex.charge("a", 1));
        // a fresh scope after a poisoned one starts at zero
        assertEquals(Boolean.TRUE, SafeRegex.withBudget(() -> {
            boolean all = true;
            for (int k = 0; k < 64; k++) all &= SafeRegex.charge("a", 1);
            return all && !SafeRegex.charge("a", 1);
        }));
    }
}
