package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Boundary kills for SafeRegex parser / char-set internals that the TS-differential corpus does not reach. */
class K042SafeRegexGapTest {
    private static Boolean fm(String p, String s) { return SafeRegex.fullMatch(p, s); }

    @Test void binarySearchOverManyRanges() {
        // 40 disjoint ranges {4k, 4k+1}; every code unit in [0, 170] is classified exactly
        List<int[]> in = new ArrayList<>();
        for (int k = 0; k < 40; k++) in.add(new int[] {4 * k, 4 * k + 1});
        int[][] rs = SafeRegex.normalize(in);
        SafeRegex.CharSet pos = new SafeRegex.CharSet(rs, false), neg = new SafeRegex.CharSet(rs, true);
        for (int c = 0; c <= 170; c++) {
            boolean inside = c < 160 && c % 4 < 2;
            assertEquals(inside, pos.has(c), "has " + c);
            assertEquals(!inside, neg.has(c), "negated has " + c);
        }
        // a few ranges: first, last, and just outside either end
        SafeRegex.CharSet three = new SafeRegex.CharSet(new int[][] {{10, 12}, {20, 22}, {30, 32}}, false);
        for (int c : new int[] {9, 10, 12, 13, 19, 20, 22, 23, 29, 30, 32, 33}) assertEquals(Arrays.asList(10, 11, 12, 20, 21, 22, 30, 31, 32).contains(c), three.has(c), "three " + c);
    }

    @Test void complementReachesTheLastCodeUnit() {
        assertEquals(Arrays.deepToString(new int[][] {{0xffff, 0xffff}}), Arrays.deepToString(SafeRegex.complement(new int[][] {{0, 0xfffe}})));
        assertEquals(Arrays.deepToString(new int[][] {}), Arrays.deepToString(SafeRegex.complement(new int[][] {{0, 0xffff}})));
        assertEquals(Arrays.deepToString(new int[][] {{0, 0xfffd}}), Arrays.deepToString(SafeRegex.complement(new int[][] {{0xfffe, 0xffff}})));
        assertEquals(Boolean.TRUE, fm("[\\D]", "\uffff"));
        assertEquals(Boolean.TRUE, fm("[\\W]", "\uffff"));
    }

    @Test void nulCharactersAreOrdinary() {
        assertEquals(Boolean.TRUE, fm("\\\u0000", "\u0000"));          // backslash + NUL is an identity escape
        assertEquals(Boolean.TRUE, fm("[\u0000]", "\u0000"));          // NUL inside a class
        assertEquals(Boolean.FALSE, fm("[\u0000]", "a"));
        assertEquals(Boolean.TRUE, fm("[\u0000-\u0001]", "\u0001"));
        assertEquals(Boolean.FALSE, fm("[\u0000-\u0001]", "-"));
        assertEquals(Boolean.TRUE, fm("[\u0000-\u0000]", "\u0000"));   // a range ending in NUL is a range
        assertEquals(Boolean.FALSE, fm("[\u0000-\u0000]", "-"));
        assertNull(SafeRegex.compile("[a-\u0000]"));                   // ... and out of order
        assertEquals(Boolean.TRUE, fm("[\\0-\\x01]", "\u0001"));
    }

    @Test void classDashHandlingAtEveryOffset() {
        for (int pad = 0; pad < 140; pad++) {
            String p = "a".repeat(pad);
            assertEquals(Boolean.TRUE, fm(p + "[a-c]", p + "b"), "range pad " + pad);
            assertEquals(Boolean.FALSE, fm(p + "[a-c]", p + "-"), "range dash pad " + pad);
            assertEquals(Boolean.TRUE, fm(p + "[a-]", p + "-"), "trailing dash pad " + pad);
            assertEquals(Boolean.FALSE, fm(p + "[a-]", p + "b"), "trailing dash pad " + pad);
        }
        // an escaped ']' before a dash still starts a range
        assertEquals(Boolean.TRUE, fm("[\\]-a]", "^"));
        assertEquals(Boolean.FALSE, fm("[\\]-a]", "-"));
        assertEquals(Boolean.TRUE, fm("[\\]-a]", "a"));
        assertNull(SafeRegex.compile("[a-"));
        assertNull(SafeRegex.compile("[a-b"));
        // class escapes around a dash are literal members
        assertEquals(Boolean.TRUE, fm("[\\d-x]", "-"));
        assertEquals(Boolean.TRUE, fm("[\\d-x]", "x"));
        assertEquals(Boolean.TRUE, fm("[\\d-x]", "5"));
        assertEquals(Boolean.FALSE, fm("[\\d-x]", "w"));
        assertEquals(Boolean.TRUE, fm("[a-\\d]", "-"));
        assertEquals(Boolean.TRUE, fm("[a-\\d]", "7"));
        assertEquals(Boolean.FALSE, fm("[a-\\d]", "b"));
    }

    @Test void hexEscapesRejectSignsAndNonAsciiDigits() {
        for (String p : new String[] {"\\x+1", "\\x-1", "\\x1+", "\\u+001", "\\u-001", "\\u001-", "\\u00+1", "\\x\uff11\uff11", "\\u\u0661\u0661\u0661\u0661", "\\x 1", "\\x1 "})
            assertNull(SafeRegex.compile(p), p);
        assertNull(SafeRegex.compile("\\x"));
        assertNull(SafeRegex.compile("\\x4"));
        assertNull(SafeRegex.compile("\\u123"));
        assertEquals(Boolean.TRUE, fm("\\x41", "A"));
        assertEquals(Boolean.TRUE, fm("\\x4a", "J"));
        assertEquals(Boolean.TRUE, fm("\\u0041", "A"));
        assertEquals(Boolean.TRUE, fm("a\\x41", "aA"));
        assertEquals(Boolean.TRUE, fm("\\u00e9", "\u00e9"));
    }

    @Test void escapeSetsAreExact() {
        // every class escape against its exact definition, over the whole BMP
        for (int c = 0; c <= 0xffff; c++) {
            String s = String.valueOf((char) c);
            boolean d = c >= '0' && c <= '9';
            boolean w = d || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
            boolean sp = (c >= 9 && c <= 13) || c == 32 || c == 0xa0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029
                || c == 0x202f || c == 0x205f || c == 0x3000 || c == 0xfeff;
            assertEquals(d, SafeRegex.run(DIG, s), "\\d " + c);
            assertEquals(!d, SafeRegex.run(NDIG, s), "\\D " + c);
            assertEquals(w, SafeRegex.run(WRD, s), "\\w " + c);
            assertEquals(!w, SafeRegex.run(NWRD, s), "\\W " + c);
            assertEquals(sp, SafeRegex.run(SPC, s), "\\s " + c);
            assertEquals(!sp, SafeRegex.run(NSPC, s), "\\S " + c);
            // inside a class, complemented sets are materialized via complement()
            assertEquals(d, SafeRegex.run(CDIG, s), "[\\d] " + c);
            assertEquals(!d, SafeRegex.run(CNDIG, s), "[\\D] " + c);
            assertEquals(!w, SafeRegex.run(CNWRD, s), "[\\W] " + c);
            assertEquals(!sp, SafeRegex.run(CNSPC, s), "[\\S] " + c);
            assertEquals(c != 10 && c != 13 && c != 0x2028 && c != 0x2029, SafeRegex.run(DOT, s), ". " + c);
        }
    }
    private static final SafeRegex.Compiled DIG = SafeRegex.compile("\\d"), NDIG = SafeRegex.compile("\\D"), WRD = SafeRegex.compile("\\w"), NWRD = SafeRegex.compile("\\W"),
        SPC = SafeRegex.compile("\\s"), NSPC = SafeRegex.compile("\\S"), CDIG = SafeRegex.compile("[\\d]"), CNDIG = SafeRegex.compile("[\\D]"),
        CNWRD = SafeRegex.compile("[\\W]"), CNSPC = SafeRegex.compile("[\\S]"), DOT = SafeRegex.compile(".");

    @Test void identityEscapesAndControlEscapes() {
        for (char c : "@[`{:/!\"#%&',-;<=>~ ^$.*+?()[]{}|\\/".toCharArray()) assertEquals(Boolean.TRUE, fm("\\" + c, String.valueOf(c)), "\\" + c);
        for (char c : "AZaz09_BDSWdswkKpPuxcb".toCharArray()) {
            if ("dswDSWxuc0".indexOf(c) >= 0) continue;
            assertNull(SafeRegex.compile("\\" + c), "\\" + c);
        }
        assertNull(SafeRegex.compile("\\9"));
        assertNull(SafeRegex.compile("\\1"));
        assertNull(SafeRegex.compile("\\00"));
        assertNull(SafeRegex.compile("\\01"));
        assertEquals(Boolean.TRUE, fm("\\0", "\u0000"));
        assertEquals(Boolean.TRUE, fm("\\0a", "\u0000a"));
        assertEquals(Boolean.TRUE, fm("\\ca", "\u0001"));
        assertEquals(Boolean.TRUE, fm("\\cA", "\u0001"));
        assertEquals(Boolean.TRUE, fm("\\cz", "\u001a"));
        assertEquals(Boolean.TRUE, fm("\\cZ", "\u001a"));
        assertNull(SafeRegex.compile("\\c1"));
        assertNull(SafeRegex.compile("\\c@"));
        assertNull(SafeRegex.compile("\\c["));
        assertNull(SafeRegex.compile("\\c`"));
        assertNull(SafeRegex.compile("\\c{"));
        assertNull(SafeRegex.compile("\\c"));
        assertEquals(Boolean.TRUE, fm("[\\b]", "\b"));
        assertNull(SafeRegex.compile("\\b"));
        assertNull(SafeRegex.compile("a\\"));
        for (String[] e : new String[][] {{"\\t", "\t"}, {"\\n", "\n"}, {"\\v", "\u000b"}, {"\\f", "\f"}, {"\\r", "\r"}}) assertEquals(Boolean.TRUE, fm(e[0], e[1]), e[0]);
    }

    @Test void quantifierWindow() {
        assertEquals(Boolean.TRUE, fm("a{1234,5678}".replace("1234", "0").replace("5678", "2"), "aa"));
        assertNull(SafeRegex.compile("a{12345}"));
        assertNull(SafeRegex.compile("a{1,12345}"));
        assertNull(SafeRegex.compile("a{1234,5678}"));   // repeat bound too large (> 1000)? parsed fine, refused for size
        assertNull(SafeRegex.compile("a{2,1}"));
        assertNull(SafeRegex.compile("a{,2}"));
        assertNull(SafeRegex.compile("a{1,2"));
        assertNull(SafeRegex.compile("a{"));
        assertNull(SafeRegex.compile("{1}"));
        assertEquals(Boolean.TRUE, fm("a{2,}", "aaaa"));
        assertEquals(Boolean.FALSE, fm("a{2,}", "a"));
        assertEquals(Boolean.TRUE, fm("a{2}", "aa"));
        assertEquals(Boolean.FALSE, fm("a{2}", "aaa"));
        assertEquals(Boolean.TRUE, fm("a{0,2}?", "aa"));
    }

    @Test void alternationOfOneAndMany() {
        assertEquals(Boolean.TRUE, fm("a|b", "b"));
        assertEquals(Boolean.TRUE, fm("a|b|c", "c"));
        assertEquals(Boolean.FALSE, fm("a|b|c", "d"));
        assertEquals(Boolean.TRUE, fm("(?:ab|cd)e", "cde"));
        assertEquals(Boolean.TRUE, fm("|a", ""));
        assertEquals(Boolean.TRUE, fm("a|", ""));
        assertEquals(Boolean.TRUE, fm("", ""));
        assertEquals(Boolean.FALSE, fm("", "a"));
    }

    @Test void stepCapBoundaryIsExact() {
        SafeRegex.Compiled two = SafeRegex.compile("a");   // 2 instructions
        SafeRegex.Compiled three = SafeRegex.compile("ab"); // 3 instructions
        assertEquals(2, two.size());
        assertEquals(3, three.size());
        assertNotNull(SafeRegex.run(two, "a".repeat(999_999)));          // 2 * 1_000_000 = 2_000_000: allowed
        assertNull(SafeRegex.run(two, "a".repeat(1_000_000)));           // 2_000_002: refused
        assertNotNull(SafeRegex.run(three, "a".repeat(666_665)));        // 3 * 666_666 = 1_999_998
        assertNull(SafeRegex.run(three, "a".repeat(666_666)));           // 3 * 666_667 = 2_000_001: refused (one past the cap)
    }

    @Test void guardScansEscapedBracketsAndLazyQuantifiers() {
        assertTrue(SafeRegex.isSafeSource("(?:[\\]|])+"));              // an escaped ] does not end the class: the | is class content
        assertTrue(SafeRegex.isSafeSource("(?:[\\]a|b])+"));
        assertFalse(SafeRegex.isSafeSource("(?:[a]|b)+"));
        assertTrue(SafeRegex.isSafeSource("a*b*a{0,63}?"));              // 16 + 6 = 22 bits: a lazy marker after braces costs nothing
        assertFalse(SafeRegex.isSafeSource("a*b*a{0,63}??"));
        assertFalse(SafeRegex.isSafeSource("a*b*a{0,63}c?"));            // 23
        assertTrue(SafeRegex.isSafeSource("a*b*a{0,62}?"));
        assertTrue(SafeRegex.isSafeSource("a{1,2}?b{1,2}?"));
    }
}
