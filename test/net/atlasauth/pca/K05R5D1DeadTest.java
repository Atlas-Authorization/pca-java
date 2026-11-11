package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.5 dead-minion kills (round 5, tag D1): every loop whose mutation made the run hang or allocate without bound is exercised on a
 * small input whose correct result is asserted, inside a preemptive 5 s bound, so the mutant fails by assertion or timeout while the
 * unmutated code finishes in milliseconds.
 */
public class K05R5D1DeadTest {

    static final Duration BOUND = Duration.ofSeconds(5);

    static void bounded(Runnable r) { assertTimeoutPreemptively(BOUND, r::run); }

    // ---- SafeRegex: parser, compiler, matcher, guard ----

    static void match(String src, String subject, boolean want) {
        assertEquals(Boolean.valueOf(want), SafeRegex.fullMatch(src, subject), src + " vs " + subject);
    }

    @Test void regexParserAcceptsEveryConstruct() {
        bounded(() -> {
            match("a|b|c", "b", true);
            match("a|b|c", "d", false);
            match("a|b|c", "", false);
            match("(?:ab)+c", "ababc", true);
            match("(?:ab)+c", "c", false);
            match("(ab)*", "abab", true);
            match("(ab)*", "aba", false);
            match("x(a|b)y", "xby", true);
            match("[a-c\\d]+", "b1c2", true);
            match("[a-c\\d]+", "d", false);
            match("[^a-c]", "d", true);
            match("[^a-c]", "b", false);
            match("[abc]", "c", true);
            match("[a-]", "-", true);
            match("[\\w-z]", "-", true);
            match("[\\b]", "\b", true);
            match("a{2,3}", "aaa", true);
            match("a{2,3}", "aaaa", false);
            match("a{2,3}", "a", false);
            match("a{2}", "aa", true);
            match("a{2,}", "aaaaa", true);
            match("a*?b", "aab", true);
            match("a+?b", "b", false);
            match("a??b", "ab", true);
            match("a?", "", true);
            match("a*", "", true);
            match("a+", "", false);
            match(".x", "ax", true);
            match(".", "\n", false);
            match("^a$", "a", true);
            match("\\x41\\u0042", "AB", true);
            match("\\cJ", "\n", true);
            match("\\0", "\u0000", true);
            match("\\t\\n\\v\\f\\r", "\t\n\u000b\f\r", true);
            match("\\d\\D\\w\\W\\s\\S", "1a_ \tx", true);
            match("\\.\\*\\/", ".*/", true);
            match("", "", true);
            match("abc", "abc", true);
            match("abc", "abd", false);
            match("(?:a|b)(?:c|d)", "bd", true);
        });
    }

    @Test void regexRefusals() {
        bounded(() -> {
            for (String bad : new String[] {"(?=a)", "(?<n>a)", "a{", "a{x}", "*", "+a", "?", "a{3,2}", "a{65}", "a{1,65}", "[a", "[b-a]", "(a", "a)", "\\",
                    "\\x4", "\\u00", "\\1", "\\b", "^*", "$+", "\\08", "\\c1", "\\q", "{", "[\\d-a]x)"}) {
                assertNull(SafeRegex.compile(bad), bad);
            }
            assertNull(SafeRegex.compile(null));
            assertNull(SafeRegex.fullMatch("(", "a"));
            assertTrue(SafeRegex.compile("a{2}") != null);
        });
    }

    @Test void charSetBinarySearch() {
        bounded(() -> {
            SafeRegex.CharSet cs = new SafeRegex.CharSet(new int[][] {{1, 3}, {10, 12}, {20, 30}, {50, 50}}, false);
            for (int c : new int[] {1, 2, 3, 10, 11, 12, 20, 25, 30, 50}) assertTrue(cs.has(c), "in " + c);
            for (int c : new int[] {0, 4, 9, 13, 19, 31, 49, 51, 1000}) assertFalse(cs.has(c), "out " + c);
            SafeRegex.CharSet neg = new SafeRegex.CharSet(new int[][] {{1, 3}, {10, 12}}, true);
            assertFalse(neg.has(2));
            assertTrue(neg.has(5));
            assertTrue(neg.has(100));
            assertTrue(new SafeRegex.CharSet(new int[0][], false).has(1) == false);
            assertTrue(new SafeRegex.CharSet(new int[0][], true).has(1));
        });
    }

    @Test void safeSourceGuardWalksEveryToken() {
        bounded(() -> {
            for (String ok : new String[] {"a(?:b|c)d", "[a-c\\]x]+", "(a)(?:b)*", "a{2,3}b?", "a|b|c", "\\d+\\.\\d{1,2}", "(ab)", "[^a]x", "a*?b", "abc",
                    "x{2}y{3,}", "[\\\\]a", "((a))", "(?:(?:a))"}) {
                assertTrue(SafeRegex.isSafeSource(ok), ok);
            }
            for (String bad : new String[] {"(a|b)*", "(a*)+", "(a", "a)", "a**", "[a", "\\", "\\1", "\\k", "(?=a)", "(?a)", "*a", "a{", "a{3,2}", "a{65}", "(?:a|b){2}", "{2}"}) {
                assertFalse(SafeRegex.isSafeSource(bad), bad);
            }
            assertFalse(SafeRegex.isSafeSource(null));
            // the 22-bit cost budget: 22 alternations fit, 23 do not
            String alt22 = "a" + "|a".repeat(22), alt23 = "a" + "|a".repeat(23);
            assertTrue(SafeRegex.isSafeSource(alt22));
            assertFalse(SafeRegex.isSafeSource(alt23));
        });
    }

    // ---- Ledger.consistency ----

    @Test void ledgerConsistencyOverEverySizePair() {
        bounded(() -> {
            String stranger = Pca.b64(Pca.leafHash("stranger"));
            for (int first = 0; first <= 20; first++) {
                for (int second = first; second <= 22; second++) {
                    String oldRoot = first == 0 ? Ledger.EMPTY_TREE_ROOT : MeshK05KillTest.logRoot(first);
                    String newRoot = second == 0 ? Ledger.EMPTY_TREE_ROOT : MeshK05KillTest.logRoot(second);
                    List<Object> path = MeshK05KillTest.consistencyPath(first, second);
                    String at = first + "->" + second;
                    assertTrue(Ledger.verifyLedgerConsistency(oldRoot, newRoot, proof(first, second, path)), at);
                    if (first > 0 && second > first) {
                        assertFalse(Ledger.verifyLedgerConsistency(oldRoot, stranger, proof(first, second, path)), at + " other new root");
                        assertFalse(Ledger.verifyLedgerConsistency(stranger, newRoot, proof(first, second, path)), at + " other old root");
                        List<Object> longer = new ArrayList<>(path);
                        longer.add(Pca.b64(MeshK05KillTest.LOG.get(0)));
                        assertFalse(Ledger.verifyLedgerConsistency(oldRoot, newRoot, proof(first, second, longer)), at + " longer");
                        if (!path.isEmpty()) assertFalse(Ledger.verifyLedgerConsistency(oldRoot, newRoot, proof(first, second, path.subList(0, path.size() - 1))), at + " shorter");
                    }
                }
            }
            assertFalse(Ledger.verifyLedgerConsistency(Ledger.EMPTY_TREE_ROOT, MeshK05KillTest.logRoot(3), proof(0, 3, MeshK05KillTest.consistencyPath(1, 3))));
            assertFalse(Ledger.verifyLedgerConsistency(MeshK05KillTest.logRoot(3), MeshK05KillTest.logRoot(2), proof(3, 2, List.of())));
        });
    }

    static Map<String, Object> proof(long a, long b, List<?> path) {
        return MeshK05KillTest.obj("oldSize", IntentJs.ofLong(a), "newSize", IntentJs.ofLong(b), "path", new ArrayList<Object>(path));
    }

    // ---- AttestXml.parseXml ----

    static final String XML = "<?xml version=\"1.0\"?>\n<!DOCTYPE r [<!ELEMENT r ANY>]>\n<!-- c -->\n"
        + "<r xmlns=\"urn:a\" xmlns:p='urn:p' a='1' b=\"2\"> t1 <p:c d=\"3\"/><![CDATA[cd]]><e x = '7' >x</e ></r>\n";

    @Test void xmlParserReadsEveryTokenKind() {
        bounded(() -> {
            AttestXml.Doc doc = AttestXml.parseXml(XML);
            assertEquals("XML processing instructions are not permitted", doc.violation);
            AttestXml.Node r = doc.root;
            assertEquals("r", r.name);
            assertEquals("1", r.attr("a"));
            assertEquals("2", r.attr("b"));
            assertEquals(2, r.elementChildren().size());
            assertEquals("p:c", r.elementChildren().get(0).name);
            assertEquals("3", r.elementChildren().get(0).attr("d"));
            assertEquals("e", r.elementChildren().get(1).name);
            assertEquals("7", r.elementChildren().get(1).attr("x"));
            assertEquals(" t1 cdx", r.textContent());
            Map<String, String> scope = r.elementChildren().get(0).scope();
            assertEquals("urn:p", scope.get("p"));
            assertEquals("urn:a", scope.get(""));
            assertEquals(2, scope.size());
            AttestXml.Doc small = AttestXml.parseXml("<a><b><c/></b></a>");
            assertEquals("", small.violation);
            assertEquals(1, small.root.descendantsNs("", "c"));
            small.root.removeChild(small.root.elementChildren().get(0));
            assertEquals(0, small.root.elementChildren().size());
            assertEquals("DTD / DOCTYPE is not permitted", AttestXml.parseXml("<!DOCTYPE a [<!ENTITY x \"y\">]><a/>").violation);
            assertEquals("XML comments are not permitted", AttestXml.parseXml("<a><!--x--></a>").violation);
        });
    }

    @Test void xmlParserRefusesMalformedDocuments() {
        bounded(() -> {
            for (String bad : new String[] {"<a>", "<a></b>", "<a b=1/>", "<a b='x' b='y'/>", "text", "<a/><b/>", "</a>", "<a b>", "<a", "<>", "<a b='x/>",
                    "<a b='<'/>", "<!-- x", "<?x", "<a><![CDATA[x</a>", "<![CDATA[x]]>", "<!DOCTYPE a", "<a/>x", "", "<p:a/>", "<a / >"}) {
                assertThrows(AttestException.class, () -> AttestXml.parseXml(bad), bad);
            }
        });
    }

    // ---- AttestV8Json.v8JsonError ----

    @Test void v8JsonGrammarOverEveryRow() {
        bounded(() -> {
            for (String[] r : AttestV8JsonKillTest.ROWS) assertEquals(r[1], AttestV8Json.v8JsonError(r[0]), r[0]);
            for (String ok : new String[] {" {\"a\":[1,-2.5e+3,0,10,true,false,null,\"s\\n\\u00e9\\\\\\/\"],\"b\":{},\"c\":[]} ", "[1,2,3]", "0", "-0.5E-2", "\"x\"", "  7  ", "[[],[[]]]",
                    "{\"a\":{\"b\":{\"c\":1}}}", "\"\\u0041\\uD83D\""}) {
                assertEquals("", AttestV8Json.v8JsonError(ok), ok);
            }
            for (String bad : new String[] {"[1,x", "{\"a\" 1}", "[1 2]", "01", "1.", "1e", "-", "\"abc", "\"a\\q\"", "\"a\\u00g0\"", "tru", "nul", "{", "[", "{\"a\":1,}", "[1,]", "1 2",
                    "\"\\u12\"", "[\"a\u0001\"]", "{1:2}", "-x", "1.e5", "1e+"}) {
                String m = AttestV8Json.v8JsonError(bad);
                assertTrue(!m.isEmpty(), bad);
            }
        });
    }

    // ---- Json parser and helpers ----

    @Test void jsonParserReadsNumbersStringsAndWhitespace() {
        bounded(() -> {
            String text = " \t\r\n{ \"a\" : [ 1 , -2.5e+3 , 0 , 10 , 0.5 , -0 , 123456789012 , 1E5 ] , \"b\" : null , \"c\" : true , \"d\" : \"x\\n\\u00e9\\ud83d\\ude00\\/\\\\\" } \n ";
            @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) Json.parseLenient(text);
            @SuppressWarnings("unchecked") List<Object> a = (List<Object>) m.get("a");
            String[] raws = {"1", "-2.5e+3", "0", "10", "0.5", "-0", "123456789012", "1E5"};
            assertEquals(raws.length, a.size());
            for (int k = 0; k < raws.length; k++) assertEquals(raws[k], ((Json.Num) a.get(k)).raw);
            assertNull(m.get("b"));
            assertEquals(Boolean.TRUE, m.get("c"));
            assertEquals("x\n\u00e9\ud83d\ude00/\\", m.get("d"));
            assertEquals("12", ((Json.Num) Json.parse("12")).raw);
            assertEquals("-3.25", ((Json.Num) Json.parse(" -3.25 ")).raw);
            assertEquals("0", ((Json.Num) Json.parse("0")).raw);
            assertEquals("abc", Json.parse("\"abc\""));
            assertEquals("", Json.parse("\"\""));
            for (String bad : new String[] {"-", "1.", "1e", "1e+", "01", "-x", "+1", ".5", "\"abc", "\"a\\q\"", "\"a\u0001\"", "\"\\u12\"", "\"\\u12g4\"", "[1,", "{\"a\"}", "tru", "1 2", ""}) {
                assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), bad);
            }
        });
    }

    @Test void jsonUnicodeEscapesAcceptOnlyAsciiHexDigits() {
        bounded(() -> {
            assertEquals("A", Json.parse("\"\\u0041\""));
            assertEquals("\u00ff", Json.parse("\"\\u00ff\""));
            assertEquals("\u00ff", Json.parse("\"\\u00FF\""));
            assertEquals("\u0f9a", Json.parse("\"\\u0f9A\""));
            assertEquals("\u1000", Json.parse("\"\\u1000\""));
            assertEquals("\u9a5f", Json.parse("\"\\u9a5F\""));
            assertEquals("\u0000", Json.parse("\"\\u0000\""));
            assertEquals("\u0123\u4567", Json.parse("\"\\u0123\\u4567\""));
            assertEquals("\u89ab", Json.parse("\"\\u89ab\""));
            assertEquals("\ucdef", Json.parse("\"\\uCDEF\""));
            // the characters next to the digit ranges, and non-ASCII digits that Character.digit would accept
            for (String c : new String[] {"/", ":", "`", "g", "@", "G", "\uFF11", "\u0661", "\uFF21"}) {
                String bad = "\"\\u00" + c + "0\"";
                assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), bad);
                String bad2 = "\"\\u000" + c + "\"";
                assertThrows(IllegalArgumentException.class, () -> Json.parse(bad2), bad2);
            }
            assertThrows(IllegalArgumentException.class, () -> Json.parse("\"\\u123"));
            assertThrows(IllegalArgumentException.class, () -> Json.parse("\"\\u12\""));
        });
    }

    @Test void loneSurrogateScanAdvancesPastPairs() {
        bounded(() -> {
            assertFalse(Json.hasLoneSurrogate("a\uD83D\uDE00b"));
            assertFalse(Json.hasLoneSurrogate("\uD83D\uDE00\uD83D\uDE00"));
            assertFalse(Json.hasLoneSurrogate(""));
            assertTrue(Json.hasLoneSurrogate("a\uD83Db"));
            assertTrue(Json.hasLoneSurrogate("\uDE00"));
            assertTrue(Json.hasLoneSurrogate("\uD83D"));
            assertTrue(Json.hasLoneSurrogate("\uD83D\uDE00\uD83D"));
            assertTrue(Json.hasLoneSurrogate("\uDE00\uD83D\uDE00"));
        });
    }

    @Test void shortestDigitsLoopAdvancesThePrecision() {
        bounded(() -> {
            assertEquals("1.5", Json.shortest(1.5d).toPlainString());
            assertEquals("0.3", Json.shortest(0.3d).toPlainString());
            assertEquals("123.456", Json.shortest(123.456d).toPlainString());
            assertEquals("0.1", Json.shortest(0.1d).toPlainString());
            assertEquals("3.141592653589793", Json.shortest(Math.PI).toPlainString());
            assertEquals("100", Json.shortest(100d).toPlainString());
            assertEquals("2", Json.shortest(2d).toPlainString());
        });
    }
}
