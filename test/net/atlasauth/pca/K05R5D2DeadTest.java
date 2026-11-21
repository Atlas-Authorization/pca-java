package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import org.junit.jupiter.api.Test;

/**
 * 0.5 dead-minion kills (round 5, tag D2): every loop whose mutation made the run hang, fail with a run error or allocate without
 * bound is driven on a small input with a known result inside a preemptive bound, so the mutant fails by timeout or assertion while
 * the unmutated code finishes in milliseconds. Fixture-heavy sites reuse the existing kill tests (run here under the same bound).
 */
public class K05R5D2DeadTest {

    static final Duration BOUND = Duration.ofSeconds(5);
    static final Duration HEAVY = Duration.ofSeconds(60); // an existing fixture-heavy kill test, on a slow runner

    static void bounded(Runnable r) { assertTimeoutPreemptively(BOUND, r::run); }

    static void runMethod(Class<?> c, String name) {
        assertTimeoutPreemptively(HEAVY, () -> {
            try {
                Method m = c.getDeclaredMethod(name);
                m.setAccessible(true);
                m.invoke(c.getDeclaredConstructor().newInstance());
            } catch (InvocationTargetException e) {
                if (e.getCause() instanceof Exception) throw (Exception) e.getCause();
                if (e.getCause() instanceof Error) throw (Error) e.getCause();
                throw e;
            }
        });
    }

    /** Every parameterless {@code @Test} method of the class, each under the bound. */
    static void runAll(Class<?> c) {
        int ran = 0;
        for (Method m : c.getDeclaredMethods()) {
            if (m.getParameterCount() != 0 || !m.isAnnotationPresent(Test.class)) continue;
            runMethod(c, m.getName());
            ran++;
        }
        assertTrue(ran > 0, c.getName());
    }

    static Json.Num n(long v) { return IntentJs.ofLong(v); }
    static Map<String, Object> obj(Object... kv) { return MeshK05KillTest.obj(kv); }
    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    // ---- small direct loops ----

    @Test void caveatsAppendedByTheHopsAreCopied() {
        bounded(() -> {
            Map<String, Object> a = obj("type", "scope"), b = obj("type", "resource"), c = obj("type", "audience");
            Map<String, Object> grant = obj("caveats", list(a));
            Map<String, Object> leaf = obj("caveats", list(a, b, c));
            assertEquals(list(a, b, c), Caveats.policyCaveats(grant, list(leaf)));
            assertEquals(list(a), Caveats.policyCaveats(grant, list(obj("caveats", list(a)))));
            assertEquals(list(a), Caveats.policyCaveats(grant, list()));
        });
    }

    @Test void respondsWithinStates() {
        bounded(() -> {
            assertEquals(List.of("idle", "pending:1", "pending:2", "pending:3", "missed"), IntentAcc.monitorStates(obj("kind", "responds_within", "within", n(3))));
            assertEquals(List.of("idle", "missed"), IntentAcc.monitorStates(obj("kind", "responds_within", "within", n(0))));
            assertEquals(List.of("idle", "missed"), IntentAcc.monitorStates(obj("kind", "responds_within")));
            assertEquals(List.of("unmet", "met"), IntentAcc.monitorStates(obj("kind", "precedes")));
            assertEquals(List.of(), IntentAcc.monitorStates(obj("kind", "x")));
        });
    }

    @Test void mapCommitmentTreeSplitAndSizeEncoding() {
        bounded(() -> assertArrayEquals(new byte[] {0, 0, 0, 0, 0, 1, 0, 2}, IntentMap.u64be(65_538L)));
        bounded(() -> assertArrayEquals(new byte[] {(byte) 0xff, 0, 0, 0, 0, 0, 0, 1}, IntentMap.u64be(0xff00000000000001L)));
        runMethod(IntentMapKillTest.class, "commitmentMatchesTheReferenceShape");
        runMethod(IntentMapKillTest.class, "rootFromPathShape");
    }

    @Test void globMatching() {
        bounded(() -> {
            Object[][] rows = {
                {"a*b", "axxb", true}, {"a*b", "axxc", false}, {"*", "", true}, {"*", "abc", true}, {"a**b", "ab", true}, {"a?c", "abc", true}, {"a?c", "ac", false},
                {"\\*a", "*a", true}, {"\\*a", "xa", false}, {"a*", "a", true}, {"a*", "ab", true}, {"a*", "", false}, {"*a*b", "xaxab", true}, {"*ab", "aab", true},
                {"*ab", "aba", false}, {"", "", true}, {"", "a", false}, {"a*b*c", "aXbYc", true}, {"a*b*c", "aXbY", false}, {"**", "", true}, {"x*", "x", true},
                {"a\\?b", "a?b", true}, {"a\\?b", "axb", false}, {"*abc", "ababc", true},
            };
            for (Object[] r : rows) assertEquals(r[2], Predicates.globMatch((String) r[0], (String) r[1]), r[0] + " ~ " + r[1]);
            assertNull(Predicates.globMatch("\\", "x"));
            assertNull(Predicates.globMatch("a\\", "a"));
        });
    }

    @Test void percentDecodingAdvancesPastEveryByte() throws Exception {
        Method m = PcaJdbcStateStore.class.getDeclaredMethod("percentDecode", String.class);
        m.setAccessible(true);
        bounded(() -> {
            try {
                assertEquals("a b%zz%4", m.invoke(null, "a%20b%zz%4"));
                assertEquals("Ab", m.invoke(null, "%41%62"));
                assertEquals("", m.invoke(null, ""));
                assertEquals("%", m.invoke(null, "%"));
                assertEquals("%4", m.invoke(null, "%4"));
                assertEquals("a/b", m.invoke(null, "a%2Fb"));
            } catch (ReflectiveOperationException e) {
                throw new AssertionError(e);
            }
        });
    }

    @Test void stepUpBaseUrlDropsEveryTrailingSlash() throws Exception {
        Method m = Class.forName("net.atlasauth.pca.stepup.StepUpClient").getDeclaredMethod("base", String.class);
        m.setAccessible(true);
        bounded(() -> {
            try {
                assertEquals("https://h/a", m.invoke(null, "https://h/a///"));
                assertEquals("http://h", m.invoke(null, "http://h/"));
                assertEquals("http://h/x", m.invoke(null, "http://h/x"));
            } catch (ReflectiveOperationException e) {
                throw new AssertionError(e);
            }
        });
    }

    @Test void jsTrimAndStripTrailingNul() {
        bounded(() -> {
            assertEquals("a b", AttestCommon.jsTrim(" \t\n a b \u00a0\u3000"));
            assertEquals("", AttestCommon.jsTrim("  \u2003 "));
            assertEquals("", AttestCommon.jsTrim(""));
            assertEquals("x", AttestCommon.jsTrim("x"));
            assertEquals("ab", AttestNvidia.stripTrailingNul("ab\0\0"));
            assertEquals("", AttestNvidia.stripTrailingNul("\0"));
            assertEquals("a\0b", AttestNvidia.stripTrailingNul("a\0b\0"));
            assertEquals("ab", AttestNvidia.stripTrailingNul("ab"));
        });
    }

    @Test void bindingBytesWriteEveryEpochByte() {
        bounded(() -> {
            byte[] a = AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", 1, "n"));
            assertEquals(64, a.length);
            assertArrayEquals(a, AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", 1, "n")));
            assertNotEquals(Arrays.toString(a), Arrays.toString(AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", 2, "n"))));
            assertNotEquals(Arrays.toString(a), Arrays.toString(AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", 1L << 40, "n"))));
        });
        runMethod(AttestFoundationTest.class, "azureRuntimeDataBinding");
    }

    @Test void rawJsonObjectScansStringsAndSpaces() {
        bounded(() -> {
            assertEquals("{\"a\":1}", AttestIntelCollateral.rawJsonObject("  {  \"tcbInfo\"  :  {\"a\":1}, \"x\":2}", "tcbInfo"));
            assertEquals("{\"s\":\"}\\\"{\",\"b\":{}}", AttestIntelCollateral.rawJsonObject("{\"k\":{\"s\":\"}\\\"{\",\"b\":{}}}", "k"));
            assertNull(AttestIntelCollateral.rawJsonObject("{\"k\":{\"a\":", "k"));
            assertNull(AttestIntelCollateral.rawJsonObject("{\"other\":{}}", "k"));
            assertNull(AttestIntelCollateral.rawJsonObject("   ", "k"));
        });
    }

    @Test void utf8LengthStepsOverSurrogatePairs() {
        bounded(() -> {
            assertEquals(10, IntentJs.u8len("a\u00e9\u20ac\ud83d\ude00"));
            assertEquals(3, IntentJs.u8len("\ud83d"));
            assertEquals(8, IntentJs.u8len("\ud83d\ude00\ud83d\ude00"));
            assertEquals(7, IntentJs.u8len("\ud83d\ude00\ud83d"));
            assertEquals(0, IntentJs.u8len(""));
        });
    }

    @Test void approvalSurrogatesAndMinorUnits() throws Exception {
        Method lone = Approval.class.getDeclaredMethod("lone", String.class);
        lone.setAccessible(true);
        bounded(() -> {
            try {
                assertEquals(false, lone.invoke(null, "a\ud83d\ude00b"));
                assertEquals(false, lone.invoke(null, "\ud83d\ude00\ud83d\ude00"));
                assertEquals(true, lone.invoke(null, "\ud83d"));
                assertEquals(true, lone.invoke(null, "x\ude00"));
                assertEquals(true, lone.invoke(null, "\ud83d\ude00\ud83d"));
            } catch (ReflectiveOperationException e) {
                throw new AssertionError(e);
            }
            assertEquals("0.005", Approval.minorToDecimal(5, 3));
            assertEquals("123.45", Approval.minorToDecimal(12345, 2));
            assertEquals("0", Approval.minorToDecimal(0, 0));
            assertEquals("0.00", Approval.minorToDecimal(0, 2));
            assertEquals("1.00", Approval.minorToDecimal(100, 2));
            assertEquals("0.000000000000000007", Approval.minorToDecimal(7, 18));
            assertEquals("42", Approval.minorToDecimal(42, 0));
            assertEquals("9007199254740991", Approval.minorToDecimal(9007199254740991L, 0));
            assertThrows(RuntimeException.class, () -> Approval.minorToDecimal(-1, 2));
            assertThrows(RuntimeException.class, () -> Approval.minorToDecimal(1, 19));
            assertThrows(RuntimeException.class, () -> Approval.minorToDecimal(1, -1));
            assertThrows(RuntimeException.class, () -> Approval.minorToDecimal(9007199254740992L, 0));
        });
    }

    @Test void bindContextWalksEveryPrefix() {
        bounded(() -> {
            Map<String, Object> bound = obj("env", obj("x", "1"), "subject", obj("u", "alice"));
            Map<String, Object> supplied = obj("env", obj("a", obj("b", "2")), "subject", obj("u", "alice"));
            Map<String, Object> out = MissingContext.bindContext(bound, supplied, obj());
            assertNotNull(out.get("context"));
            assertEquals(List.of(), out.get("conflicts"));
            Map<?, ?> env = (Map<?, ?>) ((Map<?, ?>) out.get("context")).get("env");
            assertEquals("1", env.get("x"));
            assertEquals("2", ((Map<?, ?>) env.get("a")).get("b"));
            // a bound scalar blocks a deeper supplied path
            Map<String, Object> blocked = MissingContext.bindContext(obj("env", obj("a", "scalar")), obj("env", obj("a", obj("b", "2"))), obj());
            assertEquals(List.of("env.a.b"), blocked.get("conflicts"));
        });
        runAll(MissingContextRestKillTest.class);
    }

    @Test void obligationsOverdueAreListedOnMalformedInput() {
        bounded(() -> {
            Obligations.Outcome o = Obligations.outcome(list("x", "y"), list(), n(5));
            assertEquals("escalate", o.outcome);
            assertEquals("obligation_unmet", o.status);
            assertEquals(List.of(0, 1), o.overdue);
            assertEquals(List.of(), Obligations.outcome(list(), "x", n(5)).overdue);
            assertEquals(List.of(0, 1), Obligations.outcome(list("x", "y"), "x", n(5)).overdue);
        });
        runAll(ObligationsRestKillTest.class);
    }

    @Test void libraryCandidateSearchWalksUpToTheRoot() {
        bounded(() -> assertNotNull(LessNative.candidates()));
    }

    @Test void provenanceLabelsClipAndTokens() {
        bounded(() -> {
            assertEquals("-", ArgProvenance.clip(""));
            assertEquals("short", ArgProvenance.clip("short"));
            String clipped = ArgProvenance.clip("a".repeat(300));
            assertTrue(IntentJs.u8len(clipped) <= 256 && !clipped.isEmpty(), clipped.length() + "");
            assertEquals(150, clipped.length());
            String pairs = ArgProvenance.clip("\ud83d\ude00".repeat(200));
            assertTrue(IntentJs.u8len(pairs) <= 256);
            assertFalse(Json.hasLoneSurrogate(pairs));
            assertTrue(ArgProvenance.occursAsToken("a b c", "b"));
            assertFalse(ArgProvenance.occursAsToken("abab", "b"));
            assertTrue(ArgProvenance.occursAsToken("abab b", "b"));
            assertTrue(ArgProvenance.occursAsToken("xbx,b", "b"));
            assertFalse(ArgProvenance.occursAsToken("xbxbxb", "b"));
            assertTrue(ArgProvenance.occursAsToken("aaa bbb", "bbb"));
            assertFalse(ArgProvenance.occursAsToken("aaabbb", "bbb"));
            assertFalse(ArgProvenance.occursAsToken("", "b"));
            assertFalse(ArgProvenance.occursAsToken("b", ""));
            assertFalse(ArgProvenance.occursAsToken(null, "b"));
            assertTrue(ArgProvenance.occursAsToken("x,y", ",y"));
        });
        runAll(ArgProvenanceKillTest.class);
        runAll(ArgProvenanceRestKillTest.class);
    }

    @Test void evolutionSearchEndsAfterItsSteps() throws Exception {
        Method m = ActionRegistry.class.getDeclaredMethod("search", Map.class, String.class, String.class, boolean.class);
        m.setAccessible(true);
        bounded(() -> {
            try {
                Map<String, List<String[]>> edges = new LinkedHashMap<>();
                edges.put("a", List.of(new String[] {"b", null}, new String[] {"c", "x"}));
                edges.put("b", java.util.Collections.singletonList(new String[] {"d", null}));
                Map<?, ?> all = (Map<?, ?>) m.invoke(null, edges, "a", "d", false);
                assertEquals(3, all.size());
                Map<?, ?> usable = (Map<?, ?>) m.invoke(null, edges, "a", "d", true);
                assertEquals(2, usable.size());
                assertEquals(0, ((Map<?, ?>) m.invoke(null, new LinkedHashMap<String, List<String[]>>(), "a", "a", false)).size());
            } catch (ReflectiveOperationException e) {
                throw new AssertionError(e);
            }
        });
        runAll(ActionRegistryRestKillTest.class);
    }

    @Test void laplaceSamplerTerminates() {
        bounded(() -> {
            ReadVault.Draws d = ReadVault.seededDraws("seed-d2");
            long a = ReadVault.discreteLaplace(d, 1, 1);
            assertEquals(a, ReadVault.discreteLaplace(ReadVault.seededDraws("seed-d2"), 1, 1));
            for (int i = 0; i < 50; i++) assertTrue(Math.abs(ReadVault.discreteLaplace(d, 1, 3)) < 100_000);
            assertThrows(IllegalArgumentException.class, () -> ReadVault.discreteLaplace(ReadVault.seededDraws("s"), 0, 1));
        });
        runMethod(ReadVaultTest.class, "samplerStreams");
    }

    // ---- the race harness ----

    @Test void raceRunsExactlyOneThreadPerSlot() {
        bounded(() -> {
            try {
                Object[] r = StoreConformance.race(new CyclicBarrier(3), 3, i -> i * 2);
                assertArrayEquals(new Object[] {0, 2, 4}, r);
                assertEquals(1, StoreConformance.race(new CyclicBarrier(1), 1, i -> "x").length);
            } catch (InterruptedException e) {
                throw new AssertionError(e);
            }
        });
    }

    @Test void storeConformanceRounds() {
        runAll(StoreConformanceTest.class);
    }

    // ---- SQLite ----

    @Test void sqliteMainDatabaseMustBeAFile() throws Exception {
        Path dir = Files.createTempDirectory("pca-d2");
        bounded(() -> {
            try (Connection file = AuthorizeFixtures.sqliteConnection(dir.resolve("main.db"))) {
                PcaJdbcStateStore.requireSqliteFileDatabase(file);
            } catch (SQLException e) {
                throw new AssertionError(e);
            }
            try (Connection mem = DriverManager.getConnection("jdbc:sqlite::memory:")) {
                try (Statement st = mem.createStatement()) {
                    st.execute("ATTACH DATABASE '" + dir.resolve("other.db").toString().replace("'", "''") + "' AS other");
                }
                assertThrows(SQLException.class, () -> PcaJdbcStateStore.requireSqliteFileDatabase(mem));
            } catch (SQLException e) {
                throw new AssertionError(e);
            }
        });
    }

    @Test void compareAndSetGivesUpAfterItsAttempts() throws Exception {
        Path f = Files.createTempDirectory("pca-d2kv").resolve("kv.db");
        PcaJdbcAtomicKv kv = new PcaJdbcAtomicKv(() -> AuthorizeFixtures.sqliteConnection(f)).createTable();
        kv.set("a", "x");
        // every UPDATE is ignored by a trigger, so the compare-and-set can never win
        try (Connection c = AuthorizeFixtures.sqliteConnection(f); Statement st = c.createStatement()) {
            st.execute("CREATE TRIGGER ignore_update BEFORE UPDATE ON " + PcaJdbcAtomicKv.TABLE + " BEGIN SELECT RAISE(IGNORE); END");
        }
        int[] calls = {0};
        IllegalStateException e = assertTimeoutPreemptively(Duration.ofSeconds(30), () ->
            assertThrows(IllegalStateException.class, () -> kv.update("a", prev -> { calls[0]++; return "y"; })));
        assertEquals("kv store: compare-and-set kept losing (" + PcaJdbcAtomicKv.MAX_ATTEMPTS + " attempts)", e.getMessage());
        assertEquals(PcaJdbcAtomicKv.MAX_ATTEMPTS, calls[0]);
        assertEquals("x", kv.get("a"));
    }

    // ---- the Merkle helpers ----

    @Test void merkleSplitAndPathShape() {
        bounded(() -> {
            int[][] splits = {{1, 1}, {2, 1}, {3, 2}, {4, 2}, {5, 4}, {8, 4}, {9, 8}, {1000, 512}, {1025, 1024}};
            for (int[] s : splits) assertEquals(s[1], Pca.split(s[0]), "split " + s[0]);
            assertEquals(List.of(), Pca.pathShape(0, 1));
            assertEquals(List.of("R"), Pca.pathShape(0, 2));
            assertEquals(List.of("L"), Pca.pathShape(1, 2));
            assertEquals(List.of("R", "R"), Pca.pathShape(0, 3));
            assertEquals(List.of("L"), Pca.pathShape(2, 3));
            assertEquals(List.of("L"), Pca.pathShape(4, 5));
            assertEquals(List.of("L", "L", "R"), Pca.pathShape(3, 5));
            assertEquals(List.of("L", "L"), Pca.pathShape(6, 7));
            assertEquals(20, Pca.pathShape(0, 1_000_000).size());
            assertEquals(12, Pca.pathShape(999_999, 1_000_000).size());
            assertEquals(21, Pca.pathShape(0, (1 << 20) + 1).size());
            assertEquals(1, Pca.pathShape((1 << 20), (1 << 20) + 1).size());
            List<byte[]> hs = new ArrayList<>();
            for (int i = 0; i < 11; i++) hs.add(Pca.leafHash("leaf-" + i));
            for (int i = 0; i < 11; i++) assertEquals(Pca.pathShape(i, 11).size(), MeshK05KillTest.path(hs, i).size(), "index " + i);
        });
        runMethod(MeshK05KillTest.class, "leafBoundsAreChecked");
        runMethod(MeshK05KillTest.class, "consistencyOverEverySizePair");
        runMethod(MeshK05KillTest.class, "consistencyRefusesElementsPastTheNewRoot");
        runMethod(K05R5G2MeshTest.class, "validConsistencyProofsAreAccepted");
    }

    // ---- fixture-heavy sites: the existing kill tests under the bound ----

    @Test void intelQuoteWalks() {
        for (String t : new String[] {"sgxExtensionScanAccepts", "sgxExtensionComponentValues", "sgxExtensionWalksAtMost65Components", "pckChainOutcomes",
                "genuineQuoteWholeResult", "qeReportDataTailMustBeZero", "attestationKeyMustBeACurvePoint"}) runMethod(AttestIntelK05KillTest.class, t);
        for (String t : new String[] {"tcbLevelsMissing", "tdxComponentsFromZeroForMinorZero", "moduleIdentityPathSkipsTheFirstTwoTdxComponents", "tcbLevelRefusals", "everyComponentIsCompared"})
            runMethod(AttestIntelCollateralK05KillTest.class, t);
    }

    @Test void derAndSnpAndOcspWalks() {
        runAll(AttestCommonDerK05KillTest.class);
        runAll(AttestAmdK05KillTest.class);
        runAll(AttestNvidiaOcspKillTest.class);
        runAll(AttestNvidiaOcspK05bKillTest.class);
    }

    @Test void provenanceGateInclusionAndActionProofs() {
        runAll(ProvGateRestKillTest.class);
        runMethod(ActionVectorsTest.class, "pinnedDigests");
    }
}
