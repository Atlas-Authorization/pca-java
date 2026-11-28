package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The durable state store's data and recovery side, pinned file by file: the exact journal / head / fence / lock bytes it writes,
 * every shape and chain check of load, corruption quarantine, operator recovery (holder classification, the cut, the fence, the
 * release) and the in-memory store.
 */
@Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class DurableStateRecoveryTest {
    private static final String G0 = DurableState.GENESIS;
    private static final String HEX = "ab".repeat(32);
    private static final String HEX2 = "cd".repeat(32);
    private static final long TS = 1000L;
    private static final long PID = ProcessHandle.current().pid();
    private static final long DEAD = 999_999_999L;
    private static final String HOST = DurableState.hostname();
    private static final String FOREIGN = "elsewhere.invalid";
    private static final byte[] KEY = new byte[32];

    static {
        for (int i = 0; i < KEY.length; i++) KEY[i] = (byte) (i + 1);
    }

    private final List<File> dirs = new ArrayList<>();

    @AfterEach void cleanUp() { for (File d : dirs) deleteTree(d); }

    // ---- helpers ----

    private static void deleteTree(File f) {
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteTree(k);
        f.delete();
    }

    private File tmp() throws IOException {
        File d = Files.createTempDirectory("pca-ds-rec-").toFile();
        dirs.add(d);
        return d;
    }

    private static void write(File d, String name, String text) throws IOException { Files.write(new File(d, name).toPath(), text.getBytes(StandardCharsets.UTF_8)); }

    private static String read(File d, String name) throws IOException { return new String(Files.readAllBytes(new File(d, name).toPath()), StandardCharsets.UTF_8); }

    private static boolean exists(File d, String name) { return new File(d, name).exists(); }

    private static List<String> names(File d) {
        String[] l = d.list();
        List<String> out = new ArrayList<>(Arrays.asList(l == null ? new String[0] : l));
        Collections.sort(out);
        return out;
    }

    private static List<String> matching(File d, String regex) {
        List<String> out = new ArrayList<>();
        for (String n : names(d)) if (n.matches(regex)) out.add(n);
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(String text) { return (Map<String, Object>) Json.parseLenient(text); }

    private static long num(Object o) { return IntentJs.lng(o); }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    private static String sha(String s) throws Exception { return hex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8))); }

    private static String hmac(String msg) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
        return hex(mac.doFinal(msg.getBytes(StandardCharsets.UTF_8)));
    }

    private static final class R {
        final long seq; final String h; final String line;

        R(long seq, String h, String line) { this.seq = seq; this.h = h; this.line = line; }
    }

    /** A journal record exactly as the store writes it (ts fixed at {@link #TS}). */
    private static R rec(long seq, String prev, String op, String payload, Long gen, boolean mac) throws Exception {
        List<Object> arr = new ArrayList<>();
        arr.add(seq); arr.add(prev); arr.add(op); arr.add(payload); arr.add(TS);
        if (gen != null) arr.add(gen);
        String h = sha(DurableState.DOMAIN + Json.stringify(arr));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("seq", seq); m.put("prev", prev); m.put("op", op); m.put("payload", payload); m.put("ts", TS);
        if (gen != null) m.put("gen", gen);
        m.put("h", h);
        if (mac) m.put("mac", hmac(h));
        return new R(seq, h, Json.stringify(m));
    }

    /** set records k1=1, k2=2, ... chained from genesis, one per generation given (null = no gen member). */
    private static R[] chain(Long... gens) throws Exception {
        R[] out = new R[gens.length];
        String prev = G0;
        for (int i = 0; i < gens.length; i++) {
            out[i] = rec(i + 1, prev, "set", "k" + (i + 1) + "\n" + (i + 1), gens[i], false);
            prev = out[i].h;
        }
        return out;
    }

    private static String journal(R... rs) {
        StringBuilder sb = new StringBuilder();
        for (R r : rs) sb.append(r.line).append('\n');
        return sb.toString();
    }

    private static String head(long seq, String h, Long gen) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("seq", seq); m.put("h", h);
        if (gen != null) m.put("gen", gen);
        return Json.stringify(m) + "\n";
    }

    private static String fence(long gen, long seq, String h) { return "{\"gen\":" + gen + ",\"seq\":" + seq + ",\"h\":\"" + h + "\"}"; }

    private static String fences(String... raw) { return "{\"v\":1,\"fences\":[" + String.join(",", raw) + "]}"; }

    private static String entry(String rawFence) { return "{\"v\":1,\"fence\":" + rawFence + "}"; }

    private static DurableState.Options opts(File d, byte[] key) {
        DurableState.Options o = new DurableState.Options(d.getPath());
        o.now = () -> TS;
        o.lockTimeoutMs = 300;
        o.hmacKey = key;
        return o;
    }

    private static DurableState open(File d) { return DurableState.open(opts(d, null)); }

    private static String refused(File d, byte[] key) { return assertThrows(DurableStateError.class, () -> DurableState.open(opts(d, key))).getMessage(); }

    private static String refused(File d) { return refused(d, null); }

    private static void intrude(File d) {
        try {
            write(d, "state.lock.999", "{\"st\":\"held\",\"pid\":" + PID + ",\"host\":\"" + HOST + "\",\"nonce\":\"intruder\"}");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // ---- the in-memory store ----

    @Test void theInMemoryStoreRoundTripsSortsAndSnapshots() {
        DurableState.MemoryDurableKv mem = DurableState.createMemoryDurableKv();
        assertNull(mem.get("missing"));
        mem.set("b", "x");
        mem.set("ad", Arrays.asList("y"));
        mem.set("c", "z");
        mem.set("ab", "w");
        assertEquals("x", mem.get("b"));
        assertEquals(Arrays.asList("y"), mem.get("ad"));
        assertEquals(Arrays.asList("ab", "ad", "b", "c"), mem.keys()); // a HashMap iterates these as ab, b, ad, c
        Map<String, Object> snap = mem.snapshot();
        assertEquals(Arrays.asList("ab", "ad", "b", "c"), new ArrayList<>(snap.keySet()));
        assertEquals("w", snap.get("ab"));
        assertEquals(Arrays.asList("y"), snap.get("ad"));
        assertEquals("x", snap.get("b"));
        assertEquals("z", snap.get("c"));
        assertEquals("invalid: value is not JSON-serialisable", assertThrows(DurableStateError.class, () -> mem.set("k", new Object())).getMessage());
    }

    // ---- keys and values ----

    @Test void keysMustBeOneTo256CharsWithoutNewlines() throws Exception {
        DurableState s = open(tmp());
        String msg = "invalid: key must be 1..256 chars without newlines";
        for (String bad : Arrays.asList(null, "", "k".repeat(257), "a\nb")) {
            assertEquals(msg, assertThrows(DurableStateError.class, () -> s.set(bad, "v")).getMessage());
            assertEquals(msg, assertThrows(DurableStateError.class, () -> s.get(bad)).getMessage());
            assertEquals(msg, assertThrows(DurableStateError.class, () -> s.update(bad, p -> "v")).getMessage());
        }
        String k256 = "k".repeat(256);
        s.set(k256, "v");
        assertEquals("v", s.get(k256));
    }

    @Test void aValueThatIsNotJsonIsInvalid() throws Exception {
        DurableState s = open(tmp());
        assertEquals("invalid: value is not JSON-serialisable", assertThrows(DurableStateError.class, () -> s.set("k", new Object())).getMessage());
        assertEquals("invalid: value is not JSON-serialisable", assertThrows(DurableStateError.class, () -> s.update("k", p -> new Object())).getMessage());
    }

    @Test void aValueMayBeExactlyMaxValueBytesLong() throws Exception {
        DurableState.Options o = opts(tmp(), null);
        o.maxValueBytes = 5;
        DurableState s = DurableState.open(o);
        s.set("k", "abc"); // "abc" serialises to 5 chars
        assertEquals("abc", s.get("k"));
        assertEquals("too-large: value exceeds maxValueBytes=5", assertThrows(DurableStateError.class, () -> s.set("k", "abcd")).getMessage());
    }

    // ---- the exact bytes a commit writes ----

    @Test void aCommitWritesExactlyThisJournalAndHead() throws Exception {
        File d = tmp();
        DurableState s = open(d); // takes generation 1, releases as 2
        s.set("a", "x"); // generation 3
        R r = rec(1, G0, "set", "a\n\"x\"", 3L, false);
        assertEquals(r.line + "\n", read(d, "state.journal"));
        assertEquals("{\"seq\":1,\"h\":\"" + r.h + "\",\"gen\":3}\n", read(d, "state.head"));
        assertEquals(1L, s.position().seq);
        assertEquals(r.h, s.position().hash);
    }

    @Test void aKeyedCommitTagsTheRecordAndTheHead() throws Exception {
        File d = tmp();
        DurableState s = DurableState.open(opts(d, KEY));
        s.set("a", "x");
        R r = rec(1, G0, "set", "a\n\"x\"", 3L, true);
        assertEquals(r.line + "\n", read(d, "state.journal"));
        assertEquals("{\"seq\":1,\"h\":\"" + r.h + "\",\"gen\":3,\"mac\":\"" + hmac("head\n1\n" + r.h + "\n3") + "\"}\n", read(d, "state.head"));
        assertEquals("x", DurableState.open(opts(d, KEY)).get("a"));
    }

    @Test void compactionWritesOneCheckpointWithTheKeysSorted() throws Exception {
        File d = tmp();
        DurableState.Options o = opts(d, null);
        o.compactEvery = 2;
        DurableState s = DurableState.open(o);
        s.set("b", "vb");
        s.set("a", "va");
        s.set("c", "vc"); // three records > compactEvery: one checkpoint at seq 3
        String[] lines = read(d, "state.journal").split("\n");
        assertEquals(1, lines.length);
        Map<String, Object> cp = obj(lines[0]);
        assertEquals("checkpoint", cp.get("op"));
        assertEquals(3L, num(cp.get("seq")));
        assertEquals(Json.stringify(Arrays.asList(Arrays.asList("a", "\"va\""), Arrays.asList("b", "\"vb\""), Arrays.asList("c", "\"vc\""))), cp.get("payload"));
        DurableState again = open(d);
        assertEquals(Arrays.asList("a", "b", "c"), again.keys());
        assertEquals("vb", again.get("b"));
    }

    // ---- the head repair before a write ----

    private static void crashingWrite(DurableState s, boolean viaUpdate, String k) {
        if (viaUpdate) assertThrows(AssertionError.class, () -> s.update(k, p -> "3"));
        else assertThrows(AssertionError.class, () -> s.set(k, "3"));
    }

    @Test void aWriteRepairsAHeadOneRecordBehindBeforeItsOwnCommit() throws Exception {
        for (boolean viaUpdate : new boolean[] {false, true}) {
            File d = tmp();
            DurableState.Options o = opts(d, null);
            DurableState s = DurableState.open(o);
            s.set("a", "1"); // gen 3
            String h1 = read(d, "state.head");
            s.set("b", "2"); // gen 5
            String j2 = read(d, "state.journal");
            write(d, "state.head", h1); // the head trails by one record: legal, repaired by the next writer
            o.testCrashAt = "after-temp-write"; // the commit dies before its journal rename (outside a crash child: an AssertionError)
            crashingWrite(s, viaUpdate, "c"); // gen 7
            o.testCrashAt = null;
            assertEquals(j2, read(d, "state.journal"));
            Map<String, Object> h = obj(read(d, "state.head"));
            assertEquals(2L, num(h.get("seq")));
            assertEquals(obj(j2.split("\n")[1]).get("h"), h.get("h"));
            assertEquals(7L, num(h.get("gen")));
        }
    }

    @Test void aWriteLeavesACurrentHeadAlone() throws Exception {
        for (boolean viaUpdate : new boolean[] {false, true}) {
            File d = tmp();
            DurableState.Options o = opts(d, null);
            DurableState s = DurableState.open(o);
            s.set("a", "1");
            s.set("b", "2");
            String h2 = read(d, "state.head");
            o.testCrashAt = "after-temp-write";
            crashingWrite(s, viaUpdate, "c");
            o.testCrashAt = null;
            assertEquals(h2, read(d, "state.head"));
        }
    }

    @Test void aWriteRestoresAMissingHeadOverOneRecord() throws Exception {
        for (boolean viaUpdate : new boolean[] {false, true}) {
            File d = tmp();
            DurableState.Options o = opts(d, null);
            DurableState s = DurableState.open(o);
            s.set("a", "1"); // gen 3
            assertTrue(new File(d, "state.head").delete()); // a one-record journal needs no head
            o.testCrashAt = "after-temp-write";
            crashingWrite(s, viaUpdate, "b"); // gen 5
            o.testCrashAt = null;
            Map<String, Object> h = obj(read(d, "state.head"));
            assertEquals(1L, num(h.get("seq")));
            assertEquals(obj(read(d, "state.journal").split("\n")[0]).get("h"), h.get("h"));
            assertEquals(5L, num(h.get("gen")));
        }
    }

    // ---- observing another writer ----

    @Test void readsAndVerifyAdvanceThePositionToAnotherWritersRecords() throws Exception {
        File d = tmp();
        DurableState a = open(d);
        DurableState b = open(d);
        b.set("x", "1");
        assertEquals("1", a.get("x"));
        assertEquals(1L, a.position().seq);
        assertEquals(b.position().hash, a.position().hash);
        b.set("y", "2");
        assertEquals(Arrays.asList("x", "y"), a.keys());
        assertEquals(2L, a.position().seq);
        b.set("z", "3");
        DurableState.Position p = a.verify();
        assertEquals(3L, p.seq);
        assertEquals(b.position().hash, p.hash);
        assertEquals(3L, a.position().seq);
    }

    // ---- what changed under an open handle ----

    @Test void stateForkedEmptiedDeletedOrMovedBackWhileOpenIsARollback() throws Exception {
        File d = tmp();
        DurableState s = open(d);
        s.set("a", "1"); // seq 1, gen 3
        R other = rec(1, G0, "set", "z\n9", 9L, false);
        write(d, "state.journal", journal(other));
        write(d, "state.head", head(1, other.h, 9L));
        assertEquals("rollback: state forked at seq 1 while open", assertThrows(DurableStateError.class, () -> s.get("a")).getMessage());

        File d2 = tmp();
        DurableState s2 = open(d2);
        s2.set("a", "1");
        write(d2, "state.journal", "");
        assertTrue(new File(d2, "state.head").delete());
        assertEquals("rollback: state was emptied while open", assertThrows(DurableStateError.class, () -> s2.get("a")).getMessage());

        File d3 = tmp();
        DurableState s3 = open(d3);
        s3.set("a", "1");
        assertTrue(new File(d3, "state.journal").delete());
        assertTrue(new File(d3, "state.head").delete());
        assertEquals("rollback: state was deleted while open", assertThrows(DurableStateError.class, () -> s3.get("a")).getMessage());

        File d4 = tmp();
        DurableState s4 = open(d4);
        s4.set("a", "1");
        String j1 = read(d4, "state.journal"), h1 = read(d4, "state.head");
        s4.set("b", "2");
        write(d4, "state.journal", j1);
        write(d4, "state.head", h1);
        assertEquals("rollback: state moved backwards from seq 2 to 1 while open", assertThrows(DurableStateError.class, () -> s4.get("a")).getMessage());
    }

    // ---- load: empty, missing and head-only states ----

    @Test void anEmptyJournalOpensEmptyWithOrWithoutAGenesisHead() throws Exception {
        File d = tmp();
        write(d, "state.journal", "");
        DurableState s = open(d);
        assertEquals(Collections.emptyList(), s.keys());
        assertEquals(0L, s.position().seq);
        File d2 = tmp();
        write(d2, "state.journal", "");
        write(d2, "state.head", head(0, G0, null));
        assertEquals(Collections.emptyList(), open(d2).keys());
    }

    @Test void aMissingJournalIsARollbackOnlyPastSeqZero() throws Exception {
        File d = tmp();
        write(d, "state.head", head(0, G0, null));
        assertEquals(Collections.emptyList(), open(d).keys());
        File d2 = tmp();
        write(d2, "state.head", head(1, HEX, null));
        assertEquals("rollback: state.journal is missing but state.head records seq 1", refused(d2));
        File d3 = tmp();
        write(d3, "state.fence", fences(fence(1, 0, G0)));
        assertEquals(Collections.emptyList(), open(d3).keys());
        File d4 = tmp();
        write(d4, "state.fence", fences(fence(1, 1, HEX)));
        assertEquals("rollback: state.journal is missing but operator recovery cut it at seq 1", refused(d4));
    }

    @Test void anUnreadableHeadFileIsAnIoErrorNotAnEmptyState() throws Exception {
        File d = tmp();
        assertTrue(new File(d, "state.head").mkdir());
        assertThrows(UncheckedIOException.class, () -> open(d));
    }

    // ---- load: the head ----

    @Test void theHeadShapeIsChecked() throws Exception {
        for (String h : Arrays.asList("{\"seq\":-1,\"h\":\"" + G0 + "\"}", "{\"seq\":0,\"h\":\"" + G0 + "\",\"gen\":0}", "{\"seq\":0,\"h\":\"" + G0 + "\",\"gen\":\"x\"}")) {
            File d = tmp();
            write(d, "state.head", h);
            assertEquals("corrupt: state.head has an invalid shape", refused(d), h);
        }
    }

    @Test void aKeyedHeadNeedsAStringMac() throws Exception {
        File d = tmp();
        write(d, "state.head", "{\"seq\":0,\"h\":\"" + G0 + "\",\"mac\":5}");
        assertEquals("key-mismatch: state.head MAC does not verify (wrong key or forged head)", refused(d, KEY));
    }

    @Test void aKeyedHeadWithoutAGenerationVerifiesOverSeqAndHashOnly() throws Exception {
        File d = tmp();
        R r = rec(1, G0, "set", "k\n1", null, true);
        write(d, "state.journal", journal(r));
        write(d, "state.head", "{\"seq\":1,\"h\":\"" + r.h + "\",\"mac\":\"" + hmac("head\n1\n" + r.h) + "\"}\n");
        assertEquals(1L, num(DurableState.open(opts(d, KEY)).get("k")));
    }

    @Test void aKeyedJournalRecordWithoutAMacIsAKeyMismatch() throws Exception {
        File d = tmp();
        write(d, "state.journal", journal(chain(1L)));
        assertEquals("key-mismatch: journal line 1: MAC does not verify (wrong key or forged record)", refused(d, KEY));
    }

    @Test void aKeyedJournalRecordWithAWrongMacIsAKeyMismatch() throws Exception {
        File d = tmp(); // no head (one record), so the record MAC is the first thing the key checks
        R r = chain(1L)[0];
        write(d, "state.journal", r.line.substring(0, r.line.length() - 1) + ",\"mac\":\"" + hmac("not " + r.h) + "\"}\n");
        assertEquals("key-mismatch: journal line 1: MAC does not verify (wrong key or forged record)", refused(d, KEY));
    }

    @Test void theHeadMustMatchOrTrailTheJournalByOne() throws Exception {
        R[] two = chain(null, null);
        File d = tmp(); // no generations anywhere: the head trails by one, fine
        write(d, "state.journal", journal(two));
        write(d, "state.head", head(1, two[0].h, null));
        assertEquals(2L, num(open(d).get("k2")));

        File d2 = tmp(); // a head of generation 1 over a generation-less tail
        write(d2, "state.journal", journal(two));
        write(d2, "state.head", head(1, two[0].h, 1L));
        assertEquals("corrupt: journal tail (seq 2) was written by lock generation 0, older than generation 1 that wrote state.head: a stale writer replaced the journal (refused)", refused(d2));

        R[] g3 = chain(3L, 3L);
        File d3 = tmp(); // same generation, head one behind
        write(d3, "state.journal", journal(g3));
        write(d3, "state.head", head(1, g3[0].h, 3L));
        assertEquals(2L, num(open(d3).get("k2")));

        R[] g1 = chain(1L);
        File d4 = tmp(); // a later generation repaired the head: the tail is older but IS the head
        write(d4, "state.journal", journal(g1));
        write(d4, "state.head", head(1, g1[0].h, 2L));
        assertEquals(1L, num(open(d4).get("k1")));

        R[] g11 = chain(1L, 1L);
        File d5 = tmp();
        write(d5, "state.journal", journal(g11));
        write(d5, "state.head", head(1, HEX, 1L));
        assertEquals("corrupt: journal tail is not chained from state.head", refused(d5));

        File d6 = tmp();
        write(d6, "state.journal", journal(g11));
        assertEquals("rollback: state.head is missing but the journal is at seq 2", refused(d6));

        File d7 = tmp(); // one record needs no head
        write(d7, "state.journal", journal(g1));
        assertEquals(1L, num(open(d7).get("k1")));

        File d8 = tmp();
        write(d8, "state.journal", journal(g1));
        write(d8, "state.head", head(2, HEX, 1L));
        assertEquals("rollback: journal is at seq 1 but state.head recorded seq 2 (truncation or older copy)", refused(d8));

        R[] g111 = chain(1L, 1L, 1L);
        File d9 = tmp();
        write(d9, "state.journal", journal(g111));
        write(d9, "state.head", head(1, g111[0].h, 1L));
        assertEquals("corrupt: journal (seq 3) is more than one record ahead of state.head (seq 1)", refused(d9));

        File d10 = tmp();
        write(d10, "state.journal", journal(g1));
        write(d10, "state.head", head(1, HEX, 1L));
        assertEquals("corrupt: journal tail does not match state.head", refused(d10));

        File d11 = tmp(); // an older tail far ahead of a newer head is "too far ahead", not a stale-writer tail
        write(d11, "state.journal", journal(g111));
        write(d11, "state.head", head(1, g111[0].h, 3L));
        assertEquals("corrupt: journal (seq 3) is more than one record ahead of state.head (seq 1)", refused(d11));
    }

    // ---- load: a head left behind by a fenced, paused holder ----

    /** records of generations gens, a head at headSeq (hash headHash, generation headGen), one fence (fenceGen, fenceSeq at that record). */
    private File staleHeadDir(Long[] gens, long headSeq, String headHash, long headGen, long fenceGen, long fenceSeq) throws Exception {
        R[] rs = chain(gens);
        File d = tmp();
        write(d, "state.journal", journal(rs));
        write(d, "state.head", head(headSeq, headHash == null ? rs[(int) headSeq - 1].h : headHash, headGen));
        write(d, "state.fence", fences(fence(fenceGen, fenceSeq, rs[(int) fenceSeq - 1].h)));
        return d;
    }

    @Test void aHeadLeftAtTheCutByAFencedGenerationIsAcceptedOnlyExactly() throws Exception {
        // the accepted case: head of generation 1 at the cut (seq 1), records after it from generation 2, the journal two past the head
        assertEquals(3L, num(open(staleHeadDir(new Long[] {1L, 2L, 2L}, 1, null, 1, 2, 1)).get("k3")));
        String ahead31 = "corrupt: journal (seq 3) is more than one record ahead of state.head (seq 1)";
        // the head's generation is not below the fence
        assertEquals(ahead31, refused(staleHeadDir(new Long[] {1L, 2L, 2L}, 1, null, 2, 2, 1)));
        // the head is past the cut
        assertEquals("corrupt: journal (seq 4) is more than one record ahead of state.head (seq 2)", refused(staleHeadDir(new Long[] {1L, 2L, 2L, 2L}, 2, null, 1, 2, 1)));
        // the journal ends at the cut
        assertEquals(ahead31, refused(staleHeadDir(new Long[] {1L, 1L, 1L}, 1, null, 1, 2, 3)));
        // the head's record is not in the journal (a foreign hash, or the hash of another seq)
        assertEquals(ahead31, refused(staleHeadDir(new Long[] {1L, 2L, 2L}, 1, HEX, 1, 2, 1)));
        R[] rs = chain(1L, 2L, 2L);
        assertEquals(ahead31, refused(staleHeadDir(new Long[] {1L, 2L, 2L}, 1, rs[1].h, 1, 2, 1)));
    }

    // ---- load: fences against the records ----

    @Test void fencesBindRecordsAfterTheCutToNewerGenerations() throws Exception {
        R[] one = chain(1L);
        File d = tmp(); // the record AT the cut may be older than the fence
        write(d, "state.journal", journal(one));
        write(d, "state.fence", fences(fence(5, 1, one[0].h)));
        assertEquals(1L, num(open(d).get("k1")));

        R[] r15 = chain(1L, 5L);
        File d2 = tmp(); // a record after the cut of exactly the fenced generation is fine
        write(d2, "state.journal", journal(r15));
        write(d2, "state.head", head(2, r15[1].h, 5L));
        write(d2, "state.fence", fences(fence(5, 1, r15[0].h)));
        assertEquals(2L, num(open(d2).get("k2")));

        R[] r11 = chain(1L, 1L);
        File d3 = tmp();
        write(d3, "state.journal", journal(r11));
        write(d3, "state.head", head(2, r11[1].h, 1L));
        write(d3, "state.fence", fences(fence(5, 1, r11[0].h)));
        assertEquals("corrupt: journal line 2 (seq 2) was written by lock generation 1, but operator recovery fenced generations below 5 after seq 1: a holder paused across recoverDurableState resumed and replaced the journal late (refused; records committed after the recovery may be lost; recoverFromCorruption quarantines the files)", refused(d3));

        File d4 = tmp(); // a fence at seq 0 binds nothing at open
        write(d4, "state.journal", journal(one));
        write(d4, "state.fence", fences(fence(1, 0, G0)));
        assertEquals(1L, num(open(d4).get("k1")));

        File d5 = tmp();
        write(d5, "state.journal", journal(one));
        write(d5, "state.fence", fences(fence(2, 5, HEX)));
        assertEquals("rollback: journal is at seq 1 but operator recovery cut it at seq 5 (truncation, or a stale writer replaced it)", refused(d5));

        File d6 = tmp();
        write(d6, "state.journal", journal(one));
        write(d6, "state.fence", fences(fence(1, 1, HEX)));
        assertEquals("corrupt: journal record at seq 1 is not the record operator recovery cut at: a stale writer replaced the journal (refused; recoverFromCorruption quarantines the files)", refused(d6));
    }

    @Test void aRecordOfAnOlderGenerationThanItsPredecessorIsRefused() throws Exception {
        File d = tmp();
        R[] rs = chain(2L, 1L);
        write(d, "state.journal", journal(rs));
        write(d, "state.head", head(2, rs[1].h, 1L));
        assertEquals("corrupt: journal line 2 (seq 2) was written by lock generation 1, older than generation 2 of an earlier record: a stale writer's record (refused)", refused(d));
    }

    // ---- load: record shapes ----

    private static String rawLine(String key, String raw) {
        Map<String, String> f = new LinkedHashMap<>();
        f.put("seq", "1"); f.put("prev", "\"" + G0 + "\""); f.put("op", "\"set\""); f.put("payload", "\"a\\n1\""); f.put("ts", "1000"); f.put("h", "\"" + HEX + "\"");
        f.put(key, raw);
        StringBuilder sb = new StringBuilder("{");
        for (Map.Entry<String, String> e : f.entrySet()) sb.append(sb.length() > 1 ? "," : "").append('"').append(e.getKey()).append("\":").append(e.getValue());
        return sb.append('}').toString();
    }

    @Test void everyRecordMemberIsShapeChecked() throws Exception {
        List<String> lines = new ArrayList<>(Arrays.asList("[]", "5", "null"));
        String[][] cases = {{"seq", "\"1\""}, {"seq", "1.5"}, {"prev", "\"x\""}, {"op", "\"bogus\""}, {"payload", "5"}, {"ts", "\"x\""}, {"ts", "-0"}, {"h", "\"zz\""}, {"gen", "0"}, {"gen", "\"x\""}};
        for (String[] c : cases) lines.add(rawLine(c[0], c[1]));
        for (String line : lines) {
            File d = tmp();
            write(d, "state.journal", line + "\n");
            assertEquals("corrupt: journal line 1 has an invalid shape", refused(d), line);
        }
    }

    @Test void aNonStringMacOnAnUnkeyedRecordIsIgnored() throws Exception {
        File d = tmp();
        R r = chain(1L)[0];
        write(d, "state.journal", r.line.substring(0, r.line.length() - 1) + ",\"mac\":5}\n");
        assertEquals(1L, num(open(d).get("k1")));
    }

    @Test void aSetPayloadNeedsANonEmptyKeyBeforeItsNewline() throws Exception {
        for (String payload : Arrays.asList("\nx", "abc")) {
            File d = tmp();
            write(d, "state.journal", journal(rec(1, G0, "set", payload, 1L, false)));
            assertEquals("corrupt: journal line 1: malformed payload", refused(d), payload);
        }
    }

    // ---- load: checkpoints ----

    @Test void aCheckpointReplacesTheWholeState() throws Exception {
        File d = tmp();
        R r1 = rec(1, G0, "set", "a\n1", 1L, false);
        R r2 = rec(2, r1.h, "checkpoint", "[[\"b\",\"2\"]]", 1L, false);
        write(d, "state.journal", journal(r1, r2));
        write(d, "state.head", head(2, r2.h, 1L));
        DurableState s = open(d);
        assertEquals(Collections.singletonList("b"), s.keys());
        assertNull(s.get("a"));
    }

    @Test void checkpointEntriesAndSeqAreChecked() throws Exception {
        for (String payload : Arrays.asList("[[\"a\"]]", "[[\"a\",\"1\",\"2\"]]", "[[1,\"x\"]]", "[[\"a\",1]]", "[\"x\"]", "[5]")) {
            File d = tmp();
            write(d, "state.journal", journal(rec(1, G0, "checkpoint", payload, 1L, false)));
            assertEquals("corrupt: checkpoint entry is malformed", refused(d), payload);
        }
        File d = tmp();
        write(d, "state.journal", journal(rec(1, G0, "checkpoint", "{}", 1L, false)));
        assertEquals("corrupt: checkpoint payload is not an array", refused(d));
        File d2 = tmp();
        write(d2, "state.journal", journal(rec(0, G0, "checkpoint", "[]", 1L, false)));
        assertEquals("corrupt: bad checkpoint seq", refused(d2));
        File d3 = tmp(); // a checkpoint may start the journal at any seq >= 1
        R cp = rec(7, HEX, "checkpoint", "[[\"a\",\"1\"]]", 1L, false);
        write(d3, "state.journal", journal(cp));
        write(d3, "state.head", head(7, cp.h, 1L));
        assertEquals(1L, num(open(d3).get("a")));
    }

    // ---- fences: file shapes, entry files, order ----

    @Test void theFenceListFileShapeIsChecked() throws Exception {
        for (String doc : Arrays.asList("[]", "{\"v\":2,\"fences\":[]}", "{\"v\":\"1\",\"fences\":[]}", "{\"v\":1,\"fences\":{}}", "{\"v\":1}")) {
            File d = tmp();
            write(d, "state.fence", doc);
            assertEquals("corrupt: state.fence has an invalid shape", refused(d), doc);
        }
        File d = tmp();
        write(d, "state.fence", "nope");
        assertEquals("corrupt: state.fence is not valid JSON", refused(d));
        File ok = tmp();
        write(ok, "state.fence", "{\"v\":1,\"fences\":[]}");
        assertEquals(Collections.emptyList(), open(ok).keys());
    }

    @Test void everyFenceMemberIsShapeChecked() throws Exception {
        List<String> bad = Arrays.asList("5", fence(0, 0, G0), "{\"gen\":\"x\",\"seq\":0,\"h\":\"" + G0 + "\"}", "{\"gen\":1,\"seq\":\"x\",\"h\":\"" + G0 + "\"}",
            fence(1, -1, G0), "{\"gen\":1,\"seq\":-0,\"h\":\"" + G0 + "\"}", "{\"gen\":1,\"seq\":0,\"h\":\"x\"}");
        for (String f : bad) {
            File d = tmp();
            write(d, "state.fence", fences(f));
            assertEquals("corrupt: state.fence has an invalid entry", refused(d), f);
        }
    }

    @Test void fenceEntryFilesAreShapeCheckedAndNamedByTheirGeneration() throws Exception {
        for (String doc : Arrays.asList("[]", "{\"v\":2,\"fence\":" + fence(3, 0, G0) + "}", "{\"v\":\"1\",\"fence\":" + fence(3, 0, G0) + "}")) {
            File d = tmp();
            write(d, "state.fence.3-ab", doc);
            assertEquals("corrupt: state.fence.3-ab has an invalid shape", refused(d), doc);
        }
        File d = tmp();
        write(d, "state.fence.3-ab", "{\"v\":1,\"fence\":5}");
        assertEquals("corrupt: state.fence.3-ab has an invalid entry", refused(d));
        File d2 = tmp();
        write(d2, "state.fence.3-ab", entry(fence(4, 0, G0)));
        assertEquals("corrupt: state.fence.3-ab names generation 3 but holds 4", refused(d2));
        File d3 = tmp(); // a generation past the long range reads as Long.MAX_VALUE
        write(d3, "state.fence.99999999999999999999-ab", entry(fence(1, 0, G0)));
        assertEquals("corrupt: state.fence.99999999999999999999-ab names generation 9223372036854775807 but holds 1", refused(d3));
        File ok = tmp();
        write(ok, "state.fence.3-ab", entry(fence(3, 0, G0)));
        assertEquals(Collections.emptyList(), open(ok).keys());
    }

    @Test void fenceEntriesAreCheckedInGenerationOrderNotNameOrder() throws Exception {
        File d = tmp(); // by name "state.fence.10-aa" sorts first; by generation 2 does
        write(d, "state.fence.2-aa", entry(fence(2, 5, HEX)));
        write(d, "state.fence.10-aa", entry(fence(10, 7, HEX)));
        assertEquals("rollback: state.journal is missing but operator recovery cut it at seq 5", refused(d));
    }

    @Test void fenceEntriesOfOneGenerationAreCheckedInNameOrder() throws Exception {
        File d = tmp();
        for (int i = 0; i < 32; i++) write(d, String.format("state.fence.3-%02x", i), entry(fence(3, 100 + i, HEX)));
        assertEquals("rollback: state.journal is missing but operator recovery cut it at seq 100", refused(d));
    }

    // ---- recoverFromCorruption: the quarantine ----

    @Test void quarantineMovesEveryFileAsideUnderOneTagAndRestartsTheFenceAtGenesis() throws Exception {
        File d = tmp();
        String oldFence = fences(fence(1, 0, G0));
        write(d, "state.journal", "garbage\n");
        write(d, "state.fence", oldFence);
        write(d, "state.fence.1-abcdef", entry(fence(1, 0, G0)));
        DurableState.Options o = opts(d, null);
        o.recoverFromCorruption = true;
        DurableState s = DurableState.open(o); // generation 1
        assertTrue(s.recovered());
        assertEquals(0L, s.position().seq);
        assertEquals(G0, s.position().hash);
        List<String> qj = matching(d, "state\\.journal\\.quarantine-1000-[0-9a-f]{6}");
        assertEquals(1, qj.size(), names(d).toString());
        String tag = qj.get(0).substring("state.journal.quarantine-".length());
        assertEquals("garbage\n", read(d, qj.get(0)));
        assertEquals(oldFence, read(d, "state.fence.quarantine-" + tag));
        assertEquals(entry(fence(1, 0, G0)), read(d, "state.fence.1-abcdef.quarantine-" + tag));
        assertFalse(exists(d, "state.journal"));
        assertFalse(exists(d, "state.fence.1-abcdef"));
        assertEquals("{\"v\":1,\"fences\":[{\"gen\":1,\"seq\":0,\"h\":\"" + G0 + "\",\"from\":0,\"t\":1000}]}\n", read(d, "state.fence"));
        assertEquals(Collections.emptyList(), s.keys());
    }

    @Test void aQuarantineByAWriterThatLostTheLockMovesNothing() throws Exception {
        File d = tmp();
        write(d, "state.journal", "garbage\n");
        DurableState.Options o = opts(d, null);
        o.recoverFromCorruption = true;
        AtomicBoolean armed = new AtomicBoolean(true);
        o.now = () -> { if (armed.getAndSet(false)) intrude(d); return TS; }; // the quarantine's first step reads the clock
        DurableStateError e = assertThrows(DurableStateError.class, () -> DurableState.open(o));
        assertEquals("lock-lost: the state lock is no longer held by this writer (generation 1, highest 999 held); nothing was written", e.getMessage());
        assertEquals("garbage\n", read(d, "state.journal"));
        assertEquals(Collections.emptyList(), matching(d, ".*quarantine.*"));
    }

    // ---- the lock re-check before every rename ----

    @Test void aCommitThatLostTheLockBeforeItsJournalRenameWritesNothing() throws Exception {
        File d = tmp();
        DurableState.Options o = opts(d, null);
        AtomicBoolean armed = new AtomicBoolean(false);
        o.now = () -> { if (armed.getAndSet(false)) intrude(d); return TS; }; // a commit reads the clock for its record before writing
        DurableState s = DurableState.open(o);
        armed.set(true);
        DurableStateError e = assertThrows(DurableStateError.class, () -> s.set("a", "1")); // generation 3
        assertEquals("lock-lost: the state lock is no longer held by this writer (generation 3, highest 999 held); nothing was written", e.getMessage());
        assertFalse(exists(d, "state.journal"));
        assertFalse(exists(d, "state.head"));
        assertEquals(Collections.emptyList(), matching(d, ".*\\.tmp-.*"));
    }

    @Test void aCommitThatLostTheLockAfterItsJournalRenameDoesNotWriteTheHead() throws Exception {
        File d = tmp();
        DurableState.Options o = opts(d, null);
        DurableState s = DurableState.open(o);
        s.set("a", "1"); // generation 3
        String h1 = read(d, "state.head");
        Runnable prevHalt = DurableState.crashHalter;
        String prevProp = System.getProperty(DurableState.CRASH_CHILD_PROPERTY);
        DurableState.crashHalter = () -> intrude(d); // the "halt" after the journal rename just loses the lock and returns
        System.setProperty(DurableState.CRASH_CHILD_PROPERTY, "1");
        o.testCrashAt = "after-journal-rename";
        try {
            DurableStateError e = assertThrows(DurableStateError.class, () -> s.set("b", "2")); // generation 5
            assertEquals("lock-lost: the state lock is no longer held by this writer (generation 5, highest 999 held); the journal record (seq 2) was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)", e.getMessage());
        } finally {
            o.testCrashAt = null;
            DurableState.crashHalter = prevHalt;
            if (prevProp == null) System.clearProperty(DurableState.CRASH_CHILD_PROPERTY); else System.setProperty(DurableState.CRASH_CHILD_PROPERTY, prevProp);
        }
        assertEquals(h1, read(d, "state.head"));
        assertEquals(2, read(d, "state.journal").split("\n").length);
    }

    // ---- lock bodies as the lock reads them ----

    @Test void aNonStringNamespaceInALockBodyIsIgnored() throws Exception {
        File d = tmp(); // a dead holder on this host whose ns member is not a string: judged by its pid, so taken over
        write(d, "state.lock.1", "{\"st\":\"held\",\"pid\":" + DEAD + ",\"host\":\"" + HOST + "\",\"nonce\":\"n\",\"ns\":5}");
        open(d).set("a", "1");
        assertEquals("1", open(d).get("a"));
    }

    @Test void aLockBodyStartTimeThatNoLongerMatchesItsPidIsADeadHolder() throws Exception {
        Assumptions.assumeTrue(DurableState.procStartOf(PID) != null, "process start times need /proc");
        File d = tmp(); // our own live pid, but a different process start: the pid was reused, the holder is gone
        write(d, "state.lock.1", "{\"st\":\"held\",\"pid\":" + PID + ",\"host\":\"" + HOST + "\",\"nonce\":\"n\",\"start\":\"bogus\"}");
        open(d).set("a", "1");
        assertEquals("1", open(d).get("a"));
    }

    @Test void aTakeoverCarriesTheRecoveringGenerationOfTheBodyItReplaces() throws Exception {
        File d = tmp();
        write(d, "state.lock.1", "{\"st\":\"held\",\"pid\":" + DEAD + ",\"host\":\"" + HOST + "\",\"nonce\":\"n\",\"recovering\":7}");
        open(d);
        assertEquals(7L, num(obj(read(d, "state.lock.2")).get("recovering")));
        assertEquals(1, matching(d, "state\\.fence\\.2-[0-9a-f]{12}").size(), names(d).toString());
    }

    // ---- operator recovery ----

    private static void foreignLock(File d, long g) throws IOException { write(d, "state.lock." + g, "{\"st\":\"held\",\"pid\":4242,\"host\":\"" + FOREIGN + "\",\"nonce\":\"abc\"}"); }

    private static DurableState.ExpectedLockHolder foreign() { return new DurableState.ExpectedLockHolder(FOREIGN, 4242, "abc"); }

    private static DurableState.RecoverResult recover(File d, Object exp) { return DurableState.recover(new DurableState.RecoverOptions(d.getPath(), true, exp)); }

    private static String recoverRefused(File d, Object exp) { return assertThrows(DurableStateError.class, () -> recover(d, exp)).getMessage(); }

    private static String lockPath(File d, long g) { return new File(d, "state.lock." + g).getPath(); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> onlyFence(File d) throws IOException {
        List<String> fs = matching(d, "state\\.fence\\.\\d+-[0-9a-f]{12}");
        assertEquals(1, fs.size(), names(d).toString());
        return (Map<String, Object>) obj(read(d, fs.get(0))).get("fence");
    }

    private String bootId() throws Exception {
        File o = tmp();
        open(o);
        return (String) obj(read(o, "state.lock.1")).get("boot");
    }

    @Test void recoveryTakesTheLockCutsFencesAndReleasesInExactlyTheseFiles() throws Exception {
        File d = tmp();
        R[] rs = chain(1L, 1L);
        write(d, "state.journal", journal(rs));
        write(d, "state.head", head(2, rs[1].h, 1L));
        foreignLock(d, 1);
        long before = System.currentTimeMillis();
        DurableState.RecoverResult r = recover(d, foreign());
        long after = System.currentTimeMillis();
        assertTrue(r.released);
        assertEquals("released", r.reason);
        assertEquals(lockPath(d, 1), r.lockFile);

        Map<String, Object> held = obj(read(d, "state.lock.2"));
        String ns = DurableState.ownNamespace();
        String start = DurableState.procStartOf(PID);
        List<String> keys = new ArrayList<>(Arrays.asList("st", "pid", "host", "nonce", "boot"));
        if (ns != null) keys.add("ns");
        if (start != null) keys.add("start");
        keys.add("recovering");
        keys.add("t");
        assertEquals(keys, new ArrayList<>(held.keySet()));
        assertEquals("held", held.get("st"));
        assertEquals(PID, num(held.get("pid")));
        assertEquals(HOST, held.get("host"));
        assertTrue(((String) held.get("nonce")).matches("[0-9a-f]{24}"), String.valueOf(held.get("nonce")));
        assertEquals(bootId(), held.get("boot"));
        if (ns != null) assertEquals(ns, held.get("ns"));
        if (start != null) assertEquals(start, held.get("start"));
        assertEquals(1L, num(held.get("recovering")));
        long ht = num(held.get("t"));
        assertTrue(ht >= before && ht <= after, Long.toString(ht));

        Map<String, Object> free = obj(read(d, "state.lock.3"));
        assertEquals(Arrays.asList("st", "t", "recoveredFrom"), new ArrayList<>(free.keySet()));
        assertEquals("free", free.get("st"));
        long ft = num(free.get("t"));
        assertTrue(ft >= before && ft <= after, Long.toString(ft));
        assertEquals(1L, num(free.get("recoveredFrom")));

        List<String> fs = matching(d, "state\\.fence\\.2-[0-9a-f]{12}");
        assertEquals(1, fs.size(), names(d).toString());
        String text = read(d, fs.get(0));
        long t = num(onlyFence(d).get("t"));
        assertTrue(t >= before && t <= after, Long.toString(t));
        assertEquals("{\"v\":1,\"fence\":{\"gen\":2,\"seq\":2,\"h\":\"" + rs[1].h + "\",\"from\":1,\"t\":" + t + "}}\n", text);
        assertEquals(Collections.emptyList(), matching(d, "state\\.lock\\.tmp-.*"));

        DurableState s = open(d); // the next writer takes generation 4 over the free 3
        assertEquals(2L, num(s.get("k2")));
        s.set("k3", "3");
        assertEquals("3", open(d).get("k3"));
    }

    @Test void theCutIsTheLastWellFormedJournalLineOrGenesis() throws Exception {
        String[][] cases = {
            {null, "0", G0},
            {"x\n", "0", G0},
            {"{\"seq\":1.5,\"h\":\"" + HEX + "\"}\n", "0", G0},
            {"{\"seq\":3,\"h\":\"x\"}\n", "0", G0},
            {"{\"seq\":0,\"h\":\"" + HEX + "\"}\n", "0", G0},
            {"{\"seq\":-2,\"h\":\"" + HEX + "\"}\n", "0", G0},
            {"{\"seq\":1,\"h\":\"" + HEX2 + "\"}\n{\"seq\":4,\"h\":\"" + HEX + "\"}\n\n", "4", HEX},
        };
        for (String[] c : cases) {
            File d = tmp();
            if (c[0] != null) write(d, "state.journal", c[0]);
            foreignLock(d, 1);
            assertTrue(recover(d, foreign()).released);
            Map<String, Object> f = onlyFence(d);
            assertEquals(Long.parseLong(c[1]), num(f.get("seq")), String.valueOf(c[0]));
            assertEquals(c[2], f.get("h"), String.valueOf(c[0]));
            assertEquals(2L, num(f.get("gen")));
            assertEquals(1L, num(f.get("from")));
        }
    }

    @Test void recoveryRefusesAnUnreadableFenceSet() throws Exception {
        File d = tmp();
        foreignLock(d, 1);
        write(d, "state.fence", "nope");
        assertEquals("corrupt: state.fence is not valid JSON", recoverRefused(d, foreign()));
    }

    @Test void aCompleteHolderMustMatchExactlyAndNotBeAliveHere() throws Exception {
        File d = tmp();
        foreignLock(d, 1);
        String p = lockPath(d, 1);
        String mismatch = "invalid: expectedHolder does not match the holder recorded in " + p + " (recorded pid=4242 host=" + FOREIGN + " nonce=abc); nothing was changed";
        assertEquals(mismatch, recoverRefused(d, new DurableState.ExpectedLockHolder("other.invalid", 4242, "abc")));
        assertEquals(mismatch, recoverRefused(d, new DurableState.ExpectedLockHolder(FOREIGN, 4243, "abc")));
        assertEquals(mismatch, recoverRefused(d, new DurableState.ExpectedLockHolder(FOREIGN, 4242, "abd")));
        assertEquals("invalid: " + p + " is readable (holder pid=4242 host=" + FOREIGN + "); expectedHolder 'unreadable' does not match", recoverRefused(d, "unreadable"));
        assertFalse(exists(d, "state.lock.2"));
        assertTrue(recover(d, foreign()).released);
    }

    @Test void anIncompleteHolderRecordIsNamedAndNeedsUnreadable() throws Exception {
        List<String> bodies = Arrays.asList(
            "{\"st\":\"held\",\"pid\":4242,\"host\":5,\"nonce\":\"abc\"}",
            "{\"st\":\"held\",\"pid\":4242,\"host\":\"" + FOREIGN + "\",\"nonce\":7}",
            "{\"st\":\"held\",\"pid\":4242,\"host\":\"" + FOREIGN + "\",\"nonce\":\"\"}",
            "{\"st\":\"held\",\"host\":\"" + FOREIGN + "\",\"nonce\":\"abc\"}",
            "{\"st\":\"held\",\"pid\":\"4242\",\"host\":\"" + FOREIGN + "\",\"nonce\":\"abc\"}",
            "[1]");
        for (String b : bodies) {
            File d = tmp();
            write(d, "state.lock.1", b);
            assertEquals("invalid: " + lockPath(d, 1) + " has an incomplete holder record (" + b + "); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it", recoverRefused(d, foreign()), b);
            assertFalse(exists(d, "state.lock.2"));
            assertTrue(recover(d, "unreadable").released, b);
        }
    }

    @Test void anIncompleteHolderRecordIsQuotedUpTo160Chars() throws Exception {
        String prefix = "{\"st\":\"held\",\"pad\":\"", suffix = "\"}";
        for (int len : new int[] {160, 161, 200}) {
            String b = prefix + "x".repeat(len - prefix.length() - suffix.length()) + suffix;
            assertEquals(len, b.length());
            File d = tmp();
            write(d, "state.lock.1", b);
            String quoted = len > 160 ? b.substring(0, 160) : b;
            assertEquals("invalid: " + lockPath(d, 1) + " has an incomplete holder record (" + quoted + "); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it", recoverRefused(d, foreign()));
        }
    }

    @Test void anIncompleteRecordOfALiveHolderHereIsNeverReleased() throws Exception {
        File d = tmp();
        write(d, "state.lock.1", "{\"st\":\"held\",\"pid\":" + PID + ",\"host\":\"" + HOST + "\"}");
        assertEquals("invalid: the holder of " + lockPath(d, 1) + " (pid " + PID + ") is alive in this PID namespace; refusing to release a live holder", recoverRefused(d, "unreadable"));
        assertFalse(exists(d, "state.lock.2"));
    }

    @Test void anUnreadableHolderRecordNeedsUnreadable() throws Exception {
        for (String b : Arrays.asList("5", "null", "\"s\"", "{oops")) {
            File d = tmp();
            write(d, "state.lock.1", b);
            assertEquals("invalid: " + lockPath(d, 1) + " is unreadable; pass expectedHolder: 'unreadable' to release it", recoverRefused(d, foreign()), b);
            assertTrue(recover(d, "unreadable").released, b);
        }
    }

    @Test void aLegacyLockIsMovedAsideAndFencedAboveTheTopGeneration() throws Exception {
        for (boolean withFreeGeneration : new boolean[] {false, true}) {
            File d = tmp();
            if (withFreeGeneration) write(d, "state.lock.1", "{\"st\":\"free\"}");
            write(d, "state.lock", "{\"st\":\"held\",\"pid\":4242,\"host\":\"" + FOREIGN + "\",\"nonce\":\"abc\"}");
            DurableState.RecoverOptions ro = new DurableState.RecoverOptions(d.getPath(), true, foreign());
            ro.legacyLock = true;
            long before = System.currentTimeMillis();
            DurableState.RecoverResult r = DurableState.recover(ro);
            long after = System.currentTimeMillis();
            assertTrue(r.released);
            assertEquals("released", r.reason);
            assertEquals(new File(d, "state.lock").getPath(), r.lockFile);
            assertFalse(exists(d, "state.lock"));
            List<String> moved = matching(d, "state\\.lock\\.legacy-recovered-\\d+-[0-9a-f]{6}");
            assertEquals(1, moved.size(), names(d).toString());
            Matcher m = Pattern.compile("state\\.lock\\.legacy-recovered-(\\d+)-.*").matcher(moved.get(0));
            assertTrue(m.matches());
            long t = Long.parseLong(m.group(1));
            assertTrue(t >= before && t <= after, Long.toString(t));
            Map<String, Object> f = onlyFence(d);
            long g = withFreeGeneration ? 1 : 0;
            assertEquals(g + 1, num(f.get("gen")));
            assertEquals(g, num(f.get("from")));
        }
    }

    // ---- operator recovery: every crash point, in process ----

    private interface Body { void run() throws Exception; }

    /** Runs body with the recovery hook at point armed; the "halt" records the point, runs action and returns (the recovery goes on). */
    private static List<String> withHook(UnaryOperator<String> env, String point, Body action, Body body) throws Exception {
        List<String> hits = new ArrayList<>();
        UnaryOperator<String> prevEnv = DurableState.crashEnv;
        Runnable prevHalt = DurableState.crashHalter;
        String prevProp = System.getProperty(DurableState.CRASH_CHILD_PROPERTY);
        DurableState.crashEnv = env;
        DurableState.crashHalter = () -> {
            hits.add(point);
            try {
                action.run();
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        };
        System.setProperty(DurableState.CRASH_CHILD_PROPERTY, "1");
        try {
            body.run();
        } finally {
            DurableState.crashEnv = prevEnv;
            DurableState.crashHalter = prevHalt;
            if (prevProp == null) System.clearProperty(DurableState.CRASH_CHILD_PROPERTY); else System.setProperty(DurableState.CRASH_CHILD_PROPERTY, prevProp);
        }
        return hits;
    }

    private static UnaryOperator<String> armedAt(String test, String point) {
        return k -> "PCA_DURABLE_TEST".equals(k) ? test : DurableState.RECOVER_CRASH_ENV.equals(k) ? point : null;
    }

    private static List<String> withHook(String point, Body action, Body body) throws Exception { return withHook(armedAt("1", point), point, action, body); }

    @Test void everyRecoveryCrashPointFiresOnceInOrderOfTheFiles() throws Exception {
        String tmpRe = "state\\.lock\\.tmp-" + PID + "-[0-9a-f]{12}";
        String[][] points = {
            // point, state.lock.2 present?, fence written?, state.lock.3 present?, a lock temp present?
            {"before-lock", "n", "n", "n", "n"},
            {"after-lock-temp", "n", "n", "n", "y"},
            {"after-lock", "y", "n", "n", "n"},
            {"after-fence-temp", "y", "n", "n", "n"},
            {"after-fence", "y", "y", "n", "n"},
            {"after-release-temp", "y", "y", "n", "y"},
            {"after-release", "y", "y", "y", "n"},
        };
        for (String[] p : points) {
            File d = tmp();
            foreignLock(d, 1);
            List<String> seen = new ArrayList<>();
            List<String> hits = withHook(p[0], () -> {
                seen.add(exists(d, "state.lock.2") ? "y" : "n");
                seen.add(matching(d, "state\\.fence\\.2-[0-9a-f]{12}").size() == 1 ? "y" : "n");
                seen.add(exists(d, "state.lock.3") ? "y" : "n");
                List<String> tmps = matching(d, "state\\.lock\\.tmp-.*");
                for (String t : tmps) assertTrue(t.matches(tmpRe), t);
                seen.add(tmps.size() == 1 ? "y" : "n");
            }, () -> assertTrue(recover(d, foreign()).released));
            assertEquals(Collections.singletonList(p[0]), hits);
            assertEquals(Arrays.asList(p[1], p[2], p[3], p[4]), seen, p[0]);
            assertEquals(Collections.emptyList(), matching(d, "state\\.lock\\.tmp-.*"), p[0]);
        }
    }

    @Test void aRecoveryHookNeedsBothSwitches() throws Exception {
        for (UnaryOperator<String> env : Arrays.asList(armedAt("0", "after-lock"), armedAt("1", "nowhere"))) {
            File d = tmp();
            foreignLock(d, 1);
            assertEquals(Collections.emptyList(), withHook(env, "after-lock", () -> { }, () -> assertTrue(recover(d, foreign()).released)));
        }
    }

    @Test void aGenerationCreatedUnderTheRecoveryIsASupersede() throws Exception {
        File d = tmp();
        foreignLock(d, 1);
        withHook("after-release-temp", () -> write(d, "state.lock.3", "{\"st\":\"free\"}"), () -> {
            DurableStateError e = assertThrows(DurableStateError.class, () -> recover(d, foreign()));
            assertEquals("invalid: " + lockPath(d, 1) + " was superseded while recovering; re-read the lock state and retry", e.getMessage());
        });
        assertEquals(Collections.emptyList(), matching(d, "state\\.lock\\.tmp-.*"));
    }

    @Test void aLinkFailureOtherThanSupersedeIsAnIoError() throws Exception {
        File d = tmp();
        foreignLock(d, 1);
        withHook("after-lock-temp", () -> { for (String t : matching(d, "state\\.lock\\.tmp-.*")) Files.delete(new File(d, t).toPath()); },
            () -> assertThrows(UncheckedIOException.class, () -> recover(d, foreign())));
        assertFalse(exists(d, "state.lock.2"));
    }

    @Test void aDirectoryThatCannotBeListedFailsTheCutWithAnIoError() throws Exception {
        File d = tmp();
        foreignLock(d, 1);
        withHook("after-lock", () -> deleteTree(d), () -> {
            UncheckedIOException e = assertThrows(UncheckedIOException.class, () -> recover(d, foreign()));
            assertNotNull(e.getCause());
            assertEquals("cannot list " + d.getPath(), e.getCause().getMessage());
        });
    }
}
