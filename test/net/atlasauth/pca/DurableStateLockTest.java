package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The durable state store's lock, process and platform side: who holds the lock and how it is judged, the lock files and their
 * garbage collection, the open-time link probe, the hostname / PID-namespace / process-start sources, the low-level file helpers
 * and the test-only crash hooks. Everything here runs on Linux and Windows; a check that only one OS can answer is chosen per OS.
 */
@Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class DurableStateLockTest {
    private static final long DEAD = 999_999_999L;
    private static final long PID = ProcessHandle.current().pid();
    private static final String HOST = DurableState.hostname();
    private static final String OS = System.getProperty("os.name", "").toLowerCase();
    private static final boolean LINUX = OS.contains("linux");
    private static final boolean WINDOWS = OS.contains("win");

    // ---- helpers ----

    private static File tmp() throws IOException { return Files.createTempDirectory("pca-ds-lock-").toFile(); }

    private static DurableState.Options opts(File d) {
        DurableState.Options o = new DurableState.Options(d.getPath());
        o.lockTimeoutMs = 2000;
        return o;
    }

    private static DurableState open(File d) { return DurableState.open(opts(d)); }

    private static Json.Num num(String s) { return new Json.Num(s); }

    private static String read(File d, String f) {
        try {
            return new String(Files.readAllBytes(new File(d, f).toPath()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void write(File d, String f, String text) {
        try {
            Files.write(new File(d, f).toPath(), text.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static boolean has(File d, String f) { return new File(d, f).exists(); }

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

    private static List<Long> gens(File d) {
        List<Long> out = new ArrayList<>();
        for (String n : names(d)) if (n.matches("state\\.lock\\.\\d{1,18}")) out.add(Long.parseLong(n.substring("state.lock.".length())));
        return out;
    }

    private static long top(File d) {
        long g = 0;
        for (long x : gens(d)) g = Math.max(g, x);
        return g;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    private static String holder(long pid, String nonce, String extra) {
        return "{\"st\":\"held\",\"pid\":" + pid + ",\"host\":\"" + HOST + "\",\"nonce\":\"" + nonce + "\"" + extra + "}";
    }

    /** Field 22 of /proc/&lt;pid&gt;/stat (the process start time), read independently; null where there is no /proc. */
    private static String startOracle(long pid) {
        try {
            String st = new String(Files.readAllBytes(Paths.get("/proc/" + pid + "/stat")), StandardCharsets.UTF_8);
            return st.substring(st.lastIndexOf(')') + 1).trim().split("\\s+")[19]; // fields after ")" start at field 3
        } catch (Exception e) {
            return null;
        }
    }

    private static String nsOracle() {
        try {
            return Files.readSymbolicLink(Paths.get("/proc/self/ns/pid")).toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static Method method(String name, Class<?>... types) throws NoSuchMethodException {
        Method mt = DurableState.class.getDeclaredMethod(name, types);
        mt.setAccessible(true);
        return mt;
    }

    private static Object invoke(Method mt, Object target, Object... args) throws Throwable {
        try {
            return mt.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private static Field hostnameCache() throws NoSuchFieldException {
        Field f = DurableState.class.getDeclaredField("hostnameCache");
        f.setAccessible(true);
        return f;
    }

    /** The holder record of the generation this handle holds, read from disk while it holds it. */
    private static Map<String, Object> heldBody(DurableState s, File d) {
        String[] raw = new String[1];
        s.update("probe-key", p -> {
            raw[0] = read(d, "state.lock." + top(d));
            return null;
        });
        return m(Json.parseLenient(raw[0]));
    }

    // ---- options and opening ----

    @Test void theOptionDefaultsAreTheDocumentedOnes() {
        DurableState.Options o = new DurableState.Options("x");
        assertEquals(10_000L, o.lockTimeoutMs);
        assertEquals(256, o.compactEvery);
        assertEquals(1_048_576, o.maxValueBytes);
    }

    @Test void aMissingOrEmptyDirIsRefused() {
        for (String dir : Arrays.asList(null, "")) {
            DurableStateError e = assertThrows(DurableStateError.class, () -> DurableState.open(new DurableState.Options(dir)));
            assertEquals("invalid: dir is required", e.getMessage());
        }
    }

    @Test void aDirThatIsARegularFileFailsWithTheIoError() throws Exception {
        File f = new File(tmp(), "a-file");
        Files.write(f.toPath(), new byte[] {1});
        UncheckedIOException e = assertThrows(UncheckedIOException.class, () -> DurableState.open(opts(f)));
        assertTrue(e.getCause() instanceof FileAlreadyExistsException, String.valueOf(e.getCause()));
    }

    @Test void anExistingDirectoryIsTightenedToOwnerOnly() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"), "POSIX permissions only");
        File d = tmp();
        Files.setPosixFilePermissions(d.toPath(), PosixFilePermissions.fromString("rwxr-xr-x"));
        open(d);
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(d.toPath())));
    }

    @Test void theHmacKeyMustBeAtLeast32Bytes() throws Exception {
        DurableState.Options o = opts(tmp());
        o.hmacKey = new byte[31];
        assertEquals("invalid: hmacKey must be at least 32 bytes", assertThrows(DurableStateError.class, () -> DurableState.open(o)).getMessage());
        o.hmacKey = new byte[32];
        DurableState.open(o).set("a", num("1"));
    }

    @Test void compactEveryHasAFloorOfTwo() throws Exception {
        File d = tmp();
        DurableState.Options o = opts(d);
        o.compactEvery = 1;
        DurableState s = DurableState.open(o);
        for (int i = 1; i <= 3; i++) s.set("k" + i, num(Integer.toString(i)));
        String[] lines = read(d, "state.journal").split("\n");
        assertEquals(1, lines.length, read(d, "state.journal"));
        assertTrue(lines[0].contains("\"op\":\"checkpoint\""), lines[0]);
    }

    // ---- what opening does to the existing state ----

    @Test void openingObservesThePositionOnDisk() throws Exception {
        File d = tmp();
        DurableState s1 = open(d);
        s1.set("a", num("1"));
        s1.set("b", num("2"));
        DurableState s2 = open(d);
        assertEquals(2L, s2.position().seq);
        assertEquals(s1.position().hash, s2.position().hash);
    }

    @Test void openingRepairsAHeadOneRecordBehind() throws Exception {
        File d = tmp();
        DurableState s1 = open(d);
        s1.set("a", num("1"));
        String behind = read(d, "state.head");
        s1.set("b", num("2"));
        write(d, "state.head", behind);
        open(d);
        Map<String, Object> head = m(Json.parseLenient(read(d, "state.head")));
        assertEquals(2L, IntentJs.lng(head.get("seq")));
        assertEquals(s1.position().hash, head.get("h"));
    }

    @Test void openingLeavesAHeadInStepUntouched() throws Exception {
        File d = tmp();
        DurableState s1 = open(d);
        s1.set("a", num("1"));
        s1.set("b", num("2"));
        String head = read(d, "state.head");
        open(d);
        assertEquals(head, read(d, "state.head"));
    }

    // ---- the holder record ----

    @Test void theHeldGenerationNamesThisProcessExactly() throws Exception {
        File d = tmp();
        DurableState s = open(d);
        long before = System.currentTimeMillis();
        Map<String, Object> b = heldBody(s, d);
        long after = System.currentTimeMillis();
        String ns = nsOracle();
        String start = startOracle(PID);
        if (LINUX) {
            assertNotNull(ns);
            assertNotNull(start);
        }
        List<String> keys = new ArrayList<>(Arrays.asList("st", "pid", "host", "nonce", "boot"));
        if (ns != null) keys.add("ns");
        if (start != null) keys.add("start");
        keys.add("t");
        assertEquals(keys, new ArrayList<>(b.keySet()));
        assertEquals("held", b.get("st"));
        assertEquals(PID, IntentJs.lng(b.get("pid")));
        assertEquals(HOST, b.get("host"));
        assertTrue(((String) b.get("nonce")).matches("[0-9a-f]{24}"), String.valueOf(b.get("nonce")));
        assertTrue(((String) b.get("boot")).matches("[0-9a-f]{24}"), String.valueOf(b.get("boot")));
        if (ns != null) assertEquals(ns, b.get("ns"));
        if (start != null) assertEquals(start, b.get("start"));
        long t = IntentJs.lng(b.get("t"));
        assertTrue(t >= before && t <= after, t + " not in [" + before + ", " + after + "]");
        Map<String, Object> b2 = heldBody(s, d);
        assertNotEquals(b.get("nonce"), b2.get("nonce"));
        assertEquals(b.get("boot"), b2.get("boot"));
        // the release is a "free" generation right above, and no takeover fence was written
        Map<String, Object> rel = m(Json.parseLenient(read(d, "state.lock." + top(d))));
        assertEquals("free", rel.get("st"));
        assertEquals(Collections.emptyList(), matching(d, "state\\.fence.*"));
    }

    @Test void takingOverARecoveringHolderCarriesItsMarkAndFencesFirst() throws Exception {
        File d = tmp();
        DurableState s = open(d);
        long g = top(d);
        write(d, "state.lock." + (g + 1), holder(DEAD, "n", ",\"recovering\":" + g));
        Map<String, Object> b = heldBody(s, d);
        assertEquals(g, IntentJs.lng(b.get("recovering")));
        assertEquals("held", b.get("st"));
        assertEquals(PID, IntentJs.lng(b.get("pid")));
        List<String> fences = matching(d, "state\\.fence.*");
        assertEquals(1, fences.size(), fences.toString());
        assertTrue(fences.get(0).matches("state\\.fence\\." + (g + 2) + "-[0-9a-f]{12}"), fences.get(0));
        Map<String, Object> f = m(m(Json.parseLenient(read(d, fences.get(0)))).get("fence"));
        assertEquals(g + 2, IntentJs.lng(f.get("gen")));
        assertEquals(g + 1, IntentJs.lng(f.get("from")));
    }

    @Test void aFreeTopWithARecoveringMarkIsNoTakeover() throws Exception {
        File d = tmp();
        DurableState s = open(d);
        long g = top(d);
        write(d, "state.lock." + (g + 1), "{\"st\":\"free\",\"recovering\":3}");
        Map<String, Object> b = heldBody(s, d);
        assertFalse(b.containsKey("recovering"), b.toString());
        assertEquals(Collections.emptyList(), matching(d, "state\\.fence.*"));
    }

    // ---- waiting for the lock and timing out ----

    private static String timeoutMessage(File d) {
        DurableState.Options o = new DurableState.Options(d.getPath());
        o.lockTimeoutMs = 150;
        DurableStateError e = assertThrows(DurableStateError.class, () -> DurableState.open(o));
        assertEquals("lock-timeout", e.code());
        return e.getMessage();
    }

    private static String legacyMsg(File d, String desc) {
        return "lock-timeout: could not acquire the state lock in " + d.getPath() + " within 150 ms; blocked by " + new File(d, "state.lock").getPath()
            + " (legacy single-file lock of an older version; " + desc
            + "). If that holder is provably gone, an operator can release it with recoverDurableState({ dir, force: true, legacyLock: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs";
    }

    private static String genMsg(File d, long g, String desc) {
        return "lock-timeout: could not acquire the state lock in " + d.getPath() + " within 150 ms; blocked by " + new File(d, "state.lock." + g).getPath() + " (" + desc
            + "). If that holder is provably gone (e.g. a crashed container in another PID namespace), an operator can release it with recoverDurableState({ dir, force: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs";
    }

    private static String live(String nonce) { return "holder pid=" + PID + " host=" + HOST + " nonce=" + nonce; }

    @Test void aLiveLegacyHolderBlocksAndIsNamedInTheTimeout() throws Exception {
        File d = tmp();
        write(d, "state.lock", holder(PID, "n", ""));
        // a readable record is judged by its holder, never by the file's age
        assertTrue(new File(d, "state.lock").setLastModified(System.currentTimeMillis() - 3_600_000L));
        assertEquals(legacyMsg(d, live("n")), timeoutMessage(d));
    }

    @Test void aLiveLegacyHolderAboveAFreeGenerationIsTheBlocker() throws Exception {
        File d = tmp();
        write(d, "state.lock", holder(PID, "n", ""));
        write(d, "state.lock.1", "{\"st\":\"free\"}");
        assertEquals(legacyMsg(d, live("n")), timeoutMessage(d));
    }

    @Test void aLiveGenerationHolderIsNamedInTheTimeout() throws Exception {
        File d = tmp();
        write(d, "state.lock.1", holder(PID, "m", ""));
        assertEquals(genMsg(d, 1, live("m")), timeoutMessage(d));
    }

    @Test void aLiveGenerationHolderIsTheBlockerEvenWithALiveLegacyLock() throws Exception {
        File d = tmp();
        write(d, "state.lock", holder(PID, "n", ""));
        write(d, "state.lock.1", holder(PID, "m", ""));
        assertEquals(genMsg(d, 1, live("m")), timeoutMessage(d));
    }

    @Test void aDeadGenerationHolderLeavesTheLegacyLockAsTheBlocker() throws Exception {
        File d = tmp();
        write(d, "state.lock", holder(PID, "n", ""));
        write(d, "state.lock.1", holder(DEAD, "m", ""));
        assertEquals(legacyMsg(d, live("n")), timeoutMessage(d));
    }

    @Test void aFreshUnreadableLegacyLockBlocks() throws Exception {
        File d = tmp();
        write(d, "state.lock", "{");
        // a modification time in the future keeps it "fresh" however slow this runner is
        assertTrue(new File(d, "state.lock").setLastModified(System.currentTimeMillis() + 60_000L));
        assertEquals(legacyMsg(d, "an unreadable holder record"), timeoutMessage(d));
    }

    @Test void anUnreadableLegacyLockOlderThanASecondIsDead() throws Exception {
        File d = tmp();
        write(d, "state.lock", "{");
        assertTrue(new File(d, "state.lock").setLastModified(System.currentTimeMillis() - 3_600_000L));
        DurableState s = open(d);
        s.set("a", num("1"));
        assertEquals(1L, IntentJs.lng(s.get("a")));
        assertTrue(has(d, "state.lock"));
    }

    @Test void aWaiterGetsTheLockOnceTheHolderReleasesIt() throws Exception {
        File d = tmp();
        DurableState.Options o = opts(d);
        o.lockTimeoutMs = 5000;
        DurableState s = DurableState.open(o);
        long g = top(d);
        write(d, "state.lock." + (g + 1), holder(PID, "n", ""));
        Thread releaser = new Thread(() -> {
            try {
                Thread.sleep(150);
            } catch (InterruptedException e) {
                return;
            }
            write(d, "state.lock." + (g + 2), "{\"st\":\"free\"}");
        });
        long t0 = System.currentTimeMillis();
        releaser.start();
        s.set("a", num("1"));
        releaser.join();
        assertTrue(System.currentTimeMillis() - t0 >= 100, "acquired before the holder released");
        assertEquals(1L, IntentJs.lng(s.get("a")));
        assertEquals(g + 6, top(d)); // set: g+3 held, g+4 free; get: g+5 held, g+6 free
    }

    @Test void anInterruptedWaiterFailsAndKeepsTheInterrupt() throws Exception {
        File d = tmp();
        DurableState.Options o = opts(d);
        o.lockTimeoutMs = 5000;
        DurableState s = DurableState.open(o);
        write(d, "state.lock." + (top(d) + 1), holder(PID, "n", ""));
        DurableStateError e;
        boolean stillInterrupted;
        Thread.currentThread().interrupt();
        try {
            e = assertThrows(DurableStateError.class, () -> s.get("a"));
        } finally {
            stillInterrupted = Thread.interrupted();
        }
        assertTrue(stillInterrupted, "the interrupt status was swallowed");
        assertEquals("lock-timeout: interrupted while waiting for the state lock in " + d.getPath(), e.getMessage());
    }

    @Test void aGenerationCreatedAboveOursWhileTakingTheLockSendsUsRoundAgain() throws Exception {
        File d = tmp();
        DurableState s = open(d);
        long g = top(d);
        Field cache = hostnameCache();
        Object saved = cache.get(null);
        DurableState.Thrower prev = DurableState.HOSTNAME_SOURCES[0];
        AtomicBoolean planted = new AtomicBoolean();
        // hostname() is asked while the holder record is built, after the top was read and before generation g+1 is linked
        DurableState.HOSTNAME_SOURCES[0] = () -> {
            if (planted.compareAndSet(false, true)) write(d, "state.lock." + (g + 2), "{\"st\":\"free\"}");
            return HOST;
        };
        try {
            cache.set(null, null);
            s.set("a", num("1"));
        } finally {
            DurableState.HOSTNAME_SOURCES[0] = prev;
            cache.set(null, saved);
        }
        assertTrue(planted.get());
        assertEquals(g + 4, top(d)); // g+1 (buried), g+2 (planted), g+3 held, g+4 released
        assertEquals("free", m(Json.parseLenient(read(d, "state.lock." + (g + 4)))).get("st"));
        assertEquals(1L, IntentJs.lng(s.get("a")));
    }

    // ---- the lock re-check before every rename ----

    private interface Tamper { void apply(File d, long g, String text); }

    /** Tamper with the held generation inside an update, then let it commit: the journal rename must be refused, nothing written. */
    private static void lockLost(Tamper tamper, String highest) throws Exception {
        File d = tmp();
        DurableState s = open(d);
        s.set("k", num("1"));
        String journal = read(d, "state.journal");
        long[] held = new long[1];
        DurableStateError e = assertThrows(DurableStateError.class, () -> s.update("k", p -> {
            held[0] = top(d);
            tamper.apply(d, held[0], read(d, "state.lock." + held[0]));
            return num("2");
        }));
        long g = held[0];
        String hi = highest.replace("$G+1", Long.toString(g + 1)).replace("$G", Long.toString(g));
        assertEquals("lock-lost: the state lock is no longer held by this writer (generation " + g + ", highest " + hi + "); nothing was written", e.getMessage());
        assertEquals(journal, read(d, "state.journal"));
        assertEquals(Collections.emptyList(), matching(d, ".*\\.tmp-.*"));
    }

    private static String withMember(String body, String k, String v) {
        Map<String, Object> b = m(Json.parseLenient(body));
        b.put(k, v);
        return Json.stringify(b);
    }

    @Test void aHigherGenerationMeansTheLockIsLost() throws Exception {
        lockLost((d, g, text) -> write(d, "state.lock." + (g + 1), text), "$G+1 held");
    }

    @Test void anUnreadableOwnGenerationMeansTheLockIsLost() throws Exception {
        lockLost((d, g, text) -> write(d, "state.lock." + g, "garbage"), "$G unreadable");
    }

    @Test void aFreedOwnGenerationMeansTheLockIsLost() throws Exception {
        lockLost((d, g, text) -> write(d, "state.lock." + g, withMember(text, "st", "free")), "$G free");
    }

    @Test void anotherNonceInTheOwnGenerationMeansTheLockIsLost() throws Exception {
        lockLost((d, g, text) -> write(d, "state.lock." + g, withMember(text, "nonce", "someone-else")), "$G held");
    }

    @Test void theReCheckRefusesOutsideAHeldLock() throws Throwable {
        File d = tmp();
        DurableState s = open(d);
        s.set("k", num("1"));
        long free = top(d);
        Files.delete(new File(d, "state.lock." + free).toPath()); // the top is again the generation this handle held, naming its old nonce
        Method check = method("assertLockHeld", String.class);
        DurableStateError e = assertThrows(DurableStateError.class, () -> invoke(check, s, "x"));
        assertEquals("lock-lost: the state lock is no longer held by this writer (generation " + (free - 1) + ", highest " + (free - 1) + " held); x", e.getMessage());
    }

    // ---- judging a holder ----

    @Test void theHolderDescriptionNamesWhatIsMissing() throws Throwable {
        DurableState s = open(tmp());
        Method desc = method("desc", Map.class);
        String inc = "); release it with expectedHolder: 'unreadable'";
        assertEquals("an unreadable holder record", invoke(desc, s, (Object) null));
        assertEquals("holder pid=5 host=h nonce=n", invoke(desc, s, map("pid", 5L, "host", "h", "nonce", "n")));
        assertEquals("holder pid=5 host=h nonce=n (another PID namespace)", invoke(desc, s, map("pid", 5L, "host", "h", "nonce", "n", "ns", "pid:[0]")));
        String ns = nsOracle();
        if (ns != null) assertEquals("holder pid=5 host=h nonce=n", invoke(desc, s, map("pid", 5L, "host", "h", "nonce", "n", "ns", ns)));
        assertEquals("an incomplete holder record (pid=? host=h nonce=n" + inc, invoke(desc, s, map("host", "h", "nonce", "n")));
        assertEquals("an incomplete holder record (pid=5 host=? nonce=n" + inc, invoke(desc, s, map("pid", 5L, "nonce", "n")));
        assertEquals("an incomplete holder record (pid=5 host=h nonce=?" + inc, invoke(desc, s, map("pid", 5L, "host", "h")));
        assertEquals("an incomplete holder record (pid=5 host=h nonce=?" + inc, invoke(desc, s, map("pid", 5L, "host", "h", "nonce", "")));
        assertEquals("an incomplete holder record (pid=5 host=h nonce=?" + inc, invoke(desc, s, map("pid", 5L, "host", "h", "nonce", 7L)));
    }

    @Test void aHolderIsDeadOnlyWhenThisHostCanProveIt() throws Throwable {
        DurableState s = open(tmp());
        Method mt = method("holderDead", Map.class, long.class);
        assertFalse((Boolean) invoke(mt, s, null, 1000L), "an unreadable legacy file of exactly 1 s");
        assertTrue((Boolean) invoke(mt, s, null, 1001L), "an unreadable legacy file older than 1 s");
        assertTrue((Boolean) invoke(mt, s, map("pid", DEAD, "host", HOST), 0L));
        assertFalse((Boolean) invoke(mt, s, map("pid", DEAD, "host", "another-host"), 0L));
        assertFalse((Boolean) invoke(mt, s, map("pid", "123", "host", HOST), 0L));
        assertFalse((Boolean) invoke(mt, s, map("pid", DEAD, "host", HOST, "ns", "pid:[0]"), 0L), "another PID namespace");
        String ns = nsOracle();
        if (ns != null) assertTrue((Boolean) invoke(mt, s, map("pid", DEAD, "host", HOST, "ns", ns), 0L), "this PID namespace");
        assertFalse((Boolean) invoke(mt, s, map("pid", PID, "host", HOST), 0L));
        String start = startOracle(PID);
        // a start time that is not the live process's own: the pid was reused (judgeable only where the start time is readable)
        assertEquals(start != null, invoke(mt, s, map("pid", PID, "host", HOST, "start", "bogus"), 0L));
        if (start != null) assertFalse((Boolean) invoke(mt, s, map("pid", PID, "host", HOST, "start", start), 0L));
        assertFalse((Boolean) invoke(mt, s, map("pid", PID, "host", HOST, "start", 5L), 0L));
    }

    @Test void aHolderIsAliveHereOnlyWhenJudgeableAndRunning() throws Throwable {
        Method mt = method("holderAliveHere", Object.class);
        assertFalse((Boolean) invoke(mt, null, "a string"));
        assertFalse((Boolean) invoke(mt, null, new ArrayList<Object>()));
        assertFalse((Boolean) invoke(mt, null, map("host", HOST)));
        assertTrue((Boolean) invoke(mt, null, map("pid", PID, "host", HOST)));
        assertFalse((Boolean) invoke(mt, null, map("pid", PID, "host", "another-host")));
        assertFalse((Boolean) invoke(mt, null, map("pid", PID, "host", HOST, "ns", "pid:[0]")));
        assertTrue((Boolean) invoke(mt, null, map("pid", PID, "host", HOST, "ns", 5L)), "a non-string ns falls back to the hostname");
        String ns = nsOracle();
        if (ns != null) assertTrue((Boolean) invoke(mt, null, map("pid", PID, "host", "another-host", "ns", ns)), "this PID namespace, whatever the hostname");
        assertFalse((Boolean) invoke(mt, null, map("pid", DEAD, "host", HOST)));
        String start = startOracle(PID);
        assertEquals(start == null, invoke(mt, null, map("pid", PID, "host", HOST, "start", "bogus")));
        if (start != null) assertTrue((Boolean) invoke(mt, null, map("pid", PID, "host", HOST, "start", start)));
        assertTrue((Boolean) invoke(mt, null, map("pid", PID, "host", HOST, "start", 5L)));
    }

    // ---- collecting old lock files ----

    @Test void lockGenerationsAreCollectedBehindAWindow() throws Exception {
        File d = tmp();
        DurableState s = open(d);
        for (int i = 0; i < 9; i++) s.set("k", num(Integer.toString(i))); // open took 1-2, each set two more: 20 now
        long[] inside = new long[2];
        s.update("k", p -> {
            List<Long> gs = gens(d);
            inside[0] = Collections.max(gs);
            inside[1] = Collections.min(gs);
            return null;
        });
        assertEquals(21L, inside[0]);
        assertEquals(21L - 16, inside[1]);
        List<Long> after = gens(d);
        assertEquals(22L, (long) Collections.max(after));
        assertEquals(22L - 16, (long) Collections.min(after));
    }

    @Test void staleLockTempsOfDeadProcessesAreCollectedAndNothingElse() throws Exception {
        File d = tmp();
        String[] gone = {"state.lock.tmp-" + DEAD + "-aa", "state.lock.tmp-" + DEAD + "-bb"};
        // "state.lock.tmp--aa" sorts before the dead temps where the directory lists in name order (NTFS)
        String[] kept = {"state.lock.tmp--aa", "state.lock.tmp-0-aa", "state.lock.tmp-" + PID + "-aa", "state.lock.tmp-99999999999999999999-aa", "xstate.lock.tmp-" + DEAD + "-aa",
            "state.lock.99999999999999999999"};
        for (String n : gone) write(d, n, "x");
        for (String n : kept) write(d, n, "x");
        open(d).set("a", num("1"));
        for (String n : gone) assertFalse(has(d, n), n);
        for (String n : kept) assertTrue(has(d, n), n);
    }

    // ---- hard links: the open-time probe and the lock generations ----

    private static final DurableState.Linker REAL = DurableState.linker;
    private static final String LINK_HEAD = "link-unsupported: the state directory's filesystem does not provide working hard links with exclusive-create semantics (";
    private static final String LINK_TAIL = "); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS), not NFS/SMB/FUSE";

    private static DurableStateError openWith(File d, DurableState.Linker l) {
        DurableState.Linker prev = DurableState.linker;
        DurableState.linker = l;
        try {
            return assertThrows(DurableStateError.class, () -> DurableState.open(opts(d)));
        } finally {
            DurableState.linker = prev;
        }
    }

    @Test void theProbeAndTheLockLinkFreshTempsOfTheirOwn() throws Exception {
        File d = tmp();
        List<Path[]> calls = new ArrayList<>();
        DurableState.Linker prev = DurableState.linker;
        DurableState.linker = (n, x) -> {
            calls.add(new Path[] {n, x});
            prev.link(n, x);
        };
        try {
            open(d);
        } finally {
            DurableState.linker = prev;
        }
        assertEquals(4, calls.size()); // the probe twice, then generation 1 (taken) and 2 (released)
        String a = calls.get(0)[1].getFileName().toString();
        assertTrue(a.matches("state\\.probe-" + PID + "-[0-9a-f]{12}"), a);
        for (int i = 0; i < 2; i++) {
            assertEquals(a + ".lnk", calls.get(i)[0].getFileName().toString());
            assertEquals(a, calls.get(i)[1].getFileName().toString());
        }
        for (int i = 2; i < 4; i++) {
            assertEquals("state.lock." + (i - 1), calls.get(i)[0].getFileName().toString());
            assertTrue(calls.get(i)[1].getFileName().toString().matches("state\\.lock\\.tmp-" + PID + "-[0-9a-f]{12}"), calls.get(i)[1].toString());
        }
        for (Path[] c : calls) {
            assertEquals(d.toPath(), c[0].getParent());
            assertEquals(d.toPath(), c[1].getParent());
        }
        assertEquals(Collections.emptyList(), matching(d, "state\\.(probe|lock\\.tmp)-.*")); // every temp is gone
    }

    @Test void aFilesystemWhoseSecondLinkAlsoSucceedsIsRefused() throws Exception {
        File d = tmp();
        AtomicInteger calls = new AtomicInteger();
        DurableStateError e = openWith(d, (n, x) -> {
            if (calls.getAndIncrement() == 0) REAL.link(n, x);
        });
        assertEquals(LINK_HEAD + "link(2) is not atomic/exclusive here" + LINK_TAIL, e.getMessage());
        assertEquals(Collections.emptyList(), matching(d, "state\\.probe-.*"));
    }

    @Test void aSecondLinkFailingOtherwiseThanExistsIsRefused() throws Exception {
        File d = tmp();
        AtomicInteger calls = new AtomicInteger();
        DurableStateError e = openWith(d, (n, x) -> {
            if (calls.getAndIncrement() == 0) REAL.link(n, x);
            else throw new IOException("not here");
        });
        assertEquals(LINK_HEAD + "link(2) is not atomic/exclusive here" + LINK_TAIL, e.getMessage());
        assertEquals(Collections.emptyList(), matching(d, "state\\.probe-.*"));
    }

    @Test void aFirstLinkThatFailsNamesTheError() throws Exception {
        File d = tmp();
        DurableStateError e = openWith(d, (n, x) -> {
            throw new IOException("boom");
        });
        assertEquals(LINK_HEAD + "IOException" + LINK_TAIL, e.getMessage());
        assertEquals(Collections.emptyList(), matching(d, "state\\.probe-.*"));
    }

    @Test void aLinkThatDoesNotRaiseTheLinkCountIsRefused() throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("unix"), "needs the unix:nlink attribute");
        File d = tmp();
        AtomicInteger calls = new AtomicInteger();
        DurableStateError e = openWith(d, (n, x) -> {
            if (calls.getAndIncrement() > 0) throw new FileAlreadyExistsException(n.toString()); // "exclusive", yet no link was made
        });
        assertEquals(LINK_HEAD + "link(2) is not atomic/exclusive here" + LINK_TAIL, e.getMessage());
    }

    @Test void aLockLinkThatFailsIsAnUnfitFilesystemAndLeavesNoTemp() throws Exception {
        File d = tmp();
        DurableState s = open(d);
        DurableState.Linker prev = DurableState.linker;
        try {
            DurableState.linker = (n, x) -> {
                throw new IOException("no");
            };
            assertEquals("invalid: the state directory's filesystem cannot create the lock atomically (link: IOException)", assertThrows(DurableStateError.class, () -> s.set("a", num("1"))).getMessage());
            DurableState.linker = (n, x) -> {
                throw new UnsupportedOperationException("no");
            };
            assertEquals("invalid: the state directory's filesystem cannot create the lock atomically (link: UnsupportedOperationException)",
                assertThrows(DurableStateError.class, () -> s.set("a", num("1"))).getMessage());
        } finally {
            DurableState.linker = prev;
        }
        assertEquals(Collections.emptyList(), matching(d, "state\\.lock\\.tmp-.*"));
        s.set("a", num("1"));
        assertEquals(1L, IntentJs.lng(s.get("a")));
    }

    // ---- the takeover crash hooks (armed in-process: the halter records instead of halting) ----

    private static List<List<String>> armTakeover(String flag, String point) throws Exception {
        File d = tmp();
        DurableState s = open(d);
        long g = top(d);
        write(d, "state.lock." + (g + 1), holder(DEAD, "n", ",\"recovering\":" + g));
        List<List<String>> halts = new ArrayList<>();
        Map<String, String> env = new HashMap<>();
        env.put("PCA_DURABLE_TEST", flag);
        env.put(DurableState.RECOVER_CRASH_ENV, point);
        Runnable prevHalter = DurableState.crashHalter;
        UnaryOperator<String> prevEnv = DurableState.crashEnv;
        String prevProp = System.getProperty(DurableState.CRASH_CHILD_PROPERTY);
        DurableState.crashHalter = () -> {
            halts.add(names(d));
            throw new IllegalStateException("halted");
        };
        DurableState.crashEnv = env::get;
        try {
            System.setProperty(DurableState.CRASH_CHILD_PROPERTY, "1");
            try {
                s.get("a");
            } catch (IllegalStateException e) {
                assertEquals("halted", e.getMessage());
            }
        } finally {
            DurableState.crashHalter = prevHalter;
            DurableState.crashEnv = prevEnv;
            if (prevProp == null) System.clearProperty(DurableState.CRASH_CHILD_PROPERTY); else System.setProperty(DurableState.CRASH_CHILD_PROPERTY, prevProp);
        }
        return halts;
    }

    private static boolean any(List<String> names, String regex) {
        for (String n : names) if (n.matches(regex)) return true;
        return false;
    }

    @Test void theTakeoverHaltsRightAfterTakingTheLockWhenArmedThere() throws Exception {
        List<List<String>> halts = armTakeover("1", "takeover-after-lock");
        assertEquals(1, halts.size());
        assertFalse(any(halts.get(0), "state\\.fence.*"), halts.toString()); // before any fence file
    }

    @Test void theTakeoverHaltsWithTheFenceTempWrittenWhenArmedThere() throws Exception {
        List<List<String>> halts = armTakeover("1", "takeover-after-fence-temp");
        assertEquals(1, halts.size());
        assertTrue(any(halts.get(0), "state\\.fence\\.\\d+-[0-9a-f]{12}\\.tmp-\\d+-[0-9a-f]{12}"), halts.toString());
        assertFalse(any(halts.get(0), "state\\.fence\\.\\d+-[0-9a-f]{12}"), halts.toString());
    }

    @Test void theTakeoverHooksStayQuietUnlessBothSwitchesMatch() throws Exception {
        assertEquals(Collections.emptyList(), armTakeover("0", "takeover-after-lock"));
        assertEquals(Collections.emptyList(), armTakeover("1", "before-lock"));
    }

    // ---- low-level file helpers ----

    private static void assertIoCause(Throwable e) {
        assertTrue(e instanceof UncheckedIOException, String.valueOf(e));
        assertTrue(e.getCause() instanceof IOException, String.valueOf(e.getCause()));
    }

    @Test void theFileHelpersFailWithTheIoError() throws Throwable {
        File d = tmp();
        Method writeNew = method("writeNew", String.class, String.class);
        Method move = method("move", String.class, String.class);
        Method link = method("link", String.class, String.class);
        String missing = new File(d, "missing").getPath();
        String x = new File(d, "x").getPath();
        invoke(writeNew, null, x, "data");
        assertEquals("data", read(d, "x"));
        assertIoCause(assertThrows(Throwable.class, () -> invoke(writeNew, null, x, "again")));
        assertIoCause(assertThrows(Throwable.class, () -> invoke(writeNew, null, new File(missing, "y").getPath(), "z")));
        assertIoCause(assertThrows(Throwable.class, () -> invoke(move, null, missing, new File(d, "m").getPath())));
        assertIoCause(assertThrows(Throwable.class, () -> invoke(link, null, new File(d, "l").getPath(), missing)));
        invoke(link, null, new File(d, "l").getPath(), x);
        assertEquals("data", read(d, "l"));
        invoke(move, null, x, new File(d, "moved").getPath());
        assertEquals("data", read(d, "moved"));
        assertFalse(has(d, "x"));
    }

    @Test void fsyncOfAMissingDirectoryFailsExceptOnWindows() throws Exception {
        File d = tmp();
        DurableState.fsyncDir(d.getPath());
        String missing = new File(d, "missing").getPath();
        if (WINDOWS) DurableState.fsyncDir(missing); // a directory cannot be opened for fsync there: skipped
        else assertIoCause(assertThrows(UncheckedIOException.class, () -> DurableState.fsyncDir(missing)));
    }

    @Test void atomicWriteRenamesAFreshTempAfterTheCheckAndCleansUpWhenItFails() throws Throwable {
        File d = tmp();
        Method aw = method("atomicWrite", String.class, String.class, Runnable.class, boolean.class);
        String path = new File(d, "f").getPath();
        List<List<String>> seen = new ArrayList<>();
        invoke(aw, null, path, "one", (Runnable) () -> seen.add(names(d)), false);
        assertEquals(1, seen.size());
        assertEquals(1, seen.get(0).size(), seen.toString());
        assertTrue(seen.get(0).get(0).matches("f\\.tmp-" + PID + "-[0-9a-f]{12}"), seen.toString());
        assertEquals("one", read(d, "f"));
        assertEquals(Collections.singletonList("f"), names(d));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> invoke(aw, null, path, "two", (Runnable) () -> {
            throw new IllegalStateException("refused");
        }, false));
        assertEquals("refused", e.getMessage());
        assertEquals("one", read(d, "f"));
        assertEquals(Collections.singletonList("f"), names(d));
        invoke(aw, null, path, "three", null, false);
        assertEquals("three", read(d, "f"));
        assertEquals(Collections.singletonList("f"), names(d));
    }

    @Test void recoveringAMissingDirectoryCannotListIt() throws Exception {
        String missing = new File(tmp(), "missing").getPath();
        UncheckedIOException e = assertThrows(UncheckedIOException.class, () -> DurableState.recover(new DurableState.RecoverOptions(missing, true, "unreadable")));
        assertEquals("cannot list " + missing, e.getCause().getMessage());
    }

    // ---- the host: process start time, PID namespace, hostname ----

    @Test void theProcessStartTimeAndPidNamespaceComeFromProc() {
        String start = startOracle(PID);
        String ns = nsOracle();
        if (LINUX) {
            assertNotNull(start);
            assertNotNull(ns);
            assertTrue(ns.matches("pid:\\[\\d+\\]"), ns);
        }
        assertEquals(start, DurableState.procStartOf(PID));
        assertNull(DurableState.procStartOf(DEAD));
        assertEquals(ns, DurableState.ownNamespace());
        assertTrue(DurableState.pidAlive(PID));
        assertFalse(DurableState.pidAlive(DEAD));
    }

    private static String runHostname() throws Exception {
        Process p = new ProcessBuilder("hostname").start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        return out;
    }

    @Test void eachHostnameSourceAnswersFromItsOwnPlace() throws Exception {
        DurableState.Thrower[] src = DurableState.HOSTNAME_SOURCES;
        assertEquals(5, src.length);
        File proc = new File("/proc/sys/kernel/hostname");
        if (proc.exists()) assertEquals(new String(Files.readAllBytes(proc.toPath()), StandardCharsets.UTF_8), src[0].get());
        else assertThrows(UncheckedIOException.class, src[0]::get);
        assertEquals(runHostname(), src[1].get());
        UnaryOperator<String> prev = DurableState.crashEnv;
        Map<String, String> env = new HashMap<>();
        env.put("HOSTNAME", " env-host ");
        env.put("COMPUTERNAME", "env-computer");
        DurableState.crashEnv = env::get;
        try {
            assertEquals(" env-host ", src[2].get());
            assertEquals("env-computer", src[3].get());
        } finally {
            DurableState.crashEnv = prev;
        }
        assertEquals(java.net.InetAddress.getLocalHost().getHostName(), src[4].get());
    }

    @Test void theHostnameIsTheFirstNonBlankSourceAndIsCached() throws Exception {
        Field cache = hostnameCache();
        Object saved = cache.get(null);
        try {
            cache.set(null, null);
            File proc = new File("/proc/sys/kernel/hostname");
            String expected = proc.exists() ? new String(Files.readAllBytes(proc.toPath()), StandardCharsets.UTF_8).trim() : runHostname().trim();
            assertEquals(expected, DurableState.hostname());
            assertEquals(expected, cache.get(null));
            cache.set(null, "cached-host");
            assertEquals("cached-host", DurableState.hostname());
        } finally {
            cache.set(null, saved);
        }
    }

    @Test void firstCleanTakesTheFirstNonBlankTrimmedAnswer() {
        DurableState.Thrower none = () -> null;
        DurableState.Thrower blank = () -> "  \n";
        DurableState.Thrower boom = () -> {
            throw new IOException("x");
        };
        assertEquals("b", DurableState.firstClean(new DurableState.Thrower[] {none, blank, boom, () -> " b ", () -> "c"}));
        assertNull(DurableState.firstClean(new DurableState.Thrower[] {none, blank, boom}));
        assertNull(DurableState.firstClean(new DurableState.Thrower[0]));
        assertEquals("c", DurableState.firstClean(new DurableState.Thrower[] {() -> "c", () -> "d"}));
    }
}
