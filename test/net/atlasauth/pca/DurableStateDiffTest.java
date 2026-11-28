package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.function.ThrowingSupplier;
import org.opentest4j.AssertionFailedError;

/**
 * The durable state store: the shared scenario corpus (every lane replays the same directory scenarios), plus what a corpus cannot
 * carry: file modes, racing writers, a live holder and the in-memory store.
 * Hang guard: every test (and every corpus scenario) runs under a deadline far above its normal time and below PIT's per-test time
 * limit (3 x normal + 15 s), so a mutant that never returns (e.g. a lock wait that can no longer time out) fails a test, not the run.
 */
@Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class DurableStateDiffTest {
    private static final Duration SCENARIO_LIMIT = Duration.ofSeconds(10);
    private static final long DEAD = 999_999_999L;
    private static final long PID = ProcessHandle.current().pid();
    private static final String HOST = DurableState.hostname();

    private static File tmp() throws Exception { return Files.createTempDirectory("pca-ds-java-").toFile(); }

    private static String subst(String s) { return s.replace("$HOST", HOST).replace("$PID", Long.toString(PID)).replace("$DEAD", Long.toString(DEAD)); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static Object so(Object v) {
        if ("$HOST".equals(v)) return HOST;
        if ("$PID".equals(v)) return new Json.Num(Long.toString(PID));
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<?>) v) out.add(so(x)); return out; }
        if (v instanceof Map) { Map<String, Object> out = new LinkedHashMap<>(); for (Map.Entry<String, Object> e : m(v).entrySet()) out.put(e.getKey(), so(e.getValue())); return out; }
        return v;
    }

    private static String normName(String f) {
        return f.replaceAll("^(state\\.fence\\.\\d+)-[0-9a-f]+", "$1-*")
            .replaceAll("\\.quarantine-.*$", ".quarantine-*")
            .replaceAll("^state\\.lock\\.legacy-recovered-.*$", "state.lock.legacy-recovered-*")
            .replaceAll("^state\\.lock\\.tmp-.*$", "state.lock.tmp-*");
    }

    private static String readOpt(File dir, String f) throws Exception {
        File p = new File(dir, f);
        return p.exists() ? new String(Files.readAllBytes(p.toPath()), StandardCharsets.UTF_8) : null;
    }

    private static void write(File dir, String f, String text) throws Exception { Files.write(new File(dir, f).toPath(), text.getBytes(StandardCharsets.UTF_8)); }

    private static Object parseFile(File dir, String f) {
        try {
            String t = readOpt(dir, f);
            return t == null ? null : Json.parseLenient(t);
        } catch (Exception e) {
            return null;
        }
    }

    private static Object strip(Object x) {
        if (!(x instanceof Map)) return x;
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : m(x).entrySet()) if (!e.getKey().equals("t")) out.put(e.getKey(), e.getValue());
        return out;
    }

    private static Map<String, Object> unreadable(String name) { Map<String, Object> u = new LinkedHashMap<>(); u.put("unreadable", normName(name)); return u; }

    private static Map<String, Object> snapshot(File dir) throws Exception {
        String[] list = dir.list();
        List<String> names = new ArrayList<>(Arrays.asList(list == null ? new String[0] : list));
        Collections.sort(names);
        List<Object> fences = new ArrayList<>();
        if (names.contains("state.fence")) {
            Object o = parseFile(dir, "state.fence");
            Object l = o instanceof Map ? m(o).get("fences") : null;
            if (l instanceof List) { for (Object f : (List<?>) l) fences.add(strip(f)); } else fences.add(unreadable("state.fence"));
        }
        Pattern entry = Pattern.compile("state\\.fence\\.(\\d+)-[0-9a-f]+");
        List<String> ents = new ArrayList<>();
        for (String n : names) if (entry.matcher(n).matches()) ents.add(n);
        ents.sort((a, b) -> {
            Matcher ma = entry.matcher(a), mb = entry.matcher(b);
            ma.matches(); mb.matches();
            double ga = Double.parseDouble(ma.group(1)), gb = Double.parseDouble(mb.group(1));
            return ga != gb ? Double.compare(ga, gb) : a.compareTo(b);
        });
        for (String n : ents) {
            Object o = parseFile(dir, n);
            Object f = o instanceof Map ? m(o).get("fence") : null;
            if (f != null) fences.add(strip(f)); else fences.add(unreadable(n));
        }
        Pattern lockGen = Pattern.compile("state\\.lock\\.(\\d+)");
        long g = 0;
        for (String n : names) { Matcher mm = lockGen.matcher(n); if (mm.matches()) g = Math.max(g, Long.parseLong(mm.group(1))); }
        Object top = null;
        if (g > 0) {
            Object b = parseFile(dir, "state.lock." + g);
            Map<String, Object> t = new LinkedHashMap<>();
            t.put("g", g);
            if (b == null) t.put("st", "unreadable"); // an unparseable or null body throws in the reference; an array or scalar has no members
            else if (b instanceof Map) for (String k : new String[] {"st", "recovering", "recoveredFrom"}) if (m(b).containsKey(k)) t.put(k, m(b).get(k));
            top = t;
        }
        List<Object> files = new ArrayList<>();
        for (String n : names) if (!n.startsWith("state.lock.tmp-") && !n.startsWith("state.probe-") && !n.contains(".tmp-")) files.add(normName(n));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("t", "dir"); out.put("files", files); out.put("journal", readOpt(dir, "state.journal")); out.put("head", readOpt(dir, "state.head")); out.put("fences", fences); out.put("top", top);
        return out;
    }

    private static Map<String, Object> err(DurableStateError e, File dir) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("code", e.code());
        o.put("msg", norm(e.getMessage(), dir)); // the reference message carries the code prefix
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("err", o);
        return r;
    }

    private static String norm(String s, File dir) { return s.replace(dir.getPath(), "$DIR").replace("$DIR" + File.separator, "$DIR/").replace(HOST, "$HOST").replace("pid=" + PID, "pid=$PID").replace("pid " + PID, "pid $PID"); }

    private static Map<String, Object> ok(Object v) { Map<String, Object> r = new LinkedHashMap<>(); r.put("ok", v); return r; }

    private static Map<String, Object> undef() { Map<String, Object> u = new LinkedHashMap<>(); u.put("$undef", true); return u; }

    private static Map<String, Object> pos(DurableState.Position p) { Map<String, Object> o = new LinkedHashMap<>(); o.put("seq", p.seq); o.put("hash", p.hash); return o; }

    @SuppressWarnings("unchecked")
    private static Object runScenario(Map<String, Object> sc) throws Exception {
        File dir = tmp();
        try {
            List<Object> out = new ArrayList<>();
            if (sc.get("files") instanceof Map) for (Map.Entry<String, Object> e : m(sc.get("files")).entrySet()) write(dir, e.getKey(), subst((String) e.getValue()));
            for (Object so0 : (List<Object>) sc.get("steps")) {
                Map<String, Object> st = m(so0);
                String t = (String) st.get("t");
                if (t.equals("write")) {
                    if (st.get("text") instanceof String) write(dir, (String) st.get("file"), subst((String) st.get("text"))); else new File(dir, (String) st.get("file")).delete();
                    out.add(null);
                } else if (t.equals("dir")) {
                    out.add(snapshot(dir));
                } else if (t.equals("recover")) {
                    Map<String, Object> o = st.get("opts") instanceof Map ? m(so(st.get("opts"))) : new LinkedHashMap<>();
                    Object eh = o.get("expectedHolder");
                    Object exp = eh;
                    if (eh instanceof Map && m(eh).get("host") instanceof String && IntentJs.num(m(eh).get("pid")) != null && m(eh).get("nonce") instanceof String) {
                        exp = new DurableState.ExpectedLockHolder((String) m(eh).get("host"), (long) (double) IntentJs.num(m(eh).get("pid")), (String) m(eh).get("nonce"));
                    }
                    try {
                        DurableState.RecoverOptions ro = new DurableState.RecoverOptions(dir.getPath(), !Boolean.FALSE.equals(o.get("force")), exp);
                        ro.legacyLock = Boolean.TRUE.equals(o.get("legacyLock"));
                        DurableState.RecoverResult r = DurableState.recoverDurableState(ro);
                        Map<String, Object> res = new LinkedHashMap<>();
                        res.put("released", r.released); res.put("reason", r.reason);
                        if (r.lockFile != null) res.put("lockFile", norm(r.lockFile, dir));
                        out.add(ok(res));
                    } catch (DurableStateError e) {
                        out.add(err(e, dir));
                    }
                } else if (t.equals("open")) {
                    Map<String, Object> op = st.get("opts") instanceof Map ? m(st.get("opts")) : new LinkedHashMap<>();
                    AtomicLong c = new AtomicLong(1000);
                    DurableState.Options opts = new DurableState.Options("".equals(op.get("dir")) ? "" : dir.getPath());
                    if (op.get("hmacKey") instanceof String) opts.hmacKey = MessageDigest.getInstance("SHA-256").digest(((String) op.get("hmacKey")).getBytes(StandardCharsets.UTF_8));
                    else if (op.get("hmacKeyBytes") != null) opts.hmacKey = new byte[(int) IntentJs.lng(op.get("hmacKeyBytes"))];
                    opts.recoverFromCorruption = Boolean.TRUE.equals(op.get("recoverFromCorruption"));
                    if (op.get("lockTimeoutMs") != null) opts.lockTimeoutMs = IntentJs.lng(op.get("lockTimeoutMs"));
                    if (op.get("compactEvery") != null) opts.compactEvery = (int) IntentJs.lng(op.get("compactEvery"));
                    if (op.get("maxValueBytes") != null) opts.maxValueBytes = (int) IntentJs.lng(op.get("maxValueBytes"));
                    opts.now = c::getAndIncrement;
                    DurableState h;
                    try {
                        h = DurableState.openDurableState(opts);
                    } catch (DurableStateError e) {
                        out.add(err(e, dir));
                        continue;
                    }
                    List<Object> res = new ArrayList<>();
                    Map<String, String[]> saved = new HashMap<>();
                    List<Object> ops = st.get("ops") instanceof List ? (List<Object>) st.get("ops") : new ArrayList<>();
                    for (Object xo : ops) {
                        Map<String, Object> x = m(xo);
                        String k = x.get("key") instanceof String ? (String) x.get("key") : "";
                        try {
                            Object v = null;
                            String name = (String) x.get("op");
                            switch (name) {
                                case "set": h.set(k, x.get("value")); break;
                                case "get": { Object r = h.get(k); v = r != null ? r : undef(); break; }
                                case "keys": v = h.keys(); break;
                                case "verify": v = pos(h.verify()); break;
                                case "position": v = pos(h.position()); break;
                                case "update": {
                                    Object arg = x.get("arg");
                                    String kind = (String) x.get("kind");
                                    Object r = h.update(k, p -> {
                                        switch (kind) {
                                            case "append": { List<Object> l = new ArrayList<>(p instanceof List ? (List<?>) p : new ArrayList<>()); l.add(arg); return l; }
                                            case "max": return p == null || IntentJs.num(arg) > IntentJs.num(p) ? arg : null;
                                            case "noop": return null;
                                            case "same": return p;
                                            case "set": return arg;
                                            default: throw new IllegalStateException("unknown update kind " + kind);
                                        }
                                    });
                                    v = r != null ? r : undef();
                                    break;
                                }
                                case "fs":
                                    if (x.get("text") instanceof String) write(dir, (String) x.get("file"), subst((String) x.get("text"))); else new File(dir, (String) x.get("file")).delete();
                                    break;
                                case "save": saved.put((String) x.get("name"), new String[] {readOpt(dir, "state.journal"), readOpt(dir, "state.head")}); break;
                                case "restore": {
                                    String[] jh = saved.get((String) x.get("name"));
                                    String[] fs = {"state.journal", "state.head"};
                                    for (int i = 0; i < 2; i++) if (jh[i] == null) new File(dir, fs[i]).delete(); else write(dir, fs[i], jh[i]);
                                    break;
                                }
                                default: throw new IllegalStateException("unknown op " + name);
                            }
                            res.add(ok(v));
                        } catch (DurableStateError e) {
                            res.add(err(e, dir));
                        }
                    }
                    Map<String, Object> body = new LinkedHashMap<>();
                    body.put("recovered", h.recovered()); body.put("ops", res);
                    out.add(ok(body));
                } else {
                    throw new IllegalStateException("unknown step " + t);
                }
            }
            out.add(snapshot(dir));
            return out;
        } finally {
            deleteTree(dir);
        }
    }

    private static void deleteTree(File f) {
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteTree(k);
        f.delete();
    }

    @Test @Timeout(value = 900, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    void everyScenarioOfTheReferenceCorpusReplaysIdentically() throws Exception {
        // each scenario has its own deadline (the class one would cut the whole replay); after the first that does not finish, the rest
        // are not started, so a hanging mutant costs one deadline, not one per scenario
        boolean[] hung = {false};
        OracleCases.each("ref-durable-state", "scenario", a -> {
            if (hung[0]) throw new IllegalStateException("not run: an earlier scenario did not finish within " + SCENARIO_LIMIT);
            try {
                return assertTimeoutPreemptively(SCENARIO_LIMIT, (ThrowingSupplier<Object>) () -> runScenario(m(a.get(0))));
            } catch (AssertionFailedError e) {
                hung[0] = true;
                throw e;
            }
        });
        assertFalse(hung[0], "a scenario did not finish within " + SCENARIO_LIMIT);
    }

    @Test void theDirectoryIs0700AndTheFiles0600() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix"), "no POSIX permissions on this file system");
        File d = new File(tmp(), "state");
        DurableState s = DurableState.open(new DurableState.Options(d.getPath()));
        s.set("a", new Json.Num("1"));
        assertEquals("rwx------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(d.toPath())));
        assertEquals("rw-------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(new File(d, "state.journal").toPath())));
        assertEquals("rw-------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(new File(d, "state.head").toPath())));
    }

    @Test @Timeout(value = 30, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    void racingWritersLoseNoUpdateAndTheChainStaysIntact() throws Exception {
        File d = tmp();
        int threads = 4, each = 12;
        List<Thread> ts = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            Thread t = new Thread(() -> {
                DurableState.Options o = new DurableState.Options(d.getPath());
                o.lockTimeoutMs = 60_000;
                DurableState s = DurableState.open(o);
                for (int j = 0; j < each; j++) s.update("n", p -> new Json.Num(Long.toString((p == null ? 0L : IntentJs.lng(p)) + 1)));
            });
            t.setDaemon(true); // a writer a mutant left spinning must not keep the JVM alive after the hang guard fails the test
            ts.add(t);
            t.start();
        }
        for (Thread t : ts) t.join();
        DurableState s = DurableState.open(new DurableState.Options(d.getPath()));
        assertEquals((long) threads * each, IntentJs.lng(s.get("n")));
        assertTrue(s.verify().seq >= (long) threads * each);
    }

    @Test void aLiveHolderIsNeverRobbedTheWaiterTimesOut() throws Exception {
        File d = tmp();
        DurableState s = DurableState.open(new DurableState.Options(d.getPath()));
        s.set("a", new Json.Num("1"));
        long top = 0;
        for (String n : d.list()) if (n.matches("state\\.lock\\.\\d+")) top = Math.max(top, Long.parseLong(n.substring("state.lock.".length())));
        write(d, "state.lock." + (top + 1), "{\"st\":\"held\",\"pid\":" + PID + ",\"host\":\"" + HOST + "\",\"nonce\":\"n\"}");
        DurableState.Options o = new DurableState.Options(d.getPath());
        o.lockTimeoutMs = 150;
        DurableStateError e = null;
        try { DurableState.open(o); } catch (DurableStateError x) { e = x; }
        assertEquals("lock-timeout", e.code());
    }

    /** Arms a commit hook in this (non-child) process with the halt replaced by a recorder; returns the points the halter was called at. */
    private static List<String> fireHook(String point, boolean asChild) throws Exception {
        List<String> halted = new ArrayList<>();
        Runnable prev = DurableState.crashHalter;
        String prevProp = System.getProperty(DurableState.CRASH_CHILD_PROPERTY);
        DurableState.crashHalter = () -> { halted.add(point); throw new IllegalStateException("halted"); };
        try {
            if (asChild) System.setProperty(DurableState.CRASH_CHILD_PROPERTY, "1");
            DurableState.Options o = new DurableState.Options(tmp().getPath());
            o.testCrashAt = point;
            DurableState s = DurableState.open(o);
            if (asChild) assertEquals("halted", assertThrows(IllegalStateException.class, () -> s.set("a", new Json.Num("1"))).getMessage());
            else assertEquals("crash hook fired outside a crash child (" + point + ")", assertThrows(AssertionError.class, () -> s.set("a", new Json.Num("1"))).getMessage());
        } finally {
            DurableState.crashHalter = prev;
            if (prevProp == null) System.clearProperty(DurableState.CRASH_CHILD_PROPERTY); else System.setProperty(DurableState.CRASH_CHILD_PROPERTY, prevProp);
        }
        return halted;
    }

    @Test void aCrashHookOutsideACrashChildThrowsInsteadOfHalting() throws Exception {
        for (String point : Arrays.asList("after-temp-write", "after-journal-rename")) assertEquals(Collections.emptyList(), fireHook(point, false));
    }

    @Test void aCrashHookInACrashChildHalts() throws Exception {
        for (String point : Arrays.asList("after-temp-write", "after-journal-rename")) assertEquals(Collections.singletonList(point), fireHook(point, true));
    }

    /** A crash child: one durable write, which the after-temp-write hook ends through the DEFAULT halter (nothing replaced). */
    public static final class CrashChild {
        public static void main(String[] args) {
            DurableState.Options o = new DurableState.Options(args[0]);
            o.testCrashAt = "after-temp-write";
            DurableState s = DurableState.open(o);
            System.out.println("opened");
            System.out.flush();
            s.set("a", new Json.Num("2"));
            System.out.println("after the halt");
            System.out.flush();
            System.exit(0);
        }
    }

    // The default halter can only be observed from outside: a child JVM (the unmutated class) dies at the hook with exactly 137, runs
    // nothing after it, leaves the journal temp written and the journal and head untouched, and a fresh open carries on from them.
    @Test @Timeout(value = 20, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    void theDefaultHalterEndsACrashChildWithExit137AtItsHook() throws Exception {
        File d = tmp();
        DurableState.open(new DurableState.Options(d.getPath())).set("a", new Json.Num("1"));
        String journal = readOpt(d, "state.journal"), head = readOpt(d, "state.head");
        String javaBin = java.nio.file.Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        Process p = new ProcessBuilder(javaBin, "-cp", System.getProperty("java.class.path"), "-D" + DurableState.CRASH_CHILD_PROPERTY + "=1", CrashChild.class.getName(), d.getPath())
            .redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS), "the crash child did not exit: " + out);
        assertEquals(137, p.exitValue(), out);
        assertTrue(out.contains("opened"), out);
        assertFalse(out.contains("after the halt"), out);
        assertEquals(journal, readOpt(d, "state.journal"));
        assertEquals(head, readOpt(d, "state.head"));
        String tmpName = null;
        for (String n : d.list()) if (n.startsWith("state.journal.tmp-" + p.pid() + "-")) tmpName = n;
        assertTrue(tmpName != null, "no journal temp of the child in " + Arrays.toString(d.list()));
        String temp = readOpt(d, tmpName);
        assertTrue(temp.startsWith(journal) && temp.length() > journal.length(), temp);
        DurableState fresh = DurableState.open(new DurableState.Options(d.getPath()));
        assertEquals(1L, IntentJs.lng(fresh.get("a")));
        fresh.set("a", new Json.Num("3"));
        assertEquals(3L, IntentJs.lng(DurableState.open(new DurableState.Options(d.getPath())).get("a")));
    }

    @Test void theInMemoryStoreHasTheSameUpdateSemantics() {
        DurableState.MemoryDurableKv mem = DurableState.createMemoryDurableKv();
        assertEquals(5L, IntentJs.lng(mem.update("hw", p -> p == null ? new Json.Num("5") : null)));
        assertEquals(5L, IntentJs.lng(mem.update("hw", p -> p == null ? new Json.Num("9") : null)));
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("x", Arrays.asList(new Json.Num("1"), null));
        mem.set("b", b);
        assertEquals(Arrays.asList("b", "hw"), mem.keys());
        assertNull(mem.update("nope", p -> null));
    }
}
