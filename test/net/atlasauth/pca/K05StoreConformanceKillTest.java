package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link StoreConformance} and {@link MemoryOperationStore}: the conformance profiles run against
 * scripted stores that log every call and break one contract at a time. Each run asserts the whole report text, the full
 * multiset of store calls (keys normalised to {@code prefix:ID}, with one 12-hex run id), and the crash / restart / close /
 * teardown hooks.
 */
public class K05StoreConformanceKillTest {
    static final Pattern KEY = Pattern.compile("^([a-z-]+):([0-9a-f]{12})(:\\d+)?$");

    static final class Log {
        final List<String> lines = Collections.synchronizedList(new ArrayList<>());
        String runId;
        int handles;

        synchronized String norm(String key) {
            if (key.indexOf(':') < 0) return key;
            Matcher m = KEY.matcher(key);
            if (!m.matches()) return "BADKEY:" + key;
            if (runId == null) runId = m.group(2);
            else if (!runId.equals(m.group(2))) return "BADID:" + key;
            return m.group(1) + ":ID" + (m.group(3) == null ? "" : m.group(3));
        }

        synchronized int nextHandle() { return handles++; }

        void add(String s) { lines.add(s); }

        List<String> sorted() {
            synchronized (lines) {
                List<String> c = new ArrayList<>(lines);
                Collections.sort(c);
                return c;
            }
        }

        List<String> ordered() {
            synchronized (lines) { return new ArrayList<>(lines); }
        }
    }

    static String prefix(String key) {
        int i = key.indexOf(':');
        return i < 0 ? key : key.substring(0, i);
    }

    static String lines(String... ls) {
        StringBuilder s = new StringBuilder();
        for (String l : ls) s.append(l).append('\n');
        return s.toString();
    }

    static List<String> sortedList(List<String> l) {
        List<String> c = new ArrayList<>(l);
        Collections.sort(c);
        return c;
    }

    static void times(List<String> l, int n, String s) { for (int i = 0; i < n; i++) l.add(s); }

    static void closes(List<String> l, int upTo) { for (int h = 0; h < upTo; h++) l.add("h" + h + " close"); }

    static StoreConformance.Options opts(Log log, Runnable restart, int threads, int rounds, int handles) {
        return new StoreConformance.Options().threads(threads).rounds(rounds).handles(handles).restart(restart)
            .crash(() -> log.add("crash")).teardown(() -> log.add("teardown"));
    }

    // ---- replay store ---------------------------------------------------------------------------------------------------

    interface Fault { StateStore.ClaimResult claim(int h, String prefix, long counter, Supplier<StateStore.ClaimResult> real); }

    static class StateBackend {
        final Log log = new Log();
        final Map<String, Long> last = new HashMap<>();
        Fault fault;
        boolean closeThrows;

        StateBackend() {}
        StateBackend(Fault f) { fault = f; }

        synchronized StateStore.ClaimResult real(String key, long counter) {
            Long prev = last.get(key);
            if (prev != null && counter <= prev) return StateStore.ClaimResult.replay(prev);
            last.put(key, counter);
            return StateStore.ClaimResult.claimed();
        }

        synchronized StateStore.ClaimResult claim(int h, String key, long counter) {
            return fault == null ? real(key, counter) : fault.claim(h, prefix(key), counter, () -> real(key, counter));
        }

        void restart() { log.add("restart"); }

        synchronized void wipe() { last.clear(); }

        StateHandle open() { return new StateHandle(this, log.nextHandle()); }
    }

    static final class StateHandle implements StateStore, AutoCloseable {
        final StateBackend b;
        final int h;

        StateHandle(StateBackend b, int h) { this.b = b; this.h = h; }

        @Override public ClaimResult claim(String key, long counter) {
            b.log.add("h" + h + " claim " + b.log.norm(key) + " " + counter);
            return b.claim(h, key, counter);
        }

        @Override public void close() throws Exception {
            b.log.add("h" + h + " close");
            if (b.closeThrows) throw new Exception("close failed");
        }
    }

    static String state(int t, int r, int hd, int idx, String line) {
        String[] ls = {"pass claim-sequence", "pass claim-burst: " + r + " rounds x " + t + " threads",
            "pass claim-concurrent: " + r + " rounds x " + t + " threads over " + hd + " handles", "pass claim-durability", "pass crash-after-claim", "pass retry-after-timeout"};
        if (idx >= 0) ls[idx] = line;
        return lines(ls);
    }

    static StoreConformance.Report runState(StateBackend b, StoreConformance.Options o) {
        return StoreConformance.runStateStoreConformance(b::open, o);
    }

    static void stateFault(int idx, String line, int t, int r, int hd, Fault f) {
        StateBackend b = new StateBackend(f);
        StoreConformance.Report rep = runState(b, opts(b.log, b::restart, t, r, hd));
        assertEquals(state(t, r, hd, idx, line), rep.render());
        assertFalse(rep.ok());
        assertEquals(1, rep.failures().size());
        assertEquals(1, Collections.frequency(b.log.ordered(), "teardown"));
    }

    static StateStore.ClaimResult claimed() { return StateStore.ClaimResult.claimed(); }

    static StateStore.ClaimResult replay(Long l) { return StateStore.ClaimResult.replay(l); }

    @Test void aSharedDurableReplayStorePassesWithExactlyTheseCalls() {
        StateBackend b = new StateBackend();
        StoreConformance.Report rep = runState(b, opts(b.log, b::restart, 3, 2, 2).name("custom"));
        assertEquals("custom", rep.name);
        assertTrue(rep.ok());
        assertEquals(state(3, 2, 2, -1, null), rep.render());
        List<String> w = new ArrayList<>();
        w.addAll(Arrays.asList("h0 claim seq:ID 1", "h0 claim seq:ID 1", "h0 claim seq:ID 5", "h0 claim seq:ID 3", "h0 claim seq:ID 5", "h0 claim seq-other:ID 1"));
        times(w, 3, "h1 claim burst:ID 1");
        times(w, 3, "h1 claim burst:ID 2");
        for (int c = 1; c <= 2; c++) {
            times(w, 2, "h2 claim conc:ID " + c);
            times(w, 1, "h3 claim conc:ID " + c);
        }
        w.add("h4 claim dur:ID 7");
        closes(w, 5);
        w.add("restart");
        w.addAll(Arrays.asList("h5 claim dur:ID 7", "h6 claim dur:ID 8", "h7 claim crash:ID 1", "crash", "restart", "h8 claim crash:ID 1", "h8 claim crash:ID 2",
            "h9 claim retry:ID 1", "h10 claim retry:ID 1", "h10 claim retry:ID 2", "h9 claim retry:ID 3", "h10 claim retry:ID 3"));
        closes(w, 11);
        w.add("teardown");
        assertEquals(sortedList(w), b.log.sorted());
        List<String> ord = b.log.ordered();
        assertEquals("teardown", ord.get(ord.size() - 1));
        assertTrue(ord.indexOf("h7 claim crash:ID 1") < ord.indexOf("crash"));
        assertTrue(ord.indexOf("crash") < ord.lastIndexOf("restart"));
        assertTrue(ord.lastIndexOf("restart") < ord.indexOf("h8 claim crash:ID 1"));
        assertTrue(ord.indexOf("h4 close") < ord.indexOf("restart"));
        assertTrue(ord.indexOf("restart") < ord.indexOf("h5 claim dur:ID 7"));
        // a fresh run id every run
        StateBackend b2 = new StateBackend();
        runState(b2, opts(b2.log, b2::restart, 1, 1, 1));
        assertFalse(b.log.runId.equals(b2.log.runId));
    }

    @Test void defaultOptionsAndNoHooks() {
        for (StoreConformance.Options o : Arrays.asList(null, new StoreConformance.Options())) {
            StateBackend b = new StateBackend();
            StoreConformance.Report rep = runState(b, o);
            assertEquals("state store", rep.name);
            assertEquals(state(16, 5, 4, -1, null), rep.render());
            assertEquals(1 + 1 + 4 + 3 + 2 + 2, b.log.handles);
            assertFalse(b.log.lines.contains("restart"));
            assertEquals(16, Collections.frequency(b.log.ordered(), "h1 claim burst:ID 5"));
            assertEquals(5 * 16, b.log.ordered().stream().filter(l -> l.startsWith("h1 claim burst:ID ")).count());
        }
        // no restart / crash hook: a durable store still passes, and nothing is called
        StateBackend b = new StateBackend();
        assertEquals(state(2, 1, 2, -1, null), runState(b, new StoreConformance.Options().threads(2).rounds(1).handles(2)).render());
        assertFalse(b.log.lines.contains("crash"));
    }

    @Test void processLocalDeclarationsSkip() {
        StateBackend b = new StateBackend();
        StoreConformance.Report rep = runState(b, opts(b.log, b::restart, 2, 1, 2).durable(false).shared(false));
        assertEquals(lines("pass claim-sequence", "pass claim-burst: 1 rounds x 2 threads",
            "skip claim-concurrent: the adapter declares shared(false) (a process-local store)",
            "skip claim-durability: the adapter declares durable(false) (state dies with the process)",
            "skip crash-after-claim: the adapter declares durable(false) (state dies with the process)", "pass retry-after-timeout"), rep.render());
        assertTrue(rep.ok());
        assertFalse(b.log.lines.contains("crash"));
        assertFalse(b.log.lines.contains("restart"));
        assertEquals(3, b.log.handles);
    }

    @Test void claimSequenceFailures() {
        stateFault(0, "fail claim-sequence: first claim of counter 1 refused", 2, 1, 2, (h, p, c, r) -> p.equals("seq") ? replay(null) : r.get());
        stateFault(0, "fail claim-sequence: first claim of counter 1 refused", 2, 1, 2, (h, p, c, r) -> p.equals("seq") ? null : r.get());
        stateFault(0, "fail claim-sequence: counter 1 claimed twice", 2, 1, 2, (h, p, c, r) -> p.equals("seq") ? claimed() : r.get());
        stateFault(0, "fail claim-sequence: a refused claim must report lastCounter=1, got ClaimResult{ok=false, lastCounter=null}", 2, 1, 2,
            (h, p, c, r) -> { StateStore.ClaimResult x = r.get(); return p.equals("seq") && !x.ok ? replay(null) : x; });
        stateFault(0, "fail claim-sequence: a refused claim must report lastCounter=1, got ClaimResult{ok=false, lastCounter=2}", 2, 1, 2,
            (h, p, c, r) -> { StateStore.ClaimResult x = r.get(); return p.equals("seq") && !x.ok ? replay(2L) : x; });
        stateFault(0, "fail claim-sequence: a refused claim must report lastCounter=1, got null", 2, 1, 2,
            (h, p, c, r) -> { StateStore.ClaimResult x = r.get(); return p.equals("seq") && !x.ok ? null : x; });
        stateFault(0, "fail claim-sequence: a larger counter (a gap) must be admitted", 2, 1, 2, (h, p, c, r) -> p.equals("seq") && c == 5 ? replay(1L) : r.get());
        stateFault(0, "fail claim-sequence: an older counter was admitted after 5", 2, 1, 2, (h, p, c, r) -> p.equals("seq") && c == 3 ? claimed() : r.get());
        stateFault(0, "fail claim-sequence: counter 5 claimed twice", 2, 1, 2,
            (h, p, c, r) -> { StateStore.ClaimResult x = r.get(); return p.equals("seq") && c == 5 ? claimed() : x; });
        stateFault(0, "fail claim-sequence: another key must be independent", 2, 1, 2, (h, p, c, r) -> p.equals("seq-other") ? replay(1L) : r.get());
        stateFault(0, "fail claim-sequence: IllegalStateException: boom", 2, 1, 2, (h, p, c, r) -> {
            if (p.equals("seq")) throw new IllegalStateException("boom");
            return r.get();
        });
        stateFault(0, "fail claim-sequence: null", 2, 1, 2, (h, p, c, r) -> {
            if (p.equals("seq")) throw new AssertionError();
            return r.get();
        });
    }

    @Test void claimBurstFailures() {
        stateFault(1, "fail claim-burst: round 1: 2 of 2 concurrent claims of counter 1 were admitted (want exactly 1)", 2, 2, 2,
            (h, p, c, r) -> { StateStore.ClaimResult x = r.get(); return p.equals("burst") ? claimed() : x; });
        stateFault(1, "fail claim-burst: round 1: 0 of 2 concurrent claims of counter 1 were admitted (want exactly 1)", 2, 2, 2,
            (h, p, c, r) -> p.equals("burst") ? replay(0L) : r.get());
        stateFault(1, "fail claim-burst: round 1: 0 of 2 concurrent claims of counter 1 were admitted (want exactly 1)", 2, 2, 2,
            (h, p, c, r) -> p.equals("burst") ? null : r.get());
        stateFault(1, "fail claim-burst: round 2: 2 of 2 concurrent claims of counter 2 were admitted (want exactly 1)", 2, 2, 2,
            (h, p, c, r) -> { StateStore.ClaimResult x = r.get(); return p.equals("burst") && c == 2 ? claimed() : x; });
        stateFault(1, "fail claim-burst: 2 of 3 concurrent calls raised: java.lang.IllegalStateException: busy", 3, 1, 2, (h, p, c, r) -> {
            StateStore.ClaimResult x = r.get();
            if (p.equals("burst") && !x.ok) throw new IllegalStateException("busy");
            return x;
        });
    }

    @Test void claimConcurrentFailures() {
        Map<Integer, Long> isl = new HashMap<>();
        stateFault(2, "fail claim-concurrent: round 1: 2 of 3 claims over 2 handles were admitted (want exactly 1)", 3, 2, 2, (h, p, c, r) -> {
            if (!p.equals("conc")) return r.get();
            Long prev = isl.get(h);
            if (prev != null && c <= prev) return replay(prev);
            isl.put(h, c);
            return claimed();
        });
        stateFault(2, "fail claim-concurrent: round 2: 3 of 3 claims over 2 handles were admitted (want exactly 1)", 3, 2, 2,
            (h, p, c, r) -> { StateStore.ClaimResult x = r.get(); return p.equals("conc") && c == 2 ? claimed() : x; });
        stateFault(2, "fail claim-concurrent: 2 of 2 concurrent calls raised: java.lang.IllegalStateException: boom h2", 2, 1, 2, (h, p, c, r) -> {
            if (p.equals("conc")) throw new IllegalStateException("boom h" + h);
            return r.get();
        });
    }

    @Test void durabilityAndCrashFailures() {
        stateFault(3, "fail claim-durability: claim refused", 2, 1, 2, (h, p, c, r) -> p.equals("dur") && c == 7 ? replay(null) : r.get());
        stateFault(3, "fail claim-durability: the next counter must be admitted after a restart", 2, 1, 2, (h, p, c, r) -> p.equals("dur") && c == 8 ? replay(7L) : r.get());
        stateFault(4, "fail crash-after-claim: claim refused", 2, 1, 2, (h, p, c, r) -> p.equals("crash") && c == 1 ? replay(null) : r.get());
        stateFault(4, "fail crash-after-claim: the next counter must be admitted after the crash", 2, 1, 2, (h, p, c, r) -> p.equals("crash") && c == 2 ? replay(1L) : r.get());
        stateFault(5, "fail retry-after-timeout: the retry of a claim whose answer was lost was admitted: the commit had already landed", 2, 1, 2,
            (h, p, c, r) -> p.equals("retry") && c == 1 ? claimed() : r.get());
        stateFault(5, "fail retry-after-timeout: the next counter after the retry must be admitted", 2, 1, 2,
            (h, p, c, r) -> p.equals("retry") && c == 2 ? replay(1L) : r.get());
        stateFault(5, "fail retry-after-timeout: 2 of 2 in-flight retries were admitted", 2, 1, 2,
            (h, p, c, r) -> p.equals("retry") && c == 3 ? claimed() : r.get());
        stateFault(5, "fail retry-after-timeout: 0 of 2 in-flight retries were admitted", 2, 1, 2,
            (h, p, c, r) -> p.equals("retry") && c == 3 ? replay(2L) : r.get());

        StateBackend wipeOnRestart = new StateBackend();
        StoreConformance.Report rep = runState(wipeOnRestart, opts(wipeOnRestart.log, () -> { wipeOnRestart.restart(); wipeOnRestart.wipe(); }, 2, 1, 2));
        assertEquals(lines("pass claim-sequence", "pass claim-burst: 1 rounds x 2 threads", "pass claim-concurrent: 1 rounds x 2 threads over 2 handles",
            "fail claim-durability: counter 7 was admitted again after the handles were closed (the claim was not durable)",
            "fail crash-after-claim: the proof admitted before the crash was admitted again", "pass retry-after-timeout"), rep.render());

        StateBackend wipeOnCrash = new StateBackend();
        StoreConformance.Options o = opts(wipeOnCrash.log, wipeOnCrash::restart, 2, 1, 2).crash(wipeOnCrash::wipe);
        assertEquals(state(2, 1, 2, 4, "fail crash-after-claim: the proof admitted before the crash was admitted again"), runState(wipeOnCrash, o).render());
    }

    @Test void aHandleWhoseCloseThrowsIsStillClosedAndPasses() {
        StateBackend b = new StateBackend();
        b.closeThrows = true;
        StoreConformance.Report rep = runState(b, opts(b.log, b::restart, 2, 1, 2));
        assertEquals(state(2, 1, 2, -1, null), rep.render());
        assertEquals(5 + 11, b.log.sorted().stream().filter(s -> s.endsWith(" close")).count());
    }

    @Test void aFactoryWithoutAStoreFailsEveryTestAndStillTearsDown() {
        Log log = new Log();
        StoreConformance.Report rep = StoreConformance.runStateStoreConformance(() -> null, opts(log, () -> log.add("restart"), 2, 1, 2));
        String no = ": the factory returned no store";
        assertEquals(lines("fail claim-sequence" + no, "fail claim-burst" + no, "fail claim-concurrent" + no, "fail claim-durability" + no, "fail crash-after-claim" + no, "fail retry-after-timeout" + no), rep.render());
        assertEquals(Arrays.asList("teardown"), log.ordered());
        Log log2 = new Log();
        StoreConformance.Report thrown = StoreConformance.runStateStoreConformance(() -> { throw new IllegalStateException("no backend"); }, opts(log2, () -> log2.add("restart"), 2, 1, 2));
        String nb = ": IllegalStateException: no backend";
        assertEquals(lines("fail claim-sequence" + nb, "fail claim-burst" + nb, "fail claim-concurrent" + nb, "fail claim-durability" + nb, "fail crash-after-claim" + nb, "fail retry-after-timeout" + nb), thrown.render());
        assertEquals(6, thrown.failures().size());
        assertEquals(Arrays.asList("teardown"), log2.ordered());

        Log log3 = new Log();
        StoreConformance.Report ops = StoreConformance.runOperationStoreConformance(() -> null, opts(log3, () -> log3.add("restart"), 2, 1, 2));
        assertEquals(lines("fail semantics" + no, "fail create-race" + no, "fail transition-race" + no, "fail cross-handle" + no, "fail durability" + no), ops.render());
        assertEquals(Arrays.asList("teardown"), log3.ordered());
        StoreConformance.Report opsThrown = StoreConformance.runOperationStoreConformance(() -> { throw new IllegalStateException("no backend"); }, null);
        assertEquals("operation store", opsThrown.name);
        assertEquals(lines("fail semantics" + nb, "fail create-race" + nb, "fail transition-race" + nb, "fail cross-handle" + nb, "fail durability" + nb), opsThrown.render());
    }

    // ---- report / options -----------------------------------------------------------------------------------------------

    @Test void reportVerdictAndRender() {
        StoreConformance.Report r = new StoreConformance.Report("n");
        assertEquals("n", r.name);
        assertFalse(r.ok(), "nothing passed");
        assertEquals("", r.render());
        r.results.add(new StoreConformance.TestResult("a", "skip", "why"));
        assertFalse(r.ok(), "only skips");
        r.results.add(new StoreConformance.TestResult("b", "pass", ""));
        assertTrue(r.ok());
        r.results.add(new StoreConformance.TestResult("c", "fail", "x"));
        assertFalse(r.ok());
        r.results.add(new StoreConformance.TestResult("d", "pass", "y"));
        assertFalse(r.ok());
        assertEquals("skip a: why\npass b\nfail c: x\npass d: y\n", r.render());
        assertEquals(1, r.failures().size());
        assertSame(r.results.get(2), r.failures().get(0));
        StoreConformance.Report f = new StoreConformance.Report("f");
        f.results.add(new StoreConformance.TestResult("c", "fail", ""));
        f.results.add(new StoreConformance.TestResult("b", "pass", ""));
        assertFalse(f.ok());
        assertEquals("fail c\npass b\n", f.render());
        StoreConformance.TestResult t = new StoreConformance.TestResult("t", "skip", "n");
        assertEquals("t", t.test);
        assertEquals("skip", t.status);
        assertEquals("n", t.note);
        assertEquals("skip t: n", t.toString());
    }

    @Test void optionsSettersReturnTheBuilder() {
        StoreConformance.Options o = new StoreConformance.Options();
        assertTrue(o.durable && o.shared);
        assertEquals(16, o.threads);
        assertEquals(5, o.rounds);
        assertEquals(4, o.handles);
        assertNull(o.name);
        Runnable a = () -> {}, b = () -> {}, c = () -> {};
        assertSame(o, o.durable(false));
        assertSame(o, o.shared(false));
        assertSame(o, o.crash(a));
        assertSame(o, o.restart(b));
        assertSame(o, o.teardown(c));
        assertSame(o, o.threads(7));
        assertSame(o, o.rounds(8));
        assertSame(o, o.handles(9));
        assertSame(o, o.name("x"));
        assertFalse(o.durable);
        assertFalse(o.shared);
        assertSame(a, o.crash);
        assertSame(b, o.restart);
        assertSame(c, o.teardown);
        assertEquals(7, o.threads);
        assertEquals(8, o.rounds);
        assertEquals(9, o.handles);
        assertEquals("x", o.name);
    }

    // ---- operation store ------------------------------------------------------------------------------------------------

    static class OpBackend {
        final Log log = new Log();
        final Map<String, OperationRecord> recs = new HashMap<>();
        boolean closeThrows;

        synchronized OperationRecord create(int h, OperationRecord r) {
            OperationRecord cur = recs.get(r.id());
            if (cur != null) return cur;
            recs.put(r.id(), r);
            return null;
        }

        synchronized OperationRecord get(int h, String id) { return recs.get(id); }

        synchronized boolean transition(int h, String id, String from, OperationRecord next) {
            OperationRecord cur = recs.get(id);
            if (cur == null || !from.equals(cur.state())) return false;
            recs.put(id, next);
            return true;
        }

        void restart() { log.add("restart"); }

        synchronized void wipe() { recs.clear(); }

        OpHandle open() { return new OpHandle(this, log.nextHandle()); }

        String render(OperationRecord r) {
            return log.norm(r.id()) + "|" + r.state() + "|" + r.verb() + "|" + r.resource() + "|" + r.paramsDigest() + "|" + r.reversibility() + "|"
                + r.startedAt() + "|" + r.executingAt() + "|" + r.finishedAt() + "|" + r.error();
        }
    }

    static final class OpHandle implements OperationStore, AutoCloseable {
        final OpBackend b;
        final int h;

        OpHandle(OpBackend b, int h) { this.b = b; this.h = h; }

        @Override public OperationRecord create(OperationRecord record) {
            b.log.add("h" + h + " create " + b.render(record));
            return b.create(h, record);
        }

        @Override public OperationRecord get(String id) {
            b.log.add("h" + h + " get " + b.log.norm(id));
            return b.get(h, id);
        }

        @Override public boolean transition(String id, String from, OperationRecord next) {
            b.log.add("h" + h + " transition " + b.log.norm(id) + " " + from + " " + b.render(next));
            return b.transition(h, id, from, next);
        }

        @Override public void close() throws Exception {
            b.log.add("h" + h + " close");
            if (b.closeThrows) throw new Exception("close failed");
        }
    }

    static String op(int t, int r, int hd, int idx, String line) {
        String[] ls = {"pass semantics", "pass create-race: " + r + " rounds x " + t + " threads", "pass transition-race: " + r + " rounds x " + t + " threads",
            "pass cross-handle: over " + hd + " handles", "pass durability"};
        if (idx >= 0) ls[idx] = line;
        return lines(ls);
    }

    static StoreConformance.Report runOps(OpBackend b, StoreConformance.Options o) {
        return StoreConformance.runOperationStoreConformance(b::open, o);
    }

    static void opFault(int idx, String line, int t, int r, int hd, OpBackend b) {
        StoreConformance.Report rep = runOps(b, opts(b.log, b::restart, t, r, hd));
        assertEquals(op(t, r, hd, idx, line), rep.render());
        assertFalse(rep.ok());
        assertEquals(1, rep.failures().size());
    }

    static String pend(String id) { return id + "|pending|v|/r|d|reversible|1|null|null|null"; }

    static String exec(String id, int at) { return id + "|executing|v|/r|d|reversible|1|" + at + "|null|null"; }

    static boolean sem(String id) { return id.startsWith("op-sem:"); }

    @Test void aSharedDurableOperationStorePassesWithExactlyTheseCalls() {
        OpBackend b = new OpBackend();
        StoreConformance.Report rep = runOps(b, opts(b.log, b::restart, 3, 2, 2).name("ops"));
        assertEquals("ops", rep.name);
        assertTrue(rep.ok());
        assertEquals(op(3, 2, 2, -1, null), rep.render());
        String s = "op-sem:ID";
        List<String> w = new ArrayList<>(Arrays.asList(
            "h0 get " + s,
            "h0 create " + pend(s),
            "h0 create " + s + "|pending|other|/r|d|reversible|1|null|null|null",
            "h0 transition nope:ID pending " + pend("nope"),
            "h0 transition " + s + " executing " + exec(s, 2),
            "h0 get " + s,
            "h0 transition " + s + " pending " + exec(s, 2),
            "h0 get " + s,
            "h0 get " + s,
            "h0 transition " + s + " pending " + s + "|aborted|v|/r|d|reversible|1|null|3|x"));
        for (int r = 0; r < 2; r++) times(w, 3, "h1 create " + pend("op-create:ID:" + r));
        for (int r = 0; r < 2; r++) {
            String i = "op-cas:ID:" + r;
            w.add("h2 create " + pend(i));
            for (int n = 0; n < 3; n++) w.add("h2 transition " + i + " pending " + exec(i, n));
        }
        String x = "op-shared:ID";
        times(w, 2, "h3 create " + pend(x));
        w.add("h4 create " + pend(x));
        w.addAll(Arrays.asList("h3 transition " + x + " pending " + exec(x, 0), "h4 transition " + x + " pending " + exec(x, 1), "h3 transition " + x + " pending " + exec(x, 2)));
        String d = "op-dur:ID";
        w.addAll(Arrays.asList("h5 create " + pend(d), "h5 transition " + d + " pending " + exec(d, 3)));
        closes(w, 6);
        w.addAll(Arrays.asList("restart", "h6 get " + d));
        closes(w, 7);
        w.add("teardown");
        assertEquals(sortedList(w), b.log.sorted());
        List<String> ord = b.log.ordered();
        assertEquals("teardown", ord.get(ord.size() - 1));
        assertTrue(ord.indexOf("h5 close") < ord.indexOf("restart"));
        assertTrue(ord.indexOf("restart") < ord.indexOf("h6 get " + d));
    }

    @Test void operationDefaultsAndSkips() {
        OpBackend b = new OpBackend();
        StoreConformance.Report rep = runOps(b, null);
        assertEquals("operation store", rep.name);
        assertEquals(op(16, 5, 4, -1, null), rep.render());
        assertEquals(1 + 1 + 1 + 4 + 2, b.log.handles);
        OpBackend local = new OpBackend();
        StoreConformance.Report skipped = runOps(local, opts(local.log, local::restart, 2, 1, 2).durable(false).shared(false));
        assertEquals(lines("pass semantics", "pass create-race: 1 rounds x 2 threads", "pass transition-race: 1 rounds x 2 threads",
            "skip cross-handle: the adapter declares shared(false) (a process-local store)",
            "skip durability: the adapter declares durable(false) (state dies with the process)"), skipped.render());
        assertTrue(skipped.ok());
        assertFalse(local.log.lines.contains("restart"));
        assertEquals(3, local.log.handles);
        OpBackend closing = new OpBackend();
        closing.closeThrows = true;
        assertEquals(op(2, 1, 2, -1, null), runOps(closing, opts(closing.log, closing::restart, 2, 1, 2)).render());
        assertEquals(6 + 7, closing.log.sorted().stream().filter(l -> l.endsWith(" close")).count());
    }

    @Test void semanticsFailures() {
        opFault(0, "fail semantics: get of an unknown id must be null", 2, 1, 2, new OpBackend() {
            @Override synchronized OperationRecord get(int h, String id) {
                OperationRecord cur = super.get(h, id);
                return cur == null && sem(id) ? OperationRecord.pending(id, "x", "/x", "x", "x", 0) : cur;
            }
        });
        opFault(0, "fail semantics: create of a new id must return null", 2, 1, 2, new OpBackend() {
            @Override synchronized OperationRecord create(int h, OperationRecord r) {
                OperationRecord cur = super.create(h, r);
                return sem(r.id()) ? r : cur;
            }
        });
        String unchanged = "fail semantics: create of an existing id must return the existing record unchanged";
        opFault(0, unchanged, 2, 1, 2, new OpBackend() {
            @Override synchronized OperationRecord create(int h, OperationRecord r) {
                if (!sem(r.id())) return super.create(h, r);
                recs.put(r.id(), r);
                return null;
            }
        });
        opFault(0, unchanged, 2, 1, 2, new OpBackend() {
            @Override synchronized OperationRecord create(int h, OperationRecord r) {
                OperationRecord cur = super.create(h, r);
                return cur == null || !sem(r.id()) ? cur : r;
            }
        });
        opFault(0, "fail semantics: transition of an unknown id must be false", 2, 1, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                return id.startsWith("nope:") || super.transition(h, id, from, next);
            }
        });
        opFault(0, "fail semantics: transition from the wrong state must be false", 2, 1, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                if (!sem(id) || !recs.containsKey(id)) return super.transition(h, id, from, next);
                recs.put(id, next);
                return true;
            }
        });
        opFault(0, "fail semantics: a refused transition changed the record", 2, 1, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                boolean ok = super.transition(h, id, from, next);
                if (!ok && sem(id) && recs.containsKey(id)) recs.put(id, next);
                return ok;
            }
        });
        opFault(0, "fail semantics: transition pending -> executing refused", 2, 1, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                return !sem(id) && super.transition(h, id, from, next);
            }
        });
        String notStored = "fail semantics: the transition was not stored";
        opFault(0, notStored, 2, 1, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                OperationRecord cur = recs.get(id);
                if (sem(id) && cur != null && from.equals(cur.state())) return true;
                return super.transition(h, id, from, next);
            }
        });
        opFault(0, notStored, 2, 1, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                return super.transition(h, id, from, sem(id) && next.executingAt() != null ? next.with("executingAt", IntentJs.ofLong(9)) : next);
            }
        });
        opFault(0, "fail semantics: the old state must no longer match", 2, 1, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                return sem(id) && "aborted".equals(next.state()) || super.transition(h, id, from, next);
            }
        });
        opFault(0, "fail semantics: IllegalStateException: boom", 2, 1, 2, new OpBackend() {
            @Override synchronized OperationRecord create(int h, OperationRecord r) {
                if (sem(r.id())) throw new IllegalStateException("boom");
                return super.create(h, r);
            }
        });
    }

    @Test void raceFailures() {
        opFault(1, "fail create-race: round 0: 2 of 2 concurrent creates reported 'created' (want exactly 1)", 2, 2, 2, new OpBackend() {
            @Override synchronized OperationRecord create(int h, OperationRecord r) {
                OperationRecord cur = super.create(h, r);
                return r.id().startsWith("op-create:") ? null : cur;
            }
        });
        opFault(1, "fail create-race: round 1: 2 of 2 concurrent creates reported 'created' (want exactly 1)", 2, 2, 2, new OpBackend() {
            @Override synchronized OperationRecord create(int h, OperationRecord r) {
                OperationRecord cur = super.create(h, r);
                return r.id().startsWith("op-create:") && r.id().endsWith(":1") ? null : cur;
            }
        });
        opFault(1, "fail create-race: 2 of 2 concurrent calls raised: java.lang.IllegalStateException: boom", 2, 1, 2, new OpBackend() {
            @Override synchronized OperationRecord create(int h, OperationRecord r) {
                if (r.id().startsWith("op-create:")) throw new IllegalStateException("boom");
                return super.create(h, r);
            }
        });
        opFault(2, "fail transition-race: round 0: 2 of 2 concurrent pending -> executing transitions succeeded (want exactly 1)", 2, 2, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                return super.transition(h, id, from, next) || id.startsWith("op-cas:");
            }
        });
        opFault(2, "fail transition-race: round 1: 2 of 2 concurrent pending -> executing transitions succeeded (want exactly 1)", 2, 2, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                return super.transition(h, id, from, next) || id.startsWith("op-cas:") && id.endsWith(":1");
            }
        });
        opFault(2, "fail transition-race: 2 of 2 concurrent calls raised: java.lang.IllegalStateException: boom", 2, 1, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                if (id.startsWith("op-cas:")) throw new IllegalStateException("boom");
                return super.transition(h, id, from, next);
            }
        });
    }

    @Test void crossHandleAndDurabilityFailures() {
        Set<Integer> seen = new HashSet<>();
        opFault(3, "fail cross-handle: creates over 2 handles: not exactly one 'created'", 3, 1, 2, new OpBackend() {
            @Override synchronized OperationRecord create(int h, OperationRecord r) {
                OperationRecord cur = super.create(h, r);
                if (!r.id().startsWith("op-shared:")) return cur;
                return seen.add(h) ? null : r;
            }
        });
        opFault(3, "fail cross-handle: transitions over 2 handles: not exactly one success", 3, 1, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                return super.transition(h, id, from, next) || id.startsWith("op-shared:");
            }
        });
        opFault(3, "fail cross-handle: 2 of 2 concurrent calls raised: java.lang.IllegalStateException: boom h3", 2, 1, 2, new OpBackend() {
            @Override synchronized OperationRecord create(int h, OperationRecord r) {
                if (r.id().startsWith("op-shared:")) throw new IllegalStateException("boom h" + h);
                return super.create(h, r);
            }
        });
        opFault(3, "fail cross-handle: 2 of 2 concurrent calls raised: java.lang.IllegalStateException: boom h3", 2, 1, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                if (id.startsWith("op-shared:")) throw new IllegalStateException("boom h" + h);
                return super.transition(h, id, from, next);
            }
        });
        String lost = "fail durability: the record did not survive closing every handle";
        opFault(4, lost, 2, 1, 2, new OpBackend() {
            @Override synchronized boolean transition(int h, String id, String from, OperationRecord next) {
                return super.transition(h, id, from, id.startsWith("op-dur:") ? next.with("executingAt", IntentJs.ofLong(4)) : next);
            }
        });
        OpBackend wipe = new OpBackend();
        assertEquals(op(2, 1, 2, 4, lost), runOps(wipe, opts(wipe.log, () -> { wipe.restart(); wipe.wipe(); }, 2, 1, 2)).render());
        OpBackend revert = new OpBackend();
        Runnable undo = () -> {
            revert.restart();
            synchronized (revert) { revert.recs.replaceAll((k, v) -> v.with("state", OperationRecord.PENDING)); }
        };
        assertEquals(op(2, 1, 2, 4, lost), runOps(revert, opts(revert.log, undo, 2, 1, 2)).render());
    }

    // ---- MemoryOperationStore -------------------------------------------------------------------------------------------

    static OperationRecord rec(String id) { return OperationRecord.pending(id, "v", "/r", "d", "reversible", 1L); }

    @Test void memoryOperationStoreKeysByIdAndListsOnlyOpenRecords() {
        MemoryOperationStore s = new MemoryOperationStore();
        assertTrue(s.processLocal());
        assertTrue(s.supportsListOpen());
        List<String> states = Arrays.asList(OperationRecord.PENDING, OperationRecord.EXECUTING, OperationRecord.COMMITTED, OperationRecord.FAILED,
            OperationRecord.ABORTED, OperationRecord.UNCERTAIN);
        for (String st : states) assertNull(s.create(rec(st)));
        assertFalse(s.transition("absent", OperationRecord.PENDING, rec("absent")));
        assertFalse(s.transition(OperationRecord.COMMITTED, OperationRecord.EXECUTING, rec("x")));
        for (String st : states) {
            if (st.equals(OperationRecord.PENDING)) continue;
            // the stored record is keyed by the transitioned id, whatever id `next` carries
            assertTrue(s.transition(st, OperationRecord.PENDING, rec("other").moved(st, null, null, null)));
        }
        assertNull(s.get("other"));
        assertNull(s.get("absent"));
        for (String st : states) {
            assertEquals(st, s.get(st).id());
            assertEquals(st, s.get(st).state());
        }
        List<OperationRecord> open = s.listOpen();
        Set<String> ids = new HashSet<>();
        for (OperationRecord r : open) ids.add(r.id());
        assertEquals(2, open.size());
        assertEquals(new HashSet<>(Arrays.asList(OperationRecord.PENDING, OperationRecord.EXECUTING)), ids);
    }
}
