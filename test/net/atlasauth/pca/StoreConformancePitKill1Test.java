package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * Mutation kills for the trust-budget and kv-registry profiles of {@link StoreConformance}: scripted stores log every call and break one contract at
 * a time, and each run asserts the whole report and the full multiset of store calls.
 */
public class StoreConformancePitKill1Test {
    static final Pattern KEY = Pattern.compile("^([a-z0-9-]+):([0-9a-f]{12})$");

    static final class Log {
        final List<String> lines = Collections.synchronizedList(new ArrayList<>());
        String runId;
        int handles;

        synchronized String norm(String key) {
            Matcher m = KEY.matcher(key);
            if (!m.matches()) return "BADKEY:" + key;
            if (runId == null) runId = m.group(2);
            else if (!runId.equals(m.group(2))) return "BADID:" + key;
            return m.group(1) + ":ID";
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

    static String lines(String... ls) {
        StringBuilder s = new StringBuilder();
        for (String l : ls) s.append(l).append('\n');
        return s.toString();
    }

    static String prefix(String key) {
        int i = key.indexOf(':');
        return i < 0 ? key : key.substring(0, i);
    }

    static void times(List<String> l, int n, String s) { for (int i = 0; i < n; i++) l.add(s); }

    static List<String> sortedList(List<String> l) {
        List<String> c = new ArrayList<>(l);
        Collections.sort(c);
        return c;
    }

    static long count(List<String> l, String s) { return Collections.frequency(l, s); }

    // ---- the budget store ----------------------------------------------------------------------------------------------

    interface ClaimF { StateStore.ClaimResult apply(int h, String p, long c, Map<String, Object> before, Map<String, Object> after, Supplier<StateStore.ClaimResult> real); }

    interface BudgetF { Map<String, Object> apply(int h, String p, int n, Supplier<Map<String, Object>> real); }

    static Map<String, Object> bm(double b) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("B", b);
        m.put("tau", 1000.0);
        m.put("asOf", 1000.0);
        return m;
    }

    static String fmt(Map<String, Object> m) { return m == null ? "null" : m.get("B") + "/" + m.get("tau") + "/" + m.get("asOf"); }

    static String f(int b) { return b + ".0/1000.0/1000.0"; }

    static double bOf(Map<String, Object> m) { return ((Number) m.get("B")).doubleValue(); }

    static class BBackend {
        final Log log = new Log();
        volatile MemoryStateStore real = new MemoryStateStore();
        final Map<String, Integer> budgetCalls = new HashMap<>();
        boolean closeThrows, holds = true, wipeOnRestart;
        ClaimF cf;
        BudgetF bf;

        BBackend() {}
        BBackend(ClaimF cf, BudgetF bf) { this.cf = cf; this.bf = bf; }

        BHandle open() { return new BHandle(this, log.nextHandle()); }

        void restart() {
            log.add("restart");
            if (wipeOnRestart) real = new MemoryStateStore();
        }
    }

    static final class BHandle implements StateStore, AutoCloseable {
        final BBackend b;
        final int h;

        BHandle(BBackend b, int h) { this.b = b; this.h = h; }

        @Override public ClaimResult claim(String key, long counter) {
            b.log.add("h" + h + " claim2 " + b.log.norm(key) + " " + counter);
            return b.real.claim(key, counter);
        }

        @Override public boolean holdsBudgets() { return b.holds; }

        @Override public Map<String, Object> budget(String key) {
            b.log.add("h" + h + " budget " + b.log.norm(key));
            int n;
            synchronized (b.budgetCalls) { n = b.budgetCalls.merge(prefix(key), 1, Integer::sum); }
            Supplier<Map<String, Object>> real = () -> b.real.budget(key);
            return b.bf == null ? real.get() : b.bf.apply(h, prefix(key), n, real);
        }

        @Override public ClaimResult claim(String key, long counter, Map<String, Object> before, Map<String, Object> after) {
            b.log.add("h" + h + " claim " + b.log.norm(key) + " " + counter + " " + fmt(before) + "->" + fmt(after));
            Supplier<ClaimResult> real = () -> b.real.claim(key, counter, before, after);
            return b.cf == null ? real.get() : b.cf.apply(h, prefix(key), counter, before, after, real);
        }

        @Override public void close() throws Exception {
            b.log.add("h" + h + " close");
            if (b.closeThrows) throw new Exception("close failed");
        }
    }

    static StoreConformance.Options opts(BBackend b, int threads, int rounds, int handles) {
        return new StoreConformance.Options().threads(threads).rounds(rounds).handles(handles).restart(b::restart).teardown(() -> b.log.add("teardown"));
    }

    static StoreConformance.Report runBudget(BBackend b, StoreConformance.Options o) {
        return StoreConformance.runBudgetStoreConformance(b::open, o);
    }

    static String budgetRender(int t, int r, int idx, String line) {
        String[] ls = {"pass budget-absent-then-set", "pass budget-conflict-consumes-nothing", "pass budget-replay-spends-nothing",
            "pass budget-burst: " + r + " rounds x " + t + " threads", "pass budget-keys-independent", "pass budget-durability"};
        if (idx >= 0) ls[idx] = line;
        return lines(ls);
    }

    static void budgetFault(int idx, String line, ClaimF cf, BudgetF bf) {
        BBackend b = new BBackend(cf, bf);
        StoreConformance.Report rep = runBudget(b, opts(b, 3, 2, 2));
        assertEquals(budgetRender(3, 2, idx, line), rep.render());
        assertFalse(rep.ok());
        assertEquals(1, rep.failures().size());
        assertEquals(1, count(b.log.ordered(), "teardown"));
    }

    static StateStore.ClaimResult claimed() { return StateStore.ClaimResult.claimed(); }

    static StateStore.ClaimResult replay(Long l) { return StateStore.ClaimResult.replay(l); }

    @Test void aSharedDurableBudgetStorePassesWithExactlyTheseCalls() {
        BBackend b = new BBackend();
        StoreConformance.Report rep = runBudget(b, opts(b, 3, 2, 2).name("custom"));
        assertEquals("custom", rep.name);
        assertTrue(rep.ok());
        assertEquals(budgetRender(3, 2, -1, null), rep.render());
        List<String> w = new ArrayList<>();
        times(w, 4, "h0 budget b1:ID");
        w.addAll(Arrays.asList("h0 claim b1:ID 1 null->" + f(10), "h0 claim b1:ID 2 " + f(10) + "->" + f(9), "h0 claim b1:ID 3 " + f(9) + "->null"));
        w.addAll(Arrays.asList("h1 claim b2:ID 1 null->" + f(5), "h1 claim b2:ID 2 " + f(99) + "->" + f(1), "h1 budget b2:ID", "h1 claim b2:ID 2 " + f(5) + "->" + f(4),
            "h1 claim b2-absent:ID 1 " + f(5) + "->" + f(4)));
        w.addAll(Arrays.asList("h2 claim b3:ID 1 null->" + f(5), "h2 claim b3:ID 1 " + f(5) + "->" + f(1), "h2 budget b3:ID"));
        w.add("h3 claim b4:ID 1 null->" + f(100));
        times(w, 4, "h3 budget b4:ID");
        times(w, 3, "h3 claim b4:ID 2 " + f(100) + "->" + f(99));
        times(w, 3, "h3 claim b4:ID 3 " + f(99) + "->" + f(98));
        w.addAll(Arrays.asList("h4 claim b5a:ID 1 null->" + f(3), "h4 budget b5b:ID", "h4 claim b5b:ID 1 null->" + f(7), "h4 budget b5a:ID"));
        w.addAll(Arrays.asList("h5 claim b6:ID 1 null->" + f(8), "restart", "h6 budget b6:ID"));
        for (int h = 0; h <= 5; h++) times(w, 2, "h" + h + " close");
        w.add("h6 close");
        w.add("teardown");
        assertEquals(sortedList(w), b.log.sorted());
        assertEquals(7, b.log.handles);
        List<String> ord = b.log.ordered();
        assertEquals("teardown", ord.get(ord.size() - 1));
        assertTrue(ord.indexOf("h5 claim b6:ID 1 null->" + f(8)) < ord.indexOf("h5 close"));
        assertTrue(ord.indexOf("h5 close") < ord.indexOf("restart"));
        assertTrue(ord.indexOf("restart") < ord.indexOf("h6 budget b6:ID"));
        // a fresh run id every run
        BBackend b2 = new BBackend();
        runBudget(b2, opts(b2, 1, 1, 1));
        assertFalse(b.log.runId.equals(b2.log.runId));
    }

    @Test void defaultOptionsAndNoHooks() {
        for (StoreConformance.Options o : Arrays.asList(null, new StoreConformance.Options())) {
            BBackend b = new BBackend();
            StoreConformance.Report rep = runBudget(b, o);
            assertEquals("budget store", rep.name);
            assertEquals(budgetRender(16, 5, -1, null), rep.render());
            assertEquals(7, b.log.handles);
            assertFalse(b.log.lines.contains("restart"));
            assertEquals(1 + 5 * 16, b.log.ordered().stream().filter(l -> l.startsWith("h3 claim b4:ID ")).count());
            assertEquals(16, count(b.log.ordered(), "h3 claim b4:ID 6 " + f(96) + "->" + f(95)));
        }
    }

    @Test void aProcessLocalStoreSkipsTheDurabilityTest() {
        BBackend b = new BBackend();
        StoreConformance.Report rep = runBudget(b, opts(b, 2, 1, 2).durable(false));
        assertEquals(budgetRender(2, 1, 5, "skip budget-durability: the adapter declares durable(false) (state dies with the process)"), rep.render());
        assertTrue(rep.ok());
        assertFalse(b.log.lines.contains("restart"));
        assertEquals(5, b.log.handles);
        for (int h = 0; h <= 4; h++) assertEquals(1, count(b.log.ordered(), "h" + h + " close"));
    }

    @Test void aHandleWhoseCloseThrowsIsStillClosedAndPasses() {
        BBackend b = new BBackend();
        b.closeThrows = true;
        StoreConformance.Report rep = runBudget(b, opts(b, 2, 1, 2));
        assertEquals(budgetRender(2, 1, -1, null), rep.render());
        assertEquals(6 + 7, b.log.sorted().stream().filter(s -> s.endsWith(" close")).count());
    }

    @Test void aFactoryWithoutAStoreFailsEveryTestAndStillTearsDown() {
        Log log = new Log();
        String no = ": the factory returned no store";
        StoreConformance.Report rep = StoreConformance.runBudgetStoreConformance(() -> null, new StoreConformance.Options().teardown(() -> log.add("teardown")));
        assertEquals(lines("fail budget-absent-then-set" + no, "fail budget-conflict-consumes-nothing" + no, "fail budget-replay-spends-nothing" + no,
            "fail budget-burst" + no, "fail budget-keys-independent" + no, "fail budget-durability" + no), rep.render());
        assertEquals(Arrays.asList("teardown"), log.ordered());
        String nb = ": IllegalStateException: no backend";
        StoreConformance.Report thrown = StoreConformance.runBudgetStoreConformance(() -> { throw new IllegalStateException("no backend"); }, null);
        assertEquals(lines("fail budget-absent-then-set" + nb, "fail budget-conflict-consumes-nothing" + nb, "fail budget-replay-spends-nothing" + nb,
            "fail budget-burst" + nb, "fail budget-keys-independent" + nb, "fail budget-durability" + nb), thrown.render());
        assertEquals("budget store", thrown.name);
    }

    @Test void absentThenSetFailures() {
        String t = "fail budget-absent-then-set: ";
        BBackend noHold = new BBackend();
        noHold.holds = false;
        StoreConformance.Report rep = runBudget(noHold, opts(noHold, 3, 2, 2));
        assertEquals(budgetRender(3, 2, 0, t + "the store does not declare holdsBudgets()"), rep.render());
        budgetFault(0, t + "a new key must hold no budget", null, (h, p, n, r) -> p.equals("b1") && n == 1 ? bm(1) : r.get());
        budgetFault(0, t + "the first claim (budgetBefore absent) was refused", (h, p, c, bf, af, r) -> p.equals("b1") && c == 1 ? replay(null) : r.get(), null);
        budgetFault(0, t + "the first claim (budgetBefore absent) was refused", (h, p, c, bf, af, r) -> p.equals("b1") && c == 1 ? null : r.get(), null);
        budgetFault(0, t + "the budget after the first claim must be 10, got null", null, (h, p, n, r) -> p.equals("b1") && n == 2 ? null : r.get());
        budgetFault(0, t + "the budget after the first claim must be 10, got {B=11.0, tau=1000.0, asOf=1000.0}", null, (h, p, n, r) -> p.equals("b1") && n == 2 ? bm(11) : r.get());
        budgetFault(0, t + "a claim with the stored budget as budgetBefore was refused", (h, p, c, bf, af, r) -> p.equals("b1") && c == 2 ? replay(1L) : r.get(), null);
        budgetFault(0, t + "the budget after the second claim must be 9", null, (h, p, n, r) -> p.equals("b1") && n == 3 ? bm(10) : r.get());
        budgetFault(0, t + "a claim with budgetAfter absent was refused", (h, p, c, bf, af, r) -> p.equals("b1") && c == 3 ? StateStore.ClaimResult.conflict() : r.get(), null);
        budgetFault(0, t + "budgetAfter absent must keep the stored budget", null, (h, p, n, r) -> p.equals("b1") && n == 4 ? bm(8) : r.get());
    }

    static boolean stale(Map<String, Object> before) { return before != null && bOf(before) == 99.0; }

    @Test void conflictFailures() {
        String t = "fail budget-conflict-consumes-nothing: ";
        budgetFault(1, t + "setup claim refused", (h, p, c, bf, af, r) -> p.equals("b2") && c == 1 ? replay(null) : r.get(), null);
        String conflict = "a stale budgetBefore must be a conflict, got ";
        budgetFault(1, t + conflict + "ClaimResult{ok=true, lastCounter=null}", (h, p, c, bf, af, r) -> p.equals("b2") && stale(bf) ? claimed() : r.get(), null);
        budgetFault(1, t + conflict + "null", (h, p, c, bf, af, r) -> p.equals("b2") && stale(bf) ? null : r.get(), null);
        budgetFault(1, t + conflict + "ClaimResult{ok=false, lastCounter=1}", (h, p, c, bf, af, r) -> p.equals("b2") && stale(bf) ? replay(1L) : r.get(), null);
        budgetFault(1, t + "a conflict must leave the budget alone", null, (h, p, n, r) -> p.equals("b2") && n == 1 ? bm(6) : r.get());
        budgetFault(1, t + "counter 2 must still be unconsumed after the conflict",
            (h, p, c, bf, af, r) -> p.equals("b2") && c == 2 && bf != null && bOf(bf) == 5.0 ? StateStore.ClaimResult.conflict() : r.get(), null);
        String absent = "budgetBefore present against an absent stored budget must be a conflict, got ";
        budgetFault(1, t + absent + "ClaimResult{ok=true, lastCounter=null}", (h, p, c, bf, af, r) -> p.equals("b2-absent") ? claimed() : r.get(), null);
        budgetFault(1, t + absent + "null", (h, p, c, bf, af, r) -> p.equals("b2-absent") ? null : r.get(), null);
        budgetFault(1, t + absent + "ClaimResult{ok=false, lastCounter=null}", (h, p, c, bf, af, r) -> p.equals("b2-absent") ? replay(null) : r.get(), null);
    }

    @Test void replayFailures() {
        String t = "fail budget-replay-spends-nothing: ";
        String rep = "a replay must report the stored counter, got ";
        budgetFault(2, t + "setup claim refused", (h, p, c, bf, af, r) -> p.equals("b3") && bf == null ? replay(null) : r.get(), null);
        budgetFault(2, t + rep + "ClaimResult{ok=true, lastCounter=null}", (h, p, c, bf, af, r) -> p.equals("b3") && bf != null ? claimed() : r.get(), null);
        budgetFault(2, t + rep + "ClaimResult{ok=false, lastCounter=null}", (h, p, c, bf, af, r) -> p.equals("b3") && bf != null ? StateStore.ClaimResult.conflict() : r.get(), null);
        budgetFault(2, t + rep + "ClaimResult{ok=false, lastCounter=null}", (h, p, c, bf, af, r) -> p.equals("b3") && bf != null ? replay(null) : r.get(), null);
        budgetFault(2, t + rep + "ClaimResult{ok=false, lastCounter=2}", (h, p, c, bf, af, r) -> p.equals("b3") && bf != null ? replay(2L) : r.get(), null);
        budgetFault(2, t + rep + "null", (h, p, c, bf, af, r) -> p.equals("b3") && bf != null ? null : r.get(), null);
        budgetFault(2, t + "a replay must not spend budget", null, (h, p, n, r) -> p.equals("b3") && n == 1 ? bm(1) : r.get());
    }

    @Test void burstFailures() {
        String t = "fail budget-burst: ";
        budgetFault(3, t + "setup claim refused", (h, p, c, bf, af, r) -> p.equals("b4") && c == 1 ? replay(null) : r.get(), null);
        budgetFault(3, t + "round 2: 3 of 3 claims against one budget were admitted (want exactly 1)",
            (h, p, c, bf, af, r) -> { StateStore.ClaimResult x = r.get(); return p.equals("b4") && c >= 2 ? claimed() : x; }, null);
        budgetFault(3, t + "round 2: 0 of 3 claims against one budget were admitted (want exactly 1)", (h, p, c, bf, af, r) -> p.equals("b4") && c >= 2 ? replay(0L) : r.get(), null);
        budgetFault(3, t + "round 3: 3 of 3 claims against one budget were admitted (want exactly 1)",
            (h, p, c, bf, af, r) -> { StateStore.ClaimResult x = r.get(); return p.equals("b4") && c == 3 ? claimed() : x; }, null);
        budgetFault(3, t + "2 of 3 concurrent calls raised: java.lang.IllegalStateException: busy", (h, p, c, bf, af, r) -> {
            StateStore.ClaimResult x = r.get();
            if (p.equals("b4") && c >= 2 && !x.ok) throw new IllegalStateException("busy");
            return x;
        }, null);
        budgetFault(3, t + "round 2: the budget must be debited exactly once", null, (h, p, n, r) -> p.equals("b4") && n == 2 ? bm(5) : r.get());
        budgetFault(3, t + "round 3: the budget must be debited exactly once", null, (h, p, n, r) -> p.equals("b4") && n == 4 ? bm(5) : r.get());
    }

    @Test void keysIndependentAndDurabilityFailures() {
        String k = "fail budget-keys-independent: ";
        budgetFault(4, k + "claim refused", (h, p, c, bf, af, r) -> p.equals("b5a") ? replay(null) : r.get(), null);
        budgetFault(4, k + "another key must hold no budget", null, (h, p, n, r) -> p.equals("b5b") && n == 1 ? bm(1) : r.get());
        budgetFault(4, k + "another key must be independent", (h, p, c, bf, af, r) -> p.equals("b5b") ? replay(null) : r.get(), null);
        budgetFault(4, k + "the first key's budget changed", null, (h, p, n, r) -> p.equals("b5a") && n == 1 ? bm(7) : r.get());
        String d = "fail budget-durability: ";
        budgetFault(5, d + "claim refused", (h, p, c, bf, af, r) -> p.equals("b6") ? replay(null) : r.get(), null);
        budgetFault(5, d + "the budget was lost across a restart, got {B=7.0, tau=1000.0, asOf=1000.0}", null, (h, p, n, r) -> p.equals("b6") ? bm(7) : r.get());
        BBackend wipe = new BBackend();
        wipe.wipeOnRestart = true;
        StoreConformance.Report rep = runBudget(wipe, opts(wipe, 3, 2, 2));
        assertEquals(budgetRender(3, 2, 5, d + "the budget was lost across a restart, got null"), rep.render());
    }

    // ---- the kv registries ----------------------------------------------------------------------------------------------

    static final class KvBackend {
        final Log log = new Log();
        final MemoryAtomicKv shared = new MemoryAtomicKv();
        final Map<String, Object> lastStored = new ConcurrentHashMap<>();
        final List<String> outcomes = Collections.synchronizedList(new ArrayList<>());
        boolean fresh, amnesia, updateThrows, hideMax, closeThrows;
        String failPrefix;
        int failAfter, shardUpdates;

        KvHandle open() { return new KvHandle(this, log.nextHandle()); }
    }

    static final class KvHandle implements AtomicKv, AutoCloseable {
        final KvBackend b;
        final int h;
        final MemoryAtomicKv store;

        KvHandle(KvBackend b, int h) {
            this.b = b;
            this.h = h;
            this.store = b.fresh ? new MemoryAtomicKv() : b.shared;
        }

        @Override public Object get(String key) {
            b.log.add("h" + h + " get " + key);
            if (b.amnesia || (b.hideMax && key.equals("blueprint/max"))) return null;
            return store.get(key);
        }

        @Override public void set(String key, Object value) {
            b.log.add("h" + h + " set " + key);
            store.set(key, value);
        }

        @Override public Object update(String key, UnaryOperator<Object> fn) {
            b.log.add("h" + h + " update " + key);
            if (b.updateThrows) throw new IllegalStateException("update down");
            if (b.failPrefix != null && key.startsWith(b.failPrefix + "/") && key.matches("[a-z]+/\\d+/\\d+")) {
                boolean fail;
                synchronized (b) { fail = b.shardUpdates++ >= b.failAfter; }
                if (fail) throw new IllegalStateException("shard down");
            }
            if (b.amnesia) return fn.apply(null);
            return store.update(key, prev -> {
                Object n = fn.apply(prev);
                b.outcomes.add(key + (n == null ? " keep" : " set"));
                if (n != null) b.lastStored.put(key, n);
                return n;
            });
        }

        @Override public void close() throws Exception {
            b.log.add("h" + h + " close");
            if (b.closeThrows) throw new Exception("close failed");
        }
    }

    static Map<String, Object> lease() { return Track3Vectors.load("lease-vectors.json"); }

    static Map<String, Object> bg() { return Track3Vectors.load("break-glass-vectors.json"); }

    static Map<String, Object> bp() { return Track3Vectors.load("blueprint-vectors.json"); }

    static StoreConformance.Report runKv(KvBackend b, StoreConformance.Options o) {
        return StoreConformance.runKvRegistryConformance(b::open, o, lease(), bg(), bp());
    }

    static final String[] KV_TESTS = {"lease-revocation-survives-reopen", "lease-shard-count-is-pinned", "break-glass-budget-is-shared", "break-glass-concurrent-uses", "blueprint-stale-epoch-is-refused"};

    static String kvRender(int idx, String line) {
        String[] ls = new String[KV_TESTS.length];
        for (int i = 0; i < ls.length; i++) ls[i] = "pass " + KV_TESTS[i];
        if (idx >= 0) ls[idx] = line;
        return lines(ls);
    }

    static StoreConformance.Options kvOpts(KvBackend b, int threads, int handles) {
        return new StoreConformance.Options().threads(threads).handles(handles).teardown(() -> b.log.add("teardown"));
    }

    static String joined(KvBackend b) { return String.join("\n", b.lastStored.entrySet().stream().map(e -> e.getKey() + "=" + Json.canonicalize(e.getValue())).sorted().toArray(String[]::new)); }

    @Test void aSharedKvPassesAndRecordsTheVectorRecordsNotOthers() {
        KvBackend b = new KvBackend();
        StoreConformance.Report rep = runKv(b, kvOpts(b, 3, 2).name("kvs"));
        assertEquals("kvs", rep.name);
        assertEquals(kvRender(-1, null), rep.render());
        assertTrue(rep.ok());
        // 2 + 1 + 2 + (1 + 2 handles) + 2 handles, each closed once and never re-opened
        assertEquals(10, b.log.handles);
        for (int h = 0; h < 10; h++) assertEquals(1, count(b.log.ordered(), "h" + h + " close"), "h" + h);
        assertEquals("teardown", b.log.ordered().get(b.log.ordered().size() - 1));
        String all = joined(b);
        // the lease record 0 (seq 1) and the revocation 0 (a lease revocation) are what the store holds, not the renewal or the prefix revocation
        assertTrue(all.contains("\"lease_id\":\"L1\""), all);
        // the first test pinned two shards; the shard-count test's registries of other counts were refused and wrote nothing
        assertTrue(b.lastStored.keySet().stream().anyMatch(k -> k.startsWith("lease/2/")), all);
        assertTrue(b.lastStored.keySet().stream().noneMatch(k -> k.startsWith("lease/3/") || k.startsWith("lease/5/")), all);
        assertTrue(all.contains("lease/meta={\"shards\":2,\"v\":1}"), all);
        assertTrue(all.contains("\"target\":\"lease\""), all);
        assertTrue(all.contains("\"revoked_at\":1800000100000"), all);
        assertFalse(all.contains("\"target\":\"prefix\""), all);
        assertFalse(all.contains("\"seq\":2"), all);
        // the one use of bg2 is recorded at exactly the time it was made
        assertTrue(all.contains("\"action_digest\":\"act-1\",\"at\":1800000000000"), all);
        // every concurrent use of bg3 is recorded at its own time: base + the index in its action digest
        Matcher m2 = Pattern.compile("\"action_digest\":\"act-(\\d+)\",\"at\":(\\d+)").matcher(all);
        while (m2.find()) {
            long i = Long.parseLong(m2.group(1)), at = Long.parseLong(m2.group(2));
            assertTrue(at == 1800000000000L || at == 1800000000000L + i, "use act-" + i + " recorded at " + at);
        }
        // the blueprint registry holds the highest epoch and kept it through the stale record
        assertTrue(all.contains("blueprint/max={\"epoch\":3}"), all);
    }

    @Test void kvDefaultOptionsAndNoHooks() {
        for (StoreConformance.Options o : Arrays.asList(null, new StoreConformance.Options())) {
            KvBackend b = new KvBackend();
            StoreConformance.Report rep = runKv(b, o);
            assertEquals("kv registries", rep.name);
            assertEquals(kvRender(-1, null), rep.render());
            assertEquals(8 + 4, b.log.handles);
        }
    }

    @Test void aProcessLocalKvSkipsEverySharedTest() {
        KvBackend b = new KvBackend();
        StoreConformance.Report rep = runKv(b, kvOpts(b, 3, 2).shared(false));
        StringBuilder want = new StringBuilder();
        for (String t : KV_TESTS) want.append("skip ").append(t).append(": the adapter declares shared(false)\n");
        assertEquals(want.toString(), rep.render());
        assertEquals(0, b.log.handles);
        assertEquals(Arrays.asList("teardown"), b.log.ordered());
        assertFalse(rep.ok());
    }

    @Test void aHandleWhoseCloseThrowsIsStillClosedByTheKvProfile() {
        KvBackend b = new KvBackend();
        b.closeThrows = true;
        StoreConformance.Report rep = runKv(b, kvOpts(b, 3, 2));
        assertEquals(kvRender(-1, null), rep.render());
        assertEquals(10, b.log.sorted().stream().filter(s -> s.endsWith(" close")).count());
    }

    @Test void aKvFactoryWithoutAStoreFailsEveryTest() {
        String no = ": the factory returned no store";
        Log log = new Log();
        StoreConformance.Report rep = StoreConformance.runKvRegistryConformance(() -> null, new StoreConformance.Options().teardown(() -> log.add("teardown")), lease(), bg(), bp());
        StringBuilder want = new StringBuilder();
        for (String t : KV_TESTS) want.append("fail ").append(t).append(no).append('\n');
        assertEquals(want.toString(), rep.render());
        assertEquals(Arrays.asList("teardown"), log.ordered());
    }

    @Test void kvFaults() {
        // the lease cannot be taken at all
        KvBackend down = new KvBackend();
        down.updateThrows = true;
        assertEquals("fail lease-revocation-survives-reopen: the lease was refused", resultOf(runKv(down, kvOpts(down, 3, 2)), 0));
        // the revocation cannot be written (the lease itself was)
        KvBackend rev = new KvBackend();
        rev.failPrefix = "lease";
        rev.failAfter = 1;
        assertEquals("fail lease-revocation-survives-reopen: the revocation was refused", resultOf(runKv(rev, kvOpts(rev, 3, 2)), 0));
        // every handle is its own island: nothing is shared
        KvBackend fresh = new KvBackend();
        fresh.fresh = true;
        StoreConformance.Report r = runKv(fresh, kvOpts(fresh, 3, 2));
        assertEquals("fail lease-revocation-survives-reopen: a registry on another handle did not see the revocation", resultOf(r, 0));
        assertEquals("fail break-glass-budget-is-shared: a second use of a max_uses=1 grant on another handle was not refused", resultOf(r, 2));
        assertEquals("fail break-glass-concurrent-uses: 0 concurrent uses of a max_uses=2 grant were allowed (want exactly 2)", resultOf(r, 3));
        assertEquals("fail blueprint-stale-epoch-is-refused: an older epoch was accepted on another handle", resultOf(r, 4));
        // a store that forgets what it was first used with cannot pin the shard count
        KvBackend amnesic = new KvBackend();
        amnesic.amnesia = true;
        assertEquals("fail lease-shard-count-is-pinned: a registry with another shard count must be refused as store_unreachable", resultOf(runKv(amnesic, kvOpts(amnesic, 3, 2)), 1));
        // the first break-glass use cannot be recorded
        KvBackend use = new KvBackend();
        use.failPrefix = "breakglass";
        use.failAfter = 1;
        assertEquals("fail break-glass-budget-is-shared: the first use was refused", resultOf(runKv(use, kvOpts(use, 3, 2)), 2));
        // the grant itself cannot be recorded
        KvBackend grant = new KvBackend();
        grant.updateThrows = true;
        StoreConformance.Report gr = runKv(grant, kvOpts(grant, 3, 2));
        assertEquals("fail break-glass-budget-is-shared: the grant was refused", resultOf(gr, 2));
        assertEquals("fail break-glass-concurrent-uses: the grant was refused", resultOf(gr, 3));
        assertEquals("fail blueprint-stale-epoch-is-refused: the epoch 3 record was refused", resultOf(gr, 4));
        // the highest epoch must be visible on the other handle
        KvBackend hide = new KvBackend();
        hide.hideMax = true;
        assertEquals("fail blueprint-stale-epoch-is-refused: the highest epoch must be visible on another handle", resultOf(runKv(hide, kvOpts(hide, 3, 2)), 4));
    }

    static String resultOf(StoreConformance.Report r, int idx) { return r.results.get(idx).toString(); }

    @Test void aStoreWithNoHandlesToRaceOverIsReportedNotHidden() {
        KvBackend b = new KvBackend();
        StoreConformance.Report rep = runKv(b, kvOpts(b, 3, 0));
        assertEquals("fail break-glass-concurrent-uses: 3 of 3 concurrent calls raised: java.lang.ArithmeticException: / by zero", resultOf(rep, 3));
    }

    // ---- the blueprint registry on a recording store --------------------------------------------------------------------

    static Map<String, Object> blueprint(String key, int epoch) {
        Map<String, Object> b = BlueprintKillTest.base();
        b.put("key", key);
        b.put("epoch", epoch);
        return BlueprintKillTest.signed(b, BlueprintKillTest.OP);
    }

    @Test void theHighestEpochMovesOnlyWhenARecordIsReplacedByAHigherOrFirstEpoch() {
        KvBackend b = new KvBackend();
        Blueprint.Registry r = new Blueprint.Registry(Arrays.asList(BlueprintKillTest.OP.id()), b.open());
        assertEquals(0L, r.epoch());
        assertNull(r.accept(blueprint("K1", 5)).code);
        assertEquals(5L, r.epoch());
        assertNull(r.accept(blueprint("K2", 5)).code); // an equal epoch on another key does not rewrite the highest
        assertEquals(5L, r.epoch());
        assertNull(r.accept(blueprint("K3", 4)).code); // a lower one never lowers it
        assertEquals(5L, r.epoch());
        assertNull(r.accept(blueprint("K4", 6)).code);
        assertEquals(6L, r.epoch());
        // the identical record again changes nothing and does not touch the highest epoch
        assertNull(r.accept(blueprint("K4", 6)).code);
        assertEquals("stale_epoch", r.accept(blueprint("K4", 2)).code);
        assertEquals(6L, r.epoch());
        List<String> maxes = new ArrayList<>();
        for (String o : b.outcomes) if (o.startsWith("blueprint/max")) maxes.add(o);
        assertEquals(Arrays.asList("blueprint/max set", "blueprint/max keep", "blueprint/max keep", "blueprint/max set"), maxes);
    }

    @Test void aStoreThatDoesNothingOrThrowsIsStoreUnreachableAndNotReplaced() {
        AtomicKv lying = new AtomicKv() {
            @Override public Object get(String key) { return null; }
            @Override public void set(String key, Object value) {}
            @Override public Object update(String key, UnaryOperator<Object> fn) { return null; }
        };
        Blueprint.Accept a = new Blueprint.Registry(Arrays.asList(BlueprintKillTest.OP.id()), lying).accept(blueprint("K1", 1));
        assertEquals("store_unreachable", a.code);
        assertFalse(a.replaced);
        AtomicKv throwing = new AtomicKv() {
            @Override public Object get(String key) { return null; }
            @Override public void set(String key, Object value) {}
            @Override public Object update(String key, UnaryOperator<Object> fn) { throw new IllegalStateException("down"); }
        };
        Blueprint.Accept t = new Blueprint.Registry(Arrays.asList(BlueprintKillTest.OP.id()), throwing).accept(blueprint("K1", 1));
        assertEquals("store_unreachable", t.code);
        assertFalse(t.replaced);
    }
}
