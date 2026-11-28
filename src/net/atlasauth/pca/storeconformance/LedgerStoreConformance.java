package net.atlasauth.pca.storeconformance;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.function.Supplier;
import net.atlasauth.pca.AtomicKv;
import net.atlasauth.pca.KvLedgerStore;
import net.atlasauth.pca.LedgerDoc;
import net.atlasauth.pca.LedgerStore;
import net.atlasauth.pca.MemoryAtomicKv;
import net.atlasauth.pca.StoreJs;
import net.atlasauth.pca.storeconformance.Suite.Check;

/**
 * Conformance for transparency-log stores ({@link LedgerStore}). A ledger store is the durable side of a tamper-evident log: what it
 * must get right is atomic compare-and-swap on the length (one winner per position, all of a batch or none, no holes), idempotent retries,
 * the cryptography-free checkpoint rules, and durability of acknowledged writes. Each check is one such claim, driven against YOUR store
 * through an {@link Adapter}; a violation throws with the exact mismatch.
 */
public final class LedgerStoreConformance {
    private LedgerStoreConformance() {}

    /** One isolated backend plus the means to reconnect to it. */
    public static final class Handle implements Suite.Handle {
        public final LedgerStore store;
        private final Callable<LedgerStore> reopen, crash;
        private final Callable<Void> closer;

        public Handle(LedgerStore store, Callable<LedgerStore> reopen, Callable<LedgerStore> crash, Callable<Void> closer) {
            this.store = store;
            this.reopen = reopen;
            this.crash = crash;
            this.closer = closer;
        }

        /** Another client on the SAME backend (the first stays usable). */
        public LedgerStore reopen() throws Exception { return reopen.call(); }

        /** Kill the backend abruptly (no flush), then return a client on whatever survived. */
        public LedgerStore crash() throws Exception { return crash.call(); }

        @Override public boolean canCrash() { return crash != null; }

        @Override public void close() throws Exception { if (closer != null) closer.call(); }
    }

    /** The adapter a store author implements. */
    public interface Adapter {
        String name();

        /** Default true. Declare false ONLY for an in-process store; the durability checks are then skipped and reported. */
        default boolean durable() { return true; }

        /** A fresh, empty, isolated backend. Called once per check. */
        Handle create() throws Exception;
    }

    // ---- fixtures ----

    static String cm(int i) { return "commit-" + i + "-" + "x".repeat(30); }

    static Map<String, Object> cp(long size) { return cp(size, "root-" + size, ""); }

    static Map<String, Object> cp(long size, String root, String prev) {
        Map<String, Object> sth = new LinkedHashMap<>();
        sth.put("instance_id", "i");
        sth.put("principal", "p");
        sth.put("size", StoreJs.num(size));
        sth.put("root", root);
        sth.put("prev_root", prev);
        sth.put("timestamp", StoreJs.num(1));
        sth.put("guardian", "g");
        sth.put("sig", "s");
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("sth", sth);
        return c;
    }

    static List<String> range(int a, int b) {
        List<String> out = new ArrayList<>();
        for (int i = a; i < b; i++) out.add(cm(i));
        return out;
    }

    static List<String> all(LedgerStore s) { return s.read(0, s.size()); }

    static Map<String, Object> outcome(String o, long size) { return new LedgerStore.AppendOutcome(o, size).toJson(); }

    static Map<String, Object> cpOutcome(String o, long count) { return new LedgerStore.CheckpointOutcome(o, count, null).toJson(); }

    static List<Object> sizes(List<Map<String, Object>> cps) {
        List<Object> out = new ArrayList<>();
        for (Map<String, Object> c : cps) out.add(StoreJs.map(c.get("sth")).get("size"));
        return out;
    }

    /** A writer that retries until its commit is in, the way a real client does. */
    static long appendRetrying(LedgerStore s, String commit) {
        for (;;) {
            long size = s.size();
            LedgerStore.AppendOutcome r = s.append(size, List.of(commit));
            if (r.outcome.equals("appended") || r.outcome.equals("replayed")) return size;
        }
    }

    // ---- the checks ----

    public static final List<Check<Handle>> CHECKS = List.of(
        new Check<Handle>("empty-store-is-empty", "a new store has no entries and no checkpoints, and reads of the empty range succeed", h -> {
            LedgerStore s = h.store;
            Suite.eq(0, s.size());
            Suite.eq(List.of(), s.read(0, 0));
            Suite.eq(0, s.checkpointCount());
            Suite.eq(List.of(), s.checkpoints(0));
        }),
        new Check<Handle>("append-assigns-the-next-position", "an append at the current length adds its commits in order at exactly those positions", h -> {
            LedgerStore s = h.store;
            Suite.eq(outcome("appended", 1), s.append(0, List.of(cm(0))).toJson());
            Suite.eq(outcome("appended", 3), s.append(1, List.of(cm(1), cm(2))).toJson());
            Suite.eq(range(0, 3), s.read(0, 3));
            Suite.eq(range(1, 3), s.read(1, 3));
            Suite.eq(List.of(), s.read(3, 3));
        }),
        new Check<Handle>("append-at-another-position-conflicts-without-trace", "an append whose expected length is not the current length conflicts, reports the real length, and writes nothing", h -> {
            LedgerStore s = h.store;
            s.append(0, range(0, 3));
            Suite.eq(outcome("conflict", 3), s.append(5, List.of(cm(9))).toJson());
            Suite.eq(outcome("conflict", 3), s.append(2, List.of(cm(9))).toJson());
            Suite.eq(range(0, 3), all(s));
        }),
        new Check<Handle>("append-retry-is-a-replay", "repeating a batch already stored at that position is a replay (a prefix of it too); a different batch there conflicts", h -> {
            LedgerStore s = h.store;
            s.append(0, range(0, 3));
            Suite.eq(outcome("replayed", 3), s.append(0, range(0, 3)).toJson());
            Suite.eq(outcome("replayed", 3), s.append(1, range(1, 3)).toJson());
            Suite.eq(outcome("conflict", 3), s.append(0, List.of(cm(0), "other")).toJson());
            Suite.eq(outcome("conflict", 3), s.append(2, List.of(cm(2), cm(3))).toJson());
            Suite.eq(range(0, 3), all(s));
        }),
        new Check<Handle>("invalid-input-is-refused", "empty batches, empty or non-string commits and a bad expected length throw and write nothing", h -> {
            LedgerStore s = h.store;
            s.append(0, List.of(cm(0)));
            for (List<String> bad : List.of(List.<String>of(), List.of(""), Arrays.asList(cm(1), null), Arrays.asList((String) null))) {
                Suite.rejects(IllegalArgumentException.class, () -> s.append(1, bad), "append of " + bad);
            }
            for (long bad : new long[] {-1, Long.MAX_VALUE, 9007199254740992L}) Suite.rejects(IllegalArgumentException.class, () -> s.append(bad, List.of(cm(1))), "append at " + bad);
            Suite.eq(List.of(cm(0)), all(s));
            for (long[] r : new long[][] {{-1, 1}, {1, 0}, {0, 2}}) Suite.rejects(IllegalArgumentException.class, () -> s.read(r[0], r[1]), "read " + Arrays.toString(r));
        }),
        new Check<Handle>("commit-strings-are-stored-exactly", "unicode, quotes, separators and long commits come back byte for byte", h -> {
            LedgerStore s = h.store;
            List<String> odd = List.of("a\"b\\c", "gr\u00e4nt-\ud83d\udd12-\t-\u0001", "x".repeat(5000), "__proto__", " leading and trailing ");
            s.append(0, odd);
            Suite.eq(odd, all(s));
        }),
        new Check<Handle>("racing-appends-at-one-position-have-one-winner", "clients appending at the same expected length: exactly one is appended, none is lost or duplicated, the log is the winner batch", h -> {
            List<LedgerStore> clients = new ArrayList<>(List.of(h.store, h.reopen(), h.reopen(), h.reopen()));
            List<Callable<LedgerStore.AppendOutcome>> tasks = new ArrayList<>();
            for (int i = 0; i < 8; i++) { int n = i; tasks.add(() -> clients.get(n % 4).append(0, List.of(cm(100 + n)))); }
            List<LedgerStore.AppendOutcome> r = Suite.parallel(tasks);
            Suite.eq(1, r.stream().filter(x -> x.outcome.equals("appended")).count());
            Suite.eq(7, r.stream().filter(x -> x.outcome.equals("conflict")).count());
            List<String> log = all(h.store);
            Suite.eq(1, log.size());
            Suite.ok(range(100, 108).contains(log.get(0)), "the log holds a winner's commit");
        }),
        new Check<Handle>("racing-writers-with-retry-fill-every-position-once", "sixteen writers each retrying until their commit is in: positions are unique, there are no holes, every commit is present exactly once", h -> {
            List<LedgerStore> clients = List.of(h.store, h.reopen(), h.reopen());
            List<Callable<Long>> tasks = new ArrayList<>();
            for (int i = 0; i < 16; i++) { int n = i; tasks.add(() -> appendRetrying(clients.get(n % 3), cm(200 + n))); }
            List<Long> idx = Suite.parallel(tasks);
            Suite.eq(16, new LinkedHashSet<>(idx).size());
            List<Long> sorted = new ArrayList<>(idx);
            Collections.sort(sorted);
            List<Object> want = new ArrayList<>();
            for (long i = 0; i < 16; i++) want.add(i);
            Suite.eq(want, sorted);
            List<String> log = all(h.store);
            Suite.eq(new ArrayList<>(new TreeSet<>(range(200, 216))), new ArrayList<>(new TreeSet<>(log)));
            Suite.eq(16, log.size());
            for (int i = 0; i < 16; i++) Suite.eq(cm(200 + i), log.get((int) (long) idx.get(i)));
        }),
        new Check<Handle>("a-batch-is-all-or-nothing", "a batch that conflicts leaves none of its commits behind, and a batch that lands lands every commit", h -> {
            LedgerStore s = h.store;
            s.append(0, range(0, 2));
            Suite.eq("conflict", s.append(5, range(10, 14)).outcome);
            Suite.eq(range(0, 2), all(s));
            Suite.eq(outcome("appended", 6), s.append(2, range(10, 14)).toJson());
            List<String> want = new ArrayList<>(range(0, 2));
            want.addAll(range(10, 14));
            Suite.eq(want, all(s));
        }),
        new Check<Handle>("checkpoints-append-by-count-and-replay", "a checkpoint appends at the exact count; the same one again is a replay; another at that position conflicts", h -> {
            LedgerStore s = h.store;
            s.append(0, range(0, 6));
            Suite.eq(cpOutcome("appended", 1), s.appendCheckpoint(0, cp(2)).toJson());
            Suite.eq(cpOutcome("replayed", 1), s.appendCheckpoint(0, cp(2)).toJson());
            Suite.eq("conflict", s.appendCheckpoint(0, cp(3)).outcome);
            Suite.eq("conflict", s.appendCheckpoint(2, cp(3)).outcome);
            Suite.eq(cpOutcome("appended", 2), s.appendCheckpoint(1, cp(5, "root-5", "root-2")).toJson());
            Suite.eq(List.of(2, 5), sizes(s.checkpoints(0)));
            Suite.eq(List.of(5), sizes(s.checkpoints(1)));
            Suite.eq(2, s.checkpointCount());
        }),
        new Check<Handle>("checkpoints-stay-inside-the-log-and-never-go-back", "a checkpoint beyond the end of the log, below the previous one, or equal in size with another root is refused", h -> {
            LedgerStore s = h.store;
            s.append(0, range(0, 4));
            Suite.eq("conflict", s.appendCheckpoint(0, cp(5)).outcome);
            Suite.eq("appended", s.appendCheckpoint(0, cp(3)).outcome);
            Suite.eq("conflict", s.appendCheckpoint(1, cp(2)).outcome);
            Suite.eq("conflict", s.appendCheckpoint(1, cp(3, "other-root", "")).outcome);
            Suite.eq("appended", s.appendCheckpoint(1, cp(3)).outcome); // equal size, same root: allowed
            Suite.eq("conflict", s.appendCheckpoint(2, null).outcome);
            Suite.eq(2, s.checkpointCount());
        }),
        new Check<Handle>("racing-checkpoints-have-one-winner", "checkpoints racing for one position: exactly one lands", h -> {
            h.store.append(0, range(0, 6));
            LedgerStore other = h.reopen();
            List<LedgerStore> who = List.of(h.store, other, h.store, other);
            List<Callable<LedgerStore.CheckpointOutcome>> tasks = new ArrayList<>();
            for (int i = 0; i < 4; i++) { int n = i; tasks.add(() -> who.get(n).appendCheckpoint(0, cp(2 + n))); }
            List<LedgerStore.CheckpointOutcome> r = Suite.parallel(tasks);
            Suite.eq(1, r.stream().filter(x -> x.outcome.equals("appended")).count());
            Suite.eq(1, h.store.checkpointCount());
        }),
        new Check<Handle>("reads-are-snapshots", "mutating what a read returned cannot change the store", h -> {
            LedgerStore s = h.store;
            s.append(0, range(0, 3));
            s.appendCheckpoint(0, cp(2));
            try { s.read(0, 3).set(0, "mutated"); } catch (UnsupportedOperationException ignored) { /* an unmodifiable copy is as good */ }
            List<Map<String, Object>> c = s.checkpoints(0);
            StoreJs.map(c.get(0).get("sth")).put("size", StoreJs.num(99));
            Suite.eq(range(0, 3), all(s));
            Suite.eq(2, StoreJs.map(s.checkpoints(0).get(0).get("sth")).get("size"));
        }),
        new Check<Handle>("state-survives-reopen", "every acknowledged append and checkpoint is visible to a new client after the backend restarts", "durable", h -> {
            h.store.append(0, range(0, 5));
            h.store.appendCheckpoint(0, cp(3));
            h.store.append(5, range(5, 7));
            LedgerStore back = h.reopen();
            Suite.eq(range(0, 7), all(back));
            Suite.eq(List.of(cp(3)), back.checkpoints(0));
            Suite.eq(outcome("appended", 8), back.append(7, List.of(cm(7))).toJson());
        }),
        new Check<Handle>("acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged write is present and the log is a prefix of what was written: no holes, no partial batch", "crash", h -> {
            h.store.append(0, range(0, 3));
            h.store.appendCheckpoint(0, cp(2));
            Thread inflight = new Thread(() -> { try { h.store.append(3, range(3, 7)); } catch (RuntimeException ignored) { /* killed in flight */ } });
            inflight.start();
            LedgerStore back = h.crash();
            inflight.join();
            List<String> log = all(back);
            Suite.ok(log.size() == 3 || log.size() == 7, "log has " + log.size() + " entries"); // the batch of four is whole or absent
            Suite.eq(range(0, log.size()), log);
            Suite.eq(List.of(cp(2)), back.checkpoints(0));
            Suite.eq(outcome(log.size() == 3 ? "appended" : "replayed", 7), back.append(3, range(3, 7)).toJson());
            Suite.eq(range(0, 7), all(back));
        })
    );

    /** Run the suite against {@code adapter} (only the named checks when {@code only} is non-null). */
    public static Suite.Report run(Adapter adapter, Collection<String> only) {
        return Suite.run("ledger store", adapter.name(), adapter.durable(), adapter::create, CHECKS, only);
    }

    public static Suite.Report run(Adapter adapter) { return run(adapter, null); }

    // ---- reference adapters: GOOD ones must pass, BAD ones are positive controls the suite MUST flag ----

    /** An adapter over any {@link AtomicKv}: {@code backend} opens one isolated backend and returns a supplier of clients on it. */
    public static Adapter kvAdapter(String name, boolean durable, Callable<Supplier<AtomicKv>> backend, boolean crashable) {
        return new Adapter() {
            @Override public String name() { return name; }
            @Override public boolean durable() { return durable; }
            @Override public Handle create() throws Exception {
                Supplier<AtomicKv> clients = backend.call();
                Callable<LedgerStore> open = () -> new KvLedgerStore(clients.get());
                return new Handle(open.call(), open, crashable ? open : null, null);
            }
        };
    }

    /** GOOD, in process: the reference store over a {@link MemoryAtomicKv}. Not durable (declared). */
    public static Adapter memoryAdapter() {
        return kvAdapter("KvLedgerStore over MemoryAtomicKv", false, () -> { MemoryAtomicKv kv = new MemoryAtomicKv(); return () -> kv; }, false);
    }

    /** The mistakes a bad store makes. */
    public enum Defect {
        NO_CAS("BAD no compare-and-swap (appends at the tail whatever the caller saw)"),
        PARTIAL_BATCH("BAD partial batch (a conflicting batch leaves its first commit behind)"),
        LOST_UPDATE("BAD lost update (read, pause, write)"),
        AMNESIA("BAD amnesia (claims durability, forgets on reopen)"),
        CHECKPOINT_REGRESS("BAD checkpoint regression (accepts a checkpoint below the previous one)"),
        NO_REPLAY("BAD no idempotence (a retried batch conflicts)");

        final String label;
        Defect(String label) { this.label = label; }
    }

    /** A store with one switchable defect, for the positive controls (each reproduces a real mistake). */
    private static final class Defective implements LedgerStore {
        private final Defect defect;
        private final Object lock = new Object();
        private volatile LedgerDoc doc = LedgerDoc.empty();

        Defective(Defect defect) { this.defect = defect; }

        void forget() { doc = LedgerDoc.empty(); }

        @Override public long size() { return doc.commits.size(); }

        @Override public List<String> read(long f, long t) {
            LedgerDoc d = doc;
            if (f < 0 || f > t || t > d.commits.size()) throw new IllegalArgumentException("read");
            return new ArrayList<>(d.commits.subList((int) f, (int) t));
        }

        @Override public AppendOutcome append(long expected, List<String> commits) {
            if (expected < 0 || commits == null || commits.isEmpty()) throw new IllegalArgumentException("append");
            for (String c : commits) if (c == null || c.isEmpty()) throw new IllegalArgumentException("append");
            if (defect == Defect.LOST_UPDATE) {
                LedgerDoc work = LedgerDoc.decode(doc.toJson());
                try { Thread.sleep(2); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                AppendOutcome out = LedgerDoc.appendToLedgerDoc(work, expected, commits);
                if (out.outcome.equals("appended")) doc = work;
                return out;
            }
            synchronized (lock) {
                LedgerDoc d = doc;
                if (defect == Defect.NO_CAS) {
                    d.commits.addAll(commits);
                    return new AppendOutcome("appended", d.commits.size());
                }
                if (defect == Defect.PARTIAL_BATCH && expected != d.commits.size()) {
                    d.commits.add(commits.get(0));
                    return new AppendOutcome("conflict", d.commits.size());
                }
                AppendOutcome out = LedgerDoc.appendToLedgerDoc(d, expected, commits);
                if (defect == Defect.NO_REPLAY && out.outcome.equals("replayed")) return new AppendOutcome("conflict", out.size);
                return out;
            }
        }

        @Override public long checkpointCount() { return doc.checkpoints.size(); }

        @Override public List<Map<String, Object>> checkpoints(long from) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Map<String, Object> c : doc.checkpoints.subList((int) from, doc.checkpoints.size())) out.add(StoreJs.map(StoreJs.deepCopy(c)));
            return out;
        }

        @Override public CheckpointOutcome appendCheckpoint(long expected, Map<String, Object> c) {
            synchronized (lock) {
                LedgerDoc d = doc;
                Map<String, Object> sth = c == null ? null : StoreJs.map(c.get("sth"));
                if (defect == Defect.CHECKPOINT_REGRESS && expected == d.checkpoints.size() && sth != null) {
                    d.checkpoints.add(StoreJs.map(StoreJs.deepCopy(c)));
                    return new CheckpointOutcome("appended", d.checkpoints.size(), null);
                }
                return LedgerDoc.checkpointToLedgerDoc(d, expected, c);
            }
        }
    }

    /** A bad adapter: one store object shared by every client (a reopen on AMNESIA clears it). */
    public static Adapter defectiveAdapter(Defect defect) {
        return new Adapter() {
            @Override public String name() { return defect.label; }
            @Override public Handle create() {
                Defective d = new Defective(defect);
                Callable<LedgerStore> again = () -> { if (defect == Defect.AMNESIA) d.forget(); return d; };
                return new Handle(d, again, again, null);
            }
        };
    }

    /** The reference adapters by name (the bad ones are positive controls). */
    public static Map<String, Supplier<Adapter>> referenceAdapters() {
        Map<String, Supplier<Adapter>> m = new LinkedHashMap<>();
        m.put("ledger-memory", LedgerStoreConformance::memoryAdapter);
        for (Defect d : Defect.values()) m.put("bad-ledger-" + d.name().toLowerCase().replace('_', '-'), () -> defectiveAdapter(d));
        return m;
    }
}
