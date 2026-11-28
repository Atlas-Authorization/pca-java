package net.atlasauth.pca.storeconformance;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Supplier;
import net.atlasauth.pca.AtomicKv;
import net.atlasauth.pca.BudgetDoc;
import net.atlasauth.pca.BudgetLedger;
import net.atlasauth.pca.KvBudgetLedger;
import net.atlasauth.pca.MemoryAtomicKv;
import net.atlasauth.pca.StoreJs;
import net.atlasauth.pca.storeconformance.Suite.Check;

/**
 * Conformance for aggregate budget ledgers ({@link BudgetLedger}): no overspend at principal, org and fleet scope given a ledger that is
 * linearizable per key and durable. Each check is one claim (the cap holds under racing reservations, a reservation counts at once, a
 * release frees budget only for a real reservation, a committed event is never released, expiry frees only what never started, a crash can
 * only over-restrict), driven against YOUR ledger through an {@link Adapter}.
 */
public final class BudgetLedgerConformance {
    private BudgetLedgerConformance() {}

    /** One isolated backend plus the means to reconnect to it. */
    public static final class Handle implements Suite.Handle {
        public final BudgetLedger ledger;
        /** Set by the runner: the adapter's declared durability, so a check can compare it with the ledger's own claim. */
        public boolean adapterDurable = true;
        private final Callable<BudgetLedger> reopen, crash;
        private final Callable<Void> closer;

        public Handle(BudgetLedger ledger, Callable<BudgetLedger> reopen, Callable<BudgetLedger> crash, Callable<Void> closer) {
            this.ledger = ledger;
            this.reopen = reopen;
            this.crash = crash;
            this.closer = closer;
        }

        /** Another client on the SAME backend (the first stays usable). */
        public BudgetLedger reopen() throws Exception { return reopen.call(); }

        /** Kill the backend abruptly, then return a client on whatever survived. */
        public BudgetLedger crash() throws Exception { return crash.call(); }

        @Override public boolean canCrash() { return crash != null; }

        @Override public void close() throws Exception { if (closer != null) closer.call(); }
    }

    /** The adapter a ledger author implements. */
    public interface Adapter {
        String name();

        /** Default true. Declare false ONLY for an in-process ledger; its {@code durable()} must then be false too, and the durability checks are skipped. */
        default boolean durable() { return true; }

        Handle create() throws Exception;
    }

    // ---- fixtures ----

    static final long CAP = 200;
    static final String K = "principal/alice", K2 = "principal/bob";

    static Map<String, Object> spend() { return spend(Map.of()); }

    static Map<String, Object> spend(Map<String, Object> over) {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("id", "spend");
        a.put("agg", "sum");
        a.put("val", "action.params.amount");
        a.put("sel", Map.of("verbs", List.of("pay")));
        a.put("win", Map.of("kind", "task"));
        a.put("key", null);
        a.put("domain_max", StoreJs.num(CAP));
        a.put("holder", Map.of("kind", "site_local"));
        a.put("scope", "principal");
        a.putAll(over);
        return a;
    }

    static Map<String, Object> ev(String id, Object amount, long t) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("id", id);
        e.put("verb", "pay");
        e.put("resource", "r");
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("amount", amount instanceof Number ? StoreJs.num(((Number) amount).doubleValue()) : amount);
        e.put("params", params);
        e.put("t", StoreJs.num(t));
        return e;
    }

    static Map<String, Object> ev(String id, double amount) { return ev(id, amount, 1000); }

    static BudgetLedger.ReserveRequest req(Map<String, Object> event, List<Map<String, Object>> accs) {
        BudgetLedger.ReserveRequest r = new BudgetLedger.ReserveRequest();
        r.event = event;
        r.accumulators = accs;
        return r;
    }

    static BudgetLedger.ReserveRequest req(String id, double amount) { return req(ev(id, amount), List.of(spend())); }

    static BudgetLedger.ReserveRequest req(String id, double amount, Long expectedVersion, Long expiresAt) {
        BudgetLedger.ReserveRequest r = req(id, amount);
        r.expectedVersion = expectedVersion;
        r.expiresAt = expiresAt;
        return r;
    }

    static double reservedTotal(BudgetLedger l, String key) {
        double t = 0;
        for (Map<String, Object> e : l.snapshot(key).events) if (!"released".equals(e.get("status"))) t += StoreJs.dbl(StoreJs.map(e.get("params")).get("amount"));
        return t;
    }

    static List<Object> statuses(BudgetLedger l, String key) {
        List<Object> out = new ArrayList<>();
        for (Map<String, Object> e : l.snapshot(key).events) out.add(e.get("status"));
        return out;
    }

    static Map<String, Object> mkEvidence(String id) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", StoreJs.num(1));
        m.put("key", K);
        m.put("id", id);
        m.put("reason", "effect_failed");
        m.put("at", StoreJs.num(5));
        m.put("signer", "s");
        m.put("sig", "x");
        return m;
    }

    static long count(List<BudgetLedger.ReserveOutcome> r, String outcome) {
        long n = 0;
        for (BudgetLedger.ReserveOutcome o : r) if (o.outcome.equals(outcome)) n++;
        return n;
    }

    /** The outcome name, or the entry's status when the settlement was refused. */
    static String refusedStatus(BudgetLedger.SettleOutcome o) { return o.outcome.equals("refused") ? o.status : o.outcome; }

    static List<Callable<BudgetLedger.ReserveOutcome>> reserves(List<BudgetLedger> clients, int n, java.util.function.IntFunction<BudgetLedger.ReserveRequest> req) {
        List<Callable<BudgetLedger.ReserveOutcome>> tasks = new ArrayList<>();
        for (int i = 0; i < n; i++) { int k = i; tasks.add(() -> clients.get(k % clients.size()).reserve(K, req.apply(k))); }
        return tasks;
    }

    // ---- the checks ----

    public static final List<Check<Handle>> CHECKS = List.of(
        new Check<Handle>("empty-key-is-empty", "a key nobody reserved on has version 0 and no events", h -> {
            Map<String, Object> want = new LinkedHashMap<>();
            want.put("version", 0);
            want.put("events", List.of());
            Suite.eq(want, h.ledger.snapshot(K).toJson());
        }),
        new Check<Handle>("reservation-counts-at-once-and-cap-is-inclusive", "a reservation counts as soon as it is made; one that would pass the cap is refused with the post-value, one that reaches it exactly is admitted", h -> {
            BudgetLedger l = h.ledger;
            BudgetLedger.ReserveOutcome a = l.reserve(K, req("a", 150));
            Suite.eq("reserved", a.outcome);
            Suite.eq(Map.of("spend", 150), a.toJson().get("post"));
            BudgetLedger.ReserveOutcome b = l.reserve(K, req("b", 51));
            Suite.eq(List.of("over_cap", "spend", 201, CAP), List.of(b.outcome, String.valueOf(b.acc), b.postValue, b.cap));
            Suite.eq("reserved", l.reserve(K, req("c", 50)).outcome);
            Suite.eq(CAP, reservedTotal(l, K));
        }),
        new Check<Handle>("a-refusal-writes-nothing", "an over-cap reservation leaves no event and does not move the version", h -> {
            BudgetLedger l = h.ledger;
            l.reserve(K, req("a", 150));
            Map<String, Object> before = l.snapshot(K).toJson();
            Suite.eq("over_cap", l.reserve(K, req("b", 60)).outcome);
            Suite.eq(before, l.snapshot(K).toJson());
        }),
        new Check<Handle>("reserve-retry-is-a-replay", "the same event again is a replay that changes nothing and does not count twice; another event under the same id conflicts", h -> {
            BudgetLedger l = h.ledger;
            BudgetLedger.ReserveOutcome first = l.reserve(K, req("a", 150));
            Suite.eq(new BudgetLedger.ReserveOutcome("replayed", first.version, null, "reserved", null, null, null).toJson(), l.reserve(K, req("a", 150)).toJson());
            Suite.eq("id_conflict", l.reserve(K, req("a", 10)).outcome);
            Suite.eq(150, reservedTotal(l, K));
            Suite.eq("reserved", l.reserve(K, req("b", 50)).outcome);
        }),
        new Check<Handle>("expected-version-is-compare-and-swap", "a reservation naming a stale version conflicts and writes nothing; the current version succeeds; a replay wins over a stale version", h -> {
            BudgetLedger l = h.ledger;
            Suite.eq("reserved", l.reserve(K, req("a", 10, 0L, null)).outcome);
            Suite.eq(new BudgetLedger.ReserveOutcome("conflict", 1, null, null, null, null, null).toJson(), l.reserve(K, req("b", 10, 0L, null)).toJson());
            Suite.eq(1, l.snapshot(K).events.size());
            Suite.eq("reserved", l.reserve(K, req("b", 10, 1L, null)).outcome);
            Suite.eq("replayed", l.reserve(K, req("a", 10, 0L, null)).outcome);
        }),
        new Check<Handle>("racing-reserves-never-pass-the-cap", "forty reservations of 30 racing from four clients against a cap of 200: exactly six land, the total is never above the cap, none is lost or counted twice", h -> {
            List<BudgetLedger> clients = List.of(h.ledger, h.reopen(), h.reopen(), h.reopen());
            List<BudgetLedger.ReserveOutcome> rs = Suite.parallel(reserves(clients, 40, i -> req("r" + i, 30)));
            Suite.eq(6, count(rs, "reserved"));
            Suite.eq(34, count(rs, "over_cap"));
            Suite.eq(180, reservedTotal(h.ledger, K));
            java.util.Set<Object> ids = new java.util.HashSet<>();
            for (Map<String, Object> e : h.ledger.snapshot(K).events) ids.add(e.get("id"));
            Suite.eq(6, ids.size());
        }),
        new Check<Handle>("racing-reserves-at-one-version-have-one-winner", "clients reserving with the same expected version: exactly one lands, the others conflict", h -> {
            List<BudgetLedger> clients = List.of(h.ledger, h.reopen(), h.reopen());
            List<BudgetLedger.ReserveOutcome> rs = Suite.parallel(reserves(clients, 9, i -> req("v" + i, 1, 0L, null)));
            Suite.eq(1, count(rs, "reserved"));
            Suite.eq(8, count(rs, "conflict"));
            Suite.eq(1, h.ledger.snapshot(K).events.size());
        }),
        new Check<Handle>("racing-writers-with-retry-fill-the-cap-exactly", "twenty writers of 10 each retrying on conflict against a cap of 200: all twenty land, the twenty-first is refused", h -> {
            List<BudgetLedger> clients = List.of(h.ledger, h.reopen(), h.reopen());
            List<Callable<String>> tasks = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                int n = i;
                tasks.add(() -> {
                    BudgetLedger c = clients.get(n % 3);
                    for (;;) {
                        long v = c.snapshot(K).version;
                        BudgetLedger.ReserveOutcome r = c.reserve(K, req("w" + n, 10, v, null));
                        if (!r.outcome.equals("conflict")) return r.outcome;
                    }
                });
            }
            for (String o : Suite.parallel(tasks)) Suite.eq("reserved", o);
            Suite.eq(CAP, reservedTotal(h.ledger, K));
            Suite.eq("over_cap", h.ledger.reserve(K, req("extra", 1)).outcome);
        }),
        new Check<Handle>("settle-rules", "commit and release settle only a reservation, are idempotent, and refuse the opposite settlement; an unknown id changes nothing", h -> {
            BudgetLedger l = h.ledger;
            l.reserve(K, req("a", 10));
            l.reserve(K, req("b", 10));
            Suite.eq("unknown", l.commit(K, "ghost").outcome);
            Suite.eq("unknown", l.release(K, "ghost", null).outcome);
            Suite.eq("settled", l.commit(K, "a").outcome);
            Suite.eq("replayed", l.commit(K, "a").outcome);
            Suite.eq("committed", refusedStatus(l.release(K, "a", null)));
            Suite.eq("settled", l.release(K, "b", null).outcome);
            Suite.eq("replayed", l.release(K, "b", null).outcome);
            Suite.eq("released", refusedStatus(l.commit(K, "b")));
            Suite.eq(List.of("committed", "released"), statuses(l, K));
        }),
        new Check<Handle>("release-frees-budget-and-commit-keeps-it", "a released reservation no longer counts; a committed one still does; an open one keeps counting until settled", h -> {
            BudgetLedger l = h.ledger;
            l.reserve(K, req("a", 100));
            l.reserve(K, req("b", 100));
            Suite.eq("over_cap", l.reserve(K, req("c", 1)).outcome);
            l.release(K, "a", null);
            l.commit(K, "b");
            Suite.eq("reserved", l.reserve(K, req("d", 100)).outcome);
            Suite.eq("over_cap", l.reserve(K, req("e", 1)).outcome);
        }),
        new Check<Handle>("release-without-reserve-credits-nothing", "releasing an id that was never reserved does not create headroom, now or after the id is reserved later", h -> {
            BudgetLedger l = h.ledger;
            Suite.eq("unknown", l.release(K, "ghost", null).outcome);
            Suite.eq("over_cap", l.reserve(K, req("a", 201)).outcome);
            Suite.eq("reserved", l.reserve(K, req("ghost", 200)).outcome);
            Suite.eq("over_cap", l.reserve(K, req("b", 1)).outcome);
        }),
        new Check<Handle>("a-late-commit-cannot-overspend", "after a reservation was released and its budget reused, committing it is refused, so the committed total never passes the cap", h -> {
            BudgetLedger l = h.ledger;
            l.reserve(K, req("a", 200));
            l.release(K, "a", null);
            l.reserve(K, req("b", 200));
            Suite.eq("refused", l.commit(K, "a").outcome);
            l.commit(K, "b");
            long committed = l.snapshot(K).events.stream().filter(e -> "committed".equals(e.get("status"))).count();
            Suite.eq(1, committed);
        }),
        new Check<Handle>("expiry-releases-only-open-reservations-past-their-deadline", "expire frees a reservation at or after its deadline, never an earlier one, never a committed, started or deadline-less one, and a late commit or start of it is refused", h -> {
            BudgetLedger l = h.ledger;
            l.reserve(K, req("a", 40, null, 500L));
            l.reserve(K, req("b", 40, null, 500L));
            l.reserve(K, req("c", 40));
            l.reserve(K, req("d", 40, null, 500L));
            l.commit(K, "b");
            l.start(K, "d");
            Suite.eq(List.of(), l.expire(K, 499).released);
            Suite.eq(List.of("a"), l.expire(K, 500).released);
            Suite.eq(List.of(), l.expire(K, 10_000).released);
            Suite.eq(120, reservedTotal(l, K));
            Suite.eq("refused", l.commit(K, "a").outcome);
            Suite.eq("refused", l.start(K, "a").outcome);
        }),
        new Check<Handle>("start-rules", "start marks an open reservation non-expirable and is idempotent; an unknown id changes nothing; a started one can still be committed, or released (the effect did not happen); a released one cannot start", h -> {
            BudgetLedger l = h.ledger;
            l.reserve(K, req("a", 10, null, 5L));
            l.reserve(K, req("b", 10));
            l.reserve(K, req("c", 10));
            long v = l.snapshot(K).version;
            Suite.eq("unknown", l.start(K, "ghost").outcome);
            Suite.eq(v, l.snapshot(K).version);
            Suite.eq("settled", l.start(K, "a").outcome);
            Suite.eq("replayed", l.start(K, "a").outcome);
            Suite.eq(List.of(), l.expire(K, 100).released);
            Suite.eq("settled", l.commit(K, "a").outcome);
            Suite.eq("replayed", l.start(K, "a").outcome);
            l.start(K, "b");
            Suite.eq("settled", l.release(K, "b", null).outcome);
            Suite.eq("released", refusedStatus(l.start(K, "b")));
            for (Map<String, Object> e : l.snapshot(K).events) if ("c".equals(e.get("id"))) Suite.ok(!e.containsKey("started"), "an unstarted reservation has no started flag");
        }),
        new Check<Handle>("keys-are-independent", "two keys have their own caps, versions and events", h -> {
            BudgetLedger l = h.ledger;
            l.reserve(K, req("a", 200));
            Suite.eq("reserved", l.reserve(K2, req("a", 200)).outcome);
            Suite.eq("over_cap", l.reserve(K, req("b", 1)).outcome);
            Suite.eq(List.of("a"), l.snapshot(K2).events.stream().map(e -> e.get("id")).collect(java.util.stream.Collectors.toList()));
            Suite.eq(1, l.snapshot(K2).version);
        }),
        new Check<Handle>("windows-reset-the-count", "a period window counts only the events of the period of the new event", h -> {
            BudgetLedger l = h.ledger;
            Map<String, Object> win = new LinkedHashMap<>();
            win.put("kind", "period");
            win.put("ms", StoreJs.num(1000));
            win.put("t0", StoreJs.num(0));
            List<Map<String, Object>> w = List.of(spend(Map.of("win", win)));
            Suite.eq("reserved", l.reserve(K, req(ev("a", 200, 100), w)).outcome);
            Suite.eq("over_cap", l.reserve(K, req(ev("b", 1, 900), w)).outcome);
            Suite.eq("reserved", l.reserve(K, req(ev("c", 200, 1100), w)).outcome);
        }),
        new Check<Handle>("release-evidence-is-stored-and-bound", "evidence for the reservation is kept with the released event; evidence for another reservation is refused and the reservation stays open", h -> {
            BudgetLedger l = h.ledger;
            l.reserve(K, req("a", 10));
            Suite.rejects(IllegalArgumentException.class, () -> l.release(K, "a", mkEvidence("other")), "evidence for another reservation");
            Suite.eq("reserved", l.snapshot(K).events.get(0).get("status"));
            Suite.eq("settled", l.release(K, "a", mkEvidence("a")).outcome);
            Suite.eq(mkEvidence("a"), l.snapshot(K).events.get(0).get("rel"));
        }),
        new Check<Handle>("invalid-input-is-refused", "a malformed event or request throws and writes nothing", h -> {
            BudgetLedger l = h.ledger;
            Map<String, Object> badT = ev("x", 1);
            badT.put("t", StoreJs.num(0.5));
            Map<String, Object> badVerb = ev("x", 1);
            badVerb.put("verb", 7);
            for (Map<String, Object> bad : List.of(ev("", 1), badT, badVerb)) Suite.rejects(IllegalArgumentException.class, () -> l.reserve(K, req(bad, List.of(spend()))), "reserve of " + bad);
            Suite.rejects(IllegalArgumentException.class, () -> l.reserve(K, req("x", 1, -1L, null)), "negative expected version");
            Map<String, Object> noCap = spend();
            noCap.put("domain_max", null);
            Suite.rejects(IllegalArgumentException.class, () -> l.reserve(K, req(ev("x", 1), List.of(noCap))), "accumulator without a cap");
            Map<String, Object> want = new LinkedHashMap<>();
            want.put("version", 0);
            want.put("events", List.of());
            Suite.eq(want, l.snapshot(K).toJson());
        }),
        new Check<Handle>("snapshots-are-copies", "mutating what a snapshot returned cannot change the ledger", h -> {
            BudgetLedger l = h.ledger;
            l.reserve(K, req("a", 10));
            l.snapshot(K).events.get(0).put("status", "released");
            Suite.eq("reserved", l.snapshot(K).events.get(0).get("status"));
        }),
        new Check<Handle>("durable-claim-matches-the-adapter", "a ledger says durable exactly when its adapter declares durability, so a volatile ledger can never satisfy the non-session refusal", h ->
            Suite.ok(h.ledger.durable() == h.adapterDurable, "ledger.durable()=" + h.ledger.durable() + " but the adapter declares durable=" + h.adapterDurable)),
        new Check<Handle>("state-survives-reopen", "every acknowledged reserve, commit and release is visible to a new client after the backend restarts, and the cap still holds", "durable", h -> {
            h.ledger.reserve(K, req("a", 150));
            h.ledger.reserve(K, req("b", 50));
            h.ledger.commit(K, "a");
            h.ledger.release(K, "b", null);
            BudgetLedger back = h.reopen();
            List<Object> pairs = new ArrayList<>();
            for (Map<String, Object> e : back.snapshot(K).events) pairs.add(List.of(e.get("id"), e.get("status")));
            Suite.eq(List.of(List.of("a", "committed"), List.of("b", "released")), pairs);
            Suite.eq("over_cap", back.reserve(K, req("c", 51)).outcome);
            Suite.eq("reserved", back.reserve(K, req("c", 50)).outcome);
        }),
        new Check<Handle>("acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged reservation still counts, so a crash can only over-restrict, never reset a cap", "crash", h -> {
            h.ledger.reserve(K, req("a", 200));
            Thread inflight = new Thread(() -> { try { h.ledger.reserve(K, req("b", 0)); } catch (RuntimeException ignored) { /* killed in flight */ } });
            inflight.start();
            BudgetLedger back = h.crash();
            inflight.join();
            Suite.eq("over_cap", back.reserve(K, req("c", 1)).outcome);
            Suite.eq("a", back.snapshot(K).events.get(0).get("id"));
        })
    );

    /** Run the suite against {@code adapter} (only the named checks when {@code only} is non-null). */
    public static Suite.Report run(Adapter adapter, Collection<String> only) {
        return Suite.run("budget ledger", adapter.name(), adapter.durable(), () -> { Handle h = adapter.create(); h.adapterDurable = adapter.durable(); return h; }, CHECKS, only);
    }

    public static Suite.Report run(Adapter adapter) { return run(adapter, null); }

    // ---- reference adapters ----

    /** An adapter over any {@link AtomicKv}: {@code backend} opens one isolated backend and returns a supplier of clients on it. */
    public static Adapter kvAdapter(String name, boolean durable, Callable<Supplier<AtomicKv>> backend, boolean crashable) {
        return new Adapter() {
            @Override public String name() { return name; }
            @Override public boolean durable() { return durable; }
            @Override public Handle create() throws Exception {
                Supplier<AtomicKv> clients = backend.call();
                Callable<BudgetLedger> open = () -> new KvBudgetLedger(clients.get(), durable);
                return new Handle(open.call(), open, crashable ? open : null, null);
            }
        };
    }

    /** GOOD, in process: the reference ledger over a {@link MemoryAtomicKv}. Not durable (declared, and the ledger says so too). */
    public static Adapter memoryAdapter() {
        return kvAdapter("KvBudgetLedger over MemoryAtomicKv", false, () -> { MemoryAtomicKv kv = new MemoryAtomicKv(); return () -> kv; }, false);
    }

    /** The mistakes a bad ledger makes. */
    public enum Defect {
        NO_CAP("BAD no cap check (records every reservation)"),
        NO_CAS("BAD no compare-and-swap (ignores expectedVersion)"),
        LOST_UPDATE("BAD lost update (read, pause, write)"),
        AMNESIA("BAD amnesia (claims durability, forgets on reopen)"),
        RELEASE_UNRESERVED("BAD release without reserve (credits budget for an unknown id)"),
        RELEASE_COMMITTED("BAD release of a committed event (frees spent budget)"),
        LATE_COMMIT("BAD late commit (a released reservation can be committed again)"),
        NO_REPLAY("BAD no idempotence (a retried reservation counts twice)"),
        SHARED_KEYS("BAD one state for every key (keys leak into each other)"),
        EXPIRE_COMMITTED("BAD expiry releases committed events"),
        EXPIRE_STARTED("BAD expiry releases started reservations (an effect that ran stops counting)"),
        VOLATILE_CLAIMS_DURABLE("BAD in-process ledger that claims durable: true");

        final String label;
        Defect(String label) { this.label = label; }
    }

    private static final class Defective implements BudgetLedger {
        private final Defect defect;
        private final Object lock = new Object();
        private volatile Map<String, BudgetDoc> docs = new HashMap<>();

        Defective(Defect defect) { this.defect = defect; }

        void forget() { docs = new HashMap<>(); }

        private BudgetDoc doc(String key) { return docs.computeIfAbsent(defect == Defect.SHARED_KEYS ? "*" : key, k -> BudgetDoc.empty()); }

        @Override public boolean durable() { return true; } // every defective ledger claims durability (VOLATILE_CLAIMS_DURABLE is the lie the check catches)

        @Override public Snapshot snapshot(String key) {
            synchronized (lock) {
                BudgetDoc d = doc(key);
                List<Map<String, Object>> evs = new ArrayList<>();
                for (Map<String, Object> e : d.events) evs.add(StoreJs.map(StoreJs.deepCopy(e)));
                return new Snapshot(d.ver, evs);
            }
        }

        @Override public ReserveOutcome reserve(String key, ReserveRequest r) {
            ReserveRequest rr = r;
            if (defect == Defect.NO_CAS) { rr = copy(r); rr.expectedVersion = null; }
            if (defect == Defect.NO_CAP) {
                rr = copy(rr);
                List<Map<String, Object>> accs = new ArrayList<>();
                for (Map<String, Object> a : r.accumulators) { Map<String, Object> c = new LinkedHashMap<>(a); c.put("domain_max", StoreJs.num(9007199254740991L)); accs.add(c); }
                rr.accumulators = accs;
            }
            if (defect == Defect.LOST_UPDATE) {
                BudgetDoc work = BudgetDoc.decode(doc(key).encode());
                try { Thread.sleep(2); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                ReserveOutcome out = work.reserveInDoc(rr);
                if (out.outcome.equals("reserved")) docs.put(key, work);
                return out;
            }
            synchronized (lock) {
                BudgetDoc d = doc(key);
                if (defect == Defect.NO_REPLAY) {
                    for (Map<String, Object> e : d.events) {
                        if (e.get("id").equals(r.event.get("id"))) {
                            Map<String, Object> dup = StoreJs.map(StoreJs.deepCopy(e));
                            dup.put("id", r.event.get("id") + "#dup");
                            d.events.add(dup);
                            d.ver += 1;
                            return new ReserveOutcome("reserved", d.ver, new LinkedHashMap<>(), null, null, null, null);
                        }
                    }
                }
                return d.reserveInDoc(rr);
            }
        }

        private static ReserveRequest copy(ReserveRequest r) {
            ReserveRequest c = new ReserveRequest();
            c.event = r.event;
            c.accumulators = r.accumulators;
            c.schema = r.schema;
            c.expectedVersion = r.expectedVersion;
            c.expiresAt = r.expiresAt;
            return c;
        }

        private static Map<String, Object> find(BudgetDoc d, String id) {
            for (Map<String, Object> e : d.events) if (id.equals(e.get("id"))) return e;
            return null;
        }

        @Override public SettleOutcome start(String key, String id) { synchronized (lock) { return doc(key).startInDoc(id); } }

        @Override public SettleOutcome commit(String key, String id) {
            synchronized (lock) {
                BudgetDoc d = doc(key);
                if (defect == Defect.LATE_COMMIT) {
                    Map<String, Object> e = find(d, id);
                    if (e != null && "released".equals(e.get("status"))) {
                        e.put("status", "committed");
                        d.ver += 1;
                        return new SettleOutcome("settled", d.ver, null);
                    }
                }
                return d.commitInDoc(id);
            }
        }

        @Override public SettleOutcome release(String key, String id, Map<String, Object> evidence) {
            synchronized (lock) {
                BudgetDoc d = doc(key);
                Map<String, Object> e = find(d, id);
                if (defect == Defect.RELEASE_UNRESERVED && e == null) {
                    Map<String, Object> ghost = ev(id, 0, 0);
                    StoreJs.map(ghost.get("params")).put("amount", StoreJs.num(-CAP));
                    ghost.put("status", "committed");
                    d.events.add(ghost);
                    d.ver += 1;
                    return new SettleOutcome("settled", d.ver, null);
                }
                if (defect == Defect.RELEASE_COMMITTED && e != null && "committed".equals(e.get("status"))) {
                    e.put("status", "released");
                    d.ver += 1;
                    return new SettleOutcome("settled", d.ver, null);
                }
                return d.releaseInDoc(key, id, evidence);
            }
        }

        @Override public Expired expire(String key, long now) {
            synchronized (lock) {
                BudgetDoc d = doc(key);
                if (defect == Defect.EXPIRE_COMMITTED || defect == Defect.EXPIRE_STARTED) {
                    List<String> released = new ArrayList<>();
                    for (Map<String, Object> e : d.events) {
                        Double exp = e.containsKey("exp") ? StoreJs.dbl(e.get("exp")) : null;
                        boolean hit = exp != null && exp <= now && (defect == Defect.EXPIRE_COMMITTED ? !"released".equals(e.get("status")) : "reserved".equals(e.get("status")));
                        if (hit) { e.put("status", "released"); released.add((String) e.get("id")); }
                    }
                    if (!released.isEmpty()) d.ver += 1;
                    return new Expired(released, d.ver);
                }
                return d.expireInDoc(now);
            }
        }
    }

    /** A bad adapter: one ledger object shared by every client (a reopen on AMNESIA clears it). */
    public static Adapter defectiveAdapter(Defect defect) {
        return new Adapter() {
            @Override public String name() { return defect.label; }
            @Override public boolean durable() { return defect != Defect.VOLATILE_CLAIMS_DURABLE; }
            @Override public Handle create() {
                Defective d = new Defective(defect);
                Callable<BudgetLedger> again = () -> { if (defect == Defect.AMNESIA) d.forget(); return d; };
                return new Handle(d, again, again, null);
            }
        };
    }

    /** The reference adapters by name (the bad ones are positive controls). */
    public static Map<String, Supplier<Adapter>> referenceAdapters() {
        Map<String, Supplier<Adapter>> m = new LinkedHashMap<>();
        m.put("budget-memory", BudgetLedgerConformance::memoryAdapter);
        for (Defect d : Defect.values()) m.put("bad-budget-" + d.name().toLowerCase().replace('_', '-'), () -> defectiveAdapter(d));
        return m;
    }
}
