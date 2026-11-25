package net.atlasauth.pca.storeconformance;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Supplier;
import net.atlasauth.pca.AtomicKv;
import net.atlasauth.pca.BondDoc;
import net.atlasauth.pca.BondStore;
import net.atlasauth.pca.KvBondStore;
import net.atlasauth.pca.MemoryAtomicKv;
import net.atlasauth.pca.StoreJs;
import net.atlasauth.pca.storeconformance.Suite.Check;

/**
 * Conformance for bond-settlement stores ({@link BondStore}). A bond store keeps INTERNAL ACCOUNTING for the optimistic path (escrow,
 * depositors, challengers, treasury); no money moves. What it must get right is atomicity and idempotence: a transition (open, release,
 * slash) applies in full or not at all, a retry of a committed transition returns the stored record and moves nothing, two racing
 * transitions on one bond have exactly one winner, and an acknowledged commit survives a restart or a crash. Each check is one such claim,
 * driven against YOUR store through an {@link Adapter}.
 */
public final class BondStoreConformance {
    private BondStoreConformance() {}

    /** One isolated backend plus the means to reconnect to it. */
    public static final class Handle implements Suite.Handle {
        public final BondStore store;
        private final Callable<BondStore> reopen, crash;
        private final Callable<Void> closer;

        public Handle(BondStore store, Callable<BondStore> reopen, Callable<BondStore> crash, Callable<Void> closer) {
            this.store = store;
            this.reopen = reopen;
            this.crash = crash;
            this.closer = closer;
        }

        /** Another client on the SAME backend. After a restart this is how state is read back. */
        public BondStore reopen() throws Exception { return reopen.call(); }

        /** Kill the backend abruptly, then return a client on whatever survived. */
        public BondStore crash() throws Exception { return crash.call(); }

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

    // ---- plan builders (the store never verifies signatures; records are opaque to it) ----

    static Map<String, Object> rec(String claimId, String action, double amount, String from, String to, String evidenceDigest, Map<String, Object> split) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("claimId", claimId);
        r.put("action", action);
        r.put("amount", StoreJs.num(amount));
        r.put("from", from);
        r.put("to", to);
        r.put("at", StoreJs.num(1));
        r.put("evidenceDigest", evidenceDigest);
        if (split != null) r.put("split", split);
        r.put("sig", "sig");
        return r;
    }

    static Map<String, Object> move(String account, String op, double amount) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("account", account);
        m.put("op", op);
        m.put("amount", StoreJs.num(amount));
        return m;
    }

    static Map<String, Object> openPlan(String id, String dep, double amount) { return openPlan(id, dep, amount, 100, 1e9); }

    static Map<String, Object> openPlan(String id, String dep, double amount, double maxOpenClaims, double maxOpenAmount) {
        Map<String, Object> open = new LinkedHashMap<>();
        open.put("amount", StoreJs.num(amount));
        open.put("depositor", dep);
        open.put("maxOpenClaims", StoreJs.num(maxOpenClaims));
        open.put("maxOpenAmount", StoreJs.num(maxOpenAmount));
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("claimId", id);
        p.put("expect", "none");
        p.put("next", "open");
        p.put("open", open);
        p.put("moves", new ArrayList<Object>(List.of(move(dep, "debit", amount), move("escrow", "credit", amount))));
        p.put("record", rec(id, "open", amount, dep, "escrow", "", null));
        return p;
    }

    static Map<String, Object> releasePlan(String id, String dep, double amount) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("claimId", id);
        p.put("expect", "open");
        p.put("next", "released");
        p.put("moves", new ArrayList<Object>(List.of(move("escrow", "debit", amount), move(dep, "credit", amount))));
        p.put("record", rec(id, "release", amount, "escrow", dep, "", null));
        return p;
    }

    static Map<String, Object> slashPlan(String id, double amount) { return slashPlan(id, amount, "ev"); }

    static Map<String, Object> slashPlan(String id, double amount, String evidence) {
        Map<String, Object> split = new LinkedHashMap<>();
        split.put("amount", StoreJs.num(amount));
        split.put("challengerReward", StoreJs.num(amount / 2));
        split.put("victimCompensation", StoreJs.num(0));
        split.put("treasuryRemainder", StoreJs.num(amount / 2));
        split.put("challengerAccount", "chal");
        split.put("victimAccount", "pool");
        split.put("treasuryAccount", "treasury");
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("claimId", id);
        p.put("expect", "open");
        p.put("next", "slashed");
        p.put("moves", new ArrayList<Object>(List.of(move("escrow", "debit", amount), move("chal", "credit", amount / 2), move("treasury", "credit", amount / 2))));
        p.put("record", rec(id, "slash", amount, "escrow", "treasury", evidence, split));
        return p;
    }

    static Map<String, Object> record(Map<String, Object> plan) { return StoreJs.map(plan.get("record")); }

    static Map<String, Object> committed(Map<String, Object> plan) { return new BondStore.CommitOutcome("committed", record(plan), null, null).toJson(); }

    static Map<String, Object> replayed(Map<String, Object> plan) { return new BondStore.CommitOutcome("replayed", record(plan), null, null).toJson(); }

    static BondStore.CommitOutcome commit(BondStore s, Map<String, Object> plan, double at) { return s.commit(plan, at); }

    static List<Object> bal(BondStore s, String... accounts) {
        List<Object> out = new ArrayList<>();
        for (String a : accounts) out.add(s.read("", a).balances.get(a));
        return out;
    }

    static String status(BondStore s, String id) {
        BondStore.Snapshot sn = s.read(id, null);
        return sn.bond == null ? "none" : (String) sn.bond.get("status");
    }

    static final String[] ACCOUNTS = {"alice", "bob", "escrow", "chal", "treasury"};

    static double total(BondStore s) {
        double t = 0;
        for (Object o : bal(s, ACCOUNTS)) t += (Double) o;
        return t;
    }

    static List<String> outcomes(List<BondStore.CommitOutcome> r) {
        List<String> out = new ArrayList<>();
        for (BondStore.CommitOutcome o : r) out.add(o.outcome);
        Collections.sort(out);
        return out;
    }

    static long count(List<BondStore.CommitOutcome> r, String outcome) {
        long n = 0;
        for (BondStore.CommitOutcome o : r) if (o.outcome.equals(outcome)) n++;
        return n;
    }

    @SuppressWarnings("unchecked")
    static List<Object> records(BondStore s, String id) { return (List<Object>) s.read(id, null).bond.get("records"); }

    // ---- the checks ----

    public static final List<Check<Handle>> CHECKS = List.of(
        new Check<Handle>("empty-store-reads-empty", "an unknown bond reads as absent, an unknown account as balance 0, and the time high-water mark starts at 0", h -> {
            Map<String, Object> want = new LinkedHashMap<>();
            want.put("balances", List.of(List.of("alice", 0)));
            want.put("openTotals", Map.of("count", 0, "sum", 0));
            want.put("highWater", 0);
            Suite.eq(want, h.store.read("nope", "alice").toJson());
        }),
        new Check<Handle>("deposit-validates-and-accumulates", "deposit credits exactly, returns the new balance, and refuses a non-positive, non-finite or unnamed deposit", h -> {
            BondStore s = h.store;
            Suite.eq(2.5, s.deposit("alice", 2.5));
            Suite.eq(3.0, s.deposit("alice", 0.5));
            for (double bad : new double[] {0, -1, Double.NaN, Double.POSITIVE_INFINITY}) Suite.rejects(() -> s.deposit("alice", bad), "deposit of " + bad);
            Suite.rejects(() -> s.deposit("", 1), "deposit to an unnamed account");
            Suite.eq(List.of(3), bal(s, "alice"));
        }),
        new Check<Handle>("open-is-atomic-and-recorded", "an open moves the collateral, stores the row with its record, and raises the high-water mark, all together", h -> {
            BondStore s = h.store;
            s.deposit("alice", 100);
            Map<String, Object> plan = openPlan("b1", "alice", 60);
            Suite.eq(committed(plan), commit(s, plan, 500).toJson());
            Map<String, Object> bond = new LinkedHashMap<>();
            bond.put("claimId", "b1");
            bond.put("amount", 60);
            bond.put("depositor", "alice");
            bond.put("status", "open");
            bond.put("records", List.of(record(plan)));
            Map<String, Object> want = new LinkedHashMap<>();
            want.put("bond", bond);
            want.put("balances", List.of(List.of("alice", 40)));
            want.put("openTotals", Map.of("count", 1, "sum", 60));
            want.put("highWater", 500);
            Suite.eq(want, s.read("b1", "alice").toJson());
            Suite.eq(List.of(60), bal(s, "escrow"));
        }),
        new Check<Handle>("open-overdraft-refused-without-trace", "an open the depositor cannot fund is a conflict and leaves balances, bonds and the high-water mark untouched", h -> {
            BondStore s = h.store;
            s.deposit("alice", 10);
            Suite.eq("conflict", commit(s, openPlan("b1", "alice", 60), 900).outcome);
            Map<String, Object> want = new LinkedHashMap<>();
            want.put("balances", List.of(List.of("alice", 10)));
            want.put("openTotals", Map.of("count", 0, "sum", 0));
            want.put("highWater", 0);
            Suite.eq(want, s.read("b1", "alice").toJson());
            Suite.eq(List.of(0), bal(s, "escrow"));
        }),
        new Check<Handle>("open-retry-is-replayed-and-different-terms-conflict", "committing the same open again returns the stored record and moves nothing; other terms for that bond conflict", h -> {
            BondStore s = h.store;
            s.deposit("alice", 100);
            Map<String, Object> plan = openPlan("b1", "alice", 60);
            commit(s, plan, 1);
            Suite.eq(replayed(plan), commit(s, plan, 2).toJson());
            Suite.eq("conflict", commit(s, openPlan("b1", "alice", 61), 3).outcome);
            Suite.eq("conflict", commit(s, openPlan("b1", "bob", 60), 3).outcome);
            Suite.eq(List.of(40, 60), bal(s, "alice", "escrow"));
            Suite.eq(1, records(s, "b1").size());
        }),
        new Check<Handle>("open-caps-are-rechecked-at-commit", "the per-depositor open-claim and open-amount caps hold inside the store, whatever the planner saw", h -> {
            BondStore s = h.store;
            s.deposit("alice", 100);
            Suite.eq("committed", commit(s, openPlan("c1", "alice", 30, 2, 50), 1).outcome);
            Suite.eq("conflict", commit(s, openPlan("c2", "alice", 21, 2, 50), 1).outcome); // 30 + 21 > 50
            Suite.eq("committed", commit(s, openPlan("c3", "alice", 20, 2, 50), 1).outcome);
            Suite.eq("conflict", commit(s, openPlan("c4", "alice", 1, 2, 50), 1).outcome); // third open claim
            Suite.eq(List.of(50, 50), bal(s, "alice", "escrow"));
        }),
        new Check<Handle>("settle-applies-every-move-once", "a release and a slash apply all their balance moves, store the record, and conserve the total", h -> {
            BondStore s = h.store;
            s.deposit("alice", 100);
            commit(s, openPlan("r", "alice", 20), 1);
            commit(s, openPlan("s", "alice", 40), 1);
            Map<String, Object> rel = releasePlan("r", "alice", 20), sl = slashPlan("s", 40);
            Suite.eq(committed(rel), commit(s, rel, 2).toJson());
            Suite.eq(committed(sl), commit(s, sl, 3).toJson());
            Suite.eq(List.of(60, 0, 20, 20), bal(s, "alice", "escrow", "chal", "treasury"));
            Suite.eq(100, total(s));
            Suite.eq(List.of("released", "slashed"), List.of(status(s, "r"), status(s, "s")));
            Suite.eq(List.of(record(openPlan("s", "alice", 40)), record(sl)), records(s, "s"));
        }),
        new Check<Handle>("settle-needs-the-expected-phase", "settling an absent bond or from the wrong phase is a conflict that changes nothing, high-water mark included", h -> {
            BondStore s = h.store;
            s.deposit("alice", 100);
            Suite.eq("conflict", commit(s, releasePlan("ghost", "alice", 5), 9).outcome);
            commit(s, openPlan("b", "alice", 20), 10);
            commit(s, releasePlan("b", "alice", 20), 11);
            List<Object> before = new ArrayList<>(bal(s, "alice", "escrow", "treasury", "chal"));
            before.add(s.read("b", null).highWater);
            Suite.eq("conflict", commit(s, slashPlan("b", 20), 99).outcome);
            List<Object> after = new ArrayList<>(bal(s, "alice", "escrow", "treasury", "chal"));
            after.add(s.read("b", null).highWater);
            Suite.eq(before, after);
            Suite.eq("released", status(s, "b"));
        }),
        new Check<Handle>("settle-overdraw-refused-without-trace", "a settlement whose debit would overdraw an account is refused whole: no credit lands, the phase does not change", h -> {
            BondStore s = h.store;
            s.deposit("alice", 100);
            commit(s, openPlan("b", "alice", 20), 1);
            Map<String, Object> greedy = slashPlan("b", 20);
            greedy.put("moves", new ArrayList<Object>(List.of(move("escrow", "debit", 21), move("treasury", "credit", 21))));
            Suite.eq("conflict", commit(s, greedy, 5).outcome);
            Suite.eq(List.of(20, 0), bal(s, "escrow", "treasury"));
            Suite.eq("open", status(s, "b"));
        }),
        new Check<Handle>("settle-retry-returns-the-stored-record", "the same settlement again is replayed with the first record and moves nothing; the same action with other evidence conflicts", h -> {
            BondStore s = h.store;
            s.deposit("alice", 100);
            commit(s, openPlan("b", "alice", 40), 1);
            Map<String, Object> sl = slashPlan("b", 40, "ev-1");
            commit(s, sl, 2);
            Map<String, Object> again = slashPlan("b", 40, "ev-1");
            Map<String, Object> other = new LinkedHashMap<>(record(sl));
            other.put("at", StoreJs.num(77));
            other.put("sig", "other");
            again.put("record", other);
            Suite.eq(replayed(sl), commit(s, again, 3).toJson());
            Suite.eq("conflict", commit(s, slashPlan("b", 40, "ev-2"), 3).outcome);
            Suite.eq("conflict", commit(s, releasePlan("b", "alice", 40), 3).outcome);
            Suite.eq(List.of(60, 0, 20, 20), bal(s, "alice", "escrow", "chal", "treasury"));
            Suite.eq(2, records(s, "b").size());
        }),
        new Check<Handle>("racing-identical-settles-commit-once", "eight clients racing the same release: one commits, seven are replays, funds move once", h -> {
            h.store.deposit("alice", 100);
            commit(h.store, openPlan("b", "alice", 40), 1);
            List<BondStore> clients = new ArrayList<>(List.of(h.store, h.reopen(), h.reopen(), h.reopen()));
            List<Callable<BondStore.CommitOutcome>> tasks = new ArrayList<>();
            for (int i = 0; i < 8; i++) { int n = i; tasks.add(() -> clients.get(n % clients.size()).commit(releasePlan("b", "alice", 40), 10 + n)); }
            List<String> want = new ArrayList<>(List.of("committed"));
            for (int i = 0; i < 7; i++) want.add("replayed");
            Suite.eq(want, outcomes(Suite.parallel(tasks)));
            Suite.eq(List.of(100, 0), bal(h.store, "alice", "escrow"));
            Suite.eq(2, records(h.store, "b").size());
        }),
        new Check<Handle>("racing-conflicting-settles-have-one-winner", "a release racing a slash on one bond: exactly one commits, the books show only the winner, the total is conserved", h -> {
            h.store.deposit("alice", 100);
            commit(h.store, openPlan("b", "alice", 40), 1);
            BondStore other = h.reopen();
            List<Callable<BondStore.CommitOutcome>> tasks = List.of(
                () -> h.store.commit(releasePlan("b", "alice", 40), 5), () -> other.commit(slashPlan("b", 40), 5),
                () -> h.store.commit(slashPlan("b", 40), 5), () -> other.commit(releasePlan("b", "alice", 40), 5));
            List<BondStore.CommitOutcome> r = Suite.parallel(tasks);
            Suite.eq(1, count(r, "committed"));
            Suite.eq(3, count(r, "conflict") + count(r, "replayed"));
            String st = status(h.store, "b");
            Suite.eq(st.equals("released") ? List.of(100, 0, 0, 0) : List.of(60, 0, 20, 20), bal(h.store, "alice", "escrow", "chal", "treasury"));
            Suite.eq(100, total(h.store));
        }),
        new Check<Handle>("racing-opens-for-the-same-bond-commit-once", "concurrent identical opens collect the collateral once; a differing open loses", h -> {
            h.store.deposit("alice", 100);
            BondStore other = h.reopen();
            List<Callable<BondStore.CommitOutcome>> tasks = List.of(
                () -> h.store.commit(openPlan("b", "alice", 60), 1), () -> other.commit(openPlan("b", "alice", 60), 1),
                () -> h.store.commit(openPlan("b", "alice", 60), 1), () -> other.commit(openPlan("b", "alice", 50), 1));
            List<BondStore.CommitOutcome> r = Suite.parallel(tasks);
            Suite.eq(1, count(r, "committed"));
            Suite.eq(r.get(3).outcome.equals("committed") ? List.of(50, 50) : List.of(40, 60), bal(h.store, "alice", "escrow"));
            Suite.eq(100, total(h.store));
        }),
        new Check<Handle>("racing-opens-cannot-overdraw", "concurrent opens by one depositor that together exceed the balance: the sum committed never exceeds what was deposited", h -> {
            h.store.deposit("alice", 100);
            BondStore other = h.reopen();
            List<Callable<BondStore.CommitOutcome>> tasks = new ArrayList<>();
            for (int i = 0; i < 6; i++) { int n = i; tasks.add(() -> (n % 2 == 1 ? h.store : other).commit(openPlan("b" + n, "alice", 40), 1)); }
            Suite.eq(2, count(Suite.parallel(tasks), "committed"));
            Suite.eq(List.of(20, 80), bal(h.store, "alice", "escrow"));
        }),
        new Check<Handle>("concurrent-deposits-lose-nothing", "sixteen racing deposits add up exactly", h -> {
            BondStore other = h.reopen();
            List<Callable<Double>> tasks = new ArrayList<>();
            for (int i = 0; i < 16; i++) { int n = i; tasks.add(() -> (n % 2 == 1 ? h.store : other).deposit("alice", 1)); }
            Suite.parallel(tasks);
            Suite.eq(List.of(16), bal(h.store, "alice"));
        }),
        new Check<Handle>("time-high-water-only-moves-forward", "the recorded time is the maximum of every committed observedAt; a smaller or non-finite one never lowers it", h -> {
            BondStore s = h.store;
            s.deposit("alice", 100);
            commit(s, openPlan("a", "alice", 10), 100);
            commit(s, openPlan("b", "alice", 10), 40);
            Suite.eq(100, s.read("", null).highWater);
            commit(s, openPlan("c", "alice", 10), Double.NaN);
            Suite.eq(100, s.read("", null).highWater);
            commit(s, openPlan("d", "alice", 10), 101);
            Suite.eq(101, s.read("", null).highWater);
        }),
        new Check<Handle>("reads-are-snapshots", "mutating a returned snapshot cannot change the store", h -> {
            BondStore s = h.store;
            s.deposit("alice", 100);
            commit(s, openPlan("b", "alice", 10), 1);
            BondStore.Snapshot snap = s.read("b", "alice");
            snap.bond.put("amount", StoreJs.num(999));
            ((List<?>) snap.bond.get("records")).clear();
            snap.balances.put("alice", 12345.0);
            BondStore.Snapshot again = s.read("b", "alice");
            Suite.eq(10, again.bond.get("amount"));
            Suite.eq(1, ((List<?>) again.bond.get("records")).size());
            Suite.eq(List.of(List.of("alice", 90)), again.toJson().get("balances"));
        }),
        new Check<Handle>("hostile-names-are-plain-keys", "claim and account names such as __proto__, constructor and toString behave like any other name", h -> {
            BondStore s = h.store;
            for (String n : new String[] {"__proto__", "constructor", "toString", "hasOwnProperty"}) {
                s.deposit(n, 50);
                Suite.eq("committed", commit(s, openPlan(n, n, 20), 1).outcome, n);
                Suite.eq(List.of(30), bal(s, n), n);
                Suite.eq("open", status(s, n), n);
            }
            Suite.eq("none", status(s, "valueOf"));
            Suite.eq(List.of(0), bal(s, "valueOf"));
        }),
        new Check<Handle>("state-survives-reopen", "every acknowledged commit and deposit is visible to a new client after the backend restarts", "durable", h -> {
            h.store.deposit("alice", 100);
            commit(h.store, openPlan("a", "alice", 40), 7);
            commit(h.store, openPlan("b", "alice", 20), 8);
            Map<String, Object> sl = slashPlan("b", 20);
            commit(h.store, sl, 9);
            BondStore back = h.reopen();
            Map<String, Object> bond = new LinkedHashMap<>();
            bond.put("claimId", "b");
            bond.put("amount", 20);
            bond.put("depositor", "alice");
            bond.put("status", "slashed");
            bond.put("records", List.of(record(openPlan("b", "alice", 20)), record(sl)));
            Map<String, Object> want = new LinkedHashMap<>();
            want.put("bond", bond);
            want.put("balances", List.of(List.of("alice", 40)));
            want.put("openTotals", Map.of("count", 1, "sum", 40));
            want.put("highWater", 9);
            Suite.eq(want, back.read("b", "alice").toJson());
            Suite.eq(List.of(40, 10, 10), bal(back, "escrow", "chal", "treasury"));
            Suite.eq("replayed", commit(back, sl, 10).outcome);
        }),
        new Check<Handle>("acknowledged-commits-survive-a-crash", "after an abrupt kill, every acknowledged transition is present, and a transition that was in flight is applied entirely or not at all", "crash", h -> {
            h.store.deposit("alice", 100);
            commit(h.store, openPlan("a", "alice", 40), 1);
            commit(h.store, openPlan("b", "alice", 30), 2);
            Thread inflight = new Thread(() -> { try { h.store.commit(slashPlan("b", 30), 3); } catch (RuntimeException ignored) { /* killed in flight */ } });
            inflight.start();
            BondStore back = h.crash();
            inflight.join();
            Suite.eq("open", status(back, "a"));
            String st = status(back, "b");
            Suite.ok(st.equals("open") || st.equals("slashed"), "bond b is " + st);
            Suite.eq(st.equals("slashed") ? List.of(30, 40, 15, 15) : List.of(30, 70, 0, 0), bal(back, "alice", "escrow", "chal", "treasury"));
            Suite.eq(100, total(back));
            Suite.eq(st.equals("slashed") ? "replayed" : "committed", commit(back, slashPlan("b", 30), 4).outcome);
            Suite.eq(List.of(30, 40, 15, 15), bal(back, "alice", "escrow", "chal", "treasury"));
        })
    );

    /** Run the suite against {@code adapter} (only the named checks when {@code only} is non-null). */
    public static Suite.Report run(Adapter adapter, Collection<String> only) {
        return Suite.run("bond store", adapter.name(), adapter.durable(), adapter::create, CHECKS, only);
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
                Callable<BondStore> open = () -> new KvBondStore(clients.get());
                return new Handle(open.call(), open, crashable ? open : null, null);
            }
        };
    }

    /** GOOD, in process: the reference store over a {@link MemoryAtomicKv}. Not durable (declared). */
    public static Adapter memoryAdapter() {
        return kvAdapter("KvBondStore over MemoryAtomicKv", false, () -> { MemoryAtomicKv kv = new MemoryAtomicKv(); return () -> kv; }, false);
    }

    /** The mistakes a bad store makes. */
    public enum Defect {
        NON_ATOMIC("BAD non-atomic (moves land before the phase check)"),
        NO_REPLAY("BAD no idempotence (a retried transition conflicts)"),
        LOST_UPDATE("BAD lost update (read, pause, write)"),
        AMNESIA("BAD amnesia (claims durability, forgets on reopen)"),
        CLOCK_REWIND("BAD clock rewind (high-water mark follows the last call)");

        final String label;
        Defect(String label) { this.label = label; }
    }

    private static final class Defective implements BondStore {
        private final Defect defect;
        private final Object lock = new Object();
        private volatile BondDoc doc = BondDoc.empty();

        Defective(Defect defect) { this.defect = defect; }

        void forget() { doc = BondDoc.empty(); }

        @Override public Snapshot read(String claimId, String depositor) { return doc.snapshot(claimId, depositor); }

        @Override public double deposit(String account, double amount) {
            if (!(amount > 0) || Double.isInfinite(amount) || account == null || account.isEmpty()) throw new IllegalArgumentException("deposit");
            if (defect == Defect.LOST_UPDATE) {
                BondDoc base = BondDoc.decode(doc.encode());
                try { Thread.sleep(2); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                double v = base.balances.getOrDefault(account, 0.0) + amount;
                base.balances.put(account, v);
                doc = base;
                return v;
            }
            synchronized (lock) {
                double v = doc.balances.getOrDefault(account, 0.0) + amount;
                doc.balances.put(account, v);
                return v;
            }
        }

        @SuppressWarnings("unchecked")
        @Override public CommitOutcome commit(Map<String, Object> plan, double observedAt) {
            if (defect == Defect.LOST_UPDATE) {
                BondDoc working = BondDoc.decode(doc.encode());
                try { Thread.sleep(2); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                CommitOutcome out = BondDoc.commitBondPlan(working, plan, observedAt);
                if (out.outcome.equals("committed")) doc = working;
                return out;
            }
            synchronized (lock) {
                BondDoc d = doc;
                String claimId = (String) plan.get("claimId");
                if (defect == Defect.NON_ATOMIC) {
                    // applies the balance moves first, then checks the phase: a conflict leaves the money moved
                    for (Object mo : (List<Object>) plan.get("moves")) {
                        Map<String, Object> m = StoreJs.map(mo);
                        double a = StoreJs.dbl(m.get("amount"));
                        d.balances.merge((String) m.get("account"), "credit".equals(m.get("op")) ? a : -a, Double::sum);
                    }
                    Map<String, Object> b = d.bonds.get(claimId);
                    boolean bad = "none".equals(plan.get("expect")) ? b != null : b == null || !plan.get("expect").equals(b.get("status"));
                    if (bad) return new CommitOutcome("conflict", null, "phase", b == null ? "none" : (String) b.get("status"));
                    Map<String, Object> open = StoreJs.map(plan.get("open"));
                    if (open != null) {
                        Map<String, Object> row = new LinkedHashMap<>();
                        row.put("claimId", claimId);
                        row.put("amount", open.get("amount"));
                        row.put("depositor", open.get("depositor"));
                        row.put("status", "open");
                        row.put("records", new ArrayList<Object>(List.of(plan.get("record"))));
                        d.bonds.put(claimId, row);
                    } else {
                        b.put("status", plan.get("next"));
                        ((List<Object>) b.get("records")).add(plan.get("record"));
                    }
                    d.highWater = Math.max(d.highWater, observedAt);
                    return new CommitOutcome("committed", StoreJs.map(plan.get("record")), null, null);
                }
                CommitOutcome out = BondDoc.commitBondPlan(d, plan, observedAt);
                if (defect == Defect.NO_REPLAY && out.outcome.equals("replayed")) return new CommitOutcome("conflict", null, "already applied", "open");
                if (defect == Defect.CLOCK_REWIND && out.outcome.equals("committed")) d.highWater = observedAt;
                return out;
            }
        }
    }

    /** A bad adapter: one store object shared by every client (a reopen on AMNESIA clears it). */
    public static Adapter defectiveAdapter(Defect defect) {
        return new Adapter() {
            @Override public String name() { return defect.label; }
            @Override public Handle create() {
                Defective d = new Defective(defect);
                Callable<BondStore> again = () -> { if (defect == Defect.AMNESIA) d.forget(); return d; };
                return new Handle(d, again, again, null);
            }
        };
    }

    /** The reference adapters by name (the bad ones are positive controls). */
    public static Map<String, Supplier<Adapter>> referenceAdapters() {
        Map<String, Supplier<Adapter>> m = new LinkedHashMap<>();
        m.put("bond-memory", BondStoreConformance::memoryAdapter);
        for (Defect d : Defect.values()) m.put("bad-bond-" + d.name().toLowerCase().replace('_', '-'), () -> defectiveAdapter(d));
        return m;
    }
}
