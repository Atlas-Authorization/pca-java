package net.atlasauth.pca.ciba;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Function;
import java.util.function.Supplier;
import net.atlasauth.pca.Approvals;
import net.atlasauth.pca.Facade;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.ciba.CibaApproval.ApprovalBroker;
import net.atlasauth.pca.ciba.CibaApproval.ApprovalStore;
import net.atlasauth.pca.ciba.CibaApproval.Versioned;

/**
 * Conformance cases for an {@link ApprovalStore}, plus broker-level cases run over it. Run them against your store:
 * {@code for (Case c : CibaStoreConformance.approvalStoreCases(MyStore::new, null)) c.run.run();}
 *
 * <p>Each case throws an AssertionError when the store breaks the contract: absent means version 0, {@code cas} writes only at the
 * expected version and bumps it by one, exactly one of many concurrent {@code cas} calls wins, returned values are snapshots and (with
 * {@code reopen}) written records survive a restart. The broker cases check what the contract is for: exactly one concurrent decision
 * wins and an approval redeems once.
 */
public final class CibaStoreConformance {
    private CibaStoreConformance() {}

    /** A runnable that may throw. */
    public interface ThrowingRunnable { void run() throws Exception; }

    /** A named check. */
    public static final class Case {
        public final String name;
        public final ThrowingRunnable run;
        Case(String name, ThrowingRunnable run) { this.name = name; this.run = run; }
    }

    private static void check(boolean ok, String what) { if (!ok) throw new AssertionError(what); }

    private static Json.Num n(long v) { return new Json.Num(Long.toString(v)); }

    private static String canon(Object v) { return Json.canonicalize(v); }

    private static void is(Versioned got, long version, Object value, String what) {
        check(got != null && got.version == version && canon(got.value).equals(canon(value)), what);
    }

    /** Runs {@code n} tasks released together on {@code n} threads; each result is its value or the exception it threw. */
    private static <T> List<Object> concurrently(int n, java.util.function.IntFunction<Callable<T>> task) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(n);
        try {
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Object>> fs = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                Callable<T> t = task.apply(i);
                fs.add(pool.submit(() -> {
                    go.await();
                    try { return t.call(); } catch (Exception e) { return e; }
                }));
            }
            go.countDown();
            List<Object> out = new ArrayList<>();
            for (Future<Object> f : fs) out.add(f.get());
            return out;
        } finally {
            pool.shutdownNow();
        }
    }

    /**
     * @param make a store over a fresh, empty backing location each call
     * @param reopen for a persistent store: a NEW store object over the same backing location as {@code previous}, as after a restart
     *               (null skips the durability case)
     */
    public static List<Case> approvalStoreCases(Supplier<ApprovalStore> make, Function<ApprovalStore, ApprovalStore> reopen) {
        List<Case> cs = new ArrayList<>();
        cs.add(new Case("an absent key reads null", () -> check(make.get().get("nope") == null, "an absent key must read null")));
        cs.add(new Case("cas at version 0 creates the key at version 1 with the whole value", () -> {
            ApprovalStore s = make.get();
            Object v = Issue.obj("a", n(1), "nested", Issue.obj("b", new ArrayList<Object>(java.util.Arrays.asList("x", n(2), null))));
            check(s.cas("k", 0, v), "cas at 0 on an absent key must succeed");
            is(s.get("k"), 1, v, "the key must read at version 1 with the whole value");
        }));
        cs.add(new Case("cas at version 0 on an existing key is refused and changes nothing", () -> {
            ApprovalStore s = make.get();
            s.cas("k", 0, "first");
            check(!s.cas("k", 0, "second"), "cas at 0 on an existing key must be refused");
            is(s.get("k"), 1, "first", "a refused cas must change nothing");
        }));
        cs.add(new Case("cas succeeds only at the current version and bumps it by exactly one", () -> {
            ApprovalStore s = make.get();
            s.cas("k", 0, n(1));
            check(s.cas("k", 1, n(2)), "cas at the current version must succeed");
            check(!s.cas("k", 1, n(3)), "a stale cas must be refused");
            check(!s.cas("k", 5, n(4)), "a cas from the future must be refused");
            check(s.cas("k", 2, n(5)), "cas at the new current version must succeed");
            is(s.get("k"), 3, n(5), "the version must be 3 and the value the last write");
        }));
        cs.add(new Case("cas on a key that does not exist at a non-zero version is refused and creates nothing", () -> {
            ApprovalStore s = make.get();
            check(!s.cas("k", 1, "x"), "cas at version 1 on an absent key must be refused");
            check(s.get("k") == null, "a refused cas must create nothing");
        }));
        cs.add(new Case("keys are independent", () -> {
            ApprovalStore s = make.get();
            s.cas("a", 0, "A");
            s.cas("b", 0, "B");
            s.cas("a", 1, "A2");
            is(s.get("a"), 2, "A2", "key a");
            is(s.get("b"), 1, "B", "key b");
        }));
        cs.add(new Case("a read is a snapshot: changing the returned value does not change the store", () -> {
            ApprovalStore s = make.get();
            s.cas("k", 0, Issue.obj("list", new ArrayList<Object>(List.of(n(1)))));
            @SuppressWarnings("unchecked") List<Object> got = (List<Object>) ((Map<String, Object>) s.get("k").value).get("list");
            try { got.add(n(2)); } catch (UnsupportedOperationException e) { /* an immutable snapshot is a snapshot */ }
            is(s.get("k"), 1, Issue.obj("list", List.of(n(1))), "the store changed through a returned value");
        }));
        cs.add(new Case("a written value is a snapshot: changing it after cas does not change the store", () -> {
            ApprovalStore s = make.get();
            List<Object> list = new ArrayList<>(List.of(n(1)));
            s.cas("k", 0, Issue.obj("list", list));
            list.add(n(2));
            is(s.get("k"), 1, Issue.obj("list", List.of(n(1))), "the store changed through the value that was written");
        }));
        cs.add(new Case("exactly one of many concurrent creates wins", () -> {
            ApprovalStore s = make.get();
            List<Object> rs = concurrently(32, i -> () -> s.cas("k", 0, n(i)));
            check(count(rs) == 1, "exactly one concurrent create must win");
            is(s.get("k"), 1, n(rs.indexOf(Boolean.TRUE)), "the stored value must be the winner's");
        }));
        cs.add(new Case("exactly one of many concurrent updates at the same version wins", () -> {
            ApprovalStore s = make.get();
            s.cas("k", 0, "base");
            List<Object> rs = concurrently(32, i -> () -> s.cas("k", 1, n(i)));
            check(count(rs) == 1, "exactly one concurrent update must win");
            is(s.get("k"), 2, n(rs.indexOf(Boolean.TRUE)), "the stored value must be the winner's");
        }));
        cs.add(new Case("a retry loop over concurrent writers loses no increment", () -> {
            ApprovalStore s = make.get();
            s.cas("n", 0, n(0));
            List<Object> rs = concurrently(24, i -> () -> {
                for (;;) {
                    Versioned cur = s.get("n");
                    if (cur != null && s.cas("n", cur.version, n(Long.parseLong(canon(cur.value)) + 1))) return Boolean.TRUE;
                }
            });
            for (Object r : rs) check(r instanceof Boolean, "a writer failed: " + r);
            is(s.get("n"), 25, n(24), "every increment must land");
        }));
        if (reopen != null) {
            cs.add(new Case("records and their versions survive reopening the store", () -> {
                ApprovalStore s = make.get();
                s.cas("k", 0, Issue.obj("v", n(1)));
                s.cas("k", 1, Issue.obj("v", n(2)));
                ApprovalStore again = reopen.apply(s);
                is(again.get("k"), 2, Issue.obj("v", n(2)), "the record must survive a reopen");
                check(!again.cas("k", 1, Issue.obj("v", "stale")), "a stale cas after reopen must be refused");
                check(again.cas("k", 2, Issue.obj("v", n(3))), "a current cas after reopen must succeed");
            }));
        }
        return cs;
    }

    private static int count(List<Object> rs) {
        int c = 0;
        for (Object r : rs) if (Boolean.TRUE.equals(r)) c++;
        return c;
    }

    private static Map<String, Object> stepUp() {
        Facade.AgentOptions o = new Facade.AgentOptions(Keys.ed25519(Keys.edGenerate()), "pay suppliers", Issue.obj("stripe", List.of("payout")))
            .limits(Issue.obj("payout", "$100")).aud("ins_conformance").riskPolicy(Issue.obj("theta1", new Json.Num("0.3"), "theta2", new Json.Num("0.6"))).now(0);
        Approvals.ReviewOptions ro = new Approvals.ReviewOptions();
        ro.now = 1L;
        ro.goal = "pay suppliers";
        ro.insecureUnboundApproval = true;
        Map<String, Object> r = Approvals.reviewAction(Facade.agent(o), "stripe.payout", "acct:1",
            Issue.obj("amount", n(80), "currency", "USD", "payee", "bob"), ro);
        if (!"step_up".equals(r.get("kind"))) throw new IllegalStateException("conformance fixture did not produce a step-up");
        @SuppressWarnings("unchecked") Map<String, Object> req = (Map<String, Object>) r.get("request");
        return req;
    }

    private static List<ApprovalBroker> brokers(Supplier<ApprovalStore> make, int n) {
        ApprovalStore store = make.get();
        List<ApprovalBroker> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            CibaApproval.DurableBrokerOptions o = new CibaApproval.DurableBrokerOptions();
            o.store = store;
            out.add(CibaApproval.createDurableCibaBroker(o));
        }
        return out;
    }

    /** Broker-level cases over a store: what the compare-and-set contract is for. */
    public static List<Case> approvalBrokerCases(Supplier<ApprovalStore> make) {
        List<Case> cs = new ArrayList<>();
        cs.add(new Case("concurrent resolves through separate brokers: exactly one wins and its decision stands", () -> {
            List<ApprovalBroker> bs = brokers(make, 8);
            String id = (String) bs.get(0).start(stepUp(), null).get("auth_req_id");
            List<Object> rs = concurrently(8, i -> () -> bs.get(i).resolve(id, i % 2 == 0 ? "approve" : "deny", "user-" + i));
            int won = -1, wins = 0;
            for (int i = 0; i < rs.size(); i++) if (rs.get(i) instanceof Map) { won = i; wins++; }
            check(wins == 1, "exactly one concurrent resolve must win");
            Map<String, Object> fin = bs.get(0).get(id);
            check(("user-" + won).equals(fin.get("decidedBy")), "the decision of the winner must stand");
            check((won % 2 == 0 ? "approved" : "denied").equals(fin.get("status")), "the status must be the winner's decision");
        }));
        cs.add(new Case("an approval redeems once even when many brokers redeem at the same time", () -> {
            List<ApprovalBroker> bs = brokers(make, 8);
            String id = (String) bs.get(0).start(stepUp(), null).get("auth_req_id");
            bs.get(0).resolve(id, "approve", "owner");
            List<Object> rs = concurrently(8, i -> () -> bs.get(i).token(id));
            int ok = 0;
            for (Object r : rs) if (r instanceof Map && Boolean.TRUE.equals(((Map<?, ?>) r).get("ok"))) ok++;
            check(ok == 1, "an approval must redeem exactly once");
        }));
        cs.add(new Case("a second broker over the same store sees the decision of the first", () -> {
            List<ApprovalBroker> bs = brokers(make, 2);
            String id = (String) bs.get(0).start(stepUp(), null).get("auth_req_id");
            check("pending".equals(bs.get(1).poll(id).get("status")), "the second broker must see the request pending");
            bs.get(0).resolve(id, "approve", "owner");
            check("approved".equals(bs.get(1).poll(id).get("status")), "the second broker must see the approval");
            try {
                bs.get(1).resolve(id, "deny", "late");
            } catch (RuntimeException expected) {
                return;
            }
            throw new AssertionError("a late resolve must be refused");
        }));
        return cs;
    }
}
