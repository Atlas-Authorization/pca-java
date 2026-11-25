package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * Plan lifecycle (T10): the shared plan vectors scenario by scenario (roots are Merkle roots of the plan-node leaves, so the
 * registry must reproduce the reference commitment), the concurrency guarantee (N parallel claims of one transition: exactly one
 * wins) over the in-memory and a durable SQLite store, and the {@code plans} option of {@code Authorize}.
 */
public class PlanVectorsTest {
    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked")
    static List<Object> l(Object o) { return (List<Object>) o; }

    static PlanRegistry.Validator validatorOf(String kind) {
        if (kind == null) return null;
        switch (kind) {
            case "accept": return r -> null;
            case "refuse": return r -> "node outside the grant";
            default: return r -> { throw new IllegalStateException("policy down"); };
        }
    }

    @Test void scenarios() {
        Map<String, Object> doc = Track3Vectors.load("plan-vectors.json");
        List<Object> scenarios = l(doc.get("scenarios"));
        assertEquals(12, scenarios.size());
        for (Object so : scenarios) {
            Map<String, Object> sc = m(so);
            String name = (String) sc.get("name");
            long[] now = {0};
            PlanRegistry reg = new PlanRegistry(new MemoryAtomicKv(), null, () -> now[0], validatorOf((String) sc.get("validator")));
            List<Object> steps = l(sc.get("steps")), expect = l(sc.get("expect"));
            assertEquals(steps.size(), expect.size(), name);
            for (int i = 0; i < steps.size(); i++) {
                Map<String, Object> s = m(steps.get(i));
                long at = Json.asLong(s.get("at"));
                now[0] = at;
                String grant = (String) s.get("grant"), root = (String) s.get("root");
                Object got;
                switch ((String) s.get("op")) {
                    case "draft": got = reg.draft(grant, l(s.get("nodes"))).toMap(); break;
                    case "validate": got = reg.validate(grant, root).toMap(); break;
                    case "commit": got = reg.commit(grant, root).toMap(); break;
                    case "authorize": {
                        Object ap = s.get("approval");
                        // a JSON null approval is "no approval"
                        got = reg.authorize(grant, root, ap instanceof Map ? m(ap) : null).toMap();
                        break;
                    }
                    case "revoke": got = reg.revoke(grant, root, (String) s.get("reason")).toMap(); break;
                    case "status": got = reg.status(grant, root, at).toMap(); break;
                    case "check": {
                        Authorize.Operation op = null;
                        if (s.get("operation") instanceof Map) {
                            Map<String, Object> o = m(s.get("operation"));
                            op = new Authorize.Operation((String) o.get("verb"), (String) o.get("resource"), o.containsKey("params") ? m(o.get("params")) : null);
                        }
                        got = reg.check(grant, root, (String) s.get("node_id"), op, at).toMap();
                        break;
                    }
                    case "is_plan_authorized": got = reg.isPlanAuthorized(grant, root); break;
                    case "context": {
                        PlanRegistry.PlanContext pc = reg.context(grant, root, at);
                        got = pc == null ? null : pc.toMap();
                        break;
                    }
                    default: throw new AssertionError(name + ": unknown step " + s.get("op"));
                }
                assertEquals(Json.canonicalize(expect.get(i)), Json.canonicalize(got), name + " step " + i + " (" + s.get("op") + ")");
            }
        }
    }

    // ---- concurrency ---------------------------------------------------------------------------------------------------

    static List<Object> nodes() {
        Map<String, Object> n = new LinkedHashMap<>();
        n.put("id", "n1");
        n.put("verb", "payments.refund");
        n.put("resource", "/orders/1");
        return new ArrayList<>(List.of(n));
    }

    static void parallelClaimsOfOneTransition(AtomicKv kv) throws Exception {
        PlanRegistry reg = new PlanRegistry(kv, null, () -> 1_800_000_000_000L, null);
        String root = (String) reg.draft("g1", nodes()).record.root();
        assertTrue(reg.validate("g1", root).ok);
        int n = 12;
        // N parallel commits: exactly one wins
        AtomicInteger wins = new AtomicInteger();
        CountDownLatch go = new CountDownLatch(1);
        List<Thread> ts = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            Thread t = new Thread(() -> {
                try { go.await(); } catch (InterruptedException e) { return; }
                if (reg.commit("g1", root).ok) wins.incrementAndGet();
            });
            ts.add(t);
            t.start();
        }
        go.countDown();
        for (Thread t : ts) t.join();
        assertEquals(1, wins.get(), "exactly one commit wins");
        // N parallel authorize and N parallel revoke after it
        AtomicInteger approved = new AtomicInteger(), revoked = new AtomicInteger();
        CountDownLatch go2 = new CountDownLatch(1);
        List<Thread> ts2 = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            Thread t = new Thread(() -> {
                try { go2.await(); } catch (InterruptedException e) { return; }
                if (reg.authorize("g1", root, "principal", null).ok) approved.incrementAndGet();
            });
            ts2.add(t);
            t.start();
        }
        go2.countDown();
        for (Thread t : ts2) t.join();
        assertEquals(1, approved.get(), "exactly one authorize wins");
        assertTrue(reg.status("g1", root).executable);
        CountDownLatch go3 = new CountDownLatch(1);
        List<Thread> ts3 = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            Thread t = new Thread(() -> {
                try { go3.await(); } catch (InterruptedException e) { return; }
                if (reg.revoke("g1", root, "stop").ok) revoked.incrementAndGet();
            });
            ts3.add(t);
            t.start();
        }
        go3.countDown();
        for (Thread t : ts3) t.join();
        assertEquals(1, revoked.get(), "exactly one revoke wins");
        assertFalse(reg.status("g1", root).executable);
        assertEquals("revoked", reg.get("g1", root).state());
    }

    @Test void parallelClaimsInMemory() throws Exception { parallelClaimsOfOneTransition(new MemoryAtomicKv()); }

    @Test void parallelClaimsOnSqlite() throws Exception {
        Path f = Files.createTempFile("pca-plans", ".db");
        try {
            parallelClaimsOfOneTransition(new PcaJdbcAtomicKv(() -> AuthorizeFixtures.sqliteConnection(f)).createTable());
        } finally {
            Files.deleteIfExists(f);
        }
    }

    @Test void keysEncodeLikeEncodeUriComponent() {
        assertEquals("a%20b%2Fc%3Fd!'()*~-_.", PlanRegistry.encodeUriComponent("a b/c?d!'()*~-_."));
        assertEquals("%C3%A9", PlanRegistry.encodeUriComponent("é"));
    }

    // ---- authorize({ plans }) ------------------------------------------------------------------------------------------

    @Test void authorizeNamesThePlanState() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Map<String, Object> p = m(AuthorizeFixtures.pcactn(c, 0));
        String grantRef = (String) p.get("grant_ref");
        String planRoot = (String) m(p.get("plan")).get("root");
        Map<String, Object> pl = m(p.get("plan"));
        Authorize.Operation op = AuthorizeFixtures.operation(c, 0);
        Map<String, Object> node = new LinkedHashMap<>();
        node.put("id", pl.get("node_id"));
        node.put("verb", op.verb);
        node.put("resource", op.resource);
        node.put("params_digest", Pca.paramsDigest(Authorize.copyParams(op.params)));
        node.put("reversibility_class", m(p.get("action")).get("reversibility_class"));

        PlanRegistry reg = new PlanRegistry();
        PlanRegistry.PlanTransition d = reg.draft(grantRef, List.of(node));
        assertTrue(d.ok, d.reason);
        assertEquals(planRoot, d.record.root(), "the registry commits to the same root the PCActn signed");

        // not committed yet: refused, and the state is named
        Authorize.AuthorizeResult draftOnly = Authorize.authorize(p, AuthorizeFixtures.input(c, 0).plan(null).plans(reg));
        assertFalse(draftOnly.allow);
        assertEquals("fail", draftOnly.checks.get("plan_state"));
        assertTrue(draftOnly.reason.startsWith("plan_state: plan " + planRoot + " is draft, not authorized"), draftOnly.reason);

        assertTrue(reg.validate(grantRef, planRoot).ok);
        assertTrue(reg.commit(grantRef, planRoot).ok);
        Authorize.AuthorizeResult committed = Authorize.authorize(p, AuthorizeFixtures.input(c, 0).plan(null).plans(reg));
        assertFalse(committed.allow);
        assertEquals("plan_state: plan " + planRoot + " is committed but not authorized by the principal", committed.reason);

        // authorized: allowed, and nothing was consumed by the refusals
        assertTrue(reg.authorize(grantRef, planRoot, "principal", null).ok);
        StateStore store = new MemoryStateStore();
        Authorize.AuthorizeResult ok = Authorize.authorize(p, AuthorizeFixtures.input(c, 0).plan(null).plans(reg).stateStore(store));
        assertTrue(ok.allow, ok.reasons.toString());
        assertEquals("pass", ok.checks.get("plan_state"));
        assertEquals("pass", ok.checks.get("plan_root_authorized"));

        // revoked: refused again
        assertTrue(reg.revoke(grantRef, planRoot, "stop").ok);
        Authorize.AuthorizeResult revoked = Authorize.authorize(p, AuthorizeFixtures.input(c, 0).plan(null).plans(reg));
        assertFalse(revoked.allow);
        assertTrue(revoked.reason.startsWith("plan_state: plan " + planRoot + " is revoked (stop)"), revoked.reason);
    }

    @Test void anUnknownRootIsRefusedUnlessSingleStepApplies() {
        Map<String, Object> c = AuthorizeFixtures.cases().get(0);
        Map<String, Object> p = m(AuthorizeFixtures.pcactn(c, 0));
        String planRoot = (String) m(p.get("plan")).get("root");
        PlanRegistry empty = new PlanRegistry();
        Authorize.AuthorizeResult refused = Authorize.authorize(p, AuthorizeFixtures.input(c, 0).plan(null).plans(empty));
        assertFalse(refused.allow);
        assertEquals("plan_state: plan " + planRoot + " is unknown to the plan registry", refused.reason);
        // single-step: the registry does not know the root, the grant alone limits what runs
        Authorize.AuthorizeResult single = Authorize.authorize(p, AuthorizeFixtures.input(c, 0).plan(Authorize.SINGLE_STEP).plans(empty));
        assertTrue(single.allow, single.reasons.toString());
        assertFalse(single.checks.containsKey("plan_state"));
    }
}
