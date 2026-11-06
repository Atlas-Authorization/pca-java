package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;

import org.junit.jupiter.api.Test;

/**
 * The plan registry (T10) member by member: the record accessors, the key scope, every refusal reason of every transition
 * (with its reported state), the structural checks one by one, the status and per-action check reasons, and the failure modes
 * of a store (one that throws, one that never runs the update).
 */
public class PlanRegistryKillTest {
    static final long T0 = 1_800_000_000_000L;

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(java.util.Arrays.asList(xs)); }

    static Map<String, Object> node(String id, Object... extra) {
        Map<String, Object> n = map("id", id, "verb", "payments.refund", "resource", "/orders/1");
        n.putAll(map(extra));
        return n;
    }

    static Map<String, Object> no(String state, String reason) { return map("ok", false, "state", state, "reason", reason); }

    static String canon(Object v) { return Json.canonicalize(v); }

    /** draft, validate, commit, authorize (by alice, until {@code exp}; null: no expiry). */
    static String authorized(PlanRegistry reg, String grant, List<Object> nodes, Long exp) {
        PlanRegistry.PlanTransition d = reg.draft(grant, nodes);
        assertTrue(d.ok, String.valueOf(d.toMap()));
        String root = d.record.root();
        assertTrue(reg.validate(grant, root).ok);
        assertTrue(reg.commit(grant, root).ok);
        assertTrue(reg.authorize(grant, root, "alice", exp).ok);
        return root;
    }

    // ---- PlanRecord ------------------------------------------------------------------------------------------------

    @Test void planRecordOfAndItsMembers() {
        assertNull(PlanRegistry.PlanRecord.of("x"));
        assertNull(PlanRegistry.PlanRecord.of(map("root", IntentJs.ofLong(1), "nodes", list(), "state", "s")));
        assertNull(PlanRegistry.PlanRecord.of(map("root", "r", "nodes", "x", "state", "s")));
        assertNull(PlanRegistry.PlanRecord.of(map("root", "r", "nodes", list(), "state", IntentJs.ofLong(2))));
        assertNull(PlanRegistry.PlanRecord.of(map("nodes", list(), "state", "s")));
        assertNull(PlanRegistry.PlanRecord.of(map("root", "r", "state", "s")));
        assertNull(PlanRegistry.PlanRecord.of(map("root", "r", "nodes", list())));

        PlanRegistry.PlanRecord r = PlanRegistry.PlanRecord.of(map("grantRef", "g", "root", "r", "nodes", list(node("n1")), "state", "s",
            "createdAt", IntentJs.ofLong(1), "validatedAt", IntentJs.ofLong(2), "committedAt", IntentJs.ofLong(3), "authorizedAt", IntentJs.ofLong(4),
            "revokedAt", IntentJs.ofLong(5), "approval", map("by", "alice"), "revokedReason", "why"));
        assertEquals("g", r.grantRef());
        assertEquals("r", r.root());
        assertEquals("s", r.state());
        assertEquals(Long.valueOf(1), r.createdAt());
        assertEquals(Long.valueOf(2), r.validatedAt());
        assertEquals(Long.valueOf(3), r.committedAt());
        assertEquals(Long.valueOf(4), r.authorizedAt());
        assertEquals(Long.valueOf(5), r.revokedAt());
        assertEquals("why", r.revokedReason());
        assertEquals(map("by", "alice"), r.approval());
        // copies: changing what was returned never changes the record
        r.nodes().add("extra");
        ((Map<String, Object>) r.nodes().get(0)).put("verb", "changed");
        assertEquals(canon(list(node("n1"))), canon(r.nodes()));
        r.approval().put("by", "mallory");
        assertEquals(map("by", "alice"), r.approval());
        r.toMap().put("state", "t");
        assertEquals("s", r.state());

        PlanRegistry.PlanRecord bare = PlanRegistry.PlanRecord.of(map("root", "r", "nodes", list(), "state", "s"));
        assertEquals("PlanRecord{root=r, nodes=[], state=s}", bare.toString());
        assertNull(bare.grantRef());
        assertNull(bare.createdAt());
        assertNull(bare.validatedAt());
        assertNull(bare.committedAt());
        assertNull(bare.authorizedAt());
        assertNull(bare.revokedAt());
        assertNull(bare.approval());
        assertNull(bare.revokedReason());
        PlanRegistry.PlanRecord odd = PlanRegistry.PlanRecord.of(map("root", "r", "nodes", list(), "state", "s", "approval", "x", "revokedReason", IntentJs.ofLong(1)));
        assertNull(odd.approval());
        assertNull(odd.revokedReason());
        Object[][] instants = {
            {Double.NaN, null}, {Double.POSITIVE_INFINITY, null}, {Double.NEGATIVE_INFINITY, null}, {new Json.Num("x"), null},
            {"5", null}, {12.7, 12L}, {IntentJs.ofLong(-3), -3L},
        };
        for (Object[] c : instants)
            assertEquals(c[1], PlanRegistry.PlanRecord.of(map("root", "r", "nodes", list(), "state", "s", "createdAt", c[0])).createdAt(), String.valueOf(c[0]));
    }

    // ---- construction and keys --------------------------------------------------------------------------------------

    @Test void constructionAndKeyScope() {
        assertEquals("kv", assertThrows(IllegalArgumentException.class, () -> new PlanRegistry(null, "p", () -> 1L, null)).getMessage());
        String grant = "a b/é!'()~*";
        assertEquals("a%20b%2F%C3%A9!'()~*", PlanRegistry.encodeUriComponent(grant));
        MemoryAtomicKv kv = new MemoryAtomicKv();
        String root = new PlanRegistry(kv, null, () -> T0, null).draft(grant, list(node("n1"))).record.root();
        assertNotNull(kv.get("pca-plan:a%20b%2F%C3%A9!'()~*:" + root));
        assertNull(kv.get("nulla%20b%2F%C3%A9!'()~*:" + root));
        PlanRegistry custom = new PlanRegistry(kv, "x/", () -> T0, null);
        assertTrue(custom.draft("g", list(node("n1"))).ok);
        assertNotNull(kv.get("x/g:" + root));
        assertEquals("draft", custom.get("g", root).state());
        assertNull(custom.get(grant, root), "another prefix is another scope");

        long before = System.currentTimeMillis();
        long a = new PlanRegistry(kv, "w/", null, null).draft("g", list(node("n1"))).record.createdAt();
        long b = new PlanRegistry().draft("g", list(node("n1"))).record.createdAt();
        long after = System.currentTimeMillis();
        assertTrue(a >= before && a <= after);
        assertTrue(b >= before && b <= after);
        assertEquals(Long.valueOf(T0), custom.get("g", root).createdAt());
    }

    // ---- draft -----------------------------------------------------------------------------------------------------

    /** A list whose iteration fails with an exception that carries no message. */
    static List<Object> unreadable() {
        return new ArrayList<Object>() {
            @Override public Iterator<Object> iterator() { throw new IllegalStateException(); }
        };
    }

    static final AtomicKv INERT = new AtomicKv() {
        @Override public Object get(String key) { return null; }
        @Override public void set(String key, Object value) {}
        @Override public Object update(String key, UnaryOperator<Object> fn) { return null; }
    };

    @Test void draftRefusals() {
        PlanRegistry reg = new PlanRegistry(new MemoryAtomicKv(), null, () -> T0, null);
        assertEquals(no("unknown", "a plan needs a grant"), reg.draft(null, list(node("n1"))).toMap());
        assertEquals(no("unknown", "a plan needs a grant"), reg.draft("", list(node("n1"))).toMap());
        assertEquals(no("unknown", "the plan cannot be committed: merkleRoot: empty leaf set"), reg.draft("g", list()).toMap());
        assertEquals(no("unknown", "the plan cannot be committed: unknown"), reg.draft("g", unreadable()).toMap());
        PlanRegistry.PlanTransition first = reg.draft("g", list(node("n1")));
        assertTrue(first.ok);
        String root = first.record.root();
        assertEquals(no("draft", "plan " + root + " already exists (draft)"), reg.draft("g", list(node("n1"))).toMap());
        // a store that never runs the update records nothing and says so
        PlanRegistry inert = new PlanRegistry(INERT, null, () -> T0, null);
        assertEquals(no("unknown", "plan " + root + " was not recorded (the store did not run the update)"), inert.draft("g", list(node("n1"))).toMap());
        assertEquals(no("unknown", "plan " + root + " is unknown for this grant"), inert.commit("g", root).toMap());
        assertEquals(no("unknown", "plan " + root + " is unknown for this grant"), inert.revoke("g", root, "x").toMap());
    }

    @Test void theDraftKeepsAPrivateCopyAndTheRootCoversConditions() {
        PlanRegistry reg = new PlanRegistry(new MemoryAtomicKv(), null, () -> T0, null);
        List<Object> ns = list(node("n1", "pre", map("a", IntentJs.ofLong(1)), "post", list("b")));
        PlanRegistry.PlanTransition t = reg.draft("g", ns);
        String root = t.record.root();
        @SuppressWarnings("unchecked")
        Map<String, Object> copy = (Map<String, Object>) PlanRegistry.deepCopy(ns.get(0));
        assertEquals(Pca.merkleRoot(list(Pca.planLeaf("n1", copy, Pca.conditionsDigest(copy.get("pre"), copy.get("post"))))), root);
        assertFalse(root.equals(reg.draft("g", list(node("n1"))).record.root()), "pre/post are part of the commitment");
        String before = canon(reg.get("g", root).nodes());
        ((Map<String, Object>) ns.get(0)).put("verb", "changed");
        ns.add(node("n2"));
        assertEquals(before, canon(reg.get("g", root).nodes()));
        assertEquals(canon(list(node("n1", "pre", map("a", IntentJs.ofLong(1)), "post", list("b")))), before);
        assertEquals(canon(map("ok", true, "record", map("grantRef", "g", "root", root, "nodes", PlanRegistry.deepCopy(list(node("n1", "pre", map("a", IntentJs.ofLong(1)), "post", list("b")))),
            "state", "draft", "createdAt", IntentJs.ofLong(T0)))), canon(t.toMap()));
    }

    // ---- validate --------------------------------------------------------------------------------------------------

    static PlanRegistry seeded(MemoryAtomicKv kv, List<Object> nodes, String state, PlanRegistry.Validator v) {
        kv.set("p:g:R", map("grantRef", "g", "root", "R", "nodes", nodes, "state", state, "createdAt", IntentJs.ofLong(T0)));
        return new PlanRegistry(kv, "p:", () -> T0, v);
    }

    @Test void structuralProblemsOneByOne() {
        Object[][] cases = {
            {list(), "a plan needs at least one node"},
            {list("x"), "every node needs an id"},
            {list(map("verb", "v", "resource", "r")), "every node needs an id"},
            {list(map("id", IntentJs.ofLong(1), "verb", "v", "resource", "r")), "every node needs an id"},
            {list(map("id", "", "verb", "v", "resource", "r")), "every node needs an id"},
            {list(node("a"), node("a")), "duplicate node id 'a'"},
            {list(map("id", "a", "resource", "r")), "node 'a' needs a verb and a resource"},
            {list(map("id", "a", "verb", IntentJs.ofLong(1), "resource", "r")), "node 'a' needs a verb and a resource"},
            {list(map("id", "a", "verb", "", "resource", "r")), "node 'a' needs a verb and a resource"},
            {list(map("id", "a", "verb", "v")), "node 'a' needs a verb and a resource"},
            {list(map("id", "a", "verb", "v", "resource", IntentJs.ofLong(1))), "node 'a' needs a verb and a resource"},
            {list(map("id", "a", "verb", "v", "resource", "")), "node 'a' needs a verb and a resource"},
            {list(node("a", "reversibility_class", "bogus")), "node 'a' has an unknown reversibility class 'bogus'"},
            {list(node("a", "reversibility_class", IntentJs.ofLong(7))), "node 'a' has an unknown reversibility class '7'"},
            {list(node("a", "reversibility_class", null)), "node 'a' has an unknown reversibility class 'null'"},
            // structurally valid: the stored root is not theirs
            {list(node("a")), "the stored nodes no longer hash to the root"},
            {list(node("a", "reversibility_class", "reversible")), "the stored nodes no longer hash to the root"},
            {list(node("a", "reversibility_class", "rate_limited")), "the stored nodes no longer hash to the root"},
            {list(node("a", "reversibility_class", "costly")), "the stored nodes no longer hash to the root"},
            {list(node("a", "reversibility_class", "irreversible")), "the stored nodes no longer hash to the root"},
            {list(node("a"), node("b", "reversibility_class", "x")), "node 'b' has an unknown reversibility class 'x'"},
        };
        for (Object[] c : cases) {
            @SuppressWarnings("unchecked")
            List<Object> nodes = (List<Object>) c[0];
            PlanRegistry reg = seeded(new MemoryAtomicKv(), nodes, "draft", r -> { throw new AssertionError("the validator runs only on a sound plan"); });
            assertEquals(no("draft", "plan R is invalid: " + c[1]), reg.validate("g", "R").toMap(), String.valueOf(c[1]));
            assertEquals("draft", reg.get("g", "R").state());
        }
    }

    @Test void validateStatesAndTheValidator() {
        PlanRegistry reg = new PlanRegistry(new MemoryAtomicKv(), null, () -> T0, null);
        assertEquals(no("unknown", "plan R is unknown for this grant"), reg.validate("g", "R").toMap());
        String root = reg.draft("g", list(node("n1"))).record.root();
        PlanRegistry.PlanTransition v = reg.validate("g", root);
        assertTrue(v.ok);
        assertEquals(Long.valueOf(T0), v.record.validatedAt());
        assertEquals(no("validated", "plan " + root + " is validated: cannot validate"), reg.validate("g", root).toMap());

        Object[][] validators = {
            {(PlanRegistry.Validator) r -> { throw new IllegalStateException(); }, "plan %s is invalid: validator error (fail closed): unknown"},
            {(PlanRegistry.Validator) r -> { throw new Exception("down"); }, "plan %s is invalid: validator error (fail closed): down"},
            {(PlanRegistry.Validator) r -> "outside the grant", "plan %s is invalid: outside the grant"},
        };
        for (Object[] c : validators) {
            PlanRegistry vr = new PlanRegistry(new MemoryAtomicKv(), null, () -> T0, (PlanRegistry.Validator) c[0]);
            String rt = vr.draft("g", list(node("n1"))).record.root();
            assertEquals(no("draft", String.format((String) c[1], rt)), vr.validate("g", rt).toMap());
        }
        List<String> seen = new ArrayList<>();
        PlanRegistry ok = new PlanRegistry(new MemoryAtomicKv(), null, () -> T0, r -> { seen.add(r.root()); return null; });
        String rt = ok.draft("g", list(node("n1"))).record.root();
        assertTrue(ok.validate("g", rt).ok);
        assertEquals(List.of(rt), seen);
        PlanRegistry fresh = new PlanRegistry(new MemoryAtomicKv(), null, () -> T0, null);
        String d = fresh.draft("g", list(node("n1"))).record.root();
        assertEquals(no("draft", "plan " + d + " is draft: cannot commit"), fresh.commit("g", d).toMap());
    }

    // ---- authorize and revoke ----------------------------------------------------------------------------------------

    @Test void authorizeRefusalsAndTheApprovalCopy() {
        long[] now = {T0};
        PlanRegistry reg = new PlanRegistry(new MemoryAtomicKv(), null, () -> now[0], null);
        String root = reg.draft("g", list(node("n1"))).record.root();
        assertTrue(reg.validate("g", root).ok);
        assertTrue(reg.commit("g", root).ok);
        String noBy = "an approval names who approved (`by`)";
        assertEquals(no("committed", noBy), reg.authorize("g", root, (Map<String, Object>) null).toMap());
        assertEquals(no("committed", noBy), reg.authorize("g", root, map("by", IntentJs.ofLong(1))).toMap());
        assertEquals(no("committed", noBy), reg.authorize("g", root, map("by", "")).toMap());
        assertEquals(no("committed", noBy), reg.authorize("g", root, map()).toMap());
        assertEquals(no("unknown", noBy), reg.authorize("g", "other", map()).toMap());
        assertEquals(no("committed", "approval.expiresAt must be a time (epoch ms)"), reg.authorize("g", root, map("by", "a", "expiresAt", "soon")).toMap());
        assertEquals(no("unknown", "approval.expiresAt must be a time (epoch ms)"), reg.authorize("g", "other", map("by", "a", "expiresAt", "soon")).toMap());

        Map<String, Object> approval = map("by", "alice", "expiresAt", IntentJs.ofLong(T0 + 10));
        now[0] = T0 + 1;
        PlanRegistry.PlanTransition t = reg.authorize("g", root, approval);
        assertTrue(t.ok);
        assertEquals(Long.valueOf(T0 + 1), t.record.authorizedAt());
        approval.put("by", "mallory");
        assertEquals(canon(map("by", "alice", "expiresAt", IntentJs.ofLong(T0 + 10))), canon(reg.get("g", root).approval()));
        assertEquals(no("authorized", "plan " + root + " is authorized: cannot authorize"), reg.authorize("g", root, "bob", null).toMap());

        // the (by, expiresAt) form
        PlanRegistry r2 = new PlanRegistry(new MemoryAtomicKv(), null, () -> T0, null);
        String a = authorized(r2, "g", list(node("n1")), null);
        assertEquals(canon(map("by", "alice")), canon(r2.get("g", a).approval()));
        PlanRegistry r3 = new PlanRegistry(new MemoryAtomicKv(), null, () -> T0, null);
        String b = authorized(r3, "g", list(node("n1")), T0 + 5);
        assertEquals(canon(map("by", "alice", "expiresAt", IntentJs.ofLong(T0 + 5))), canon(r3.get("g", b).approval()));
    }

    @Test void revokeAndTheNonExecutableReasons() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        PlanRegistry reg = new PlanRegistry(kv, "p:", () -> T0 + 7, null);
        String root = reg.draft("g", list(node("n1"))).record.root();
        assertEquals(canon(map("state", "draft", "executable", false, "reason", "plan " + root + " is draft, not authorized", "record", reg.get("g", root).toMap())),
            canon(reg.status("g", root, T0).toMap()));
        PlanRegistry.PlanTransition rv = reg.revoke("g", root, null);
        assertTrue(rv.ok);
        assertEquals("", rv.record.revokedReason());
        assertEquals(Long.valueOf(T0 + 7), rv.record.revokedAt());
        assertEquals("plan " + root + " is revoked ()", reg.status("g", root, T0).reason);
        assertEquals(no("revoked", "plan " + root + " is revoked: cannot revoke"), reg.revoke("g", root, "again").toMap());
        String r2 = reg.draft("g", list(node("n2"))).record.root();
        assertEquals("because", reg.revoke("g", r2, "because").record.revokedReason());
        assertEquals("plan " + r2 + " is revoked (because)", reg.status("g", r2, T0).reason);
        kv.set("p:g:R", map("grantRef", "g", "root", "R", "nodes", list(node("n1")), "state", "revoked"));
        assertEquals("plan R is revoked (no reason given)", reg.status("g", "R", T0).reason);
        kv.set("p:g:C", map("grantRef", "g", "root", "C", "nodes", list(node("n1")), "state", "committed"));
        assertEquals("plan C is committed but not authorized by the principal", reg.status("g", "C", T0).reason);
        assertEquals(map("state", "unknown", "executable", false, "reason", "plan Z is unknown for this grant"), reg.status("g", "Z", T0).toMap());
    }

    // ---- status and check ------------------------------------------------------------------------------------------

    @Test void statusOfAnAuthorizedPlan() {
        MemoryAtomicKv kv = new MemoryAtomicKv();
        long[] now = {T0};
        PlanRegistry reg = new PlanRegistry(kv, "p:", () -> now[0], null);
        String root = authorized(reg, "g", list(node("n1")), T0 + 100);
        PlanRegistry.PlanStatus ok = reg.status("g", root, T0 + 99);
        assertEquals(canon(map("state", "authorized", "executable", true, "record", reg.get("g", root).toMap())), canon(ok.toMap()));
        assertNull(ok.reason);
        String expired = "plan " + root + ": the principal's approval expired at 1800000000100";
        assertEquals(canon(map("state", "authorized", "executable", false, "reason", expired, "record", reg.get("g", root).toMap())), canon(reg.status("g", root, T0 + 100).toMap()));
        now[0] = T0 + 100;
        assertEquals(expired, reg.status("g", root).reason, "no time given: the registry's clock");
        now[0] = T0;
        assertTrue(reg.status("g", root).executable);
        assertTrue(reg.isPlanAuthorized("g", root));
        assertFalse(reg.isPlanAuthorized("g", "nope"));

        // no approval object, or one without an expiry: executable
        Map<String, Object> stored = new LinkedHashMap<>(IntentJs.obj(kv.get("p:g:" + root)));
        stored.remove("approval");
        kv.set("p:g:" + root, stored);
        assertTrue(reg.status("g", root, T0 + 1_000_000).executable);
        stored.put("approval", map("by", "alice"));
        kv.set("p:g:" + root, stored);
        assertTrue(reg.status("g", root, T0 + 1_000_000).executable);
        // an expiry that is not a number has lapsed
        stored.put("approval", map("by", "alice", "expiresAt", "soon"));
        kv.set("p:g:" + root, stored);
        assertEquals("plan " + root + ": the principal's approval expired at soon", reg.status("g", root, T0).reason);
        // nodes that no longer hash to the root (changed, or none at all)
        stored.put("approval", map("by", "alice"));
        stored.put("nodes", list(node("n9")));
        kv.set("p:g:" + root, stored);
        PlanRegistry.PlanStatus moved = reg.status("g", root, T0);
        assertFalse(moved.executable);
        assertEquals("authorized", moved.state);
        assertEquals("plan " + root + ": the stored nodes no longer hash to the root", moved.reason);
        stored.put("nodes", list());
        kv.set("p:g:" + root, stored);
        assertEquals("plan " + root + ": the stored nodes no longer hash to the root", reg.status("g", root, T0).reason);
    }

    @Test void checkPerAction() {
        long[] now = {T0};
        PlanRegistry reg = new PlanRegistry(new MemoryAtomicKv(), null, () -> now[0], null);
        Map<String, Object> params = map("n", (short) 5);
        String digest = Pca.paramsDigest(Authorize.copyParams(params));
        String root = authorized(reg, "g", list(node("n1"), node("n2", "verb", "payments.capture", "params_digest", digest)), T0 + 100);
        Map<String, Object> rec = reg.get("g", root).toMap();

        assertTrue(reg.check("g", root, null, null, T0).executable);
        assertTrue(reg.check("g", root, "n1", null, T0).executable);
        assertEquals(canon(map("state", "authorized", "executable", false, "reason", "plan " + root + " has no node 'nX'", "record", rec)),
            canon(reg.check("g", root, "nX", null, T0).toMap()));
        // the operation must be one the principal approved (verb, resource, params digest; no digest: empty params)
        Authorize.Operation refund = Authorize.Operation.of("payments.refund", "/orders/1", new LinkedHashMap<>());
        assertTrue(reg.check("g", root, null, refund, T0).executable);
        assertTrue(reg.check("g", root, "n1", refund, T0).executable);
        assertTrue(reg.check("g", root, "n1", new Authorize.Operation("payments.refund", "/orders/1", null), T0).executable);
        Authorize.Operation capture = Authorize.Operation.of("payments.capture", "/orders/1", params);
        assertTrue(reg.check("g", root, null, capture, T0).executable);
        assertTrue(reg.check("g", root, "n2", capture, T0).executable);
        String notApproved = "plan " + root + ": the operation (payments.capture on /orders/1 with these params) is not what the principal approved";
        assertEquals(canon(map("state", "authorized", "executable", false, "reason", notApproved, "record", rec)), canon(reg.check("g", root, "n1", capture, T0).toMap()));
        assertEquals(notApproved, reg.check("g", root, null, Authorize.Operation.of("payments.capture", "/orders/1", map("n", (short) 6)), T0).reason);
        assertEquals("plan " + root + ": the operation (payments.refund on /orders/2 with these params) is not what the principal approved",
            reg.check("g", root, null, Authorize.Operation.of("payments.refund", "/orders/2", new LinkedHashMap<>()), T0).reason);
        assertEquals("plan " + root + ": the operation (payments.void on /orders/1 with these params) is not what the principal approved",
            reg.check("g", root, null, Authorize.Operation.of("payments.void", "/orders/1", new LinkedHashMap<>()), T0).reason);
        assertEquals(canon(map("state", "authorized", "executable", false, "reason", "plan " + root + ": the operation's params cannot be hashed", "record", rec)),
            canon(reg.check("g", root, null, Authorize.Operation.of("payments.refund", "/orders/1", map("x", new Object())), T0).toMap()));
        // not executable: the status as it is, the action rules are not applied
        assertEquals(canon(reg.status("g", root, T0 + 100).toMap()), canon(reg.check("g", root, "nX", refund, T0 + 100).toMap()));
        assertEquals("plan Z is unknown for this grant", reg.check("g", "Z", "n1", refund, T0).reason);
        // no time given: the registry's clock
        now[0] = T0 + 100;
        assertFalse(reg.check("g", root, null, null, null).executable);
        now[0] = T0;
        assertTrue(reg.check("g", root, null, null, null).executable);
    }

    @Test void contextAndAFailingStore() {
        long[] now = {T0};
        PlanRegistry reg = new PlanRegistry(new MemoryAtomicKv(), null, () -> now[0], null);
        String root = authorized(reg, "g", list(node("n1")), T0 + 100);
        assertNull(reg.context("g", "nope", T0));
        PlanRegistry.PlanContext c = reg.context("g", root, T0);
        assertTrue(c.planAuthorized);
        assertEquals(canon(list(node("n1"))), canon(c.plan));
        assertEquals(canon(map("plan", list(node("n1")), "planAuthorized", true, "status", reg.status("g", root, T0).toMap())), canon(c.toMap()));
        assertFalse(reg.context("g", root, T0 + 100).planAuthorized);
        now[0] = T0 + 100;
        assertFalse(reg.context("g", root, null).planAuthorized);
        now[0] = T0;
        assertTrue(reg.context("g", root, null).planAuthorized);

        AtomicKv down = new AtomicKv() {
            @Override public Object get(String key) { throw new IllegalStateException("down"); }
            @Override public void set(String key, Object value) { throw new IllegalStateException("down"); }
            @Override public Object update(String key, UnaryOperator<Object> fn) { throw new IllegalStateException("down"); }
        };
        assertFalse(new PlanRegistry(down, null, () -> T0, null).isPlanAuthorized("g", root));
    }
}
