package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** PCA 0.5 mutation kills for Actions.java below line 600: validateDef / paramError, the strict JSON profile, registry, closure, profile algebra. */
public class K05R4ActionsAKillTest {
    static Map<String, Object> m(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    static Map<String, Object> def() {
        return m("v", 1L, "kind", "pca-action-def", "verb", "a.b", "title", "T", "effects", list("read"),
            "resource", m("type", "doc", "id", "*", "scope", "one"), "params", m(), "review", m("state", "authored"));
    }

    @SuppressWarnings("unchecked")
    static Object imm(Object o) {
        if (o instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) o).entrySet()) out.put(e.getKey(), imm(e.getValue()));
            return Map.copyOf(out);
        }
        if (o instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) o) out.add(imm(x));
            return List.copyOf(out);
        }
        return o;
    }

    static String withParam(Map<String, Object> p) {
        Map<String, Object> d = def();
        d.put("params", m("x", p));
        return Actions.validateDef(d);
    }

    /** a dotted name of exactly {@code total} chars: 32,32,32 and the rest (valid for the verb, alias and resource-type shapes). */
    static String dotted(int total) { return "a".repeat(32) + "." + "a".repeat(32) + "." + "a".repeat(32) + "." + "a".repeat(total - 99); }

    @Test
    void immutableMapsAreAcceptedAndNeverProbedWithNull() {
        Map<String, Object> d = def();
        d.put("params", m(
            "p", m("type", "integer", "min", 0L, "max", 5L),
            "q", m("type", "array", "items", "integer", "min", 1L, "min_items", 0L, "max_items", 3L)));
        assertNull(Actions.validateDef(imm(d)));
        assertNull(Actions.validateDef(d));
    }

    @Test
    void jsonProfile() {
        assertNull(Actions.jsonProfileError(new Json.Num("5"), 0));
        assertEquals("numbers must be safe integers (no floats, no -0)", Actions.jsonProfileError(new Json.Num("1.5"), 0));
        assertEquals("numbers must be safe integers (no floats, no -0)", Actions.jsonProfileError(new Json.Num("-0"), 0));
        assertNull(Actions.jsonProfileError(5L, 0));
        assertEquals("numbers must be safe integers (no floats, no -0)", Actions.jsonProfileError(1.5, 0));
        assertNull(Actions.jsonProfileError("x", 0));
        assertNull(Actions.jsonProfileError(list("x", true), 0));
        assertNull(Actions.jsonProfileError(m("a", "b", "c", list()), 0));
        assertEquals("numbers must be safe integers (no floats, no -0)", Actions.jsonProfileError(m("a", m("b", 1.5)), 0));
        assertEquals("only JSON values are allowed", Actions.jsonProfileError(new Object(), 0));
        assertEquals("not strict JSON: only JSON values are allowed", Actions.validateDef(new Object()));
        assertNull(Actions.jsonProfileError(list(), 32));
        assertEquals("nesting deeper than 32", Actions.jsonProfileError(list(), 33));
    }

    @Test
    void jsonDepthStartsAtZeroForTheDef() {
        for (int levels : new int[] {30, 31}) {
            Object nest = new ArrayList<Object>();
            for (int i = 1; i < levels; i++) nest = list(nest);
            Map<String, Object> d = def();
            d.put("params", m("x", m("type", "string", "default", nest)));
            if (levels == 30) assertNull(Actions.validateDef(d));
            else assertEquals("not strict JSON: nesting deeper than 32", Actions.validateDef(d));
        }
    }

    @Test
    void byteBoundsOnVerbAliasAndResourceType() {
        Map<String, Object> d = def();
        d.put("verb", dotted(128));
        assertNull(Actions.validateDef(d));
        d.put("verb", dotted(129));
        assertEquals("verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)", Actions.validateDef(d));

        d = def();
        d.put("aliases", list(dotted(128)));
        assertNull(Actions.validateDef(d));
        d.put("aliases", list(dotted(129)));
        assertEquals("aliases must be distinct verb-shaped names other than the verb", Actions.validateDef(d));

        d = def();
        d.put("resource", m("type", dotted(128), "id", "*", "scope", "one"));
        assertNull(Actions.validateDef(d));
        for (Object bad : new Object[] {dotted(129), "UPPER", 5L, "9x"}) {
            d.put("resource", m("type", bad, "id", "*", "scope", "one"));
            assertEquals("resource.type is malformed", Actions.validateDef(d));
        }
    }

    @Test
    void malformedDefReportsTheException() {
        Map<String, Object> d = new LinkedHashMap<String, Object>() {
            @Override public Object get(Object k) {
                if ("title".equals(k)) throw new IllegalStateException("boom");
                return super.get(k);
            }
        };
        d.putAll(def());
        assertEquals("malformed def: java.lang.IllegalStateException: boom", Actions.validateDef(d));
    }

    @Test
    void parentAndValueParamNames() {
        Map<String, Object> d = def();
        d.put("params", m("a", m("type", "string"), "a.b", m("type", "string")));
        assertEquals("param 'a' is both a value and the parent of 'a.b'", Actions.validateDef(d));
        d.put("params", m("a", m("type", "string"), "ab", m("type", "string"), "a_b.c", m("type", "string")));
        assertNull(Actions.validateDef(d));
    }

    @Test
    void examples() {
        String bad = "example must be {params, under?, expect}";
        for (String e : new String[] {"allow", "escalate", "deny"}) {
            Map<String, Object> d = def();
            d.put("examples", list(m("params", m(), "expect", e)));
            assertNull(Actions.validateDef(d));
        }
        Map<String, Object> d = def();
        d.put("examples", list(m("params", m(), "under", m(), "expect", "deny")));
        assertNull(Actions.validateDef(d));
        for (Object ex : new Object[] {m("params", m(), "expect", "maybe"), m("params", m(), "expect", 5L), m("params", m()), m("expect", "allow"),
            m("params", "x", "expect", "allow"), m("params", m(), "expect", "allow", "zzz", 1L), "x"}) {
            d = def();
            d.put("examples", list(ex));
            assertEquals(bad, Actions.validateDef(d));
        }
    }

    @Test
    void roleRequiresAnIntegerParameter() {
        assertEquals("x: role money.amount requires an integer parameter", withParam(m("type", "string", "role", "money.amount")));
        assertEquals("x: role money.fee requires an integer parameter", withParam(m("type", "duration", "role", "money.fee")));
        assertEquals("x: role bytes.size requires an integer parameter", withParam(m("type", "string", "role", "bytes.size")));
        assertNull(withParam(m("type", "integer", "role", "money.amount")));
        assertNull(withParam(m("type", "string", "role", "contact.email")));
        assertEquals("x: unknown role", withParam(m("type", "string", "role", 5L)));
    }

    @Test
    void minMaxNeedAnIntegerLikeParameter() {
        assertNull(withParam(m("type", "integer", "min", 1L, "max", 2L)));
        assertNull(withParam(m("type", "duration", "min", 1L)));
        assertNull(withParam(m("type", "array", "items", "integer", "min", 1L, "max", 9L)));
        String minMsg = "x: min must be a safe integer on an integer parameter";
        assertEquals(minMsg, withParam(m("type", "array", "items", "string", "min", 1L)));
        assertEquals(minMsg, withParam(m("type", "array", "min", 1L)));
        assertEquals(minMsg, withParam(m("type", "string", "min", 1L)));
        assertEquals("x: max must be a safe integer on an integer parameter", withParam(m("type", "integer", "max", "a")));
        assertEquals("x: max must be a safe integer on an integer parameter", withParam(m("type", "string", "max", 1L)));
    }

    @Test
    void minMaxItems() {
        assertNull(withParam(m("type", "array", "min_items", 0L, "max_items", 3L)));
        assertNull(withParam(m("type", "set", "values", list("a"), "max_items", 1L)));
        assertEquals("x: min_items must be a non-negative integer on a set or array", withParam(m("type", "string", "min_items", 0L)));
        assertEquals("x: max_items must be a non-negative integer on a set or array", withParam(m("type", "array", "max_items", -1L)));
    }

    /** A list whose stream() must never run: a tag list longer than the known tag count is refused before it is scanned. */
    static final class NoStream extends ArrayList<Object> {
        @Override public Stream<Object> stream() { throw new AssertionError("an over-long tag list must be refused by its size"); }
    }

    @Test
    void tags() {
        String bad = "x: tags must be distinct known tags";
        assertNull(withParam(m("type", "string", "tags", list("pii"))));
        assertNull(withParam(m("type", "string", "tags", list("pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"))));
        assertEquals(bad, withParam(m("type", "string", "tags", list("pii", "pii"))));
        assertEquals(bad, withParam(m("type", "string", "tags", list("zzz"))));
        assertEquals(bad, withParam(m("type", "string", "tags", "pii")));
        NoStream tooMany = new NoStream();
        for (int i = 0; i < 10; i++) tooMany.add("pii");
        assertEquals(bad, withParam(m("type", "string", "tags", tooMany)));
    }

    // ---- registry, closure --------------------------------------------------------------------------------------------------

    static Map<String, Object> floor() {
        return m("risk", 0L, "rev", "reversible", "blast_ppm", 0L, "esc", 0L, "caveats", list(), "context", list(), "prules", list());
    }

    static Map<String, Object> trait(String id, Object implies) { return m("id", id, "implies", implies, "floor", floor(), "card_phrase", "phrase"); }

    @Test
    void registryImpliesAndCycle() {
        assertNull(Actions.registryError(list(trait("x.one", list())), false));
        assertEquals("trait 'x.one': implies must be up to 8 distinct trait ids", Actions.registryError(list(trait("x.one", list(5L))), false));
        assertEquals("trait 'x.one': implies must be up to 8 distinct trait ids", Actions.registryError(list(trait("x.one", "x.two")), false));
        assertEquals("trait 'x.one': implies must be up to 8 distinct trait ids", Actions.registryError(list(trait("x.one", list("x.one", "x.one"))), false));
        assertNull(Actions.registryError(list(trait("x.a", list("x.b")), trait("x.b", list())), false));
        assertEquals("trait 'x.a': implies cycle", Actions.registryError(list(trait("x.a", list("x.b")), trait("x.b", list("x.a"))), false));
    }

    @Test
    void extendRegistry() {
        Actions.Registry core = Actions.CORE_REGISTRY;
        Actions.Registry ext = Actions.extendRegistry(core, list(trait("x.one", list())));
        assertTrue(ext.traits.containsKey("x.one"));
        assertTrue(ext.traits.keySet().containsAll(core.traits.keySet()));
        String coreId = core.traits.keySet().iterator().next();

        Object[][] cases = {
            {core, trait("pca.zz_not_core", list()), "pca.zz_not_core"},
            {core, trait(coreId, list()), coreId},
            {ext, trait("x.one", list()), "x.one"},
            {core, "x", "undefined"},
            {core, m("implies", list()), "undefined"},
            {core, m("id", 5L), "5"},
        };
        for (Object[] c : cases) {
            List<Object> custom = list(c[1]);
            Actions.ActionKitError e = assertThrows(Actions.ActionKitError.class, () -> Actions.extendRegistry((Actions.Registry) c[0], custom));
            assertEquals("bad_registry", e.code);
            assertEquals("custom trait '" + c[2] + "' may not redefine a core trait", e.getMessage());
        }
    }

    static final class CountToArray extends ArrayList<String> {
        int n;
        CountToArray(String... xs) { super(Arrays.asList(xs)); }
        @Override public Object[] toArray() { n++; return super.toArray(); }
    }

    static Actions.Trait tr(String id, List<String> implies) { return new Actions.Trait(id, implies, Actions.Profile.BOTTOM, "p"); }

    @Test
    void closureExpandsEachTraitOnce() {
        CountToArray dImplies = new CountToArray();
        Map<String, Actions.Trait> ts = new LinkedHashMap<>();
        ts.put("a", tr("a", new ArrayList<>(List.of("b", "c"))));
        ts.put("b", tr("b", new ArrayList<>(List.of("d"))));
        ts.put("c", tr("c", new ArrayList<>(List.of("d"))));
        ts.put("d", tr("d", dImplies));
        Actions.Registry reg = new Actions.Registry(ts);
        assertEquals(List.of("a", "b", "c", "d"), Actions.closure(reg, list("a")));
        assertEquals(1, dImplies.n);
        assertEquals(List.of("b", "d"), Actions.closure(reg, list("b", "d", "b")));

        Actions.ActionKitError e = assertThrows(Actions.ActionKitError.class, () -> Actions.closure(reg, list("zzz")));
        assertEquals("unknown_trait", e.code);
        assertEquals("unknown trait 'zzz'", e.getMessage());
        // a non-string id after a known one: the seen-set (a TreeSet of strings) must never be probed with it
        e = assertThrows(Actions.ActionKitError.class, () -> Actions.closure(reg, Arrays.<Object>asList(5, "a")));
        assertEquals("unknown_trait", e.code);
        assertEquals("unknown trait '5'", e.getMessage());
        e = assertThrows(Actions.ActionKitError.class, () -> Actions.closure(reg, Arrays.<Object>asList((Object) null)));
        assertEquals("unknown trait 'null'", e.getMessage());
    }

    static final class CountIter extends ArrayList<Object> {
        int n;
        CountIter(Object... xs) { super(Arrays.asList(xs)); }
        @Override public Iterator<Object> iterator() { n++; return super.iterator(); }
    }

    @SuppressWarnings("unchecked")
    static int walk(Map<String, Map<String, Object>> by, String id, Map<String, Integer> depth, java.util.Set<String> visiting) throws Exception {
        Method w = Actions.class.getDeclaredMethod("walk", Map.class, String.class, Map.class, java.util.Set.class);
        w.setAccessible(true);
        return (Integer) w.invoke(null, by, id, depth, visiting);
    }

    @Test
    void walkMemoisesAndClearsVisiting() throws Exception {
        CountIter dImplies = new CountIter();
        Map<String, Map<String, Object>> by = new LinkedHashMap<>();
        by.put("a", m("implies", list("b", "c")));
        by.put("b", m("implies", list("d")));
        by.put("c", m("implies", list("d")));
        by.put("d", m("implies", dImplies));
        Map<String, Integer> depth = new LinkedHashMap<>();
        java.util.Set<String> visiting = new HashSet<>();
        assertEquals(3, walk(by, "a", depth, visiting));
        assertEquals(Map.of("a", 3, "b", 2, "c", 2, "d", 1), depth);
        assertTrue(visiting.isEmpty());
        assertEquals(1, dImplies.n);

        // a recorded depth is returned as is, without descending
        Map<String, Integer> seeded = new LinkedHashMap<>();
        seeded.put("d", 5);
        assertEquals(5, walk(by, "d", seeded, new HashSet<>()));
        assertEquals(1, dImplies.n);

        Map<String, Map<String, Object>> cyc = new LinkedHashMap<>();
        cyc.put("a", m("implies", list("b")));
        cyc.put("b", m("implies", list("a")));
        assertEquals(-1, walk(cyc, "a", new LinkedHashMap<>(), new HashSet<>()));
    }

    // ---- profile algebra ----------------------------------------------------------------------------------------------------

    static Actions.Profile prof(List<String> cav, List<String> ctx, List<String> pr) { return new Actions.Profile(1, "rate_limited", 10, 1, cav, ctx, pr); }

    @Test
    void leqChecksEachSet() {
        List<String> cav = List.of("amount_cap"), ctx = List.of("approval_ref"), pr = List.of("pay_has_idempotency");
        Actions.Profile p = prof(cav, ctx, pr);
        assertTrue(p.leq(prof(cav, ctx, pr)));
        assertTrue(p.leq(prof(List.of("amount_cap", "count_cap"), List.of("approval_ref", "idempotency"), List.of("pay_has_idempotency", "secret_not_logged"))));
        assertTrue(Actions.Profile.BOTTOM.leq(p));
        assertFalse(p.leq(prof(List.of(), ctx, pr)));
        assertFalse(p.leq(prof(cav, List.of(), pr)));
        assertFalse(p.leq(prof(cav, ctx, List.of())));
        assertFalse(p.leq(Actions.Profile.BOTTOM));
    }

    @Test
    void fromMapNamesTheMissingMember() {
        for (String k : new String[] {"risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules"}) {
            Map<String, Object> f = floor();
            f.remove(k);
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Actions.Profile.fromMap(f));
            assertEquals("profile member missing: " + k, e.getMessage());
        }
        Actions.Profile ok = Actions.Profile.fromMap(floor());
        assertEquals("reversible", ok.rev);
    }

    @Test
    void joinTakesTheWorstReversibility() {
        Actions.Profile a = new Actions.Profile(0, "reversible", 5, 0, List.of(), List.of(), List.of());
        Actions.Profile b = new Actions.Profile(2, "irreversible", 3, 1, List.of("amount_cap"), List.of(), List.of());
        assertEquals("irreversible", a.join(b).rev);
        assertEquals("irreversible", b.join(a).rev);
        assertEquals("rate_limited", prof(List.of(), List.of(), List.of()).join(a).rev);
        assertEquals(5, a.join(b).blastPpm);
        assertEquals(2, a.join(b).risk);
        assertEquals(List.of("amount_cap"), a.join(b).caveats);
    }
}
