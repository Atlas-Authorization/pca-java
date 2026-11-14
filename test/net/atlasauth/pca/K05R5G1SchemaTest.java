package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for {@link ActionSchema} (reference packages/pca/src/action-schema.ts): the parameter declaration rules
 * per type (min/max, unit, items, tags, v2 members), the v2 parent/child parameter rule, the verb member lists, reversibility_by,
 * and the immutable / sorted Map shapes a Java caller can hand in (a lookup of a null key or of a foreign-typed key must not
 * crash a rule into a different refusal). Each case asserts the refusal text or that the schema is accepted.
 */
public class K05R5G1SchemaTest {
    static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    static final String DEF = Keys.b64u(new byte[32]);
    static final String P = "action.params.p";

    static Map<String, Object> decl(String type, Object... kv) {
        Map<String, Object> d = map("type", type, "semantic", "s", "sensitivity", "free");
        for (int i = 0; i < kv.length; i += 2) d.put((String) kv[i], kv[i + 1]);
        return d;
    }

    static Map<String, Object> floors() {
        return map("risk", 0L, "esc", 0L, "rev", "reversible", "blast_ppm", 0L, "caveats", list(), "context", list(), "prules", list());
    }

    static Map<String, Object> verb1(Map<String, Object> params) {
        return map("verb", "pay", "kind", "write", "params", params);
    }

    static Map<String, Object> verb2(Map<String, Object> params) {
        return map("verb", "pay", "kind", "write", "params", params, "effects", list("pay"), "traits", list(), "def", DEF, "floors", floors());
    }

    static Map<String, Object> doc(long v, Map<String, Object> verb) {
        return map("v", v, "kind", "pca-action-schema", "site", "https://s.example", "aud", "aud", "version", "1", "verbs", list(verb));
    }

    static String shape(long v, Map<String, Object> params) {
        return ActionSchema.shapeError(doc(v, v == 2 ? verb2(params) : verb1(params)), false);
    }

    static String one(long v, Map<String, Object> d) { return shape(v, map(P, d)); }

    static void refused(String contains, String got) {
        assertNotNull(got, "expected a refusal containing " + contains);
        assertTrue(got.contains(contains), "refusal <" + got + "> lacks <" + contains + ">");
        assertFalse(got.startsWith("malformed schema"), got);
    }

    // ---- baseline ----

    @Test void baselinesAreAccepted() {
        assertNull(one(1, decl("integer")));
        assertNull(one(2, decl("string")));
        assertNull(shape(1, map()));
    }

    @Test void reservedAndMalformedPaths() {
        refused("is not action.params.<name>", shape(1, map("action.params.a b", decl("string"))));
        refused("is reserved", shape(1, map("action.params.constructor", decl("string"))));
        refused("is reserved", shape(2, map("action.params.a.__proto__", decl("string"))));
        assertNull(shape(2, map("action.params.a.b.c", decl("string"))));
    }

    // ---- min / max ----

    @Test void minMaxApplyToIntegerDurationAndIntegerArrays() {
        assertNull(one(1, decl("integer", "min", 1L, "max", 5L)));
        assertNull(one(1, decl("integer", "min", 5L, "max", 5L)));
        refused("min must be a safe integer", one(1, decl("integer", "min", "x")));
        refused("max must be a safe integer", one(1, decl("integer", "max", 1.5)));
        refused("min must be a safe integer", one(1, decl("string", "min", 1L)));
        refused("max must be a safe integer", one(1, decl("boolean", "max", 1L)));
        refused("min > max", one(1, decl("integer", "min", 6L, "max", 5L)));
        assertNull(one(1, decl("array", "items", "integer", "min", 1L, "max", 2L)));
        refused("min must be a safe integer", one(1, decl("array", "items", "string", "min", 1L)));
        refused("min must be a safe integer", one(1, decl("array", "min", 1L)));
        assertNull(one(2, decl("duration", "min", 1L, "max", 9L)));
        refused("min must be a safe integer", one(2, decl("duration", "min", "x")));
        refused("max must be a safe integer", one(2, decl("datetime", "max", 1L)));
    }

    // ---- unit ----

    static Map<String, Object> docWithUnits(Object units, Map<String, Object> d) {
        Map<String, Object> dc = doc(1, verb1(map(P, d)));
        if (units != null) dc.put("units", units);
        return dc;
    }

    @Test void unitMustNameADeclaredUnitOfAnIntegerParameter() {
        Map<String, Object> units = map("usd", map("kind", "money"));
        assertNull(ActionSchema.shapeError(docWithUnits(units, decl("integer", "unit", "usd")), false));
        refused("unit must name a declared unit", ActionSchema.shapeError(docWithUnits(units, decl("integer", "unit", "eur")), false));
        refused("unit must name a declared unit", ActionSchema.shapeError(docWithUnits(units, decl("string", "unit", "usd")), false));
        refused("unit must name a declared unit", ActionSchema.shapeError(docWithUnits(units, decl("integer", "unit", 5L)), false));
        refused("unit must name a declared unit", ActionSchema.shapeError(docWithUnits(null, decl("integer", "unit", "usd")), false));
        // a sorted map of units answers a foreign-typed key lookup with a ClassCastException: the rule itself must refuse
        Map<String, Object> sorted = new TreeMap<>(units);
        refused("unit must name a declared unit", ActionSchema.shapeError(docWithUnits(sorted, decl("integer", "unit", 5L)), false));
        assertNull(ActionSchema.shapeError(docWithUnits(sorted, decl("integer", "unit", "usd")), false));
    }

    @Test void unitDeclarationShapes() {
        refused("must be an object with a kind", ActionSchema.shapeError(docWithUnits(map("usd", "x"), decl("integer")), false));
        refused("must be an object with a kind", ActionSchema.shapeError(docWithUnits(map("usd", map("currency", "USD")), decl("integer")), false));
        refused("must be an object with a kind", ActionSchema.shapeError(docWithUnits(map("usd", null), decl("integer")), false));
        assertNull(ActionSchema.shapeError(docWithUnits(map("usd", map("kind", "money", "currency", "USD", "exponent", 2L)), decl("integer")), false));
    }

    // ---- sorted maps (a null key lookup throws) ----

    @Test void declarationLookupsNeverProbeANullKey() {
        assertNull(one(1, new TreeMap<>(decl("integer", "min", 1L, "max", 2L))));
        assertNull(one(1, new TreeMap<>(decl("array", "min_items", 1L, "max_items", 2L))));
        assertNull(one(2, new TreeMap<>(decl("set", "values", list("a", "b"), "min_items", 0L))));
        refused("min_items must be a non-negative safe integer", one(1, new TreeMap<>(decl("array", "min_items", -1L))));
        refused("max_items must be a non-negative safe integer", one(1, decl("string", "max_items", 1L)));
        refused("min_items > max_items", one(1, decl("array", "min_items", 3L, "max_items", 2L)));
    }

    @Test void verbLookupsNeverProbeANullKey() {
        Map<String, Object> v1 = new TreeMap<>(verb1(map(P, decl("string"))));
        assertNull(ActionSchema.shapeError(doc(1, v1), false));
        v1.put("harm", "x");
        refused("harm must be an object", ActionSchema.shapeError(doc(1, v1), false));
        Map<String, Object> v1b = new TreeMap<>(verb1(map(P, decl("string"))));
        v1b.put("effects", "x");
        refused("effects must be an object", ActionSchema.shapeError(doc(1, v1b), false));
        Map<String, Object> v1c = new TreeMap<>(verb1(map(P, decl("string"))));
        v1c.put("returns", "x");
        refused("returns must be an object", ActionSchema.shapeError(doc(1, v1c), false));
        Map<String, Object> v2 = new TreeMap<>(verb2(map(P, decl("string"))));
        assertNull(ActionSchema.shapeError(doc(2, v2), false));
        v2.put("returns", "x");
        refused("returns must be an object", ActionSchema.shapeError(doc(2, v2), false));
        Map<String, Object> v2b = new TreeMap<>(verb2(map(P, decl("string"))));
        v2b.put("harm", "x");
        refused("harm must be an object", ActionSchema.shapeError(doc(2, v2b), false));
        // v2 has no `effects` object rule: the list of effects is its own member
        Map<String, Object> v2c = verb2(map(P, decl("string")));
        v2c.put("effects", map());
        refused("effects must be 1..", ActionSchema.shapeError(doc(2, v2c), false));
    }

    // ---- v2 members ----

    static final class Poison extends AbstractList<Object> {
        @Override public int size() { return 10; }
        @Override public Object get(int i) { throw new AssertionError("an oversize list was iterated"); }
    }

    @Test void tagsMustBeDistinctKnownTagsWithinTheCap() {
        assertNull(one(2, decl("string", "tags", list("pii", "secret"))));
        assertNull(one(2, decl("string", "tags", list())));
        assertNull(one(2, decl("string", "tags", list("pii", "phi", "pci", "secret", "credential", "free_text_outbound", "code", "path", "sql"))));
        refused("tags must be distinct known tags", one(2, decl("string", "tags", list("nope"))));
        refused("tags must be distinct known tags", one(2, decl("string", "tags", list("pii", "pii"))));
        refused("tags must be distinct known tags", one(2, decl("string", "tags", list(5L))));
        refused("tags must be distinct known tags", one(2, decl("string", "tags", "pii")));
        // 10 entries exceed the 9 known tags: refused from the length alone, without walking the list
        refused("tags must be distinct known tags", one(2, decl("string", "tags", new Poison())));
    }

    @Test void v2OnlyMembersAreCheckedInV2() {
        refused("role must be a non-empty string", one(2, decl("string", "role", "")));
        assertNull(one(2, decl("string", "role", "owner")));
        refused("format must be a known format", one(2, decl("string", "format", "bogus_fmt")));
        refused("format must be a known format", one(2, decl("integer", "format", "email")));
        refused("format must be a known format", one(2, decl("string", "format", 5L)));
        assertNull(one(2, decl("string", "format", "email")));
        assertNull(one(2, decl("object_ref", "format", "id:user")));
        refused("unknown provenance_min", one(2, decl("string", "provenance_min", "bogus")));
        assertNull(one(2, decl("string", "provenance_min", "tool")));
        // none of them is a v1 member
        refused("unknown member 'role'", one(1, decl("string", "role", "owner")));
        refused("unknown member 'tags'", one(1, decl("string", "tags", list())));
        refused("unknown type", one(1, decl("duration")));
    }

    @Test void v2DocumentMembers() {
        Map<String, Object> d = doc(2, verb2(map()));
        d.put("traits_digest", "not-a-digest");
        refused("traits_digest must be a canonical base64url", ActionSchema.shapeError(d, false));
        Map<String, Object> e = doc(2, verb2(map()));
        e.put("traits_digest", DEF);
        e.put("trait_defs", list("x"));
        refused("trait_defs must be an array", ActionSchema.shapeError(e, false));
        Map<String, Object> f = doc(2, verb2(map()));
        f.put("pack", map("ns", "n", "version", "1"));
        refused("pack must be {ns, version, root}", ActionSchema.shapeError(f, false));
        Map<String, Object> g = doc(2, verb2(map()));
        g.put("traits_digest", DEF);
        g.put("trait_defs", list(map("x", 1L)));
        g.put("pack", map("ns", "n", "version", "1", "root", DEF));
        assertNull(ActionSchema.shapeError(g, false));
        Map<String, Object> h = doc(1, verb1(map()));
        h.put("traits_digest", DEF);
        refused("unknown member 'traits_digest'", ActionSchema.shapeError(h, false));
    }

    // ---- verb member lists ----

    @Test void verbMembersFollowTheSchemaVersion() {
        Map<String, Object> v1 = verb1(map());
        v1.put("traits", list());
        refused("unknown member 'traits'", ActionSchema.shapeError(doc(1, v1), false));
        Map<String, Object> v1b = verb1(map());
        v1b.put("floors", floors());
        refused("unknown member 'floors'", ActionSchema.shapeError(doc(1, v1b), false));
        Map<String, Object> v2 = verb2(map());
        v2.put("zzz", 1L);
        refused("unknown member 'zzz'", ActionSchema.shapeError(doc(2, v2), false));
        assertNull(ActionSchema.shapeError(doc(2, verb2(map())), false));
        // v1 keeps the effects object, v2 replaced it with the effect list
        Map<String, Object> v1c = verb1(map());
        v1c.put("effects", map());
        assertNull(ActionSchema.shapeError(doc(1, v1c), false));
    }

    @Test void aParameterIsNeverBothAValueAndTheParentOfAnother() {
        refused("is both a value and the parent of", shape(2, map("action.params.a", decl("string"), "action.params.a.b", decl("string"))));
        refused("is both a value and the parent of", shape(2, map("action.params.a.b", decl("string"), "action.params.a", decl("string"))));
        assertNull(shape(2, map("action.params.a", decl("string"), "action.params.b", decl("string"))));
        assertNull(shape(2, map("action.params.a", decl("string"), "action.params.ab", decl("string"))));
        assertNull(shape(2, map("action.params.a.x", decl("string"), "action.params.a.y", decl("string"))));
        assertNull(shape(1, map("action.params.a", decl("string"), "action.params.ab", decl("string"))));
    }

    // ---- reversibility_by ----

    static String revBy(Object rb, boolean sorted) {
        Map<String, Object> params = map(P, decl("string"));
        if (sorted) params = new TreeMap<>(params);
        Map<String, Object> verb = verb1(params);
        verb.put("reversibility_by", rb);
        return ActionSchema.shapeError(doc(1, verb), false);
    }

    @Test void reversibilityByNamesADeclaredParameterAndMapsToClasses() {
        for (boolean sorted : new boolean[] {false, true}) {
            assertNull(revBy(map("param", P, "map", map("x", "reversible")), sorted));
            assertNull(revBy(map("param", P, "map", map("x", "irreversible", "y", "rate_limited"), "default", "reversible"), sorted));
            refused("reversibility_by.param must be a declared parameter", revBy(map("param", "action.params.q", "map", map("x", "reversible")), sorted));
            refused("reversibility_by.param must be a declared parameter", revBy(map("param", 5L, "map", map("x", "reversible")), sorted));
            refused("reversibility_by.param must be a declared parameter", revBy(map("param", null, "map", map("x", "reversible")), sorted));
            refused("reversibility_by.map must map values", revBy(map("param", P, "map", map()), sorted));
            refused("reversibility_by.map must map values", revBy(map("param", P, "map", map("x", "bogus")), sorted));
            refused("reversibility_by.default is not a reversibility class", revBy(map("param", P, "map", map("x", "reversible"), "default", "bogus"), sorted));
            refused("reversibility_by must be {param, map, default?}", revBy(map("param", P, "map", map("x", "reversible"), "extra", 1L), sorted));
            refused("reversibility_by must be {param, map, default?}", revBy("x", sorted));
        }
    }
}
