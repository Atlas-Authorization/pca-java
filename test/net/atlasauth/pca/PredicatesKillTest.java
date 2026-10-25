package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Mutation kills for the predicate evaluator ({@code layers} ceilings) and the linear-time regex engine and guard. */
public class PredicatesKillTest {
    static Map<String, Object> map(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }
    @SafeVarargs static <T> List<Object> list(T... xs) { return new ArrayList<>(Arrays.asList(xs)); }
    static Json.Num n(String s) { return new Json.Num(s); }

    static Map<String, Object> ctx() {
        return map("action", map("verb", "air.book", "resource", "skyair.example/bookings/7", "params",
            map("total", n("38900"), "name", "Ana", "tags", list("a", "b"), "nested", map("x", n("1")), "astral", "😀")),
            "env", map("canon", map("add_ons", "[\"none\"]"), "groups", map("ana", "staff", "staff", list("emp")), "cur", "dev1"));
    }
    static Predicates.Tri leaf(String field, String op, Object value) { return Predicates.evaluateConditionTri(map("field", field, "op", op, "value", value), ctx()); }
    static final Predicates.Tri T = Predicates.Tri.TRUE, F = Predicates.Tri.FALSE, U = Predicates.Tri.UNKNOWN;

    @Test void comparisons() {
        assertEquals(T, leaf("action.params.total", "eq", n("38900")));
        assertEquals(T, leaf("action.params.total", "eq", n("38900.0")));
        assertEquals(F, leaf("action.params.total", "eq", "38900"));
        assertEquals(T, leaf("action.params.total", "ne", "38900"));
        assertEquals(T, leaf("action.params.total", "lte", n("38900")));
        assertEquals(F, leaf("action.params.total", "lt", n("38900")));
        assertEquals(T, leaf("action.params.total", "gte", n("38900")));
        assertEquals(F, leaf("action.params.total", "gt", n("38900")));
        assertEquals(U, leaf("action.params.total", "lt", "x"));
        assertEquals(T, leaf("action.params.name", "lt", "Bob"));
        // UTF-8 byte order: U+1F600 sorts after U+FFFF (UTF-16 order would put it before)
        assertEquals(T, leaf("action.params.astral", "gt", "￿"));
        assertEquals(T, leaf("action.params.tags", "eq", list("a", "b")));
        assertEquals(F, leaf("action.params.tags", "eq", list("b", "a")));
        assertEquals(T, leaf("action.params.nested", "eq", map("x", n("1.0"))));
        assertEquals(T, leaf("action.params.name", "in", list("x", "Ana")));
        assertEquals(F, leaf("action.params.name", "nin", list("x", "Ana")));
        assertEquals(U, leaf("action.params.name", "in", "Ana"));
        assertEquals(T, leaf("action.params.name", "prefix", "An"));
        assertEquals(U, leaf("action.params.total", "prefix", "3"));
        assertEquals(U, leaf("action.params.name", "nope", "x"));
        assertEquals(T, leaf("env.canon.add_ons", "eq", "[\"none\"]"));
    }

    @Test void existsRefsAndParams() {
        assertEquals(T, leaf("action.params.name", "exists", true));
        assertEquals(F, leaf("action.params.missing", "exists", true));
        assertEquals(T, leaf("action.params.missing", "exists", false));
        assertEquals(U, leaf("action.params.missing", "eq", "x"));
        assertEquals(T, Predicates.evaluateConditionTri(map("field", "action.params.name", "op", "exists"), ctx()));
        // a value-less leaf is unknown (operand missing); a ref resolves the operand
        assertEquals(U, Predicates.evaluateConditionTri(map("field", "action.params.name", "op", "eq"), ctx()));
        assertEquals(F, Predicates.evaluateConditionTri(map("field", "action.params.name", "op", "eq", "ref", "env.cur"), ctx()));
        assertEquals(U, Predicates.evaluateConditionTri(map("field", "action.params.name", "op", "eq", "ref", "env.none"), ctx()));
        // params unavailable: a params-rooted condition (even exists:false) is unknown
        Map<String, Object> noParams = map("action", map("verb", "v", "resource", "r"));
        assertEquals(U, Predicates.evaluateConditionTri(map("field", "action.params.x", "op", "exists", "value", false), noParams));
        assertEquals(T, Predicates.evaluateConditionTri(map("field", "action.verb", "op", "eq", "value", "v"), noParams));
        // forbidden segments and array indices
        assertEquals(F, leaf("action.params.__proto__", "exists", true));
        assertEquals(T, leaf("action.params.tags.1", "eq", "b"));
        assertEquals(U, leaf("action.params.tags.2", "eq", "b"));
        assertEquals(U, leaf("action.params.tags.01", "eq", "b"));
        assertFalse(Predicates.resolvePath(ctx(), "subject.x").found);
        assertFalse(Predicates.resolvePath(ctx(), "other.x").found);
        assertFalse(Predicates.resolvePath(ctx(), "").found);
    }

    @Test void groups() {
        Map<String, Object> t = map("field", "action.verb", "op", "eq", "value", "air.book");
        Map<String, Object> f = map("field", "action.verb", "op", "eq", "value", "x");
        Map<String, Object> u = map("field", "action.params.zz", "op", "eq", "value", "x");
        assertEquals(T, Predicates.evaluateConditionTri(map("all_of", list(t, t)), ctx()));
        assertEquals(F, Predicates.evaluateConditionTri(map("all_of", list(u, f)), ctx()));
        assertEquals(U, Predicates.evaluateConditionTri(map("all_of", list(t, u)), ctx()));
        assertEquals(U, Predicates.evaluateConditionTri(map("all_of", list()), ctx()));
        assertEquals(T, Predicates.evaluateConditionTri(map("any_of", list(u, t)), ctx()));
        assertEquals(U, Predicates.evaluateConditionTri(map("any_of", list(u, f)), ctx()));
        assertEquals(F, Predicates.evaluateConditionTri(map("any_of", list(f, f)), ctx()));
        assertEquals(F, Predicates.evaluateConditionTri(map("not", t), ctx()));
        assertEquals(T, Predicates.evaluateConditionTri(map("not", f), ctx()));
        assertEquals(U, Predicates.evaluateConditionTri(map("not", u), ctx()));
        assertEquals(U, Predicates.evaluateConditionTri(list(t), ctx()));
        // all_of wins over any_of when both are present
        assertEquals(F, Predicates.evaluateConditionTri(map("all_of", list(f), "any_of", list(t)), ctx()));
    }

    @Test void likeIsATypeAndMembership() {
        assertEquals(T, leaf("action.params.name", "like", "A*"));
        assertEquals(T, leaf("action.params.name", "like", "A?a"));
        assertEquals(F, leaf("action.params.name", "like", "A?"));
        assertEquals(T, leaf("action.params.name", "like", "*n*"));
        assertEquals(T, leaf("action.params.name", "like", "A\\na"));
        assertEquals(U, leaf("action.params.name", "like", "A\\"));
        assertEquals(U, leaf("action.params.name", "like", "x".repeat(513)));
        assertEquals(T, leaf("action.params.name", "like", "*".repeat(512)));
        assertEquals(T, Predicates.evaluateConditionTri(map("field", "action.params.name", "op", "is_a", "value", "Ana"), ctx()));
        assertEquals(U, Predicates.evaluateConditionTri(map("field", "action.params.total", "op", "is_a", "value", "x"), ctx()));
        Map<String, Object> c = ctx();
        ((Map<String, Object>) c.get("env")).put("obj", map("type", "Doc::pdf", "tags", list("x")));
        assertEquals(T, Predicates.evaluateConditionTri(map("field", "env.obj", "op", "is_a", "value", "Doc"), c));
        assertEquals(T, Predicates.evaluateConditionTri(map("field", "env.obj", "op", "is_a", "value", "x"), c));
        assertEquals(F, Predicates.evaluateConditionTri(map("field", "env.obj", "op", "is_a", "value", "Do"), c));
        assertEquals(T, Predicates.evaluateConditionTri(map("field", "action.params.name", "op", "member_of", "value", "emp", "collection", "env.groups"), map("action",
            map("verb", "v", "resource", "r", "params", map("name", "ana")), "env", map("groups", map("ana", "staff", "staff", list("emp"))))));
        assertEquals(U, Predicates.evaluateConditionTri(map("field", "action.params.name", "op", "member_of", "value", "emp"), ctx()));
        assertEquals(U, Predicates.evaluateConditionTri(map("field", "action.params.name", "op", "member_of", "value", list(), "collection", "env.groups"), ctx()));
    }

    @Test void predicatesAndResources() {
        Map<String, Object> c = ctx();
        assertTrue(Predicates.evaluatePredicates(list(map("verb", "air.book")), c));
        assertTrue(Predicates.evaluatePredicates(list(map("verb", "*")), c));
        assertTrue(Predicates.evaluatePredicates(list(map("verb", list("x", "air.book"))), c));
        assertFalse(Predicates.evaluatePredicates(list(map("verb", "x")), c));
        assertFalse(Predicates.evaluatePredicates(list(), c));
        assertFalse(Predicates.evaluatePredicates(map("verb", "*"), c));
        assertTrue(Predicates.evaluatePredicates(list(map("verb", "*", "resource", "skyair.example/*")), c));
        assertFalse(Predicates.evaluatePredicates(list(map("verb", "*", "resource", "skyair.example/x*")), c));
        assertTrue(Predicates.evaluatePredicates(list(map("verb", "*", "resource", "skyair.example/bookings/7")), c));
        assertFalse(Predicates.evaluatePredicates(list(map("verb", "*", "resource", null)), c));
        assertTrue(Predicates.evaluatePredicates(list(map("verb", "*", "resource", "re:skyair\\.example/bookings/\\d+")), c));
        assertFalse(Predicates.evaluatePredicates(list(map("verb", "*", "resource", "re:skyair")), c)); // full match only
        assertFalse(Predicates.evaluatePredicates(list(map("verb", "*", "resource", "re:(a+)+")), c));
        assertFalse(Predicates.evaluatePredicates(list(map("verb", "*", "where", "x")), c));
        assertTrue(Predicates.evaluatePredicates(list(map("verb", "x"), map("verb", "air.book", "where", list())), c));
    }

    @Test void regexGuard() {
        assertTrue(SafeRegex.isSafeSource("/acct/[^/]+/items/\\d+"));
        assertTrue(SafeRegex.isSafeSource("(?:GET|POST) /x"));
        assertFalse(SafeRegex.isSafeSource("(a+)+"));
        assertFalse(SafeRegex.isSafeSource("(a|aa)+"));
        assertFalse(SafeRegex.isSafeSource("(a)\\1"));
        assertFalse(SafeRegex.isSafeSource("(?=a)"));
        assertFalse(SafeRegex.isSafeSource("a{65}"));
        assertTrue(SafeRegex.isSafeSource("a{64}"));
        assertFalse(SafeRegex.isSafeSource("a{2,1}"));
        assertFalse(SafeRegex.isSafeSource("a{"));
        assertFalse(SafeRegex.isSafeSource("*a"));
        assertFalse(SafeRegex.isSafeSource("a**"));
        assertTrue(SafeRegex.isSafeSource("a*b*"));
        assertFalse(SafeRegex.isSafeSource("a*b*c*")); // 24 bits > 22
        assertFalse(SafeRegex.isSafeSource("[^](a+)+]")); // JS class semantics: [^] ends at the first ]
        // the cost budget: 22 one-bit choices pass, 23 fail
        assertTrue(SafeRegex.isSafeSource("a?".repeat(22)));
        assertFalse(SafeRegex.isSafeSource("a?".repeat(23)));
        // {m,n}: ceil(log2(n-m+1)) bits
        assertEquals(6, SafeRegex.ceilLog2(64));
        assertEquals(7, SafeRegex.ceilLog2(65));
        assertEquals(1, SafeRegex.ceilLog2(2));
        assertEquals(2, SafeRegex.ceilLog2(3));
        assertFalse(SafeRegex.isSafeSource("(a"));
        assertFalse(SafeRegex.isSafeSource("a)"));
        assertFalse(SafeRegex.isSafeSource("[a"));
        assertFalse(SafeRegex.isSafeSource("\\"));
        assertFalse(SafeRegex.isSafeSource("\\b"));
        assertFalse(SafeRegex.isSafeSource("\\q"));
    }

    @Test void regexEngine() {
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("a|b", "b"));
        assertEquals(Boolean.FALSE, SafeRegex.fullMatch("a|b", "ab"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("[]|x", "x"));
        assertEquals(Boolean.FALSE, SafeRegex.fullMatch("[]", ""));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("[^]", "\n"));
        assertEquals(Boolean.FALSE, SafeRegex.fullMatch(".", "\n"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch(".", "\u0085"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("\\d{2,3}", "123"));
        assertEquals(Boolean.FALSE, SafeRegex.fullMatch("\\d{2,3}", "1234"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("[\\w-]+", "a-b_9"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("[a\\-z]+", "-az"));
        assertEquals(Boolean.FALSE, SafeRegex.fullMatch("[a-c]", "d"));
        assertNull(SafeRegex.fullMatch("[c-a]", "b"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("\\x41\\u0042\\cJ", "AB\n"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("[\\b]", "\b"));
        assertNull(SafeRegex.fullMatch("\\01", "x"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("\\0", "\0"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("^a$", "a"));
        assertNull(SafeRegex.fullMatch("^*", "a"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("a{0}b", "b"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("a+?", "aaa"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("\\s", "　"));
        assertEquals(Boolean.FALSE, SafeRegex.fullMatch("\\S", "　"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("\\.", "."));
        // UTF-16 code units: an astral character is two units
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("..", "😀"));
        // the step cap: |program| x (|subject| + 1) > 2,000,000 is refused
        SafeRegex.Compiled c = SafeRegex.compile("a*");
        int n = (int) (SafeRegex.MAX_MATCH_STEPS / c.size());
        assertNotNull(SafeRegex.run(c, "a".repeat(n - 1)));
        assertNull(SafeRegex.run(c, "a".repeat(n)));
    }

    @Test void documentBudget() {
        // 64 matches evaluations per document; the 65th (and everything after it) is unknown
        List<Object> where = new ArrayList<>();
        for (int i = 0; i < 64; i++) where.add(map("field", "action.params.name", "op", "matches", "value", "A.a"));
        assertTrue(Predicates.evaluatePredicates(list(map("verb", "*", "where", where)), ctx()));
        where.add(map("field", "action.params.name", "op", "matches", "value", "A.a"));
        assertFalse(Predicates.evaluatePredicates(list(map("verb", "*", "where", where)), ctx()));
        // each evaluatePredicates call is its own document
        assertTrue(Predicates.evaluatePredicates(list(map("verb", "*", "where", list(map("field", "action.params.name", "op", "matches", "value", "A.a")))), ctx()));
        assertEquals(U, Predicates.evaluateConditionTri(map("field", "action.params.name", "op", "matches", "value", "x".repeat(201)), ctx()));
    }
}
