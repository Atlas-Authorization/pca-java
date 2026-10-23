package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Exhaustive / boundary kills for Predicates internals (glob matching, path resolution) not reached by the TS corpus. */
class K042PredicatesGapTest {
    /** Reference glob matcher: ? = one unit, * = any run, backslash escapes the next unit; null on a dangling backslash. */
    private static Boolean ref(String glob, String s) {
        List<Object[]> t = new ArrayList<>();   // {'L', char} | {'?'} | {'*'}
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            if (c == '\\') { if (i + 1 >= glob.length()) return null; t.add(new Object[] {'L', glob.charAt(++i)}); }
            else if (c == '*') t.add(new Object[] {'*'});
            else if (c == '?') t.add(new Object[] {'?'});
            else t.add(new Object[] {'L', c});
        }
        boolean[][] m = new boolean[t.size() + 1][s.length() + 1];
        m[0][0] = true;
        for (int i = 1; i <= t.size(); i++) {
            Object[] k = t.get(i - 1);
            for (int j = 0; j <= s.length(); j++) {
                if (k[0].equals('*')) m[i][j] = m[i - 1][j] || (j > 0 && m[i][j - 1]);
                else if (j > 0 && (k[0].equals('?') || (char) k[1] == s.charAt(j - 1))) m[i][j] = m[i - 1][j - 1];
            }
        }
        return m[t.size()][s.length()];
    }

    private static void words(String alpha, int max, List<String> out) {
        out.add("");
        List<String> prev = new ArrayList<>(List.of(""));
        for (int n = 1; n <= max; n++) {
            List<String> next = new ArrayList<>();
            for (String p : prev) for (char c : alpha.toCharArray()) next.add(p + c);
            out.addAll(next);
            prev = next;
        }
    }

    @Test void globMatchesTheReferenceExhaustively() {
        List<String> pats = new ArrayList<>(), subs = new ArrayList<>();
        words("a\u0002*?\\", 4, pats);
        words("a\u0002*?\\b", 4, subs);
        int bad = 0;
        StringBuilder sb = new StringBuilder();
        for (String p : pats) for (String s : subs) {
            Boolean want = ref(p, s), got = Predicates.globMatch(p, s);
            if (!java.util.Objects.equals(want, got) && bad++ < 20) sb.append(p.replace("\u0002", "^B")).append(" ~ ").append(s.replace("\u0002", "^B")).append(": want ").append(want).append(" got ").append(got).append('\n');
        }
        assertEquals(0, bad, sb.toString());
    }

    @Test void globStarRunsAndEscapes() {
        assertEquals(Boolean.TRUE, Predicates.globMatch("a**b", "axxb"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("**", ""));
        assertEquals(Boolean.TRUE, Predicates.globMatch("*a*b*", "xxaxxbxx"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("*a*b*", "xxbxxaxx"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("\\*", "*"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("\\*", "x"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("\\?", "?"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("\\?", "x"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("\\\\", "\\"));
        assertNull(Predicates.globMatch("a\\", "a"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("\u0002*", "\u0002abc"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("\u0002", "x"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("?*?", "ab"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("?*?", "a"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("a*", "a"));
        assertEquals(Boolean.TRUE, Predicates.globMatch("*a", "bba"));
        assertEquals(Boolean.FALSE, Predicates.globMatch("*a", "bbab"));
    }

    @Test void resolvePathRejectsWhatIsNotAPathOrARoot() {
        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("action", new LinkedHashMap<>(Map.of("verb", "v")));
        ctx.put("other", "x");
        ctx.put("", "empty");
        for (Object p : new Object[] {null, 5L, List.of("action"), Map.of(), true, ""}) assertFalse(Predicates.resolvePath(ctx, p).found, String.valueOf(p));
        assertFalse(Predicates.resolvePath(ctx, "other").found);
        assertFalse(Predicates.resolvePath(ctx, "other.x").found);
        assertFalse(Predicates.resolvePath(ctx, ".x").found);
        assertFalse(Predicates.resolvePath(ctx, "subject").found);   // a root the context lacks
        assertFalse(Predicates.resolvePath(null, "action").found);
        assertTrue(Predicates.resolvePath(ctx, "action.verb").found);
        assertEquals("v", Predicates.resolvePath(ctx, "action.verb").value);
        assertFalse(Predicates.resolvePath(ctx, "action.verb.x").found);
        assertFalse(Predicates.resolvePath(ctx, "action..verb").found);
    }

    private static final Predicates.Tri T = Predicates.Tri.TRUE, F = Predicates.Tri.FALSE, U = Predicates.Tri.UNKNOWN;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ctx(String json) { return (Map<String, Object>) Json.parseLenient(json); }
    private static Predicates.Tri tri(String cond, String ctx) { return Predicates.evaluateConditionTri(Json.parseLenient(cond), ctx(ctx)); }

    private static final String NOPARAMS = "{\"action\":{\"verb\":\"v\",\"resource\":\"r\"},\"subject\":{\"id\":\"s\",\"name\":\"n\"},\"env\":{}}";
    private static final String PARAMS = "{\"action\":{\"verb\":\"v\",\"resource\":\"r\",\"params\":{\"x\":\"s\"}},\"subject\":{\"id\":\"s\",\"name\":\"n\"},\"env\":{}}";

    @Test void refRootedAtUnavailableParamsIsUnknownBeforeAnyOp() {
        // params absent: a ref under action.params can never resolve, even for ops that ignore refs (exists)
        assertEquals(U, tri("{\"field\":\"subject.id\",\"op\":\"exists\",\"ref\":\"action.params.x\"}", NOPARAMS));
        assertEquals(U, tri("{\"field\":\"subject.id\",\"op\":\"eq\",\"ref\":\"action.params.x\"}", NOPARAMS));
        assertEquals(U, tri("{\"field\":\"subject.id\",\"op\":\"exists\",\"ref\":\"action.params\"}", NOPARAMS));
        // a ref elsewhere is judged normally
        assertEquals(T, tri("{\"field\":\"subject.id\",\"op\":\"exists\",\"ref\":\"subject.name\"}", NOPARAMS));
        assertEquals(F, tri("{\"field\":\"subject.id\",\"op\":\"eq\",\"ref\":\"subject.name\"}", NOPARAMS));
        assertEquals(T, tri("{\"field\":\"subject.id\",\"op\":\"ne\",\"ref\":\"subject.name\"}", NOPARAMS));
        // a non-string ref is not params-rooted
        assertEquals(T, tri("{\"field\":\"subject.id\",\"op\":\"exists\",\"ref\":5}", NOPARAMS));
        // params present: the same ref resolves
        assertEquals(T, tri("{\"field\":\"subject.id\",\"op\":\"eq\",\"ref\":\"action.params.x\"}", PARAMS));
        assertEquals(T, tri("{\"field\":\"subject.id\",\"op\":\"exists\",\"ref\":\"action.params.x\"}", PARAMS));
        // a params-rooted FIELD with params unavailable
        assertEquals(U, tri("{\"field\":\"action.params.x\",\"op\":\"exists\"}", NOPARAMS));
        assertEquals(U, tri("{\"field\":\"action.params\",\"op\":\"exists\"}", NOPARAMS));
        assertEquals(T, tri("{\"field\":\"action.paramsx\",\"op\":\"exists\",\"value\":false}", NOPARAMS));
        // params that are not an object (a list is an object in JS) / null / a scalar
        assertEquals(T, tri("{\"field\":\"action.params.0\",\"op\":\"eq\",\"value\":\"q\"}", "{\"action\":{\"verb\":\"v\",\"resource\":\"r\",\"params\":[\"q\"]}}"));
        assertEquals(U, tri("{\"field\":\"action.params.0\",\"op\":\"eq\",\"value\":\"q\"}", "{\"action\":{\"verb\":\"v\",\"resource\":\"r\",\"params\":\"q\"}}"));
        assertEquals(U, tri("{\"field\":\"action.params.0\",\"op\":\"eq\",\"value\":\"q\"}", "{\"action\":{\"verb\":\"v\",\"resource\":\"r\",\"params\":null}}"));
        assertEquals(U, tri("{\"field\":\"action.params.0\",\"op\":\"eq\",\"value\":\"q\"}", "{\"action\":[1]}"));
        assertEquals(U, tri("{\"field\":\"action.params.0\",\"op\":\"eq\",\"value\":\"q\"}", "{}"));
        assertEquals(U, Predicates.evaluateConditionTri(Json.parseLenient("{\"field\":\"action.params.0\",\"op\":\"eq\",\"value\":\"q\"}"), null));
    }

    @Test void emptyGroupsAndEmptyTypeTagsAreUnknown() {
        assertEquals(U, tri("{\"all_of\":[]}", PARAMS));
        assertEquals(U, tri("{\"any_of\":[]}", PARAMS));
        assertEquals(U, tri("{\"all_of\":{}}", PARAMS));
        assertEquals(U, tri("{\"any_of\":\"x\"}", PARAMS));
        assertEquals(U, tri("{\"field\":\"subject.name\",\"op\":\"is_a\",\"value\":\"\"}", PARAMS));
        assertEquals(U, tri("{\"field\":\"subject.name\",\"op\":\"is_a\",\"value\":5}", PARAMS));
        assertEquals(T, tri("{\"field\":\"subject.name\",\"op\":\"is_a\",\"value\":\"n\"}", PARAMS));
        assertEquals(U, tri("{\"field\":\"subject.name\",\"op\":\"member_of\",\"collection\":\"\",\"value\":\"n\"}", PARAMS));
        assertEquals(U, tri("{\"field\":\"subject.name\",\"op\":\"member_of\",\"collection\":5,\"value\":\"n\"}", PARAMS));
        assertEquals(U, tri("{\"field\":\"subject.name\",\"op\":\"member_of\",\"collection\":\"subject.id\",\"value\":\"n\"}", PARAMS)); // a string is no group map
    }

    @Test void memberClosureNeverFollowsPrototypeNames() {
        String c = "{\"action\":{\"verb\":\"v\",\"resource\":\"r\"},\"subject\":{\"id\":\"a\",\"g\":{\"a\":\"__proto__\",\"__proto__\":\"target\",\"constructor\":\"t2\",\"b\":\"constructor\"}}}";
        assertEquals(T, tri("{\"field\":\"subject.id\",\"op\":\"member_of\",\"collection\":\"subject.g\",\"value\":\"__proto__\"}", c));
        assertEquals(F, tri("{\"field\":\"subject.id\",\"op\":\"member_of\",\"collection\":\"subject.g\",\"value\":\"target\"}", c));
        assertEquals(F, tri("{\"field\":\"subject.id\",\"op\":\"member_of\",\"collection\":\"subject.g\",\"value\":\"t2\"}", c));
        // a node that is NOT a key has no neighbours (and is not an error)
        assertEquals(F, tri("{\"field\":\"subject.id\",\"op\":\"member_of\",\"collection\":\"subject.g\",\"value\":\"zzz\"}", c));
    }

    @Test void predicateWithoutResourceOrWhere() {
        Map<String, Object> cx = ctx(PARAMS);
        assertTrue(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\"}"), cx));
        assertTrue(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\",\"resource\":\"*\"}"), cx));
        assertTrue(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\",\"resource\":\"r\"}"), cx));
        assertTrue(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\",\"resource\":\"*r\"}".replace("*r", "r*")), cx));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\",\"resource\":null}"), cx));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\",\"resource\":5}"), cx));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\",\"resource\":\"x\"}"), cx));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\",\"where\":{}}"), cx));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\",\"where\":null}"), cx));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"x\"}"), cx));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{}"), cx));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("[]"), cx));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("5"), cx));
        assertFalse(Predicates.predicateMatches(null, cx));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\"}"), null));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\"}"), ctx("{\"action\":5}")));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\"}"), ctx("{\"action\":{\"verb\":5,\"resource\":\"r\"}}")));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\"}"), ctx("{\"action\":{\"verb\":\"v\",\"resource\":5}}")));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{\"verb\":\"v\"}"), ctx("{\"action\":{\"verb\":\"v\"}}")));
        assertTrue(Predicates.predicateMatches(Json.parseLenient("{\"verb\":[null,5,\"v\"]}"), cx));
        assertTrue(Predicates.predicateMatches(Json.parseLenient("{\"verb\":[\"x\",\"*\"]}"), cx));
        assertFalse(Predicates.predicateMatches(Json.parseLenient("{\"verb\":[null,5]}"), cx));
        assertFalse(Predicates.evaluatePredicates(Json.parseLenient("[]"), cx));
        assertFalse(Predicates.evaluatePredicates(Json.parseLenient("{}"), cx));
        assertFalse(Predicates.evaluatePredicates(null, cx));
        assertTrue(Predicates.evaluatePredicates(Json.parseLenient("[5,{\"verb\":\"v\"}]"), cx));
    }

    /** One document may not spend more than 5,000,000 NFA steps; each evaluation is charged program size x (subject + 1). */
    @Test void documentStepBudgetIsChargedBySubjectLength() {
        String pat = "a".repeat(130) + "b{64}";        // 195 instructions, never matches the subject below
        SafeRegex.Compiled c = SafeRegex.compile(pat);
        assertNotNull(c);
        assertTrue(SafeRegex.isSafeSource(pat));
        String subj = "a".repeat(512);
        int per = c.size() * 513;                      // steps per evaluation
        int fit = (int) (5_000_000L / per);            // evaluations that fit
        assertTrue(fit > 10 && fit < 60, "fit " + fit);
        Object cond = Json.parseLenient("{\"field\":\"subject.s\",\"op\":\"matches\",\"value\":\"" + pat + "\"}");
        Map<String, Object> cx = ctx("{\"subject\":{\"s\":\"" + subj + "\"}}");
        Map<String, Object> anyOf = new LinkedHashMap<>();
        anyOf.put("any_of", new ArrayList<>(java.util.Collections.nCopies(fit, cond)));
        assertEquals(F, Predicates.evaluateConditionTri(anyOf, cx));           // all decided (false)
        anyOf.put("any_of", new ArrayList<>(java.util.Collections.nCopies(fit + 1, cond)));
        assertEquals(U, Predicates.evaluateConditionTri(anyOf, cx));           // one more exceeds the cap: refused
        // the same through the resource patterns of a predicate list, then a cheap predicate that WOULD allow
        Map<String, Object> rcx = ctx("{\"action\":{\"verb\":\"v\",\"resource\":\"" + subj + "\"}}");
        Object miss = Json.parseLenient("{\"verb\":\"v\",\"resource\":\"re:" + pat + "\"}");
        Object allow = Json.parseLenient("{\"verb\":\"v\",\"resource\":\"re:.*\"}");
        List<Object> ok = new ArrayList<>(java.util.Collections.nCopies(fit, miss));
        ok.add(allow);
        assertTrue(Predicates.evaluatePredicates(ok, rcx));
        List<Object> over = new ArrayList<>(java.util.Collections.nCopies(fit + 1, miss));
        over.add(allow);
        assertFalse(Predicates.evaluatePredicates(over, rcx));
    }
}
