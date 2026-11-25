package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import net.atlasauth.pca.authzen.Authzen;
import net.atlasauth.pca.oauth.JsVal;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the AuthZEN package (guards, mapping, AARP, PDP refusal paths, handler, search). */
public class AuthzenDiffTest {
    private static final String M = "ref-authzen";
    private static final long NOW = 1_000_000;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    private static List<Object> list(Object... xs) {
        List<Object> l = new ArrayList<>();
        for (Object x : xs) l.add(x);
        return l;
    }

    // ---- PDP configs, by the names the vectors use ----

    private static Authzen.AuthzenPdp pdp(String name) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("now", (LongSupplier) () -> NOW);
        switch (name) {
            case "none": c.put("resolve", (Authzen.Resolver) r -> null); break;
            case "throws": c.put("resolve", (Authzen.Resolver) r -> { throw new Exception("boom"); }); break;
            case "noauth": c.put("resolve", (Authzen.Resolver) r -> map("grant", map(), "policy", map())); break;
            case "auth":
                c.put("resolve", (Authzen.Resolver) r -> map("grant", map(), "policy", map()));
                c.put("authorizer", (Authzen.Authorizer) in -> map("allow", Boolean.TRUE));
                break;
            case "max2": c.put("resolve", (Authzen.Resolver) r -> null); c.put("maxEvaluations", 2); break;
            case "toolmap": c.put("resolve", (Authzen.Resolver) r -> null); c.put("toolCapability", (Authzen.ToolCapability) n -> "cap." + n); break;
            case "toolthrow": c.put("resolve", (Authzen.Resolver) r -> null); c.put("toolCapability", (Authzen.ToolCapability) n -> { throw new Exception("bad tool"); }); break;
            default: throw new IllegalArgumentException(name);
        }
        return Authzen.authzenPdp(c);
    }

    // ---- search providers, by name ----

    private static Map<String, Object> user(String id) { return map("type", "user", "id", id); }

    private static Map<String, Object> provider(String name) {
        Map<String, Object> p = new LinkedHashMap<>();
        Authzen.SearchFn boom = r -> { throw new Exception("x"); };
        switch (name) {
            case "none": break;
            case "full":
                p.put("searchSubject", (Authzen.SearchFn) r -> map("results", list(user("a"), user("b"), map("type", "group", "id", "g"), user("a"), map("id", "a", "type", "user")),
                    "page", map("next_token", "", "total", JsVal.n(3), "properties", map("k", JsVal.n(1))), "context", map("c", JsVal.n(1))));
                p.put("searchResource", (Authzen.SearchFn) r -> map("results", list(map("type", "doc", "id", "1"), map("type", "doc", "id", "2"), map("type", "user", "id", "x")), "page", map("next_token", "n1")));
                p.put("searchAction", (Authzen.SearchFn) r -> map("results", list(map("name", "read"), map("name", "write"), map("name", "read"), map("name", "read", "properties", map("p", JsVal.n(1))))));
                break;
            case "nopage":
                p.put("searchSubject", (Authzen.SearchFn) r -> map("results", list(user("a"), user("b"))));
                p.put("searchResource", (Authzen.SearchFn) r -> map("results", list()));
                p.put("searchAction", (Authzen.SearchFn) r -> map("results", list()));
                break;
            case "emptyprops":
                p.put("searchSubject", (Authzen.SearchFn) r -> map("results", list(user("a")), "page", map("next_token", "z", "properties", map()), "context", map()));
                break;
            case "bad":
                p.put("searchSubject", (Authzen.SearchFn) r -> map("results", list((Object) null)));
                p.put("searchResource", (Authzen.SearchFn) r -> map("results", list(JsVal.n(5))));
                p.put("searchAction", (Authzen.SearchFn) r -> map("results", list(null, JsVal.n(5))));
                break;
            case "notarray":
                p.put("searchSubject", (Authzen.SearchFn) r -> map("results", "x"));
                p.put("searchResource", (Authzen.SearchFn) r -> map());
                p.put("searchAction", (Authzen.SearchFn) r -> map("results", null));
                break;
            case "throws":
                p.put("searchSubject", boom);
                p.put("searchResource", boom);
                p.put("searchAction", boom);
                break;
            case "echo":
                p.put("searchSubject", (Authzen.SearchFn) r -> map("results", list(), "context", map("saw", r)));
                p.put("searchResource", (Authzen.SearchFn) r -> map("results", list(), "context", map("saw", r)));
                p.put("searchAction", (Authzen.SearchFn) r -> map("results", list(), "context", map("saw", r)));
                break;
            case "partial":
                p.put("searchResource", (Authzen.SearchFn) r -> map("results", list()));
                break;
            default: throw new IllegalArgumentException(name);
        }
        return p;
    }

    @Test void isAccessEvaluationRequest() throws Exception { OracleCases.each(M, "isAccessEvaluationRequest", a -> Authzen.isAccessEvaluationRequest(a.get(0))); }
    @Test void isAccessEvaluationsRequest() throws Exception { OracleCases.each(M, "isAccessEvaluationsRequest", a -> Authzen.isAccessEvaluationsRequest(a.get(0))); }
    @Test void isCoazToolAuthorizationRequest() throws Exception { OracleCases.each(M, "isCoazToolAuthorizationRequest", a -> Authzen.isCoazToolAuthorizationRequest(a.get(0))); }
    @Test void isAuthzenSubject() throws Exception { OracleCases.each(M, "isAuthzenSubject", a -> Authzen.isAuthzenSubject(a.get(0))); }
    @Test void isAuthzenAction() throws Exception { OracleCases.each(M, "isAuthzenAction", a -> Authzen.isAuthzenAction(a.get(0))); }
    @Test void isAuthzenResource() throws Exception { OracleCases.each(M, "isAuthzenResource", a -> Authzen.isAuthzenResource(a.get(0))); }
    @Test void isSubjectSearch() throws Exception { OracleCases.each(M, "isSubjectSearch", a -> Authzen.isSubjectSearch(a.get(0))); }
    @Test void isResourceSearch() throws Exception { OracleCases.each(M, "isResourceSearch", a -> Authzen.isResourceSearch(a.get(0))); }
    @Test void isActionSearch() throws Exception { OracleCases.each(M, "isActionSearch", a -> Authzen.isActionSearch(a.get(0))); }
    @Test void defaultToAction() throws Exception { OracleCases.each(M, "defaultToAction", a -> Authzen.defaultToAction(m(a.get(0)))); }
    @Test void approvalOf() throws Exception { OracleCases.each(M, "approvalOf", a -> Authzen.approvalOf(a.get(0))); }
    @Test void isApprovalRequired() throws Exception { OracleCases.each(M, "isApprovalRequired", a -> Authzen.isApprovalRequired(a.get(0))); }
    @Test void pdpEvaluate() throws Exception { OracleCases.each(M, "pdp.evaluate", a -> pdp((String) a.get(0)).evaluate(a.get(1))); }
    @Test void pdpEvaluations() throws Exception { OracleCases.each(M, "pdp.evaluations", a -> pdp((String) a.get(0)).evaluations(a.get(1))); }
    @Test void pdpEvaluateTool() throws Exception { OracleCases.each(M, "pdp.evaluateTool", a -> pdp((String) a.get(0)).evaluateTool(m(a.get(1)))); }
    @Test void authzenHandler() throws Exception { OracleCases.each(M, "authzenHandler", a -> pdp((String) a.get(0)).handle(m(a.get(1)))); }
    @Test void authzenSearchHandler() throws Exception { OracleCases.each(M, "authzenSearchHandler", a -> Authzen.authzenSearchHandler(provider((String) a.get(0)), m(a.get(1)))); }
    @Test void searchMetadata() throws Exception { OracleCases.each(M, "searchMetadata", a -> Authzen.searchMetadata((String) a.get(0), provider((String) a.get(1)))); }

    @Test void constants() {
        assertEquals("/access/v1/evaluation", Authzen.EVALUATION_PATH);
        assertEquals("/access/v1/evaluations", Authzen.EVALUATIONS_PATH);
        assertEquals("/access/v1/mcp/tool/evaluation", Authzen.COAZ_TOOL_PATH);
        assertEquals("/access/v1/search/subject", Authzen.SEARCH_SUBJECT_PATH);
        assertEquals(1000, Authzen.MAX_SEARCH_LIMIT);
        assertEquals(100, Authzen.DEFAULT_MAX_EVALUATIONS);
    }
}
