package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Exact-outcome kill tests for {@link MissingContext}: the merge (copying, depth cap, blocking, action creation) and the typed decision. */
public class MissingContextRestKillTest {
    static Object j(String s) { return AuthorizeFixtures.j(s); }
    static Map<String, Object> jm(String s) { return AuthorizeFixtures.jm(s); }
    static String canon(Object v) { return Json.canonicalize(v); }
    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static final String B = "{'action':{'verb':'refund','resource':'/a','params':{'amount':50}},'subject':{'id':'u1'},'env':{'tier':'gold'}}";

    static void bind(String bound, String supplied, String table, String want) {
        Map<String, Object> t = table == null ? new LinkedHashMap<>() : jm(table);
        assertEquals(canon(j(want)), canon(MissingContext.bindContext(j(bound), supplied == null ? null : j(supplied), t)), supplied);
    }

    static void decide(String where, String bound, String supplied, String suppliers, String want) {
        Object r = MissingContext.decide(j(where), j(bound), supplied == null ? null : j(supplied), suppliers == null ? null : j(suppliers));
        assertEquals(canon(j(want)), canon(r), where);
    }

    /** {a1: {a2: ... {an: leaf}}}. */
    static Map<String, Object> chain(int n, Object leaf) {
        Object v = leaf;
        for (int i = n; i >= 1; i--) {
            Map<String, Object> x = new LinkedHashMap<>();
            x.put("a" + i, v);
            v = x;
        }
        return m(v);
    }

    static String chainPath(int n) {
        StringBuilder b = new StringBuilder();
        for (int i = 1; i <= n; i++) b.append(i == 1 ? "" : ".").append("a").append(i);
        return b.toString();
    }

    // ---- supplierOf / supplierTableError ----

    @Test void supplierOfIsTheLongestSegmentPrefixWhateverTheTableOrder() {
        Map<String, Object> t = jm("{'env.obs':'rs_observation','env':'discharge_issuer','env.kyc':'principal'}");
        assertEquals("rs_observation", MissingContext.supplierOf("env.obs.load", t));
        assertEquals("rs_observation", MissingContext.supplierOf("env.obs", t));
        assertEquals("discharge_issuer", MissingContext.supplierOf("env.observed", t));
        assertEquals("principal", MissingContext.supplierOf("env.kyc", t));
        assertEquals("principal", MissingContext.supplierOf("subject.id", t));
        Map<String, Object> exact = jm("{'env.kyc':'discharge_issuer'}");
        assertEquals("discharge_issuer", MissingContext.supplierOf("env.kyc", exact));
        assertEquals("discharge_issuer", MissingContext.supplierOf("env.kyc.a", exact));
        assertEquals("principal", MissingContext.supplierOf("env.kycx", exact));
        assertEquals("principal", MissingContext.supplierOf("env", exact));
    }

    @Test void supplierTableErrorsAreExact() {
        assertEquals("the supplier table must be an object", MissingContext.supplierTableError("x"));
        assertEquals("the supplier table must be an object", MissingContext.supplierTableError(null));
        assertEquals("the supplier table must be an object", MissingContext.supplierTableError(List.of()));
        assertEquals("bad supplier path 'env.__proto__'", MissingContext.supplierTableError(jm("{'env.__proto__':'principal'}")));
        assertEquals("bad supplier path 'subject.constructor.x'", MissingContext.supplierTableError(jm("{'subject.constructor.x':'principal'}")));
        assertEquals("bad supplier path 'env.'", MissingContext.supplierTableError(jm("{'env.':'principal'}")));
        assertEquals("bad supplier for 'env.a'", MissingContext.supplierTableError(jm("{'env.a':5}")));
        assertEquals("bad supplier for 'env.a'", MissingContext.supplierTableError(jm("{'env.a':null}")));
        assertEquals("bad supplier for 'env.a'", MissingContext.supplierTableError(jm("{'env.a':'nobody'}")));
        assertNull(MissingContext.supplierTableError(jm("{'env.a':'principal','action.params.x':'agent_declared_untrusted'}")));
        assertNull(MissingContext.supplierTableError(jm("{}")));
    }

    // ---- bindContext ----

    @Test void theMergeCopiesNeverAliasesAndKeepsSiblings() {
        Map<String, Object> bound = jm("{'action':{'verb':'v','resource':'r','params':{'amount':5}},'env':{'a':{'z':1},'tags':[{'k':1},[2]]}}");
        Map<String, Object> supplied = jm("{'action':{'params':{'extra':1}},'env':{'a':{'b':2},'list':[{'m':1},[3]],'e':{}},'subject':{'id':'u'}}");
        String boundBefore = canon(bound);
        Map<String, Object> r = MissingContext.bindContext(bound, supplied, new LinkedHashMap<>());
        assertEquals(canon(j("{'context':{'action':{'verb':'v','resource':'r','params':{'amount':5,'extra':1}},"
            + "'env':{'a':{'z':1,'b':2},'tags':[{'k':1},[2]],'e':{},'list':[{'m':1},[3]]},'subject':{'id':'u'}},'conflicts':[],'dropped':[]}")), canon(r));
        assertEquals(boundBefore, canon(bound), "the bound context is never written");
        Map<String, Object> ctx = m(r.get("context"));
        assertNotSame(bound, ctx);
        assertNotSame(bound.get("env"), ctx.get("env"));
        assertNotSame(m(bound.get("env")).get("a"), m(ctx.get("env")).get("a"));
        List<Object> bt = l(m(bound.get("env")).get("tags")), ct = l(m(ctx.get("env")).get("tags"));
        assertNotSame(bt, ct);
        assertNotSame(bt.get(0), ct.get(0));
        assertNotSame(bt.get(1), ct.get(1));
        Map<String, Object> se = m(supplied.get("env"));
        List<Object> sl = l(se.get("list")), cl = l(m(ctx.get("env")).get("list"));
        assertNotSame(sl, cl);
        assertNotSame(sl.get(0), cl.get(0));
        assertNotSame(sl.get(1), cl.get(1));
        assertNotSame(se.get("e"), m(ctx.get("env")).get("e"));
    }

    @Test void forbiddenKeysAreSkippedAndAnEmptyKeyIsAMember() {
        bind("{'action':{'verb':'v','resource':'r'},'env':{}}", "{'env':{'__proto__':{'x':1},'constructor':5,'prototype':{'y':2},'':7,'k':1}}", null,
            "{'context':{'action':{'verb':'v','resource':'r'},'env':{'':7,'k':1}},'conflicts':[],'dropped':[]}");
    }

    @Test void anAbsentActionIsCreatedOnlyForActionParams() {
        bind("{'env':{'t':1}}", "{'action':{'params':{'x':{'y':1}}},'env':{'t':1}}", null,
            "{'context':{'env':{'t':1},'action':{'verb':'','resource':'','params':{'x':{'y':1}}}},'conflicts':[],'dropped':[]}");
        bind("{'env':{}}", "{'env':{'k':1}}", null, "{'context':{'env':{'k':1}},'conflicts':[],'dropped':[]}");
        // a bound action that is present but null is a bound value (TS 08f482520): the supplied params conflict, nothing is created
        bind("{'action':null}", "{'action':{'params':{'p':1}}}", null, "{'context':{'action':null},'conflicts':['action.params.p'],'dropped':[]}");
        bind("{'action':'refund'}", "{'action':{'params':{'p':1}}}", null, "{'context':{'action':'refund'},'conflicts':['action.params.p'],'dropped':[]}");
        bind("{'action':[1]}", "{'action':{'params':{'p':1}}}", null, "{'context':{'action':[1]},'conflicts':['action.params.p'],'dropped':[]}");
        bind("{'subject':5,'env':'e'}", "{'subject':{'id':'u'},'env':{'a':1}}", null, "{'context':{'subject':5,'env':'e'},'conflicts':['env.a','subject.id'],'dropped':[]}");
        bind("{'action':{'verb':'v','resource':'r'}}", "{'env':{'k':1}}", null,
            "{'context':{'action':{'verb':'v','resource':'r'},'env':{'k':1}},'conflicts':[],'dropped':[]}");
        bind("{'action':{'verb':'v','resource':'r'}}", "{'action':{'params':{}}}", null,
            "{'context':{'action':{'verb':'v','resource':'r','params':{}}},'conflicts':[],'dropped':[]}");
        bind("{'action':{'verb':'v','resource':'r'}}", "{'action':{'params':{'q':[1]}}}", null,
            "{'context':{'action':{'verb':'v','resource':'r','params':{'q':[1]}}},'conflicts':[],'dropped':[]}");
    }

    @Test void aBoundLeafAboveBlocksOnlyThatPath() {
        bind("{'action':{'verb':'v','resource':'r'},'env':{'a':5}}", "{'env':{'a':{'b':1},'c':{'d':1}}}", null,
            "{'context':{'action':{'verb':'v','resource':'r'},'env':{'a':5,'c':{'d':1}}},'conflicts':['env.a.b'],'dropped':[]}");
        bind("{'action':{'verb':'v','resource':'r','params':null}}", "{'action':{'params':{'x':1}}}", null,
            "{'context':{'action':{'verb':'v','resource':'r','params':null}},'conflicts':['action.params.x'],'dropped':[]}");
        bind("{'action':{'verb':'v','resource':'r','params':'s'}}", "{'action':{'params':{'x':1}}}", null,
            "{'context':{'action':{'verb':'v','resource':'r','params':'s'}},'conflicts':['action.params.x'],'dropped':[]}");
    }

    @Test void untrustedPathsAreDroppedAndNonObjectsIgnored() {
        bind(B, "{'env':{'a':1,'b':2}}", "{'env.a':'agent_declared_untrusted'}",
            "{'context':{'action':{'verb':'refund','resource':'/a','params':{'amount':50}},'subject':{'id':'u1'},'env':{'tier':'gold','b':2}},'conflicts':[],'dropped':['env.a']}");
        bind("'x'", "{'env':{'a':1}}", null, "{'context':'x','conflicts':[],'dropped':[]}");
        bind("null", "{'env':{'a':1}}", null, "{'context':null,'conflicts':[],'dropped':[]}");
        bind(B, "5", null, "{'context':" + B + ",'conflicts':[],'dropped':[]}");
        bind(B, null, null, "{'context':" + B + ",'conflicts':[],'dropped':[]}");
        // supplied action / subject / env that are not objects contribute nothing
        bind(B, "{'action':{'params':5},'subject':'s','env':[1]}", null, "{'context':" + B + ",'conflicts':[],'dropped':[]}");
    }

    /** Below depth 16 a supplied object is flattened; at depth 17 it is one leaf, compared whole against the bound value. */
    @Test void theFlatteningDepthCapIsSeventeenLevelsForEveryRoot() {
        String p = chainPath(17);
        for (String root : new String[] {"env", "subject", "action.params"}) {
            Map<String, Object> bound = new LinkedHashMap<>(), supplied = new LinkedHashMap<>();
            Map<String, Object> action = new LinkedHashMap<>();
            action.put("verb", "v");
            action.put("resource", "r");
            bound.put("action", action);
            Map<String, Object> bc = chain(17, jm("{'x':1,'y':2}")), sc = chain(17, jm("{'x':1}"));
            if (root.equals("action.params")) {
                action.put("params", bc);
                Map<String, Object> sa = new LinkedHashMap<>();
                sa.put("params", sc);
                supplied.put("action", sa);
            } else {
                bound.put(root, bc);
                supplied.put(root, sc);
            }
            String before = canon(bound);
            Map<String, Object> r = MissingContext.bindContext(bound, supplied, new LinkedHashMap<>());
            assertEquals(List.of(root + "." + p), r.get("conflicts"), root);
            assertEquals(List.of(), r.get("dropped"), root);
            assertEquals(before, canon(r.get("context")), root);
        }
    }

    // ---- decide ----

    static final String ESC_A = "{'decision':'escalate','reason':'escalate: missing_context principal:env.a','missing':[{'path':'env.a','supplier':'principal'}]}";
    static final String ESC_B = "{'decision':'escalate','reason':'escalate: missing_context principal:env.b','missing':[{'path':'env.b','supplier':'principal'}]}";
    static final String ILL = "{'decision':'deny','reason':'ill_typed_context','missing':[]}";

    @Test void groupsAreWalkedByTheKeyPredicatesUses() {
        decide("[{'all_of':[{'field':'env.a','op':'eq','value':1}],'any_of':[{'field':'env.b','op':'eq','value':1}]}]", B, null, null, ESC_A);
        decide("[{'any_of':[{'field':'env.b','op':'eq','value':1}],'not':{'field':'env.a','op':'eq','value':1}}]", B, null, null, ESC_B);
        decide("[{'all_of':[{'field':'env.a','op':'eq','value':1}]}]", B, null, null, ESC_A);
        decide("[{'any_of':[{'field':'env.a','op':'eq','value':1}]}]", B, null, null, ESC_A);
        decide("[{'not':{'field':'env.a','op':'eq','value':1}}]", B, null, null, ESC_A);
        decide("[{'not':null},{'field':'env.b','op':'eq','value':1}]", B, null, null, ILL);
        decide("[{'any_of':[]},{'field':'env.b','op':'eq','value':1}]", B, null, null, ILL);
        decide("[{'all_of':'x'},{'field':'env.b','op':'eq','value':1}]", B, null, null, ILL);
        decide("[[1],{'field':'env.b','op':'eq','value':1}]", B, null, null, ILL);
    }

    static Object notChain(int k) {
        Object c = jm("{'field':'env.a','op':'eq','value':true}");
        for (int i = 0; i < k; i++) {
            Map<String, Object> x = new LinkedHashMap<>();
            x.put("not", c);
            c = x;
        }
        return c;
    }

    @Test void aMissingLeafIsNamedDownToDepthSixtyFour() {
        Map<String, Object> bound = jm(B);
        assertEquals(canon(j(ESC_A)), canon(MissingContext.decide(new ArrayList<>(List.of(notChain(64))), bound, null, null)));
        assertEquals(canon(j(ILL)), canon(MissingContext.decide(new ArrayList<>(List.of(notChain(65), jm("{'field':'env.b','op':'eq','value':1}"))), bound, null, null)));
        assertEquals(canon(j(ILL)), canon(MissingContext.decide(new ArrayList<>(List.of(notChain(65))), bound, null, null)));
    }

    @Test void decidedLeavesAreSkippedAndPresentWrongTypesAreIll() {
        decide("[{'field':'env.tier','op':'eq','value':'gold'},{'field':'env.b','op':'eq','value':1}]", B, null, null, ESC_B);
        decide("[{'field':'env.tier','op':'lt','value':5},{'field':'env.b','op':'eq','value':1}]", B, null, null, ILL);
        decide("[{'field':'','op':'eq','value':1}]", B, null, null, ILL);
        decide("[{'field':'env.tier','op':'eq','ref':'env.want'}]", B, null, null,
            "{'decision':'escalate','reason':'escalate: missing_context principal:env.want','missing':[{'path':'env.want','supplier':'principal'}]}");
        decide("[{'field':'env.a','op':'eq','ref':'env.b'}]", B, null, null,
            "{'decision':'escalate','reason':'escalate: missing_context principal:env.a,principal:env.b','missing':[{'path':'env.a','supplier':'principal'},{'path':'env.b','supplier':'principal'}]}");
    }

    @Test void anUnusableParamsValueIsNamedOnlyWhenItIsNotAnObject() {
        String esc = "{'decision':'escalate','reason':'escalate: missing_context principal:action.params','missing':[{'path':'action.params','supplier':'principal'}]}";
        decide("[{'field':'action.params','op':'eq','value':'s'}]", "{'action':{'verb':'v','resource':'r','params':'s'}}", null, null, esc);
        decide("[{'field':'action.params','op':'eq','value':null}]", "{'action':{'verb':'v','resource':'r','params':null}}", null, null, esc);
        decide("[{'field':'action.params','op':'lt','value':5}]", "{'action':{'verb':'v','resource':'r','params':[1]}}", null, null, ILL);
        decide("[{'field':'action.params','op':'lt','value':5}]", B, null, null, ILL);
        decide("[{'field':'action.params.x','op':'eq','value':1}]", "{'action':{'verb':'v','resource':'r','params':'s'}}", null, null,
            "{'decision':'escalate','reason':'escalate: missing_context principal:action.params.x','missing':[{'path':'action.params.x','supplier':'principal'}]}");
        decide("[{'field':'action.params.amount','op':'lte','value':100}]", "{'action':{'verb':'v','resource':'r'}}", null, null,
            "{'decision':'escalate','reason':'escalate: missing_context principal:action.params.amount','missing':[{'path':'action.params.amount','supplier':'principal'}]}");
    }

    /** The whole list exhausts the regex budget (65 > 64 evaluations: unknown) though each leaf alone is true: nothing is missing, so ill-typed. */
    @Test void anUnknownWithNothingMissingIsIllTyped() {
        List<Object> where = new ArrayList<>();
        for (int i = 0; i < 65; i++) where.add(jm("{'field':'env.tier','op':'matches','value':'gold'}"));
        assertEquals(canon(j(ILL)), canon(MissingContext.decide(where, jm(B), null, null)));
        assertEquals(canon(j("{'decision':'allow','missing':[]}")), canon(MissingContext.decide(new ArrayList<>(where.subList(0, 64)), jm(B), null, null)));
    }

    @Test void suppliersTypeTheMissingPaths() {
        decide("[{'field':'env.obs.load','op':'eq','value':1},{'field':'env.x','op':'eq','value':1}]", B, null, "{'env.obs':'rs_observation','env':'discharge_issuer'}",
            "{'decision':'escalate','reason':'escalate: missing_context rs_observation:env.obs.load,discharge_issuer:env.x',"
            + "'missing':[{'path':'env.obs.load','supplier':'rs_observation'},{'path':'env.x','supplier':'discharge_issuer'}]}");
        decide("[{'field':'env.y','op':'eq','value':1},{'field':'env.x','op':'eq','value':1}]", B, null, "{'env.x':'agent_declared_untrusted'}",
            "{'decision':'deny','reason':'missing_context_untrusted: env.x','missing':[{'path':'env.x','supplier':'agent_declared_untrusted'},{'path':'env.y','supplier':'principal'}]}");
        decide("[{'field':'env.k','op':'eq','value':1}]", B, "{'env':{'k':1}}", "{}", "{'decision':'allow','missing':[]}");
        decide("[{'field':'env.k','op':'eq','value':1}]", B, "{'env':{'tier':'x','k':1}}", null, "{'decision':'deny','reason':'context_shadow: env.tier','missing':[]}");
    }

    @Test void aThrowingEvaluationFailsClosed() {
        Map<Object, Object> table = new HashMap<>();
        table.put(1, "principal"); // a non-string key: the table check throws
        Map<String, Object> r = MissingContext.decide(j("[{'field':'env.tier','op':'eq','value':'gold'}]"), jm(B), null, table);
        assertEquals(canon(j("{'decision':'deny','reason':'evaluation error (fail closed)','missing':[]}")), canon(r));
    }
}
