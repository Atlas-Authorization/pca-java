package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Exact-output kills for {@link Contracts}: clause and contract validation (every boundary and message), the per-clause transition, the contract
 * monitor (check / advance / check-and-advance) with the full result shape, and signing / verification.
 */
public class ContractsPitKill1Test {
    static Object j(String s) { return Json.parseLenient(s.replace('\'', '"')); }

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static void eq(String want, Object got) { assertEquals(Json.canonicalize(j(want)), Json.canonicalize(got)); }

    static List<String> vc(String json) { return Contracts.validateContract(j(json)); }

    static List<String> vcl(String json, Set<String> seen, int depth) { return Contracts.validateClause(j(json), seen, depth); }

    static List<String> one(String s) { return new ArrayList<>(List.of(s)); }

    static final String NEVER_X = "'kind':'never','p':{'verb':'x'}";

    // ---- validateClause -------------------------------------------------------------------------------------------------

    @Test void clauseDepthShapeAndId() {
        assertEquals(one("clause nesting too deep"), vcl("{'id':'a'," + NEVER_X + "}", new HashSet<>(), 17));
        assertEquals(new ArrayList<String>(), vcl("{'id':'a'," + NEVER_X + "}", new HashSet<>(), 16));
        assertEquals(one("clause not an object"), Contracts.validateClause("x", new HashSet<>(), 1));
        assertEquals(one("clause not an object"), Contracts.validateClause(null, new HashSet<>(), 1));
        assertEquals(one("<no id>: missing clause id"), vcl("{'kind':'never','p':{'verb':'x'}}", new HashSet<>(), 1));
        assertEquals(one("<no id>: missing clause id"), vcl("{'id':''," + NEVER_X + "}", new HashSet<>(), 1));
        assertEquals(one("<no id>: missing clause id"), vcl("{'id':5," + NEVER_X + "}", new HashSet<>(), 1));
        String id128 = "a".repeat(128), id129 = "a".repeat(129);
        assertEquals(new ArrayList<String>(), vcl("{'id':'" + id128 + "'," + NEVER_X + "}", new HashSet<>(), 1));
        assertEquals(one(id129 + ": id too long"), vcl("{'id':'" + id129 + "'," + NEVER_X + "}", new HashSet<>(), 1));
        for (String bad : Arrays.asList("__proto__", "constructor", "prototype")) {
            assertEquals(one(bad + ": forbidden id"), vcl("{'id':'" + bad + "'," + NEVER_X + "}", new HashSet<>(), 1));
        }
        Set<String> seen = new HashSet<>();
        assertEquals(new ArrayList<String>(), vcl("{'id':'a'," + NEVER_X + "}", seen, 1));
        assertTrue(seen.contains("a"));
        assertEquals(one("a: duplicate id"), vcl("{'id':'a'," + NEVER_X + "}", seen, 1));
        assertEquals(1, seen.size());
    }

    @Test void alwaysAndNeverTriggers() {
        for (String kind : Arrays.asList("always", "never")) {
            assertEquals(new ArrayList<String>(), vcl("{'id':'a','kind':'" + kind + "','p':{'verb':'x'}}", new HashSet<>(), 1));
            assertEquals(one("a: p: not an object"), vcl("{'id':'a','kind':'" + kind + "','p':5}", new HashSet<>(), 1));
            assertEquals(one("a: p: not an object"), vcl("{'id':'a','kind':'" + kind + "'}", new HashSet<>(), 1));
            assertEquals(one("a: p: bad verb"), vcl("{'id':'a','kind':'" + kind + "','p':{}}", new HashSet<>(), 1));
            // q is not looked at by these kinds
            assertEquals(new ArrayList<String>(), vcl("{'id':'a','kind':'" + kind + "','p':{'verb':'x'},'q':5}", new HashSet<>(), 1));
        }
    }

    @Test void pairedClauseKindsCheckPThenQ() {
        for (String kind : Arrays.asList("precedes", "requires_prior")) {
            String ok = "{'id':'a','kind':'" + kind + "','p':{'verb':'x'},'q':{'verb':'y'}}";
            assertEquals(new ArrayList<String>(), vcl(ok, new HashSet<>(), 1));
            assertEquals(one("a: p: not an object"), vcl("{'id':'a','kind':'" + kind + "','p':5,'q':{'verb':'y'}}", new HashSet<>(), 1));
            assertEquals(one("a: q: not an object"), vcl("{'id':'a','kind':'" + kind + "','p':{'verb':'x'},'q':5}", new HashSet<>(), 1));
            assertEquals(one("a: q: bad verb"), vcl("{'id':'a','kind':'" + kind + "','p':{'verb':'x'},'q':{}}", new HashSet<>(), 1));
            // both bad: only the first problem (p) is reported
            assertEquals(one("a: p: not an object"), vcl("{'id':'a','kind':'" + kind + "','p':5,'q':6}", new HashSet<>(), 1));
            // within is not required of these kinds
            assertEquals(new ArrayList<String>(), vcl("{'id':'a','kind':'" + kind + "','p':{'verb':'x'},'q':{'verb':'y'},'within':0}", new HashSet<>(), 1));
        }
    }

    @Test void respondsWithinBounds() {
        String pre = "{'id':'a','kind':'responds_within','p':{'verb':'x'},'q':{'verb':'y'}";
        String msg = "a: within must be an integer in [1, MAX_DEADLINE]";
        assertEquals(new ArrayList<String>(), vcl(pre + ",'within':1}", new HashSet<>(), 1));
        assertEquals(new ArrayList<String>(), vcl(pre + ",'within':2}", new HashSet<>(), 1));
        assertEquals(new ArrayList<String>(), vcl(pre + ",'within':1000000}", new HashSet<>(), 1));
        assertEquals(one(msg), vcl(pre + ",'within':1000001}", new HashSet<>(), 1));
        assertEquals(one(msg), vcl(pre + ",'within':0}", new HashSet<>(), 1));
        assertEquals(one(msg), vcl(pre + ",'within':-1}", new HashSet<>(), 1));
        assertEquals(one(msg), vcl(pre + ",'within':2.5}", new HashSet<>(), 1));
        assertEquals(one(msg), vcl(pre + ",'within':'3'}", new HashSet<>(), 1));
        assertEquals(one(msg), vcl(pre + "}", new HashSet<>(), 1));
        assertEquals(one("a: p: not an object"), vcl("{'id':'a','kind':'responds_within','p':1,'q':{'verb':'y'},'within':3}", new HashSet<>(), 1));
        assertEquals(one("a: q: not an object"), vcl("{'id':'a','kind':'responds_within','p':{'verb':'x'},'q':1,'within':3}", new HashSet<>(), 1));
    }

    @Test void andClausesAndUnknownKinds() {
        String msg = "a: and.clauses must be a non-empty array";
        assertEquals(one(msg), vcl("{'id':'a','kind':'and'}", new HashSet<>(), 1));
        assertEquals(one(msg), vcl("{'id':'a','kind':'and','clauses':[]}", new HashSet<>(), 1));
        assertEquals(one(msg), vcl("{'id':'a','kind':'and','clauses':'x'}", new HashSet<>(), 1));
        assertEquals(new ArrayList<String>(), vcl("{'id':'a','kind':'and','clauses':[{'id':'b'," + NEVER_X + "}]}", new HashSet<>(), 1));
        // sub problems are collected in order, ids are unique across the whole tree
        assertEquals(Arrays.asList("b: p: not an object", "b: duplicate id", "<no id>: missing clause id"),
            vcl("{'id':'a','kind':'and','clauses':[{'id':'b','kind':'never','p':1},{'id':'b'," + NEVER_X + "},{'kind':'never'}]}", new HashSet<>(), 1));
        assertEquals(one("a: duplicate id"), vcl("{'id':'a','kind':'and','clauses':[{'id':'a'," + NEVER_X + "}]}", new HashSet<>(), 1));
        assertEquals(one("clause nesting too deep"), vcl("{'id':'a','kind':'and','clauses':[{'id':'b'," + NEVER_X + "}]}", new HashSet<>(), 16));
        assertEquals(one("a: unknown clause kind bogus"), vcl("{'id':'a','kind':'bogus'}", new HashSet<>(), 1));
        assertEquals(one("a: unknown clause kind undefined"), vcl("{'id':'a'}", new HashSet<>(), 1));
    }

    // ---- validateContract / countClauses --------------------------------------------------------------------------------

    @Test void versionAndPrincipal() {
        assertEquals(Arrays.asList("unsupported version undefined", "principal missing"), vc("{}"));
        assertEquals(one("unsupported version 2"), vc("{'version':2,'principal':'p'}"));
        assertEquals(one("unsupported version 1"), vc("{'version':'1','principal':'p'}"));
        assertEquals(one("principal missing"), vc("{'version':1,'principal':''}"));
        assertEquals(one("principal missing"), vc("{'version':1,'principal':5}"));
        assertEquals(one("principal missing"), vc("{'version':1}"));
        assertEquals(new ArrayList<String>(), vc("{'version':1,'principal':'p'}"));
        assertEquals(one("contract not an object"), Contracts.validateContract(null));
        assertEquals(one("contract not an object"), Contracts.validateContract("x"));
    }

    static String invariants(int n) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < n; i++) b.append(i == 0 ? "" : ",").append("{'id':'i").append(i).append("','kind':'never','when':{'verb':'x'}}");
        return b.append("]").toString();
    }

    static String neverClauses(int n, String prefix) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < n; i++) b.append(i == 0 ? "" : ",").append("{'id':'").append(prefix).append(i).append("','kind':'never','p':{'verb':'x'}}");
        return b.append("]").toString();
    }

    @Test void invariantsArrayRules() {
        assertEquals(one("invariants not an array"), vc("{'version':1,'principal':'p','invariants':'x','clauses':5}"));
        assertEquals(one("invariants not an array"), vc("{'version':1,'principal':'p','invariants':{}}"));
        assertEquals(new ArrayList<String>(), vc("{'version':1,'principal':'p','invariants':" + invariants(256) + "}"));
        assertEquals(one("too many invariants"), vc("{'version':1,'principal':'p','invariants':" + invariants(257) + "}"));
        assertEquals(one("invariant not an object"), vc("{'version':1,'principal':'p','invariants':['x']}"));
        assertEquals(one("<no id>: missing id"), vc("{'version':1,'principal':'p','invariants':[{'id':5,'kind':'never','when':{'verb':'x'}}]}"));
        assertEquals(one("i0: duplicate id"), vc("{'version':1,'principal':'p','invariants':[" + "{'id':'i0','kind':'never','when':{'verb':'x'}},{'id':'i0','kind':'never','when':{'verb':'y'}}]}"));
        // an invariant's own problems are reported (and a bad one still registers its id)
        assertEquals(Arrays.asList("i0: when: not an object", "i0: duplicate id"),
            vc("{'version':1,'principal':'p','invariants':[{'id':'i0','kind':'never','when':1},{'id':'i0','kind':'never','when':{'verb':'x'}}]}"));
        // a clause id may not reuse an invariant id (they share the state keys)
        assertEquals(one("i0: duplicate id"), vc("{'version':1,'principal':'p','invariants':" + invariants(1) + ",'clauses':[{'id':'i0'," + NEVER_X + "}]}"));
    }

    @Test void clausesArrayRulesAndTheCountBound() {
        assertEquals(one("clauses not an array"), vc("{'version':1,'principal':'p','clauses':'x'}"));
        assertEquals(one("clauses not an array"), vc("{'version':1,'principal':'p','clauses':{}}"));
        assertEquals(new ArrayList<String>(), vc("{'version':1,'principal':'p','clauses':" + neverClauses(256, "c") + "}"));
        assertEquals(one("too many clauses"), vc("{'version':1,'principal':'p','clauses':" + neverClauses(257, "c") + "}"));
        assertEquals(one("clause not an object"), vc("{'version':1,'principal':'p','clauses':['x']}"));
        // a non-and clause carrying a clauses array is counted once
        StringBuilder many = new StringBuilder();
        for (int i = 0; i < 300; i++) many.append(i == 0 ? "" : ",").append("{'id':'z").append(i).append("','kind':'never','p':{'verb':'x'}}");
        assertEquals(new ArrayList<String>(), vc("{'version':1,'principal':'p','clauses':[{'id':'a','kind':'never','p':{'verb':'x'},'clauses':[" + many + "]}]}"));
        // an and clause counts itself and every sub clause: 254 + 1 + 1 = 256 fits, 255 + 1 + 1 does not
        String sub = "{'id':'s','kind':'never','p':{'verb':'x'}}";
        assertEquals(new ArrayList<String>(), vc("{'version':1,'principal':'p','clauses':" + neverClauses(254, "c").replace("]", ",{'id':'a','kind':'and','clauses':[" + sub + "]}]") + "}"));
        assertEquals(one("too many clauses"), vc("{'version':1,'principal':'p','clauses':" + neverClauses(255, "c").replace("]", ",{'id':'a','kind':'and','clauses':[" + sub + "]}]") + "}"));
        // an and clause with 256 subs is 257 in all
        StringBuilder subs = new StringBuilder();
        for (int i = 0; i < 256; i++) subs.append(i == 0 ? "" : ",").append("{'id':'s").append(i).append("','kind':'never','p':{'verb':'x'}}");
        assertEquals(one("too many clauses"), vc("{'version':1,'principal':'p','clauses':[{'id':'a','kind':'and','clauses':[" + subs + "]}]}"));
        // a clauses key that is not a list inside an and is not descended into (and is reported by the clause)
        assertEquals(one("a: and.clauses must be a non-empty array"), vc("{'version':1,'principal':'p','clauses':[{'id':'a','kind':'and','clauses':'x'}]}"));
    }

    static String nestedAnds(int levels) {
        StringBuilder open = new StringBuilder(), close = new StringBuilder();
        for (int i = 1; i <= levels; i++) {
            open.append("{'id':'a").append(i).append("','kind':'and','clauses':[");
            close.append("]}");
        }
        return open + "{'id':'leaf'," + NEVER_X + "}" + close;
    }

    @Test void nestingDepthIsBoundedAtBothTheCountAndTheValidation() {
        String pre = "{'version':1,'principal':'p','clauses':[";
        assertEquals(new ArrayList<String>(), vc(pre + nestedAnds(15) + "]}"));
        assertEquals(one("clause nesting too deep"), vc(pre + nestedAnds(16) + "]}"));
        // 17 levels: the count gives up at once (too many) and the validation reports the depth
        assertEquals(Arrays.asList("too many clauses", "clause nesting too deep"), vc(pre + nestedAnds(17) + "]}"));
        assertEquals(Arrays.asList("too many clauses", "clause nesting too deep"), vc(pre + nestedAnds(40) + "]}"));
    }

    // ---- sign / verify --------------------------------------------------------------------------------------------------

    static byte[] seed(int fill) {
        byte[] s = new byte[32];
        Arrays.fill(s, (byte) fill);
        return s;
    }

    static Map<String, Object> contractFor(String principal) {
        return m(j("{'version':1,'principal':'" + principal + "','clauses':[{'id':'a','kind':'never','p':{'verb':'x'}}]}"));
    }

    static final class ThrowingEntries extends LinkedHashMap<String, Object> {
        private static final long serialVersionUID = 1L;
        @Override public java.util.Set<Map.Entry<String, Object>> entrySet() { throw new IllegalStateException("boom"); }
    }

    @Test void signContractBindsTheBodyAndLeavesTheInputAlone() {
        byte[] seed = seed(7);
        String principal = Keys.edFromSeed(seed).id();
        Map<String, Object> c = contractFor(principal);
        Map<String, Object> signed = Contracts.signContract(c, seed);
        assertFalse(c.containsKey("id"));
        assertFalse(c.containsKey("sig"));
        assertNotSame(c, signed);
        assertEquals(new HashSet<>(Arrays.asList("version", "principal", "clauses", "id", "sig")), signed.keySet());
        assertEquals(Contracts.contractId(c), signed.get("id"));
        assertEquals(signed.get("id"), Contracts.contractId(signed));
        assertNull(Contracts.verifyContract(signed, principal));
        assertNull(Contracts.verifyContract(signed, null));
        // a stale id / sig on the input is stripped, not signed over
        Map<String, Object> stale = contractFor(principal);
        stale.put("id", "zz");
        stale.put("sig", "yy");
        Map<String, Object> again = Contracts.signContract(stale, seed);
        assertEquals(signed.get("id"), again.get("id"));
        assertEquals(signed.get("sig"), again.get("sig"));
        assertEquals("zz", stale.get("id"));
        assertEquals("yy", stale.get("sig"));
    }

    @Test void signContractRefusesAnInvalidContractNamingEveryProblem() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Contracts.signContract(m(j("{'version':2,'clauses':[]}")), seed(7)));
        assertEquals("signContract: unsupported version 2; principal missing", e.getMessage());
        IllegalArgumentException one = assertThrows(IllegalArgumentException.class, () -> Contracts.signContract(m(j("{'version':1,'principal':'p','clauses':5}")), seed(7)));
        assertEquals("signContract: clauses not an array", one.getMessage());
    }

    @Test void verifyContractReasons() {
        byte[] seed = seed(7);
        String principal = Keys.edFromSeed(seed).id();
        Map<String, Object> signed = Contracts.signContract(contractFor(principal), seed);
        assertNull(Contracts.verifyContract(signed, principal));
        assertEquals("principal mismatch", Contracts.verifyContract(signed, "someone-else"));
        assertEquals("unsupported version 2", Contracts.verifyContract(m(j("{'version':2,'principal':'p'}")), null));
        // changed content
        Map<String, Object> changed = new LinkedHashMap<>(signed);
        changed.put("clauses", j("[{'id':'a','kind':'never','p':{'verb':'y'}}]"));
        assertEquals("id does not match content", Contracts.verifyContract(changed, principal));
        Map<String, Object> noId = new LinkedHashMap<>(signed);
        noId.remove("id");
        assertEquals("id does not match content", Contracts.verifyContract(noId, principal));
        Map<String, Object> numId = new LinkedHashMap<>(signed);
        numId.put("id", j("5"));
        assertEquals("id does not match content", Contracts.verifyContract(numId, principal));
        // signature problems
        Map<String, Object> other = Contracts.signContract(contractFor(principal), seed(8));
        Map<String, Object> wrongKey = new LinkedHashMap<>(signed);
        wrongKey.put("sig", other.get("sig"));
        assertEquals("bad signature", Contracts.verifyContract(wrongKey, principal));
        Map<String, Object> noSig = new LinkedHashMap<>(signed);
        noSig.remove("sig");
        assertEquals("bad signature", Contracts.verifyContract(noSig, principal));
        Map<String, Object> numSig = new LinkedHashMap<>(signed);
        numSig.put("sig", j("5"));
        assertEquals("bad signature", Contracts.verifyContract(numSig, principal));
        // the embedded principal is the key that must have signed it
        Map<String, Object> swapped = new LinkedHashMap<>(signed);
        swapped.put("principal", Keys.edFromSeed(seed(8)).id());
        assertEquals("id does not match content", Contracts.verifyContract(swapped, null));
        // a store or map that fails mid-verification is a refusal, never an exception
        ThrowingEntries bad = new ThrowingEntries();
        bad.put("version", j("1"));
        bad.put("principal", "p");
        bad.put("id", "x");
        assertEquals("verification error (fail closed)", Contracts.verifyContract(bad, null));
    }

    @Test void theEmbeddedConstitutionKeepsPrincipalAndInvariants() {
        eq("{'version':1,'principal':'p','invariants':[{'id':'i'}]}", Contracts.embeddedConstitution(m(j("{'principal':'p','invariants':[{'id':'i'}],'clauses':[]}"))));
        eq("{'version':1,'principal':'p','invariants':[]}", Contracts.embeddedConstitution(m(j("{'principal':'p'}"))));
        eq("{'version':1,'principal':'p','invariants':[]}", Contracts.embeddedConstitution(m(j("{'principal':'p','invariants':'x'}"))));
        eq("{'version':1,'principal':null,'invariants':[]}", Contracts.embeddedConstitution(m(j("{'invariants':5}"))));
    }

    // ---- evalClause -----------------------------------------------------------------------------------------------------

    static Map<String, Object> ev(String clause, String verb, String state) {
        return Contracts.evalClause(m(j(clause)), m(j("{'action':{'verb':'" + verb + "','resource':'/r'}}")), m(j(state)), j("1000"));
    }

    static final String NO_STATE = "{'latched':{}}";

    static String row(String id, String kind, boolean ok, String reason) {
        return "{'id':'" + id + "','kind':'" + kind + "','result':'" + (ok ? "pass" : "violated") + "'" + (reason == null ? "" : ",'reason':'" + reason + "'") + "}";
    }

    static String res(boolean ok, String rows, String latchSet, String deadlineSet, String reason) {
        return "{'ok':" + ok + ",'rows':[" + rows + "],'latchSet':" + latchSet + ",'deadlineSet':" + deadlineSet + (reason == null ? "" : ",'reason':'" + reason + "'") + "}";
    }

    @Test void alwaysClause() {
        String cl = "{'id':'c1','kind':'always','p':{'verb':'read'}}";
        eq(res(true, row("c1", "always", true, null), "{}", "{}", null), ev(cl, "read", NO_STATE));
        String r = "always-invariant violated (action does not satisfy p)";
        eq(res(false, row("c1", "always", false, r), "{}", "{}", r), ev(cl, "write", NO_STATE));
        eq(res(false, row("c1", "always", false, "custom"), "{}", "{}", "custom"),
            ev("{'id':'c1','kind':'always','p':{'verb':'read'},'description':'custom'}", "write", NO_STATE));
    }

    @Test void neverClause() {
        String cl = "{'id':'n1','kind':'never','p':{'verb':'delete'}}";
        eq(res(true, row("n1", "never", true, null), "{}", "{}", null), ev(cl, "read", NO_STATE));
        String r = "never-invariant violated (forbidden action)";
        eq(res(false, row("n1", "never", false, r), "{}", "{}", r), ev(cl, "delete", NO_STATE));
        eq(res(false, row("n1", "never", false, "no deletes"), "{}", "{}", "no deletes"),
            ev("{'id':'n1','kind':'never','p':{'verb':'delete'},'description':'no deletes'}", "delete", NO_STATE));
    }

    @Test void precedesAndRequiresPriorLatchOnAnAffirmativePrerequisite() {
        String viol = "precedence violated (prerequisite p not yet admitted before q)";
        for (String kind : Arrays.asList("precedes", "requires_prior")) {
            String cl = "{'id':'o','kind':'" + kind + "','p':{'verb':'review'},'q':{'verb':'deploy'}}";
            // the guarded action without the prerequisite
            eq(res(false, row("o", kind, false, viol), "{}", "{}", viol), ev(cl, "deploy", NO_STATE));
            // the prerequisite is latched with the clock
            eq(res(true, row("o", kind, true, null), "{'o':1000}", "{}", null), ev(cl, "review", NO_STATE));
            // an unrelated action changes nothing
            eq(res(true, row("o", kind, true, null), "{}", "{}", null), ev(cl, "read", NO_STATE));
            // once latched the guarded action passes and nothing is latched again
            eq(res(true, row("o", kind, true, null), "{}", "{}", null), ev(cl, "deploy", "{'latched':{'o':1}}"));
            eq(res(true, row("o", kind, true, null), "{}", "{}", null), ev(cl, "review", "{'latched':{'o':1}}"));
            // a latch of another clause does not count
            eq(res(false, row("o", kind, false, viol), "{}", "{}", viol), ev(cl, "deploy", "{'latched':{'zz':1}}"));
            // the prerequisite and the guarded action are one verb: violated now, latched for later
            String same = "{'id':'o','kind':'" + kind + "','p':{'verb':'x'},'q':{'verb':'x'}}";
            eq(res(false, row("o", kind, false, viol), "{'o':1000}", "{}", viol), ev(same, "x", NO_STATE));
            eq(res(true, row("o", kind, true, null), "{}", "{}", null), ev(same, "x", "{'latched':{'o':5}}"));
            // a custom description names the violation
            eq(res(false, row("o", kind, false, "review first"), "{}", "{}", "review first"),
                ev("{'id':'o','kind':'" + kind + "','p':{'verb':'review'},'q':{'verb':'deploy'},'description':'review first'}", "deploy", NO_STATE));
        }
    }

    static final String RESP = "{'id':'r','kind':'responds_within','p':{'verb':'alarm'},'q':{'verb':'ack'},'within':3}";

    @Test void respondsWithinOpensCarriesAndDischargesTheDeadline() {
        eq(res(true, row("r", "responds_within", true, null), "{}", "{'r':3}", null), ev(RESP, "alarm", NO_STATE));
        eq(res(true, row("r", "responds_within", true, null), "{}", "{'r':null}", null), ev(RESP, "read", NO_STATE));
        String d2 = "{'latched':{},'deadlines':{'r':2}}";
        // the response discharges every open obligation
        eq(res(true, row("r", "responds_within", true, null), "{}", "{'r':null}", null), ev(RESP, "ack", d2));
        // an action that is neither counts the window down
        eq(res(true, row("r", "responds_within", true, null), "{}", "{'r':1}", null), ev(RESP, "read", d2));
        // a new alarm keeps the nearer deadline (carried 1 vs within 3), and replaces a farther one (carried 4 vs within 3)
        eq(res(true, row("r", "responds_within", true, null), "{}", "{'r':1}", null), ev(RESP, "alarm", d2));
        eq(res(true, row("r", "responds_within", true, null), "{}", "{'r':3}", null), ev(RESP, "alarm", "{'latched':{},'deadlines':{'r':5}}"));
        eq(res(true, row("r", "responds_within", true, null), "{}", "{'r':2}", null), ev(RESP, "alarm", "{'latched':{},'deadlines':{'r':3}}"));
        // an action that is both the alarm and the response discharges the old obligation and opens a new one
        String both = "{'id':'r','kind':'responds_within','p':{'verb':'x'},'q':{'verb':'x'},'within':3}";
        eq(res(true, row("r", "responds_within", true, null), "{}", "{'r':3}", null), ev(both, "x", d2));
        // the window runs out without a response: violated at this action, whatever the action is
        String miss = "bounded-liveness deadline missed (no q within 3 actions of p)";
        String d1 = "{'latched':{},'deadlines':{'r':1}}";
        eq(res(false, row("r", "responds_within", false, miss), "{}", "{}", miss), ev(RESP, "read", d1));
        eq(res(false, row("r", "responds_within", false, miss), "{}", "{}", miss), ev(RESP, "alarm", d1));
        // a response in time still discharges
        eq(res(true, row("r", "responds_within", true, null), "{}", "{'r':null}", null), ev(RESP, "ack", d1));
        // a custom description replaces the default reason; the deadlines of other clauses are not this clause's
        eq(res(false, row("r", "responds_within", false, "late"), "{}", "{}", "late"),
            ev("{'id':'r','kind':'responds_within','p':{'verb':'alarm'},'q':{'verb':'ack'},'within':3,'description':'late'}", "read", d1));
        eq(res(true, row("r", "responds_within", true, null), "{}", "{'r':null}", null), ev(RESP, "read", "{'latched':{},'deadlines':{'other':1}}"));
        // deadlines that are not an object are no deadlines
        eq(res(true, row("r", "responds_within", true, null), "{}", "{'r':3}", null), ev(RESP, "alarm", "{'latched':{},'deadlines':5}"));
        eq(res(true, row("r", "responds_within", true, null), "{}", "{'r':3}", null), ev(RESP, "alarm", "{'latched':{},'deadlines':null}"));
    }

    @Test void aCarriedDeadlineEqualToTheWindowStaysTheCarriedNumber() {
        // within 2.0 is an integer; the carried deadline (3 - 1 = 2) is kept as the computed number "2", not the clause's own text "2.0"
        String cl = "{'id':'r','kind':'responds_within','p':{'verb':'alarm'},'q':{'verb':'ack'},'within':2.0}";
        Map<String, Object> out = ev(cl, "alarm", "{'latched':{},'deadlines':{'r':3}}");
        Map<String, Object> ds = m(out.get("deadlineSet"));
        assertEquals("2", ((Json.Num) ds.get("r")).raw);
        // a nearer carried deadline wins, a farther one is replaced by the window
        assertEquals("1", ((Json.Num) m(ev(cl, "alarm", "{'latched':{},'deadlines':{'r':2}}").get("deadlineSet")).get("r")).raw);
        assertEquals("2.0", ((Json.Num) m(ev(cl, "alarm", "{'latched':{},'deadlines':{'r':9}}").get("deadlineSet")).get("r")).raw);
    }

    @Test void andClauseConcatenatesRowsAndMergesTheUpdates() {
        String and = "{'id':'both','kind':'and','clauses':["
            + "{'id':'s1','kind':'never','p':{'verb':'read'}},"
            + "{'id':'s2','kind':'precedes','p':{'verb':'review'},'q':{'verb':'deploy'}},"
            + "{'id':'s3','kind':'responds_within','p':{'verb':'review'},'q':{'verb':'ack'},'within':4}]}";
        String rows = row("s1", "never", true, null) + "," + row("s2", "precedes", true, null) + "," + row("s3", "responds_within", true, null);
        eq(res(true, rows, "{'s2':1000}", "{'s3':4}", null), ev(and, "review", NO_STATE));
        String nv = "never-invariant violated (forbidden action)";
        String rows2 = row("s1", "never", false, nv) + "," + row("s2", "precedes", true, null) + "," + row("s3", "responds_within", true, null);
        eq(res(false, rows2, "{}", "{'s3':null}", nv), ev(and, "read", NO_STATE));
        // the reason is the FIRST failing sub clause's
        String two = "{'id':'both','kind':'and','clauses':["
            + "{'id':'a1','kind':'never','p':{'verb':'delete'},'description':'first'},"
            + "{'id':'a2','kind':'never','p':{'verb':'delete'},'description':'second'}]}";
        eq(res(false, row("a1", "never", false, "first") + "," + row("a2", "never", false, "second"), "{}", "{}", "first"), ev(two, "delete", NO_STATE));
        // later sub clauses still contribute their updates when an earlier one failed
        String mixed = "{'id':'both','kind':'and','clauses':["
            + "{'id':'a1','kind':'never','p':{'verb':'x'},'description':'no x'},"
            + "{'id':'a2','kind':'precedes','p':{'verb':'x'},'q':{'verb':'y'}},"
            + "{'id':'a3','kind':'responds_within','p':{'verb':'x'},'q':{'verb':'z'},'within':2}]}";
        eq(res(false, row("a1", "never", false, "no x") + "," + row("a2", "precedes", true, null) + "," + row("a3", "responds_within", true, null), "{'a2':1000}", "{'a3':2}", "no x"),
            ev(mixed, "x", NO_STATE));
        // an and inside an and
        String nested = "{'id':'o','kind':'and','clauses':[{'id':'i','kind':'and','clauses':[{'id':'n','kind':'never','p':{'verb':'delete'}}]}]}";
        eq(res(true, row("n", "never", true, null), "{}", "{}", null), ev(nested, "read", NO_STATE));
    }

    @Test void anUnknownOrUnreadableKindFailsClosedWithARow() {
        String u = "unknown clause kind (fail closed)";
        eq(res(false, row("x", "bogus", false, u), "{}", "{}", u), ev("{'id':'x','kind':'bogus'}", "read", NO_STATE));
        String e = "clause evaluation error (fail closed)";
        eq("{'ok':false,'rows':[{'id':'x','kind':null,'result':'violated','reason':'" + e + "'}],'latchSet':{},'deadlineSet':{},'reason':'" + e + "'}",
            ev("{'id':'x','kind':null}", "read", NO_STATE));
        eq("{'ok':false,'rows':[{'id':'x','kind':5,'result':'violated','reason':'" + e + "'}],'latchSet':{},'deadlineSet':{},'reason':'" + e + "'}",
            ev("{'id':'x','kind':5}", "read", NO_STATE));
        // a state without latches cannot answer a precedes clause
        eq("{'ok':false,'rows':[{'id':'o','kind':'precedes','result':'violated','reason':'" + e + "'}],'latchSet':{},'deadlineSet':{},'reason':'" + e + "'}",
            ev("{'id':'o','kind':'precedes','p':{'verb':'a'},'q':{'verb':'b'}}", "a", "{}"));
    }

    // ---- checkContract --------------------------------------------------------------------------------------------------

    static final String S0 = "{'now':1000,'seq':0,'parent':null,'ledger':{},'latched':{}}";

    static final String CONTRACT_A = "{'version':1,'principal':'p','clauses':["
        + "{'id':'order','kind':'precedes','p':{'verb':'review'},'q':{'verb':'deploy'}},{'id':'nodel','kind':'never','p':{'verb':'delete'}}]}";

    static String act(String verb) { return "{'action':{'verb':'" + verb + "','resource':'/r'}}"; }

    @Test void checkContractWithoutClausesOrWithoutInvariants() {
        eq("{'ok':true,'violated':[],'reasons':[],'evaluated':[{'id':'no-wire','kind':'never','result':'pass'}]}",
            Contracts.checkContract(j(act("read")), j("{'version':1,'principal':'p','invariants':[{'id':'no-wire','kind':'never','when':{'verb':'wire'}}]}"), j(S0)));
        eq("{'ok':false,'violated':['no-wire'],'reasons':['no-wire: forbidden action'],'evaluated':[{'id':'no-wire','kind':'never','result':'violated','reason':'forbidden action'}]}",
            Contracts.checkContract(j(act("wire")), j("{'version':1,'principal':'p','invariants':[{'id':'no-wire','kind':'never','when':{'verb':'wire'}}]}"), j(S0)));
        eq("{'ok':true,'violated':[],'reasons':[],'evaluated':[]}", Contracts.checkContract(j(act("read")), j("{'version':1,'principal':'p'}"), j(S0)));
        // invariants come first, then the clauses
        eq("{'ok':true,'violated':[],'reasons':[],'evaluated':[{'id':'inv','kind':'never','result':'pass'},{'id':'order','kind':'precedes','result':'pass'},{'id':'nodel','kind':'never','result':'pass'}]}",
            Contracts.checkContract(j(act("read")), j("{'version':1,'principal':'p','invariants':[{'id':'inv','kind':'never','when':{'verb':'wire'}}],'clauses':["
                + "{'id':'order','kind':'precedes','p':{'verb':'review'},'q':{'verb':'deploy'}},{'id':'nodel','kind':'never','p':{'verb':'delete'}}]}"), j(S0)));
    }

    @Test void checkContractStructuralFailures() {
        eq("{'ok':false,'violated':['<contract>'],'reasons':['<contract>: contract not an object'],'evaluated':[{'id':'<contract>','kind':'structural','result':'violated','reason':'contract not an object'}]}",
            Contracts.checkContract(j(act("read")), null, j(S0)));
        eq("{'ok':false,'violated':['<action>'],'reasons':['<action>: malformed action'],'evaluated':[{'id':'<action>','kind':'structural','result':'violated','reason':'malformed action'}]}",
            Contracts.checkContract(j("{'action':{'verb':'x'}}"), j(CONTRACT_A), j(S0)));
        eq("{'ok':false,'violated':['<state>'],'reasons':['<state>: malformed monitor state'],'evaluated':[{'id':'<state>','kind':'structural','result':'violated','reason':'malformed monitor state'}]}",
            Contracts.checkContract(j(act("read")), j(CONTRACT_A), j("{'now':1}")));
    }

    static final class ThrowingDeadlines extends LinkedHashMap<String, Object> {
        private static final long serialVersionUID = 1L;
        @Override public Object get(Object k) {
            if ("deadlines".equals(k)) throw new IllegalStateException("boom");
            return super.get(k);
        }
    }

    static final class ThrowingInvariants extends LinkedHashMap<String, Object> {
        private static final long serialVersionUID = 1L;
        @Override public Object get(Object k) {
            if ("invariants".equals(k)) throw new IllegalStateException("boom");
            return super.get(k);
        }
    }

    @Test void aClauseThatCannotBeEvaluatedIsAViolationRowNotAnException() {
        ThrowingDeadlines state = new ThrowingDeadlines();
        state.putAll(m(j(S0)));
        String e = "clause evaluation error (fail closed)";
        eq("{'ok':false,'violated':['n1','n2'],'reasons':['n1: " + e + "','n2: " + e + "'],'evaluated':["
            + "{'id':'n1','kind':'never','result':'violated','reason':'" + e + "'},{'id':'n2','kind':'precedes','result':'violated','reason':'" + e + "'}]}",
            Contracts.checkContract(j(act("read")), j("{'version':1,'principal':'p','clauses':[{'id':'n1','kind':'never','p':{'verb':'x'}},"
                + "{'id':'n2','kind':'precedes','p':{'verb':'a'},'q':{'verb':'b'}}]}"), state));
    }

    @Test void aMonitorFailureIsAStructuralViolation() {
        ThrowingInvariants c = new ThrowingInvariants();
        c.putAll(m(j("{'version':1,'principal':'p'}")));
        eq("{'ok':false,'violated':['<monitor>'],'reasons':['<monitor>: monitor error (fail closed)'],'evaluated':[{'id':'<monitor>','kind':'structural','result':'violated','reason':'monitor error (fail closed)'}]}",
            Contracts.checkContract(j(act("read")), c, j(S0)));
    }

    // ---- advanceContract ------------------------------------------------------------------------------------------------

    static Map<String, Object> adv(String state, String action, String contract, Object now, Object seq, String digest) {
        return Contracts.advanceContract(j(state), j(action), j(contract), now, seq, digest);
    }

    static final String EV_A_PASS = "[" + row("order", "precedes", true, null) + "," + row("nodel", "never", true, null) + "]";

    @Test void anAdmittedActionAdvancesTheChainAndLatchesThePrerequisite() {
        Object state = j(S0);
        Map<String, Object> r = Contracts.advanceContract(state, j(act("review")), j(CONTRACT_A), null, null, null);
        assertEquals(new HashSet<>(Arrays.asList("ok", "violated", "reasons", "evaluated", "next", "decidedBy")), r.keySet());
        assertEquals(Boolean.TRUE, r.get("ok"));
        assertEquals("none", r.get("decidedBy"));
        eq("[]", r.get("violated"));
        eq("[]", r.get("reasons"));
        eq(EV_A_PASS, r.get("evaluated"));
        Map<String, Object> next = m(r.get("next"));
        assertEquals(new HashSet<>(Arrays.asList("now", "seq", "parent", "ledger", "latched")), next.keySet());
        eq("1", next.get("seq"));
        eq("1000", next.get("now"));
        eq("{'order':1000}", next.get("latched"));
        eq("{}", next.get("ledger"));
        assertTrue(next.get("parent") instanceof String);
        assertNull(Prohibitions.stateProblem(next));
        // the input state is untouched
        eq(S0, state);
        // the second step: the guarded action passes, the latch stays, the chain moves on
        Map<String, Object> r2 = Contracts.advanceContract(next, j(act("deploy")), j(CONTRACT_A), null, null, null);
        assertEquals(Boolean.TRUE, r2.get("ok"));
        eq("2", m(r2.get("next")).get("seq"));
        eq("{'order':1000}", m(r2.get("next")).get("latched"));
        assertFalse(m(r2.get("next")).get("parent").equals(next.get("parent")));
    }

    @Test void theClockOptionDefaultsToTheStatesOwn() {
        Map<String, Object> at = adv(S0, act("review"), CONTRACT_A, j("1050"), null, null);
        assertEquals(Boolean.TRUE, at.get("ok"));
        eq("1050", m(at.get("next")).get("now"));
        eq("{'order':1050}", m(at.get("next")).get("latched"));
        Map<String, Object> dflt = adv(S0, act("review"), CONTRACT_A, null, null, null);
        assertEquals(Boolean.TRUE, dflt.get("ok"));
        eq("1000", m(dflt.get("next")).get("now"));
        eq("{'order':1000}", m(dflt.get("next")).get("latched"));
        // a clock behind the state's is a regression, refused as a state problem
        Map<String, Object> back = adv(S0, act("review"), CONTRACT_A, j("500"), null, null);
        eq("{'ok':false,'violated':['<state>'],'reasons':['<state>: advance failed: clock regression'],'evaluated':" + EV_A_PASS + ",'next':" + S0 + ",'decidedBy':'state'}", back);
    }

    @Test void aViolationIsDecidedByTheContractAndAStructuralOneByTheState() {
        Object state = j(S0);
        Map<String, Object> r = Contracts.advanceContract(state, j(act("delete")), j(CONTRACT_A), null, null, null);
        assertEquals(new HashSet<>(Arrays.asList("ok", "violated", "reasons", "evaluated", "next", "decidedBy")), r.keySet());
        assertEquals(Boolean.FALSE, r.get("ok"));
        assertEquals("contract", r.get("decidedBy"));
        assertSame(state, r.get("next"));
        eq("['nodel']", r.get("violated"));
        eq("['nodel: never-invariant violated (forbidden action)']", r.get("reasons"));
        // a deployed-before-reviewed action is a contract violation too
        Map<String, Object> d = adv(S0, act("deploy"), CONTRACT_A, null, null, null);
        assertEquals("contract", d.get("decidedBy"));
        eq("['order']", d.get("violated"));
        // a malformed state is the state's
        Map<String, Object> bad = adv("{'now':1000}", act("review"), CONTRACT_A, null, null, null);
        assertEquals("state", bad.get("decidedBy"));
        eq("['<state>']", bad.get("violated"));
        eq("['<state>: malformed monitor state']", bad.get("reasons"));
        eq("{'now':1000}", bad.get("next"));
        // a malformed action and an invalid contract are structural as well
        assertEquals("state", adv(S0, "{'action':{'verb':'x'}}", CONTRACT_A, null, null, null).get("decidedBy"));
        assertEquals("state", adv(S0, act("x"), "{'version':2,'principal':'p'}", null, null, null).get("decidedBy"));
    }

    @Test void onlyAViolatedIdWrappedInAngleBracketsIsStructural() {
        String[] ids = {"<a", "a>", "<a>", "<>", "a"};
        String[] want = {"contract", "contract", "state", "state", "contract"};
        for (int i = 0; i < ids.length; i++) {
            String contract = "{'version':1,'principal':'p','clauses':[{'id':'" + ids[i] + "','kind':'never','p':{'verb':'x'}}]}";
            Map<String, Object> r = adv(S0, act("x"), contract, null, null, null);
            assertEquals(Boolean.FALSE, r.get("ok"), ids[i]);
            assertEquals(want[i], r.get("decidedBy"), ids[i]);
        }
        // a structural id among ordinary ones still decides by the state
        String mixed = "{'version':1,'principal':'p','clauses':[{'id':'a','kind':'never','p':{'verb':'x'}},{'id':'<s>','kind':'never','p':{'verb':'x'}}]}";
        assertEquals("state", adv(S0, act("x"), mixed, null, null, null).get("decidedBy"));
    }

    @Test void staleHeadChecksComeFirstAndKeepTheBaseVerdict() {
        // matching expectations pass
        assertEquals(Boolean.TRUE, adv(S0, act("review"), CONTRACT_A, null, j("0"), null).get("ok"));
        assertEquals(Boolean.TRUE, adv(S0, act("review"), CONTRACT_A, null, null, Prohibitions.stateDigest(j(S0))).get("ok"));
        assertEquals(Boolean.TRUE, adv(S0, act("review"), CONTRACT_A, null, j("0"), Prohibitions.stateDigest(j(S0))).get("ok"));
        // a wrong sequence
        eq("{'ok':false,'violated':['<state>'],'reasons':['<state>: stale state head (seq)'],'evaluated':" + EV_A_PASS + ",'next':" + S0 + ",'decidedBy':'state'}",
            adv(S0, act("review"), CONTRACT_A, null, j("1"), null));
        // a wrong digest
        eq("{'ok':false,'violated':['<state>'],'reasons':['<state>: stale state head (digest)'],'evaluated':" + EV_A_PASS + ",'next':" + S0 + ",'decidedBy':'state'}",
            adv(S0, act("review"), CONTRACT_A, null, null, "x"));
        // the base violations stay and the state entry is added once
        eq("{'ok':false,'violated':['nodel','<state>'],'reasons':['nodel: never-invariant violated (forbidden action)','<state>: stale state head (seq)'],"
            + "'evaluated':[" + row("order", "precedes", true, null) + "," + row("nodel", "never", false, "never-invariant violated (forbidden action)") + "],'next':" + S0 + ",'decidedBy':'state'}",
            adv(S0, act("delete"), CONTRACT_A, null, j("9"), null));
        // a state that is not an object / has no finite seq has no head to compare
        eq("{'ok':false,'violated':['<state>'],'reasons':['<state>: malformed monitor state','<state>: stale state head (seq)'],"
            + "'evaluated':[{'id':'<state>','kind':'structural','result':'violated','reason':'malformed monitor state'}],'next':null,'decidedBy':'state'}",
            Contracts.advanceContract(null, j(act("review")), j(CONTRACT_A), null, j("0"), null));
        Map<String, Object> noSeq = adv("{'now':1000,'seq':'x','parent':null,'ledger':{},'latched':{}}", act("review"), CONTRACT_A, null, j("0"), null);
        eq("['<state>']", noSeq.get("violated"));
        assertEquals("<state>: stale state head (seq)", ((List<?>) noSeq.get("reasons")).get(((List<?>) noSeq.get("reasons")).size() - 1));
        // a malformed state whose digest cannot be computed reads as the unhashable marker
        Map<String, Object> unh = adv("{'now':1000}", act("review"), CONTRACT_A, null, null, Prohibitions.UNHASHABLE);
        eq("['<state>: malformed monitor state']", unh.get("reasons"));
        Map<String, Object> notUnh = adv("{'now':1000}", act("review"), CONTRACT_A, null, null, "x");
        eq("['<state>: malformed monitor state','<state>: stale state head (digest)']", notUnh.get("reasons"));
    }

    @Test void anUnreadableExpectedHeadFailsClosed() {
        eq("{'ok':false,'violated':['<state>'],'reasons':['<state>: advance error (fail closed)'],'evaluated':" + EV_A_PASS + ",'next':" + S0 + ",'decidedBy':'state'}",
            adv(S0, act("review"), CONTRACT_A, null, "x", null));
    }

    static final String CONTRACT_B = "{'version':1,'principal':'p','clauses':[{'id':'r','kind':'responds_within','p':{'verb':'alarm'},'q':{'verb':'ack'},'within':3}]}";

    @Test void deadlinesAreOpenedCountedDownDischargedAndEventuallyViolated() {
        Map<String, Object> s1 = adv(S0, act("alarm"), CONTRACT_B, null, null, null);
        assertEquals(Boolean.TRUE, s1.get("ok"));
        eq("{'r':3}", m(s1.get("next")).get("deadlines"));
        Map<String, Object> s2 = Contracts.advanceContract(s1.get("next"), j(act("read")), j(CONTRACT_B), null, null, null);
        eq("{'r':2}", m(s2.get("next")).get("deadlines"));
        Map<String, Object> s3 = Contracts.advanceContract(s2.get("next"), j(act("read")), j(CONTRACT_B), null, null, null);
        eq("{'r':1}", m(s3.get("next")).get("deadlines"));
        Map<String, Object> s4 = Contracts.advanceContract(s3.get("next"), j(act("read")), j(CONTRACT_B), null, null, null);
        assertEquals(Boolean.FALSE, s4.get("ok"));
        assertEquals("contract", s4.get("decidedBy"));
        assertSame(s3.get("next"), s4.get("next"));
        eq("['r']", s4.get("violated"));
        eq("['r: bounded-liveness deadline missed (no q within 3 actions of p)']", s4.get("reasons"));
        // a response discharges: the deadlines key disappears with the last deadline
        Map<String, Object> ack = Contracts.advanceContract(s2.get("next"), j(act("ack")), j(CONTRACT_B), null, null, null);
        assertEquals(Boolean.TRUE, ack.get("ok"));
        assertFalse(m(ack.get("next")).containsKey("deadlines"));
        // a first action that opens nothing leaves no deadlines key either
        Map<String, Object> idle = adv(S0, act("read"), CONTRACT_B, null, null, null);
        assertFalse(m(idle.get("next")).containsKey("deadlines"));
        // deadlines of other clauses carry over untouched
        Map<String, Object> keep = adv("{'now':1000,'seq':0,'parent':null,'ledger':{},'latched':{},'deadlines':{'zz':5}}", act("read"), CONTRACT_B, null, null, null);
        assertEquals(Boolean.TRUE, keep.get("ok"));
        eq("{'zz':5}", m(keep.get("next")).get("deadlines"));
        Map<String, Object> both = adv("{'now':1000,'seq':0,'parent':null,'ledger':{},'latched':{},'deadlines':{'zz':5}}", act("alarm"), CONTRACT_B, null, null, null);
        eq("{'zz':5,'r':3}", m(both.get("next")).get("deadlines"));
        // an open deadline in a state that carries none is the clause's own only
        Map<String, Object> notMap = adv("{'now':1000,'seq':0,'parent':null,'ledger':{},'latched':{}}", act("alarm"), CONTRACT_B, null, null, null);
        eq("{'r':3}", m(notMap.get("next")).get("deadlines"));
    }

    @Test void aStateAtTheDeadlineKeyLimitCannotTakeAnotherDeadline() {
        Map<String, Object> state = Prohibitions.emptyState(j("1000"));
        Map<String, Object> dl = new LinkedHashMap<>();
        for (int i = 0; i < 1024; i++) dl.put("d" + i, j("5"));
        state.put("deadlines", dl);
        assertNull(Prohibitions.stateProblem(state));
        Map<String, Object> r = Contracts.advanceContract(state, j(act("alarm")), j(CONTRACT_B), null, null, null);
        assertEquals(Boolean.FALSE, r.get("ok"));
        eq("['<state>']", r.get("violated"));
        eq("['<state>: resulting state invalid: malformed monitor state: too many deadline keys']", r.get("reasons"));
        eq("[" + row("r", "responds_within", true, null) + "]", r.get("evaluated"));
        assertEquals("state", r.get("decidedBy"));
        assertSame(state, r.get("next"));
    }

    @Test void aContractWithOnlyInvariantsAdvancesToo() {
        String c = "{'version':1,'principal':'p','invariants':[{'id':'cap1','kind':'rate','when':{'verb':'x'},'max':5,'window_secs':60}]}";
        Map<String, Object> r = adv(S0, act("x"), c, null, null, null);
        assertEquals(Boolean.TRUE, r.get("ok"));
        assertEquals("none", r.get("decidedBy"));
        eq("1", m(r.get("next")).get("seq"));
        eq("{}", m(r.get("next")).get("latched"));
        eq("{'cap1':[{'t':1000,'amount':1}]}", m(r.get("next")).get("ledger"));
        assertFalse(m(r.get("next")).containsKey("deadlines"));
        // no invariants and no clauses at all
        Map<String, Object> empty = adv(S0, act("x"), "{'version':1,'principal':'p'}", null, null, null);
        assertEquals(Boolean.TRUE, empty.get("ok"));
        eq("1", m(empty.get("next")).get("seq"));
        eq("[]", empty.get("evaluated"));
    }

    // ---- checkAndAdvanceContract ----------------------------------------------------------------------------------------

    static Map<String, Object> both(boolean permitted, String action) {
        return Contracts.checkAndAdvanceContract(permitted, j(S0), j(action), j(CONTRACT_A), null, null, null);
    }

    @Test void allowIsPermittedAndTheContractHolds() {
        Map<String, Object> r = both(true, act("review"));
        assertEquals(new HashSet<>(Arrays.asList("ok", "violated", "reasons", "evaluated", "next", "decidedBy", "allow", "permitted")), r.keySet());
        assertEquals(Boolean.TRUE, r.get("ok"));
        assertEquals(Boolean.TRUE, r.get("allow"));
        assertEquals(Boolean.TRUE, r.get("permitted"));
        assertEquals("none", r.get("decidedBy"));
        eq("1", m(r.get("next")).get("seq"));
    }

    @Test void notPermittedDeniesButRunsTheMonitorAndKeepsTheOldState() {
        Object state = j(S0);
        Map<String, Object> r = Contracts.checkAndAdvanceContract(false, state, j(act("review")), j(CONTRACT_A), null, null, null);
        assertEquals(new HashSet<>(Arrays.asList("ok", "violated", "reasons", "evaluated", "next", "decidedBy", "allow", "permitted")), r.keySet());
        assertEquals(Boolean.FALSE, r.get("ok"));
        assertEquals(Boolean.FALSE, r.get("allow"));
        assertEquals(Boolean.FALSE, r.get("permitted"));
        assertEquals("contract", r.get("decidedBy"));
        assertSame(state, r.get("next"));
        eq("[]", r.get("violated"));
        eq("['<permission>: not permitted']", r.get("reasons"));
        eq(EV_A_PASS, r.get("evaluated"));
    }

    @Test void aContractViolationDeniesWhateverThePermission() {
        for (boolean permitted : new boolean[] {true, false}) {
            Map<String, Object> r = both(permitted, act("delete"));
            assertEquals(Boolean.FALSE, r.get("ok"));
            assertEquals(Boolean.FALSE, r.get("allow"));
            assertEquals(Boolean.valueOf(permitted), r.get("permitted"));
            assertEquals("contract", r.get("decidedBy"));
            eq("['nodel']", r.get("violated"));
            eq("['nodel: never-invariant violated (forbidden action)']", r.get("reasons"));
        }
        Map<String, Object> st = Contracts.checkAndAdvanceContract(true, j("{'now':1}"), j(act("review")), j(CONTRACT_A), null, null, null);
        assertEquals("state", st.get("decidedBy"));
        assertEquals(Boolean.FALSE, st.get("allow"));
        assertEquals(Boolean.TRUE, st.get("permitted"));
    }
}
