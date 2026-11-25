package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * PCA 0.5 mutation kills for {@link PolicyAuthoring} (reference: packages/pca/src/forbid-certificate.ts and policy-link.ts):
 * the forbid-wins table, placeholder splicing, slot domains, the signer gates, the catch-all refusals, and the link resolver.
 */
public class K05R5G3PolicyTest {
    static Object j(String s) { return AuthorizeFixtures.j(s); }

    static Map<String, Object> hostile() {
        return new HashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("hostile"); }
        };
    }

    // ---- forbid-wins certificate --------------------------------------------------------------------------------------

    static String cert(String v, String kind, String decision, String winner, String shadowed, String clauses) {
        return "{'v':" + v + ",'kind':'" + kind + "','decision':'" + decision + "','winner':" + winner + ",'shadowed':" + shadowed + ",'clauses':" + clauses + "}";
    }

    static boolean ok(String cert) { return PolicyAuthoring.forbidCertificateConsistent(j(cert), List.of()); }

    static final String ROW_A = "{'id':'a','kind':'permit','value':'true'}";
    static final String WIN_A = "{'kind':'permit','id':'a'}";

    @Test void aConsistentCertificateIsAccepted() {
        assertTrue(ok(cert("1", "forbid-wins", "allow", WIN_A, "[]", "[" + ROW_A + "]")));
        assertTrue(ok(cert("1", "forbid-wins", "deny", "{'kind':'forbid','id':'f'}", "['p']",
            "[{'id':'p','kind':'permit','value':'true'},{'id':'f','kind':'forbid','value':'true'}]")));
        assertTrue(ok(cert("1", "forbid-wins", "escalate", "{'kind':'escalate','id':'e'}", "['p']",
            "[{'id':'p','kind':'permit','value':'true'},{'id':'e','kind':'escalate','value':'unknown'}]")));
        assertTrue(ok(cert("1", "forbid-wins", "deny", "{'kind':'none','id':null}", "[]", "[]")));
        assertTrue(ok(cert("1", "forbid-wins", "deny", "{'kind':'malformed','id':null}", "[]", "[]")));
    }

    @Test void everyMemberOfTheCertificateIsRequired() {
        String rows = "[" + ROW_A + "]";
        assertFalse(ok(cert("2", "forbid-wins", "allow", WIN_A, "[]", rows)), "version");
        assertFalse(ok(cert("'1'", "forbid-wins", "allow", WIN_A, "[]", rows)), "version text");
        assertFalse(ok(cert("1", "other", "allow", WIN_A, "[]", rows)), "kind");
        assertFalse(ok(cert("1", "forbid-wins", "deny", WIN_A, "[]", rows)), "decision");
        assertFalse(ok(cert("1", "forbid-wins", "allow", "{'kind':'permit','id':'b'}", "[]", rows)), "winner id");
        assertFalse(ok(cert("1", "forbid-wins", "allow", "{'kind':'forbid','id':'a'}", "[]", rows)), "winner kind");
        assertFalse(ok(cert("1", "forbid-wins", "allow", WIN_A, "['x']", rows)), "shadowed");
        assertFalse(ok(cert("1", "forbid-wins", "allow", "'x'", "[]", rows)), "winner not an object");
        assertFalse(ok(cert("1", "forbid-wins", "allow", WIN_A, "'x'", rows)), "shadowed not a list");
        assertFalse(ok(cert("1", "forbid-wins", "allow", WIN_A, "[]", "'x'")), "clauses not a list");
        assertFalse(PolicyAuthoring.forbidCertificateConsistent("x", List.of()));
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(null, null));
    }

    @Test void everyClauseMemberIsRequired() {
        // a row without an id is malformed even when its value is "false" (it would never be a hit)
        assertFalse(ok(cert("1", "forbid-wins", "allow", WIN_A, "[]", "[{'kind':'permit','value':'false'}," + ROW_A + "]")));
        assertFalse(ok(cert("1", "forbid-wins", "allow", WIN_A, "[]", "[{'id':7,'kind':'permit','value':'false'}," + ROW_A + "]")));
        assertFalse(ok(cert("1", "forbid-wins", "allow", WIN_A, "[]", "[{'id':'z','kind':'bad','value':'false'}," + ROW_A + "]")));
        assertFalse(ok(cert("1", "forbid-wins", "allow", WIN_A, "[]", "[{'id':'z','kind':'permit','value':'maybe'}," + ROW_A + "]")));
        assertFalse(ok(cert("1", "forbid-wins", "allow", WIN_A, "[]", "[{'id':'z','kind':'permit'}," + ROW_A + "]")));
        assertFalse(ok(cert("1", "forbid-wins", "allow", WIN_A, "[]", "[5," + ROW_A + "]")));
        // the same row set with a well-formed non-hit row is consistent
        assertTrue(ok(cert("1", "forbid-wins", "allow", WIN_A, "[]", "[{'id':'z','kind':'permit','value':'false'}," + ROW_A + "]")));
    }

    @Test void aCertificateThatCannotBeReadIsInconsistent() {
        assertFalse(PolicyAuthoring.forbidCertificateConsistent(hostile(), List.of()));
    }

    // ---- placeholders --------------------------------------------------------------------------------------------------

    static Object def(String slots, String predicates) {
        return j("{'v':1,'kind':'pca-policy-template','id':'t','version':'1','slots':" + slots + ",'body':{'predicates':" + predicates + "}}");
    }

    static PolicyAuthoring.Result inst(String slotDecl, String placeholder, Object value) {
        Map<String, Object> sl = new LinkedHashMap<>();
        sl.put("s", value);
        return PolicyAuthoring.instantiateTemplate(def("{'s':" + slotDecl + "}", "[{'note':" + placeholder + "}]"), sl);
    }

    static void refused(PolicyAuthoring.Result r, String reason) {
        assertNull(r.policy);
        assertEquals(0, r.overlays);
        assertEquals(reason, r.reason);
    }

    static void spliced(PolicyAuthoring.Result r, Object note) {
        assertNull(r.reason);
        assertEquals(0, r.overlays);
        assertEquals(List.of(Map.of("note", note)), r.policy.get("predicates"));
        assertEquals(List.of(), r.policy.get("caveats"));
    }

    @Test void aRegexPrefixIsRefusedOnlyWhenTheSlotValueProvidesIt() {
        refused(inst("{'type':'string'}", "{'$slot':'s','post':'!'}", "re:abc"), "slot 's' would inject a regex matcher");
        spliced(inst("{'type':'string'}", "{'$slot':'s','post':'!'}", "abc"), "abc!");
        // the template's own prefix is the author's, not an injection
        spliced(inst("{'type':'string'}", "{'$slot':'s','pre':'re:'}", "abc"), "re:abc");
        spliced(inst("{'type':'string'}", "{'$slot':'s','pre':'x','post':'!'}", "re:abc"), "xre:abc!");
        // an unadorned placeholder is the value itself
        spliced(inst("{'type':'string'}", "{'$slot':'s'}", "re:abc"), "re:abc");
    }

    @Test void aSplicedValueMayNotCarryAWildcardNulOrBeNonString() {
        String why = "slot 's' cannot be spliced into a string (wildcard or non-string)";
        refused(inst("{'type':'string'}", "{'$slot':'s','pre':'x-'}", "a*b"), why);
        refused(inst("{'type':'string'}", "{'$slot':'s','post':'-y'}", "a\0b"), why);
        refused(inst("{'type':'integer'}", "{'$slot':'s','pre':'x-'}", new Json.Num("5")), why);
        spliced(inst("{'type':'string'}", "{'$slot':'s','pre':'x-','post':'-y'}", "ab"), "x-ab-y");
    }

    // ---- slot domains --------------------------------------------------------------------------------------------------

    @Test void anIntegerSlotHonoursItsBounds() {
        String d = "{'type':'integer','min':1,'max':1000}";
        refused(inst(d, "{'$slot':'s'}", new Json.Num("0")), "slot 's' is below its minimum");
        refused(inst(d, "{'$slot':'s'}", new Json.Num("1001")), "slot 's' is above its maximum");
        assertNull(inst(d, "{'$slot':'s'}", new Json.Num("1")).reason);
        assertNull(inst(d, "{'$slot':'s'}", new Json.Num("1000")).reason);
        assertNull(inst("{'type':'integer'}", "{'$slot':'s'}", new Json.Num("-5")).reason, "no bounds declared");
        refused(inst(d, "{'$slot':'s'}", "7"), "slot 's' must be a safe integer");
    }

    @Test void aClosedValueSetRefusesAnythingOutsideIt() {
        refused(inst("{'type':'string','values':['a']}", "{'$slot':'s'}", "b"), "slot 's' is outside its closed value set");
        assertNull(inst("{'type':'string','values':['a']}", "{'$slot':'s'}", "a").reason);
        refused(inst("{'type':'set','values':['a','b']}", "{'$slot':'s'}", List.of("a", "c")), "slot 's' has a member outside its closed set");
        assertNull(inst("{'type':'set','values':['a','b']}", "{'$slot':'s'}", List.of("a", "b")).reason);
        refused(inst("{'type':'set','values':['a','b']}", "{'$slot':'s'}", List.of("a", "a")), "slot 's' has duplicate members");
    }

    // ---- catch-all refusals --------------------------------------------------------------------------------------------

    @Test void anInstantiationThatThrowsFailsClosed() {
        Map<String, Object> sl = new LinkedHashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("hostile"); }
        };
        sl.put("s", "abc");
        refused(PolicyAuthoring.instantiateTemplate(def("{'s':{'type':'string'}}", "[{'note':{'$slot':'s'}}]"), sl), "instantiation error (fail closed)");
    }

    @Test void aResolutionThatThrowsFailsClosed() throws Exception {
        Map<String, Object> c = caseNamed("a reference resolves");
        refused(PolicyAuthoring.resolveLink(c.get("ref"), hostile()), "link resolution error (fail closed)");
    }

    @Test void aVerificationThatThrowsFailsClosed() {
        assertEquals("template verification error (fail closed)", PolicyAuthoring.verifyTemplate(hostile(), List.of("k")));
        assertEquals("overlay verification error (fail closed)", PolicyAuthoring.verifyTighten(hostile(), List.of("k")));
    }

    @Test void theRefusalCarriesNoStackTraceAndRecordsNoSuppressed() throws Exception {
        Class<?> c = Class.forName("net.atlasauth.pca.PolicyAuthoring$Refusal");
        Constructor<?> k = c.getDeclaredConstructor(String.class);
        k.setAccessible(true);
        RuntimeException e = (RuntimeException) k.newInstance("m");
        assertEquals("m", e.getMessage());
        assertEquals(0, e.getStackTrace().length, "writableStackTrace is false");
        e.addSuppressed(new RuntimeException("x"));
        assertEquals(0, e.getSuppressed().length, "enableSuppression is false");
    }

    // ---- definitions made of immutable maps (a null probe would throw) -------------------------------------------------

    @Test void immutableDefinitionsAreScannedWithoutNullProbes() {
        Map<String, Object> def = Map.of("v", 1, "kind", "pca-policy-template", "id", "t", "version", "1",
            "slots", Map.of("s", Map.of("type", "string"), "n", Map.of("type", "integer")),
            "body", Map.of("predicates", List.of(Map.of("a", Map.of("$slot", "s"), "b", Map.of("$slot", "n")))));
        assertNull(PolicyAuthoring.templateDefError(def));
    }

    @Test void aNullPlaceholderNameIsRefusedBeforeTheSlotTableIsProbed() {
        Map<String, Object> ph = new HashMap<>();
        ph.put("$slot", null);
        Map<String, Object> def = Map.of("v", 1, "kind", "pca-policy-template", "id", "t", "version", "1",
            "slots", Map.of("s", Map.of("type", "string")), "body", Map.of("predicates", List.of(Map.of("a", ph))));
        assertEquals("placeholder names undeclared slot 'null'", PolicyAuthoring.templateDefError(def));
    }

    // ---- overlays ------------------------------------------------------------------------------------------------------

    @Test void overlayCaveatsMustBeObjectsWithAStringType() {
        String head = "{'v':1,'kind':'pca-template-tighten','template_id':'t','version_digest':'d','add_caveats':";
        String bad = "overlay add_caveats must be a list of caveats";
        assertNull(PolicyAuthoring.tightenOverlayError(j(head + "[{'type':'x'}]}")));
        assertEquals(bad, PolicyAuthoring.tightenOverlayError(j(head + "[{}]}")));
        assertEquals(bad, PolicyAuthoring.tightenOverlayError(j(head + "[{'type':5}]}")));
        assertEquals(bad, PolicyAuthoring.tightenOverlayError(j(head + "[5]}")));
        assertEquals(bad, PolicyAuthoring.tightenOverlayError(j(head + "'x'}")));
    }

    // ---- the link resolver over the shared vectors ---------------------------------------------------------------------

    static Map<String, Object> caseNamed(String prefix) throws Exception {
        for (Map<String, Object> c : PolicyAuthoringTest.list(PolicyAuthoringTest.load("policy-link-vectors.json").get("resolve")))
            if (String.valueOf(c.get("name")).startsWith(prefix)) return c;
        throw new AssertionError("no vector " + prefix);
    }

    static Map<String, Object> verifyCase(String name) throws Exception {
        for (Map<String, Object> c : PolicyAuthoringTest.list(PolicyAuthoringTest.load("policy-link-vectors.json").get("verify")))
            if (name.equals(c.get("name"))) return c;
        throw new AssertionError("no vector " + name);
    }

    @Test void overlaysThatAreNotListsAreRefusedUnlessTheyAreStrings() throws Exception {
        Map<String, Object> c = caseNamed("a reference resolves");
        Map<String, Object> reg = PolicyAuthoringTest.m(c.get("registry"));
        reg.put("overlays", new Json.Num("5"));
        refused(PolicyAuthoring.resolveLink(c.get("ref"), reg), "link resolution error (fail closed)");
        reg.put("overlays", "x");
        PolicyAuthoring.Result r = PolicyAuthoring.resolveLink(c.get("ref"), reg);
        assertNull(r.reason);
        assertEquals(0, r.overlays);
        assertNotNull(r.policy);
    }

    @Test void aRegistryWithoutATemplateTableHasNoTemplateVersion() throws Exception {
        String why = "template version is not in the registry";
        for (Object templates : new Object[] {null, "x", new Json.Num("1"), new LinkedHashMap<String, Object>(), List.of()}) {
            Map<String, Object> c = caseNamed("a reference resolves");
            Map<String, Object> reg = PolicyAuthoringTest.m(c.get("registry"));
            if (templates == null) reg.remove("templates"); else reg.put("templates", templates);
            refused(PolicyAuthoring.resolveLink(c.get("ref"), reg), why);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> firstOverlay(Map<String, Object> reg) {
        return PolicyAuthoringTest.m(((List<Object>) reg.get("overlays")).get(0));
    }

    @Test void onlyAnOverlayForThisTemplateAndVersionIsConsidered() throws Exception {
        Map<String, Object> c = caseNamed("a verified tighten overlay");
        PolicyAuthoring.Result control = PolicyAuthoring.resolveLink(c.get("ref"), c.get("registry"));
        assertNull(control.reason);
        assertEquals(1, control.overlays);

        // another template id (the edit would break the signature, so the overlay must not even be verified)
        Map<String, Object> c2 = caseNamed("a verified tighten overlay");
        PolicyAuthoringTest.m(firstOverlay(PolicyAuthoringTest.m(c2.get("registry"))).get("overlay")).put("template_id", "other_tpl");
        PolicyAuthoring.Result other = PolicyAuthoring.resolveLink(c2.get("ref"), c2.get("registry"));
        assertNull(other.reason);
        assertEquals(0, other.overlays);

        // another version digest
        Map<String, Object> c3 = caseNamed("a verified tighten overlay");
        PolicyAuthoringTest.m(firstOverlay(PolicyAuthoringTest.m(c3.get("registry"))).get("overlay")).put("version_digest", "other");
        PolicyAuthoring.Result ver = PolicyAuthoring.resolveLink(c3.get("ref"), c3.get("registry"));
        assertNull(ver.reason);
        assertEquals(0, ver.overlays);

        // an entry whose overlay is not an object is skipped
        Map<String, Object> c4 = caseNamed("a verified tighten overlay");
        PolicyAuthoringTest.m(c4.get("registry")).put("overlays", new java.util.ArrayList<Object>(List.of(5)));
        PolicyAuthoring.Result bad = PolicyAuthoring.resolveLink(c4.get("ref"), c4.get("registry"));
        assertNull(bad.reason);
        assertEquals(0, bad.overlays);
    }

    @Test void aMissingSignerIsUntrustedEvenAgainstAnImmutableTrustList() throws Exception {
        Map<String, Object> t = verifyCase("signed template under a trusted key");
        Map<String, Object> signed = PolicyAuthoringTest.m(t.get("signed"));
        signed.remove("signer");
        assertEquals("template signer is not trusted", PolicyAuthoring.verifyTemplate(signed, List.of("k")));
        Map<String, Object> o = verifyCase("tighten overlay under a trusted key");
        Map<String, Object> signedO = PolicyAuthoringTest.m(o.get("signed"));
        signedO.remove("signer");
        assertEquals("overlay signer is not trusted", PolicyAuthoring.verifyTighten(signedO, List.of("k")));
    }
}
