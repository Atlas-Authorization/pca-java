package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** A grant carrying a template_ref must hold exactly the policy the reference denotes (requireLinkedTemplate's check), over the shared link vectors. */
class PolicyLinkVerifyTest {
    @Test void aLinkedGrantHoldsExactlyTheInstantiation() throws Exception {
        Map<String, Object> c = K05R5G3PolicyTest.caseNamed("a reference resolves");
        Map<String, Object> reg = PolicyAuthoringTest.m(c.get("registry"));
        Map<String, Object> policy = PolicyAuthoringTest.m(PolicyAuthoringTest.m(c.get("expect")).get("policy"));
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("template_ref", c.get("ref"));
        env.put("predicates", policy.get("predicates"));
        env.put("caveats", policy.get("caveats"));
        assertNull(PolicyAuthoring.verifyLinkedPolicy(env, reg));
        // the grant's policy edited: refused
        Map<String, Object> edited = new LinkedHashMap<>(env);
        edited.put("caveats", new ArrayList<>());
        assertEquals("grant policy differs from the linked template instantiation", PolicyAuthoring.verifyLinkedPolicy(edited, reg));
        // no link: nothing to verify here (the authorize check refuses it separately)
        Map<String, Object> bare = new LinkedHashMap<>(env);
        bare.remove("template_ref");
        assertNull(PolicyAuthoring.verifyLinkedPolicy(bare, reg));
        // a reference that does not resolve: the resolver's reason
        Map<String, Object> missing = K05R5G3PolicyTest.caseNamed("a registry without the version");
        Map<String, Object> badEnv = new LinkedHashMap<>(env);
        badEnv.put("template_ref", missing.get("ref"));
        assertEquals(PolicyAuthoringTest.m(missing.get("expect")).get("reason"), PolicyAuthoring.verifyLinkedPolicy(badEnv, PolicyAuthoringTest.m(missing.get("registry"))));
    }
}
