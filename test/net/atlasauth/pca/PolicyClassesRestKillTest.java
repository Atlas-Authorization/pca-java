package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Exact-message kill tests for {@link PolicyClasses}: every refusal text and bound, and the fail-closed catch. */
public class PolicyClassesRestKillTest {
    static Object j(String s) { return AuthorizeFixtures.j(s); }
    static Map<String, Object> jm(String s) { return AuthorizeFixtures.jm(s); }

    static Map<String, Object> pc(String cls, String decision) {
        Map<String, Object> m = jm("{'class':'org','revision':0,'digest':'d','decision':'allow'}");
        m.put("class", cls);
        m.put("decision", decision);
        return m;
    }

    @Test void listErrorsAreExact() {
        assertEquals("policy classes must be an array", PolicyClasses.listError("x"));
        assertEquals("policy classes must be an array", PolicyClasses.listError(null));
        List<Object> six = new ArrayList<>();
        for (String c : new String[] {"constitution", "regulatory", "org", "blueprint", "user", "org"}) six.add(pc(c, "allow"));
        assertEquals("more than 5 policy classes", PolicyClasses.listError(six));
        assertNull(PolicyClasses.listError(new ArrayList<>(six.subList(0, 5))));
        assertEquals("policy_classes[1] must be an object", PolicyClasses.listError(Arrays.asList(pc("org", "allow"), 5)));
        assertEquals("policy_classes[0] has unknown member 'x'", PolicyClasses.listError(j("[{'class':'org','revision':0,'digest':'d','decision':'allow','x':1}]")));
        assertEquals("policy_classes[0].class is not a known class", PolicyClasses.listError(j("[{'class':'zzz','revision':0,'digest':'d','decision':'allow'}]")));
        assertEquals("policy_classes[0].class is not a known class", PolicyClasses.listError(j("[{'class':5,'revision':0,'digest':'d','decision':'allow'}]")));
        assertEquals("policy_classes[0].class is not a known class", PolicyClasses.listError(j("[{'revision':0,'digest':'d','decision':'allow'}]")));
        assertEquals("policy class 'org' appears twice", PolicyClasses.listError(Arrays.asList(pc("org", "allow"), pc("org", "deny"))));
        assertEquals("policy_classes[0].revision must be a non-negative safe integer", PolicyClasses.listError(j("[{'class':'org','revision':-1,'digest':'d','decision':'allow'}]")));
        assertEquals("policy_classes[0].revision must be a non-negative safe integer", PolicyClasses.listError(j("[{'class':'org','revision':'0','digest':'d','decision':'allow'}]")));
        assertNull(PolicyClasses.listError(j("[{'class':'org','revision':0,'digest':'d','decision':'allow'}]")));
        Map<String, Object> d = pc("org", "allow");
        d.put("digest", "x".repeat(128));
        assertNull(PolicyClasses.listError(List.of(d)));
        d.put("digest", "x".repeat(129));
        assertEquals("policy_classes[0].digest invalid", PolicyClasses.listError(List.of(d)));
        d.put("digest", "");
        assertEquals("policy_classes[0].digest invalid", PolicyClasses.listError(List.of(d)));
        d.put("digest", 5);
        assertEquals("policy_classes[0].digest invalid", PolicyClasses.listError(List.of(d)));
        assertEquals("policy_classes[1].decision must be allow, escalate or deny", PolicyClasses.listError(Arrays.asList(pc("org", "allow"), pc("user", "maybe"))));
    }

    @Test void aThrowingEvaluationFailsClosed() {
        List<Object> l = new ArrayList<Object>(List.of(pc("org", "allow"))) {
            @Override public Iterator<Object> iterator() { throw new IllegalStateException("not iterable"); }
        };
        assertEquals(Json.canonicalize(j("{'decision':'deny','classes':[],'denied_by':[],'escalated_by':[],'reason':'evaluation error (fail closed)'}")),
            Json.canonicalize(PolicyClasses.decide(l)));
    }

    @Test void theMeetNamesWhoSaidNo() {
        assertEquals(Json.canonicalize(j("{'decision':'deny','classes':[{'class':'regulatory','revision':0,'digest':'d','decision':'deny'},"
                + "{'class':'org','revision':0,'digest':'d','decision':'escalate'},{'class':'user','revision':0,'digest':'d','decision':'allow'}],"
                + "'denied_by':['regulatory'],'escalated_by':['org']}")),
            Json.canonicalize(PolicyClasses.decide(Arrays.asList(pc("user", "allow"), pc("org", "escalate"), pc("regulatory", "deny")))));
    }
}
