package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The policy-class corpus (policy-classes-vectors.json). A missing file FAILS. */
public class PolicyClassesVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("policy-classes-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void validate() {
        assertTrue(l(DOC.get("validate")).size() >= 10);
        for (Object x : l(DOC.get("validate"))) {
            Map<String, Object> c = m(x);
            assertEquals(m(c.get("expect")).get("ok"), PolicyClasses.listError(c.get("input")) == null, (String) c.get("name"));
        }
    }

    @Test void decide() {
        assertTrue(l(DOC.get("decide")).size() >= 8);
        for (Object x : l(DOC.get("decide"))) {
            Map<String, Object> c = m(x);
            assertEquals(Json.canonicalizeStrict(c.get("expect")), Json.canonicalizeStrict(PolicyClasses.decide(c.get("input"))), (String) c.get("name"));
        }
    }

    @Test void totalOnHostileInput() {
        for (Object x : new Object[] {null, "x", 1, Map.of(), List.of(), List.of(1)}) assertEquals("deny", PolicyClasses.decide(x).get("decision"));
    }
}
