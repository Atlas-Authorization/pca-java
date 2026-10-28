package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The typed-missing-context corpus (missing-context-vectors.json). A missing file FAILS. */
public class MissingContextVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("missing-context-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }
    static String canon(Object o) { return Json.canonicalizeStrict(o); }

    @Test void decide() {
        assertTrue(l(DOC.get("decide")).size() >= 26);
        for (Object x : l(DOC.get("decide"))) {
            Map<String, Object> c = m(x);
            assertEquals(canon(c.get("expect")), canon(MissingContext.decide(c.get("where"), c.get("bound"), c.get("supplied"), c.get("suppliers"))), (String) c.get("name"));
        }
    }

    @Test void bind() {
        assertTrue(l(DOC.get("bind")).size() >= 8);
        for (Object x : l(DOC.get("bind"))) {
            Map<String, Object> c = m(x);
            Map<String, Object> table = c.get("suppliers") == null ? new LinkedHashMap<>() : m(c.get("suppliers"));
            assertEquals(canon(c.get("expect")), canon(MissingContext.bindContext(c.get("bound"), c.get("supplied"), table)), (String) c.get("name"));
        }
    }

    @Test void totalOnHostileInput() {
        for (Object x : new Object[] {null, "x", 1, List.of(), Map.of()}) {
            assertEquals("deny", MissingContext.decide(x, x, x, x).get("decision"));
        }
    }
}
