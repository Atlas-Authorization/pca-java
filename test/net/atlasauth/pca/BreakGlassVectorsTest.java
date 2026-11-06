package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The break-glass corpus (break-glass-vectors.json). A missing file FAILS. */
public class BreakGlassVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("break-glass-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void scenarios() {
        assertTrue(l(DOC.get("scenarios")).size() >= 10);
        for (Object sx : l(DOC.get("scenarios"))) {
            Map<String, Object> s = m(sx);
            List<String> reviewers = new ArrayList<>(List.of((String) DOC.get("reviewer")));
            if (s.containsKey("extra_reviewers")) for (Object x : l(s.get("extra_reviewers"))) reviewers.add((String) x);
            BreakGlass.Registry reg = new BreakGlass.Registry(List.of((String) DOC.get("authority")), reviewers);
            for (Object stx : l(s.get("steps"))) {
                Map<String, Object> st = m(stx);
                String op = (String) st.get("op"), label = s.get("name") + ": " + op;
                Object now = st.get("now");
                switch (op) {
                    case "accept" -> assertEquals(Json.canonicalizeStrict(st.get("expect")), Json.canonicalizeStrict(reg.accept(l(DOC.get("grants")).get((int) Json.asLong(st.get("grant"))), now)), label);
                    case "use" -> assertEquals(Json.canonicalizeStrict(st.get("expect")), Json.canonicalizeStrict(reg.use(st.get("id"), st.get("holder"), st.get("action_digest"), now, st.get("notified"))), label);
                    case "review" -> assertEquals(Json.canonicalizeStrict(st.get("expect")), Json.canonicalizeStrict(reg.review(l(DOC.get("reviews")).get((int) Json.asLong(st.get("review"))), st.get("holder"), now)), label);
                    case "frozen" -> assertEquals(st.get("expect"), reg.frozen(st.get("holder"), now), label);
                    default -> throw new AssertionError("unknown op " + op);
                }
            }
        }
    }

    @Test void totalOnHostileInput() {
        BreakGlass.Registry reg = new BreakGlass.Registry(List.of(), List.of());
        for (Object x : new Object[] {null, "x", 1, List.of(), Map.of()}) {
            assertFalse(BreakGlass.verify(x));
            assertFalse(BreakGlass.verifyReview(x));
            assertEquals("bad_record", reg.accept(x, 1L).get("code"));
            assertEquals("bad_record", reg.review(x, "h", 1L).get("code"));
            if (!"x".equals(x)) assertEquals("bad_input", reg.use(x, "h", "a", 1L, true).get("code"));
            if (!"x".equals(x)) assertTrue(reg.frozen(x, 1L));
        }
    }
}
