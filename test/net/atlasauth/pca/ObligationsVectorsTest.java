package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The decision-obligation corpus (obligations-vectors.json). A missing file FAILS. */
public class ObligationsVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("obligations-vectors.json");

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    /** Parsed JSON compared by canonical text (numbers by lexeme, keys sorted). */
    static String canon(Object o) { return Json.canonicalizeStrict(o); }

    @Test void validate() {
        assertFalse(l(DOC.get("validate")).isEmpty());
        for (Object x : l(DOC.get("validate"))) {
            Map<String, Object> c = m(x);
            assertEquals(m(c.get("expect")).get("ok"), Obligations.listError(c.get("input")) == null, (String) c.get("name"));
        }
    }

    @Test void merge() {
        assertFalse(l(DOC.get("merge")).isEmpty());
        for (Object x : l(DOC.get("merge"))) {
            Map<String, Object> c = m(x), e = m(c.get("expect"));
            Obligations.Merge got = Obligations.merge(l(c.get("inputs")));
            assertEquals(e.get("ok"), got.ok, c.get("name") + ": ok");
            if (got.ok) assertEquals(canon(e.get("obligations")), canon(got.obligations), c.get("name") + ": obligations");
        }
    }

    @Test void gate() {
        assertFalse(l(DOC.get("gate")).isEmpty());
        for (Object x : l(DOC.get("gate"))) {
            Map<String, Object> c = m(x), e = m(c.get("expect"));
            Obligations.Gate got = Obligations.gate((String) c.get("decision"), c.get("answered"), c.get("obligations"), c.get("supported"));
            String name = (String) c.get("name");
            assertEquals(e.get("decision"), got.decision, name + ": decision");
            assertEquals(canon(e.get("perform")), canon(got.perform), name + ": perform");
            assertEquals(canon(e.get("unsupported")), canon(new ArrayList<Object>(got.unsupported)), name + ": unsupported");
        }
    }

    @Test void outcome() {
        assertFalse(l(DOC.get("outcome")).isEmpty());
        for (Object x : l(DOC.get("outcome"))) {
            Map<String, Object> c = m(x), e = m(c.get("expect"));
            Obligations.Outcome got = Obligations.outcome(c.get("obligations"), c.get("fulfilled"), c.get("now"));
            String name = (String) c.get("name");
            assertEquals(e.get("outcome"), got.outcome, name + ": outcome");
            assertEquals(e.get("status"), got.status, name + ": status");
            List<Object> want = l(e.get("overdue"));
            assertEquals(want.size(), got.overdue.size(), name + ": overdue size");
            for (int i = 0; i < want.size(); i++) assertEquals(Json.asLong(want.get(i)), (long) got.overdue.get(i), name + ": overdue");
        }
    }
}
