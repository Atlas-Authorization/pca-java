package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * Provenance by default: arg-provenance-vectors.json (token matching, leaves, read-only actions and the full decision), computed
 * by the TypeScript reference. Every section is replayed with full equality. A missing file FAILS, it is never skipped.
 */
public class ArgProvenanceVectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("arg-provenance-vectors.json");

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Object> rows(String name) {
        Object x = DOC.get(name);
        assertTrue(x instanceof List && !((List<?>) x).isEmpty(), name + ": missing or empty section");
        return (List<Object>) x;
    }

    static void same(Object want, Object got, String name) {
        assertTrue(IntentJs.jsonEquals(want, got), name + ": want " + want + ", got " + got);
    }

    /** The vector input as the decision's input: absent members stay absent (null), flags default to false. */
    static ArgProvenance.Input input(Map<String, Object> in) {
        ArgProvenance.Input x = new ArgProvenance.Input();
        x.bundle = in.get("bundle");
        x.operation = in.get("operation");
        x.mediators = in.get("mediators");
        x.action = in.get("action");
        x.principalPlan = Boolean.TRUE.equals(in.get("principal_plan"));
        x.principalControl = Boolean.TRUE.equals(in.get("principal_control"));
        x.observed = in.get("observed");
        return x;
    }

    @Test void format() {
        assertEquals("pca-arg-provenance-vectors/1", DOC.get("format"));
        Map<String, Object> pin = m(DOC.get("pin"));
        assertTrue(ArgProvenance.isMediatorPin(pin), "the corpus pin is a mediator pin");
    }

    @Test void tokens() {
        List<Object> rs = rows("tokens");
        assertEquals(18, rs.size());
        for (Object o : rs) {
            Map<String, Object> t = m(o);
            assertEquals(t.get("expect"), ArgProvenance.occursAsToken((String) t.get("text"), (String) t.get("needle")),
                "token '" + t.get("needle") + "' in '" + t.get("text") + "'");
        }
    }

    @Test void leaves() {
        List<Object> rs = rows("leaves");
        assertEquals(11, rs.size());
        for (Object o : rs) {
            Map<String, Object> l = m(o);
            same(l.get("expect"), ArgProvenance.leaves(l.get("value")), "leaves " + l.get("name"));
        }
    }

    @Test void readOnly() {
        List<Object> rs = rows("read_only");
        assertEquals(7, rs.size());
        for (Object o : rs) {
            Map<String, Object> r = m(o);
            assertEquals(r.get("expect"), ArgProvenance.isReadOnlyAction(r.get("action")), "read-only " + r.get("name"));
        }
    }

    @Test void decisions() {
        List<Object> rs = rows("decisions");
        assertEquals(38, rs.size());
        for (Object o : rs) {
            Map<String, Object> c = m(o);
            ArgProvenance.Result d = ArgProvenance.decide(input(m(c.get("input"))));
            Map<String, Object> want = new java.util.LinkedHashMap<>(m(c.get("expect"))), got = d.toJson();
            if ("deny".equals(want.get("outcome"))) {
                // a deny is pinned by its code; its reason text is free but never empty
                assertTrue(d.reason != null && !d.reason.isEmpty(), "decision " + c.get("name") + ": a deny names its reason");
                want.remove("reason");
                got.remove("reason");
            }
            same(want, got, "decision " + c.get("name"));
        }
    }

    @Test void exercisesEveryOutcomeAndCode() {
        Set<Object> outcomes = new HashSet<>(), codes = new HashSet<>();
        for (Object o : rows("decisions")) {
            Map<String, Object> e = m(m(o).get("expect"));
            outcomes.add(e.get("outcome"));
            if (e.get("code") != null) codes.add(e.get("code"));
        }
        assertEquals(Set.of("pass", "escalate", "deny"), outcomes);
        for (String k : new String[] {"untrusted_control", "untrusted_args", "untrusted_control_and_args", "malformed_bundle", "broken_chain",
            "bad_signature", "unbound_action", "content_mismatch", "malformed_action", "malformed_config"})
            assertTrue(codes.contains(k), "the corpus exercises " + k);
    }
}
