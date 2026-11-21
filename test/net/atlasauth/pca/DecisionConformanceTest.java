package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** The shared vectors for rules 20, 21, the ternary decision and escalation answers (decision-vectors.json). */
public class DecisionConformanceTest {
    static final String FILE = "conformance/decision-vectors.json";

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> table(String name) throws Exception {
        Map<String, Object> d = (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(FILE)));
        return (List<Map<String, Object>>) (List<?>) ((Map<String, Object>) d.get("primitives")).get(name);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    /** `input_text` is raw JSON text each runner parses itself (key order is part of the input); else `input`. */
    static Map<String, Object> inputOf(Map<String, Object> v) {
        return m(v.containsKey("input_text") ? Json.parseLenient((String) v.get("input_text")) : v.get("input"));
    }

    @Test void tableSizes() throws Exception {
        assertEquals(85, table("intent_units").size());
        assertEquals(73, table("intent_tighten").size());
        assertEquals(25, table("decision_of").size());
        assertEquals(31, table("decision_lattice").size());
        assertEquals(18, table("escalation_fold").size());
        assertEquals(11, table("escalation_truncate").size());
        assertEquals(85, table("escalation_answer").size());
    }

    @Test void truncateVectors() throws Exception {
        for (Map<String, Object> v : table("escalation_truncate")) {
            @SuppressWarnings("unchecked")
            List<String> reasons = (List<String>) m(v.get("input")).get("reasons");
            Map<String, Object> req = Escalation.buildRequest("a", Map.of("id", "g"), Map.of("action", Map.of("verb", "v", "resource", "r")), null, reasons, 1L);
            assertEquals(m(v.get("expect")).get("wire"), Escalation.reasonsWire(req), String.valueOf(v.get("name")));
        }
    }

    @Test void unitsVectors() throws Exception {
        for (Map<String, Object> v : table("intent_units")) {
            Decision.UnitsResult r = Decision.decideUnits(inputOf(v));
            assertEquals(m(v.get("expect")).get("ok"), r.ok, v.get("name") + ": " + r.reason);
            assertEquals(m(v.get("expect")).get("reason"), r.reason, String.valueOf(v.get("name")));
            assertEquals(r.ok, r.reason == null, v.get("name") + " reason iff refused");
        }
    }

    @Test void tightenVectors() throws Exception {
        for (Map<String, Object> v : table("intent_tighten")) {
            Decision.TightenResult r = Decision.decideTighten(inputOf(v));
            Map<String, Object> e = m(v.get("expect"));
            assertEquals(e.get("outcome"), r.outcome, v.get("name") + ": " + r.reason);
            assertEquals(e.get("legacy"), r.legacy, String.valueOf(v.get("name")));
            assertEquals(e.get("offending"), r.offending, String.valueOf(v.get("name")));
            assertEquals(e.get("reason"), r.reason, String.valueOf(v.get("name")));
        }
    }

    @Test void decisionOfVectors() throws Exception {
        for (Map<String, Object> v : table("decision_of"))
            assertEquals(m(v.get("expect")).get("decision"), Decision.decisionOf(m(v.get("input"))), String.valueOf(v.get("name")));
    }

    @Test void latticeVectors() throws Exception {
        for (Map<String, Object> v : table("decision_lattice")) {
            String n = (String) v.get("name");
            Map<String, Object> in = m(v.get("input"));
            String got;
            switch (n.substring(0, 3)) {
                case "mee": got = Decision.meet((String) in.get("a"), (String) in.get("b")); break;
                case "pep": got = Decision.pepDecision((String) in.get("decision"), in.get("answered")); break;
                default: got = Decision.tighten((String) in.get("decision"), in.get("signal"));
            }
            assertEquals(m(v.get("expect")).get("decision"), got, n);
        }
    }

    @Test void escalationAnswerVectors() throws Exception {
        int skipped = 0;
        for (Map<String, Object> v : table("escalation_answer")) {
            Map<String, Object> in = inputOf(v);
            Map<String, Object> b = m(in.get("bind"));
            Double d = IntentJs.num(in.get("now"));
            long now = d != null && d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0 ? (long) (double) d : Long.MAX_VALUE; // a non-integer clock is refused
            Object need = v.get("requires_suite");
            if (need != null && !Pq.supportedSuites().contains(need)) {
                // a suite this SDK does not implement is never accepted: the answer is refused as unsupported_suite
                Escalation.Result u = Escalation.verify(in.get("answer"), (List<?>) in.get("principals"),
                    new Escalation.Binding((String) b.get("policy_digest"), (String) b.get("action_digest"), (String) b.get("history_head")), now);
                assertFalse(u.ok, v.get("name") + " must not verify under an unimplemented suite");
                assertTrue(u.reason.contains("unsupported_suite"), v.get("name") + ": " + u.reason);
                skipped++;
                continue;
            }
            Escalation.Result r = Escalation.verify(in.get("answer"), (List<?>) in.get("principals"),
                new Escalation.Binding((String) b.get("policy_digest"), (String) b.get("action_digest"), (String) b.get("history_head")), now);
            Map<String, Object> e = m(v.get("expect"));
            assertEquals(e.get("ok"), r.ok, v.get("name") + ": " + r.reason);
            if (r.ok) {
                assertEquals(e.get("principal"), r.principal, String.valueOf(v.get("name")));
                assertEquals(e.get("decision"), r.decision, String.valueOf(v.get("name")));
            } else {
                assertTrue(r.reason.contains((String) e.get("reason_contains")), v.get("name") + ": " + r.reason);
            }
        }
        // only the suites this SDK does not implement (FN-DSA) may be refused as unsupported
        for (Map<String, Object> v : table("escalation_answer")) {
            Object need = v.get("requires_suite");
            if (need != null && !Pq.supportedSuites().contains(need)) assertTrue(String.valueOf(need).startsWith("fn-dsa"), "unexpected unimplemented suite " + need);
        }
        assertTrue(skipped <= 10, "skipped " + skipped);
    }

    /** The reason fold of authorize: the core reason first, then every failed v2 check's reason not already listed. */
    @Test void escalationFoldVectors() throws Exception {
        for (Map<String, Object> v : table("escalation_fold")) {
            Map<String, Object> in = m(v.get("input"));
            List<String> reasons = new ArrayList<>();
            for (Object r : (List<?>) in.get("core_reasons")) reasons.add((String) r);
            List<IntentV2.Check> v2 = new ArrayList<>();
            for (Object o : (List<?>) in.get("v2")) {
                Map<String, Object> c = m(o);
                v2.add(new IntentV2.Check((String) c.get("name"), Boolean.TRUE.equals(c.get("ok")), (String) c.get("reason")));
            }
            Authorize.foldV2Reasons(reasons, v2);
            Map<String, String> checks = new java.util.LinkedHashMap<>();
            boolean allow = true;
            for (Map.Entry<String, Object> e : m(in.get("checks")).entrySet()) {
                checks.put(e.getKey(), (String) e.getValue());
                if ("fail".equals(e.getValue())) allow = false;
            }
            Map<String, Object> e = m(v.get("expect"));
            assertEquals(e.get("reasons"), reasons, String.valueOf(v.get("name")));
            assertEquals(e.get("decision"), Decision.decisionOf(allow, checks, reasons), String.valueOf(v.get("name")));
        }
    }
}
