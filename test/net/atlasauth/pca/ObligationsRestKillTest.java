package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Exact-message kill tests for {@link Obligations}: every refusal text, every length bound, merge / gate / outcome in full. */
public class ObligationsRestKillTest {
    static Object j(String s) { return AuthorizeFixtures.j(s); }
    static Map<String, Object> jm(String s) { return AuthorizeFixtures.jm(s); }

    /** A list that answers size / get but refuses to be iterated: drives the fail-closed catch after validation. */
    static List<Object> unIterable(Object... xs) {
        return new ArrayList<Object>(Arrays.asList(xs)) {
            @Override public Iterator<Object> iterator() { throw new IllegalStateException("not iterable"); }
        };
    }

    static String rep(char c, int n) { return String.valueOf(c).repeat(n); }

    static Map<String, Object> ob(String kind, String pk, Object pv) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("kind", kind);
        Map<String, Object> p = new LinkedHashMap<>();
        p.put(pk, pv);
        o.put("params", p);
        return o;
    }

    @Test void memberAndKindErrorsAreExact() {
        assertEquals("an obligation must be an object", Obligations.error("x"));
        assertEquals("an obligation must be an object", Obligations.error(null));
        assertEquals("unknown member 'x'", Obligations.error(j("{'kind':'log','x':1}")));
        assertEquals("unknown obligation kind 'zap'", Obligations.error(j("{'kind':'zap'}")));
        assertEquals("unknown obligation kind ''", Obligations.error(j("{'kind':7}")));
        assertEquals("unknown obligation kind ''", Obligations.error(j("{}")));
        assertEquals("due must be a non-negative safe integer", Obligations.error(j("{'kind':'log','due':-1}")));
        assertEquals("due must be a non-negative safe integer", Obligations.error(j("{'kind':'log','due':'1'}")));
        assertNull(Obligations.error(j("{'kind':'log','due':0}")));
        assertEquals("params must be an object", Obligations.error(j("{'kind':'log','params':'x'}")));
        assertEquals("params must be an object", Obligations.error(j("{'kind':'log','params':[]}")));
        assertNull(Obligations.error(j("{'kind':'log'}")));
        assertNull(Obligations.error(j("{'kind':'log','params':{}}")));
        assertNull(Obligations.error(j("{'kind':'require_receipt'}")));
    }

    @Test void parameterErrorsAndLengthBoundsAreExact() {
        assertEquals("unknown parameter 'x' for 'require_receipt'", Obligations.error(j("{'kind':'require_receipt','params':{'x':1}}")));
        assertEquals("unknown parameter 'to' for 'log'", Obligations.error(j("{'kind':'log','params':{'to':'a'}}")));
        assertEquals("unknown parameter 'sink' for 'notify'", Obligations.error(j("{'kind':'notify','params':{'to':'a','sink':'s'}}")));
        String sink = "log.sink must be a non-empty string of at most 128 characters";
        assertNull(Obligations.error(ob("log", "sink", rep('s', 128))));
        assertEquals(sink, Obligations.error(ob("log", "sink", rep('s', 129))));
        assertEquals(sink, Obligations.error(ob("log", "sink", "")));
        assertEquals(sink, Obligations.error(ob("log", "sink", 5)));
        assertEquals(sink, Obligations.error(ob("log", "sink", null)));
        String to = "notify.to is required (a non-empty string of at most 256 characters)";
        assertNull(Obligations.error(ob("notify", "to", rep('t', 256))));
        assertEquals(to, Obligations.error(ob("notify", "to", rep('t', 257))));
        assertEquals(to, Obligations.error(j("{'kind':'notify'}")));
        String wm = "watermark.id is required (a non-empty string of at most 128 characters)";
        assertNull(Obligations.error(ob("watermark", "id", rep('w', 128))));
        assertEquals(wm, Obligations.error(ob("watermark", "id", rep('w', 129))));
        assertEquals(wm, Obligations.error(j("{'kind':'watermark'}")));
        String uw = "undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)";
        assertNull(Obligations.error(j("{'kind':'undo_window','params':{'id':'u','window_end':0}}")));
        assertEquals(uw, Obligations.error(j("{'kind':'undo_window','params':{'id':'u'}}")));
        assertEquals(uw, Obligations.error(j("{'kind':'undo_window','params':{'id':'','window_end':5}}")));
        assertEquals(uw, Obligations.error(j("{'kind':'undo_window','params':{'id':'u','window_end':-1}}")));
    }

    @Test void redactFieldsAreBoundedPathsWithoutDuplicates() {
        String bad = "redact.fields must be 1..32 dotted field paths";
        List<Object> f32 = new ArrayList<>(), f33 = new ArrayList<>();
        for (int i = 0; i < 33; i++) { if (i < 32) f32.add("f" + i); f33.add("f" + i); }
        assertNull(Obligations.error(ob("redact", "fields", f32)));
        assertEquals(bad, Obligations.error(ob("redact", "fields", f33)));
        assertEquals(bad, Obligations.error(ob("redact", "fields", new ArrayList<>())));
        assertEquals(bad, Obligations.error(ob("redact", "fields", "a")));
        assertEquals(bad, Obligations.error(j("{'kind':'redact'}")));
        assertEquals(bad, Obligations.error(j("{'kind':'redact','params':{'fields':[5]}}")));
        assertEquals(bad, Obligations.error(j("{'kind':'redact','params':{'fields':['a','a..b']}}")));
        assertEquals("redact.fields has a duplicate", Obligations.error(j("{'kind':'redact','params':{'fields':['a','b.c','a']}}")));
        assertNull(Obligations.error(j("{'kind':'redact','params':{'fields':['a','b.c']}}")));
    }

    @Test void keysCarryTheDueOnlyWhenPresent() {
        assertEquals("{\"kind\":\"log\",\"params\":{}}", Obligations.key(jm("{'kind':'log'}")));
        assertEquals("{\"due\":5,\"kind\":\"log\",\"params\":{}}", Obligations.key(jm("{'kind':'log','due':5}")));
        assertEquals("{\"due\":0,\"kind\":\"notify\",\"params\":{\"to\":\"a\"}}", Obligations.key(jm("{'kind':'notify','params':{'to':'a'},'due':0}")));
    }

    @Test void listErrorsAreExact() {
        assertNull(Obligations.listError(null));
        assertEquals("obligations must be an array", Obligations.listError("x"));
        List<Object> seventeen = new ArrayList<>();
        for (int i = 0; i < 17; i++) seventeen.add(ob("watermark", "id", "w" + i));
        assertEquals("more than 16 obligations", Obligations.listError(seventeen));
        assertNull(Obligations.listError(new ArrayList<>(seventeen.subList(0, 16))));
        assertEquals("obligations[1]: unknown obligation kind 'zap'", Obligations.listError(j("[{'kind':'log'},{'kind':'zap'}]")));
        assertEquals("obligations[1] duplicates an earlier obligation", Obligations.listError(j("[{'kind':'log'},{'kind':'log','params':{}}]")));
        assertNull(Obligations.listError(j("[{'kind':'log'},{'kind':'log','due':1}]")));
        // a lone surrogate passes the length check but not the strict canonical key: fail closed
        assertEquals("evaluation error (fail closed)", Obligations.listError(List.of(ob("watermark", "id", String.valueOf((char) 0xD800)))));
    }

    @Test void mergeDeduplicatesSortsAndCapsAtSixteen() {
        Obligations.Merge m = Obligations.merge(Arrays.asList(j("[{'kind':'notify','params':{'to':'b'}},{'kind':'log'}]"), null, j("[{'kind':'log'}]")));
        assertTrue(m.ok);
        assertNull(m.reason);
        assertEquals(Json.canonicalize(j("[{'kind':'log'},{'kind':'notify','params':{'to':'b'}}]")), Json.canonicalize(m.obligations));
        List<Object> sixteen = new ArrayList<>();
        for (int i = 0; i < 16; i++) sixteen.add(ob("watermark", "id", "w" + i));
        Obligations.Merge ok16 = Obligations.merge(List.of(sixteen, List.of(ob("watermark", "id", "w0"))));
        assertTrue(ok16.ok);
        assertEquals(16, ok16.obligations.size());
        Obligations.Merge over = Obligations.merge(List.of(sixteen, List.of(ob("watermark", "id", "w16"))));
        assertFalse(over.ok);
        assertNull(over.obligations);
        assertEquals("more than 16 obligations after merging", over.reason);
        Obligations.Merge bad = Obligations.merge(List.of("x"));
        assertFalse(bad.ok);
        assertNull(bad.obligations);
        assertEquals("obligations must be an array", bad.reason);
        Obligations.Merge thrown = Obligations.merge(unIterable(j("[{'kind':'log'}]")));
        assertFalse(thrown.ok);
        assertNull(thrown.obligations);
        assertEquals("evaluation error (fail closed)", thrown.reason);
    }

    static void gate(Obligations.Gate g, String decision, Object perform, List<String> unsupported, String reason) {
        assertEquals(decision, g.decision);
        assertEquals(Json.canonicalize(perform), Json.canonicalize(g.perform));
        assertEquals(unsupported, g.unsupported);
        assertEquals(reason, g.reason);
    }

    @Test void theGateRefusesWhatTheEnforcementPointCannotDo() {
        Object obs = j("[{'kind':'notify','params':{'to':'x'}},{'kind':'redact','params':{'fields':['a']}},{'kind':'log'}]");
        gate(Obligations.gate("allow", null, obs, List.of("redact")), "deny", List.of(), List.of("log", "notify"),
            "the enforcement point does not support obligation(s) log, notify");
        gate(Obligations.gate("allow", null, obs, List.of("redact", "log", "notify")), "allow", obs, List.of(), null);
        gate(Obligations.gate("escalate", true, obs, List.of("redact", "log", "notify")), "allow", obs, List.of(), null);
        gate(Obligations.gate("escalate", false, obs, List.of()), "escalate", List.of(), List.of(), null);
        gate(Obligations.gate("deny", true, obs, List.of()), "deny", List.of(), List.of(), null);
        gate(Obligations.gate("allow", null, null, List.of()), "allow", List.of(), List.of(), null);
        gate(Obligations.gate("allow", null, List.of(), "x"), "deny", List.of(), List.of(), "the supported obligation kinds are malformed");
        gate(Obligations.gate("allow", null, List.of(), j("[5]")), "deny", List.of(), List.of(), "the supported obligation kinds are malformed");
        gate(Obligations.gate("allow", null, j("['x']"), List.of()), "deny", List.of(), List.of(), "malformed obligations: obligations[0]: an obligation must be an object");
        gate(Obligations.gate("allow", null, unIterable(jm("{'kind':'log'}")), List.of("log")), "deny", List.of(), List.of(), "evaluation error (fail closed)");
    }

    static void outcome(Obligations.Outcome o, String outcome, List<Integer> overdue, String status) {
        assertEquals(outcome, o.outcome);
        assertEquals(overdue, o.overdue);
        assertEquals(status, o.status);
    }

    @Test void outcomesNameOverdueObligationsAndMalformedInputIsAllOverdue() {
        outcome(Obligations.outcome(null, List.of(), 5), "ok", List.of(), null);
        outcome(Obligations.outcome(j("[{'kind':'zap'}]"), List.of(), 5), "escalate", List.of(0), "obligation_unmet");
        outcome(Obligations.outcome(j("[{'kind':'log'},{'kind':'notify','params':{'to':'a'}}]"), j("['x']"), 5), "escalate", List.of(0, 1), "obligation_unmet");
        outcome(Obligations.outcome(j("[{'kind':'log'}]"), j("[-1]"), 5), "escalate", List.of(0), "obligation_unmet");
        outcome(Obligations.outcome(j("[{'kind':'log'}]"), "x", 5), "escalate", List.of(0), "obligation_unmet");
        outcome(Obligations.outcome(j("[{'kind':'log'}]"), List.of(), -1), "escalate", List.of(0), "obligation_unmet");
        outcome(Obligations.outcome("x", List.of(), 5), "escalate", List.of(), "obligation_unmet");
        Object two = j("[{'kind':'log','due':5},{'kind':'log','due':6},{'kind':'notify','params':{'to':'a'}}]");
        outcome(Obligations.outcome(two, List.of(), 5), "escalate", List.of(0), "obligation_unmet");
        outcome(Obligations.outcome(two, List.of(), 6), "escalate", List.of(0, 1), "obligation_unmet");
        outcome(Obligations.outcome(two, j("[0]"), 5), "ok", List.of(), null);
        outcome(Obligations.outcome(two, j("[1]"), 6), "escalate", List.of(0), "obligation_unmet");
        outcome(Obligations.outcome(two, List.of(), 4), "ok", List.of(), null);
        outcome(Obligations.outcome(j("[{'kind':'log'}]"), unIterable(), 5), "escalate", List.of(), "obligation_unmet");
    }
}
