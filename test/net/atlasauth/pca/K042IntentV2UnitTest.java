package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.4.2 mutation kills for {@link IntentV2}: the Java-only surface the differential oracle cannot pin (the exception class
 * name in a fail-closed reason, the receipt suite refusal of a runner without the suite, the {@link IntentV2.Context}
 * factories on a malformed context). Fixtures are the oracle cases of {@link K042IntentV2DiffTest}.
 */
public class K042IntentV2UnitTest {
    @SuppressWarnings("unchecked")
    static Map<String, Object> caseNamed(String name) throws Exception {
        for (Map<String, Object> c : K042IntentV2DiffTest.all()) if (name.equals(c.get("name"))) return c;
        throw new AssertionError("no case " + name);
    }
    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked")
    static List<Object> list(Object o) { return (List<Object>) o; }
    static Map<String, Object> parse(Object text) { return obj(Json.parseLenient((String) text)); }

    static List<String> render(IntentV2.Decision d) {
        List<String> r = new ArrayList<>();
        for (IntentV2.Check c : d.checks) r.add(c.name + "|" + c.ok + "|" + c.reason);
        return r;
    }

    /** A step that throws fails ITS check with "<check> error (fail closed): <exception class>"; the others still run. */
    @Test void aThrowingStepFailsClosedWithTheExceptionClass() throws Exception {
        Map<String, Object> c = caseNamed("vec/session-g0");
        Map<String, Object> p = parse(c.get("p"));
        obj(p.get("intent_session")).put("seq", "x"); // not a number: the seq read throws inside rule 13 only
        IntentV2.Decision d = IntentV2.decide(p, parse(c.get("grant")), IntentV2.Context.fromJsonText((String) c.get("ctx")), Json.asLong(c.get("now")));
        assertEquals(List.of("schema|true|null", "intent_session|false|intent_session error (fail closed): NullPointerException", "accumulators|true|null"), render(d));
        assertEquals("{\"acc\":{\"trip_spend\":{\"post\":38900}},\"canon\":{\"add_ons\":\"[\\\"none\\\"]\",\"refundable\":\"false\"},\"mon\":{}}", Json.canonicalize(d.env));
    }

    /** The sequenced receipt's alg: a suite this runner lacks (or no runner has) is refused with unsupported_suite. */
    @Test void receiptSuiteRefusal() throws Exception {
        Map<String, Object> c = caseNamed("vec/acc-receipt");
        String base = "the reservation receipt for 'trip_spend'";
        String unsigned = base + " is not signed by a key the session sequencer's root-signed key set lists for its issue time";
        Object[][] algs = {{"fn-dsa-512", base + ": unsupported_suite"}, {"rot13", base + ": unsupported_suite"}, {7L, unsigned}, {"ml-dsa-65", unsigned}, {"ed25519", null}};
        for (Object[] a : algs) {
            Map<String, Object> p = parse(c.get("p"));
            Map<String, Object> ctx = parse(c.get("ctx"));
            Map<String, Object> rc = obj(list(obj(ctx.get("acc")).get("receipts")).get(0));
            rc.put("alg", a[0]);
            obj(list(obj(p.get("intent_session")).get("acc")).get(0)).put("receipt", IntentAcc.receiptDigest(rc));
            IntentV2.Decision d = IntentV2.decide(p, parse(c.get("grant")), IntentV2.Context.fromJson(ctx), Json.asLong(c.get("now")));
            assertEquals("accumulators|" + (a[1] == null) + "|" + a[1], render(d).get(2), String.valueOf(a[0]));
        }
        // no alg at all and a broken signature: not signed (never unsupported_suite)
        Map<String, Object> p = parse(c.get("p"));
        Map<String, Object> ctx = parse(c.get("ctx"));
        Map<String, Object> rc = obj(list(obj(ctx.get("acc")).get("receipts")).get(0));
        rc.remove("alg");
        rc.put("sig", rc.get("sig").toString().substring(0, 10) + "A" + rc.get("sig").toString().substring(11).replace('A', 'B'));
        obj(list(obj(p.get("intent_session")).get("acc")).get(0)).put("receipt", IntentAcc.receiptDigest(rc));
        IntentV2.Decision d = IntentV2.decide(p, parse(c.get("grant")), IntentV2.Context.fromJson(ctx), Json.asLong(c.get("now")));
        assertEquals("accumulators|false|" + unsigned, render(d).get(2));
    }

    /** A malformed context stays malformed through withParams (and never throws). */
    @Test void malformedContextFactories() throws Exception {
        Map<String, Object> c = caseNamed("vec/session-g0");
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("total", 1L);
        for (IntentV2.Context ctx : new IntentV2.Context[] {IntentV2.Context.fromJson(7L).withParams(params), IntentV2.Context.fromJsonText("[1]").withParams(params),
                IntentV2.Context.fromJsonText("null").withParams(null)}) {
            IntentV2.Decision d = IntentV2.decide(parse(c.get("p")), parse(c.get("grant")), ctx, Json.asLong(c.get("now")));
            String r = "malformed v2 context: the v2 verifier context must be an object";
            assertEquals(List.of("schema|false|" + r, "intent_session|false|" + r, "accumulators|false|" + r), render(d));
            assertTrue(d.env.isEmpty());
            assertFalse(ctx.wellFormed);
            assertEquals(List.of("params"), new ArrayList<>(ctx.raw.keySet()));
        }
        // a well-formed context: withParams is a copy (the original keeps its params) with normalized numbers
        IntentV2.Context ctx = IntentV2.Context.fromJsonText((String) c.get("ctx"));
        IntentV2.Context w = ctx.withParams(Json.parseLenient("{\"total\":3.89e4}"));
        assertTrue(w.wellFormed);
        assertEquals("{\"total\":38900}", Json.canonicalize(w.raw.get("params")));
        assertEquals("38900", Json.canonicalize(obj(ctx.raw.get("params")).get("total")));
        assertNotSame(ctx.raw, w.raw);
        assertEquals(ctx.raw.keySet(), w.raw.keySet());
        assertNull(IntentV2.Context.fromJsonText("{\"a\":1}").get("b"));
    }
}
