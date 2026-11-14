package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills (round 5, tag G2) for {@link ReadVault}: self-signed aggregate and read grants (keys generated here), so the
 * request validation of an aggregate read, the state it returns on a refusal, the shape of a rule, and what the vault records are
 * pinned by exact results of the reference (packages/pca/src/read-vault.ts).
 */
public class K05R5G2ReadVaultTest {

    static final K05R5G2MeshTest.Key P = K05R5G2ReadSideTest.P;
    static final String SALT = "0123456789abcdef";

    static Json.Num n(long v) { return IntentJs.ofLong(v); }
    static Map<String, Object> obj(Object... kv) { return MeshK05KillTest.obj(kv); }
    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }
    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    // ---- aggregate grants ----

    static Map<String, Object> rule(List<Object> purposes) {
        return obj("verb", "orders.stats", "resource_prefix", "orders/", "purposes", purposes, "fns", list("count", "sum"), "min_group", n(1),
            "clamp", n(100), "epsilon_micro", n(0), "dp", Boolean.FALSE);
    }
    static Map<String, Object> aggBody(String principal, Map<String, Object> rule) {
        return obj("v", n(1), "id", "ag1", "principal", principal, "issued_at", n(1000), "expires_at", n(9000), "rules", list(rule),
            "epsilon_budget_micro", n(1000), "max_queries", n(10));
    }
    static Map<String, Object> aggGrant(Map<String, Object> body) {
        return obj("body", body, "sig", K05R5G2ReadSideTest.sign(ReadVault.AGGREGATE_DOMAIN, body, P));
    }
    static final Map<String, Object> GRANT = aggGrant(aggBody(P.pub, rule(list("analytics"))));

    static Map<String, Object> stateOf(long spent, long queries) { return obj("spent_micro", n(spent), "queries", n(queries), "answered", obj()); }

    static ReadVault.Aggregate agg(Object grant, Object verb, Object resource, Object purpose, Object fn, Object values, Object salt, Object noise, Object state) {
        return ReadVault.aggregateRead(grant, P.pub, n(2000), verb, resource, purpose, fn, values, salt, noise, state);
    }
    static ReadVault.Aggregate agg(Object values, Object salt, Object state) {
        return agg(GRANT, "orders.stats", "orders/eu", "analytics", "count", values, salt, "seeded", state);
    }

    @Test void anAggregateReadAnswersAValidRequest() {
        ReadVault.Aggregate a = agg(list(n(1), n(2), n(3)), SALT, ReadVault.State.empty().toMap());
        assertEquals("allow", a.decision);
        assertEquals(Long.valueOf(3), a.value);
        assertEquals(0, a.chargedMicro);
        assertEquals(new ReadVault.State(0, 1, a.state.answered).toMap(), a.state.toMap());
    }

    @Test void saltAndValueBoundsAreExact() {
        Map<String, Object> st = stateOf(5, 2);
        Map<String, Object> want = new ReadVault.State(5, 2, new LinkedHashMap<>()).toMap();
        // salt: 16 characters are enough, 15 are not
        assertEquals("allow", agg(list(n(1)), "0123456789abcdef", st).decision);
        ReadVault.Aggregate shortSalt = agg(list(n(1)), "0123456789abcde", st);
        assertEquals("bad_request", shortSalt.code);
        assertEquals(want, shortSalt.state.toMap());
        // values: 1,000,000 rows are enough, 1,000,001 are not
        List<Object> million = Collections.nCopies(1_000_000, (Object) 1L);
        ReadVault.Aggregate at = agg(million, SALT, st);
        assertEquals("allow", at.decision);
        assertEquals(Long.valueOf(1_000_000), at.value);
        List<Object> over = Collections.nCopies(1_000_001, (Object) 1L);
        ReadVault.Aggregate refused = agg(over, SALT, st);
        assertEquals("deny", refused.decision);
        assertEquals("bad_request", refused.code);
        assertEquals(want, refused.state.toMap());
    }

    @Test void aMalformedRequestKeepsTheInputState() {
        Map<String, Object> st = stateOf(5, 2);
        Map<String, Object> want = new ReadVault.State(5, 2, new LinkedHashMap<>()).toMap();
        Object[][] bad = {
            {GRANT, "", "orders/eu", "analytics", "count", list(n(1)), SALT, "seeded"},
            {GRANT, null, "orders/eu", "analytics", "count", list(n(1)), SALT, "seeded"},
            {GRANT, "orders.stats", "", "analytics", "count", list(n(1)), SALT, "seeded"},
            {GRANT, "orders.stats", "orders/" + "x".repeat(506), "analytics", "count", list(n(1)), SALT, "seeded"},
            {GRANT, "orders.stats", "orders/eu", "bad purpose", "count", list(n(1)), SALT, "seeded"},
            {GRANT, "orders.stats", "orders/eu", null, "count", list(n(1)), SALT, "seeded"},
            {GRANT, "orders.stats", "orders/eu", "analytics", "avg", list(n(1)), SALT, "seeded"},
            {GRANT, "orders.stats", "orders/eu", "analytics", null, list(n(1)), SALT, "seeded"},
            {GRANT, "orders.stats", "orders/eu", "analytics", "count", list(n(1)), SALT, "zzz"},
            {GRANT, "orders.stats", "orders/eu", "analytics", "count", list(n(1)), SALT, null},
            {GRANT, "orders.stats", "orders/eu", "analytics", "count", list(n(1)), null, "seeded"},
            {GRANT, "orders.stats", "orders/eu", "analytics", "count", list(n(1)), n(5), "seeded"},
            {GRANT, "orders.stats", "orders/eu", "analytics", "count", null, SALT, "seeded"},
            {GRANT, "orders.stats", "orders/eu", "analytics", "count", "x", SALT, "seeded"},
            {GRANT, "orders.stats", "orders/eu", "analytics", "count", obj(), SALT, "seeded"},
            {GRANT, "orders.stats", "orders/eu", "analytics", "count", list("a"), SALT, "seeded"},
            {GRANT, "orders.stats", "orders/eu", "analytics", "count", list(new Json.Num("1.5")), SALT, "seeded"},
        };
        for (Object[] row : bad) {
            ReadVault.Aggregate a = agg(row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], st);
            assertEquals("deny", a.decision, Arrays.toString(row));
            assertEquals("bad_request", a.code, Arrays.toString(row));
            assertEquals(want, a.state.toMap(), Arrays.toString(row));
        }
        // a verb the grant does not name is a scope refusal
        ReadVault.Aggregate scope = agg(GRANT, "orders.other", "orders/eu", "analytics", "count", list(n(1)), SALT, "seeded", st);
        assertEquals("no_read_scope", scope.code);
        assertEquals(want, scope.state.toMap());
        // a valid fn / noise pair
        assertEquals("allow", agg(GRANT, "orders.stats", "orders/eu", "analytics", "sum", list(n(1)), SALT, "secure", st).decision);
        assertEquals("allow", agg(GRANT, "orders.stats", "orders/" + "x".repeat(505), "analytics", "sum", list(n(1)), SALT, "seeded", st).decision);
    }

    @Test void aMalformedStateIsRefusedWithTheEmptyStateWhateverElseIsWrong() {
        Map<String, Object> bad = obj("spent_micro", n(-1), "queries", n(0), "answered", obj());
        ReadVault.Aggregate a = agg(null, "orders.stats", "orders/eu", "analytics", "count", list(n(1)), SALT, "seeded", bad);
        assertEquals("bad_request", a.code);
        assertNotNull(a.state);
        assertEquals(ReadVault.State.empty().toMap(), a.state.toMap());
        for (Object s : new Object[] {null, "x", obj(), obj("spent_micro", n(0), "queries", n(0)), obj("spent_micro", n(0), "queries", n(0), "answered", "x"),
                obj("spent_micro", n(0), "queries", n(0), "answered", obj("q", "x")), obj("spent_micro", "0", "queries", n(0), "answered", obj())}) {
            ReadVault.Aggregate r = agg(null, "orders.stats", "orders/eu", "analytics", "count", list(n(1)), SALT, "seeded", s);
            assertEquals("bad_request", r.code, String.valueOf(s));
            assertNotNull(r.state, String.valueOf(s));
            assertEquals(ReadVault.State.empty().toMap(), r.state.toMap(), String.valueOf(s));
        }
    }

    @Test void anAggregateGrantNeedsExactlyBodyAndSig() {
        Map<String, Object> st = stateOf(5, 2);
        Map<String, Object> want = new ReadVault.State(5, 2, new LinkedHashMap<>()).toMap();
        Map<String, Object> extra = new LinkedHashMap<>(GRANT);
        extra.put("extra", n(1));
        Map<String, Object> noSig = new LinkedHashMap<>(GRANT);
        noSig.remove("sig");
        for (Object g : new Object[] {extra, noSig, "x", null, obj("body", "x", "sig", "y")}) {
            ReadVault.Aggregate a = agg(g, "orders.stats", "orders/eu", "analytics", "count", list(n(1)), SALT, "seeded", st);
            assertEquals("bad_grant", a.code, String.valueOf(g));
            assertEquals(want, a.state.toMap());
        }
        // the body names another principal, signed by the caller
        Map<String, Object> other = aggGrant(aggBody(K05R5G2ReadSideTest.Q.pub, rule(list("analytics"))));
        assertEquals("bad_signature", agg(other, "orders.stats", "orders/eu", "analytics", "count", list(n(1)), SALT, "seeded", st).code);
    }

    // ---- aggregate rule shape ----

    @Test void ruleShape() {
        assertTrue(ReadVault.validAggregateGrantBody(aggBody(P.pub, rule(list("analytics")))));
        List<Object> sixteen = new ArrayList<>(), seventeen = new ArrayList<>();
        for (int i = 0; i < 17; i++) {
            if (i < 16) sixteen.add(String.format("p%02d", i));
            seventeen.add(String.format("p%02d", i));
        }
        assertTrue(ReadVault.validAggregateGrantBody(aggBody(P.pub, rule(sixteen))));
        assertFalse(ReadVault.validAggregateGrantBody(aggBody(P.pub, rule(seventeen))));
        assertFalse(ReadVault.validAggregateGrantBody(aggBody(P.pub, rule(list()))));
        assertFalse(ReadVault.validAggregateGrantBody(aggBody(P.pub, rule(list("b", "a")))));
        Map<String, Object> r = rule(list("analytics"));
        r.put("fns", list("count", "sum"));
        assertTrue(ReadVault.validAggregateGrantBody(aggBody(P.pub, r)));
        r.put("fns", list("sum", "count"));
        assertFalse(ReadVault.validAggregateGrantBody(aggBody(P.pub, r)));
        r.put("fns", list("count", "count"));
        assertFalse(ReadVault.validAggregateGrantBody(aggBody(P.pub, r)));
        r.put("fns", list("avg"));
        assertFalse(ReadVault.validAggregateGrantBody(aggBody(P.pub, r)));
        r.put("fns", list());
        assertFalse(ReadVault.validAggregateGrantBody(aggBody(P.pub, r)));
        r.put("fns", list("count", "sum", "zzz"));
        assertFalse(ReadVault.validAggregateGrantBody(aggBody(P.pub, r)));
        Map<String, Object> extra = rule(list("analytics"));
        extra.put("extra", n(1));
        assertFalse(ReadVault.validAggregateGrantBody(aggBody(P.pub, extra)));
        assertFalse(ReadVault.validAggregateGrantBody(aggBody(P.pub, null)));
        Map<String, Object> body = aggBody(P.pub, rule(list("analytics")));
        l(body.get("rules")).set(0, "x");
        assertFalse(ReadVault.validAggregateGrantBody(body));
        Map<String, Object> bodyExtra = aggBody(P.pub, rule(list("analytics")));
        bodyExtra.put("extra", n(1));
        assertFalse(ReadVault.validAggregateGrantBody(bodyExtra));
        assertFalse(ReadVault.validAggregateGrantBody("x"));
        assertFalse(ReadVault.validAggregateGrantBody(null));
        Map<String, Object> clampHigh = rule(list("analytics"));
        clampHigh.put("clamp", n(1_000_001));
        assertFalse(ReadVault.validAggregateGrantBody(aggBody(P.pub, clampHigh)));
        clampHigh.put("clamp", n(1_000_000));
        assertTrue(ReadVault.validAggregateGrantBody(aggBody(P.pub, clampHigh)));
    }

    // ---- the vault ----

    static final String SINK = "sink1";

    static ReadSide.Read redact(Map<String, Object> grant, Object record, ReadVault.VaultStore store) {
        return ReadVault.redactReadWithVault(grant, P.pub, n(2000), "orders.read", "/o/1", "support", K05R5G2ReadSideTest.schema(), record, obj(), SALT, obj(), store);
    }
    static ReadVault.Detok detok(Map<String, Object> grant, Object token, ReadVault.VaultStore store) {
        return ReadVault.detokenize(grant, P.pub, n(2000), SINK, token, store);
    }

    @Test void aTokenisedIntegerComesBackAsAnInteger() {
        Map<String, Object> g = K05R5G2ReadSideTest.grantMode("token");
        ReadVault.VaultStore store = ReadVault.memoryVault();
        ReadSide.Read r = redact(g, K05R5G2ReadSideTest.recordOf("{\"age\":42,\"card\":\"abcdef\"}"), store);
        assertEquals("allow", r.decision);
        Object ageTok = r.view.get("age"), cardTok = r.view.get("card");
        assertTrue(((String) ageTok).startsWith("tok_"));
        ReadVault.Detok d = detok(g, ageTok, store);
        assertEquals("allow", d.decision);
        assertEquals(Long.valueOf(42), d.value);
        assertEquals("abcdef", detok(g, cardTok, store).value);
    }

    @Test void onlyTokensAreRecordedInTheVault() {
        for (String mode : new String[] {"last4", "hash", "show"}) {
            Map<String, Object> g = K05R5G2ReadSideTest.grantMode(mode);
            ReadVault.VaultStore store = ReadVault.memoryVault();
            ReadSide.Read r = redact(g, K05R5G2ReadSideTest.recordOf("{\"card\":\"abcdef\"}"), store);
            assertEquals("allow", r.decision, mode);
            Object shown = r.view.get("card");
            assertNotNull(shown, mode);
            ReadVault.Detok d = detok(g, shown, store);
            assertEquals("deny", d.decision, mode);
            assertEquals("unknown_token", d.code, mode);
        }
        // a bucketed integer is not recorded either (and does not turn the read into a refusal)
        Map<String, Object> g = K05R5G2ReadSideTest.grantMode("bucket:10");
        ReadVault.VaultStore store = ReadVault.memoryVault();
        ReadSide.Read r = redact(g, K05R5G2ReadSideTest.recordOf("{\"age\":42}"), store);
        assertEquals("allow", r.decision);
        assertEquals(Long.valueOf(40), r.view.get("age"));
    }

    @Test void detokenizeRefusesNonStringArguments() {
        Map<String, Object> g = K05R5G2ReadSideTest.grantMode("token");
        ReadVault.VaultStore store = ReadVault.memoryVault();
        ReadSide.Read r = redact(g, K05R5G2ReadSideTest.recordOf("{\"card\":\"abcdef\"}"), store);
        String tok = (String) r.view.get("card");
        assertEquals("allow", detok(g, tok, store).decision);
        for (Object bad : new Object[] {null, n(5), obj(), list()}) {
            ReadVault.Detok d = detok(g, bad, store);
            assertEquals("deny", d.decision);
            assertEquals("bad_request", d.code, String.valueOf(bad));
        }
        assertEquals("bad_request", ReadVault.detokenize(g, P.pub, n(2000), null, tok, store).code);
        assertEquals("bad_request", ReadVault.detokenize(g, P.pub, n(2000), n(1), tok, store).code);
        assertEquals("bad_request", ReadVault.detokenize(g, "x", n(2000), SINK, tok, store).code);
        assertEquals("bad_request", ReadVault.detokenize(g, P.pub, "x", SINK, tok, store).code);
        assertEquals("bad_request", ReadVault.detokenize(g, P.pub, n(-1), SINK, tok, store).code);
        // an invalid grant with a non-string token is still a malformed request, not a grant verdict
        assertEquals("bad_request", ReadVault.detokenize(null, P.pub, n(2000), SINK, null, store).code);
        assertEquals("bad_grant", ReadVault.detokenize(null, P.pub, n(2000), SINK, tok, store).code);
        assertEquals("unknown_token", detok(g, "tok_unknown", store).code);
        assertEquals("unknown_sink", ReadVault.detokenize(g, P.pub, n(2000), "other-sink", tok, store).code);
    }
}
