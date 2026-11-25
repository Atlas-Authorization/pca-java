package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Authorize over grants whose id or issuer is not a string, and the replay branch of the escalation decision. */
class AuthorizeNonStringIdsPitKill2Test {
    static final Map<String, Object> GRANT = AuthorizeK05KillTest.GRANT;
    static final String ISSUER = (String) GRANT.get("issuer");

    @AfterEach void clearHook() { Authorize.coreHook = null; }

    /** Every value a hostile store could hand back for a field the protocol defines as a string. */
    static List<Object> nonStrings() {
        List<Object> l = new ArrayList<>();
        l.add(IntentJs.ofLong(7));
        l.add(Boolean.TRUE);
        l.add(null);
        l.add(new LinkedHashMap<String, Object>(Map.of("a", IntentJs.ofLong(1))));
        l.add(new ArrayList<Object>(List.of("x")));
        return l;
    }

    static Map<String, Object> with(String key, Object value) {
        Map<String, Object> g = new LinkedHashMap<>(GRANT);
        g.put(key, value);
        return g;
    }

    /** A last-store that records the calls made to it. */
    static final class RecStore implements StateStore, LastStore {
        final MemoryStateStore m = new MemoryStateStore();
        final List<String> budgetKeys = new ArrayList<>(), lastKeys = new ArrayList<>();
        @Override public StateStore.ClaimResult claim(String key, long counter) { return m.claim(key, counter); }
        @Override public boolean holdsBudgets() { return true; }
        @Override public Map<String, Object> budget(String key) { budgetKeys.add(String.valueOf(key)); return m.budget(key); }
        @Override public StateStore.ClaimResult claim(String key, long counter, Map<String, Object> before, Map<String, Object> after) { return m.claim(key, counter, before, after); }
        @Override public Long last(String key) { lastKeys.add(key); return m.last(key); }
    }

    static Authorize.AuthorizeResult withBeacon(Map<String, Object> grant, StateStore store) {
        // a beacon scoped to another grant: a grant without a string id skips the scope check
        Map<String, Object> b = BeaconTest.beacon("inst", "another-grant", 5, BeaconTest.ISSUED, BeaconTest.ISSUED + 300_000L, BeaconTest.ISSUER);
        Map<String, Object> bcCtx = AuthorizeGatesPitKill1Test.bc(b);
        Map<String, Object> fr = new LinkedHashMap<>();
        fr.put("beacon_ref", Beacons.ref(b));
        fr.put("epoch", IntentJs.ofLong(1));
        fr.put("accumulator_witness", "");
        return Authorize.authorize(K05ParityAuditTest.agentSigned("freshness", fr),
            AuthorizeK05KillTest.input(Map.of("amount", 50L)).resolveGrant(ref -> grant).stateStore(store).context(p -> Map.of("beacon", bcCtx)));
    }

    @Test void aGrantIdThatIsNotAStringHasNoBeaconScopeNoPinAndNoBudgetKey() {
        for (Object bad : nonStrings()) {
            RecStore store = new RecStore();
            Authorize.AuthorizeResult r = withBeacon(with("id", bad), store);
            String what = String.valueOf(bad) + " " + r.reasons;
            assertFalse(r.checks.containsKey("authorize"), what);
            assertFalse(r.allow, what);
            assertEquals("pass", r.checks.get("beacon"), what);
            assertEquals("fail", r.checks.get("grant_ref"), what);
            assertTrue(r.reasons.contains("grant_ref: does not reference the supplied grant"), what);
            assertEquals(List.of(), store.budgetKeys, what);
            assertEquals(List.of(), store.lastKeys, what);
        }
        // the same beacon against a string id is scoped to it
        Authorize.AuthorizeResult scoped = withBeacon(GRANT, new RecStore());
        assertEquals("fail", scoped.checks.get("beacon"), scoped.reasons.toString());
        assertTrue(scoped.reasons.contains("beacon: scope not covered"), scoped.reasons.toString());
    }

    @Test void aStringIdReadsTheBudgetAndTheCounterPins() {
        RecStore store = new RecStore();
        Authorize.AuthorizeResult r = Authorize.authorize(AuthorizeK05KillTest.pcactn(), AuthorizeK05KillTest.input(Map.of("amount", 50L)).stateStore(store));
        assertTrue(r.allow, r.reasons.toString());
        String key = Authorize.stateKey((String) GRANT.get("id"), AuthorizeK05KillTest.AGENT.id());
        assertTrue(store.budgetKeys.contains(key), store.budgetKeys.toString());
        assertTrue(store.lastKeys.contains(key), store.lastKeys.toString());
    }

    // ---- the server-side post-quantum pin

    /** A pin table that claims to hold every issuer, so only the issuer's type keeps a non-string issuer out of it. */
    static final class EveryIssuer extends HashMap<String, Object> {
        private static final long serialVersionUID = 1L;
        @Override public boolean containsKey(Object k) { return true; }
        @Override public Object get(Object k) { return "pinned"; }
    }

    static Authorize.AuthorizeResult pinned(Map<String, Object> grant, Map<String, Object> pins) {
        return Authorize.authorize(AuthorizeK05KillTest.pcactn(), AuthorizeK05KillTest.input(Map.of("amount", 50L)).resolveGrant(ref -> grant).pqPins(pins));
    }

    @Test void aNonStringIssuerIsNeverPinned() {
        for (Object bad : nonStrings()) {
            Map<String, Object> classical = with("issuer", bad);
            Authorize.AuthorizeResult c = pinned(classical, new EveryIssuer());
            String what = String.valueOf(bad) + " " + c.reasons;
            assertFalse(c.checks.containsKey("authorize"), what);
            assertEquals("pass", c.checks.get("pq_pin"), what);
            Map<String, Object> pq = with("issuer", bad);
            pq.put("alg", "ml-dsa-65");
            pq.put("pq_pk", "pinned");
            Authorize.AuthorizeResult r = pinned(pq, new EveryIssuer());
            assertFalse(r.checks.containsKey("authorize"), what);
            assertEquals("fail", r.checks.get("pq_pin"), what);
            assertTrue(r.reasons.contains("pq_pin: no server-side PQ pin for the grant issuer (suite ml-dsa-65)"), what);
            // an immutable table refuses a null key: the issuer is not looked up when it is not a string
            Authorize.AuthorizeResult im = pinned(classical, Map.of("k", "v"));
            assertFalse(im.checks.containsKey("authorize"), what);
            assertEquals("pass", im.checks.get("pq_pin"), what);
        }
    }

    @Test void aPinWithoutAStringKeyRefusesTheGrant() {
        Map<String, Object> pins = new HashMap<>();
        pins.put(ISSUER, null);
        Map<String, Object> pq = with("alg", "ml-dsa-65");
        pq.put("pq_pk", "pinned");
        Authorize.AuthorizeResult r = pinned(pq, pins);
        assertFalse(r.checks.containsKey("authorize"), r.reasons.toString());
        assertEquals("fail", r.checks.get("pq_pin"));
        assertTrue(r.reasons.contains("pq_pin: the grant pq_pk does not match the server-side pin"), r.reasons.toString());
        // a pin that is not a string never matches either
        pins.put(ISSUER, IntentJs.ofLong(5));
        Authorize.AuthorizeResult num = pinned(pq, pins);
        assertEquals("fail", num.checks.get("pq_pin"));
        assertTrue(num.reasons.contains("pq_pin: the grant pq_pk does not match the server-side pin"), num.reasons.toString());
        // a matching string pin passes; a non-string pq_pk never matches it
        pins.put(ISSUER, "pinned");
        assertEquals("pass", pinned(pq, pins).checks.get("pq_pin"));
        Map<String, Object> badKey = with("alg", "ml-dsa-65");
        badKey.put("pq_pk", IntentJs.ofLong(5));
        Authorize.AuthorizeResult nk = pinned(badKey, pins);
        assertEquals("fail", nk.checks.get("pq_pin"));
        assertTrue(nk.reasons.contains("pq_pin: the grant pq_pk does not match the server-side pin"), nk.reasons.toString());
    }

    // ---- the principal resolver

    @Test void theResolverIsAskedForAnEmptyIssuerWhenTheGrantNamesNone() {
        for (Object bad : nonStrings()) {
            AtomicReference<String> asked = new AtomicReference<>("unset");
            Map<String, Object> g = with("issuer", bad);
            Authorize.AuthorizeResult r = Authorize.authorize(AuthorizeK05KillTest.pcactn(), AuthorizeK05KillTest.input(Map.of("amount", 50L))
                .resolveGrant(ref -> g).principal((iss, grant) -> { asked.set(iss); return new Authorize.PrincipalInfo(true, "agent", "a1"); }, true));
            String what = String.valueOf(bad) + " " + r.reasons;
            assertFalse(r.checks.containsKey("authorize"), what);
            assertEquals("", asked.get(), what);
            assertEquals("pass", r.checks.get("principal"), what);
        }
        AtomicReference<String> asked = new AtomicReference<>("unset");
        Authorize.AuthorizeResult r = Authorize.authorize(AuthorizeK05KillTest.pcactn(), AuthorizeK05KillTest.input(Map.of("amount", 50L))
            .principal((iss, grant) -> { asked.set(iss); return new Authorize.PrincipalInfo(true, "agent", "a1"); }, true));
        assertEquals(ISSUER, asked.get());
        assertEquals("pass", r.checks.get("principal"), r.reasons.toString());
    }

    // ---- the replay branch of the escalation decision

    /** A last-store that answers its reads in order (then the final answer): a null or a thrown error as scripted. */
    static final class Script implements StateStore, LastStore {
        final MemoryStateStore m = new MemoryStateStore();
        final Object[] answers;
        int reads;
        Script(Object... answers) { this.answers = answers; }
        @Override public StateStore.ClaimResult claim(String key, long counter) { return m.claim(key, counter); }
        @Override public boolean holdsBudgets() { return true; }
        @Override public Map<String, Object> budget(String key) { return m.budget(key); }
        @Override public StateStore.ClaimResult claim(String key, long counter, Map<String, Object> before, Map<String, Object> after) { return m.claim(key, counter, before, after); }
        @Override public Long last(String key) {
            Object a = answers[Math.min(reads++, answers.length - 1)];
            if (a instanceof RuntimeException) throw (RuntimeException) a;
            return (Long) a;
        }
    }

    static Authorize.AuthorizeResult escalating(StateStore store) {
        AuthorizeRunK05bKillTest.escalate();
        return Authorize.authorize(AuthorizeRunK05bKillTest.pcactn(), AuthorizeRunK05bKillTest.input().stateStore(store));
    }

    static long counter() { return Json.asLong(AuthorizeRunK05bKillTest.pcactn().get("counter")); }

    @Test void aStreamThatMovedPastTheCounterWhileEscalatingIsAReplayNamingTheNewHead() {
        long c = counter();
        Authorize.AuthorizeResult r = escalating(new Script(c - 1, c + 3));
        assertEquals("deny", r.decision, r.reasons.toString());
        assertFalse(r.allow);
        assertEquals("fail", r.checks.get("replay"));
        assertNull(r.escalation);
        assertEquals(AuthorizeRunK05bKillTest.ESCALATE_REASON, r.reasons.get(0));
        assertEquals("replay: " + c + " is not greater than last seen " + (c + 3) + " (replay)", r.reasons.get(r.reasons.size() - 1));
    }

    @Test void aStreamWithNoHeadWhileEscalatingStillEscalates() {
        for (StateStore store : new StateStore[] {new Script((Long) null), new Script(counter() - 1, null), new Script(counter() - 1, new IllegalStateException("down")),
            new AuthorizeGatesPitKill1Test.PlainStore()}) {
            Authorize.AuthorizeResult r = escalating(store);
            assertEquals("escalate", r.decision, r.reasons.toString());
            assertEquals("pass", r.checks.get("replay"));
            assertNotNull(r.escalation);
            assertEquals(List.of(AuthorizeRunK05bKillTest.ESCALATE_REASON), r.reasons);
        }
    }
}
