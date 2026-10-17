package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Mutation-kill tests for {@link Caveats} (PCA 0.4.1 policy-layer caveats; oracle: {@code envelopeCaveatEvaluator} in
 * packages/pca/src/predicates.ts + {@code max_spend}). {@link Caveats#satisfied} is public and documented as "false
 * (unsatisfied) for anything malformed": every guard is exercised by a DIRECT call, so a removed guard that would surface
 * as a ClassCastException / NullPointerException (masked by the catch in {@link Caveats#evaluateCaveats}) is observed.
 */
public class CaveatsKillTest {
    static Map<String, Object> map(Object... kv) { return PcaUnitTest.map(kv); }
    static List<Object> list(Object... xs) { return R041Test.list(xs); }
    static Json.Num n(String raw) { return new Json.Num(raw); }

    /** satisfied(cv, ctx) must be exactly {@code want} and must not throw. */
    static void sat(boolean want, Object cv, Object ctx) {
        boolean got;
        try {
            got = Caveats.satisfied(cv, ctx);
        } catch (RuntimeException e) {
            throw new AssertionError("satisfied threw " + e + " for " + cv + " / " + ctx, e);
        }
        assertEquals(want, got, cv + " / " + ctx);
    }

    static Map<String, Object> now() { return map("now", n("1000")); }

    @Test void resultIsImmutableAndPrints() {
        Caveats.Result r = Caveats.evaluateCaveats(list(map("type", "note")), now());
        assertThrows(UnsupportedOperationException.class, () -> r.failed.add("x"));
        assertEquals("Result{ok=false, failed=[note]}", r.toString());
        assertEquals("Result{ok=true, failed=[]}", Caveats.evaluateCaveats(list(), now()).toString());
    }

    @Test void rootCaveatsSkipsNonObjectEntries() {
        Map<String, Object> env = map("type", "envelope");
        Json.Num one = n("1");
        assertEquals(list("x", one), Caveats.rootCaveats(map("caveats", list("x", env, one))));
        assertEquals(list("x", null), Caveats.rootCaveats(map("caveats", list("x", null))));
    }

    @Test void evaluatorExceptionIsUnsatisfied() {
        Map<String, Object> throwingCtx = new HashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("boom"); }
        };
        Caveats.Result r = Caveats.evaluateCaveats(list(map("type", "expires", "at", n("2000"))), throwingCtx);
        assertFalse(r.ok);
        assertEquals(List.of("expires"), r.failed);
    }

    @Test void nonObjectCaveatOrContext() {
        sat(false, "x", now());
        sat(false, null, now());
        sat(false, list(), now());
        sat(false, map("type", "expires", "at", n("2000")), "ctx");
        sat(false, map("type", "expires", "at", n("2000")), null);
        sat(false, map("type", "max_spend", "usd", n("1")), "ctx");
        sat(true, map("type", "expires", "at", n("2000")), now());
    }

    @Test void missingNowOrNonStringType() {
        sat(false, map("type", "expires", "at", n("2000")), map());
        sat(false, map("type", "not_before", "at", n("0")), map());
        sat(false, map("type", n("1")), now());
        sat(false, map("type", null), now());
        sat(false, map(), now());
        sat(false, map("type", list("expires")), now());
    }

    @Test void expiresAndNotBeforeNeedAt() {
        sat(false, map("type", "expires"), now());
        sat(false, map("type", "expires", "at", "2000"), now());
        sat(false, map("type", "not_before"), now());
        sat(false, map("type", "not_before", "at", "0"), now());
        sat(true, map("type", "not_before", "at", n("1000")), now());
    }

    @Test void rateGuards() {
        Map<String, Object> c = map("now", n("1000"), "recent_action_times", list(n("1000")));
        sat(true, map("type", "rate", "max", n("2"), "per_secs", n("1")), c);
        sat(false, map("type", "rate", "per_secs", n("1")), c);
        sat(false, map("type", "rate", "max", n("2")), c);
        sat(false, map("type", "rate", "max", n("2"), "per_secs", n("-1")), c);
        sat(false, map("type", "rate", "max", n("2"), "per_secs", n("1")), now());
        sat(false, map("type", "rate", "max", n("2"), "per_secs", n("1")), map("now", n("1000"), "recent_action_times", "x"));
        sat(false, map("type", "rate", "max", n("2"), "per_secs", n("1")), map("now", n("1000"), "recent_action_times", map()));
    }

    @Test void blastRadiusDepthBudgetNeedTheirNumbers() {
        Map<String, Object> c = map("now", n("1000"), "blast_radius", n("1"), "delegation_depth", n("1"));
        sat(true, map("type", "max_blast_radius", "max", n("1")), c);
        sat(false, map("type", "max_blast_radius"), c);
        sat(false, map("type", "max_blast_radius", "max", n("1")), now());
        sat(true, map("type", "delegation_depth", "max", n("1")), c);
        sat(false, map("type", "delegation_depth"), c);
        sat(false, map("type", "delegation_depth", "max", n("1")), now());
        sat(true, map("type", "budget_alloc", "limit", n("0")), now());
        sat(false, map("type", "budget_alloc"), now());
        sat(false, map("type", "budget_alloc", "limit", "5"), now());
    }

    @Test void reversibilityMax() {
        Map<String, Object> rev = map("now", n("1000"), "reversibility_class", "reversible");
        // the least severe class bounds itself (index 0 on both sides)
        sat(true, map("type", "reversibility_max", "class", "reversible"), rev);
        sat(true, map("type", "reversibility_max", "class", "irreversible"), rev);
        // an unknown current class is never "no more severe"
        sat(false, map("type", "reversibility_max", "class", "irreversible"), map("now", n("1000"), "reversibility_class", "bogus"));
        sat(false, map("type", "reversibility_max", "class", "bogus"), rev);
        // absent class / absent context class
        sat(false, map("type", "reversibility_max"), rev);
        sat(false, map("type", "reversibility_max", "class", "irreversible"), now());
        sat(false, map("type", "reversibility_max", "class", null), rev);
        sat(false, map("type", "reversibility_max", "class", "irreversible"), map("now", n("1000"), "reversibility_class", null));
    }

    static Map<String, Object> pay(Object params) {
        return map("action", map("verb", "pay", "params", params));
    }

    @Test void maxSpendGuards() {
        // a zero limit admits a zero amount
        sat(true, map("type", "max_spend", "usd", n("0")), pay(map("amount", n("0"))));
        sat(false, map("type", "max_spend", "usd", n("0")), pay(map("amount", n("0.01"))));
        sat(false, map("type", "max_spend"), pay(map("amount", n("0"))));
        sat(false, map("type", "max_spend", "usd", "5"), pay(map("amount", n("0"))));
        sat(false, map("type", "max_spend", "usd", n("5")), map("action", "pay"));
        sat(false, map("type", "max_spend", "usd", n("5")), map());
        sat(false, map("type", "max_spend", "usd", n("5")), pay("x"));
        sat(false, map("type", "max_spend", "usd", n("5")), pay(null));
        sat(false, map("type", "max_spend", "usd", n("5")), map("action", map("verb", "pay")));
        sat(false, map("type", "max_spend", "usd", n("5")), pay(map()));
        sat(false, map("type", "max_spend", "usd", n("5")), pay(map("amount", "1")));
        sat(false, map("type", "max_spend", "usd", n("5")), pay(map("amount", null)));
        sat(false, map("type", "max_spend", "usd", n("5")), pay(map("amount", n("-0.5"))));
    }

    @Test void finNumbers() {
        assertEquals(1.5d, Caveats.fin(1.5f));
        assertEquals(3d, Caveats.fin((short) 3));
        assertEquals(-4d, Caveats.fin((byte) -4));
        assertEquals(10d, Caveats.fin(BigInteger.TEN));
        assertEquals(7d, Caveats.fin(7));
        assertEquals(8d, Caveats.fin(8L));
        assertEquals(2.25d, Caveats.fin(2.25d));
        assertEquals(1e3, Caveats.fin(n("1e3")));
        // an unparseable lexeme is not a number (and not 0)
        assertNull(Caveats.fin(n("abc")));
        assertNull(Caveats.fin(n("1e400")));
        assertNull(Caveats.fin(Float.POSITIVE_INFINITY));
        assertNull(Caveats.fin("1"));
        assertNull(Caveats.fin(true));
        assertNull(Caveats.fin(null));
        // end to end: an unparseable `at` leaves not_before unsatisfied (a mutant reading it as 0 would admit now=1000)
        sat(false, map("type", "not_before", "at", n("abc")), now());
        // programmatic Float / Short / Byte / BigInteger values are numbers for every caveat
        sat(true, map("type", "max_blast_radius", "max", 2.5f), map("now", n("1000"), "blast_radius", (short) 2));
        sat(true, map("type", "delegation_depth", "max", (byte) 3), map("now", n("1000"), "delegation_depth", BigInteger.TWO));
    }
}
