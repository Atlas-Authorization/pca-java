package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * The facade's pure parts: number form, limit parsing, the catalog fallback and policy compilation. Every expected value is the
 * TypeScript reference's output for the same input (facade.ts), except where noted as stricter.
 */
public class FacadeKillTest {
    static String canon(Object o) { return Json.canonicalize(o); }

    static String refusal(Executable e) { return assertThrows(IllegalArgumentException.class, e).getMessage(); }

    static Facade.CompiledPolicy compile(Map<String, Object> permissions, Map<String, Object> limits) {
        return Facade.compilePolicy(permissions, limits, null, null, null, 1_000_000L);
    }

    static Facade.CompiledPolicy compile(Map<String, Object> permissions, Map<String, Object> limits, Catalog catalog, String budgetModel,
                                         Map<String, Object> riskPolicy, long now) {
        return Facade.compilePolicy(permissions, limits, catalog, budgetModel, riskPolicy, now);
    }

    static String limitsJson(Facade.CompiledPolicy p) { return canon(p.toJson().get("limits")); }

    static final String DEFAULT_POLICY = canon(Issue.defaultRiskPolicy());

    /** The policy a dollar limit derives (gamma 1, kappa the largest cap, bMax the sum). */
    static String dollarsPolicy(String kappa, String bMax, String theta1, String theta2) {
        return "{\"bMax\":" + bMax + ",\"kappa\":" + kappa + ",\"lambda\":0,\"rho\":0.5,\"theta1\":" + theta1 + ",\"theta2\":" + theta2
            + ",\"weights\":{\"alpha\":0,\"beta\":0,\"delta\":0,\"epsilon\":0,\"gamma\":1,\"zeta\":0}}";
    }

    static Catalog bank() {
        return new Catalog(List.of(new Catalog.Spec("bank", "transfer", "bank.transfer", "reversible", 0.3, "amt", "t", null, null)));
    }

    // ---- numbers -------------------------------------------------------------------------------------------------------------

    @Test void aSafeIntegerIsALongAndAnythingElseADecimal() {
        assertEquals(5L, Facade.jn(5.0));
        assertEquals(0L, Facade.jn(0.0));
        assertEquals(-3L, Facade.jn(-3.0));
        assertEquals(9007199254740991L, Facade.jn(9007199254740991.0));
        assertEquals(-9007199254740991L, Facade.jn(-9007199254740991.0));
        String[][] dec = {{"0.5", "0.5"}, {"12.5", "12.5"}, {"-0.25", "-0.25"}, {"0.1", "0.1"},
            {"9007199254740992", "9007199254740992"}, {"-9007199254740992", "-9007199254740992"}};
        for (String[] c : dec) {
            Object j = Facade.jn(Double.parseDouble(c[0]));
            assertTrue(j instanceof Json.Num, c[0]);
            assertEquals(c[1], ((Json.Num) j).raw, c[0]);
        }
    }

    @Test void numberTextIsWhatJavaScriptPrints() {
        assertEquals("5", Facade.jsText(5.0));
        assertEquals("12.5", Facade.jsText(12.5));
        assertEquals("1e-7", Facade.jsText(1e-7));
        assertEquals("1e+21", Facade.jsText(1e21));
    }

    // ---- limits --------------------------------------------------------------------------------------------------------------

    static String limit(Object s) { return canon(Facade.parseLimit(s).toJson()); }

    @Test void aLimitIsAnAmountAnOptionalDollarAndAnOptionalPeriod() {
        assertEquals("{\"amount\":500,\"periodMs\":86400000,\"unit\":\"usd\"}", limit("$500/day"));
        assertEquals("{\"amount\":12.5,\"unit\":\"usd\"}", limit("$12.50"));
        assertEquals("{\"amount\":10,\"periodMs\":3600000,\"unit\":\"count\"}", limit("10 / Hours"));
        assertEquals("{\"amount\":3,\"unit\":\"count\"}", limit("3"));
        // zero and fractions are amounts (only a negative or infinite one is refused)
        assertEquals("{\"amount\":0,\"unit\":\"count\"}", limit("0"));
        assertEquals("{\"amount\":0,\"periodMs\":86400000,\"unit\":\"usd\"}", limit("$0/day"));
        assertEquals("{\"amount\":0.5,\"unit\":\"count\"}", limit("0.5"));
        assertEquals("{\"amount\":5,\"periodMs\":1000,\"unit\":\"usd\"}", limit(" $ 5 / s "));
        assertEquals("{\"amount\":5,\"periodMs\":1000,\"unit\":\"count\"}", limit(" 5/SEC﻿"));
        assertEquals("{\"amount\":5,\"unit\":\"count\"}", limit(" 5 "));
        assertEquals("{\"amount\":5,\"periodMs\":86400000,\"unit\":\"count\"}", limit("5 /　d"));
        // the grammar runs on the trimmed text: a leading space before '$' or after the period would not match untrimmed
        assertEquals("{\"amount\":5,\"unit\":\"usd\"}", limit(" $5"));
        assertEquals("{\"amount\":5,\"periodMs\":86400000,\"unit\":\"count\"}", limit("5/day "));
        Facade.ParsedLimit p = Facade.parseLimit("$7.25/week");
        assertEquals(7.25, p.amount, 0.0);
        assertEquals("usd", p.unit);
        assertEquals(604_800_000L, p.periodMs);
        assertNull(Facade.parseLimit("7").periodMs);
        assertEquals("count", Facade.parseLimit("7").unit);
    }

    @Test void everyPeriodNameHasItsLength() {
        Object[][] groups = {{new String[] {"s", "sec", "second", "seconds"}, 1000L}, {new String[] {"m", "min", "minute", "minutes"}, 60_000L},
            {new String[] {"h", "hr", "hour", "hours"}, 3_600_000L}, {new String[] {"d", "day", "days"}, 86_400_000L},
            {new String[] {"w", "week", "weeks"}, 604_800_000L}, {new String[] {"mo", "month", "months"}, 2_592_000_000L}};
        for (Object[] g : groups) for (String n : (String[]) g[0]) {
            assertEquals(g[1], Facade.parseLimit("1/" + n).periodMs, n);
            assertEquals(g[1], Facade.parseLimit("1/" + n.toUpperCase(java.util.Locale.ROOT)).periodMs, n);
        }
        for (String bad : new String[] {"fortnight", "y", "ms", "years", "constructor", "toString", "secs"})
            assertEquals("parseLimit: unknown period '" + bad + "' in '5/" + bad + "'", refusal(() -> Facade.parseLimit("5/" + bad)));
    }

    @Test void aMalformedLimitIsRefusedWithTheReferenceText() {
        for (Object e : new Object[] {null, "", "   ", " ﻿", 5L, new Json.Num("5"), List.of("5"), Issue.obj()})
            assertEquals("parseLimit: empty limit", refusal(() -> Facade.parseLimit(e)), String.valueOf(e));
        for (String bad : new String[] {"abc", "5.", ".5", "-5", "5/", "5/day/x", "$$5", "5 day", "1e3", "١",
            // JavaScript's trim keeps the information separators and U+0085, so the grammar sees them
            "\u001C5", "5\u001F", "\u00855"})
            assertEquals("parseLimit: cannot parse limit '" + bad + "'", refusal(() -> Facade.parseLimit(bad)), bad);
        assertEquals(64, Facade.MAX_LIMIT_LENGTH);
        assertEquals("count", Facade.parseLimit("1".repeat(64)).unit);
        assertEquals("parseLimit: limit is longer than 64 characters", refusal(() -> Facade.parseLimit("1".repeat(65))));
        assertEquals("parseLimit: limit is longer than 64 characters", refusal(() -> Facade.parseLimit(" " + "1".repeat(64))));
    }

    // ---- the catalog fallback ------------------------------------------------------------------------------------------------

    static List<Object> fields(Catalog.Spec s) {
        return List.of(s.connector, s.action, s.verb, s.reversibility, s.blastRadius, s.description, String.valueOf(s.amountField), s.aliases.size(), s.traits.size());
    }

    @Test void aCataloguedVerbOrItsOneAliasIsUsedAsIs() {
        Catalog.Spec s = Catalog.DEFAULT.get("stripe.refund");
        assertSame(s, Facade.specFor(Catalog.DEFAULT, "stripe.refund"));
        assertSame(s, Facade.specFor(Catalog.DEFAULT, "stripe.issue_refund"));
        assertSame(Catalog.DEFAULT.get("stripe.payout"), Facade.specFor(Catalog.DEFAULT, "stripe.pay_out"));
        // a catalogued verb without a connector dot is found by its verb alone
        Catalog solo = new Catalog(List.of(new Catalog.Spec("solo", "solo", "solo", "reversible", 0.1, null, "d", null, null),
            new Catalog.Spec("", "y", ".y", "reversible", 0.1, null, "d", null, null)));
        assertSame(solo.get("solo"), Facade.specFor(solo, "solo"));
        assertSame(solo.get(".y"), Facade.specFor(solo, ".y"));
    }

    @Test void anUncataloguedVerbIsIrreversibleAndWide() {
        assertEquals(List.of("stripe", "unknown", "stripe.unknown", "irreversible", 0.8, "(uncatalogued) stripe.unknown", "null", 0, 0),
            fields(Facade.specFor(Catalog.DEFAULT, "stripe.unknown")));
        assertEquals(List.of("foo", "foo", "foo", "irreversible", 0.8, "(uncatalogued) foo", "null", 0, 0), fields(Facade.specFor(Catalog.DEFAULT, "foo")));
        assertEquals(List.of("a", "b.c", "a.b.c"), fields(Facade.specFor(Catalog.DEFAULT, "a.b.c")).subList(0, 3));
        assertEquals(List.of("a", "a.", "a."), fields(Facade.specFor(Catalog.DEFAULT, "a.")).subList(0, 3));
        assertEquals(List.of("", "x", ".x"), fields(Facade.specFor(Catalog.DEFAULT, ".x")).subList(0, 3));
        assertEquals(List.of("", "", ""), fields(Facade.specFor(Catalog.DEFAULT, "")).subList(0, 3));
        assertEquals(List.of("ab", "cd", "ab.cd"), fields(Facade.specFor(Catalog.DEFAULT, "ab.cd")).subList(0, 3));
    }

    @Test void anAliasLookupNeedsAConnectorBeforeTheDot() {
        Catalog noConnector = new Catalog(List.of(new Catalog.Spec("", "y", ".y", "reversible", 0.1, null, "d", List.of("x"), null)));
        assertEquals("(uncatalogued) .x", Facade.specFor(noConnector, ".x").description);
        Catalog c = new Catalog(List.of(new Catalog.Spec("c", "y", "c.y", "reversible", 0.1, null, "d", List.of("x"), null)));
        assertEquals("c.y", Facade.specFor(c, "c.x").verb);
        assertEquals("(uncatalogued) c.z", Facade.specFor(c, "c.z").description);
        assertEquals("(uncatalogued) cc.x", Facade.specFor(c, "cc.x").description);
    }

    // ---- policy compilation --------------------------------------------------------------------------------------------------

    @Test void aPermissionWithoutLimitsIsOnePredicateAndTheReversibilityCeiling() {
        Facade.CompiledPolicy p = compile(Issue.obj("github", List.of("read")), null);
        assertEquals("[{\"resource\":\"*\",\"verb\":\"github.read\"}]", canon(p.predicates));
        assertEquals("[{\"class\":\"reversible\",\"type\":\"reversibility_max\"}]", canon(p.caveats));
        assertEquals("risk", p.budgetModel);
        assertEquals(DEFAULT_POLICY, canon(p.riskPolicy));
        assertTrue(p.limits.isEmpty());
        assertTrue(p.approximations.isEmpty());
        assertEquals("{}", canon(p.inputLimits));
        assertEquals(1, p.actions.size());
        assertSame(Catalog.DEFAULT.get("github.read"), p.actions.get(0));
    }

    @Test void aDollarLimitBoundsTheAmountAndOpensOneWindow() {
        Map<String, Object> limits = Issue.obj("refund", "$500/day");
        Facade.CompiledPolicy p = compile(Issue.obj("stripe", List.of("refund", "charge")), limits);
        String where = "[{\"field\":\"action.params.amount\",\"op\":\"lte\",\"value\":500},{\"field\":\"action.params.amount\",\"op\":\"gte\",\"value\":0}]";
        assertEquals("[{\"resource\":\"*\",\"verb\":\"stripe.refund\",\"where\":" + where + "},{\"resource\":\"*\",\"verb\":\"stripe.charge\"}]", canon(p.predicates));
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"},{\"at\":87400000,\"type\":\"expires\"}]", canon(p.caveats));
        assertEquals("dollars", p.budgetModel);
        assertEquals("{\"stripe.refund\":{\"amount\":500,\"periodMs\":86400000,\"unit\":\"usd\"}}", limitsJson(p));
        assertEquals(List.of("stripe.refund: $500/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap"), p.approximations);
        assertEquals(canon(limits), canon(p.inputLimits));
        assertEquals(List.of("stripe.refund", "stripe.charge"), verbs(p));
        assertEquals(dollarsPolicy("500", "500", "0.25", "0.6"), canon(p.riskPolicy));
    }

    static List<String> verbs(Facade.CompiledPolicy p) {
        List<String> v = new ArrayList<>();
        for (Catalog.Spec s : p.actions) v.add(s.verb);
        return v;
    }

    @Test void theApproximationNamesTheAmountAsJavaScriptPrintsIt() {
        assertEquals(List.of("stripe.refund: $12.5/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap"),
            compile(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$12.5/week")).approximations);
        assertEquals(List.of("stripe.refund: $1e-7/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap"),
            compile(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$0.0000001/day")).approximations);
        assertEquals(List.of("stripe.refund: $1e+21/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap"),
            compile(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$1000000000000000000000/day")).approximations);
        // a count limit with a window, or a dollar limit without one, is exact
        assertTrue(compile(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$5")).approximations.isEmpty());
        assertTrue(compile(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "5/day")).approximations.isEmpty());
    }

    static String limitOf(Map<String, Object> limits) { return limitsJson(compile(Issue.obj("stripe", List.of("refund")), limits)); }

    @Test void theLimitOfAnActionIsFoundByVerbThenActionThenAliasInOrder() {
        assertEquals("{\"stripe.refund\":{\"amount\":7,\"unit\":\"usd\"}}", limitOf(Issue.obj("stripe.refund", "$7", "refund", "$5")));
        assertEquals("{\"stripe.refund\":{\"amount\":7,\"unit\":\"usd\"}}", limitOf(Issue.obj("stripe.refund", "$7")));
        assertEquals("{\"stripe.refund\":{\"amount\":5,\"unit\":\"usd\"}}", limitOf(Issue.obj("refund", "$5", "issue_refund", "$9")));
        assertEquals("{\"stripe.refund\":{\"amount\":5,\"unit\":\"usd\"}}", limitOf(Issue.obj("issue_refund", "$5", "reimburse", "$9")));
        assertEquals("{\"stripe.refund\":{\"amount\":9,\"unit\":\"usd\"}}", limitOf(Issue.obj("reimburse", "$9")));
        assertEquals("{\"stripe.refund\":{\"amount\":4,\"unit\":\"usd\"}}", limitOf(Issue.obj("refund_charge", "$4")));
        // a null entry is passed over when a later key holds a limit
        assertEquals("{\"stripe.refund\":{\"amount\":3,\"unit\":\"usd\"}}", limitOf(Issue.obj("stripe.refund", null, "refund", "$3")));
        assertEquals("{\"stripe.refund\":{\"amount\":2,\"unit\":\"usd\"}}", limitOf(Issue.obj("issue_refund", null, "reimburse", "$2")));
        assertEquals("{}", limitOf(Issue.obj("charge", "$9")));
        assertEquals("{}", limitOf(Issue.obj()));
        assertEquals("{}", limitOf(null));
    }

    @Test void aLimitGivenAsNullIsRefusedNotDropped() {
        // the reference refuses these too
        assertEquals("parseLimit: empty limit", refusal(() -> limitOf(Issue.obj("reimburse", null))));
        assertEquals("parseLimit: empty limit", refusal(() -> compile(Issue.obj("c", List.of("x")), Issue.obj("x", null))));
        // stricter than the reference, which drops these (its alias scan resets a null to undefined, facade.ts:214)
        assertEquals("parseLimit: empty limit", refusal(() -> limitOf(Issue.obj("refund", null))));
        assertEquals("parseLimit: empty limit", refusal(() -> limitOf(Issue.obj("stripe.refund", null))));
        assertEquals("parseLimit: empty limit", refusal(() -> compile(Issue.obj("c", List.of("x")), Issue.obj("c.x", null))));
    }

    @Test void countLimitsAddOneRateCaveatEachAndTheShortestWindowExpiresTheGrant() {
        Facade.CompiledPolicy p = compile(Issue.obj("slack", List.of("post_message"), "github", List.of("comment", "read")),
            Issue.obj("post_message", "10/hour", "github.comment", "3/min", "read", "2/sec"), null, null, null, 5_000L);
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"},{\"at\":6000,\"type\":\"expires\"},"
            + "{\"max\":10,\"per_secs\":3600,\"type\":\"rate\"},{\"max\":3,\"per_secs\":60,\"type\":\"rate\"},{\"max\":2,\"per_secs\":1,\"type\":\"rate\"}]", canon(p.caveats));
        assertEquals("risk", p.budgetModel);
        assertTrue(p.approximations.isEmpty());
        assertEquals(DEFAULT_POLICY, canon(p.riskPolicy));
        // the shortest window first, and last: the grant expires at the shortest either way
        Facade.CompiledPolicy first = compile(Issue.obj("github", List.of("comment", "read")), Issue.obj("comment", "3/min", "read", "9/hours"), null, null, null, 10L);
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"},{\"at\":60010,\"type\":\"expires\"},"
            + "{\"max\":3,\"per_secs\":60,\"type\":\"rate\"},{\"max\":9,\"per_secs\":3600,\"type\":\"rate\"}]", canon(first.caveats));
        Facade.CompiledPolicy last = compile(Issue.obj("github", List.of("comment", "read")), Issue.obj("comment", "7/day", "read", "9/hours"), null, null, null, 10L);
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"},{\"at\":3600010,\"type\":\"expires\"},"
            + "{\"max\":7,\"per_secs\":86400,\"type\":\"rate\"},{\"max\":9,\"per_secs\":3600,\"type\":\"rate\"}]", canon(last.caveats));
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"},{\"at\":1001000,\"type\":\"expires\"},{\"max\":2.5,\"per_secs\":1,\"type\":\"rate\"}]",
            canon(compile(Issue.obj("github", List.of("comment")), Issue.obj("comment", "2.5/s")).caveats));
        // a count limit without a window adds no rate caveat and no expiry; a dollar limit with one adds no rate caveat
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"}]", canon(compile(Issue.obj("github", List.of("comment")), Issue.obj("comment", "5")).caveats));
        assertEquals("{\"github.comment\":{\"amount\":5,\"unit\":\"count\"}}", limitsJson(compile(Issue.obj("github", List.of("comment")), Issue.obj("comment", "5"))));
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"},{\"at\":87400000,\"type\":\"expires\"}]",
            canon(compile(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$5/day")).caveats));
    }

    @Test void theReversibilityCeilingIsTheStrictestGrantedClass() {
        assertEquals("[{\"class\":\"rate_limited\",\"type\":\"reversibility_max\"}]", canon(compile(Issue.obj("github", List.of("read"), "calendar", List.of("delete_event")), null).caveats));
        assertEquals("[{\"class\":\"rate_limited\",\"type\":\"reversibility_max\"}]", canon(compile(Issue.obj("files", List.of("write"), "github", List.of("read")), null).caveats));
        // a later, milder class never lowers it
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"}]", canon(compile(Issue.obj("stripe", List.of("refund"), "files", List.of("write")), null).caveats));
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"}]", canon(compile(Issue.obj("files", List.of("write"), "stripe", List.of("refund")), null).caveats));
    }

    @Test void anAmountLimitNeedsAnAmountFieldAndACountLimitDoesNot() {
        assertEquals("compilePolicy: '$' limit on 'github.read' but the catalog gives that verb no amount field, so the limit could not be enforced",
            refusal(() -> compile(Issue.obj("github", List.of("read")), Issue.obj("read", "$5"))));
        Facade.CompiledPolicy q = compile(Issue.obj("github", List.of("read")), Issue.obj("read", "5/day"));
        assertEquals("[{\"resource\":\"*\",\"verb\":\"github.read\"}]", canon(q.predicates));
        assertEquals("[{\"class\":\"reversible\",\"type\":\"reversibility_max\"},{\"at\":87400000,\"type\":\"expires\"},{\"max\":5,\"per_secs\":86400,\"type\":\"rate\"}]", canon(q.caveats));
        assertEquals("{\"github.read\":{\"amount\":5,\"periodMs\":86400000,\"unit\":\"count\"}}", limitsJson(q));
    }

    @Test void aLimitThatIsNotAStringIsRefused() {
        assertEquals("parseLimit: empty limit", refusal(() -> compile(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", 5L))));
    }

    @Test void permissionsMustBeArraysAndGrantSomething() {
        assertEquals("compilePolicy: permissions.stripe must be an array", refusal(() -> compile(Issue.obj("stripe", "refund"), null)));
        assertEquals("compilePolicy: permissions.stripe must be an array", refusal(() -> compile(Issue.obj("stripe", null), null)));
        assertEquals("compilePolicy: no permissions granted", refusal(() -> compile(Issue.obj(), null)));
        assertEquals("compilePolicy: no permissions granted", refusal(() -> compile(Issue.obj("stripe", List.of()), null)));
        assertEquals(List.of("github.read"), verbs(compile(Issue.obj("stripe", List.of(), "github", List.of("read")), null)));
    }

    @Test void uncataloguedAndAliasedPermissionsResolveLikeTheReference() {
        Facade.CompiledPolicy p = compile(Issue.obj("a", List.of("b.c", ""), "", List.of("x"), "stripe", List.of("issue_refund", "unknown")), null);
        assertEquals("[{\"resource\":\"*\",\"verb\":\"a.b.c\"},{\"resource\":\"*\",\"verb\":\"a.\"},{\"resource\":\"*\",\"verb\":\".x\"},"
            + "{\"resource\":\"*\",\"verb\":\"stripe.refund\"},{\"resource\":\"*\",\"verb\":\"stripe.unknown\"}]", canon(p.predicates));
        assertEquals("[{\"class\":\"irreversible\",\"type\":\"reversibility_max\"}]", canon(p.caveats));
    }

    @Test void nothingIrreversibleLetsAWithinCapActionAutoApprove() {
        Catalog cat = bank();
        Facade.CompiledPolicy p = compile(Issue.obj("bank", List.of("transfer")), Issue.obj("transfer", "$100"), cat, null, null, 1_000_000L);
        assertEquals("[{\"resource\":\"*\",\"verb\":\"bank.transfer\",\"where\":[{\"field\":\"action.params.amt\",\"op\":\"lte\",\"value\":100},"
            + "{\"field\":\"action.params.amt\",\"op\":\"gte\",\"value\":0}]}]", canon(p.predicates));
        assertEquals("[{\"class\":\"reversible\",\"type\":\"reversibility_max\"}]", canon(p.caveats));
        assertEquals("dollars", p.budgetModel);
        assertEquals("{\"bank.transfer\":{\"amount\":100,\"unit\":\"usd\"}}", limitsJson(p));
        assertEquals(dollarsPolicy("100", "100", "1", "1"), canon(p.riskPolicy));
        assertSame(cat.get("bank.transfer"), p.actions.get(0));
        // a count limit on the same catalog keeps the default policy
        Facade.CompiledPolicy r = compile(Issue.obj("bank", List.of("transfer")), Issue.obj("transfer", "5/min"), cat, null, null, 1_000_000L);
        assertEquals("[{\"class\":\"reversible\",\"type\":\"reversibility_max\"},{\"at\":1060000,\"type\":\"expires\"},{\"max\":5,\"per_secs\":60,\"type\":\"rate\"}]", canon(r.caveats));
        assertEquals(DEFAULT_POLICY, canon(r.riskPolicy));
    }

    static Map<String, Object> rp(Map<String, Object> permissions, Map<String, Object> limits) { return compile(permissions, limits).riskPolicy; }

    @Test void theLargestLimitIsTheCapAndTheSumIsTheBudget() {
        assertEquals(dollarsPolicy("250.5", "370.5", "0.25", "0.6"),
            canon(rp(Issue.obj("stripe", List.of("refund", "payout", "charge")), Issue.obj("refund", "$100", "payout", "$250.5", "charge", "$20"))));
        // a cap below one is kept as it is
        assertEquals(dollarsPolicy("0.5", "0.5", "0.25", "0.6"), canon(rp(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$0.5"))));
        // a zero limit cannot be the cap: the policy keeps a unit cap and budget
        Facade.CompiledPolicy z = compile(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$0"));
        assertEquals(dollarsPolicy("1", "1", "0.25", "0.6"), canon(z.riskPolicy));
        assertEquals("dollars", z.budgetModel);
        assertEquals(dollarsPolicy("100", "160", "0.25", "0.6"), canon(rp(Issue.obj("stripe", List.of("refund", "payout")), Issue.obj("refund", "$100", "payout", "$60"))));
        assertEquals(dollarsPolicy("100", "160", "0.25", "0.6"), canon(rp(Issue.obj("stripe", List.of("refund", "payout")), Issue.obj("refund", "$60", "payout", "$100"))));
    }

    static Facade.CompiledPolicy model(Map<String, Object> limits, String budgetModel) {
        return compile(Issue.obj("stripe", List.of("refund")), limits, null, budgetModel, null, 1_000_000L);
    }

    @Test void theBudgetModelIsChosenFromTheLimitsUnlessForced() {
        Map<String, Object> usd = Issue.obj("refund", "$5");
        for (String m : new String[] {null, "other", "auto", "dollars"}) {
            assertEquals("dollars", model(usd, m).budgetModel, m);
            assertEquals(dollarsPolicy("5", "5", "0.25", "0.6"), canon(model(usd, m).riskPolicy), m);
        }
        assertEquals("risk", model(usd, "risk").budgetModel);
        assertEquals(DEFAULT_POLICY, canon(model(usd, "risk").riskPolicy));
        assertEquals("risk", model(null, null).budgetModel);
        assertEquals("risk", model(null, "auto").budgetModel);
        // forced dollars with no dollar limit: the label, but the default policy
        assertEquals("dollars", model(null, "dollars").budgetModel);
        assertEquals(DEFAULT_POLICY, canon(model(null, "dollars").riskPolicy));
        assertEquals("dollars", model(Issue.obj("refund", "5/day"), "dollars").budgetModel);
        assertEquals(DEFAULT_POLICY, canon(model(Issue.obj("refund", "5/day"), "dollars").riskPolicy));
        assertEquals("risk", model(Issue.obj("refund", "5/day"), null).budgetModel);
    }

    static Facade.CompiledPolicy override(Map<String, Object> limits, Map<String, Object> riskPolicy) {
        return compile(Issue.obj("stripe", List.of("refund")), limits, null, null, riskPolicy, 1_000_000L);
    }

    @Test void aRiskPolicyOverrideIsMergedOverTheDerivedOne() {
        Facade.CompiledPolicy p = override(Issue.obj("refund", "$100"), Issue.obj("rho", new Json.Num("0.9"), "weights", Issue.obj("alpha", new Json.Num("0.5"))));
        assertEquals("{\"bMax\":100,\"kappa\":100,\"lambda\":0,\"rho\":0.9,\"theta1\":0.25,\"theta2\":0.6,"
            + "\"weights\":{\"alpha\":0.5,\"beta\":0,\"delta\":0,\"epsilon\":0,\"gamma\":1,\"zeta\":0}}", canon(p.riskPolicy));
        // members of the override win; weights merge member by member; a non-object weights is ignored
        assertEquals("{\"bMax\":1,\"kappa\":1,\"lambda\":0.0005,\"rho\":0.5,\"theta1\":0.1,\"theta2\":0.6,"
            + "\"weights\":{\"alpha\":0.25,\"beta\":0.2,\"delta\":0.2,\"epsilon\":0.1,\"gamma\":0.2,\"zeta\":0.05}}",
            canon(override(null, Issue.obj("theta1", new Json.Num("0.1"), "weights", 5L)).riskPolicy));
        assertEquals("{\"bMax\":1,\"kappa\":1,\"lambda\":0.0005,\"rho\":0.5,\"theta1\":0.25,\"theta2\":0.6,"
            + "\"weights\":{\"alpha\":0.25,\"beta\":0.3,\"delta\":0.2,\"epsilon\":0.1,\"gamma\":0.2,\"zeta\":0.05}}",
            canon(override(null, Issue.obj("weights", Issue.obj("beta", new Json.Num("0.3")))).riskPolicy));
        assertEquals("{\"bMax\":0.4,\"kappa\":1,\"lambda\":0.0005,\"rho\":0.5,\"theta1\":0.25,\"theta2\":0.6,"
            + "\"weights\":{\"alpha\":0.25,\"beta\":0.2,\"delta\":0.2,\"epsilon\":0.1,\"gamma\":0.2,\"zeta\":0.05}}",
            canon(override(null, Issue.obj("bMax", new Json.Num("0.4"))).riskPolicy));
        assertEquals(DEFAULT_POLICY, canon(override(null, Issue.obj()).riskPolicy));
        // the derived policy is validated after the merge
        assertEquals("compilePolicy: derived risk policy invalid: risk_policy.kappa must be finite", refusal(() -> override(null, Issue.obj("kappa", "x"))));
    }

    @Test void theCompiledPolicySerialisesWithTheReferencesMemberNames() {
        Facade.CompiledPolicy p = compile(Issue.obj("stripe", List.of("refund")), Issue.obj("refund", "$5/day"));
        Map<String, Object> j = p.toJson();
        assertEquals(List.of("predicates", "caveats", "riskPolicy", "budgetModel", "limits", "approximations"), new ArrayList<>(j.keySet()));
        assertEquals(canon(p.predicates), canon(j.get("predicates")));
        assertEquals(canon(p.caveats), canon(j.get("caveats")));
        assertEquals(canon(p.riskPolicy), canon(j.get("riskPolicy")));
        assertEquals("dollars", j.get("budgetModel"));
        assertEquals(1, ((List<?>) j.get("approximations")).size());
        assertEquals("{\"stripe.refund\":{\"amount\":5,\"periodMs\":86400000,\"unit\":\"usd\"}}", canon(j.get("limits")));
        assertEquals("{\"refund\":\"$5/day\"}", canon(p.inputLimits));
    }
}
