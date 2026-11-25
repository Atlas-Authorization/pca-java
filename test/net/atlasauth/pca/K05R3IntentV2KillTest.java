package net.atlasauth.pca;

import static net.atlasauth.pca.IntentV2KillTest.list;
import static net.atlasauth.pca.IntentV2KillTest.map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for the wiring of the grant action pin and rule 22 in {@link IntentV2#decide} (intent-v2.ts:613-633): the
 * verifier's evolution records, registry keys, re-approvals and the grant identity all reach the pin decision, the blocked
 * step is named in the reason, the schema step runs at most once, and an unpinned grant takes tier defaults 3 / 0.
 */
public class K05R3IntentV2KillTest {
    static final String VERB = K05Rule22WiringTest.VERB;
    static final String NS = ActionRegistryRestKillTest.NS, P = ActionRegistryRestKillTest.P, GID = ActionRegistryRestKillTest.GID;
    static final String OK_SCHEMA = K05Rule22WiringTest.OK_SCHEMA, OK_PIN = K05Rule22WiringTest.OK_PIN, OK_TRAITS = K05Rule22WiringTest.OK_TRAITS;
    static final String NO_CHAIN = "pin|false|def_changed: the definition differs from the pinned digest and no signed evolution record chains to it";

    /** action-pin.ts:350 + intent-v2.ts:620. */
    static String blocked(String diff) {
        return "pin|false|def_changed: the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve (re-approve diff " + diff + ")";
    }

    /** A grant by the test's principal whose pin holds an older digest of the verb, so only a chain can reach the presented one. */
    static Map<String, Object> pinnedAway(Map<String, Object> doc) {
        Map<String, Object> g = K05Rule22WiringTest.grant(K05Rule22WiringTest.pin(doc, "defs", map(VERB, P)));
        g.put("id", GID);
        g.put("issuer", ActionRegistryRestKillTest.PRINCIPAL.id());
        return g;
    }

    static Map<String, Object> step(Map<String, Object> doc, String cls) {
        return ActionRegistryRestKillTest.rec(NS, VERB, P, (String) K05Rule22WiringTest.verbOf(doc).get("def"), cls);
    }

    /** A PCActn counting the schema step's audience read: nothing else reads {@code aud} without an intent_session. */
    static final class CountingPcactn extends LinkedHashMap<String, Object> {
        private static final long serialVersionUID = 1L;
        int schemaSteps;
        CountingPcactn(Map<String, Object> m) { super(m); }
        @Override public Object get(Object k) {
            if ("aud".equals(k)) schemaSteps++;
            return super.get(k);
        }
    }

    /** intent-v2.ts:87 checks the three named members and nothing else (here a host-built map whose stray member has a null key). */
    @Test void onlyTheThreeNamedActionMembersAreTyped() {
        Map<String, Object> actions = new LinkedHashMap<>();
        actions.put(null, 5L);
        actions.put("other", 5L);
        assertNull(IntentV2.contextError(IntentV2.Context.fromJson(map("actions", actions))));
    }

    /** intent-v2.ts:619: a verified narrowing step moves the pin only with both the records and the keys. */
    @Test void theRecordsAndKeysReachThePinDecision() throws Exception {
        Map<String, Object> d = K05Rule22WiringTest.doc("rule22-allow", null);
        Map<String, Object> narrow = step(d, "narrow");
        List<Object> keys = ActionRegistryRestKillTest.keys();
        assertEquals(List.of(OK_SCHEMA, OK_PIN, OK_TRAITS),
            K05Rule22WiringTest.run(pinnedAway(d), K05Rule22WiringTest.context(d, "actions", map("records", list(narrow), "keys", keys))));
        assertEquals(List.of(OK_SCHEMA, NO_CHAIN, OK_TRAITS),
            K05Rule22WiringTest.run(pinnedAway(d), K05Rule22WiringTest.context(d, "actions", map("records", list(narrow)))), "no keys: nothing verifies");
        assertEquals(List.of(OK_SCHEMA, NO_CHAIN, OK_TRAITS),
            K05Rule22WiringTest.run(pinnedAway(d), K05Rule22WiringTest.context(d, "actions", map("keys", keys))), "no records: no chain");
    }

    /** intent-v2.ts:619-620: a widening step is blocked and named, until the grant's own issuer re-approves it for this grant id. */
    @Test void aBlockedStepIsNamedAndOnlyTheGrantsPrincipalUnblocksIt() throws Exception {
        Map<String, Object> d = K05Rule22WiringTest.doc("rule22-allow", null);
        Map<String, Object> widen = step(d, "widen");
        String diff = ActionRegistry.evolutionDiffDigest(widen);
        List<Object> keys = ActionRegistryRestKillTest.keys();
        Map<String, Object> approval = ActionRegistryRestKillTest.reapproval(ActionRegistryRestKillTest.rapBody(diff));

        assertEquals(List.of(OK_SCHEMA, blocked(diff), OK_TRAITS),
            K05Rule22WiringTest.run(pinnedAway(d), K05Rule22WiringTest.context(d, "actions", map("records", list(widen), "keys", keys))));
        Map<String, Object> approved = K05Rule22WiringTest.context(d, "actions", map("records", list(widen), "keys", keys, "reapprovals", list(approval)));
        assertEquals(List.of(OK_SCHEMA, OK_PIN, OK_TRAITS), K05Rule22WiringTest.run(pinnedAway(d), approved));

        Map<String, Object> otherId = pinnedAway(d);
        otherId.put("id", ActionRegistryRestKillTest.d("another grant"));
        assertEquals(List.of(OK_SCHEMA, blocked(diff), OK_TRAITS), K05Rule22WiringTest.run(otherId, approved), "approved for another grant");
        Map<String, Object> otherIssuer = pinnedAway(d);
        otherIssuer.put("issuer", ActionRegistryRestKillTest.REG.id());
        assertEquals(List.of(OK_SCHEMA, blocked(diff), OK_TRAITS), K05Rule22WiringTest.run(otherIssuer, approved), "approved by someone else");
    }

    /** intent-v2.ts:613-614 schemaMemo: the schema check's document is reused, else one schema step serves pin and traits. */
    @Test void theSchemaStepRunsOnce() throws Exception {
        Map<String, Object> d = K05Rule22WiringTest.doc("rule22-allow", null);
        Map<String, Object> g = K05Rule22WiringTest.grant(K05Rule22WiringTest.pin(d));

        CountingPcactn afterCheck = new CountingPcactn(K05Rule22WiringTest.pcactn());
        assertEquals(List.of(OK_SCHEMA, OK_PIN, OK_TRAITS), K042IntentV2UnitTest.render(
            IntentV2.decide(afterCheck, g, IntentV2.Context.fromJson(K05Rule22WiringTest.context(d)), K05Rule22WiringTest.NOW)));
        assertEquals(1, afterCheck.schemaSteps, "the schema check's document is reused");

        Map<String, Object> noPolicy = K05Rule22WiringTest.context(d);
        noPolicy.remove("policy");
        CountingPcactn pinOnly = new CountingPcactn(K05Rule22WiringTest.pcactn());
        assertEquals(List.of(OK_PIN, OK_TRAITS), K042IntentV2UnitTest.render(
            IntentV2.decide(pinOnly, g, IntentV2.Context.fromJson(noPolicy), K05Rule22WiringTest.NOW)));
        assertEquals(1, pinOnly.schemaSteps, "the pin's schema step serves the traits decision and check");
    }

    /**
     * A schema step that throws fails the pin and leaves nothing to read: no traits check (IntentV2.java:655). The reference
     * rethrows out of decideIntentV2 at intent-v2.ts:623 instead; both refuse the action.
     */
    @Test void aThrowingSchemaStepFailsThePinAndReportsNoTraits() throws Exception {
        Map<String, Object> d = K05Rule22WiringTest.doc("rule22-allow", null);
        String loneSurrogate = "k" + (char) 0xD800;
        Map<String, Object> ctx = K05Rule22WiringTest.context(d, "params", map("amount", 1000L, "charge", "ch_abcdefgh", "idempotency_key", loneSurrogate));
        ctx.remove("policy");
        assertEquals(List.of("pin|false|pin error (fail closed): IllegalArgumentException"),
            K05Rule22WiringTest.run(K05Rule22WiringTest.grant(K05Rule22WiringTest.pin(d)), ctx));
    }

    /** intent-v2.ts:623: traits needs the schema check or a pin; a configured v2 schema alone reports nothing. */
    @Test void withoutClosedWorldOrPinNoTraitsAreReported() throws Exception {
        Map<String, Object> d = K05Rule22WiringTest.doc("rule22-allow", null);
        Map<String, Object> ctx = K05Rule22WiringTest.context(d);
        ctx.remove("policy");
        assertEquals(List.of(), K05Rule22WiringTest.run(K05Rule22WiringTest.grant(null), ctx));
    }

    /** intent-v2.ts:631 {@code pin?.preauth_esc ?? 0}: the esc-1 verb (gmail.send) is not preauthorized by a grant without a pin, and is at preauth 1. */
    @Test void withoutAPinNoTierIsPreauthorized() throws Exception {
        Map<String, Object> d = K05Rule22WiringTest.doc("rule22-allow", null);
        Map<String, Object> params = map("body", "b", "idempotency_key", "k1", "subject", "s", "to", "a@example.com");
        Map<String, Object> p = map("aud", IntentV2KillTest.AUD, "action", map("verb", "gmail.send", "resource", "r", "params_digest", Pca.paramsDigest(params)));
        IntentV2.Context ctx = IntentV2.Context.fromJson(K05Rule22WiringTest.context(d, "params", params));
        Object[] floorsCaveats = {map("type", "rate_cap"), map("type", "recipient_scope"), map("type", "resource_scope")};

        assertEquals(List.of(OK_SCHEMA, "traits|false|" + K05Rule22WiringTest.FLOOR_ESCALATE),
            K042IntentV2UnitTest.render(IntentV2.decide(p, K05Rule22WiringTest.grant(null, floorsCaveats), ctx, K05Rule22WiringTest.NOW)));
        // the same floors under a pin at preauth 1 pass, so only the default tier refused above (the pin itself names no gmail.send)
        Map<String, Object> preauthOne = K05Rule22WiringTest.pin(d, "preauth_esc", 1L);
        assertEquals(OK_TRAITS,
            K042IntentV2UnitTest.render(IntentV2.decide(p, K05Rule22WiringTest.grant(preauthOne, floorsCaveats), ctx, K05Rule22WiringTest.NOW)).get(2));
    }
}
