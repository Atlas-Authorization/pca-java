package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

/**
 * Rule 22 and the grant action pin inside {@link IntentV2#decide} (intent-v2.ts:321-325, 614-634): the shared rule 22 vectors'
 * documents, re-signed by a site key and citing a pack, under a closed-world verifier.
 */
public class K05Rule22WiringTest {
    static final long NOW = 1_800_000_000_000L;
    static final String VERB = "stripe.refund";
    static final String ROOT = "A".repeat(43);
    static final String FLOOR_ESCALATE = "escalate: the action floors need a caveat, context or confirmation the grant does not provide (rule 22)";
    static final String FLOOR_DENY = "the action floors exceed what the grant authorizes (rule 22)";

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static Map<String, Object> vector(String name) throws Exception {
        String text = Files.readString(ActionVectorsTest.dir().toPath().resolve(name + ".json"), StandardCharsets.UTF_8);
        return m(m(IntentJs.normalize(Json.parseLenient(text))).get("input"));
    }

    static Map<String, Object> verbOf(Map<String, Object> doc) {
        for (Object v : l(doc.get("verbs"))) if (VERB.equals(m(v).get("verb"))) return m(v);
        throw new AssertionError("no " + VERB);
    }

    /** The vector's document, optionally changed, citing the pack and signed by the site key. */
    static Map<String, Object> doc(String vector, Consumer<Map<String, Object>> change) throws Exception {
        Map<String, Object> d = m(vector(vector).get("doc"));
        d.remove("sig");
        d.put("aud", IntentV2KillTest.AUD);
        d.put("pack", IntentV2KillTest.map("ns", "stripe", "version", "1.0.0", "root", ROOT));
        if (change != null) change.accept(d);
        return IntentV2KillTest.signSchema(d, "skyair-2026", IntentV2KillTest.SITE);
    }

    static final Map<String, Object> PARAMS = IntentV2KillTest.map("amount", 1000L, "charge", "ch_abcdefgh", "idempotency_key", "k1");

    static Map<String, Object> pcactn() {
        return IntentV2KillTest.map("aud", IntentV2KillTest.AUD, "action", IntentV2KillTest.map("verb", VERB, "resource", "r", "params_digest", Pca.paramsDigest(PARAMS)));
    }

    static Map<String, Object> context(Map<String, Object> doc, Object... extra) throws Exception {
        Map<String, Object> allow = vector("rule22-allow");
        Map<String, Object> c = IntentV2KillTest.map("policy", IntentV2KillTest.map("schema", IntentV2KillTest.map("closed_world", true)), "params", PARAMS,
            "schema", IntentV2KillTest.map("docs", IntentV2KillTest.list(doc), "keys", IntentV2KillTest.KEYS),
            "reviewers", allow.get("pins"), "call_context", allow.get("context"));
        for (int i = 0; i < extra.length; i += 2) c.put((String) extra[i], extra[i + 1]);
        return c;
    }

    /** A pin that provides everything the refund's floors need: the vector's grant facts, pinning the verb's definition digest. */
    static Map<String, Object> pin(Map<String, Object> doc, Object... extra) {
        Map<String, Object> v = verbOf(doc);
        Map<String, Object> defs = new LinkedHashMap<>();
        defs.put(VERB, v.get("def"));
        Map<String, Object> p = IntentV2KillTest.map("pack", IntentV2KillTest.map("ns", "stripe", "root", ROOT), "defs", defs, "on_new_action", "deny",
            "max_esc", 3L, "preauth_esc", 2L, "caveats", IntentV2KillTest.list("amount_cap", "count_cap", "window"));
        for (int i = 0; i < extra.length; i += 2) {
            if (extra[i + 1] == null) p.remove((String) extra[i]);
            else p.put((String) extra[i], extra[i + 1]);
        }
        return p;
    }

    static Map<String, Object> grant(Object pin, Object... envelopeCaveats) {
        Map<String, Object> cv = Issue.obj("type", Authorize.ENVELOPE_CAVEAT, "goal_commit", "g", "predicates", new ArrayList<>(),
            "caveats", new ArrayList<>(List.of(envelopeCaveats)), "agent_binding", new LinkedHashMap<>(), "risk_policy", Issue.defaultRiskPolicy());
        if (pin != null) cv.put("actions", pin);
        return IntentV2KillTest.map("id", "g1", "issuer", "i1", "caveats", IntentV2KillTest.list(cv));
    }

    static List<String> run(Map<String, Object> grant, Map<String, Object> ctx) {
        return K042IntentV2UnitTest.render(IntentV2.decide(pcactn(), grant, IntentV2.Context.fromJson(ctx), NOW));
    }

    static final String OK_SCHEMA = "schema|true|null", OK_PIN = "pin|true|null", OK_TRAITS = "traits|true|null";

    @Test void aConsistentSchemaAnExactPinAndAGrantThatProvidesTheFloorsPass() throws Exception {
        Map<String, Object> d = doc("rule22-allow", null);
        assertEquals(List.of(OK_SCHEMA, OK_PIN, OK_TRAITS), run(grant(pin(d)), context(d)));
    }

    @Test void forgedDocumentsAreRefusedByTheSchemaStepAndThePin() throws Exception {
        for (String[] c : new String[][] {{"rule22-forged-floors-denied", "schema_floor_forged"}, {"rule22-dropped-traits-denied", "schema_traits_forged"}}) {
            Map<String, Object> d = doc(c[0], null);
            List<String> got = run(grant(pin(d)), context(d));
            assertEquals(2, got.size(), got.toString());
            assertTrue(got.get(0).startsWith("schema|false|schema_floor_forged: "), got.get(0));
            assertTrue(got.get(0).contains(c[1]), got.get(0));
            assertEquals(got.get(0).replace("schema|", "pin|"), got.get(1), "the pin reads the same schema step");
        }
    }

    @Test void anUnknownTraitIsRefused() throws Exception {
        Map<String, Object> d = doc("rule22-allow", x -> l(verbOf(x).get("traits")).add("pca.no_such_trait"));
        List<String> got = run(grant(null), context(d));
        assertTrue(got.get(0).startsWith("schema|false|schema_floor_forged: "), got.toString());
    }

    @Test void theIntegrityCheckSitsAfterTheAudienceAndBeforeTheParams() throws Exception {
        Map<String, Object> forged = doc("rule22-forged-floors-denied", null);
        Map<String, Object> noParams = context(forged);
        noParams.remove("params");
        assertTrue(run(grant(null), noParams).get(0).startsWith("schema|false|schema_floor_forged: "));
        Map<String, Object> otherAud = doc("rule22-forged-floors-denied", x -> x.put("aud", "elsewhere"));
        assertEquals("schema|false|schema aud does not match the PCActn aud", run(grant(null), context(otherAud)).get(0));
    }

    @Test void withoutPinnedReviewersNoVerbIsConfirmed() throws Exception {
        Map<String, Object> d = doc("rule22-allow", null);
        Map<String, Object> ctx = context(d);
        ctx.remove("reviewers");
        assertTrue(run(grant(pin(d)), ctx).get(0).startsWith("schema|false|schema_floor_forged: "));
    }

    @Test void theFloorDecisionMeetsTheGrant() throws Exception {
        Map<String, Object> d = doc("rule22-allow", null);
        // esc 2: above max_esc denies, above preauth_esc escalates
        assertEquals(List.of(OK_SCHEMA, OK_PIN, "traits|false|" + FLOOR_DENY), run(grant(pin(d, "max_esc", 1L, "preauth_esc", 0L)), context(d)));
        assertEquals(List.of(OK_SCHEMA, OK_PIN, "traits|false|" + FLOOR_ESCALATE), run(grant(pin(d, "preauth_esc", 1L)), context(d)));
        // a caveat missing from the pin, and one the call context lacks
        assertEquals(List.of(OK_SCHEMA, OK_PIN, "traits|false|" + FLOOR_ESCALATE), run(grant(pin(d, "caveats", IntentV2KillTest.list("amount_cap"))), context(d)));
        assertEquals(List.of(OK_SCHEMA, OK_PIN, "traits|false|" + FLOOR_ESCALATE), run(grant(pin(d)), context(d, "call_context", IntentV2KillTest.list())));
        Map<String, Object> noContext = context(d);
        noContext.remove("call_context");
        assertEquals(List.of(OK_SCHEMA, OK_PIN, "traits|false|" + FLOOR_ESCALATE), run(grant(pin(d)), noContext));
    }

    @Test void envelopeCaveatsAndPinCaveatsBothCount() throws Exception {
        Map<String, Object> d = doc("rule22-allow", null);
        Object two = IntentV2KillTest.list("amount_cap", "count_cap");
        assertEquals(List.of(OK_SCHEMA, OK_PIN, OK_TRAITS), run(grant(pin(d, "caveats", two), IntentV2KillTest.map("type", "window")), context(d)));
        assertEquals(List.of(OK_SCHEMA, OK_PIN, OK_TRAITS), run(grant(pin(d, "caveats", null), IntentV2KillTest.map("type", "amount_cap"), IntentV2KillTest.map("type", "count_cap"), IntentV2KillTest.map("type", "window")), context(d)));
        assertEquals(List.of(OK_SCHEMA, OK_PIN, "traits|false|" + FLOOR_ESCALATE), run(grant(pin(d, "caveats", two), "window", IntentV2KillTest.map("type", 5L)), context(d)), "an envelope caveat without a string type counts for nothing");
    }

    @Test void withoutAPinTheTiersDefaultToAllTiersCappedNonePreauthorized() throws Exception {
        Map<String, Object> d = doc("rule22-allow", null);
        Map<String, Object> env = grant(null, IntentV2KillTest.map("type", "amount_cap"), IntentV2KillTest.map("type", "count_cap"), IntentV2KillTest.map("type", "window"));
        assertEquals(List.of(OK_SCHEMA, "traits|false|" + FLOOR_ESCALATE), run(env, context(d)), "esc 2 is within tier 3 but above preauth 0: escalate, not deny");
        assertEquals(List.of(OK_SCHEMA, "traits|false|" + FLOOR_ESCALATE), run(IntentV2KillTest.map("id", "g1", "issuer", "i1", "caveats", IntentV2KillTest.list()), context(d)), "a grant with no envelope");
        // a pin with no tiers takes the same defaults, and one that is malformed counts for nothing
        assertEquals(List.of(OK_SCHEMA, OK_PIN, "traits|false|" + FLOOR_ESCALATE), run(grant(pin(d, "max_esc", null, "preauth_esc", null)), context(d)));
        Map<String, Object> bad = pin(d, "max_esc", 9L);
        List<String> got = run(grant(bad), context(d));
        assertTrue(got.get(1).startsWith("pin|false|bad_pin: "), got.toString());
        assertEquals("traits|false|" + FLOOR_ESCALATE, got.get(2));
    }

    @Test void thePinIsEnforced() throws Exception {
        Map<String, Object> d = doc("rule22-allow", null);
        String other = "B".repeat(43);
        Map<String, Object> defs = IntentV2KillTest.map(VERB, other);
        assertEquals("pin|false|def_changed: the definition differs from the pinned digest and no signed evolution record chains to it", run(grant(pin(d, "defs", defs)), context(d)).get(1));
        assertEquals("pin|false|new_action: the grant does not name 'stripe.refund' (on_new_action: deny)", run(grant(pin(d, "defs", IntentV2KillTest.map("gmail.send", other))), context(d)).get(1));
        assertEquals("pin|false|escalate: new_action: the grant does not name 'stripe.refund' (on_new_action: escalate)",
            run(grant(pin(d, "defs", IntentV2KillTest.map("gmail.send", other), "on_new_action", "escalate")), context(d)).get(1));
        assertEquals("pin|false|pack_mismatch: the schema does not come from the pinned pack 'other'", run(grant(pin(d, "pack", IntentV2KillTest.map("ns", "other", "root", ROOT))), context(d)).get(1));
        assertEquals("pin|false|pack_mismatch: the pack root differs from the pinned root (the grant pins the pack as a whole)",
            run(grant(pin(d, "defs", null, "pack", IntentV2KillTest.map("ns", "stripe", "root", other))), context(d)).get(1));
    }

    @Test void thePinAloneReachesTheSchemaWithoutAClosedWorldPolicy() throws Exception {
        Map<String, Object> d = doc("rule22-allow", null);
        Map<String, Object> ctx = context(d);
        ctx.remove("policy");
        assertEquals(List.of(OK_PIN, OK_TRAITS), run(grant(pin(d)), ctx), "pin reports traits for a v2 schema it read itself");
        assertEquals("pin|false|this verifier has no action schema configured", K042IntentV2UnitTest.render(IntentV2.decide(pcactn(), grant(pin(d)), null, NOW)).get(0));
        // a schema that fails leaves nothing to read: no traits check
        assertEquals(1, K042IntentV2UnitTest.render(IntentV2.decide(pcactn(), grant(pin(d)), null, NOW)).size());
        // the verifier clock fails both, after the schema was read
        assertEquals(List.of("pin|false|the verifier clock is not a safe integer (fail closed)", "traits|false|the verifier clock is not a safe integer (fail closed)"),
            K042IntentV2UnitTest.render(IntentV2.decide(pcactn(), grant(pin(d)), IntentV2.Context.fromJson(ctx), Long.MAX_VALUE)));
    }

    @Test void aV1SchemaIsUnchanged() {
        Map<String, Object> ctx = IntentV2KillTest.map("policy", IntentV2KillTest.map("schema", IntentV2KillTest.map("closed_world", true)),
            "schema", IntentV2KillTest.map("docs", IntentV2KillTest.list(IntentV2KillTest.SCHEMA), "keys", IntentV2KillTest.KEYS), "params", PARAMS);
        for (String s : run(grant(null), ctx)) assertTrue(!s.startsWith("traits") && !s.startsWith("pin"), s);
    }

    @Test void theContextIsClosedAndTyped() {
        String[][] bad = {
            {"\"reviewers\":null", "reviewers must be {keys: [...]}"}, {"\"reviewers\":[]", "reviewers must be {keys: [...]}"}, {"\"reviewers\":{}", "reviewers must be {keys: [...]}"}, {"\"reviewers\":{\"keys\":{}}", "reviewers must be {keys: [...]}"},
            {"\"call_context\":null", "call_context must be an array of strings"}, {"\"call_context\":\"x\"", "call_context must be an array of strings"}, {"\"call_context\":[1]", "call_context must be an array of strings"},
            {"\"actions\":null", "actions must be an object"}, {"\"actions\":[]", "actions must be an object"},
            {"\"actions\":{\"records\":{}}", "actions.records must be an array"}, {"\"actions\":{\"keys\":null}", "actions.keys must be an array"}, {"\"actions\":{\"reapprovals\":1}", "actions.reapprovals must be an array"},
        };
        for (String[] c : bad) assertEquals(c[1], IntentV2.contextError(IntentV2.Context.fromJsonText("{" + c[0] + "}")), c[0]);
        assertEquals("params must be an object", IntentV2.contextError(IntentV2.Context.fromJsonText("{\"reviewers\":{\"keys\":[]},\"call_context\":[\"a\"],\"actions\":{\"records\":[],\"keys\":[],\"reapprovals\":[]},\"params\":1}")), "valid members pass on to the next check");
        assertEquals("reviewers must be {keys: [...]}", IntentV2.contextError(IntentV2.Context.fromJsonText("{\"reviewers\":1,\"params\":1}")), "before params");
    }
}
