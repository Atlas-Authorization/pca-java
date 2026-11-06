package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for the Intent Layer v2 model rules (rules 20 and 21, {@link IntentV2#decide}): the ceiling layers are
 * allow-side predicate lists, a verifier with no context still decides {@code tighten}, a strict polarity policy always
 * reports {@code tighten}, a schema with no units table is an empty table, a single-source world (rule 16) is model-derived
 * and the verifier-computed env reaches the tighten rules. Each case asserts the exact rendered checks.
 */
public class IntentV2K05KillTest {
    static final long NOW = 1_800_000_000_000L;
    static final String RISK = "{\"bMax\":1,\"kappa\":1,\"lambda\":0,\"rho\":0,\"theta1\":0.5,\"theta2\":0.8,"
        + "\"weights\":{\"alpha\":0,\"beta\":0,\"delta\":0,\"epsilon\":0,\"gamma\":0,\"zeta\":0}}";
    static final String DENY_T1 = ",\"tighten\":[{\"id\":\"t1\",\"when\":{\"field\":\"action.verb\",\"op\":\"eq\",\"value\":\"air.book\"},\"signal\":\"deny\"}]";
    static final String RULE21 = ": a model may only tighten (move them into tighten[]) (rule 21)";

    static Map<String, Object> json(String text) { return K042IntentV2UnitTest.obj(Json.parseLenient(text)); }

    /** A stored grant whose envelope allows air.book, plus {@code extra} envelope members (a JSON fragment: empty or starting with a comma). */
    static Map<String, Object> grant(String extra) {
        return json("{\"caveats\":[{\"type\":\"envelope\",\"goal_commit\":\"g\",\"predicates\":[{\"verb\":\"air.book\"}],\"caveats\":[],\"agent_binding\":{},"
            + "\"risk_policy\":" + RISK + extra + "}]}");
    }

    /** A PCActn without intent_session: only the model rules can be reported. */
    static Map<String, Object> pcactn() { return json("{\"aud\":\"skyair.example\",\"action\":{\"verb\":\"air.book\",\"resource\":\"r\"}}"); }

    static List<String> run(Map<String, Object> g, String ctx) {
        return K042IntentV2UnitTest.render(IntentV2.decide(pcactn(), g, ctx == null ? null : IntentV2.Context.fromJsonText(ctx), NOW));
    }

    static Map<String, Object> envelope(Map<String, Object> g) {
        for (Object cv : (List<?>) g.get("caveats")) if ("envelope".equals(K042IntentV2UnitTest.obj(cv).get("type"))) return K042IntentV2UnitTest.obj(cv);
        throw new AssertionError("no envelope caveat");
    }

    /** The rendered tighten checks of a decision (in order). */
    static List<String> tighten(IntentV2.Decision d) {
        List<String> r = new ArrayList<>();
        for (String c : K042IntentV2UnitTest.render(d)) if (c.startsWith("tighten|")) r.add(c);
        return r;
    }

    /** Every ceiling layer (org, site, std) is an allow-side list: a model-derived path in its where is refused (rule 21). */
    @Test void ceilingLayersAreAllowSide() {
        String model = "{\"verb\":\"air.book\",\"where\":[{\"field\":\"env.class.risky\",\"op\":\"eq\",\"value\":true}]}";
        String refused = "tighten|false|a grant's where reads model-derived path(s) env.class.risky" + RULE21;
        for (String k : new String[] {"org", "site", "std"})
            assertEquals(List.of(refused), run(grant(""), "{\"layers\":{\"" + k + "\":{\"predicates\":[" + model + "]}}}"), k);
        // a layer reading no model path, an empty context and no context at all: no rule-21 check
        assertEquals(List.of(), run(grant(""), "{\"layers\":{\"org\":{\"predicates\":[{\"verb\":\"air.book\"}]}}}"));
        assertEquals(List.of(), run(grant(""), "{}"));
        assertEquals(List.of(), run(grant(""), null));
    }

    /** No v2 context (a verifier that only has the grant's tighten rules): tighten is still decided, never an internal error. */
    @Test void noContextStillDecidesTighten() {
        assertEquals(List.of("tighten|false|denied by tighten rule 't1'"), run(grant(DENY_T1), null));
        assertEquals(List.of("tighten|false|denied by tighten rule 't1'"), run(grant(DENY_T1), "{}"));
    }

    /** policy.model_polarity "strict" (no polarity in effect) still reports the tighten check. */
    @Test void aStrictPolicyAlwaysReportsTighten() {
        assertEquals(List.of("tighten|true|null"), run(grant(""), "{\"policy\":{\"model_polarity\":\"strict\"}}"));
        assertEquals(List.of(), run(grant(""), "{\"policy\":{}}"));
    }

    /** A signed schema with no units member: rule 20 reads an empty units table (never "the schema units table must be an object"). */
    @Test void aSchemaWithoutAUnitsTableIsAnEmptyTable() {
        Map<String, Object> search = IntentV2KillTest.map("verb", "air.search", "kind", "read", "params", IntentV2KillTest.map(
            "action.params.pax", IntentV2KillTest.map("type", "integer", "min", 1L, "max", 9L, "semantic", "quantity", "sensitivity", "material")),
            "reversibility", "reversible");
        Map<String, Object> doc = IntentV2KillTest.signSchema(IntentV2KillTest.map("v", 1L, "kind", "pca-action-schema", "site", "https://skyair.example",
            "aud", IntentV2KillTest.AUD, "version", "2026-10-01", "verbs", IntentV2KillTest.list(search)), "skyair-2026", IntentV2KillTest.SITE);
        Map<String, Object> params = IntentV2KillTest.map("pax", 2L);
        Map<String, Object> p = IntentV2KillTest.map("aud", IntentV2KillTest.AUD,
            "action", IntentV2KillTest.map("verb", "air.search", "resource", "r", "params_digest", Pca.paramsDigest(params)));
        IntentV2.Context ctx = IntentV2.Context.fromJson(IntentV2KillTest.map("params", params,
            "schema", IntentV2KillTest.map("docs", IntentV2KillTest.list(doc), "keys", IntentV2KillTest.KEYS)));
        assertEquals(List.of("units|true|null"), K042IntentV2UnitTest.render(IntentV2.decide(p, grant(",\"units\":{}"), ctx, NOW)));
    }

    /**
     * A world decided by ONE oracle (rule 16) is model-derived: it is recorded, a grant-side where on it is refused, and a
     * tighten rule reads the verifier-computed env.world value.
     */
    @Test void singleSourceWorldsAreModelDerived() throws Exception {
        Map<String, Object> c = K042IntentV2UnitTest.caseNamed("wb16/wb16-single-source");
        long now = Json.asLong(c.get("now"));
        String ctx = (String) c.get("ctx");

        IntentV2.Decision d = IntentV2.decide(K042IntentV2UnitTest.parse(c.get("p")), K042IntentV2UnitTest.parse(c.get("grant")), IntentV2.Context.fromJsonText(ctx), now);
        assertEquals(List.of("fare"), d.singleSource);
        assertEquals(List.of(), tighten(d));

        Map<String, Object> g1 = K042IntentV2UnitTest.parse(c.get("grant"));
        envelope(g1).put("tighten", Json.parseLenient("[{\"id\":\"t1\",\"when\":{\"field\":\"env.world.fare\",\"op\":\"lte\",\"value\":40000},\"signal\":\"deny\"}]"));
        d = IntentV2.decide(K042IntentV2UnitTest.parse(c.get("p")), g1, IntentV2.Context.fromJsonText(ctx), now);
        assertEquals(List.of("tighten|false|denied by tighten rule 't1'"), tighten(d));

        Map<String, Object> g2 = K042IntentV2UnitTest.parse(c.get("grant"));
        K042IntentV2UnitTest.obj(K042IntentV2UnitTest.list(envelope(g2).get("predicates")).get(0))
            .put("where", Json.parseLenient("[{\"field\":\"env.world.fare\",\"op\":\"lte\",\"value\":40000}]"));
        d = IntentV2.decide(K042IntentV2UnitTest.parse(c.get("p")), g2, IntentV2.Context.fromJsonText(ctx), now);
        assertEquals(List.of("tighten|false|a grant's where reads model-derived path(s) env.world.fare" + RULE21), tighten(d));
    }

    /** A step verdict as a check reason: null iff ok, and a failure without a reason of its own still fails ("refused"). */
    @Test void failWhyAlwaysCarriesAReason() {
        assertNull(IntentV2.failWhy(true, "ignored"));
        assertNull(IntentV2.failWhy(true, null));
        assertEquals("r", IntentV2.failWhy(false, "r"));
        assertEquals("refused", IntentV2.failWhy(false, null));
    }
}
