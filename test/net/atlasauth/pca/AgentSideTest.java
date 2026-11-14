package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** The agent side: grant envelope checks, the suite-aware PCActn signer, request headers, the facade and the built-in catalog. */
public class AgentSideTest {
    static final long NOW = 1_800_000_000_000L;
    static final Keys.SuiteKey PRINCIPAL = Keys.ed25519(Keys.edFromSeed(new byte[32]));
    static final Keys.EdKey AGENT = Keys.edFromSeed(ProducerTest.fill(1, 32));

    static Map<String, Object> envelope(Object... extra) {
        List<Object> preds = new ArrayList<>();
        preds.add(Issue.obj("verb", "*"));
        Map<String, Object> e = Issue.obj("predicates", preds, "caveats", new ArrayList<Object>(), "risk_policy", Issue.defaultRiskPolicy());
        e.putAll(Issue.obj(extra));
        return e;
    }

    static String mintError(Map<String, Object> env) {
        return assertThrows(IllegalArgumentException.class, () -> Issue.mintGrant(PRINCIPAL, AGENT.id(), null, env, "g", "s")).getMessage();
    }

    @Test void mintGrantRefusesAMalformedEnvelopeWithTheReferenceText() {
        assertEquals("mintGrant: model_polarity must be 'legacy' when present", mintError(envelope("model_polarity", "inverted")));
        assertEquals("mintGrant: model_polarity must be 'legacy' when present", mintError(envelope("model_polarity", null)));
        assertEquals("mintGrant: goal required", assertThrows(IllegalArgumentException.class,
            () -> Issue.mintGrant(PRINCIPAL, AGENT.id(), null, envelope(), "", "s")).getMessage());
        Map<String, Object> noPreds = envelope();
        noPreds.remove("predicates");
        assertEquals("mintGrant: envelope.predicates is required", mintError(noPreds));
        Map<String, Object> badRisk = envelope();
        badRisk.put("risk_policy", Issue.obj("v", 1L));
        assertTrue(mintError(badRisk).startsWith("mintGrant: "));
    }

    @Test void mintGrantKeepsOnlyTheEnvelopeMembers() {
        Issue.Grant g = Issue.mintGrant(PRINCIPAL, AGENT.id(), null, envelope("model_polarity", "legacy", "surprise", 1L), "g", "s");
        @SuppressWarnings("unchecked") Map<String, Object> env = (Map<String, Object>) ((List<Object>) g.grant.get("caveats")).get(0);
        // the signed grant is canonical JSON, so its members come back sorted
        assertEquals("[agent_binding, caveats, goal_commit, model_polarity, predicates, risk_policy, type]", env.keySet().toString());
        assertEquals(new LinkedHashMap<String, Object>(), env.get("agent_binding"));
    }

    @Test void signPCActnBindsTheSuiteAndVerifies() {
        Keys.PqKey pq = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ProducerTest.fill(7, 32));
        Keys.SuiteKey me = Keys.suite("hybrid-ed25519-ml-dsa-65", AGENT, pq);
        Issue.Grant g = Issue.mintGrant(PRINCIPAL, AGENT.id(), pq.pkB64u(), envelope(), "g", "s");
        Map<String, Object> a = Agent.create(me, "rs", g.grant, null).clock(() -> NOW).act("read", "x", null);
        Map<String, Object> body = new LinkedHashMap<>(a);
        body.put("sig", "junk");
        Map<String, Object> re = Issue.signPCActn(body, me);
        assertEquals("hybrid-ed25519-ml-dsa-65", re.get("alg"));
        assertEquals(pq.pkB64u(), re.get("pq_pk"));
        assertEquals(a.get("sig"), re.get("sig")); // Ed25519 and ML-DSA are deterministic: re-signing reproduces the PCActn
        assertEquals(a.get("pq_sig"), re.get("pq_sig"));
        assertTrue(Pca.verifyPcactn(re, g.grant, NOW, "rs", null, null, null, null, Pca.PlanRoots.SKIP).allow);
        Map<String, Object> ed = Issue.signPCActn(body, Keys.ed25519(AGENT));
        assertFalse(ed.containsKey("alg") || ed.containsKey("pq_pk") || ed.containsKey("pq_sig"));
    }

    @Test void headersCarryOnlyWhatIsGiven() {
        Issue.Grant g = Issue.mintGrant(PRINCIPAL, AGENT.id(), null, envelope(), "g", "s");
        Map<String, Object> a = Agent.create(Keys.ed25519(AGENT), "rs", g.grant, null).clock(() -> NOW).act("read", "x", null);
        assertEquals("[PCA-Action]", Issue.headers(a, new ArrayList<Object>(), null, null, null, null).keySet().toString());
        Map<String, Object> fresh = Issue.obj("scope", "s");
        Map<String, String> h = Issue.headers(a, List.of(Issue.obj("d", 1L)), Issue.obj("n", 1L), Issue.obj("e", 1L), fresh, Issue.obj("p", 1L));
        assertEquals("[PCA-Action, PCA-Provenance, PCA-Discharges, PCA-Narrow, PCA-Escalation-Answer, pca-fresh-at]", h.keySet().toString());
        assertEquals("[{\"d\":1}]", new String(Pca.decodeB64uStrict(h.get("PCA-Discharges"), -1), StandardCharsets.UTF_8));
        assertEquals("{\"scope\":\"s\"}", h.get("pca-fresh-at"));
        assertEquals(Issue.header(a), h.get("PCA-Action"));
        Map<String, Object> big = Issue.obj("p", "x".repeat(Issue.PROVENANCE_HEADER_MAX));
        assertFalse(Issue.headers(a, null, null, null, null, big).containsKey("PCA-Provenance"));
    }

    @Test void facadeRefusesAnOutOfPolicyActionAndSignsAnInPolicyOne() {
        Map<String, Object> perms = Issue.obj("stripe", new ArrayList<Object>(List.of("refund")));
        Facade.Handle h = Agent.fromPrincipal(new Facade.AgentOptions(PRINCIPAL, "refund order 1", perms).limits(Issue.obj("refund", "$500/day"))
            .holder(Keys.ed25519(AGENT)).aud("rs").now(NOW).goalSalt("s"));
        assertFalse(h.dryRun("stripe.charge", "charge:ch_1", Issue.obj("amount", 5L), NOW).allowed);
        assertTrue(h.dryRun("stripe.refund", "charge:ch_1", Issue.obj("amount", 5L), NOW).allowed);
        Facade.ActOptions o = new Facade.ActOptions();
        o.now = NOW;
        Facade.ActResult r = h.act("stripe.refund", "charge:ch_1", Issue.obj("amount", 5L), o);
        assertEquals(1L, r.pcactn.get("counter"));
        assertEquals(r.encoded, Issue.encode(r.pcactn));
        assertTrue(Pca.verifyPcactn(r.pcactn, h.grant, NOW, "rs", null, null, null, null, Pca.PlanRoots.SKIP).allow);
        assertEquals(Json.canonicalize(h.grant), h.encodeGrant());
        assertEquals(2, h.subAgent(Keys.ed25519(Keys.edFromSeed(ProducerTest.fill(2, 32))), new ArrayList<Object>()).chain.size());
    }

    @Test void parseLimitRefusals() {
        assertEquals("parseLimit: empty limit", assertThrows(IllegalArgumentException.class, () -> Facade.parseLimit("")).getMessage());
        assertEquals("parseLimit: cannot parse limit 'abc'", assertThrows(IllegalArgumentException.class, () -> Facade.parseLimit("abc")).getMessage());
        assertEquals("{\"amount\":500,\"periodMs\":86400000,\"unit\":\"usd\"}", Json.canonicalize(Facade.parseLimit("$500/day").toJson()));
    }

    /** The built-in catalog is generated from the reference's: every row must match it member for member. */
    @Test void builtinCatalogMatchesTheReference() throws Exception {
        // the monorepo (and the CI layouts) carry the reference catalog at packages/pca/src above the working directory
        Path src = null;
        for (Path d = Path.of("").toAbsolutePath(); d != null && src == null; d = d.getParent()) {
            Path c = d.resolve("packages").resolve("pca").resolve("src").resolve("catalog-builtin.generated.ts");
            if (Files.exists(c)) src = c;
        }
        if (src == null) throw new IllegalStateException("the reference catalog is missing: the comparison must run (never skipped)");
        String ts = new String(Files.readAllBytes(src), StandardCharsets.UTF_8);
        List<Object> rows = new ArrayList<>();
        for (String line : ts.split("\n")) {
            String t = line.trim();
            if (!t.startsWith("{ connector:")) continue;
            if (t.endsWith(",")) t = t.substring(0, t.length() - 1);
            @SuppressWarnings("unchecked") Map<String, Object> row = (Map<String, Object>) Json.parseLenient(t.replaceAll("([{,]\\s*)(\\w+):", "$1\"$2\":"));
            row.values().removeIf(v -> v instanceof List && ((List<?>) v).isEmpty()); // an empty list and no list read the same
            rows.add(row);
        }
        assertEquals(rows.size(), Catalog.BUILTIN.size());
        for (int i = 0; i < rows.size(); i++) {
            Catalog.Spec s = Catalog.BUILTIN.get(i);
            Map<String, Object> o = Issue.obj("connector", s.connector, "action", s.action, "verb", s.verb, "reversibility", s.reversibility,
                "blastRadius", Facade.jn(s.blastRadius), "description", s.description);
            if (s.amountField != null) o.put("amountField", s.amountField);
            if (!s.aliases.isEmpty()) o.put("aliases", new ArrayList<Object>(s.aliases));
            if (!s.traits.isEmpty()) o.put("traits", new ArrayList<Object>(s.traits));
            assertEquals(Json.canonicalize(rows.get(i)), Json.canonicalize(o), s.verb);
        }
        assertEquals("stripe.refund", Catalog.DEFAULT.resolve("stripe", "issue_refund").verb);
        assertNull(Catalog.DEFAULT.resolve("stripe", "no_such_action"));
    }
}
