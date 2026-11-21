package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The grant envelope checks of {@code mintGrant} (each check, a present JSON null, and the reference's order: the first refusal
 * wins), {@code signPCActn} (the body's members are kept as given, as the reference's {@code signPCActnSuite} does) and the
 * request headers (the provenance header bound: present at exactly 8192 characters, absent above).
 */
class IssueAgentSidePitKill1Test {
    static final Keys.SuiteKey PRINCIPAL = Keys.ed25519(Keys.edFromSeed(new byte[32]));
    static final Keys.EdKey AGENT = Keys.edFromSeed(ProducerTest.fill(1, 32));

    static Map<String, Object> envelope(Object... extra) {
        List<Object> preds = new ArrayList<>();
        preds.add(Issue.obj("verb", "*"));
        Map<String, Object> e = Issue.obj("predicates", preds, "caveats", new ArrayList<Object>(), "risk_policy", Issue.defaultRiskPolicy());
        for (int i = 0; i < extra.length; i += 2) e.put((String) extra[i], extra[i + 1]);
        return e;
    }

    static Issue.Grant mint(Map<String, Object> env) { return Issue.mintGrant(PRINCIPAL, AGENT.id(), null, env, "g", "s"); }

    static String mintError(Map<String, Object> env) { return assertThrows(IllegalArgumentException.class, () -> mint(env)).getMessage(); }

    // ---- mintGrant envelope checks (envelope.ts mintGrant) -----------------------------------------------------------------

    @Test void eachEnvelopeMemberIsChecked() {
        assertEquals("mintGrant: units must be an object", mintError(envelope("units", "x")));
        assertEquals("mintGrant: tighten must be an array", mintError(envelope("tighten", "x")));
        assertEquals("mintGrant: template_ref must be an object", mintError(envelope("template_ref", "x")));
        assertEquals("mintGrant: actions must be an object", mintError(envelope("actions", "x")));
        assertEquals("mintGrant: provenance must be an object", mintError(envelope("provenance", "x")));
    }

    /** Each check reads its own member: an object / array that is malformed inside gets the inner refusal, not the type refusal. */
    @Test void eachCheckReadsItsOwnMember() {
        assertEquals("mintGrant: units key 'x' must be an action.params.<name> path", mintError(envelope("units", Issue.obj("x", Issue.obj("kind", "usd")))));
        assertEquals("mintGrant: tighten[0] must be an object", mintError(envelope("tighten", new ArrayList<Object>(List.of(5L)))));
        assertEquals("mintGrant: template_ref.template_id invalid", mintError(envelope("template_ref", Issue.obj())));
        assertEquals("mintGrant: actions.pack must be {ns, root}", mintError(envelope("actions", Issue.obj())));
        assertEquals("mintGrant: provenance.mode must be 'enforce' or 'insecure_off'", mintError(envelope("provenance", Issue.obj("mode", "off"))));
    }

    /** A present JSON null is checked (the reference tests `!== undefined`); an absent member is not. */
    @Test void aPresentNullIsCheckedAndAnAbsentMemberIsNot() {
        assertEquals("mintGrant: units must be an object", mintError(envelope("units", null)));
        assertEquals("mintGrant: tighten must be an array", mintError(envelope("tighten", null)));
        assertEquals("mintGrant: template_ref must be an object", mintError(envelope("template_ref", null)));
        assertEquals("mintGrant: actions must be an object", mintError(envelope("actions", null)));
        assertEquals("mintGrant: provenance must be an object", mintError(envelope("provenance", null)));
        assertNotNull(mint(envelope()).grant);
        assertNotNull(mint(envelope("units", Issue.obj(), "tighten", new ArrayList<Object>(), "provenance", Issue.obj())).grant);
    }

    /** The reference's order: risk_policy, units, tighten, template_ref, actions, provenance, model_polarity; the first refusal wins. */
    @Test void theFirstRefusalInTheReferenceOrderWins() {
        Map<String, Object> badRisk = envelope();
        badRisk.put("risk_policy", Issue.obj("v", 1L));
        String risk = mintError(badRisk);
        badRisk.put("units", "x");
        assertEquals(risk, mintError(badRisk));
        assertEquals("mintGrant: units must be an object", mintError(envelope("units", "x", "tighten", "x")));
        assertEquals("mintGrant: tighten must be an array", mintError(envelope("tighten", "x", "template_ref", "x")));
        assertEquals("mintGrant: template_ref must be an object", mintError(envelope("template_ref", "x", "actions", "x")));
        assertEquals("mintGrant: actions must be an object", mintError(envelope("actions", "x", "provenance", "x")));
        assertEquals("mintGrant: provenance must be an object", mintError(envelope("provenance", "x", "model_polarity", "inverted")));
    }

    // ---- signPCActn (pcactn.ts signPCActnSuite) -------------------------------------------------------------------------------

    static Map<String, Object> body() {
        return Issue.obj("ver", 2L, "params", Issue.obj("amount", 5L), "threshold", Issue.obj("t", 1L), "alg", "ml-dsa-65", "pq_pk", "old", "pq_sig", "old",
            "sig", "old");
    }

    @Test void anEd25519SignatureKeepsTheBodyAsGiven() {
        Map<String, Object> b = body();
        Map<String, Object> got = Issue.signPCActn(b, Keys.ed25519(AGENT));
        Map<String, Object> want = new LinkedHashMap<>(b);
        want.put("sig", Pca.b64(AGENT.sign(Pca.thresholdMessage(b))));
        assertEquals(Json.canonicalize(want), Json.canonicalize(got));
    }

    @Test void aPostQuantumSignatureBindsItsSuiteAndKeepsTheRest() {
        Keys.PqKey pq = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, ProducerTest.fill(7, 32));
        Map<String, Object> b = body();
        b.put("alg", "ed25519");
        // pure ML-DSA-65: alg and pq_pk are the signer's, the body's pq_sig stays (the suite makes none)
        Keys.SuiteKey pure = Keys.suite("ml-dsa-65", null, pq);
        Map<String, Object> want = new LinkedHashMap<>(b);
        want.put("alg", "ml-dsa-65");
        want.put("pq_pk", pq.pkB64u());
        want.put("sig", pure.sign(Pca.thresholdMessage(want))[0]);
        assertEquals(Json.canonicalize(want), Json.canonicalize(Issue.signPCActn(b, pure)));
        // hybrid: both signatures are the signer's
        Keys.SuiteKey hy = Keys.suite("hybrid-ed25519-ml-dsa-65", AGENT, pq);
        Map<String, Object> w2 = new LinkedHashMap<>(b);
        w2.put("alg", "hybrid-ed25519-ml-dsa-65");
        w2.put("pq_pk", pq.pkB64u());
        String[] sg = hy.sign(Pca.thresholdMessage(w2));
        w2.put("sig", sg[0]);
        w2.put("pq_sig", sg[1]);
        assertEquals(Json.canonicalize(w2), Json.canonicalize(Issue.signPCActn(b, hy)));
    }

    /** The signed PCActn shares no object with the caller's body: a later edit of the body cannot change a signed artifact. */
    @Test void theSignedActionDoesNotShareTheCallersObjects() {
        Map<String, Object> b = body();
        Map<String, Object> got = Issue.signPCActn(b, Keys.ed25519(AGENT));
        String before = Json.canonicalize(got);
        @SuppressWarnings("unchecked") Map<String, Object> params = (Map<String, Object>) b.get("params");
        params.put("amount", 500L);
        assertEquals(before, Json.canonicalize(got));
    }

    // ---- headers (adapters.ts provenanceHeaders, require-pca.ts header encodings) ------------------------------------------------

    static Map<String, Object> action() {
        Issue.Grant g = mint(envelope());
        return Agent.create(Keys.ed25519(AGENT), "rs", g.grant, null).clock(() -> 1_800_000_000_000L).act("read", "x", null);
    }

    static String decode(String v) { return new String(Pca.decodeB64uStrict(v, -1), StandardCharsets.UTF_8); }

    /** 6144 bytes of canonical JSON are exactly 8192 base64url characters (sent); 6145 bytes are 8194 (left out). */
    @Test void theProvenanceHeaderIsSentUpToExactly8192Characters() {
        Map<String, Object> a = action();
        Map<String, Object> fits = Issue.obj("p", "x".repeat(6144 - 8));
        assertEquals(6144, Json.canonicalizeStrict(fits).getBytes(StandardCharsets.UTF_8).length);
        String v = Issue.headers(a, null, null, null, null, fits).get(ArgProvenance.HEADER);
        assertNotNull(v);
        assertEquals(Issue.PROVENANCE_HEADER_MAX, v.length());
        assertEquals(Json.canonicalizeStrict(fits), decode(v));
        Map<String, Object> over = Issue.obj("p", "x".repeat(6145 - 8));
        assertFalse(Issue.headers(a, null, null, null, null, over).containsKey(ArgProvenance.HEADER));
    }

    @Test void theNarrowAndEscalationAnswerHeadersAreBase64urlJson() {
        Map<String, Object> narrow = Issue.obj("b", 2L, "a", "n");
        Map<String, Object> answer = Issue.obj("decision", "allow", "nonce", "q");
        Map<String, String> h = Issue.headers(action(), null, narrow, answer, null, null);
        assertEquals("{\"a\":\"n\",\"b\":2}", decode(h.get("PCA-Narrow")));
        assertEquals("{\"decision\":\"allow\",\"nonce\":\"q\"}", decode(h.get("PCA-Escalation-Answer")));
    }
}
