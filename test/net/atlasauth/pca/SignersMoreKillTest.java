package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/** The agent-side signers: every refusal text, every branch, and the exact bytes signed (recomputed here from the documented layout). */
public class SignersMoreKillTest {
    static final Map<String, Object> DOC = Track3Vectors.load("producer-vectors.json");
    static final ProducerOps OPS = new ProducerOps(m(DOC.get("keys")), null);

    static byte[] fill(int n, int b) { byte[] x = new byte[n]; Arrays.fill(x, (byte) b); return x; }

    static final Keys.EdKey AGENT = Keys.edFromSeed(fill(32, 1));
    static final Keys.SuiteKey AGENT_S = Keys.ed25519(AGENT);
    static final Keys.PqKey PQ = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(32, 7));
    static final String HYB = "hybrid-ed25519-ml-dsa-65";
    static final Keys.SuiteKey HYBRID = Keys.suite(HYB, AGENT, PQ);
    /** A pure ML-DSA-65 suite key with no Ed25519 identity. */
    static final Keys.SuiteKey PURE_PQ = Keys.suite("ml-dsa-65", null, PQ);
    /** A pure ML-DSA-65 suite key that also carries an Ed25519 identity (the share's publicKey, as the reference's secretKey gives it). */
    static final Keys.SuiteKey PURE_PQ_ED = Keys.suite("ml-dsa-65", AGENT, PQ);

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }
    static Map<String, Object> obj(Object... kv) { return Issue.obj(kv); }
    static String canon(Object o) { return Json.canonicalize(o); }
    static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    static String d32(int n) { return Pca.b64(fill(32, n)); }
    static Object deep(Object o) { return Json.parseLenient(Json.canonicalize(o)); }
    static String str(int n, char c) { char[] a = new char[n]; Arrays.fill(a, c); return new String(a); }

    static String refusal(Executable f) { return assertThrows(IllegalArgumentException.class, f).getMessage(); }

    static Map<String, Object> caseArgs(String op, String name) {
        for (Object c : l(DOC.get("cases"))) {
            Map<String, Object> v = m(c);
            if (op.equals(v.get("op")) && (name == null || name.equals(v.get("name")))) return m(deep(v.get("args")));
        }
        throw new AssertionError("no vector " + op + "/" + name);
    }

    static Map<String, Object> argMap(String op, String key) { return new LinkedHashMap<>(m(caseArgs(op, null).get(key))); }

    // ---- an Ed25519 identity is needed where the wire names one ------------------------------------------------------------

    @Test void aPurePostQuantumSignerIsRefusedWhereAnEd25519IdentityIsNamed() {
        assertEquals("signPreparedShare: the signer needs an Ed25519 identity", refusal(() -> SignersMore.signPreparedShare("agent", PURE_PQ, new byte[1])));
        assertEquals("signRevocationEpoch: the signer needs an Ed25519 identity", refusal(() -> SignersMore.signRevocationEpoch(PURE_PQ, obj())));
        assertEquals("signSessionRoot: the signer needs an Ed25519 identity", refusal(() -> SignersMore.signSessionRoot(obj(), PURE_PQ)));
        assertEquals("actionSchemaKeyOf: the signer needs an Ed25519 identity", refusal(() -> SignersMore.actionSchemaKeyOf("k", PURE_PQ)));
    }

    // ---- threshold shares --------------------------------------------------------------------------------------------------

    @Test void aPreparedShareIsTheRoleTheKeyAndTheSignature() {
        byte[] prepared = new byte[40];
        for (int i = 0; i < prepared.length; i++) prepared[i] = (byte) i;
        Map<String, Object> s = SignersMore.signPreparedShare("guardian", AGENT_S, prepared);
        assertEquals(List.of("role", "publicKey", "sig"), new ArrayList<>(s.keySet()));
        assertEquals("guardian", s.get("role"));
        assertEquals(AGENT.id(), s.get("publicKey"));
        assertEquals(Pca.b64(AGENT.sign(prepared)), s.get("sig"));

        Map<String, Object> h = SignersMore.signPreparedShare("agent", HYBRID, prepared);
        assertEquals(List.of("role", "publicKey", "sig", "alg", "pq_sig"), new ArrayList<>(h.keySet()));
        assertEquals(HYB, h.get("alg"));
        String[] want = HYBRID.sign(prepared);
        assertEquals(want[0], h.get("sig"));
        assertEquals(want[1], h.get("pq_sig"));

        // a pure post-quantum suite: sig is the PQ signature, alg is named and there is no pq_sig (threshold.ts signPreparedShare)
        Map<String, Object> p = SignersMore.signPreparedShare("principal", PURE_PQ_ED, prepared);
        assertEquals(List.of("role", "publicKey", "sig", "alg"), new ArrayList<>(p.keySet()));
        assertEquals("ml-dsa-65", p.get("alg"));
        assertEquals(AGENT.id(), p.get("publicKey"));
        assertEquals(PURE_PQ_ED.sign(prepared)[0], p.get("sig"));
    }

    @Test void aThresholdShareBindsTheSignerSetAndTheThreshold() {
        List<Object> set = l(caseArgs("sign_threshold_share", null).get("signer_set"));
        byte[] msg = fill(32, 5);
        assertEquals("signShare: a 'agent' share must bind {signerSet, t}", refusal(() -> SignersMore.signThresholdShare("agent", AGENT_S, msg, null, 1)));
        assertEquals("signShare: a 'guardian' share must bind {signerSet, t}", refusal(() -> SignersMore.signThresholdShare("guardian", AGENT_S, msg, null, 0)));
        for (int t : new int[] {0, 4, -1}) assertEquals("shareMessage: t must be 1, 2 or 3", refusal(() -> SignersMore.signThresholdShare("agent", AGENT_S, msg, set, t)), "t=" + t);
        Set<Object> sigs = new HashSet<>();
        for (int t = 1; t <= 3; t++) {
            Map<String, Object> s = SignersMore.signThresholdShare("agent", AGENT_S, msg, set, t);
            assertEquals(canon(SignersMore.signPreparedShare("agent", AGENT_S, Threshold.shareMessage("agent", msg, set, t, "ed25519", true))), canon(s));
            sigs.add(s.get("sig"));
        }
        assertEquals(3, sigs.size());
        Map<String, Object> h = SignersMore.signThresholdShare("agent", HYBRID, msg, set, 2);
        assertEquals(canon(SignersMore.signPreparedShare("agent", HYBRID, Threshold.shareMessage("agent", msg, set, 2, HYB, true))), canon(h));
    }

    // ---- PQ key binding ----------------------------------------------------------------------------------------------------

    @Test void aPqBindingNeedsAPositiveSafeEpochAndAnAudience() {
        String epochText = "signPqBinding: epoch must be a positive safe integer";
        String audText = "signPqBinding: aud (the instance/audience id) is required";
        for (long e : new long[] {0L, -1L, 9007199254740992L}) assertEquals(epochText, refusal(() -> SignersMore.signPqBinding(AGENT, "pk", e, "aud")), "epoch " + e);
        assertEquals(audText, refusal(() -> SignersMore.signPqBinding(AGENT, "pk", 1L, null)));
        assertEquals(audText, refusal(() -> SignersMore.signPqBinding(AGENT, "pk", 1L, "")));
        assertEquals(epochText, refusal(() -> SignersMore.signPqBinding(AGENT, "pk", 0L, null)));
        for (long e : new long[] {1L, 2L, 9007199254740991L}) {
            Map<String, Object> b = SignersMore.signPqBinding(AGENT, "pqpk", e, "inst");
            assertEquals(List.of("ed", "pq", "epoch", "aud", "sig"), new ArrayList<>(b.keySet()));
            assertEquals(AGENT.id(), b.get("ed"));
            assertEquals("pqpk", b.get("pq"));
            assertEquals(e, b.get("epoch"));
            assertEquals("inst", b.get("aud"));
            assertEquals(Pca.b64(AGENT.sign(SignersMore.pqBindingMessage(AGENT.id(), "pqpk", e, "inst"))), b.get("sig"));
        }
        assertEquals("atlas-pca/pq-binding/v2\u0000ed\u0000pk\u00007\u0000aud", new String(SignersMore.pqBindingMessage("ed", "pk", 7L, "aud"), StandardCharsets.UTF_8));
    }

    // ---- caution -----------------------------------------------------------------------------------------------------------

    static Map<String, Object> cautionBody() { return obj("action_digest", "digest", "holder", "holder", "caution", new Json.Num("0.5")); }

    @Test void theCautionBodyCheckSaysWhatIsWrong() {
        assertNull(SignersMore.cautionBodyError(cautionBody()));
        for (Object b : Arrays.asList(null, "x", List.of(1L), 5L)) assertEquals("not an object", SignersMore.cautionBodyError(b));
        for (Object v : Arrays.asList(null, "", 5L, List.of("a"))) {
            Map<String, Object> b = cautionBody();
            b.put("action_digest", v);
            assertEquals("action_digest required", SignersMore.cautionBodyError(b));
            Map<String, Object> h = cautionBody();
            h.put("holder", v);
            assertEquals("holder required", SignersMore.cautionBodyError(h));
        }
        Map<String, Object> both = cautionBody();
        both.remove("action_digest");
        both.remove("holder");
        assertEquals("action_digest required", SignersMore.cautionBodyError(both));
        Map<String, Object> noHolder = cautionBody();
        noHolder.remove("holder");
        assertEquals("holder required", SignersMore.cautionBodyError(noHolder));
        String range = "caution must be a finite number in [0,1]";
        for (Object c : Arrays.asList(null, "0.5", Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, -1L, 2L, new Json.Num("-0.1"),
            new Json.Num("1.0000001"), new Json.Num("1.5"))) {
            Map<String, Object> b = cautionBody();
            b.put("caution", c);
            assertEquals(range, SignersMore.cautionBodyError(b), "caution " + c);
        }
        Map<String, Object> noCaution = cautionBody();
        noCaution.remove("caution");
        assertEquals(range, SignersMore.cautionBodyError(noCaution));
        for (Object c : Arrays.asList(0L, 1L, 0.0, 1.0, new Json.Num("0.25"), new Json.Num("1"), new Json.Num("0"))) {
            Map<String, Object> b = cautionBody();
            b.put("caution", c);
            assertNull(SignersMore.cautionBodyError(b), "caution " + c);
        }
    }

    @Test void theCautionReasonIsASmallToken() {
        for (String r : List.of("ambiguous_instruction", "a", "A-z_.:-09", str(64, 'x'))) {
            Map<String, Object> b = cautionBody();
            b.put("reason", r);
            assertNull(SignersMore.cautionBodyError(b), r);
        }
        for (Object r : Arrays.asList("", "a b", str(65, 'x'), 5L, null, "café", "a/b")) {
            Map<String, Object> b = cautionBody();
            b.put("reason", r);
            assertEquals("invalid reason", SignersMore.cautionBodyError(b), "reason " + r);
        }
    }

    @Test void aCautionClaimIsTheThreeMembersTheReasonAndTheSignature() {
        Map<String, Object> b = cautionBody();
        b.put("zzz", 1L);
        Map<String, Object> c = SignersMore.signCaution(b, AGENT);
        assertEquals(List.of("action_digest", "caution", "holder", "sig"), new ArrayList<>(c.keySet()));
        Map<String, Object> clean = obj("action_digest", "digest", "caution", new Json.Num("0.5"), "holder", "holder");
        assertEquals(Pca.b64(AGENT.sign(Pca.canonBytes(obj("d", "atlas-pca/caution/v1", "b", clean)))), c.get("sig"));
        assertFalse(b.containsKey("sig"));
        b.put("reason", "why_not");
        Map<String, Object> r = SignersMore.signCaution(b, AGENT);
        assertEquals(List.of("action_digest", "caution", "holder", "reason", "sig"), new ArrayList<>(r.keySet()));
        clean.put("reason", "why_not");
        assertEquals(Pca.b64(AGENT.sign(Pca.canonBytes(obj("d", "atlas-pca/caution/v1", "b", clean)))), r.get("sig"));
        assertEquals("signCaution: invalid reason", refusal(() -> SignersMore.signCaution(obj("action_digest", "d", "holder", "h", "caution", 1L, "reason", "a b"), AGENT)));
        assertEquals("signCaution: caution must be a finite number in [0,1]", refusal(() -> SignersMore.signCaution(obj("action_digest", "d", "holder", "h", "caution", 1.5), AGENT)));
    }

    // ---- lease heartbeat ---------------------------------------------------------------------------------------------------

    @Test void aHeartbeatNeedsEveryMemberAndSignsOnlyThose() {
        Map<String, Object> full = obj("cap_id", "cap", "seq", 3L, "at", 1000L, "holder", "h", "lease_issued_at", 900L);
        for (String k : full.keySet()) {
            Map<String, Object> b = new LinkedHashMap<>(full);
            b.remove(k);
            assertEquals("signHeartbeat: " + k + " required", refusal(() -> SignersMore.signHeartbeat(b, AGENT)));
        }
        Map<String, Object> two = new LinkedHashMap<>(full);
        two.remove("seq");
        two.remove("holder");
        assertEquals("signHeartbeat: seq required", refusal(() -> SignersMore.signHeartbeat(two, AGENT)));
        Map<String, Object> withExtra = new LinkedHashMap<>(full);
        withExtra.put("zzz", 1L);
        Map<String, Object> hb = SignersMore.signHeartbeat(withExtra, AGENT);
        assertEquals(List.of("cap_id", "seq", "at", "holder", "lease_issued_at", "sig"), new ArrayList<>(hb.keySet()));
        assertEquals(Pca.b64(AGENT.sign(Pca.canonBytes(obj("d", "atlas-pca/lease-hb/v2", "b", full)))), hb.get("sig"));
        assertFalse(withExtra.containsKey("sig"));
    }

    // ---- read receipt ------------------------------------------------------------------------------------------------------

    @Test void aReadReceiptCountsFromThePreviousOne() {
        Map<String, Object> a = caseArgs("sign_read_receipt", "read-receipt-chained");
        Keys.EdKey rs = OPS.ed("rs");
        Map<String, Object> grant = m(a.get("grant"));
        long at = Json.asLong(a.get("issued_at"));
        Map<String, Object> prev = new LinkedHashMap<>(m(a.get("prev")));
        prev.put("seq", 5L);
        Map<String, Object> r = SignersMore.signReadReceipt(rs, grant, "read", "customers/7", "support", m(a.get("fields")), l(a.get("labels")), at, prev);
        assertEquals(6L, Json.asLong(r.get("seq")));
        assertEquals(ReadSide.readReceiptRef(prev), r.get("prev"));
        Map<String, Object> first = SignersMore.signReadReceipt(rs, grant, "read", "customers/7", "support", m(a.get("fields")), l(a.get("labels")), at, null);
        assertEquals(0L, Json.asLong(first.get("seq")));
        assertTrue(first.containsKey("prev"));
        assertNull(first.get("prev"));
        assertEquals(ReadSide.readGrantDigest(grant), first.get("grant"));
        // the receipt is a copy: changing the caller's members afterwards does not reach it
        Map<String, Object> fields = new LinkedHashMap<>(m(deep(a.get("fields"))));
        Map<String, Object> sealed = SignersMore.signReadReceipt(rs, grant, "read", "customers/7", "support", fields, l(a.get("labels")), at, null);
        String before = canon(sealed.get("fields"));
        fields.put("zzz", 1L);
        assertEquals(before, canon(sealed.get("fields")));
        assertTrue(sealed.get("seq") instanceof Json.Num);
        assertTrue(sealed.get("issued_at") instanceof Json.Num);
    }

    // ---- session root ------------------------------------------------------------------------------------------------------

    static final Set<String> ROOT_MEMBERS = new LinkedHashSet<>(List.of("v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors",
        "question_uri", "expires_at", "signer", "sig"));

    @Test void aSessionRootCarriesItsMembersTheSignerAndTheSignature() {
        Keys.EdKey p = OPS.ed("principal");
        Map<String, Object> body = argMap("sign_session_root", "body");
        String bodyBefore = canon(body);
        Map<String, Object> r = SignersMore.signSessionRoot(body, Keys.ed25519(p));
        assertEquals(ROOT_MEMBERS, r.keySet());
        assertEquals(p.id(), r.get("signer"));
        assertNull(IntentSession.rootShapeError(r));
        assertEquals(bodyBefore, canon(body), "the caller's body is not changed");

        Map<String, Object> extra = new LinkedHashMap<>(body);
        extra.put("flows", obj());
        extra.put("revocation", obj("epoch_uri", "https://r.example/e", "max_age_s", 60L, "key", d32(9)));
        Map<String, Object> r2 = SignersMore.signSessionRoot(extra, Keys.ed25519(p));
        Set<String> want = new HashSet<>(ROOT_MEMBERS);
        want.add("flows");
        want.add("revocation");
        assertEquals(want, r2.keySet());
        assertEquals(canon(extra.get("revocation")), canon(r2.get("revocation")));
        assertEquals("{}", canon(r2.get("flows")));
        assertNull(IntentSession.rootShapeError(r2));

        Map<String, Object> onlyFlows = new LinkedHashMap<>(body);
        onlyFlows.put("flows", obj("f", 1L));
        Map<String, Object> r3 = SignersMore.signSessionRoot(onlyFlows, Keys.ed25519(p));
        assertEquals("{\"f\":1}", canon(r3.get("flows")));
        assertFalse(r3.containsKey("revocation"));
    }

    @Test void aSessionRootIgnoresSignatureMembersTheCallerLeftOnTheBody() {
        Keys.EdKey p = OPS.ed("principal");
        Map<String, Object> body = argMap("sign_session_root", "body");
        body.put("sig", "old");
        body.put("alg", "junk");
        body.put("pq_pk", "AA");
        body.put("pq_sig", "AA");
        Map<String, Object> r = SignersMore.signSessionRoot(body, Keys.ed25519(p));
        assertNotEquals("old", r.get("sig"));
        for (String k : List.of("alg", "pq_pk", "pq_sig")) assertFalse(r.containsKey(k), k);
        assertNull(IntentSession.rootShapeError(r));
        assertEquals("old", body.get("sig"));
        assertEquals("junk", body.get("alg"));
        assertFalse(body.containsKey("signer"));
        // each suite member on its own (each alone would fail the signed-root shape check if it reached it)
        for (Object[] kv : new Object[][] {{"alg", "junk"}, {"pq_pk", "AA"}, {"pq_sig", "AA"}, {"sig", 5L}}) {
            Map<String, Object> b = argMap("sign_session_root", "body");
            b.put((String) kv[0], kv[1]);
            Map<String, Object> s = SignersMore.signSessionRoot(b, Keys.ed25519(p));
            assertNull(IntentSession.rootShapeError(s), (String) kv[0]);
            assertEquals(canon(SignersMore.signSessionRoot(argMap("sign_session_root", "body"), Keys.ed25519(p))), canon(s), (String) kv[0]);
        }
    }

    @Test void aSessionRootRefusesWhatTheReferenceRefuses() {
        Keys.EdKey p = OPS.ed("principal");
        Map<String, Object> body = argMap("sign_session_root", "body");
        assertEquals("signSessionRoot: the signer is not one of the session principals", refusal(() -> SignersMore.signSessionRoot(body, Keys.ed25519(OPS.ed("agent")))));
        Map<String, Object> noUri = new LinkedHashMap<>(body);
        noUri.put("question_uri", "");
        assertEquals("signSessionRoot: question_uri must be a non-empty string", refusal(() -> SignersMore.signSessionRoot(noUri, Keys.ed25519(p))));
        Map<String, Object> unknown = new LinkedHashMap<>(body);
        unknown.put("zzz", 1L);
        assertEquals("signSessionRoot: session root: unknown member 'zzz'", refusal(() -> SignersMore.signSessionRoot(unknown, Keys.ed25519(p))));
    }

    // ---- session grant -----------------------------------------------------------------------------------------------------

    static final String SESSION = d32(3), ROOT = d32(4), MAP_DIGEST = d32(5);
    static final List<Object> PREDS = List.of(obj("verb", "read", "resource", "x/*"));

    static SignersMore.SessionGrant grant(long seq, String prev, String form, List<Object> caveats, String salt, String holderPq,
                                          Map<String, Object> binding, Map<String, Object> risk) {
        return SignersMore.mintSessionGrant(AGENT_S, AGENT.id(), SESSION, seq, ROOT, prev, MAP_DIGEST, form, PREDS, caveats, binding, risk, salt, holderPq);
    }

    static SignersMore.SessionGrant grant() { return grant(0L, null, null, null, "fixed-salt", null, null, null); }

    @Test void aSessionGrantCommitsTheGoalOfItsMap() {
        SignersMore.SessionGrant g = grant();
        assertEquals("fixed-salt", g.goalSalt);
        List<Object> cav = l(g.grant.get("caveats"));
        assertEquals(2, cav.size());
        Map<String, Object> env = m(cav.get(0));
        assertEquals(Set.of("type", "goal_commit", "predicates", "caveats", "agent_binding", "risk_policy"), env.keySet());
        assertEquals(Issue.ENVELOPE_CAVEAT, env.get("type"));
        assertEquals(Issue.goalCommit(IntentSession.intentGoalV2(SESSION, MAP_DIGEST), "fixed-salt"), env.get("goal_commit"));
        assertEquals(canon(PREDS), canon(env.get("predicates")));
        assertEquals("[]", canon(env.get("caveats")));
        assertEquals("{}", canon(env.get("agent_binding")));
        assertEquals(canon(Issue.defaultRiskPolicy()), canon(env.get("risk_policy")));
        assertEquals(canon(obj("type", "intent_session", "session", SESSION, "seq", 0L, "root", ROOT)), canon(cav.get(1)));
        assertFalse(g.grant.containsKey("holder_pq"));
        assertEquals(AGENT.id(), g.grant.get("holder"));
    }

    @Test void aCommittedMapChangesTheGoalAndOnlyThatForm() {
        Object plain = m(l(grant().grant.get("caveats")).get(0)).get("goal_commit");
        Object committed = m(l(grant(0L, null, IntentMap.MAP_FORM_COMMIT, null, "fixed-salt", null, null, null).grant.get("caveats")).get(0)).get("goal_commit");
        Object other = m(l(grant(0L, null, "other", null, "fixed-salt", null, null, null).grant.get("caveats")).get(0)).get("goal_commit");
        assertEquals(Issue.goalCommit(IntentSession.intentGoalV2c(SESSION, MAP_DIGEST), "fixed-salt"), committed);
        assertNotEquals(plain, committed);
        assertEquals(plain, other);
    }

    @Test void aSessionGrantKeepsWhatTheCallerGave() {
        List<Object> cav = List.of(obj("type", "budget_alloc", "limit", 3L));
        Map<String, Object> binding = obj("operator", "acme");
        Map<String, Object> risk = obj("custom", 1L);
        SignersMore.SessionGrant g = grant(1L, d32(6), null, cav, "fixed-salt", PQ.pkB64u(), binding, risk);
        Map<String, Object> env = m(l(g.grant.get("caveats")).get(0));
        assertEquals(canon(cav), canon(env.get("caveats")));
        assertEquals(canon(binding), canon(env.get("agent_binding")));
        assertEquals(canon(risk), canon(env.get("risk_policy")));
        assertEquals(canon(obj("type", "intent_session", "session", SESSION, "seq", 1L, "root", ROOT, "prev", d32(6))), canon(l(g.grant.get("caveats")).get(1)));
        assertEquals(Pca.holderPqCommitment(PQ.pkB64u()), g.grant.get("holder_pq"));
    }

    @Test void aSessionGrantWithoutASaltDrawsAFreshOne() {
        SignersMore.SessionGrant a = grant(0L, null, null, null, null, null, null, null);
        SignersMore.SessionGrant b = grant(0L, null, null, null, null, null, null, null);
        assertEquals(22, a.goalSalt.length());
        assertEquals(16, Pca.decodeB64uStrict(a.goalSalt, 16).length);
        assertNotEquals(a.goalSalt, b.goalSalt);
        assertEquals(Issue.goalCommit(IntentSession.intentGoalV2(SESSION, MAP_DIGEST), a.goalSalt), m(l(a.grant.get("caveats")).get(0)).get("goal_commit"));
    }

    @Test void aSessionGrantRefusesAMalformedLinkOrDigest() {
        String prevText = "mintSessionGrant: intent_session caveat: prev is present exactly when seq > 0";
        assertEquals(prevText, refusal(() -> grant(0L, d32(6), null, null, "s", null, null, null)));
        assertEquals(prevText, refusal(() -> grant(1L, null, null, null, "s", null, null, null)));
        assertEquals("mintSessionGrant: intent_session caveat: prev must be canonical base64url (32 bytes)", refusal(() -> grant(1L, "x", null, null, "s", null, null, null)));
        String seqText = "mintSessionGrant: intent_session caveat: seq must be a safe integer in [0, 2147483647]";
        assertEquals(seqText, refusal(() -> grant(-1L, d32(6), null, null, "s", null, null, null)));
        assertEquals(seqText, refusal(() -> grant(2147483648L, d32(6), null, null, "s", null, null, null)));
        grant(2147483647L, d32(6), null, null, "s", null, null, null);
        assertEquals("mintSessionGrant: mapDigest must be canonical base64url (32 bytes)",
            refusal(() -> SignersMore.mintSessionGrant(AGENT_S, AGENT.id(), SESSION, 0L, ROOT, null, "x", null, PREDS, null, null, null, null, null)));
        assertEquals("mintSessionGrant: intent_session caveat: session and root must be canonical base64url (32 bytes)",
            refusal(() -> SignersMore.mintSessionGrant(AGENT_S, AGENT.id(), "x", 0L, ROOT, null, "x", null, PREDS, null, null, null, null, null)));
    }

    // ---- action schema and its discovery key -------------------------------------------------------------------------------

    @Test void anActionSchemaCarriesTheSitesSignatureOverItsBody() {
        Map<String, Object> schema = argMap("sign_action_schema", "doc");
        Keys.SuiteKey site = Keys.ed25519(OPS.ed("site"));
        byte[] msg = Pca.concat(utf8(ActionSchema.ACTION_SCHEMA_DOMAIN), Pca.canonBytes(schema));
        Map<String, Object> s = SignersMore.signActionSchema(schema, "site-k1", site);
        Map<String, Object> sig = m(s.get("sig"));
        assertEquals(List.of("alg", "kid", "value"), new ArrayList<>(sig.keySet()));
        assertEquals("ed25519", sig.get("alg"));
        assertEquals("site-k1", sig.get("kid"));
        assertEquals(site.sign(msg)[0], sig.get("value"));
        assertFalse(schema.containsKey("sig"), "the caller's document is not changed");
        assertNull(ActionSchema.shapeError(s, true));
        for (String k : schema.keySet()) assertEquals(canon(schema.get(k)), canon(s.get(k)));

        Map<String, Object> hs = m(SignersMore.signActionSchema(schema, "site-k1", HYBRID).get("sig"));
        assertEquals(List.of("alg", "kid", "value", "pq_value"), new ArrayList<>(hs.keySet()));
        assertEquals(HYB, hs.get("alg"));
        String[] want = HYBRID.sign(msg);
        assertEquals(want[0], hs.get("value"));
        assertEquals(want[1], hs.get("pq_value"));

        Map<String, Object> ps = m(SignersMore.signActionSchema(schema, "site-k1", PURE_PQ).get("sig"));
        assertEquals(List.of("alg", "kid", "value"), new ArrayList<>(ps.keySet()));
        assertEquals("ml-dsa-65", ps.get("alg"));
        assertEquals(PURE_PQ.sign(msg)[0], ps.get("value"));
    }

    @Test void anActionSchemaIsCheckedBeforeItIsSigned() {
        Keys.SuiteKey site = Keys.ed25519(OPS.ed("site"));
        assertEquals("signActionSchema: " + ActionSchema.shapeError(obj(), false), refusal(() -> SignersMore.signActionSchema(obj(), "k", site)));
        Map<String, Object> signed = argMap("sign_action_schema", "doc");
        signed.put("sig", obj());
        assertEquals("signActionSchema: an unsigned schema must not carry sig", refusal(() -> SignersMore.signActionSchema(signed, "k", site)));
    }

    @Test void theDiscoveryKeyEntryNamesTheSuiteAndThePins() {
        Map<String, Object> k = SignersMore.actionSchemaKeyOf("site-k1", AGENT_S);
        assertEquals(List.of("kid", "alg", "pk"), new ArrayList<>(k.keySet()));
        assertEquals("site-k1", k.get("kid"));
        assertEquals("ed25519", k.get("alg"));
        assertEquals(AGENT.id(), k.get("pk"));
        Map<String, Object> h = SignersMore.actionSchemaKeyOf("site-k2", HYBRID);
        assertEquals(List.of("kid", "alg", "pk", "pq_pk"), new ArrayList<>(h.keySet()));
        assertEquals("site-k2", h.get("kid"));
        assertEquals(HYB, h.get("alg"));
        assertEquals(AGENT.id(), h.get("pk"));
        assertEquals(PQ.pkB64u(), h.get("pq_pk"));
    }

    // ---- intent required ---------------------------------------------------------------------------------------------------

    static Map<String, Object> cellCoords() { return obj("a", List.of(0L, 5L), "b", List.of("x", "y")); }

    static List<Object> values(int from, int to) { List<Object> v = new ArrayList<>(); for (int i = from; i < to; i++) v.add("v" + i); return v; }

    @Test void cellCoordinatesAreOneToSixtyFourDimensions() {
        String text = "coords must be an object of 1..64 dimensions";
        for (Object c : Arrays.asList(null, "x", List.of("a"), 5L, obj())) assertEquals(text, SignersMore.cellCoordsError(c));
        assertNull(SignersMore.cellCoordsError(cellCoords()));
        Map<String, Object> many = new LinkedHashMap<>();
        for (int i = 0; i < 64; i++) many.put("k" + i, List.of("a"));
        assertNull(SignersMore.cellCoordsError(many));
        many.put("k64", List.of("a"));
        assertEquals(text, SignersMore.cellCoordsError(many));
        assertNull(SignersMore.cellCoordsError(obj("k", List.of("a"))));
    }

    @Test void aCoordinatePathIsOneToTwoHundredFiftySixCharacters() {
        String text = "a coordinate path must be 1..256 characters";
        assertEquals(text, SignersMore.cellCoordsError(obj("", List.of("a"))));
        assertEquals(text, SignersMore.cellCoordsError(obj(str(257, 'k'), List.of("a"))));
        assertNull(SignersMore.cellCoordsError(obj(str(256, 'k'), List.of("a"))));
        assertNull(SignersMore.cellCoordsError(obj("k", List.of("a"))));
    }

    @Test void anIndexRangeIsTwoNonNegativeOrderedIntegers() {
        String text = "coords 'r': need 0 <= lo <= hi";
        for (List<Long> r : List.of(List.of(5L, 4L), List.of(-1L, 3L), List.of(1L, 0L), List.of(-2L, -1L), List.of(-1L, -1L)))
            assertEquals(text, SignersMore.cellCoordsError(obj("r", r)), "" + r);
        for (List<Long> r : List.of(List.of(0L, 0L), List.of(5L, 5L), List.of(0L, 9007199254740991L), List.of(3L, 4L), List.of(1L, 1L), List.of(0L, 1L)))
            assertNull(SignersMore.cellCoordsError(obj("r", r)), "" + r);
        // minus zero is not an integer of the profile, so it is read as a (malformed) value set
        String set = "coords 'r': an index range [lo, hi] or a value set";
        assertEquals(set, SignersMore.cellCoordsError(obj("r", List.of(-0.0, 1L))));
        assertEquals(set, SignersMore.cellCoordsError(obj("r", List.of(new Json.Num("0.5"), 1L))));
        assertEquals(set, SignersMore.cellCoordsError(obj("r", List.of(0L, new Json.Num("1.5")))));
        assertEquals(set, SignersMore.cellCoordsError(obj("r", List.of(0L, 1L, 2L))));
    }

    @Test void aValueSetIsOneToTwoHundredFiftySixDistinctStrings() {
        String text = "coords 's': an index range [lo, hi] or a value set";
        for (Object v : Arrays.asList(null, "x", 5L, List.of(), List.of("a", 1L), List.of(1L, 2L, 3L), List.of(1L, "a"), List.of(1L), values(0, 257)))
            assertEquals(text, SignersMore.cellCoordsError(obj("s", v)), "" + v);
        assertEquals("coords 's': values must be distinct", SignersMore.cellCoordsError(obj("s", List.of("a", "a"))));
        assertEquals("coords 's': values must be distinct", SignersMore.cellCoordsError(obj("s", List.of("a", "b", "a"))));
        assertNull(SignersMore.cellCoordsError(obj("s", values(0, 256))));
        assertNull(SignersMore.cellCoordsError(obj("s", List.of("a"))));
        assertNull(SignersMore.cellCoordsError(obj("s", List.of("a", "b"))));
    }

    @Test void everyDimensionIsCheckedNotOnlyTheFirst() {
        assertEquals("coords 'bad': need 0 <= lo <= hi", SignersMore.cellCoordsError(obj("ok", List.of(0L, 1L), "bad", List.of(2L, 1L))));
        assertEquals("coords 'bad': values must be distinct", SignersMore.cellCoordsError(obj("ok", List.of("a"), "bad", List.of("z", "z"))));
        assertEquals("a coordinate path must be 1..256 characters", SignersMore.cellCoordsError(obj("ok", List.of("a"), "", List.of("z"))));
        assertEquals("coords 'bad': an index range [lo, hi] or a value set", SignersMore.cellCoordsError(obj("ok", List.of("a"), "bad", List.of())));
    }

    static Map<String, Object> irBody() { return argMap("sign_intent_required", "body"); }

    static Map<String, Object> irWith(String k, Object v) { Map<String, Object> b = irBody(); b.put(k, v); return b; }

    static Map<String, Object> irWithout(String k) { Map<String, Object> b = irBody(); b.remove(k); return b; }

    @Test void anIntentRequiredBodyIsWellFormedOrSaysWhy() {
        assertNull(SignersMore.intentRequiredShapeError(irBody()));
        for (Object b : Arrays.asList(null, "x", List.of(1L), 5L)) assertEquals("not an object", SignersMore.intentRequiredShapeError(b));
        assertEquals("unknown member 'extra'", SignersMore.intentRequiredShapeError(irWith("extra", 1L)));
        String v1 = "not a pca-intent-required v1";
        for (Object v : Arrays.asList(2L, 0L, "1", null, new Json.Num("1.5"), new Json.Num("9007199254740993")))
            assertEquals(v1, SignersMore.intentRequiredShapeError(irWith("v", v)), "v=" + v);
        assertEquals(v1, SignersMore.intentRequiredShapeError(irWithout("v")));
        assertEquals(v1, SignersMore.intentRequiredShapeError(irWith("kind", "pca-intent-requiredx")));
        assertEquals(v1, SignersMore.intentRequiredShapeError(irWithout("kind")));
    }

    @Test void theFiveDigestsAreCanonicalThirtyTwoByteValuesCheckedInOrder() {
        for (String k : List.of("session", "map_digest", "schema", "pcactn_digest", "action_digest")) {
            for (Object bad : Arrays.asList("x", Pca.b64(new byte[31]), Pca.b64(new byte[33]), null, 5L))
                assertEquals(k + " must be canonical base64url (32 bytes)", SignersMore.intentRequiredShapeError(irWith(k, bad)), k + "=" + bad);
        }
        Map<String, Object> two = irBody();
        two.put("session", "x");
        two.put("map_digest", "x");
        assertEquals("session must be canonical base64url (32 bytes)", SignersMore.intentRequiredShapeError(two));
        Map<String, Object> later = irBody();
        later.put("map_digest", "x");
        later.put("action_digest", "x");
        assertEquals("map_digest must be canonical base64url (32 bytes)", SignersMore.intentRequiredShapeError(later));
    }

    @Test void theCellIsExactlyAVerbAndCoordinates() {
        String text = "cell must be {verb, coords}";
        Map<String, Object> coords = cellCoords();
        for (Object c : Arrays.asList("x", null, obj("verb", "v", "coords", coords, "more", 1L), obj("coords", coords), obj("verb", "v"),
            obj("verb", "", "coords", coords), obj("verb", 5L, "coords", coords), obj("verb", "v", "other", coords),
            obj("coords", coords, "other", "v"), obj("verb", null, "coords", coords)))
            assertEquals(text, SignersMore.intentRequiredShapeError(irWith("cell", c)), "cell=" + c);
        assertEquals("coords must be an object of 1..64 dimensions", SignersMore.intentRequiredShapeError(irWith("cell", obj("verb", "refund", "coords", obj()))));
        assertEquals("coords 'a': need 0 <= lo <= hi", SignersMore.intentRequiredShapeError(irWith("cell", obj("verb", "refund", "coords", obj("a", List.of(2L, 1L))))));
        assertNull(SignersMore.intentRequiredShapeError(irWith("cell", obj("verb", "refund", "coords", coords))));
        assertNull(SignersMore.intentRequiredShapeError(irWith("cell", obj("coords", coords, "verb", "x"))));
    }

    @Test void theReasonQuestionFrictionAndDeliveryAreChecked() {
        assertEquals("reason must be 'uncertain'", SignersMore.intentRequiredShapeError(irWith("reason", "certain")));
        assertEquals("reason must be 'uncertain'", SignersMore.intentRequiredShapeError(irWithout("reason")));
        String qText = "question_id must match [A-Za-z0-9_-]{1,64}";
        for (Object q : Arrays.asList("", str(65, 'a'), "a b", 5L, null, "a.b")) assertEquals(qText, SignersMore.intentRequiredShapeError(irWith("question_id", q)), "q=" + q);
        for (String q : List.of("a", str(64, 'a'), "a-b_9", "Z")) assertNull(SignersMore.intentRequiredShapeError(irWith("question_id", q)), q);
        assertEquals(qText, SignersMore.intentRequiredShapeError(irWithout("question_id")));
        for (String f : List.of("tap", "hold", "typed", "device")) assertNull(SignersMore.intentRequiredShapeError(irWith("friction", f)), f);
        for (Object f : Arrays.asList("nope", "TAP", null, "", 1L)) assertEquals("unknown friction tier", SignersMore.intentRequiredShapeError(irWith("friction", f)), "f=" + f);
        assertEquals("unknown friction tier", SignersMore.intentRequiredShapeError(irWithout("friction")));
        for (String t : List.of("wallet", "agent")) assertNull(SignersMore.intentRequiredShapeError(irWith("delivered_to", t)), t);
        for (Object t : Arrays.asList("x", "Wallet", null, 1L))
            assertEquals("delivered_to must be 'wallet' or 'agent'", SignersMore.intentRequiredShapeError(irWith("delivered_to", t)), "t=" + t);
        assertEquals("delivered_to must be 'wallet' or 'agent'", SignersMore.intentRequiredShapeError(irWithout("delivered_to")));
    }

    @Test void theExpiryIsANonNegativeSafeIntegerAndTheBodyIsUnsigned() {
        String text = "expires_at must be a non-negative safe integer";
        for (Object e : Arrays.asList(-1L, "5", null, new Json.Num("9007199254740992"), new Json.Num("1.5"), -0.0))
            assertEquals(text, SignersMore.intentRequiredShapeError(irWith("expires_at", e)), "e=" + e);
        assertEquals(text, SignersMore.intentRequiredShapeError(irWithout("expires_at")));
        for (Object e : Arrays.asList(0L, 1L, 9007199254740991L)) assertNull(SignersMore.intentRequiredShapeError(irWith("expires_at", e)), "e=" + e);
        assertEquals("an unsigned body must not carry sig", SignersMore.intentRequiredShapeError(irWith("sig", obj())));
        assertEquals("an unsigned body must not carry sig", SignersMore.intentRequiredShapeError(irWith("sig", null)));
    }

    @Test void anIntentRequiredBodyIsSignedByTheSite() {
        Map<String, Object> body = irBody();
        Keys.SuiteKey site = Keys.ed25519(OPS.ed("site"));
        Map<String, Object> s = SignersMore.signIntentRequired(body, "site-k1", site);
        Map<String, Object> sig = m(s.get("sig"));
        assertEquals(List.of("alg", "kid", "value"), new ArrayList<>(sig.keySet()));
        assertEquals("ed25519", sig.get("alg"));
        assertEquals("site-k1", sig.get("kid"));
        byte[] msg = Pca.concat(utf8(SignersMore.INTENT_REQUIRED_DOMAIN), Pca.canonBytes(body));
        assertEquals(site.sign(msg)[0], sig.get("value"));
        assertFalse(body.containsKey("sig"), "the caller's body is not changed");
        for (String k : body.keySet()) assertEquals(canon(body.get(k)), canon(s.get(k)));
        Map<String, Object> h = m(SignersMore.signIntentRequired(body, "site-k1", HYBRID).get("sig"));
        assertEquals(List.of("alg", "kid", "value", "pq_value"), new ArrayList<>(h.keySet()));
        assertEquals(HYB, h.get("alg"));
        String[] want = HYBRID.sign(msg);
        assertEquals(want[0], h.get("value"));
        assertEquals(want[1], h.get("pq_value"));
        Map<String, Object> p = m(SignersMore.signIntentRequired(body, "site-k1", PURE_PQ).get("sig"));
        assertEquals(List.of("alg", "kid", "value"), new ArrayList<>(p.keySet()));
        assertEquals(PURE_PQ.sign(msg)[0], p.get("value"));
        assertEquals("signIntentRequired: unknown member 'extra'", refusal(() -> SignersMore.signIntentRequired(irWith("extra", 1L), "k", site)));
    }

    // ---- templates ---------------------------------------------------------------------------------------------------------

    @Test void aTemplateIsSignedByThePrincipalOverItsDigest() {
        Map<String, Object> def = m(caseArgs("sign_template", null).get("def"));
        Keys.EdKey p = OPS.ed("principal");
        Map<String, Object> t = SignersMore.signTemplate(def, p);
        assertEquals(List.of("def", "signer", "sig"), new ArrayList<>(t.keySet()));
        assertEquals(p.id(), t.get("signer"));
        byte[] msg = Pca.concat(utf8("atlas-pca/policy-template/v1\u0000"), Pca.sha(utf8(PolicyAuthoring.templateDigest(def))));
        assertEquals(Pca.b64(p.sign(msg)), t.get("sig"));
        assertNull(PolicyAuthoring.verifyTemplate(t, List.of(p.id())));
        String e = PolicyAuthoring.templateDefError(obj());
        assertTrue(e != null && !e.isEmpty());
        assertEquals("signTemplate: " + e, refusal(() -> SignersMore.signTemplate(obj(), p)));
    }

    @Test void aTightenOverlayIsSignedByThePrincipalOverItsHash() {
        Map<String, Object> overlay = m(caseArgs("sign_tighten", null).get("overlay"));
        Keys.EdKey p = OPS.ed("principal");
        Map<String, Object> t = SignersMore.signTighten(overlay, p);
        assertEquals(List.of("overlay", "signer", "sig"), new ArrayList<>(t.keySet()));
        assertEquals(p.id(), t.get("signer"));
        byte[] msg = Pca.concat(utf8("atlas-pca/template-tighten/v1\u0000"), Pca.sha(utf8(Pca.hashCanonical(overlay))));
        assertEquals(Pca.b64(p.sign(msg)), t.get("sig"));
        String e = PolicyAuthoring.tightenOverlayError(obj());
        assertTrue(e != null && !e.isEmpty());
        assertEquals("signTighten: " + e, refusal(() -> SignersMore.signTighten(obj(), p)));
    }

    // ---- revocation epoch --------------------------------------------------------------------------------------------------

    static final List<String> EPOCH_FIELDS = List.of("instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after");

    static Map<String, Object> epochBody() { return argMap("sign_revocation_epoch", "body"); }

    @Test void aRevocationEpochNeedsEveryField() {
        for (String k : EPOCH_FIELDS) {
            Map<String, Object> b = epochBody();
            b.remove(k);
            assertEquals("signRevocationEpoch: " + k + " required", refusal(() -> SignersMore.signRevocationEpoch(AGENT_S, b)));
        }
        Map<String, Object> two = epochBody();
        two.remove("epoch");
        two.remove("root");
        assertEquals("signRevocationEpoch: epoch required", refusal(() -> SignersMore.signRevocationEpoch(AGENT_S, two)));
    }

    @Test void aRevocationEpochIsSignedByTheGuardianOverItsFieldsAndTheSuite() {
        Map<String, Object> body = epochBody();
        body.put("zzz", 1L);
        Map<String, Object> e = SignersMore.signRevocationEpoch(AGENT_S, body);
        Set<String> keys = new HashSet<>(EPOCH_FIELDS);
        keys.add("guardian");
        keys.add("sig");
        assertEquals(keys, e.keySet());
        assertEquals(AGENT.id(), e.get("guardian"));
        assertEquals(Pca.b64(AGENT.sign(Pca.concat(utf8(IntentRevocation.REVEPOCH_DOMAIN), Pca.canonBytes(epochBody())))), e.get("sig"));
        assertFalse(body.containsKey("sig"));
        // numbers come back as the canonical Json.Num whatever type the caller used
        Map<String, Object> ints = epochBody();
        ints.put("epoch", 3);
        ints.put("set_size", 2);
        Map<String, Object> ie = SignersMore.signRevocationEpoch(AGENT_S, ints);
        assertTrue(ie.get("epoch") instanceof Json.Num);
        assertTrue(ie.get("set_size") instanceof Json.Num);
        Map<String, Object> longs = epochBody();
        longs.put("epoch", 3L);
        longs.put("set_size", 2L);
        assertEquals(ie.get("sig"), SignersMore.signRevocationEpoch(AGENT_S, longs).get("sig"));

        Map<String, Object> h = SignersMore.signRevocationEpoch(HYBRID, body);
        Set<String> hk = new HashSet<>(keys);
        hk.addAll(List.of("alg", "pq_pk", "pq_sig"));
        assertEquals(hk, h.keySet());
        assertEquals(HYB, h.get("alg"));
        assertEquals(PQ.pkB64u(), h.get("pq_pk"));
        Map<String, Object> bound = epochBody();
        bound.put("alg", HYB);
        bound.put("pq_pk", PQ.pkB64u());
        String[] sg = HYBRID.sign(Pca.concat(utf8(IntentRevocation.REVEPOCH_DOMAIN), Pca.canonBytes(bound)));
        assertEquals(sg[0], h.get("sig"));
        assertEquals(sg[1], h.get("pq_sig"));
        assertFalse(body.containsKey("alg"), "the caller's body is not changed");

        // a pure post-quantum guardian with an Ed25519 identity: alg and pq_pk are bound, sig is the PQ signature, no pq_sig
        Map<String, Object> p = SignersMore.signRevocationEpoch(PURE_PQ_ED, epochBody());
        Set<String> pk = new HashSet<>(keys);
        pk.addAll(List.of("alg", "pq_pk"));
        assertEquals(pk, p.keySet());
        Map<String, Object> pb = epochBody();
        pb.put("alg", "ml-dsa-65");
        pb.put("pq_pk", PQ.pkB64u());
        assertEquals(PURE_PQ_ED.sign(Pca.concat(utf8(IntentRevocation.REVEPOCH_DOMAIN), Pca.canonBytes(pb)))[0], p.get("sig"));
    }

    // ---- constitution ------------------------------------------------------------------------------------------------------

    @Test void aConstitutionIsSignedOverItsIdOrRefusedWithEveryProblem() {
        Map<String, Object> c = m(caseArgs("sign_constitution", null).get("constitution"));
        String before = canon(c);
        Keys.EdKey p = OPS.ed("principal");
        Map<String, Object> s = SignersMore.signConstitution(c, p);
        String id = Prohibitions.constitutionId(c);
        assertEquals(id, s.get("id"));
        assertEquals(Pca.b64(p.sign(Prohibitions.domainMessage(Prohibitions.CONSTITUTION_SIG_DOMAIN, id))), s.get("sig"));
        assertNull(Prohibitions.verifyConstitution(s, p.id()));
        assertEquals(before, canon(c), "the caller's constitution is not changed");
        assertNotSame(c, s);
        List<String> problems = Prohibitions.validateConstitution(obj());
        assertTrue(problems.size() >= 2, "an empty constitution has several problems");
        assertEquals("signConstitution: " + String.join("; ", problems), refusal(() -> SignersMore.signConstitution(obj(), p)));
    }

    // ---- mesh: the leaf's action signature ---------------------------------------------------------------------------------

    static final Keys.EdKey LEAF = Keys.edFromSeed(fill(32, 11));
    static final Map<String, Object> CAP0 = obj("id", "cap-0", "holder", "h0");
    static final Map<String, Object> CAP1 = obj("id", "cap-1", "holder", "h1");
    static final Map<String, Object> ACTION = obj("verb", "read", "resource", "doc/1");

    static String actionSig(Map<String, Object> tipCap) {
        return Pca.b64(LEAF.sign(Pca.concat(utf8(Mesh.ACTION_DOMAIN), Pca.canonBytes(obj("action", ACTION, "tip", Pca.capHash(tipCap))))));
    }

    @Test void theLeafSignsTheActionBoundToTheLastHopOfTheChain() {
        String sig = SignersMore.signMeshAction(List.of(CAP0, CAP1), ACTION, LEAF);
        assertEquals(actionSig(CAP1), sig);
        assertNotEquals(actionSig(CAP0), sig);
        assertEquals(actionSig(CAP0), SignersMore.signMeshAction(List.of(CAP0), ACTION, LEAF));
    }

    @Test void anEmptyChainIsRefused() {
        assertEquals("signMeshAction: empty chain", refusal(() -> SignersMore.signMeshAction(List.of(), ACTION, LEAF)));
        assertEquals("signMeshAction: empty chain", refusal(() -> SignersMore.signMeshAction(null, ACTION, LEAF)));
        assertEquals("signMeshAction: empty chain", refusal(() -> SignersMore.assembleMeshProof(List.of(), List.of(), ACTION, LEAF, null)));
    }

    // ---- mesh: the compact proof (mesh.ts assembleMeshProof) -----------------------------------------------------------------

    static Map<String, Object> leafOf(String id) { return obj("id", id); }

    static Map<String, Object> head(long n, String root) { return obj("size", n, "root", root); }

    static Map<String, Object> cosig(String w) { return obj("witness", w, "sig", "sig-" + w); }

    static Map<String, Object> hop(Object domain, Map<String, Object> head, Object inclusion, Map<String, Object> cap, Map<String, Object> issuerKey) {
        return obj("domain", domain, "head", head, "inclusion", inclusion, "revocation", obj("cap", cap, "issuer_key", issuerKey));
    }

    static Map<String, Object> cosigned(Map<String, Object> h, String sig, List<Object> cosigs) { return obj("head", h, "sig", sig, "cosigs", cosigs); }

    static Map<String, Object> plainHop() { return hop("d", cosigned(head(1L, "r"), "s", List.of()), obj("path", List.of()), obj("size", 0L), obj("size", 0L)); }

    static Map<String, Object> proof(Object... hops) { return SignersMore.assembleMeshProof(List.of(CAP0), Arrays.asList(hops), ACTION, LEAF, null); }

    @Test void hopsOnTheSameHeadShareOneTableEntryAndLeavesAreCarriedOnce() {
        Map<String, Object> h1 = head(1L, "r1"), h2 = head(2L, "r2");
        List<Object> hop0Cosigs = new ArrayList<>(List.of(cosig("w1")));
        Map<String, Object> hop0 = hop("d0", cosigned(h1, "s1", hop0Cosigs), obj("path", List.of("x")),
            obj("size", 2L, "lo", leafOf("L1"), "hi", leafOf("H1")), obj("size", 2L, "lo", leafOf("L1")));
        hop0.put("binding", obj("b", 1L));
        Map<String, Object> hop1 = hop("d1", cosigned(h1, "s1", List.of(cosig("w1"), cosig("w2"))), obj("path", List.of("y")),
            obj("size", 3L, "lo", leafOf("L2")), obj("size", 2L, "hi", leafOf("H1")));
        Map<String, Object> hop2 = hop("d2", cosigned(h1, "s2", List.of()), obj("path", List.of()), obj("size", 5L, "lo", leafOf("L1")), obj("size", 1L));
        Map<String, Object> hop3 = hop("d3", cosigned(h2, "s1", List.of(cosig("w3"))), obj("path", List.of("z")), obj("size", 1L), obj("size", 1L));
        hop3.put("binding", null);
        List<Object> chain = new ArrayList<>(List.of(CAP0, CAP1));
        Map<String, Object> p = SignersMore.assembleMeshProof(chain, List.of(hop0, hop1, hop2, hop3), ACTION, LEAF, null);

        Map<String, Object> expected = obj(
            "chain", List.of(CAP0, CAP1),
            "heads", List.of(
                obj("head", h1, "sig", "s1", "cosigs", List.of(cosig("w1"), cosig("w2"))),
                obj("head", h1, "sig", "s2", "cosigs", List.of()),
                obj("head", h2, "sig", "s1", "cosigs", List.of(cosig("w3")))),
            "rev_leaves", List.of(leafOf("L1"), leafOf("H1"), leafOf("L2")),
            "hops", List.of(
                obj("domain", "d0", "head", 0L, "inclusion", obj("path", List.of("x")),
                    "revocation", obj("cap", obj("size", 2L, "lo", 0L, "hi", 1L), "issuer_key", obj("size", 2L, "lo", 0L)), "binding", obj("b", 1L)),
                obj("domain", "d1", "head", 0L, "inclusion", obj("path", List.of("y")),
                    "revocation", obj("cap", obj("size", 3L, "lo", 2L), "issuer_key", obj("size", 2L, "hi", 1L))),
                obj("domain", "d2", "head", 1L, "inclusion", obj("path", List.of()),
                    "revocation", obj("cap", obj("size", 5L, "lo", 0L), "issuer_key", obj("size", 1L))),
                obj("domain", "d3", "head", 2L, "inclusion", obj("path", List.of("z")),
                    "revocation", obj("cap", obj("size", 1L), "issuer_key", obj("size", 1L)))),
            "action", ACTION,
            "action_sig", actionSig(CAP1));
        assertEquals(canon(expected), canon(p));
        assertEquals(List.of("chain", "heads", "rev_leaves", "hops", "action", "action_sig"), new ArrayList<>(p.keySet()));
        // the caller's own cosignature list is not merged into, and the chain is a copy
        assertEquals(1, hop0Cosigs.size());
        assertNotSame(chain, p.get("chain"));
        chain.add(CAP0);
        assertEquals(2, l(p.get("chain")).size());
    }

    @Test void aRepeatedHeadPastTheFirstEntryMergesIntoItsOwnEntry() {
        Map<String, Object> a = head(1L, "ra"), b = head(2L, "rb");
        Map<String, Object> p = proof(
            hop("d0", cosigned(a, "sa", List.of(cosig("w1"))), obj(), obj("size", 0L), obj("size", 0L)),
            hop("d1", cosigned(b, "sb", List.of(cosig("w2"))), obj(), obj("size", 0L), obj("size", 0L)),
            hop("d2", cosigned(b, "sb", List.of(cosig("w2"), cosig("w3"))), obj(), obj("size", 0L), obj("size", 0L)));
        assertEquals(canon(List.of(
            obj("head", a, "sig", "sa", "cosigs", List.of(cosig("w1"))),
            obj("head", b, "sig", "sb", "cosigs", List.of(cosig("w2"), cosig("w3"))))), canon(p.get("heads")));
        List<Object> idx = new ArrayList<>();
        for (Object h : l(p.get("hops"))) idx.add(m(h).get("head"));
        assertEquals(List.of(0L, 1L, 1L), idx);
    }

    @Test void theSameLeafInAnyMemberOrderIsOneEntry() {
        Map<String, Object> ab = obj("a", 1L, "b", 2L), ba = obj("b", 2L, "a", 1L);
        Map<String, Object> p = proof(hop("d", cosigned(head(1L, "r"), "s", List.of()), obj(), obj("size", 2L, "lo", ab, "hi", ba), obj("size", 2L, "hi", ab)));
        assertEquals(1, l(p.get("rev_leaves")).size());
        assertEquals("{\"cap\":{\"hi\":0,\"lo\":0,\"size\":2},\"issuer_key\":{\"hi\":0,\"size\":2}}", canon(m(l(p.get("hops")).get(0)).get("revocation")));
    }

    @Test void cosignaturesAreMergedByWitness() {
        Map<String, Object> h = head(1L, "r");
        // a cosignature without a witness (or that is not an object) has an undefined witness in the reference: one such entry is kept
        Map<String, Object> p = proof(
            hop("a", cosigned(h, "s", List.of(obj("sig", "x"))), obj(), obj("size", 0L), obj("size", 0L)),
            hop("b", cosigned(h, "s", List.of(5L, cosig("w"))), obj(), obj("size", 0L), obj("size", 0L)),
            hop("c", cosigned(h, "s", List.of(cosig("w"), cosig("v"))), obj(), obj("size", 0L), obj("size", 0L)));
        assertEquals(canon(List.of(obj("sig", "x"), cosig("w"), cosig("v"))), canon(m(l(p.get("heads")).get(0)).get("cosigs")));
        assertEquals(1, l(p.get("heads")).size());
    }

    @Test void aNullCosignatureIsRefusedWhereTheReferenceReadsItsWitness() {
        Map<String, Object> h = head(1L, "r");
        String text = "assembleMeshProof: a cosignature is null";
        // a first hop's null cosignature is only copied (the reference reads no witness there)
        Map<String, Object> one = proof(hop("a", cosigned(h, "s", Arrays.asList((Object) null)), obj(), obj("size", 0L), obj("size", 0L)));
        assertEquals("[null]", canon(m(l(one.get("heads")).get(0)).get("cosigs")));
        assertEquals(text, refusal(() -> proof(
            hop("a", cosigned(h, "s", Arrays.asList((Object) null)), obj(), obj("size", 0L), obj("size", 0L)),
            hop("b", cosigned(h, "s", List.of(cosig("w"))), obj(), obj("size", 0L), obj("size", 0L)))));
        assertEquals(text, refusal(() -> proof(
            hop("a", cosigned(h, "s", List.of(cosig("w"))), obj(), obj("size", 0L), obj("size", 0L)),
            hop("b", cosigned(h, "s", Arrays.asList(cosig("v"), null)), obj(), obj("size", 0L), obj("size", 0L)))));
    }

    @Test void evidenceWithoutACosignedHeadOrItsBracketingIsRefused() {
        String headText = "assembleMeshProof: hop evidence needs a cosigned head with a cosigs array";
        String revText = "assembleMeshProof: hop evidence needs its revocation bracketing";
        for (Object cs : Arrays.asList(null, "w", 5L, obj())) {
            Map<String, Object> e = plainHop();
            m(e.get("head")).put("cosigs", cs);
            assertEquals(headText, refusal(() -> proof(e)), "cosigs=" + cs);
        }
        Map<String, Object> noCosigs = plainHop();
        m(noCosigs.get("head")).remove("cosigs");
        assertEquals(headText, refusal(() -> proof(noCosigs)));
        for (Object hd : Arrays.asList(null, "x", 5L)) {
            Map<String, Object> e = plainHop();
            e.put("head", hd);
            assertEquals(headText, refusal(() -> proof(e)), "head=" + hd);
        }
        Map<String, Object> noHead = plainHop();
        noHead.remove("head");
        assertEquals(headText, refusal(() -> proof(noHead)));
        assertEquals(headText, refusal(() -> proof((Object) null)));
        for (String side : List.of("cap", "issuer_key")) {
            Map<String, Object> absent = plainHop();
            m(absent.get("revocation")).remove(side);
            assertEquals(revText, refusal(() -> proof(absent)), side + " absent");
            Map<String, Object> nul = plainHop();
            m(nul.get("revocation")).put(side, null);
            assertEquals(revText, refusal(() -> proof(nul)), side + " null");
        }
        Map<String, Object> noRev = plainHop();
        noRev.remove("revocation");
        assertEquals(revText, refusal(() -> proof(noRev)));
        // a bracketing that is not an object has no members: {} (the reference reads undefined members off it)
        Map<String, Object> odd = plainHop();
        m(odd.get("revocation")).put("cap", 5L);
        assertEquals("{}", canon(m(m(m(l(proof(odd).get("hops")).get(0)).get("revocation")).get("cap"))));
    }

    @Test void membersTheEvidenceLeavesOutStayOut() {
        Map<String, Object> e = plainHop();
        e.remove("domain");
        e.remove("inclusion");
        m(m(e.get("revocation")).get("cap")).remove("size");
        Map<String, Object> hd = m(e.get("head"));
        hd.remove("head");
        hd.remove("sig");
        Map<String, Object> p = proof(e);
        Map<String, Object> o = m(l(p.get("hops")).get(0));
        assertEquals(List.of("head", "revocation"), new ArrayList<>(o.keySet()));
        assertEquals("{\"cap\":{},\"issuer_key\":{\"size\":0}}", canon(o.get("revocation")));
        assertEquals(List.of("cosigs"), new ArrayList<>(m(l(p.get("heads")).get(0)).keySet()));

        // a member given as null is carried as null
        Map<String, Object> n = plainHop();
        n.put("domain", null);
        n.put("inclusion", null);
        m(m(n.get("revocation")).get("cap")).put("size", null);
        m(n.get("head")).put("sig", null);
        Map<String, Object> pn = proof(n);
        Map<String, Object> on = m(l(pn.get("hops")).get(0));
        assertEquals(List.of("domain", "head", "inclusion", "revocation"), new ArrayList<>(on.keySet()));
        assertNull(on.get("domain"));
        assertNull(on.get("inclusion"));
        assertEquals("{\"size\":null}", canon(m(on.get("revocation")).get("cap")));
        assertEquals(List.of("head", "sig", "cosigs"), new ArrayList<>(m(l(pn.get("heads")).get(0)).keySet()));
    }

    @Test void aFalsyBracketingLeafOrBindingIsDropped() {
        for (Object v : Arrays.asList(null, 0L, new Json.Num("0"), "", false, 0.0)) {
            Map<String, Object> e = plainHop();
            m(m(e.get("revocation")).get("cap")).put("lo", v);
            m(m(e.get("revocation")).get("issuer_key")).put("hi", v);
            e.put("binding", v);
            Map<String, Object> p = proof(e);
            Map<String, Object> o = m(l(p.get("hops")).get(0));
            assertFalse(o.containsKey("binding"), "binding " + v);
            assertEquals("{\"cap\":{\"size\":0},\"issuer_key\":{\"size\":0}}", canon(o.get("revocation")), "leaf " + v);
            assertEquals(0, l(p.get("rev_leaves")).size());
        }
        for (Object v : Arrays.asList(5L, "x", true, List.of())) {
            Map<String, Object> e = plainHop();
            m(m(e.get("revocation")).get("cap")).put("hi", v);
            e.put("binding", v);
            Map<String, Object> p = proof(e);
            Map<String, Object> o = m(l(p.get("hops")).get(0));
            assertEquals(canon(v), canon(o.get("binding")), "binding " + v);
            assertEquals("{\"hi\":0,\"size\":0}", canon(m(o.get("revocation")).get("cap")), "leaf " + v);
            assertEquals(canon(List.of(v)), canon(p.get("rev_leaves")));
        }
    }

    @Test void pinProofsAreCarriedOnlyWhenThereAreSome() {
        List<Object> chain = List.of(CAP0);
        assertFalse(SignersMore.assembleMeshProof(chain, List.of(plainHop()), ACTION, LEAF, null).containsKey("pin_proofs"));
        assertFalse(SignersMore.assembleMeshProof(chain, List.of(plainHop()), ACTION, LEAF, List.of()).containsKey("pin_proofs"));
        List<Object> pins = new ArrayList<>(List.of(obj("pin", 1L)));
        Map<String, Object> p = SignersMore.assembleMeshProof(chain, List.of(plainHop()), ACTION, LEAF, pins);
        assertEquals(canon(List.of(obj("pin", 1L))), canon(p.get("pin_proofs")));
        assertNotSame(pins, p.get("pin_proofs"));
        assertEquals(List.of("chain", "heads", "rev_leaves", "hops", "action", "action_sig", "pin_proofs"), new ArrayList<>(p.keySet()));
    }

    @Test void aProofWithNoHopsHasEmptyTables() {
        Map<String, Object> p = SignersMore.assembleMeshProof(List.of(CAP0), List.of(), ACTION, LEAF, null);
        assertEquals(0, l(p.get("heads")).size());
        assertEquals(0, l(p.get("rev_leaves")).size());
        assertEquals(0, l(p.get("hops")).size());
        assertEquals(1, l(p.get("chain")).size());
        assertEquals(actionSig(CAP0), p.get("action_sig"));
        assertEquals(canon(ACTION), canon(p.get("action")));
    }
}
