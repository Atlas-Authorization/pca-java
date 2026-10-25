package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Intent Layer v2 W-A mutation kills: the {@code intent_session} wire (rule 13), the session root, delta chain and
 * revocation (rule 13), the closed-world schema check (rule 14), accumulators / monitors / receipts / sequencer key sets
 * (rule 15), the {@code layers} slot and the pipeline's reporting and order, signed end to end (the scenario mirrors
 * packages/pca/scripts/gen-conformance-intent-v2.mjs).
 */
public class IntentV2KillTest {
    static final long NOW = 1_800_000_000_000L;
    static final String AUD = "skyair.example";

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }
    @SafeVarargs static <T> List<Object> list(T... xs) { return new ArrayList<>(Arrays.asList(xs)); }
    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static Map<String, Object> deep(Map<String, Object> o) { return (Map<String, Object>) Json.parseLenient(Json.canonicalize(o)); }

    // ---- keys: seed = sha256("atlas-pca-conformance/<label>") ----
    static byte[] seed(String label) {
        try { return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8)); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
    static String pub(String label) {
        byte[] pk = new byte[32];
        org.bouncycastle.math.ec.rfc8032.Ed25519.generatePublicKey(seed(label), 0, pk, 0);
        return Pca.b64(pk);
    }
    static String sign(String label, byte[] msg) {
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(seed(label), 0, msg, 0, msg.length, sig, 0);
        return Pca.b64(sig);
    }
    static String b64seed(String label) { return Pca.b64(seed(label)); }

    static final String PRINCIPAL = "v2/principal", AGENT = "v2/agent", SITE = "v2/site", SEQ_ROOT = "v2/sequencer-root", SEQ_KEY = "v2/sequencer", STRANGER = "v2/stranger";
    static final String REF = b64seed("v2/ref"), MAP0 = b64seed("v2/map0"), MAP1 = b64seed("v2/map1"), SESSION = b64seed("v2/session");

    // ---- the site schema ----
    static Map<String, Object> unsignedSchema() {
        Map<String, Object> book = map("verb", "air.book", "kind", "write", "params", map(
            "action.params.offer_id", map("type", "string", "semantic", "product.ref", "sensitivity", "material"),
            "action.params.total", map("type", "integer", "unit", "usd_cents", "min", 0L, "max", 5_000_000L, "semantic", "money.amount", "sensitivity", "critical",
                "accumulates_into", list("spend.usd_cents")),
            "action.params.add_ons", map("type", "set", "values", list("none", "tripshield", "seat_plus"), "default", list("none"), "principal_neutral_default", true,
                "semantic", "product.addon", "sensitivity", "material"),
            "action.params.refundable", map("type", "boolean", "semantic", "flag", "sensitivity", "material"),
            "action.params.passengers", map("type", "array", "max_items", 9L, "max_len", 64L, "semantic", "person.identity", "sensitivity", "critical", "required", false),
            "action.params.note", map("type", "string", "semantic", "text.note", "sensitivity", "free", "required", false, "max_len", 16L)),
            "reversibility_by", map("param", "action.params.refundable", "map", map("true", "reversible", "false", "irreversible")));
        Map<String, Object> search = map("verb", "air.search", "kind", "read", "params", map(
            "action.params.from", map("type", "string", "values", list("SFO", "JFK"), "semantic", "place.airport", "sensitivity", "material"),
            "action.params.date", map("type", "date", "semantic", "schedule.date", "sensitivity", "material"),
            "action.params.pax", map("type", "integer", "min", 1L, "max", 9L, "semantic", "quantity", "sensitivity", "material")),
            "reversibility", "reversible");
        return map("v", 1L, "kind", "pca-action-schema", "site", "https://skyair.example", "aud", AUD, "version", "2026-10-01",
            "units", map("usd_cents", map("kind", "money", "currency", "USD", "exponent", 2L)), "verbs", list(book, search));
    }
    static Map<String, Object> signSchema(Map<String, Object> unsigned, String kid, String key) {
        String sig = sign(key, IntentJs.message(ActionSchema.ACTION_SCHEMA_DOMAIN, unsigned));
        Map<String, Object> s = new LinkedHashMap<>(unsigned);
        s.put("sig", map("alg", "ed25519", "kid", kid, "value", sig));
        return s;
    }
    static final Map<String, Object> SCHEMA = signSchema(unsignedSchema(), "skyair-2026", SITE);
    static final List<Object> KEYS = list(map("kid", "skyair-2026", "alg", "ed25519", "pk", pub(SITE)));
    static final String SD = ActionSchema.digest(SCHEMA);

    // ---- session roots ----
    static Map<String, Object> trip() {
        return map("id", "trip_spend", "agg", "sum", "unit", "usd_cents", "sel", map("accumulates_into", "spend.usd_cents"), "win", map("kind", "task"), "key", null,
            "domain_max", 500_000L, "holder", map("kind", "site_local"));
    }
    static Map<String, Object> questions() {
        return map("id", "questions", "agg", "count", "sel", map("event", "intent_required"), "win", map("kind", "task"), "key", null, "cap", 6L, "holder", map("kind", "wallet"));
    }
    static Map<String, Object> rootBody() {
        return map("v", 1L, "kind", "pca-intent-session", "session", SESSION, "principals", list(map("key", pub(PRINCIPAL))), "intent_ref", REF,
            "schema", map("aud", AUD, "digest", SD), "layers", map("task", map("map_digest", MAP0)), "accumulators", list(trip(), questions()), "monitors", list(),
            "question_uri", "https://atlas.example/q", "expires_at", NOW + 86_400_000L);
    }
    static Map<String, Object> signRoot(Map<String, Object> body, String key) {
        Map<String, Object> s = new LinkedHashMap<>(body);
        s.put("signer", pub(key));
        s.put("sig", sign(key, IntentJs.message(IntentSession.INTENT_SESSION_SIG_DOMAIN, s)));
        return s;
    }
    static final Map<String, Object> S = signRoot(rootBody(), PRINCIPAL);
    static final String R = IntentSession.rootDigest(S);

    // ---- grants ----
    static Map<String, Object> mint(long seq, String prev, String mapDigest, String salt, String signer, String root) {
        Map<String, Object> env = map("type", "envelope", "goal_commit", Pca.intentGoalCommitV2(SESSION, mapDigest, salt), "predicates", list(map("verb", "air.book")),
            "caveats", list(), "agent_binding", map());
        Map<String, Object> sc = map("type", "intent_session", "session", SESSION, "seq", seq, "root", root);
        if (prev != null) sc.put("prev", prev);
        Map<String, Object> body = map("issuer", pub(signer), "holder", pub(AGENT), "caveats", list(env, sc), "parent", null);
        String digest = Pca.hashCanonical(body);
        byte[] msg = Pca.concat(Pca.CAP_DOMAIN, Pca.decodeB64uStrict(digest, 32));
        return map("id", digest, "issuer", pub(signer), "holder", pub(AGENT), "caveats", body.get("caveats"), "body_digest", digest, "sig", sign(signer, msg));
    }
    static final Map<String, Object> G0 = mint(0, null, MAP0, "salt0", PRINCIPAL, R);
    static final Map<String, Object> D1 = mint(1, (String) G0.get("id"), MAP1, "salt1", PRINCIPAL, R);

    static Map<String, Object> params() { return map("offer_id", "OF-1", "total", 38_900L, "add_ons", list("none"), "refundable", false); }

    /** A signed PCActn under {@code grant} carrying {@code intent} (goal salt / map) and, when non-null, {@code is}. */
    static Map<String, Object> build(Map<String, Object> grant, String salt, String mapDigest, Map<String, Object> is, Map<String, Object> params, String ref) {
        Map<String, Object> action = map("verb", "air.book", "resource", "skyair.example/bookings", "params_digest", Pca.paramsDigest(params), "reversibility_class", "irreversible");
        Map<String, Object> leaf = Pca.planLeaf("book", action, Pca.conditionsDigest(null, null));
        Map<String, Object> p = map("ver", 2L, "action", action, "grant_ref", grant.get("id"), "cap_chain", list(grant),
            "plan", map("root", Pca.merkleRoot(list(leaf)), "inclusion_proof", map("index", 0L, "size", 1L, "path", list()), "node_id", "book"),
            "attestation", map("quote_digest", "", "epoch", 0L, "model_id", "unattested", "measurement", "", "operator", "unattested"),
            "provenance", map("causal_hash", "", "taint_level", 0L, "trusted_refs", list()),
            "freshness", map("beacon_ref", "", "epoch", 0L, "accumulator_witness", ""), "counter", 1L, "risk_claim", map("r", 0L, "inputs", map()),
            "aud", AUD, "iat", NOW, "exp", NOW + 600_000L,
            "intent", map("ref", ref, "map_digest", mapDigest, "goal_salt", salt, "fidelity_ppm", 1_000_000L, "residual_risk_ppm", 0L));
        if (is != null) p.put("intent_session", is);
        return resign(p);
    }
    static Map<String, Object> resign(Map<String, Object> p) {
        p.remove("sig");
        p.put("sig", sign(AGENT, Pca.thresholdMessage(p)));
        return p;
    }
    static Map<String, Object> is0(Object... over) {
        Map<String, Object> is = map("session", SESSION, "root", R, "seq", 0L, "schema", SD, "acc", list(map("id", "trip_spend", "post", 38_900L)));
        for (int i = 0; i < over.length; i += 2) is.put((String) over[i], over[i + 1]);
        return is;
    }
    static Map<String, Object> ctx(Object... over) {
        Map<String, Object> c = map("params", params(), "schema", map("docs", list(SCHEMA), "keys", KEYS), "session", map("root", S, "grants", list()),
            "acc", map("state", map("trip_spend", map("sum", 0L)), "monitors", map()));
        for (int i = 0; i < over.length; i += 2) c.put((String) over[i], over[i + 1]);
        return c;
    }
    static Pca.Verdict verify(Map<String, Object> grant, Map<String, Object> p, Map<String, Object> ctx) {
        return Pca.verifyPcactn(p, grant, NOW, AUD, null, null, IntentV2.Context.fromJson(ctx));
    }
    static final List<String> CORE = List.of("wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter", "intent");
    static List<String> keys(String... extra) { List<String> k = new ArrayList<>(CORE); k.addAll(Arrays.asList(extra)); return k; }
    static List<String> failed(Pca.Verdict v) {
        List<String> f = new ArrayList<>();
        for (Map.Entry<String, Boolean> e : v.checks.entrySet()) if (!e.getValue()) f.add(e.getKey());
        return f;
    }

    /** G_0 accepted end to end (the {@code session-g0} vector). */
    static Pca.Verdict g0Verdict() { return verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx()); }

    // ------------------------------------------------------------------ pipeline: acceptance, reporting, order
    @Test void acceptsG0AndD1() {
        Pca.Verdict v = g0Verdict();
        assertTrue(v.allow, v.reason);
        assertEquals(keys("schema", "intent_session", "accumulators"), new ArrayList<>(v.checks.keySet()));
        Map<String, Object> p1 = build(D1, "salt1", MAP1, is0("seq", 1L, "acc", list(map("id", "trip_spend", "post", 77_800L))), params(), REF);
        Pca.Verdict d1 = verify(D1, p1, ctx("session", map("root", S, "grants", list(G0)), "acc", map("state", map("trip_spend", map("sum", 38_900L)), "monitors", map())));
        assertTrue(d1.allow, d1.reason);
        Pca.Verdict unheld = verify(D1, p1, ctx("acc", map("state", map("trip_spend", map("sum", 38_900L)), "monitors", map())));
        assertEquals(List.of("intent_session"), failed(unheld));
    }

    @Test void backCompatAndPolicies() {
        Map<String, Object> plain = build(G0, "salt0", MAP0, null, params(), REF);
        // no intent_session, no v2 policy: no v2 key; the v1 goal does not open the v2 grant
        Pca.Verdict v = verify(G0, plain, ctx());
        assertEquals(CORE, new ArrayList<>(v.checks.keySet()));
        assertEquals(List.of("intent"), failed(v));
        Pca.Verdict none = Pca.verifyPcactn(plain, G0, NOW, AUD, null, null, null);
        assertEquals(CORE, new ArrayList<>(none.checks.keySet()));
        // session.require: intent_session reported and failed
        Pca.Verdict req = verify(G0, plain, ctx("policy", map("session", map("require", true))));
        assertEquals(keys("intent_session"), new ArrayList<>(req.checks.keySet()));
        assertEquals(List.of("intent", "intent_session"), failed(req));
        // require false: no v2 key; a non-boolean flag (or null) makes the context malformed: schema and intent_session fail
        assertEquals(CORE, new ArrayList<>(verify(G0, plain, ctx("policy", map("session", map("require", false)))).checks.keySet()));
        for (Object notBool : new Object[] {"true", 1L, null}) {
            Pca.Verdict m = verify(G0, plain, ctx("policy", map("session", map("require", notBool))));
            assertEquals(keys("schema", "intent_session"), new ArrayList<>(m.checks.keySet()), String.valueOf(notBool));
            assertEquals(List.of("intent", "schema", "intent_session"), failed(m), String.valueOf(notBool));
        }
        // the policy is closed: an unknown member is malformed
        assertEquals(List.of("intent", "schema", "intent_session"), failed(verify(G0, plain, ctx("policy", map("extra", true)))));
        assertEquals(List.of("intent", "schema", "intent_session"), failed(verify(G0, plain, ctx("policy", map("session", map("reqiure", true))))));
        // a malformed top-level member fails accumulators too when the PCActn carries intent_session
        assertEquals(List.of("schema", "intent_session", "accumulators"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx("params", null))));
        // a present intent_v2 that is not an object is malformed (never "no context")
        assertEquals(List.of("intent", "schema", "intent_session"), failed(Pca.verifyPcactn(plain, G0, NOW, AUD, null, null, IntentV2.Context.fromJson(null))));
        // closed world: schema runs against the FIRST schema and passes
        Pca.Verdict cw = verify(G0, plain, ctx("policy", map("schema", map("closed_world", true))));
        assertEquals(keys("schema"), new ArrayList<>(cw.checks.keySet()));
        assertEquals(List.of("intent"), failed(cw));
        assertEquals(List.of("intent", "schema", "intent_session"), failed(verify(G0, plain, ctx("policy", map("schema", map("closed_world", "true"))))));
    }

    @Test void rule12V2Goal() {
        // the v2 goal is opened through intent_session.session, never through the v1 ref goal
        Pca.Verdict v = g0Verdict();
        assertTrue(v.checks.get("intent"));
        Map<String, Object> other = is0("session", b64seed("v2/other-session"));
        Pca.Verdict w = verify(G0, build(G0, "salt0", MAP0, other, params(), REF), ctx());
        assertFalse(w.checks.get("intent"));
        assertEquals(Pca.intentGoalCommitV2(SESSION, MAP0, "s"), Pca.intentGoalCommitV2(SESSION, MAP0, "s"));
        assertNotEquals(Pca.intentGoalCommitV2(SESSION, MAP0, "s"), Pca.intentGoalCommit(SESSION, MAP0, "s"));
        assertEquals("pca-intent:v2:" + SESSION + ":" + MAP0, IntentSession.intentGoalV2(SESSION, MAP0));
    }

    @Test void checksOneToFourAreIndependent() {
        // a root the verifier does not hold fails both intent_session and accumulators; schema still passes
        Pca.Verdict v = verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx("session", map("grants", list())));
        assertEquals(List.of("intent_session", "accumulators"), failed(v));
        assertTrue(v.checks.get("schema"));
        // params that do not open the digest: schema fails AND the accumulator value read from them no longer matches
        Map<String, Object> bad = params(); bad.put("total", 1L);
        assertEquals(List.of("schema", "accumulators"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx("params", bad))));
        // tampering after signing: leaf_signature fails and the claim no longer equals the verifier post
        Map<String, Object> p = build(G0, "salt0", MAP0, is0(), params(), REF);
        p.put("intent_session", is0("acc", list(map("id", "trip_spend", "post", 1L))));
        assertEquals(List.of("leaf_signature", "accumulators"), failed(verify(G0, p, ctx())));
    }

    // ------------------------------------------------------------------ rule 13
    @Test void rule13Failures() {
        Map<String, Object> forged = mint(1, (String) G0.get("id"), MAP1, "salt1", AGENT, R);
        Map<String, Object> d1ctx = ctx("session", map("root", S, "grants", list(G0)), "acc", map("state", map("trip_spend", map("sum", 38_900L)), "monitors", map()));
        Map<String, Object> is1 = is0("seq", 1L, "acc", list(map("id", "trip_spend", "post", 77_800L)));
        assertEquals(List.of("intent_session"), failed(verify(forged, build(forged, "salt1", MAP1, is1, params(), REF), d1ctx)));
        Map<String, Object> loose = mint(1, b64seed("v2/nope"), MAP1, "salt1", PRINCIPAL, R);
        assertEquals(List.of("intent_session"), failed(verify(loose, build(loose, "salt1", MAP1, is1, params(), REF), d1ctx)));
        assertEquals(List.of("intent_session"), failed(verify(G0, build(G0, "salt0", MAP0, is0("seq", 1L), params(), REF), ctx("session", map("root", S, "grants", list(G0))))));
        assertEquals(List.of("intent_session"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), b64seed("v2/x")), ctx())));
        // expires_at == now is expired (strict now < expires_at)
        Map<String, Object> eb = rootBody(); eb.put("expires_at", NOW);
        Map<String, Object> eS = signRoot(eb, PRINCIPAL);
        String eR = IntentSession.rootDigest(eS);
        Map<String, Object> ge = mint(0, null, MAP0, "salt0", PRINCIPAL, eR);
        assertEquals(List.of("intent_session", "accumulators"), failed(verify(ge, build(ge, "salt0", MAP0, is0("root", eR), params(), REF), ctx("session", map("root", eS, "grants", list())))));
        Map<String, Object> lb = rootBody(); lb.put("expires_at", NOW + 1);
        Map<String, Object> lS = signRoot(lb, PRINCIPAL);
        String lR = IntentSession.rootDigest(lS);
        Map<String, Object> gl = mint(0, null, MAP0, "salt0", PRINCIPAL, lR);
        assertTrue(verify(gl, build(gl, "salt0", MAP0, is0("root", lR), params(), REF), ctx("session", map("root", lS, "grants", list()))).allow);
        // a seq-0 action must use the task map: an intent map != S.layers.task.map_digest
        Map<String, Object> gm = mint(0, null, MAP1, "salt0", PRINCIPAL, R);
        assertEquals(List.of("intent_session"), failed(verify(gm, build(gm, "salt0", MAP1, is0(), params(), REF), ctx())));
        // a root signed by a key that is not its signer principal does not verify
        Map<String, Object> wrong = new LinkedHashMap<>(S);
        wrong.put("sig", sign(STRANGER, IntentJs.message(IntentSession.INTENT_SESSION_SIG_DOMAIN, rootBody())));
        assertNotNull(IntentSession.verifyRoot(wrong));
        assertNull(IntentSession.verifyRoot(S));
    }

    @Test void sessionWireBoundaries() {
        assertNull(IntentSession.validateWire(is0()));
        assertNull(IntentSession.validateWire(is0("seq", 2_147_483_647L)));
        assertEquals("'intent_session.seq' must be a safe integer in [0, 2147483647]", IntentSession.validateWire(is0("seq", 2_147_483_648L)));
        assertEquals("'intent_session.seq' must be a safe integer in [0, 2147483647]", IntentSession.validateWire(is0("seq", -1L)));
        assertEquals("'intent_session.seq' must be a safe integer in [0, 2147483647]", IntentSession.validateWire(is0("seq", new Json.Num("1.5"))));
        assertEquals("'intent_session.seq' must be a safe integer in [0, 2147483647]", IntentSession.validateWire(is0("seq", new Json.Num("-0"))));
        assertEquals("'intent_session' must be an object", IntentSession.validateWire(list(is0())));
        assertEquals("unknown field 'intent_session.note'", IntentSession.validateWire(is0("note", "x")));
        Map<String, Object> noSchema = is0(); noSchema.remove("schema");
        assertEquals("missing field 'intent_session.schema'", IntentSession.validateWire(noSchema));
        Map<String, Object> both = is0("zz", 1L); both.remove("root"); // unknown before missing
        assertEquals("unknown field 'intent_session.zz'", IntentSession.validateWire(both));
        assertEquals("'intent_session.root' is not canonical base64url (32 bytes)", IntentSession.validateWire(is0("root", Pca.b64(new byte[31]))));
        // acc: <= 16, distinct ids, [A-Za-z0-9_]{1,64}, post >= 0 safe integer, receipt a digest
        List<Object> sixteen = new ArrayList<>(), seventeen = new ArrayList<>();
        for (int i = 0; i < 17; i++) { if (i < 16) sixteen.add(map("id", "a" + i, "post", 0L)); seventeen.add(map("id", "a" + i, "post", 0L)); }
        assertNull(IntentSession.validateWire(is0("acc", sixteen)));
        assertNotNull(IntentSession.validateWire(is0("acc", seventeen)));
        assertEquals("'intent_session.acc' ids must be distinct", IntentSession.validateWire(is0("acc", list(map("id", "a", "post", 1L), map("id", "a", "post", 2L)))));
        assertNotNull(IntentSession.validateWire(is0("acc", list(map("id", "a-b", "post", 1L)))));
        assertNull(IntentSession.validateWire(is0("acc", list(map("id", "a".repeat(64), "post", 1L)))));
        assertNotNull(IntentSession.validateWire(is0("acc", list(map("id", "a".repeat(65), "post", 1L)))));
        assertNotNull(IntentSession.validateWire(is0("acc", list(map("id", "a", "post", new Json.Num("1.5"))))));
        assertNotNull(IntentSession.validateWire(is0("acc", list(map("id", "a", "post", 0L, "receipt", "x")))));
        assertNull(IntentSession.validateWire(is0("acc", list(map("id", "a", "post", 0L, "receipt", REF)))));
        assertNotNull(IntentSession.validateWire(is0("acc", list(map("id", "a", "post", 0L, "other", 1L)))));
        // digest lists: facts <= 16, classes <= 8, labels <= 16, distinct
        for (Object[] c : new Object[][] {{"facts", 16}, {"classes", 8}, {"labels", 16}}) {
            List<Object> ok = new ArrayList<>(), over = new ArrayList<>();
            for (int i = 0; i <= (Integer) c[1]; i++) { String d = b64seed("v2/d" + i); if (i < (Integer) c[1]) ok.add(d); over.add(d); }
            assertNull(IntentSession.validateWire(is0(c[0], ok)), (String) c[0]);
            assertNotNull(IntentSession.validateWire(is0(c[0], over)), (String) c[0]);
            assertEquals("'intent_session." + c[0] + "' entries must be distinct", IntentSession.validateWire(is0(c[0], list(REF, REF))));
        }
        assertNotNull(IntentSession.validateWire(is0("offer_set", "x")));
        // prov: <= 32 paths, action.params.<name>, 1..8 refs of 1..256 UTF-8 bytes
        assertNull(IntentSession.validateWire(is0("prov", map("action.params.total", list("r".repeat(256))))));
        assertNotNull(IntentSession.validateWire(is0("prov", map("action.params.total", list("r".repeat(257))))));
        assertNotNull(IntentSession.validateWire(is0("prov", map("action.params.total", list("é".repeat(128) + "a")))));
        assertNotNull(IntentSession.validateWire(is0("prov", map("env.x", list("r")))));
        assertNotNull(IntentSession.validateWire(is0("prov", map("action.params.total", list()))));
        List<Object> eight = new ArrayList<>(), nine = new ArrayList<>();
        for (int i = 0; i < 9; i++) { if (i < 8) eight.add("r" + i); nine.add("r" + i); }
        assertNull(IntentSession.validateWire(is0("prov", map("action.params.total", eight))));
        assertNotNull(IntentSession.validateWire(is0("prov", map("action.params.total", nine))));
        Map<String, Object> p32 = new LinkedHashMap<>(), p33 = new LinkedHashMap<>();
        for (int i = 0; i < 33; i++) { if (i < 32) p32.put("action.params.p" + i, list("r")); p33.put("action.params.p" + i, list("r")); }
        assertNull(IntentSession.validateWire(is0("prov", p32)));
        assertNotNull(IntentSession.validateWire(is0("prov", p33)));
        // a wire refusal is terminal through the verifier
        Map<String, Object> p = build(G0, "salt0", MAP0, is0("seq", -1L), params(), REF);
        assertEquals(List.of("wire"), new ArrayList<>(verify(G0, p, ctx()).checks.keySet()));
    }

    @Test void sessionCaveat() {
        Map<String, Object> c = map("type", "intent_session", "session", SESSION, "seq", 0L, "root", R);
        assertNull(IntentSession.caveatError(c));
        c.put("prev", REF);
        assertEquals("intent_session caveat: prev is present exactly when seq > 0", IntentSession.caveatError(c));
        c.put("seq", 1L);
        assertNull(IntentSession.caveatError(c));
        c.remove("prev");
        assertEquals("intent_session caveat: prev is present exactly when seq > 0", IntentSession.caveatError(c));
        assertEquals("not an intent_session caveat", IntentSession.caveatError(map("type", "envelope")));
        assertNotNull(IntentSession.caveatError(map("type", "intent_session", "session", SESSION, "seq", 0L, "root", R, "x", 1L)));
        assertNotNull(IntentSession.caveatError(map("type", "intent_session", "session", SESSION, "seq", 2_147_483_648L, "root", R, "prev", REF)));
        // rule 10: a well-formed session caveat is satisfied in the policy layer, a malformed one is not
        assertTrue(Caveats.satisfied(map("type", "intent_session", "session", SESSION, "seq", 0L, "root", R), map("now", NOW)));
        assertFalse(Caveats.satisfied(map("type", "intent_session", "session", SESSION, "seq", 1L, "root", R), map("now", NOW)));
        assertFalse(Caveats.satisfied(map("type", "intent_session", "session", SESSION, "seq", 0L, "root", R), map()));
    }

    // ------------------------------------------------------------------ rule 13 step 7: revocation
    static final String REV = "v2/revocation-authority";
    static final String ID_SESSION = IntentRevocation.sessionRevocationId(SESSION);

    /** A signed epoch over the FULL sorted list {@code revoked} (epoch == set_size == |revoked|). */
    static Map<String, Object> epoch(List<String> revoked, long issued, String signer, String scope) {
        List<String> sorted = new ArrayList<>(revoked);
        sorted.sort(Json::compareUtf8);
        Map<String, Object> body = map("instance_id", "ana", "grant_ref", scope, "epoch", (long) sorted.size(), "set_size", (long) sorted.size(),
            "root", IntentRevocation.revsetRoot(sorted), "issued_at", issued, "not_after", issued + 300_000L);
        Map<String, Object> ep = new LinkedHashMap<>(body);
        ep.put("guardian", pub(signer));
        ep.put("sig", sign(signer, Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.getBytes(StandardCharsets.UTF_8), IntentJs.canonBytes(body))));
        return ep;
    }
    static Map<String, Object> evidence(List<String> revoked, long issued, String signer) {
        List<String> sorted = new ArrayList<>(revoked);
        sorted.sort(Json::compareUtf8);
        return map("epoch", epoch(revoked, issued, signer, IntentRevocation.sessionRevocationScope(SESSION)), "revoked", new ArrayList<Object>(sorted));
    }
    static String rev(Map<String, Object> ev, List<String> ids, double maxAge, Map<String, Object> last) {
        return IntentRevocation.checkSessionRevocation(IntentJs.normalize(ev), SESSION, pub(REV), ids, NOW, maxAge, null, null,
            last != null, last == null ? null : IntentJs.normalize(last));
    }
    static String rev(Map<String, Object> ev, List<String> ids, double maxAge) { return rev(ev, ids, maxAge, null); }

    @Test void revocationStepOrder() {
        List<String> ids = List.of(ID_SESSION);
        List<String> high = List.of("pca-intent:zzz");
        assertNull(rev(evidence(high, NOW - 10_000, REV), ids, 60_000));
        assertNull(rev(evidence(List.of(), NOW - 10_000, REV), ids, 60_000));
        // d: inclusive age bound
        assertNull(rev(evidence(high, NOW - 60_000, REV), ids, 60_000));
        assertNotNull(rev(evidence(high, NOW - 60_001, REV), ids, 60_000));
        // c: issued at most 60 s ahead (inclusive)
        assertNull(rev(evidence(high, NOW + 60_000, REV), ids, 60_000));
        assertEquals("revocation epoch issued in the future", rev(evidence(high, NOW + 60_001, REV), ids, 60_000));
        // g: the id itself revoked
        assertEquals("'" + ID_SESSION + "' is revoked", rev(evidence(List.of(ID_SESSION), NOW - 1_000, REV), ids, 60_000));
        // e: the list must be the full signed set
        Map<String, Object> shortList = evidence(List.of("a", "b"), NOW - 1_000, REV); shortList.put("revoked", list("a"));
        assertEquals("the epoch must be numbered by its set size and list exactly set_size ids", rev(shortList, ids, 60_000));
        Map<String, Object> swapped = evidence(List.of("a", "b"), NOW - 1_000, REV); swapped.put("revoked", list("a", "c"));
        assertEquals("the revoked list is not the signed set (root mismatch)", rev(swapped, ids, 60_000));
        Map<String, Object> unsorted = evidence(List.of("a", "b"), NOW - 1_000, REV); unsorted.put("revoked", list("b", "a"));
        assertEquals("revoked must be sorted by UTF-8 bytes and distinct", rev(unsorted, ids, 60_000));
        Map<String, Object> notList = evidence(List.of("a"), NOW - 1_000, REV); notList.put("revoked", map("0", "a"));
        assertEquals("revoked must be an array of ids", rev(notList, ids, 60_000));
        // b: only the dedicated authority; a: a misconfigured max age (checked first, even with no evidence)
        assertEquals("the revocation epoch is not signed by the session revocation authority", rev(evidence(high, NOW - 1_000, PRINCIPAL), ids, 60_000));
        assertEquals("revocation max age misconfigured (fail closed)", rev(null, ids, -1));
        assertEquals("revocation max age misconfigured (fail closed)", rev(null, ids, 0.5));
        assertEquals("no session revocation epoch supplied", rev(null, ids, 0));
        Map<String, Object> extra = evidence(high, NOW - 1_000, REV); extra.put("proofs", map());
        assertEquals("the revocation evidence has the unknown member 'proofs' (it is exactly {epoch, revoked})", rev(extra, ids, 60_000));
        Map<String, Object> noList = evidence(high, NOW - 1_000, REV); noList.remove("revoked");
        assertEquals("revoked must be an array of ids", rev(noList, ids, 60_000));
        Map<String, Object> in = map("epoch", evidence(high, NOW - 1_000, REV).get("epoch"), "revoked", list("pca-intent:zzz"), "session", SESSION, "authority", pub(REV),
            "ids", list(ID_SESSION), "now", NOW, "max_age_ms", 60_000L);
        assertTrue(IntentRevocation.checkPrimitive(in));
        in.put("proofs", map());
        assertFalse(IntentRevocation.checkPrimitive(in));
        // another scope
        Map<String, Object> other = map("epoch", epoch(high, NOW - 1_000, REV, IntentRevocation.sessionRevocationScope(REF)), "revoked", list("pca-intent:zzz"));
        assertEquals("revocation epoch is for a different grant", rev(other, ids, 60_000));
        // a tampered epoch member breaks the authority signature
        Map<String, Object> t = evidence(high, NOW - 1_000, REV);
        m(t.get("epoch")).put("instance_id", "bob");
        assertEquals("revocation epoch signature invalid", rev(t, ids, 60_000));
        // f: append-only against the tracked last epoch
        Map<String, Object> last = evidence(List.of("a"), NOW - 30_000, REV);
        assertNull(rev(evidence(List.of("a", "b"), NOW - 1_000, REV), ids, 60_000, last));
        assertNull(rev(evidence(List.of("a"), NOW - 1_000, REV), ids, 60_000, last));
        assertEquals("revocation epoch rollback (older than the last accepted)", rev(evidence(List.of(), NOW - 1_000, REV), ids, 60_000, last));
        assertEquals("the epoch drops 'a', revoked in the last accepted epoch (not append-only)", rev(evidence(List.of("b"), NOW - 1_000, REV), ids, 60_000, last));
        // another set under the same epoch number: the drop is caught first (a same-size superset is the same set)
        assertEquals("the epoch drops 'c', revoked in the last accepted epoch (not append-only)",
            rev(evidence(List.of("a"), NOW - 1_000, REV), ids, 60_000, evidence(List.of("c"), NOW - 30_000, REV)));
        Map<String, Object> badLast = evidence(List.of("a"), NOW - 30_000, REV); badLast.put("revoked", list());
        assertEquals("the tracked last epoch is malformed (fail closed)", rev(evidence(List.of("a"), NOW - 1_000, REV), ids, 60_000, badLast));
    }

    @Test void revocationThroughTheSession() {
        Map<String, Object> body = rootBody();
        body.put("revocation", map("epoch_uri", "https://atlas.example/rev", "max_age_s", 60L, "key", pub(REV)));
        Map<String, Object> s4 = signRoot(body, PRINCIPAL);
        String r4 = IntentSession.rootDigest(s4);
        Map<String, Object> g = mint(0, null, MAP0, "salt0", PRINCIPAL, r4);
        Map<String, Object> p = build(g, "salt0", MAP0, is0("root", r4), params(), REF);
        List<String> ids = List.of(ID_SESSION, IntentRevocation.mapRevocationId(MAP0), IntentRevocation.deltaRevocationId((String) g.get("id")));
        List<String> high = List.of("pca-intent:zzz");
        java.util.function.BiFunction<Map<String, Object>, Map<String, Object>, Pca.Verdict> run = (ev, policy) -> {
            Map<String, Object> sess = map("root", s4, "grants", list());
            if (ev != null) sess.put("revocation", ev);
            Map<String, Object> c = ctx("session", sess);
            if (policy != null) c.put("policy", policy);
            return verify(g, p, c);
        };
        assertTrue(run.apply(evidence(high, NOW - 30_000, REV), null).allow);
        assertEquals(List.of("intent_session"), failed(run.apply(null, null)));
        assertEquals(List.of("intent_session"), failed(run.apply(evidence(high, NOW - 61_000, REV), null)));
        for (String revoked : ids) assertEquals(List.of("intent_session"), failed(run.apply(evidence(List.of(revoked), NOW - 1_000, REV), null)), revoked);
        assertEquals(List.of("intent_session"), failed(run.apply(evidence(high, NOW - 1_000, PRINCIPAL), null)));
        // the stricter of S (60 s) and the policy (10 s) applies
        assertEquals(List.of("intent_session"), failed(run.apply(evidence(high, NOW - 20_000, REV), map("session", map("max_revocation_age_s", 10L)))));
        assertTrue(run.apply(evidence(high, NOW - 10_000, REV), map("session", map("max_revocation_age_s", 10L))).allow);
        // a bad policy age is a malformed context: every reportable check fails
        assertEquals(List.of("schema", "intent_session", "accumulators"), failed(run.apply(evidence(high, NOW - 1_000, REV), map("session", map("max_revocation_age_s", -1L)))));
        assertEquals(List.of("schema", "intent_session", "accumulators"), failed(run.apply(evidence(high, NOW - 1_000, REV), map("session", map("max_revocation_age_s", null)))));
        // with no revocation authority in S, the policy max age alone fails closed
        Map<String, Object> noRev = ctx("policy", map("session", map("max_revocation_age_s", 60L)));
        assertEquals(List.of("intent_session"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), noRev)));
        // the tracked last epoch: a newer epoch that drops a revoked id is refused
        Map<String, Object> sess = map("root", s4, "grants", list(), "revocation", evidence(high, NOW - 1_000, REV),
            "revocation_last", evidence(List.of("pca-intent:yyy"), NOW - 20_000, REV));
        assertEquals(List.of("intent_session"), failed(verify(g, p, ctx("session", sess))));
        // S.revocation: the key is required and is never a principal
        Map<String, Object> keyless = rootBody();
        keyless.put("revocation", map("epoch_uri", "https://atlas.example/rev", "max_age_s", 60L));
        assertNotNull(IntentSession.rootShapeError(signRoot(keyless, PRINCIPAL)));
        Map<String, Object> principalKeyed = rootBody();
        principalKeyed.put("revocation", map("epoch_uri", "https://atlas.example/rev", "max_age_s", 60L, "key", pub(PRINCIPAL)));
        assertEquals("revocation.key must not be a session principal (a dedicated revocation authority)", IntentSession.rootShapeError(signRoot(principalKeyed, PRINCIPAL)));
    }

    @Test void revsetRoot() {
        // the empty list binds the empty tree; any change of the list changes the root
        assertEquals(Pca.b64(Pca.sha("pca-revset/v1\0".getBytes(StandardCharsets.UTF_8), IntentJs.canonBytes(map("size", 0L, "tree", Pca.b64(Pca.sha(new byte[0])))))),
            IntentRevocation.revsetRoot(List.of()));
        assertNotEquals(IntentRevocation.revsetRoot(List.of("a", "b")), IntentRevocation.revsetRoot(List.of("a", "c")));
        assertNotEquals(IntentRevocation.revsetRoot(List.of("a")), IntentRevocation.revsetRoot(List.of("a", "b")));
    }

    // ------------------------------------------------------------------ rule 14
    @Test void rule14ThroughTheVerifier() {
        Map<String, Object> extra = params(); extra.put("reseller", "x");
        assertEquals(List.of("schema"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), extra, REF), ctx("params", extra))));
        Map<String, Object> bag = params(); bag.put("add_ons", list("bag"));
        assertEquals(List.of("schema"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), bag, REF), ctx("params", bag))));
        Map<String, Object> at16 = params(); at16.put("note", "é".repeat(8));
        assertTrue(verify(G0, build(G0, "salt0", MAP0, is0(), at16, REF), ctx("params", at16)).allow);
        Map<String, Object> at17 = params(); at17.put("note", "é".repeat(8) + "a");
        assertEquals(List.of("schema"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), at17, REF), ctx("params", at17))));
        Map<String, Object> v2 = new LinkedHashMap<>(unsignedSchema()); v2.put("version", "v2");
        assertEquals(List.of("schema", "accumulators"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF),
            ctx("schema", map("docs", list(signSchema(v2, "skyair-2026", SITE)), "keys", KEYS)))));
        assertEquals(List.of("schema"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF),
            ctx("schema", map("docs", list(SCHEMA), "keys", list(map("kid", "skyair-2026", "alg", "ed25519", "pk", pub(STRANGER))))))));
        assertEquals(List.of("schema", "accumulators"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), ctx("schema", map("docs", list(), "keys", KEYS)))));
        Map<String, Object> noParams = ctx(); noParams.remove("params");
        assertEquals(List.of("schema", "accumulators"), failed(verify(G0, build(G0, "salt0", MAP0, is0(), params(), REF), noParams)));
    }

    static ActionSchema.Conform conform(String verb, Object params) { return ActionSchema.conform(IntentJs.normalize(SCHEMA), verb, IntentJs.normalize(params)); }
    static void code(String code, String path, ActionSchema.Conform c) {
        assertFalse(c.ok);
        assertEquals(code, c.code);
        assertEquals(path, c.path);
    }

    @Test void conformanceOrderAndDomains() {
        assertTrue(conform("air.book", params()).ok);
        code("unknown_verb", null, conform("air.cancel", params()));
        code("params_not_object", null, conform("air.book", list()));
        code("params_not_object", null, conform("air.cancel", list())); // params before verb
        Map<String, Object> two = params(); two.put("zz", 1L); two.put("aa", 1L);
        code("undeclared_param", "action.params.aa", conform("air.book", two));
        code("undeclared_param", "action.params.extra", conform("air.book", map("offer_id", "x", "extra", 1L)));
        code("missing_param", "action.params.add_ons", conform("air.book", map()));
        String[][] ints = {{"38900", null}, {"1.5", "bad_type"}, {"-0", "bad_type"}, {"-1", "out_of_domain"}, {"0", null}, {"5000000", null}, {"5000001", "out_of_domain"}};
        for (String[] t : ints) {
            Map<String, Object> p = params(); p.put("total", new Json.Num(t[0]));
            ActionSchema.Conform c = conform("air.book", p);
            if (t[1] == null) assertTrue(c.ok, t[0]); else code(t[1], "action.params.total", c);
        }
        Map<String, Object> s = params(); s.put("total", "38900");
        code("bad_type", "action.params.total", conform("air.book", s));
        Map<String, Object> b = params(); b.put("refundable", "false");
        code("bad_type", "action.params.refundable", conform("air.book", b));
        Map<String, Object> dup = params(); dup.put("add_ons", list("none", "none"));
        code("out_of_domain", "action.params.add_ons", conform("air.book", dup));
        Map<String, Object> empty = params(); empty.put("add_ons", list());
        assertTrue(conform("air.book", empty).ok);
        Map<String, Object> num = params(); num.put("add_ons", list(1L));
        code("bad_type", "action.params.add_ons", conform("air.book", num));
        Map<String, Object> all3 = params(); all3.put("add_ons", list("none", "tripshield", "seat_plus"));
        assertTrue(conform("air.book", all3).ok); // max_items defaults to |values|
        List<Object> nine = new ArrayList<>(), ten = new ArrayList<>();
        for (int i = 0; i < 10; i++) { if (i < 9) nine.add("p" + i); ten.add("p" + i); }
        Map<String, Object> a9 = params(); a9.put("passengers", nine);
        assertTrue(conform("air.book", a9).ok);
        Map<String, Object> a10 = params(); a10.put("passengers", ten);
        code("out_of_domain", "action.params.passengers", conform("air.book", a10));
        Map<String, Object> long64 = params(); long64.put("passengers", list("x".repeat(64)));
        assertTrue(conform("air.book", long64).ok);
        Map<String, Object> long65 = params(); long65.put("passengers", list("x".repeat(65)));
        code("bad_type", "action.params.passengers", conform("air.book", long65));
        code("out_of_domain", "action.params.from", conform("air.search", map("from", "LAX", "date", "2026-11-20", "pax", 2L)));
        String[][] dates = {{"2028-02-29", null}, {"2026-02-29", "x"}, {"1900-02-29", "x"}, {"2000-02-29", null}, {"2026-1-05", "x"}, {"0000-01-01", "x"},
            {"0001-01-01", null}, {"9999-12-31", null}, {"2026-13-01", "x"}, {"2026-04-31", "x"}, {"2026-04-30", null}, {"2026-00-10", "x"}, {"2026-01-00", "x"}};
        for (String[] d : dates) {
            ActionSchema.Conform c = conform("air.search", map("from", "SFO", "date", d[0], "pax", 2L));
            if (d[1] == null) assertTrue(c.ok, d[0]); else code("out_of_domain", "action.params.date", c);
        }
        code("bad_type", "action.params.date", conform("air.search", map("from", "SFO", "date", 20260101L, "pax", 2L)));
        code("out_of_domain", "action.params.pax", conform("air.search", map("from", "SFO", "date", "2026-01-01", "pax", 0L)));
        assertTrue(conform("air.search", map("from", "SFO", "date", "2026-01-01", "pax", 9L)).ok);
        code("out_of_domain", "action.params.pax", conform("air.search", map("from", "SFO", "date", "2026-01-01", "pax", 10L)));
    }

    @Test void schemaSignatureAndShape() {
        Map<String, Object> n = m(IntentJs.normalize(SCHEMA));
        assertNull(ActionSchema.verify(n, IntentJs.normalize(KEYS)));
        assertNotNull(ActionSchema.verify(n, list(map("kid", "other", "alg", "ed25519", "pk", pub(SITE)))));
        assertEquals("sig.alg does not match the pinned key suite", ActionSchema.verify(n, list(map("kid", "skyair-2026", "alg", "ml-dsa-65", "pk", pub(SITE)))));
        Map<String, Object> algMismatch = new LinkedHashMap<>(n);
        algMismatch.put("sig", map("alg", "ml-dsa-65", "kid", "skyair-2026", "value", m(n.get("sig")).get("value")));
        assertEquals("sig.alg does not match the pinned key suite", ActionSchema.verify(algMismatch, KEYS));
        Map<String, Object> tampered = new LinkedHashMap<>(n); tampered.put("version", "x");
        assertEquals("schema signature invalid", ActionSchema.verify(tampered, KEYS));
        Map<String, Object> extra = new LinkedHashMap<>(n); extra.put("extra", 1L);
        assertEquals("unknown member 'extra'", ActionSchema.verify(extra, KEYS));
        assertNotNull(ActionSchema.verify(n, list(map("kid", "skyair-2026", "pk", "x"))));
        // the digest is over the whole signed document
        assertNotEquals(ActionSchema.digest(n), ActionSchema.digest(tampered));
        assertEquals(SD, ActionSchema.digest(n));
    }

    @Test void canonProjection() {
        Map<String, Object> p = params();
        p.put("add_ons", list("tripshield", "none"));
        p.put("passengers", list("b", "a"));
        Map<String, Object> c = ActionSchema.canonProjection(IntentJs.normalize(SCHEMA), "air.book", m(IntentJs.normalize(p)));
        assertEquals("[\"none\",\"tripshield\"]", c.get("add_ons"));
        assertEquals("[\"b\",\"a\"]", c.get("passengers"));
        assertEquals("false", c.get("refundable"));
        assertFalse(c.containsKey("total"));
        assertFalse(c.containsKey("offer_id"));
        assertFalse(c.containsKey("note"));
    }

    // ------------------------------------------------------------------ rule 15
    @Test void rule15SiteLocal() {
        java.util.function.BiFunction<Map<String, Object>, Map<String, Object>, List<String>> run = (is, c) -> failed(verify(G0, build(G0, "salt0", MAP0, is, params(), REF), c));
        assertEquals(List.of("accumulators"), run.apply(is0("acc", list(map("id", "trip_spend", "post", 38_899L))), ctx()));
        assertEquals(List.of("accumulators"), run.apply(is0("acc", list()), ctx()));
        assertEquals(List.of("accumulators"), run.apply(is0("acc", list(map("id", "trip_spend", "post", 38_900L), map("id", "nope", "post", 0L))), ctx()));
        assertEquals(List.of("accumulators"), run.apply(is0("acc", list(map("id", "trip_spend", "post", 38_900L), map("id", "questions", "post", 1L))), ctx()));
        assertEquals(List.of("accumulators"), run.apply(is0(), ctx("acc", map("state", map(), "monitors", map()))));
        assertEquals(List.of("accumulators"), run.apply(is0(), ctx("acc", map("state", map("trip_spend", map("count", 0L)), "monitors", map()))));
        assertEquals(List.of("accumulators"), run.apply(is0("acc", list(map("id", "trip_spend", "post", 500_100L))), ctx("acc", map("state", map("trip_spend", map("sum", 461_200L)), "monitors", map()))));
        assertEquals(List.of(), run.apply(is0("acc", list(map("id", "trip_spend", "post", 500_000L))), ctx("acc", map("state", map("trip_spend", map("sum", 461_100L)), "monitors", map()))));
        // a site-local claim must not carry a receipt
        assertEquals(List.of("accumulators"), run.apply(is0("acc", list(map("id", "trip_spend", "post", 38_900L, "receipt", REF))), ctx()));
    }

    static Map<String, Object> rootWith(String k, Object v) {
        Map<String, Object> b = rootBody();
        b.put(k, v);
        return signRoot(b, PRINCIPAL);
    }

    @Test void rule15MonitorsAndAggregates() {
        Map<String, Object> mon = map("id", "hotel_after_flight", "kind", "requires_prior", "p", map("verb", "air.book"), "q", map("verb", "hotel.book"), "status", "committed");
        Map<String, Object> rm = rootWith("monitors", list(mon));
        String rmR = IntentSession.rootDigest(rm);
        Map<String, Object> gm = mint(0, null, MAP0, "salt0", PRINCIPAL, rmR);
        Map<String, Object> pm = build(gm, "salt0", MAP0, is0("root", rmR), params(), REF);
        java.util.function.Function<Map<String, Object>, Pca.Verdict> cm = mons -> verify(gm, pm, ctx("session", map("root", rm, "grants", list()), "acc", map("state", map("trip_spend", map("sum", 0L)), "monitors", mons)));
        assertTrue(cm.apply(map("hotel_after_flight", "unmet")).allow);
        assertTrue(cm.apply(map("hotel_after_flight", "met")).allow);
        assertEquals(List.of("accumulators"), failed(cm.apply(map())));
        assertEquals(List.of("accumulators"), failed(cm.apply(map("hotel_after_flight", "maybe"))));
        assertEquals(List.of("accumulators"), failed(cm.apply(map("hotel_after_flight", 1L))));
        assertEquals(List.of("idle", "pending:1", "pending:2", "missed"), IntentAcc.monitorStates(map("kind", "responds_within", "within", 2L)));
        assertEquals(List.of("clean", "seen"), IntentAcc.monitorStates(map("kind", "never")));
        assertEquals(List.of("ok", "broken"), IntentAcc.monitorStates(map("kind", "always")));
        // distinct / max / keyed count
        Map<String, Object> dist = map("id", "payees", "agg", "distinct", "val", "action.params.offer_id", "sel", map("verbs", list("air.book")), "win", map("kind", "task"), "key", null,
            "domain_max", 3L, "holder", map("kind", "site_local"));
        Map<String, Object> max = map("id", "largest", "agg", "max", "val", "action.params.total", "sel", map("verbs", list("air.book")), "win", map("kind", "task"), "key", null,
            "holder", map("kind", "site_local"));
        Map<String, Object> cnt = map("id", "per_offer", "agg", "count", "sel", map("verbs", list("air.book")), "win", map("kind", "sliding", "ms", 60_000L),
            "key", "action.params.offer_id", "domain_max", 1L, "holder", map("kind", "site_local"));
        Map<String, Object> rx = rootWith("accumulators", list(dist, max, cnt));
        String rxR = IntentSession.rootDigest(rx);
        Map<String, Object> gx = mint(0, null, MAP0, "salt0", PRINCIPAL, rxR);
        List<Object> good = list(map("id", "payees", "post", 2L), map("id", "largest", "post", 40_000L), map("id", "per_offer", "post", 1L));
        Map<String, Object> st = map("payees", map("values", list("\"OF-1\"", "\"OF-9\"")), "largest", map("max", 40_000L), "per_offer", map("count", 0L));
        java.util.function.BiFunction<List<Object>, Map<String, Object>, Pca.Verdict> cx = (acc, state) ->
            verify(gx, build(gx, "salt0", MAP0, is0("root", rxR, "acc", acc), params(), REF), ctx("session", map("root", rx, "grants", list()), "acc", map("state", state, "monitors", map())));
        assertTrue(cx.apply(good, st).allow);
        Map<String, Object> st2 = new LinkedHashMap<>(st); st2.put("payees", map("values", list("\"OF-7\"", "\"OF-9\"")));
        assertEquals(List.of("accumulators"), failed(cx.apply(good, st2)));
        Map<String, Object> st3 = new LinkedHashMap<>(st); st3.put("per_offer", map("count", 1L));
        assertEquals(List.of("accumulators"), failed(cx.apply(list(good.get(0), good.get(1), map("id", "per_offer", "post", 2L)), st3)));
        Map<String, Object> st4 = new LinkedHashMap<>(st); st4.put("payees", map("values", list("\"OF-1\"", "\"OF-1\"")));
        assertEquals(List.of("accumulators"), failed(cx.apply(good, st4)));
        // unit seams
        assertEquals("pre-state of a sum accumulator is {sum}", IntentAcc.preStateError("sum", map("sum", 0L, "x", 1L)));
        assertNull(IntentAcc.preStateError("max", map("max", 0L)));
        assertNotNull(IntentAcc.preStateError("count", map("count", -1L)));
        assertEquals(Long.valueOf(9007199254740991L), IntentAcc.combineAcc("sum", map("sum", 9007199254740990L), new IntentAcc.AccValue(null, 1, null)));
        assertNull(IntentAcc.combineAcc("sum", map("sum", 9007199254740991L), new IntentAcc.AccValue(null, 1, null)));
        assertEquals(Long.valueOf(7L), IntentAcc.combineAcc("max", map("max", 7L), new IntentAcc.AccValue(null, 3, null)));
        assertEquals(Long.valueOf(2L), IntentAcc.combineAcc("distinct", map("values", list("\"a\"")), new IntentAcc.AccValue(null, 1, "\"b\"")));
        assertEquals(Long.valueOf(1L), IntentAcc.combineAcc("distinct", map("values", list("\"a\"")), new IntentAcc.AccValue(null, 1, "\"a\"")));
        assertEquals("\"OF-1\"", IntentAcc.distinctKey("OF-1"));
        assertEquals("7", IntentAcc.distinctKey(7L));
        assertNull(IntentAcc.distinctKey(new Json.Num("1.5")));
        assertNull(IntentAcc.distinctKey(true));
    }

    @Test void accumulatorDeclarations() {
        assertNull(IntentAcc.accumulatorDeclError(trip()));
        assertNull(IntentAcc.accumulatorDeclError(questions()));
        Map<String, Object> noKey = trip(); noKey.remove("key");
        assertEquals("accumulator 'trip_spend': key must be null or action.params.<name>", IntentAcc.accumulatorDeclError(noKey));
        Map<String, Object> both = trip(); both.put("sel", map("verbs", list("a"), "event", "question"));
        assertNotNull(IntentAcc.accumulatorDeclError(both));
        Map<String, Object> walletAction = trip(); walletAction.put("holder", map("kind", "wallet"));
        assertEquals("accumulator 'trip_spend': wallet events are wallet-held and only wallet events are", IntentAcc.accumulatorDeclError(walletAction));
        Map<String, Object> cntVal = map("id", "c", "agg", "count", "val", "action.params.x", "sel", map("verbs", list("a")), "win", map("kind", "task"), "key", null, "holder", map("kind", "site_local"));
        assertEquals("accumulator 'c': count takes no val", IntentAcc.accumulatorDeclError(cntVal));
        Map<String, Object> maxNoVal = map("id", "c", "agg", "max", "sel", map("accumulates_into", "u"), "win", map("kind", "task"), "key", null, "holder", map("kind", "site_local"));
        assertEquals("accumulator 'c': max needs val", IntentAcc.accumulatorDeclError(maxNoVal));
        Map<String, Object> sliding0 = trip(); sliding0.put("win", map("kind", "sliding", "ms", 0L));
        assertNotNull(IntentAcc.accumulatorDeclError(sliding0));
        Map<String, Object> period = trip(); period.put("win", map("kind", "period", "ms", 1L, "t0", 0L));
        assertNull(IntentAcc.accumulatorDeclError(period));
        Map<String, Object> seqOk = trip(); seqOk.put("holder", map("kind", "sequenced", "uri", "https://s", "root", pub(SEQ_ROOT), "keys_uri", "https://k"));
        assertNull(IntentAcc.accumulatorDeclError(seqOk));
        Map<String, Object> seqOld = trip(); seqOld.put("holder", map("kind", "sequenced", "uri", "https://s", "key", pub(SEQ_ROOT)));
        assertEquals("accumulator 'trip_spend': holder sequenced has unknown member 'key'", IntentAcc.accumulatorDeclError(seqOld));
        assertNull(IntentAcc.monitorDeclError(map("id", "m", "kind", "responds_within", "p", map("verb", "a"), "q", map("verb", list("b")), "within", 64L)));
        assertNotNull(IntentAcc.monitorDeclError(map("id", "m", "kind", "responds_within", "p", map("verb", "a"), "q", map("verb", "b"), "within", 65L)));
        assertNotNull(IntentAcc.monitorDeclError(map("id", "m", "kind", "never", "p", map("verb", "a"), "q", map("verb", "b"))));
        assertNotNull(IntentAcc.monitorDeclError(map("id", "m", "kind", "never", "p", map("verb", list()))));
    }

    // ---- sequenced holders, receipts and the root-signed key set ----
    static Map<String, Object> keySet(List<Object> keys, String rootKey) { return keySet(keys, rootKey, 1L, NOW - 100_000L); }
    static Map<String, Object> keySet(List<Object> keys, String rootKey, long version, long issued) {
        Map<String, Object> body = map("v", 1L, "kind", "pca-sequencer-keys", "sequencer", pub(rootKey), "version", version, "issued_at", issued, "keys", keys);
        Map<String, Object> k = new LinkedHashMap<>(body);
        k.put("sig", sign(rootKey, IntentJs.message(IntentAcc.SEQUENCER_KEYS_DOMAIN, body)));
        return k;
    }
    static Map<String, Object> receipt(Map<String, Object> draft, String signer, String kid, Object... over) {
        Map<String, Object> r = map("v", 1L, "kind", "pca-acc-receipt", "session", SESSION, "acc", "trip_spend", "seq", 3L, "pre", 10_000L, "delta", 38_900L, "post", 48_900L,
            "pcactn_digest", IntentAcc.pcactnReservationDigest(draft), "aud", AUD, "issued_at", NOW - 1_000L, "expires_at", NOW + 60_000L, "kid", kid,
            "ledger", map("index", 7L, "head", b64seed("v2/head")));
        for (int i = 0; i < over.length; i += 2) r.put((String) over[i], over[i + 1]);
        r.put("signer", pub(signer));
        r.put("sig", sign(signer, IntentJs.message(IntentAcc.ACC_RECEIPT_DOMAIN, r)));
        return r;
    }

    @Test void rule15Sequenced() {
        Map<String, Object> seqAcc = trip();
        seqAcc.put("holder", map("kind", "sequenced", "uri", "https://atlas.example/seq", "root", pub(SEQ_ROOT)));
        Map<String, Object> rs = rootWith("accumulators", list(seqAcc));
        String rsR = IntentSession.rootDigest(rs);
        Map<String, Object> gs = mint(0, null, MAP0, "salt0", PRINCIPAL, rsR);
        Map<String, Object> draft = build(gs, "salt0", MAP0, null, params(), REF);
        Map<String, Object> ks = keySet(list(map("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 10_000L)), SEQ_ROOT);
        class Run {
            Pca.Verdict go(Map<String, Object> rc, long post, List<Object> receipts, List<Object> keySets, Long last) {
                Map<String, Object> p = build(gs, "salt0", MAP0, is0("root", rsR, "acc", list(map("id", "trip_spend", "post", post, "receipt", IntentAcc.receiptDigest(rc)))), params(), REF);
                Map<String, Object> acc = map("receipts", receipts, "monitors", map(), "sequencer_keys", keySets);
                if (last != null) acc.put("last_seq", map("trip_spend", last));
                return verify(gs, p, ctx("session", map("root", rs, "grants", list()), "acc", acc));
            }
        }
        Run r = new Run();
        Map<String, Object> rc = receipt(draft, SEQ_KEY, "k1");
        assertTrue(r.go(rc, 48_900L, list(rc), list(ks), null).allow, r.go(rc, 48_900L, list(rc), list(ks), null).reason);
        assertEquals(List.of("accumulators"), failed(r.go(rc, 48_900L, list(), list(ks), null)));
        assertEquals(List.of("accumulators"), failed(r.go(rc, 48_900L, list(rc), list(), null)));          // no key set
        assertEquals(List.of("accumulators"), failed(r.go(rc, 48_900L, list(rc), list(ks), 3L)));           // replay: seq must be ABOVE last
        assertTrue(r.go(rc, 48_900L, list(rc), list(ks), 2L).allow);
        Map<String, Object> foreignSet = keySet(list(map("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 10_000L)), STRANGER);
        assertEquals(List.of("accumulators"), failed(r.go(rc, 48_900L, list(rc), list(foreignSet), null)));
        Map<String, Object> forged = receipt(draft, STRANGER, "k1");
        assertEquals(List.of("accumulators"), failed(r.go(forged, 48_900L, list(forged), list(ks), null)));
        Map<String, Object> bent = receipt(draft, SEQ_KEY, "k1", "post", 48_901L);
        assertEquals(List.of("accumulators"), failed(r.go(bent, 48_901L, list(bent), list(ks), null)));
        Map<String, Object> otherAud = receipt(draft, SEQ_KEY, "k1", "aud", "hotel.example");
        assertEquals(List.of("accumulators"), failed(r.go(otherAud, 48_900L, list(otherAud), list(ks), null)));
        Map<String, Object> late = receipt(draft, SEQ_KEY, "k1", "expires_at", NOW - 1L);
        assertEquals(List.of("accumulators"), failed(r.go(late, 48_900L, list(late), list(ks), null)));
        Map<String, Object> edge = receipt(draft, SEQ_KEY, "k1", "expires_at", NOW);
        assertTrue(r.go(edge, 48_900L, list(edge), list(ks), null).allow); // now <= expires_at inclusive
        Map<String, Object> otherAction = receipt(draft, SEQ_KEY, "k1", "pcactn_digest", b64seed("v2/other-action"));
        assertEquals(List.of("accumulators"), failed(r.go(otherAction, 48_900L, list(otherAction), list(ks), null)));
        // key validity window: issued_at in [not_before, not_after] inclusive; future receipts beyond 60 s refused
        Map<String, Object> windowed = keySet(list(map("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 1_000L, "not_after", NOW - 1_000L)), SEQ_ROOT);
        assertTrue(r.go(rc, 48_900L, list(rc), list(windowed), null).allow);
        Map<String, Object> retired = keySet(list(map("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 10_000L, "not_after", NOW - 1_001L)), SEQ_ROOT);
        assertEquals(List.of("accumulators"), failed(r.go(rc, 48_900L, list(rc), list(retired), null)));
        Map<String, Object> notYet = keySet(list(map("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 999L)), SEQ_ROOT);
        assertEquals(List.of("accumulators"), failed(r.go(rc, 48_900L, list(rc), list(notYet), null)));
        Map<String, Object> wrongKid = receipt(draft, SEQ_KEY, "k2");
        assertEquals(List.of("accumulators"), failed(r.go(wrongKid, 48_900L, list(wrongKid), list(ks), null)));
        Map<String, Object> future = receipt(draft, SEQ_KEY, "k1", "issued_at", NOW + 60_001L);
        Map<String, Object> wide = keySet(list(map("kid", "k1", "pk", pub(SEQ_KEY), "not_before", 0L)), SEQ_ROOT);
        assertEquals(List.of("accumulators"), failed(r.go(future, 48_900L, list(future), list(wide), null)));
        Map<String, Object> nearFuture = receipt(draft, SEQ_KEY, "k1", "issued_at", NOW + 60_000L);
        assertTrue(r.go(nearFuture, 48_900L, list(nearFuture), list(wide), null).allow);
        // SOME presented key set suffices: an invalid one first does not hide a valid one
        assertTrue(r.go(rc, 48_900L, list(rc), list(foreignSet, ks), null).allow);
        // arithmetic per aggregate
        Map<String, Object> rr = map("pre", 10L, "delta", 5L, "post", 15L);
        assertTrue(IntentAcc.receiptArithmeticOk("sum", rr, 5));
        assertFalse(IntentAcc.receiptArithmeticOk("sum", rr, 4));
        assertTrue(IntentAcc.receiptArithmeticOk("max", map("pre", 10L, "delta", 5L, "post", 10L), 5));
        assertFalse(IntentAcc.receiptArithmeticOk("max", map("pre", 10L, "delta", 5L, "post", 15L), 5));
        assertTrue(IntentAcc.receiptArithmeticOk("count", map("pre", 10L, "delta", 1L, "post", 11L), 1));
        assertFalse(IntentAcc.receiptArithmeticOk("count", map("pre", 10L, "delta", 2L, "post", 12L), 1));
        assertTrue(IntentAcc.receiptArithmeticOk("distinct", map("pre", 10L, "delta", 0L, "post", 10L), 1));
        assertFalse(IntentAcc.receiptArithmeticOk("distinct", map("pre", 10L, "delta", 2L, "post", 12L), 1));
    }

    @Test void rule15Freshness() {
        Map<String, Object> holder = map("kind", "sequenced", "uri", "https://atlas.example/seq", "root", pub(SEQ_ROOT));
        Map<String, Object> draft = build(G0, "salt0", MAP0, null, params(), REF);
        List<Object> k1 = list(map("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 10_000L));
        Map<String, Object> ks = keySet(k1, SEQ_ROOT);
        java.util.function.Function<Object[], Boolean> ok = a -> IntentAcc.verifyReceiptAgainstHolder(m(IntentJs.normalize(a[0])), holder, IntentJs.normalize(a[1]), NOW,
            (Double) a[2], (Double) a[3], IntentJs.normalize(a[4]));
        double R = IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS, K = IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS;
        Map<String, Object> rc = receipt(draft, SEQ_KEY, "k1");
        assertTrue(ok.apply(new Object[] {rc, list(ks), R, K, null}));
        // receipt lifetime at most 15 min, expires_at not before issued_at
        assertNull(IntentAcc.receiptShapeError(IntentJs.normalize(receipt(draft, SEQ_KEY, "k1", "expires_at", NOW - 1_000L + 900_000L))));
        assertNotNull(IntentAcc.receiptShapeError(IntentJs.normalize(receipt(draft, SEQ_KEY, "k1", "expires_at", NOW - 1_000L + 900_001L))));
        assertNotNull(IntentAcc.receiptShapeError(IntentJs.normalize(receipt(draft, SEQ_KEY, "k1", "expires_at", NOW - 1_001L))));
        // receipt age: at the bound ok, over it refused
        assertTrue(ok.apply(new Object[] {rc, list(ks), 1_000.0, K, null}));
        assertFalse(ok.apply(new Object[] {rc, list(ks), 999.0, K, null}));
        // key set age and future issue
        assertTrue(ok.apply(new Object[] {rc, list(ks), R, 100_000.0, null}));
        assertFalse(ok.apply(new Object[] {rc, list(ks), R, 99_999.0, null}));
        assertTrue(ok.apply(new Object[] {rc, list(keySet(k1, SEQ_ROOT, 1L, NOW + 60_000L)), R, K, null}));
        assertFalse(ok.apply(new Object[] {rc, list(keySet(k1, SEQ_ROOT, 1L, NOW + 60_001L)), R, K, null}));
        // tracked {version, digest}: an older set is refused (rollback), the same set or a newer one accepted, another set under
        // the tracked version refused (equivocation); a malformed tracked entry refuses everything
        Map<String, Object> v3 = keySet(k1, SEQ_ROOT, 3L, NOW - 100_000L);
        Map<String, Object> t3 = map("version", 3L, "digest", IntentAcc.keySetDigest(IntentJs.normalize(v3)));
        assertTrue(ok.apply(new Object[] {rc, list(v3), R, K, t3}));
        assertTrue(ok.apply(new Object[] {rc, list(keySet(k1, SEQ_ROOT, 4L, NOW - 100_000L)), R, K, t3}));
        assertFalse(ok.apply(new Object[] {rc, list(keySet(k1, SEQ_ROOT, 2L, NOW - 100_000L)), R, K, t3}));
        assertFalse(ok.apply(new Object[] {rc, list(keySet(k1, SEQ_ROOT, 3L, NOW - 99_000L)), R, K, t3}));
        for (Object bad : new Object[] {3L, map("version", 3L), map("version", 0L, "digest", t3.get("digest")), map("version", 3L, "digest", "x"), map("version", 3L, "digest", t3.get("digest"), "x", 1L)})
            assertFalse(ok.apply(new Object[] {rc, list(v3), R, K, bad}), String.valueOf(bad));
        assertNull(IntentAcc.trackedKeySetError(IntentJs.normalize(t3)));
        assertEquals("a tracked key set must be an object {version, digest}", IntentAcc.trackedKeySetError(IntentJs.normalize(3L)));
        assertNotNull(IntentAcc.keySetShapeError(IntentJs.normalize(keySet(k1, SEQ_ROOT, 0L, NOW))));
        Map<String, Object> noVersion = keySet(k1, SEQ_ROOT); noVersion.remove("version");
        assertNotNull(IntentAcc.keySetShapeError(IntentJs.normalize(noVersion)));
        // a retired key stops verifying 60 s after not_after even for a receipt dated inside its window
        Map<String, Object> old = receipt(draft, SEQ_KEY, "k1", "issued_at", NOW - 70_000L, "expires_at", NOW + 1_000L);
        assertTrue(ok.apply(new Object[] {old, list(keySet(list(map("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 80_000L, "not_after", NOW - 60_000L)), SEQ_ROOT)), R, K, null}));
        assertFalse(ok.apply(new Object[] {old, list(keySet(list(map("kid", "k1", "pk", pub(SEQ_KEY), "not_before", NOW - 80_000L, "not_after", NOW - 60_001L)), SEQ_ROOT)), R, K, null}));
        // bounds and clock must be safe integers
        assertFalse(ok.apply(new Object[] {rc, list(ks), -1.0, K, null}));
        assertFalse(ok.apply(new Object[] {rc, list(ks), R, 0.5, null}));
        // the policy is closed and typed: policy.acc {max_receipt_age_s, max_keyset_age_s}, acc.keyset_versions values
        Map<String, Object> p = build(G0, "salt0", MAP0, is0(), params(), REF);
        assertTrue(verify(G0, p, ctx("policy", map("acc", map("max_receipt_age_s", 60L, "max_keyset_age_s", 60L)))).allow);
        assertEquals(List.of("schema", "intent_session", "accumulators"), failed(verify(G0, p, ctx("policy", map("acc", map("max_receipt_age_s", "60"))))));
        assertEquals(List.of("schema", "intent_session", "accumulators"), failed(verify(G0, p, ctx("policy", map("acc", map("other", 1L))))));
        assertEquals(List.of("schema", "intent_session", "accumulators"), failed(verify(G0, p, ctx("policy", map("acc", null)))));
        Map<String, Object> badVersions = ctx(); m(badVersions.get("acc")).put("keyset_versions", map(pub(SEQ_ROOT), 1L));
        assertEquals(List.of("accumulators"), failed(verify(G0, p, badVersions)));
    }

    // ------------------------------------------------------------------ layers (V5)
    @Test void layers() {
        Map<String, Object> p = build(G0, "salt0", MAP0, is0(), params(), REF);
        Map<String, Object> site = map("site", map("predicates", list(map("verb", "air.book", "where", list(map("field", "env.canon.add_ons", "op", "eq", "value", "[\"none\"]"))))));
        Pca.Verdict ok = verify(G0, p, ctx("layers", site));
        assertTrue(ok.allow, ok.reason);
        assertEquals(keys("schema", "intent_session", "layers", "accumulators"), new ArrayList<>(ok.checks.keySet()));
        Map<String, Object> org = map("org", map("predicates", list(map("verb", "air.book", "where", list(map("field", "action.params.total", "op", "lte", "value", 10_000L))))));
        assertEquals(List.of("layers"), failed(verify(G0, p, ctx("layers", org))));
        // absent ceilings admit everything; a null ceiling or one without a predicate list makes the context malformed
        assertTrue(verify(G0, p, ctx("layers", map())).allow);
        assertEquals(List.of("schema", "intent_session", "accumulators"), failed(verify(G0, p, ctx("layers", map("std", map())))));
        assertEquals(List.of("schema", "intent_session", "accumulators"), failed(verify(G0, p, ctx("layers", map("org", null)))));
        assertEquals(List.of("schema", "intent_session", "accumulators"), failed(verify(G0, p, ctx("layers", map("other", map("predicates", list()))))));
        // a ceiling with a member besides predicates fails as that ceiling; an empty predicate list admits nothing
        assertEquals(List.of("layers"), failed(verify(G0, p, ctx("layers", map("site", map("predicates", list(map("verb", "*")), "note", "x"))))));
        assertEquals(List.of("layers"), failed(verify(G0, p, ctx("layers", map("org", map("predicates", list()))))));
        // env.canon is empty when the schema check failed
        Map<String, Object> bad = params(); bad.put("total", 1L);
        assertEquals(List.of("schema", "layers", "accumulators"), failed(verify(G0, p, ctx("params", bad, "layers", site))));
        // no intent_session: layers is not reported even when configured
        Map<String, Object> plain = build(G0, "salt0", MAP0, null, params(), REF);
        assertEquals(CORE, new ArrayList<>(verify(G0, plain, ctx("layers", org)).checks.keySet()));
    }

    // ------------------------------------------------------------------ W-B through the pipeline
    @Test void wbThroughThePipeline() {
        // an inactive W-B unit reports nothing; a provenance policy activates provenance (an untouched path: pass)
        Map<String, Object> p = build(G0, "salt0", MAP0, is0(), params(), REF);
        Pca.Verdict v = verify(G0, p, ctx("wb", map("policy", map("provenance", map("params", map())))));
        assertEquals(keys("schema", "intent_session", "accumulators", "provenance"), new ArrayList<>(v.checks.keySet()));
        assertTrue(v.allow, v.reason);
        // a tainted material parameter: question -> provenance fails with intent_required
        Pca.Verdict q = verify(G0, p, ctx("wb", map("policy", map("provenance", map("params", map("action.params.offer_id", "material"))))));
        assertEquals(List.of("provenance"), failed(q));
        assertTrue(q.reason.startsWith("provenance: intent_required: "), q.reason);
        // a misconfigured (and active: a non-empty worlds list) world policy: facts fails and ends the unit
        Pca.Verdict f = verify(G0, p, ctx("wb", map("policy", map("world", map("worlds", list(map())), "provenance", map("params", map())))));
        assertEquals(keys("schema", "intent_session", "accumulators", "facts"), new ArrayList<>(f.checks.keySet()));
        // no intent_session: no W-B key even with an active W-B policy
        Map<String, Object> plain = build(G0, "salt0", MAP0, null, params(), REF);
        assertEquals(CORE, new ArrayList<>(verify(G0, plain, ctx("wb", map("policy", map("provenance", map("params", map()))))).checks.keySet()));
    }
}
