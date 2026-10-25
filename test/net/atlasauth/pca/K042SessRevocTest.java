package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.4.2 mutation kills for IntentSession.java (rule 13: the {@code intent_session} wire member, the grant caveat, the
 * signed session root) and IntentRevocation.java (rule 13 step 7). Differential against the TypeScript reference: the
 * cases and their exact reasons come from tools/pca-audit/java-mutate/k042-sessrevoc-oracle.mts
 * (test-data/k042-sessrevoc-cases.json); the JavaScript-semantics helpers (template-literal text, truthiness) and the
 * inputs JSON cannot carry (NaN, Infinity, -0 as a double) are pinned inline.
 */
public class K042SessRevocTest {
    static final String FAIL_CLOSED = "(fail closed): ";

    @SuppressWarnings("unchecked")
    static Map<String, Object> cases() throws Exception {
        return (Map<String, Object>) Json.parseLenient(new String(Files.readAllBytes(Path.of("test-data/k042-sessrevoc-cases.json")), StandardCharsets.UTF_8));
    }
    @SuppressWarnings("unchecked") static List<Map<String, Object>> list(String kind) throws Exception { return (List<Map<String, Object>>) (Object) cases().get(kind); }
    static Object json(Object text) { return IntentJs.normalize(Json.parseLenient((String) text)); }
    static double dbl(Object n) { return Double.parseDouble(((Json.Num) n).raw); }
    static void same(String name, Object want, String got) {
        if (want instanceof String && ((String) want).endsWith(FAIL_CLOSED)) {
            assertNotNull(got, name);
            assertTrue(got.startsWith((String) want), name + ": " + got);
        } else assertEquals(want, got, name);
    }
    static Map<String, Object> map(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }
    @SafeVarargs static <T> List<Object> lst(T... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    // ---- differential ----

    @Test void wire() throws Exception {
        List<Map<String, Object>> cs = list("wire");
        assertTrue(cs.size() >= 60);
        for (Map<String, Object> c : cs) same("wire " + c.get("name"), c.get("reason"), IntentSession.validateWire(json(c.get("v"))));
    }

    @Test void caveat() throws Exception {
        List<Map<String, Object>> cs = list("caveat");
        assertTrue(cs.size() >= 17);
        for (Map<String, Object> c : cs) same("caveat " + c.get("name"), c.get("reason"), IntentSession.caveatError(json(c.get("c"))));
    }

    /** Where the Java verifier refuses with another reason than the reference (both refuse). None since the verifier pins
     *  come before the body is bound (R3-01): an absent artifact pq_pk is refused by the pin checks in both. */
    static final Map<String, String> VERIFY_DIVERGES = Map.of();

    @Test void root() throws Exception {
        List<Map<String, Object>> cs = list("root");
        assertTrue(cs.size() >= 150);
        for (Map<String, Object> c : cs) {
            String n = (String) c.get("name");
            Object s = json(c.get("s"));
            same("shape " + n, c.get("shape"), IntentSession.rootShapeError(s));
            Object pins = c.containsKey("pq_pins") ? json(c.get("pq_pins")) : null;
            same("verify " + n, VERIFY_DIVERGES.containsKey(n) ? VERIFY_DIVERGES.get(n) : c.get("verify"), IntentSession.verifyRoot(s, pins));
        }
    }

    @Test void revocation() throws Exception {
        List<Map<String, Object>> cs = list("rev");
        assertTrue(cs.size() >= 100);
        for (Map<String, Object> c : cs) {
            Object ev = c.get("ev") == null ? null : json(c.get("ev"));
            Object ids = c.get("ids") == null ? null : json(c.get("ids"));
            boolean lastPresent = c.get("last") != null;
            Object last = lastPresent ? json(c.get("last")) : null;
            String got = IntentRevocation.checkSessionRevocation(ev, (String) c.get("session"), json(c.get("authority")), ids instanceof List ? (List<?>) ids : null,
                dbl(c.get("now")), dbl(c.get("maxAge")), (String) c.get("scope"), null, lastPresent, last);
            same("rev " + c.get("name"), c.get("reason"), got);
        }
    }

    @Test void primitive() throws Exception {
        List<Map<String, Object>> cs = list("prim");
        assertTrue(cs.size() >= 27);
        for (Map<String, Object> c : cs) {
            Object in = Json.parseLenient((String) c.get("text")); // raw spellings (1e3, 1.50): primitiveReason normalizes
            String got = IntentRevocation.primitiveReason(in);
            same("prim " + c.get("name"), c.get("reason"), got);
            assertEquals(c.get("reason") == null, IntentRevocation.checkPrimitive(in), "prim ok " + c.get("name"));
        }
    }

    // ---- inline: what JSON cannot carry ----

    static final String AUTH = Pca.b64(new byte[32]);

    @Test void nonFiniteAndNegZeroClock() {
        String mis = "revocation max age misconfigured (fail closed)", clk = "the verifier clock is not a safe integer (fail closed)";
        List<Object> ids = lst();
        assertEquals(mis, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, 0, Double.NaN, null, null, false, null));
        assertEquals(mis, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, 0, Double.POSITIVE_INFINITY, null, null, false, null));
        assertEquals(mis, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, 0, -0.0, null, null, false, null));
        assertEquals(mis, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, 0, 0.5, null, null, false, null));
        assertEquals(clk, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, Double.NaN, 0, null, null, false, null));
        assertEquals(clk, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, Double.NEGATIVE_INFINITY, 0, null, null, false, null));
        assertEquals(clk, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, -0.0, 0, null, null, false, null));
        assertEquals(clk, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, -1.5, 0, null, null, false, null));
        String none = "no session revocation epoch supplied";
        assertEquals(none, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, 0.0, 0.0, null, null, false, null));
        assertEquals(none, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, -1, 0, null, null, false, null));
        assertEquals(none, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, IntentJs.MAX_SAFE, IntentJs.MAX_SAFE, null, null, false, null));
        assertEquals(none, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, -IntentJs.MAX_SAFE, 0, null, null, false, null));
        assertEquals(clk, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, -IntentJs.MAX_SAFE - 1, 0, null, null, false, null));
        assertEquals(mis, IntentRevocation.checkSessionRevocation(null, "s", AUTH, ids, 0, IntentJs.MAX_SAFE + 1, null, null, false, null));
        assertEquals("ids must be an array and the authority a key", IntentRevocation.checkSessionRevocation(null, "s", AUTH, null, 0, 0, null, null, false, null));
        assertEquals("ids must be an array and the authority a key", IntentRevocation.checkSessionRevocation(null, "s", null, ids, 0, 0, null, null, false, null));
    }

    @Test void primitiveNotAnObject() {
        assertEquals("session revocation check error (fail closed)", IntentRevocation.primitiveReason(lst(1)));
        assertEquals("session revocation check error (fail closed)", IntentRevocation.primitiveReason("x"));
        assertFalse(IntentRevocation.checkPrimitive(lst(1)));
    }

    @Test void revocationIds() {
        assertEquals("pca-intent:session:S", IntentRevocation.sessionRevocationId("S"));
        assertEquals("pca-intent:map:M", IntentRevocation.mapRevocationId("M"));
        assertEquals("pca-intent:delta:D", IntentRevocation.deltaRevocationId("D"));
        assertEquals("pca-intent:profile:travel@2", IntentRevocation.profileRevocationId("travel", "2"));
        assertEquals("pca-intent-session:S", IntentRevocation.sessionRevocationScope("S"));
        // the empty set root (tree = SHA-256("")) and a one-element root, pinned
        assertEquals(IntentRevocation.revsetRoot(List.of()), IntentRevocation.revsetRoot(new ArrayList<>()));
        assertNotEquals(IntentRevocation.revsetRoot(List.of()), IntentRevocation.revsetRoot(List.of("a")));
    }

    /** {@code `${x}`} of a JSON value. */
    @Test void jsText() {
        assertEquals("undefined", IntentRevocation.jsText("x", false));
        assertEquals("undefined", IntentRevocation.jsText(null, false));
        assertEquals("null", IntentRevocation.jsText(null, true));
        assertEquals("0", IntentRevocation.jsText(new Json.Num("-0"), true));
        assertEquals("-1", IntentRevocation.jsText(new Json.Num("-1"), true));
        assertEquals("1.5", IntentRevocation.jsText(new Json.Num("1.5"), true));
        assertEquals("abc", IntentRevocation.jsText("abc", true));
        assertEquals("", IntentRevocation.jsText("", true));
        assertEquals("true", IntentRevocation.jsText(Boolean.TRUE, true));
        assertEquals("false", IntentRevocation.jsText(Boolean.FALSE, true));
        assertEquals("[object Object]", IntentRevocation.jsText(map("a", 1), true));
        assertEquals("[object Object]", IntentRevocation.jsText(map(), true));
        assertEquals("", IntentRevocation.jsText(lst(), true));
        assertEquals("a", IntentRevocation.jsText(lst("a"), true));
        assertEquals("a,b", IntentRevocation.jsText(lst("a", "b"), true));
        // null / holes print empty; nested arrays flatten; objects print [object Object]; -0 prints 0
        assertEquals("1,,x,2,3,[object Object],0,true", IntentRevocation.jsText(lst(new Json.Num("1"), null, "x", lst(new Json.Num("2"), new Json.Num("3")), map("k", "v"), new Json.Num("-0"), true), true));
        assertEquals(",", IntentRevocation.jsText(lst(null, null), true));
        assertEquals(",a", IntentRevocation.jsText(lst(null, "a"), true));
        assertEquals("a,", IntentRevocation.jsText(lst("a", null), true));
        assertEquals("", IntentRevocation.jsText(lst(lst()), true));
        assertEquals(",", IntentRevocation.jsText(lst(lst(), lst()), true));
    }

    /** JavaScript truthiness of a JSON value. */
    @Test void truthy() {
        assertFalse(IntentRevocation.truthy(null));
        assertTrue(IntentRevocation.truthy(Boolean.TRUE));
        assertFalse(IntentRevocation.truthy(Boolean.FALSE));
        assertFalse(IntentRevocation.truthy(""));
        assertTrue(IntentRevocation.truthy("0"));
        assertTrue(IntentRevocation.truthy("false"));
        assertFalse(IntentRevocation.truthy(new Json.Num("0")));
        assertFalse(IntentRevocation.truthy(new Json.Num("-0")));
        assertTrue(IntentRevocation.truthy(new Json.Num("1")));
        assertTrue(IntentRevocation.truthy(new Json.Num("-1")));
        assertTrue(IntentRevocation.truthy(new Json.Num("0.5")));
        assertFalse(IntentRevocation.truthy(Double.NaN));
        assertFalse(IntentRevocation.truthy(0.0));
        assertTrue(IntentRevocation.truthy(2.0));
        assertTrue(IntentRevocation.truthy(map()));
        assertTrue(IntentRevocation.truthy(lst()));
    }

    @Test void grantSessionCaveat() {
        Map<String, Object> sc = map("type", "intent_session", "session", "s", "seq", new Json.Num("0"), "root", "r");
        Map<String, Object> sc2 = map("type", "intent_session", "session", "t");
        Map<String, Object> env = map("type", "envelope");
        assertSame(sc, IntentSession.grantSessionCaveat(map("caveats", lst(env, "x", lst(1), null, sc, sc2))));
        assertSame(sc, IntentSession.grantSessionCaveat(map("caveats", lst(sc, sc2))));
        assertSame(sc2, IntentSession.grantSessionCaveat(map("caveats", lst(map("type", "intent_sessionx"), sc2))));
        assertNull(IntentSession.grantSessionCaveat(map("caveats", lst(env, "intent_session", map("kind", "intent_session")))));
        assertNull(IntentSession.grantSessionCaveat(map("caveats", lst())));
        assertNull(IntentSession.grantSessionCaveat(map("caveats", map("a", sc))));
        assertNull(IntentSession.grantSessionCaveat(map("caveats", null)));
        assertNull(IntentSession.grantSessionCaveat(map()));
        assertNull(IntentSession.grantSessionCaveat(lst(sc)));
        assertNull(IntentSession.grantSessionCaveat(null));
        assertNull(IntentSession.grantSessionCaveat("x"));
    }

    @Test void caveatNonJsonShapes() {
        assertEquals("not an intent_session caveat", IntentSession.caveatError(null));
        assertEquals("not an intent_session caveat", IntentSession.caveatError(lst(map("type", "intent_session"))));
        assertEquals("not an intent_session caveat", IntentSession.caveatError(map()));
    }

    @Test void goals() {
        assertEquals("pca-intent:v2:S:M", IntentSession.intentGoalV2("S", "M"));
        assertEquals("pca-intent:v2c:S:M", IntentSession.intentGoalV2c("S", "M"));
    }

    // ---- a lone surrogate in a SIGNED revocation epoch's revoked list: the strict leaf canonicalization throws ----

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

    @Test void loneSurrogateRevokedFailsClosedWithTheExceptionName() {
        String rev = "k042sr/rev";
        long now = 1_800_000_000_000L;
        Map<String, Object> body = map("instance_id", "ana", "grant_ref", "pca-intent-session:S", "epoch", IntentJs.ofLong(1), "set_size", IntentJs.ofLong(1),
            "root", IntentRevocation.revsetRoot(List.of("x")), "issued_at", IntentJs.ofLong(now - 1000), "not_after", IntentJs.ofLong(now + 1000));
        Map<String, Object> ep = new LinkedHashMap<>(body);
        ep.put("guardian", pub(rev));
        ep.put("sig", sign(rev, Pca.concat(IntentRevocation.REVEPOCH_DOMAIN.getBytes(StandardCharsets.UTF_8), IntentJs.canonBytes(body))));
        Map<String, Object> ok = map("epoch", ep, "revoked", lst("x"));
        assertNull(IntentRevocation.checkSessionRevocation(ok, "S", pub(rev), lst("y"), now, 60_000, null, null, false, null));
        assertEquals("'x' is revoked", IntentRevocation.checkSessionRevocation(ok, "S", pub(rev), lst("y", "x"), now, 60_000, null, null, false, null));
        Map<String, Object> bad = map("epoch", ep, "revoked", lst("\uD800"));
        assertEquals("session revocation check error (fail closed): IllegalArgumentException",
            IntentRevocation.checkSessionRevocation(bad, "S", pub(rev), lst("y"), now, 60_000, null, null, false, null));
        // a lone surrogate in the signed body: the epoch check itself fails closed
        Map<String, Object> ep2 = new LinkedHashMap<>(ep);
        ep2.put("instance_id", "\uD800");
        assertEquals("revocation epoch check error",
            IntentRevocation.checkSessionRevocation(map("epoch", ep2, "revoked", lst("x")), "S", pub(rev), lst("y"), now, 60_000, null, null, false, null));
        assertEquals("revocation epoch check error", IntentRevocation.checkRevocationEpoch(ep2, pub(rev), now, "pca-intent-session:S", null));
        assertNull(IntentRevocation.checkRevocationEpoch(ep, pub(rev), now, "pca-intent-session:S", null));
        assertEquals("revocation epoch not signed by the pinned guardian", IntentRevocation.checkRevocationEpoch(ep, AUTH, now, "pca-intent-session:S", null));
        Map<String, Object> ep3 = new LinkedHashMap<>(ep);
        ep3.put("alg", "nope-dsa");
        assertEquals("revocation epoch not signed by the pinned guardian", IntentRevocation.checkRevocationEpoch(ep3, pub(rev), now, "pca-intent-session:S", null));
        // the scope default is the session scope; an explicit scope overrides it
        assertEquals("revocation epoch is for a different grant",
            IntentRevocation.checkSessionRevocation(ok, "S", pub(rev), lst("y"), now, 60_000, "pca-intent-session:T", null, false, null));
        assertNull(IntentRevocation.checkSessionRevocation(ok, "T", pub(rev), lst("y"), now, 60_000, "pca-intent-session:S", null, false, null));
        // the tracked last epoch equal to the new one is accepted (no false equivocation)
        assertNull(IntentRevocation.checkSessionRevocation(ok, "S", pub(rev), lst("y"), now, 60_000, null, null, true, map("epoch", new LinkedHashMap<>(ep), "revoked", lst("x"))));
    }
}
