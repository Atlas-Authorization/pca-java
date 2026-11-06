package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link K3}: every check of every verifier, signed end to end (keys: seed = sha256("k3kill/&lt;label&gt;")),
 * asserting the whole verdict (decision, code, reason, every field). Boundaries are probed on both sides with a VALID signature, so
 * a dropped check is observable; {@link Boom} (a map whose every read throws) reaches the fail-closed catch blocks.
 */
public class K3K05KillTest {

    // ---- keys and builders ----

    static byte[] seed(String label) {
        try { return MessageDigest.getInstance("SHA-256").digest(("k3kill/" + label).getBytes(StandardCharsets.UTF_8)); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
    static String pub(String label) {
        byte[] pk = new byte[32];
        org.bouncycastle.math.ec.rfc8032.Ed25519.generatePublicKey(seed(label), 0, pk, 0);
        return Pca.b64(pk);
    }
    static String sign(String label, String domain, Object body) {
        byte[] msg = Pca.concat(domain.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body));
        byte[] sig = new byte[64];
        org.bouncycastle.math.ec.rfc8032.Ed25519.sign(seed(label), 0, msg, 0, msg.length, sig, 0);
        return Pca.b64(sig);
    }

    static final String PA = pub("a"), PB = pub("b"), PC = pub("c"), PP = pub("principal"), PG = pub("agent");
    static final Object DEL = new Object();

    static Map<String, Object> o(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }
    static List<Object> l(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }
    /** A copy of m with the pairs applied (value DEL removes the key). */
    static Map<String, Object> with(Map<String, Object> m, Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>(m);
        for (int i = 0; i < kv.length; i += 2) {
            if (kv[i + 1] == DEL) out.remove((String) kv[i]);
            else out.put((String) kv[i], kv[i + 1]);
        }
        return out;
    }
    static Map<String, Object> without(Map<String, Object> m, String k) { return with(m, k, DEL); }
    static String rep(char c, int n) { return String.valueOf(c).repeat(n); }
    static Json.Num num(String raw) { return new Json.Num(raw); }
    static String canon(Object v) { return Json.canonicalize(v); }
    static String hash(Object v) { return Pca.hashCanonical(v); }
    static List<Object> strs(String prefix, int n) {
        List<Object> out = new ArrayList<>();
        for (int i = 0; i < n; i++) out.add(prefix + i);
        return out;
    }

    /** A map whose every read throws: reaches the catch blocks. */
    static final class Boom extends AbstractMap<String, Object> {
        @Override public Set<Map.Entry<String, Object>> entrySet() { throw new IllegalStateException("boom"); }
    }

    // =================================================================================================================
    // fresh_at
    // =================================================================================================================

    static final String[] FRESH_BODY = {"v", "scope", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest", "issued_at", "signer"};

    /** The base token with the overrides applied, signed by "a" over exactly the members the verifier signs. */
    static Map<String, Object> fresh(Object... kv) {
        Map<String, Object> t = with(o("v", 1L, "scope", "s", "revocation_epoch", 5L, "ledger_tree_size", 6L, "budget_version", 7L, "policy_revision", 8L,
            "policy_digest", "pd", "issued_at", 1000L, "signer", PA), kv);
        Map<String, Object> body = new LinkedHashMap<>();
        for (String k : FRESH_BODY) body.put(k, t.get(k));
        t.put("sig", sign("a", K3.FRESH_AT_DOMAIN, body));
        return t;
    }

    @Test void verifyFreshAtEveryCheck() {
        assertTrue(K3.verifyFreshAt(fresh(), PA));
        assertTrue(K3.verifyFreshAt(fresh("scope", rep('s', 256)), PA));
        assertTrue(K3.verifyFreshAt(fresh("policy_digest", rep('d', 128)), PA));
        assertTrue(K3.verifyFreshAt(fresh("issued_at", 0L, "revocation_epoch", 0L), PA));
        assertFalse(K3.verifyFreshAt("x", PA));
        assertFalse(K3.verifyFreshAt(fresh(), null));
        assertFalse(K3.verifyFreshAt(fresh(), PB));
        assertFalse(K3.verifyFreshAt(fresh("signer", PB), PA)); // signed by a, claims b
        for (Object v : new Object[] {2L, "1", DEL, 0L}) assertFalse(K3.verifyFreshAt(fresh("v", v), PA), "v " + v);
        for (Object s : new Object[] {"", rep('s', 257), 5L, DEL}) assertFalse(K3.verifyFreshAt(fresh("scope", s), PA), "scope " + s);
        for (Object s : new Object[] {"", rep('d', 129), 5L, DEL}) assertFalse(K3.verifyFreshAt(fresh("policy_digest", s), PA), "digest " + s);
        for (Object s : new Object[] {-1L, DEL, num("1.5"), "1"}) assertFalse(K3.verifyFreshAt(fresh("issued_at", s), PA), "issued " + s);
        for (String k : new String[] {"revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision"}) {
            assertFalse(K3.verifyFreshAt(fresh(k, -1L), PA), k);
            assertFalse(K3.verifyFreshAt(fresh(k, DEL), PA), k);
            assertTrue(K3.verifyFreshAt(fresh(k, 0L), PA), k);
        }
        assertFalse(K3.verifyFreshAt(with(fresh(), "sig", fresh("scope", "t").get("sig")), PA));
        assertFalse(K3.verifyFreshAt(with(fresh(), "sig", 5L), PA));
        assertFalse(K3.verifyFreshAt(with(fresh(), "sig", DEL), PA));
    }

    @Test void freshAtDigest() {
        Map<String, Object> t = fresh();
        assertEquals(hash(o("d", K3.FRESH_AT_REF_DOMAIN, "t", t)), K3.freshAtDigest(t));
        assertNull(K3.freshAtDigest(with(t, "x", num("1e5")))); // outside the strict profile
    }

    static final Map<String, Object> LOCAL = o("revocation_epoch", 5L, "ledger_tree_size", 6L, "budget_version", 7L, "policy_revision", 8L, "policy_digest", "pd");

    static void verdict(K3.FreshVerdict v, String decision, String code, String... behind) {
        assertEquals(decision, v.decision);
        assertEquals(code, v.code);
        assertEquals(Arrays.asList(behind), v.behind);
    }

    @Test void checkFreshAtEveryOutcome() {
        Map<String, Object> t = fresh();
        verdict(K3.checkFreshAt(t, LOCAL, PA, "s", 1000L, null), "ok", null);
        verdict(K3.checkFreshAt(fresh("v", 2L), LOCAL, PA, "s", 1000L, null), "deny", "bad_token");
        verdict(K3.checkFreshAt(t, LOCAL, PA, "other", 1000L, null), "deny", "wrong_scope");
        verdict(K3.checkFreshAt(t, LOCAL, PA, "s", -59000L, null), "ok", null);
        verdict(K3.checkFreshAt(t, LOCAL, PA, "s", -59001L, null), "deny", "token_from_the_future");
        verdict(K3.checkFreshAt(t, LOCAL, PA, "s", 1500L, 500.0), "ok", null);
        verdict(K3.checkFreshAt(t, LOCAL, PA, "s", 1500L, 499.0), "deny", "token_too_old");
        verdict(K3.checkFreshAt(t, LOCAL, PA, "s", 1500L, Double.NaN), "deny", "token_too_old");
        verdict(K3.checkFreshAt(t, null, PA, "s", 1000L, null), "escalate", "stale_state", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision");
        verdict(K3.checkFreshAt(t, with(LOCAL, "policy_digest", "other"), PA, "s", 1000L, null), "deny", "policy_fork");
        verdict(K3.checkFreshAt(t, with(LOCAL, "policy_digest", "other", "policy_revision", 9L), PA, "s", 1000L, null), "ok", null);
        verdict(K3.checkFreshAt(t, with(LOCAL, "policy_digest", "other", "policy_revision", DEL), PA, "s", 1000L, null), "escalate", "stale_state", "policy_revision");
        verdict(K3.checkFreshAt(t, with(LOCAL, "revocation_epoch", 4L, "budget_version", "9"), PA, "s", 1000L, null), "escalate", "stale_state", "revocation_epoch", "budget_version");
        verdict(K3.checkFreshAt(t, with(LOCAL, "ledger_tree_size", 5L, "revocation_epoch", 99L), PA, "s", 1000L, null), "escalate", "stale_state", "ledger_tree_size");
        verdict(K3.checkFreshAt(t, new Boom(), PA, "s", 1000L, null), "deny", "bad_token");
        verdict(K3.checkFreshAt(new Boom(), LOCAL, PA, "s", 1000L, null), "deny", "bad_token");
    }

    @Test void validateFreshAtWireEveryMessage() {
        Map<String, Object> w = fresh();
        assertNull(K3.validateFreshAtWire(w));
        assertNull(K3.validateFreshAtWire(with(w, "scope", rep('s', 256), "policy_digest", rep('d', 128))));
        assertEquals("'fresh_at' must be an object", K3.validateFreshAtWire("x"));
        assertEquals("'fresh_at' has an unknown field 'z'", K3.validateFreshAtWire(with(w, "z", 1L)));
        assertEquals("'fresh_at.v' must be 1", K3.validateFreshAtWire(with(w, "v", 2L)));
        String sp = "'fresh_at' scope and policy_digest must be non-empty strings";
        assertEquals(sp, K3.validateFreshAtWire(with(w, "scope", "")));
        assertEquals(sp, K3.validateFreshAtWire(with(w, "scope", rep('s', 257))));
        assertEquals(sp, K3.validateFreshAtWire(with(w, "policy_digest", "")));
        assertEquals(sp, K3.validateFreshAtWire(with(w, "policy_digest", rep('d', 129))));
        for (String k : new String[] {"revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "issued_at"}) {
            assertEquals("'fresh_at." + k + "' must be a non-negative safe integer", K3.validateFreshAtWire(with(w, k, -1L)), k);
            assertEquals("'fresh_at." + k + "' must be a non-negative safe integer", K3.validateFreshAtWire(with(w, k, DEL)), k);
        }
        assertEquals("'fresh_at.signer' is not canonical base64url (32 bytes)", K3.validateFreshAtWire(with(w, "signer", "abc")));
        assertEquals("'fresh_at.sig' is not canonical base64url (64 bytes)", K3.validateFreshAtWire(with(w, "sig", PA)));
    }

    @Test void freshAtPolicyFromJson() {
        Map<String, Object> local = o("policy_revision", 1L);
        K3.FreshAtPolicy p = K3.FreshAtPolicy.fromJson(o("signer", "sg", "scope", "sc", "local", local, "max_token_age_ms", 5L, "require", true, "side_carried", "tok"));
        assertEquals("sg", p.signer);
        assertEquals("sc", p.scope);
        assertSame(local, p.local);
        assertEquals(5.0, p.maxTokenAgeMs);
        assertTrue(p.require);
        assertTrue(p.hasSideCarried);
        assertEquals("tok", p.sideCarried);
        K3.FreshAtPolicy q = K3.FreshAtPolicy.fromJson(o("signer", 5L, "scope", 6L, "local", "x", "max_token_age_ms", "x"));
        assertNull(q.signer);
        assertNull(q.scope);
        assertNull(q.local);
        assertTrue(q.maxTokenAgeMs.isNaN());
        assertFalse(q.require);
        assertFalse(q.hasSideCarried);
        assertNull(q.sideCarried);
        K3.FreshAtPolicy e = K3.FreshAtPolicy.fromJson(o());
        assertNull(e.maxTokenAgeMs);
        assertTrue(K3.FreshAtPolicy.fromJson(o("side_carried", null)).hasSideCarried);
        assertNull(K3.FreshAtPolicy.fromJson("x"));
        // require is JavaScript truthiness
        Object[] truthy = {true, 1L, num("0.5"), num("-2"), "x", l(), o(), 2.5};
        Object[] falsy = {null, false, 0L, num("0"), num("-0"), num("NaN"), "", 0.0};
        for (Object v : truthy) assertTrue(K3.FreshAtPolicy.fromJson(o("require", v)).require, "truthy " + v);
        for (Object v : falsy) assertFalse(K3.FreshAtPolicy.fromJson(o("require", v)).require, "falsy " + v);
    }

    // =================================================================================================================
    // policy bundles
    // =================================================================================================================

    static Map<String, Object> body1(Object... kv) {
        return with(o("v", 1L, "kind", "pca-policy-bundle", "revision", 1L, "grants", l("g1"), "template_digests", l("t1"), "min_verifier_version", "1.2",
            "issued_at", 100L), kv);
    }
    static Map<String, Object> sigOf(String label, Map<String, Object> body) { return o("signer", pub(label), "sig", sign(label, K3.BUNDLE_DOMAIN, body)); }
    static Map<String, Object> bundle(Map<String, Object> body, Object... sigs) { return with(body, "sigs", l(sigs)); }
    static String bdigest(Map<String, Object> body) { return hash(o("d", K3.BUNDLE_REF_DOMAIN, "b", body)); }

    @Test void bundleShapeErrorEveryMessage() {
        assertNull(K3.bundleShapeError(body1()));
        String nb = "not a policy bundle", rt = "bad revision or time", pv = "prev must be absent at revision 1 and present after";
        assertEquals(nb, K3.bundleShapeError("x"));
        assertEquals(nb, K3.bundleShapeError(body1("v", 2L)));
        assertEquals(nb, K3.bundleShapeError(body1("kind", "x")));
        for (Object r : new Object[] {num("1.5"), 0L, DEL, "1"}) assertEquals(rt, K3.bundleShapeError(body1("revision", r)), "revision " + r);
        for (Object r : new Object[] {-1L, DEL}) assertEquals(rt, K3.bundleShapeError(body1("issued_at", r)), "issued " + r);
        assertEquals(pv, K3.bundleShapeError(body1("prev", "p")));
        assertEquals(pv, K3.bundleShapeError(body1("prev", null)));
        assertEquals(pv, K3.bundleShapeError(body1("revision", 2L)));
        assertEquals(pv, K3.bundleShapeError(body1("revision", 2L, "prev", "")));
        assertEquals(pv, K3.bundleShapeError(body1("revision", 2L, "prev", rep('p', 129))));
        assertNull(K3.bundleShapeError(body1("revision", 2L, "prev", rep('p', 128))));
        for (String k : new String[] {"grants", "template_digests"}) {
            String bad = "bad " + k;
            assertEquals(bad, K3.bundleShapeError(body1(k, "x")), k);
            assertEquals(bad, K3.bundleShapeError(body1(k, DEL)), k);
            assertEquals(bad, K3.bundleShapeError(body1(k, strs("g", 4097))), k);
            assertNull(K3.bundleShapeError(body1(k, strs("g", 4096))), k);
            assertNull(K3.bundleShapeError(body1(k, l())), k);
            assertEquals(bad, K3.bundleShapeError(body1(k, l("g", ""))), k);
            assertEquals(bad, K3.bundleShapeError(body1(k, l(5L))), k);
            assertEquals(bad, K3.bundleShapeError(body1(k, l(rep('g', 129)))), k);
            assertNull(K3.bundleShapeError(body1(k, l(rep('g', 128)))), k);
        }
        for (String k : new String[] {"schema_digest", "constitution_digest", "flow_rules_digest"}) {
            assertEquals("bad " + k, K3.bundleShapeError(body1(k, "")), k);
            assertEquals("bad " + k, K3.bundleShapeError(body1(k, rep('x', 129))), k);
            assertEquals("bad " + k, K3.bundleShapeError(body1(k, 5L)), k);
            assertEquals("bad " + k, K3.bundleShapeError(body1(k, null)), k);
            assertNull(K3.bundleShapeError(body1(k, rep('x', 128))), k);
        }
        Map<String, Object> nullKey = body1();
        nullKey.put(null, ""); // only the three named digests are checked
        assertNull(K3.bundleShapeError(nullKey));
        String mv = "bad min_verifier_version";
        for (Object v : new Object[] {DEL, 5L, "1.2.3.4.5", "1234567", "a", "", "1.", "1..2"}) assertEquals(mv, K3.bundleShapeError(body1("min_verifier_version", v)), "mv " + v);
        for (Object v : new Object[] {"1.2.3.4", "123456.1", "0"}) assertNull(K3.bundleShapeError(body1("min_verifier_version", v)), "mv " + v);
        // shadow (the reference's shapeError): 1..16 distinct digest strings
        assertNull(K3.bundleShapeError(body1("shadow", l("a"))));
        assertNull(K3.bundleShapeError(body1("shadow", strs("s", 16))));
        assertNull(K3.bundleShapeError(body1("shadow", l(rep('s', 128)))));
        for (Object v : new Object[] {l(), strs("s", 17), l("a", "a"), l(""), l(rep('s', 129)), l(5L), "x", null})
            assertEquals("bad shadow", K3.bundleShapeError(body1("shadow", v)), "shadow " + v);
    }

    @Test void compareVersionEveryBranch() {
        String[][] cases = {
            {"1.2", "1.10", "-1"}, {"1.10", "1.2", "1"}, {"1.0", "1", "0"}, {"1", "1.0.0", "0"}, {"1.0.1", "1", "1"}, {"1", "1.0.1", "-1"},
            {"2", "10", "-1"}, {"2", "1", "1"}, {"1.", "1.0", "0"}, {"1. ", "1", "0"}, {" 2", "2", "0"}, {"a", "1", "1"}, {"1", "a", "1"},
            {"", "0", "0"}, {"0", "", "0"}, {"1..", "1", "0"}, {"1", "1.1", "-1"}, {"1.1", "1", "1"}, {"3.4.5.6", "3.4.5.6", "0"}, {"5e-1", "0", "1"}, {"0", "5e-1", "-1"}};
        for (String[] c : cases) assertEquals(Integer.parseInt(c[2]), K3.compareVersion(c[0], c[1]), c[0] + " vs " + c[1]);
    }

    static void bundleOk(K3.BundleVerdict r, long rev, String digest, String... signers) {
        assertTrue(r.ok, () -> r.code + ": " + r.reason);
        assertNull(r.code);
        assertNull(r.reason);
        assertEquals(rev, r.revision);
        assertEquals(digest, r.digest);
        assertEquals(Arrays.asList(signers), r.signers);
    }
    static void bundleFail(K3.BundleVerdict r, String code, String reason) {
        assertFalse(r.ok);
        assertEquals(code, r.code);
        assertEquals(reason, r.reason);
        assertEquals(0L, r.revision);
        assertNull(r.digest);
        assertNull(r.signers);
    }

    @Test void verifyBundleEveryOutcome() {
        Map<String, Object> b1 = body1();
        Map<String, Object> sa = sigOf("a", b1), sb = sigOf("b", b1), sc = sigOf("c", b1);
        String d1 = bdigest(b1);
        List<Object> pin = l(PA);
        bundleOk(K3.verifyBundle(bundle(b1, sa), pin, 1L, "1.2", null, null), 1, d1, PA);
        assertEquals(d1, K3.bundleDigest(bundle(b1, sa)));
        assertNull(K3.bundleDigest("x"));
        bundleFail(K3.verifyBundle(bundle(body1("v", 2L), sa), pin, 1L, "1.2", null, null), "malformed", "not a policy bundle");
        String bst = "bad sigs or threshold";
        bundleFail(K3.verifyBundle(with(b1, "sigs", "x"), pin, 1L, "1.2", null, null), "malformed", bst);
        bundleFail(K3.verifyBundle(b1, pin, 1L, "1.2", null, null), "malformed", bst);
        for (Object t : new Object[] {0L, num("1.5"), "1", null, -1L}) bundleFail(K3.verifyBundle(bundle(b1, sa), pin, t, "1.2", null, null), "malformed", bst);
        List<Object> s64 = l(sa), s65 = l(sa);
        for (int i = 0; i < 63; i++) s64.add(o());
        for (int i = 0; i < 64; i++) s65.add(o());
        bundleOk(K3.verifyBundle(with(b1, "sigs", s64), pin, 1L, "1.2", null, null), 1, d1, PA);
        bundleFail(K3.verifyBundle(with(b1, "sigs", s65), pin, 1L, "1.2", null, null), "malformed", bst);
        // junk entries are skipped
        bundleOk(K3.verifyBundle(bundle(b1, "x", o("signer", 5L), o("sig", "x"), sa), pin, 1L, "1.2", null, null), 1, d1, PA);
        // a pinned non-string signer object is still not a signer
        Json.Num odd = num("7");
        bundleOk(K3.verifyBundle(bundle(b1, o("signer", odd, "sig", sa.get("sig")), sa), l(PA, odd), 1L, "1.2", null, null), 1, d1, PA);
        bundleFail(K3.verifyBundle(bundle(b1, sa, sc), l(PA, PB), 2L, "1.2", null, null), "below_threshold", "1 valid pinned signature(s), need 2");
        bundleFail(K3.verifyBundle(bundle(b1, sa, sa), l(PA, PB), 2L, "1.2", null, null), "below_threshold", "1 valid pinned signature(s), need 2");
        bundleFail(K3.verifyBundle(bundle(b1, o("signer", PA, "sig", sb.get("sig"))), pin, 1L, "1.2", null, null), "below_threshold", "0 valid pinned signature(s), need 1");
        bundleFail(K3.verifyBundle(bundle(b1, sigOf("a", body1("issued_at", 101L))), pin, 1L, "1.2", null, null), "below_threshold", "0 valid pinned signature(s), need 1");
        bundleOk(K3.verifyBundle(bundle(b1, sa, sb), l(PA, PB), 2L, "1.2", null, null), 1, d1, PA, PB);
        bundleOk(K3.verifyBundle(bundle(b1, sb, sa), l(PA, PB), 2L, "1.2", null, null), 1, d1, PB, PA);
        String old = "needs verifier >= 1.2";
        for (String v : new String[] {null, "1.1", "x.1", "1.2.3.4.5", "", "0.9.9"}) bundleFail(K3.verifyBundle(bundle(b1, sa), pin, 1L, v, null, null), "verifier_too_old", old);
        for (String v : new String[] {"1.2", "1.10", "2", "1.2.0.1"}) bundleOk(K3.verifyBundle(bundle(b1, sa), pin, 1L, v, null, null), 1, d1, PA);
        // the accepted chain
        bundleFail(K3.verifyBundle(bundle(b1, sa), pin, 1L, "1.2", 2L, d1), "rollback", "revision 1 < accepted 2");
        bundleOk(K3.verifyBundle(bundle(b1, sa), pin, 1L, "1.2", 1L, d1), 1, d1, PA);
        bundleFail(K3.verifyBundle(bundle(b1, sa), pin, 1L, "1.2", 1L, "other"), "broken_chain", "same revision, different content");
        bundleFail(K3.verifyBundle(bundle(b1, sa), pin, 1L, "1.2", 1L, null), "broken_chain", "same revision, different content");
        bundleFail(K3.verifyBundle(bundle(b1, sa), pin, 1L, "1.2", 0L, "anything"), "broken_chain", "prev does not chain to the accepted revision");
        bundleOk(K3.verifyBundle(bundle(b1, sa), pin, 1L, "1.2", 0L, null), 1, d1, PA);
        Map<String, Object> b2 = body1("revision", 2L, "prev", "P");
        Map<String, Object> s2 = sigOf("a", b2);
        String d2 = bdigest(b2);
        bundleOk(K3.verifyBundle(bundle(b2, s2), pin, 1L, "1.2", 1L, "P"), 2, d2, PA);
        bundleFail(K3.verifyBundle(bundle(b2, s2), pin, 1L, "1.2", 1L, "Q"), "broken_chain", "prev does not chain to the accepted revision");
        bundleOk(K3.verifyBundle(bundle(b2, s2), pin, 1L, "1.2", 0L, "Q"), 2, d2, PA);
        bundleOk(K3.verifyBundle(bundle(b2, s2), pin, 1L, "1.2", 2L, d2), 2, d2, PA);
        bundleFail(K3.verifyBundle(bundle(b2, s2), pin, 1L, "1.2", 3L, d2), "rollback", "revision 2 < accepted 3");
        // fail closed on a throw
        bundleFail(K3.verifyBundle(new Boom(), pin, 1L, "1.2", null, null), "malformed", "malformed bundle");
        bundleFail(K3.verifyBundle(bundle(b1, sa), null, 1L, "1.2", null, null), "malformed", "malformed bundle");
    }

    // =================================================================================================================
    // decision log
    // =================================================================================================================

    static Map<String, Object> head(Object size, Object root, Object last, Object... kv) {
        Map<String, Object> h = with(o("v", 1L, "size", size, "root", root, "last_commit", last, "issued_at", 5L, "signer", PA), kv);
        h.put("sig", sign("a", K3.LOG_HEAD_DOMAIN, h));
        return h;
    }
    static String commit(Object rec) { return hash(o("d", K3.RECORD_DOMAIN, "r", rec)); }

    @Test void verifyLogHeadEveryCheck() {
        assertTrue(K3.verifyLogHead(head(2L, "r", "c"), PA));
        assertTrue(K3.verifyLogHead(head(0L, "", "", "issued_at", 0L), PA));
        assertFalse(K3.verifyLogHead(head(2L, "r", "c"), null));
        assertFalse(K3.verifyLogHead(head(2L, "r", "c"), PB));
        assertFalse(K3.verifyLogHead("x", PA));
        assertFalse(K3.verifyLogHead(head(2L, "r", "c", "signer", PB), PA));
        for (Object v : new Object[] {2L, DEL}) assertFalse(K3.verifyLogHead(head(2L, "r", "c", "v", v), PA));
        for (Object v : new Object[] {-1L, num("1.5"), "2"}) assertFalse(K3.verifyLogHead(head(v, "r", "c"), PA), "size " + v);
        assertFalse(K3.verifyLogHead(head(2L, "r", "c", "size", DEL), PA));
        for (Object v : new Object[] {-1L, DEL}) assertFalse(K3.verifyLogHead(head(2L, "r", "c", "issued_at", v), PA), "issued " + v);
        assertFalse(K3.verifyLogHead(head(2L, 5L, "c"), PA));
        assertFalse(K3.verifyLogHead(head(2L, "r", "c", "root", DEL), PA));
        assertFalse(K3.verifyLogHead(head(2L, "r", 5L), PA));
        assertFalse(K3.verifyLogHead(head(2L, "r", "c", "last_commit", DEL), PA));
        assertFalse(K3.verifyLogHead(with(head(2L, "r", "c"), "sig", head(3L, "r", "c").get("sig")), PA));
        assertFalse(K3.verifyLogHead(with(head(2L, "r", "c"), "sig", 5L), PA));
        // a member outside the strict profile makes the body unsignable: refused, never accepted
        assertFalse(K3.verifyLogHead(with(head(2L, "r", "c"), "x", num("1e5")), PA));
    }

    @Test void recordInclusion() {
        Map<String, Object> rec = o("v", 1L, "seq", 0L, "prev", "");
        String c0 = commit(rec);
        assertEquals(c0, K3.recordCommit(rec));
        assertNull(K3.recordCommit(o("x", num("1e5"))));
        Map<String, Object> proof = o("index", 0L, "size", 1L, "path", l());
        assertTrue(K3.verifyRecordInclusion(rec, proof, head(1L, Pca.b64(Pca.leafHash(c0)), c0), PA));
        assertFalse(K3.verifyRecordInclusion(rec, proof, head(1L, Pca.b64(Pca.leafHash(c0)), c0), PB));
        assertFalse(K3.verifyRecordInclusion(o("v", 1L, "seq", 1L, "prev", ""), proof, head(1L, Pca.b64(Pca.leafHash(c0)), c0), PA));
        // an unhashable record never verifies, even against a root built from the "null" leaf
        assertFalse(K3.verifyRecordInclusion(o("x", num("1e5")), proof, head(1L, Pca.b64(Pca.leafHash(null)), ""), PA));
        assertFalse(K3.verifyRecordInclusion(rec, proof, new Boom(), PA));
    }

    static void batchOk(K3.BatchVerdict r, long next, String last) {
        assertTrue(r.ok, () -> r.reason);
        assertEquals(next, r.next);
        assertEquals(last, r.lastCommit);
        assertNull(r.reason);
    }
    static void batchBad(K3.BatchVerdict r, String reason) {
        assertFalse(r.ok);
        assertEquals(reason, r.reason);
        assertEquals(0L, r.next);
        assertNull(r.lastCommit);
    }

    @Test void verifyBatchEveryOutcome() {
        Map<String, Object> r0 = o("v", 1L, "seq", 0L, "prev", "");
        String c0 = commit(r0);
        Map<String, Object> r1 = o("v", 1L, "seq", 1L, "prev", c0);
        String c1 = commit(r1);
        Map<String, Object> h2 = head(2L, "root", c1);
        batchOk(K3.verifyBatch(o("from", 0L, "records", l(r0, r1), "head", h2), 0L, "", PA), 2, c1);
        batchOk(K3.verifyBatch(o("from", 1L, "records", l(r1), "head", h2), 1L, c0, PA), 2, c1);
        batchOk(K3.verifyBatch(o("from", 0L, "records", l(r0, r1), "head", head(3L, "root", "zz")), 0L, "", PA), 2, c1);
        batchOk(K3.verifyBatch(o("from", 0L, "records", l(), "head", head(0L, "", "")), 0L, "", PA), 0, "");
        batchOk(K3.verifyBatch(o("from", 0L, "records", l(r0), "head", h2), 0L, "", PA), 1, c0);
        String gap = "gap or replay: batch starts at ";
        batchBad(K3.verifyBatch(o("from", 1L, "records", l(r0), "head", h2), 0L, "", PA), gap + "1, expected 0");
        batchBad(K3.verifyBatch(o("records", l(r0), "head", h2), 0L, "", PA), gap + "undefined, expected 0");
        batchBad(K3.verifyBatch(o("from", "0", "records", l(r0), "head", h2), 0L, "", PA), gap + "undefined, expected 0");
        batchBad(K3.verifyBatch(o("from", num("0.5"), "records", l(r0), "head", h2), 0L, "", PA), gap + "0.5, expected 0");
        batchBad(K3.verifyBatch(o("from", 9007199254740991L, "records", l(r0), "head", h2), 0L, "", PA), gap + "9007199254740991, expected 0");
        batchBad(K3.verifyBatch(o("from", num("9007199254740993"), "records", l(r0), "head", h2), 0L, "", PA), gap + "9007199254740992, expected 0");
        batchBad(K3.verifyBatch(o("from", num("-9007199254740993"), "records", l(r0), "head", h2), 0L, "", PA), gap + "-9007199254740992, expected 0");
        batchBad(K3.verifyBatch(o("from", num("1e21"), "records", l(r0), "head", h2), 0L, "", PA), gap + "1e+21, expected 0");
        batchBad(K3.verifyBatch(o("from", 0L, "records", l(r0), "head", h2), 7L, "", PA), gap + "0, expected 7");
        batchBad(K3.verifyBatch(o("from", 0L, "records", l(r0), "head", h2), 0L, "", PB), "head not signed by the pinned log signer");
        batchBad(K3.verifyBatch(o("from", 0L, "records", l(r0), "head", "x"), 0L, "", PA), "head not signed by the pinned log signer");
        for (Object recs : new Object[] {"x", DEL, l("x"), l(r0, 5L)})
            batchBad(K3.verifyBatch(with(o("from", 0L, "head", h2), "records", recs), 0L, "", PA), "malformed batch");
        batchBad(K3.verifyBatch(o("from", 0L, "records", l(r1), "head", h2), 0L, "", PA), "chain broken at seq 1");
        batchBad(K3.verifyBatch(o("from", 0L, "records", l(o("v", 1L, "seq", 0L, "prev", "zz")), "head", h2), 0L, "", PA), "chain broken at seq 0");
        batchBad(K3.verifyBatch(o("from", 0L, "records", l(o("v", 1L, "prev", "")), "head", h2), 0L, "", PA), "chain broken at seq undefined");
        batchBad(K3.verifyBatch(o("from", 0L, "records", l(o("v", 1L, "seq", num("0.5"), "prev", "")), "head", h2), 0L, "", PA), "chain broken at seq 0.5");
        batchBad(K3.verifyBatch(o("from", 0L, "records", l(r0, with(r1, "prev", "zz")), "head", h2), 0L, "", PA), "chain broken at seq 1");
        batchBad(K3.verifyBatch(o("from", 0L, "records", l(o("v", 1L, "seq", 0L, "prev", "", "x", num("1e5"))), "head", head(5L, "root", "")), 0L, "", PA),
            "malformed batch");
        batchBad(K3.verifyBatch(o("from", 0L, "records", l(r0, r1), "head", head(1L, "root", c1)), 0L, "", PA), "batch is longer than the signed head");
        batchBad(K3.verifyBatch(o("from", 0L, "records", l(r0, r1), "head", head(2L, "root", c0)), 0L, "", PA), "batch end does not match the signed head");
        batchBad(K3.verifyBatch(o("from", 0L, "records", l(), "head", head(0L, "", "x")), 0L, "", PA), "batch end does not match the signed head");
        batchBad(K3.verifyBatch("x", 0L, "", PA), "malformed batch");
        batchBad(K3.verifyBatch(new Boom(), 0L, "", PA), "malformed batch");
    }

    // =================================================================================================================
    // list receipts and cursors
    // =================================================================================================================

    static Map<String, Object> receipt(Object... kv) {
        Map<String, Object> r = with(o("v", 1L, "signer", PA, "subject", "sub", "resource_type", "doc", "count", 2L, "issued_at", 5L,
            "objects_digest", hash(o("d", "atlas-pca/list-objects/v1", "o", l("a", "b")))), kv);
        r.put("sig", sign("a", K3.LIST_RECEIPT_DOMAIN, r));
        return r;
    }

    @Test void verifyListReceiptEveryCheck() {
        List<Object> objs = l("a", "b");
        assertEquals(hash(o("d", "atlas-pca/list-objects/v1", "o", objs)), K3.objectsDigest(objs));
        assertNull(K3.objectsDigest(l(num("1e5"))));
        assertTrue(K3.verifyListReceipt(receipt(), PA, null));
        assertTrue(K3.verifyListReceipt(receipt(), PA, objs));
        assertFalse(K3.verifyListReceipt(receipt(), PA, l("a")));
        assertFalse(K3.verifyListReceipt(receipt(), PA, l("b", "a")));
        assertFalse(K3.verifyListReceipt(receipt("count", 3L), PA, objs));
        assertTrue(K3.verifyListReceipt(receipt("count", 3L), PA, null));
        assertFalse(K3.verifyListReceipt(receipt("objects_digest", "x"), PA, objs));
        assertFalse(K3.verifyListReceipt(receipt(), null, null));
        assertFalse(K3.verifyListReceipt(receipt(), PB, null));
        assertFalse(K3.verifyListReceipt(receipt("signer", PB), PA, null));
        assertFalse(K3.verifyListReceipt("x", PA, null));
        for (Object v : new Object[] {2L, DEL}) assertFalse(K3.verifyListReceipt(receipt("v", v), PA, null));
        for (String k : new String[] {"subject", "resource_type"}) {
            assertTrue(K3.verifyListReceipt(receipt(k, rep('s', 512)), PA, null), k);
            for (Object v : new Object[] {"", rep('s', 513), 5L, DEL}) assertFalse(K3.verifyListReceipt(receipt(k, v), PA, null), k + " " + v);
        }
        for (String k : new String[] {"count", "issued_at"}) {
            assertTrue(K3.verifyListReceipt(receipt(k, 0L), PA, null), k);
            for (Object v : new Object[] {-1L, DEL, num("1.5")}) assertFalse(K3.verifyListReceipt(receipt(k, v), PA, null), k + " " + v);
        }
        assertTrue(K3.verifyListReceipt(receipt("count", 0L, "objects_digest", hash(o("d", "atlas-pca/list-objects/v1", "o", l()))), PA, l()));
        assertFalse(K3.verifyListReceipt(with(receipt(), "sig", receipt("count", 9L).get("sig")), PA, null));
        assertFalse(K3.verifyListReceipt(new Boom(), PA, null));
    }

    static final Map<String, Object> BIND = o("subject", "sub", "resourceType", "doc", "filterId", "f", "policyDigest", "pd", "relation", o("relation", "owner"), "limit", 10L);

    @Test void listBind() {
        assertEquals(hash(o("s", "sub", "t", "doc", "f", "f", "p", "pd", "r", "owner", "l", 10L)), K3.listBind(BIND));
        assertEquals(hash(o("s", "sub", "t", "doc", "f", "f", "p", "pd", "r", null, "l", 10L)), K3.listBind(with(BIND, "relation", DEL)));
        assertEquals(hash(o("s", "sub", "t", "doc", "f", "f", "p", "pd", "r", null, "l", 10L)), K3.listBind(with(BIND, "relation", "owner")));
        assertNull(K3.listBind(null));
        assertNull(K3.listBind(with(BIND, "limit", num("1e5"))));
    }

    static String payload(Map<String, Object> c) { return Pca.b64(canon(c).getBytes(StandardCharsets.UTF_8)); }
    static String cursor(Object... kv) {
        Map<String, Object> c = with(o("v", 1L, "bind", K3.listBind(BIND), "skip", 3L, "inner", "in", "signer", PA), kv);
        return payload(c) + "." + sign("a", K3.LIST_CURSOR_DOMAIN, c);
    }
    static void cursorOk(K3.CursorVerdict r, String inner, long skip) {
        assertTrue(r.ok, () -> r.reason);
        assertEquals(inner, r.inner);
        assertEquals(skip, r.skip);
        assertNull(r.reason);
    }
    static void cursorBad(K3.CursorVerdict r, String reason) {
        assertFalse(r.ok);
        assertEquals(reason, r.reason);
        assertNull(r.inner);
        assertEquals(0L, r.skip);
    }

    @Test void verifyListCursorEveryOutcome() {
        String tok = cursor();
        cursorOk(K3.verifyListCursor(tok, PA, BIND), "in", 3);
        cursorOk(K3.verifyListCursor(tok, PA, null), "in", 3);
        cursorOk(K3.verifyListCursor(cursor("inner", DEL, "skip", 0L), PA, BIND), null, 0);
        cursorBad(K3.verifyListCursor(tok, PA, with(BIND, "limit", 11L)), "bind");
        cursorBad(K3.verifyListCursor(5L, PA, null), "malformed");
        cursorBad(K3.verifyListCursor(tok + ".", PA, null), "malformed");
        cursorBad(K3.verifyListCursor(tok + ".x", PA, null), "malformed");
        String p = tok.substring(0, tok.indexOf('.')), s = tok.substring(tok.indexOf('.') + 1);
        cursorBad(K3.verifyListCursor(p, PA, null), "malformed");
        cursorBad(K3.verifyListCursor(p + ".", PA, null), "malformed");
        cursorBad(K3.verifyListCursor("." + s, PA, null), "malformed");
        cursorBad(K3.verifyListCursor("!!." + s, PA, null), "malformed");
        cursorBad(K3.verifyListCursor(Pca.b64("[1]".getBytes(StandardCharsets.UTF_8)) + "." + s, PA, null), "malformed");
        cursorBad(K3.verifyListCursor(Pca.b64("{".getBytes(StandardCharsets.UTF_8)) + "." + s, PA, null), "malformed");
        cursorBad(K3.verifyListCursor(cursor("v", 2L), PA, null), "malformed");
        cursorBad(K3.verifyListCursor(cursor("v", DEL), PA, null), "malformed");
        cursorBad(K3.verifyListCursor(cursor("bind", 5L), PA, null), "malformed");
        cursorBad(K3.verifyListCursor(cursor("bind", DEL), PA, null), "malformed");
        cursorBad(K3.verifyListCursor(cursor("skip", -1L), PA, null), "malformed");
        cursorBad(K3.verifyListCursor(cursor("skip", DEL), PA, null), "malformed");
        cursorBad(K3.verifyListCursor(cursor("inner", 5L), PA, null), "malformed");
        cursorBad(K3.verifyListCursor(cursor("inner", null), PA, null), "malformed");
        cursorBad(K3.verifyListCursor(tok, null, null), "signature");
        cursorBad(K3.verifyListCursor(tok, PB, null), "signature");
        cursorBad(K3.verifyListCursor(cursor("signer", PB), PA, null), "signature");
        cursorBad(K3.verifyListCursor(cursor("signer", DEL), PA, null), "signature");
        cursorBad(K3.verifyListCursor(p + "." + cursor("skip", 4L).substring(cursor("skip", 4L).indexOf('.') + 1), PA, null), "signature");
        cursorBad(K3.verifyListCursor(tok, PA, new Boom()), "malformed");
    }

    // =================================================================================================================
    // authority + grant management
    // =================================================================================================================

    static Map<String, Object> auth(Object verbs, Object resources, Object... kv) { return with(o("verbs", verbs, "resources", resources), kv); }
    static final Map<String, Object> X = auth(l("read"), l("doc/*"));

    @Test void compareAuthorityEveryOrder() {
        assertEquals("equal", K3.compareAuthority(X, X));
        assertEquals("narrower", K3.compareAuthority(X, auth(l("read"), l("doc/a"))));
        assertEquals("wider", K3.compareAuthority(X, auth(l("read", "write"), l("doc/*"))));
        assertEquals("narrower", K3.compareAuthority(auth(l("read", "write"), l("doc/*")), X));
        assertEquals("incomparable", K3.compareAuthority(auth(l("read"), l("doc/a")), auth(l("write"), l("doc/a"))));
        assertEquals("narrower", K3.compareAuthority(auth(l("r"), l("a/*")), auth(l("r"), l("a/b*"))));
        assertEquals("wider", K3.compareAuthority(auth(l("r"), l("a/b")), auth(l("r"), l("a/b*"))));
        assertEquals("narrower", K3.compareAuthority(auth(l("r"), l("a/b*")), auth(l("r"), l("a/b"))));
        assertEquals("incomparable", K3.compareAuthority(auth(l("r"), l("a/b")), auth(l("r"), l("a/c"))));
        assertEquals("equal", K3.compareAuthority(auth(l("r"), l("a/*")), auth(l("r"), l("a/*", "a/b"))));
        // ceilings
        assertEquals("narrower", K3.compareAuthority(auth(l("r"), l("x"), "limits", o("usd", 5L)), auth(l("r"), l("x"), "limits", o("usd", 3L))));
        assertEquals("wider", K3.compareAuthority(auth(l("r"), l("x"), "limits", o("usd", 5L)), auth(l("r"), l("x"), "limits", o("usd", 7L))));
        assertEquals("equal", K3.compareAuthority(auth(l("r"), l("x"), "limits", o("usd", 5L)), auth(l("r"), l("x"), "limits", o("usd", 5L))));
        assertEquals("narrower", K3.compareAuthority(auth(l("r"), l("x")), auth(l("r"), l("x"), "limits", o("usd", 5L))));
        assertEquals("wider", K3.compareAuthority(auth(l("r"), l("x"), "limits", o("usd", 5L)), auth(l("r"), l("x"))));
        assertEquals("incomparable", K3.compareAuthority(auth(l("r"), l("x"), "limits", o("usd", 5L)), auth(l("r"), l("x"), "limits", o("eur", 5L))));
        assertEquals("equal", K3.compareAuthority(auth(l("r"), l("x")), auth(l("r"), l("x"), "limits", o())));
        // expiry
        assertEquals("narrower", K3.compareAuthority(auth(l("r"), l("x")), auth(l("r"), l("x"), "expires_at", 10L)));
        assertEquals("wider", K3.compareAuthority(auth(l("r"), l("x"), "expires_at", 10L), auth(l("r"), l("x"), "expires_at", 20L)));
        assertEquals("narrower", K3.compareAuthority(auth(l("r"), l("x"), "expires_at", 20L), auth(l("r"), l("x"), "expires_at", 10L)));
        assertEquals("equal", K3.compareAuthority(auth(l("r"), l("x"), "expires_at", 10L), auth(l("r"), l("x"), "expires_at", 10L)));
        assertEquals("wider", K3.compareAuthority(auth(l("r"), l("x"), "expires_at", 10L), auth(l("r"), l("x"))));
    }

    static void wellFormed(Map<String, Object> a, boolean ok) {
        assertEquals(ok ? "equal" : "incomparable", K3.compareAuthority(a, a), String.valueOf(a));
    }

    @Test void authorityShapeBoundaries() {
        wellFormed(auth(strs("v", 256), l("x")), true);
        wellFormed(auth(strs("v", 257), l("x")), false);
        wellFormed(auth(l(rep('v', 128)), l("x")), true);
        wellFormed(auth(l(rep('v', 129)), l("x")), false);
        wellFormed(auth(l(""), l("x")), false);
        wellFormed(auth(l(5L), l("x")), false);
        wellFormed(auth(l("v"), strs("r", 1024)), true);
        wellFormed(auth(l("v"), strs("r", 1025)), false);
        wellFormed(auth(l("v"), l(rep('r', 512))), true);
        wellFormed(auth(l("v"), l(rep('r', 513))), false);
        wellFormed(auth("v", l("x")), false);
        wellFormed(auth(l("v"), "x"), false);
        wellFormed(without(auth(l("v"), l("x")), "verbs"), false);
        wellFormed(without(auth(l("v"), l("x")), "resources"), false);
        for (Object lim : new Object[] {o("a", 0L), o("a", num("0.5")), o("a", 5L), o()}) wellFormed(auth(l("v"), l("x"), "limits", lim), true);
        for (Object lim : new Object[] {"x", null, o("a", "1"), o("a", -1L), o("a", num("-0.5")), o("a", num("1e999")), o("a", num("NaN")), o("a", null)})
            wellFormed(auth(l("v"), l("x"), "limits", lim), false);
        for (Object e : new Object[] {0L, 10L}) wellFormed(auth(l("v"), l("x"), "expires_at", e), true);
        for (Object e : new Object[] {-1L, "1", num("1.5"), null}) wellFormed(auth(l("v"), l("x"), "expires_at", e), false);
        assertEquals("incomparable", K3.compareAuthority("x", X));
        assertEquals("incomparable", K3.compareAuthority(X, null));
        assertEquals("incomparable", K3.compareAuthority(new Boom(), X));
        assertEquals("incomparable", K3.compareAuthority(X, new Boom()));
    }

    @Test void authorityDigestSortsByUtf8() {
        Map<String, Object> a = auth(l("b", "a"), l("z", "y"), "limits", o("x", 1L));
        assertEquals(hash(o("d", "atlas-pca/authority/v1", "a", o("verbs", l("a", "b"), "resources", l("y", "z"), "limits", o("x", 1L)))), K3.authorityDigest(a));
        assertEquals(l("b", "a"), a.get("verbs")); // the input is not reordered
        String hi = "￿", astral = "😀"; // UTF-16 order puts the astral first, UTF-8 order puts U+FFFF first
        assertEquals(hash(o("d", "atlas-pca/authority/v1", "a", o("verbs", l(hi, astral), "resources", l(hi, astral)))),
            K3.authorityDigest(auth(l(astral, hi), l(astral, hi))));
        assertNull(K3.authorityDigest(auth(l(5L), l("x"))));
        assertNull(K3.authorityDigest(auth(l("v"), l(5L))));
        assertNull(K3.authorityDigest(auth("v", l("x"))));
        assertNull(K3.authorityDigest(auth(l("v"), "x")));
        assertNull(K3.authorityDigest(without(auth(l("v"), l("x")), "resources")));
        assertNull(K3.authorityDigest(without(auth(l("v"), l("x")), "verbs")));
        assertNull(K3.authorityDigest("x"));
        assertNull(K3.authorityDigest(new Boom()));
        assertNull(K3.authorityDigest(auth(l("v"), l("x"), "limits", o("a", num("1e5")))));
    }

    // ---- amendments ----

    static final Map<String, Object> AUTH = auth(l("read", "write"), l("doc/*"), "limits", o("usd", 100L), "expires_at", 1000L);
    static Map<String, Object> grant(Object... kv) { return with(o("id", "g1", "rev", 3L, "principal", PP, "agent", PG, "status", "active", "authority", AUTH), kv); }
    static Map<String, Object> amend(String action, Object authority, String by, String label) {
        Map<String, Object> msg = o("grant", "g1", "rev", 3L, "action", action, "authority", K3.authorityDigest(authority));
        return o("action", action, "authority", authority, "signed_by", by, "sig", sign(label, K3.GRANT_AMEND_DOMAIN, msg));
    }
    static void amendOk(K3.AmendVerdict r, boolean widens, Object next) {
        assertTrue(r.ok, () -> r.code);
        assertNull(r.code);
        assertEquals(widens, r.widens);
        assertEquals(canon(next), canon(r.next));
    }
    static void amendFail(K3.AmendVerdict r, String code) {
        assertFalse(r.ok);
        assertEquals(code, r.code);
        assertFalse(r.widens);
        assertNull(r.next);
    }

    @Test void verifyAmendmentEveryOutcome() {
        Map<String, Object> narrow = auth(l("read"), l("doc/a"), "limits", o("usd", 50L), "expires_at", 500L);
        Map<String, Object> wider = auth(l("read", "write", "admin"), l("doc/*"), "limits", o("usd", 100L), "expires_at", 1000L);
        Map<String, Object> incomparable = auth(l("admin"), l("doc/*"), "limits", o("usd", 100L), "expires_at", 1000L);
        amendOk(K3.verifyAmendment(grant(), amend("narrow", narrow, "holder", "agent"), false), false, narrow);
        amendOk(K3.verifyAmendment(grant(), amend("narrow", narrow, "principal", "principal"), false), false, narrow);
        amendFail(K3.verifyAmendment(grant(), amend("narrow", AUTH, "holder", "agent"), true), "not_narrower");
        amendFail(K3.verifyAmendment(grant(), amend("narrow", wider, "principal", "principal"), true), "not_narrower");
        amendFail(K3.verifyAmendment(grant(), amend("narrow", incomparable, "principal", "principal"), true), "not_narrower");
        amendOk(K3.verifyAmendment(grant(), amend("replace", AUTH, "holder", "agent"), false), false, AUTH);
        amendOk(K3.verifyAmendment(grant(), amend("replace", narrow, "holder", "agent"), false), false, narrow);
        amendOk(K3.verifyAmendment(grant(), amend("replace", wider, "principal", "principal"), true), true, wider);
        amendOk(K3.verifyAmendment(grant(), amend("replace", incomparable, "principal", "principal"), true), true, incomparable);
        amendFail(K3.verifyAmendment(grant(), amend("replace", wider, "principal", "principal"), false), "step_up_required");
        amendFail(K3.verifyAmendment(grant(), amend("replace", wider, "holder", "agent"), true), "signature_required");
        amendFail(K3.verifyAmendment(grant(), amend("replace", wider, "holder", "principal"), true), "signature_required");
        // merge: union; a ceiling or expiry only rises; one the grant lacks is not added
        Map<String, Object> delta = auth(l("admin"), l("img/*"), "limits", o("usd", 200L, "eur", 5L), "expires_at", 2000L);
        amendOk(K3.verifyAmendment(grant(), amend("merge", delta, "principal", "principal"), true), true,
            auth(l("read", "write", "admin"), l("doc/*", "img/*"), "limits", o("usd", 200L), "expires_at", 2000L));
        Map<String, Object> lower = auth(l("read"), l("doc/*"), "limits", o("usd", 50L), "expires_at", 500L);
        amendOk(K3.verifyAmendment(grant(), amend("merge", lower, "holder", "agent"), false), false, AUTH);
        amendOk(K3.verifyAmendment(grant(), amend("merge", auth(l("read"), l("doc/*")), "holder", "agent"), false), false, AUTH);
        Map<String, Object> bare = grant("authority", auth(l("read"), l("doc/*")));
        Map<String, Object> rich = auth(l("read"), l("doc/*"), "limits", o("usd", 5L), "expires_at", 9L);
        K3.AmendVerdict m = K3.verifyAmendment(bare, amend("merge", rich, "holder", "agent"), false);
        amendOk(m, false, auth(l("read"), l("doc/*")));
        assertFalse(m.next.containsKey("limits"));
        assertFalse(m.next.containsKey("expires_at"));
        // an equal delta keeps the grant's own value objects
        Json.Num usd = num("100"), exp = num("1000");
        Map<String, Object> own = grant("authority", auth(l("read", "write"), l("doc/*"), "limits", o("usd", usd), "expires_at", exp));
        K3.AmendVerdict same = K3.verifyAmendment(own, amend("merge", auth(l("read"), l("doc/*"), "limits", o("usd", num("100")), "expires_at", num("1000")), "holder", "agent"), false);
        amendOk(same, false, AUTH);
        assertSame(usd, ((Map<?, ?>) same.next.get("limits")).get("usd"));
        assertSame(exp, same.next.get("expires_at"));
        // bad_request
        amendFail(K3.verifyAmendment(grant(), "x", true), "bad_request");
        amendFail(K3.verifyAmendment(grant(), with(amend("narrow", narrow, "holder", "agent"), "action", "x"), true), "bad_request");
        amendFail(K3.verifyAmendment(grant(), with(amend("narrow", narrow, "holder", "agent"), "action", DEL), true), "bad_request");
        amendFail(K3.verifyAmendment(grant(), amend("narrow", auth("x", l("doc/a")), "holder", "agent"), true), "bad_request");
        amendFail(K3.verifyAmendment(grant(), with(amend("narrow", narrow, "holder", "agent"), "authority", DEL), true), "bad_request");
        amendFail(K3.verifyAmendment("x", amend("narrow", narrow, "holder", "agent"), true), "bad_request");
        amendFail(K3.verifyAmendment(grant("authority", "x"), amend("narrow", narrow, "holder", "agent"), true), "bad_request");
        amendFail(K3.verifyAmendment(grant("status", "revoked", "authority", "x"), amend("narrow", narrow, "holder", "agent"), true), "bad_request");
        amendFail(K3.verifyAmendment(grant("status", "revoked"), amend("narrow", auth("x", l("a")), "holder", "agent"), true), "bad_request");
        amendFail(K3.verifyAmendment(grant(), new Boom(), true), "bad_request");
        amendFail(K3.verifyAmendment(new Boom(), amend("narrow", narrow, "holder", "agent"), true), "bad_request");
        // not_active
        amendFail(K3.verifyAmendment(grant("status", "revoked"), amend("narrow", narrow, "holder", "agent"), true), "not_active");
        amendFail(K3.verifyAmendment(grant("status", DEL), amend("narrow", narrow, "holder", "agent"), true), "not_active");
        // signature
        amendFail(K3.verifyAmendment(grant(), with(amend("narrow", narrow, "holder", "agent"), "sig", DEL), true), "signature_required");
        amendFail(K3.verifyAmendment(grant(), with(amend("narrow", narrow, "holder", "agent"), "sig", 5L), true), "signature_required");
        amendFail(K3.verifyAmendment(grant(), with(amend("narrow", narrow, "holder", "agent"), "signed_by", DEL), true), "signature_required");
        amendFail(K3.verifyAmendment(grant(), with(amend("narrow", narrow, "holder", "agent"), "signed_by", "admin"), true), "signature_required");
        amendFail(K3.verifyAmendment(grant(), amend("narrow", narrow, "holder", "principal"), true), "bad_signature");
        amendFail(K3.verifyAmendment(grant(), amend("narrow", narrow, "principal", "agent"), true), "bad_signature");
        amendFail(K3.verifyAmendment(grant("agent", 5L), amend("narrow", narrow, "holder", "agent"), true), "bad_signature");
        amendFail(K3.verifyAmendment(grant("principal", 5L), amend("narrow", narrow, "principal", "principal"), true), "bad_signature");
        amendFail(K3.verifyAmendment(grant("rev", 4L), amend("narrow", narrow, "holder", "agent"), true), "bad_signature");
        amendFail(K3.verifyAmendment(grant("id", "g2"), amend("narrow", narrow, "holder", "agent"), true), "bad_signature");
        amendFail(K3.verifyAmendment(grant(), with(amend("narrow", narrow, "holder", "agent"), "action", "replace"), true), "bad_signature");
    }

    // ---- revocation ----

    static String revokeSig(String label, Object id, Object scope) { return sign(label, K3.GRANT_REVOKE_DOMAIN, o("grant", id, "scope", scope)); }

    @Test void verifyRevokeSignatureEveryOutcome() {
        Map<String, Object> root = o("id", "g1", "principal", PP);
        for (String s : new String[] {"grant", "agent", "subtree"}) {
            K3.RevokeVerdict r = K3.verifyRevokeSignature(root, s, revokeSig("principal", "g1", s));
            assertTrue(r.ok, s);
            assertEquals(s, r.scope);
            assertNull(r.code);
        }
        Object[][] bad = {
            {root, "all", revokeSig("principal", "g1", "all"), "bad_request"},
            {root, 5L, revokeSig("principal", "g1", 5L), "bad_request"},
            {root, null, "x", "bad_request"},
            {"x", "grant", revokeSig("principal", null, "grant"), "bad_signature"},
            {with(root, "principal", 5L), "grant", revokeSig("principal", "g1", "grant"), "bad_signature"},
            {root, "grant", revokeSig("principal", "g1", "agent"), "bad_signature"},
            {root, "grant", revokeSig("agent", "g1", "grant"), "bad_signature"},
            {with(root, "id", "g2"), "grant", revokeSig("principal", "g1", "grant"), "bad_signature"},
            {new Boom(), "grant", "x", "bad_request"},
        };
        for (Object[] c : bad) {
            K3.RevokeVerdict r = K3.verifyRevokeSignature(c[0], c[1], c[2]);
            assertFalse(r.ok, String.valueOf(c[3]));
            assertNull(r.scope);
            assertEquals(c[3], r.code);
        }
    }

    // ---- needs approval ----

    static final Map<String, Object> GN_AUTH = auth(l("read"), l("doc/*"), "limits", o("usd", 10L));
    static Map<String, Object> need(Object... kv) { return with(o("verb", "pay", "resource", "acct/1", "limits", o("usd", 50L)), kv); }
    static Map<String, Object> nreq(Object needs, Object... kv) { return with(o("id", "n1", "grant_id", "g1", "status", "pending", "needs", needs), kv); }
    static Map<String, Object> ngrant(Object... kv) { return with(grant("authority", GN_AUTH), kv); }
    static String needSig(String label, Object approved) { return sign(label, K3.NEED_APPROVE_DOMAIN, o("need", "n1", "grant", "g1", "rev", 3L, "approved", approved)); }
    static K3.NeedVerdict approve(Object nr, Object g, Object approved, boolean stepUp) { return K3.verifyNeedApproval(nr, g, approved, needSig("principal", approved), stepUp); }
    static void needOk(K3.NeedVerdict r, Object authority) {
        assertTrue(r.ok, () -> r.code);
        assertNull(r.code);
        assertEquals(canon(authority), canon(r.authority));
    }
    static void needFail(K3.NeedVerdict r, String code) {
        assertFalse(r.ok);
        assertEquals(code, r.code);
        assertNull(r.authority);
    }

    @Test void verifyNeedApprovalEveryOutcome() {
        Map<String, Object> nr = nreq(l(need()));
        Map<String, Object> g = ngrant();
        Map<String, Object> raised = auth(l("read", "pay"), l("doc/*", "acct/1"), "limits", o("usd", 50L));
        needOk(approve(nr, g, l(need()), true), raised);
        needOk(approve(nr, g, l(need("adjustable", true)), true), raised);
        needFail(approve(nr, g, l(need("limits", o("usd", 40L))), true), "need_not_adjustable");
        needFail(approve(nreq(l(need("adjustable", false))), g, l(need("limits", o("usd", 40L))), true), "need_not_adjustable");
        needFail(approve(nreq(l(need("adjustable", 0L))), g, l(need("limits", o("usd", 40L))), true), "need_not_adjustable");
        needOk(approve(nreq(l(need("adjustable", true))), g, l(need("limits", o("usd", 40L))), true), auth(l("read", "pay"), l("doc/*", "acct/1"), "limits", o("usd", 40L)));
        needOk(approve(nreq(l(need("adjustable", "yes"))), g, l(need("limits", o("usd", 5L))), true), auth(l("read", "pay"), l("doc/*", "acct/1"), "limits", o("usd", 10L)));
        needFail(approve(nr, g, l(need("limits", o("usd", 60L))), true), "need_not_lowered_only");
        needFail(approve(nreq(l(need("limits", DEL))), g, l(need()), true), "need_not_lowered_only");
        needFail(approve(nr, g, l(need("limits", o("eur", 5L))), true), "need_not_lowered_only");
        needFail(approve(nr, g, l(need("limits", "x")), true), "need_not_lowered_only");
        needFail(approve(nr, g, l(need("limits", o("usd", "5"))), true), "need_not_lowered_only");
        needFail(approve(nreq(l(need("limits", o("usd", "50")))), g, l(need()), true), "need_not_lowered_only");
        needOk(approve(nr, g, l(need("limits", null)), true), auth(l("read", "pay"), l("doc/*", "acct/1"), "limits", o("usd", 10L)));
        needOk(approve(nr, g, l(need("limits", DEL)), true), auth(l("read", "pay"), l("doc/*", "acct/1"), "limits", o("usd", 10L)));
        for (Object[] kv : new Object[][] {{"verb", "refund"}, {"resource", "acct/2"}, {"verb", 5L}, {"resource", 5L}, {"verb", DEL}, {"resource", DEL}})
            needFail(approve(nr, g, l(need(kv[0], kv[1])), true), "need_not_lowered_only");
        needFail(approve(nreq(l(need("verb", 5L))), g, l(need("verb", 5L)), true), "need_not_lowered_only");
        needFail(approve(nr, g, l("x"), true), "need_not_lowered_only");
        needFail(approve(nreq(l("x")), g, l(need()), true), "need_not_lowered_only");
        needFail(approve(nr, g, "x", true), "need_not_lowered_only");
        needFail(approve(nr, g, l(), true), "need_not_lowered_only");
        needFail(approve(nr, g, l(need(), need()), true), "need_not_lowered_only");
        needFail(approve(nreq("x"), g, l(need()), true), "need_not_lowered_only");
        needFail(approve(nreq(l(need()), "status", "approved"), g, l(need()), true), "conflict");
        needFail(approve(nreq(l(need()), "status", DEL), g, l(need()), true), "conflict");
        needFail(approve(nr, "x", l(need()), true), "bad_request");
        needFail(approve("x", g, l(need()), true), "bad_request");
        needFail(approve(nreq(l(need()), "status", "approved"), "x", l(need()), true), "bad_request");
        needFail(approve(new Boom(), g, l(need()), true), "bad_request");
        needFail(approve(nr, ngrant("authority", "x"), l(need()), true), "bad_request");
        needFail(approve(nr, ngrant("authority", auth("x", l("a"))), l(need()), true), "bad_request");
        needFail(approve(nr, ngrant("principal", 5L), l(need()), true), "bad_signature");
        needFail(K3.verifyNeedApproval(nr, g, l(need()), needSig("agent", l(need())), true), "bad_signature");
        needFail(K3.verifyNeedApproval(nr, g, l(need()), needSig("principal", l(need("limits", o("usd", 49L)))), true), "bad_signature");
        needFail(approve(nr, ngrant("rev", 4L), l(need()), true), "bad_signature");
        needFail(approve(nr, g, l(need()), false), "step_up_required");
        // fractional raise above a zero ceiling
        needOk(approve(nreq(l(need("limits", o("usd", 1L), "adjustable", true))), ngrant("authority", auth(l("read"), l("doc/*"), "limits", o("usd", 0L))),
            l(need("limits", o("usd", num("0.5")))), true), auth(l("read", "pay"), l("doc/*", "acct/1"), "limits", o("usd", num("0.5"))));
        // two approvals of one ceiling: the larger wins, in either order; an equal later one keeps the first value object
        Map<String, Object> two = nreq(l(need("adjustable", true), need("resource", "acct/2", "adjustable", true)));
        Map<String, Object> raised2 = auth(l("read", "pay"), l("doc/*", "acct/1", "acct/2"), "limits", o("usd", 50L));
        needOk(approve(two, g, l(need(), need("resource", "acct/2", "limits", o("usd", 30L))), true), raised2);
        needOk(approve(two, g, l(need("limits", o("usd", 30L)), need("resource", "acct/2")), true), raised2);
        Json.Num first = num("50");
        K3.NeedVerdict eq = approve(two, g, l(need("limits", o("usd", first)), need("resource", "acct/2", "limits", o("usd", num("50")))), true);
        needOk(eq, raised2);
        assertSame(first, ((Map<?, ?>) eq.authority.get("limits")).get("usd"));
        // a grant without ceilings gains none
        needOk(approve(nr, ngrant("authority", auth(l("read"), l("doc/*"))), l(need()), true), auth(l("read", "pay"), l("doc/*", "acct/1")));
        assertFalse(approve(nr, ngrant("authority", auth(l("read"), l("doc/*"))), l(need()), true).authority.containsKey("limits"));
        // a grant expiry is kept
        needOk(approve(nr, ngrant("authority", auth(l("read"), l("doc/*"), "expires_at", 77L)), l(need()), true),
            auth(l("read", "pay"), l("doc/*", "acct/1"), "expires_at", 77L));
    }
}
