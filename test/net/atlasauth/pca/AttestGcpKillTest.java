package net.atlasauth.pca;

import static net.atlasauth.pca.AttestMaaTest.BINDING;
import static net.atlasauth.pca.AttestMaaTest.NOW;
import static net.atlasauth.pca.AttestMaaTest.assertDenied;
import static net.atlasauth.pca.AttestMaaTest.b64u;
import static net.atlasauth.pca.AttestMaaTest.cfg;
import static net.atlasauth.pca.AttestMaaTest.constructError;
import static net.atlasauth.pca.AttestMaaTest.json;
import static net.atlasauth.pca.AttestMaaTest.obj;
import static net.atlasauth.pca.AttestMaaTest.rawBinding;
import static net.atlasauth.pca.AttestMaaTest.run;
import static net.atlasauth.pca.AttestMaaTest.signEs256;
import static net.atlasauth.pca.AttestMaaTest.unsignedJwt;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

/**
 * Google Confidential Space, exact outcomes the mutation run left open: the constructor's anchor arithmetic and type
 * guards, the JWK key-reader table, kid selection, the trusted-JWKS / SPKI / x5c anchoring paths, the x5c chain table,
 * second-resolution time and skew edges, swname / swversion / eat_nonce shapes and the optional image_reference.
 */
public class AttestGcpKillTest {
    static final String V = "gcp-confidential-space";
    static final String ISSUER = AttestGcpTest.ISSUER;
    static final String POLICY = "{\"imageDigests\":[\"sha256:abc\"]}";
    static final String NO_KID = "Confidential Space signing key invalid: no kid on the token and no unambiguous single signing key available";
    static final String NEITHER = "Confidential Space signing key invalid: JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate";
    static final String UNSUPPORTED = "Confidential Space signing key invalid: JWKS key is not a usable public key: error:1E08010C:DECODER routines::unsupported";
    static final String NOT_ANCHORED = "Confidential Space signing key invalid: signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)";
    static final String NOT_TRUSTED = "Confidential Space signing key invalid: signing key not trusted: ";

    private final KeyPair key = AttestTestDer.ecKey("secp256r1");
    private final KeyPair other = AttestTestDer.ecKey("secp256r1");
    private final KeyPair root = AttestTestDer.ecKey("secp256r1");
    private final byte[] rootDer = AttestTestDer.cert("root", "root", root, root, AttestTestDer.basicConstraints(true, -1));
    private final byte[] leafDer = AttestTestDer.cert("leaf", "root", key, root);

    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    static String spki(KeyPair kp) { return AttestCommon.toHexLower(AttestCommon.sha256Sum(kp.getPublic().getEncoded())); }

    static String b64(byte[] der) { return Base64.getEncoder().encodeToString(der); }

    static String pemCert(byte[] der) { return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(der) + "\n-----END CERTIFICATE-----\n"; }

    /** A configuration with these trust anchors and policy. */
    static Map<String, Object> config(Map<String, Object> anchors, String policy) {
        Map<String, Object> c = cfg("{\"trustedIssuers\":[\"" + ISSUER + "\"],\"policy\":" + policy + "}");
        c.put("trustAnchors", anchors);
        return c;
    }

    static Map<String, Object> pins(String... hex) { return obj("trustedKeySpki", list((Object[]) hex)); }

    static Map<String, Object> jwks(Object... keys) { return obj("trustedJwks", obj("keys", list(keys))); }

    static String claims(Consumer<Map<String, Object>> mut) {
        long nowSec = NOW / 1000;
        Map<String, Object> m = obj("iss", ISSUER, "exp", nowSec + 3600, "iat", nowSec - 60, "nbf", nowSec - 60,
            "swname", "CONFIDENTIAL_SPACE", "swversion", list("240500"), "hwmodel", "GCP_INTEL_TDX", "dbgstat", "disabled-since-boot",
            "eat_nonce", list(Base64.getEncoder().encodeToString(rawBinding(BINDING))),
            "submods", obj("confidential_space", obj(), "container", obj("image_digest", "sha256:abc", "image_reference", "r/i@sha256:abc")));
        if (mut != null) mut.accept(m);
        return json(m);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> container(Map<String, Object> m) {
        return (Map<String, Object>) ((Map<String, Object>) m.get("submods")).get("container");
    }

    private Map<String, Object> trusted() { return config(jwks(AttestGcpTest.jwkOf(key, "k1")), POLICY); }

    private String tok(Consumer<Map<String, Object>> mut) { return signEs256(key, "{\"alg\":\"ES256\",\"kid\":\"k1\"}", claims(mut)); }

    private HardwareResult gcp(Map<String, Object> config, String token, long now) { return run(V, config, obj("token", token), BINDING, now); }

    private static void assertOk(String name, HardwareResult r) {
        assertEquals("", r.reason, name);
        assertTrue(r.ok && r.bound, name);
    }

    // ------------------------------------------------------------- construction

    @Test
    void constructionGuards() {
        assertEquals("createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string", constructError(V, "{\"trustedIssuers\":[\"\"]}"));
        assertEquals("createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string", constructError(V, "{\"trustedIssuers\":[\"https://i\",\"\"]}"));
        // a string trustedKeySpki counts by its length (listLen) and pins nothing
        assertNull(constructError(V, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"trustedKeySpki\":\"aa\"},\"policy\":" + POLICY + "}"));
        // the anchor count is a sum: one JWKS key + one pin, one pin + one root
        assertNull(constructError(V, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"trustedJwks\":{\"keys\":[{}]},\"trustedKeySpki\":[\"aa\"]},\"policy\":" + POLICY + "}"));
        assertNull(constructError(V, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"trustedKeySpki\":[\"aa\"],\"rootCertsPem\":[\"x\"]},\"policy\":" + POLICY + "}"));
        // trustedJwks.keys that is not a list adds no key
        assertEquals("createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted",
            constructError(V, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"trustedJwks\":{\"keys\":\"x\"}},\"policy\":" + POLICY + "}"));
        // a non-string nonceHash is ignored (the raw binding is expected)
        Map<String, Object> c = config(jwks(AttestGcpTest.jwkOf(key, "k1")), "{\"imageDigests\":[\"sha256:abc\"],\"nonceHash\":5}");
        assertOk("non-string nonceHash", gcp(c, tok(null), NOW));
        Map<String, Object> unknown = config(jwks(AttestGcpTest.jwkOf(key, "k1")), "{\"imageDigests\":[\"sha256:abc\"],\"nonceHash\":\"md5\"}");
        assertOk("unknown nonceHash mode", gcp(unknown, tok(null), NOW));
    }

    // ------------------------------------------------------------- the JWK key reader

    @Test
    void jwkKeyTable() throws Exception {
        Map<String, Object> c = config(pins("aa"), POLICY);
        String unsigned = unsignedJwt("{\"alg\":\"ES256\",\"kid\":\"k1\"}", "{}");
        Map<String, Object> good = AttestGcpTest.jwkOf(key, "k1");
        Object x = good.get("x"), y = good.get("y");
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        RSAPublicKey rsa = (RSAPublicKey) g.generateKeyPair().getPublic();
        String n = b64u(rsa.getModulus().toByteArray()), e = b64u(rsa.getPublicExponent().toByteArray());
        Object[][] rows = {
            {obj("kid", "k1", "n", n), NEITHER},
            {obj("kid", "k1", "e", e), NEITHER},
            {obj("kid", "k1", "n", n, "e", 5L), NEITHER},
            {obj("kid", "k1", "n", "", "e", e), UNSUPPORTED},
            {obj("kid", "k1", "n", n, "e", "AQ"), UNSUPPORTED},
            {obj("kid", "k1", "kty", "EC", "crv", "P-256", "x", x), NEITHER},
            {obj("kid", "k1", "kty", "EC", "crv", "P-256", "y", y), NEITHER},
            {obj("kid", "k1", "kty", "EC", "x", x, "y", y), NEITHER},
            {obj("kid", "k1", "kty", "EC", "crv", 5L, "x", x, "y", y), NEITHER},
            {obj("kid", "k1", "kty", "EC", "crv", "P-256", "x", x, "y", 5L), NEITHER},
            {obj("kid", "k1", "kty", "OKP", "crv", "P-256", "x", x, "y", y), NEITHER},
            {obj("kid", "k1", "crv", "P-256", "x", x, "y", y), NEITHER},
            {obj("kid", "k1", "kty", "EC", "crv", "P-256", "x", "AA", "y", "AA"), UNSUPPORTED},
            {obj("kid", "k1", "kty", "EC", "crv", "P-999", "x", x, "y", y), UNSUPPORTED},
            {obj("kid", "k1", "x5c", list()), NEITHER},
            {obj("kid", "k1", "x5c", list(5L)), NEITHER},
            {obj("kid", "k1", "x5c", "MAA="), NEITHER},
            {obj("kid", "k1", "x5c", list("MAA=")), "Confidential Space signing key invalid: JWKS key is not a usable public key: error:0680007B:asn1 encoding routines::not enough data"},
            // a usable RSA key that is not anchored
            {obj("kid", "k1", "n", n, "e", e), NOT_ANCHORED},
            // a usable RSA key with an empty x5c: the chain is not consulted
            {obj("kid", "k1", "n", n, "e", e, "x5c", list()), NOT_ANCHORED},
        };
        for (Object[] row : rows) {
            HardwareResult r = run(V, c, obj("token", unsigned, "jwks", obj("keys", list(row[0]))), BINDING, NOW);
            assertDenied(json(row[0]), r, (String) row[1]);
        }
        // evidence keys that are not a list hold no key
        assertDenied("keys not a list", run(V, c, obj("token", unsigned, "jwks", obj("keys", "x")), BINDING, NOW),
            "Confidential Space signing key invalid: no JWKS key matches the token kid 'k1' (untrusted signer)");
    }

    // ------------------------------------------------------------- kid selection and anchoring

    @Test
    void keySelectionAndAnchoring() {
        // an empty kid is no kid: the sole trusted key signs
        assertOk("empty kid, sole trusted key", gcp(trusted(), signEs256(key, "{\"alg\":\"ES256\",\"kid\":\"\"}", claims(null)), NOW));
        assertDenied("empty kid, no key", gcp(config(pins("aa"), POLICY), signEs256(key, "{\"alg\":\"ES256\",\"kid\":\"\"}", claims(null)), NOW), NO_KID);
        // kid lookup skips non-object members and keys with another kid
        Map<String, Object> pinned = config(pins(spki(key).toUpperCase()), POLICY);
        Map<String, Object> ev = obj("token", tok(null), "jwks", obj("keys", list(5L, AttestGcpTest.jwkOf(other, "x"), AttestGcpTest.jwkOf(key, "k1"))));
        assertOk("kid among several keys", run(V, pinned, ev, BINDING, NOW));
        // an evidence key anchored by an equal pinned JWKS key (a non-object JWKS member is skipped)
        Map<String, Object> viaTrusted = config(jwks(5L, AttestGcpTest.jwkOf(key, "renamed")), POLICY);
        Map<String, Object> evKey = obj("token", tok(null), "jwks", obj("keys", list(AttestGcpTest.jwkOf(key, "k1"))));
        assertOk("anchored through an equal trusted key", run(V, viaTrusted, evKey, BINDING, NOW));
        assertDenied("trusted key differs", run(V, config(jwks(AttestGcpTest.jwkOf(other, "o")), POLICY), evKey, BINDING, NOW), NOT_ANCHORED);
        // the header x5c is used only when no JWKS key was picked
        String otherLeaf = b64(AttestTestDer.cert("o", "root", other, root));
        assertOk("kid wins over the header x5c", gcp(trusted(), signEs256(key, "{\"alg\":\"ES256\",\"kid\":\"k1\",\"x5c\":[\"" + otherLeaf + "\"]}", claims(null)), NOW));
        assertDenied("empty header x5c", gcp(config(pins("aa"), POLICY), signEs256(key, "{\"alg\":\"ES256\",\"x5c\":[]}", claims(null)), NOW), NO_KID);
        // an x5c key with neither a pin nor a root configured is not chain-checked
        String leafHdr = "{\"alg\":\"ES256\",\"kid\":\"zz\",\"x5c\":[\"" + b64(leafDer) + "\"]}";
        assertDenied("x5c without pins or roots", gcp(config(jwks(AttestGcpTest.jwkOf(other, "o")), POLICY), signEs256(key, leafHdr, claims(null)), NOW), NOT_ANCHORED);
        // pins only (no rootCertsPem): the chain is checked against the pins, and no root is tried
        assertDenied("pins only, chain unpinned", gcp(config(pins("aa"), POLICY), signEs256(key, leafHdr, claims(null)), NOW),
            NOT_TRUSTED + "x5c chain does not anchor in a configured GCP trust root");
    }

    // ------------------------------------------------------------- the x5c chain

    private String x5cTok(Object... chain) {
        List<String> parts = new ArrayList<>();
        for (Object c : chain) parts.add(json(c));
        return signEs256(key, "{\"alg\":\"ES256\",\"x5c\":[" + String.join(",", parts) + "]}", claims(null));
    }

    @Test
    void x5cChainTable() {
        Map<String, Object> rootPinned = config(pins(spki(root)), POLICY);
        assertOk("leaf + pinned root", gcp(rootPinned, x5cTok(b64(leafDer), b64(rootDer)), NOW));
        byte[] strangerLeaf = AttestTestDer.cert("leaf", "root", key, other);
        assertDenied("bad link", gcp(rootPinned, x5cTok(b64(strangerLeaf), b64(rootDer)), NOW), NOT_TRUSTED + "x5c link 0 is not signed by the certificate above it");
        assertDenied("empty entry", gcp(rootPinned, x5cTok(b64(leafDer), ""), NOW), NOT_TRUSTED + "empty x5c entry at index 1");
        assertDenied("malformed entry", gcp(rootPinned, x5cTok(b64(leafDer), "MAA="), NOW),
            NOT_TRUSTED + "malformed x5c certificate at index 1: error:0680007B:asn1 encoding routines::not enough data");
        byte[] old = AttestTestDer.certWithValidity("leaf", "root", "200101000000Z", "210101000000Z", key, root);
        assertDenied("expired leaf", gcp(rootPinned, x5cTok(b64(old)), NOW), NOT_TRUSTED + "x5c certificate at index 0 is outside its validity window");
        // a non-string entry (only a JWKS member can carry one)
        Map<String, Object> ev = obj("token", tok(null), "jwks", obj("keys", list(obj("kid", "k1", "x5c", list(b64(leafDer), 5L)))));
        assertDenied("non-string entry", run(V, rootPinned, ev, BINDING, NOW), NOT_TRUSTED + "empty x5c entry at index 1");
        // an unreadable root entry is skipped; the next root anchors the chain
        Map<String, Object> roots = config(obj("rootCertsPem", list("not pem", pemCert(rootDer))), POLICY);
        assertOk("second root anchors", gcp(roots, x5cTok(b64(leafDer)), NOW));
        assertDenied("only an unreadable root", gcp(config(obj("rootCertsPem", list("not pem")), POLICY), x5cTok(b64(leafDer)), NOW),
            NOT_TRUSTED + "x5c chain does not anchor in a configured GCP trust root");
        // rootKeyFromPem: a PEM block that is not base64 or not a key
        assertNull(AttestGcp.rootKeyFromPem("-----BEGIN PUBLIC KEY-----\n@@@@\n-----END PUBLIC KEY-----\n"));
        assertNull(AttestGcp.rootKeyFromPem("-----BEGIN PUBLIC KEY-----\nMAA=\n-----END PUBLIC KEY-----\n"));
        assertEquals(spki(root), AttestGcp.rootKeyFromPem(pemCert(rootDer)).spkiSha256());
    }

    // ------------------------------------------------------------- claims

    private Map<String, Object> withSkew(long skewMs) {
        Map<String, Object> c = trusted();
        c.put("clockSkewMs", skewMs);
        return c;
    }

    @Test
    void timeEdges() {
        long nowSec = NOW / 1000;
        assertOk("exp at this second (milliseconds ignored)", gcp(trusted(), tok(m -> m.put("exp", nowSec)), NOW + 999));
        assertDenied("exp one second ago", gcp(trusted(), tok(m -> m.put("exp", nowSec)), NOW + 1000), "Confidential Space token expired");
        assertOk("nbf at this second", gcp(trusted(), tok(m -> m.put("nbf", nowSec)), NOW));
        assertOk("nbf two seconds ahead, skew 2 s", gcp(withSkew(2000), tok(m -> m.put("nbf", nowSec + 2)), NOW));
        assertDenied("nbf three seconds ahead, skew 2 s", gcp(withSkew(2000), tok(m -> m.put("nbf", nowSec + 3)), NOW), "Confidential Space token not yet valid (nbf)");
        // a 1500 ms skew rounds up to 2 s
        assertOk("iat two seconds ahead, skew 1.5 s", gcp(withSkew(1500), tok(m -> {
            m.remove("nbf");
            m.put("iat", nowSec + 2);
        }), NOW));
        assertDenied("iat three seconds ahead, skew 1.5 s", gcp(withSkew(1500), tok(m -> {
            m.remove("nbf");
            m.put("iat", nowSec + 3);
        }), NOW), "Confidential Space token issued in the future (iat)");
        assertDenied("exp two seconds ago, skew 1.5 s", gcp(withSkew(1500), tok(m -> m.put("exp", nowSec - 3)), NOW), "Confidential Space token expired");
        assertOk("exp two seconds ago, skew 1.5 s", gcp(withSkew(1500), tok(m -> m.put("exp", nowSec - 2)), NOW));
    }

    @Test
    void claimShapes() {
        String want = "unexpected swname 'undefined' (expected 'CONFIDENTIAL_SPACE')";
        assertDenied("no swname", gcp(trusted(), tok(m -> m.remove("swname")), NOW), want);
        assertDenied("numeric swname", gcp(trusted(), tok(m -> m.put("swname", 5L)), NOW), want);
        Map<String, Object> emptyVersion = config(jwks(AttestGcpTest.jwkOf(key, "k1")), "{\"imageDigests\":[\"sha256:abc\"],\"allowedSwVersions\":[\"\",\"5\"]}");
        assertDenied("empty swversion", gcp(emptyVersion, tok(m -> m.put("swversion", "")), NOW), "swversion not in policy allowlist");
        assertDenied("numeric swversion", gcp(emptyVersion, tok(m -> m.put("swversion", 5L)), NOW), "swversion not in policy allowlist");
        assertOk("swversion list", gcp(emptyVersion, tok(m -> m.put("swversion", list("x", "5"))), NOW));
        String noNonce = "token carries no eat_nonce claim to bind the PCA challenge";
        assertDenied("empty eat_nonce list entry", gcp(trusted(), tok(m -> m.put("eat_nonce", list(""))), NOW), noNonce);
        assertDenied("empty eat_nonce", gcp(trusted(), tok(m -> m.put("eat_nonce", "")), NOW), noNonce);
        assertDenied("eat_nonce with a non-string", gcp(trusted(), tok(m -> m.put("eat_nonce", list(5L))), NOW), noNonce);
        String rawB64 = Base64.getEncoder().encodeToString(rawBinding(BINDING));
        assertOk("an undecodable candidate before the binding", gcp(trusted(), tok(m -> m.put("eat_nonce", list("!!!", rawB64))), NOW));
        // the host fields: no image_reference
        HardwareResult r = gcp(trusted(), tok(m -> container(m).remove("image_reference")), NOW);
        assertOk("no image_reference", r);
        assertEquals(3, r.hostAsserted.size());
        assertEquals("tdx", r.hostAsserted.get("attestation_type"));
        assertEquals("GCP_INTEL_TDX", r.hostAsserted.get("hwmodel"));
        assertEquals("sha256:abc", r.hostAsserted.get("image_digest"));
        assertFalse(r.hostAsserted.containsKey("image_reference"));
    }

    // gcp:384: the whole chain, after its links and before any anchor is looked at
    @Test
    void strictChainProfile() {
        Map<String, Object> rootPinned = config(pins(spki(root)), POLICY);
        Map<String, Object> rootCert = config(obj("rootCertsPem", list(pemCert(rootDer))), POLICY);
        Map<String, Object> unrelated = config(pins(spki(other)), POLICY);
        for (K05StrictChainTest.Case c : K05StrictChainTest.cases(key, root, "secp256r1")) {
            Object[] full = new Object[c.ders.size()];
            for (int i = 0; i < full.length; i++) full[i] = b64(c.ders.get(i));
            if (c.reason.isEmpty()) {
                assertOk(c.name, gcp(rootPinned, x5cTok(full), NOW));
                assertOk(c.name + " (root certificate)", gcp(rootCert, x5cTok(full), NOW));
            } else {
                assertDenied(c.name, gcp(rootPinned, x5cTok(full), NOW), NOT_TRUSTED + "x5c chain profile: " + c.reason);
                assertDenied(c.name + " (root certificate)", gcp(rootCert, x5cTok(full), NOW), NOT_TRUSTED + "x5c chain profile: " + c.reason);
                assertDenied(c.name + " (before the anchors)", gcp(unrelated, x5cTok(full), NOW), NOT_TRUSTED + "x5c chain profile: " + c.reason);
            }
        }
    }

    // the commit "GCP Confidential Space refuses a JWK whose n/e or x/y is not the key of its x5c leaf": a genuine public chain must not vouch for the attacker's key
    @Test
    void jwkKeyMustBeItsX5cLeaf() {
        String attackerToken = signEs256(other, "{\"alg\":\"ES256\",\"kid\":\"k1\"}", claims(null));
        Map<String, Object> forged = AttestGcpTest.jwkOf(other, "k1");
        forged.put("x5c", list(b64(leafDer), b64(rootDer)));
        Map<String, Object> ev = obj("token", attackerToken, "jwks", obj("keys", list(forged)));
        String refused = NOT_TRUSTED + "the JWK key is not the key of its x5c leaf";
        Map<String, Object> rootCert = config(obj("rootCertsPem", list(pemCert(rootDer))), POLICY);
        Map<String, Object> rootPin = config(pins(spki(root)), POLICY);
        assertDenied("forgery under a root certificate", run(V, rootCert, ev, BINDING, NOW), refused);
        assertDenied("forgery under a pinned chain key", run(V, rootPin, ev, BINDING, NOW), refused);
        // the honest leaf key written as x/y beside its own chain, and the chain alone
        Map<String, Object> honest = AttestGcpTest.jwkOf(key, "k1");
        honest.put("x5c", list(b64(leafDer), b64(rootDer)));
        Map<String, Object> evHonest = obj("token", tok(null), "jwks", obj("keys", list(honest)));
        assertOk("honest key beside its chain, root certificate", run(V, rootCert, evHonest, BINDING, NOW));
        assertOk("honest key beside its chain, pinned chain key", run(V, rootPin, evHonest, BINDING, NOW));
        // a chain that does not verify reports that first
        Map<String, Object> broken = AttestGcpTest.jwkOf(other, "k1");
        broken.put("x5c", list(b64(leafDer), ""));
        assertDenied("the chain error comes first", run(V, rootCert, obj("token", attackerToken, "jwks", obj("keys", list(broken))), BINDING, NOW),
            NOT_TRUSTED + "empty x5c entry at index 1");
        // a genuine leaf whose key the reader refuses is not the JWK's key either
        KeyPair x;
        try {
            x = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (java.security.GeneralSecurityException e) {
            throw new AssertionError(e);
        }
        Map<String, Object> unreadable = AttestGcpTest.jwkOf(other, "k1");
        unreadable.put("x5c", list(b64(AttestTestDer.cert("x", "root", x, root)), b64(rootDer)));
        assertDenied("unreadable leaf key", run(V, rootCert, obj("token", attackerToken, "jwks", obj("keys", list(unreadable))), BINDING, NOW), refused);
    }
}
