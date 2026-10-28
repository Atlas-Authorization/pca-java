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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

/**
 * Google Confidential Space: replay of the gcp-confidential-space rows of the shared attestation evidence vectors, the
 * constructor refusals, the fail-closed table, and tokens signed under a generated key (pinned JWKS, SPKI pin, x5c root).
 */
public class AttestGcpTest {
    static final String ISSUER = "https://confidentialcomputing.googleapis.com";
    static final String V = "gcp-confidential-space";

    @Test
    void vectors() { AttestMaaTest.replayVendor(V); }

    @Test
    void constructRefusals() {
        assertEquals("createGcpConfidentialSpaceVerifier: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs", constructError(V, "{}"));
        assertEquals("createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string", constructError(V, "{\"trustedIssuers\":[5]}"));
        assertEquals("createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted",
            constructError(V, "{\"trustedIssuers\":[\"https://i\"]}"));
        assertEquals("createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)",
            constructError(V, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"trustedKeySpki\":[\"aa\"]},\"policy\":{}}"));
        assertEquals("createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)",
            constructError(V, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"trustedKeySpki\":[\"aa\"]}}"));
        assertEquals("createGcpConfidentialSpaceVerifier: policy.allowedTeeTypes, when present, must be non-empty",
            constructError(V, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"trustedKeySpki\":[\"aa\"]},\"policy\":{\"imageDigests\":[\"sha256:x\"],\"allowedTeeTypes\":[]}}"));
        assertNull(constructError(V, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"trustedKeySpki\":[\"aa\"]},\"policy\":{\"imageDigests\":[\"sha256:x\"]}}"));
    }

    @Test
    void failClosedNoEvidenceAndBadEvidence() {
        Map<String, Object> c = cfg("{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"trustedKeySpki\":[\"aa\"]},\"policy\":{\"imageDigests\":[\"sha256:x\"]}}");
        assertDenied("nil evidence", run(V, c, null, BINDING, NOW), "no GCP Confidential Space token for this action");
        assertDenied("not a JWS", run(V, c, obj("token", "x"), BINDING, NOW), "Confidential Space token parse failed: parseGcpCsJwt: a compact JWS has exactly three dot-separated parts");
        assertDenied("alg none", run(V, c, obj("token", unsignedJwt("{\"alg\":\"none\"}", "{}")), BINDING, NOW), "unsupported JWS alg 'none' (Confidential Space uses RS256)");
        assertDenied("no kid, no key", run(V, c, obj("token", unsignedJwt("{\"alg\":\"ES256\"}", "{}")), BINDING, NOW),
            "Confidential Space signing key invalid: no kid on the token and no unambiguous single signing key available");
        assertDenied("unknown kid", run(V, c, obj("token", unsignedJwt("{\"alg\":\"ES256\",\"kid\":\"zz\"}", "{}")), BINDING, NOW),
            "Confidential Space signing key invalid: no JWKS key matches the token kid 'zz' (untrusted signer)");
        List<Object> bare = new ArrayList<>();
        bare.add(obj("kid", "zz", "kty", "OKP"));
        assertDenied("key without material", run(V, c, obj("token", unsignedJwt("{\"alg\":\"ES256\",\"kid\":\"zz\"}", "{}"), "jwks", obj("keys", bare)), BINDING, NOW),
            "Confidential Space signing key invalid: JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate");
    }

    // ------------------------------------------------------------- signed tokens

    private final KeyPair key = AttestTestDer.ecKey("secp256r1");
    private final String hdr = "{\"alg\":\"ES256\",\"kid\":\"k1\"}";

    static Map<String, Object> jwkOf(KeyPair kp, String kid) {
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        return obj("kid", kid, "kty", "EC", "crv", "P-256", "x", b64u(fixed(pub.getW().getAffineX())), "y", b64u(fixed(pub.getW().getAffineY())));
    }

    private static byte[] fixed(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(32, b.length);
        System.arraycopy(b, b.length - n, out, 32 - n, n);
        return out;
    }

    private String claims(Consumer<Map<String, Object>> mut) {
        long nowSec = NOW / 1000;
        List<Object> nonce = new ArrayList<>();
        nonce.add(Base64.getEncoder().encodeToString(rawBinding(BINDING)));
        List<Object> sw = new ArrayList<>();
        sw.add("240500");
        Map<String, Object> m = obj("iss", ISSUER, "exp", nowSec + 3600, "iat", nowSec - 60, "nbf", nowSec - 60,
            "swname", "CONFIDENTIAL_SPACE", "swversion", sw, "hwmodel", "GCP_AMD_SEV", "dbgstat", "disabled-since-boot",
            "eat_nonce", nonce,
            "submods", obj("confidential_space", obj("support_attributes", new ArrayList<Object>()),
                "container", obj("image_digest", "sha256:ABC", "image_reference", "r/i@sha256:abc")));
        if (mut != null) mut.accept(m);
        return json(m);
    }

    private Map<String, Object> gcfg(String policy) {
        Map<String, Object> c = cfg("{\"trustedIssuers\":[\"" + ISSUER + "\"],\"trustAnchors\":{},\"policy\":" + policy + "}");
        List<Object> keys = new ArrayList<>();
        keys.add(jwkOf(key, "k1"));
        c.put("trustAnchors", obj("trustedJwks", obj("keys", keys)));
        return c;
    }

    private static HardwareResult gcp(Map<String, Object> config, String token, AttestationBinding b, long now) {
        return run(V, config, obj("token", token), b, now);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> container(Map<String, Object> m) {
        return (Map<String, Object>) ((Map<String, Object>) m.get("submods")).get("container");
    }

    @Test
    void signedTokens() {
        String good = signEs256(key, hdr, claims(null));
        Map<String, Object> ok = gcfg("{\"imageDigests\":[\"sha256:abc\"]}");
        HardwareResult r = gcp(ok, good, BINDING, NOW);
        assertTrue(r.ok && r.bound, "baseline: " + r.reason);
        assertEquals("sha256:ABC", r.measured.get("runtime_measurement"));
        assertEquals(Boolean.FALSE, r.measured.get("weights_measured"));
        assertEquals("sev-snp", r.hostAsserted.get("attestation_type"));
        assertEquals("GCP_AMD_SEV", r.hostAsserted.get("hwmodel"));
        assertEquals("sha256:ABC", r.hostAsserted.get("image_digest"));
        assertEquals("r/i@sha256:abc", r.hostAsserted.get("image_reference"));

        AttestationBinding relay = new AttestationBinding("holder-key", "passport:abc", 0, "nonce-2");
        KeyPair other = AttestTestDer.ecKey("secp256r1");
        assertDenied("relayed nonce", gcp(ok, good, relay, NOW), "eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)");
        assertDenied("image not allowed", gcp(gcfg("{\"imageDigests\":[\"sha256:other\"]}"), good, BINDING, NOW), "workload image_digest not in policy allowlist");
        assertDenied("expired token", gcp(ok, good, BINDING, NOW + 4_000_000), "Confidential Space token expired");
        assertDenied("not yet valid", gcp(ok, good, BINDING, NOW - 600_000), "Confidential Space token not yet valid (nbf)");
        assertDenied("issued in the future", gcp(ok, signEs256(key, hdr, claims(m -> {
            m.remove("nbf");
            m.put("iat", NOW / 1000 + 5);
        })), BINDING, NOW), "Confidential Space token issued in the future (iat)");
        assertTrue(gcp(cfgWithSkew("{\"imageDigests\":[\"sha256:abc\"]}", 5000), signEs256(key, hdr, claims(m -> {
            m.remove("nbf");
            m.put("iat", NOW / 1000 + 5);
        })), BINDING, NOW).ok, "clock skew covers a 5 s early iat");
        assertDenied("another signer", gcp(ok, signEs256(other, hdr, claims(null)), BINDING, NOW),
            "JWS ES256 signature does not verify under the Confidential Space signing key");
        assertDenied("issuer not configured", gcp(ok, signEs256(key, hdr, claims(m -> m.put("iss", "https://other"))), BINDING, NOW),
            "token iss 'https://other' is not a configured trusted Google attestation issuer");
        assertDenied("debug build", gcp(ok, signEs256(key, hdr, claims(m -> m.put("dbgstat", "enabled"))), BINDING, NOW),
            "token dbgstat 'enabled' is not 'disabled-since-boot' (debug build — no confidentiality)");
        assertDenied("no dbgstat", gcp(ok, signEs256(key, hdr, claims(m -> m.remove("dbgstat"))), BINDING, NOW),
            "token dbgstat 'undefined' is not 'disabled-since-boot' (debug build — no confidentiality)");
        assertTrue(gcp(gcfg("{\"imageDigests\":[\"sha256:abc\"],\"allowDebug\":true}"), signEs256(key, hdr, claims(m -> m.put("dbgstat", "enabled"))), BINDING, NOW).ok, "allowDebug");
        assertDenied("wrong software", gcp(ok, signEs256(key, hdr, claims(m -> m.put("swname", "OTHER"))), BINDING, NOW),
            "unexpected swname 'OTHER' (expected 'CONFIDENTIAL_SPACE')");
        assertDenied("no submods.confidential_space", gcp(ok, signEs256(key, hdr, claims(m -> m.put("submods", obj("container", obj("image_digest", "sha256:ABC"))))), BINDING, NOW),
            "token carries no submods.confidential_space (not a Confidential Space token)");
        assertDenied("tee type pinned away", gcp(gcfg("{\"imageDigests\":[\"sha256:abc\"],\"allowedTeeTypes\":[\"tdx\"]}"), good, BINDING, NOW),
            "attestation type 'sev-snp' (hwmodel 'GCP_AMD_SEV') is not in the policy allowlist");
        assertTrue(gcp(gcfg("{\"imageDigests\":[\"sha256:abc\"],\"allowedTeeTypes\":[\"tdx\"]}"), signEs256(key, hdr, claims(m -> m.put("hwmodel", "GCP_INTEL_TDX"))), BINDING, NOW).ok, "tdx allowed");
        assertDenied("unknown hardware model", gcp(ok, signEs256(key, hdr, claims(m -> m.put("hwmodel", "SOMETHING"))), BINDING, NOW),
            "unrecognized hwmodel 'SOMETHING' (not a known AMD SEV-SNP / Intel TDX model)");
        assertDenied("no hardware model", gcp(ok, signEs256(key, hdr, claims(m -> m.remove("hwmodel"))), BINDING, NOW), "token carries no hwmodel claim");
        assertDenied("no nonce claim", gcp(ok, signEs256(key, hdr, claims(m -> m.remove("eat_nonce"))), BINDING, NOW),
            "token carries no eat_nonce claim to bind the PCA challenge");
        assertDenied("no exp", gcp(ok, signEs256(key, hdr, claims(m -> m.remove("exp"))), BINDING, NOW), "token has no exp (cannot bound validity — fail closed)");
        assertDenied("swversion not allowed", gcp(gcfg("{\"imageDigests\":[\"sha256:abc\"],\"allowedSwVersions\":[\"1\"]}"), good, BINDING, NOW), "swversion not in policy allowlist");
        assertTrue(gcp(gcfg("{\"imageDigests\":[\"sha256:abc\"],\"allowedSwVersions\":[\"7\"]}"), signEs256(key, hdr, claims(m -> m.put("swversion", "7"))), BINDING, NOW).ok,
            "a single-string swversion");
        assertDenied("no image digest", gcp(ok, signEs256(key, hdr, claims(m -> container(m).remove("image_digest"))), BINDING, NOW),
            "token carries no submods.container.image_digest to measure the workload");
        assertDenied("binding not constructible", gcp(ok, good, new AttestationBinding(null, "g", 0, "n"), NOW), "binding not constructible: binding: holderPub required");
        assertDenied("no expected binding", gcp(ok, good, null, NOW), "no expected attestation binding supplied");
        // a single-string eat_nonce, and the nonce hash option binding H(binding)
        assertTrue(gcp(ok, signEs256(key, hdr, claims(m -> m.put("eat_nonce", Base64.getEncoder().encodeToString(rawBinding(BINDING))))), BINDING, NOW).ok, "string eat_nonce");
        String hashed = signEs256(key, hdr, claims(m -> m.put("eat_nonce", Base64.getEncoder().encodeToString(AttestCommon.sha256Sum(rawBinding(BINDING))))));
        assertTrue(gcp(gcfg("{\"imageDigests\":[\"sha256:abc\"],\"nonceHash\":\"sha256\"}"), hashed, BINDING, NOW).ok, "sha256 nonce");
        assertDenied("hashed nonce without the option", gcp(ok, hashed, BINDING, NOW), "eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)");
    }

    private Map<String, Object> cfgWithSkew(String policy, long skewMs) {
        Map<String, Object> c = gcfg(policy);
        c.put("clockSkewMs", skewMs);
        return c;
    }

    @Test
    void spkiPinAndEvidenceJwks() {
        // the key comes from the evidence JWKS and is trusted through an SPKI pin only
        String pin = AttestCommon.toHexLower(AttestCommon.sha256Sum(key.getPublic().getEncoded()));
        Map<String, Object> c = cfg("{\"trustedIssuers\":[\"" + ISSUER + "\"],\"trustAnchors\":{\"trustedKeySpki\":[\"" + pin.toUpperCase() + "\"]},\"policy\":{\"imageDigests\":[\"sha256:abc\"]}}");
        List<Object> keys = new ArrayList<>();
        keys.add(jwkOf(key, "k1"));
        String good = signEs256(key, hdr, claims(null));
        assertTrue(run(V, c, obj("token", good, "jwks", obj("keys", keys)), BINDING, NOW).ok, "pinned SPKI");
        KeyPair other = AttestTestDer.ecKey("secp256r1");
        List<Object> otherKeys = new ArrayList<>();
        otherKeys.add(jwkOf(other, "k1"));
        assertDenied("unpinned evidence key", run(V, c, obj("token", signEs256(other, hdr, claims(null)), "jwks", obj("keys", otherKeys)), BINDING, NOW),
            "Confidential Space signing key invalid: signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)");
    }

    @Test
    void x5cRootAnchor() {
        KeyPair root = AttestTestDer.ecKey("secp256r1");
        byte[] rootDer = AttestTestDer.cert("root", "root", root, root, AttestTestDer.basicConstraints(true, -1));
        byte[] leafDer = AttestTestDer.cert("leaf", "root", key, root);
        String pem = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(rootDer) + "\n-----END CERTIFICATE-----\n";
        Map<String, Object> c = cfg("{\"trustedIssuers\":[\"" + ISSUER + "\"],\"trustAnchors\":{\"rootCertsPem\":[" + json(pem) + "]},\"policy\":{\"imageDigests\":[\"sha256:abc\"]}}");
        String tok = signEs256(key, "{\"alg\":\"ES256\",\"x5c\":[\"" + Base64.getEncoder().encodeToString(leafDer) + "\"]}", claims(null));
        assertTrue(run(V, c, obj("token", tok), BINDING, NOW).ok, "leaf signed by a configured root");
        // the same root given as a bare public key
        String keyPem = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString(root.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----\n";
        Map<String, Object> ck = cfg("{\"trustedIssuers\":[\"" + ISSUER + "\"],\"trustAnchors\":{\"rootCertsPem\":[" + json(keyPem) + "]},\"policy\":{\"imageDigests\":[\"sha256:abc\"]}}");
        assertTrue(run(V, ck, obj("token", tok), BINDING, NOW).ok, "root as a bare public key");
        assertNotNull(AttestGcp.rootKeyFromPem(keyPem));
        assertNull(AttestGcp.rootKeyFromPem("not pem"));
        byte[] stranger = AttestTestDer.cert("leaf", "root", key, AttestTestDer.ecKey("secp256r1"));
        String unanchored = signEs256(key, "{\"alg\":\"ES256\",\"x5c\":[\"" + Base64.getEncoder().encodeToString(stranger) + "\"]}", claims(null));
        assertDenied("leaf not signed by the root", run(V, c, obj("token", unanchored), BINDING, NOW),
            "Confidential Space signing key invalid: signing key not trusted: x5c chain does not anchor in a configured GCP trust root");
    }

    @Test
    void teeTypes() {
        assertEquals("sev-snp", AttestGcp.gcpTeeType("GCP_AMD_SEV"));
        assertEquals("sev-snp", AttestGcp.gcpTeeType("GCP_AMD_SEV_ES"));
        assertEquals("sev-snp", AttestGcp.gcpTeeType("GCP_AMD_SEV_SNP"));
        assertEquals("sev-snp", AttestGcp.gcpTeeType("gcp_amd_sev_future"));
        assertEquals("tdx", AttestGcp.gcpTeeType("GCP_INTEL_TDX"));
        assertEquals("tdx", AttestGcp.gcpTeeType("gcp_intel_tdx2"));
        assertEquals("", AttestGcp.gcpTeeType("GCP_SHIELDED_VM"));
        assertEquals("", AttestGcp.gcpTeeType("AMD_SEV"));
    }
}
