package net.atlasauth.pca;

import static net.atlasauth.pca.AttestMaaTest.BINDING;
import static net.atlasauth.pca.AttestMaaTest.MRTD;
import static net.atlasauth.pca.AttestMaaTest.NOW;
import static net.atlasauth.pca.AttestMaaTest.assertDenied;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

/**
 * Azure MAA, exact outcomes the mutation run left open: constructor guards, the signing-chain resolution table (JWKS / kid /
 * header x5c), the x5c chain table (anchor by root certificate fingerprint, full-chain links, unreadable roots and keys),
 * the ES256 / RS256 key checks, time and skew edges, and the optional TDX / SEV-SNP host fields.
 */
public class AttestMaaKillTest {
    static final String V = "azure-maa";
    static final String TDX = "{\"tdxMrtds\":[\"" + MRTD + "\"]}";

    private final KeyPair key = AttestTestDer.ecKey("secp256r1");
    private final byte[] certDer = AttestTestDer.cert("maa-test", "maa-test", key, key, AttestTestDer.basicConstraints(true, -1));
    private final String pinHex = AttestCommon.toHexLower(AttestCommon.sha256Sum(key.getPublic().getEncoded()));

    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }

    static String b64(byte[] der) { return Base64.getEncoder().encodeToString(der); }

    static String pemCert(byte[] der) { return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(der) + "\n-----END CERTIFICATE-----\n"; }

    static Map<String, Object> config(String anchors, String policy) {
        return cfg("{\"trustedIssuers\":[\"https://maa.test\"],\"trustAnchors\":" + anchors + ",\"policy\":" + policy + "}");
    }

    private Map<String, Object> pinned(String policy) { return config("{\"rootSpkiSha256\":[\"" + pinHex + "\"]}", policy); }

    static String claims(Consumer<Map<String, Object>> mut) {
        long nowSec = NOW / 1000;
        Map<String, Object> m = obj("iss", "https://maa.test", "exp", nowSec + 3600, "iat", nowSec - 60, "nbf", nowSec - 60,
            "x-ms-isolation-tee", obj("x-ms-attestation-type", "tdxvm", "tdx_mrtd", MRTD.toUpperCase(), "tdx_report_data",
                AttestCommon.toHexLower(rawBinding(BINDING)), "attester_tcb_status", "UpToDate", "tdx_rtmr0", "bb"));
        if (mut != null) mut.accept(m);
        return json(m);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> tee(Map<String, Object> m) { return (Map<String, Object>) m.get("x-ms-isolation-tee"); }

    /** A token signed by kp carrying chain as its header x5c. */
    static String x5cTok(KeyPair kp, Consumer<Map<String, Object>> mut, Object... chain) {
        List<String> parts = new ArrayList<>();
        for (Object c : chain) parts.add(json(c));
        return signEs256(kp, "{\"alg\":\"ES256\",\"x5c\":[" + String.join(",", parts) + "]}", claims(mut));
    }

    private String tok(Consumer<Map<String, Object>> mut) { return x5cTok(key, mut, b64(certDer)); }

    private static HardwareResult maa(Map<String, Object> config, String token) { return run(V, config, obj("token", token), BINDING, NOW); }

    private static HardwareResult maa(Map<String, Object> config, String token, Object jwks) {
        return run(V, config, obj("token", token, "jwks", jwks), BINDING, NOW);
    }

    private static void assertOk(String name, HardwareResult r) {
        assertEquals("", r.reason, name);
        assertTrue(r.ok && r.bound, name);
    }

    // ------------------------------------------------------------- construction

    @Test
    void constructionGuards() {
        assertEquals("createAzureMaaVerifier: every trusted issuer must be a non-empty URL string", constructError(V, "{\"trustedIssuers\":[5]}"));
        // the anchor count is a sum
        assertNull(constructError(V, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"rootCertsPem\":[\"a\"],\"rootSpkiSha256\":[\"b\"]},\"policy\":" + TDX + "}"));
        assertEquals("createAzureMaaVerifier: policy.sevSnpMinTcb.snp must be a non-negative integer",
            constructError(V, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"aa\"]},\"policy\":{\"sevSnpMeasurements\":[\"aa\"],\"sevSnpMinTcb\":{\"snp\":\"3\"}}}"));
        assertEquals("createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)",
            constructError(V, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"aa\"]},\"policy\":{\"sevSnpMeasurements\":[],\"tdxMrtds\":[]}}"));
        // a non-string reportDataHash is ignored; an unknown mode binds the raw value
        assertOk("non-string reportDataHash", maa(pinned("{\"tdxMrtds\":[\"" + MRTD + "\"],\"reportDataHash\":5}"), tok(null)));
        assertOk("unknown reportDataHash", maa(pinned("{\"tdxMrtds\":[\"" + MRTD + "\"],\"reportDataHash\":\"md5\"}"), tok(null)));
        // the RTMR allowlist is compared lower-case on both sides
        HardwareResult r = maa(pinned("{\"tdxMrtds\":[\"" + MRTD + "\"],\"tdxRtmrs\":[\"BB\"]}"), tok(m -> tee(m).put("tdx_rtmr0", "Bb")));
        assertOk("rtmr0 case-insensitive", r);
        assertEquals("bb", r.hostAsserted.get("rtmr0"));
        // an empty SEV-SNP allowlist next to a TDX one does not enable SEV-SNP
        String rd = AttestCommon.toHexLower(rawBinding(BINDING));
        assertDenied("empty SEV-SNP allowlist", maa(pinned("{\"sevSnpMeasurements\":[],\"tdxMrtds\":[\"" + MRTD + "\"]}"), tok(m -> {
            tee(m).put("x-ms-attestation-type", "sevsnpvm");
            tee(m).put("x-ms-sevsnpvm-reportdata", rd);
            tee(m).put("x-ms-sevsnpvm-launchmeasurement", MRTD);
        })), "sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)");
    }

    // ------------------------------------------------------------- signing chain resolution

    @Test
    void resolveSigningChain() {
        Map<String, Object> c = pinned(TDX);
        String noKid = signEs256(key, "{\"alg\":\"ES256\"}", claims(null));
        String emptyKid = signEs256(key, "{\"alg\":\"ES256\",\"kid\":\"\"}", claims(null));
        String kidZz = signEs256(key, "{\"alg\":\"ES256\",\"kid\":\"zz\"}", claims(null));
        List<Object> chain = list(b64(certDer));
        assertOk("empty kid, one key", maa(c, emptyKid, obj("keys", list(obj("kid", "other", "x5c", chain)))));
        assertOk("kid after a non-object member", maa(c, kidZz, obj("keys", list(5L, obj("kid", "zz", "x5c", chain)))));
        assertOk("keys not a list: the header x5c", maa(c, tok(null), obj("keys", "x")));
        assertOk("empty key list: the header x5c", maa(c, tok(null), obj("keys", list())));
        String noChain = "JWKS key carries no x5c chain";
        assertDenied("sole key without x5c", maa(c, noKid, obj("keys", list(obj("kid", "a")))), noChain);
        assertDenied("sole key not an object", maa(c, noKid, obj("keys", list(5L))), noChain);
        assertDenied("sole key x5c not a list", maa(c, noKid, obj("keys", list(obj("x5c", "s")))), noChain);
        assertDenied("sole key empty x5c", maa(c, noKid, obj("keys", list(obj("x5c", list())))), noChain);
        assertDenied("matched key empty x5c", maa(c, kidZz, obj("keys", list(obj("kid", "zz", "x5c", list())))), "JWKS key 'zz' carries no x5c chain");
        assertDenied("empty header x5c", maa(c, signEs256(key, "{\"alg\":\"ES256\",\"x5c\":[]}", claims(null))), "no signing x5c available (no JWKS and no header x5c)");
    }

    // ------------------------------------------------------------- the x5c chain

    @Test
    void x5cChainTable() throws Exception {
        Map<String, Object> c = pinned(TDX);
        assertDenied("non-string entry", maa(c, signEs256(key, "{\"alg\":\"ES256\",\"kid\":\"k\"}", claims(null)), obj("keys", list(obj("kid", "k", "x5c", list(b64(certDer), 5L))))),
            "MAA signing chain invalid: empty x5c entry at index 1");
        assertDenied("malformed entry", maa(c, x5cTok(key, null, "MAA=")),
            "MAA signing chain invalid: malformed x5c certificate at index 0: error:0680007B:asn1 encoding routines::not enough data");
        // an unreadable configured root fails closed
        assertDenied("unreadable root", maa(config("{\"rootCertsPem\":[\"garbage\"]}", TDX), tok(null)),
            "MAA signing chain invalid: x5c chain verification error (fail closed): error:0480006C:PEM routines::no start line");
        // an empty fingerprint is no anchor
        assertDenied("empty fingerprint only", maa(config("{\"rootSpkiSha256\":[\"\"]}", TDX), tok(null)),
            "MAA signing chain invalid: no MAA trust anchor configured (fail closed)");
        assertOk("empty fingerprint next to a real one", maa(config("{\"rootSpkiSha256\":[\"\",\"" + pinHex.toUpperCase() + "\"]}", TDX), tok(null)));
        // a chain certificate whose key cannot be read fails closed
        KeyPairGenerator xg = KeyPairGenerator.getInstance("X25519");
        byte[] xCert = AttestTestDer.cert("x", "maa-test", xg.generateKeyPair(), key);
        assertDenied("unreadable chain key", maa(c, x5cTok(key, null, b64(xCert))),
            "MAA signing chain invalid: x5c chain verification error (fail closed): error:1E08010C:DECODER routines::unsupported");

        KeyPair root = AttestTestDer.ecKey("secp256r1");
        KeyPair stranger = AttestTestDer.ecKey("secp256r1");
        KeyPair inter = AttestTestDer.ecKey("secp256r1");
        KeyPair leaf = AttestTestDer.ecKey("secp256r1");
        byte[] rootDer = AttestTestDer.cert("root", "root", root, root, AttestTestDer.basicConstraints(true, -1));
        Map<String, Object> byRoot = config("{\"rootCertsPem\":[" + json(pemCert(rootDer)) + "]}", TDX);
        // the root certificate's key anchors a chain member that carries it (that member's own issuer is not checked)
        byte[] crossSigned = AttestTestDer.cert("root", "stranger", root, stranger, AttestTestDer.basicConstraints(true, -1));
        byte[] leafByRoot = AttestTestDer.cert("leaf", "root", leaf, root);
        assertOk("anchored by the root key fingerprint", maa(byRoot, x5cTok(leaf, null, b64(leafByRoot), b64(crossSigned))));
        // no fingerprint match: every link is checked, then the top against the root certificates
        byte[] interDer = AttestTestDer.cert("inter", "root", inter, root, AttestTestDer.basicConstraints(true, -1));
        byte[] leafByInter = AttestTestDer.cert("leaf", "inter", leaf, inter);
        byte[] leafByStranger = AttestTestDer.cert("leaf", "inter", leaf, stranger);
        assertOk("two links to a root certificate", maa(byRoot, x5cTok(leaf, null, b64(leafByInter), b64(interDer))));
        assertDenied("bad first link", maa(byRoot, x5cTok(leaf, null, b64(leafByStranger), b64(interDer))),
            "MAA signing chain invalid: x5c link 0 is not signed by the certificate above it");
        // with a fingerprint match only the links below the anchor are checked
        Map<String, Object> interPinned = config("{\"rootSpkiSha256\":[\"" + AttestCommon.toHexLower(AttestCommon.sha256Sum(inter.getPublic().getEncoded())) + "\"]}", TDX);
        assertOk("anchor in the middle (the link above it is not checked)", maa(interPinned, x5cTok(leaf, null, b64(leafByInter), b64(interDer), b64(leafByStranger))));
        assertDenied("bad link below the anchor", maa(interPinned, x5cTok(leaf, null, b64(leafByStranger), b64(interDer))),
            "MAA signing chain invalid: x5c link 0 is not signed by the certificate above it");
    }

    // ------------------------------------------------------------- signature key checks

    @Test
    void jwsSignatureKeyChecks() throws Exception {
        AttestJws.JwtParsed es = AttestJws.parseJwt(signEs256(key, "{\"alg\":\"ES256\"}", "{}"), "t");
        KeyPair p384 = AttestTestDer.ecKey("secp384r1");
        assertEquals("ES256 token but signing key is EC/P-384 (not EC P-256)",
            AttestMaa.jwsSignature(es, CertKey.of(p384.getPublic(), p384.getPublic().getEncoded()), "MAA"));
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair rsa = g.generateKeyPair();
        CertKey rsaKey = CertKey.of(rsa.getPublic(), rsa.getPublic().getEncoded());
        assertEquals("ES256 token but signing key is RSA/undefined (not EC P-256)", AttestMaa.jwsSignature(es, rsaKey, "MAA"));
        CertKey ecKey = CertKey.of(key.getPublic(), key.getPublic().getEncoded());
        assertEquals("", AttestMaa.jwsSignature(es, ecKey, "MAA"));
        AttestJws.JwtParsed rs = AttestJws.parseJwt(unsignedJwt("{\"alg\":\"RS256\"}", "{}"), "t");
        assertEquals("RS256 token but signing key is EC (not RSA)", AttestMaa.jwsSignature(rs, ecKey, "MAA"));
        assertEquals("JWS RS256 signature does not verify under the X signing key", AttestMaa.jwsSignature(rs, rsaKey, "X"));
        assertNull(AttestMaa.jwsSignature(AttestJws.parseJwt(unsignedJwt("{\"alg\":\"none\"}", "{}"), "t"), ecKey, "MAA"));
        assertNull(AttestMaa.jwsSignature(AttestJws.parseJwt(unsignedJwt("{\"alg\":\"ES384\"}", "{}"), "t"), ecKey, "MAA"));
    }

    // ------------------------------------------------------------- claims

    private Map<String, Object> withSkew(String policy, long skewMs) {
        Map<String, Object> c = pinned(policy);
        c.put("clockSkewMs", skewMs);
        return c;
    }

    @Test
    void timeAndShapeEdges() {
        long nowSec = NOW / 1000;
        assertOk("iat two seconds ahead, skew 1.5 s", maa(withSkew(TDX, 1500), tok(m -> {
            m.remove("nbf");
            m.put("iat", nowSec + 2);
        })));
        assertDenied("iat three seconds ahead, skew 1.5 s", maa(withSkew(TDX, 1500), tok(m -> {
            m.remove("nbf");
            m.put("iat", nowSec + 3);
        })), "MAA token issued in the future (iat)");
        assertOk("iat two seconds ahead, skew 2 s", maa(withSkew(TDX, 2000), tok(m -> {
            m.remove("nbf");
            m.put("iat", nowSec + 2);
        })));
        assertOk("nbf two seconds ahead, skew 2 s", maa(withSkew(TDX, 2000), tok(m -> m.put("nbf", nowSec + 2))));
        assertDenied("nbf three seconds ahead, skew 2 s", maa(withSkew(TDX, 2000), tok(m -> m.put("nbf", nowSec + 3))), "MAA token not yet valid (nbf)");
        // a non-string attestation type, inside the TEE claim and at the top level
        assertDenied("numeric attestation type", maa(pinned(TDX), tok(m -> {
            tee(m).put("x-ms-attestation-type", 5L);
            m.put("x-ms-attestation-type", 5L);
        })), "unexpected x-ms-attestation-type 'undefined' (expected sevsnpvm | tdxvm)");
        // the top-level type is used when the TEE claim has none
        assertOk("top-level attestation type", maa(pinned(TDX), tok(m -> {
            tee(m).remove("x-ms-attestation-type");
            m.put("x-ms-attestation-type", "tdxvm");
        })));
        assertDenied("undecodable runtime user-data", maa(pinned("{\"tdxMrtds\":[\"" + MRTD + "\"],\"runtimeUserDataBinding\":true}"),
            tok(m -> m.put("x-ms-runtime", obj("user-data", "!!!")))), "runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)");
    }

    @Test
    void tdxHostFields() {
        // a non-string TCB status is not checked and not asserted
        HardwareResult r = maa(pinned(TDX), tok(m -> tee(m).put("attester_tcb_status", 5L)));
        assertOk("numeric tcb status", r);
        assertFalse(r.hostAsserted.containsKey("tcb_status"));
        assertEquals("bb", r.hostAsserted.get("rtmr0"));
        assertEquals(2, r.hostAsserted.size());
        // an empty TCB status allowed by policy is not asserted
        HardwareResult e = maa(pinned("{\"tdxMrtds\":[\"" + MRTD + "\"],\"tdxAllowedTcbStatuses\":[\"\"]}"), tok(m -> tee(m).put("attester_tcb_status", "")));
        assertOk("empty tcb status", e);
        assertFalse(e.hostAsserted.containsKey("tcb_status"));
        // the alternative MRTD / RTMR0 / report-data claim names, and an upper-case RTMR0 asserted lower-case
        HardwareResult alt = maa(pinned(TDX), tok(m -> {
            Map<String, Object> t = tee(m);
            t.put("x-ms-tdx-mrtd", t.remove("tdx_mrtd"));
            t.put("x-ms-tdx-reportdata", t.remove("tdx_report_data"));
            t.remove("tdx_rtmr0");
            t.put("x-ms-tdx-rtmr0", "CC");
            t.remove("attester_tcb_status");
        }));
        assertOk("alternative claim names", alt);
        assertEquals("cc", alt.hostAsserted.get("rtmr0"));
        assertEquals("tdxvm", alt.hostAsserted.get("attestation_type"));
        assertEquals(2, alt.hostAsserted.size());
        assertEquals(MRTD, alt.measured.get("runtime_measurement"));
    }

    @Test
    void sevSnpWithoutHostData() {
        String rd = AttestCommon.toHexLower(rawBinding(BINDING));
        HardwareResult r = maa(pinned("{\"sevSnpMeasurements\":[\"" + MRTD + "\"]}"), tok(m -> m.put("x-ms-isolation-tee",
            obj("x-ms-attestation-type", "sevsnpvm", "x-ms-sevsnpvm-reportdata", rd, "x-ms-sevsnpvm-launchmeasurement", MRTD))));
        assertOk("no host data", r);
        assertEquals(1, r.hostAsserted.size());
        assertEquals("sevsnpvm", r.hostAsserted.get("attestation_type"));
    }

    private static String[] b64All(List<byte[]> ders) {
        String[] out = new String[ders.size()];
        for (int i = 0; i < out.length; i++) out[i] = b64(ders.get(i));
        return out;
    }

    // azure:395 (slice to the anchor) and azure:411 (the whole chain, after the external root check)
    @Test
    void strictChainProfile() {
        KeyPair root = AttestTestDer.ecKey("secp256r1");
        KeyPair leaf = AttestTestDer.ecKey("secp256r1");
        byte[] rootDer = AttestTestDer.cert("root", "root", root, root, AttestTestDer.basicConstraints(true, -1));
        Map<String, Object> pinned = config("{\"rootSpkiSha256\":[\"" + AttestCommon.toHexLower(AttestCommon.sha256Sum(root.getPublic().getEncoded())) + "\"]}", TDX);
        Map<String, Object> external = config("{\"rootCertsPem\":[" + json(pemCert(rootDer)) + "]}", TDX);
        for (K05StrictChainTest.Case c : K05StrictChainTest.cases(leaf, root, "secp256r1")) {
            String full = x5cTok(leaf, null, (Object[]) b64All(c.ders));
            String below = x5cTok(leaf, null, (Object[]) b64All(c.ders.subList(0, c.ders.size() - 1)));
            if (c.reason.isEmpty()) {
                assertOk(c.name + " (in-chain anchor)", maa(pinned, full));
                assertOk(c.name + " (external root)", maa(external, below));
            } else {
                assertDenied(c.name + " (in-chain anchor)", maa(pinned, full), "MAA signing chain invalid: x5c chain profile: " + c.reason);
                assertDenied(c.name + " (external root)", maa(external, below), "MAA signing chain invalid: x5c chain profile: " + c.reason);
            }
        }
        // the anchor check comes first at the external site: an unanchored chain says so, whatever its profile
        KeyPair stranger = AttestTestDer.ecKey("secp256r1");
        byte[] strangerRoot = AttestTestDer.cert("root", "root", stranger, stranger, AttestTestDer.basicConstraints(true, -1));
        Map<String, Object> elsewhere = config("{\"rootCertsPem\":[" + json(pemCert(strangerRoot)) + "]}", TDX);
        byte[] caLeaf = AttestTestDer.cert("leaf", "root", leaf, root, AttestTestDer.basicConstraints(true, -1));
        assertDenied("not anchored", maa(elsewhere, x5cTok(leaf, null, b64(caLeaf), b64(rootDer))),
            "MAA signing chain invalid: x5c chain does not anchor in a configured MAA trust root");
    }
}
