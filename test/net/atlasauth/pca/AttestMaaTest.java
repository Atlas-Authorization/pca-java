package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

/**
 * Azure MAA: replay of the azure-maa rows of the shared attestation evidence vectors, the constructor refusals, the
 * fail-closed table for absent / malformed evidence, and tokens signed under a generated signing certificate.
 */
public class AttestMaaTest {
    static final AttestationBinding BINDING = new AttestationBinding("holder-key", "passport:abc", 0, "nonce-1");
    static final long NOW = 1_800_000_000_000L;
    static final String MRTD = "a".repeat(96);

    // ------------------------------------------------------------- shared helpers (AttestGcpTest uses them too)

    @SuppressWarnings("unchecked")
    static Map<String, Object> cfg(String json) { return (Map<String, Object>) Json.parseLenient(json); }

    static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    static String json(Object v) { return Json.canonicalize(v); }

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static String unsignedJwt(String header, String payload) {
        return b64u(header.getBytes(StandardCharsets.UTF_8)) + "." + b64u(payload.getBytes(StandardCharsets.UTF_8)) + ".AA";
    }

    /** A compact ES256 JWS (raw r||s) of header.payload under kp. */
    static String signEs256(KeyPair kp, String header, String payload) {
        String input = b64u(header.getBytes(StandardCharsets.UTF_8)) + "." + b64u(payload.getBytes(StandardCharsets.UTF_8));
        try {
            Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
            s.initSign(kp.getPrivate());
            s.update(input.getBytes(StandardCharsets.US_ASCII));
            return input + "." + b64u(s.sign());
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] rawBinding(AttestationBinding b) { return AttestCommon.attestationBindingBytes(b); }

    static HardwareResult run(String vendor, Map<String, Object> config, Map<String, Object> ev, AttestationBinding b, long now) {
        return AttestFactory.verifierFromConfig(vendor, config).verify(ev, b, now);
    }

    static String constructError(String vendor, String config) {
        try {
            AttestFactory.verifierFromConfig(vendor, cfg(config));
            return null;
        } catch (AttestException e) {
            return e.getMessage();
        }
    }

    static void assertDenied(String name, HardwareResult r, String want) {
        assertFalse(r.ok, name + ": must be denied");
        assertFalse(r.bound, name + ": bound on a denial");
        assertNull(r.measured, name + ": measured on a denial");
        assertNull(r.hostAsserted, name + ": hostAsserted on a denial");
        assertEquals(want, r.reason, name);
    }

    /** Replays every attestation_vectors row of one vendor (wire form compared through the canonical JSON form). */
    @SuppressWarnings("unchecked")
    static void replayVendor(String vendor) {
        int n = 0;
        List<String> failures = new ArrayList<>();
        for (Map<String, Object> row : AttestVectors.rows("attestation_vectors")) {
            if (!vendor.equals(row.get("vendor"))) continue;
            n++;
            Map<String, Object> got;
            try {
                VendorVerifier v = AttestFactory.verifierFromConfig(vendor, AttestCommon.asRec(row.get("config")));
                Double now = AttestCommon.asFinite(row.get("now"));
                assertTrue(now != null, row.get("id") + ": now is not a number");
                got = v.verify(AttestCommon.asRec(row.get("evidence")), AttestVectors.bindingOf(row.get("expected_binding")), (long) (double) now).wire();
            } catch (AttestException e) {
                got = obj("construct_error", e.getMessage());
            }
            Map<String, Object> exp = new LinkedHashMap<>((Map<String, Object>) row.get("expect"));
            Map<String, Object> gotN = new LinkedHashMap<>(got);
            if ("prefix".equals(exp.get("reason_match"))) {
                String prefix = (String) exp.get("reason_prefix");
                Object reason = gotN.get("reason");
                if (!(reason instanceof String) || !((String) reason).startsWith(prefix)) {
                    failures.add(row.get("id") + ": reason " + reason + " does not start with " + prefix);
                    continue;
                }
                gotN.remove("reason");
                exp.remove("reason");
            }
            exp.remove("reason_match");
            exp.remove("reason_prefix");
            String g = AttestVectors.canon(gotN), w = AttestVectors.canon(exp);
            if (!g.equals(w)) failures.add(row.get("id") + " (intent " + row.get("intent") + ")\n got  " + g + "\n want " + w);
        }
        assertTrue(n > 0, "no attestation vectors for " + vendor);
        if (!failures.isEmpty()) fail(failures.size() + " of " + n + " " + vendor + " vectors disagree:\n" + String.join("\n", failures));
    }

    // ------------------------------------------------------------- tests

    @Test
    void vectors() { replayVendor("azure-maa"); }

    @Test
    void constructRefusals() {
        String v = "azure-maa";
        assertEquals("createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs", constructError(v, "{}"));
        assertEquals("createAzureMaaVerifier: every trusted issuer must be a non-empty URL string", constructError(v, "{\"trustedIssuers\":[\"\"]}"));
        assertEquals("createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted",
            constructError(v, "{\"trustedIssuers\":[\"https://i\"]}"));
        assertEquals("createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)",
            constructError(v, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"aa\"]}}"));
        assertEquals("createAzureMaaVerifier: policy.sevSnpMinTcb.bogus is not a known field (bootloader | snp | microcode | tee)",
            constructError(v, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"aa\"]},\"policy\":{\"sevSnpMeasurements\":[\"aa\"],\"sevSnpMinTcb\":{\"bogus\":1}}}"));
        assertEquals("createAzureMaaVerifier: policy.sevSnpMinTcb.snp must be a non-negative integer",
            constructError(v, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"aa\"]},\"policy\":{\"sevSnpMeasurements\":[\"aa\"],\"sevSnpMinTcb\":{\"snp\":-1}}}"));
        assertEquals("createAzureMaaVerifier: policy.sevSnpMinTcb.snp must be a non-negative integer",
            constructError(v, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"aa\"]},\"policy\":{\"sevSnpMeasurements\":[\"aa\"],\"sevSnpMinTcb\":{\"snp\":1.5}}}"));
        assertEquals("createAzureMaaVerifier: policy.sevSnpMinTcb must be an object",
            constructError(v, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"aa\"]},\"policy\":{\"sevSnpMeasurements\":[\"aa\"],\"sevSnpMinTcb\":3}}"));
        // a TDX-only policy may still carry an SVN floor; it is accepted
        assertNull(constructError(v, "{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"aa\"]},\"policy\":{\"tdxMrtds\":[\"aa\"],\"sevSnpMinTcb\":{\"snp\":3}}}"));
    }

    @Test
    void failClosedNoEvidenceAndBadEvidence() {
        Map<String, Object> c = cfg("{\"trustedIssuers\":[\"https://i\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"aa\"]},\"policy\":{\"tdxMrtds\":[\"aa\"]}}");
        String v = "azure-maa";
        assertDenied("nil evidence", run(v, c, null, BINDING, NOW), "no Azure MAA token for this action");
        assertDenied("empty token", run(v, c, obj("token", ""), BINDING, NOW), "no Azure MAA token for this action");
        assertDenied("not a JWS", run(v, c, obj("token", "x"), BINDING, NOW), "MAA token parse failed: parseMaaJwt: a compact JWS has exactly three dot-separated parts");
        assertDenied("non-canonical header", run(v, c, obj("token", "a.b.c"), BINDING, NOW),
            "MAA token parse failed: parseMaaJwt: malformed JSON segment: non-canonical compact JWS: non-canonical-base64url (impossible length)");
        assertDenied("alg none", run(v, c, obj("token", unsignedJwt("{\"alg\":\"none\"}", "{}")), BINDING, NOW), "unsupported JWS alg 'none' (MAA uses ES256 / RS256)");
        assertDenied("no signing chain", run(v, c, obj("token", unsignedJwt("{\"alg\":\"ES256\"}", "{}")), BINDING, NOW), "no signing x5c available (no JWKS and no header x5c)");
        List<Object> keys = new ArrayList<>();
        keys.add(obj("kid", "other", "x5c", List.of("AA==")));
        assertDenied("kid matches nothing", run(v, c, obj("token", unsignedJwt("{\"alg\":\"ES256\",\"kid\":\"zz\"}", "{}"), "jwks", obj("keys", keys)), BINDING, NOW),
            "no JWKS key matches the token kid 'zz' (untrusted signer)");
        List<Object> two = new ArrayList<>();
        two.add(obj("kid", "a", "x5c", List.of("AA==")));
        two.add(obj("kid", "b", "x5c", List.of("AA==")));
        assertDenied("no kid, two keys", run(v, c, obj("token", unsignedJwt("{\"alg\":\"ES256\"}", "{}"), "jwks", obj("keys", two)), BINDING, NOW),
            "token has no kid and the JWKS publishes multiple keys (ambiguous)");
        List<Object> noChain = new ArrayList<>();
        noChain.add(obj("kid", "zz"));
        assertDenied("matched key without x5c", run(v, c, obj("token", unsignedJwt("{\"alg\":\"ES256\",\"kid\":\"zz\"}", "{}"), "jwks", obj("keys", noChain)), BINDING, NOW),
            "JWKS key 'zz' carries no x5c chain");
        assertDenied("malformed x5c", run(v, c, obj("token", unsignedJwt("{\"alg\":\"ES256\",\"kid\":\"zz\"}", "{}"), "jwks", obj("keys", keys(obj("kid", "zz", "x5c", List.of(""))))), BINDING, NOW),
            "MAA signing chain invalid: empty x5c entry at index 0");
    }

    private static List<Object> keys(Object... ks) {
        List<Object> out = new ArrayList<>();
        for (Object k : ks) out.add(k);
        return out;
    }

    // ------------------------------------------------------------- tokens signed under a generated certificate

    private final KeyPair key = AttestTestDer.ecKey("secp256r1");
    private final byte[] certDer = AttestTestDer.certWithValidity("maa-test", "maa-test", "250101000000Z", "391231000000Z", key, key,
        AttestTestDer.basicConstraints(true, -1));
    private final String pinHex = AttestCommon.toHexLower(AttestCommon.sha256Sum(key.getPublic().getEncoded()));
    private final String hdr = "{\"alg\":\"ES256\",\"kid\":\"k1\"}";

    private Map<String, Object> jwks() {
        return obj("keys", keys(obj("kid", "k1", "kty", "EC", "x5c", List.of(Base64.getEncoder().encodeToString(certDer)))));
    }

    private String claims(Consumer<Map<String, Object>> mut) {
        long nowSec = NOW / 1000;
        Map<String, Object> m = obj("iss", "https://maa.test", "exp", nowSec + 3600, "iat", nowSec - 60, "nbf", nowSec - 60,
            "x-ms-isolation-tee", obj("x-ms-attestation-type", "tdxvm", "tdx_mrtd", MRTD.toUpperCase(), "tdx_report_data",
                AttestCommon.toHexLower(rawBinding(BINDING)), "attester_tcb_status", "UpToDate", "tdx_rtmr0", "bb"));
        if (mut != null) mut.accept(m);
        return json(m);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> tee(Map<String, Object> m) { return (Map<String, Object>) m.get("x-ms-isolation-tee"); }

    private Map<String, Object> mcfg(String pin, String policy) {
        return cfg("{\"trustedIssuers\":[\"https://maa.test\"],\"trustAnchors\":{\"rootSpkiSha256\":[\"" + pin + "\"]},\"policy\":" + policy + "}");
    }

    private HardwareResult maa(Map<String, Object> config, String token, AttestationBinding b, long now) {
        return run("azure-maa", config, obj("token", token, "jwks", jwks()), b, now);
    }

    @Test
    void signedTdxTokens() {
        String good = signEs256(key, hdr, claims(null));
        Map<String, Object> okCfg = mcfg(pinHex, "{\"tdxMrtds\":[\"" + MRTD + "\"]}");
        HardwareResult r = maa(okCfg, good, BINDING, NOW);
        assertTrue(r.ok && r.bound, "baseline: " + r.reason);
        assertEquals(MRTD, r.measured.get("runtime_measurement"));
        assertEquals(Boolean.FALSE, r.measured.get("weights_measured"));
        assertEquals("tdxvm", r.hostAsserted.get("attestation_type"));
        assertEquals("UpToDate", r.hostAsserted.get("tcb_status"));
        assertEquals("bb", r.hostAsserted.get("rtmr0"));

        // the header x5c is used when no JWKS is supplied
        String withX5c = signEs256(key, "{\"alg\":\"ES256\",\"x5c\":[\"" + Base64.getEncoder().encodeToString(certDer) + "\"]}", claims(null));
        assertTrue(run("azure-maa", okCfg, obj("token", withX5c), BINDING, NOW).ok, "header x5c");

        AttestationBinding relay = new AttestationBinding("holder-key", "passport:other", 0, "nonce-1");
        KeyPair other = AttestTestDer.ecKey("secp256r1");
        assertDenied("another trust pin", maa(mcfg("00".repeat(32), "{\"tdxMrtds\":[\"" + MRTD + "\"]}"), good, BINDING, NOW),
            "MAA signing chain invalid: x5c chain does not anchor in a configured MAA trust root");
        assertDenied("signing cert expired", maa(okCfg, good, BINDING, 2_240_611_200_000L), // 2041-01-01
            "MAA signing chain invalid: x5c certificate at index 0 is outside its validity window");
        assertDenied("relayed binding", maa(okCfg, good, relay, NOW), "report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)");
        assertDenied("another signer", maa(okCfg, signEs256(other, hdr, claims(null)), BINDING, NOW), "JWS ES256 signature does not verify under the MAA signing key");
        assertDenied("measurement not allowed", maa(mcfg(pinHex, "{\"tdxMrtds\":[\"" + "bb".repeat(48) + "\"]}"), good, BINDING, NOW), "TDX MRTD not in policy allowlist");
        assertDenied("debug guest", maa(okCfg, signEs256(key, hdr, claims(m -> tee(m).put("tdx_td_attributes_debug", true))), BINDING, NOW),
            "TDX guest is debuggable (no confidentiality)");
        assertDenied("dbgstat enabled", maa(okCfg, signEs256(key, hdr, claims(m -> tee(m).put("dbgstat", "enabled"))), BINDING, NOW),
            "TDX guest is debuggable (no confidentiality)");
        assertTrue(maa(okCfg, signEs256(key, hdr, claims(m -> tee(m).put("dbgstat", "disabled"))), BINDING, NOW).ok, "dbgstat disabled");
        assertDenied("tcb status not accepted", maa(okCfg, signEs256(key, hdr, claims(m -> tee(m).put("attester_tcb_status", "OutOfDate"))), BINDING, NOW),
            "TDX platform TCB status 'OutOfDate' is not accepted by policy");
        assertTrue(maa(okCfg, signEs256(key, hdr, claims(m -> tee(m).put("attester_tcb_status", "SWHardeningNeeded"))), BINDING, NOW).ok, "SWHardeningNeeded is a default status");
        assertDenied("policy statuses replace the default", maa(mcfg(pinHex, "{\"tdxMrtds\":[\"" + MRTD + "\"],\"tdxAllowedTcbStatuses\":[\"OutOfDate\"]}"), good, BINDING, NOW),
            "TDX platform TCB status 'UpToDate' is not accepted by policy");
        assertDenied("rtmr0 not allowed", maa(mcfg(pinHex, "{\"tdxMrtds\":[\"" + MRTD + "\"],\"tdxRtmrs\":[\"cc\"]}"), good, BINDING, NOW), "TDX RTMR0 not in policy allowlist");
        assertDenied("token expired", maa(okCfg, good, BINDING, NOW + 4_000_000), "MAA token expired");
        assertTrue(maa(okCfg, good, BINDING, NOW + 3_600_999).ok, "exp is inclusive at second resolution");
        assertDenied("token expired by one second", maa(okCfg, good, BINDING, NOW + 3_601_000), "MAA token expired");
        assertDenied("not yet valid", maa(okCfg, good, BINDING, NOW - 61_000), "MAA token not yet valid (nbf)");
        assertDenied("issued in the future", maa(okCfg, signEs256(key, hdr, claims(m -> {
            m.remove("nbf");
            m.put("iat", NOW / 1000 + 10);
        })), BINDING, NOW), "MAA token issued in the future (iat)");
        assertDenied("no exp", maa(okCfg, signEs256(key, hdr, claims(m -> m.remove("exp"))), BINDING, NOW), "token has no exp (cannot bound validity — fail closed)");
        assertDenied("issuer not configured", maa(okCfg, signEs256(key, hdr, claims(m -> m.put("iss", "https://x"))), BINDING, NOW),
            "token iss 'https://x' is not a configured trusted MAA instance");
        assertDenied("issuer not a string", maa(okCfg, signEs256(key, hdr, claims(m -> m.put("iss", 5L))), BINDING, NOW),
            "token iss 'undefined' is not a configured trusted MAA instance");
        assertDenied("isolation type unknown", maa(okCfg, signEs256(key, hdr, claims(m -> tee(m).put("x-ms-attestation-type", "vbs"))), BINDING, NOW),
            "unexpected x-ms-attestation-type 'vbs' (expected sevsnpvm | tdxvm)");
        assertDenied("isolation type absent", maa(okCfg, signEs256(key, hdr, claims(m -> tee(m).remove("x-ms-attestation-type"))), BINDING, NOW),
            "unexpected x-ms-attestation-type 'undefined' (expected sevsnpvm | tdxvm)");
        assertDenied("sevsnp token with only a TDX allowlist", maa(okCfg, signEs256(key, hdr, claims(m -> {
            tee(m).put("x-ms-attestation-type", "sevsnpvm");
            tee(m).put("x-ms-sevsnpvm-reportdata", AttestCommon.toHexLower(rawBinding(BINDING)));
        })), BINDING, NOW), "sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)");
        assertDenied("no report-data claim", maa(okCfg, signEs256(key, hdr, claims(m -> tee(m).remove("tdx_report_data"))), BINDING, NOW),
            "token carries no report-data claim to bind the PCA challenge");
        assertDenied("report-data not decodable", maa(okCfg, signEs256(key, hdr, claims(m -> tee(m).put("tdx_report_data", "!!!"))), BINDING, NOW),
            "report-data claim is not decodable (hex/base64)");
        assertDenied("no expected binding", maa(okCfg, good, null, NOW), "no expected attestation binding supplied");
        assertDenied("binding not constructible", maa(okCfg, good, new AttestationBinding(null, "g", 0, "n"), NOW), "binding not constructible: binding: holderPub required");
        // the report-data hash option binds H(binding)
        String hashed = signEs256(key, hdr, claims(m -> tee(m).put("tdx_report_data", AttestCommon.toHexLower(AttestCommon.sha256Sum(rawBinding(BINDING))))));
        assertTrue(maa(mcfg(pinHex, "{\"tdxMrtds\":[\"" + MRTD + "\"],\"reportDataHash\":\"sha256\"}"), hashed, BINDING, NOW).ok, "sha256 report data");
        assertDenied("hash option against the raw binding", maa(mcfg(pinHex, "{\"tdxMrtds\":[\"" + MRTD + "\"],\"reportDataHash\":\"sha256\"}"), good, BINDING, NOW),
            "report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)");
    }

    @Test
    void runtimeUserDataBinding() {
        Map<String, Object> c = mcfg(pinHex, "{\"tdxMrtds\":[\"" + MRTD + "\"],\"runtimeUserDataBinding\":true}");
        String ud = AttestCommon.toHexLower(rawBinding(BINDING));
        assertTrue(maa(c, signEs256(key, hdr, claims(m -> m.put("x-ms-runtime", obj("user-data", ud)))), BINDING, NOW).ok, "runtime user-data");
        assertDenied("no x-ms-runtime", maa(c, signEs256(key, hdr, claims(null)), BINDING, NOW),
            "token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)");
        assertDenied("no user-data", maa(c, signEs256(key, hdr, claims(m -> m.put("x-ms-runtime", obj()))), BINDING, NOW),
            "x-ms-runtime carries no user-data to bind the PCA challenge");
        AttestationBinding relay = new AttestationBinding("holder-key", "passport:abc", 1, "nonce-1");
        assertDenied("relayed user-data", maa(c, signEs256(key, hdr, claims(m -> m.put("x-ms-runtime", obj("user-data", ud)))), relay, NOW),
            "runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)");
    }

    @Test
    void signedSevSnpTokens() {
        String rd = AttestCommon.toHexLower(rawBinding(BINDING));
        Consumer<Map<String, Object>> base = m -> m.put("x-ms-isolation-tee", obj("x-ms-attestation-type", "sevsnpvm", "x-ms-sevsnpvm-reportdata", rd,
            "x-ms-sevsnpvm-launchmeasurement", MRTD.toUpperCase(), "x-ms-sevsnpvm-is-debuggable", false, "x-ms-sevsnpvm-snpfw-svn", 5L,
            "x-ms-sevsnpvm-hostdata", "ABCD"));
        String sev = signEs256(key, hdr, claims(base));
        HardwareResult r = maa(mcfg(pinHex, "{\"sevSnpMeasurements\":[\"" + MRTD + "\"],\"sevSnpMinTcb\":{\"snp\":5}}"), sev, BINDING, NOW);
        assertTrue(r.ok, "sev-snp baseline: " + r.reason);
        assertEquals("5", r.hostAsserted.get("snpfw_svn"));
        assertEquals("abcd", r.hostAsserted.get("host_data"));
        assertEquals("sevsnpvm", r.hostAsserted.get("attestation_type"));
        assertEquals(MRTD, r.measured.get("runtime_measurement"));
        assertDenied("svn floor", maa(mcfg(pinHex, "{\"sevSnpMeasurements\":[\"" + MRTD + "\"],\"sevSnpMinTcb\":{\"snp\":6}}"), sev, BINDING, NOW),
            "SEV-SNP snp SVN 5 is below the policy minimum 6");
        assertDenied("svn missing", maa(mcfg(pinHex, "{\"sevSnpMeasurements\":[\"" + MRTD + "\"],\"sevSnpMinTcb\":{\"tee\":1}}"), sev, BINDING, NOW),
            "SEV-SNP tee SVN claim 'x-ms-sevsnpvm-tee-svn' is missing or not a non-negative integer (policy requires a minimum)");
        assertDenied("measurement not allowed", maa(mcfg(pinHex, "{\"sevSnpMeasurements\":[\"cc\"]}"), sev, BINDING, NOW), "SEV-SNP launch measurement not in policy allowlist");
        assertDenied("host data not allowed", maa(mcfg(pinHex, "{\"sevSnpMeasurements\":[\"" + MRTD + "\"],\"sevSnpHostData\":[\"ef\"]}"), sev, BINDING, NOW),
            "SEV-SNP host-data not in policy allowlist");
        assertTrue(maa(mcfg(pinHex, "{\"sevSnpMeasurements\":[\"" + MRTD + "\"],\"sevSnpHostData\":[\"ABCD\"]}"), sev, BINDING, NOW).ok, "host data compared lower-case");
        String dbg = signEs256(key, hdr, claims(base.andThen(m -> tee(m).put("x-ms-sevsnpvm-is-debuggable", true))));
        assertDenied("debuggable", maa(mcfg(pinHex, "{\"sevSnpMeasurements\":[\"" + MRTD + "\"]}"), dbg, BINDING, NOW), "SEV-SNP guest is debuggable (no confidentiality)");
        assertTrue(maa(mcfg(pinHex, "{\"sevSnpMeasurements\":[\"" + MRTD + "\"],\"allowDebug\":true}"), dbg, BINDING, NOW).ok, "allowDebug");
        String noMeas = signEs256(key, hdr, claims(base.andThen(m -> tee(m).remove("x-ms-sevsnpvm-launchmeasurement"))));
        assertDenied("no launch measurement", maa(mcfg(pinHex, "{\"sevSnpMeasurements\":[\"" + MRTD + "\"]}"), noMeas, BINDING, NOW),
            "sevsnpvm token carries no launch-measurement claim");
    }

    @Test
    void rootCertificateAnchor() {
        // a chain leaf -> root where only the root certificate is configured (no SPKI pin)
        KeyPair root = AttestTestDer.ecKey("secp256r1");
        KeyPair leaf = AttestTestDer.ecKey("secp256r1");
        byte[] rootDer = AttestTestDer.cert("root", "root", root, root, AttestTestDer.basicConstraints(true, -1));
        byte[] leafDer = AttestTestDer.cert("leaf", "root", leaf, root);
        String pem = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(rootDer) + "\n-----END CERTIFICATE-----\n";
        Map<String, Object> c = cfg("{\"trustedIssuers\":[\"https://maa.test\"],\"trustAnchors\":{\"rootCertsPem\":[" + json(pem) + "]},\"policy\":{\"tdxMrtds\":[\"" + MRTD + "\"]}}");
        String b64Leaf = Base64.getEncoder().encodeToString(leafDer);
        String tok = signEs256(leaf, "{\"alg\":\"ES256\",\"x5c\":[\"" + b64Leaf + "\"]}", claims(null));
        assertTrue(run("azure-maa", c, obj("token", tok), BINDING, NOW).ok, "leaf signed by a configured root");
        String forged = signEs256(other(), "{\"alg\":\"ES256\",\"x5c\":[\"" + b64Leaf + "\"]}", claims(null));
        assertDenied("leaf key did not sign", run("azure-maa", c, obj("token", forged), BINDING, NOW), "JWS ES256 signature does not verify under the MAA signing key");
        byte[] stranger = AttestTestDer.cert("leaf", "root", leaf, other());
        String unanchored = signEs256(leaf, "{\"alg\":\"ES256\",\"x5c\":[\"" + Base64.getEncoder().encodeToString(stranger) + "\"]}", claims(null));
        assertDenied("leaf not signed by the root", run("azure-maa", c, obj("token", unanchored), BINDING, NOW),
            "MAA signing chain invalid: x5c chain does not anchor in a configured MAA trust root");
    }

    private static KeyPair other() { return AttestTestDer.ecKey("secp256r1"); }

    @Test
    void helpers() {
        assertEquals(3, AttestMaa.listLen(List.of(1, 2, 3)));
        assertEquals(2, AttestMaa.listLen("ab"));
        assertEquals(0, AttestMaa.listLen(null));
        assertEquals(0.0, AttestMaa.skewOf(cfg("{\"clockSkewMs\":-5}")));
        assertEquals(1500.0, AttestMaa.skewOf(cfg("{\"clockSkewMs\":1500}")));
        assertEquals(0.0, AttestMaa.skewOf(cfg("{\"clockSkewMs\":\"9\"}")));
        byte[] b = {1, 2, 3};
        assertEquals(32, AttestMaa.transformBinding(b, "sha256").length);
        assertEquals(64, AttestMaa.transformBinding(b, "sha512").length);
        assertSame(b, AttestMaa.transformBinding(b, ""));
        assertEquals("y", AttestMaa.firstString(obj("a", "", "b", "y"), "a", "b"));
        assertNull(AttestMaa.firstString(null, "a"));
    }
}
