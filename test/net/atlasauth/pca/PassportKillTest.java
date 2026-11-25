package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;

/** Exact-outcome tests of Passport.verify, one per reason code and boundary (signed with a throwaway key built at runtime). */
public class PassportKillTest {
    static final long NBF = 500_000L, EXP = 2_000_000L, NOW = 1_000_000L;
    static final Ed25519PrivateKeyParameters KEY = new Ed25519PrivateKeyParameters(new byte[32], 0);
    static final String ISS = Pca.b64(KEY.generatePublicKey().getEncoded());
    static final String SUB = Pca.b64(new Ed25519PrivateKeyParameters(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}, 0).generatePublicKey().getEncoded());

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }

    static Map<String, Object> identity(boolean hw) {
        return map("model_id", "m1", "operator", "op", "hardware_rooted", hw, "weights_digest", "wd", "weights_measured", true);
    }

    static String fingerprint(Map<String, Object> p) {
        Map<String, Object> fp = map("d", "atlas-pca/passport/v1", "operator", p.get("operator"), "hardware_rooted", p.get("hardware_rooted"));
        for (String k : new String[] {"model_id", "weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"})
            fp.put(k, p.containsKey(k) ? p.get(k) : null);
        return Pca.hashCanonical(fp);
    }

    static Map<String, Object> signBody(Map<String, Object> body) {
        byte[] msg = Pca.concat(Passport.SIG_DOMAIN, Json.canonicalizeStrict(body).getBytes(StandardCharsets.UTF_8));
        Ed25519Signer s = new Ed25519Signer();
        s.init(true, KEY);
        s.update(msg, 0, msg.length);
        Map<String, Object> out = new LinkedHashMap<>(body);
        out.put("sig", Pca.b64(s.generateSignature()));
        return out;
    }

    static Map<String, Object> body(Map<String, Object> p, Map<String, Object> evidence) {
        Map<String, Object> pp = new LinkedHashMap<>(p);
        pp.put("id", fingerprint(p));
        Map<String, Object> b = map("typ", "atlas-pca/passport", "ver", 1L, "passport", pp, "iss", ISS, "sub", SUB, "iat", NBF, "nbf", NBF, "exp", EXP);
        if (evidence != null) b.put("evidence", evidence);
        return b;
    }

    static Map<String, Object> soft() { return signBody(body(identity(false), null)); }

    static Map<String, Object> evidence(long at, String nonce) {
        return map("document", map("nonce", nonce), "at", at);
    }

    static Map<String, Object> hardware() { return signBody(body(identity(true), evidence(NOW, "n1"))); }

    static Passport.Options opts() {
        Passport.Options o = new Passport.Options();
        o.trustedIssuers = List.of(ISS);
        o.nowMs = NOW;
        o.revoked = (id, iss, sub) -> false;
        return o;
    }

    static Passport.Attest good() {
        return (d, b) -> new Passport.Attestation(true, true, identity(true));
    }

    static void is(String want, Object signed, Passport.Options o) { assertEquals(want, Passport.verify(signed, o)); }

    @Test void okAndMalformed() {
        is("", soft(), opts());
        is("malformed", null, opts());
        is("malformed", "x", opts());
        Map<String, Object> s = soft(); s.put("typ", "other"); is("malformed", s, opts());
        s = soft(); s.remove("passport"); is("malformed", s, opts());
        s = soft(); s.put("sub", ""); is("malformed", s, opts());
        s = soft(); s.put("sig", 5L); is("malformed", s, opts());
        s = soft(); s.remove("iat"); is("malformed", s, opts());
        Map<String, Object> b = body(identity(false), null); b.put("exp", NBF);
        is("malformed", signBody(b), opts());
        Map<String, Object> p = identity(false); p.put("hardware_rooted", "yes");
        b = body(p, null); is("malformed", signBody(b), opts());
        Passport.Options o = opts(); o.nowMs = 9007199254740992L; is("malformed", soft(), o);
    }

    @Test void versionSuiteIssuerSignature() {
        Map<String, Object> s = soft(); s.put("ver", 2L); is("unsupported_version", s, opts());
        s = soft(); s.remove("ver"); is("unsupported_version", s, opts());
        s = soft(); s.put("alg", "not-a-suite"); is("unsupported_suite", s, opts());
        Passport.Options o = opts(); o.trustedIssuers = List.of("other");
        is("unknown_issuer", soft(), o);
        s = soft(); s.put("sig", Pca.b64(new byte[64])); is("bad_signature", s, opts());
        s = soft(); ((Map<String, Object>) s.get("passport")).put("operator", "evil"); is("bad_signature", s, opts());
        Map<String, Object> b = body(identity(false), null);
        ((Map<String, Object>) b.get("passport")).put("id", "wrong");
        is("id_mismatch", signBody(b), opts());
    }

    @Test void validityWindowBoundaries() {
        Passport.Options o = opts();
        o.nowMs = NBF - 1; is("not_yet_valid", soft(), o);
        o.nowMs = NBF; is("", soft(), o);
        o.nowMs = EXP; is("expired", soft(), o);
        o.nowMs = EXP - 1; is("", soft(), o);
        o.clockSkewMs = 1_000_000_000L; // clamped to 60 s
        o.nowMs = NBF - 60_000; is("", soft(), o);
        o.nowMs = NBF - 60_001; is("not_yet_valid", soft(), o);
        o.nowMs = EXP + 59_999; is("", soft(), o);
        o.nowMs = EXP + 60_000; is("expired", soft(), o);
        o.clockSkewMs = -5L; o.nowMs = NBF - 1; is("not_yet_valid", soft(), o);
    }

    @Test void subjectAndRevocation() {
        Passport.Options o = opts(); o.subject = "someone-else"; is("subject_mismatch", soft(), o);
        o.subject = SUB; is("", soft(), o);
        o = opts(); o.revoked = null; is("revocation_unavailable", soft(), o);
        o.revoked = (id, iss, sub) -> { throw new IllegalStateException("down"); }; is("revocation_unavailable", soft(), o);
        o.revoked = (id, iss, sub) -> true; is("revoked", soft(), o);
        String[] seen = new String[3];
        o.revoked = (id, iss, sub) -> { seen[0] = id; seen[1] = iss; seen[2] = sub; return false; };
        Map<String, Object> s = soft(); is("", s, o);
        assertEquals(((Map<?, ?>) s.get("passport")).get("id"), seen[0]);
        assertEquals(ISS, seen[1]);
        assertEquals(SUB, seen[2]);
        // revocation is checked before the hardware branch
        o.revoked = (id, iss, sub) -> true; is("revoked", hardware(), o);
    }

    @Test void hardwareEvidenceShape() {
        Passport.Options o = opts();
        is("hardware_verifier_missing", hardware(), o);
        o.attest = good();
        is("", hardware(), o);
        is("hardware_evidence_missing", signBody(body(identity(true), null)), o);
        is("hardware_evidence_missing", signBody(body(identity(true), evidence(NOW, ""))), o);
        is("hardware_evidence_missing", signBody(body(identity(true), map("document", map("nonce", "n"))) ), o);
        is("hardware_evidence_missing", signBody(body(identity(true), map("at", NOW))), o);
    }

    @Test void hardwareEvidenceAge() {
        Passport.Options o = opts(); o.attest = good();
        is("", signBody(body(identity(true), evidence(NOW - Passport.DEFAULT_EVIDENCE_AGE_MS, "n"))), o);
        is("hardware_evidence_stale", signBody(body(identity(true), evidence(NOW - Passport.DEFAULT_EVIDENCE_AGE_MS - 1, "n"))), o);
        is("hardware_evidence_stale", signBody(body(identity(true), evidence(NOW + 1, "n"))), o); // future beyond zero skew
        o.clockSkewMs = 10L;
        is("", signBody(body(identity(true), evidence(NOW + 10, "n"))), o);
        is("hardware_evidence_stale", signBody(body(identity(true), evidence(NOW + 11, "n"))), o);
        o.maxEvidenceAgeMs = 5L;
        is("", signBody(body(identity(true), evidence(NOW - 5, "n"))), o);
        is("hardware_evidence_stale", signBody(body(identity(true), evidence(NOW - 6, "n"))), o);
        o.maxEvidenceAgeMs = -1L;
        is("hardware_evidence_stale", hardware(), o);
    }

    @Test void hardwareVerifierOutcomeAndIdentity() {
        Passport.Options o = opts();
        Passport.Binding[] got = new Passport.Binding[1];
        o.attest = (d, b) -> { got[0] = b; return new Passport.Attestation(true, true, identity(true)); };
        Map<String, Object> s = hardware();
        is("", s, o);
        assertNotNull(got[0]);
        assertEquals(SUB, got[0].holderPub);
        assertEquals("passport:" + ((Map<?, ?>) s.get("passport")).get("id"), got[0].grantRef);
        assertEquals(0L, got[0].epoch);
        assertEquals("n1", got[0].nonce);
        o.attest = (d, b) -> new Passport.Attestation(false, true, identity(true)); is("hardware_attestation_failed", hardware(), o);
        o.attest = (d, b) -> new Passport.Attestation(true, false, identity(true)); is("hardware_attestation_failed", hardware(), o);
        o.attest = (d, b) -> { throw new IllegalStateException("down"); }; is("hardware_attestation_failed", hardware(), o);
        o.attest = (d, b) -> null; is("hardware_attestation_failed", hardware(), o);
        o.attest = (d, b) -> new Passport.Attestation(true, true, null); is("hardware_identity_mismatch", hardware(), o);
        for (String k : new String[] {"model_id", "operator", "weights_digest"}) {
            Map<String, Object> m = identity(true); m.put(k, "different");
            o.attest = (d, b) -> new Passport.Attestation(true, true, m);
            is("hardware_identity_mismatch", hardware(), o);
            Map<String, Object> m2 = identity(true); m2.remove(k);
            o.attest = (d, b) -> new Passport.Attestation(true, true, m2);
            is("hardware_identity_mismatch", hardware(), o);
        }
        Map<String, Object> m = identity(true); m.put("weights_measured", false);
        o.attest = (d, b) -> new Passport.Attestation(true, true, m);
        is("hardware_identity_mismatch", hardware(), o);
        // a passport that states no weights claim is not held to the measured one
        Map<String, Object> p = map("model_id", "m1", "operator", "op", "hardware_rooted", true);
        Map<String, Object> mm = map("model_id", "m1", "operator", "op");
        o.attest = (d, b) -> new Passport.Attestation(true, true, mm);
        is("", signBody(body(p, evidence(NOW, "n"))), o);
    }

    @Test void integratorAttestWinsOverDefault() {
        Passport.Options o = opts();
        boolean[] usedDefault = {false};
        o.defaultHardware = now -> { usedDefault[0] = true; return (d, b) -> new Passport.Attestation(false, false, null); };
        o.attest = good();
        is("", hardware(), o);
        assertEquals(false, usedDefault[0]);
        o.attest = null;
        is("hardware_attestation_failed", hardware(), o);
        assertEquals(true, usedDefault[0]);
    }
}
