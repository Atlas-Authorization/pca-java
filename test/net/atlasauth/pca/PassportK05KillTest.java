package net.atlasauth.pca;

import static net.atlasauth.pca.PassportKillTest.body;
import static net.atlasauth.pca.PassportKillTest.evidence;
import static net.atlasauth.pca.PassportKillTest.good;
import static net.atlasauth.pca.PassportKillTest.identity;
import static net.atlasauth.pca.PassportKillTest.is;
import static net.atlasauth.pca.PassportKillTest.map;
import static net.atlasauth.pca.PassportKillTest.opts;
import static net.atlasauth.pca.PassportKillTest.signBody;
import static net.atlasauth.pca.PassportKillTest.soft;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** 0.5 mutation kills for {@link Passport} beyond PassportKillTest (same signed fixtures): exact reason codes. */
public class PassportK05KillTest {
    static final long NOW = PassportKillTest.NOW;
    static final long MAX_SAFE = 9007199254740991L;

    @SuppressWarnings("unchecked")
    static Map<String, Object> pp(Map<String, Object> s) { return (Map<String, Object>) s.get("passport"); }

    @Test void bindingAndDefaults() {
        Passport.Binding b = new Passport.Binding("h", "g", 7, "n");
        assertEquals("h", b.holderPub);
        assertEquals("g", b.grantRef);
        assertEquals(7L, b.epoch);
        assertEquals("n", b.nonce);
        Passport.Options o = new Passport.Options();
        assertEquals(List.of(), o.trustedIssuers);
        o.nowMs = NOW;
        o.revoked = (id, iss, sub) -> false;
        is("unknown_issuer", soft(), o); // the default trusts no issuer (and is a list, not null)
    }

    @Test void neverThrows() {
        is("malformed", soft(), null);
        Map<String, Object> s = soft();
        s.put("passport", "x");
        s.put("ver", 2L);
        is("malformed", s, opts()); // a non-object passport is malformed before the version
        s.remove("passport");
        is("malformed", s, opts());
    }

    @Test void emptyRequiredMembers() {
        for (String k : new String[] {"iss", "sub", "sig"}) {
            Map<String, Object> s = soft();
            s.put(k, "");
            is("malformed", s, opts());
        }
        Passport.Options o = opts();
        o.trustedIssuers = List.of(PassportKillTest.ISS, "");
        Map<String, Object> s = soft();
        s.put("iss", "");
        is("malformed", s, o);
        for (String k : new String[] {"model_id", "operator"}) {
            Map<String, Object> p = identity(false);
            p.put(k, "");
            is("malformed", signBody(body(p, null)), opts()); // id is the fingerprint of these very values
        }
        Map<String, Object> b = body(identity(false), null);
        pp(b).put("id", "");
        is("malformed", signBody(b), opts());
    }

    @Test void nonIntegerTimesAreMalformedBeforeTheIssuer() {
        Passport.Options o = opts();
        o.trustedIssuers = List.of("other");
        for (Object[] kv : new Object[][] {{"nbf", 500_000.0d}, {"exp", 2_000_000.0d}, {"iat", 500_000.0d}}) {
            Map<String, Object> s = soft();
            s.put((String) kv[0], kv[1]);
            is("malformed", s, o);
        }
        is("unknown_issuer", soft(), o);
    }

    @Test void clockRange() {
        Passport.Options o = opts();
        o.nowMs = MAX_SAFE;
        is("expired", soft(), o);
        o.nowMs = -MAX_SAFE;
        is("not_yet_valid", soft(), o);
        o.nowMs = -MAX_SAFE - 1;
        is("malformed", soft(), o);
        o.nowMs = MAX_SAFE + 1;
        is("malformed", soft(), o);
    }

    @Test void bodyThatIsNotStrictlyCanonical() {
        Map<String, Object> s = soft();
        s.put("note", "\uD800");
        is("malformed", s, opts());
    }

    @Test void evidenceShapes() {
        Passport.Options o = opts();
        o.attest = good();
        Map<String, Object> b = body(identity(true), null);
        b.put("evidence", "x");
        is("hardware_evidence_missing", signBody(b), o);
        b = body(identity(true), map("document", "x", "at", NOW));
        is("hardware_evidence_missing", signBody(b), o);
        b = body(identity(true), map("document", map("nonce", 5L), "at", NOW));
        is("hardware_evidence_missing", signBody(b), o);
        b = body(identity(true), map("document", map("nonce", "n"), "at", "now"));
        is("hardware_evidence_missing", signBody(b), o);
    }

    @Test void evidenceAgeEdges() {
        Passport.Options o = opts();
        o.attest = good();
        o.maxEvidenceAgeMs = 0L;
        is("", signBody(body(identity(true), evidence(NOW, "n"))), o);
        is("hardware_evidence_stale", signBody(body(identity(true), evidence(NOW - 1, "n"))), o);
        o.maxEvidenceAgeMs = -1L; // a negative window refuses even evidence inside the skew
        o.clockSkewMs = 10L;
        is("hardware_evidence_stale", signBody(body(identity(true), evidence(NOW + 5, "n"))), o);
        o.maxEvidenceAgeMs = 1L;
        is("", signBody(body(identity(true), evidence(NOW + 5, "n"))), o);
    }

    @Test void identityWithNullOrNonStringClaims() {
        Passport.Options o = opts();
        o.attest = good(); // measures identity(true): weights_digest "wd"
        Map<String, Object> p = identity(true);
        p.put("weights_digest", null);
        is("hardware_identity_mismatch", signBody(body(p, evidence(NOW, "n"))), o);
        for (String k : new String[] {"runtime_measurement", "system_prompt_digest", "tool_manifest_digest"}) {
            Map<String, Object> q = identity(true);
            q.put(k, "claimed");
            is("hardware_identity_mismatch", signBody(body(q, evidence(NOW, "n"))), o);
            Map<String, Object> m = identity(true);
            m.put(k, "claimed");
            Passport.Options o2 = opts();
            o2.attest = (d, bd) -> new Passport.Attestation(true, true, m);
            is("", signBody(body(q, evidence(NOW, "n"))), o2);
            Map<String, Object> m5 = identity(true);
            m5.put(k, 5L);
            o2.attest = (d, bd) -> new Passport.Attestation(true, true, m5);
            is("hardware_identity_mismatch", signBody(body(q, evidence(NOW, "n"))), o2);
        }
    }
}
