package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import net.atlasauth.pca.webauthn.Webauthn;
import org.junit.jupiter.api.Test;

/**
 * Differential test of {@link Webauthn} against the TypeScript reference (test-data/ref-webauthn.json.gz): the COSE_Key reader,
 * authenticatorData header, step-up and approval challenges, Secure Payment Confirmation and the full assertion verifier.
 * A reference throw requires a throw. A verifyAssertion refusal reason is compared exactly, except the two engine-message tails.
 */
public class WebauthnDiffTest {
    static final String M = "ref-webauthn";

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    /** {"$bytes": b64u} members (at any depth) become byte[]. */
    @SuppressWarnings("unchecked")
    static Object rev(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(rev(x));
            return out;
        }
        if (v instanceof Map) {
            Map<String, Object> mm = (Map<String, Object>) v;
            if (mm.size() == 1 && mm.get("$bytes") instanceof String) return Keys.unb64u((String) mm.get("$bytes"));
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : mm.entrySet()) out.put(e.getKey(), rev(e.getValue()));
            return out;
        }
        return v;
    }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("MAX_AUTHENTICATOR_DATA_BYTES", Webauthn.MAX_AUTHENTICATOR_DATA_BYTES);
            r.put("MAX_CLIENT_DATA_BYTES", Webauthn.MAX_CLIENT_DATA_BYTES);
            r.put("MAX_SIGNATURE_BYTES", Webauthn.MAX_SIGNATURE_BYTES);
            return r;
        });
    }

    @Test void coseKeyToJwk() throws Exception {
        OracleCases.each(M, "coseKeyToJwk", a -> {
            Object x = rev(a.get(0));
            if (!(x instanceof byte[])) throw new IllegalArgumentException("coseKeyToJwk: expected a Uint8Array");
            return Webauthn.coseKeyToJwk((byte[]) x);
        });
    }

    @Test void parseAuthenticatorData() throws Exception {
        OracleCases.each(M, "parseAuthenticatorData", a -> {
            Object x = rev(a.get(0));
            Webauthn.ParsedAuthenticatorData p = x instanceof byte[] ? Webauthn.parseAuthenticatorData((byte[]) x) : null;
            return p == null ? null : p.toMap();
        });
    }

    @Test void buildStepUpChallenge() throws Exception {
        OracleCases.each(M, "buildStepUpChallenge", a -> Webauthn.buildStepUpChallenge(rev(a.get(0))));
    }

    @Test void stepUpChallengeB64u() throws Exception {
        OracleCases.each(M, "stepUpChallengeB64u", a -> Webauthn.stepUpChallengeB64u(rev(a.get(0))));
    }

    @Test void buildApprovalChallenge() throws Exception {
        OracleCases.each(M, "buildApprovalChallenge", a -> Webauthn.buildApprovalChallenge(rev(a.get(0)), a.get(1)));
    }

    @Test void approvalChallengeForActn() throws Exception {
        OracleCases.each(M, "approvalChallengeForActn", a -> Webauthn.approvalChallengeForActn(rev(a.get(0)), a.get(1)));
    }

    @Test void spcPaymentError() throws Exception {
        OracleCases.each(M, "spcPaymentError", a -> Webauthn.spcPaymentError(a.get(0), m(a.get(1)), (String) a.get(2)));
    }

    @Test void verifyAssertion() throws Exception {
        OracleCases.each(M, "verifyAssertion", a -> {
            Map<String, Object> assertion = m(rev(a.get(0)));
            Map<String, Object> expect = new LinkedHashMap<>(m(rev(a.get(1))));
            List<Object> calls = new ArrayList<>();
            if (expect.remove("hook") != null) {
                Consumer<Map<String, Object>> hook = calls::add;
                expect.put("onSignCountRegression", hook);
            }
            Map<String, Object> result = new LinkedHashMap<>(Webauthn.verifyAssertion(assertion, expect));
            if (result.get("reason") instanceof String) {
                result.put("reason", ((String) result.get("reason")).replaceAll("(?s)^(public key could not be resolved|verification error \\(fail closed\\)):.*$", "$1"));
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("result", result);
            out.put("hook", calls);
            return out;
        });
    }

    // ---- what the oracle does not pin ----

    @Test void neverThrowsOnNonsense() {
        Map<String, Object> r = Webauthn.verifyAssertion(new LinkedHashMap<>(), new LinkedHashMap<>());
        assertFalse((Boolean) r.get("ok"));
        assertEquals("authenticatorData is not bytes", r.get("reason"));
    }

    @Test void stepUpChallengeIsStableForABody() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ver", new Json.Num("2"));
        body.put("aud", "rs");
        byte[] a = Webauthn.buildStepUpChallenge(body);
        Map<String, Object> withSig = new LinkedHashMap<>(body);
        withSig.put("sig", "x");
        assertTrue(java.util.Arrays.equals(a, Webauthn.buildStepUpChallenge(withSig)), "sig is not part of the challenge");
        assertEquals(32, a.length);
    }
}
