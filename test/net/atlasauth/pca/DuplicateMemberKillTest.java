package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import net.atlasauth.pca.payments.Rails;
import net.atlasauth.pca.sdjwt.Sdjwt;
import net.atlasauth.pca.vc.Vc;
import org.junit.jupiter.api.Test;

/**
 * Third-party signed JSON is refused when a member repeats (a last-wins parse and the signer's parse then disagree), and
 * number spellings stay as written. Keys are generated here and thrown away.
 */
public class DuplicateMemberKillTest {
    private static String b64u(String s) { return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8)); }

    // ---- Stripe webhook body ----

    private static java.util.Map<String, Object> send(String raw) {
        Rails.StripeWebhookOptions o = new Rails.StripeWebhookOptions();
        o.secret = "whsec_test";
        o.authorize = r -> { throw new AssertionError("must not be asked"); };
        o.nowSec = () -> 1000;
        return Rails.stripeIssuingWebhook(o, raw, Rails.signStripePayload(raw, "whsec_test", 1000));
    }

    @Test void stripeBodyDuplicateMemberIsBadJson() {
        java.util.Map<String, Object> r = send("{\"type\":\"x\",\"type\":\"issuing_authorization.request\"}");
        assertEquals("400", String.valueOf(r.get("status")));
        assertTrue(String.valueOf(r.get("body")).contains("bad_json"));
    }

    @Test void stripeBodyNonCanonicalNumbersStayAccepted() {
        assertEquals("200", String.valueOf(send("{\"type\":\"other\",\"amount\":8.0,\"n\":1e3}").get("status")));
    }

    // ---- SD-JWT issuer payload (the canonical gate refuses it first; the refusal names the duplicate) ----

    @Test void sdjwtIssuerPayloadDuplicateMemberIsRefused() {
        String sd = b64u("{\"alg\":\"EdDSA\"}") + "." + b64u("{\"_sd\":[],\"_sd\":[\"x\"]}") + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[64]) + "~";
        RuntimeException e = assertThrows(RuntimeException.class, () -> Sdjwt.present(sd, List.of(), new LinkedHashMap<>()));
        assertTrue(e.getMessage().contains("bad-json (duplicate key"), e.getMessage());
    }

    // ---- VC disclosures ----

    private static String vcWith(KeyPair kp, String disclosureText) throws Exception {
        String disclosure = b64u(disclosureText);
        String digest = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(disclosure.getBytes(StandardCharsets.US_ASCII)));
        String payload = "{\"vc\":{\"@context\":[\"" + Vc.VC_CONTEXT + "\",\"" + Vc.AGENT_PASSPORT_CONTEXT + "\"],\"type\":[\"VerifiableCredential\",\""
            + Vc.AGENT_PASSPORT_VC_TYPE + "\"],\"credentialSubject\":{\"id\":\"did:example:s\",\"passport_id\":\"p\",\"model_id\":\"m\",\"operator\":\"o\","
            + "\"hardware_rooted\":true,\"issued_at\":1,\"_sd\":[\"" + digest + "\"]}},\"_sd_alg\":\"sha-256\",\"iss\":\"did:example:i\",\"sub\":\"did:example:s\"}";
        String input = b64u("{\"alg\":\"EdDSA\",\"typ\":\"vc+sd-jwt\"}") + "." + b64u(payload);
        Signature sg = Signature.getInstance("Ed25519");
        sg.initSign(kp.getPrivate());
        sg.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(sg.sign()) + "~" + disclosure + "~";
    }

    private static byte[] rawPub(KeyPair kp) { byte[] x = kp.getPublic().getEncoded(); return Arrays.copyOfRange(x, x.length - 32, x.length); }

    @Test void vcDisclosureDuplicateMemberIsRefused() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> Vc.verifyPassportVC(vcWith(kp, "[\"s\",\"weights_digest\",{\"a\":1,\"a\":2}]"), rawPub(kp), null));
        assertEquals("pca-vc: malformed disclosure", e.getMessage());
    }

    @Test void vcDisclosureNonCanonicalNumbersStayAccepted() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        java.util.Map<String, Object> out = Vc.verifyPassportVC(vcWith(kp, "[8.0,\"weights_digest\",\"dd\"]"), rawPub(kp), null);
        assertEquals("dd", ((java.util.Map<?, ?>) out.get("passport")).get("weights_digest"));
        Vc.verifyPassportVC(vcWith(kp, "[1e3,\"weights_digest\",\"dd\"]"), rawPub(kp), null);
    }

    // ---- Sigstore entry body and statement ----

    @Test void sigstoreEntryBodyDuplicateMemberIsRefused() {
        for (String kind : new String[] {"dsse", "intoto"}) {
            SigstoreBaseKillTest.Bun b = new SigstoreBaseKillTest.Bun();
            b.kind = kind;
            b.bodyText = j -> "{\"kind\":\"x\"," + j.substring(1);
            SigstoreBaseKillTest.refused(b.build().verify(), "tlog_body", "fail closed: duplicate key \"kind\"");
        }
    }

    @Test void sigstoreStatementDuplicateMemberIsRefused() {
        SigstoreBaseKillTest.Bun b = new SigstoreBaseKillTest.Bun();
        b.payload = "{\"_type\":\"x\"," + b.payload.substring(1);
        SigstoreBaseKillTest.refused(b.build().verify(), "statement", "fail closed: duplicate key \"_type\"");
    }

    @Test void sigstoreNonCanonicalNumbersStayAccepted() {
        SigstoreBaseKillTest.Bun b = new SigstoreBaseKillTest.Bun();
        b.bodyText = j -> "{\"n\":8.0,\"e\":1e3," + j.substring(1);
        SigstoreBaseKillTest.accepted(b.build().verify());
        SigstoreBaseKillTest.Bun s = new SigstoreBaseKillTest.Bun();
        s.payload = "{\"n\":8.0,\"e\":1e3," + s.payload.substring(1);
        SigstoreBaseKillTest.accepted(s.build().verify());
    }
}
