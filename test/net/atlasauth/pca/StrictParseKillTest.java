package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.events.Events;
import net.atlasauth.pca.webbotauth.SignedDirectory;
import org.junit.jupiter.api.Test;

/** The event parser and the third-party JSON parsers refuse what the reference's strict or no-duplicate profile refuses (never looser). */
public class StrictParseKillTest {
    private static String eventText() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("at", new Json.Num("1700000000000"));
        data.put("grant_ref", "g1");
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("verb", "v");
        action.put("resource", "r");
        data.put("action", action);
        data.put("tier", new Json.Num("2"));
        return Events.serializeEvent(Events.buildStepUpEvent("step_up.approved", data));
    }

    @Test void aWellFormedEventParses() {
        assertNotNull(Events.parseEvent(eventText()));
    }

    @Test void parseEventRefusesWhatTheStrictProfileRefuses() {
        String ok = eventText();
        String[] bad = {
            ok.replace("\"tier\":2", "\"tier\":2.0"),                 // a trailing-zero fraction
            ok.replace("\"tier\":2", "\"tier\":2e0"),                 // an exponent
            ok.replace("\"at\":1700000000000", "\"at\":1.7e12"),      // an exponent
            ok.replace("{\"", "{\"grant_ref\":\"g0\",\""),            // a duplicate member (grant_ref twice)
            ok.replace("\"grant_ref\":\"g1\"", "\"grant_ref\":\"g\\ud800\""), // a lone surrogate (escaped)
        };
        for (String b : bad) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Events.parseEvent(b), b);
            assertTrue(e.getMessage().startsWith(Events.SYNTAX_PREFIX), e.getMessage());
        }
    }

    @Test void noDuplicatesRefusesADuplicateMemberOnlyAndSaysWhich() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Json.parseNoDuplicates("{\"keys\":[],\"keys\":[]}"));
        assertEquals("duplicate key \"keys\"", e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> Json.parseNoDuplicates("{\"a\":{\"b\":1,\"b\":2}}")); // nested
        assertNotNull(Json.parseNoDuplicates("{\"a\":1e3,\"b\":1.0}")); // numbers and the rest stay as lenient as JSON.parse
    }

    @Test void aKeyDirectoryWithADuplicateMemberIsRefused() {
        String dup = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"nyhMxDazvaOFgheJPwoXUUeByeYzQY0CCEXGg1KRPZg\",\"kid\":\"ka\"}],\"keys\":[]}";
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> SignedDirectory.parseKeyDirectory(dup));
        assertEquals("duplicate key \"keys\"", e.getMessage());
    }

    private static String seg(String json) { return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8)); }

    @Test void vendorJwtSegmentsRefuseDuplicatesAndNonJson() {
        String header = seg("{\"alg\":\"RS256\"}");
        for (String payload : new String[] {"{\"a\":1,\"a\":2}", "{\"a\":", "not json"}) {
            String token = header + "." + seg(payload) + ".c2ln";
            AttestException m = assertThrows(AttestException.class, () -> AttestVendorsApi.parseMaaJwt(token), payload);
            assertEquals("parseMaaJwt: malformed JSON segment: invalid JSON", m.getMessage(), payload);
            AttestException g = assertThrows(AttestException.class, () -> AttestVendorsApi.parseGcpCsJwt(token), payload);
            assertEquals("parseGcpCsJwt: malformed JSON segment: invalid JSON", g.getMessage(), payload);
        }
    }

    @Test void aSignedCollateralDocumentWithADuplicateMemberIsNotValidJson() {
        String text = "{\"tcbInfo\":{\"a\":1,\"a\":2},\"signature\":\"00\"}";
        assertEquals("tcbInfo document is not valid JSON", AttestIntelCollateral.verifySignedJson(text, "tcbInfo", null).reason);
    }
}
