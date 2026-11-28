package example;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import net.atlasauth.pca.ArgProvenance;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Json;

@SpringBootTest
@AutoConfigureMockMvc
@Import(RefundsSmokeTest.FixedClock.class)
class RefundsSmokeTest {
    static final Map<String, Object> PROOF = load();

    @SuppressWarnings("unchecked")
    static Map<String, Object> load() {
        try (InputStream in = RefundsSmokeTest.class.getResourceAsStream("/proof.json")) {
            return (Map<String, Object>) Json.parseLenient(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The agent's provenance mediator: it records that the refund came straight from the principal's request. */
    static final ArgProvenance.Recorder MEDIATOR = ArgProvenance.Recorder.create("refund-assistant", "k1");

    /** The recorded proof was made at a fixed time, so the server's clock is pinned to it; the server pins the test mediator. */
    @TestConfiguration
    static class FixedClock {
        @Bean @Primary Clock clock() { return Clock.fixed(Instant.ofEpochMilli(Json.asLong(PROOF.get("now"))), ZoneOffset.UTC); }
        @Bean @Primary ArgProvenance.Options testProvenance() { return new ArgProvenance.Options().mediators(java.util.List.of(MEDIATOR.pin())); }
    }

    static String b64(Object json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Json.canonicalizeStrict(json).getBytes(StandardCharsets.UTF_8));
    }

    @Autowired MockMvc mvc;

    @Test void allowsTheSignedRefundThenRefusesTheReplayWithADocLink() throws Exception {
        String header = b64(PROOF.get("pcactn"));
        String body = "{\"amount\":50,\"currency\":\"usd\"}";
        // the principal asked for exactly this refund: a principal-direct provenance bundle
        Map<String, Object> bundle = ArgProvenance.principalDirect(MEDIATOR,
            Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 50L, "currency", "usd")));
        String provenance = b64(bundle);

        // without provenance a refund is not run: it escalates to the principal
        String escalated = mvc.perform(post("/refunds").header("PCA-Action", header).contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isForbidden())
            .andReturn().getResponse().getContentAsString();
        assertTrue(escalated.contains("provenance_flow:") && escalated.contains("\"decision\":\"escalate\""), escalated);

        mvc.perform(post("/refunds").header("PCA-Action", header).header("PCA-Provenance", provenance)
                .contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isOk())
            .andExpect(content().json("{\"refunded\":50,\"currency\":\"usd\"}"));

        String refusal = mvc.perform(post("/refunds").header("PCA-Action", header).header("PCA-Provenance", provenance)
                .contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isForbidden())
            .andReturn().getResponse().getContentAsString();
        assertTrue(refusal.contains("replay:"), refusal);
        assertTrue(refusal.contains("\"doc\":\"https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#replay\""), refusal);
    }
}
