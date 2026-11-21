package net.atlasauth.pca.springsecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import net.atlasauth.pca.ArgProvenance;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.spring.Protect;

@ExtendWith(SpringExtension.class)
@WebAppConfiguration
@org.springframework.test.context.ContextConfiguration(classes = PcaSecurityTest.App.class)
class PcaSecurityTest {
    @SuppressWarnings("unchecked")
    static Map<String, Object> read(String name) {
        try (InputStream in = PcaSecurityTest.class.getResourceAsStream(name)) {
            return (Map<String, Object>) Json.parseLenient(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static final Map<String, Object> PROOF = read("/proof.json");
    static final ArgProvenance.Recorder MEDIATOR = ArgProvenance.Recorder.create("refund-assistant", "k1");
    static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(Json.asLong(PROOF.get("now"))), ZoneOffset.UTC);

    static String b64(Object json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Json.canonicalizeStrict(json).getBytes(StandardCharsets.UTF_8));
    }

    static Authorize.Operation refund() {
        return Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 50L, "currency", "usd"));
    }

    static String provenance() { return b64(ArgProvenance.principalDirect(MEDIATOR, refund())); }

    @SuppressWarnings("unchecked")
    static PcaSecurity dsl() {
        Map<String, Map<String, Object>> byId = new java.util.HashMap<>();
        for (Object g : (List<Object>) Json.parseLenient(new String(readBytes("/grants.json"), StandardCharsets.UTF_8)))
            byId.put(String.valueOf(((Map<String, Object>) g).get("id")), (Map<String, Object>) g);
        Authorize.Options options = Protect.protect(new Protect.Config("payments-rs", (r, b) -> null).grants(byId::get)
            .clock(CLOCK).provenance(new ArgProvenance.Options().mediators(List.of(MEDIATOR.pin())))).options();
        return PcaSecurity.pca("payments-rs", byId::get, CLOCK, options,
            (request, body) -> "/refunds".equals(request.getRequestURI()) ? refund() : null);
    }

    static byte[] readBytes(String name) {
        try (InputStream in = PcaSecurityTest.class.getResourceAsStream(name)) {
            return in.readAllBytes();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @RestController
    static class RefundController {
        @PostMapping("/refunds")
        @PreAuthorize("@pca.hasVerb(authentication, 'payments.send')")
        Map<String, Object> refund() { return Map.of("refunded", 50); }
    }

    @Configuration
    @EnableWebMvc
    @EnableWebSecurity
    @EnableMethodSecurity
    static class App {
        @Bean RefundController refundController() { return new RefundController(); }
        @Bean PcaMethodSecurity pca() { return new PcaMethodSecurity(); }

        @Bean
        SecurityFilterChain chain(HttpSecurity http) throws Exception {
            http.csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .with(dsl(), Customizer.withDefaults())
                .authorizeHttpRequests(a -> a.anyRequest().authenticated());
            return http.build();
        }
    }

    @Autowired WebApplicationContext ctx;

    @Test void refusesMissingProofThenRunsTheSignedOperationOnceAndRefusesReplay() throws Exception {
        MockMvc mvc = MockMvcBuilders.webAppContextSetup(ctx).apply(springSecurity()).build();
        mvc.perform(post("/refunds").contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isUnauthorized())
            .andExpect(header().string("WWW-Authenticate", "PCA realm=\"pca\""));
        String h = b64(PROOF.get("pcactn"));
        mvc.perform(post("/refunds").header("PCA-Action", h).contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isForbidden()); // a refund without provenance escalates, it does not run
        mvc.perform(post("/refunds").header("PCA-Action", h).header("PCA-Provenance", provenance()).contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isOk()).andExpect(content().json("{\"refunded\":50}"));
        String replay = mvc.perform(post("/refunds").header("PCA-Action", h).header("PCA-Provenance", provenance()).contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isForbidden()).andReturn().getResponse().getContentAsString();
        assertTrue(replay.contains("replay:"), replay);
    }

    @Test void garbageProofIsRefusedAndNoContextLeaks() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/refunds");
        req.addHeader("PCA-Action", "!!not-base64!!");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        new PcaAuthenticationFilter(new ProviderManager(provider()), null).doFilter(req, res, chain);
        assertEquals(401, res.getStatus());
        assertNull(chain.getRequest(), "the chain must not run on a refusal");
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    static PcaAuthenticationProvider provider() {
        Map<String, Object> grants = Map.of();
        return new PcaAuthenticationProvider("payments-rs", ref -> grants.get(ref), CLOCK,
            new Authorize.Options(new net.atlasauth.pca.MemoryStateStore(), (p, g) -> Boolean.TRUE), (r, b) -> null);
    }

    @Test void authorityAndMethodSecurityHelperAreFailClosed() {
        PcaMethodSecurity m = new PcaMethodSecurity();
        assertFalse(m.hasVerb(null, "payments.send"));
        Authentication other = new org.springframework.security.authentication.TestingAuthenticationToken("u", "p", "PCA_payments.send");
        assertFalse(m.hasVerb(other, "payments.send"), "another kind of login never counts");
        assertFalse(m.hasVerb(new PcaAuthenticationToken(new MockHttpServletRequest()), "payments.send"));
        assertEquals("PCA_payments.send:payments/acme", PcaAuthenticationToken.verbAuthority("payments.send", "payments/acme"));
    }

    @Test void unauthenticatedTokenCannotBeMarkedAuthenticated() {
        PcaAuthenticationToken t = new PcaAuthenticationToken(new MockHttpServletRequest());
        try {
            t.setAuthenticated(true);
            org.junit.jupiter.api.Assertions.fail("must throw");
        } catch (IllegalArgumentException expected) {
            assertFalse(t.isAuthenticated());
        }
    }
}
