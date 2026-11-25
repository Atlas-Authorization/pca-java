package net.atlasauth.pca.boot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import net.atlasauth.pca.ArgProvenance;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.MemoryStateStore;
import net.atlasauth.pca.PcaJdbcStateStore;
import net.atlasauth.pca.StateStore;
import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.spring.PcaInterceptor;

class PcaAutoConfigurationTest {
    @SuppressWarnings("unchecked")
    static final Map<String, Object> PROOF = parse("/proof.json");
    static final ArgProvenance.Recorder MEDIATOR = ArgProvenance.Recorder.create("refund-assistant", "k1");
    static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(Json.asLong(PROOF.get("now"))), ZoneOffset.UTC);

    @SuppressWarnings("unchecked")
    static Map<String, Object> parse(String name) {
        try (InputStream in = PcaAutoConfigurationTest.class.getResourceAsStream(name)) {
            return (Map<String, Object>) Json.parseLenient(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String b64(Object json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Json.canonicalizeStrict(json).getBytes(StandardCharsets.UTF_8));
    }

    static Authorize.Operation refund() {
        return Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 50L, "currency", "usd"));
    }

    @Configuration(proxyBeanMethods = false)
    static class UserConfig {
        @Bean PcaFilter.OperationMapper operation() { return (r, b) -> "/refunds".equals(r.getRequestURI()) ? refund() : null; }
        @Bean Clock clock() { return CLOCK; }
        @Bean ArgProvenance.Options provenance() { return new ArgProvenance.Options().mediators(List.of(MEDIATOR.pin())); }
    }

    @RestController
    static class RefundController {
        @PostMapping("/refunds") Map<String, Object> refund() { return Map.of("refunded", 50); }
    }

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(PcaAutoConfiguration.class))
        .withUserConfiguration(UserConfig.class);

    @Test void backsOffWithoutAnAudience() {
        runner.run(ctx -> assertEquals(0, ctx.getBeansOfType(PcaInterceptor.class).size()));
    }

    @Test void backsOffWhenDisabled() {
        runner.withPropertyValues("pca.enabled=false", "pca.audience=payments-rs", "pca.grants-location=classpath:grants.json")
            .run(ctx -> assertEquals(0, ctx.getBeansOfType(PcaInterceptor.class).size()));
    }

    @Test void failsStartupWithoutGrants() {
        runner.withPropertyValues("pca.audience=payments-rs").run(ctx -> assertNotNull(ctx.getStartupFailure()));
    }

    @Test void failsStartupWithoutAnOperationMapper() {
        new WebApplicationContextRunner().withConfiguration(AutoConfigurations.of(PcaAutoConfiguration.class))
            .withPropertyValues("pca.audience=payments-rs", "pca.grants-location=classpath:grants.json")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
    }

    @Test void wiresMemoryStoreAndInterceptorFromProperties() {
        runner.withPropertyValues("pca.audience=payments-rs", "pca.grants-location=classpath:grants.json").run(ctx -> {
            assertNull(ctx.getStartupFailure());
            assertInstanceOf(MemoryStateStore.class, ctx.getBean(StateStore.class));
            assertNotNull(ctx.getBean(PcaInterceptor.class));
        });
    }

    private static void assertNull(Throwable t) { org.junit.jupiter.api.Assertions.assertNull(t); }

    @Test void userBeansWin() {
        StateStore mine = new MemoryStateStore();
        PcaInterceptor myInterceptor = PcaInterceptor.signatureOnly("payments-rs", ref -> null);
        runner.withPropertyValues("pca.audience=payments-rs", "pca.grants-location=classpath:grants.json")
            .withBean("mine", StateStore.class, () -> mine).withBean("myInterceptor", PcaInterceptor.class, () -> myInterceptor)
            .run(ctx -> {
                assertSame(mine, ctx.getBean(StateStore.class));
                assertSame(myInterceptor, ctx.getBean(PcaInterceptor.class));
            });
    }

    @Test void jdbcStoreNeedsADataSource() {
        runner.withPropertyValues("pca.audience=payments-rs", "pca.grants-location=classpath:grants.json", "pca.store=jdbc")
            .run(ctx -> assertNotNull(ctx.getStartupFailure())); // no StateStore: the guard never starts on a silent memory fallback
    }

    @Test void jdbcStoreFromTheApplicationDataSource(@TempDir Path dir) {
        org.sqlite.SQLiteDataSource ds = new org.sqlite.SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + dir.resolve("pca.db"));
        runner.withPropertyValues("pca.audience=payments-rs", "pca.grants-location=classpath:grants.json", "pca.store=jdbc", "pca.jdbc.create-table=true")
            .withBean(DataSource.class, () -> ds)
            .run(ctx -> assertInstanceOf(PcaJdbcStateStore.class, ctx.getBean(StateStore.class)));
    }

    @Test void securityModeExposesPcaSecurityAndNoInterceptor() {
        runner.withPropertyValues("pca.audience=payments-rs", "pca.grants-location=classpath:grants.json", "pca.mode=security").run(ctx -> {
            assertEquals(0, ctx.getBeansOfType(PcaInterceptor.class).size());
            assertNotNull(ctx.getBean(net.atlasauth.pca.springsecurity.PcaSecurity.class));
            assertNotNull(ctx.getBean("pca"));
        });
    }

    @Test void theWiredInterceptorRefusesWithoutProofAndRunsTheSignedOperationOnce() {
        runner.withPropertyValues("pca.audience=payments-rs", "pca.grants-location=classpath:grants.json").run(ctx -> {
            MockMvc mvc = MockMvcBuilders.standaloneSetup(new RefundController()).addInterceptors(ctx.getBean(PcaInterceptor.class)).build();
            mvc.perform(post("/refunds").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized()).andExpect(header().string("WWW-Authenticate", "PCA realm=\"pca\""));
            String h = b64(PROOF.get("pcactn"));
            String prov = b64(ArgProvenance.principalDirect(MEDIATOR, refund()));
            mvc.perform(post("/refunds").header("PCA-Action", h).header("PCA-Provenance", prov).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isOk());
            String replay = mvc.perform(post("/refunds").header("PCA-Action", h).header("PCA-Provenance", prov).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isForbidden()).andReturn().getResponse().getContentAsString();
            assertTrue(replay.contains("replay:"), replay);
        });
    }
}
