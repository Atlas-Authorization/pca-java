package net.atlasauth.pca.boot;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.core.io.ResourceLoader;
import org.springframework.web.servlet.config.annotation.InterceptorRegistration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import net.atlasauth.pca.ArgProvenance;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.MemoryStateStore;
import net.atlasauth.pca.PcaJdbcStateStore;
import net.atlasauth.pca.StateStore;
import net.atlasauth.pca.servlet.GrantResolver;
import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.spring.PcaInterceptor;
import net.atlasauth.pca.spring.Protect;

/**
 * Wires the PCA guard from {@code pca.*} properties; every bean backs off to one you define. Active only once
 * {@code pca.audience} is set. You supply two things the SDK cannot guess: the {@link PcaFilter.OperationMapper} bean (the
 * operation YOUR route executes; null denies) and the accepted grants ({@code pca.grants-location} or a {@link GrantResolver}
 * bean). A missing one fails the startup: the guard never starts open. Same protection as {@link Protect}: authorize
 * pipeline, replay store, revocation, single-step plan, fail closed with 401/403.
 */
@AutoConfiguration(afterName = "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration")
@ConditionalOnClass(PcaInterceptor.class)
@ConditionalOnProperty(prefix = "pca", name = "enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnProperty(prefix = "pca", name = "audience")
@EnableConfigurationProperties(PcaProperties.class)
public class PcaAutoConfiguration {

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "pca", name = "store", havingValue = "memory", matchIfMissing = true)
    static class MemoryStore {
        @Bean
        @ConditionalOnMissingBean(StateStore.class)
        StateStore pcaStateStore() { return new MemoryStateStore(); }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "pca", name = "store", havingValue = "jdbc")
    @ConditionalOnBean(DataSource.class)
    static class JdbcStore {
        @Bean
        @ConditionalOnMissingBean(StateStore.class)
        StateStore pcaStateStore(DataSource dataSource, PcaProperties props) throws SQLException {
            // the DataSource constructor creates a SQLite file atomically; a custom table name needs the connection-factory form (no SQLite pre-open)
            String table = props.getJdbc().getTable();
            PcaJdbcStateStore store = PcaJdbcStateStore.TABLE.equals(table) ? new PcaJdbcStateStore(dataSource)
                : new PcaJdbcStateStore(dataSource::getConnection, table);
            if (props.getJdbc().isCreateTable()) store.createTable();
            return store;
        }
    }

    @Bean
    @ConditionalOnMissingBean(GrantResolver.class)
    GrantResolver pcaGrantResolver(PcaProperties props, ResourceLoader loader) throws IOException {
        String location = props.getGrantsLocation();
        if (location == null || location.isBlank())
            throw new IllegalStateException("pca.audience is set: give pca.grants-location or define a GrantResolver bean (the guard never starts without the grants it accepts)");
        String text;
        try (InputStream in = loader.getResource(location).getInputStream()) {
            text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        Object parsed = Json.parseLenient(text);
        if (!(parsed instanceof List<?> list)) throw new IllegalStateException("pca.grants-location must hold a JSON array of grants");
        Map<String, Map<String, Object>> byId = new HashMap<>();
        for (Object g : list) {
            @SuppressWarnings("unchecked")
            Map<String, Object> grant = (Map<String, Object>) g;
            byId.put(String.valueOf(grant.get("id")), grant);
        }
        return byId::get;
    }

    @Bean
    @ConditionalOnMissingBean(Protect.Protected.class)
    Protect.Protected pcaProtected(PcaProperties props, GrantResolver grants, StateStore store, PcaFilter.OperationMapper operation,
                                   ObjectProvider<Clock> clock, ObjectProvider<ArgProvenance.Options> provenance,
                                   ObjectProvider<Authorize.RevocationCheck> revocation) {
        Protect.Config c = new Protect.Config(props.getAudience(), operation).grants(grants).stateStore(store)
            .clock(clock.getIfAvailable(Clock::systemUTC));
        ArgProvenance.Options prov = provenance.getIfAvailable();
        if (prov != null) c.provenance(prov);
        Authorize.RevocationCheck rev = revocation.getIfAvailable();
        if (rev != null) c.isRevoked(rev);
        return Protect.protect(c);
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnProperty(prefix = "pca", name = "mode", havingValue = "interceptor", matchIfMissing = true)
    static class Mvc {
        @Bean
        @ConditionalOnMissingBean(PcaInterceptor.class)
        PcaInterceptor pcaInterceptor(Protect.Protected protection) { return protection.interceptor(); }

        @Bean
        @ConditionalOnMissingBean(name = "pcaWebMvcConfigurer")
        WebMvcConfigurer pcaWebMvcConfigurer(PcaInterceptor interceptor, PcaProperties props) {
            return new WebMvcConfigurer() {
                @Override
                public void addInterceptors(InterceptorRegistry registry) {
                    InterceptorRegistration r = registry.addInterceptor(interceptor).addPathPatterns(props.getPathPatterns());
                    if (!props.getExcludePathPatterns().isEmpty()) r.excludePathPatterns(props.getExcludePathPatterns());
                }
            };
        }
    }

    /** {@code pca.mode=security}: hand the application a {@code PcaSecurity} for {@code http.with(pcaSecurity, Customizer.withDefaults())}. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(net.atlasauth.pca.springsecurity.PcaSecurity.class)
    @ConditionalOnProperty(prefix = "pca", name = "mode", havingValue = "security")
    static class Security {
        @Bean
        @Scope("prototype") // a configurer instance belongs to one HttpSecurity
        @ConditionalOnMissingBean(net.atlasauth.pca.springsecurity.PcaSecurity.class)
        net.atlasauth.pca.springsecurity.PcaSecurity pcaSecurity(PcaProperties props, GrantResolver grants, PcaFilter.OperationMapper operation,
                                                                 Protect.Protected protection, ObjectProvider<Clock> clock) {
            return net.atlasauth.pca.springsecurity.PcaSecurity.pca(props.getAudience(), grants, clock.getIfAvailable(Clock::systemUTC),
                protection.options(), operation);
        }

        @Bean(name = "pca")
        @ConditionalOnMissingBean(net.atlasauth.pca.springsecurity.PcaMethodSecurity.class)
        net.atlasauth.pca.springsecurity.PcaMethodSecurity pcaMethodSecurity() { return new net.atlasauth.pca.springsecurity.PcaMethodSecurity(); }
    }
}
