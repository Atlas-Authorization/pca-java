package net.atlasauth.pca.springsecurity;

import java.time.Clock;
import java.util.Objects;

import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.servlet.GrantResolver;
import net.atlasauth.pca.servlet.PcaFilter;

/**
 * The {@code SecurityFilterChain} DSL: {@code http.with(PcaSecurity.pca(audience, resolver, options, operation), Customizer.withDefaults())}
 * (Spring Security 6.2+). Adds a {@link PcaAuthenticationFilter} before the authorization filter, so rules such as
 * {@code authorizeHttpRequests(a -> a.requestMatchers("/refunds").hasAuthority("PCA_payments.send"))} and
 * {@code @PreAuthorize("hasAuthority('PCA_payments.send')")} see the verified action. Use a stateless session policy; the
 * filter never writes a session.
 *
 * <p>Restrict which requests carry a proof with {@link #matching}; by default every request in the chain must (a request with no
 * proof is refused 401 before the authorization rules run).
 */
public final class PcaSecurity extends AbstractHttpConfigurer<PcaSecurity, HttpSecurity> {
    private final PcaAuthenticationProvider provider;
    private RequestMatcher matcher;

    private PcaSecurity(PcaAuthenticationProvider provider) { this.provider = Objects.requireNonNull(provider, "provider"); }

    /** The DSL for the given verifier settings (same arguments as {@code PcaInterceptor}). */
    public static PcaSecurity pca(String audience, GrantResolver resolver, Authorize.Options options, PcaFilter.OperationMapper operation) {
        return pca(audience, resolver, Clock.systemUTC(), options, operation);
    }

    public static PcaSecurity pca(String audience, GrantResolver resolver, Clock clock, Authorize.Options options, PcaFilter.OperationMapper operation) {
        return new PcaSecurity(new PcaAuthenticationProvider(audience, resolver, clock, options, operation));
    }

    /** The DSL around a provider you configured yourself (fresh_at, workflow step). */
    public static PcaSecurity pca(PcaAuthenticationProvider provider) { return new PcaSecurity(provider); }

    /** Only requests this matcher accepts are verified; the rest pass to the authorization rules. Default: all. */
    public PcaSecurity matching(RequestMatcher matcher) { this.matcher = matcher; return this; }

    @Override
    public void configure(HttpSecurity http) {
        http.addFilterBefore(new PcaAuthenticationFilter(new ProviderManager(provider), matcher), AuthorizationFilter.class);
    }
}
