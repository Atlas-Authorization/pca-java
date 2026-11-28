package net.atlasauth.pca.springsecurity;

import java.time.Clock;
import java.util.Objects;
import java.util.function.Function;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;

import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.K3;
import net.atlasauth.pca.servlet.GrantResolver;
import net.atlasauth.pca.servlet.PcaCore;
import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.servlet.PcaResult;

/**
 * Verifies a {@link PcaAuthenticationToken} with the same decision as {@code PcaInterceptor}: the full
 * {@link Authorize#authorize} pipeline for the operation the mapper derives from the request, bound to the {@code PCA-Action}
 * header (header transport only: the body is never read). A refusal throws {@link PcaAuthenticationException}; an
 * allow returns the authenticated token. A mapper that returns null or throws is a missing operation, which authorize refuses.
 */
public final class PcaAuthenticationProvider implements AuthenticationProvider {
    private final String audience;
    private final GrantResolver resolver;
    private final Clock clock;
    private final Authorize.Options authorize;
    private final PcaFilter.OperationMapper operation;
    private K3.FreshAtPolicy freshAt;
    private Function<HttpServletRequest, Authorize.WorkflowStep> workflowStep;

    public PcaAuthenticationProvider(String audience, GrantResolver resolver, Clock clock, Authorize.Options authorize,
                                     PcaFilter.OperationMapper operation) {
        this.audience = Objects.requireNonNull(audience, "audience");
        this.resolver = Objects.requireNonNull(resolver, "resolver");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.authorize = Objects.requireNonNull(authorize, "authorize");
        this.operation = Objects.requireNonNull(operation, "operation");
    }

    /** The K3 {@code fresh_at} policy forwarded to the core verifier. Call before use. */
    public PcaAuthenticationProvider withFreshAt(K3.FreshAtPolicy freshAt) { this.freshAt = freshAt; return this; }

    /** Per-request workflow step (see {@code PcaInterceptor#withWorkflowStep}). Call before use. */
    public PcaAuthenticationProvider withWorkflowStep(Function<HttpServletRequest, Authorize.WorkflowStep> workflowStep) {
        this.workflowStep = workflowStep;
        return this;
    }

    private Authorize.WorkflowStep stepOf(HttpServletRequest r) {
        if (workflowStep == null) return null;
        try {
            return workflowStep.apply(r);
        } catch (RuntimeException e) {
            return new Authorize.WorkflowStep(null, null, null, null, null); // fail closed: admission refuses it
        }
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        if (!(authentication instanceof PcaAuthenticationToken token) || token.isAuthenticated() || token.request() == null) return null;
        HttpServletRequest request = token.request();
        Authorize.Operation op = null; // no operation: authorize refuses it (authorize_config)
        try {
            op = operation.map(request, new byte[0]);
        } catch (RuntimeException e) {
            op = null;
        }
        PcaResult result = PcaCore.authorize(request.getHeader(PcaCore.HEADER), null, audience, clock.millis(), resolver, authorize, op,
            request.getHeader(PcaCore.ESCALATION_HEADER), request.getHeader(PcaCore.DISCHARGES_HEADER), request.getHeader(PcaCore.NARROW_HEADER),
            freshAt, request.getHeader(PcaCore.FRESH_AT_HEADER), stepOf(request), request.getHeader(PcaCore.PROVENANCE_HEADER));
        if (!result.allowed()) throw new PcaAuthenticationException(result);
        return PcaAuthenticationToken.authenticated(result);
    }

    @Override
    public boolean supports(Class<?> authentication) { return PcaAuthenticationToken.class.isAssignableFrom(authentication); }
}
