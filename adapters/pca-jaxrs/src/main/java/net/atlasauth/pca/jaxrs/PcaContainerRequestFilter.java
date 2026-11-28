package net.atlasauth.pca.jaxrs;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Objects;
import java.util.function.Function;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.K3;
import net.atlasauth.pca.servlet.GrantResolver;
import net.atlasauth.pca.servlet.PcaCore;
import net.atlasauth.pca.servlet.PcaResult;

/**
 * Jakarta REST (JAX-RS) filter enforcing Proof-Carrying Authority, with the protection semantics of {@code PcaInterceptor}:
 * the full {@link Authorize#authorize} pipeline for the operation the mapper derives from the request, header transport
 * ({@code PCA-Action}; the entity is never read), fail closed. A refusal aborts the request with {@code 401}/{@code 403}, the
 * {@code WWW-Authenticate} challenge and the JSON body; an allow sets the {@code "pca"} request property to the
 * {@link PcaResult}. Annotate the filter class (done here) and your resources with {@link PcaProtected} to bind it.
 *
 * <p>It has constructor arguments, so it is not auto-discovered: register an instance
 * ({@code register(new PcaContainerRequestFilter(...))} or return it from {@code Application#getSingletons}).
 * It runs at {@code Priorities.AUTHENTICATION}. The mapper must not rely on the entity: derive the operation from the path, query and headers.
 */
@PcaProtected
@Priority(Priorities.AUTHENTICATION)
public final class PcaContainerRequestFilter implements ContainerRequestFilter {
    /** The request property holding the {@link PcaResult} after an allow. */
    public static final String PROPERTY = PcaCore.ATTRIBUTE;

    /** Maps a request to the operation the resource method will execute; null (or a throw) denies. */
    @FunctionalInterface
    public interface OperationMapper {
        Authorize.Operation map(ContainerRequestContext request);
    }

    private final String audience;
    private final GrantResolver resolver;
    private final Clock clock;
    private final Authorize.Options authorize;
    private final OperationMapper operation;
    private K3.FreshAtPolicy freshAt;
    private Function<ContainerRequestContext, Authorize.WorkflowStep> workflowStep;

    public PcaContainerRequestFilter(String audience, GrantResolver resolver, Authorize.Options authorize, OperationMapper operation) {
        this(audience, resolver, Clock.systemUTC(), authorize, operation);
    }

    public PcaContainerRequestFilter(String audience, GrantResolver resolver, Clock clock, Authorize.Options authorize, OperationMapper operation) {
        this.audience = Objects.requireNonNull(audience, "audience");
        this.resolver = Objects.requireNonNull(resolver, "resolver");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.authorize = Objects.requireNonNull(authorize, "authorize");
        this.operation = Objects.requireNonNull(operation, "operation");
    }

    /** The K3 {@code fresh_at} policy forwarded to the core verifier. Call before registering. */
    public PcaContainerRequestFilter withFreshAt(K3.FreshAtPolicy freshAt) { this.freshAt = freshAt; return this; }

    /** Per-request workflow step (see {@code PcaInterceptor#withWorkflowStep}); a callback that throws is a refused step. Call before registering. */
    public PcaContainerRequestFilter withWorkflowStep(Function<ContainerRequestContext, Authorize.WorkflowStep> workflowStep) {
        this.workflowStep = workflowStep;
        return this;
    }

    private Authorize.WorkflowStep stepOf(ContainerRequestContext r) {
        if (workflowStep == null) return null;
        try {
            return workflowStep.apply(r);
        } catch (RuntimeException e) {
            return new Authorize.WorkflowStep(null, null, null, null, null); // fail closed: admission refuses it
        }
    }

    @Override
    public void filter(ContainerRequestContext request) {
        Authorize.Operation op = null; // no operation: authorize refuses it (authorize_config)
        try {
            op = operation.map(request);
        } catch (RuntimeException e) {
            op = null;
        }
        PcaResult result = PcaCore.authorize(request.getHeaderString(PcaCore.HEADER), null, audience, clock.millis(), resolver, authorize, op,
            request.getHeaderString(PcaCore.ESCALATION_HEADER), request.getHeaderString(PcaCore.DISCHARGES_HEADER),
            request.getHeaderString(PcaCore.NARROW_HEADER), freshAt, request.getHeaderString(PcaCore.FRESH_AT_HEADER), stepOf(request),
            request.getHeaderString(PcaCore.PROVENANCE_HEADER));
        if (result.allowed()) {
            request.setProperty(PROPERTY, result);
            return;
        }
        request.abortWith(Response.status(result.status())
            .header(HttpHeaders.WWW_AUTHENTICATE, result.wwwAuthenticate())
            .type("application/json;charset=UTF-8")
            .entity(Json.utf8(result.httpBody()))
            .build());
    }
}
