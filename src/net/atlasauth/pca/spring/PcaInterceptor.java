package net.atlasauth.pca.spring;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.servlet.HandlerInterceptor;

import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.servlet.GrantResolver;
import net.atlasauth.pca.servlet.PcaCore;
import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.servlet.PcaResult;

/**
 * A Spring MVC {@link HandlerInterceptor} that enforces Proof-Carrying Authority, sharing the same
 * {@link PcaCore} decision as {@link net.atlasauth.pca.servlet.PcaFilter}.
 *
 * <p>In {@code preHandle} it reads the PCActn from the {@code PCA-Action} header, resolves its {@code grant_ref},
 * and runs the existing verifier. On allow it sets the {@code "pca"} request attribute (a {@link PcaResult}) and
 * returns {@code true}; on failure it writes {@code 401}/{@code 403} with a {@code WWW-Authenticate} challenge and
 * returns {@code false}.
 *
 * <p>This interceptor uses the header transport only: it does not read the request body (reading it in
 * {@code preHandle} would consume it before a {@code @RequestBody} handler). For body-delivered PCActns register
 * {@link net.atlasauth.pca.servlet.PcaFilter}, which buffers the body.
 *
 * <p>0.5 default (breaking): the interceptor runs the full {@link Authorize#authorize} pipeline for the operation the
 * {@link PcaFilter.OperationMapper} derives from the request (the mapper gets an empty body: this interceptor never
 * reads it; map from the route and query, or use {@link PcaFilter}). Without authorize options every request is refused
 * with {@code 403 authorize_config}. Signature-only is an explicit opt-in: {@link #signatureOnly}. Giving both throws
 * {@link IllegalArgumentException} at construction.
 *
 * <p>Both {@code jakarta.servlet} and {@code spring-webmvc} are provided/optional dependencies.
 */
public final class PcaInterceptor implements HandlerInterceptor {

    public static final String ATTRIBUTE = PcaCore.ATTRIBUTE;

    private final String audience;
    private final GrantResolver resolver;
    private final Clock clock;
    private final Authorize.Options authorize;
    private final PcaFilter.OperationMapper operation;
    private final boolean signatureOnly;

    public PcaInterceptor(String audience, GrantResolver resolver) {
        this(audience, resolver, Clock.systemUTC());
    }

    /** Authorize mode with an empty option set: every request is refused with 403 {@code authorize_config}. */
    public PcaInterceptor(String audience, GrantResolver resolver, Clock clock) {
        this(audience, resolver, clock, null, null, false);
    }

    /** An interceptor that runs {@link Authorize#authorize} (see {@link PcaFilter}'s authorize constructor). */
    public PcaInterceptor(String audience, GrantResolver resolver, Clock clock, Authorize.Options authorize,
                          PcaFilter.OperationMapper operation) {
        this(audience, resolver, clock, Objects.requireNonNull(authorize, "authorize"), Objects.requireNonNull(operation, "operation"), false);
    }

    /** The explicit signature-only opt-in: only the core verifier runs; envelope, replay, revocation and operation are not enforced. */
    public static PcaInterceptor signatureOnly(String audience, GrantResolver resolver) {
        return signatureOnly(audience, resolver, Clock.systemUTC());
    }

    /** {@link #signatureOnly(String, GrantResolver)} with an explicit clock. */
    public static PcaInterceptor signatureOnly(String audience, GrantResolver resolver, Clock clock) {
        return new PcaInterceptor(audience, resolver, clock, null, null, true);
    }

    /** The full constructor; {@code signatureOnly} together with {@code authorize} or {@code operation} throws {@link IllegalArgumentException}. */
    public PcaInterceptor(String audience, GrantResolver resolver, Clock clock, Authorize.Options authorize,
                          PcaFilter.OperationMapper operation, boolean signatureOnly) {
        this.audience = Objects.requireNonNull(audience, "audience");
        this.resolver = Objects.requireNonNull(resolver, "resolver");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (signatureOnly && (authorize != null || operation != null))
            throw new IllegalArgumentException("signatureOnly cannot be combined with authorize options or an operation mapper");
        this.authorize = authorize;
        this.operation = operation;
        this.signatureOnly = signatureOnly;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String header = request.getHeader(PcaCore.HEADER);
        PcaResult result;
        if (!signatureOnly) {
            Authorize.Operation op = null; // no mapper: authorize refuses the missing operation (authorize_config)
            try {
                if (operation != null) op = operation.map(request, new byte[0]);
            } catch (RuntimeException e) {
                op = null; // fail closed: authorize refuses a missing operation
            }
            result = PcaCore.authorize(header, null, audience, clock.millis(), resolver, authorize, op, request.getHeader(PcaCore.ESCALATION_HEADER));
        } else {
            result = PcaCore.authorize(header, null, audience, clock.millis(), resolver);
        }
        if (result.allowed()) {
            request.setAttribute(ATTRIBUTE, result);
            return true;
        }
        response.reset();
        response.setStatus(result.status());
        response.setHeader("WWW-Authenticate", result.wwwAuthenticate());
        response.setContentType("application/json;charset=UTF-8");
        byte[] out = result.jsonBody().getBytes(StandardCharsets.UTF_8);
        response.setContentLength(out.length);
        response.getOutputStream().write(out);
        return false;
    }
}
