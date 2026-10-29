package net.atlasauth.pca.servlet;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Objects;

import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.K3;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

/**
 * A {@link jakarta.servlet.Filter} that enforces Proof-Carrying Authority on every request it covers. It reads a
 * PCActn from the {@code PCA-Action} header (base64url(JSON)) or, failing that, a JSON body {@code {"pcactn":...}},
 * resolves its {@code grant_ref} to a root capability, and runs the existing {@link net.atlasauth.pca.Pca} verifier
 * (the eight offline checks: audience against the signed {@code aud}, cap chain rooted at the resolved grant, plan
 * inclusion, leaf signature, validity, counter_format, version, wire).
 *
 * <p>On allow it sets the {@code "pca"} request attribute (a {@link PcaResult} carrying the verdict and the decoded
 * PCActn) and continues the chain. On failure it writes {@code 401} (absent / undecodable / unknown grant) or
 * {@code 403} (denying verdict) with a {@code WWW-Authenticate: PCA realm="pca", ...} header and a small JSON body,
 * and does <em>not</em> continue the chain.
 *
 * <p>When the body transport is used the body is buffered so a downstream servlet can still read it.
 *
 * <p>0.5 default (breaking): the filter runs the full {@link Authorize#authorize} pipeline. Constructed with
 * {@link Authorize.Options} and an {@link OperationMapper}, the PCActn must authorize exactly the operation the mapper
 * derives from the request (verb, resource, params), the envelope predicates and caveats are enforced against it, the
 * revocation check must answer {@code false}, and the counter is consumed in the replay store. Any denial (including a
 * mapper that returns null or throws) is answered before the chain continues; on allow
 * {@link PcaResult#authorization()} carries the bound operation. Constructed without them, every request is refused
 * with {@code 403 authorize_config} naming the missing components: the filter never downgrades to signature-only.
 * Verifying the signature only is an explicit opt-in: {@link #signatureOnly}. Giving both the authorize options and
 * {@code signatureOnly} throws {@link IllegalArgumentException} at construction.
 *
 * <p>The guard options of {@link Authorize.Options} apply unchanged: {@code withApprovedGoal} (goal binding v3),
 * {@code withRevocationStaleness} with {@code withRevocationState} (an irreversible action needs a guardian-signed epoch
 * younger than the policy allows), {@code withRequireAssurance} (a high-assurance policy), {@code withPlans} (the plan
 * lifecycle) and {@code withIntentPolicy}. A refusal never reaches the chain and consumes nothing. An allowed request's
 * {@link PcaResult#execute} runs the side effect at most once with a durable record, and {@link #writeOperation} answers
 * with the outcome.
 *
 * <p>The {@code jakarta.servlet} API is a provided/optional dependency: this class is only loaded inside a servlet
 * container that already supplies it.
 */
public final class PcaFilter implements Filter {

    /** Request attribute holding the {@link PcaResult} after a successful verify. */
    public static final String ATTRIBUTE = PcaCore.ATTRIBUTE;

    private final String audience;
    private final GrantResolver resolver;
    private final Clock clock;
    private final Authorize.Options authorize;
    private final OperationMapper operation;
    private final boolean signatureOnly;
    private K3.FreshAtPolicy freshAt; // set once by withFreshAt before the filter is registered

    private java.util.function.Function<HttpServletRequest, Authorize.WorkflowStep> workflowStep; // set once before registering

    /**
     * Per-request workflow step callback, used when the {@link Authorize.Options} carry a workflow pin ({@code withWorkflow}); returns
     * null for "none". Without it the JSON body member {@code workflow} is read. A callback that throws is a step that is refused. Call before registering.
     */
    public PcaFilter withWorkflowStep(java.util.function.Function<HttpServletRequest, Authorize.WorkflowStep> workflowStep) {
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

    /**
     * Sets the K3 {@code fresh_at} consistency-token policy (default none) forwarded to the core verifier; the
     * {@code pca-fresh-at} request header is read as a side-carried token when the PCActn has no member. Call before registering.
     */
    public PcaFilter withFreshAt(K3.FreshAtPolicy freshAt) {
        this.freshAt = freshAt;
        return this;
    }

    /**
     * Maps a request to the operation the handler will execute (0.5 authorize option). {@code body} is the buffered
     * request body (never null; empty when there is none). Return null when the request names no operation: the filter
     * then denies.
     */
    @FunctionalInterface
    public interface OperationMapper {
        Authorize.Operation map(HttpServletRequest request, byte[] body);
    }

    /**
     * @param audience this resource server's audience; @param resolver grant_ref -> capability. With no authorize
     * options every request is refused with 403 {@code authorize_config}; use the options constructor, or
     * {@link #signatureOnly} to verify the signature only.
     */
    public PcaFilter(String audience, GrantResolver resolver) {
        this(audience, resolver, Clock.systemUTC());
    }

    /** @param clock the clock used for validity/skew checks (handy for tests). */
    public PcaFilter(String audience, GrantResolver resolver, Clock clock) {
        this(audience, resolver, clock, null, null, false);
    }

    /**
     * A filter that runs {@link Authorize#authorize} for every request: {@code authorize} holds the replay store,
     * the revocation check, the plan mode (default {@code "single-step"}), the context and extra required checks;
     * {@code operation} maps the request to what the handler will execute.
     */
    public PcaFilter(String audience, GrantResolver resolver, Clock clock, Authorize.Options authorize, OperationMapper operation) {
        this(audience, resolver, clock, Objects.requireNonNull(authorize, "authorize"), Objects.requireNonNull(operation, "operation"), false);
    }

    /**
     * The explicit signature-only opt-in: only the core verifier runs (signature, chain, audience, validity, plan
     * inclusion, counter_format). The envelope, replay, revocation and the operation binding are NOT enforced.
     */
    public static PcaFilter signatureOnly(String audience, GrantResolver resolver) {
        return signatureOnly(audience, resolver, Clock.systemUTC());
    }

    /** {@link #signatureOnly(String, GrantResolver)} with an explicit clock. */
    public static PcaFilter signatureOnly(String audience, GrantResolver resolver, Clock clock) {
        return new PcaFilter(audience, resolver, clock, null, null, true);
    }

    /**
     * The full constructor. {@code signatureOnly} together with {@code authorize} or {@code operation} is a
     * configuration error ({@link IllegalArgumentException}); with neither, the filter is in authorize mode with an
     * empty option set and refuses every request with 403 {@code authorize_config}.
     */
    public PcaFilter(String audience, GrantResolver resolver, Clock clock, Authorize.Options authorize, OperationMapper operation,
                     boolean signatureOnly) {
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
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        String header = req.getHeader(PcaCore.HEADER);
        if (!signatureOnly) {
            // the operation mapper reads the body, so it is always buffered (and re-readable downstream)
            byte[] buffered = req.getInputStream().readAllBytes();
            HttpServletRequest wrapped = new CachedBodyHttpServletRequest(req, buffered);
            Authorize.Operation op = null; // no mapper: authorize refuses the missing operation (authorize_config)
            try {
                if (operation != null) op = operation.map(wrapped, buffered);
            } catch (RuntimeException e) {
                op = null; // fail closed: authorize refuses a missing operation
            }
            PcaResult r = PcaCore.authorize(header, buffered, audience, clock.millis(), resolver, authorize, op, req.getHeader(PcaCore.ESCALATION_HEADER),
                req.getHeader(PcaCore.DISCHARGES_HEADER), req.getHeader(PcaCore.NARROW_HEADER),
                freshAt, req.getHeader(PcaCore.FRESH_AT_HEADER), stepOf(wrapped), req.getHeader(PcaCore.PROVENANCE_HEADER));
            if (r.allowed()) {
                wrapped.setAttribute(ATTRIBUTE, r);
                chain.doFilter(wrapped, resp);
            } else {
                writeChallenge(resp, r);
            }
            return;
        }
        byte[] body = null;
        HttpServletRequest downstream = req;
        if (header == null || header.isEmpty()) {
            // Only consume the body when we must; buffer it so downstream can read it again.
            body = req.getInputStream().readAllBytes();
            downstream = new CachedBodyHttpServletRequest(req, body);
        }

        PcaResult result = PcaCore.authorizeSignatureOnly(header, body, audience, clock.millis(), resolver, freshAt, req.getHeader(PcaCore.FRESH_AT_HEADER));
        if (result.allowed()) {
            downstream.setAttribute(ATTRIBUTE, result);
            chain.doFilter(downstream, resp);
        } else {
            writeChallenge(resp, result);
        }
    }

    /**
     * Answer a request with an execution outcome ({@link PcaResult#execute}): the status of {@link PcaCore#operationStatus} and
     * the JSON body of {@link PcaCore#operationBody}.
     */
    public static void writeOperation(HttpServletResponse resp, net.atlasauth.pca.Operations.ExecuteOutcome outcome) throws IOException {
        resp.setStatus(PcaCore.operationStatus(outcome));
        resp.setContentType("application/json;charset=UTF-8");
        byte[] out = PcaCore.operationBody(outcome).getBytes(StandardCharsets.UTF_8);
        resp.setContentLength(out.length);
        resp.getOutputStream().write(out);
    }

    private static void writeChallenge(HttpServletResponse resp, PcaResult result) throws IOException {
        resp.reset();
        resp.setStatus(result.status());
        resp.setHeader("WWW-Authenticate", result.wwwAuthenticate());
        resp.setContentType("application/json;charset=UTF-8");
        byte[] out = result.httpBody().getBytes(StandardCharsets.UTF_8);
        resp.setContentLength(out.length);
        resp.getOutputStream().write(out);
    }

    /** Wraps a request so its already-read body can be re-read by a downstream servlet. */
    private static final class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {
        private final byte[] body;

        CachedBodyHttpServletRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public ServletInputStream getInputStream() {
            final ByteArrayInputStream buf = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override public boolean isFinished() { return buf.available() == 0; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(ReadListener listener) { throw new UnsupportedOperationException(); }
                @Override public int read() { return buf.read(); }
                @Override public int read(byte[] b, int off, int len) { return buf.read(b, off, len); }
            };
        }

        @Override
        public BufferedReader getReader() {
            Charset cs = StandardCharsets.UTF_8;
            String enc = getCharacterEncoding();
            if (enc != null) {
                try { cs = Charset.forName(enc); } catch (RuntimeException ignored) { /* keep UTF-8 */ }
            }
            return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), cs));
        }

        @Override
        public int getContentLength() { return body.length; }

        @Override
        public long getContentLengthLong() { return body.length; }
    }
}
