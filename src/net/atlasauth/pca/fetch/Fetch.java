package net.atlasauth.pca.fetch;

import net.atlasauth.pca.Json;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.function.LongSupplier;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.servlet.GrantResolver;
import net.atlasauth.pca.servlet.PcaCore;
import net.atlasauth.pca.servlet.PcaResult;

/**
 * A transport-neutral request guard and a {@code java.net.http} helper for Proof-Carrying Authority, the Java counterpart of the
 * Fetch guard: any runtime that can hand over a method, a URL, headers and a body gets the same decisions as the servlet filter
 * (default-deny). The server side verifies the inbound PCActn ({@code PCA-Action: <base64url>} or a JSON body {@code {"pcactn": ...}}) with
 * {@link PcaCore} and calls the handler with the result on success, else answers 401 / 403 with a {@code WWW-Authenticate} challenge.
 * The client side attaches the PCActn header to an outgoing {@link HttpRequest}. Nothing here authorizes on its own: the verifier decides.
 *
 * <p>The default deny body is the reference's {@code {error, verdict, decision}} ({@link #referenceDenyBody}; {@code escalation} when the decision
 * has one); the servlet filter's body stays available as {@link PcaResult#httpBody()} through {@code withDenyBody}. Differences from the TypeScript
 * reference: the verdict carries {@code allow}, {@code checks} and {@code reasons} (no recomputed risk score or threshold); the guard modes are those
 * of the servlet filter (authorize with an operation mapper, or the explicit signature-only mode).
 */
public final class Fetch {
    private Fetch() {}

    /** The header carrying the base64url PCActn. */
    public static final String PCA_HEADER = PcaCore.HEADER;

    // ---- client ------------------------------------------------------------------------------------------------------------------------

    /** The header map that carries an encoded PCActn: {@code PCA-Action: base64url(utf8(encoded))}, unpadded. */
    public static Map<String, String> pcaHeaders(String encoded) {
        Map<String, String> h = new LinkedHashMap<>();
        h.put(PCA_HEADER, Base64.getUrlEncoder().withoutPadding().encodeToString(Json.utf8(encoded)));
        return h;
    }

    /** Attach the PCActn header to an outgoing request. */
    public static HttpRequest.Builder attach(HttpRequest.Builder request, String encoded) {
        for (Map.Entry<String, String> e : pcaHeaders(encoded).entrySet()) request.setHeader(e.getKey(), e.getValue());
        return request;
    }

    /** Send {@code request} with the PCActn header attached. */
    public static <T> HttpResponse<T> send(HttpClient client, HttpRequest.Builder request, String encoded, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        return client.send(attach(request, encoded).build(), handler);
    }

    // ---- server ------------------------------------------------------------------------------------------------------------------------

    /** The subset of an inbound request the guard reads. Header names match case-insensitively; the body may be empty but not null. */
    public static final class FetchRequest {
        public final String method;
        public final String url;
        public final Map<String, String> headers;
        public final byte[] body;
        public FetchRequest(String method, String url, Map<String, String> headers, byte[] body) {
            this.method = method;
            this.url = url;
            this.headers = headers == null ? Collections.<String, String>emptyMap() : headers;
            this.body = body == null ? new byte[0] : body;
        }

        /** The first header with this name (case-insensitive), or null. */
        public String header(String name) {
            for (Map.Entry<String, String> e : headers.entrySet()) if (e.getKey() != null && e.getKey().equalsIgnoreCase(name)) return e.getValue();
            return null;
        }
    }

    /** The response of a guarded handler or of a deny. */
    public static final class FetchResponse {
        public final int status;
        public final Map<String, String> headers;
        public final String body;
        public FetchResponse(int status, Map<String, String> headers, String body) { this.status = status; this.headers = headers; this.body = body; }
    }

    /** The guarded handler: called only when the proof verified, with the verdict and the PCActn in {@code pca}. */
    @FunctionalInterface
    public interface Handler { FetchResponse handle(FetchRequest request, PcaResult pca); }

    /**
     * Guard configuration. Use {@link #authorized} (the full pipeline for the operation the route executes, from your routing and parsed
     * body, never from the PCActn) or {@link #signatureOnly} (the explicit opt-in: signature, chain, audience, validity and plan inclusion only).
     */
    public static final class Options {
        final String audience;
        final GrantResolver resolver;
        final Authorize.Options authorize;
        final Function<FetchRequest, Authorize.Operation> operation;
        final boolean signatureOnly;
        LongSupplier now = System::currentTimeMillis;
        Function<PcaResult, String> denyBody;

        private Options(String audience, GrantResolver resolver, Authorize.Options authorize, Function<FetchRequest, Authorize.Operation> operation, boolean signatureOnly) {
            this.audience = audience; this.resolver = resolver; this.authorize = authorize; this.operation = operation; this.signatureOnly = signatureOnly;
        }

        public static Options signatureOnly(String audience, GrantResolver resolver) { return new Options(audience, resolver, null, null, true); }

        /** The authorize pipeline; a null mapper result (or a throw) denies. */
        public static Options authorized(String audience, GrantResolver resolver, Authorize.Options authorize, Function<FetchRequest, Authorize.Operation> operation) {
            if (authorize == null || operation == null) throw new IllegalArgumentException("authorized needs authorize options and an operation mapper");
            return new Options(audience, resolver, authorize, operation, false);
        }

        /** The clock (epoch ms) for the validity window; default the system clock. */
        public Options withClock(LongSupplier now) { this.now = now; return this; }

        /** Shape the 401 / 403 body (default {@link #referenceDenyBody}). */
        public Options withDenyBody(Function<PcaResult, String> denyBody) { this.denyBody = denyBody; return this; }
    }

    /** Build a verifier over a request. Returns the full result so you can compose it yourself; use {@link #withPCA} to wrap a handler. */
    public static Function<FetchRequest, PcaResult> createPcaFetchGuard(Options o) {
        if (o == null || o.audience == null || o.resolver == null) throw new IllegalArgumentException("audience and resolver are required");
        return req -> {
            String header = req.header(PcaCore.HEADER);
            if (o.signatureOnly) {
                return PcaCore.authorizeSignatureOnly(header, req.body, o.audience, o.now.getAsLong(), o.resolver, null, req.header(PcaCore.FRESH_AT_HEADER));
            }
            Authorize.Operation op = null; // a mapper that throws names no operation: authorize refuses
            try { op = o.operation.apply(req); } catch (RuntimeException e) { op = null; }
            return PcaCore.authorize(header, req.body, o.audience, o.now.getAsLong(), o.resolver, o.authorize, op, req.header(PcaCore.ESCALATION_HEADER),
                req.header(PcaCore.DISCHARGES_HEADER), req.header(PcaCore.NARROW_HEADER), null, req.header(PcaCore.FRESH_AT_HEADER), null, req.header(PcaCore.PROVENANCE_HEADER));
        };
    }

    /** The 401 / 403 answer for a refused request: JSON body and a {@code WWW-Authenticate} challenge. */
    public static FetchResponse denyResponse(PcaResult result, Function<PcaResult, String> denyBody) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("content-type", "application/json");
        headers.put("WWW-Authenticate", result.wwwAuthenticate());
        return new FetchResponse(result.status(), headers, denyBody != null ? denyBody.apply(result) : referenceDenyBody(result));
    }

    /** The reference's default 401 / 403 body: {@code {error, verdict, decision}} (+ {@code escalation}); {@code error} is the first reason, else {@code "forbidden"}. */
    public static String referenceDenyBody(PcaResult result) {
        Map<String, Object> verdict = new LinkedHashMap<>();
        java.util.List<Object> reasons = new java.util.ArrayList<>();
        if (result.verdict() != null) {
            verdict.put("allow", result.verdict().allow);
            verdict.put("checks", new LinkedHashMap<String, Object>(result.verdict().checks));
            if (!result.verdict().reason.isEmpty()) reasons.add(result.verdict().reason);
        } else {
            verdict.put("allow", false);
            verdict.put("checks", new LinkedHashMap<String, Object>());
            if (!result.detail().isEmpty()) reasons.add(result.detail());
        }
        verdict.put("reasons", reasons);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", reasons.isEmpty() ? "forbidden" : reasons.get(0));
        body.put("verdict", verdict);
        body.put("decision", result.decision());
        if (result.escalation() != null) body.put("escalation", result.escalation());
        return net.atlasauth.pca.Json.canonicalize(body);
    }

    /** Wrap a handler so the inbound PCActn is verified first; on success the handler runs with the result, else the deny response is returned. */
    public static Function<FetchRequest, FetchResponse> withPCA(Options o, Handler handler) {
        Function<FetchRequest, PcaResult> guard = createPcaFetchGuard(o);
        return req -> {
            PcaResult r = guard.apply(req);
            return r.allowed() ? handler.handle(req, r) : denyResponse(r, o.denyBody);
        };
    }
}
