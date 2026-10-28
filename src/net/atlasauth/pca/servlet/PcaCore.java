package net.atlasauth.pca.servlet;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.K3;
import net.atlasauth.pca.Operations;
import net.atlasauth.pca.Pca;

/**
 * Transport-neutral core shared by {@link PcaFilter} and the Spring interceptor. It turns a {@code PCA-Action}
 * header and/or a request body into a {@link PcaResult} by running the existing {@link Pca} verifier. It depends on
 * nothing in {@code jakarta.servlet} / Spring, so the same decision is reachable from any HTTP integration.
 */
public final class PcaCore {
    private PcaCore() {}

    /** The request attribute the filter/interceptor set to the {@link PcaResult} on success. */
    public static final String ATTRIBUTE = "pca";

    /** The header carrying a base64url(JSON) PCActn. */
    public static final String HEADER = "PCA-Action";

    /**
     * Authorize one request. Exactly one PCActn source is consulted: the {@code pcaHeader} when present, otherwise
     * the JSON {@code body} (expected shape {@code {"pcactn": <PCActn>}}). Never throws.
     *
     * @param pcaHeader the raw {@code PCA-Action} header value, or {@code null}/empty if absent (a whitespace-only value is
     *                  present and refused: it is not strict base64url)
     * @param body      the request body bytes (only read when the header is absent), or {@code null}
     * @param audience  this resource server's audience; matched against the signed {@code aud}
     * @param now       current time in epoch milliseconds (from the configured clock)
     * @param resolver  maps the PCActn's {@code grant_ref} to its root capability
     */
    public static PcaResult authorize(String pcaHeader, byte[] body, String audience, long now, GrantResolver resolver) {
        Object d = decode(pcaHeader, body);
        if (d instanceof PcaResult) return (PcaResult) d;
        return verify(((Decoded) d).pcactn, audience, now, resolver, null);
    }

    /**
     * 0.5: the full {@link Authorize#authorize} pipeline for one request. The PCActn is read exactly as by
     * {@link #authorize(String, byte[], String, long, GrantResolver)} (an absent / undecodable one is the same 401); it is
     * then authorized for {@code operation} (what the handler will execute, from the server's own routing and parsed
     * body; null denies) with the {@code options} replay store, revocation check, plan mode, context and extra required
     * checks. Never throws.
     */
    public static PcaResult authorize(String pcaHeader, byte[] body, String audience, long now, GrantResolver resolver,
                                      Authorize.Options options, Authorize.Operation operation) {
        return authorize(pcaHeader, body, audience, now, resolver, options, operation, null);
    }

    /** The header carrying the principal's base64url(JSON) escalation answer. */
    public static final String ESCALATION_HEADER = "PCA-Escalation-Answer";

    /**
     * As above, with the {@code PCA-Escalation-Answer} header value ({@code escalationHeader}, may be null). The principal's
     * answer is read from that header (strict unpadded base64url of the JSON), else from the JSON body member
     * {@code escalation_answer}; an unreadable answer is no answer. Only consulted when {@code options} pins escalation
     * principals. A refusal then carries {@link PcaResult#decision()} {@code "escalate"} and the request in
     * {@link PcaResult#escalation()}. Never throws.
     */
    public static PcaResult authorize(String pcaHeader, byte[] body, String audience, long now, GrantResolver resolver,
                                      Authorize.Options options, Authorize.Operation operation, String escalationHeader) {
        return authorize(pcaHeader, body, audience, now, resolver, options, operation, escalationHeader, null, null, null, null);
    }

    /** The header carrying the base64url(JSON array) discharges for {@code needs_discharge} caveats. */
    public static final String DISCHARGES_HEADER = "PCA-Discharges";
    /** The header carrying the base64url(JSON) narrow block. */
    public static final String NARROW_HEADER = "PCA-Narrow";

    /** What {@link #presentedK1} read: {@code ok} with {@code value} ({@code discharges?}, {@code narrow?}), or an {@code error}. */
    public static final class PresentedK1 {
        public final boolean ok;
        public final Map<String, Object> value;
        public final String error;
        private PresentedK1(boolean ok, Map<String, Object> value, String error) { this.ok = ok; this.value = value; this.error = error; }
    }

    /**
     * The discharges and narrow block a request presents, from the raw header values (null or empty = absent). Strict unpadded
     * base64url of UTF-8, then strict JSON; {@code PCA-Discharges} must be a JSON array, {@code PCA-Narrow} may be any JSON value.
     * Never throws.
     */
    public static PresentedK1 presentedK1(String discharges, String narrow) {
        try {
            Map<String, Object> out = new LinkedHashMap<>();
            if (discharges != null && !discharges.isEmpty()) {
                String text = Pca.decodePcaHeader(discharges);
                if (text == null) return new PresentedK1(false, null, HEADER_BAD + DISCHARGES_HEADER);
                Object arr = Json.parse(text);
                if (!(arr instanceof List)) return new PresentedK1(false, null, DISCHARGES_HEADER + " must be a JSON array");
                out.put("discharges", arr);
            }
            if (narrow != null && !narrow.isEmpty()) {
                String text = Pca.decodePcaHeader(narrow);
                if (text == null) return new PresentedK1(false, null, HEADER_BAD + NARROW_HEADER);
                out.put("narrow", Json.parse(text));
            }
            return new PresentedK1(true, out, null);
        } catch (RuntimeException e) {
            return new PresentedK1(false, null, "unreadable discharge header: " + e.getMessage());
        }
    }

    private static final String HEADER_BAD = "not canonical base64url: ";

    /** {@link #presentedK1(String, String)} from a header map (names matched case-insensitively; conflicting spellings count as absent). */
    public static PresentedK1 presentedK1(Map<String, String> headers) {
        return presentedK1(headerValue(headers, DISCHARGES_HEADER), headerValue(headers, NARROW_HEADER));
    }

    private static String headerValue(Map<String, String> headers, String name) {
        String found = null;
        if (headers != null) for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey() == null || !e.getKey().equalsIgnoreCase(name)) continue;
            if (found != null && !found.equals(e.getValue())) return null;
            found = e.getValue();
        }
        return found;
    }

    /** The header carrying a side-carried {@code fresh_at} consistency token (JSON); read only when the PCActn has no {@code fresh_at} member. */
    public static final String FRESH_AT_HEADER = "pca-fresh-at";

    /** As above, with the raw {@code PCA-Discharges} / {@code PCA-Narrow} header values and no {@code fresh_at} policy. */
    public static PcaResult authorize(String pcaHeader, byte[] body, String audience, long now, GrantResolver resolver,
                                      Authorize.Options options, Authorize.Operation operation, String escalationHeader,
                                      String dischargesHeader, String narrowHeader) {
        return authorize(pcaHeader, body, audience, now, resolver, options, operation, escalationHeader, dischargesHeader, narrowHeader, null, null);
    }

    /** As above with the K3 {@code fresh_at} policy and {@code pca-fresh-at} header value, and no caveat-language headers. */
    public static PcaResult authorize(String pcaHeader, byte[] body, String audience, long now, GrantResolver resolver,
                                      Authorize.Options options, Authorize.Operation operation, String escalationHeader,
                                      K3.FreshAtPolicy freshAt, String freshAtHeader) {
        return authorize(pcaHeader, body, audience, now, resolver, options, operation, escalationHeader, null, null, freshAt, freshAtHeader);
    }

    /**
     * The full form: the raw {@code PCA-Discharges} / {@code PCA-Narrow} header values (read with {@link #presentedK1} and merged
     * under the options' own k1 only when {@code options} configures k1; unreadable headers are no discharges), and the K3
     * {@code fresh_at} policy ({@code freshAt}, null = none) with the {@code pca-fresh-at} header value ({@code freshAtHeader}, may be
     * null; read only when a policy is set and the PCActn has no member, an unparseable value is a null token, denied). Never throws.
     */
    public static PcaResult authorize(String pcaHeader, byte[] body, String audience, long now, GrantResolver resolver,
                                      Authorize.Options options, Authorize.Operation operation, String escalationHeader,
                                      String dischargesHeader, String narrowHeader, K3.FreshAtPolicy freshAt, String freshAtHeader) {
        return authorize(pcaHeader, body, audience, now, resolver, options, operation, escalationHeader, dischargesHeader, narrowHeader, freshAt, freshAtHeader, null);
    }

    /**
     * As above, with the workflow step this call is ({@code workflowStep}, from a per-request callback; null: read the JSON body
     * member {@code workflow} {commitment, receipts, step, units, goal_digest}, else none). Only consulted when {@code options}
     * has a workflow pin ({@link Authorize.Options#withWorkflow}); a body member that is not an object is a step that is refused.
     */
    public static PcaResult authorize(String pcaHeader, byte[] body, String audience, long now, GrantResolver resolver,
                                      Authorize.Options options, Authorize.Operation operation, String escalationHeader,
                                      String dischargesHeader, String narrowHeader, K3.FreshAtPolicy freshAt, String freshAtHeader,
                                      Authorize.WorkflowStep workflowStep) {
        Object d = decode(pcaHeader, body);
        Authorize.WorkflowStep ws = options == null || options.workflow() == null ? null : workflowStep != null ? workflowStep : workflowFromBody(body);
        if (d instanceof PcaResult) {
            // workflow required and no step: that refusal comes first, as in Authorize (it needs no PCActn)
            if (ws == null && options != null && options.workflow() != null && options.workflow().required)
                return PcaResult.ofAuthorization(options.run(null, operation, audience, resolver == null ? null : resolver::resolve, now), null);
            return (PcaResult) d;
        }
        K3.FreshAtPolicy fa = withSideCarried(freshAt, ((Decoded) d).pcactn, freshAtHeader);
        Authorize.AuthorizeResult r;
        if (options == null) {
            r = Authorize.authorize(((Decoded) d).pcactn, new Authorize.Input().operation(operation).audience(audience)
                .resolveGrant(resolver == null ? null : resolver::resolve).now(now).freshAt(fa));
        } else {
            Object answer = options.escalationPrincipals.isEmpty() ? null : escalationAnswer(escalationHeader, body);
            PresentedK1 pk = presentedK1(dischargesHeader, narrowHeader);
            r = options.run(((Decoded) d).pcactn, operation, audience, resolver == null ? null : resolver::resolve, now, answer, pk.ok ? pk.value : null, fa, ws);
        }
        return PcaResult.ofAuthorization(r, ((Decoded) d).pcactn);
    }

    /**
     * The HTTP status for an execution outcome: 200 for a commit (also when answered from the record), 500 for a failed function,
     * 409 for an aborted, in-flight or uncertain operation (retry later or reconcile), 403 for a refusal or a denial.
     */
    public static int operationStatus(Operations.ExecuteOutcome outcome) {
        if (outcome == null) return 403;
        switch (outcome.status) {
            case Operations.ExecuteOutcome.COMMITTED: return 200;
            case Operations.ExecuteOutcome.FAILED: return 500;
            case Operations.ExecuteOutcome.ABORTED:
            case Operations.ExecuteOutcome.PENDING:
            case Operations.ExecuteOutcome.UNCERTAIN: return 409;
            default: return 403;
        }
    }

    /** The JSON body for an execution outcome, as the shared vectors write it (a result that is not JSON is left out). */
    public static String operationBody(Operations.ExecuteOutcome outcome) {
        if (outcome == null) return "{\"status\":\"refused\"}";
        try {
            return Json.canonicalize(outcome.toMap());
        } catch (RuntimeException e) {
            Map<String, Object> m = outcome.toMap();
            m.remove("result");
            return Json.canonicalize(m);
        }
    }

    /** Signature-only mode with the K3 {@code fresh_at} policy and {@code pca-fresh-at} header value (see the authorize overload). */
    public static PcaResult authorizeSignatureOnly(String pcaHeader, byte[] body, String audience, long now, GrantResolver resolver,
                                                   K3.FreshAtPolicy freshAt, String freshAtHeader) {
        Object d = decode(pcaHeader, body);
        if (d instanceof PcaResult) return (PcaResult) d;
        return verify(((Decoded) d).pcactn, audience, now, resolver, withSideCarried(freshAt, ((Decoded) d).pcactn, freshAtHeader));
    }

    /** The policy with the side-carried header token, when a policy is set, the PCActn has no member and the policy carries none. */
    static K3.FreshAtPolicy withSideCarried(K3.FreshAtPolicy policy, Object pcactn, String header) {
        if (policy == null || policy.hasSideCarried || header == null || header.isEmpty()) return policy;
        if (pcactn instanceof Map && ((Map<?, ?>) pcactn).containsKey("fresh_at")) return policy;
        Object token;
        try {
            token = Json.parse(header);
        } catch (RuntimeException e) {
            token = null; // unparseable: a bad token (deny), not a missing one
        }
        return new K3.FreshAtPolicy(policy.signer, policy.scope, policy.local, policy.maxTokenAgeMs, policy.require, true, token);
    }

    /** The body member {@code workflow} as a step; null when there is none. A malformed member is a step with nothing in it (admission refuses it). */
    static Authorize.WorkflowStep workflowFromBody(byte[] body) {
        try {
            if (body == null || body.length == 0) return null;
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(body)).toString();
            Object env = Json.parse(text);
            Object w = env instanceof Map ? ((Map<?, ?>) env).get("workflow") : null;
            if (w == null) return null;
            if (!(w instanceof Map)) return new Authorize.WorkflowStep(null, null, null, null, null);
            Map<?, ?> m = (Map<?, ?>) w;
            Object step = m.get("step"), units = m.get("units"), goal = m.get("goal_digest");
            if (!(step instanceof String) || (units != null && !(units instanceof Map)) || (goal != null && !(goal instanceof String)))
                return new Authorize.WorkflowStep(null, null, null, null, null);
            @SuppressWarnings("unchecked") Map<String, ?> u = (Map<String, ?>) units;
            return new Authorize.WorkflowStep(m.get("commitment"), m.get("receipts"), (String) step, u, (String) goal);
        } catch (CharacterCodingException | RuntimeException e) {
            return null; // body unreadable: the PCActn decode refuses it first
        }
    }

    /** The escalation answer from the header, else the body member {@code escalation_answer}; null when absent or unreadable. */
    static Object escalationAnswer(String header, byte[] body) {
        try {
            if (header != null && !header.isEmpty()) {
                String text = Pca.decodePcaHeader(header);
                return text == null ? null : Json.parse(text);
            }
            if (body == null || body.length == 0) return null;
            String bodyText = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(body)).toString();
            Object env = Json.parse(bodyText);
            return env instanceof Map ? ((Map<?, ?>) env).get("escalation_answer") : null;
        } catch (CharacterCodingException | RuntimeException e) {
            return null;
        }
    }

    /** A decoded PCActn (a {@link Json#parse} tree). */
    private static final class Decoded {
        final Object pcactn;
        Decoded(Object pcactn) { this.pcactn = pcactn; }
    }

    /** The PCActn from the header or the body: a {@link Decoded}, or the {@link PcaResult} refusal. */
    private static Object decode(String pcaHeader, byte[] body) {
        if (pcaHeader != null && !pcaHeader.isEmpty()) {
            // Header transport: STRICT unpadded base64url -> STRICT UTF-8 JSON text -> strict decode inside the verifier
            // (0.4.1: nothing is trimmed or normalized; whitespace, padding, the standard alphabet or invalid UTF-8 => 401).
            String text = Pca.decodePcaHeader(pcaHeader);
            if (text == null) return PcaResult.of(PcaResult.Outcome.UNDECODABLE, HEADER + " is not canonical base64url");
            Object parsed;
            try {
                parsed = Json.parse(text);
            } catch (RuntimeException e) {
                return PcaResult.of(PcaResult.Outcome.UNDECODABLE, "PCActn is not strict JSON: " + e.getMessage());
            }
            return new Decoded(parsed);
        }

        if (body != null && body.length > 0) {
            // Body transport: {"pcactn": <PCActn>}.
            // STRICT UTF-8 (REPORT), the same decoder the header path uses: `new String(bytes, UTF_8)` silently replaced
            // malformed sequences with U+FFFD, so byte-distinct bodies decoded to the same text. Invalid UTF-8 => 401.
            String bodyText;
            try {
                bodyText = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(body)).toString();
            } catch (CharacterCodingException e) {
                return PcaResult.of(PcaResult.Outcome.UNDECODABLE, "request body is not valid UTF-8");
            }
            Object env;
            try {
                env = Json.parse(bodyText);
            } catch (RuntimeException e) {
                return PcaResult.of(PcaResult.Outcome.UNDECODABLE, "request body is not strict JSON: " + e.getMessage());
            }
            if (!(env instanceof Map)) return PcaResult.of(PcaResult.Outcome.ABSENT, "no PCActn in request");
            Object pcactn = ((Map<?, ?>) env).get("pcactn");
            if (pcactn == null) return PcaResult.of(PcaResult.Outcome.ABSENT, "no \"pcactn\" field in request body");
            return new Decoded(pcactn);
        }

        return PcaResult.of(PcaResult.Outcome.ABSENT, "no " + HEADER + " header and no PCActn body");
    }

    /** Resolve the grant from the decoded PCActn, then run the verifier. */
    private static PcaResult verify(Object pcactn, String audience, long now, GrantResolver resolver, K3.FreshAtPolicy freshAt) {
        String grantRef = null;
        if (pcactn instanceof Map) {
            Object gr = ((Map<?, ?>) pcactn).get("grant_ref");
            if (gr instanceof String) grantRef = (String) gr;
        }
        if (grantRef == null) return PcaResult.of(PcaResult.Outcome.UNKNOWN_GRANT, "PCActn has no grant_ref");

        Map<String, Object> grant;
        try {
            grant = resolver.resolve(grantRef);
        } catch (RuntimeException e) {
            // A throwing resolver is treated as "not found", never as an allow.
            return PcaResult.of(PcaResult.Outcome.UNKNOWN_GRANT, "grant resolver failed");
        }
        if (grant == null) return PcaResult.of(PcaResult.Outcome.UNKNOWN_GRANT, "no capability registered for grant_ref");

        Pca.Verdict v = Pca.verifyPcactn(pcactn, grant, now, audience, null, null, null, freshAt);
        PcaResult.Outcome outcome = v.allow ? PcaResult.Outcome.ALLOW : PcaResult.Outcome.DENIED;
        return new PcaResult(outcome, v, pcactn, v.reason);
    }
}
