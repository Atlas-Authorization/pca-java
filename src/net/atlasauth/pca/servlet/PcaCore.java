package net.atlasauth.pca.servlet;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Json;
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
        return verify(((Decoded) d).pcactn, audience, now, resolver);
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
        Object d = decode(pcaHeader, body);
        if (d instanceof PcaResult) return (PcaResult) d;
        Authorize.AuthorizeResult r;
        if (options == null) {
            r = Authorize.authorize(((Decoded) d).pcactn, new Authorize.Input().operation(operation).audience(audience)
                .resolveGrant(resolver == null ? null : resolver::resolve).now(now));
        } else {
            Object answer = options.escalationPrincipals.isEmpty() ? null : escalationAnswer(escalationHeader, body);
            r = options.run(((Decoded) d).pcactn, operation, audience, resolver == null ? null : resolver::resolve, now, answer);
        }
        return PcaResult.ofAuthorization(r, ((Decoded) d).pcactn);
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
    private static PcaResult verify(Object pcactn, String audience, long now, GrantResolver resolver) {
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

        Pca.Verdict v = Pca.verifyPcactn(pcactn, grant, now, audience);
        PcaResult.Outcome outcome = v.allow ? PcaResult.Outcome.ALLOW : PcaResult.Outcome.DENIED;
        return new PcaResult(outcome, v, pcactn, v.reason);
    }
}
