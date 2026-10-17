package net.atlasauth.pca.servlet;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Map;

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
            return verify(parsed, audience, now, resolver);
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
            return verify(pcactn, audience, now, resolver);
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
