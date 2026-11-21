package net.atlasauth.pca.acp;

import static net.atlasauth.pca.acp.AcpJs.def;
import static net.atlasauth.pca.acp.AcpJs.get;
import static net.atlasauth.pca.acp.AcpJs.isObj;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.oauth.JsVal;

/**
 * x402 v2 HTTP transport: three headers, each the base64 of a JSON object. {@code PAYMENT-REQUIRED} (see {@link X402V2}),
 * {@code PAYMENT-SIGNATURE} (client to server, the PaymentPayload) and {@code PAYMENT-RESPONSE} (server to client, the SettlementResponse).
 * No I/O.
 */
public final class X402Http {
    private X402Http() {}

    public static final String X402_PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE";
    public static final String X402_PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE";
    /** The HTTP status for each x402 outcome. */
    public static final int STATUS_PAYMENT_REQUIRED = 402;
    public static final int STATUS_MALFORMED = 400;
    public static final int STATUS_FAILED = 402;
    public static final int STATUS_INTERNAL_ERROR = 500;
    public static final int STATUS_SETTLED = 200;
    /** The HTTP status per x402 outcome, keyed by the outcome name. */
    public static final Map<String, Integer> X402_HTTP_STATUS;
    static {
        Map<String, Integer> m = new java.util.LinkedHashMap<>();
        m.put("payment_required", STATUS_PAYMENT_REQUIRED);
        m.put("malformed", STATUS_MALFORMED);
        m.put("failed", STATUS_FAILED);
        m.put("internal_error", STATUS_INTERNAL_ERROR);
        m.put("settled", STATUS_SETTLED);
        X402_HTTP_STATUS = java.util.Collections.unmodifiableMap(m);
    }

    private static final Pattern ATOMIC = Pattern.compile("0|[1-9][0-9]*");

    /** Problems with a v2 {@code PaymentPayload} (empty = valid). */
    public static List<String> paymentPayloadV2Problems(Object p) {
        List<String> out = new ArrayList<>();
        if (!isObj(p)) { out.add("PaymentPayload must be an object"); return out; }
        Double v = JsVal.num(get(p, "x402Version"));
        if (v == null || v != 2.0) out.add("x402Version must be 2");
        if (def(p, "resource")) out.addAll(X402V2.resourceInfoProblems(get(p, "resource")));
        for (String m : X402V2.requirementV2Problems(get(p, "accepted"))) out.add("accepted." + m);
        if (!isObj(get(p, "payload"))) out.add("payload must be an object");
        if (def(p, "extensions") && !isObj(get(p, "extensions"))) out.add("extensions must be an object");
        return out;
    }

    /** Problems with a SettlementResponse (empty = valid). A success must not carry an errorReason; a failure must. */
    public static List<String> settlementResponseProblems(Object r) {
        List<String> out = new ArrayList<>();
        if (!isObj(r)) { out.add("SettlementResponse must be an object"); return out; }
        Object success = get(r, "success");
        if (!(success instanceof Boolean)) out.add("success must be a boolean");
        Object tx = get(r, "transaction");
        if (!(tx instanceof String)) out.add("transaction must be a string");
        else if (Boolean.TRUE.equals(success) && ((String) tx).isEmpty()) out.add("a successful settlement needs a transaction");
        if (!AcpJs.matches(X402V2.CAIP2, get(r, "network"))) out.add("network must be a CAIP-2 identifier");
        Object er = get(r, "errorReason");
        if (def(r, "errorReason") && !(er instanceof String)) out.add("errorReason must be a string");
        if (Boolean.TRUE.equals(success) && def(r, "errorReason")) out.add("errorReason must be omitted on success");
        if (Boolean.FALSE.equals(success) && !(er instanceof String && !((String) er).isEmpty())) out.add("errorReason is required on failure");
        if (def(r, "payer") && !(get(r, "payer") instanceof String)) out.add("payer must be a string");
        if (def(r, "amount") && !AcpJs.matches(ATOMIC, get(r, "amount"))) out.add("amount must be a decimal string of atomic units");
        if (def(r, "extensions") && !isObj(get(r, "extensions"))) out.add("extensions must be an object");
        return out;
    }

    private static String encodeHeader(Object obj, List<String> problems) {
        if (!problems.isEmpty()) throw new IllegalArgumentException("x402: " + String.join("; ", problems));
        return AcpJs.b64encode(AcpJs.stringify(obj));
    }

    private static Object decodeHeader(Object value, String name) {
        if (!AcpJs.looksBase64(value)) throw new IllegalArgumentException("x402: " + name + " is not base64");
        try {
            return AcpJs.parse(new String(AcpJs.b64decode((String) value), StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("x402: " + name + " is not JSON");
        }
    }

    /** Encode a PaymentPayload for the {@code PAYMENT-SIGNATURE} request header (validates first; throws IllegalArgumentException). */
    public static String encodePaymentSignatureHeader(Object p) { return encodeHeader(p, paymentPayloadV2Problems(p)); }

    /** Decode and validate a {@code PAYMENT-SIGNATURE} header value. Throws IllegalArgumentException on bad base64, bad JSON or an invalid object. */
    public static Map<String, Object> decodePaymentSignatureHeader(Object value) {
        Object doc = decodeHeader(value, "PAYMENT-SIGNATURE");
        List<String> problems = paymentPayloadV2Problems(doc);
        if (!problems.isEmpty()) throw new IllegalArgumentException("x402: " + String.join("; ", problems));
        return JsVal.map(doc);
    }

    /** Encode a SettlementResponse for the {@code PAYMENT-RESPONSE} response header. */
    public static String encodePaymentResponseHeader(Object r) { return encodeHeader(r, settlementResponseProblems(r)); }

    /** Decode and validate a {@code PAYMENT-RESPONSE} header value. */
    public static Map<String, Object> decodePaymentResponseHeader(Object value) {
        Object doc = decodeHeader(value, "PAYMENT-RESPONSE");
        List<String> problems = settlementResponseProblems(doc);
        if (!problems.isEmpty()) throw new IllegalArgumentException("x402: " + String.join("; ", problems));
        return JsVal.map(doc);
    }

    private static final Object UNDEFINED = new Object();

    /** Case-insensitive header lookup over a header record (first value of a list); UNDEFINED when absent. */
    private static Object header(Map<String, Object> headers, String name) {
        for (Map.Entry<String, Object> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) {
                Object v = e.getValue();
                return v instanceof List ? (((List<?>) v).isEmpty() ? UNDEFINED : ((List<?>) v).get(0)) : v;
            }
        }
        return UNDEFINED;
    }

    /**
     * Server side: read the client's {@code PAYMENT-SIGNATURE} header. A missing header is 402 (answer with a PAYMENT-REQUIRED challenge); a
     * present but undecodable or invalid one is 400 (malformed). Never throws. Returns {ok, payload} or {ok:false, status, reason}.
     */
    public static Map<String, Object> readPaymentSignature(Map<String, Object> headers) {
        Object v = header(headers, X402_PAYMENT_SIGNATURE_HEADER);
        Map<String, Object> out = new LinkedHashMap<>();
        if (v == UNDEFINED || "".equals(v)) {
            out.put("ok", Boolean.FALSE);
            out.put("status", AcpJs.num(STATUS_PAYMENT_REQUIRED));
            out.put("reason", "PAYMENT-SIGNATURE header is required");
            return out;
        }
        try {
            Map<String, Object> payload = decodePaymentSignatureHeader(v);
            out.put("ok", Boolean.TRUE);
            out.put("payload", payload);
        } catch (IllegalArgumentException e) {
            out.put("ok", Boolean.FALSE);
            out.put("status", AcpJs.num(STATUS_MALFORMED));
            out.put("reason", e.getMessage());
        }
        return out;
    }

    /**
     * Server side: the status and {@code PAYMENT-RESPONSE} header for a settlement outcome. {@code outcome} = {settled: true, transaction, payer?,
     * amount?} or {settled: false, reason, transaction?, payer?}. Throws IllegalArgumentException if the response would be invalid.
     * Returns {status, headers}.
     */
    public static Map<String, Object> x402SettlementResponse(Map<String, Object> outcome, Object network) {
        boolean settled = JsVal.truthy(outcome.get("settled"));
        Map<String, Object> body = new LinkedHashMap<>();
        if (settled) {
            body.put("success", Boolean.TRUE);
            if (def(outcome, "transaction")) body.put("transaction", outcome.get("transaction"));
            body.put("network", network);
            if (def(outcome, "payer")) body.put("payer", outcome.get("payer"));
            if (def(outcome, "amount")) body.put("amount", outcome.get("amount"));
        } else {
            body.put("success", Boolean.FALSE);
            if (def(outcome, "reason")) body.put("errorReason", outcome.get("reason"));
            body.put("transaction", outcome.get("transaction") != null ? outcome.get("transaction") : "");
            body.put("network", network);
            if (def(outcome, "payer")) body.put("payer", outcome.get("payer"));
        }
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put(X402_PAYMENT_RESPONSE_HEADER, encodePaymentResponseHeader(body));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", AcpJs.num(settled ? STATUS_SETTLED : STATUS_FAILED));
        out.put("headers", headers);
        return out;
    }

    /** Client side: the request header to attach on the retry, from a payload built for an offered requirement. */
    public static Map<String, Object> x402PaymentSignatureHeaders(Object p) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put(X402_PAYMENT_SIGNATURE_HEADER, encodePaymentSignatureHeader(p));
        return out;
    }
}
