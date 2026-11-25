package net.atlasauth.pca.acp;

import static net.atlasauth.pca.acp.AcpJs.def;
import static net.atlasauth.pca.acp.AcpJs.get;
import static net.atlasauth.pca.acp.AcpJs.isObj;
import static net.atlasauth.pca.acp.AcpJs.isSafeInteger;
import static net.atlasauth.pca.acp.AcpJs.matches;
import static net.atlasauth.pca.acp.AcpJs.nonEmpty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.oauth.WhatwgUrl;

/**
 * x402 v2 alongside v1, negotiated: PaymentRequired / PaymentRequirements / ResourceInfo validation, the base64
 * {@code PAYMENT-REQUIRED} header, version negotiation and payload normalisation. Values are parsed JSON (Map, List, String,
 * Boolean, Json.Num, null); every "problems" function returns the reference's messages, empty = valid. No I/O.
 */
public final class X402V2 {
    private X402V2() {}

    public static final int X402_VERSION_1 = 1;
    public static final int X402_VERSION_2 = 2;
    /** Versions this package can speak, newest first. */
    public static final List<Integer> X402_SUPPORTED_VERSIONS = List.of(2, 1);
    public static final String X402_V2_PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED";

    static final Pattern CAIP2 = Pattern.compile("[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}");
    private static final Pattern ASCII_PRINTABLE = Pattern.compile("[\\x20-\\x7e]*");
    private static final Pattern ATOMIC = Pattern.compile("0|[1-9][0-9]*");

    private static boolean absoluteHttp(Object u) {
        if (!(u instanceof String)) return false;
        WhatwgUrl p = WhatwgUrl.parse((String) u);
        return p != null && (p.protocol.equals("https:") || p.protocol.equals("http:"));
    }

    /** Problems with a {@code ResourceInfo} (empty = valid). */
    public static List<String> resourceInfoProblems(Object r) {
        List<String> p = new ArrayList<>();
        if (!isObj(r)) { p.add("resource must be an object"); return p; }
        if (!absoluteHttp(get(r, "url"))) p.add("resource.url must be an absolute http(s) URL");
        for (String k : new String[] {"description", "mimeType"}) if (def(r, k) && !(get(r, k) instanceof String)) p.add("resource." + k + " must be a string");
        if (def(r, "serviceName")) {
            Object s = get(r, "serviceName");
            if (!(s instanceof String && ((String) s).length() <= 32 && matches(ASCII_PRINTABLE, s))) p.add("resource.serviceName must be printable ASCII up to 32 characters");
        }
        if (def(r, "tags")) {
            Object t = get(r, "tags");
            boolean ok = t instanceof List && ((List<?>) t).size() <= 5;
            if (ok) for (Object x : (List<?>) t) if (!(x instanceof String && ((String) x).length() <= 32 && matches(ASCII_PRINTABLE, x))) { ok = false; break; }
            if (!ok) p.add("resource.tags must be up to 5 printable ASCII strings of up to 32 characters");
        }
        if (def(r, "iconUrl")) {
            Object u = get(r, "iconUrl");
            if (!(absoluteHttp(u) && ((String) u).length() <= 2048)) p.add("resource.iconUrl must be an absolute http(s) URL up to 2048 characters");
        }
        return p;
    }

    /** Problems with one v2 {@code PaymentRequirements} (empty = valid). */
    public static List<String> requirementV2Problems(Object q) {
        List<String> p = new ArrayList<>();
        if (!isObj(q)) { p.add("requirements must be an object"); return p; }
        if (!nonEmpty(get(q, "scheme"))) p.add("scheme is required");
        if (!matches(CAIP2, get(q, "network"))) p.add("network must be a CAIP-2 identifier");
        Object amount = get(q, "amount");
        if (!matches(ATOMIC, amount) || "0".equals(amount)) p.add("amount must be a positive decimal string of atomic units");
        if (!nonEmpty(get(q, "asset"))) p.add("asset is required");
        if (!nonEmpty(get(q, "payTo"))) p.add("payTo is required");
        Object t = get(q, "maxTimeoutSeconds");
        if (!(isSafeInteger(t) && JsVal.num(t) > 0)) p.add("maxTimeoutSeconds must be a positive integer");
        if (def(q, "extra") && !isObj(get(q, "extra"))) p.add("extra must be an object");
        return p;
    }

    /** Problems with a v2 {@code PaymentRequired} (empty = valid). */
    public static List<String> paymentRequiredV2Problems(Object pr) {
        List<String> p = new ArrayList<>();
        if (!isObj(pr)) { p.add("PaymentRequired must be an object"); return p; }
        Double v = JsVal.num(get(pr, "x402Version"));
        if (v == null || v != 2.0) p.add("x402Version must be 2");
        if (def(pr, "error") && !(get(pr, "error") instanceof String)) p.add("error must be a string");
        p.addAll(resourceInfoProblems(get(pr, "resource")));
        Object acc = get(pr, "accepts");
        if (!(acc instanceof List) || ((List<?>) acc).isEmpty()) p.add("accepts must be a non-empty array");
        else {
            int i = 0;
            for (Object q : (List<?>) acc) { for (String m : requirementV2Problems(q)) p.add("accepts[" + i + "]." + m); i++; }
        }
        if (def(pr, "extensions")) {
            Object ext = get(pr, "extensions");
            if (!isObj(ext)) p.add("extensions must be an object");
            else for (Map.Entry<?, ?> e : ((Map<?, ?>) ext).entrySet()) {
                Object v2 = e.getValue();
                if (!isObj(v2) || !isObj(get(v2, "info")) || !isObj(get(v2, "schema"))) p.add("extensions." + e.getKey() + " needs info and schema objects");
            }
        }
        return p;
    }

    /** Encode a {@code PaymentRequired} for the {@code PAYMENT-REQUIRED} header (validates first; throws on a problem). */
    public static String encodePaymentRequiredHeader(Object pr) {
        List<String> problems = paymentRequiredV2Problems(pr);
        if (!problems.isEmpty()) throw new IllegalArgumentException("x402: " + String.join("; ", problems));
        return AcpJs.b64encode(AcpJs.stringify(pr));
    }

    /** Decode and validate a {@code PAYMENT-REQUIRED} header value. Throws IllegalArgumentException on bad base64, bad JSON or an invalid object. */
    public static Map<String, Object> decodePaymentRequiredHeader(Object value) {
        if (!AcpJs.looksBase64(value)) throw new IllegalArgumentException("x402: PAYMENT-REQUIRED is not base64");
        Object doc;
        try {
            doc = AcpJs.parse(new String(AcpJs.b64decode((String) value), java.nio.charset.StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("x402: PAYMENT-REQUIRED is not JSON");
        }
        List<String> problems = paymentRequiredV2Problems(doc);
        if (!problems.isEmpty()) throw new IllegalArgumentException("x402: " + String.join("; ", problems));
        return JsVal.map(doc);
    }

    /**
     * Build the v2 402 challenge ({status, headers, body}): JSON body plus the base64 {@code PAYMENT-REQUIRED} header. {@code resource} is a
     * URL string or a ResourceInfo map; {@code opts} carries amount, asset, payTo, network and the optional scheme, maxTimeoutSeconds, extra,
     * error, extensions. Throws on anything the v2 spec makes invalid.
     */
    public static Map<String, Object> x402ChallengeV2(Object resource, Map<String, Object> opts) {
        Object amount = opts.get("amount");
        if (!(isSafeInteger(amount) && JsVal.num(amount) > 0)) throw new IllegalArgumentException("x402Challenge: amount must be a positive integer in atomic units");
        Map<String, Object> info = new LinkedHashMap<>();
        if (resource instanceof String) info.put("url", resource);
        else info.putAll(AcpJs.spread(resource));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("x402Version", AcpJs.num(2));
        body.put("error", opts.get("error") != null ? opts.get("error") : "PAYMENT-SIGNATURE header is required");
        body.put("resource", info);
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("scheme", opts.get("scheme") != null ? opts.get("scheme") : "exact");
        if (def(opts, "network")) req.put("network", opts.get("network"));
        req.put("amount", AcpJs.str(amount));
        if (def(opts, "asset")) req.put("asset", opts.get("asset"));
        if (def(opts, "payTo")) req.put("payTo", opts.get("payTo"));
        req.put("maxTimeoutSeconds", opts.get("maxTimeoutSeconds") != null ? opts.get("maxTimeoutSeconds") : AcpJs.num(60));
        if (def(opts, "extra")) req.put("extra", opts.get("extra"));
        body.put("accepts", new ArrayList<Object>(List.of(req)));
        if (def(opts, "extensions")) body.put("extensions", opts.get("extensions"));
        String header = encodePaymentRequiredHeader(body); // validates
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put(X402_V2_PAYMENT_REQUIRED_HEADER, header);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", AcpJs.num(402));
        out.put("headers", headers);
        out.put("body", body);
        return out;
    }

    /**
     * Version negotiation: the highest version both sides support, or null when there is none (answer 402 v1 with an error, never guess).
     * {@code offered} null or empty means the client speaks v1 only.
     */
    public static Integer x402Negotiate(List<Integer> offered, List<Integer> supported) {
        List<Integer> mine = new ArrayList<>();
        for (Integer v : supported) if (v == 1 || v == 2) mine.add(v);
        List<Integer> theirs = offered == null || offered.isEmpty() ? List.of(1) : offered;
        mine.sort((a, b) -> b - a);
        for (Integer v : mine) if (theirs.contains(v)) return v;
        return null;
    }

    public static Integer x402Negotiate(List<Integer> offered) { return x402Negotiate(offered, X402_SUPPORTED_VERSIONS); }

    private static String stable(Object v) {
        if (v == null || !(v instanceof Map || v instanceof List)) return AcpJs.stringify(v);
        if (v instanceof List) {
            List<String> parts = new ArrayList<>();
            for (Object x : (List<?>) v) parts.add(stable(x));
            return "[" + String.join(",", parts) + "]";
        }
        Map<?, ?> o = (Map<?, ?>) v;
        String[] keys = new String[o.size()];
        int i = 0;
        for (Object k : o.keySet()) keys[i++] = (String) k;
        Arrays.sort(keys);
        StringBuilder sb = new StringBuilder("{");
        for (int j = 0; j < keys.length; j++) {
            if (j > 0) sb.append(',');
            sb.append(AcpJs.stringify(keys[j])).append(':').append(stable(o.get(keys[j])));
        }
        return sb.append('}').toString();
    }

    /** True when {@code accepted} (echoed by the client in its v2 payload) is exactly one of the requirements the server offered. */
    public static boolean x402AcceptedMatches(List<?> offered, Object accepted) {
        if (!requirementV2Problems(accepted).isEmpty()) return false;
        String a = stable(accepted);
        for (Object o : offered) if (stable(o).equals(a)) return true;
        return false;
    }

    private static Map<String, Object> fail(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", Boolean.FALSE);
        m.put("reason", reason);
        return m;
    }

    /**
     * Read a client payload of either version: {ok, version, token, merchant?, amount?, accepted?} or {ok:false, reason}. v1: token, merchant
     * and amount are top-level members. v2: the delegated token is {@code payload.token} and the echoed {@code accepted} must be a valid v2
     * requirement; the merchant is never read from a v2 payload and the amount only from {@code accepted.amount}.
     */
    public static Map<String, Object> normalizeX402Payload(Object raw) {
        if (!isObj(raw)) return fail("x402 payment payload is not an object");
        Object ver = get(raw, "x402Version");
        Double vd = JsVal.num(ver);
        if (vd != null && vd == 2.0) {
            Object inner = get(raw, "payload");
            if (!isObj(inner) || !(get(inner, "token") instanceof String) || ((String) get(inner, "token")).isEmpty()) return fail("x402 v2 payload is missing payload.token");
            List<String> problems = requirementV2Problems(get(raw, "accepted"));
            if (!problems.isEmpty()) return fail("x402 v2 payload.accepted is invalid: " + String.join("; ", problems));
            Object accepted = get(raw, "accepted");
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", Boolean.TRUE);
            out.put("version", AcpJs.num(2));
            out.put("token", get(inner, "token"));
            out.put("accepted", accepted);
            double amount = Double.parseDouble((String) get(accepted, "amount"));
            if (isSafeInteger(new net.atlasauth.pca.Json.Num(Double.toString(amount)))) out.put("amount", AcpJs.num((long) amount));
            return out;
        }
        if (def(raw, "x402Version") && !(vd != null && vd == 1.0)) return fail("unsupported x402Version " + AcpJs.str(ver));
        if (!(get(raw, "token") instanceof String)) return fail("x402 payment payload is missing a token");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", Boolean.TRUE);
        out.put("version", AcpJs.num(1));
        out.put("token", get(raw, "token"));
        if (get(raw, "merchant") instanceof String) out.put("merchant", get(raw, "merchant"));
        if (JsVal.isNumber(get(raw, "amount"))) out.put("amount", get(raw, "amount"));
        return out;
    }
}
