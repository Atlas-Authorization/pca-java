package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BiFunction;

/**
 * An HTTP QRNG backend for a configurable REST endpoint (ANU-style JSON, hex or base64 bodies), validated into exactly the requested
 * number of bytes. Fail-closed: a non-2xx status, a malformed body, a wrong-length payload, an out-of-range byte, a cleartext endpoint
 * or a timeout all throw. The API key travels only as a request header and never appears in an error. The library has no HTTP client:
 * the caller supplies the {@link Transport}.
 */
public final class HttpQrngSource implements Entropy.QrngSource {
    /** Body format. Anything else a caller might name falls to base64, as the reference does. */
    public enum Format { ANU_UINT8, HEX, BASE64 }

    /** One outgoing request. {@code redirect} is always "error" (a transport must not follow redirects); {@code timeoutMs} bounds the call. */
    public record Request(String url, Map<String, String> headers, String redirect, int timeoutMs) {}

    /** The response subset the source reads: only {@code ok()} decides success; {@code json()} / {@code text()} may throw. */
    public interface Response {
        boolean ok();
        int status();
        /** The parsed JSON body (Map, List, Number, String, Boolean or null). */
        Object json() throws Exception;
        String text() throws Exception;
    }

    /** The injected transport. It is run on its own thread and interrupted when the timeout elapses. */
    public interface Transport { Response send(Request request) throws Exception; }

    /** Configuration; null fields take the reference defaults. */
    public static final class Config {
        /** Base endpoint URL (required). */
        public String url;
        /** Optional API key, sent as a header, never logged. */
        public String apiKey;
        /** Header name for the key (default x-api-key). */
        public String apiKeyHeader;
        /** Default ANU_UINT8. */
        public Format format;
        /** Request timeout in ms (default 5000). */
        public Integer timeoutMs;
        /** Max bytes per request (default 1024). */
        public Integer maxBytes;
        /** Query parameter carrying the length (default "length"). */
        public String lengthParam;
        /** Extra query parameters, applied in order after the length. */
        public Map<String, String> extraParams;
        /** Builds the whole URL itself (its result still goes through the https check). */
        public BiFunction<String, Integer, String> buildUrl;
        /** Permit plain http only for localhost, 127.0.0.1 or [::1]. Default false. */
        public boolean allowInsecureLoopback;
        /** The transport; a source with none refuses every fetch. */
        public Transport transport;
    }

    private final String name;
    private final String url, apiKey, apiKeyHeader, lengthParam;
    private final Format format;
    private final int timeoutMs, maxBytes;
    private final Map<String, String> extraParams;
    private final BiFunction<String, Integer, String> buildUrl;
    private final boolean allowInsecureLoopback;
    private final Transport transport;

    public HttpQrngSource(Config c) {
        if (c.url == null || c.url.isEmpty()) throw new IllegalArgumentException("HttpQrngSource: `url` must be a non-empty string");
        int max = c.maxBytes == null ? Entropy.DEFAULT_MAX_QRNG_BYTES : c.maxBytes;
        if (max <= 0) throw new IllegalArgumentException("HttpQrngSource: `maxBytes` must be a positive integer");
        int timeout = c.timeoutMs == null ? Entropy.DEFAULT_TIMEOUT_MS : c.timeoutMs;
        if (timeout <= 0) throw new IllegalArgumentException("HttpQrngSource: `timeoutMs` must be a positive integer");
        this.url = c.url;
        this.apiKey = c.apiKey;
        this.apiKeyHeader = c.apiKeyHeader == null ? "x-api-key" : c.apiKeyHeader;
        this.format = c.format == null ? Format.ANU_UINT8 : c.format;
        this.timeoutMs = timeout;
        this.maxBytes = max;
        this.lengthParam = c.lengthParam == null ? "length" : c.lengthParam;
        this.extraParams = c.extraParams;
        this.buildUrl = c.buildUrl;
        this.allowInsecureLoopback = c.allowInsecureLoopback;
        this.transport = c.transport;
        this.name = "http-qrng(" + safeHost(c.url) + ")";
    }

    @Override public String name() { return name; }

    private String buildRequestUrl(int n) {
        if (buildUrl != null) return buildUrl.apply(url, n);
        WhatwgUrl u = WhatwgUrl.parse(url);
        // shortcut: an opaque (non-special scheme) URL cannot take query parameters; it is refused here, as it would be at the https check
        if (u.isOpaque()) throw new IllegalArgumentException("Invalid URL");
        u.setParam(lengthParam, Integer.toString(n));
        if (extraParams != null) for (Map.Entry<String, String> e : extraParams.entrySet()) u.setParam(e.getKey(), e.getValue());
        return u.href();
    }

    @Override public byte[] fetch(int numBytes) throws Exception {
        if (numBytes <= 0) throw new IllegalArgumentException("QRNG: numBytes must be a positive integer, got " + numBytes);
        if (numBytes > maxBytes) throw new IllegalArgumentException("QRNG: requested " + numBytes + " bytes exceeds per-request cap " + maxBytes);
        if (transport == null) throw new IllegalStateException("QRNG: no fetch implementation available in this runtime");

        String full = buildRequestUrl(numBytes);
        assertSecureTransport(full, allowInsecureLoopback);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("accept", "application/json, text/plain");
        if (apiKey != null && !apiKey.isEmpty()) headers.put(apiKeyHeader, apiKey);

        Request req = new Request(full, headers, "error", timeoutMs);
        FutureTask<Response> call = new FutureTask<>(() -> transport.send(req));
        Thread t = new Thread(call, "qrng-fetch");
        t.setDaemon(true);
        t.start();
        Response res;
        try {
            res = call.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            call.cancel(true);
            throw new IllegalStateException("QRNG: fetch failed (timeout)");
        } catch (ExecutionException e) {
            throw new IllegalStateException("QRNG: fetch failed (" + scrub(describe(e.getCause()), apiKey) + ")");
        } catch (InterruptedException e) {
            call.cancel(true);
            Thread.currentThread().interrupt();
            throw new IllegalStateException("QRNG: fetch failed (timeout)");
        }

        if (!res.ok()) throw new IllegalStateException("QRNG: endpoint returned HTTP " + res.status());
        byte[] bytes;
        if (format == Format.ANU_UINT8) bytes = Entropy.parseAnuUint8(res.json());
        else {
            String text = jsTrim(res.text());
            bytes = format == Format.HEX ? Entropy.parseHex(text) : Entropy.parseBase64(text);
        }
        if (bytes.length != numBytes) throw new IllegalStateException("QRNG: expected " + numBytes + " bytes, response decoded to " + bytes.length);
        return bytes;
    }

    private static boolean isJsSpace(char c) {
        return c == ' ' || (c >= '\t' && c <= '\r') || c == ' ' || c == ' ' || (c >= ' ' && c <= ' ')
            || c == ' ' || c == ' ' || c == ' ' || c == ' ' || c == '　' || c == '﻿';
    }

    /** {@code String.prototype.trim}: strips JavaScript whitespace and line terminators, not only ASCII control characters. */
    static String jsTrim(String s) {
        int b = 0, e = s.length();
        while (b < e && isJsSpace(s.charAt(b))) b++;
        while (e > b && isJsSpace(s.charAt(e - 1))) e--;
        return s.substring(b, e);
    }

    private static void assertSecureTransport(String url, boolean allowLoopback) {
        WhatwgUrl u;
        try { u = WhatwgUrl.parse(url); } catch (IllegalArgumentException e) { throw new EntropyError("insecure_transport", "QRNG: endpoint URL is not a valid URL"); }
        if (u.protocol().equals("https:")) return;
        String h = u.hostname();
        boolean loop = h.equals("localhost") || h.equals("127.0.0.1") || h.equals("[::1]");
        if (u.protocol().equals("http:") && allowLoopback && loop) return;
        throw new EntropyError("insecure_transport", "QRNG: endpoint must be https (http only for loopback with allowInsecureLoopback)");
    }

    private static String safeHost(String url) {
        try {
            String h = WhatwgUrl.parse(url).hostWithPort();
            return h.isEmpty() ? "unknown" : h;
        } catch (IllegalArgumentException e) {
            return "unknown";
        }
    }

    private static String describe(Throwable err) {
        if (err instanceof InterruptedException) return "timeout";
        if (err != null && err.getMessage() != null) return err.getMessage();
        return "unknown error";
    }

    /** Remove the API key from a message if it somehow appears (defense in depth). */
    private static String scrub(String msg, String apiKey) {
        return apiKey == null || apiKey.isEmpty() ? msg : msg.replace(apiKey, "[redacted]");
    }
}
