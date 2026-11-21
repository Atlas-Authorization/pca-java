package net.atlasauth.pca.oauth;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/** An injectable HTTP GET (the reference's injectable {@code fetch}): the default uses java.net.http, tests pass a scripted one. */
@FunctionalInterface
public interface Fetch {
    /** The parts of a response the OAuth-family ports read. {@code contentLength} is the header value or null. */
    final class Response {
        public final boolean ok;
        public final int status;
        public final String contentLength;
        public final String text;
        public Response(boolean ok, int status, String contentLength, String text) { this.ok = ok; this.status = status; this.contentLength = contentLength; this.text = text; }
    }

    /** GET {@code url}; {@code timeoutMs} 0 means no timeout. Throws on a network failure. */
    Response get(String url, Map<String, String> headers, long timeoutMs) throws Exception;

    /** The default fetch over {@link HttpClient}. */
    static Fetch http() {
        final HttpClient client = HttpClient.newHttpClient();
        return (url, headers, timeoutMs) -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).GET();
            if (timeoutMs > 0) b.timeout(Duration.ofMillis(timeoutMs));
            for (Map.Entry<String, String> h : headers.entrySet()) b.header(h.getKey(), h.getValue());
            HttpResponse<String> r = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
            int s = r.statusCode();
            return new Response(s >= 200 && s < 300, s, r.headers().firstValue("content-length").orElse(null), r.body());
        };
    }
}
