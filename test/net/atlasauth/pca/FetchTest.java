package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import net.atlasauth.pca.fetch.Fetch;
import net.atlasauth.pca.servlet.GrantResolver;
import org.junit.jupiter.api.Test;

/** The request guard and the java.net.http helper: plumbing and the default-deny shapes (the decisions themselves are the core's, covered there). */
class FetchTest {
    private static String json, aud;
    private static String grantRef;
    private static Map<String, Object> grant;
    private static long now;

    @SuppressWarnings("unchecked")
    private static synchronized void init() throws Exception {
        if (json != null) return;
        Map<String, Object> core = (Map<String, Object>) Json.parseLenient(java.nio.file.Files.readString(java.nio.file.Path.of("conformance/vectors.json")));
        for (Object x : (List<Object>) core.get("vectors")) {
            Map<String, Object> v = (Map<String, Object>) x;
            if ("valid-raw-json-format-insensitive".equals(v.get("name"))) {
                json = (String) v.get("pcactn_json");
                grant = (Map<String, Object>) v.get("grant");
                aud = (String) ((Map<String, Object>) v.get("context")).get("aud");
                now = Json.asLong(((Map<String, Object>) v.get("context")).get("now"));
            }
        }
        grantRef = (String) ((Map<String, Object>) Json.parse(json)).get("grant_ref");
    }

    private static GrantResolver resolver() { return ref -> grantRef.equals(ref) ? grant : null; }

    @Test void headersRoundTrip() {
        Map<String, String> h = Fetch.pcaHeaders("{\"a\":\"é\"}");
        assertEquals(List.of("PCA-Action"), List.copyOf(h.keySet()));
        assertEquals("{\"a\":\"é\"}", Pca.decodePcaHeader(h.get("PCA-Action")));
        assertFalse(h.get("PCA-Action").contains("="));
    }

    @Test void attachSetsTheHeader() {
        HttpRequest r = Fetch.attach(HttpRequest.newBuilder(URI.create("https://rs.example/x")), "{}").build();
        assertEquals(Fetch.pcaHeaders("{}").get("PCA-Action"), r.headers().firstValue("PCA-Action").orElse(null));
    }

    @Test void noProofIsRefusedWithAChallengeAndTheHandlerNeverRuns() throws Exception {
        init();
        AtomicInteger calls = new AtomicInteger();
        Function<Fetch.FetchRequest, Fetch.FetchResponse> f = Fetch.withPCA(Fetch.Options.signatureOnly(aud, resolver()).withClock(() -> now), (rq, pca) -> { calls.incrementAndGet(); return null; });
        Fetch.FetchResponse res = f.apply(new Fetch.FetchRequest("POST", "https://rs.example/x", new LinkedHashMap<>(), null));
        assertEquals(401, res.status);
        assertEquals("PCA realm=\"pca\"", res.headers.get("WWW-Authenticate"));
        assertEquals("application/json", res.headers.get("content-type"));
        assertEquals(0, calls.get());
    }

    @Test void aValidProofReachesTheHandlerInSignatureOnlyMode() throws Exception {
        init();
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("pca-action", Fetch.pcaHeaders(json).get("PCA-Action"));
        Fetch.FetchResponse ok = new Fetch.FetchResponse(200, new LinkedHashMap<>(), "ok");
        Function<Fetch.FetchRequest, Fetch.FetchResponse> f = Fetch.withPCA(Fetch.Options.signatureOnly(aud, resolver()).withClock(() -> now), (rq, pca) -> ok);
        assertTrue(f.apply(new Fetch.FetchRequest("POST", "https://rs.example/x", headers, null)) == ok);
        // the same proof for another audience is refused
        Function<Fetch.FetchRequest, Fetch.FetchResponse> other = Fetch.withPCA(Fetch.Options.signatureOnly("someone-else", resolver()).withClock(() -> now), (rq, pca) -> ok);
        Fetch.FetchResponse denied = other.apply(new Fetch.FetchRequest("POST", "https://rs.example/x", headers, null));
        assertEquals(403, denied.status);
    }

    @Test void theGuardReturnsTheResultAndAnUnknownGrantIsRefused() throws Exception {
        init();
        Function<Fetch.FetchRequest, net.atlasauth.pca.servlet.PcaResult> g = Fetch.createPcaFetchGuard(Fetch.Options.signatureOnly(aud, ref -> null).withClock(() -> now));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("PCA-ACTION", Fetch.pcaHeaders(json).get("PCA-Action"));
        net.atlasauth.pca.servlet.PcaResult r = g.apply(new Fetch.FetchRequest("POST", "u", headers, null));
        assertFalse(r.allowed());
        assertEquals(401, r.status());
        assertNull(r.verdict());
    }

    @SuppressWarnings("unchecked")
    @Test void theDefaultDenyBodyIsTheReferenceShape() throws Exception {
        init();
        Function<Fetch.FetchRequest, Fetch.FetchResponse> f = Fetch.withPCA(Fetch.Options.signatureOnly(aud, resolver()).withClock(() -> now), (rq, pca) -> null);
        Map<String, Object> body = (Map<String, Object>) Json.parse(f.apply(new Fetch.FetchRequest("POST", "u", null, null)).body);
        assertEquals("deny", body.get("decision"));
        Map<String, Object> verdict = (Map<String, Object>) body.get("verdict");
        assertEquals(Boolean.FALSE, verdict.get("allow"));
        assertEquals(((List<Object>) verdict.get("reasons")).get(0), body.get("error"));
        // a verified-but-refused proof carries the failing checks
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("pca-action", Fetch.pcaHeaders(json).get("PCA-Action"));
        Function<Fetch.FetchRequest, Fetch.FetchResponse> other = Fetch.withPCA(Fetch.Options.signatureOnly("someone-else", resolver()).withClock(() -> now), (rq, pca) -> null);
        Map<String, Object> b2 = (Map<String, Object>) Json.parse(other.apply(new Fetch.FetchRequest("POST", "u", headers, null)).body);
        assertFalse(((Map<String, Object>) ((Map<String, Object>) b2.get("verdict")).get("checks")).isEmpty());
    }

    @Test void aCustomDenyBodyIsUsed() throws Exception {
        init();
        Function<Fetch.FetchRequest, Fetch.FetchResponse> f = Fetch.withPCA(Fetch.Options.signatureOnly(aud, resolver()).withDenyBody(r -> "{\"no\":true}"), (rq, pca) -> null);
        assertEquals("{\"no\":true}", f.apply(new Fetch.FetchRequest("GET", "u", null, null)).body);
    }

    @Test void authorizedModeNeedsOptionsAndAMapper() {
        assertThrows(IllegalArgumentException.class, () -> Fetch.Options.authorized("a", ref -> null, null, null));
    }
}
