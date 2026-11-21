package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import net.atlasauth.pca.gateway.Gateway;
import org.junit.jupiter.api.Test;

/** The Worker adapter replayed against the reference with a structural request (method, url, headers) and injected next / respond. */
class GatewayWorkerDiffTest {
    /** Header names are lower-cased and iterate sorted, as a Fetch Headers does. */
    private static final class Req implements Gateway.WorkerRequest {
        final String method, url;
        final TreeMap<String, String> headers = new TreeMap<>();
        Req(String method, String url, Map<String, String> h) { this.method = method; this.url = url; for (Map.Entry<String, String> e : h.entrySet()) headers.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue()); }
        @Override public String method() { return method; }
        @Override public String url() { return url; }
        @Override public String header(String name) { return headers.get(name.toLowerCase(Locale.ROOT)); }
        @Override public Iterable<String> headerNames() { return headers.keySet(); }
    }

    @SuppressWarnings("unchecked")
    @Test void workerScenario() throws Exception {
        OracleCases.each("ref-gateway-worker", "workerScenario", a -> {
            Map<String, Object> spec = (Map<String, Object>) a.get(0);
            Map<String, Object> ev = (Map<String, Object>) ((List<Object>) spec.get("events")).get(0);
            Map<String, String> headers = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) ev.get("headers")).entrySet()) headers.put(e.getKey(), (String) e.getValue());
            Object mode = ev.get("rewrite");
            Gateway.RewriteRequest<Req> rewrite = null;
            if (!"null".equals(mode)) {
                final boolean tag = "custom".equals(mode);
                rewrite = (r, drop) -> {
                    Map<String, String> h = new LinkedHashMap<>(r.headers);
                    for (String n : drop) h.remove(n);
                    if (tag) h.put("x-rewritten", String.join(",", drop));
                    return new Req(r.method, r.url, h);
                };
            }
            Gateway.GatewayOptions opts = GatewayDiffTest.options(spec);
            java.util.function.Function<Req, Object> w;
            try {
                w = Gateway.<Req, Object>cloudflareWorker(opts, r -> {
                    Map<String, Object> f = new LinkedHashMap<>();
                    f.put("method", r.method);
                    f.put("url", r.url);
                    f.put("headers", new LinkedHashMap<String, Object>(r.headers));
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("forwarded", f);
                    return out;
                }, rewrite, (body, status, h) -> {
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("status", status);
                    out.put("headers", new LinkedHashMap<String, Object>(h));
                    out.put("body", Json.parse(body));
                    return out;
                });
            } catch (RuntimeException e) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("create", e.getMessage());
                return m;
            }
            return GatewayDiffTest.mask(w.apply(new Req((String) ev.get("method"), (String) ev.get("url"), headers)));
        });
    }
}
