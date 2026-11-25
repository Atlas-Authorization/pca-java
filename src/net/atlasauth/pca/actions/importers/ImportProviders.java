package net.atlasauth.pca.actions.importers;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.Actions.ActionKitError;
import net.atlasauth.pca.Json;

/**
 * Model adapters for {@code --suggest model}: a pinned model id on a named provider, the API key read from the environment at call time
 * (never a flag, never printed, never stored, never put in an error). The request is exactly the names-and-types prompt of
 * {@link ImportModel}; the answer is parsed against the closed trait vocabulary there. The transport is injectable.
 */
public final class ImportProviders {
    private ImportProviders() {}

    public static final List<String> PROVIDERS = List.of("anthropic", "openai");

    private static final Pattern MODEL_RE = Pattern.compile("[A-Za-z0-9._:/-]{1,128}");

    /** What a transport answers: status, and the parsed JSON body on demand. */
    public interface FetchResponse {
        boolean ok();
        int status();
        Object json() throws Exception;
    }

    /** One POST: url, headers, JSON body text, timeout. */
    public interface FetchLike {
        FetchResponse fetch(String url, Map<String, String> headers, String body, long timeoutMs) throws Exception;
    }

    /** The provider, the pinned model and the key (kept out of {@link #toString()} and {@link #toMap()}). */
    public static final class ModelEnvConfig {
        public final String provider, model;
        private final String apiKey;
        ModelEnvConfig(String provider, String model, String apiKey) { this.provider = provider; this.model = model; this.apiKey = apiKey; }
        public Map<String, Object> toMap() { return Jx.obj("provider", provider, "model", model); }
        @Override public String toString() { return provider + ":" + model; }
    }

    private static String keyEnv(String provider) { return provider.equals("anthropic") ? "ANTHROPIC_API_KEY" : "OPENAI_API_KEY"; }
    private static String urlOf(String provider) { return provider.equals("anthropic") ? "https://api.anthropic.com/v1/messages" : "https://api.openai.com/v1/chat/completions"; }

    private static Object first(Object a, Object b) { return a != null ? a : b; }

    /**
     * Read the model assist configuration. {@code model} and {@code provider} come from flags or ATLAS_PCA_SUGGEST_MODEL /
     * ATLAS_PCA_SUGGEST_PROVIDER; the model must be named explicitly (a pinned id). The key comes only from the provider's env var.
     */
    public static ModelEnvConfig modelConfigFromEnv(Map<String, Object> env, Map<String, Object> flags) {
        Map<String, Object> fl = flags == null ? new LinkedHashMap<>() : flags;
        Object provider = first(fl.get("provider"), first(env.get("ATLAS_PCA_SUGGEST_PROVIDER"), "anthropic"));
        if (!(provider instanceof String) || !PROVIDERS.contains(provider)) throw new ActionKitError("bad_model_config", "unknown provider (one of " + String.join(", ", PROVIDERS) + ")");
        Object model = first(fl.get("model"), env.get("ATLAS_PCA_SUGGEST_MODEL"));
        if (!Jx.truthy(model) || !MODEL_RE.matcher(Jx.jsStr(model)).matches()) throw new ActionKitError("bad_model_config", "--model <pinned model id> (or ATLAS_PCA_SUGGEST_MODEL) is required");
        Object key = env.get(keyEnv((String) provider));
        if (!Jx.truthy(key)) throw new ActionKitError("bad_model_config", keyEnv((String) provider) + " is not set");
        return new ModelEnvConfig((String) provider, Jx.jsStr(model), Jx.jsStr(key));
    }

    /** A transport over {@code java.net.http.HttpClient}. */
    public static FetchLike httpFetch() {
        HttpClient client = HttpClient.newHttpClient();
        return (url, headers, body, timeoutMs) -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofMillis(timeoutMs)).POST(HttpRequest.BodyPublishers.ofString(body));
            for (Map.Entry<String, String> h : headers.entrySet()) b.header(h.getKey(), h.getValue());
            HttpResponse<String> r = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
            return new FetchResponse() {
                @Override public boolean ok() { return r.statusCode() >= 200 && r.statusCode() < 300; }
                @Override public int status() { return r.statusCode(); }
                @Override public Object json() { return Json.parseLenient(r.body()); }
            };
        };
    }

    public static ImportModel.ModelAdapter providerAdapter(ModelEnvConfig cfg, FetchLike fetch) { return providerAdapter(cfg, fetch, 30_000); }

    /** A ModelAdapter for the provider. Errors carry the HTTP status only: never the key, the request or the response body. */
    public static ImportModel.ModelAdapter providerAdapter(ModelEnvConfig cfg, FetchLike fetch, long timeoutMs) {
        return new ImportModel.ModelAdapter() {
            @Override public String id() { return cfg.provider + ":" + cfg.model; }
            @Override public String version() { return null; }

            @Override public String complete(Map<String, Object> req) throws Exception {
                Map<String, String> headers = new LinkedHashMap<>();
                headers.put("content-type", "application/json");
                Object body;
                if (cfg.provider.equals("anthropic")) {
                    headers.put("x-api-key", cfg.apiKey);
                    headers.put("anthropic-version", "2023-06-01");
                    body = Jx.obj("model", cfg.model, "max_tokens", Jx.n(512), "temperature", req.get("temperature"), "system", req.get("system"),
                        "messages", Jx.list(Jx.obj("role", "user", "content", req.get("user"))));
                } else {
                    headers.put("authorization", "Bearer " + cfg.apiKey);
                    body = Jx.obj("model", cfg.model, "max_tokens", Jx.n(512), "temperature", req.get("temperature"),
                        "messages", Jx.list(Jx.obj("role", "system", "content", req.get("system")), Jx.obj("role", "user", "content", req.get("user"))));
                }
                FetchResponse res;
                try {
                    res = fetch.fetch(urlOf(cfg.provider), headers, Jx.stringify(body), timeoutMs);
                } catch (Exception e) {
                    throw new RuntimeException(cfg.provider + " request failed");
                }
                if (!res.ok()) throw new RuntimeException(cfg.provider + " returned HTTP " + res.status());
                Object j = res.json();
                if (j == null) throw new RuntimeException("Cannot read properties of null (reading '" + (cfg.provider.equals("anthropic") ? "content" : "choices") + "')");
                Object text;
                if (cfg.provider.equals("anthropic")) {
                    text = null;
                    Object content = Jx.get(j, "content");
                    if (content instanceof List) for (Object c : Jx.a(content)) if ("text".equals(Jx.get(c, "type"))) { text = Jx.get(c, "text"); break; }
                } else {
                    Object choices = Jx.get(j, "choices");
                    text = choices instanceof List && !Jx.a(choices).isEmpty() ? Jx.get(Jx.get(Jx.a(choices).get(0), "message"), "content") : null;
                }
                if (!(text instanceof String)) throw new RuntimeException(cfg.provider + " returned no text");
                return (String) text;
            }
        };
    }
}
