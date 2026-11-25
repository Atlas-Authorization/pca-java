package net.atlasauth.pca.oidc;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.oauth.Fetch;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.oauth.Jws;

/**
 * A caching JWKS key resolver that FAILS CLOSED on stale or unreachable keys: keys are cached for {@code cacheMaxAgeSec}; after
 * that they are refetched and, if the refetch fails, verification is REFUSED (a stale key set is never used). A {@code kid} that is
 * not in the cached set triggers at most one refetch per {@code cooldownSec}. Options (reference names): jwksUri, fetch ({@link Fetch}),
 * cacheMaxAgeSec (600), cooldownSec (30), maxBytes (1 MiB), requireHttps (true), timeoutMs (5000), now ({@link LongSupplier} of epoch ms).
 */
public final class OidcJwks implements Jws.KeyResolver {
    /** Default timeout of one key-set request (5 s). */
    public static final long DEFAULT_JWKS_TIMEOUT_MS = 5000;

    private final String jwksUri;
    private final Fetch fetch;
    private final LongSupplier now;
    private final double maxAgeMs, cooldownMs, maxBytes, timeoutMs;
    private Jws.KeyResolver cache;
    private long cacheAt;
    private Set<String> kids;
    private double lastFetch = Double.NEGATIVE_INFINITY;

    public OidcJwks(Map<String, Object> opts) {
        Object uri = opts.get("jwksUri");
        if (!(uri instanceof String) || ((String) uri).isEmpty()) throw new IllegalArgumentException("createOidcJwks: jwksUri is required");
        jwksUri = (String) uri;
        Object rh = opts.get("requireHttps");
        if ((rh == null || JsVal.truthy(rh)) && !jwksUri.regionMatches(true, 0, "https://", 0, 8)) {
            throw new IllegalArgumentException("createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)");
        }
        fetch = opts.get("fetch") instanceof Fetch ? (Fetch) opts.get("fetch") : Fetch.http();
        now = opts.get("now") instanceof LongSupplier ? (LongSupplier) opts.get("now") : System::currentTimeMillis;
        // A NaN or infinite age / cooldown would make every staleness comparison false and serve one key set forever.
        for (String name : new String[] {"cacheMaxAgeSec", "cooldownSec", "maxBytes", "timeoutMs"}) {
            Object v = opts.get(name);
            if (v != null) {
                Double d = JsVal.num(v);
                if (d == null || Double.isNaN(d) || Double.isInfinite(d) || d < 0) throw new IllegalArgumentException("createOidcJwks: " + name + " must be a finite number >= 0");
            }
        }
        maxAgeMs = num(opts, "cacheMaxAgeSec", 600) * 1000;
        cooldownMs = num(opts, "cooldownSec", 30) * 1000;
        maxBytes = num(opts, "maxBytes", 1024 * 1024);
        timeoutMs = num(opts, "timeoutMs", DEFAULT_JWKS_TIMEOUT_MS);
    }

    private static double num(Map<String, Object> o, String k, double dflt) { return o.get(k) == null ? dflt : JsVal.num(o.get(k)); }

    private static OidcVerificationError keysError(String message, Throwable cause) { return new OidcVerificationError("keys", message, cause); }

    private void refetch() {
        lastFetch = now.getAsLong();
        Jws.KeyResolver resolve;
        Object jwks;
        try {
            Map<String, String> h = new LinkedHashMap<>();
            h.put("accept", "application/json");
            Fetch.Response res = fetch.get(jwksUri, h, (long) timeoutMs);
            if (!res.ok) throw new IllegalStateException("HTTP " + res.status);
            if (Json.utf8(res.text).length > maxBytes) throw new IllegalStateException("response exceeds " + maxBytes + " bytes");
            jwks = Json.parseLenient(res.text);
            if (!(jwks instanceof Map) || !(((Map<?, ?>) jwks).get("keys") instanceof List)) throw new IllegalStateException("not a JWK Set");
            resolve = Jws.localJwks(jwks);
        } catch (Exception e) {
            throw keysError("could not fetch the issuer signing keys from " + jwksUri, e);
        }
        Set<String> ks = new HashSet<>();
        for (Object k : (List<?>) ((Map<?, ?>) jwks).get("keys")) {
            Object kid = ((Map<?, ?>) k).get("kid");
            if (kid instanceof String) ks.add((String) kid);
        }
        cache = resolve;
        cacheAt = now.getAsLong();
        kids = ks;
    }

    @Override
    public synchronized Object getKey(Map<String, Object> header) {
        long t = now.getAsLong();
        if (cache == null || t - cacheAt >= maxAgeMs) {
            cache = null; // never serve a stale set, even if the refetch below fails
            refetch();
        } else if (header != null && header.get("kid") instanceof String && !kids.contains(header.get("kid")) && t - lastFetch >= cooldownMs) {
            refetch();
        }
        return cache.getKey(header);
    }
}
