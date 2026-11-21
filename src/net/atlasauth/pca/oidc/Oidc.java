package net.atlasauth.pca.oidc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.oauth.Fetch;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.oauth.Jws;
import net.atlasauth.pca.oauth.WhatwgUrl;

/**
 * Root a Proof-Carrying Authority grant in a real OIDC-authenticated human: provider discovery (OpenID Connect Discovery 1.0 section 4),
 * ID-token verification (OpenID Connect Core 3.1.3.7: signature, iss / aud / exp / nbf / iat, nonce, azp, at_hash, c_hash) and the
 * mapping of verified claims onto a PCA principal descriptor. Options use the reference's names; an option value may be a Java object
 * where the reference takes a function or key ({@code key}: {@link Jws.KeyResolver}, a public key or a public JWK map; {@code fetch}:
 * {@link Fetch}). A verification failure throws {@link OidcVerificationError}; a discovery failure {@link OidcDiscoveryError}.
 */
public final class Oidc {
    private Oidc() {}

    public static final String OIDC_SUBJECT_CAVEAT = "oidc_subject";
    /** Default size cap for a discovery document (1 MiB). */
    public static final long DEFAULT_MAX_DISCOVERY_BYTES = 1024 * 1024;
    public static final long DEFAULT_JWKS_TIMEOUT_MS = OidcJwks.DEFAULT_JWKS_TIMEOUT_MS;
    /** The asymmetric OIDC signing algorithms allowed by default (symmetric algorithms are excluded). */
    public static final List<String> DEFAULT_ID_TOKEN_ALGS = List.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA");

    private static final String WELL_KNOWN = "/.well-known/openid-configuration";

    // ---- discovery ----

    private static boolean isHttps(String u) {
        WhatwgUrl p = WhatwgUrl.parse(u);
        return p != null && p.protocol.equals("https:");
    }

    /** The discovery URL of an issuer: the well-known path appended, one trailing slash of the issuer dropped. */
    public static String discoveryUrl(String issuer) {
        String trimmed = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        return trimmed + WELL_KNOWN;
    }

    public static Map<String, Object> discoverOidc(String issuer) { return discoverOidc(issuer, null); }

    /** Fetch and parse {@code <issuer>/.well-known/openid-configuration} (opts: fetch, maxBytes, requireHttps). */
    public static Map<String, Object> discoverOidc(String issuer, Map<String, Object> opts) {
        Map<String, Object> o = opts == null ? new LinkedHashMap<>() : opts;
        if (issuer == null || issuer.isEmpty()) throw new OidcDiscoveryError("discoverOidc: issuer must be a non-empty string");
        boolean requireHttps = !Boolean.FALSE.equals(o.get("requireHttps"));
        if (requireHttps && !isHttps(issuer)) throw new OidcDiscoveryError("discoverOidc: issuer '" + issuer + "' is not an https URL");
        Fetch fetch = o.get("fetch") instanceof Fetch ? (Fetch) o.get("fetch") : Fetch.http();
        String url = discoveryUrl(issuer);
        Fetch.Response res;
        try {
            Map<String, String> h = new LinkedHashMap<>();
            h.put("accept", "application/json");
            res = fetch.get(url, h, 0);
        } catch (Exception e) {
            throw new OidcDiscoveryError("discoverOidc: fetch of " + url + " failed", e);
        }
        if (!res.ok) throw new OidcDiscoveryError("discoverOidc: " + url + " returned HTTP " + res.status);
        double maxBytes = o.get("maxBytes") == null ? DEFAULT_MAX_DISCOVERY_BYTES : JsVal.num(o.get("maxBytes"));
        double declared = declaredLength(res.contentLength);
        if (!Double.isNaN(declared) && !Double.isInfinite(declared) && declared > maxBytes) throw new OidcDiscoveryError("discoverOidc: " + url + " response exceeds " + (long) maxBytes + " bytes");
        Object body;
        try {
            if (Json.utf8(res.text).length > maxBytes) throw new OidcDiscoveryError("discoverOidc: " + url + " response exceeds " + (long) maxBytes + " bytes");
            body = Json.parseLenient(res.text);
        } catch (OidcDiscoveryError e) {
            throw e;
        } catch (RuntimeException e) {
            throw new OidcDiscoveryError("discoverOidc: " + url + " did not return valid JSON", e);
        }
        Map<String, Object> meta = asMetadata(body);
        if (!issuer.equals(meta.get("issuer"))) throw new OidcDiscoveryError("discoverOidc: metadata issuer '" + meta.get("issuer") + "' does not match requested '" + issuer + "'");
        if (requireHttps && !isHttps((String) meta.get("jwks_uri"))) throw new OidcDiscoveryError("discoverOidc: jwks_uri '" + meta.get("jwks_uri") + "' is not an https URL");
        return meta;
    }

    /** Number(headers.get('content-length')): null reads as 0, an unparseable value as NaN. */
    private static double declaredLength(String v) {
        if (v == null) return 0;
        String t = v.trim();
        if (t.isEmpty()) return 0;
        try { return Double.parseDouble(t); } catch (NumberFormatException e) { return Double.NaN; }
    }

    private static Map<String, Object> asMetadata(Object body) {
        if (!(body instanceof Map)) throw new OidcDiscoveryError("discoverOidc: metadata is not a JSON object");
        Map<?, ?> rec = (Map<?, ?>) body;
        Object issuer = rec.get("issuer");
        if (!(issuer instanceof String) || ((String) issuer).isEmpty()) throw new OidcDiscoveryError("discoverOidc: metadata is missing a string \"issuer\"");
        Object jwksUri = rec.get("jwks_uri");
        if (!(jwksUri instanceof String) || ((String) jwksUri).isEmpty()) throw new OidcDiscoveryError("discoverOidc: metadata is missing a string \"jwks_uri\"");
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("issuer", issuer);
        meta.put("jwks_uri", jwksUri);
        for (Map.Entry<?, ?> e : rec.entrySet()) {
            String k = (String) e.getKey();
            if (!k.equals("issuer") && !k.equals("jwks_uri")) meta.put(k, e.getValue());
        }
        return meta;
    }

    // ---- JWKS resolver ----

    /** A fail-closed caching JWKS resolver (see {@link OidcJwks}); pass it as {@code key}. */
    public static OidcJwks createOidcJwks(Map<String, Object> opts) { return new OidcJwks(opts); }

    /** Discover the issuer's jwks_uri (https unless requireHttps is false) and build the resolver. */
    public static OidcJwks createOidcJwksFromIssuer(String issuer, Map<String, Object> opts) {
        Map<String, Object> o = opts == null ? new LinkedHashMap<>() : opts;
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("requireHttps", o.get("requireHttps"));
        d.put("fetch", o.get("fetch"));
        Map<String, Object> meta = discoverOidc(issuer, d);
        Map<String, Object> j = new LinkedHashMap<>(o);
        j.put("jwksUri", meta.get("jwks_uri"));
        return new OidcJwks(j);
    }

    // ---- ID-token verification ----

    public static Map<String, Object> verifyIdToken(String idToken, Map<String, Object> opts) { return verifyIdToken(idToken, opts, System::currentTimeMillis); }

    /** Verify an ID token and return its verified claims. {@code clock} supplies the verification time (epoch ms). */
    public static Map<String, Object> verifyIdToken(String idToken, Map<String, Object> opts, LongSupplier clock) {
        if (idToken == null || idToken.isEmpty()) throw new OidcVerificationError("invalid_token", "verifyIdToken: idToken must be a non-empty string");
        if (opts == null) throw new OidcVerificationError("config", "verifyIdToken: opts is required");
        Object issuer = opts.get("issuer");
        if (!(issuer instanceof String) || ((String) issuer).isEmpty()) throw new OidcVerificationError("config", "verifyIdToken: opts.issuer is required");
        Object audience = opts.get("audience");
        if (!(audience instanceof String) && !(audience instanceof List)) throw new OidcVerificationError("config", "verifyIdToken: opts.audience is required");
        // a non-finite skew tolerance would make every expiry comparison pass; a NaN age limit would disable the age check
        if (opts.get("clockToleranceSec") != null) {
            Double ct = JsVal.num(opts.get("clockToleranceSec"));
            if (ct == null || !(Double.isFinite(ct) && ct >= 0)) throw new OidcVerificationError("config", "verifyIdToken: clockToleranceSec must be a finite number >= 0");
        }
        if (opts.get("maxTokenAgeSec") != null) {
            Double mt = JsVal.num(opts.get("maxTokenAgeSec"));
            if (mt == null || !(mt >= 0)) throw new OidcVerificationError("config", "verifyIdToken: maxTokenAgeSec must be a number >= 0");
        }

        Jws.Canonical canon;
        try {
            canon = Jws.assertCanonicalCompactJws(idToken);
        } catch (RuntimeException cause) {
            throw new OidcVerificationError("invalid_token", cause.getMessage());
        }
        Object key = resolveKey(opts);
        List<Object> algs = new ArrayList<>();
        Object ao = opts.get("algorithms");
        if (ao == null) algs.addAll(DEFAULT_ID_TOKEN_ALGS);
        else if (ao instanceof List) algs.addAll((List<?>) ao);
        else throw new IllegalArgumentException("verifyIdToken: algorithms must be an array");
        Map<String, Object> vo = new LinkedHashMap<>();
        vo.put("issuer", issuer);
        vo.put("audience", audience);
        vo.put("algorithms", algs);
        if (opts.get("clockToleranceSec") != null) vo.put("clockTolerance", opts.get("clockToleranceSec"));
        if (opts.get("maxTokenAgeSec") != null) vo.put("maxTokenAge", opts.get("maxTokenAgeSec"));

        Jws.Verified verified;
        try {
            verified = Jws.jwtVerify(idToken, canon, key, vo, clock.getAsLong());
        } catch (RuntimeException cause) {
            throw mapJoseError(cause);
        }
        Map<String, Object> claims = projectClaims(verified.payload, opts);
        Object alg = canon.header.get("alg");
        if (opts.get("accessToken") != null) checkHalfHash("at_hash", claims.get("at_hash"), opts.get("accessToken"), alg);
        if (opts.get("code") != null) checkHalfHash("c_hash", claims.get("c_hash"), opts.get("code"), alg);
        return claims;
    }

    /** OIDC Core 3.1.3.6: base64url(left half of H(value)), H chosen by the ID token's alg (EdDSA = SHA-512). */
    private static void checkHalfHash(String name, Object actual, Object value, Object alg) {
        if (actual == null) throw new OidcVerificationError(name, "id token is missing the expected " + name);
        String bits = null;
        if ("EdDSA".equals(alg)) bits = "512";
        else if (alg instanceof String) {
            String a = (String) alg;
            if (a.endsWith("256") || a.endsWith("384") || a.endsWith("512")) bits = a.substring(a.length() - 3);
        }
        if (bits == null) throw new OidcVerificationError(name, "cannot compute " + name + " for alg " + alg);
        if (!(value instanceof String)) throw new IllegalArgumentException("verifyIdToken: " + name + " source must be a string");
        String v = (String) value;
        byte[] raw = new byte[v.length()];
        for (int i = 0; i < raw.length; i++) raw[i] = (byte) v.charAt(i); // 'ascii' encoding keeps the low byte
        byte[] digest;
        try { digest = MessageDigest.getInstance("SHA-" + bits).digest(raw); } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
        String expected = Keys.b64u(Arrays.copyOf(digest, digest.length / 2));
        if (!expected.equals(actual)) throw new OidcVerificationError(name, "id token " + name + " does not match the supplied value");
    }

    /** {@code key} wins, then {@code jwksUri}, then {@code discover}; a URI is wrapped in the fail-closed resolver, built per call. */
    private static Object resolveKey(Map<String, Object> opts) {
        if (opts.get("key") != null) return opts.get("key");
        Object requireHttps = opts.get("requireHttps");
        Object jwksUri = opts.get("jwksUri");
        if (jwksUri == null && Boolean.TRUE.equals(opts.get("discover"))) {
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("requireHttps", requireHttps);
            d.put("fetch", opts.get("fetch"));
            jwksUri = discoverOidc((String) opts.get("issuer"), d).get("jwks_uri");
        }
        if (jwksUri == null) throw new OidcVerificationError("config", "verifyIdToken: no key source (pass opts.key, opts.jwksUri, or opts.discover)");
        try {
            Map<String, Object> j = new LinkedHashMap<>();
            j.put("jwksUri", jwksUri);
            j.put("requireHttps", requireHttps);
            return new OidcJwks(j);
        } catch (RuntimeException cause) {
            throw new OidcVerificationError("config", "verifyIdToken: " + cause.getMessage(), cause);
        }
    }

    private static String asString(Object v) { return v instanceof String && !((String) v).isEmpty() ? (String) v : null; }

    private static Double asFiniteNumber(Object v) {
        Double d = v instanceof Json.Num || v instanceof Number ? JsVal.num(v) : null;
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) ? d : null;
    }

    private static Map<String, Object> projectClaims(Map<String, Object> payload, Map<String, Object> opts) {
        String iss = asString(payload.get("iss"));
        if (iss == null) throw new OidcVerificationError("issuer", "id token is missing the \"iss\" claim");
        String sub = asString(payload.get("sub"));
        if (sub == null) throw new OidcVerificationError("claims", "id token is missing the \"sub\" claim");
        Object aud = payload.get("aud");
        if (aud == null) throw new OidcVerificationError("audience", "id token is missing the \"aud\" claim");
        if (asFiniteNumber(payload.get("iat")) == null) throw new OidcVerificationError("issued_at", "id token is missing a numeric \"iat\" claim");
        if (asFiniteNumber(payload.get("exp")) == null) throw new OidcVerificationError("expired", "id token is missing a numeric \"exp\" claim");

        String nonce = asString(payload.get("nonce"));
        String azp = asString(payload.get("azp"));
        Object expectedNonce = opts.get("nonce");
        if (expectedNonce != null && !expectedNonce.equals(nonce)) {
            throw new OidcVerificationError("nonce", nonce == null ? "id token is missing the expected nonce" : "id token nonce does not match the expected value");
        }
        int audCount = aud instanceof List ? ((List<?>) aud).size() : 1;
        Object expectedAzp = opts.get("authorizedParty") != null ? opts.get("authorizedParty") : opts.get("audience") instanceof String ? opts.get("audience") : null;
        if (audCount > 1 && azp == null) throw new OidcVerificationError("azp", "id token has multiple audiences but no azp (authorized party)");
        if (azp != null && expectedAzp != null && !azp.equals(expectedAzp)) throw new OidcVerificationError("azp", "id token azp does not match the authorized party");

        Map<String, Object> c = new LinkedHashMap<>();
        c.put("iss", iss);
        c.put("sub", sub);
        c.put("aud", aud);
        c.put("iat", payload.get("iat"));
        c.put("exp", payload.get("exp"));
        if (nonce != null) c.put("nonce", nonce);
        if (azp != null) c.put("azp", azp);
        if (asString(payload.get("at_hash")) != null) c.put("at_hash", payload.get("at_hash"));
        if (asString(payload.get("c_hash")) != null) c.put("c_hash", payload.get("c_hash"));
        if (asFiniteNumber(payload.get("auth_time")) != null) c.put("auth_time", payload.get("auth_time"));
        if (asString(payload.get("email")) != null) c.put("email", payload.get("email"));
        if (payload.get("email_verified") instanceof Boolean) c.put("email_verified", payload.get("email_verified"));
        if (asString(payload.get("name")) != null) c.put("name", payload.get("name"));
        if (asString(payload.get("preferred_username")) != null) c.put("preferred_username", payload.get("preferred_username"));
        if (asString(payload.get("given_name")) != null) c.put("given_name", payload.get("given_name"));
        if (asString(payload.get("family_name")) != null) c.put("family_name", payload.get("family_name"));
        if (asString(payload.get("picture")) != null) c.put("picture", payload.get("picture"));
        if (payload.get("cnf") instanceof Map) {
            Map<String, Object> cnf = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) payload.get("cnf")).entrySet()) cnf.put((String) e.getKey(), e.getValue());
            c.put("cnf", cnf);
        }
        return c;
    }

    private static OidcVerificationError mapJoseError(RuntimeException e) {
        if (e instanceof OidcVerificationError) return (OidcVerificationError) e;
        if (e instanceof Jws.JoseException) {
            Jws.JoseException j = (Jws.JoseException) e;
            switch (j.kind) {
                case "expired":
                    return "iat".equals(j.claim) ? new OidcVerificationError("issued_at", "id token is older than the maximum accepted age", e)
                        : new OidcVerificationError("expired", "id token has expired", e);
                case "claim": {
                    String code = "iss".equals(j.claim) ? "issuer" : "aud".equals(j.claim) ? "audience" : "iat".equals(j.claim) ? "issued_at" : "nbf".equals(j.claim) ? "not_before" : "claims";
                    return new OidcVerificationError(code, j.getMessage(), e);
                }
                case "signature":
                    return new OidcVerificationError("signature", "id token signature verification failed", e);
                default:
                    return new OidcVerificationError("invalid_token", j.getMessage(), e);
            }
        }
        return new OidcVerificationError("invalid_token", "id token verification failed", e);
    }

    // ---- principal ----

    /** Map verified OIDC claims onto a PCA principal descriptor. Throws on a missing iss / sub or a bad key. */
    public static Map<String, Object> oidcPrincipal(Map<String, Object> claims) { return oidcPrincipal(claims, null); }

    public static Map<String, Object> oidcPrincipal(Map<String, Object> claims, Map<String, Object> opts) {
        Object iss = claims.get("iss"), sub = claims.get("sub");
        if (!(iss instanceof String) || ((String) iss).isEmpty()) throw new IllegalArgumentException("oidcPrincipal: claims.iss is required");
        if (!(sub instanceof String) || ((String) sub).isEmpty()) throw new IllegalArgumentException("oidcPrincipal: claims.sub is required");
        String fromToken = ed25519PublicFromCnf(claims.get("cnf"));
        String principalPublic = fromToken;
        if (opts != null && opts.containsKey("principalPublic")) {
            String provided = canonicalEd25519B64u(opts.get("principalPublic"));
            if (provided == null) throw new IllegalArgumentException("oidcPrincipal: opts.principalPublic is not a canonical base64url Ed25519 public key");
            if (fromToken != null && !fromToken.equals(provided)) throw new IllegalStateException("oidcPrincipal: opts.principalPublic does not match the cnf-bound key in the ID token");
            principalPublic = provided;
        }
        Map<String, Object> caveat = new LinkedHashMap<>();
        caveat.put("type", OIDC_SUBJECT_CAVEAT);
        caveat.put("iss", iss);
        caveat.put("sub", sub);
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("iss", iss);
        p.put("sub", sub);
        p.put("principalId", iss + "#" + sub);
        p.put("subjectCaveat", caveat);
        p.put("claims", claims);
        if (principalPublic != null) p.put("principalPublic", principalPublic);
        if (claims.containsKey("email")) p.put("email", claims.get("email"));
        if (claims.containsKey("email_verified")) p.put("emailVerified", claims.get("email_verified"));
        if (claims.containsKey("name")) p.put("name", claims.get("name"));
        if (claims.containsKey("preferred_username")) p.put("preferredUsername", claims.get("preferred_username"));
        if (claims.containsKey("auth_time")) p.put("authTime", claims.get("auth_time"));
        return p;
    }

    /** Narrowing guard for an oidc_subject caveat. */
    public static boolean isOidcSubjectCaveat(Object cv) {
        if (!(cv instanceof Map)) return false;
        Map<?, ?> m = (Map<?, ?>) cv;
        return OIDC_SUBJECT_CAVEAT.equals(m.get("type")) && m.get("iss") instanceof String && !((String) m.get("iss")).isEmpty()
            && m.get("sub") instanceof String && !((String) m.get("sub")).isEmpty();
    }

    private static String ed25519PublicFromCnf(Object cnf) {
        if (cnf == null) return null;
        Object jwk = JsVal.get(cnf, "jwk");
        if (!(jwk instanceof Map)) return null;
        Map<?, ?> j = (Map<?, ?>) jwk;
        if (!"OKP".equals(j.get("kty")) || !"Ed25519".equals(j.get("crv"))) return null;
        if (!(j.get("x") instanceof String)) return null;
        return canonicalEd25519B64u(j.get("x"));
    }

    /** {@code s} iff it is the canonical, unpadded base64url of exactly 32 bytes; else null. */
    private static String canonicalEd25519B64u(Object s) {
        if (!(s instanceof String) || ((String) s).isEmpty()) return null;
        return Pca.decodeB64uStrict(s, 32) == null ? null : (String) s;
    }
}
