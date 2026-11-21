package net.atlasauth.pca.idjag;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.oauth.Jws;
import net.atlasauth.pca.oidc.Oidc;
import net.atlasauth.pca.oidc.OidcVerificationError;

/**
 * An ID-JAG / OAuth Cross-App-Access bridge for Proof-Carrying Authority (draft-ietf-oauth-identity-assertion-authz-grant): verify an
 * ID-JAG (reusing the OIDC verifier for every crypto and registered-claim check), project it onto a PCA principal and a signed root
 * capability, and build the RFC 8693 token-exchange and RFC 7523 jwt-bearer requests of the flow. Options use the reference's names;
 * {@code key} / {@code fetch} take the same Java objects as {@link Oidc}, {@code consumeJti} a {@link JtiStore}.
 */
public final class IdJag {
    private IdJag() {}

    /** Upper bound on an accepted ID-JAG string (adversarial-size guard, checked before any parsing). */
    public static final int MAX_ID_JAG_CHARS = 16384;
    public static final String IDJAG_AUTHORITY_CAVEAT = "idjag_authority";
    public static final String IDJAG_PROVENANCE_CAVEAT = "idjag_provenance";
    public static final String GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String TOKEN_TYPE_ID_JAG = "urn:ietf:params:oauth:token-type:id-jag";
    public static final String TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
    public static final String TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
    public static final String TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";
    public static final String CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    // ---- verification ----

    public static Map<String, Object> verifyIdJag(String jwt, Map<String, Object> opts) { return verifyIdJag(jwt, opts, System::currentTimeMillis); }

    /** Verify an ID-JAG and return the parsed grant; fails closed with an {@link IdJagVerificationError}. {@code clock}: verification time (epoch ms). */
    public static Map<String, Object> verifyIdJag(String jwt, Map<String, Object> opts, LongSupplier clock) {
        if (jwt == null || jwt.isEmpty()) throw new IdJagVerificationError("invalid_token", "verifyIdJag: jwt must be a non-empty string");
        if (jwt.length() > MAX_ID_JAG_CHARS) throw new IdJagVerificationError("invalid_token", "verifyIdJag: jwt exceeds the size limit");
        if (opts == null) throw new IdJagVerificationError("config", "verifyIdJag: opts is required");
        if (!(opts.get("issuer") instanceof String) || ((String) opts.get("issuer")).isEmpty()) throw new IdJagVerificationError("config", "verifyIdJag: opts.issuer is required");
        if (!(opts.get("audience") instanceof String) || ((String) opts.get("audience")).isEmpty()) throw new IdJagVerificationError("config", "verifyIdJag: opts.audience is required (ID-JAG is single-audience)");
        String audience = (String) opts.get("audience");

        boolean strict = !Boolean.FALSE.equals(opts.get("strictDraft"));
        if (strict && !(opts.get("consumeJti") instanceof JtiStore)) throw new IdJagVerificationError("config", "verifyIdJag: strictDraft requires opts.consumeJti (single-use store)");
        if (strict && (!(opts.get("clientId") instanceof String) || ((String) opts.get("clientId")).isEmpty())) {
            throw new IdJagVerificationError("config", "verifyIdJag: strictDraft requires opts.clientId (the client authenticated at the token endpoint)");
        }

        Map<String, Object> o = new LinkedHashMap<>();
        o.put("issuer", opts.get("issuer"));
        o.put("audience", audience);
        for (String k : new String[] {"nonce", "clockToleranceSec", "maxTokenAgeSec", "algorithms", "key", "jwksUri", "discover", "fetch"}) if (opts.get(k) != null) o.put(k, opts.get(k));
        Map<String, Object> base;
        try {
            base = Oidc.verifyIdToken(jwt, o, clock);
        } catch (OidcVerificationError cause) {
            throw new IdJagVerificationError(cause.code(), cause.getMessage(), cause);
        } catch (RuntimeException cause) {
            throw new IdJagVerificationError("invalid_token", "ID-JAG verification failed", cause);
        }

        // ID-JAG is SINGLE-AUDIENCE: the resource app must be the sole aud.
        Object aud = base.get("aud");
        List<?> audList = aud instanceof List ? (List<?>) aud : List.of(aud);
        if (audList.size() != 1 || !audience.equals(audList.get(0))) {
            throw new IdJagVerificationError("audience", "ID-JAG must carry exactly one audience equal to the resource app (single-audience grant)");
        }

        Jws.Canonical canon;
        try {
            canon = Jws.assertCanonicalCompactJws(jwt);
        } catch (RuntimeException cause) {
            throw new IdJagVerificationError("invalid_token", "ID-JAG payload could not be decoded", cause);
        }
        Map<String, Object> raw = canon.payload;

        Map<String, Object> actor = asActor(raw.get("act"));
        if (actor == null) throw new IdJagVerificationError("actor", "ID-JAG is missing a well-formed \"act\" (agent) claim with a string \"sub\"");

        List<Object> scopes = parseScopes(raw.get("scope"), raw.get("scopes"));
        if (scopes == null) throw new IdJagVerificationError("scope", "ID-JAG is missing the \"scope\" (or \"scopes\") claim");
        if (opts.get("requiredScopes") instanceof List) {
            Set<Object> have = new HashSet<>(scopes);
            for (Object req : (List<?>) opts.get("requiredScopes")) {
                if (!have.contains(req)) throw new IdJagVerificationError("scope", "ID-JAG does not grant the required scope \"" + req + "\"");
            }
        }

        Object jtiRaw = raw.get("jti");
        String jti = jtiRaw instanceof String && !((String) jtiRaw).isEmpty() ? (String) jtiRaw : null;

        if (strict) {
            if (!"oauth-id-jag+jwt".equals(canon.header.get("typ"))) throw new IdJagVerificationError("grant", "ID-JAG header typ must be \"oauth-id-jag+jwt\"");
            Object cid = raw.get("client_id");
            if (!(cid instanceof String) || ((String) cid).isEmpty()) throw new IdJagVerificationError("grant", "ID-JAG is missing \"client_id\"");
            if (!cid.equals(opts.get("clientId"))) throw new IdJagVerificationError("grant", "ID-JAG client_id does not match the expected client");
            if (jti == null) throw new IdJagVerificationError("grant", "ID-JAG is missing \"jti\"");
            boolean fresh;
            try {
                fresh = Boolean.TRUE.equals(((JtiStore) opts.get("consumeJti")).consume(jti, JsVal.num(base.get("exp"))));
            } catch (Exception e) {
                fresh = false;
            }
            if (!fresh) throw new IdJagVerificationError("grant", "ID-JAG jti was already used or the single-use store failed");
        }

        Map<String, Object> g = new LinkedHashMap<>();
        g.put("iss", base.get("iss"));
        g.put("sub", base.get("sub"));
        g.put("actor", actor);
        g.put("agent", actor.get("sub"));
        g.put("audience", audience);
        g.put("scopes", scopes);
        g.put("iat", base.get("iat"));
        g.put("exp", base.get("exp"));
        if (jti != null) g.put("jti", jti);
        if (base.containsKey("nonce")) g.put("nonce", base.get("nonce"));
        if (base.containsKey("cnf")) g.put("cnf", base.get("cnf"));
        g.put("oidcClaims", base);
        return g;
    }

    private static Map<String, Object> asActor(Object v) {
        if (!(v instanceof Map)) return null;
        Object sub = ((Map<?, ?>) v).get("sub");
        if (!(sub instanceof String) || ((String) sub).isEmpty()) return null;
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) out.put((String) e.getKey(), e.getValue());
        out.put("sub", sub);
        return out;
    }

    private static boolean nonEmptyString(Object s) { return s instanceof String && !((String) s).isEmpty(); }

    private static List<Object> strings(List<?> l) {
        List<Object> out = new ArrayList<>();
        for (Object s : l) if (nonEmptyString(s)) out.add(s);
        return out;
    }

    /** s.split(/\s+/) without the empty entries: the JavaScript whitespace set separates. */
    private static List<Object> splitWords(String s) {
        List<Object> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (AttestCommon.isJsSpace(c)) {
                if (cur.length() > 0) { out.add(cur.toString()); cur.setLength(0); }
            } else cur.append(c);
        }
        if (cur.length() > 0) out.add(cur.toString());
        return out;
    }

    /** The delegated authority from the scope (space-delimited string or array) / scopes claim. */
    private static List<Object> parseScopes(Object scope, Object scopes) {
        if (scope instanceof String) return splitWords((String) scope);
        if (scope instanceof List) return strings((List<?>) scope);
        if (scopes instanceof List) return strings((List<?>) scopes);
        return null;
    }

    // ---- ID-JAG -> PCA principal / capability ----

    public static Map<String, Object> idJagToPcaPrincipal(Map<String, Object> grant) { return idJagToPcaPrincipal(grant, null); }

    /** The PCA principal descriptor of a verified ID-JAG (delegates to the OIDC mapping over the grant's base claims). */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> idJagToPcaPrincipal(Map<String, Object> grant, Map<String, Object> opts) {
        if (grant == null) throw new IllegalArgumentException("idJagToPcaPrincipal: grant is required");
        Object claims = grant.get("oidcClaims");
        if (!(claims instanceof Map)) throw new IllegalArgumentException("idJagToPcaPrincipal: grant has no claims");
        return Oidc.oidcPrincipal((Map<String, Object>) claims, opts);
    }

    /**
     * Project a verified ID-JAG onto a signed PCA ROOT capability (authority = the grant's scopes, holder = the agent key, subject =
     * the human, plus provenance). Options: principalSecret (the 32-byte Ed25519 seed, byte[]), principalPublic (b64u, must be that
     * seed's public key: a mismatch is refused here rather than signed), holder (b64u), extraCaveats. Returns {capability, principal, scopes}.
     * Optional {@code suite} (a {@code Keys.SuiteKey}) signs the root under ML-DSA / a hybrid; its Ed25519 key must be the principal's key.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> idJagToCapability(Map<String, Object> grant, Map<String, Object> opts) {
        if (grant == null) throw new IllegalArgumentException("idJagToCapability: grant is required");
        if (opts == null) throw new IllegalArgumentException("idJagToCapability: opts is required");
        Object secret = opts.get("principalSecret");
        if (!(secret instanceof byte[])) throw new IllegalArgumentException("idJagToCapability: opts.principalSecret must be a byte array");
        if (!nonEmptyString(opts.get("principalPublic"))) throw new IllegalArgumentException("idJagToCapability: opts.principalPublic is required");
        if (!nonEmptyString(opts.get("holder"))) throw new IllegalArgumentException("idJagToCapability: opts.holder (the agent key) is required");

        Map<String, Object> po = new LinkedHashMap<>();
        po.put("principalPublic", opts.get("principalPublic"));
        Map<String, Object> principal = idJagToPcaPrincipal(grant, po);

        Map<String, Object> authority = new LinkedHashMap<>();
        authority.put("type", IDJAG_AUTHORITY_CAVEAT);
        authority.put("scopes", new ArrayList<Object>((List<Object>) grant.get("scopes")));
        authority.put("aud", grant.get("audience"));
        Map<String, Object> provenance = new LinkedHashMap<>();
        provenance.put("type", IDJAG_PROVENANCE_CAVEAT);
        provenance.put("iss", grant.get("iss"));
        provenance.put("sub", grant.get("sub"));
        provenance.put("agent", grant.get("agent"));
        provenance.put("aud", grant.get("audience"));
        provenance.put("iat", grant.get("iat"));
        provenance.put("exp", grant.get("exp"));
        if (grant.get("jti") != null) provenance.put("jti", grant.get("jti"));
        List<Object> caveats = new ArrayList<>();
        caveats.add(authority);
        caveats.add(provenance);
        caveats.add(principal.get("subjectCaveat"));
        Object extra = opts.get("extraCaveats");
        if (extra != null) {
            if (!(extra instanceof List)) throw new IllegalArgumentException("idJagToCapability: opts.extraCaveats must be an array");
            caveats.addAll((List<Object>) extra);
        }

        Keys.EdKey key = Keys.edFromSeed((byte[]) secret);
        if (!key.id().equals(opts.get("principalPublic"))) throw new IllegalArgumentException("idJagToCapability: opts.principalSecret does not match opts.principalPublic");
        Object so = opts.get("suite");
        if (so != null && !(so instanceof Keys.SuiteKey)) throw new IllegalArgumentException("idJagToCapability: opts.suite must be a Keys.SuiteKey");
        Keys.SuiteKey suite = so != null ? (Keys.SuiteKey) so : Keys.ed25519(key);
        if (suite.ed == null || !key.id().equals(suite.ed.id())) throw new IllegalArgumentException("idJagToCapability: opts.suite does not carry the principal's Ed25519 key");
        Map<String, Object> capability = Issue.mintRoot(suite, (String) opts.get("holder"), null, caveats);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("capability", capability);
        out.put("principal", principal);
        out.put("scopes", new ArrayList<Object>((List<Object>) grant.get("scopes")));
        return out;
    }

    public static boolean isIdJagAuthorityCaveat(Object cv) {
        if (!(cv instanceof Map)) return false;
        Map<?, ?> m = (Map<?, ?>) cv;
        if (!IDJAG_AUTHORITY_CAVEAT.equals(m.get("type")) || !(m.get("scopes") instanceof List)) return false;
        for (Object s : (List<?>) m.get("scopes")) if (!(s instanceof String)) return false;
        return nonEmptyString(m.get("aud"));
    }

    public static boolean isIdJagProvenanceCaveat(Object cv) {
        if (!(cv instanceof Map)) return false;
        Map<?, ?> m = (Map<?, ?>) cv;
        return IDJAG_PROVENANCE_CAVEAT.equals(m.get("type")) && m.get("iss") instanceof String && m.get("sub") instanceof String && m.get("agent") instanceof String
            && m.get("aud") instanceof String && JsVal.isNumber(m.get("iat")) && JsVal.isNumber(m.get("exp"));
    }

    private static Object firstCaveat(Object cap, String type) {
        if (!(cap instanceof Map)) return null;
        Object cvs = ((Map<?, ?>) cap).get("caveats");
        if (cvs == null) return null;
        if (!(cvs instanceof List)) throw new IllegalArgumentException("cap?.caveats?.find is not a function"); // a JavaScript TypeError
        for (Object c : (List<?>) ((Map<?, ?>) cap).get("caveats")) if (c instanceof Map && type.equals(((Map<?, ?>) c).get("type"))) return c;
        return null;
    }

    /** The authority caveat of a root capability, or null when absent or malformed. */
    public static Object readIdJagAuthority(Object cap) {
        Object cv = firstCaveat(cap, IDJAG_AUTHORITY_CAVEAT);
        return cv != null && isIdJagAuthorityCaveat(cv) ? cv : null;
    }

    /** The provenance caveat of a root capability, or null when absent or malformed. */
    public static Object readIdJagProvenance(Object cap) {
        Object cv = firstCaveat(cap, IDJAG_PROVENANCE_CAVEAT);
        return cv != null && isIdJagProvenanceCaveat(cv) ? cv : null;
    }

    // ---- XAA flow: token-exchange and jwt-bearer request shapes ----

    private static String formEncode(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { sb.append(c).append(s.charAt(++i)); }
            else if (Character.isSurrogate(c)) sb.append('�'); // USVString conversion
            else sb.append(c);
        }
        return URLEncoder.encode(sb.toString(), StandardCharsets.UTF_8);
    }

    private static Map<String, Object> formRequest(String url, Map<String, Object> params) {
        Map<String, Object> clean = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : params.entrySet()) if (nonEmptyString(e.getValue())) clean.put(e.getKey(), e.getValue());
        StringBuilder body = new StringBuilder();
        for (Map.Entry<String, Object> e : clean.entrySet()) {
            if (body.length() > 0) body.append('&');
            body.append(formEncode(e.getKey())).append('=').append(formEncode((String) e.getValue()));
        }
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("content-type", "application/x-www-form-urlencoded");
        headers.put("accept", "application/json");
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("url", url);
        r.put("method", "POST");
        r.put("headers", headers);
        r.put("params", clean);
        r.put("body", body.toString());
        return r;
    }

    /** A scope string or array as the space-delimited OAuth scope, or null when empty. */
    private static String scopeParam(Object scope) {
        if (scope == null) return null;
        List<Object> parts;
        if (scope instanceof List) parts = strings((List<?>) scope);
        else if (scope instanceof String) parts = splitWords((String) scope);
        else throw new IllegalArgumentException("scopeParam: scope must be a string or an array");
        if (parts.isEmpty()) return null;
        List<String> s = new ArrayList<>();
        for (Object p : parts) s.add((String) p);
        return String.join(" ", s);
    }

    private static Object orDefault(Object v, Object d) { return v == null ? d : v; }

    /** The RFC 8693 token-exchange request that OBTAINS an ID-JAG from the IdP (the first XAA leg). */
    public static Map<String, Object> tokenExchangeRequest(Map<String, Object> opts) {
        if (opts == null) throw new IllegalArgumentException("tokenExchangeRequest: opts is required");
        if (!nonEmptyString(opts.get("tokenEndpoint"))) throw new IllegalArgumentException("tokenExchangeRequest: opts.tokenEndpoint is required");
        if (!nonEmptyString(opts.get("subjectToken"))) throw new IllegalArgumentException("tokenExchangeRequest: opts.subjectToken is required");
        boolean hasActor = nonEmptyString(opts.get("actorToken"));
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("grant_type", GRANT_TYPE_TOKEN_EXCHANGE);
        p.put("subject_token", opts.get("subjectToken"));
        p.put("subject_token_type", orDefault(opts.get("subjectTokenType"), TOKEN_TYPE_ID_TOKEN));
        p.put("requested_token_type", orDefault(opts.get("requestedTokenType"), TOKEN_TYPE_ID_JAG));
        if (opts.get("audience") != null) p.put("audience", opts.get("audience"));
        if (opts.get("resource") != null) p.put("resource", opts.get("resource"));
        String scope = scopeParam(opts.get("scope"));
        if (scope != null) p.put("scope", scope);
        if (hasActor) {
            p.put("actor_token", opts.get("actorToken"));
            p.put("actor_token_type", orDefault(opts.get("actorTokenType"), TOKEN_TYPE_JWT));
        }
        if (opts.get("clientId") != null) p.put("client_id", opts.get("clientId"));
        putExtra(p, opts.get("extra"));
        return formRequest((String) opts.get("tokenEndpoint"), p);
    }

    private static void putExtra(Map<String, Object> p, Object extra) {
        if (extra instanceof Map) for (Map.Entry<?, ?> e : ((Map<?, ?>) extra).entrySet()) p.put((String) e.getKey(), e.getValue());
    }

    /** The RFC 7523 jwt-bearer representation and request that REDEEMS an ID-JAG at the resource app's token endpoint (the second XAA leg). */
    public static Map<String, Object> jwtBearerAssertion(Map<String, Object> opts) {
        if (opts == null) throw new IllegalArgumentException("jwtBearerAssertion: opts is required");
        if (!nonEmptyString(opts.get("tokenEndpoint"))) throw new IllegalArgumentException("jwtBearerAssertion: opts.tokenEndpoint is required");
        if (!nonEmptyString(opts.get("assertion"))) throw new IllegalArgumentException("jwtBearerAssertion: opts.assertion is required");
        String scope = scopeParam(opts.get("scope"));
        boolean hasClientAssertion = nonEmptyString(opts.get("clientAssertion"));
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("grant_type", GRANT_TYPE_JWT_BEARER);
        p.put("assertion", opts.get("assertion"));
        if (scope != null) p.put("scope", scope);
        if (opts.get("clientId") != null) p.put("client_id", opts.get("clientId"));
        if (hasClientAssertion) {
            p.put("client_assertion_type", CLIENT_ASSERTION_TYPE_JWT_BEARER);
            p.put("client_assertion", opts.get("clientAssertion"));
        }
        putExtra(p, opts.get("extra"));
        Map<String, Object> request = formRequest((String) opts.get("tokenEndpoint"), p);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("grantType", GRANT_TYPE_JWT_BEARER);
        out.put("assertion", opts.get("assertion"));
        if (scope != null) out.put("scope", scope);
        out.put("request", request);
        return out;
    }
}
