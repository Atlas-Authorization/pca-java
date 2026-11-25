package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import net.atlasauth.pca.oauth.Fetch;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.oauth.Jws;
import net.atlasauth.pca.oidc.Oidc;
import net.atlasauth.pca.oidc.OidcDiscoveryError;
import net.atlasauth.pca.oidc.OidcJwks;
import net.atlasauth.pca.oidc.OidcVerificationError;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the OIDC package (discovery, ID-token verification, principal, JWKS resolver). */
public class OidcDiffTest {
    private static final String M = "ref-oidc-java";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    /** An exception that carries the reference's stable code, as the replay helper compares it. */
    static final class Coded extends RuntimeException implements OracleCases.Coded {
        private final String code;
        Coded(String code) { super(code); this.code = code; }
        @Override public String code() { return code; }
    }

    private static Map<String, Object> verifyOpts(Map<String, Object> opts) {
        if (opts == null) return null;
        Map<String, Object> o = new LinkedHashMap<>(opts);
        if (o.containsKey("jwks")) o.put("key", Jws.localJwks(o.remove("jwks")));
        return o;
    }

    private static Fetch.Response respond(Map<String, Object> r) throws Exception {
        if (r.containsKey("throws")) throw new Exception("net");
        int status = (int) (double) JsVal.num(r.get("status"));
        return new Fetch.Response(status >= 200 && status < 300, status, (String) r.get("contentLength"), (String) r.get("text"));
    }

    @Test void discoveryUrl() throws Exception { OracleCases.each(M, "discoveryUrl", a -> Oidc.discoveryUrl((String) a.get(0))); }

    @Test void discoverOidc() throws Exception {
        OracleCases.each(M, "discoverOidc", a -> {
            if (!(a.get(0) instanceof String)) throw new OidcDiscoveryError("issuer must be a string");
            Map<String, Object> o = new LinkedHashMap<>(m(a.get(1)));
            Map<String, Object> resp = m(a.get(2));
            o.put("fetch", (Fetch) (url, headers, timeout) -> respond(resp));
            return Oidc.discoverOidc((String) a.get(0), o);
        });
    }

    @Test void verifyIdToken() throws Exception {
        OracleCases.each(M, "verifyIdToken", a -> {
            if (!(a.get(0) instanceof String)) throw new Coded("invalid_token");
            try {
                Double clock = OracleCases.caseClockMs();
                Map<String, Object> vo = verifyOpts(a.get(1) == null ? null : m(a.get(1)));
                return clock == null ? Oidc.verifyIdToken((String) a.get(0), vo) : Oidc.verifyIdToken((String) a.get(0), vo, () -> (long) (double) clock);
            } catch (OidcVerificationError e) {
                throw new Coded(e.code());
            }
        });
    }

    @Test void oidcPrincipal() throws Exception { OracleCases.each(M, "oidcPrincipal", a -> Oidc.oidcPrincipal(m(a.get(0)), a.size() > 1 ? m(a.get(1)) : null)); }

    @Test void isOidcSubjectCaveat() throws Exception { OracleCases.each(M, "isOidcSubjectCaveat", a -> Oidc.isOidcSubjectCaveat(a.get(0))); }

    @Test void jwksScenario() throws Exception {
        OracleCases.each(M, "jwksScenario", a -> {
            final long[] cur = {0};
            final int[] fetches = {0};
            final Object[] queue = {null};
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("jwksUri", "https://idp.example.com/jwks");
            o.putAll(m(a.get(0)));
            o.put("fetch", (Fetch) (url, headers, timeout) -> {
                fetches[0]++;
                if (queue[0] == null || "throw".equals(queue[0])) throw new Exception("net");
                Map<String, Object> q = m(queue[0]);
                int st = (int) (double) JsVal.num(q.get("status"));
                return new Fetch.Response(st >= 200 && st < 300, st, null, (String) q.get("text"));
            });
            o.put("now", (LongSupplier) () -> cur[0]);
            OidcJwks r = Oidc.createOidcJwks(o);
            List<Object> out = new ArrayList<>();
            for (Object s : (List<?>) a.get(1)) {
                Map<String, Object> step = m(s);
                cur[0] = (long) (double) JsVal.num(step.get("t"));
                queue[0] = step.get("resp");
                Map<String, Object> res = new LinkedHashMap<>();
                try {
                    r.getKey(m(step.get("header")));
                    res.put("fetches", JsVal.n(fetches[0]));
                    res.put("ok", Boolean.TRUE);
                } catch (OidcVerificationError e) {
                    res.put("fetches", JsVal.n(fetches[0]));
                    res.put("ok", Boolean.FALSE);
                    res.put("code", e.code());
                } catch (RuntimeException e) {
                    res.put("fetches", JsVal.n(fetches[0]));
                    res.put("ok", Boolean.FALSE);
                    res.put("code", "other");
                }
                out.add(res);
            }
            return out;
        });
    }

    // ---- RSA and RSA-PSS (their signatures are randomized or need a fresh key, so no shared vector) ----

    private static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    private static String rsaToken(String alg, KeyPair kp, String kid) throws Exception {
        String h = b64u(("{\"alg\":\"" + alg + "\",\"kid\":\"" + kid + "\"}").getBytes(StandardCharsets.UTF_8));
        String p = b64u("{\"iss\":\"https://idp.example.com\",\"sub\":\"u\",\"aud\":\"c\",\"iat\":1700000000,\"exp\":4000000000}".getBytes(StandardCharsets.UTF_8));
        Signature s;
        if (alg.startsWith("PS")) {
            s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        } else {
            s = Signature.getInstance("SHA256withRSA");
        }
        s.initSign(kp.getPrivate());
        s.update((h + "." + p).getBytes(StandardCharsets.UTF_8));
        return h + "." + p + "." + b64u(s.sign());
    }

    @Test void rsaAndPssTokensVerify() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("kid", "r1");
        jwk.put("n", b64u(unsigned(pub.getModulus().toByteArray())));
        jwk.put("e", b64u(unsigned(pub.getPublicExponent().toByteArray())));
        Map<String, Object> jwks = new LinkedHashMap<>();
        jwks.put("keys", new ArrayList<Object>(List.of(jwk)));
        Map<String, Object> opts = new LinkedHashMap<>();
        opts.put("issuer", "https://idp.example.com");
        opts.put("audience", "c");
        opts.put("key", Jws.localJwks(jwks));
        for (String alg : new String[] {"RS256", "PS256"}) {
            Map<String, Object> claims = Oidc.verifyIdToken(rsaToken(alg, kp, "r1"), opts);
            assertEquals("u", claims.get("sub"));
        }
        String tampered = rsaToken("RS256", kp, "r1");
        int at = tampered.length() - 10;
        String bad = tampered.substring(0, at) + (tampered.charAt(at) == 'A' ? 'B' : 'A') + tampered.substring(at + 1);
        assertEquals("signature", assertThrows(OidcVerificationError.class, () -> Oidc.verifyIdToken(bad, opts)).code());
        Map<String, Object> only = new LinkedHashMap<>(opts);
        only.put("algorithms", new ArrayList<Object>(List.of("ES256")));
        assertEquals("invalid_token", assertThrows(OidcVerificationError.class, () -> Oidc.verifyIdToken(rsaToken("RS256", kp, "r1"), only)).code());
    }

    private static byte[] unsigned(byte[] b) {
        if (b.length > 1 && b[0] == 0) return java.util.Arrays.copyOfRange(b, 1, b.length);
        return b;
    }
}
