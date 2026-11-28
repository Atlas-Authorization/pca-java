package net.atlasauth.pca.a2a;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.jose.Jose;

/**
 * Detached-payload flattened JWS for A2A Agent Cards and AgentFacts attestations (the signing primitive behind the reference's
 * {@code FlattenedSign} / {@code flattenedVerify} use). Keys are JWK maps. Profiles: the legacy detached profile
 * ({@code b64:false}, {@code crit:["b64"]}) and the A2A 1.0 section 8.4 profile (payload base64url in the signing input, {@code typ:"JOSE"}).
 * Verification gates the protected and signature segments for canonical spelling first, then applies the reference library's header
 * rules ({@code alg}, {@code crit}, {@code b64}) and key selection (single key, or a JWKS matched by {@code kid} / {@code alg} / {@code kty}).
 */
public final class A2aJws {
    private A2aJws() {}

    /** Sign {@code payload}; returns {@code {protected, signature}}. {@code header} members follow {@code kid} in the protected header. */
    public static Map<String, Object> signDetached(byte[] payload, Map<String, Object> jwk, String alg, String kid, boolean standardPayload, Map<String, Object> header) {
        Map<String, Object> prot = new LinkedHashMap<>();
        prot.put("alg", alg);
        if (standardPayload) prot.put("typ", "JOSE");
        else {
            prot.put("b64", Boolean.FALSE);
            prot.put("crit", new ArrayList<Object>(List.of("b64")));
        }
        if (kid != null) prot.put("kid", kid);
        if (header != null) prot.putAll(header);
        String protectedB64 = Jose.b64u(Jose.utf8(Jose.stringify(prot)));
        byte[] input = signingInput(protectedB64, payload, standardPayload);
        Map<String, Object> key = new LinkedHashMap<>(jwk);
        key.remove("alg"); // importJWK(jwk, alg) takes the algorithm from the argument; the member is not compared
        byte[] sig = Jose.signRaw(alg, key, input);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("protected", protectedB64);
        out.put("signature", Jose.b64u(sig));
        return out;
    }

    private static byte[] signingInput(String protectedB64, byte[] payload, boolean b64) {
        byte[] p = b64 ? Jose.b64u(payload).getBytes(StandardCharsets.US_ASCII) : payload;
        byte[] h = (protectedB64 + ".").getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[h.length + p.length];
        System.arraycopy(h, 0, out, 0, h.length);
        System.arraycopy(p, 0, out, h.length, p.length);
        return out;
    }

    /** What a verify call resolves its key from. */
    public static final class Resolver {
        final Map<String, Object> key;      // a single JWK (null when a JWKS is used)
        final List<Object> jwks;            // the JWKS keys (null when a single key is used)
        final String alg;                   // importJWK algorithm for a single key
        final boolean invalid;              // a key that is not a JWK: passed through, and no signature verifies under it
        Resolver(Map<String, Object> key, List<Object> jwks, String alg, boolean invalid) { this.key = key; this.jwks = jwks; this.alg = alg; this.invalid = invalid; }
    }

    /** {@code error} non-null: key resolution failed (the message). */
    public static final class Resolved {
        public final Resolver resolver;
        public final String error;
        Resolved(Resolver r, String e) { this.resolver = r; this.error = e; }
    }

    /**
     * Resolve the verification key. {@code jwks} (a parsed JWKS, truthy) wins over {@code key}; neither: "no verification key or JWKS supplied".
     * {@code key} must be a JWK map (an object with {@code kty}); {@code alg} is the importJWK algorithm (default EdDSA).
     */
    @SuppressWarnings("unchecked")
    public static Resolved resolveVerifyKey(Object jwks, Object key, String alg) {
        if (net.atlasauth.pca.oauth.JsVal.truthy(jwks)) {
            if (!(jwks instanceof Map) || !(((Map<String, Object>) jwks).get("keys") instanceof List)) return new Resolved(null, "could not resolve verification key: JSON Web Key Set malformed");
            List<Object> keys = (List<Object>) ((Map<String, Object>) jwks).get("keys");
            for (Object k : keys) if (!(k instanceof Map)) return new Resolved(null, "could not resolve verification key: JSON Web Key Set malformed");
            return new Resolved(new Resolver(null, keys, null, false), null);
        }
        if (key != null) {
            if (!(key instanceof Map) || !((Map<String, Object>) key).containsKey("kty")) return new Resolved(new Resolver(null, null, null, true), null);
            Map<String, Object> jwk = (Map<String, Object>) key;
            Object kty = jwk.get("kty");
            if (!(kty instanceof String)) return new Resolved(null, "could not resolve verification key: JWK must have a kty");
            if (!"oct".equals(kty)) { // importJWK fails at resolve time for a key that cannot be imported at all
                String probe = "OKP".equals(kty) ? "EdDSA" : "RSA".equals(kty) ? "RS256" : "EC".equals(kty) ? ("P-384".equals(jwk.get("crv")) ? "ES384" : "P-521".equals(jwk.get("crv")) ? "ES512" : "ES256") : "EdDSA";
                try { Jose.verifySignature(probe, jwk, new byte[64], new byte[0]); }
                catch (Jose.JoseException e) { return new Resolved(null, "could not resolve verification key: " + e.getMessage()); }
            }
            return new Resolved(new Resolver(jwk, null, alg == null ? "EdDSA" : alg, false), null);
        }
        return new Resolved(null, "no verification key or JWKS supplied");
    }

    /** {@code ok} false: {@code reason} says why (the library's wording is not reproduced); {@code protectedHeader} when ok. */
    public static final class Result {
        public final boolean ok;
        public final String reason;
        public final Map<String, Object> protectedHeader;
        Result(boolean ok, String reason, Map<String, Object> h) { this.ok = ok; this.reason = reason; this.protectedHeader = h; }
        static Result fail(String why) { return new Result(false, why, null); }
    }

    private static Result fail(String why) { return Result.fail(why); }

    /** Verify a detached-payload JWS ({@code sig} = {@code {protected, signature}}) over {@code payload}. Never throws. */
    @SuppressWarnings("unchecked")
    public static Result verifyDetached(byte[] payload, Object sig, Resolver resolver) {
        try {
            if (!(sig instanceof Map) || !(((Map<String, Object>) sig).get("protected") instanceof String) || !(((Map<String, Object>) sig).get("signature") instanceof String))
                return fail("signature is malformed");
            String prot = (String) ((Map<String, Object>) sig).get("protected");
            String sg = (String) ((Map<String, Object>) sig).get("signature");
            // canonical-spelling gate BEFORE the JOSE rules (a payload segment of one byte stands in: only the two segments are gated)
            if (prot.length() + sg.length() > Jose.DEFAULT_MAX_JWS_BYTES) return fail("non-canonical compact JWS: too-long");
            Jose.CanonicalJws gate = Jose.assertCanonicalCompactJws(prot + ".AA." + sg, 3, Integer.MAX_VALUE, false);
            Map<String, Object> header = gate.header;
            Object algO = header.get("alg");
            if (!(algO instanceof String) || ((String) algO).isEmpty()) return fail("JWS \"alg\" (Algorithm) Header Parameter missing or invalid");
            String alg = (String) algO;
            boolean b64 = true;
            if (header.containsKey("crit")) {
                Object crit = header.get("crit");
                if (!(crit instanceof List) || ((List<Object>) crit).isEmpty()) return fail("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present");
                boolean b64Listed = false;
                for (Object c : (List<Object>) crit) {
                    if (!(c instanceof String) || ((String) c).isEmpty()) return fail("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present");
                    if (!"b64".equals(c)) return fail("Extension Header Parameter \"" + c + "\" is not recognized");
                    if (!header.containsKey("b64")) return fail("Extension Header Parameter \"b64\" is missing");
                    b64Listed = true;
                }
                if (b64Listed) {
                    Object b = header.get("b64");
                    if (!(b instanceof Boolean)) return fail("The \"b64\" (base64url-encode payload) Header Parameter must be a boolean");
                    b64 = (Boolean) b;
                }
            }
            // the payload the caller hands over: raw bytes under a header that says b64:false, else base64url text
            boolean rawGiven = Boolean.FALSE.equals(header.get("b64"));
            if (b64 && rawGiven) return fail("JWS Payload must be a string");
            if (resolver.invalid) throw new Jose.JoseException("Key must be a key object");
            Map<String, Object> jwk = pickKey(resolver, alg, header);
            byte[] signature = Jose.decodeCanonicalBase64url(sg);
            boolean ok = Jose.verifySignature(alg, jwk, signature, signingInput(prot, payload, b64));
            return ok ? new Result(true, null, header) : fail("signature verification failed");
        } catch (Jose.JoseException | Jose.CanonicalJwsError e) {
            return fail(e.getMessage());
        } catch (RuntimeException e) {
            return fail("signature verification failed");
        }
    }

    private static String ktyOf(String alg) {
        if (alg.startsWith("RS") || alg.startsWith("PS")) return "RSA";
        if (alg.startsWith("ES")) return "EC";
        if (alg.equals("EdDSA")) return "OKP";
        throw new Jose.JoseException("Unsupported \"alg\" value for a JSON Web Key Set");
    }

    private static String crvOf(String alg) {
        switch (alg) {
            case "ES256": return "P-256";
            case "ES384": return "P-384";
            case "ES512": return "P-521";
            default: return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> pickKey(Resolver r, String alg, Map<String, Object> header) {
        if (r.jwks == null) return r.key;
        String kty = ktyOf(alg), kid = header.get("kid") instanceof String ? (String) header.get("kid") : null;
        List<Map<String, Object>> cand = new ArrayList<>();
        for (Object o : r.jwks) {
            Map<String, Object> k = (Map<String, Object>) o;
            boolean c = kty.equals(k.get("kty"));
            if (c && kid != null) c = kid.equals(k.get("kid"));
            if (c && k.get("alg") instanceof String) c = alg.equals(k.get("alg"));
            if (c && k.get("use") instanceof String) c = "sig".equals(k.get("use"));
            if (c && k.get("key_ops") instanceof List) c = ((List<Object>) k.get("key_ops")).contains("verify");
            if (c) {
                if (alg.equals("EdDSA")) c = "Ed25519".equals(k.get("crv")) || "Ed448".equals(k.get("crv"));
                else if (crvOf(alg) != null) c = crvOf(alg).equals(k.get("crv"));
            }
            if (c) cand.add(k);
        }
        if (cand.isEmpty()) throw new Jose.JoseException("no applicable key found in the JSON Web Key Set");
        if (cand.size() != 1) throw new Jose.JoseException("multiple matching keys found in the JSON Web Key Set");
        return cand.get(0);
    }
}
