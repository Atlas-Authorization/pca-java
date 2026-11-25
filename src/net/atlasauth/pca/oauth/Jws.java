package net.atlasauth.pca.oauth;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Json;

/**
 * The slice of a JOSE library (jose 5.x) the OAuth-family ports use: the canonical compact-JWS gate, compact JWS verification
 * with a static key or a key resolver (a local JWK Set), and JWT claim validation (issuer, audience, exp, nbf, iat, max token
 * age, required claims, typ). Verification keys are {@link PublicKey}s (Ed25519, ECDSA P-256/384/521, RSA / RSA-PSS >= 2048 bits)
 * or public JWK maps.
 * shortcut: no HMAC (the OIDC default algorithm set excludes it), no Ed448 / ES256K keys; a token needing them is refused
 * (invalid) rather than verified. Upgrade when a deployment signs with them.
 */
public final class Jws {
    private Jws() {}

    public static final int DEFAULT_MAX_JWS_BYTES = 64 * 1024;

    /** A JOSE failure. {@code kind}: signature, expired, claim, other. {@code claim} names the JWT claim of an expired / claim failure. */
    public static final class JoseException extends RuntimeException {
        public final String kind;
        public final String claim;
        public JoseException(String kind, String claim, String message) { super(message); this.kind = kind; this.claim = claim; }
        public JoseException(String message) { this("other", null, message); }
    }

    /** Resolves the verification key of a token from its protected header. */
    public interface KeyResolver { Object getKey(Map<String, Object> protectedHeader); }

    // ---- canonical compact JWS ----

    public static final class CanonicalJwsError extends RuntimeException {
        public final String reason;
        public CanonicalJwsError(String reason) { super("non-canonical compact JWS: " + reason); this.reason = reason; }
    }

    public static final class Canonical {
        public final List<String> segments;
        public final Map<String, Object> header;
        public final Map<String, Object> payload;
        Canonical(List<String> segments, Map<String, Object> header, Map<String, Object> payload) { this.segments = segments; this.header = header; this.payload = payload; }
    }

    private static boolean b64uAlphabet(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
        }
        return true;
    }

    public static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    /** One strictly canonical unpadded base64url segment. */
    public static byte[] decodeCanonicalBase64url(String seg) {
        if (!b64uAlphabet(seg)) throw new CanonicalJwsError("bad-character");
        if (seg.length() % 4 == 1) throw new CanonicalJwsError("non-canonical-base64url");
        byte[] b = Base64.getUrlDecoder().decode(seg);
        if (!b64u(b).equals(seg)) throw new CanonicalJwsError("non-canonical-base64url");
        return b;
    }

    private static Object parseJsonBytes(byte[] bytes) {
        if (bytes.length >= 3 && (bytes[0] & 0xff) == 0xef && (bytes[1] & 0xff) == 0xbb && (bytes[2] & 0xff) == 0xbf) throw new CanonicalJwsError("bom");
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) { throw new CanonicalJwsError("bad-utf8"); }
        try { return Json.parse(text); } catch (RuntimeException | StackOverflowError e) { throw new CanonicalJwsError("bad-json"); }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObject(Object v) {
        if (!(v instanceof Map)) throw new CanonicalJwsError("not-an-object");
        return (Map<String, Object>) v;
    }

    /** Throws unless {@code token} is the one canonical spelling of a compact JWS: 3 unpadded canonical base64url segments, strict-JSON object header and payload. */
    public static Canonical assertCanonicalCompactJws(Object token) { return assertCanonicalCompactJws(token, 3, DEFAULT_MAX_JWS_BYTES, true); }

    /**
     * The same gate with options: {@code parts} (3 = JWS, 5 = JWE: the encrypted-key segment of a JWE may be empty), {@code maxBytes} (the
     * token length bound) and {@code jsonPayload} (false: the payload only needs canonical base64url, and {@code payload} is null).
     */
    public static Canonical assertCanonicalCompactJws(Object token, int parts, int maxBytes, boolean jsonPayload) {
        if (!(token instanceof String)) throw new CanonicalJwsError("not-a-string");
        String t = (String) token;
        if (t.length() > maxBytes) throw new CanonicalJwsError("too-long");
        String[] segs = t.split("\\.", -1);
        if (segs.length != parts) throw new CanonicalJwsError("bad-segment-count");
        byte[][] bytes = new byte[parts][];
        for (int i = 0; i < parts; i++) {
            if (segs[i].isEmpty()) {
                if (parts == 5 && i == 1) { bytes[i] = new byte[0]; continue; }
                throw new CanonicalJwsError("empty-segment");
            }
            bytes[i] = decodeCanonicalBase64url(segs[i]);
        }
        Map<String, Object> header = asObject(parseJsonBytes(bytes[0]));
        Map<String, Object> payload = parts == 3 && jsonPayload ? asObject(parseJsonBytes(bytes[1])) : null;
        return new Canonical(List.of(segs), header, payload);
    }

    /** True iff {@link #assertCanonicalCompactJws(Object)} accepts {@code token}. Never throws. */
    public static boolean isCanonicalCompactJws(Object token) {
        try {
            assertCanonicalCompactJws(token);
            return true;
        } catch (RuntimeException | StackOverflowError e) {
            return false;
        }
    }

    /**
     * Canonical gate for the PROTECTED and SIGNATURE segments of a flattened or detached JWS (A2A / AgentCard signatures, GNAP detached JWS),
     * where the payload is supplied out of band. Same rules as the compact form; returns the protected header.
     */
    public static Map<String, Object> assertCanonicalJwsSegments(Object protectedB64u, Object signatureB64u, int maxBytes) {
        if (!(protectedB64u instanceof String) || !(signatureB64u instanceof String)) throw new CanonicalJwsError("not-a-string");
        String p = (String) protectedB64u, s = (String) signatureB64u;
        if (p.length() + s.length() > maxBytes) throw new CanonicalJwsError("too-long");
        if (p.isEmpty() || s.isEmpty()) throw new CanonicalJwsError("empty-segment");
        Map<String, Object> header = asObject(parseJsonBytes(decodeCanonicalBase64url(p)));
        decodeCanonicalBase64url(s);
        return header;
    }

    public static Map<String, Object> assertCanonicalJwsSegments(Object protectedB64u, Object signatureB64u) {
        return assertCanonicalJwsSegments(protectedB64u, signatureB64u, DEFAULT_MAX_JWS_BYTES);
    }

    // ---- key import ----

    private static ECParameterSpec ecSpec(String crv) {
        String name;
        switch (crv) {
            case "P-256": name = "secp256r1"; break;
            case "P-384": name = "secp384r1"; break;
            case "P-521": name = "secp521r1"; break;
            default: throw new JoseException("unsupported curve");
        }
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec(name));
            return ap.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) { throw new JoseException("unsupported curve"); }
    }

    private static boolean onCurve(ECParameterSpec spec, BigInteger x, BigInteger y) {
        BigInteger p = ((ECFieldFp) spec.getCurve().getField()).getP();
        if (x.signum() < 0 || y.signum() < 0 || x.compareTo(p) >= 0 || y.compareTo(p) >= 0) return false;
        BigInteger lhs = y.multiply(y).mod(p);
        BigInteger rhs = x.multiply(x).multiply(x).add(spec.getCurve().getA().multiply(x)).add(spec.getCurve().getB()).mod(p);
        return lhs.equals(rhs);
    }

    private static String str(Object o) { return o instanceof String ? (String) o : null; }

    private static byte[] jwkBytes(Map<String, Object> jwk, String name) {
        String s = str(jwk.get(name));
        if (s == null) throw new JoseException("invalid JWK: missing " + name);
        try { return Base64.getUrlDecoder().decode(s); } catch (IllegalArgumentException e) { throw new JoseException("invalid JWK: " + name); }
    }

    private static final byte[] ED25519_SPKI = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};

    /** A public JWK (OKP Ed25519, EC P-256/384/521 on-curve, RSA) as a verification key; JoseException for anything else, a private JWK included. */
    public static PublicKey importPublicJwk(Map<String, Object> jwk) {
        if (jwk.get("d") != null) throw new JoseException("JSON Web Key Set members must be public keys");
        String kty = str(jwk.get("kty"));
        if (kty == null) throw new JoseException("JWK must have a kty");
        try {
            switch (kty) {
                case "OKP": {
                    if (!"Ed25519".equals(jwk.get("crv"))) throw new JoseException("unsupported OKP curve");
                    byte[] x = jwkBytes(jwk, "x");
                    if (x.length != 32) throw new JoseException("invalid OKP JWK");
                    byte[] spki = new byte[44];
                    System.arraycopy(ED25519_SPKI, 0, spki, 0, 12);
                    System.arraycopy(x, 0, spki, 12, 32);
                    return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
                }
                case "EC": {
                    ECParameterSpec spec = ecSpec(str(jwk.get("crv")) == null ? "" : (String) jwk.get("crv"));
                    BigInteger x = new BigInteger(1, jwkBytes(jwk, "x")), y = new BigInteger(1, jwkBytes(jwk, "y"));
                    if (!onCurve(spec, x, y)) throw new JoseException("invalid EC JWK: not on the curve");
                    return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
                }
                case "RSA": {
                    BigInteger n = new BigInteger(1, jwkBytes(jwk, "n")), e = new BigInteger(1, jwkBytes(jwk, "e"));
                    if (n.signum() == 0 || !e.testBit(0) || e.compareTo(BigInteger.valueOf(3)) < 0 || e.compareTo(n) >= 0) throw new JoseException("invalid RSA JWK");
                    return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
                }
                default:
                    throw new JoseException("unsupported kty");
            }
        } catch (GeneralSecurityException | RuntimeException x) {
            if (x instanceof JoseException) throw (JoseException) x;
            throw new JoseException("invalid JWK: " + x.getMessage());
        }
    }

    private static String hashName(String alg) {
        String n = alg.substring(alg.length() - 3);
        return n.equals("256") ? "SHA256" : n.equals("384") ? "SHA384" : "SHA512";
    }

    private static boolean verifyRaw(String alg, PublicKey key, byte[] sig, byte[] data) {
        try {
            Signature s;
            switch (alg) {
                case "EdDSA": s = Signature.getInstance("Ed25519"); break;
                case "ES256": case "ES384": case "ES512": s = Signature.getInstance(hashName(alg) + "withECDSAinP1363Format"); break;
                case "RS256": case "RS384": case "RS512": s = Signature.getInstance(hashName(alg) + "withRSA"); break;
                default: {
                    s = Signature.getInstance("RSASSA-PSS");
                    String md = hashName(alg).replace("SHA", "SHA-");
                    int len = Integer.parseInt(alg.substring(2)) / 8;
                    s.setParameter(new PSSParameterSpec(md, "MGF1", new MGF1ParameterSpec(md), len, 1));
                }
            }
            s.initVerify(key);
            s.update(data);
            return s.verify(sig);
        } catch (GeneralSecurityException | RuntimeException e) { return false; }
    }

    /** jose's key / algorithm agreement: the key's type (and curve, RSA size) must fit {@code alg}; a mismatch is not a signature failure. */
    private static void checkKeyForAlg(String alg, PublicKey key) {
        switch (alg) {
            case "EdDSA":
                if (!"Ed25519".equals(key.getAlgorithm()) && !"EdDSA".equals(key.getAlgorithm())) throw new JoseException("key type does not fit EdDSA");
                return;
            case "RS256": case "RS384": case "RS512": case "PS256": case "PS384": case "PS512":
                if (!(key instanceof RSAPublicKey)) throw new JoseException("key type does not fit " + alg);
                if (((RSAPublicKey) key).getModulus().bitLength() < 2048) throw new JoseException(alg + " requires a key of 2048 bits or larger");
                return;
            case "ES256": case "ES384": case "ES512": {
                if (!(key instanceof ECPublicKey)) throw new JoseException("key type does not fit " + alg);
                int bits = ((ECPublicKey) key).getParams().getCurve().getField().getFieldSize();
                int want = alg.equals("ES256") ? 256 : alg.equals("ES384") ? 384 : 521;
                if (bits != want) throw new JoseException("key curve does not fit " + alg);
                return;
            }
            default:
                throw new JoseException("alg " + alg + " is not supported");
        }
    }

    // ---- local JWK Set ----

    @SuppressWarnings("unchecked")
    private static boolean isJwksLike(Object jwks) {
        if (!(jwks instanceof Map) || !(((Map<String, Object>) jwks).get("keys") instanceof List)) return false;
        for (Object k : (List<Object>) ((Map<String, Object>) jwks).get("keys")) if (!(k instanceof Map)) return false;
        return true;
    }

    /** jose's createLocalJWKSet: a resolver that picks the one key matching the header's alg / kid (and the key's use, key_ops, curve). */
    @SuppressWarnings("unchecked")
    public static KeyResolver localJwks(Object jwks) {
        if (!isJwksLike(jwks)) throw new JoseException("JSON Web Key Set malformed");
        final List<Object> keys = new ArrayList<>((List<Object>) ((Map<String, Object>) jwks).get("keys"));
        return header -> {
            Object alg = header.get("alg"), kid = header.get("kid");
            String kty;
            String a = alg instanceof String ? (String) alg : null;
            if (a != null && (a.startsWith("RS") || a.startsWith("PS"))) kty = "RSA";
            else if (a != null && a.startsWith("ES")) kty = "EC";
            else if (a != null && a.startsWith("Ed")) kty = "OKP";
            else throw new JoseException("Unsupported \"alg\" value for a JSON Web Key Set");
            List<Map<String, Object>> cands = new ArrayList<>();
            for (Object o : keys) {
                Map<String, Object> jwk = (Map<String, Object>) o;
                boolean c = kty.equals(jwk.get("kty"));
                if (c && kid instanceof String) c = kid.equals(jwk.get("kid"));
                if (c && jwk.get("alg") instanceof String) c = a.equals(jwk.get("alg"));
                if (c && jwk.get("use") instanceof String) c = "sig".equals(jwk.get("use"));
                if (c && jwk.get("key_ops") instanceof List) c = ((List<Object>) jwk.get("key_ops")).contains("verify");
                if (c && a.equals("EdDSA")) c = "Ed25519".equals(jwk.get("crv")) || "Ed448".equals(jwk.get("crv"));
                if (c) {
                    switch (a) {
                        case "ES256": c = "P-256".equals(jwk.get("crv")); break;
                        case "ES256K": c = "secp256k1".equals(jwk.get("crv")); break;
                        case "ES384": c = "P-384".equals(jwk.get("crv")); break;
                        case "ES512": c = "P-521".equals(jwk.get("crv")); break;
                        default: break;
                    }
                }
                if (c) cands.add(jwk);
            }
            if (cands.isEmpty()) throw new JoseException("no applicable key found in the JSON Web Key Set");
            if (cands.size() != 1) throw new JoseException("multiple matching keys found in the JSON Web Key Set");
            return importPublicJwk(cands.get(0));
        };
    }

    // ---- compact verification ----

    public static final class Verified {
        public final Map<String, Object> protectedHeader;
        public final Map<String, Object> payload;
        Verified(Map<String, Object> h, Map<String, Object> p) { protectedHeader = h; payload = p; }
    }

    /**
     * jose's compactVerify over a token that already passed {@link #assertCanonicalCompactJws}. {@code key} is a {@link PublicKey},
     * a public JWK map or a {@link KeyResolver}; {@code algorithms} the allowed JWS algorithms (null: any).
     */
    @SuppressWarnings("unchecked")
    public static Verified compactVerify(String jws, Canonical canon, Object key, Collection<String> algorithms) {
        Map<String, Object> hdr = canon.header;
        Object crit = hdr.get("crit");
        boolean b64False = false;
        if (hdr.containsKey("crit")) {
            if (!(crit instanceof List) || ((List<Object>) crit).isEmpty()) throw new JoseException("\"crit\" must be a non-empty array of strings");
            for (Object c : (List<Object>) crit) if (!(c instanceof String) || ((String) c).isEmpty()) throw new JoseException("\"crit\" must be a non-empty array of strings");
            for (Object c : (List<Object>) crit) {
                if (!"b64".equals(c)) throw new JoseException("Extension Header Parameter is not recognized");
                if (hdr.get("b64") == null) throw new JoseException("Extension Header Parameter \"b64\" is missing");
                if (!(hdr.get("b64") instanceof Boolean)) throw new JoseException("\"b64\" must be a boolean");
                b64False = Boolean.FALSE.equals(hdr.get("b64"));
            }
        }
        Object algv = hdr.get("alg");
        if (!(algv instanceof String) || ((String) algv).isEmpty()) throw new JoseException("JWS \"alg\" missing or invalid");
        String alg = (String) algv;
        if (algorithms != null && !new LinkedHashSet<>(algorithms).contains(alg)) throw new JoseException("\"alg\" not allowed");
        PublicKey pk;
        Object k = key instanceof KeyResolver ? ((KeyResolver) key).getKey(hdr) : key;
        if (k instanceof Map) pk = importPublicJwk((Map<String, Object>) k);
        else if (k instanceof PublicKey) pk = (PublicKey) k;
        else throw new JoseException("invalid key input");
        checkKeyForAlg(alg, pk);
        int d1 = jws.indexOf('.'), d2 = jws.lastIndexOf('.');
        byte[] data = Json.utf8(jws.substring(0, d2));
        byte[] sig = Base64.getUrlDecoder().decode(jws.substring(d2 + 1));
        if (!verifyRaw(alg, pk, sig, data)) throw new JoseException("signature", null, "signature verification failed");
        if (b64False) throw new JoseException("JWTs MUST NOT use unencoded payload");
        return new Verified(hdr, canon.payload);
    }

    // ---- JWT claims ----

    private static Double dbl(Object o) { return net.atlasauth.pca.oauth.JsVal.num(o); }

    /**
     * jose's JWT claim validation. Options: typ (String), requiredClaims (List), issuer (String), audience (String or List),
     * maxTokenAge (number), clockTolerance (number), currentDateMs (Long). Throws a {@link JoseException} (kind claim / expired).
     */
    @SuppressWarnings("unchecked")
    public static void validateClaims(Map<String, Object> header, Map<String, Object> payload, Map<String, Object> o, long nowMs) {
        Object typ = o.get("typ");
        if (JsVal.truthy(typ)) {
            if (!(header.get("typ") instanceof String) || !normalizeTyp((String) header.get("typ")).equals(normalizeTyp((String) typ))) {
                throw new JoseException("claim", "typ", "unexpected \"typ\" JWT header value");
            }
        }
        Object issuer = o.get("issuer"), audience = o.get("audience"), maxAge = o.get("maxTokenAge");
        List<String> presence = new ArrayList<>();
        if (o.get("requiredClaims") instanceof List) for (Object c : (List<Object>) o.get("requiredClaims")) presence.add(String.valueOf(c));
        if (maxAge != null) presence.add("iat");
        if (audience != null) presence.add("aud");
        if (issuer != null) presence.add("iss");
        java.util.Collections.reverse(presence);
        for (String c : new LinkedHashSet<>(presence)) {
            if (!payload.containsKey(c)) throw new JoseException("claim", c, "missing required \"" + c + "\" claim");
        }
        if (JsVal.truthy(issuer)) {
            List<Object> issuers = issuer instanceof List ? (List<Object>) issuer : java.util.Collections.singletonList(issuer); // not List.of: its contains(null) throws
            if (!issuers.contains(payload.get("iss"))) throw new JoseException("claim", "iss", "unexpected \"iss\" claim value");
        }
        if (JsVal.truthy(audience)) {
            List<Object> opts = audience instanceof String ? java.util.Collections.singletonList(audience) : (List<Object>) audience;
            Object pa = payload.get("aud");
            boolean ok = false;
            if (pa instanceof String) ok = opts.contains(pa);
            else if (pa instanceof List) { for (Object x : opts) if (((List<Object>) pa).contains(x)) { ok = true; break; } }
            if (!ok) throw new JoseException("claim", "aud", "unexpected \"aud\" claim value");
        }
        Object tolO = o.get("clockTolerance");
        double tol = 0;
        if (tolO != null) {
            Double t = dbl(tolO);
            if (t == null || !Double.isFinite(t)) throw new IllegalArgumentException("Invalid clockTolerance option type");
            tol = t;
        }
        long now = Math.floorDiv(nowMs, 1000L);
        Object iat = payload.get("iat");
        if ((payload.containsKey("iat") || JsVal.truthy(maxAge)) && dbl(iat) == null) throw new JoseException("claim", "iat", "\"iat\" claim must be a number");
        if (payload.containsKey("nbf")) {
            Double nbf = dbl(payload.get("nbf"));
            if (nbf == null) throw new JoseException("claim", "nbf", "\"nbf\" claim must be a number");
            if (nbf > now + tol) throw new JoseException("claim", "nbf", "\"nbf\" claim timestamp check failed");
        }
        if (payload.containsKey("exp")) {
            Double exp = dbl(payload.get("exp"));
            if (exp == null) throw new JoseException("claim", "exp", "\"exp\" claim must be a number");
            if (exp <= now - tol) throw new JoseException("expired", "exp", "\"exp\" claim timestamp check failed");
        }
        if (JsVal.truthy(maxAge)) {
            double age = now - dbl(iat);
            double max = dbl(maxAge);
            if (!(age - tol <= max)) throw new JoseException("expired", "iat", "\"iat\" claim timestamp check failed (too far in the past)");
            if (!(age >= 0 - tol)) throw new JoseException("claim", "iat", "\"iat\" claim timestamp check failed (it should be in the past)");
        }
    }

    private static String normalizeTyp(String v) {
        String l = v.toLowerCase(java.util.Locale.ROOT);
        return l.startsWith("application/") ? l.substring("application/".length()) : l;
    }

    /** compactVerify, the b64 rule and claim validation in one call (jose's jwtVerify) over a canonical token. */
    public static Verified jwtVerify(String jwt, Canonical canon, Object key, Map<String, Object> opts, long nowMs) {
        Object algs = opts.get("algorithms");
        Collection<String> allowed = null;
        if (algs != null) {
            allowed = new ArrayList<>();
            for (Object a : (List<?>) algs) {
                if (!(a instanceof String)) throw new IllegalArgumentException("\"algorithms\" option must be an array of strings");
                allowed.add((String) a);
            }
        }
        Verified v = compactVerify(jwt, canon, key, allowed);
        validateClaims(v.protectedHeader, v.payload, opts, nowMs);
        return v;
    }

    /** Signs a compact JWS with an Ed25519 key; header and payload are written in insertion order (JSON.stringify), as the reference does. */
    public static String signEd25519(Map<String, Object> header, Map<String, Object> payload, net.atlasauth.pca.Keys.EdKey key) {
        String h = b64u(JsVal.stringify(header).getBytes(StandardCharsets.UTF_8));
        String p = b64u(JsVal.stringify(payload).getBytes(StandardCharsets.UTF_8));
        String data = h + "." + p;
        return data + "." + b64u(key.sign(Json.utf8(data)));
    }

    /** An empty insertion-ordered map. */
    static Map<String, Object> obj() { return new LinkedHashMap<>(); }
}
