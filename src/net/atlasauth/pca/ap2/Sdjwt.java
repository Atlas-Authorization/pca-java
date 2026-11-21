package net.atlasauth.pca.ap2;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import net.atlasauth.pca.Json;

/**
 * SD-JWT primitives for AP2 mandates (RFC 9901): strict compact parsing, disclosure processing, the {@code sd_hash} /
 * {@code issuer_jwt_hash} binding digests, and ES256 (P-256) signing and verification.
 *
 * <p>No primitive is implemented here: SHA-2 and ECDSA come from the JDK (ECDSA in its IEEE P1363 {@code r || s} form, which is
 * the JWS form, so no DER conversion is involved). The code is the SD-JWT <em>format</em> and it fails closed on every
 * ambiguity (duplicate digests, unreferenced disclosures, malformed base64url, duplicate JSON keys, unknown {@code _sd_alg},
 * non-ES256 algorithms). JSON values are the core {@link Json} tree: Map, List, String, Boolean, {@link Json.Num}, null.
 */
public final class Sdjwt {
    private Sdjwt() {}

    // ---------------------------------------------------------------------------------------------
    // base64url + JSON helpers
    // ---------------------------------------------------------------------------------------------

    public static String b64uEncode(byte[] data) { return Base64.getUrlEncoder().withoutPadding().encodeToString(data); }

    public static String b64uEncode(String s) { return b64uEncode(Js.utf8(s)); }

    /** Strict base64url decode: canonical alphabet, no padding, and the encoding must round-trip. */
    public static byte[] b64uDecode(String s, String what) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
            if (!ok) throw new Ap2Error(what + ": not base64url");
        }
        byte[] buf;
        try {
            buf = Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new Ap2Error(what + ": non-canonical base64url");
        }
        if (!b64uEncode(buf).equals(s)) throw new Ap2Error(what + ": non-canonical base64url");
        return buf;
    }

    public static boolean isObject(Object v) { return v instanceof Map; }

    /**
     * Reject an object that repeats a key: a plain parse keeps the last duplicate, which would let two parties read different
     * claims out of the same signed bytes. Run on text that already parsed, so only string/brace structure needs tracking.
     */
    static void assertNoDuplicateKeys(String text, String what) {
        List<Set<String>> stack = new ArrayList<>(); // a null entry is an array
        boolean expectKey = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '"') {
                int j = i + 1;
                while (text.charAt(j) != '"') j += text.charAt(j) == '\\' ? 2 : 1;
                Set<String> top = stack.isEmpty() ? null : stack.get(stack.size() - 1);
                if (expectKey && top != null) {
                    String key = (String) Json.parseLenient(text.substring(i, j + 1));
                    if (!top.add(key)) throw new Ap2Error(what + ": duplicate key " + Js.stringify(key));
                    expectKey = false;
                }
                i = j;
            } else if (c == '{') {
                stack.add(new HashSet<>());
                expectKey = true;
            } else if (c == '[') {
                stack.add(null);
                expectKey = false;
            } else if (c == '}' || c == ']') {
                if (!stack.isEmpty()) stack.remove(stack.size() - 1);
                expectKey = false;
            } else if (c == ',') {
                expectKey = !stack.isEmpty() && stack.get(stack.size() - 1) != null;
            }
        }
    }

    /**
     * JSON parse that rejects duplicate keys. Numbers are parsed as written ({@code 1000.0} is accepted: the official Python SDK
     * serialises float fields that way). Objects enumerate their keys in ECMAScript order.
     */
    public static Object parseJson(String text, String what) {
        Object v;
        try {
            v = Js.jsOrder(Json.parseLenient(text));
        } catch (IllegalArgumentException e) {
            throw new Ap2Error(what + ": invalid JSON (" + e.getMessage() + ")");
        }
        assertNoDuplicateKeys(text, what);
        return v;
    }

    /** UTF-8 text of decoded bytes, FATAL on any invalid sequence. The BOM is kept, so the JSON parse refuses it. */
    static String utf8Text(byte[] bytes, String what) {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new Ap2Error(what + ": not valid UTF-8");
        }
    }

    static Map<String, Object> decodeJsonSegment(String segment, String what) {
        Object v = parseJson(utf8Text(b64uDecode(segment, what), what), what);
        if (!(v instanceof Map)) throw new Ap2Error(what + ": must be a JSON object");
        return Js.obj(v);
    }

    // ---------------------------------------------------------------------------------------------
    // hashing
    // ---------------------------------------------------------------------------------------------

    /** The {@code _sd_alg} values the AP2 reference SDK accepts: "sha-256", "sha-384", "sha-512". */
    public static boolean isSdAlg(Object v) { return "sha-256".equals(v) || "sha-384".equals(v) || "sha-512".equals(v); }

    public static String sdDigest(String value) { return sdDigest(value, "sha-256"); }

    /** base64url(hash(ascii(value))): the digest used for disclosures, {@code sd_hash} and {@code checkout_hash}. */
    public static String sdDigest(String value, String alg) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < 0x20 || c > 0x7e) throw new Ap2Error("digest input must be ASCII");
        }
        String name;
        if ("sha-256".equals(alg)) name = "SHA-256";
        else if ("sha-384".equals(alg)) name = "SHA-384";
        else if ("sha-512".equals(alg)) name = "SHA-512";
        else throw new IllegalArgumentException("unsupported hash " + alg);
        try {
            return b64uEncode(MessageDigest.getInstance(name).digest(value.getBytes(StandardCharsets.US_ASCII)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---------------------------------------------------------------------------------------------
    // ES256 keys (P-256)
    // ---------------------------------------------------------------------------------------------

    private static final BigInteger P = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger B = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    private static final BigInteger N = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final ECParameterSpec SPEC = curve();

    private static ECParameterSpec curve() {
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec("secp256r1"));
            return ap.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean b64u43(Object o) {
        if (!(o instanceof String)) return false;
        String s = (String) o;
        if (s.length() != 43) return false;
        for (int i = 0; i < 43; i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
            if (!ok) return false;
        }
        return true;
    }

    private static byte[] fixed32(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - n, out, 32 - n, n);
        return out;
    }

    /** The public key of a (shape-checked) JWK; throws when the point is not on P-256. */
    private static PublicKey publicKey(Map<String, Object> jwk) {
        try {
            BigInteger x = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("x")));
            BigInteger y = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("y")));
            if (x.compareTo(P) >= 0 || y.compareTo(P) >= 0) throw new Ap2Error("point out of range");
            BigInteger rhs = x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(B).mod(P);
            if (!y.multiply(y).mod(P).equals(rhs)) throw new Ap2Error("point not on the curve");
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), SPEC));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new Ap2Error("not a valid P-256 point");
        }
    }

    /** Validate a public JWK against {@code types/jwk.json} and prove the point is on the curve. */
    public static Map<String, Object> assertP256Jwk(Object jwk, String what) {
        if (!(jwk instanceof Map)) throw new Ap2Error(what + ": JWK must be an object");
        Map<String, Object> j = Js.obj(jwk);
        if (!"EC".equals(j.get("kty")) || !"P-256".equals(j.get("crv"))) throw new Ap2Error(what + ": JWK must be EC P-256");
        if (!b64u43(j.get("x"))) throw new Ap2Error(what + ": bad JWK x");
        if (!b64u43(j.get("y"))) throw new Ap2Error(what + ": bad JWK y");
        if (j.containsKey("d")) throw new Ap2Error(what + ": JWK carries private material");
        if (j.containsKey("alg") && !"ES256".equals(j.get("alg"))) throw new Ap2Error(what + ": JWK alg must be ES256");
        try {
            publicKey(j);
        } catch (Ap2Error e) {
            throw new Ap2Error(what + ": JWK is not a valid P-256 point");
        }
        return j;
    }

    /** A P-256 key pair: the public JWK (never carries {@code d}) and the private key. */
    public static final class Ap2KeyPair {
        public final Map<String, Object> publicJwk;
        public final PrivateKey privateKey;

        public Ap2KeyPair(Map<String, Object> publicJwk, PrivateKey privateKey) {
            this.publicJwk = publicJwk;
            this.privateKey = privateKey;
        }
    }

    private static Map<String, Object> jwkOf(BigInteger x, BigInteger y, String kid) {
        Map<String, Object> out = Js.m("kty", "EC", "crv", "P-256", "x", b64uEncode(fixed32(x)), "y", b64uEncode(fixed32(y)));
        if (kid != null) out.put("kid", kid);
        return out;
    }

    public static Ap2KeyPair generateAp2KeyPair() { return generateAp2KeyPair(null); }

    public static Ap2KeyPair generateAp2KeyPair(String kid) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = g.generateKeyPair();
            ECPoint w = ((ECPublicKey) kp.getPublic()).getW();
            return new Ap2KeyPair(jwkOf(w.getAffineX(), w.getAffineY(), kid), kp.getPrivate());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Rebuild a key pair from a private JWK ({@code d} present, with {@code x} and {@code y}), e.g. for fixtures. The public
     * point is derived from {@code d}; a JWK whose {@code x}/{@code y} disagree with it is refused.
     */
    public static Ap2KeyPair ap2KeyPairFromPrivateJwk(Map<String, Object> jwk) {
        if (!"EC".equals(jwk.get("kty")) || !"P-256".equals(jwk.get("crv")) || !b64u43(jwk.get("d")) || !b64u43(jwk.get("x")) || !b64u43(jwk.get("y"))) {
            throw new Ap2Error("private JWK must be EC P-256 with d, x and y");
        }
        BigInteger d = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("d")));
        if (d.signum() <= 0 || d.compareTo(N) >= 0) throw new Ap2Error("private JWK: d is out of range");
        org.bouncycastle.math.ec.ECPoint q = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1").getG().multiply(d).normalize();
        BigInteger x = q.getAffineXCoord().toBigInteger(), y = q.getAffineYCoord().toBigInteger();
        if (!b64uEncode(fixed32(x)).equals(jwk.get("x")) || !b64uEncode(fixed32(y)).equals(jwk.get("y"))) throw new Ap2Error("private JWK: x/y do not match d");
        try {
            PrivateKey sk = KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(d, SPEC));
            return new Ap2KeyPair(jwkOf(x, y, jwk.get("kid") instanceof String ? (String) jwk.get("kid") : null), sk);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** RFC 7638 JWK thumbprint (SHA-256) of an EC P-256 key. */
    public static String jwkThumbprint(Object jwk) {
        String canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + Js.str(Js.getU(jwk, "x")) + "\",\"y\":\"" + Js.str(Js.getU(jwk, "y")) + "\"}";
        try {
            return b64uEncode(MessageDigest.getInstance("SHA-256").digest(Js.utf8(canonical)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** ES256 over {@code signingInput}; returns the 64-byte {@code r || s} JWS signature as base64url. */
    static String es256Sign(PrivateKey privateKey, String signingInput) {
        try {
            Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
            s.initSign(privateKey);
            s.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return b64uEncode(s.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static boolean es256Verify(Map<String, Object> jwk, String signingInput, byte[] signature) {
        if (signature.length != 64) return false;
        PublicKey pk = publicKey(jwk);
        try {
            Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
            s.initVerify(pk);
            s.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return s.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // compact JWT / SD-JWT parsing
    // ---------------------------------------------------------------------------------------------

    /** One SD-JWT: an issuer-signed JWT plus its disclosures (no trailing KB-JWT; AP2 binds with chain hops). */
    public static final class SdJwtHop {
        /** Canonical serialisation {@code <jwt>~<d1>~...~<dn>~}. */
        public final String raw;
        public final String jwt;
        public final Map<String, Object> header;
        /** The signed payload exactly as issued (digest placeholders still in place). */
        public final Map<String, Object> payload;
        public final List<String> disclosures;
        public final String sdAlg;
        public final String signingInput;
        public final byte[] signature;

        SdJwtHop(String raw, String jwt, Map<String, Object> header, Map<String, Object> payload, List<String> disclosures, String sdAlg, String signingInput, byte[] signature) {
            this.raw = raw;
            this.jwt = jwt;
            this.header = header;
            this.payload = payload;
            this.disclosures = disclosures;
            this.sdAlg = sdAlg;
            this.signingInput = signingInput;
            this.signature = signature;
        }
    }

    /** The hop's {@code ~}-joined serialisation: what {@code sd_hash} is computed over. */
    public static String hopSdJwt(String jwt, List<String> disclosures) {
        StringBuilder sb = new StringBuilder(jwt).append('~');
        for (String d : disclosures) sb.append(d).append('~');
        return sb.toString();
    }

    public static String hopSdJwt(SdJwtHop hop) { return hopSdJwt(hop.jwt, hop.disclosures); }

    /** Parse one SD-JWT ({@code jwt~d1~...~dn~}). The serialisation must end with {@code ~}. */
    public static SdJwtHop parseSdJwtHop(Object tokenObj) {
        if (!(tokenObj instanceof String) || ((String) tokenObj).isEmpty()) throw new Ap2Error("SD-JWT: empty");
        String token = (String) tokenObj;
        if (token.startsWith("~")) throw new Ap2Error("SD-JWT: empty issuer JWT");
        if (!token.endsWith("~")) throw new Ap2Error("SD-JWT: must end with \"~\" (a trailing KB-JWT is not an AP2 form)");
        String[] parts = token.substring(0, token.length() - 1).split("~", -1);
        String jwt = parts[0];
        List<String> disclosures = new ArrayList<>(Arrays.asList(parts).subList(1, parts.length));
        for (String d : disclosures) if (d.isEmpty()) throw new Ap2Error("SD-JWT: empty disclosure segment");
        String[] seg = jwt.split("\\.", -1);
        if (seg.length != 3 || seg[0].isEmpty() || seg[1].isEmpty() || seg[2].isEmpty()) throw new Ap2Error("SD-JWT: issuer JWT must be header.payload.signature");
        Map<String, Object> header = decodeJsonSegment(seg[0], "JWT header");
        Map<String, Object> payload = decodeJsonSegment(seg[1], "JWT payload");
        byte[] signature = b64uDecode(seg[2], "JWT signature");
        Object rawAlg = payload.get("_sd_alg");
        if (payload.containsKey("_sd_alg") && !isSdAlg(rawAlg)) throw new Ap2Error("SD-JWT: unsupported _sd_alg " + Js.stringify(rawAlg));
        return new SdJwtHop(token, jwt, header, payload, disclosures, isSdAlg(rawAlg) ? (String) rawAlg : "sha-256", seg[0] + "." + seg[1], signature);
    }

    /** {@code sd_hash} of a hop: the digest of {@code <jwt>~<d1>~...~} (the on-wire form of the preceding hop). */
    public static String sdHashOf(SdJwtHop hop) { return sdHashOf(hop, hop.sdAlg); }

    public static String sdHashOf(SdJwtHop hop, String alg) { return sdDigest(hopSdJwt(hop), alg); }

    /** {@code issuer_jwt_hash} of a hop: the digest of the issuer-signed JWT alone. */
    public static String issuerJwtHashOf(SdJwtHop hop) { return issuerJwtHashOf(hop, hop.sdAlg); }

    public static String issuerJwtHashOf(SdJwtHop hop, String alg) { return sdDigest(hop.jwt, alg); }

    /** Verify the issuer JWT's ES256 signature. Anything other than {@code alg: ES256} is rejected. */
    public static boolean verifyHopSignature(SdJwtHop hop, Map<String, Object> key) {
        if (!"ES256".equals(hop.header.get("alg"))) return false;
        return es256Verify(assertP256Jwk(key, "verification key"), hop.signingInput, hop.signature);
    }

    // ---------------------------------------------------------------------------------------------
    // disclosure processing (RFC 9901 section 7)
    // ---------------------------------------------------------------------------------------------

    private static final class Disclosure {
        final boolean property;
        final String name;
        final Object value;

        Disclosure(boolean property, String name, Object value) {
            this.property = property;
            this.name = name;
            this.value = value;
        }
    }

    private static Disclosure decodeDisclosure(String raw) {
        Object arr = parseJson(utf8Text(b64uDecode(raw, "disclosure"), "disclosure"), "disclosure");
        if (!(arr instanceof List)) throw new Ap2Error("disclosure: must be a JSON array");
        List<Object> a = Js.arr(arr);
        if (a.isEmpty() || !(a.get(0) instanceof String) || ((String) a.get(0)).isEmpty()) throw new Ap2Error("disclosure: salt must be a non-empty string");
        if (a.size() == 3) {
            Object name = a.get(1);
            if (!(name instanceof String)) throw new Ap2Error("disclosure: claim name must be a string");
            if (name.equals("_sd") || name.equals("...")) throw new Ap2Error("disclosure: claim name " + name + " is reserved");
            return new Disclosure(true, (String) name, a.get(2));
        }
        if (a.size() == 2) return new Disclosure(false, null, a.get(1));
        throw new Ap2Error("disclosure: array must have 2 or 3 elements");
    }

    /**
     * Resolve every selectively-disclosable claim in {@code payload} using {@code disclosures}. Returns the processed claims
     * ({@code _sd}, {@code ...} markers and {@code _sd_alg} removed). Throws if a disclosure is duplicated, is not referenced
     * from the payload, collides with an existing claim, or is used in the wrong position.
     */
    public static Map<String, Object> processDisclosures(Map<String, Object> payload, List<String> disclosures, String alg) {
        Map<String, Disclosure> byDigest = new HashMap<>();
        for (String raw : disclosures) {
            Disclosure d = decodeDisclosure(raw);
            String digest = sdDigest(raw, alg);
            if (byDigest.containsKey(digest)) throw new Ap2Error("SD-JWT: duplicate disclosure");
            byDigest.put(digest, d);
        }
        Set<String> used = new HashSet<>();
        Map<String, Object> result = Js.obj(walk(payload, 0, byDigest, used));
        if (used.size() != byDigest.size()) throw new Ap2Error("SD-JWT: a disclosure is not referenced by the signed payload");
        return result;
    }

    private static Disclosure take(String digest, boolean wantProperty, Map<String, Disclosure> byDigest, Set<String> used) {
        Disclosure d = byDigest.get(digest);
        if (d == null) return null; // decoy digest, or a disclosure the holder chose not to reveal
        if (used.contains(digest)) throw new Ap2Error("SD-JWT: a digest is referenced more than once");
        if (d.property != wantProperty) {
            throw new Ap2Error("SD-JWT: a " + (d.property ? "property" : "element") + " disclosure is referenced from a " + (wantProperty ? "property" : "element") + " position");
        }
        used.add(digest);
        return d;
    }

    private static Object walk(Object node, int depth, Map<String, Disclosure> byDigest, Set<String> used) {
        if (depth > 32) throw new Ap2Error("SD-JWT: nesting too deep");
        if (node instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object el : (List<?>) node) {
                if (el instanceof Map && Js.obj(el).containsKey("...")) {
                    Map<String, Object> e = Js.obj(el);
                    if (e.size() != 1 || !(e.get("...") instanceof String)) throw new Ap2Error("SD-JWT: malformed array digest placeholder");
                    Disclosure d = take((String) e.get("..."), false, byDigest, used);
                    if (d != null) out.add(walk(d.value, depth + 1, byDigest, used));
                } else out.add(walk(el, depth + 1, byDigest, used));
            }
            return out;
        }
        if (node instanceof Map) {
            Map<String, Object> src = Js.obj(node);
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> en : src.entrySet()) {
                String k = en.getKey();
                if (k.equals("_sd") || k.equals("_sd_alg")) continue;
                if (k.equals("...")) throw new Ap2Error("SD-JWT: \"...\" is only valid as the sole key of an array element");
                out.put(k, walk(en.getValue(), depth + 1, byDigest, used));
            }
            if (src.containsKey("_sd")) {
                Object sd = src.get("_sd");
                if (!(sd instanceof List)) throw new Ap2Error("SD-JWT: _sd must be an array of strings");
                for (Object x : (List<?>) sd) if (!(x instanceof String)) throw new Ap2Error("SD-JWT: _sd must be an array of strings");
                for (Object digest : (List<?>) sd) {
                    Disclosure d = take((String) digest, true, byDigest, used);
                    if (d == null || !d.property) continue;
                    if (out.containsKey(d.name)) throw new Ap2Error("SD-JWT: disclosed claim " + d.name + " collides with an existing claim");
                    out.put(d.name, walk(d.value, depth + 1, byDigest, used));
                }
            }
            return out;
        }
        return node;
    }

    // ---------------------------------------------------------------------------------------------
    // issuing
    // ---------------------------------------------------------------------------------------------

    private static final SecureRandom RANDOM = new SecureRandom();

    public static String newSalt() {
        byte[] b = new byte[16];
        RANDOM.nextBytes(b);
        return b64uEncode(b);
    }

    /** Builds disclosures: each call appends one and returns the digest (or the {@code {"...": digest}} placeholder). */
    public static final class DisclosureBuilder {
        public final List<String> disclosures = new ArrayList<>();
        private final String alg;
        private final Supplier<String> salt;

        DisclosureBuilder(String alg, Supplier<String> salt) {
            this.alg = alg;
            this.salt = salt;
        }

        /** Array-element disclosure for {@code value}; returns the {@code {"...": digest}} placeholder. */
        public Map<String, Object> element(Object value) {
            String raw = b64uEncode(Js.stringify(Arrays.asList(salt.get(), value)));
            disclosures.add(raw);
            return Js.m("...", sdDigest(raw, alg));
        }

        /** Property disclosure; returns the digest to put into the parent's {@code _sd}. */
        public String property(String name, Object value) {
            String raw = b64uEncode(Js.stringify(Arrays.asList(salt.get(), name, value)));
            disclosures.add(raw);
            return sdDigest(raw, alg);
        }
    }

    public static DisclosureBuilder disclosureBuilder() { return disclosureBuilder(null, null); }

    /** {@code alg} defaults to sha-256 and {@code salt} to {@link #newSalt()} when null (tests inject a deterministic one). */
    public static DisclosureBuilder disclosureBuilder(String alg, Supplier<String> salt) {
        Supplier<String> source = salt;
        if (source == null) source = Sdjwt::newSalt;
        return new DisclosureBuilder(alg == null ? "sha-256" : alg, source);
    }

    private static Map<String, Object> merged(Map<String, Object> head, Map<String, Object> over) {
        Map<String, Object> out = new LinkedHashMap<>(head);
        out.putAll(over);
        return out;
    }

    /** Sign {@code payload} as an ES256 JWT and append {@code disclosures}: {@code <jwt>~<d1>~...~<dn>~}. */
    public static String signSdJwt(Map<String, Object> header, Map<String, Object> payload, List<String> disclosures, PrivateKey privateKey) {
        String h = b64uEncode(Js.stringify(merged(Js.m("alg", "ES256"), header)));
        String p = b64uEncode(Js.stringify(payload));
        String jwt = h + "." + p + "." + es256Sign(privateKey, h + "." + p);
        return hopSdJwt(jwt, disclosures);
    }

    /** Sign an arbitrary compact JWT (used for merchant-signed {@code checkout_jwt}). */
    public static String signJwtEs256(Map<String, Object> header, Map<String, Object> payload, PrivateKey privateKey) {
        String h = b64uEncode(Js.stringify(merged(Js.m("alg", "ES256", "typ", "JWT"), header)));
        String p = b64uEncode(Js.stringify(payload));
        return h + "." + p + "." + es256Sign(privateKey, h + "." + p);
    }

    /** A parsed compact JWT. */
    public static final class ParsedJwt {
        public final Map<String, Object> header;
        public final Map<String, Object> payload;
        public final String signingInput;
        public final byte[] signature;

        ParsedJwt(Map<String, Object> header, Map<String, Object> payload, String signingInput, byte[] signature) {
            this.header = header;
            this.payload = payload;
            this.signingInput = signingInput;
            this.signature = signature;
        }
    }

    public static ParsedJwt parseJwt(String jwt, String what) {
        String[] seg = jwt.split("\\.", -1);
        if (seg.length != 3 || seg[0].isEmpty() || seg[1].isEmpty() || seg[2].isEmpty()) throw new Ap2Error(what + ": must be header.payload.signature");
        Map<String, Object> header = decodeJsonSegment(seg[0], what + " header");
        Map<String, Object> payload = decodeJsonSegment(seg[1], what + " payload");
        return new ParsedJwt(header, payload, seg[0] + "." + seg[1], b64uDecode(seg[2], what + " signature"));
    }

    public static boolean verifyJwtEs256(ParsedJwt parsed, Map<String, Object> key) {
        if (!"ES256".equals(parsed.header.get("alg"))) return false;
        return es256Verify(assertP256Jwk(key, "verification key"), parsed.signingInput, parsed.signature);
    }
}
