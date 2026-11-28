package net.atlasauth.pca.jose;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

/**
 * The JOSE plumbing the identity-credential packages share (DPoP, SD-JWT, VC): the canonical compact-JWS gate, JWK handling,
 * compact JWS verify / sign for the asymmetric algorithms (EdDSA, ES256/384/512, RS256/384/512, PS256/384/512), JWT claim
 * checks with the reference library's semantics, RFC 7638 thumbprints and an insertion-order JSON writer. Keys are JWK maps.
 * Symmetric (HS*) and {@code none} are not supported: a key or an algorithm outside the asymmetric set is refused.
 * Ed25519 verification is strict RFC 8032 (canonical S, no small-order or mixed-order key or R).
 */
public final class Jose {
    private Jose() {}

    /** A JOSE failure (invalid token, key or claim). The message is the reference library's wording where it has one. */
    public static class JoseException extends RuntimeException {
        public JoseException(String message) { super(message); }
    }

    /** A token that is not the one canonical spelling of a compact JWS ({@code reason} is the gate's reason token). */
    public static final class CanonicalJwsError extends RuntimeException {
        public final String reason;
        public CanonicalJwsError(String reason, String detail) {
            super("non-canonical compact JWS: " + reason + (detail != null && !detail.isEmpty() ? " (" + detail + ")" : ""));
            this.reason = reason;
        }
    }

    public static final int DEFAULT_MAX_JWS_BYTES = 64 * 1024;

    /** Marks "verify under the {@code jwk} member of the protected header" (RFC 7515 s4.1.3, EmbeddedJWK). */
    public static final Object EMBEDDED = new Object();

    // ---- bytes ----

    public static byte[] sha256(byte[] b) { return digest("SHA-256", b); }

    static byte[] digest(String alg, byte[] b) {
        try {
            return MessageDigest.getInstance(alg).digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    /** UTF-8 bytes of a string as TextEncoder writes them: a lone surrogate becomes U+FFFD. */
    public static byte[] utf8(String s) { return Json.utf8(s.replaceAll("[\\uD800-\\uDFFF]", "\uFFFD")); }

    /** Lenient base64url (either alphabet, optional padding) as a JOSE library reads a key member; JoseException when undecodable. */
    public static byte[] decodeB64Lenient(String s) {
        String t = s.replaceAll("=+$", "").replace('+', '-').replace('/', '_');
        if (!t.matches("[A-Za-z0-9_-]*") || t.length() % 4 == 1) throw new JoseException("invalid base64url");
        return Base64.getUrlDecoder().decode(t);
    }

    /** A JWK member as the platform key import reads it: characters outside the base64 alphabets (whitespace, a replacement character) are skipped. */
    static byte[] decodeJwkMember(String s) { return decodeB64Lenient(s.replaceAll("[^A-Za-z0-9+/_=-]", "")); }

    // ---- canonical compact JWS gate ----

    /** A token that passed the canonical gate: its segments and the strict-JSON header (and payload, when JSON). */
    public static final class CanonicalJws {
        public final List<String> segments;
        public final Map<String, Object> header;
        public final Map<String, Object> payload;
        CanonicalJws(List<String> segments, Map<String, Object> header, Map<String, Object> payload) {
            this.segments = segments;
            this.header = header;
            this.payload = payload;
        }
    }

    private static boolean b64uAlphabet(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
        }
        return true;
    }

    /** One strictly canonical unpadded base64url segment (CanonicalJwsError otherwise). */
    public static byte[] decodeCanonicalBase64url(String seg) {
        if (!b64uAlphabet(seg)) throw new CanonicalJwsError("bad-character", null);
        if (seg.length() % 4 == 1) throw new CanonicalJwsError("non-canonical-base64url", "impossible length");
        byte[] b = Base64.getUrlDecoder().decode(seg);
        if (!b64u(b).equals(seg)) throw new CanonicalJwsError("non-canonical-base64url", null);
        return b;
    }

    /** A canonical base64url segment holding a strict-JSON document of any type (an SD-JWT Disclosure). */
    public static Object decodeCanonicalJsonSegment(String seg) { return parseJsonBytes(decodeCanonicalBase64url(seg)); }

    private static Object parseJsonBytes(byte[] bytes) {
        if (bytes.length >= 3 && (bytes[0] & 0xff) == 0xef && (bytes[1] & 0xff) == 0xbb && (bytes[2] & 0xff) == 0xbf) throw new CanonicalJwsError("bom", null);
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new CanonicalJwsError("bad-utf8", null);
        }
        try {
            return Json.parse(text);
        } catch (RuntimeException | StackOverflowError e) {
            throw new CanonicalJwsError("bad-json", e instanceof RuntimeException ? e.getMessage() : "nesting too deep");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObject(Object v) {
        if (!(v instanceof Map)) throw new CanonicalJwsError("not-an-object", null);
        return (Map<String, Object>) v;
    }

    /** Three-part gate with a JSON payload and the default size cap. */
    public static CanonicalJws assertCanonicalCompactJws(Object token) { return assertCanonicalCompactJws(token, 3, DEFAULT_MAX_JWS_BYTES, true); }

    /**
     * Throws CanonicalJwsError unless {@code token} is the one canonical spelling of a compact JWS ({@code parts} 3) or JWE (5):
     * non-empty unpadded base64url segments that re-encode exactly, a strict-JSON header (and payload when {@code payloadJson}).
     */
    public static CanonicalJws assertCanonicalCompactJws(Object token, int parts, int maxBytes, boolean payloadJson) {
        if (!(token instanceof String)) throw new CanonicalJwsError("not-a-string", null);
        String t = (String) token;
        if (t.length() > maxBytes) throw new CanonicalJwsError("too-long", null);
        String[] segs = t.split("\\.", -1);
        if (segs.length != parts) throw new CanonicalJwsError("bad-segment-count", segs.length + " != " + parts);
        byte[][] bytes = new byte[segs.length][];
        for (int i = 0; i < segs.length; i++) {
            String seg = segs[i];
            if (seg.isEmpty()) {
                if (parts == 5 && i == 1) { bytes[i] = new byte[0]; continue; }
                throw new CanonicalJwsError("empty-segment", "segment " + i);
            }
            bytes[i] = decodeCanonicalBase64url(seg);
        }
        Map<String, Object> header = asObject(parseJsonBytes(bytes[0]));
        Map<String, Object> payload = null;
        if (parts == 3 && payloadJson) payload = asObject(parseJsonBytes(bytes[1]));
        return new CanonicalJws(Arrays.asList(segs), header, payload);
    }

    // ---- JSON writer (JSON.stringify: insertion order) ----

    /** JSON text of a value with object members in insertion order, strings escaped like JSON.stringify. */
    public static String stringify(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder sb, Object v) {
        if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append(Json.canonicalize(e.getKey())).append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<Object>) v) {
                if (!first) sb.append(',');
                first = false;
                write(sb, x);
            }
            sb.append(']');
        } else if (v instanceof Double || v instanceof Float) {
            sb.append(Json.canonicalize(new Json.Num(v.toString())));
        } else {
            sb.append(Json.canonicalize(v));
        }
    }

    // ---- numbers / members ----

    /** The JavaScript number value of a JSON number, else null. */
    public static Double num(Object o) {
        if (o instanceof Json.Num) return Double.parseDouble(((Json.Num) o).raw);
        if (o instanceof Number) return ((Number) o).doubleValue();
        return null;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    static String str(Object o) { return o instanceof String ? (String) o : null; }

    // ---- key import ----

    /** A public verification key resolved from a JWK. */
    static final class PubKey {
        final String kind; // ed25519 | ed448 | ec | rsa
        final String crv;  // ec only
        final byte[] raw;  // ed25519 / ed448
        final PublicKey pk; // ec / rsa
        final int rsaBits;
        PubKey(String kind, String crv, byte[] raw, PublicKey pk, int rsaBits) {
            this.kind = kind; this.crv = crv; this.raw = raw; this.pk = pk; this.rsaBits = rsaBits;
        }
    }

    private static ECParameterSpec ecSpec(String crv) {
        String name;
        switch (crv) {
            case "P-256": name = "secp256r1"; break;
            case "P-384": name = "secp384r1"; break;
            case "P-521": name = "secp521r1"; break;
            default: throw new JoseException("Unsupported key curve for this operation");
        }
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
            ap.init(new ECGenParameterSpec(name));
            return ap.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new JoseException("Unsupported key curve for this operation");
        }
    }

    private static boolean onCurve(ECParameterSpec spec, BigInteger x, BigInteger y) {
        BigInteger p = ((ECFieldFp) spec.getCurve().getField()).getP();
        if (x.signum() < 0 || y.signum() < 0 || x.compareTo(p) >= 0 || y.compareTo(p) >= 0) return false;
        BigInteger lhs = y.multiply(y).mod(p);
        BigInteger rhs = x.multiply(x).multiply(x).add(spec.getCurve().getA().multiply(x)).add(spec.getCurve().getB()).mod(p);
        return lhs.equals(rhs);
    }

    private static String need(Map<String, Object> jwk, String name) {
        String s = str(jwk.get(name));
        if (s == null) throw new JoseException("Invalid JWK: missing \"" + name + "\"");
        return s;
    }

    /** A public JWK (OKP Ed25519 / Ed448, EC P-256/384/521 on-curve, RSA) as a verification key; JoseException otherwise. */
    static PubKey importPublic(Map<String, Object> jwk) {
        String kty = str(jwk.get("kty"));
        if (kty == null) throw new JoseException("JWK must have a kty");
        try {
            switch (kty) {
                case "OKP": {
                    String crv = need(jwk, "crv");
                    byte[] x = decodeJwkMember(need(jwk, "x"));
                    if (crv.equals("Ed25519") && x.length == 32) return new PubKey("ed25519", crv, x, null, 0);
                    if (crv.equals("Ed448") && x.length == 57) return new PubKey("ed448", crv, x, null, 0);
                    throw new JoseException("Invalid OKP JWK");
                }
                case "EC": {
                    String crv = need(jwk, "crv");
                    ECParameterSpec spec = ecSpec(crv);
                    BigInteger x = new BigInteger(1, decodeJwkMember(need(jwk, "x"))), y = new BigInteger(1, decodeJwkMember(need(jwk, "y")));
                    if (!onCurve(spec, x, y)) throw new JoseException("Invalid EC JWK: point is not on the curve");
                    PublicKey pk = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
                    return new PubKey("ec", crv, null, pk, 0);
                }
                case "RSA": {
                    if (jwk.containsKey("oth")) throw new JoseException("RSA JWK \"oth\" (Other Primes Info) Parameter value is not supported");
                    BigInteger n = new BigInteger(1, decodeJwkMember(need(jwk, "n"))), e = new BigInteger(1, decodeJwkMember(need(jwk, "e")));
                    if (n.signum() == 0 || !e.testBit(0) || e.compareTo(BigInteger.valueOf(3)) < 0 || e.compareTo(n) >= 0) throw new JoseException("Invalid RSA JWK");
                    PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
                    return new PubKey("rsa", null, null, pk, n.bitLength());
                }
                default:
                    throw new JoseException("Unsupported \"kty\" (Key Type) Parameter value");
            }
        } catch (GeneralSecurityException | RuntimeException x) {
            if (x instanceof JoseException) throw (JoseException) x;
            throw new JoseException("Invalid JWK: " + x.getMessage());
        }
    }

    // ---- algorithm / key agreement (the reference's keyForCrypto) ----

    private static final List<String> ALGS = List.of("EdDSA", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512");

    private static void checkKeyForAlg(String alg, PubKeyLike k) {
        switch (alg) {
            case "EdDSA":
                if (!k.kind.equals("ed25519") && !k.kind.equals("ed448")) throw new JoseException("Invalid key for this operation, its asymmetricKeyType must be ed25519 or ed448");
                break;
            case "RS256": case "RS384": case "RS512": case "PS256": case "PS384": case "PS512":
                if (!k.kind.equals("rsa")) throw new JoseException("Invalid key for this operation, its asymmetricKeyType must be rsa");
                if (k.rsaBits < 2048) throw new JoseException(alg + " requires key modulusLength to be 2048 bits or larger");
                break;
            case "ES256": case "ES384": case "ES512": {
                if (!k.kind.equals("ec")) throw new JoseException("Invalid key for this operation, its asymmetricKeyType must be ec");
                String want = alg.equals("ES256") ? "P-256" : alg.equals("ES384") ? "P-384" : "P-521";
                if (!want.equals(k.crv)) throw new JoseException("Invalid key curve for the algorithm, its curve must be " + want + ", got " + k.crv);
                break;
            }
            default:
                throw new JoseException("alg " + alg + " is not supported either by JOSE or your javascript runtime");
        }
    }

    /** What checkKeyForAlg needs of a public or private key. */
    private static final class PubKeyLike {
        final String kind, crv; final int rsaBits;
        PubKeyLike(String kind, String crv, int rsaBits) { this.kind = kind; this.crv = crv; this.rsaBits = rsaBits; }
    }

    private static String sigHash(String alg) { return alg.endsWith("256") ? "SHA256" : alg.endsWith("384") ? "SHA384" : "SHA512"; }

    private static int hashLen(String alg) { return alg.endsWith("256") ? 32 : alg.endsWith("384") ? 48 : 64; }

    private static MGF1ParameterSpec mgf(String alg) { return alg.endsWith("256") ? MGF1ParameterSpec.SHA256 : alg.endsWith("384") ? MGF1ParameterSpec.SHA384 : MGF1ParameterSpec.SHA512; }

    private static String mdName(String alg) { return alg.endsWith("256") ? "SHA-256" : alg.endsWith("384") ? "SHA-384" : "SHA-512"; }

    // ---- strict Ed25519 ----

    private static final BigInteger P25519 = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger L25519 = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger[] SMALL_ORDER_Y = {
        BigInteger.ONE,
        P25519.subtract(BigInteger.ONE),
        BigInteger.ZERO,
        new BigInteger("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7", 16),
        new BigInteger("05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826", 16),
    };

    private static BigInteger leInt(byte[] b, int off, int len, boolean clearTop) {
        byte[] be = new byte[len];
        for (int i = 0; i < len; i++) be[len - 1 - i] = b[off + i];
        if (clearTop) be[0] &= 0x7f;
        return new BigInteger(1, be);
    }

    private static boolean badPoint(byte[] b, int off) {
        BigInteger y = leInt(b, off, 32, true);
        if (y.compareTo(P25519) >= 0) return true;
        for (BigInteger s : SMALL_ORDER_Y) if (y.equals(s)) return true;
        return false;
    }

    /** Strict RFC 8032 Ed25519 verify: canonical S, no non-canonical / small-order / mixed-order key or R. */
    public static boolean verifyEd25519Strict(byte[] pk, byte[] msg, byte[] sig) {
        try {
            if (pk == null || sig == null || pk.length != 32 || sig.length != 64) return false;
            if (badPoint(pk, 0) || badPoint(sig, 0)) return false;
            if (leInt(sig, 32, 32, false).compareTo(L25519) >= 0) return false;
            if (!Ed25519.validatePublicKeyFull(pk, 0) || !Ed25519.validatePublicKeyFull(sig, 0)) return false;
            return Ed25519.verify(sig, 0, pk, 0, msg, 0, msg.length);
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- verify / sign primitives ----

    private static boolean verifyRaw(String alg, PubKey k, byte[] sig, byte[] data) {
        try {
            switch (alg) {
                case "EdDSA":
                    if (k.kind.equals("ed25519")) return verifyEd25519Strict(k.raw, data, sig);
                    {
                        Ed448Signer s = new Ed448Signer(new byte[0]);
                        s.init(false, new Ed448PublicKeyParameters(k.raw, 0));
                        s.update(data, 0, data.length);
                        return s.verifySignature(sig);
                    }
                case "ES256": case "ES384": case "ES512": {
                    Signature s = Signature.getInstance(sigHash(alg) + "withECDSAinP1363Format");
                    s.initVerify(k.pk);
                    s.update(data);
                    return s.verify(sig);
                }
                case "RS256": case "RS384": case "RS512": {
                    Signature s = Signature.getInstance(sigHash(alg) + "withRSA");
                    s.initVerify(k.pk);
                    s.update(data);
                    return s.verify(sig);
                }
                default: { // PS*
                    Signature s = Signature.getInstance("RSASSA-PSS");
                    s.setParameter(new PSSParameterSpec(mdName(alg), "MGF1", mgf(alg), hashLen(alg), 1));
                    s.initVerify(k.pk);
                    s.update(data);
                    return s.verify(sig);
                }
            }
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** Verifies a JWS signature over {@code data} under a public JWK; false for any failure. JoseException when alg and key do not agree. */
    public static boolean verifySignature(String alg, Map<String, Object> publicJwk, byte[] sig, byte[] data) {
        PubKey k = importPublic(publicJwk);
        checkKeyForAlg(alg, new PubKeyLike(k.kind, k.crv, k.rsaBits));
        return verifyRaw(alg, k, sig, data);
    }

    /** Signs {@code data} under a private JWK (OKP Ed25519 / Ed448, EC, RSA); JoseException when the key cannot sign under {@code alg}. */
    public static byte[] signRaw(String alg, Map<String, Object> jwk, byte[] data) {
        String kty = str(jwk.get("kty"));
        if (kty == null || str(jwk.get("d")) == null) throw new JoseException("JSON Web Key for this operation be a private JWK");
        if (str(jwk.get("alg")) != null && !str(jwk.get("alg")).equals(alg)) throw new JoseException("Invalid key for this operation, when present its alg must be " + alg);
        try {
            switch (kty) {
                case "OKP": {
                    String crv = need(jwk, "crv");
                    byte[] d = decodeJwkMember(need(jwk, "d"));
                    checkKeyForAlg(alg, new PubKeyLike(crv.equals("Ed25519") ? "ed25519" : crv.equals("Ed448") ? "ed448" : "okp", null, 0));
                    if (crv.equals("Ed25519") && d.length == 32) {
                        Ed25519Signer s = new Ed25519Signer();
                        s.init(true, new Ed25519PrivateKeyParameters(d, 0));
                        s.update(data, 0, data.length);
                        return s.generateSignature();
                    }
                    if (crv.equals("Ed448") && d.length == 57) {
                        Ed448Signer s = new Ed448Signer(new byte[0]);
                        s.init(true, new Ed448PrivateKeyParameters(d, 0));
                        s.update(data, 0, data.length);
                        return s.generateSignature();
                    }
                    throw new JoseException("Invalid OKP JWK");
                }
                case "EC": {
                    String crv = need(jwk, "crv");
                    checkKeyForAlg(alg, new PubKeyLike("ec", crv, 0));
                    ECParameterSpec spec = ecSpec(crv);
                    PrivateKey pk = KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, decodeJwkMember(need(jwk, "d"))), spec));
                    Signature s = Signature.getInstance(sigHash(alg) + "withECDSAinP1363Format");
                    s.initSign(pk);
                    s.update(data);
                    return s.sign();
                }
                case "RSA": {
                    BigInteger n = new BigInteger(1, decodeJwkMember(need(jwk, "n")));
                    checkKeyForAlg(alg, new PubKeyLike("rsa", null, n.bitLength()));
                    PrivateKey pk = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateCrtKeySpec(n,
                        new BigInteger(1, decodeJwkMember(need(jwk, "e"))), new BigInteger(1, decodeJwkMember(need(jwk, "d"))),
                        new BigInteger(1, decodeJwkMember(need(jwk, "p"))), new BigInteger(1, decodeJwkMember(need(jwk, "q"))),
                        new BigInteger(1, decodeJwkMember(need(jwk, "dp"))), new BigInteger(1, decodeJwkMember(need(jwk, "dq"))),
                        new BigInteger(1, decodeJwkMember(need(jwk, "qi")))));
                    Signature s;
                    if (alg.startsWith("PS")) {
                        s = Signature.getInstance("RSASSA-PSS");
                        s.setParameter(new PSSParameterSpec(mdName(alg), "MGF1", mgf(alg), hashLen(alg), 1));
                    } else s = Signature.getInstance(sigHash(alg) + "withRSA");
                    s.initSign(pk);
                    s.update(data);
                    return s.sign();
                }
                default:
                    throw new JoseException("Invalid key for this operation, its kty must be RSA, OKP, or EC");
            }
        } catch (GeneralSecurityException | RuntimeException e) {
            if (e instanceof JoseException) throw (JoseException) e;
            throw new JoseException("signing failed: " + e.getMessage());
        }
    }

    // ---- compact JWS verify ----

    /** A verified compact JWS: the parsed protected header and the payload bytes. */
    public static final class Verified {
        public final Map<String, Object> protectedHeader;
        public final byte[] payload;
        Verified(Map<String, Object> protectedHeader, byte[] payload) { this.protectedHeader = protectedHeader; this.payload = payload; }
    }

    /** The reference's header gate that runs before any key is resolved: {@code crit} well-formed and recognised, {@code b64} a boolean when declared critical. */
    public static void checkCritHeader(Map<String, Object> prot) {
        validateCrit(prot);
        if (prot.get("crit") instanceof List && ((List<?>) prot.get("crit")).contains("b64") && !(prot.get("b64") instanceof Boolean)) {
            throw new JoseException("The \"b64\" (base64url-encode payload) Header Parameter must be a boolean");
        }
    }

    @SuppressWarnings("unchecked")
    private static void validateCrit(Map<String, Object> prot) {
        if (!prot.containsKey("crit")) return;
        Object crit = prot.get("crit");
        if (!(crit instanceof List) || ((List<Object>) crit).isEmpty()) throw new JoseException("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present");
        for (Object c : (List<Object>) crit) {
            if (!(c instanceof String) || ((String) c).isEmpty()) throw new JoseException("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present");
        }
        for (Object c : (List<Object>) crit) {
            if (!"b64".equals(c)) throw new JoseException("Extension Header Parameter \"" + c + "\" is not recognized");
            if (!prot.containsKey("b64")) throw new JoseException("Extension Header Parameter \"b64\" is missing");
        }
    }

    /**
     * Verifies a compact JWS under {@code key} ({@link #EMBEDDED} or a public JWK map), allowing only {@code algorithms}
     * (null = any supported). Mirrors the reference compactVerify: header checks, crit, alg allow-list, key / alg agreement, signature.
     */
    public static Verified compactVerify(String jws, Object key, Collection<String> algorithms) {
        String[] parts = jws.split("\\.", -1);
        if (parts.length != 3) throw new JoseException("Invalid Compact JWS");
        String protectedB64 = parts[0], payloadSeg = parts[1], sigSeg = parts[2];
        Map<String, Object> prot = new LinkedHashMap<>();
        if (!protectedB64.isEmpty()) {
            try {
                Object o = Json.parseLenient(new String(decodeB64Lenient(protectedB64), StandardCharsets.UTF_8));
                if (!(o instanceof Map)) throw new JoseException("JWS Protected Header is invalid");
                prot = obj(o);
            } catch (RuntimeException e) {
                throw new JoseException("JWS Protected Header is invalid");
            }
        }
        validateCrit(prot);
        boolean b64 = true;
        if (prot.get("crit") instanceof List && ((List<?>) prot.get("crit")).contains("b64")) {
            if (!(prot.get("b64") instanceof Boolean)) throw new JoseException("The \"b64\" (base64url-encode payload) Header Parameter must be a boolean");
            b64 = (Boolean) prot.get("b64");
        }
        String alg = str(prot.get("alg"));
        if (alg == null || alg.isEmpty()) throw new JoseException("JWS \"alg\" (Algorithm) Header Parameter missing or invalid");
        if (algorithms != null && !algorithms.contains(alg)) throw new JoseException("\"alg\" (Algorithm) Header Parameter value not allowed");
        Map<String, Object> jwk;
        if (key == EMBEDDED) {
            Map<String, Object> h = obj(prot.get("jwk"));
            if (h == null) throw new JoseException("\"jwk\" (JSON Web Key) Header Parameter must be a JSON object");
            if ("oct".equals(h.get("kty")) || h.get("d") instanceof String) throw new JoseException("\"jwk\" (JSON Web Key) Header Parameter must be a public key");
            jwk = h;
        } else {
            jwk = obj(key);
            if (jwk == null) throw new JoseException("Invalid key input");
            if (str(jwk.get("kty")) == null || "oct".equals(jwk.get("kty")) || jwk.get("d") != null) throw new JoseException("JSON Web Key for this operation be a public JWK");
        }
        PubKey k = importPublic(jwk);
        checkKeyForAlg(alg, new PubKeyLike(k.kind, k.crv, k.rsaBits));
        byte[] sig;
        try {
            sig = decodeB64Lenient(sigSeg);
        } catch (JoseException e) {
            throw new JoseException("Failed to base64url decode the signature");
        }
        byte[] data = utf8(protectedB64 + "." + payloadSeg);
        if (!verifyRaw(alg, k, sig, data)) throw new JoseException("signature verification failed");
        byte[] payload;
        if (b64) {
            try {
                payload = decodeB64Lenient(payloadSeg);
            } catch (JoseException e) {
                throw new JoseException("Failed to base64url decode the payload");
            }
        } else payload = utf8(payloadSeg);
        return new Verified(prot, payload);
    }

    // ---- JWT ----

    /** Claim checks of a JWT verification (null/absent members are not checked). */
    public static final class JwtOptions {
        public String typ;
        public String issuer;
        public String subject;
        public List<String> audience; // null = no audience check
        public Double clockTolerance; // seconds; null = 0
        public Double currentDateMs;  // null = now; NaN or beyond +-8.64e15 is an invalid Date (every time check passes)
        public Collection<String> algorithms;
    }

    /** A verified JWT. */
    public static final class VerifiedJwt {
        public final Map<String, Object> payload;
        public final Map<String, Object> protectedHeader;
        VerifiedJwt(Map<String, Object> payload, Map<String, Object> protectedHeader) { this.payload = payload; this.protectedHeader = protectedHeader; }
    }

    private static String normalizeTyp(String v) { String l = v.toLowerCase(java.util.Locale.ROOT); return l.startsWith("application/") ? l.substring(12) : l; }

    /** compactVerify, then the reference JWT claim checks (typ, aud, nbf, exp, iat shape). Everything that fails throws JoseException. */
    @SuppressWarnings("unchecked")
    public static VerifiedJwt jwtVerify(String jwt, Object key, JwtOptions opts) {
        Verified v = compactVerify(jwt, key, opts.algorithms);
        Object crit = v.protectedHeader.get("crit");
        if (crit instanceof List && ((List<Object>) crit).contains("b64") && Boolean.FALSE.equals(v.protectedHeader.get("b64"))) {
            throw new JoseException("JWTs MUST NOT use unencoded payload");
        }
        Object parsed = null;
        try {
            parsed = Json.parseLenient(new String(v.payload, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            // not an object, below
        }
        if (!(parsed instanceof Map)) throw new JoseException("JWT Claims Set must be a top-level JSON object");
        Map<String, Object> payload = (Map<String, Object>) parsed;
        if (opts.typ != null && !opts.typ.isEmpty()) {
            Object t = v.protectedHeader.get("typ");
            if (!(t instanceof String) || !normalizeTyp((String) t).equals(normalizeTyp(opts.typ))) throw new JoseException("unexpected \"typ\" JWT header value");
        }
        if (opts.audience != null && !payload.containsKey("aud")) throw new JoseException("missing required \"aud\" claim");
        if (opts.subject != null && !payload.containsKey("sub")) throw new JoseException("missing required \"sub\" claim");
        if (opts.issuer != null && !payload.containsKey("iss")) throw new JoseException("missing required \"iss\" claim");
        if (opts.issuer != null && !opts.issuer.isEmpty() && !opts.issuer.equals(payload.get("iss"))) throw new JoseException("unexpected \"iss\" claim value");
        if (opts.subject != null && !opts.subject.isEmpty() && !opts.subject.equals(payload.get("sub"))) throw new JoseException("unexpected \"sub\" claim value");
        // an empty-string audience option is required to be present but, being falsy in the reference, is not compared
        if (opts.audience != null && !(opts.audience.size() == 1 && opts.audience.get(0).isEmpty())) {
            Object aud = payload.get("aud");
            boolean ok = false;
            if (aud instanceof String) ok = opts.audience.contains(aud);
            else if (aud instanceof List) {
                for (String a : opts.audience) if (((List<Object>) aud).contains(a)) ok = true;
            }
            if (!ok) throw new JoseException("unexpected \"aud\" claim value");
        }
        double tol = opts.clockTolerance == null ? 0 : opts.clockTolerance;
        double now;
        if (opts.currentDateMs == null) now = Math.floor(System.currentTimeMillis() / 1000.0);
        else {
            double ms = opts.currentDateMs;
            if (Double.isNaN(ms) || Math.abs(ms) > 8.64e15) now = Double.NaN;
            else now = Math.floor((ms < 0 ? Math.ceil(ms) : Math.floor(ms)) / 1000.0);
        }
        if (payload.containsKey("iat") && num(payload.get("iat")) == null) throw new JoseException("\"iat\" claim must be a number");
        // a clock or tolerance that is not finite would let every nbf and exp comparison pass
        if ((payload.containsKey("nbf") || payload.containsKey("exp")) && !(Double.isFinite(now) && Double.isFinite(tol))) throw new JoseException("the clock and clockTolerance must be finite numbers");
        if (payload.containsKey("nbf")) {
            Double nbf = num(payload.get("nbf"));
            if (nbf == null) throw new JoseException("\"nbf\" claim must be a number");
            if (nbf > now + tol) throw new JoseException("\"nbf\" claim timestamp check failed");
        }
        if (payload.containsKey("exp")) {
            Double exp = num(payload.get("exp"));
            if (exp == null) throw new JoseException("\"exp\" claim must be a number");
            if (exp <= now - tol) throw new JoseException("\"exp\" claim timestamp check failed");
        }
        return new VerifiedJwt(payload, v.protectedHeader);
    }

    /** SignJWT: compact JWS of {@code header} + {@code payload} (JSON.stringify member order) under a private JWK. */
    public static String signJwt(Map<String, Object> header, Map<String, Object> payload, Map<String, Object> privateJwk) {
        String alg = str(header.get("alg"));
        if (alg == null || alg.isEmpty()) throw new JoseException("JWS \"alg\" (Algorithm) Header Parameter missing or invalid");
        if (header.containsKey("crit")) throw new JoseException("crit is not supported when signing");
        String h = b64u(utf8(stringify(header))), p = b64u(utf8(stringify(payload)));
        byte[] sig = signRaw(alg, privateJwk, utf8(h + "." + p));
        return h + "." + p + "." + b64u(sig);
    }

    // ---- thumbprint ----

    private static void check(Object v, String description) {
        if (!(v instanceof String) || ((String) v).isEmpty()) throw new JoseException(description + " missing or invalid");
    }

    /** RFC 7638 JWK thumbprint (base64url of the hash of the required members, keys sorted). */
    public static String jwkThumbprint(Map<String, Object> jwk, String digest) {
        if (jwk == null) throw new JoseException("JWK must be an object");
        String d = digest == null ? "sha256" : digest;
        if (!d.equals("sha256") && !d.equals("sha384") && !d.equals("sha512")) throw new JoseException("digestAlgorithm must one of \"sha256\", \"sha384\", or \"sha512\"");
        Map<String, Object> c = new LinkedHashMap<>();
        Object kty = jwk.get("kty");
        if ("EC".equals(kty)) {
            check(jwk.get("crv"), "\"crv\" (Curve) Parameter"); check(jwk.get("x"), "\"x\" (X Coordinate) Parameter"); check(jwk.get("y"), "\"y\" (Y Coordinate) Parameter");
            c.put("crv", jwk.get("crv")); c.put("kty", kty); c.put("x", jwk.get("x")); c.put("y", jwk.get("y"));
        } else if ("OKP".equals(kty)) {
            check(jwk.get("crv"), "\"crv\" (Subtype of Key Pair) Parameter"); check(jwk.get("x"), "\"x\" (Public Key) Parameter");
            c.put("crv", jwk.get("crv")); c.put("kty", kty); c.put("x", jwk.get("x"));
        } else if ("RSA".equals(kty)) {
            check(jwk.get("e"), "\"e\" (Exponent) Parameter"); check(jwk.get("n"), "\"n\" (Modulus) Parameter");
            c.put("e", jwk.get("e")); c.put("kty", kty); c.put("n", jwk.get("n"));
        } else if ("oct".equals(kty)) {
            check(jwk.get("k"), "\"k\" (Key Value) Parameter");
            c.put("k", jwk.get("k")); c.put("kty", kty);
        } else throw new JoseException("\"kty\" (Key Type) Parameter missing or unsupported");
        String alg = d.equals("sha256") ? "SHA-256" : d.equals("sha384") ? "SHA-384" : "SHA-512";
        return b64u(digest(alg, utf8(stringify(c))));
    }

    /** True when {@code alg} is one this class can verify or sign. */
    public static boolean supportsAlg(String alg) { return ALGS.contains(alg); }

    /** Copy of a list (never null). */
    static <T> List<T> copy(List<T> l) { return l == null ? new ArrayList<>() : new ArrayList<>(l); }
}
