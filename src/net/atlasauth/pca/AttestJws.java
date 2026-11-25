package net.atlasauth.pca;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.nio.charset.StandardCharsets;

/**
 * Compact-JWS plumbing shared by the Azure MAA and Google Confidential Space verifiers: the canonical base64url gate, the
 * parsed token and the signature checks (ES256 and RS256) under a certificate or JWK key. Port of the Go attest_jws.go.
 */
public final class AttestJws {
    private AttestJws() {}

    private static final Pattern B64U = Pattern.compile("[A-Za-z0-9_-]*");

    /** Decodes one strictly canonical unpadded base64url segment (one spelling per value); AttestException otherwise. */
    public static byte[] decodeCanonicalBase64url(String seg) {
        if (!B64U.matcher(seg).matches()) throw new AttestException("non-canonical compact JWS: bad-character");
        if (seg.length() % 4 == 1) throw new AttestException("non-canonical compact JWS: non-canonical-base64url (impossible length)");
        // cannot throw: the alphabet is checked, there is no padding, and a length of 1 mod 4 is refused above
        byte[] b = Base64.getUrlDecoder().decode(seg);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(b).equals(seg)) {
            throw new AttestException("non-canonical compact JWS: non-canonical-base64url");
        }
        return b;
    }

    /** A parsed compact JWS: header fields, payload and signing input (nothing verified). */
    public static final class JwtParsed {
        public String alg;
        public String kid;
        public boolean hasKid;
        public List<String> x5c;
        public boolean hasX5c;
        public Map<String, Object> payload;
        public byte[] signingInput;
        public byte[] signature;
    }

    /** Parses a compact JWS; prefix is the reference parser's name (it leads every message). */
    public static JwtParsed parseJwt(String token, String prefix) {
        if (token.isEmpty()) throw new AttestException(prefix + ": empty token");
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) throw new AttestException(prefix + ": a compact JWS has exactly three dot-separated parts");
        String h = parts[0], p = parts[1], s = parts[2];
        if (h.isEmpty() || p.isEmpty() || s.isEmpty()) throw new AttestException(prefix + ": empty JWS segment");
        Object headerObj = jsonSegment(h, prefix);
        Object payloadObj = jsonSegment(p, prefix);
        Map<String, Object> hdr = AttestCommon.asRec(headerObj);
        if (hdr == null) throw new AttestException(prefix + ": header is not a JSON object");
        Map<String, Object> payload = AttestCommon.asRec(payloadObj);
        if (payload == null) throw new AttestException(prefix + ": payload is not a JSON object");
        Object alg = hdr.get("alg");
        if (!(alg instanceof String) || ((String) alg).isEmpty()) throw new AttestException(prefix + ": header has no alg");
        JwtParsed out = new JwtParsed();
        out.alg = (String) alg;
        out.payload = payload;
        out.signingInput = (h + "." + p).getBytes(StandardCharsets.UTF_8);
        if (hdr.get("kid") instanceof String) {
            out.kid = (String) hdr.get("kid");
            out.hasKid = true;
        }
        List<String> l = AttestCommon.asStrList(hdr.get("x5c"));
        if (l != null) {
            out.x5c = l;
            out.hasX5c = true;
        }
        try {
            out.signature = decodeCanonicalBase64url(s);
        } catch (AttestException e) {
            throw new AttestException(prefix + ": malformed signature segment: " + e.getMessage());
        }
        return out;
    }

    /** The kty / crv of a key's JWK export ("undefined" for a key type without a curve). */
    public static String[] jwkKtyCrv(CertKey k) {
        if (k.pub instanceof ECPublicKey) return new String[] {"EC", AttestCommon.ecCurveName(((ECPublicKey) k.pub).getParams())};
        if (k.pub instanceof RSAPublicKey) return new String[] {"RSA", "undefined"};
        if (k.typ.equals("ed25519")) return new String[] {"OKP", "Ed25519"};
        return new String[] {k.typ, "undefined"};
    }

    /** Verifies a raw r||s ES256 signature over the signing input under a P-256 key. */
    public static boolean jwsEs256Ok(byte[] sig, byte[] input, CertKey k) {
        if (!(k.pub instanceof ECPublicKey)) return false;
        ECPublicKey pk = (ECPublicKey) k.pub;
        if (!AttestCommon.ecCurveName(pk.getParams()).equals("P-256") || sig.length != 64) return false;
        return AttestCommon.verifyRawECDSA(pk, AttestCommon.sha256Sum(input), sig);
    }

    /** Verifies an RSASSA-PKCS1-v1_5 / SHA-256 signature under an RSA key. */
    public static boolean jwsRs256Ok(byte[] sig, byte[] input, CertKey k) {
        if (!(k.pub instanceof RSAPublicKey) || !k.typ.equals("rsa") || !CertKey.rsaKeyOk(k.pub)) return false; // a PKCS#1 signature under an rsa-pss key is refused
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(k.pub);
            s.update(input);
            return s.verify(sig);
        } catch (java.security.GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** Builds a public RSA key from base64url n / e; AttestException when it cannot be. */
    public static CertKey jwkRsaKey(String n, String e) {
        byte[] nb = AttestCommon.nodeB64(n);
        byte[] eb = AttestCommon.nodeB64(e);
        // an empty e reads 0 and is refused below
        if (nb.length == 0) throw new AttestException(AttestCert.OSSL_UNSUPPORTED);
        BigInteger ev = new BigInteger(1, eb);
        if (ev.bitLength() > 32 || !ev.testBit(0) || ev.compareTo(BigInteger.valueOf(3)) < 0) throw new AttestException(AttestCert.OSSL_UNSUPPORTED);
        try {
            RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(new BigInteger(1, nb), ev));
            if (!CertKey.rsaKeyOk(pub)) throw new AttestException(AttestCert.OSSL_UNSUPPORTED);
            return CertKey.of(pub, pub.getEncoded());
        } catch (java.security.GeneralSecurityException | RuntimeException x) {
            throw new AttestException(AttestCert.OSSL_UNSUPPORTED);
        }
    }

    /** Builds a public EC key from crv / x / y (on-curve points only); AttestException otherwise. */
    public static CertKey jwkEcKey(String crv, String x, String y) {
        if (!crv.equals("P-256") && !crv.equals("P-384") && !crv.equals("P-521")) throw new AttestException(AttestCert.OSSL_UNSUPPORTED);
        ECPublicKey pub = AttestCommon.ecKeyOf(crv, new BigInteger(1, AttestCommon.nodeB64(x)), new BigInteger(1, AttestCommon.nodeB64(y)));
        if (pub == null) throw new AttestException(AttestCert.OSSL_UNSUPPORTED);
        return CertKey.of(pub, pub.getEncoded());
    }

    /**
     * The JSON value of a header or payload segment. A segment that does not decode or parse is refused with the
     * canonical-form message of the base64url gate, else the engine's JSON.parse wording (the parser's own message when the
     * engine would accept the text, i.e. nesting deeper than this parser follows).
     */
    static Object jsonSegment(String seg, String prefix) {
        byte[] b;
        try {
            b = decodeCanonicalBase64url(seg);
        } catch (AttestException d) {
            throw new AttestException(prefix + ": malformed JSON segment: " + d.getMessage());
        }
        if (b.length > AttestCommon.MAX_JSON_BYTES) throw new AttestException(prefix + ": malformed JSON segment: input too large");
        try {
            return AttestCommon.jsonLenient(b);
        } catch (AttestException j) {
            String msg = AttestV8Json.v8JsonError(new String(b, StandardCharsets.UTF_8));
            throw new AttestException(prefix + ": malformed JSON segment: " + (msg.isEmpty() ? j.getMessage() : msg));
        }
    }
}
