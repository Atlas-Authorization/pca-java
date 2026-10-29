package net.atlasauth.pca;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

/**
 * Hardware attestation verifiers (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, Google Confidential Space, NVIDIA GPU SPDM):
 * shared helpers. The vendor verifiers answer exactly what the reference verifiers of the TypeScript package answer, reason
 * text included, and fail closed on anything they cannot establish. Port of the Go attest_common.go; method names are the
 * Go names in camelCase.
 */
public final class AttestCommon {
    private AttestCommon() {}

    static final String ATTEST_BIND_DOMAIN = "atlas-pca/attest-bind/v1\0";
    static final double MAX_SAFE_INT = 9007199254740991d;

    // ------------------------------------------------------------- binding

    static byte[] lengthPrefixed(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[4 + b.length];
        out[0] = (byte) (b.length >>> 24);
        out[1] = (byte) (b.length >>> 16);
        out[2] = (byte) (b.length >>> 8);
        out[3] = (byte) b.length;
        System.arraycopy(b, 0, out, 4, b.length);
        return out;
    }

    /** SHA-512( "atlas-pca/attest-bind/v1\0" || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce) ); throws AttestException. */
    public static byte[] attestationBindingBytes(AttestationBinding e) {
        if (e.holderPub.isEmpty()) throw new AttestException("binding: holderPub required");
        if (e.grantRef.isEmpty()) throw new AttestException("binding: grantRef required");
        if (e.nonce.isEmpty()) throw new AttestException("binding: nonce required");
        if (Double.isNaN(e.epoch) || e.epoch != Math.floor(e.epoch) || e.epoch < 0 || e.epoch > MAX_SAFE_INT) {
            throw new AttestException("binding: epoch must be a non-negative safe integer");
        }
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        byte[] dom = ATTEST_BIND_DOMAIN.getBytes(StandardCharsets.UTF_8);
        buf.write(dom, 0, dom.length);
        byte[] a = lengthPrefixed(e.holderPub);
        buf.write(a, 0, a.length);
        a = lengthPrefixed(e.grantRef);
        buf.write(a, 0, a.length);
        long ep = (long) e.epoch;
        for (int i = 7; i >= 0; i--) buf.write((int) (ep >>> (8 * i)) & 0xff);
        a = lengthPrefixed(e.nonce);
        buf.write(a, 0, a.length);
        return sha512Sum(buf.toByteArray());
    }

    // ------------------------------------------------------------- small helpers

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    public static String toHexLower(byte[] b) {
        char[] c = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            c[2 * i] = HEX[(b[i] >> 4) & 0xf];
            c[2 * i + 1] = HEX[b[i] & 0xf];
        }
        return new String(c);
    }

    /** Decodes an even-length hex string (either case); the caller has checked {@link #isHexString}. */
    public static byte[] hexDecode(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) ((Character.digit(s.charAt(2 * i), 16) << 4) | Character.digit(s.charAt(2 * i + 1), 16));
        return out;
    }

    public static boolean timingSafeEq(byte[] a, byte[] b) { return MessageDigest.isEqual(a, b); }

    /** The characters JavaScript's String.prototype.trim removes. */
    public static boolean isJsSpace(int r) {
        switch (r) {
            case '\t': case '\n': case 0x0b: case '\f': case '\r': case ' ': case 0xa0: case 0x1680: case 0x2028: case 0x2029:
            case 0x202f: case 0x205f: case 0x3000: case 0xfeff:
                return true;
            default:
                return r >= 0x2000 && r <= 0x200a;
        }
    }

    public static String jsTrim(String s) {
        int a = 0, b = s.length();
        while (a < b && isJsSpace(s.charAt(a))) a++;
        while (b > a && isJsSpace(s.charAt(b - 1))) b--;
        return s.substring(a, b);
    }

    /** Decodes like Buffer.from(s, "base64"): either alphabet, characters outside it are skipped, "=" ends the data. */
    public static byte[] nodeB64(String s) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int acc = 0;
        int bits = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int v;
            if (c >= 'A' && c <= 'Z') v = c - 'A';
            else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
            else if (c >= '0' && c <= '9') v = c - '0' + 52;
            else if (c == '+' || c == '-') v = 62;
            else if (c == '/' || c == '_') v = 63;
            else if (c == '=') break;
            else continue;
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.write((acc >>> bits) & 0xff);
                acc &= (1 << bits) - 1;
            }
        }
        return out.toByteArray();
    }

    private static final Pattern HEX_PATTERN = Pattern.compile("[0-9a-fA-F]+");

    /** True iff the whole string is hex digits (not an anchored find: Java's $ would also match before a final newline). */
    public static boolean isHexChars(String s) { return !s.isEmpty() && HEX_PATTERN.matcher(s).matches(); }

    public static boolean isHexString(String s) { return !s.isEmpty() && s.length() % 2 == 0 && HEX_PATTERN.matcher(s).matches(); }

    /** Decodes a byte-carrying claim: hex (optionally 0x-prefixed), else base64url / base64; null when it carries no bytes. */
    public static byte[] decodeClaimBytes(String value) {
        String t = jsTrim(value);
        String hx = t;
        if (t.startsWith("0x") || t.startsWith("0X")) hx = t.substring(2);
        if (isHexString(hx)) return hexDecode(hx);
        byte[] b = nodeB64(t);
        if (b.length > 0) return b;
        return null;
    }

    /** Parses like JSON.parse (numbers kept as {@link Json.Num}; the last of a duplicate key wins); throws AttestException. */
    public static Object jsonLenient(byte[] b) {
        try {
            return Json.parseLenient(new String(b, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new AttestException(String.valueOf(e.getMessage()));
        } catch (StackOverflowError e) {
            throw new AttestException("JSON nesting too deep");
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asRec(Object v) { return v instanceof Map ? (Map<String, Object>) v : null; }

    public static String asStr(Object v) { return v instanceof String ? (String) v : null; }

    /** The reference asNumber: a finite JSON number, or null. */
    public static Double asFinite(Object v) {
        double f;
        if (v instanceof Json.Num) {
            try {
                f = Double.parseDouble(((Json.Num) v).raw);
            } catch (NumberFormatException e) {
                return null;
            }
        } else if (v instanceof Double) f = (Double) v;
        else if (v instanceof Integer || v instanceof Long) f = ((Number) v).doubleValue();
        else return null;
        if (Double.isInfinite(f) || Double.isNaN(f)) return null;
        return f;
    }

    /** A list of strings, or null when v is not a list or holds a non-string. */
    public static List<String> asStrList(Object v) {
        if (!(v instanceof List)) return null;
        List<String> out = new ArrayList<>();
        for (Object x : (List<?>) v) {
            if (!(x instanceof String)) return null;
            out.add((String) x);
        }
        return out;
    }

    /** String(n) as JavaScript renders a number. */
    public static String jsNumString(double f) {
        if (Double.isNaN(f)) return "NaN";
        if (Double.isInfinite(f)) return f > 0 ? "Infinity" : "-Infinity";
        if (f == 0) return "0";
        double a = Math.abs(f);
        BigDecimal bd = new BigDecimal(Double.toString(a)).stripTrailingZeros();
        String sign = f < 0 ? "-" : "";
        if (a >= 1e-6 && a < 1e21) return sign + bd.toPlainString();
        String digits = bd.unscaledValue().toString();
        int exp = digits.length() - 1 - bd.scale();
        String m = digits.length() == 1 ? digits : digits.charAt(0) + "." + digits.substring(1);
        return sign + m + "e" + (exp < 0 ? "-" : "+") + Math.abs(exp);
    }

    public static List<String> lowerAll(List<String> in) {
        List<String> out = new ArrayList<>(in.size());
        for (String s : in) out.add(s.toLowerCase(Locale.ROOT));
        return out;
    }

    public static Map<String, Object> mergeOverrides(Map<String, Object> measured, Map<String, Object> ov) {
        Map<String, Object> out = new LinkedHashMap<>(measured);
        out.putAll(ov);
        return out;
    }

    public static String errMsg(Throwable e) { return e == null || e.getMessage() == null ? "invalid" : e.getMessage(); }

    // ------------------------------------------------------------- hashes

    private static byte[] digest(String alg, byte[] b) {
        try {
            return MessageDigest.getInstance(alg).digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] sha256Sum(byte[] b) { return digest("SHA-256", b); }
    public static byte[] sha384Sum(byte[] b) { return digest("SHA-384", b); }
    public static byte[] sha512Sum(byte[] b) { return digest("SHA-512", b); }

    // ------------------------------------------------------------- X.509 text and PEM

    private static final Pattern PEM_CERT_BLOCK = Pattern.compile("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", Pattern.DOTALL);
    static final Pattern PEM_CERT_BODY = Pattern.compile("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);

    public static List<String> pemCertBlocks(String text) {
        List<String> out = new ArrayList<>();
        Matcher m = PEM_CERT_BLOCK.matcher(text);
        while (m.find()) out.add(m.group());
        return out;
    }

    public static String normSerial(String s) {
        String l = s.toLowerCase(Locale.ROOT);
        int i = 0;
        while (i < l.length() && l.charAt(i) == '0') i++;
        return l.substring(i);
    }

    /** Go base64.StdEncoding.DecodeString for input without line breaks: padded, standard alphabet. */
    static byte[] base64StdDecode(String s) {
        if (s.length() % 4 != 0) throw new AttestException("illegal base64 data");
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new AttestException("illegal base64 data");
        }
    }

    // ------------------------------------------------------------- elliptic curves (P-224 / P-256 / P-384 / P-521)

    private static final String[][] CURVES = {
        {"P-256", "secp256r1", "prime256v1"},
        {"P-384", "secp384r1", "secp384r1"},
        {"P-521", "secp521r1", "secp521r1"},
        {"P-224", "secp224r1", "secp224r1"},
    };

    private static final Map<String, ECParameterSpec> SPECS = new java.util.concurrent.ConcurrentHashMap<>();

    /** The JDK parameter spec of a curve by its NIST name (P-256, ...), or null when the JDK build lacks the curve. */
    static ECParameterSpec jdkSpec(String nist) {
        ECParameterSpec cached = SPECS.get(nist);
        if (cached != null) return cached;
        for (String[] c : CURVES) {
            if (!c[0].equals(nist)) continue;
            try {
                AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
                ap.init(new ECGenParameterSpec(c[1]));
                ECParameterSpec s = ap.getParameterSpec(ECParameterSpec.class);
                SPECS.put(nist, s);
                return s;
            } catch (java.security.GeneralSecurityException e) {
                return null;
            }
        }
        return null;
    }

    private static boolean sameSpec(ECParameterSpec a, ECParameterSpec b) {
        return a != null && b != null && a.getCurve().equals(b.getCurve()) && a.getGenerator().equals(b.getGenerator())
            && a.getOrder().equals(b.getOrder()) && a.getCofactor() == b.getCofactor();
    }

    /** The NIST name of a curve (P-256, ...) or "unknown". */
    public static String ecCurveName(ECParameterSpec spec) {
        for (String[] c : CURVES) if (sameSpec(spec, jdkSpec(c[0]))) return c[0];
        return "unknown";
    }

    public static String curveOpenSslName(ECParameterSpec spec) {
        String n = ecCurveName(spec);
        for (String[] c : CURVES) if (c[0].equals(n)) return c[2];
        return n;
    }

    private static ECDomainParameters bcDomain(String nist) {
        for (String[] c : CURVES) {
            if (!c[0].equals(nist)) continue;
            X9ECParameters x = ECNamedCurveTable.getByName(c[1]);
            return x == null ? null : new ECDomainParameters(x.getCurve(), x.getG(), x.getN(), x.getH());
        }
        return null;
    }

    /** True iff (x, y) is a point of the named curve (coordinates in range). */
    public static boolean isOnCurve(String nist, BigInteger x, BigInteger y) {
        ECDomainParameters d = bcDomain(nist);
        if (d == null) return false;
        try {
            return d.getCurve().validatePoint(x, y) != null;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** An on-curve EC public key from affine coordinates; null when off the curve or the curve is unsupported. */
    public static ECPublicKey ecKeyOf(String nist, BigInteger x, BigInteger y) {
        ECParameterSpec spec = jdkSpec(nist);
        if (spec == null || !isOnCurve(nist, x, y)) return null;
        try {
            return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
        } catch (java.security.GeneralSecurityException e) {
            return null;
        }
    }

    /** The uncompressed SEC1 point of an EC key on exactly the named curve (P-256 or P-384); throws AttestException. */
    public static byte[] ecPointOfKey(CertKey k, String curveName) {
        if (!"ec".equals(k.typ) || !(k.pub instanceof ECPublicKey)) throw new AttestException("public key is not EC (got " + k.typ + ")");
        ECPublicKey pk = (ECPublicKey) k.pub;
        int want = "P-256".equals(curveName) ? 32 : "P-384".equals(curveName) ? 48 : 0;
        String got = ecCurveName(pk.getParams());
        if (!got.equals(curveName)) throw new AttestException("public key is not on " + curveName + " (got " + got + ")");
        byte[] out = new byte[1 + 2 * want];
        out[0] = 0x04;
        fill(pk.getW().getAffineX(), out, 1, want);
        fill(pk.getW().getAffineY(), out, 1 + want, want);
        return out;
    }

    private static void fill(BigInteger v, byte[] dst, int off, int n) {
        byte[] b = v.toByteArray();
        int skip = b.length > n ? b.length - n : 0;
        System.arraycopy(b, skip, dst, off + n - (b.length - skip), b.length - skip);
    }

    /** Verifies a raw r||s signature (equal halves) over the digest (the digest is truncated to the group order like ECDSA does). */
    public static boolean verifyRawECDSA(ECPublicKey pub, byte[] digest, byte[] sig) {
        if (sig.length == 0 || sig.length % 2 != 0) return false;
        String nist = ecCurveName(pub.getParams());
        ECDomainParameters d = bcDomain(nist);
        if (d == null) return false;
        try {
            int h = sig.length / 2;
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig, 0, h));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, h, sig.length));
            org.bouncycastle.math.ec.ECPoint q = d.getCurve().validatePoint(pub.getW().getAffineX(), pub.getW().getAffineY());
            ECDSASigner signer = new ECDSASigner();
            signer.init(false, new ECPublicKeyParameters(q, d));
            return signer.verifySignature(digest, r, s);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** An on-curve public key from an uncompressed SEC1 point on the named curve; null for anything else. */
    public static ECPublicKey pointToKey(String nist, byte[] point) {
        ECParameterSpec spec = jdkSpec(nist);
        if (spec == null) return null;
        int size = (spec.getCurve().getField().getFieldSize() + 7) / 8;
        if (point.length != 1 + 2 * size || point[0] != 0x04) return null;
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(point, 1, 1 + size));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(point, 1 + size, point.length));
        return ecKeyOf(nist, x, y);
    }

    // ------------------------------------------------------------- certificate names (OpenSSL's multi-line rendering)

    private static final Map<String, String> DN_SHORT = new LinkedHashMap<>();
    static {
        String[][] t = {
            {"2.5.4.3", "CN"}, {"2.5.4.6", "C"}, {"2.5.4.7", "L"}, {"2.5.4.8", "ST"}, {"2.5.4.10", "O"}, {"2.5.4.11", "OU"},
            {"2.5.4.5", "serialNumber"}, {"2.5.4.9", "street"}, {"2.5.4.17", "postalCode"}, {"2.5.4.4", "SN"}, {"2.5.4.42", "GN"},
            {"2.5.4.12", "title"}, {"2.5.4.46", "dnQualifier"}, {"1.2.840.113549.1.9.1", "emailAddress"},
            {"0.9.2342.19200300.100.1.25", "DC"}, {"0.9.2342.19200300.100.1.1", "UID"},
        };
        for (String[] e : t) DN_SHORT.put(e[0], e[1]);
    }

    static String escapeDnValue(String s) {
        StringBuilder sb = new StringBuilder();
        int[] cps = s.codePoints().toArray();
        for (int i = 0; i < cps.length; i++) {
            int r = cps[i];
            if (r == ',' || r == '+' || r == '"' || r == '\\' || r == '<' || r == '>' || r == ';') {
                sb.append('\\').appendCodePoint(r);
            } else if ((i == 0 && (r == ' ' || r == '#')) || (i == cps.length - 1 && r == ' ')) {
                sb.append('\\').appendCodePoint(r);
            } else if (r < 0x20 || r == 0x7f) {
                sb.append(String.format("\\%02X", r));
            } else sb.appendCodePoint(r);
        }
        return sb.toString();
    }

    /** One attribute value as Go's asn1 decodes it into an interface (a string for the string types, "&lt;nil&gt;" otherwise); null on a malformed one. */
    private static String atvString(byte[] b, AttestDer.Tlv v) {
        byte[] c = Arrays.copyOfRange(b, v.start, v.end);
        switch (v.tag) {
            case 0x13: // PrintableString
                for (byte x : c) {
                    int ch = x & 0xff;
                    boolean ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || " '()+,-./:=?".indexOf(ch) >= 0;
                    if (!ok) return null;
                }
                return new String(c, StandardCharsets.ISO_8859_1);
            case 0x16: // IA5String
                for (byte x : c) if ((x & 0x80) != 0) return null;
                return new String(c, StandardCharsets.ISO_8859_1);
            case 0x12: // NumericString
                for (byte x : c) if (!((x >= '0' && x <= '9') || x == ' ')) return null;
                return new String(c, StandardCharsets.ISO_8859_1);
            case 0x14: // T61String
                return new String(c, StandardCharsets.ISO_8859_1);
            case 0x0c: // UTF8String
                try {
                    return StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(c)).toString();
                } catch (java.nio.charset.CharacterCodingException e) {
                    return null;
                }
            case 0x1e: // BMPString
                if (c.length % 2 != 0) return null;
                return new String(c, StandardCharsets.UTF_16BE);
            default:
                // shortcut: the other value types print as Go's "<nil>"/struct text there; no attestation chain uses them, upgrade if one does
                return "<nil>";
        }
    }

    /**
     * Renders a DER Name the way Node renders a certificate subject / issuer: one "KEY=value" per attribute, in encoded
     * order, joined by newlines ("" when the Name does not parse).
     */
    public static String nameText(byte[] raw) {
        try {
            AttestDer.Tlv seq = AttestDer.readTlvStrict(raw, 0, raw.length);
            if (seq.tag != 0x30 || seq.end != raw.length) return "";
            List<String> lines = new ArrayList<>();
            for (int p = seq.start; p < seq.end; ) {
                AttestDer.Tlv set = AttestDer.readTlvStrict(raw, p, seq.end);
                p = set.end;
                if (set.tag != 0x31) return "";
                List<String> parts = new ArrayList<>();
                for (int q = set.start; q < set.end; ) {
                    AttestDer.Tlv atv = AttestDer.readTlvStrict(raw, q, set.end);
                    q = atv.end;
                    if (atv.tag != 0x30) return "";
                    AttestDer.Tlv oid = AttestDer.readTlvStrict(raw, atv.start, atv.end);
                    AttestDer.Tlv val = AttestDer.readTlvStrict(raw, oid.end, atv.end);
                    if (val.end != atv.end) return "";
                    String key = AttestDer.oidToDotted(raw, oid);
                    String sn = DN_SHORT.get(key);
                    if (sn != null) key = sn;
                    String s = atvString(raw, val);
                    if (s == null) return "";
                    parts.add(key + "=" + escapeDnValue(s));
                }
                lines.add(String.join(" + ", parts));
            }
            return String.join("\n", lines);
        } catch (AttestException e) {
            return "";
        }
    }

    // ------------------------------------------------------------- Azure runtime-data binding

    /** The Azure runtime-data binding: the hash relation and user-data equality. The failure reason, or "" when the quote binds. */
    public static String checkAzureRuntimeDataBinding(byte[] reportData, byte[] runtimeData, AttestationBinding expected) {
        if (reportData.length != 64) return "report_data is not 64 bytes";
        for (int i = 32; i < 64; i++) if (reportData[i] != 0) return "report_data[32:64] is not zero (not an Azure runtime-data hash)";
        if (!Arrays.equals(sha256Sum(runtimeData), Arrays.copyOfRange(reportData, 0, 32))) {
            return "sha256(runtime data) does not equal the quote report_data";
        }
        Object parsed;
        try {
            parsed = jsonLenient(runtimeData);
        } catch (AttestException e) {
            return "runtime data is not valid JSON";
        }
        Map<String, Object> obj = asRec(parsed);
        if (obj == null) return "runtime data is not a JSON object";
        Object ud = obj.get("user-data");
        if (!(ud instanceof String) || ((String) ud).length() != 128 || !isHexChars((String) ud)) {
            return "runtime data carries no 64-byte hex user-data";
        }
        byte[] want;
        try {
            want = attestationBindingBytes(expected);
        } catch (AttestException e) {
            return "binding not constructible: " + e.getMessage();
        }
        if (!Arrays.equals(hexDecode((String) ud), want)) {
            return "runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)";
        }
        return "";
    }
}
