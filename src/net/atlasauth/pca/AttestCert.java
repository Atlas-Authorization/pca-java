package net.atlasauth.pca;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;

/**
 * Certificates as the reference's X.509 engine (OpenSSL through node:crypto) reads them. A certificate is parsed with the
 * structure checks of the OpenSSL template decoder (nothing more); the strict rules are applied afterwards by the readers
 * of {@link AttestDer}; the JDK is used only for public keys and signature verification. Port of the Go attest_cert.go.
 */
public final class AttestCert {
    private AttestCert() {}

    static final String OSSL_WRONG_TAG = "error:068000A8:asn1 encoding routines::wrong tag";
    static final String OSSL_NESTED = "error:0688010A:asn1 encoding routines::nested asn1 error";
    static final String OSSL_BITS = "error:0680007D:asn1 encoding routines::invalid bit string bits left";
    static final String OSSL_OBJECT = "error:0688010A:asn1 encoding routines::invalid object encoding";
    static final String OSSL_UNSUPPORTED = "error:1E08010C:DECODER routines::unsupported";

    /** An element with its header offset: tag, header start, content range. */
    static final class Elem {
        final int tag;
        final int hdr;
        final int start;
        final int end;

        Elem(int tag, int hdr, int start, int end) {
            this.tag = tag;
            this.hdr = hdr;
            this.start = start;
            this.end = end;
        }
    }

    /** Reads one element at off inside limit; tag 0 accepts any tag. */
    static Elem readCertElem(byte[] b, int off, int limit, int tag) {
        if (off >= limit) throw new AttestException("error:0680007B:asn1 encoding routines::not enough data");
        AttestDer.Tlv t;
        try {
            t = AttestDer.tlvAt(b, off, limit);
        } catch (AttestException e) {
            throw new AttestException(OSSL_NESTED);
        }
        if (tag != 0 && t.tag != tag) throw new AttestException(OSSL_WRONG_TAG);
        return new Elem(t.tag, off, t.start, t.end);
    }

    static List<Elem> certKids(byte[] b, Elem e) {
        List<Elem> out = new ArrayList<>();
        for (int p = e.start; p < e.end; ) {
            Elem k = readCertElem(b, p, e.end, 0);
            out.add(k);
            p = k.end;
        }
        return out;
    }

    private static AttestDer.Tlv tlv(Elem e) { return new AttestDer.Tlv(e.tag, e.start, e.end); }

    /** The OpenSSL object-identifier content check: not empty, no arc starting with 0x80, no dangling continuation. */
    static boolean validOid(byte[] b, Elem e) {
        if (e.tag != 0x06 || e.end <= e.start || (b[e.end - 1] & 0x80) != 0) return false;
        for (int i = e.start; i < e.end; i++) {
            if ((b[i] & 0xff) == 0x80 && (i == e.start || (b[i - 1] & 0x80) == 0)) return false;
        }
        return true;
    }

    /** An AlgorithmIdentifier: the dotted OID and the parameters element with its header (null when absent). */
    static final class AlgId {
        final String oid;
        final byte[] params;

        AlgId(String oid, byte[] params) {
            this.oid = oid;
            this.params = params;
        }
    }

    static AlgId algId(byte[] b, Elem e) {
        List<Elem> kids = certKids(b, e);
        if (kids.isEmpty() || kids.size() > 2 || !validOid(b, kids.get(0))) throw new AttestException(OSSL_NESTED);
        String dotted;
        try {
            dotted = AttestDer.oidToDotted(b, tlv(kids.get(0)));
        } catch (AttestException x) {
            throw new AttestException(OSSL_OBJECT);
        }
        byte[] params = null;
        if (kids.size() == 2) params = Arrays.copyOfRange(b, kids.get(1).hdr, kids.get(1).end);
        return new AlgId(dotted, params);
    }

    static void checkBitString(byte[] b, Elem e) {
        if (e.tag != 0x03 || e.end - e.start < 1) throw new AttestException(OSSL_WRONG_TAG);
        if ((b[e.start] & 0xff) > 7) throw new AttestException(OSSL_BITS);
    }

    private static final Set<Integer> NAME_VALUE_TAGS = new HashSet<>(Arrays.asList(0x0c, 0x12, 0x13, 0x14, 0x16, 0x1c, 0x1e, 0x03, 0x30));

    /** Validates a Name: SEQUENCE OF SET OF SEQUENCE { OID, string }. */
    static void checkName(byte[] b, Elem e) {
        for (Elem rdn : certKids(b, e)) {
            if (rdn.tag != 0x31) throw new AttestException(OSSL_WRONG_TAG);
            for (Elem atv : certKids(b, rdn)) {
                if (atv.tag != 0x30) throw new AttestException(OSSL_WRONG_TAG);
                List<Elem> kv = certKids(b, atv);
                if (kv.size() != 2 || !validOid(b, kv.get(0)) || !NAME_VALUE_TAGS.contains(kv.get(1).tag)) throw new AttestException(OSSL_NESTED);
            }
        }
    }

    private static byte[] slice(byte[] b, int from, int to) { return Arrays.copyOfRange(b, from, to); }

    /** Parses a DER certificate like d2i_X509: its structure is checked, trailing bytes after it are ignored. */
    public static AttCert parseCertDer(byte[] der) {
        Elem outer = readCertElem(der, 0, der.length, 0x30);
        Elem tbs = readCertElem(der, outer.start, outer.end, 0x30);
        Elem alg = readCertElem(der, tbs.end, outer.end, 0x30);
        Elem sig = readCertElem(der, alg.end, outer.end, 0x03);
        if (sig.end != outer.end) throw new AttestException(OSSL_NESTED);
        checkBitString(der, sig);
        AttCert c = new AttCert();
        c.rawTbs = slice(der, tbs.hdr, tbs.end);
        c.signature = slice(der, sig.start + 1, sig.end);
        AlgId sa = algId(der, alg);
        c.sigOid = sa.oid;
        c.sigParams = sa.params;

        int p = tbs.start;
        if (p < tbs.end && (der[p] & 0xff) == 0xa0) {
            Elem v = readCertElem(der, p, tbs.end, 0xa0);
            Elem inner = readCertElem(der, v.start, v.end, 0x02);
            if (inner.end != v.end) throw new AttestException(OSSL_NESTED);
            p = v.end;
        }
        Elem serial = readCertElem(der, p, tbs.end, 0x02);
        if (serial.end == serial.start) throw new AttestException("error:0688010A:asn1 encoding routines::illegal zero content");
        c.serial = slice(der, serial.start, serial.end);
        p = serial.end;
        Elem inner = readCertElem(der, p, tbs.end, 0x30); // signature algorithm
        algId(der, inner);
        p = inner.end;
        Elem issuer = readCertElem(der, p, tbs.end, 0x30);
        checkName(der, issuer);
        c.rawIssuer = slice(der, issuer.hdr, issuer.end);
        p = issuer.end;
        Elem validity = readCertElem(der, p, tbs.end, 0x30);
        List<Elem> times = certKids(der, validity);
        if (times.size() != 2 || (times.get(0).tag != 0x17 && times.get(0).tag != 0x18) || (times.get(1).tag != 0x17 && times.get(1).tag != 0x18)) {
            throw new AttestException(OSSL_NESTED);
        }
        p = validity.end;
        Elem subject = readCertElem(der, p, tbs.end, 0x30);
        checkName(der, subject);
        c.rawSubject = slice(der, subject.hdr, subject.end);
        p = subject.end;
        Elem spki = readCertElem(der, p, tbs.end, 0x30);
        List<Elem> sk = certKids(der, spki);
        if (sk.size() != 2 || sk.get(0).tag != 0x30) throw new AttestException(OSSL_NESTED);
        algId(der, sk.get(0));
        checkBitString(der, sk.get(1));
        c.rawSpki = slice(der, spki.hdr, spki.end);
        p = spki.end;
        for (int uid : new int[] {0x81, 0x82}) {
            if (p < tbs.end && (der[p] & 0xff) == uid) {
                Elem u = readCertElem(der, p, tbs.end, uid);
                p = u.end;
            }
        }
        if (p < tbs.end && (der[p] & 0xff) == 0xa3) {
            Elem wrap = readCertElem(der, p, tbs.end, 0xa3);
            Elem seq = readCertElem(der, wrap.start, wrap.end, 0x30);
            if (seq.end != wrap.end) throw new AttestException(OSSL_NESTED);
            for (Elem e : certKids(der, seq)) {
                if (e.tag != 0x30) throw new AttestException(OSSL_WRONG_TAG);
                List<Elem> parts = certKids(der, e);
                if (parts.size() < 2 || parts.size() > 3 || !validOid(der, parts.get(0))) throw new AttestException(OSSL_NESTED);
                AttCert.LenientExt le = new AttCert.LenientExt();
                try {
                    le.oid = AttestDer.oidToDotted(der, tlv(parts.get(0)));
                } catch (AttestException x) {
                    throw new AttestException(OSSL_OBJECT);
                }
                int next = 1;
                if (parts.size() == 3) {
                    if (parts.get(1).tag != 0x01 || parts.get(1).end - parts.get(1).start != 1) throw new AttestException(OSSL_NESTED);
                    le.critical = der[parts.get(1).start] != 0;
                    next = 2;
                }
                if (parts.get(next).tag != 0x04) throw new AttestException(OSSL_WRONG_TAG);
                le.value = slice(der, parts.get(next).start, parts.get(next).end);
                c.exts.add(le);
            }
            p = wrap.end;
        }
        if (p != tbs.end) throw new AttestException(OSSL_NESTED);

        // the certificate as DER: the outer length in its minimal form, the content as supplied
        byte[] content = slice(der, outer.start, outer.end);
        byte[] hdr = derLengthHeader(0x30, content.length);
        c.raw = new byte[hdr.length + content.length];
        System.arraycopy(hdr, 0, c.raw, 0, hdr.length);
        System.arraycopy(content, 0, c.raw, hdr.length, content.length);
        return c;
    }

    static byte[] derLengthHeader(int tag, int n) {
        if (n < 0x80) return new byte[] {(byte) tag, (byte) n};
        if (n < 0x100) return new byte[] {(byte) tag, (byte) 0x81, (byte) n};
        if (n < 0x10000) return new byte[] {(byte) tag, (byte) 0x82, (byte) (n >> 8), (byte) n};
        if (n < 0x1000000) return new byte[] {(byte) tag, (byte) 0x83, (byte) (n >> 16), (byte) (n >> 8), (byte) n};
        return new byte[] {(byte) tag, (byte) 0x84, (byte) (n >> 24), (byte) (n >> 16), (byte) (n >> 8), (byte) n};
    }

    /** Parses the first certificate block of a PEM text (PEM_read_bio_X509_AUX: bytes after the certificate inside the block are an error). */
    public static AttCert certFromPem(String text) {
        Matcher m = AttestCommon.PEM_CERT_BODY.matcher(text);
        if (!m.find()) throw new AttestException("error:0480006C:PEM routines::no start line");
        String raw = m.group(1);
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < raw.length(); i++) {
            char ch = raw.charAt(i);
            if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') body.append(ch);
        }
        byte[] der;
        try {
            der = AttestCommon.base64StdDecode(body.toString());
        } catch (AttestException e) {
            throw new AttestException("error:1E08010C:DECODER routines::unsupported");
        }
        AttCert c = parseCertDer(der);
        Elem outer = readCertElem(der, 0, der.length, 0x30);
        if (outer.end != der.length) throw new AttestException(OSSL_NESTED);
        return c;
    }

    // ------------------------------------------------------------- keys and signatures

    static final String OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
    static final String OID_RSA_PSS = "1.2.840.113549.1.1.10";
    static final String OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
    static final String OID_ED25519 = "1.3.101.112";

    /** x509.ParsePKCS1PublicKey: RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }, strict DER, positive values. */
    private static RSAPublicKey parsePkcs1Public(byte[] b) {
        try {
            AttestDer.Tlv seq = AttestDer.readTlvStrict(b, 0, b.length);
            if (seq.tag != 0x30 || seq.end != b.length) throw new AttestException(OSSL_UNSUPPORTED);
            AttestDer.Tlv n = AttestDer.readTlvStrict(b, seq.start, seq.end);
            AttestDer.Tlv e = AttestDer.readTlvStrict(b, n.end, seq.end);
            if (n.tag != 0x02 || e.tag != 0x02 || e.end != seq.end) throw new AttestException(OSSL_UNSUPPORTED);
            BigInteger nv = derInt(b, n);
            BigInteger ev = derInt(b, e);
            if (nv.signum() <= 0 || ev.signum() <= 0 || ev.bitLength() > 63) throw new AttestException(OSSL_UNSUPPORTED);
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(nv, ev));
        } catch (java.security.GeneralSecurityException | RuntimeException x) {
            throw new AttestException(OSSL_UNSUPPORTED);
        }
    }

    /** A minimally encoded DER INTEGER (no redundant leading 0x00 / 0xff). */
    private static BigInteger derInt(byte[] b, AttestDer.Tlv t) {
        int len = t.end - t.start;
        if (len == 0) throw new AttestException(OSSL_UNSUPPORTED);
        if (len > 1) {
            int a = b[t.start] & 0xff;
            int c = b[t.start + 1] & 0xff;
            if ((a == 0 && (c & 0x80) == 0) || (a == 0xff && (c & 0x80) != 0)) throw new AttestException(OSSL_UNSUPPORTED);
        }
        return new BigInteger(Arrays.copyOfRange(b, t.start, t.end));
    }

    /**
     * The certificate's subject public key. An RSASSA-PSS key is read from its SubjectPublicKeyInfo as the RSAPublicKey it
     * carries (typed "rsa-pss"). AttestException (reference wording) when the key cannot be read.
     */
    public static CertKey keyOfCert(AttCert c) {
        Elem spki = readCertElem(c.rawSpki, 0, c.rawSpki.length, 0x30);
        List<Elem> kids = certKids(c.rawSpki, spki);
        if (kids.size() != 2) throw new AttestException(OSSL_NESTED);
        AlgId alg = algId(c.rawSpki, kids.get(0));
        byte[] bits = Arrays.copyOfRange(c.rawSpki, kids.get(1).start + 1, kids.get(1).end);
        if (alg.oid.equals(OID_RSA_ENCRYPTION) || alg.oid.equals(OID_RSA_PSS)) {
            CertKey k = CertKey.of(parsePkcs1Public(bits), c.rawSpki);
            return alg.oid.equals(OID_RSA_PSS) ? k.withType("rsa-pss") : k;
        }
        if (alg.oid.equals(OID_EC_PUBLIC_KEY) || alg.oid.equals(OID_ED25519)) {
            try {
                PublicKey pub = KeyFactory.getInstance(alg.oid.equals(OID_ED25519) ? "Ed25519" : "EC").generatePublic(new X509EncodedKeySpec(c.rawSpki));
                CertKey k = CertKey.of(pub, c.rawSpki);
                if (k.typ.equals("ec")) {
                    java.security.interfaces.ECPublicKey ek = (java.security.interfaces.ECPublicKey) pub;
                    // the JDK does not check the point is on the curve; the reference (and Go) refuse one that is not
                    if (!AttestCommon.isOnCurve(AttestCommon.ecCurveName(ek.getParams()), ek.getW().getAffineX(), ek.getW().getAffineY())) {
                        throw new AttestException(OSSL_UNSUPPORTED);
                    }
                }
                return k;
            } catch (java.security.GeneralSecurityException | RuntimeException x) {
                throw new AttestException(OSSL_UNSUPPORTED);
            }
        }
        throw new AttestException(OSSL_UNSUPPORTED);
    }

    private static final Map<String, String> SIG_HASHES = new HashMap<>();
    private static final Map<String, String> HASH_OIDS = new HashMap<>();
    static {
        SIG_HASHES.put("1.2.840.10045.4.3.2", "SHA256");
        SIG_HASHES.put("1.2.840.10045.4.3.3", "SHA384");
        SIG_HASHES.put("1.2.840.10045.4.3.4", "SHA512");
        SIG_HASHES.put("1.2.840.113549.1.1.11", "SHA256");
        SIG_HASHES.put("1.2.840.113549.1.1.12", "SHA384");
        SIG_HASHES.put("1.2.840.113549.1.1.13", "SHA512");
        HASH_OIDS.put("2.16.840.1.101.3.4.2.1", "SHA-256");
        HASH_OIDS.put("2.16.840.1.101.3.4.2.2", "SHA-384");
        HASH_OIDS.put("2.16.840.1.101.3.4.2.3", "SHA-512");
        HASH_OIDS.put("1.3.14.3.2.26", "SHA-1");
    }

    /** RSASSA-PSS-params: the hash, the salt length, and whether the profile is one this verifier checks (MGF1 over the same hash, trailer field 1). */
    static final class PssParams {
        String hash = "SHA-1";
        int salt = 20;
        boolean ok = true;
    }

    static PssParams pssParams(byte[] raw) {
        PssParams out = new PssParams();
        if (raw == null || raw.length == 0) return out;
        PssParams bad = new PssParams();
        bad.ok = false;
        try {
            Elem seq = readCertElem(raw, 0, raw.length, 0x30);
            String h = "SHA-1";
            int salt = 20;
            String mgfHash = "SHA-1";
            for (Elem k : certKids(raw, seq)) {
                List<Elem> inner = certKids(raw, k);
                if (inner.size() != 1) return bad;
                switch (k.tag) {
                    case 0xa0: {
                        String hh = HASH_OIDS.get(algId(raw, inner.get(0)).oid);
                        if (hh == null) return bad;
                        h = hh;
                        break;
                    }
                    case 0xa1: {
                        AlgId mgf = algId(raw, inner.get(0));
                        if (!mgf.oid.equals("1.2.840.113549.1.1.8") || mgf.params == null) return bad;
                        Elem pe = readCertElem(mgf.params, 0, mgf.params.length, 0x30);
                        String mh = HASH_OIDS.get(algId(mgf.params, pe).oid);
                        if (mh == null) return bad;
                        mgfHash = mh;
                        break;
                    }
                    case 0xa2:
                    case 0xa3: {
                        if (inner.get(0).tag != 0x02) return bad;
                        BigInteger v = new BigInteger(1, Arrays.copyOfRange(raw, inner.get(0).start, inner.get(0).end));
                        if (v.bitLength() > 63 || v.longValue() > (1 << 20)) return bad;
                        if (k.tag == 0xa2) salt = (int) v.longValue();
                        else if (v.longValue() != 1) return bad;
                        break;
                    }
                    default:
                        return bad;
                }
            }
            out.hash = h;
            out.salt = salt;
            out.ok = mgfHash.equals(h);
            return out;
        } catch (AttestException e) {
            return bad;
        }
    }

    /** X509Certificate.verify(publicKey): the certificate's signature under the key (no name or role checks). */
    public static boolean certSigOk(AttCert child, CertKey k) {
        try {
            if (child.sigOid.equals(OID_ED25519)) {
                if (!k.typ.equals("ed25519")) return false;
                Signature s = Signature.getInstance("Ed25519");
                s.initVerify(k.pub);
                s.update(child.rawTbs);
                return s.verify(child.signature);
            }
            if (child.sigOid.equals(OID_RSA_PSS)) {
                if (!(k.pub instanceof RSAPublicKey)) return false;
                PssParams pp = pssParams(child.sigParams);
                if (!pp.ok) return false;
                Signature s = Signature.getInstance("RSASSA-PSS");
                s.setParameter(new PSSParameterSpec(pp.hash, "MGF1", new MGF1ParameterSpec(pp.hash), pp.salt, 1));
                s.initVerify(k.pub);
                s.update(child.rawTbs);
                return s.verify(child.signature);
            }
            String h = SIG_HASHES.get(child.sigOid);
            if (h == null) return false;
            if (k.pub instanceof java.security.interfaces.ECPublicKey) {
                if (!child.sigOid.startsWith("1.2.840.10045.4.3.")) return false;
                Signature s = Signature.getInstance(h + "withECDSA");
                s.initVerify(k.pub);
                s.update(child.rawTbs);
                return s.verify(child.signature);
            }
            if (k.pub instanceof RSAPublicKey) {
                if (!child.sigOid.startsWith("1.2.840.113549.1.1.")) return false;
                Signature s = Signature.getInstance(h + "withRSA");
                s.initVerify(k.pub);
                s.update(child.rawTbs);
                return s.verify(child.signature);
            }
            return false;
        } catch (java.security.GeneralSecurityException | RuntimeException x) {
            return false;
        }
    }

    /** {@link #certSigOk} under the subject key of parent (false when that key cannot be read). */
    public static boolean certSigOkBy(AttCert child, AttCert parent) {
        CertKey k;
        try {
            k = keyOfCert(parent);
        } catch (AttestException e) {
            return false;
        }
        return certSigOk(child, k);
    }
}
