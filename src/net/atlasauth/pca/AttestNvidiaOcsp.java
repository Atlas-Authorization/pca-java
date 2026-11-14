package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * NVIDIA GPU-CC device-chain revocation through OCSP (RFC 6960): the offline-verifiable equivalent of NVIDIA's own check. For
 * each non-root certificate the supplied responses are verified (responseStatus, CertID, BasicOCSPResponse signature under the
 * issuer or a delegated responder certificate signed by the supplied chain, freshness) and the status must be GOOD where it is
 * required. Every time value in a response must be a well-formed DER time (no roll-over). Port of the Go attest_nvidia_ocsp.go.
 */
final class AttestNvidiaOcsp {
    private AttestNvidiaOcsp() {}

    static final String OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";
    static final long OCSP_DEFAULT_MAX_MS = 7L * 24 * 3600 * 1000;

    /** Signature algorithm OID -> {JCA hash name, "ec" | "rsa"}. */
    private static final Map<String, String[]> SIG_ALGS = new HashMap<>();
    /** CertID hash algorithm OID -> JCA hash name. */
    private static final Map<String, String> CERT_ID_HASHES = new HashMap<>();
    static {
        SIG_ALGS.put("1.2.840.10045.4.3.2", new String[] {"SHA-256", "ec"});
        SIG_ALGS.put("1.2.840.10045.4.3.3", new String[] {"SHA-384", "ec"});
        SIG_ALGS.put("1.2.840.10045.4.3.4", new String[] {"SHA-512", "ec"});
        SIG_ALGS.put("1.2.840.113549.1.1.11", new String[] {"SHA-256", "rsa"});
        SIG_ALGS.put("1.2.840.113549.1.1.12", new String[] {"SHA-384", "rsa"});
        SIG_ALGS.put("1.2.840.113549.1.1.13", new String[] {"SHA-512", "rsa"});
        CERT_ID_HASHES.put("1.3.14.3.2.26", "SHA-1");
        CERT_ID_HASHES.put("2.16.840.1.101.3.4.2.1", "SHA-256");
        CERT_ID_HASHES.put("2.16.840.1.101.3.4.2.2", "SHA-384");
        CERT_ID_HASHES.put("2.16.840.1.101.3.4.2.3", "SHA-512");
    }

    /** One element: tag, header offset, content range. */
    static final class Node {
        final int tag;
        final int hdr;
        final int start;
        final int end;

        Node(int tag, int hdr, int start, int end) {
            this.tag = tag;
            this.hdr = hdr;
            this.start = start;
            this.end = end;
        }

        boolean constructed() { return (tag & 0x20) != 0; }
    }

    static Node readNode(byte[] b, int off, int limit) {
        AttestDer.Tlv t;
        try {
            t = AttestDer.tlvAt(b, off, limit);
        } catch (AttestException | ArrayIndexOutOfBoundsException e) {
            throw new AttestException("not valid DER");
        }
        if ((t.tag & 0x1f) == 0x1f) throw new AttestException("multi-byte tags are not supported");
        return new Node(t.tag, off, t.start, t.end);
    }

    static List<Node> kids(byte[] b, Node n) {
        List<Node> out = new ArrayList<>();
        for (int p = n.start; p < n.end; ) {
            Node k = readNode(b, p, n.end);
            out.add(k);
            p = k.end;
        }
        return out;
    }

    /** kids, or null when the content does not parse (the Go "err != nil" branch). */
    private static List<Node> kidsOrNull(byte[] b, Node n) {
        try {
            return kids(b, n);
        } catch (AttestException e) {
            return null;
        }
    }

    static String oid(byte[] b, Node n) {
        if (n.tag != 0x06) throw new AttestException("expected an OBJECT IDENTIFIER");
        return AttestDer.oidToDotted(b, new AttestDer.Tlv(n.tag, n.start, n.end));
    }

    private static final Pattern REV_TIME = Pattern.compile("[0-9]{14}Z");
    private static final Pattern GEN_TIME = Pattern.compile("([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\\.([0-9]*[1-9]))?Z");
    private static final Pattern UTC_TIME = Pattern.compile("([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z");

    /** A DER time in range (no roll-over) as epoch ms, or null. */
    static Long timeMs(String text, boolean utc) {
        Matcher m = (utc ? UTC_TIME : GEN_TIME).matcher(text);
        if (!m.matches()) return null;
        int y = Integer.parseInt(m.group(1));
        if (utc) y += y < 50 ? 2000 : 1900;
        int mo = Integer.parseInt(m.group(2));
        int d = Integer.parseInt(m.group(3));
        int h = Integer.parseInt(m.group(4));
        int mi = Integer.parseInt(m.group(5));
        int s = Integer.parseInt(m.group(6));
        if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || s > 59) return null;
        if (d > YearMonth.of(y, mo).lengthOfMonth()) return null;
        long ms = LocalDateTime.of(y, mo, d, h, mi, s).toInstant(ZoneOffset.UTC).toEpochMilli();
        if (!utc && m.group(7) != null) ms += Integer.parseInt((m.group(7) + "000").substring(0, 3));
        return ms;
    }

    /** Every UTCTime / GeneralizedTime in the structure is a well-formed DER time. */
    static boolean timesWellFormed(byte[] b, Node n) {
        if (n.constructed()) {
            List<Node> ks = kidsOrNull(b, n);
            if (ks == null) return false;
            for (Node k : ks) if (!timesWellFormed(b, k)) return false;
            return true;
        }
        if (n.tag == 0x17 || n.tag == 0x18) return timeMs(text(b, n), n.tag == 0x17) != null;
        return true;
    }

    private static String text(byte[] b, Node n) { return new String(b, n.start, n.end - n.start, StandardCharsets.ISO_8859_1); }

    private static byte[] content(byte[] b, Node n) { return Arrays.copyOfRange(b, n.start, n.end); }

    static byte[] stripLeading0(byte[] b) {
        int i = 0;
        while (i < b.length - 1 && b[i] == 0) i++;
        return Arrays.copyOfRange(b, i, b.length);
    }

    /** The subjectPublicKey BIT STRING content of a certificate (without the unused-bits octet). */
    static byte[] spkiKeyBits(AttCert c) {
        AttestCert.Elem spki = AttestCert.readCertElem(c.rawSpki, 0, c.rawSpki.length, 0x30);
        List<AttestCert.Elem> ks = AttestCert.certKids(c.rawSpki, spki);
        if (ks.size() != 2) throw new AttestException("malformed SubjectPublicKeyInfo");
        return Arrays.copyOfRange(c.rawSpki, ks.get(1).start + 1, ks.get(1).end);
    }

    static byte[] hash(String alg, byte[] b) {
        try {
            return MessageDigest.getInstance(alg).digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static boolean sigOk(String alg, byte[] tbs, byte[] sig, CertKey k) {
        String[] a = SIG_ALGS.get(alg);
        if (a == null) return false;
        String jca = a[0].replace("-", "");
        try {
            Signature s;
            if (k.pub instanceof ECPublicKey) {
                if (!a[1].equals("ec")) return false;
                s = Signature.getInstance(jca + "withECDSA");
            } else if (k.pub instanceof RSAPublicKey) {
                if (!a[1].equals("rsa") || !k.typ.equals("rsa") || !CertKey.rsaKeyOk(k.pub)) return false; // a PKCS#1 signature under an rsa-pss key is refused
                s = Signature.getInstance(jca + "withRSA");
            } else {
                return false;
            }
            s.initVerify(k.pub);
            s.update(tbs);
            return s.verify(sig);
        } catch (java.security.GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    /** One response's outcome: ok with a status (good / revoked / unknown), or the failure reason. */
    static final class Result {
        final boolean ok;
        final String reason;
        final String status;

        Result(boolean ok, String reason, String status) {
            this.ok = ok;
            this.reason = reason;
            this.status = status;
        }
    }

    private static Result fail(String reason) { return new Result(false, reason, ""); }

    private static Result good(String status) { return new Result(true, "", status); }

    /** verifyNvidiaOcspResponse: one DER OCSPResponse for cert (issued by issuer); malformation is a failure, never a throw. */
    static Result verifyResponse(byte[] der, AttCert cert, AttCert issuer, List<AttCert> chain, long nowMs) {
        try {
            return verifyInner(der, cert, issuer, chain, nowMs);
        } catch (RuntimeException e) {
            return fail("OCSP response rejected: " + AttestCommon.errMsg(e));
        }
    }

    private static final class Single {
        Node status;
        long thisUpdate;
        long nextUpdate;
        boolean hasNext;
    }

    /** A GeneralizedTime inside the BasicOCSPResponse: timesWellFormed has already validated every one of them. */
    private static long timeOf(byte[] b, Node n) { return timeMs(text(b, n), false); }

    /** X509_check_issued: names, keyCertSign when the issuer has a keyUsage, and the subject's AKID against the issuer. */
    static boolean checkIssued(AttCert cand, AttCert issuer) {
        return Arrays.equals(cand.rawIssuer, issuer.rawSubject) && issuerLinkOk(cand, issuer);
    }

    /** X509_check_issued past the name comparison (Sigstore compares the names itself): both extension sets, keyUsage, AKID. */
    static boolean issuerLinkOk(AttCert cand, AttCert issuer) {
        try {
            AttestDer.ExtTable ce = AttestDer.parseCertExtensions(cand.raw), ie = AttestDer.parseCertExtensions(issuer.raw);
            checkExtensionShapes(ce);
            checkExtensionShapes(ie);
            AttestDer.readCertRoleInfo(cand.raw); // refuses a malformed basicConstraints or keyUsage
            AttestDer.CertRoleInfo role = AttestDer.readCertRoleInfo(issuer.raw);
            if (role.hasKeyUsage && !role.keyCertSign) return false;
            AttestDer.CertExt aki = ce.get("2.5.29.35");
            return aki == null || akidOk(aki.value, ie.get("2.5.29.14"), issuer);
        } catch (AttestException e) {
            return false;
        }
    }

    private static void need(boolean ok) {
        if (!ok) throw new AttestException("malformed extension");
    }

    private static List<Node> topKids(byte[] v) {
        Node top = readNode(v, 0, v.length);
        need(top.tag == 0x30);
        return kids(v, top);
    }

    /** {@code parts} carry only {@code tags}, each at most once and in that order. */
    private static void inOrder(List<Node> parts, int... tags) {
        int i = 0;
        for (Node k : parts) {
            while (i < tags.length && tags[i] != k.tag) i++;
            need(i < tags.length);
            i++;
        }
    }

    private static void oidOk(byte[] b, Node n) {
        need(n.tag == 0x06);
        AttestDer.oidToDotted(b, new AttestDer.Tlv(0x06, n.start, n.end));
    }

    /** A positive DER INTEGER: no redundant leading byte, top bit clear. */
    private static void positiveInt(byte[] b, Node e) {
        need(e.end > e.start && b[e.start] >= 0 && !AttestCert.nonMinimalInt(b, e.start, e.end));
    }

    /** The attributes of an RDN. Refused beyond OpenSSL: value types other than UTF8, Printable, T61 and IA5. */
    private static void rdnOk(byte[] b, Node rdn) {
        for (Node atv : kids(b, rdn)) {
            need(atv.tag == 0x30);
            List<Node> parts = kids(b, atv);
            need(parts.size() == 2);
            oidOk(b, parts.get(0));
            Node value = parts.get(1);
            need(value.tag == 0x0c || value.tag == 0x13 || value.tag == 0x14 || value.tag == 0x16);
            if (value.tag == 0x0c) {
                try {
                    java.nio.charset.StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(b, value.start, value.end - value.start));
                } catch (java.nio.charset.CharacterCodingException e) {
                    need(false);
                }
            }
        }
    }

    /** A GeneralName, fully decoded. shortcut: x400Address and ediPartyName are refused where Node decodes them; decode them if a PKI here ever sets one. */
    private static void generalName(byte[] b, Node n) {
        switch (n.tag) {
            case 0x81: case 0x82: case 0x86: case 0x87: return;
            case 0x88:
                AttestDer.oidToDotted(b, new AttestDer.Tlv(0x06, n.start, n.end));
                return;
            case 0xa0: {
                List<Node> k = kids(b, n);
                need(k.size() == 2 && k.get(1).tag == 0xa0 && kids(b, k.get(1)).size() == 1);
                oidOk(b, k.get(0));
                return;
            }
            case 0xa4: {
                Node name = readNode(b, n.start, n.end);
                need(name.tag == 0x30 && name.end == n.end);
                for (Node rdn : kids(b, name)) {
                    need(rdn.tag == 0x31);
                    rdnOk(b, rdn);
                }
                return;
            }
            default: need(false);
        }
    }

    static void generalNamesOk(byte[] v) {
        for (Node n : topKids(v)) generalName(v, n);
    }

    private static void nameConstraintsOk(byte[] v) {
        List<Node> lists = topKids(v);
        inOrder(lists, 0xa0, 0xa1);
        for (Node list : lists) {
            for (Node sub : kids(v, list)) {
                need(sub.tag == 0x30);
                List<Node> parts = kids(v, sub);
                need(!parts.isEmpty());
                generalName(v, parts.get(0));
                List<Node> bounds = parts.subList(1, parts.size());
                inOrder(bounds, 0x80, 0x81);
                for (Node x : bounds) positiveInt(v, x);
            }
        }
    }

    private static void distributionPointsOk(byte[] v) {
        for (Node dp : topKids(v)) {
            need(dp.tag == 0x30);
            List<Node> parts = kids(v, dp);
            inOrder(parts, 0xa0, 0x81, 0xa2);
            need(parts.stream().anyMatch(k -> k.tag != 0x81)); // as Node reads it: reasons alone or nothing at all does not decode
            for (Node k : parts) {
                if (k.tag == 0x81) {
                    need(k.end > k.start && (v[k.start] & 0xff) <= 7);
                } else if (k.tag == 0xa2) {
                    need(k.end > k.start);
                    for (Node n : kids(v, k)) generalName(v, n);
                } else {
                    List<Node> inner = kids(v, k);
                    need(inner.size() == 1);
                    if (inner.get(0).tag == 0xa0) for (Node n : kids(v, inner.get(0))) generalName(v, n);
                    else if (inner.get(0).tag == 0xa1) rdnOk(v, inner.get(0));
                    else need(false);
                }
            }
        }
    }

    /**
     * x509v3_cache_extensions: OpenSSL marks a certificate invalid when an extension it decodes is malformed, and checkIssued then refuses it.
     * basicConstraints and keyUsage are read by readCertRoleInfo. Refused beyond OpenSSL: a proxyCertInfo.
     */
    private static void checkExtensionShapes(AttestDer.ExtTable t) {
        for (String oid : t.oids) {
            byte[] v = t.get(oid).value;
            switch (oid) {
                case "2.5.29.14": need(readNode(v, 0, v.length).tag == 0x04); break;
                case "2.5.29.17": generalNamesOk(v); break;
                case "2.5.29.35": akidShapeOk(v); break;
                case "2.5.29.37": for (Node o : topKids(v)) oidOk(v, o); break;
                case "2.5.29.30": nameConstraintsOk(v); break;
                case "2.5.29.31": distributionPointsOk(v); break;
                case "1.3.6.1.5.5.7.1.14": need(false); break;
                default: break;
            }
        }
    }

    /** AuthorityKeyIdentifier: [0] keyid, [1] names, [2] serial, each optional and in that order; every name decodes; the serial is a minimal non-empty INTEGER. */
    private static void akidShapeOk(byte[] aki) {
        List<Node> parts = topKids(aki);
        inOrder(parts, 0x80, 0xa1, 0x82);
        for (Node t : parts) {
            if (t.tag == 0xa1) for (Node n : kids(aki, t)) generalName(aki, n);
            if (t.tag == 0x82) need(t.end > t.start && !AttestCert.nonMinimalInt(aki, t.start, t.end));
        }
    }

    private static boolean akidOk(byte[] aki, AttestDer.CertExt ski, AttCert issuer) {
        AttestDer.Tlv top = AttestDer.tlvAt(aki, 0);
        for (int p = top.start; p < top.end; ) {
            AttestDer.Tlv t = AttestDer.tlvAt(aki, p, top.end);
            byte[] body = Arrays.copyOfRange(aki, t.start, t.end);
            if (t.tag == 0x80 && ski != null) {
                AttestDer.Tlv id = AttestDer.tlvAt(ski.value, 0);
                if (!Arrays.equals(body, Arrays.copyOfRange(ski.value, id.start, id.end))) return false;
            } else if (t.tag == 0x82) {
                if (!Arrays.equals(body, issuer.serial)) return false;
            } else if (t.tag == 0xa1) {
                for (int q = 0; q < body.length; ) {
                    AttestDer.Tlv g = AttestDer.tlvAt(body, q, body.length);
                    if (g.tag == 0xa4) { // the first directoryName names the issuer's own issuer
                        if (!Arrays.equals(Arrays.copyOfRange(body, g.start, g.end), issuer.rawIssuer)) return false;
                        break;
                    }
                    q = g.end;
                }
            }
            p = t.end;
        }
        return true;
    }

    private static Result verifyInner(byte[] der, AttCert cert, AttCert issuer, List<AttCert> chain, long nowMs) {
        Node top;
        try {
            top = readNode(der, 0, der.length);
        } catch (AttestException e) {
            return fail("response is not valid DER");
        }
        if (top.end != der.length) return fail("trailing bytes after OCSPResponse");
        if (top.tag != 0x30) throw new AttestException("OCSPResponse is not a SEQUENCE");
        List<Node> tk = kidsOrNull(der, top);
        if (tk == null || tk.isEmpty() || tk.get(0).tag != 0x0a || tk.get(0).end - tk.get(0).start != 1) throw new AttestException("malformed OCSPResponse");
        int status = der[tk.get(0).start] & 0xff;
        if (status != 0) return fail("OCSP responseStatus is " + status + " (not successful)");
        if (tk.size() < 2 || tk.get(1).tag != 0xa0) return fail("successful response carries no responseBytes");
        List<Node> rbWrap = kidsOrNull(der, tk.get(1));
        if (rbWrap == null || rbWrap.size() != 1 || rbWrap.get(0).tag != 0x30) throw new AttestException("malformed responseBytes");
        List<Node> rb = kidsOrNull(der, rbWrap.get(0));
        if (rb == null || rb.size() != 2 || rb.get(1).tag != 0x04) throw new AttestException("malformed responseBytes");
        if (!oid(der, rb.get(0)).equals(OID_OCSP_BASIC)) return fail("responseType is not id-pkix-ocsp-basic");
        byte[] basic = content(der, rb.get(1));
        Node bn;
        try {
            bn = readNode(basic, 0, basic.length);
        } catch (AttestException e) {
            return fail("BasicOCSPResponse is not valid DER");
        }
        if (bn.tag != 0x30) throw new AttestException("BasicOCSPResponse is not a SEQUENCE");
        List<Node> bk = kidsOrNull(basic, bn);
        if (bk == null || bk.size() < 3 || bk.get(0).tag != 0x30 || bk.get(1).tag != 0x30 || bk.get(2).tag != 0x03) {
            throw new AttestException("malformed BasicOCSPResponse");
        }
        if (!timesWellFormed(basic, bn)) return fail("response carries a malformed (out-of-range) ASN.1 time");
        Node tbsNode = bk.get(0);
        byte[] tbsBytes = Arrays.copyOfRange(basic, tbsNode.hdr, tbsNode.end);
        // from here on every constructed element of basic parses (timesWellFormed walked it), so kids() cannot fail on one
        List<Node> algKids = kids(basic, bk.get(1));
        if (algKids.isEmpty()) throw new AttestException("malformed signatureAlgorithm");
        String sigAlg = oid(basic, algKids.get(0));
        if (!SIG_ALGS.containsKey(sigAlg)) return fail("unsupported OCSP signature algorithm " + sigAlg);
        if (bk.get(2).end - bk.get(2).start < 1) throw new AttestException("malformed signature");
        byte[] sig = Arrays.copyOfRange(basic, bk.get(2).start + 1, bk.get(2).end);

        // ResponseData: [0] version?, responderID, producedAt, responses, [1] extensions?
        List<Node> rd = kids(basic, tbsNode);
        int ri = 0;
        if (ri < rd.size() && rd.get(ri).tag == 0xa0) ri++;
        if (ri + 3 > rd.size()) throw new AttestException("malformed ResponseData");
        Node rid = rd.get(ri);
        Node produced = rd.get(ri + 1);
        Node responses = rd.get(ri + 2);
        if (produced.tag != 0x18 || responses.tag != 0x30 || (rid.tag != 0xa1 && rid.tag != 0xa2)) throw new AttestException("malformed ResponseData");
        long producedAt = timeOf(basic, produced);

        byte[] subjectSerial = stripLeading0(cert.serial);
        byte[] issuerKeyBits = spkiKeyBits(issuer);
        List<Single> matches = new ArrayList<>();
        for (Node s : kids(basic, responses)) {
            // a SingleResponse must be a SEQUENCE (a primitive one would hide its times from timesWellFormed)
            List<Node> sk = s.tag == 0x30 ? kids(basic, s) : null;
            if (sk == null || sk.size() < 3 || sk.get(0).tag != 0x30 || sk.get(2).tag != 0x18) throw new AttestException("malformed SingleResponse");
            // after thisUpdate only an optional [0] nextUpdate, then an optional [1]: anything else would hide a stale response
            int after = 3;
            if (after < sk.size() && sk.get(after).tag == 0xa0) {
                List<Node> nk = kids(basic, sk.get(after));
                if (nk.size() != 1 || nk.get(0).tag != 0x18) throw new AttestException("malformed SingleResponse");
                after++;
            }
            if (after < sk.size() && sk.get(after).tag == 0xa1) after++;
            if (after != sk.size()) throw new AttestException("malformed SingleResponse");
            List<Node> cid = kids(basic, sk.get(0));
            if (cid.size() != 4 || cid.get(0).tag != 0x30 || cid.get(1).tag != 0x04 || cid.get(2).tag != 0x04 || cid.get(3).tag != 0x02) {
                throw new AttestException("malformed CertID");
            }
            List<Node> hk = kids(basic, cid.get(0));
            if (hk.isEmpty()) throw new AttestException("malformed CertID hash algorithm");
            String h = CERT_ID_HASHES.get(oid(basic, hk.get(0)));
            if (h == null) continue;
            if (!Arrays.equals(stripLeading0(content(basic, cid.get(3))), subjectSerial)
                || !Arrays.equals(content(basic, cid.get(1)), hash(h, issuer.rawSubject))
                || !Arrays.equals(content(basic, cid.get(2)), hash(h, issuerKeyBits))) {
                continue;
            }
            Single m = new Single();
            m.status = sk.get(1);
            m.thisUpdate = timeOf(basic, sk.get(2));
            if (sk.size() > 3 && sk.get(3).tag == 0xa0) {
                m.nextUpdate = timeOf(basic, kids(basic, sk.get(3)).get(0));
                m.hasNext = true;
            }
            matches.add(m);
        }
        if (matches.isEmpty()) return fail("no SingleResponse matches the certificate (serial / issuer hashes differ)");
        if (matches.size() > 1) return fail("ambiguous: multiple SingleResponses match the certificate");
        Single one = matches.get(0);

        // responder authentication
        CertKey issuerKey = AttestCert.keyOfCert(issuer);
        List<Node> ridInner = kids(basic, rid);
        if (ridInner.size() != 1) throw new AttestException("malformed responderID");
        Node rIn = ridInner.get(0);
        boolean isIssuerId = matchesResponder(basic, rid, rIn, issuer);
        if (!(isIssuerId && sigOk(sigAlg, tbsBytes, sig, issuerKey))) {
            List<AttCert> embedded = new ArrayList<>();
            if (bk.size() > 3 && bk.get(3).tag == 0xa0) {
                List<Node> wrap = kids(basic, bk.get(3));
                if (wrap.size() == 1) {
                    List<Node> cs = kidsOrNull(basic, wrap.get(0));
                    if (cs != null) {
                        for (Node c : cs) embedded.add(AttestCert.parseCertDer(Arrays.copyOfRange(basic, c.hdr, c.end))); // a malformed one refuses the response
                    }
                }
            }
            String why = "no embedded responder certificate verifies the response";
            AttCert found = null;
            for (AttCert cand : embedded) {
                if (!matchesResponder(basic, rid, rIn, cand)) {
                    why = "embedded certificates do not match the responderID";
                    continue;
                }
                if (!cand.hasOcspSigningEku()) {
                    why = "delegated responder certificate lacks the id-kp-OCSPSigning EKU";
                    continue;
                }
                AttestDer.DerInstant[] v = AttestDer.derValidity(cand.raw);
                if (!v[0].ok || !v[1].ok || !(v[0].ms <= nowMs && nowMs <= v[1].ms)) {
                    why = "delegated responder certificate is outside its validity window";
                    continue;
                }
                List<AttCert> signers = new ArrayList<>();
                signers.add(issuer);
                for (int i = 0; i < chain.size(); i++) {
                    if (Arrays.equals(chain.get(i).raw, issuer.raw)) {
                        signers = chain.subList(i, chain.size());
                        break;
                    }
                }
                boolean okSigner = false;
                for (AttCert s : signers) if (checkIssued(cand, s) && AttestCert.certSigOkBy(cand, s)) okSigner = true;
                if (!okSigner) {
                    why = "delegated responder certificate is not signed by the supplied NVIDIA chain";
                    continue;
                }
                CertKey ck;
                try {
                    ck = AttestCert.keyOfCert(cand);
                } catch (AttestException e) {
                    ck = null;
                }
                if (ck == null || !sigOk(sigAlg, tbsBytes, sig, ck)) {
                    why = "OCSP response signature does not verify under the delegated responder key";
                    continue;
                }
                found = cand;
                break;
            }
            if (found == null) {
                if (isIssuerId) return fail("OCSP response signature does not verify under the issuer key");
                return fail(why);
            }
        }

        // freshness
        if (one.thisUpdate > nowMs) return fail("response thisUpdate is in the future");
        if (producedAt > nowMs) return fail("response producedAt is in the future");
        if (one.hasNext) {
            if (one.nextUpdate < one.thisUpdate) return fail("response nextUpdate is invalid");
            if (nowMs > one.nextUpdate) return fail("response is stale (past nextUpdate)");
        }
        if (nowMs - one.thisUpdate > OCSP_DEFAULT_MAX_MS) return fail("response is older than the maximum accepted age");

        // certStatus: CHOICE [0] good, [1] revoked, [2] unknown
        Node st = one.status;
        if ((st.tag & 0xc0) != 0x80) return fail("malformed certStatus");
        // exact tags: a constructed [0] or [2] must not read as good or unknown, nor a primitive [1] as revoked
        if (st.tag == 0x80) return good("good");
        if (st.tag == 0x82) return good("unknown");
        if (st.tag == 0xa1) {
            List<Node> items = kidsOrNull(basic, st);
            if (items == null || items.isEmpty() || !REV_TIME.matcher(text(basic, items.get(0))).matches()) return fail("malformed revoked certStatus");
            return good("revoked");
        }
        return fail((st.tag & 0x1f) <= 2 ? "malformed certStatus" : "unrecognised certStatus");
    }

    private static boolean matchesResponder(byte[] basic, Node rid, Node rIn, AttCert c) {
        // byName: the whole element (tag included) must equal the certificate's subject Name SEQUENCE
        if (rid.tag == 0xa1) return Arrays.equals(Arrays.copyOfRange(basic, rIn.hdr, rIn.end), c.rawSubject);
        // c is the issuer (its SPKI already read above) or a parsed certificate (two-element SPKI): this cannot throw
        return rIn.tag == 0x04 && Arrays.equals(content(basic, rIn), hash("SHA-1", spkiKeyBits(c)));
    }

    /**
     * checkNvidiaChainOcsp: every response must verify for exactly one chain certificate, any REVOKED fails, and every
     * certificate that advertises an OCSP responder must have a GOOD response. "" when it holds.
     */
    static String checkChainOcsp(List<AttCert> chain, List<byte[]> responses, long nowMs) {
        if (chain.size() < 2) return "chain too short for OCSP";
        if (responses.isEmpty()) return "no OCSP responses supplied";
        int last = chain.size() - 1;
        String[] statuses = new String[last];
        Arrays.fill(statuses, "absent");
        for (int ri = 0; ri < responses.size(); ri++) {
            boolean matched = false;
            String lastReason = "matches no chain certificate";
            for (int i = 0; i < last; i++) {
                Result r = verifyResponse(responses.get(ri), chain.get(i), chain.get(i + 1), chain, nowMs);
                if (!r.ok) {
                    if (!r.reason.startsWith("no SingleResponse matches")) {
                        return "OCSP response #" + ri + " for '" + AttestNvidia.subjectLine(chain.get(i)) + "' rejected: " + r.reason;
                    }
                    lastReason = r.reason;
                    continue;
                }
                if (matched) return "OCSP response #" + ri + " matches more than one chain certificate";
                matched = true;
                if (!statuses[i].equals("absent")) return "duplicate OCSP responses for chain certificate #" + i;
                statuses[i] = r.status;
                if (r.status.equals("revoked")) return "chain certificate '" + AttestNvidia.subjectLine(chain.get(i)) + "' is revoked (OCSP)";
            }
            if (!matched) return "OCSP response #" + ri + " rejected: " + lastReason;
        }
        for (int i = 0; i < last; i++) {
            // a certificate that advertises an OCSP responder requires a GOOD response
            if (!chain.get(i).ocspServers().isEmpty() && !statuses[i].equals("good")) {
                return "no GOOD OCSP response for required certificate '" + AttestNvidia.subjectLine(chain.get(i)) + "' (status: " + statuses[i] + ")";
            }
        }
        return "";
    }
}
