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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
                if (!a[1].equals("rsa")) return false;
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

    private static long timeOrZero(byte[] b, Node n) {
        Long t = timeMs(text(b, n), false);
        return t == null ? 0 : t;
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
        List<Node> algKids = kidsOrNull(basic, bk.get(1));
        if (algKids == null || algKids.isEmpty()) throw new AttestException("malformed signatureAlgorithm");
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
        long producedAt = timeOrZero(basic, produced);

        byte[] subjectSerial = stripLeading0(cert.serial);
        byte[] issuerKeyBits = spkiKeyBits(issuer);
        List<Single> matches = new ArrayList<>();
        for (Node s : kids(basic, responses)) {
            List<Node> sk = kidsOrNull(basic, s);
            if (sk == null || sk.size() < 3 || sk.get(0).tag != 0x30 || sk.get(2).tag != 0x18) throw new AttestException("malformed SingleResponse");
            List<Node> cid = kidsOrNull(basic, sk.get(0));
            if (cid == null || cid.size() != 4 || cid.get(0).tag != 0x30 || cid.get(1).tag != 0x04 || cid.get(2).tag != 0x04 || cid.get(3).tag != 0x02) {
                throw new AttestException("malformed CertID");
            }
            List<Node> hk = kidsOrNull(basic, cid.get(0));
            if (hk == null || hk.isEmpty()) throw new AttestException("malformed CertID hash algorithm");
            String h = CERT_ID_HASHES.get(oid(basic, hk.get(0)));
            if (h == null) continue;
            if (!Arrays.equals(stripLeading0(content(basic, cid.get(3))), subjectSerial)
                || !Arrays.equals(content(basic, cid.get(1)), hash(h, issuer.rawSubject))
                || !Arrays.equals(content(basic, cid.get(2)), hash(h, issuerKeyBits))) {
                continue;
            }
            Single m = new Single();
            m.status = sk.get(1);
            m.thisUpdate = timeOrZero(basic, sk.get(2));
            if (sk.size() > 3 && sk.get(3).tag == 0xa0) {
                List<Node> nk = kidsOrNull(basic, sk.get(3));
                if (nk != null && nk.size() == 1 && nk.get(0).tag == 0x18) {
                    m.nextUpdate = timeOrZero(basic, nk.get(0));
                    m.hasNext = true;
                }
            }
            matches.add(m);
        }
        if (matches.isEmpty()) return fail("no SingleResponse matches the certificate (serial / issuer hashes differ)");
        if (matches.size() > 1) return fail("ambiguous: multiple SingleResponses match the certificate");
        Single one = matches.get(0);

        // responder authentication
        CertKey issuerKey = AttestCert.keyOfCert(issuer);
        List<Node> ridInner = kidsOrNull(basic, rid);
        if (ridInner == null || ridInner.size() != 1) throw new AttestException("malformed responderID");
        Node rIn = ridInner.get(0);
        boolean isIssuerId = matchesResponder(basic, rid, rIn, issuer);
        if (!(isIssuerId && sigOk(sigAlg, tbsBytes, sig, issuerKey))) {
            List<AttCert> embedded = new ArrayList<>();
            if (bk.size() > 3 && bk.get(3).tag == 0xa0) {
                List<Node> wrap = kidsOrNull(basic, bk.get(3));
                if (wrap != null && wrap.size() == 1) {
                    List<Node> cs = kidsOrNull(basic, wrap.get(0));
                    if (cs != null) {
                        for (Node c : cs) {
                            try {
                                embedded.add(AttestCert.parseCertDer(Arrays.copyOfRange(basic, c.hdr, c.end)));
                            } catch (AttestException e) {
                                // not a certificate: skipped
                            }
                        }
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
                for (AttCert s : signers) if (Arrays.equals(cand.rawIssuer, s.rawSubject) && AttestCert.certSigOkBy(cand, s)) okSigner = true;
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
        switch (st.tag & 0x1f) {
            case 0:
                return good("good");
            case 2:
                return good("unknown");
            case 1: {
                List<Node> items = kidsOrNull(basic, st);
                if (items == null || items.isEmpty() || !REV_TIME.matcher(text(basic, items.get(0))).matches()) return fail("malformed revoked certStatus");
                return good("revoked");
            }
            default:
                return fail("unrecognised certStatus");
        }
    }

    private static boolean matchesResponder(byte[] basic, Node rid, Node rIn, AttCert c) {
        if (rid.tag == 0xa1) return rIn.tag == 0x30 && Arrays.equals(Arrays.copyOfRange(basic, rIn.hdr, rIn.end), c.rawSubject);
        byte[] bits;
        try {
            bits = spkiKeyBits(c);
        } catch (AttestException e) {
            return false;
        }
        return rIn.tag == 0x04 && Arrays.equals(content(basic, rIn), hash("SHA-1", bits));
    }

    /**
     * checkNvidiaChainOcsp: every response must verify for exactly one chain certificate, any REVOKED fails, and every
     * certificate that advertises an OCSP responder must have a GOOD response. "" when it holds.
     */
    static String checkChainOcsp(List<AttCert> chain, List<byte[]> responses, long nowMs) {
        if (chain.size() < 2) return "chain too short for OCSP";
        if (responses.isEmpty()) return "no OCSP responses supplied";
        int last = chain.size() - 1;
        Set<Integer> required = new HashSet<>();
        for (int i = 0; i < last; i++) if (!chain.get(i).ocspServers().isEmpty()) required.add(i);
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
            if (required.contains(i) && !statuses[i].equals("good")) {
                return "no GOOD OCSP response for required certificate '" + AttestNvidia.subjectLine(chain.get(i)) + "' (status: " + statuses[i] + ")";
            }
        }
        return "";
    }
}
