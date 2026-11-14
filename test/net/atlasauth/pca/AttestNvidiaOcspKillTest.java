package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * NVIDIA OCSP (RFC 6960) verifier: exact outcomes over a synthetic P-384 device PKI (Leaf / Int / Root) and an OCSP response
 * builder that can vary every field the verifier reads: the structural refusal of each element, CertID matching, issuer and
 * delegated responder authentication, freshness boundaries, certStatus, and the chain-level aggregation.
 */
public class AttestNvidiaOcspKillTest {
    static final long NOW = 1_800_000_000_000L; // 2027-01-15T08:00:00Z
    static final long HOUR = 3_600_000L;
    static final long DAY = 24 * HOUR;
    static final long T = NOW - HOUR;
    static final String EC256 = "1.2.840.10045.4.3.2";
    static final String EC384 = "1.2.840.10045.4.3.3";
    static final String EC512 = "1.2.840.10045.4.3.4";
    static final String RSA256 = "1.2.840.113549.1.1.11";
    static final String SHA384_OID = "2.16.840.1.101.3.4.2.2";
    static final String REJ = "OCSP response rejected: ";
    static final String NOMATCH = "no SingleResponse matches the certificate (serial / issuer hashes differ)";
    static final String BADTIME = "response carries a malformed (out-of-range) ASN.1 time";
    static final String NO_EMBED = "no embedded responder certificate verifies the response";
    static final String ISSUER_SIG = "OCSP response signature does not verify under the issuer key";
    static final String NOT_CHAIN = "delegated responder certificate is not signed by the supplied NVIDIA chain";
    static final String OUTSIDE = "delegated responder certificate is outside its validity window";

    // ------------------------------------------------------------- fixture

    static byte[] ascii(String s) { return s.getBytes(StandardCharsets.US_ASCII); }

    static byte[] utEl(String s) { return withTag(0x17, ascii(s)); }

    static byte[] gtEl(String s) { return withTag(0x18, ascii(s)); }

    /** GeneralizedTime text of ms (fraction without trailing zeros). */
    static String gt(long ms) {
        LocalDateTime d = LocalDateTime.ofEpochSecond(Math.floorDiv(ms, 1000L), 0, ZoneOffset.UTC);
        String s = String.format("%04d%02d%02d%02d%02d%02d", d.getYear(), d.getMonthValue(), d.getDayOfMonth(), d.getHour(), d.getMinute(), d.getSecond());
        long frac = Math.floorMod(ms, 1000L);
        if (frac != 0) {
            String f = String.format("%03d", frac);
            while (f.endsWith("0")) f = f.substring(0, f.length() - 1);
            s += "." + f;
        }
        return s + "Z";
    }

    /** UTCTime text of a whole-second ms. */
    static String ut(long ms) { return gt(ms).substring(2); }

    static byte[] gtAt(long ms) { return gtEl(gt(ms)); }

    static byte[] md(String alg, byte[] b) {
        try {
            return MessageDigest.getInstance(alg).digest(b);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] signWith(PrivateKey k, String jca, byte[] data) {
        try {
            Signature s = Signature.getInstance(jca);
            s.initSign(k);
            s.update(data);
            return s.sign();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The subjectPublicKey bits of a P-384 key: 0x04 || X || Y (the last 97 bytes of its SPKI). */
    static byte[] keyBits(KeyPair k) {
        byte[] enc = k.getPublic().getEncoded();
        return Arrays.copyOfRange(enc, enc.length - 97, enc.length);
    }

    static byte[] keyRid(KeyPair k) { return withTag(0xa2, octets(md("SHA-1", keyBits(k)))); }

    static byte[] nameRid(String cn) { return withTag(0xa1, name(cn)); }

    static final byte[] V_FROM = utEl("250101000000Z");
    static final byte[] V_TO = utEl("350101000000Z");

    static byte[] mkCert(long serial, String subj, String iss, byte[] nb, byte[] na, PublicKey pub, PrivateKey signer, byte[]... exts) {
        byte[] ex = exts.length == 0 ? new byte[0] : withTag(0xa3, seq(cat(exts)));
        byte[] tbs = seq(withTag(0xa0, integer(2)), integer(serial), SIG_ALG_ECDSA_SHA256, name(iss), seq(nb, na), name(subj), pub.getEncoded(), ex);
        return seq(tbs, SIG_ALG_ECDSA_SHA256, bits((byte) 0, signWith(signer, "SHA256withECDSA", tbs)));
    }

    static final byte[] AIA = ext("1.3.6.1.5.5.7.1.1", false, seq(seq(oid("1.3.6.1.5.5.7.48.1"), withTag(0x86, ascii("http://ocsp.example")))));
    static final byte[] EKU_OCSP = ext("2.5.29.37", false, seq(oid("1.3.6.1.5.5.7.3.9")));

    static final class Party {
        final String cn;
        final KeyPair kp;
        final byte[] der;
        final AttCert c;

        Party(String cn, KeyPair kp, byte[] der) {
            this.cn = cn;
            this.kp = kp;
            this.der = der;
            this.c = AttestCert.parseCertDer(der);
        }
    }

    static final KeyPair K_ROOT = ecKey("secp384r1");
    static final KeyPair K_INT = ecKey("secp384r1");
    static final KeyPair K_LEAF = ecKey("secp384r1");
    static final KeyPair K_DEL = ecKey("secp384r1");
    static final KeyPair K_DEL2 = ecKey("secp384r1");
    static final KeyPair K_X = ecKey("secp384r1");

    static Party party(long serial, String cn, String issuerCn, KeyPair kp, KeyPair signer, byte[]... exts) {
        return new Party(cn, kp, mkCert(serial, cn, issuerCn, V_FROM, V_TO, kp.getPublic(), signer.getPrivate(), exts));
    }

    static final Party ROOT = party(1, "Root", "Root", K_ROOT, K_ROOT, basicConstraints(true, -1), keyUsageCertSign());
    static final Party INT = party(2, "Int", "Root", K_INT, K_ROOT, basicConstraints(true, -1), keyUsageCertSign());
    /** serial 128 is the INTEGER 00 80: the leading zero must be stripped on both sides of the CertID comparison. */
    static final Party LEAF = party(128, "Leaf", "Int", K_LEAF, K_INT, AIA);
    static final Party ROOT_B = party(1, "Root", "Root", K_ROOT, K_ROOT, basicConstraints(true, -1), keyUsageCertSign(), AIA);
    static final Party INT_B = party(2, "Int", "Root", K_INT, K_ROOT, basicConstraints(true, -1), keyUsageCertSign(), AIA);
    /** Only the leaf advertises an OCSP responder. */
    static final List<AttCert> CHAIN_A = Arrays.asList(LEAF.c, INT.c, ROOT.c);
    /** Every certificate (the root too) advertises one. */
    static final List<AttCert> CHAIN_B = Arrays.asList(LEAF.c, INT_B.c, ROOT_B.c);

    /** A delegated responder certificate issued by signer (name and key), with the OCSP-signing EKU when eku. */
    static Party delegate(String cn, String issuerCn, KeyPair kp, KeyPair signer, byte[] nb, byte[] na, boolean eku) {
        byte[][] exts = eku ? new byte[][] {EKU_OCSP} : new byte[0][];
        return new Party(cn, kp, mkCert(77, cn, issuerCn, nb, na, kp.getPublic(), signer.getPrivate(), exts));
    }

    static final Party DEL = delegate("Responder", "Int", K_DEL, K_INT, V_FROM, V_TO, true);

    /** One SingleResponse. */
    static final class S {
        final Party cert;
        final Party issuer;
        String hashOid = SHA384_OID;
        String hashJca = "SHA-384";
        byte[] serial;
        byte[] nameHash;
        byte[] keyHash;
        byte[] certId;
        byte[] status = {(byte) 0x80, 0x00};
        byte[] thisUpdate = gtAt(T);
        byte[] next = withTag(0xa0, gtAt(NOW + 30 * DAY));

        S(Party cert, Party issuer) {
            this.cert = cert;
            this.issuer = issuer;
        }

        byte[] der() {
            byte[] cid = certId != null ? certId
                : seq(seq(oid(hashOid), new byte[] {0x05, 0x00}),
                    octets(nameHash != null ? nameHash : md(hashJca, name(issuer.cn))),
                    octets(keyHash != null ? keyHash : md(hashJca, keyBits(issuer.kp))),
                    withTag(0x02, serial != null ? serial : cert.c.serial));
            return seq(cid, status, thisUpdate, next == null ? new byte[0] : next);
        }
    }

    /** An OCSPResponse; the defaults are a GOOD response for Leaf signed by Int under its name. */
    static final class Resp {
        final List<byte[]> singles = new ArrayList<>();
        byte[] version = new byte[0];
        byte[] rid = nameRid("Int");
        byte[] produced = gtAt(T);
        byte[] tbsExt = new byte[0];
        String sigOid = EC384;
        String jca = "SHA384withECDSA";
        PrivateKey signer = K_INT.getPrivate();
        byte[] sig;
        byte[] embed = new byte[0];

        Resp add(S s) {
            singles.add(s.der());
            return this;
        }

        byte[] tbs() { return seq(version, rid, produced, seq(cat(singles.toArray(new byte[0][]))), tbsExt); }

        byte[] basic() {
            byte[] t = tbs();
            return seq(t, seq(oid(sigOid)), sig != null ? sig : bits((byte) 0, signWith(signer, jca, t)), embed);
        }

        byte[] der() { return wrap(basic()); }
    }

    static Resp resp() { return new Resp().add(new S(LEAF, INT)); }

    static Resp resp(S s) { return new Resp().add(s); }

    static S single() { return new S(LEAF, INT); }

    static byte[] wrap(byte[] basic) {
        return seq(withTag(0x0a, new byte[] {0}), withTag(0xa0, seq(oid(AttestNvidiaOcsp.OID_OCSP_BASIC), octets(basic))));
    }

    /** A BasicOCSPResponse around a hand-made ResponseData with a placeholder signature. */
    static byte[] rawBasic(byte[] tbs) { return seq(tbs, seq(oid(EC384)), bits((byte) 0, new byte[] {1})); }

    static byte[] embedOf(byte[]... certs) { return withTag(0xa0, seq(cat(certs))); }

    static String out(AttestNvidiaOcsp.Result r) {
        if (r.ok) return r.reason.isEmpty() ? "OK " + r.status : "BAD ok with reason " + r.reason;
        return r.status.isEmpty() ? r.reason : "BAD failure with status " + r.status;
    }

    static String v(byte[] der) { return v(der, NOW); }

    static String v(byte[] der, long now) { return out(AttestNvidiaOcsp.verifyResponse(der, LEAF.c, INT.c, CHAIN_A, now)); }

    static String v(Resp r) { return v(r.der()); }

    static String vChain(byte[] der, List<AttCert> chain) { return out(AttestNvidiaOcsp.verifyResponse(der, LEAF.c, INT.c, chain, NOW)); }

    // ------------------------------------------------------------- accepted responses

    @Test
    void acceptedVariants() {
        assertEquals("OK good", v(resp()));
        Resp r = resp();
        r.version = withTag(0xa0, integer(0));
        assertEquals("OK good", v(r));
        r = resp();
        r.rid = keyRid(K_INT);
        assertEquals("OK good", v(r));
        String[][] hashes = {{"1.3.14.3.2.26", "SHA-1"}, {"2.16.840.1.101.3.4.2.1", "SHA-256"}, {"2.16.840.1.101.3.4.2.3", "SHA-512"}};
        for (String[] h : hashes) {
            S s = single();
            s.hashOid = h[0];
            s.hashJca = h[1];
            assertEquals("OK good", v(resp(s)), h[0]);
        }
        r = resp();
        r.sigOid = EC256;
        r.jca = "SHA256withECDSA";
        assertEquals("OK good", v(r));
        r = resp();
        r.sigOid = EC512;
        r.jca = "SHA512withECDSA";
        assertEquals("OK good", v(r));
        // no nextUpdate
        S s = single();
        s.next = null;
        assertEquals("OK good", v(resp(s)));
        // a [1] (singleExtensions) in the nextUpdate slot is no nextUpdate
        s = single();
        s.next = withTag(0xa1, gtAt(T - DAY));
        assertEquals("OK good", v(resp(s)));
        // a [0] with two times or holding a UTCTime is malformed, never absent
        s = single();
        s.next = withTag(0xa0, gtAt(T - DAY), gtAt(T - DAY));
        assertEquals(REJ + "malformed SingleResponse", v(resp(s)));
        s = single();
        s.next = withTag(0xa0, utEl(ut(T - DAY)));
        assertEquals(REJ + "malformed SingleResponse", v(resp(s)));
        // extra leading zeros on the CertID serial
        s = single();
        s.serial = new byte[] {0, 0, (byte) 0x80};
        assertEquals("OK good", v(resp(s)));
        // a well-formed UTCTime in a response extension
        r = resp();
        r.tbsExt = withTag(0xa1, seq(utEl("250101000000Z")));
        assertEquals("OK good", v(r));
        // a non-matching SingleResponse (Int's) and an unknown-hash one next to the match
        S other = new S(INT, ROOT);
        S unknownHash = single();
        unknownHash.hashOid = "1.2.3.4";
        assertEquals("OK good", v(resp().add(other).add(unknownHash)));
        assertEquals("OK good", v(new Resp().add(unknownHash).add(single())));
    }

    @Test
    void certStatus() {
        S s = single();
        s.status = new byte[] {(byte) 0x82, 0x00};
        assertEquals("OK unknown", v(resp(s)));
        s.status = withTag(0xa1, gtEl("20261019120000Z"));
        assertEquals("OK revoked", v(resp(s)));
        s.status = withTag(0xa1, gtEl("20261019120000Z"), withTag(0xa0, withTag(0x0a, new byte[] {1})));
        assertEquals("OK revoked", v(resp(s)));
        s.status = new byte[] {0x05, 0x00};
        assertEquals("malformed certStatus", v(resp(s)));
        s.status = new byte[] {(byte) 0xc0, 0x00};
        assertEquals("malformed certStatus", v(resp(s)));
        s.status = new byte[] {(byte) 0x83, 0x00};
        assertEquals("unrecognised certStatus", v(resp(s)));
        s.status = new byte[] {(byte) 0xa1, 0x00};
        assertEquals("malformed revoked certStatus", v(resp(s)));
        // tags are exact: primitive [1] is not revoked, constructed [0]/[2] are not good/unknown
        s.status = new byte[] {(byte) 0x81, 0x00};
        assertEquals("malformed certStatus", v(resp(s)));
        s.status = new byte[] {(byte) 0x81, 0x01, 0x05};
        assertEquals("malformed certStatus", v(resp(s)));
        s.status = new byte[] {(byte) 0xa0, 0x00};
        assertEquals("malformed certStatus", v(resp(s)));
        s.status = new byte[] {(byte) 0xa2, 0x00};
        assertEquals("malformed certStatus", v(resp(s)));
        s.status = new byte[] {(byte) 0xa3, 0x00};
        assertEquals("unrecognised certStatus", v(resp(s)));
        s.status = withTag(0xa1, gtEl("20261019120000.5Z"));
        assertEquals("malformed revoked certStatus", v(resp(s)));
    }

    /** After thisUpdate only an optional [0] then an optional [1], in every SingleResponse (the TS schema parses them all). */
    @Test
    void elementsAfterThisUpdate() {
        String ms = REJ + "malformed SingleResponse";
        byte[] future = withTag(0xa0, gtAt(NOW + 30 * DAY));
        byte[] exts = withTag(0xa1, seq());
        S s = single();
        // a past nextUpdate under an unknown tag must not read as absent and skip the stale check
        s.next = withTag(0xa2, gtAt(T - DAY));
        assertEquals(ms, v(resp(s)));
        s.next = cat(future, exts);
        assertEquals("OK good", v(resp(s)));
        s.next = exts;
        assertEquals("OK good", v(resp(s)));
        s.next = cat(exts, future);
        assertEquals(ms, v(resp(s)));
        s.next = cat(future, exts, exts);
        assertEquals(ms, v(resp(s)));
        s.next = cat(future, future);
        assertEquals(ms, v(resp(s)));
        s.next = cat(future, withTag(0xa2, gtAt(T)));
        assertEquals(ms, v(resp(s)));
        // the stale check still reads a [0] that has a [1] behind it
        s.next = cat(withTag(0xa0, gtAt(T + 1000)), exts);
        assertEquals("response is stale (past nextUpdate)", v(resp(s).der(), T + 1001));
        // a SingleResponse for another certificate is held to the same structure, whichever side of the match it sits
        for (byte[] bad : new byte[][] {
            withTag(0xa2, gtAt(T)),
            withTag(0xa0, gtAt(T), gtAt(T)),
            withTag(0xa0, utEl(ut(T))),
            withTag(0xa0),
            cat(exts, future)
        }) {
            S other = new S(INT, ROOT);
            other.next = bad;
            assertEquals(ms, v(resp().add(other)));
            assertEquals(ms, v(new Resp().add(other).add(single())));
        }
    }

    // ------------------------------------------------------------- structural refusals

    @Test
    void outerStructure() {
        byte[] basic = resp().basic();
        byte[] en0 = withTag(0x0a, new byte[] {0});
        assertEquals("response is not valid DER", v(new byte[] {0x3f, 0x00})); // a multi-byte tag
        assertEquals(REJ + "OCSPResponse is not a SEQUENCE", v(new byte[] {0x31, 0x00}));
        assertEquals(REJ + "malformed OCSPResponse", v(new byte[] {0x30, 0x00}));
        assertEquals(REJ + "malformed OCSPResponse", v(new byte[] {0x30, 0x02, 0x30, 0x05}));
        assertEquals(REJ + "malformed OCSPResponse", v(seq(withTag(0x0a, new byte[] {0, 0}))));
        assertEquals("successful response carries no responseBytes", v(seq(en0, withTag(0xa1, seq()))));
        assertEquals(REJ + "malformed responseBytes", v(seq(en0, withTag(0xa0, new byte[] {0x30, 0x05}))));
        assertEquals(REJ + "malformed responseBytes", v(seq(en0, withTag(0xa0, seq(), seq()))));
        assertEquals(REJ + "malformed responseBytes", v(seq(en0, withTag(0xa0, withTag(0x31)))));
        assertEquals(REJ + "malformed responseBytes", v(seq(en0, withTag(0xa0, seq(new byte[] {0x30, 0x05})))));
        assertEquals(REJ + "malformed responseBytes", v(seq(en0, withTag(0xa0, seq(oid(AttestNvidiaOcsp.OID_OCSP_BASIC))))));
        assertEquals(REJ + "malformed responseBytes", v(seq(en0, withTag(0xa0, seq(oid(AttestNvidiaOcsp.OID_OCSP_BASIC), withTag(0x03, new byte[] {0}))))));
        assertEquals("responseType is not id-pkix-ocsp-basic", v(seq(en0, withTag(0xa0, seq(oid("1.3.6.1.5.5.7.48.1.2"), octets(basic))))));
        assertEquals(REJ + "expected an OBJECT IDENTIFIER", v(seq(en0, withTag(0xa0, seq(integer(1), octets(basic))))));
        assertEquals("BasicOCSPResponse is not valid DER", v(wrap(new byte[] {0x30, 0x05})));
        assertEquals(REJ + "BasicOCSPResponse is not a SEQUENCE", v(wrap(new byte[] {0x31, 0x00})));
        assertEquals(REJ + "malformed BasicOCSPResponse", v(wrap(new byte[] {0x30, 0x02, 0x30, 0x05})));
    }

    @Test
    void basicStructure() {
        byte[] tbs = resp().tbs();
        byte[] alg = seq(oid(EC384));
        byte[] sig = bits((byte) 0, new byte[] {1});
        String mb = REJ + "malformed BasicOCSPResponse";
        assertEquals(mb, v(wrap(seq(tbs, alg))));
        assertEquals(mb, v(wrap(seq(integer(1), alg, sig))));
        assertEquals(mb, v(wrap(seq(tbs, integer(1), sig))));
        assertEquals(mb, v(wrap(seq(tbs, alg, octets(new byte[] {1})))));
        assertEquals(REJ + "malformed signatureAlgorithm", v(wrap(seq(tbs, seq(), sig))));
        assertEquals(REJ + "expected an OBJECT IDENTIFIER", v(wrap(seq(tbs, seq(integer(1)), sig))));
        Resp r = resp();
        r.sigOid = "1.2.3.4";
        assertEquals("unsupported OCSP signature algorithm 1.2.3.4", v(r));
        r = resp();
        r.sig = withTag(0x03);
        assertEquals(REJ + "malformed signature", v(r));
        r = resp();
        r.sig = new byte[] {0x03, 0x01, 0x00}; // an empty signature after the unused-bits octet
        assertEquals(ISSUER_SIG, v(r));
    }

    @Test
    void malformedTimes() {
        Resp r = resp();
        r.tbsExt = withTag(0xa1, new byte[] {0x30, 0x05}); // a constructed element whose content does not parse
        assertEquals(BADTIME, v(r));
        r = resp();
        r.tbsExt = withTag(0xa1, seq(utEl("230229000000Z")));
        assertEquals(BADTIME, v(r));
        r = resp();
        r.tbsExt = withTag(0xa1, seq(gtEl("20230229000000Z")));
        assertEquals(BADTIME, v(r));
        S s = single();
        s.thisUpdate = gtEl("20231301000000Z");
        assertEquals(BADTIME, v(resp(s)));
    }

    @Test
    void responseDataStructure() {
        String md = REJ + "malformed ResponseData";
        byte[] rid = nameRid("Int");
        byte[] sd = single().der();
        assertEquals(md, v(wrap(rawBasic(seq(rid, gtAt(T))))));
        assertEquals(md, v(wrap(rawBasic(seq(withTag(0xa0, integer(0)), rid, gtAt(T))))));
        assertEquals(md, v(wrap(rawBasic(seq(rid, gtAt(T), withTag(0x31, sd))))));
        Resp r = resp();
        r.produced = utEl(ut(T));
        assertEquals(md, v(r));
        r = resp();
        r.rid = withTag(0xa3, name("Int"));
        assertEquals(md, v(r));
        r = resp();
        r.rid = withTag(0xa1);
        assertEquals(REJ + "malformed responderID", v(r));
        r = resp();
        r.rid = withTag(0xa1, name("Int"), name("Int"));
        assertEquals(REJ + "malformed responderID", v(r));
    }

    @Test
    void singleResponseStructure() {
        String ms = REJ + "malformed SingleResponse";
        Resp r = new Resp();
        r.singles.add(octets(new byte[] {1}));
        assertEquals(ms, v(r));
        // a primitive element carrying a whole SingleResponse is still refused
        byte[] sd = single().der();
        r = new Resp();
        r.singles.add(withTag(0x04, Arrays.copyOfRange(sd, AttestDer.tlvAt(sd, 0).start, sd.length)));
        assertEquals(ms, v(r));
        S good = single();
        byte[] cid = seq(seq(oid(SHA384_OID), new byte[] {0x05, 0x00}), octets(md("SHA-384", name("Int"))), octets(md("SHA-384", keyBits(K_INT))), withTag(0x02, LEAF.c.serial));
        r = new Resp();
        r.singles.add(seq(cid, good.status));
        assertEquals(ms, v(r));
        r = new Resp();
        r.singles.add(seq(integer(1), good.status, gtAt(T)));
        assertEquals(ms, v(r));
        r = new Resp();
        r.singles.add(seq(cid, good.status, utEl(ut(T))));
        assertEquals(ms, v(r));

        String mc = REJ + "malformed CertID";
        byte[] alg = seq(oid(SHA384_OID));
        byte[] nh = octets(new byte[48]);
        byte[] ser = integer(128);
        byte[][] badIds = {
            seq(alg, nh, nh),
            seq(integer(1), nh, nh, ser),
            seq(alg, integer(1), nh, ser),
            seq(alg, nh, integer(1), ser),
            seq(alg, nh, nh, octets(new byte[] {(byte) 0x80})),
        };
        for (byte[] bad : badIds) {
            S s = single();
            s.certId = bad;
            assertEquals(mc, v(resp(s)));
        }
        S s = single();
        s.certId = seq(seq(), nh, nh, ser);
        assertEquals(REJ + "malformed CertID hash algorithm", v(resp(s)));
        s.certId = seq(seq(integer(1)), nh, nh, ser);
        assertEquals(REJ + "expected an OBJECT IDENTIFIER", v(resp(s)));
    }

    @Test
    void certIdMatching() {
        S s = single();
        s.hashOid = "1.2.3.4";
        assertEquals(NOMATCH, v(resp(s)));
        s = single();
        s.serial = new byte[] {(byte) 0x81};
        assertEquals(NOMATCH, v(resp(s)));
        s = single();
        s.nameHash = md("SHA-384", name("Other"));
        assertEquals(NOMATCH, v(resp(s)));
        s = single();
        s.keyHash = md("SHA-384", keyBits(K_X));
        assertEquals(NOMATCH, v(resp(s)));
        assertEquals(NOMATCH, v(new Resp()));
        assertEquals("ambiguous: multiple SingleResponses match the certificate", v(resp().add(single())));
    }

    // ------------------------------------------------------------- responder authentication

    @Test
    void issuerResponder() {
        Resp r = resp();
        r.signer = K_X.getPrivate();
        assertEquals(ISSUER_SIG, v(r));
        r = resp();
        r.rid = keyRid(K_INT);
        r.signer = K_X.getPrivate();
        assertEquals(ISSUER_SIG, v(r));
        r = resp();
        r.sigOid = RSA256; // an RSA algorithm under the EC issuer key
        assertEquals(ISSUER_SIG, v(r));
        // signed by the issuer, but the responderID names someone else: only an embedded responder could verify it
        r = resp();
        r.rid = nameRid("Other");
        assertEquals(NO_EMBED, v(r));
        r = resp();
        r.rid = keyRid(K_X);
        assertEquals(NO_EMBED, v(r));
        r = resp();
        r.rid = withTag(0xa1, octets(name("Int")));
        assertEquals(NO_EMBED, v(r));
        r = resp();
        r.rid = withTag(0xa2, withTag(0x83, md("SHA-1", keyBits(K_INT))));
        assertEquals(NO_EMBED, v(r));
        // issuer named, signature bad, an embedded certificate that does not match: the issuer reason wins
        r = resp();
        r.signer = K_X.getPrivate();
        r.embed = embedOf(DEL.der);
        assertEquals(ISSUER_SIG, v(r));
    }

    static Resp delegated(Party d) {
        Resp r = resp();
        r.rid = keyRid(d.kp);
        r.signer = d.kp.getPrivate();
        r.embed = embedOf(d.der);
        return r;
    }

    @Test
    void delegatedResponder() {
        assertEquals("OK good", v(delegated(DEL)));
        Resp r = delegated(DEL);
        r.rid = nameRid("Responder");
        assertEquals("OK good", v(r));
        // a non-certificate before the responder refuses the response
        r = delegated(DEL);
        r.embed = embedOf(seq(integer(1)), DEL.der);
        assertTrue(v(r).startsWith(REJ), v(r));
        // certificates not in an [0] holding exactly one SEQUENCE are not read
        r = delegated(DEL);
        r.embed = withTag(0xa1, seq(DEL.der));
        assertEquals(NO_EMBED, v(r));
        r = delegated(DEL);
        r.embed = withTag(0xa0, seq(DEL.der), seq());
        assertEquals(NO_EMBED, v(r));
        r = delegated(DEL);
        r.embed = withTag(0xa0, octets(new byte[] {0x30, 0x05}));
        assertEquals(NO_EMBED, v(r));
        // the responderID names a key no embedded certificate has
        r = delegated(DEL);
        r.rid = keyRid(K_X);
        assertEquals("embedded certificates do not match the responderID", v(r));
        // the EKU
        Party noEku = delegate("Responder2", "Int", K_DEL2, K_INT, V_FROM, V_TO, false);
        assertEquals("delegated responder certificate lacks the id-kp-OCSPSigning EKU", v(delegated(noEku)));
        // the reason of the last candidate is reported
        r = delegated(noEku);
        r.embed = embedOf(noEku.der, DEL.der);
        assertEquals("embedded certificates do not match the responderID", v(r));
        r = delegated(noEku);
        r.embed = embedOf(DEL.der, noEku.der);
        assertEquals("delegated responder certificate lacks the id-kp-OCSPSigning EKU", v(r));
        // signed by another key than the responder's
        r = delegated(DEL);
        r.signer = K_X.getPrivate();
        assertEquals("OCSP response signature does not verify under the delegated responder key", v(r));
    }

    @Test
    void delegatedSigner() {
        // issued by the root: accepted while the issuer is in the chain (the signers run from the issuer up)
        Party byRoot = delegate("Responder", "Root", K_DEL, K_ROOT, V_FROM, V_TO, true);
        byte[] der = delegated(byRoot).der();
        assertEquals("OK good", vChain(der, CHAIN_A));
        assertEquals("OK good", vChain(der, Arrays.asList(INT.c, ROOT.c)));
        assertEquals(NOT_CHAIN, vChain(der, Arrays.asList(ROOT.c)));
        // the issuer itself is always a signer, even when the chain does not list it
        assertEquals("OK good", vChain(delegated(DEL).der(), Arrays.asList(ROOT.c)));
        // issued by the leaf (below the issuer)
        Party byLeaf = delegate("Responder", "Leaf", K_DEL, K_LEAF, V_FROM, V_TO, true);
        assertEquals(NOT_CHAIN, v(delegated(byLeaf)));
        // the issuer's name with a stranger's signature, a stranger's name with the issuer's signature
        assertEquals(NOT_CHAIN, v(delegated(delegate("Responder", "Int", K_DEL, K_X, V_FROM, V_TO, true))));
        assertEquals(NOT_CHAIN, v(delegated(delegate("Responder", "Other", K_DEL, K_INT, V_FROM, V_TO, true))));
    }

    @Test
    void delegatedValidity() {
        // both bounds are inclusive
        Party from = delegate("Responder", "Int", K_DEL, K_INT, utEl(ut(NOW)), V_TO, true);
        byte[] der = delegated(from).der();
        assertEquals("OK good", v(der, NOW));
        assertEquals(OUTSIDE, v(der, NOW - 1));
        Party to = delegate("Responder", "Int", K_DEL, K_INT, V_FROM, utEl(ut(NOW)), true);
        der = delegated(to).der();
        assertEquals("OK good", v(der, NOW));
        assertEquals(OUTSIDE, v(der, NOW + 1));
        // a bound with a fraction is a well-formed GeneralizedTime but not a certificate time
        assertEquals(OUTSIDE, v(delegated(delegate("Responder", "Int", K_DEL, K_INT, gtEl("20250101000000.5Z"), V_TO, true))));
        assertEquals(OUTSIDE, v(delegated(delegate("Responder", "Int", K_DEL, K_INT, V_FROM, gtEl("20350101000000.5Z"), true))));
    }

    // ------------------------------------------------------------- freshness

    @Test
    void freshness() {
        byte[] der = resp().der(); // thisUpdate = producedAt = T, nextUpdate = NOW + 30 days
        assertEquals("OK good", v(der, T));
        assertEquals("response thisUpdate is in the future", v(der, T - 1));
        assertEquals("OK good", v(der, T + 7 * DAY));
        assertEquals("response is older than the maximum accepted age", v(der, T + 7 * DAY + 1));
        Resp r = resp();
        r.produced = gtAt(T + 1000);
        der = r.der();
        assertEquals("response producedAt is in the future", v(der, T));
        assertEquals("OK good", v(der, T + 1000));
        S s = single();
        s.next = withTag(0xa0, gtAt(T - 1000));
        assertEquals("response nextUpdate is invalid", v(resp(s)));
        s.next = withTag(0xa0, gtAt(T));
        assertEquals("OK good", v(resp(s).der(), T));
        s.next = withTag(0xa0, gtAt(T + 1000));
        der = resp(s).der();
        assertEquals("OK good", v(der, T + 1000));
        assertEquals("response is stale (past nextUpdate)", v(der, T + 1001));
        s.next = null;
        der = resp(s).der();
        assertEquals("OK good", v(der, T + 7 * DAY));
        assertEquals("response is older than the maximum accepted age", v(der, T + 7 * DAY + 1));
    }

    // ------------------------------------------------------------- the chain

    static byte[] leafResp(byte[] status) {
        S s = single();
        s.status = status;
        return resp(s).der();
    }

    static byte[] intResp() {
        Resp r = new Resp().add(new S(INT, ROOT));
        r.rid = nameRid("Root");
        r.signer = K_ROOT.getPrivate();
        return r.der();
    }

    @Test
    void chainAggregation() {
        byte[] good = leafResp(new byte[] {(byte) 0x80, 0x00});
        assertEquals("", AttestNvidiaOcsp.checkChainOcsp(CHAIN_A, Arrays.asList(good), NOW));
        assertEquals("", AttestNvidiaOcsp.checkChainOcsp(CHAIN_B, Arrays.asList(good, intResp()), NOW));
        assertEquals("", AttestNvidiaOcsp.checkChainOcsp(CHAIN_B, Arrays.asList(intResp(), good), NOW));
        assertEquals("no GOOD OCSP response for required certificate 'CN=Int' (status: absent)",
            AttestNvidiaOcsp.checkChainOcsp(CHAIN_B, Arrays.asList(good), NOW));
        assertEquals("no GOOD OCSP response for required certificate 'CN=Leaf' (status: absent)",
            AttestNvidiaOcsp.checkChainOcsp(CHAIN_A, Arrays.asList(intResp()), NOW));
        assertEquals("no GOOD OCSP response for required certificate 'CN=Leaf' (status: unknown)",
            AttestNvidiaOcsp.checkChainOcsp(CHAIN_A, Arrays.asList(leafResp(new byte[] {(byte) 0x82, 0x00})), NOW));
        assertEquals("chain certificate 'CN=Leaf' is revoked (OCSP)",
            AttestNvidiaOcsp.checkChainOcsp(CHAIN_A, Arrays.asList(leafResp(withTag(0xa1, gtEl("20261019120000Z")))), NOW));
        assertEquals("duplicate OCSP responses for chain certificate #0",
            AttestNvidiaOcsp.checkChainOcsp(CHAIN_A, Arrays.asList(good, good), NOW));
        S stranger = single();
        stranger.serial = new byte[] {99};
        assertEquals("OCSP response #0 rejected: " + NOMATCH,
            AttestNvidiaOcsp.checkChainOcsp(CHAIN_A, Arrays.asList(resp(stranger).der()), NOW));
        assertEquals("OCSP response #1 for 'CN=Leaf' rejected: response is not valid DER",
            AttestNvidiaOcsp.checkChainOcsp(CHAIN_A, Arrays.asList(good, new byte[] {0x30}), NOW));
        // one response (a root-issued delegated responder) that verifies for both the leaf and the intermediate
        Party byRoot = delegate("Responder", "Root", K_DEL, K_ROOT, V_FROM, V_TO, true);
        Resp both = delegated(byRoot).add(new S(INT, ROOT));
        assertEquals("OCSP response #0 matches more than one chain certificate",
            AttestNvidiaOcsp.checkChainOcsp(CHAIN_A, Arrays.asList(both.der()), NOW));
    }

    // ------------------------------------------------------------- helpers

    @Test
    void timeReader() {
        assertEquals(Long.valueOf(60_000L), AttestNvidiaOcsp.timeMs("19700101000100Z", false));
        assertEquals(Long.valueOf(1_000L), AttestNvidiaOcsp.timeMs("19700101000001Z", false));
        assertEquals(Long.valueOf(31_535_999_000L), AttestNvidiaOcsp.timeMs("19701231235959Z", false));
        assertEquals(Long.valueOf(31_535_999_000L), AttestNvidiaOcsp.timeMs("701231235959Z", true));
        assertNull(AttestNvidiaOcsp.timeMs("19700001000000Z", false));
        assertNull(AttestNvidiaOcsp.timeMs("20230101006000Z", false));
        assertNull(AttestNvidiaOcsp.timeMs("20230101000060Z", false));
        assertNull(AttestNvidiaOcsp.timeMs("700101000000Z", false));
        assertNull(AttestNvidiaOcsp.timeMs("19700101000000Z", true));
    }

    @Test
    void stripLeadingZeros() {
        assertArrayEquals(new byte[] {1}, AttestNvidiaOcsp.stripLeading0(new byte[] {0, 0, 1}));
        assertArrayEquals(new byte[] {(byte) 0x80}, AttestNvidiaOcsp.stripLeading0(new byte[] {0, (byte) 0x80}));
        assertArrayEquals(new byte[] {0}, AttestNvidiaOcsp.stripLeading0(new byte[] {0}));
        assertArrayEquals(new byte[] {0}, AttestNvidiaOcsp.stripLeading0(new byte[] {0, 0}));
        assertArrayEquals(new byte[] {1, 0}, AttestNvidiaOcsp.stripLeading0(new byte[] {1, 0}));
        assertArrayEquals(new byte[0], AttestNvidiaOcsp.stripLeading0(new byte[0]));
    }

    @Test
    void spkiAndHash() {
        assertArrayEquals(keyBits(K_LEAF), AttestNvidiaOcsp.spkiKeyBits(LEAF.c));
        AttCert bad = new AttCert();
        bad.rawSpki = seq(seq(oid("1.2.840.10045.2.1")));
        assertEquals("malformed SubjectPublicKeyInfo", assertThrows(AttestException.class, () -> AttestNvidiaOcsp.spkiKeyBits(bad)).getMessage());
        assertThrows(IllegalStateException.class, () -> AttestNvidiaOcsp.hash("NO-SUCH-HASH", new byte[0]));
        assertArrayEquals(md("SHA-256", new byte[] {1}), AttestNvidiaOcsp.hash("SHA-256", new byte[] {1}));
    }

    @Test
    void signatureCheck() throws Exception {
        byte[] tbs = ascii("tbs");
        CertKey ec = CertKey.of(K_INT.getPublic(), K_INT.getPublic().getEncoded());
        byte[] ec384 = signWith(K_INT.getPrivate(), "SHA384withECDSA", tbs);
        assertTrue(AttestNvidiaOcsp.sigOk(EC384, tbs, ec384, ec));
        assertTrue(AttestNvidiaOcsp.sigOk(EC256, tbs, signWith(K_INT.getPrivate(), "SHA256withECDSA", tbs), ec));
        assertTrue(AttestNvidiaOcsp.sigOk(EC512, tbs, signWith(K_INT.getPrivate(), "SHA512withECDSA", tbs), ec));
        assertFalse(AttestNvidiaOcsp.sigOk("1.2.3.4", tbs, ec384, ec));
        assertFalse(AttestNvidiaOcsp.sigOk(RSA256, tbs, ec384, ec));
        assertFalse(AttestNvidiaOcsp.sigOk(EC384, ascii("other"), ec384, ec));
        assertFalse(AttestNvidiaOcsp.sigOk(EC384, tbs, new byte[] {1, 2, 3}, ec));

        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair rsa = g.generateKeyPair();
        CertKey rk = CertKey.of(rsa.getPublic(), rsa.getPublic().getEncoded());
        byte[] rs = signWith(rsa.getPrivate(), "SHA256withRSA", tbs);
        assertTrue(AttestNvidiaOcsp.sigOk(RSA256, tbs, rs, rk));
        assertTrue(AttestNvidiaOcsp.sigOk("1.2.840.113549.1.1.12", tbs, signWith(rsa.getPrivate(), "SHA384withRSA", tbs), rk));
        assertFalse(AttestNvidiaOcsp.sigOk(EC256, tbs, rs, rk));
        assertFalse(AttestNvidiaOcsp.sigOk(RSA256, ascii("other"), rs, rk));

        KeyPair ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        CertKey ek = CertKey.of(ed.getPublic(), ed.getPublic().getEncoded());
        assertFalse(AttestNvidiaOcsp.sigOk(EC256, tbs, signWith(ed.getPrivate(), "Ed25519", tbs), ek));
    }
}
