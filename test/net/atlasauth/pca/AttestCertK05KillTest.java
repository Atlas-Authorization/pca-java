package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Exact-outcome tests for the OpenSSL-style certificate reader (AttestCert), the key classifier (CertKey) and the
 * extension readers of AttCert: whole parse results, a tamper matrix with the exact refusal text per field, and
 * real-key signature checks with every wrong-key / wrong-algorithm pairing.
 */
public class AttestCertK05KillTest {
    static final String WRONG_TAG = AttestCert.OSSL_WRONG_TAG;
    static final String NESTED = AttestCert.OSSL_NESTED;
    static final String BITS = AttestCert.OSSL_BITS;
    static final String UNSUPPORTED = AttestCert.OSSL_UNSUPPORTED;
    static final String OK = "no error";

    static final KeyPair EC = ecKey("secp256r1");
    static final KeyPair EC384 = ecKey("secp384r1");
    static final KeyPair RSA = kp("RSA", 2048);
    static final KeyPair ED = kp("Ed25519", 0);

    static final byte[] NULL = {0x05, 0x00};
    static final byte[] V3 = withTag(0xa0, integer(2));
    static final byte[] SERIAL = integer(258);
    static final byte[] ALG = SIG_ALG_ECDSA_SHA256;
    static final byte[] ISSUER = name("Issuer");
    static final byte[] SUBJECT = name("Subject");
    static final byte[] VALIDITY = seq(utc("250101000000Z"), utc("350101000000Z"));
    static final byte[] SPKI = EC.getPublic().getEncoded();
    static final byte[] SIGBITS = bits((byte) 0, new byte[] {9, 8, 7});

    static final String OID_EC = "1.2.840.10045.2.1";
    static final String MGF1 = "1.2.840.113549.1.1.8";
    static final String SHA1 = "1.3.14.3.2.26";
    static final String SHA256 = "2.16.840.1.101.3.4.2.1";
    static final String SHA384 = "2.16.840.1.101.3.4.2.2";
    static final String SHA512 = "2.16.840.1.101.3.4.2.3";

    // ------------------------------------------------------------- helpers

    private static String reason(Runnable r) {
        try {
            r.run();
        } catch (AttestException e) {
            return e.getMessage();
        }
        return OK;
    }

    private static byte[] bytes(int... v) {
        byte[] b = new byte[v.length];
        for (int i = 0; i < v.length; i++) b[i] = (byte) v[i];
        return b;
    }

    static KeyPair kp(String alg, int size) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance(alg);
            if (size > 0) g.initialize(size);
            return g.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] sign(String alg, PrivateKey k, byte[] data, AlgorithmParameterSpec spec) {
        try {
            Signature s = Signature.getInstance(alg);
            if (spec != null) s.setParameter(spec);
            s.initSign(k);
            s.update(data);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] utc(String s) { return withTag(0x17, s.getBytes(StandardCharsets.US_ASCII)); }

    static byte[] gtime(String s) { return withTag(0x18, s.getBytes(StandardCharsets.US_ASCII)); }

    static byte[] certOf(byte[] tbs) { return seq(tbs, ALG, SIGBITS); }

    /** A v3 tbsCertificate with the default fields up to the subject public key, then tail. */
    static byte[] tbsWith(byte[]... tail) { return seq(V3, SERIAL, ALG, ISSUER, VALIDITY, SUBJECT, SPKI, cat(tail)); }

    static String parse(byte[] tbs) { return reason(() -> AttestCert.parseCertDer(certOf(tbs))); }

    static String exts(AttCert c) {
        StringBuilder sb = new StringBuilder();
        for (AttCert.LenientExt e : c.exts) {
            if (sb.length() > 0) sb.append('|');
            sb.append(e.oid).append(':').append(e.critical).append(':').append(AttestCommon.toHexLower(e.value));
        }
        return sb.toString();
    }

    static byte[] extBlock(byte[]... entries) { return withTag(0xa3, seq(entries)); }

    static AttestCert.Elem elemAny(byte[] b) { return AttestCert.readCertElem(b, 0, b.length, 0); }

    // ------------------------------------------------------------- validOid / algId / checkBitString / checkName

    static boolean vo(int tag, int start, int end, int... buf) {
        return AttestCert.validOid(bytes(buf), new AttestCert.Elem(tag, 0, start, end));
    }

    @Test void validOidContentRules() {
        assertTrue(vo(0x06, 2, 4, 0x06, 0x02, 0x2a, 0x03)); // ends the array
        assertTrue(vo(0x06, 2, 4, 0x06, 0x02, 0x2a, 0x03, 0x80)); // a 0x80 after the element is not part of it
        assertFalse(vo(0x04, 2, 4, 0x06, 0x02, 0x2a, 0x03));
        assertFalse(vo(0x06, 2, 2, 0x06, 0x00)); // empty
        assertFalse(vo(0x06, 2, 4, 0x06, 0x02, 0x2a, 0x81)); // dangling continuation
        assertFalse(vo(0x06, 2, 4, 0x06, 0x02, 0x80, 0x01)); // first arc starts with 0x80
        assertFalse(vo(0x06, 1, 3, 0xff, 0x80, 0x01)); // first content byte 0x80 even after a high byte outside the element
        assertFalse(vo(0x06, 2, 5, 0x06, 0x03, 0x2a, 0x80, 0x01)); // arc starts with 0x80
        assertTrue(vo(0x06, 2, 5, 0x06, 0x03, 0x81, 0x80, 0x01)); // 0x80 inside an arc is fine
    }

    static AttestCert.AlgId algOf(byte[] d) { return AttestCert.algId(d, AttestCert.readCertElem(d, 0, d.length, 0x30)); }

    @Test void algIdShapes() {
        AttestCert.AlgId a = algOf(seq(oid("1.2.840.10045.4.3.2")));
        assertEquals("1.2.840.10045.4.3.2", a.oid);
        assertNull(a.params);
        a = algOf(seq(oid("1.2.840.113549.1.1.11"), NULL));
        assertEquals("1.2.840.113549.1.1.11", a.oid);
        assertArrayEquals(NULL, a.params);
        assertEquals(NESTED, reason(() -> algOf(seq())));
        assertEquals(NESTED, reason(() -> algOf(seq(oid("1.2.3"), NULL, NULL))));
        assertEquals(NESTED, reason(() -> algOf(seq(integer(1)))));
        assertEquals(NESTED, reason(() -> algOf(seq(bytes(0x06, 0x02, 0x2a, 0x81)))));
    }

    @Test void bitStringHeader() {
        for (int unused = 0; unused <= 7; unused++) {
            final byte[] b = bytes(0x03, 0x02, unused, 0xff);
            assertEquals(OK, reason(() -> AttestCert.checkBitString(b, elemAny(b))));
        }
        final byte[] eight = bytes(0x03, 0x02, 0x08, 0xff);
        assertEquals(BITS, reason(() -> AttestCert.checkBitString(eight, elemAny(eight))));
        final byte[] notBits = bytes(0x04, 0x01, 0x00);
        assertEquals(WRONG_TAG, reason(() -> AttestCert.checkBitString(notBits, elemAny(notBits))));
        final byte[] empty = bytes(0x03, 0x00);
        assertEquals(WRONG_TAG, reason(() -> AttestCert.checkBitString(empty, elemAny(empty))));
        final byte[] one = bytes(0x03, 0x01, 0x00);
        assertEquals(OK, reason(() -> AttestCert.checkBitString(one, elemAny(one))));
    }

    static String nameCheck(byte[] n) { return reason(() -> AttestCert.checkName(n, AttestCert.readCertElem(n, 0, n.length, 0x30))); }

    @Test void nameStructure() {
        byte[] cn = oid("2.5.4.3");
        assertEquals(OK, nameCheck(name("x")));
        assertEquals(OK, nameCheck(seq()));
        assertEquals(OK, nameCheck(seq(withTag(0x31, seq(cn, utf8("a")), seq(cn, utf8("b"))), withTag(0x31, seq(cn, utf8("c"))))));
        for (int t : new int[] {0x0c, 0x12, 0x13, 0x14, 0x16, 0x1c, 0x1e, 0x03, 0x30}) {
            assertEquals(OK, nameCheck(seq(withTag(0x31, seq(cn, withTag(t, bytes(0x41)))))), "value tag " + t);
        }
        assertEquals(NESTED, nameCheck(seq(withTag(0x31, seq(cn, withTag(0x04, bytes(0x41)))))));
        assertEquals(WRONG_TAG, nameCheck(seq(seq(seq(cn, utf8("x")))))); // RDN not a SET
        assertEquals(WRONG_TAG, nameCheck(seq(withTag(0x31, withTag(0x31, cn, utf8("x")))))); // ATV not a SEQUENCE
        assertEquals(NESTED, nameCheck(seq(withTag(0x31, seq(cn, utf8("x"), utf8("y"))))));
        assertEquals(NESTED, nameCheck(seq(withTag(0x31, seq(cn)))));
        assertEquals(NESTED, nameCheck(seq(withTag(0x31, seq(octets(bytes(0x55)), utf8("x"))))));
    }

    // ------------------------------------------------------------- parseCertDer

    @Test void wholeParseResult() {
        byte[] block = extBlock(
            seq(oid("2.5.29.19"), bool(true), octets(seq())),
            seq(oid("1.2.3"), octets(bytes(5, 0))),
            seq(oid("1.2.4"), bytes(0x01, 0x01, 0x00), octets(bytes(7))),
            seq(oid("1.2.5"), bytes(0x01, 0x01, 0x01), octets(bytes())));
        byte[] tbs = tbsWith(block);
        byte[] der = certOf(tbs);
        AttCert c = AttestCert.parseCertDer(der);
        assertArrayEquals(der, c.raw);
        assertArrayEquals(tbs, c.rawTbs);
        assertArrayEquals(ISSUER, c.rawIssuer);
        assertArrayEquals(SUBJECT, c.rawSubject);
        assertArrayEquals(SPKI, c.rawSpki);
        assertArrayEquals(bytes(1, 2), c.serial);
        assertEquals("1.2.840.10045.4.3.2", c.sigOid);
        assertNull(c.sigParams);
        assertArrayEquals(bytes(9, 8, 7), c.signature);
        assertEquals("2.5.29.19:true:3000|1.2.3:false:0500|1.2.4:false:07|1.2.5:true:", exts(c));
        assertFalse(c.selfIssued());
    }

    @Test void v1CertificateWithoutVersionOrExtensions() {
        byte[] tbs = seq(SERIAL, ALG, ISSUER, VALIDITY, SUBJECT, SPKI);
        AttCert c = AttestCert.parseCertDer(certOf(tbs));
        assertArrayEquals(tbs, c.rawTbs);
        assertArrayEquals(bytes(1, 2), c.serial);
        assertEquals("", exts(c));
        assertEquals(OK, parse(tbsWith())); // v3 header, no extensions block
    }

    @Test void signatureParametersAndMinimalOuterLength() {
        byte[] alg = seq(oid("1.2.840.113549.1.1.11"), NULL);
        AttCert c = AttestCert.parseCertDer(seq(tbsWith(), alg, SIGBITS));
        assertEquals("1.2.840.113549.1.1.11", c.sigOid);
        assertArrayEquals(NULL, c.sigParams);

        byte[] content = cat(tbsWith(), ALG, SIGBITS);
        assertTrue(content.length >= 0x80 && content.length < 0x100);
        byte[] longForm = cat(bytes(0x30, 0x83, 0, 0, content.length), content);
        assertArrayEquals(cat(bytes(0x30, 0x81, content.length), content), AttestCert.parseCertDer(longForm).raw);
        // d2i_X509 ignores bytes after the certificate
        assertArrayEquals(cat(bytes(0x30, 0x81, content.length), content), AttestCert.parseCertDer(cat(longForm, bytes(0, 0))).raw);
    }

    @Test void tbsTamperMatrix() {
        assertEquals(NESTED, parse(seq(withTag(0xa0, integer(2), integer(0)), SERIAL, ALG, ISSUER, VALIDITY, SUBJECT, SPKI)));
        assertEquals(NESTED, parse(seq(V3, SERIAL, seq(integer(1)), ISSUER, VALIDITY, SUBJECT, SPKI)));
        assertEquals(WRONG_TAG, parse(seq(V3, SERIAL, ALG, ISSUER, VALIDITY, seq(seq(seq(oid("2.5.4.3"), utf8("x")))), SPKI)));
        assertEquals(WRONG_TAG, parse(seq(V3, SERIAL, ALG, seq(seq(seq(oid("2.5.4.3"), utf8("x")))), VALIDITY, SUBJECT, SPKI)));
    }

    static String withValidity(byte[] validity) { return parse(seq(V3, SERIAL, ALG, ISSUER, validity, SUBJECT, SPKI)); }

    @Test void validityShapes() {
        byte[] u = utc("250101000000Z");
        byte[] g = gtime("20350101000000Z");
        byte[] o = octets(bytes(1));
        assertEquals(OK, withValidity(seq(u, u)));
        assertEquals(OK, withValidity(seq(g, g)));
        assertEquals(OK, withValidity(seq(u, g)));
        assertEquals(OK, withValidity(seq(g, u)));
        assertEquals(NESTED, withValidity(seq(o, u)));
        assertEquals(NESTED, withValidity(seq(u, o)));
        assertEquals(NESTED, withValidity(seq(o, g)));
        assertEquals(NESTED, withValidity(seq(g, o)));
        assertEquals(NESTED, withValidity(seq(u)));
        assertEquals(NESTED, withValidity(seq(u, u, u)));
        assertEquals(NESTED, withValidity(seq()));
    }

    static String withSpki(byte[] spki) { return parse(seq(V3, SERIAL, ALG, ISSUER, VALIDITY, SUBJECT, spki)); }

    @Test void subjectPublicKeyInfoShapes() {
        byte[] ecAlg = seq(oid(OID_EC), oid("1.2.840.10045.3.1.7"));
        byte[] keyBits = bits((byte) 0, bytes(4, 1, 2));
        assertEquals(OK, withSpki(seq(ecAlg, keyBits)));
        assertEquals(NESTED, withSpki(seq(ecAlg)));
        assertEquals(NESTED, withSpki(seq(ecAlg, keyBits, NULL)));
        assertEquals(NESTED, withSpki(seq(withTag(0x31, oid(OID_EC)), keyBits)));
        assertEquals(NESTED, withSpki(seq(seq(integer(1)), keyBits)));
        assertEquals(BITS, withSpki(seq(ecAlg, bits((byte) 8, bytes(1)))));
        assertEquals(WRONG_TAG, withSpki(seq(ecAlg, octets(bytes(0, 1)))));
    }

    @Test void uniqueIdentifiers() {
        byte[] iu = withTag(0x81, bytes(0, 1));
        byte[] su = withTag(0x82, bytes(0, 2));
        byte[] block = extBlock(seq(oid("1.2.3"), octets(bytes(1))));
        assertEquals(OK, parse(tbsWith(iu)));
        assertEquals(OK, parse(tbsWith(su)));
        assertEquals(OK, parse(tbsWith(iu, su)));
        assertEquals(OK, parse(tbsWith(iu, su, block)));
        assertEquals("1.2.3:false:01", exts(AttestCert.parseCertDer(certOf(tbsWith(iu, su, block)))));
        assertEquals(NESTED, parse(tbsWith(su, iu))); // out of order
        assertEquals(NESTED, parse(tbsWith(iu, iu)));
        assertEquals(NESTED, parse(tbsWith(bytes(0x00, 0x00)))); // an element of tag 0 is not a TBS field
        assertEquals(NESTED, parse(tbsWith(block, integer(1)))); // nothing after the extensions
    }

    @Test void extensionTamperMatrix() {
        byte[] o = oid("1.2.3");
        byte[] v = octets(bytes(1));
        assertEquals(NESTED, parse(tbsWith(withTag(0xa3, seq(seq(o, v)), NULL))));
        assertEquals(WRONG_TAG, parse(tbsWith(withTag(0xa3, integer(1)))));
        assertEquals(WRONG_TAG, parse(tbsWith(extBlock(withTag(0x31, o, v)))));
        assertEquals(NESTED, parse(tbsWith(extBlock(seq(o)))));
        assertEquals(NESTED, parse(tbsWith(extBlock(seq(o, bool(true), v, v)))));
        assertEquals(NESTED, parse(tbsWith(extBlock(seq(v, v)))));
        assertEquals(NESTED, parse(tbsWith(extBlock(seq(bytes(0x06, 0x02, 0x2a, 0x81), v)))));
        assertEquals(NESTED, parse(tbsWith(extBlock(seq(o, integer(1), v)))));
        assertEquals(NESTED, parse(tbsWith(extBlock(seq(o, bytes(0x01, 0x02, 0xff, 0xff), v)))));
        assertEquals(NESTED, parse(tbsWith(extBlock(seq(o, bytes(0x01, 0x00), v)))));
        assertEquals(WRONG_TAG, parse(tbsWith(extBlock(seq(o, utf8("x"))))));
        assertEquals(WRONG_TAG, parse(tbsWith(extBlock(seq(o, bool(true), utf8("x"))))));
        assertEquals(OK, parse(tbsWith(extBlock())));
    }

    @Test void derLengthHeaderForms() {
        assertArrayEquals(bytes(0x30, 0x00), AttestCert.derLengthHeader(0x30, 0));
        assertArrayEquals(bytes(0x04, 0x7f), AttestCert.derLengthHeader(0x04, 0x7f));
        assertArrayEquals(bytes(0x30, 0x81, 0x80), AttestCert.derLengthHeader(0x30, 0x80));
        assertArrayEquals(bytes(0x30, 0x81, 0xff), AttestCert.derLengthHeader(0x30, 0xff));
        assertArrayEquals(bytes(0x30, 0x82, 0x01, 0x00), AttestCert.derLengthHeader(0x30, 0x100));
        assertArrayEquals(bytes(0x30, 0x82, 0x12, 0x34), AttestCert.derLengthHeader(0x30, 0x1234));
        assertArrayEquals(bytes(0x30, 0x82, 0xff, 0xff), AttestCert.derLengthHeader(0x30, 0xffff));
        assertArrayEquals(bytes(0x30, 0x83, 0x01, 0x00, 0x00), AttestCert.derLengthHeader(0x30, 0x10000));
        assertArrayEquals(bytes(0x30, 0x83, 0x12, 0x34, 0x56), AttestCert.derLengthHeader(0x30, 0x123456));
        assertArrayEquals(bytes(0x30, 0x83, 0xff, 0xff, 0xff), AttestCert.derLengthHeader(0x30, 0xffffff));
        assertArrayEquals(bytes(0x30, 0x84, 0x01, 0x00, 0x00, 0x00), AttestCert.derLengthHeader(0x30, 0x1000000));
        assertArrayEquals(bytes(0x31, 0x84, 0x12, 0x34, 0x56, 0x78), AttestCert.derLengthHeader(0x31, 0x12345678));
    }

    @Test void pemWhitespaceIsStripped() {
        byte[] der = certOf(tbsWith());
        String b64 = Base64.getEncoder().encodeToString(der);
        String body = b64.substring(0, 8) + " " + b64.substring(8, 16) + "\t" + b64.substring(16, 24) + "\r" + b64.substring(24, 32) + "\n"
            + b64.substring(32);
        AttCert c = AttestCert.certFromPem("x\n-----BEGIN CERTIFICATE-----" + body + "-----END CERTIFICATE-----\n");
        assertArrayEquals(der, c.raw);
        String withV = b64.substring(0, 8) + "\u000b" + b64.substring(8); // vertical tab is not stripped
        assertEquals(UNSUPPORTED, reason(() -> AttestCert.certFromPem("-----BEGIN CERTIFICATE-----" + withV + "-----END CERTIFICATE-----")));
        String trailing = Base64.getEncoder().encodeToString(cat(der, bytes(0, 0, 0)));
        assertEquals(NESTED, reason(() -> AttestCert.certFromPem("-----BEGIN CERTIFICATE-----" + trailing + "-----END CERTIFICATE-----")));
        assertEquals("error:0480006C:PEM routines::no start line", reason(() -> AttestCert.certFromPem(b64)));
    }

    // ------------------------------------------------------------- keyOfCert

    static AttCert spkiCert(byte[] spki) {
        AttCert c = new AttCert();
        c.rawSpki = spki;
        return c;
    }

    static byte[] dint(BigInteger v) { return withTag(0x02, v.toByteArray()); }

    static byte[] rsaSpki(String algOid, byte[] pkcs1) { return seq(seq(oid(algOid), NULL), bits((byte) 0, pkcs1)); }

    static String rsaKey(byte[] pkcs1) { return reason(() -> AttestCert.keyOfCert(spkiCert(rsaSpki(AttestCert.OID_RSA_ENCRYPTION, pkcs1)))); }

    @Test void rsaKeys() {
        RSAPublicKey rp = (RSAPublicKey) RSA.getPublic();
        BigInteger n = rp.getModulus();
        BigInteger e = rp.getPublicExponent();
        byte[] spki = rsaSpki(AttestCert.OID_RSA_ENCRYPTION, seq(dint(n), dint(e)));
        CertKey k = AttestCert.keyOfCert(spkiCert(spki));
        assertEquals("rsa", k.typ);
        assertEquals("", k.curve);
        assertSame(spki, k.spki);
        assertEquals(n, ((RSAPublicKey) k.pub).getModulus());
        assertEquals(e, ((RSAPublicKey) k.pub).getPublicExponent());

        CertKey pss = AttestCert.keyOfCert(spkiCert(seq(seq(oid(AttestCert.OID_RSA_PSS)), bits((byte) 0, seq(dint(n), dint(e))))));
        assertEquals("rsa-pss", pss.typ);
        assertEquals(n, ((RSAPublicKey) pss.pub).getModulus());

        // a one-byte exponent that ends the key
        CertKey three = AttestCert.keyOfCert(spkiCert(rsaSpki(AttestCert.OID_RSA_ENCRYPTION, seq(dint(n), dint(BigInteger.valueOf(3))))));
        assertEquals(BigInteger.valueOf(3), ((RSAPublicKey) three.pub).getPublicExponent());
        BigInteger e63 = BigInteger.ONE.shiftLeft(63).subtract(BigInteger.ONE);
        CertKey big = AttestCert.keyOfCert(spkiCert(rsaSpki(AttestCert.OID_RSA_ENCRYPTION, seq(dint(n), dint(e63)))));
        assertEquals(e63, ((RSAPublicKey) big.pub).getPublicExponent());
        assertEquals(UNSUPPORTED, rsaKey(seq(dint(n), dint(BigInteger.ONE.shiftLeft(63)))));
        assertEquals(UNSUPPORTED, rsaKey(seq(dint(n), dint(BigInteger.ONE.shiftLeft(63).add(BigInteger.ONE)))));

        // a redundant leading zero before a byte below 0x80 (the value itself is a usable modulus)
        byte[] nb = n.toByteArray(); // 0x00 then the 256 modulus bytes
        assertEquals(0, nb[0]);
        byte[] nonMinimal = cat(bytes(0x00, 0x7f), Arrays.copyOfRange(nb, 2, nb.length));
        assertEquals(UNSUPPORTED, rsaKey(seq(withTag(0x02, nonMinimal), dint(e))));
        assertEquals(UNSUPPORTED, rsaKey(seq(dint(n), withTag(0x02, bytes(0x00, 0x01, 0x00, 0x01)))));
        assertEquals(UNSUPPORTED, rsaKey(seq(withTag(0x02, bytes()), dint(e))));
        assertEquals(UNSUPPORTED, rsaKey(seq(dint(n), withTag(0x02, bytes()))));
        assertEquals(UNSUPPORTED, rsaKey(seq(dint(n.negate()), dint(e))));
        assertEquals(UNSUPPORTED, rsaKey(seq(dint(n), dint(e.negate()))));
        assertEquals(UNSUPPORTED, rsaKey(seq(dint(BigInteger.ZERO), dint(e))));
        assertEquals(UNSUPPORTED, rsaKey(seq(dint(n), dint(BigInteger.ZERO))));

        // RSAPublicKey structure
        assertEquals(UNSUPPORTED, rsaKey(withTag(0x31, dint(n), dint(e))));
        assertEquals(UNSUPPORTED, rsaKey(cat(seq(dint(n), dint(e)), bytes(0))));
        assertEquals(UNSUPPORTED, rsaKey(seq(withTag(0x04, nb), dint(e))));
        assertEquals(UNSUPPORTED, rsaKey(seq(dint(n), withTag(0x04, e.toByteArray()))));
        assertEquals(UNSUPPORTED, rsaKey(seq(dint(n), dint(e), dint(e))));
        assertEquals(UNSUPPORTED, rsaKey(seq(dint(n))));
        assertEquals(UNSUPPORTED, rsaKey(bytes(0x30, 0x81, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01))); // non-minimal / truncated
    }

    @Test void otherKeys() {
        CertKey ec = AttestCert.keyOfCert(spkiCert(SPKI));
        assertEquals("ec", ec.typ);
        assertEquals("prime256v1", ec.curve);
        assertEquals("secp384r1", AttestCert.keyOfCert(spkiCert(EC384.getPublic().getEncoded())).curve);
        CertKey ed = AttestCert.keyOfCert(spkiCert(ED.getPublic().getEncoded()));
        assertEquals("ed25519", ed.typ);
        assertEquals("", ed.curve);

        byte[] offCurve = SPKI.clone();
        offCurve[offCurve.length - 1] ^= 0x01;
        assertEquals(UNSUPPORTED, reason(() -> AttestCert.keyOfCert(spkiCert(offCurve))));
        assertEquals(UNSUPPORTED, reason(() -> AttestCert.keyOfCert(spkiCert(seq(seq(oid("1.2.3.4")), bits((byte) 0, bytes(1)))))));
        assertEquals(UNSUPPORTED, reason(() -> AttestCert.keyOfCert(spkiCert(seq(seq(oid(OID_EC), oid("1.2.840.10045.3.1.7")), bits((byte) 0, bytes(4, 1, 2)))))));
        assertEquals(NESTED, reason(() -> AttestCert.keyOfCert(spkiCert(seq(seq(oid(OID_EC)))))));
        assertEquals(NESTED, reason(() -> AttestCert.keyOfCert(spkiCert(seq(seq(oid(OID_EC)), bits((byte) 0, bytes(1)), NULL)))));
        assertEquals(WRONG_TAG, reason(() -> AttestCert.keyOfCert(spkiCert(NULL))));
    }

    // ------------------------------------------------------------- pssParams

    static byte[] hashAlg(String o) { return seq(oid(o), NULL); }

    static byte[] mgf(String hash) { return withTag(0xa1, seq(oid(MGF1), hashAlg(hash))); }

    static String pp(byte[] raw) {
        AttestCert.PssParams p = AttestCert.pssParams(raw);
        return p.hash + "/" + p.salt + "/" + p.ok;
    }

    @Test void pssParameterProfiles() {
        String bad = "SHA-1/20/false";
        assertEquals("SHA-1/20/true", pp(null));
        assertEquals("SHA-1/20/true", pp(new byte[0]));
        assertEquals("SHA-1/20/true", pp(seq()));
        assertEquals("SHA-256/32/true", pp(seq(withTag(0xa0, hashAlg(SHA256)), mgf(SHA256), withTag(0xa2, integer(32)))));
        assertEquals("SHA-384/48/true", pp(seq(withTag(0xa0, hashAlg(SHA384)), mgf(SHA384), withTag(0xa2, integer(48)), withTag(0xa3, integer(1)))));
        assertEquals("SHA-512/20/false", pp(seq(withTag(0xa0, hashAlg(SHA512)))));
        assertEquals("SHA-1/20/true", pp(seq(withTag(0xa0, hashAlg(SHA1)), mgf(SHA1))));
        assertEquals("SHA-256/32/false", pp(seq(withTag(0xa0, hashAlg(SHA256)), mgf(SHA1), withTag(0xa2, integer(32)))));
        assertEquals(bad, pp(seq(withTag(0xa0, hashAlg(SHA256), NULL))));
        assertEquals(bad, pp(seq(withTag(0xa0))));
        assertEquals(bad, pp(seq(withTag(0xa0, hashAlg("1.2.3")))));
        assertEquals(bad, pp(seq(withTag(0xa1, seq(oid("1.2.3"), hashAlg(SHA256))))));
        assertEquals(bad, pp(seq(withTag(0xa1, seq(oid(MGF1))))));
        assertEquals(bad, pp(seq(withTag(0xa1, seq(oid(MGF1), hashAlg("1.2.3"))))));
        assertEquals(bad, pp(seq(withTag(0xa2, octets(bytes(1))))));
        assertEquals("SHA-1/0/true", pp(seq(withTag(0xa2, integer(0)))));
        assertEquals("SHA-1/1048576/true", pp(seq(withTag(0xa2, integer(1048576)))));
        assertEquals(bad, pp(seq(withTag(0xa2, integer(1048577)))));
        assertEquals(bad, pp(seq(withTag(0xa2, withTag(0x02, BigInteger.ONE.shiftLeft(63).toByteArray())))));
        assertEquals("SHA-1/32/true", pp(seq(withTag(0xa2, integer(32)), withTag(0xa3, integer(1)))));
        assertEquals(bad, pp(seq(withTag(0xa3, integer(2)))));
        assertEquals(bad, pp(seq(withTag(0xa3, octets(bytes(1))))));
        assertEquals(bad, pp(seq(withTag(0xa4, integer(1)))));
        assertEquals(bad, pp(integer(1)));
        assertEquals(bad, pp(bytes(0x30, 0x05, 0x01)));
    }

    // ------------------------------------------------------------- certSigOk / certSigOkBy

    static final byte[] TBS = seq(integer(7), utf8("to be signed"));

    static AttCert signed(String sigOid, byte[] params, byte[] tbs, byte[] sig) {
        AttCert c = new AttCert();
        c.sigOid = sigOid;
        c.sigParams = params;
        c.rawTbs = tbs;
        c.signature = sig;
        return c;
    }

    static CertKey keyOf(KeyPair k) { return CertKey.of(k.getPublic(), k.getPublic().getEncoded()); }

    static byte[] flipLast(byte[] b) {
        byte[] c = b.clone();
        c[c.length - 1] ^= 0x01;
        return c;
    }

    @Test void ed25519Signatures() {
        byte[] sig = sign("Ed25519", ED.getPrivate(), TBS, null);
        assertTrue(AttestCert.certSigOk(signed(AttestCert.OID_ED25519, null, TBS, sig), keyOf(ED)));
        assertFalse(AttestCert.certSigOk(signed(AttestCert.OID_ED25519, null, TBS, flipLast(sig)), keyOf(ED)));
        assertFalse(AttestCert.certSigOk(signed(AttestCert.OID_ED25519, null, flipLast(TBS), sig), keyOf(ED)));
        assertFalse(AttestCert.certSigOk(signed(AttestCert.OID_ED25519, null, TBS, sig), keyOf(EC)));
        // the key type, not the JDK key, decides: an Ed25519 key not typed ed25519 is refused
        CertKey untyped = new CertKey(ED.getPublic(), "unknown", "", ED.getPublic().getEncoded());
        assertFalse(AttestCert.certSigOk(signed(AttestCert.OID_ED25519, null, TBS, sig), untyped));
        // an Ed25519 key under an ECDSA algorithm is neither EC nor RSA
        assertFalse(AttestCert.certSigOk(signed("1.2.840.10045.4.3.2", null, TBS, sig), keyOf(ED)));
    }

    @Test void ecdsaSignatures() {
        String[][] algs = {{"1.2.840.10045.4.3.2", "SHA256withECDSA"}, {"1.2.840.10045.4.3.3", "SHA384withECDSA"}, {"1.2.840.10045.4.3.4", "SHA512withECDSA"}};
        for (String[] a : algs) {
            byte[] sig = sign(a[1], EC.getPrivate(), TBS, null);
            assertTrue(AttestCert.certSigOk(signed(a[0], null, TBS, sig), keyOf(EC)), a[0]);
            assertFalse(AttestCert.certSigOk(signed(a[0], null, flipLast(TBS), sig), keyOf(EC)), a[0]);
        }
        byte[] sig = sign("SHA256withECDSA", EC.getPrivate(), TBS, null);
        assertFalse(AttestCert.certSigOk(signed("1.2.840.113549.1.1.11", null, TBS, sig), keyOf(EC))); // valid ECDSA under an RSA OID
        assertFalse(AttestCert.certSigOk(signed("1.2.840.10045.4.1", null, TBS, sig), keyOf(EC))); // unknown hash
        assertFalse(AttestCert.certSigOk(signed("1.2.840.10045.4.3.2", null, TBS, bytes(1)), keyOf(EC))); // not DER: the JDK throws
        assertFalse(AttestCert.certSigOk(signed("1.2.840.10045.4.3.2", null, TBS, sig), keyOf(EC384)));
    }

    @Test void rsaPkcs1Signatures() {
        String[][] algs = {{"1.2.840.113549.1.1.11", "SHA256withRSA"}, {"1.2.840.113549.1.1.12", "SHA384withRSA"}, {"1.2.840.113549.1.1.13", "SHA512withRSA"}};
        for (String[] a : algs) {
            byte[] sig = sign(a[1], RSA.getPrivate(), TBS, null);
            assertTrue(AttestCert.certSigOk(signed(a[0], null, TBS, sig), keyOf(RSA)), a[0]);
            assertFalse(AttestCert.certSigOk(signed(a[0], null, flipLast(TBS), sig), keyOf(RSA)), a[0]);
        }
        byte[] sig = sign("SHA256withRSA", RSA.getPrivate(), TBS, null);
        assertFalse(AttestCert.certSigOk(signed("1.2.840.10045.4.3.2", null, TBS, sig), keyOf(RSA))); // valid RSA under an ECDSA OID
        assertFalse(AttestCert.certSigOk(signed("1.2.840.113549.1.1.11", null, TBS, sig), keyOf(EC)));
    }

    @Test void rsaPssSignatures() {
        byte[] p256 = seq(withTag(0xa0, hashAlg(SHA256)), mgf(SHA256), withTag(0xa2, integer(32)));
        byte[] sig = sign("RSASSA-PSS", RSA.getPrivate(), TBS, new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        assertTrue(AttestCert.certSigOk(signed(AttestCert.OID_RSA_PSS, p256, TBS, sig), keyOf(RSA)));
        assertFalse(AttestCert.certSigOk(signed(AttestCert.OID_RSA_PSS, p256, flipLast(TBS), sig), keyOf(RSA)));
        assertFalse(AttestCert.certSigOk(signed(AttestCert.OID_RSA_PSS, p256, TBS, sig), keyOf(EC)));
        // MGF1 over a different hash: a profile this verifier does not check, even though the signature would verify under the main hash
        byte[] mixed = seq(withTag(0xa0, hashAlg(SHA256)), mgf(SHA1), withTag(0xa2, integer(32)));
        assertFalse(AttestCert.certSigOk(signed(AttestCert.OID_RSA_PSS, mixed, TBS, sig), keyOf(RSA)));
        // absent parameters: SHA-1, MGF1-SHA-1, salt 20
        byte[] sig1 = sign("RSASSA-PSS", RSA.getPrivate(), TBS, new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1));
        assertTrue(AttestCert.certSigOk(signed(AttestCert.OID_RSA_PSS, null, TBS, sig1), keyOf(RSA)));
        assertFalse(AttestCert.certSigOk(signed(AttestCert.OID_RSA_PSS, null, TBS, sig), keyOf(RSA)));
    }

    @Test void signatureByParentCertificate() {
        byte[] sig = sign("SHA256withECDSA", EC.getPrivate(), TBS, null);
        AttCert child = signed("1.2.840.10045.4.3.2", null, TBS, sig);
        assertTrue(AttestCert.certSigOkBy(child, spkiCert(SPKI)));
        assertFalse(AttestCert.certSigOkBy(child, spkiCert(EC384.getPublic().getEncoded())));
        assertFalse(AttestCert.certSigOkBy(child, spkiCert(NULL))); // the parent key cannot be read
    }

    // ------------------------------------------------------------- CertKey.of

    static PublicKey fake(String alg) {
        return new PublicKey() {
            @Override public String getAlgorithm() { return alg; }

            @Override public String getFormat() { return "X.509"; }

            @Override public byte[] getEncoded() { return new byte[0]; }
        };
    }

    @Test void keyClassification() {
        byte[] spki = bytes(1, 2, 3);
        assertEquals("ed25519", CertKey.of(fake("Ed25519"), spki).typ);
        assertEquals("ed25519", CertKey.of(fake("EdDSA"), spki).typ);
        assertEquals("ed25519", CertKey.of(fake("ed25519"), spki).typ);
        assertEquals("ed25519", CertKey.of(fake("EDDSA"), spki).typ);
        CertKey u = CertKey.of(fake("X25519"), spki);
        assertEquals("unknown", u.typ);
        assertEquals("", u.curve);
        assertSame(spki, u.spki);
        assertEquals("ed25519", CertKey.of(ED.getPublic(), spki).typ);
        assertEquals("rsa", CertKey.of(RSA.getPublic(), spki).typ);
        CertKey ec = CertKey.of(EC.getPublic(), spki);
        assertEquals("ec", ec.typ);
        assertEquals("prime256v1", ec.curve);
    }

    // ------------------------------------------------------------- AttCert extension readers

    static AttCert withExt(String extOid, byte[] value) {
        AttCert c = new AttCert();
        AttCert.LenientExt e = new AttCert.LenientExt();
        e.oid = extOid;
        e.value = value;
        c.exts.add(e);
        return c;
    }

    static final String AIA = "1.3.6.1.5.5.7.1.1";
    static final String OCSP = "1.3.6.1.5.5.7.48.1";

    static byte[] uri(int tag, String s) { return withTag(tag, s.getBytes(StandardCharsets.UTF_8)); }

    @Test void ocspResponderUrls() {
        byte[] aia = seq(
            seq(oid(OCSP), uri(0x86, "http://a")),
            seq(oid("1.3.6.1.5.5.7.48.2"), uri(0x86, "http://b")), // caIssuers
            seq(oid(OCSP), uri(0x82, "dns.example")), // not a URI
            seq(oid(OCSP)), // one part
            seq(oid(OCSP), uri(0x86, "http://x"), NULL), // three parts
            seq(integer(1), uri(0x86, "http://y")), // method is not an OID
            bytes(0x30, 0x02, 0x06, 0x05), // malformed description
            seq(oid(OCSP), uri(0x86, "http://c")));
        assertEquals(Arrays.asList("http://a", "http://c"), withExt(AIA, aia).ocspServers());

        List<String> none = new AttCert().ocspServers();
        assertTrue(none.isEmpty());
        none.add("caller-owned"); // a fresh mutable list
        assertEquals(1, none.size());
        List<String> malformed = withExt(AIA, bytes(0x04, 0x00)).ocspServers();
        assertTrue(malformed.isEmpty());
        malformed.add("caller-owned");
        assertEquals(1, malformed.size());
    }

    @Test void ocspSigningEku() {
        String eku = "2.5.29.37";
        assertTrue(withExt(eku, seq(oid("1.3.6.1.5.5.7.3.1"), integer(1), oid("1.3.6.1.5.5.7.3.9"))).hasOcspSigningEku());
        assertFalse(withExt(eku, seq(oid("1.3.6.1.5.5.7.3.1"))).hasOcspSigningEku());
        assertFalse(withExt(eku, seq(oid("1.3.6.1.5.5.7.3.1"), integer(1))).hasOcspSigningEku());
        assertFalse(withExt(eku, bytes(0x04, 0x00)).hasOcspSigningEku());
        assertFalse(withExt(eku, bytes(0x30, 0x02, 0x06, 0x05)).hasOcspSigningEku());
        assertFalse(new AttCert().hasOcspSigningEku());
    }

    @Test void serialHexDropsLeadingZeros() {
        AttCert c = new AttCert();
        c.serial = bytes(0, 0);
        assertEquals("", c.serialHex());
        c.serial = bytes(0x00, 0x1a);
        assertEquals("1a", c.serialHex());
        c.serial = bytes(0x10, 0x00);
        assertEquals("1000", c.serialHex());
    }
}
