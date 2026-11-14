package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

import org.bouncycastle.util.BigIntegers;
import org.junit.jupiter.api.Test;

/** Exact-outcome kill tests for the strict DER readers (AttestDer) and the shared attestation helpers (AttestCommon). */
public class AttestCommonDerK05KillTest {
    private static String reason(Runnable r) {
        try {
            r.run();
        } catch (AttestException e) {
            return e.getMessage();
        }
        return "no error";
    }

    private static byte[] bytes(int... v) {
        byte[] b = new byte[v.length];
        for (int i = 0; i < v.length; i++) b[i] = (byte) v[i];
        return b;
    }

    private static String hex(byte[] b) { return AttestCommon.toHexLower(b); }

    private static byte[] ascii(String s) { return s.getBytes(StandardCharsets.ISO_8859_1); }

    // ================================================================ AttestDer.readTlvStrict / tlvAt

    @Test void strictLengthForms() {
        // one length byte of 0: long form below 128 (it is not a "leading zero" of a multi-byte length)
        assertEquals("DER: non-minimal length (long form below 128)", reason(() -> AttestDer.readTlvStrict(bytes(0x04, 0x81, 0x00), 0, 3)));
        assertEquals("DER: non-minimal length (long form below 128)", reason(() -> AttestDer.readTlvStrict(bytes(0x04, 0x81, 0x7f), 0, 3)));
        byte[] b128 = new byte[3 + 128];
        b128[0] = 0x04;
        b128[1] = (byte) 0x81;
        b128[2] = (byte) 0x80;
        AttestDer.Tlv t = AttestDer.readTlvStrict(b128, 0, b128.length);
        assertEquals(4, t.tag);
        assertEquals(3, t.start);
        assertEquals(131, t.end);
        byte[] b256 = new byte[4 + 256];
        b256[0] = 0x04;
        b256[1] = (byte) 0x82;
        b256[2] = 0x01;
        b256[3] = 0x00;
        t = AttestDer.readTlvStrict(b256, 0, b256.length);
        assertEquals(4, t.start);
        assertEquals(260, t.end);
    }

    @Test void lenientTlvAt() {
        assertEquals("bad length", reason(() -> AttestDer.tlvAt(bytes(0x04, 0x80, 0), 0, 3)));
        assertEquals("bad length", reason(() -> AttestDer.tlvAt(bytes(0x04, 0x85, 0, 0, 0, 0, 1, 9), 0, 8)));
        AttestDer.Tlv t = AttestDer.tlvAt(bytes(0x04, 0x84, 0, 0, 0, 1, 9), 0, 7);
        assertEquals(4, t.tag);
        assertEquals(6, t.start);
        assertEquals(7, t.end);
        assertEquals("bad length", reason(() -> AttestDer.tlvAt(bytes(0x04, 0x82, 0x01), 0, 3)));
        // the length bytes may end exactly at the limit
        t = AttestDer.tlvAt(bytes(0x04, 0x81, 0x00), 0, 3);
        assertEquals(3, t.start);
        assertEquals(3, t.end);
        // non-minimal forms are accepted by the lenient reader
        t = AttestDer.tlvAt(bytes(0x04, 0x81, 0x01, 7), 0, 4);
        assertEquals(3, t.start);
        assertEquals(4, t.end);
        assertEquals("truncated", reason(() -> AttestDer.tlvAt(bytes(0x04, 0x02, 1), 0, 3)));
        assertEquals("truncated", reason(() -> AttestDer.tlvAt(bytes(0x04), 0, 1)));
        assertEquals("truncated", reason(() -> AttestDer.tlvAt(bytes(0x04, 0x01, 1, 0), 0, 2)));
        t = AttestDer.tlvAt(bytes(0x30, 0x01, 5), 0);
        assertEquals(0x30, t.tag);
        assertEquals(2, t.start);
        assertEquals(3, t.end);
    }

    // ================================================================ AttestDer.readCertRoleInfo

    private static AttestDer.CertRoleInfo role(byte[]... exts) { return AttestDer.readCertRoleInfo(roleCert(exts)); }

    @Test void roleInfoOidMatchIsExact() {
        byte[] bcValue = seq(bool(true), integer(3));
        byte[][] ids = {withTag(0x04, bytes(0x55, 0x1d, 0x13)), oid("2.5.29.19.1"), oid("2.6.29.19"), oid("2.5.29.20"), oid("2.5")};
        for (byte[] id : ids) {
            AttestDer.CertRoleInfo i = role(seq(id, octets(bcValue)));
            assertFalse(i.hasBasicConstraints, hex(id));
            assertFalse(i.ca, hex(id));
            assertEquals(-1, i.pathLen, hex(id));
            i = role(seq(id, octets(bits((byte) 2, new byte[] {0x04}))));
            assertFalse(i.hasKeyUsage, hex(id));
            assertFalse(i.keyCertSign, hex(id));
        }
        AttestDer.CertRoleInfo i = role(seq(oid("2.5.29.19"), octets(bcValue)));
        assertTrue(i.hasBasicConstraints);
        assertTrue(i.ca);
        assertEquals(3, i.pathLen);
    }

    @Test void roleInfoBasicConstraintsShapes() {
        assertEquals("certificate has no tbsCertificate", reason(() -> AttestDer.readCertRoleInfo(seq(integer(1)))));
        // pathLen without the cA BOOLEAN
        AttestDer.CertRoleInfo i = role(ext("2.5.29.19", true, seq(integer(0))));
        assertTrue(i.hasBasicConstraints);
        assertFalse(i.ca);
        assertEquals(0, i.pathLen);
        // an explicit cA FALSE, and a (non-DER) cA byte of 1
        i = role(ext("2.5.29.19", true, seq(bool(false))));
        assertTrue(i.hasBasicConstraints);
        assertFalse(i.ca);
        assertEquals(-1, i.pathLen);
        i = role(ext("2.5.29.19", true, seq(bytes(0x01, 0x01, 0x01))));
        assertTrue(i.ca);
        // two-byte pathLen values
        assertEquals(256, role(ext("2.5.29.19", true, seq(bool(true), integer(256)))).pathLen);
        assertEquals(200, role(ext("2.5.29.19", true, seq(bool(true), integer(200)))).pathLen);
        assertEquals(32767, role(ext("2.5.29.19", true, seq(bool(true), integer(32767)))).pathLen);
        assertEquals(127, role(ext("2.5.29.19", true, seq(bool(true), integer(127)))).pathLen);
        String malformed = "BasicConstraints pathLenConstraint malformed";
        assertEquals(malformed, reason(() -> role(ext("2.5.29.19", true, seq(bool(true), integer(70000))))));
        assertEquals(malformed, reason(() -> role(ext("2.5.29.19", true, seq(bool(true), bytes(0x02, 0x00))))));
        assertEquals(malformed, reason(() -> role(ext("2.5.29.19", true, seq(bool(true), octets(bytes(1)))))));
        assertEquals(malformed, reason(() -> role(ext("2.5.29.19", true, seq(bool(true), bytes(0x02, 0x01, 0x80))))));
        assertEquals(malformed, reason(() -> role(ext("2.5.29.19", true, seq(bool(true), bytes(0x02, 0x02, 0x80, 0x00))))));
    }

    @Test void roleInfoKeyUsageShapes() {
        assertEquals("keyUsage is not a BIT STRING", reason(() -> role(ext("2.5.29.15", true, bits((byte) 0, new byte[0])))));
        assertEquals("keyUsage is not a BIT STRING", reason(() -> role(ext("2.5.29.15", true, octets(bytes(0, 0x04))))));
        AttestDer.CertRoleInfo i = role(ext("2.5.29.15", true, bits((byte) 0, new byte[] {0x01})));
        assertTrue(i.hasKeyUsage);
        assertFalse(i.keyCertSign);
        i = role(ext("2.5.29.15", true, bits((byte) 0, new byte[] {0x04})));
        assertTrue(i.keyCertSign);
        i = role(ext("2.5.29.15", true, bits((byte) 0, new byte[] {(byte) 0xfb, (byte) 0xff})));
        assertFalse(i.keyCertSign);
    }

    // ================================================================ AttestDer.oidToDotted

    private static String dotted(int... body) {
        byte[] d = withTag(0x06, bytes(body));
        return AttestDer.oidToDotted(d, AttestDer.readTlvStrict(d, 0, d.length));
    }

    @Test void oidArcs() {
        assertEquals("extension OID has a non-minimal arc", reason(() -> dotted(0x80, 0x01)));
        assertEquals("2.16305", dotted(0x81, 0x80, 0x01)); // a 0x80 inside an open arc is fine
        assertEquals("0.39", dotted(0x27));
        assertEquals("1.0", dotted(0x28));
        assertEquals("1.39", dotted(0x4f));
        assertEquals("2.0", dotted(0x50));
        assertEquals("2.5.29.19", dotted(0x55, 0x1d, 0x13));
    }

    // ================================================================ AttestDer.parseDerTime

    @Test void derTimeEdges() {
        assertFalse(AttestDer.parseDerTime(0x17, "A00101000000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x18, "A0000101000000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x18, "2000010100000AZ").ok);
        assertFalse(AttestDer.parseDerTime(0x18, "20000101000000+").ok);
        assertFalse(AttestDer.parseDerTime(0x16, "20000101000000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x17, "20000101000000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x17, "7/0101000000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x17, "7:0101000000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x18, "2/000101000000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x18, "2:000101000000Z").ok);
        AttestDer.DerInstant d = AttestDer.parseDerTime(0x17, "991231235959Z");
        assertTrue(d.ok);
        assertEquals(946684799000L, d.ms);
        d = AttestDer.parseDerTime(0x18, "99991231235959Z");
        assertTrue(d.ok);
        assertEquals(253402300799000L, d.ms);
        for (String bad : new String[] {"20001301000000Z", "20000001000000Z", "20000100000000Z", "20000101240000Z", "20000101006000Z", "20000101000060Z", "20000230000000Z"}) {
            assertFalse(AttestDer.parseDerTime(0x18, bad).ok, bad);
        }
    }

    // ================================================================ AttestDer.derValidity / derValidAt

    private static final byte[] NB = withTag(0x17, ascii("250101000000Z"));
    private static final byte[] NA = withTag(0x17, ascii("250102000000Z"));
    private static final byte[] BAD_TIME = withTag(0x17, ascii("251301000000Z"));
    private static final byte[] VER = withTag(0xa0, integer(2));
    private static final long NB_MS = 1735689600000L;
    private static final long NA_MS = 1735776000000L;

    private static byte[] certOf(byte[]... tbsParts) { return seq(seq(tbsParts), SIG_ALG_ECDSA_SHA256, bits((byte) 0, bytes(1))); }

    private static void assertBad(byte[] der) {
        AttestDer.DerInstant[] v = AttestDer.derValidity(der);
        assertEquals(2, v.length, hex(der));
        assertFalse(v[0].ok, hex(der));
        assertFalse(v[1].ok, hex(der));
    }

    @Test void validityWalk() {
        byte[] ok = certOf(VER, integer(5), SIG_ALG_ECDSA_SHA256, name("i"), seq(NB, NA)); // validity ends the TBS
        AttestDer.DerInstant[] v = AttestDer.derValidity(ok);
        assertEquals(2, v.length);
        assertTrue(v[0].ok && v[1].ok);
        assertEquals(NB_MS, v[0].ms);
        assertEquals(NA_MS, v[1].ms);
        byte[] v1 = certOf(integer(5), SIG_ALG_ECDSA_SHA256, name("i"), seq(NB, NA), name("s")); // no [0] version
        v = AttestDer.derValidity(v1);
        assertTrue(v[0].ok && v[1].ok);
        assertEquals(NB_MS, v[0].ms);
        assertEquals(NA_MS, v[1].ms);

        assertBad(withTag(0x31, seq(VER, integer(5), SIG_ALG_ECDSA_SHA256, name("i"), seq(NB, NA))));
        assertBad(seq(withTag(0x31, VER, integer(5), SIG_ALG_ECDSA_SHA256, name("i"), seq(NB, NA)))); // a TBS that is not a SEQUENCE
        assertBad(certOf(VER, octets(bytes(5)), SIG_ALG_ECDSA_SHA256, name("i"), seq(NB, NA)));
        assertBad(certOf(VER, integer(5), oid("1.2.3"), name("i"), seq(NB, NA)));
        assertBad(certOf(VER, integer(5), SIG_ALG_ECDSA_SHA256, utf8("i"), seq(NB, NA)));
        assertBad(certOf(VER, integer(5), SIG_ALG_ECDSA_SHA256, name("i"), withTag(0x31, NB, NA)));
        assertBad(certOf(VER, integer(5), SIG_ALG_ECDSA_SHA256, name("i"), seq(NB, NA, NA)));
        assertBad(new byte[] {0x30, 0x00});
        // a TBS header that ends inside the validity
        byte[] content = cat(VER, integer(5), SIG_ALG_ECDSA_SHA256, name("i"), seq(NB, NA));
        byte[] shortTbs = cat(AttestCert.derLengthHeader(0x30, content.length - 5), content);
        assertBad(seq(shortTbs));
    }

    @Test void validAtNeedsBothBounds() {
        byte[] ok = certOf(VER, integer(5), SIG_ALG_ECDSA_SHA256, name("i"), seq(NB, NA));
        byte[] badAfter = certOf(VER, integer(5), SIG_ALG_ECDSA_SHA256, name("i"), seq(NB, BAD_TIME));
        byte[] badBefore = certOf(VER, integer(5), SIG_ALG_ECDSA_SHA256, name("i"), seq(BAD_TIME, NA));
        long huge = 10_000_000_000_000L;
        assertFalse(AttestDer.derValidAt(badAfter, NB_MS, huge));
        assertFalse(AttestDer.derValidAt(badBefore, NB_MS, 0));
        assertFalse(AttestDer.derValidAtF(badAfter, NB_MS, (double) huge));
        assertFalse(AttestDer.derValidAtF(badBefore, NB_MS, 0.0));
        // the window is inclusive at both ends
        assertTrue(AttestDer.derValidAt(ok, NB_MS, 0));
        assertTrue(AttestDer.derValidAt(ok, NA_MS, 0));
        assertTrue(AttestDer.derValidAtF(ok, NB_MS, 0.0));
        assertTrue(AttestDer.derValidAtF(ok, NA_MS, 0.0));
        assertFalse(AttestDer.derValidAtF(ok, NB_MS - 1, 0.0));
        assertFalse(AttestDer.derValidAtF(ok, NA_MS + 1, 0.0));
        assertTrue(AttestDer.derValidAtF(ok, NB_MS - 1, 1.0));
        assertFalse(AttestDer.derValidAtF(ok, NB_MS - 2, 1.5));
    }

    // ================================================================ AttestCommon: binding

    @Test void lengthPrefixIsBigEndian() {
        assertEquals("00000003616263", hex(AttestCommon.lengthPrefixed("abc")));
        assertEquals("00000002c3a9", hex(AttestCommon.lengthPrefixed("é")));
        int n = 0x01030507; // every length byte distinct and non-zero
        byte[] lp = AttestCommon.lengthPrefixed("a".repeat(n));
        assertEquals(4 + n, lp.length);
        assertEquals("01030507", hex(Arrays.copyOf(lp, 4)));
        assertEquals('a', lp[4 + n - 1]);
    }

    @Test void bindingBytesArePinned() throws Exception {
        double epoch = (double) 0x001F2E3D4C5B6A79L;
        byte[] got = AttestCommon.attestationBindingBytes(new AttestationBinding("hk", "g", epoch, "nonce-é"));
        byte[] pre = cat("atlas-pca/attest-bind/v1\0".getBytes(StandardCharsets.UTF_8),
            bytes(0, 0, 0, 2), ascii("hk"), bytes(0, 0, 0, 1), ascii("g"),
            bytes(0x00, 0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79),
            bytes(0, 0, 0, 8), "nonce-é".getBytes(StandardCharsets.UTF_8));
        assertEquals(hex(MessageDigest.getInstance("SHA-512").digest(pre)), hex(got));
        String msg = "binding: epoch must be a non-negative safe integer";
        for (double bad : new double[] {Double.NaN, 1.5, -1, 9007199254740992d, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY}) {
            assertEquals(msg, reason(() -> AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", bad, "n"))), String.valueOf(bad));
        }
        assertEquals(64, AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", 9007199254740991d, "n")).length);
        assertEquals(64, AttestCommon.attestationBindingBytes(new AttestationBinding("h", "g", 0, "n")).length);
    }

    @Test void azureReportDataTailStartsAt32() {
        byte[] rd = new byte[64];
        rd[32] = 1;
        assertEquals("report_data[32:64] is not zero (not an Azure runtime-data hash)",
            AttestCommon.checkAzureRuntimeDataBinding(rd, new byte[0], new AttestationBinding("h", "g", 1, "n")));
    }

    // ================================================================ AttestCommon: small helpers

    @Test void hexDecodePinned() {
        assertEquals("0aff", hex(AttestCommon.hexDecode("0AfF")));
        // a non-hex character decodes as Character.digit's -1 (callers check isHexString first)
        assertEquals("ff", hex(AttestCommon.hexDecode("0g")));
        assertEquals("f0", hex(AttestCommon.hexDecode("g0")));
        assertFalse(AttestCommon.isHexChars(""));
        assertFalse(AttestCommon.isHexString(""));
        assertTrue(AttestCommon.isHexChars("abc"));
        assertFalse(AttestCommon.isHexString("abc"));
    }

    @Test void jsSpaces() {
        int[] spaces = {'\t', '\n', 0x0b, '\f', '\r', ' ', 0xa0, 0x1680, 0x2000, 0x2005, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff};
        for (int r : spaces) assertTrue(AttestCommon.isJsSpace(r), Integer.toHexString(r));
        int[] not = {0x08, 0x0e, 0x1f, 'a', 0x85, 0x180e, 0x1fff, 0x200b, 0x2027, 0x202a, 0x205e, 0x2fff, 0xfefe};
        for (int r : not) assertFalse(AttestCommon.isJsSpace(r), Integer.toHexString(r));
        assertEquals("a b", AttestCommon.jsTrim("　  a b﻿ \t"));
    }

    @Test void nodeBase64() {
        assertEquals("41", hex(AttestCommon.nodeB64("QQ==")));
        // characters outside both alphabets are skipped
        assertEquals("41", hex(AttestCommon.nodeB64("Q[Q")));
        assertEquals("41", hex(AttestCommon.nodeB64("Q{Q")));
        assertEquals("41", hex(AttestCommon.nodeB64("Q:Q")));
        assertEquals("41", hex(AttestCommon.nodeB64("Q@Q`")));
        byte[] std = java.util.Base64.getDecoder().decode("AZaz09+/");
        assertEquals(hex(std), hex(AttestCommon.nodeB64("AZaz09+/")));
        assertEquals(hex(std), hex(AttestCommon.nodeB64("AZaz09-_")));
        byte[] all = java.util.Base64.getDecoder().decode("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        assertEquals(hex(all), hex(AttestCommon.nodeB64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")));
        assertEquals("", hex(AttestCommon.nodeB64("=QQ")));
    }

    @Test void jsonLenientErrors() {
        String bad = "{\"a\":";
        String want = null;
        try {
            Json.parseLenient(bad);
        } catch (IllegalArgumentException e) {
            want = e.getMessage();
        }
        assertNotNull(want);
        assertEquals(want, reason(() -> AttestCommon.jsonLenient(bad.getBytes(StandardCharsets.UTF_8))));
        assertEquals("JSON nesting too deep", reason(() -> AttestCommon.jsonLenient("[".repeat(2_000_000).getBytes(StandardCharsets.UTF_8))));
    }

    @Test void valueReaders() {
        assertEquals("x", AttestCommon.asStr("x"));
        assertNull(AttestCommon.asStr(1));
        assertNull(AttestCommon.asFinite(new Json.Num("abc")));
        assertNull(AttestCommon.asFinite(new Json.Num("NaN")));
        assertNull(AttestCommon.asFinite(new Json.Num("1e999")));
        assertEquals(Double.valueOf(2.5), AttestCommon.asFinite(new Json.Num("2.5")));
        assertEquals(Double.valueOf(1.5), AttestCommon.asFinite(1.5d));
        assertEquals(Double.valueOf(3.0), AttestCommon.asFinite(3));
        assertEquals(Double.valueOf(4.0), AttestCommon.asFinite(4L));
        assertNull(AttestCommon.asFinite(1.5f));
        assertNull(AttestCommon.asFinite("1"));
        assertNull(AttestCommon.asFinite(Double.NaN));
        assertNull(AttestCommon.asFinite(Double.POSITIVE_INFINITY));
        assertNull(AttestCommon.asFinite(Double.NEGATIVE_INFINITY));
        assertEquals("invalid", AttestCommon.errMsg(null));
        assertEquals("invalid", AttestCommon.errMsg(new RuntimeException()));
        assertEquals("boom", AttestCommon.errMsg(new RuntimeException("boom")));
        assertEquals("", AttestCommon.normSerial("000"));
        assertEquals("a1", AttestCommon.normSerial("00A1"));
        assertEquals("", AttestCommon.normSerial(""));
        assertEquals(Arrays.asList("abc", "d"), AttestCommon.lowerAll(Arrays.asList("AbC", "D")));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> AttestCommon.digest("NO-SUCH-DIGEST", new byte[0]));
        assertTrue(e.getCause() instanceof java.security.NoSuchAlgorithmException);
    }

    @Test void jsNumbers() {
        assertEquals("NaN", AttestCommon.jsNumString(Double.NaN));
        assertEquals("Infinity", AttestCommon.jsNumString(Double.POSITIVE_INFINITY));
        assertEquals("-Infinity", AttestCommon.jsNumString(Double.NEGATIVE_INFINITY));
        assertEquals("0", AttestCommon.jsNumString(-0.0));
        assertEquals("123.5", AttestCommon.jsNumString(123.5));
        assertEquals("-0.5", AttestCommon.jsNumString(-0.5));
        assertEquals("0.000001", AttestCommon.jsNumString(1e-6));
        assertEquals("1e+21", AttestCommon.jsNumString(1e21));
        assertEquals("-1e+21", AttestCommon.jsNumString(-1e21));
        assertEquals("1.2345e+21", AttestCommon.jsNumString(1.2345e21));
        assertEquals("1.5e-7", AttestCommon.jsNumString(1.5e-7));
        assertEquals("-1.5e-7", AttestCommon.jsNumString(-1.5e-7));
    }

    // ================================================================ AttestCommon: curves and keys

    private static ECPublicKey fakeKey(ECParameterSpec spec, ECPoint w) {
        return new ECPublicKey() {
            @Override public ECPoint getW() { return w; }
            @Override public ECParameterSpec getParams() { return spec; }
            @Override public String getAlgorithm() { return "EC"; }
            @Override public String getFormat() { return null; }
            @Override public byte[] getEncoded() { return null; }
        };
    }

    @Test void curveSpecs() {
        ECParameterSpec p256 = AttestCommon.jdkSpec("P-256");
        ECParameterSpec p384 = AttestCommon.jdkSpec("P-384");
        ECParameterSpec p521 = AttestCommon.jdkSpec("P-521");
        assertNotNull(p256);
        assertEquals(256, p256.getCurve().getField().getFieldSize());
        assertEquals(384, p384.getCurve().getField().getFieldSize());
        assertEquals(521, p521.getCurve().getField().getFieldSize());
        assertNull(AttestCommon.jdkSpec("P-999"));
        assertNull(AttestCommon.jdkSpec("secp256r1"));
        assertEquals("P-256", AttestCommon.ecCurveName(p256));
        assertEquals("P-384", AttestCommon.ecCurveName(p384));
        assertEquals("P-521", AttestCommon.ecCurveName(p521));
        assertEquals("prime256v1", AttestCommon.curveOpenSslName(p256));
        assertEquals("secp384r1", AttestCommon.curveOpenSslName(p384));
        assertEquals("secp521r1", AttestCommon.curveOpenSslName(p521));
        EllipticCurve c = p256.getCurve();
        ECParameterSpec[] near = {
            new ECParameterSpec(c, p256.getGenerator(), p256.getOrder(), 2),
            new ECParameterSpec(c, p256.getGenerator(), p256.getOrder().add(BigInteger.TWO), 1),
            new ECParameterSpec(c, new ECPoint(BigInteger.ONE, BigInteger.TWO), p256.getOrder(), 1),
            new ECParameterSpec(new EllipticCurve(c.getField(), c.getA().add(BigInteger.ONE), c.getB()), p256.getGenerator(), p256.getOrder(), 1),
        };
        for (ECParameterSpec s : near) {
            assertEquals("unknown", AttestCommon.ecCurveName(s));
            assertEquals("unknown", AttestCommon.curveOpenSslName(s));
        }
        assertEquals("unknown", AttestCommon.ecCurveName(null));
        assertFalse(AttestCommon.sameSpec(p256, null));
        assertFalse(AttestCommon.sameSpec(null, p256));
        assertTrue(AttestCommon.sameSpec(p256, AttestCommon.jdkSpec("P-256")));
    }

    @Test void pointsAndKeys() {
        ECPublicKey k = (ECPublicKey) ecKey("secp256r1").getPublic();
        BigInteger x = k.getW().getAffineX();
        BigInteger y = k.getW().getAffineY();
        assertTrue(AttestCommon.isOnCurve("P-256", x, y));
        assertFalse(AttestCommon.isOnCurve("P-256", x, y.add(BigInteger.ONE)));
        assertFalse(AttestCommon.isOnCurve("P-999", x, y));
        assertFalse(AttestCommon.isOnCurve("unknown", x, y));
        assertEquals(k.getW(), AttestCommon.ecKeyOf("P-256", x, y).getW());
        assertNull(AttestCommon.ecKeyOf("P-256", x, y.add(BigInteger.ONE)));
        assertNull(AttestCommon.ecKeyOf("P-999", x, y));
        byte[] pt = cat(bytes(4), BigIntegers.asUnsignedByteArray(32, x), BigIntegers.asUnsignedByteArray(32, y));
        assertEquals(k.getW(), AttestCommon.pointToKey("P-256", pt).getW());
        assertNull(AttestCommon.pointToKey("P-999", pt));
        byte[] pt5 = pt.clone();
        pt5[0] = 5;
        assertNull(AttestCommon.pointToKey("P-256", pt5));
        assertNull(AttestCommon.pointToKey("P-256", Arrays.copyOf(pt, 64)));
        assertNull(AttestCommon.pointToKey("P-384", pt));
    }

    private static String fixed(BigInteger v, int n) { return hex(BigIntegers.asUnsignedByteArray(n, v)); }

    @Test void ecPointOfKeyExact() throws Exception {
        ECPublicKey k = (ECPublicKey) ecKey("secp256r1").getPublic();
        CertKey ck = CertKey.of(k, k.getEncoded());
        assertEquals("04" + fixed(k.getW().getAffineX(), 32) + fixed(k.getW().getAffineY(), 32), hex(AttestCommon.ecPointOfKey(ck, "P-256")));
        ECPublicKey k384 = (ECPublicKey) ecKey("secp384r1").getPublic();
        CertKey ck384 = CertKey.of(k384, k384.getEncoded());
        assertEquals("04" + fixed(k384.getW().getAffineX(), 48) + fixed(k384.getW().getAffineY(), 48), hex(AttestCommon.ecPointOfKey(ck384, "P-384")));
        // another curve name than P-256 / P-384 has no coordinate width: only the 0x04 prefix
        ECPublicKey k521 = (ECPublicKey) ecKey("secp521r1").getPublic();
        assertEquals("04", hex(AttestCommon.ecPointOfKey(CertKey.of(k521, k521.getEncoded()), "P-521")));
        assertEquals("public key is not on P-384 (got P-256)", reason(() -> AttestCommon.ecPointOfKey(ck, "P-384")));
        assertEquals("public key is not EC (got rsa)", reason(() -> AttestCommon.ecPointOfKey(new CertKey(k, "rsa", "", k.getEncoded()), "P-256")));
        KeyPair ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        assertEquals("public key is not EC (got ec)", reason(() -> AttestCommon.ecPointOfKey(new CertKey(ed.getPublic(), "ec", "", ed.getPublic().getEncoded()), "P-256")));
        // a coordinate shorter than the field is left-padded with zeros
        ECPublicKey shortX = null;
        for (int i = 0; i < 100000 && shortX == null; i++) {
            ECPublicKey c = (ECPublicKey) ecKey("secp256r1").getPublic();
            if (c.getW().getAffineX().bitLength() <= 248) shortX = c;
        }
        assertNotNull(shortX);
        byte[] p = AttestCommon.ecPointOfKey(CertKey.of(shortX, shortX.getEncoded()), "P-256");
        assertEquals(0, p[1]);
        assertEquals("04" + fixed(shortX.getW().getAffineX(), 32) + fixed(shortX.getW().getAffineY(), 32), hex(p));
    }

    @Test void rawEcdsa() throws Exception {
        KeyPair kp = ecKey("secp256r1");
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        byte[] msg = "m".getBytes(StandardCharsets.UTF_8);
        Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
        s.initSign(kp.getPrivate());
        s.update(msg);
        byte[] sig = s.sign();
        byte[] digest = AttestCommon.sha256Sum(msg);
        assertTrue(AttestCommon.verifyRawECDSA(pub, digest, sig));
        // r || 0x00 || s splits unevenly: refused although the halves would still read r and s
        byte[] padded = cat(Arrays.copyOf(sig, 32), bytes(0), Arrays.copyOfRange(sig, 32, 64));
        assertFalse(AttestCommon.verifyRawECDSA(pub, digest, padded));
        assertFalse(AttestCommon.verifyRawECDSA(pub, digest, new byte[0]));
        ECParameterSpec p256 = AttestCommon.jdkSpec("P-256");
        ECParameterSpec cof2 = new ECParameterSpec(p256.getCurve(), p256.getGenerator(), p256.getOrder(), 2);
        assertFalse(AttestCommon.verifyRawECDSA(fakeKey(cof2, pub.getW()), digest, sig)); // unknown curve
        assertTrue(AttestCommon.verifyRawECDSA(fakeKey(p256, pub.getW()), digest, sig));
        assertFalse(AttestCommon.verifyRawECDSA(fakeKey(p256, new ECPoint(BigInteger.ONE, BigInteger.ONE)), digest, sig)); // off the curve
    }

    // ================================================================ AttestCommon: names

    private static byte[] rdn(byte[]... atvs) { return withTag(0x31, atvs); }

    private static byte[] atv(String oid, int tag, byte[] val) { return seq(oid(oid), withTag(tag, val)); }

    private static String cn(int tag, byte[] val) { return AttestCommon.nameText(seq(rdn(atv("2.5.4.3", tag, val)))); }

    @Test void nameValueTypes() {
        // PrintableString: exactly its alphabet
        assertEquals("CN=azAZ09 '()\\+\\,-./:=?", cn(0x13, ascii("azAZ09 '()+,-./:=?")));
        assertEquals("CN=a", cn(0x13, ascii("a")));
        for (String bad : new String[] {"`", "{", "@", "[", "*", "!", "é", "_"}) assertEquals("", cn(0x13, ascii(bad)), bad);
        // IA5String: 7-bit only
        assertEquals("CN=a@b\\01", cn(0x16, bytes('a', '@', 'b', 0x01)));
        assertEquals("", cn(0x16, bytes('a', 0x80)));
        // NumericString: digits and space
        assertEquals("CN=0 9", cn(0x12, ascii("0 9")));
        for (String bad : new String[] {":", "/", "!", "a"}) assertEquals("", cn(0x12, ascii(bad)), bad);
        // T61String as Latin-1, UTF8String strictly decoded, BMPString as UTF-16BE pairs
        assertEquals("CN=é", cn(0x14, bytes(0xe9)));
        assertEquals("CN=é", cn(0x0c, bytes(0xc3, 0xa9)));
        assertEquals("", cn(0x0c, bytes(0xff)));
        assertEquals("CN=AB", cn(0x1e, bytes(0, 'A', 0, 'B')));
        assertEquals("", cn(0x1e, bytes(0, 'A', 0)));
        // any other value type prints as Go's fmt.Sprint(nil), then DN-escaped like every value (Go nameText)
        assertEquals("CN=\\<nil\\>", cn(0x04, ascii("x")));
        // a control character and DEL are hex-escaped
        assertEquals("CN=a\\7Fb\\1F", cn(0x0c, bytes('a', 0x7f, 'b', 0x1f)));
        assertEquals("a\\7Fb", AttestCommon.escapeDnValue("a\u007fb"));
    }

    @Test void nameStructure() {
        byte[] two = seq(rdn(atv("2.5.4.3", 0x0c, ascii("a")), atv("2.5.4.10", 0x0c, ascii("b"))), rdn(atv("2.5.4.6", 0x13, ascii("US"))), rdn(atv("1.2.3", 0x0c, ascii("v"))));
        assertEquals("CN=a + O=b\nC=US\n1.2.3=v", AttestCommon.nameText(two));
        byte[] one = seq(rdn(atv("2.5.4.3", 0x0c, ascii("a"))));
        assertEquals("CN=a", AttestCommon.nameText(one));
        assertEquals("", AttestCommon.nameText(cat(one, bytes(0))));
        assertEquals("", AttestCommon.nameText(withTag(0x31, rdn(atv("2.5.4.3", 0x0c, ascii("a"))))));
        assertEquals("", AttestCommon.nameText(seq(seq(atv("2.5.4.3", 0x0c, ascii("a"))))));
        assertEquals("", AttestCommon.nameText(seq(rdn(withTag(0x31, oid("2.5.4.3"), utf8("a"))))));
        assertEquals("", AttestCommon.nameText(seq(rdn(seq(oid("2.5.4.3"), utf8("a"), utf8("b"))))));
        assertEquals("", AttestCommon.nameText(bytes(0x30)));
        assertEquals("CN=x", AttestCommon.nameText(name("x")));
    }
}
