package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.bits;
import static net.atlasauth.pca.AttestTestDer.bool;
import static net.atlasauth.pca.AttestTestDer.ext;
import static net.atlasauth.pca.AttestTestDer.integer;
import static net.atlasauth.pca.AttestTestDer.name;
import static net.atlasauth.pca.AttestTestDer.octets;
import static net.atlasauth.pca.AttestTestDer.oid;
import static net.atlasauth.pca.AttestTestDer.seq;
import static net.atlasauth.pca.AttestTestDer.withTag;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

/**
 * Two reference checks. A PKCS#1 v1.5 signature under an rsa-pss key is refused on every path. The issuer check and the
 * certificate parser match Node's X509Certificate.checkIssued and d2i, each case observed on Node 26.
 */
public class K05IssuerRsaPssTest {
    static final byte[] RSA_SHA256 = seq(oid("1.2.840.113549.1.1.11"), new byte[] {0x05, 0x00});
    static final byte[] RSA_SPKI_ALG = seq(oid(AttestCert.OID_RSA_ENCRYPTION), new byte[] {0x05, 0x00});
    static final byte[] PSS_SPKI_ALG = seq(oid(AttestCert.OID_RSA_PSS));
    static final byte[] FROM = withTag(0x17, "250101000000Z".getBytes(StandardCharsets.US_ASCII));
    static final byte[] TO = withTag(0x17, "350101000000Z".getBytes(StandardCharsets.US_ASCII));
    static final KeyPair RSA = rsa();
    static final byte[] DATA = "signed bytes".getBytes(StandardCharsets.US_ASCII);

    static KeyPair rsa() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            return g.generateKeyPair();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] pkcs1(byte[] data) {
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(RSA.getPrivate());
            s.update(data);
            return s.sign();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static CertKey rsaKey() { return CertKey.of(RSA.getPublic(), RSA.getPublic().getEncoded()); }

    static CertKey pssKey() { return rsaKey().withType("rsa-pss"); }

    /** A certificate with exactly this serial content and SubjectPublicKeyInfo, PKCS#1-signed by RSA. */
    static byte[] rsaSigned(byte[] serial, String sub, String iss, byte[] spki) {
        byte[] tbs = seq(withTag(0xa0, integer(2)), withTag(0x02, serial), RSA_SHA256, name(iss), seq(FROM, TO), name(sub), spki);
        return seq(tbs, RSA_SHA256, bits((byte) 0, pkcs1(tbs)));
    }

    static byte[] spki(byte[] alg) {
        RSAPublicKey k = (RSAPublicKey) RSA.getPublic();
        byte[] key = seq(withTag(0x02, k.getModulus().toByteArray()), withTag(0x02, k.getPublicExponent().toByteArray()));
        return seq(alg, bits((byte) 0, key));
    }

    // ---- PKCS#1 under an rsa-pss key ------------------------------------------------------------------------------------

    @Test void jwsRs256RefusesAnRsaPssKey() {
        byte[] sig = pkcs1(DATA);
        assertTrue(AttestJws.jwsRs256Ok(sig, DATA, rsaKey()), "control");
        assertFalse(AttestJws.jwsRs256Ok(sig, DATA, pssKey()));
    }

    @Test void crlsRefuseAnRsaPssKey() {
        byte[] sig = pkcs1(DATA);
        assertTrue(AttestIntelCollateral.crlSigOk(DATA, sig, rsaKey()), "control");
        assertFalse(AttestIntelCollateral.crlSigOk(DATA, sig, pssKey()));
        assertTrue(AttestNvidiaRim.crlSigOk(DATA, sig, rsaKey()), "control");
        assertFalse(AttestNvidiaRim.crlSigOk(DATA, sig, pssKey()));
    }

    @Test void aChainSignatureRefusesAnRsaPssIssuer() {
        AttCert child = AttestCert.parseCertDer(rsaSigned(new byte[] {5}, "Sub", "Int", spki(RSA_SPKI_ALG)));
        AttCert plain = AttestCert.parseCertDer(rsaSigned(new byte[] {6}, "Int", "Top", spki(RSA_SPKI_ALG)));
        AttCert pss = AttestCert.parseCertDer(rsaSigned(new byte[] {7}, "Int", "Top", spki(PSS_SPKI_ALG)));
        assertTrue(AttestCert.certSigOkBy(child, plain), "control");
        assertEquals("rsa-pss", AttestCert.keyOfCert(pss).typ);
        assertFalse(AttestCert.certSigOkBy(child, pss));
    }

    @Test void sigstoreRefusesAnRsaPssKey() throws Exception {
        Method m = Sigstore.class.getDeclaredMethod("sigOk", String.class, PublicKey.class, byte[].class, byte[].class);
        m.setAccessible(true);
        RSAPublicKey k = (RSAPublicKey) RSA.getPublic();
        PublicKey pss = KeyFactory.getInstance("RSASSA-PSS").generatePublic(new RSAPublicKeySpec(k.getModulus(), k.getPublicExponent()));
        byte[] sig = pkcs1(DATA);
        assertEquals(true, m.invoke(null, "sha256", k, DATA, sig), "control");
        assertEquals(false, m.invoke(null, "sha256", pss, DATA, sig));
    }

    @Test void ocspRefusesAnRsaPssKey() {
        byte[] sig = pkcs1(DATA);
        assertTrue(AttestNvidiaOcsp.sigOk("1.2.840.113549.1.1.11", DATA, sig, rsaKey()), "control");
        assertFalse(AttestNvidiaOcsp.sigOk("1.2.840.113549.1.1.11", DATA, sig, pssKey()));
    }

    // ---- the certificate serial ------------------------------------------------------------------------------------------

    @Test void aNonMinimalSerialIsRefusedAtParse() {
        byte[][] bad = {{0, 5}, {0, 0}, {0, 0, (byte) 0x80}, {(byte) 0xff, (byte) 0xff}, {(byte) 0xff, (byte) 0x80}};
        for (byte[] s : bad) {
            AttestException e = assertThrows(AttestException.class, () -> AttestCert.parseCertDer(rsaSigned(s, "Sub", "Int", spki(RSA_SPKI_ALG))));
            assertEquals(AttestCert.OSSL_NO_PEM, e.getMessage());
        }
        byte[][] good = {{0}, {5}, {(byte) 0xff}, {(byte) 0x80}, {0, (byte) 0x80}, {(byte) 0xff, 0x7f}, {(byte) 0xff, 0}};
        for (byte[] s : good) assertEquals(s.length, AttestCert.parseCertDer(rsaSigned(s, "Sub", "Int", spki(RSA_SPKI_ALG))).serial.length);
    }

    // ---- X509Certificate.checkIssued ------------------------------------------------------------------------------------

    static final KeyPair EC = AttestTestDer.ecKey("secp256r1");
    static final byte[] ID = {1, 2, 3};
    static final byte[] KID = withTag(0x80, ID);
    static final byte[] DIR = withTag(0xa1, withTag(0xa4, name("Top")));
    static final byte[] SKI = ext("2.5.29.14", false, octets(ID));

    static AttCert parsed(byte[] der) { return AttestCert.parseCertDer(der); }

    static AttCert sub(byte[]... exts) { return parsed(AttestTestDer.cert("Sub", "Int", EC, EC, exts)); }

    static AttCert iss(byte[]... exts) { return parsed(AttestTestDer.cert("Int", "Top", EC, EC, exts)); }

    static byte[] aki(byte[]... members) { return ext("2.5.29.35", false, seq(members)); }

    static final AttCert ISSUER = iss(SKI);

    static boolean akidIssued(byte[]... members) { return AttestNvidiaOcsp.checkIssued(sub(aki(members)), ISSUER); }

    @Test void theAkidIsReadAsOpenSslDecodesIt() {
        byte[] serial = withTag(0x82, ISSUER.serial);
        assertTrue(akidIssued(KID, DIR, serial), "every member in order");
        assertTrue(akidIssued(), "empty");
        assertTrue(akidIssued(withTag(0xa1)), "empty names");
        assertFalse(akidIssued(KID, withTag(0x83, new byte[] {1})), "unknown context member");
        assertFalse(akidIssued(KID, new byte[] {0x05, 0x00}), "unknown universal member");
        assertFalse(akidIssued(serial, KID), "serial before key id");
        assertFalse(akidIssued(serial, DIR), "serial before names");
        assertFalse(akidIssued(DIR, KID), "names before key id");
        assertFalse(akidIssued(KID, KID), "duplicate key id");
        assertFalse(akidIssued(DIR, DIR), "duplicate names");
        assertFalse(akidIssued(serial, serial), "duplicate serial");
        assertFalse(akidIssued(withTag(0x82)), "empty serial");
        // the issuer's serial, padded: only the padding differs
        AttCert i5 = parsed(rsaSigned(new byte[] {5}, "Int", "Top", spki(RSA_SPKI_ALG)));
        assertTrue(AttestNvidiaOcsp.checkIssued(sub(aki(withTag(0x82, new byte[] {5}))), i5), "control");
        assertFalse(AttestNvidiaOcsp.checkIssued(sub(aki(withTag(0x82, new byte[] {0, 5}))), i5), "non-minimal serial");
        // a mismatch and a bad name
        assertFalse(akidIssued(withTag(0x82, new byte[] {(byte) 0xfb})), "another serial");
        assertFalse(akidIssued(withTag(0xa1, withTag(0xa4, name("Other")))), "another directory name");
        assertFalse(akidIssued(withTag(0xa1, withTag(0xa9))), "not a GeneralName tag");
        assertFalse(akidIssued(withTag(0xa1, withTag(0x84, new byte[] {1}))), "a primitive directoryName");
        assertFalse(akidIssued(withTag(0xa1, withTag(0xa4, name("Top")), withTag(0xa9))), "a bad name after the first directoryName");
        assertTrue(akidIssued(withTag(0xa1, withTag(0xa4, name("Top")), withTag(0xa4, name("Other")))), "only the first directoryName is compared");
        // the AKID of the issuer is decoded too
        assertFalse(AttestNvidiaOcsp.checkIssued(sub(), iss(aki(KID, withTag(0x83, new byte[] {1})))), "the issuer's own AKID");
    }

    // ---- Sigstore's issuer link: c.checkIssued(up) in the reference (pca-attest-eat/src/sigstore.ts:356) ---------------------

    static java.security.cert.X509Certificate x509(byte[] der) throws Exception {
        return (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(der));
    }

    static boolean namedBy(byte[] c, byte[] up) throws Exception {
        Method m = Sigstore.class.getDeclaredMethod("namedBy", java.security.cert.X509Certificate.class, java.security.cert.X509Certificate.class);
        m.setAccessible(true);
        return (Boolean) m.invoke(null, x509(c), x509(up));
    }

    static byte[] subDer(byte[]... exts) { return AttestTestDer.cert("Sub", "Int", EC, EC, exts); }

    @Test void sigstoresIssuerLinkIsCheckIssued() throws Exception {
        byte[] noSki = AttestTestDer.cert("Int", "Top", EC, EC), withSki = AttestTestDer.cert("Int", "Top", EC, EC, SKI);
        byte[] serial = AttestCert.parseCertDer(withSki).serial;
        assertTrue(namedBy(subDer(), withSki), "no AKID");
        assertTrue(namedBy(subDer(aki(KID, DIR, withTag(0x82, serial))), withSki), "every member");
        assertFalse(namedBy(AttestTestDer.cert("Sub", "Else", EC, EC), withSki), "another issuer name");
        assertFalse(namedBy(subDer(aki(withTag(0x80, new byte[] {9}))), withSki), "another key id");
        assertTrue(namedBy(subDer(aki(withTag(0x80, new byte[] {9}))), noSki), "no SKI: the key id is not compared");
        assertFalse(namedBy(subDer(aki(withTag(0x82, new byte[] {9}))), withSki), "another serial");
        assertFalse(namedBy(subDer(aki(withTag(0x82, new byte[] {9}))), noSki), "another serial, no SKI");
        assertFalse(namedBy(subDer(aki(withTag(0xa1, withTag(0xa4, name("Other"))))), noSki), "another directory name");
        assertFalse(namedBy(subDer(aki(KID, withTag(0x83, new byte[] {1}))), withSki), "unknown member");
        assertFalse(namedBy(subDer(aki(KID)), AttestTestDer.cert("Int", "Top", EC, EC, SKI, AttestTestDer.keyUsageDigitalSignature())), "no keyCertSign");
        assertTrue(namedBy(subDer(aki(KID)), AttestTestDer.cert("Int", "Top", EC, EC, SKI, AttestTestDer.keyUsageCertSign())), "keyCertSign");
        // PKCS#1 under an rsa-pss key
        byte[] child = rsaSigned(new byte[] {5}, "Sub", "Int", spki(RSA_SPKI_ALG));
        assertTrue(namedBy(child, rsaSigned(new byte[] {6}, "Int", "Top", spki(RSA_SPKI_ALG))), "control");
        assertFalse(namedBy(child, rsaSigned(new byte[] {6}, "Int", "Top", spki(PSS_SPKI_ALG))));
    }

    static final String[] SHAPED = {"2.5.29.15", "2.5.29.19", "2.5.29.37", "2.5.29.17", "2.5.29.30", "2.5.29.31"};

    /** Each case on the subject and on the issuer: OpenSSL marks either certificate invalid. */
    static void shape(boolean want, String label, String o, byte[] value) {
        byte[] e = ext(o, false, value);
        assertEquals(want, AttestNvidiaOcsp.checkIssued(sub(e), iss()), "subject " + label);
        assertEquals(want, AttestNvidiaOcsp.checkIssued(sub(), iss(e)), "issuer " + label);
    }

    @Test void aMalformedDecodedExtensionIsRefused() {
        byte[] notIt = withTag(0x04, new byte[] {1});
        for (String o : SHAPED) shape(false, o + " wrong outer tag", o, notIt);
        shape(false, "SKI not an octet string", "2.5.29.14", new byte[] {0x05, 0x00});
        shape(true, "SKI empty", "2.5.29.14", octets(new byte[0]));
        // keyUsage: the subject's only needs the shape; an issuer's must also allow certSign
        byte[] certSign = bits((byte) 2, new byte[] {0x04});
        shape(true, "keyUsage", "2.5.29.15", certSign);
        shape(false, "keyUsage no bits", "2.5.29.15", withTag(0x03, new byte[] {0}));
        shape(false, "keyUsage eight unused", "2.5.29.15", withTag(0x03, new byte[] {8, (byte) 0x80}));
        shape(true, "keyUsage two bytes", "2.5.29.15", withTag(0x03, new byte[] {2, 0x04, 0x00}));
        assertTrue(AttestNvidiaOcsp.checkIssued(sub(ext("2.5.29.15", false, withTag(0x03, new byte[] {7, (byte) 0x80}))), iss()), "seven unused bits");
        // basicConstraints
        shape(true, "BC empty", "2.5.29.19", seq());
        shape(true, "BC cA", "2.5.29.19", seq(bool(true)));
        shape(true, "BC pathLen", "2.5.29.19", seq(integer(1)));
        shape(true, "BC both", "2.5.29.19", seq(bool(true), integer(1)));
        shape(false, "BC negative pathLen", "2.5.29.19", seq(bool(true), integer(-1)));
        shape(false, "BC empty pathLen", "2.5.29.19", seq(bool(true), withTag(0x02)));
        shape(false, "BC reversed", "2.5.29.19", seq(integer(1), bool(true)));
        shape(false, "BC extra", "2.5.29.19", seq(bool(true), integer(1), new byte[] {0x05, 0x00}));
        // extendedKeyUsage
        shape(true, "EKU empty", "2.5.29.37", seq());
        shape(true, "EKU", "2.5.29.37", seq(oid("1.3.6.1.5.5.7.3.9"), oid("1.2.3")));
        shape(false, "EKU not an OID", "2.5.29.37", seq(oid("1.2.3"), integer(1)));
        // subjectAltName: an empty string form decodes, an empty structured one does not (Node, issuer-link table in K05IssuerLinkTableTest)
        Function<Integer, byte[]> san = t -> seq(withTag(t, new byte[0]));
        for (int t : new int[] {0x81, 0x82, 0x86, 0x87}) shape(true, "SAN tag " + t, "2.5.29.17", san.apply(t));
        for (int t : new int[] {0xa0, 0xa4, 0xa5, 0x88}) shape(false, "SAN empty tag " + t, "2.5.29.17", san.apply(t));
        shape(false, "SAN bad tag", "2.5.29.17", san.apply(0xa9));
        shape(false, "SAN primitive directoryName", "2.5.29.17", san.apply(0x84));
        shape(false, "SAN [1] not a SEQUENCE", "2.5.29.17", withTag(0xa1, withTag(0x82, new byte[0])));
        shape(true, "SAN empty", "2.5.29.17", seq());
        // name constraints and CRL distribution points
        shape(true, "NC", "2.5.29.30", seq());
        shape(true, "CDP", "2.5.29.31", seq());
        // not decoded by this check
        shape(true, "an unknown extension", "1.2.3.4", notIt);
    }
}
