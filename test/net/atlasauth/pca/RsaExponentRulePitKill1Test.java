package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.oid;
import static net.atlasauth.pca.AttestTestDer.seq;
import static net.atlasauth.pca.AttestTestDer.withTag;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * The RSA public-key rule (modulus 512..16384 bits, exponent odd, 3..32 bits) at every place a signature is checked under a certificate or JWK key.
 * A key with an EVEN exponent is not invertible, but a signature can still be constructed for it from the two primes (a fourth root of the encoded
 * message modulo each prime); the JDK verifies such a signature, so only this rule refuses it. The same bytes under an ordinary key verify.
 */
public class RsaExponentRulePitKill1Test {
    static final BigInteger FOUR = BigInteger.valueOf(4), ONE = BigInteger.ONE;

    /** An RSA public key whose exponent is whatever the test says. */
    static final class RsaKey implements RSAPublicKey {
        private static final long serialVersionUID = 1L;
        final BigInteger n, e;

        RsaKey(BigInteger n, long e) { this(n, BigInteger.valueOf(e)); }

        RsaKey(BigInteger n, BigInteger e) { this.n = n; this.e = e; }

        @Override public BigInteger getModulus() { return n; }
        @Override public BigInteger getPublicExponent() { return e; }
        @Override public String getAlgorithm() { return "RSA"; }
        @Override public String getFormat() { return "X.509"; }
        @Override public byte[] getEncoded() {
            byte[] pkcs1 = seq(withTag(0x02, n.toByteArray()), withTag(0x02, e.toByteArray()));
            return seq(seq(oid("1.2.840.113549.1.1.1"), new byte[] {5, 0}), AttestTestDer.bits((byte) 0, pkcs1));
        }
    }

    /** Two primes congruent to 3 mod 4: x -> x^4 is then invertible on the quadratic residues. */
    static final class Rabin {
        final BigInteger p, q, n;

        Rabin() {
            Random rnd = new Random(20260101L);
            BigInteger a, c;
            do { a = BigInteger.probablePrime(512, rnd); } while (a.mod(FOUR).intValue() != 3);
            do { c = BigInteger.probablePrime(512, rnd); } while (c.mod(FOUR).intValue() != 3 || c.equals(a));
            p = a;
            q = c;
            n = p.multiply(q);
        }

        int len() { return (n.bitLength() + 7) / 8; }

        private static boolean residue(BigInteger m, BigInteger pr) { return m.mod(pr).modPow(pr.subtract(ONE).shiftRight(1), pr).equals(ONE); }

        private static BigInteger root4(BigInteger m, BigInteger pr) {
            BigInteger e = pr.add(ONE).shiftRight(2);
            return m.mod(pr).modPow(e, pr).modPow(e, pr);
        }

        /** s with s^4 = m mod n, or null when m is not a quartic residue under this construction. */
        byte[] fourthRoot(BigInteger m) {
            if (!residue(m, p) || !residue(m, q)) return null;
            BigInteger sp = root4(m, p), sq = root4(m, q);
            BigInteger s = sp.multiply(q).multiply(q.modInverse(p)).add(sq.multiply(p).multiply(p.modInverse(q))).mod(n);
            if (!s.modPow(FOUR, n).equals(m.mod(n))) return null;
            return fixed(s, len());
        }
    }

    static final Rabin R = new Rabin();

    static byte[] fixed(BigInteger v, int len) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[len];
        int copy = Math.min(raw.length, len);
        System.arraycopy(raw, raw.length - copy, out, len - copy, copy);
        return out;
    }

    static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) d.update(p);
            return d.digest();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    /** A message variant and a PKCS#1 v1.5 / SHA-256 signature over it valid under the even exponent 4. */
    static byte[][] signPkcs1(String label) {
        byte[] prefix = hex("3031300d060960864801650304020105000420");
        int k = R.len();
        for (int i = 0; i < 400; i++) {
            byte[] msg = (label + "#" + i).getBytes(StandardCharsets.UTF_8);
            byte[] h = sha256(msg);
            byte[] em = new byte[k];
            em[1] = 1;
            Arrays.fill(em, 2, k - prefix.length - h.length - 1, (byte) 0xff);
            System.arraycopy(prefix, 0, em, k - prefix.length - h.length, prefix.length);
            System.arraycopy(h, 0, em, k - h.length, h.length);
            byte[] sig = R.fourthRoot(new BigInteger(1, em));
            if (sig != null) return new byte[][] {msg, sig};
        }
        throw new IllegalStateException("no quartic residue found");
    }

    static byte[] mgf1(byte[] seed, int len) {
        byte[] out = new byte[len];
        for (int c = 0, off = 0; off < len; c++) {
            byte[] h = sha256(seed, new byte[] {(byte) (c >>> 24), (byte) (c >>> 16), (byte) (c >>> 8), (byte) c});
            int n = Math.min(h.length, len - off);
            System.arraycopy(h, 0, out, off, n);
            off += n;
        }
        return out;
    }

    /** A message variant and an RSASSA-PSS (SHA-256, MGF1-SHA-256, salt 32) signature over it valid under the even exponent 4. */
    static byte[][] signPss(String label) {
        int emBits = R.n.bitLength() - 1, emLen = (emBits + 7) / 8;
        for (int i = 0; i < 400; i++) {
            byte[] msg = (label + "#" + i).getBytes(StandardCharsets.UTF_8);
            byte[] salt = sha256(msg, "salt".getBytes(StandardCharsets.UTF_8));
            byte[] h = sha256(new byte[8], sha256(msg), salt);
            byte[] db = new byte[emLen - 32 - 1];
            db[db.length - 33] = 1;
            System.arraycopy(salt, 0, db, db.length - 32, 32);
            byte[] mask = mgf1(h, db.length);
            for (int j = 0; j < db.length; j++) db[j] ^= mask[j];
            db[0] &= (byte) (0xff >>> (8 * emLen - emBits));
            byte[] em = new byte[emLen];
            System.arraycopy(db, 0, em, 0, db.length);
            System.arraycopy(h, 0, em, db.length, 32);
            em[emLen - 1] = (byte) 0xbc;
            byte[] sig = R.fourthRoot(new BigInteger(1, em));
            if (sig != null) return new byte[][] {msg, sig};
        }
        throw new IllegalStateException("no quartic residue found");
    }

    static CertKey even() {
        RsaKey k = new RsaKey(R.n, 4);
        return new CertKey(k, "rsa", "", k.getEncoded());
    }

    /** An ordinary RSA key pair and a SHA-256 PKCS#1 signature by it. */
    static final class Ordinary {
        final KeyPair kp;
        final byte[] msg = "ordinary message".getBytes(StandardCharsets.UTF_8);
        final byte[] sig;

        Ordinary() throws Exception {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(1024);
            kp = g.generateKeyPair();
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(kp.getPrivate());
            s.update(msg);
            sig = s.sign();
        }

        CertKey key(String typ) { return new CertKey(kp.getPublic(), typ, "", kp.getPublic().getEncoded()); }
    }

    static boolean jcaVerifies(PublicKey k, byte[] msg, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(k);
        s.update(msg);
        return s.verify(sig);
    }

    // ---- CertKey ---------------------------------------------------------------------------------------------------------

    @Test void theRuleItself() throws Exception {
        assertTrue(CertKey.rsaKeyOk(new RsaKey(R.n, 3)));
        assertTrue(CertKey.rsaKeyOk(new RsaKey(R.n, 65537)));
        assertTrue(CertKey.rsaKeyOk(new RsaKey(R.n, 0xffffffffL)));
        assertFalse(CertKey.rsaKeyOk(new RsaKey(R.n, 4)));
        assertFalse(CertKey.rsaKeyOk(new RsaKey(R.n, 2)));
        assertFalse(CertKey.rsaKeyOk(new RsaKey(R.n, 1)));
        assertFalse(CertKey.rsaKeyOk(new RsaKey(R.n, 0x100000001L)));
        assertFalse(CertKey.rsaKeyOk(new RsaKey(BigInteger.ONE.shiftLeft(510).add(BigInteger.valueOf(15)), 65537)));
        assertTrue(CertKey.rsaKeyOk(new RsaKey(BigInteger.ONE.shiftLeft(511).add(BigInteger.valueOf(15)), 65537)));
        assertFalse(CertKey.rsaKeyOk(new RsaKey(BigInteger.ONE.shiftLeft(16384).add(BigInteger.valueOf(15)), 65537)));
        assertTrue(CertKey.rsaKeyOk(new RsaKey(BigInteger.ONE.shiftLeft(16383).add(BigInteger.valueOf(15)), 65537)));
        // a key of another type is not this rule's business
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(256);
        assertTrue(CertKey.rsaKeyOk(ec.generateKeyPair().getPublic()));
    }

    @Test void withTypeKeepsTheKeyRestrictions() {
        CertKey k = even();
        k.keyPss = new AttestCert.PssParams();
        k.keyPss.salt = 7;
        CertKey t = k.withType("rsa-pss");
        assertEquals("rsa-pss", t.typ);
        assertSame(k.keyPss, t.keyPss);
        assertSame(k.pub, t.pub);
        assertSame(k.spki, t.spki);
    }

    @Test void theConstructedSignatureIsOneTheJdkAccepts() throws Exception {
        byte[][] ms = signPkcs1("sanity");
        assertTrue(jcaVerifies(new RsaKey(R.n, 4), ms[0], ms[1]), "the even-exponent signature must verify without the rule");
    }

    // ---- the verifiers ---------------------------------------------------------------------------------------------------

    @Test void jwsRs256RefusesAnEvenExponentAndAPssTypedKey() throws Exception {
        byte[][] ms = signPkcs1("jws");
        assertFalse(AttestJws.jwsRs256Ok(ms[1], ms[0], even()));
        Ordinary o = new Ordinary();
        assertTrue(AttestJws.jwsRs256Ok(o.sig, o.msg, o.key("rsa")));
        assertFalse(AttestJws.jwsRs256Ok(o.sig, o.msg, o.key("rsa-pss")));
        assertFalse(AttestJws.jwsRs256Ok(o.sig, o.msg, o.key("ec")));
        assertFalse(AttestJws.jwsRs256Ok(o.sig, "other".getBytes(StandardCharsets.UTF_8), o.key("rsa")));
    }

    @Test void crlSignaturesRefuseAnEvenExponentAndAPssTypedKey() throws Exception {
        byte[][] ms = signPkcs1("crl");
        Ordinary o = new Ordinary();
        assertFalse(AttestIntelCollateral.crlSigOk(ms[0], ms[1], even()));
        assertTrue(AttestIntelCollateral.crlSigOk(o.msg, o.sig, o.key("rsa")));
        assertFalse(AttestIntelCollateral.crlSigOk(o.msg, o.sig, o.key("rsa-pss")));
        assertFalse(AttestNvidiaRim.crlSigOk(ms[0], ms[1], even()));
        assertTrue(AttestNvidiaRim.crlSigOk(o.msg, o.sig, o.key("rsa")));
        assertFalse(AttestNvidiaRim.crlSigOk(o.msg, o.sig, o.key("rsa-pss")));
    }

    @Test void ocspSignaturesRefuseAnEvenExponentAWrongFamilyAndAPssTypedKey() throws Exception {
        byte[][] ms = signPkcs1("ocsp");
        Ordinary o = new Ordinary();
        String rsa = "1.2.840.113549.1.1.11", ec = "1.2.840.10045.4.3.2";
        assertFalse(AttestNvidiaOcsp.sigOk(rsa, ms[0], ms[1], even()));
        assertTrue(AttestNvidiaOcsp.sigOk(rsa, o.msg, o.sig, o.key("rsa")));
        assertFalse(AttestNvidiaOcsp.sigOk(rsa, o.msg, o.sig, o.key("rsa-pss")));
        assertFalse(AttestNvidiaOcsp.sigOk(ec, o.msg, o.sig, o.key("rsa")), "an ECDSA algorithm identifier under an RSA key");
        assertFalse(AttestNvidiaOcsp.sigOk("1.2.3", o.msg, o.sig, o.key("rsa")));
    }

    static AttCert child(String sigOid, byte[] tbs, byte[] sig, byte[] params) {
        AttCert c = new AttCert();
        c.sigOid = sigOid;
        c.rawTbs = tbs;
        c.signature = sig;
        c.sigParams = params;
        return c;
    }

    @Test void certificateSignaturesRefuseAnEvenExponentAWrongFamilyAndAPssTypedKey() throws Exception {
        byte[][] ms = signPkcs1("cert");
        Ordinary o = new Ordinary();
        String rsa = "1.2.840.113549.1.1.11", ec = "1.2.840.10045.4.3.2";
        assertFalse(AttestCert.certSigOk(child(rsa, ms[0], ms[1], null), even()));
        assertTrue(AttestCert.certSigOk(child(rsa, o.msg, o.sig, null), o.key("rsa")));
        assertFalse(AttestCert.certSigOk(child(rsa, o.msg, o.sig, null), o.key("rsa-pss")));
        assertFalse(AttestCert.certSigOk(child(ec, o.msg, o.sig, null), o.key("rsa")), "an ECDSA signature OID under an RSA key");
    }

    static final byte[] PSS_PARAMS = seq(withTag(0xa0, seq(oid("2.16.840.1.101.3.4.2.1"))),
        withTag(0xa1, seq(oid("1.2.840.113549.1.1.8"), seq(oid("2.16.840.1.101.3.4.2.1")))), withTag(0xa2, AttestTestDer.integer(32)));

    @Test void pssCertificateSignaturesRefuseAnEvenExponent() throws Exception {
        byte[][] ms = signPss("pss");
        // the construction itself: the JDK verifies the PSS signature under the even exponent
        Signature s = Signature.getInstance("RSASSA-PSS");
        s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        s.initVerify(new RsaKey(R.n, 4));
        s.update(ms[0]);
        assertTrue(s.verify(ms[1]), "the even-exponent PSS signature must verify without the rule");
        assertFalse(AttestCert.certSigOk(child(AttestCert.OID_RSA_PSS, ms[0], ms[1], PSS_PARAMS), even().withType("rsa-pss")));
        // an ordinary PSS signature under an ordinary key is accepted (the parameters parse)
        Ordinary o = new Ordinary();
        Signature sp = Signature.getInstance("RSASSA-PSS");
        sp.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        sp.initSign(o.kp.getPrivate());
        sp.update(o.msg);
        byte[] pssSig = sp.sign();
        assertTrue(AttestCert.certSigOk(child(AttestCert.OID_RSA_PSS, o.msg, pssSig, PSS_PARAMS), o.key("rsa-pss")));
        // a non-RSA key never verifies a PSS signature
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(256);
        PublicKey ecPub = g.generateKeyPair().getPublic();
        assertFalse(AttestCert.certSigOk(child(AttestCert.OID_RSA_PSS, o.msg, pssSig, PSS_PARAMS), CertKey.of(ecPub, ecPub.getEncoded())));
    }

    @Test void sigstoreSignaturesRefuseAnEvenExponent() throws Exception {
        Method m = Sigstore.class.getDeclaredMethod("sigOk", String.class, PublicKey.class, byte[].class, byte[].class);
        m.setAccessible(true);
        byte[][] ms = signPkcs1("sigstore");
        Ordinary o = new Ordinary();
        assertEquals(Boolean.FALSE, m.invoke(null, "sha256", new RsaKey(R.n, 4), ms[0], ms[1]));
        assertEquals(Boolean.TRUE, m.invoke(null, "sha256", o.kp.getPublic(), o.msg, o.sig));
        assertNotNull(R);
    }

    // ---- Sigstore.namedBy: a certificate whose issuer key breaks the rule does not name its signer ---------------------------

    /** A certificate that answers only what namedBy asks; the DER it hands out is a real, correctly linked pair. */
    static final class StubCert extends java.security.cert.X509Certificate {
        private static final long serialVersionUID = 1L;
        final javax.security.auth.x500.X500Principal subject, issuer;
        final PublicKey key;
        final byte[] der;
        final String sigOid;

        StubCert(String subject, String issuer, PublicKey key, byte[] der, String sigOid) {
            this.subject = new javax.security.auth.x500.X500Principal("CN=" + subject);
            this.issuer = new javax.security.auth.x500.X500Principal("CN=" + issuer);
            this.key = key;
            this.der = der;
            this.sigOid = sigOid;
        }

        @Override public javax.security.auth.x500.X500Principal getSubjectX500Principal() { return subject; }
        @Override public javax.security.auth.x500.X500Principal getIssuerX500Principal() { return issuer; }
        @Override public PublicKey getPublicKey() { return key; }
        @Override public String getSigAlgOID() { return sigOid; }
        @Override public byte[] getEncoded() { return der; }
        @Override public void checkValidity() {}
        @Override public void checkValidity(java.util.Date d) {}
        @Override public int getVersion() { return 3; }
        @Override public BigInteger getSerialNumber() { return BigInteger.ONE; }
        @Override public java.security.Principal getIssuerDN() { return issuer; }
        @Override public java.security.Principal getSubjectDN() { return subject; }
        @Override public java.util.Date getNotBefore() { return new java.util.Date(0); }
        @Override public java.util.Date getNotAfter() { return new java.util.Date(0); }
        @Override public byte[] getTBSCertificate() { return new byte[0]; }
        @Override public byte[] getSignature() { return new byte[0]; }
        @Override public String getSigAlgName() { return "SHA256withECDSA"; }
        @Override public byte[] getSigAlgParams() { return null; }
        @Override public boolean[] getIssuerUniqueID() { return null; }
        @Override public boolean[] getSubjectUniqueID() { return null; }
        @Override public boolean[] getKeyUsage() { return null; }
        @Override public int getBasicConstraints() { return -1; }
        @Override public void verify(PublicKey k) {}
        @Override public void verify(PublicKey k, String p) {}
        @Override public String toString() { return "stub"; }
        @Override public boolean hasUnsupportedCriticalExtension() { return false; }
        @Override public java.util.Set<String> getCriticalExtensionOIDs() { return null; }
        @Override public java.util.Set<String> getNonCriticalExtensionOIDs() { return null; }
        @Override public byte[] getExtensionValue(String oid) { return null; }
    }

    @Test void anIssuerWithAnEvenExponentKeyNamesNoOne() throws Exception {
        Method m = Sigstore.class.getDeclaredMethod("namedBy", java.security.cert.X509Certificate.class, java.security.cert.X509Certificate.class);
        m.setAccessible(true);
        byte[] interDer = AttestTestDer.cert("NV Inter", "NV Root", AttestNvidiaCrlCoverageTest.INTER, AttestNvidiaCrlCoverageTest.G.root, AttestNvidiaCrlCoverageTest.CA, AttestTestDer.keyUsageCertSign());
        byte[] rootDer = AttestNvidiaCrlCoverageTest.G.rootDer;
        assertTrue(AttestNvidiaOcsp.issuerLinkOk(AttestCert.parseCertDer(interDer), AttestCert.parseCertDer(rootDer)), "the real pair is linked");
        Ordinary o = new Ordinary();
        String ecdsa = "1.2.840.10045.4.3.3";
        StubCert child = new StubCert("NV Inter", "NV Root", AttestNvidiaCrlCoverageTest.INTER.getPublic(), interDer, ecdsa);
        assertEquals(Boolean.TRUE, m.invoke(null, child, new StubCert("NV Root", "NV Root", o.kp.getPublic(), rootDer, ecdsa)));
        assertEquals(Boolean.FALSE, m.invoke(null, child, new StubCert("NV Root", "NV Root", new RsaKey(R.n, 4), rootDer, ecdsa)));
        assertEquals(Boolean.FALSE, m.invoke(null, child, new StubCert("Someone Else", "NV Root", o.kp.getPublic(), rootDer, ecdsa)));
    }
}
