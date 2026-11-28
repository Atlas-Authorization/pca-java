package net.atlasauth.pca;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/** A tiny DER writer and certificate builder for the attestation tests (the signing key is generated at run time). */
final class AttestTestDer {
    private AttestTestDer() {}

    static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.write(p, 0, p.length);
        return o.toByteArray();
    }

    static byte[] tlv(int tag, byte[]... parts) {
        byte[] body = cat(parts);
        return cat(AttestCert.derLengthHeader(tag, body.length), body);
    }

    static byte[] seq(byte[]... parts) { return withTag(0x30, parts); }

    static byte[] withTag(int tag, byte[]... parts) {
        byte[] body = cat(parts);
        return cat(AttestCert.derLengthHeader(tag, body.length), body);
    }

    static byte[] oid(String dotted) {
        String[] a = dotted.split("\\.");
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(Integer.parseInt(a[0]) * 40 + Integer.parseInt(a[1]));
        for (int i = 2; i < a.length; i++) {
            long v = Long.parseLong(a[i]);
            int n = 1;
            while ((v >> (7 * n)) != 0) n++;
            for (int k = n - 1; k >= 0; k--) o.write((int) ((v >> (7 * k)) & 0x7f) | (k > 0 ? 0x80 : 0));
        }
        byte[] body = o.toByteArray();
        return cat(AttestCert.derLengthHeader(0x06, body.length), body);
    }

    static byte[] integer(long v) { return withTag(0x02, BigInteger.valueOf(v).toByteArray()); }

    static byte[] bool(boolean v) { return new byte[] {0x01, 0x01, (byte) (v ? 0xff : 0x00)}; }

    static byte[] octets(byte[] b) { return withTag(0x04, b); }

    static byte[] bits(byte unused, byte[] b) { return withTag(0x03, new byte[] {unused}, b); }

    static byte[] utf8(String s) { return withTag(0x0c, s.getBytes(StandardCharsets.UTF_8)); }

    static byte[] name(String cn) { return seq(withTag(0x31, seq(oid("2.5.4.3"), utf8(cn)))); }

    static byte[] ext(String oid, boolean critical, byte[] value) {
        return critical ? seq(oid(oid), bool(true), octets(value)) : seq(oid(oid), octets(value));
    }

    static byte[] basicConstraints(boolean ca, int pathLen) {
        byte[] flag = ca ? bool(true) : new byte[0];
        byte[] pl = pathLen >= 0 ? integer(pathLen) : new byte[0];
        return ext("2.5.29.19", true, seq(flag, pl));
    }

    /** keyUsage with only keyCertSign set (bit 5). */
    static byte[] keyUsageCertSign() { return ext("2.5.29.15", true, bits((byte) 2, new byte[] {0x04})); }

    /** keyUsage with only digitalSignature set (bit 0). */
    static byte[] keyUsageDigitalSignature() { return ext("2.5.29.15", true, bits((byte) 7, new byte[] {(byte) 0x80})); }

    static final byte[] SIG_ALG_ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"));

    /** A tbsCertificate-shaped SEQUENCE carrying only a serial and one [3] extensions block (enough for the role / extension readers). */
    static byte[] roleTbs(byte[]... extensions) {
        return seq(integer(1), withTag(0xa3, seq(cat(extensions))));
    }

    static byte[] roleCert(byte[]... extensions) {
        return seq(roleTbs(extensions), SIG_ALG_ECDSA_SHA256, bits((byte) 0, new byte[] {1}));
    }

    static KeyPair ecKey(String curve) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec(curve));
            return g.generateKeyPair();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A full certificate (subject cn, issuer cn) for pub, signed with signer (ECDSA / SHA-256). */
    static byte[] cert(String subjectCn, String issuerCn, KeyPair subject, KeyPair signer, byte[]... extensions) {
        return certWithValidity(subjectCn, issuerCn, "250101000000Z", "350101000000Z", subject, signer, extensions);
    }

    static byte[] certWithValidity(String subjectCn, String issuerCn, String notBefore, String notAfter, KeyPair subject, KeyPair signer, byte[]... extensions) {
        byte[] exts = extensions.length == 0 ? new byte[0] : withTag(0xa3, seq(cat(extensions)));
        byte[] tbs = seq(withTag(0xa0, integer(2)), integer(258), SIG_ALG_ECDSA_SHA256, name(issuerCn),
            seq(withTag(0x17, notBefore.getBytes(StandardCharsets.US_ASCII)), withTag(0x17, notAfter.getBytes(StandardCharsets.US_ASCII))),
            name(subjectCn), subject.getPublic().getEncoded(), exts);
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(signer.getPrivate());
            s.update(tbs);
            return seq(tbs, SIG_ALG_ECDSA_SHA256, bits((byte) 0, s.sign()));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
