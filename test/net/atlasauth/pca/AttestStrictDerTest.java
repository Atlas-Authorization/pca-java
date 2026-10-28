package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import org.junit.jupiter.api.Test;

/** Self-contained exact-outcome tests for the strict DER readers (no shared vector file needed). */
public class AttestStrictDerTest {
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

    // ---- readTlvStrict

    @Test void tlvShortAndMinimalLongForms() {
        AttestDer.Tlv t = AttestDer.readTlvStrict(bytes(0x04, 0x02, 1, 2), 0, 4);
        assertEquals(0x04, t.tag);
        assertEquals(2, t.start);
        assertEquals(4, t.end);
        byte[] big = new byte[3 + 200];
        big[0] = 0x04;
        big[1] = (byte) 0x81;
        big[2] = (byte) 200;
        t = AttestDer.readTlvStrict(big, 0, big.length);
        assertEquals(3, t.start);
        assertEquals(203, t.end);
    }

    @Test void tlvRefusals() {
        assertEquals("DER: truncated header", reason(() -> AttestDer.readTlvStrict(bytes(0x04), 0, 1)));
        assertEquals("DER: multi-byte tags are not supported", reason(() -> AttestDer.readTlvStrict(bytes(0x1f, 0x01, 0), 0, 3)));
        assertEquals("DER: unsupported length form", reason(() -> AttestDer.readTlvStrict(bytes(0x04, 0x80), 0, 2)));
        assertEquals("DER: unsupported length form", reason(() -> AttestDer.readTlvStrict(bytes(0x04, 0x84, 0, 0, 0, 1, 0), 0, 7)));
        assertEquals("DER: truncated length", reason(() -> AttestDer.readTlvStrict(bytes(0x04, 0x82, 0x01), 0, 3)));
        assertEquals("DER: non-minimal length (leading zero)", reason(() -> AttestDer.readTlvStrict(bytes(0x04, 0x82, 0x00, 0x90), 0, 4)));
        assertEquals("DER: non-minimal length (long form below 128)", reason(() -> AttestDer.readTlvStrict(bytes(0x04, 0x81, 0x05, 1, 2, 3, 4, 5), 0, 8)));
        assertEquals("DER: element overruns its parent", reason(() -> AttestDer.readTlvStrict(bytes(0x04, 0x03, 1, 2), 0, 4)));
        // the limit, not the array length, bounds the element
        assertEquals("DER: element overruns its parent", reason(() -> AttestDer.readTlvStrict(bytes(0x04, 0x02, 1, 2), 0, 3)));
    }

    // ---- OIDs

    @Test void oidToDotted() {
        byte[] o = oid("2.5.29.19");
        assertEquals("2.5.29.19", AttestDer.oidToDotted(o, AttestDer.readTlvStrict(o, 0, o.length)));
        byte[] big = oid("1.3.6.1.4.1.311.21.7");
        assertEquals("1.3.6.1.4.1.311.21.7", AttestDer.oidToDotted(big, AttestDer.readTlvStrict(big, 0, big.length)));
        byte[] nonMinimal = bytes(0x06, 0x03, 0x55, 0x80, 0x01);
        assertEquals("extension OID has a non-minimal arc", reason(() -> AttestDer.oidToDotted(nonMinimal, AttestDer.readTlvStrict(nonMinimal, 0, 5))));
        byte[] trunc = bytes(0x06, 0x02, 0x55, 0x81);
        assertEquals("extension OID is truncated", reason(() -> AttestDer.oidToDotted(trunc, AttestDer.readTlvStrict(trunc, 0, 4))));
        byte[] notOid = bytes(0x04, 0x01, 0x55);
        assertEquals("extension OID is malformed", reason(() -> AttestDer.oidToDotted(notOid, AttestDer.readTlvStrict(notOid, 0, 3))));
    }

    // ---- RFC 5280 times

    @Test void derTimes() {
        assertEquals(0L, AttestDer.parseDerTime(0x17, "700101000000Z").ms);
        assertEquals(-631152000000L, AttestDer.parseDerTime(0x17, "500101000000Z").ms); // YY >= 50 is 19YY
        assertEquals(946684800000L, AttestDer.parseDerTime(0x17, "000101000000Z").ms);
        assertEquals(946684800000L, AttestDer.parseDerTime(0x18, "20000101000000Z").ms);
        assertEquals(951782399000L, AttestDer.parseDerTime(0x18, "20000228235959Z").ms);
        assertTrue(AttestDer.parseDerTime(0x18, "20000229235959Z").ok); // leap day
        assertFalse(AttestDer.parseDerTime(0x18, "19000229235959Z").ok); // not a leap year: no roll-over
        assertFalse(AttestDer.parseDerTime(0x18, "20000431000000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x17, "701301000000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x17, "700001000000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x17, "700100000000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x17, "700101240000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x17, "700101006000Z").ok);
        assertFalse(AttestDer.parseDerTime(0x17, "700101000060Z").ok);
        assertFalse(AttestDer.parseDerTime(0x17, "7001010000Z").ok); // no seconds: not the profile
        assertFalse(AttestDer.parseDerTime(0x17, "700101000000+").ok);
        assertFalse(AttestDer.parseDerTime(0x17, "70010100000AZ").ok);
        assertFalse(AttestDer.parseDerTime(0x18, "700101000000Z").ok); // wrong tag for the length
        assertFalse(AttestDer.parseDerTime(0x16, "700101000000Z").ok);
    }

    // ---- extension tables

    @Test void extensionTableOrderAndFlags() {
        byte[] tbs = roleTbs(basicConstraints(true, 1), keyUsageCertSign(), ext("1.2.3.4", false, bytes(5, 0)));
        AttestDer.ExtTable t = AttestDer.parseTbsExtensions(tbs);
        assertEquals(Arrays.asList("2.5.29.19", "2.5.29.15", "1.2.3.4"), t.oids);
        assertTrue(t.get("2.5.29.19").critical);
        assertFalse(t.get("1.2.3.4").critical);
        assertEquals("0500", AttestCommon.toHexLower(t.get("1.2.3.4").value));
        assertNull(t.get("9.9"));
        assertTrue(AttestDer.parseTbsExtensions(seq(integer(1))).oids.isEmpty()); // no extensions block at all
    }

    @Test void extensionTableRefusals() {
        assertEquals("duplicate extension 2.5.29.19",
            reason(() -> AttestDer.parseTbsExtensions(roleTbs(basicConstraints(true, -1), basicConstraints(false, -1)))));
        // a critical flag that is not 0xFF is not DER
        byte[] badFlag = seq(oid("2.5.29.19"), bytes(0x01, 0x01, 0x01), octets(seq()));
        assertEquals("extension 2.5.29.19 has a non-DER critical flag", reason(() -> AttestDer.parseTbsExtensions(roleTbs(badFlag))));
        byte[] twoByteFlag = seq(oid("2.5.29.19"), bytes(0x01, 0x02, 0xff, 0xff), octets(seq()));
        assertEquals("extension 2.5.29.19 has a non-DER critical flag", reason(() -> AttestDer.parseTbsExtensions(roleTbs(twoByteFlag))));
        byte[] notOctets = seq(oid("2.5.29.19"), withTag(0x0c, bytes(1)));
        assertEquals("extension 2.5.29.19 value is not an OCTET STRING", reason(() -> AttestDer.parseTbsExtensions(roleTbs(notOctets))));
        byte[] trailing = seq(oid("2.5.29.19"), octets(seq()), bytes(0x05, 0x00));
        assertEquals("extension 2.5.29.19 has trailing bytes", reason(() -> AttestDer.parseTbsExtensions(roleTbs(trailing))));
        assertEquals("extension is not a SEQUENCE", reason(() -> AttestDer.parseTbsExtensions(seq(integer(1), withTag(0xa3, seq(integer(5)))))));
        assertEquals("empty Extensions SEQUENCE", reason(() -> AttestDer.parseTbsExtensions(seq(integer(1), withTag(0xa3, seq())))));
        assertEquals("extensions is not a SEQUENCE", reason(() -> AttestDer.parseTbsExtensions(seq(integer(1), withTag(0xa3, integer(5))))));
        assertEquals("duplicate [3] extensions block",
            reason(() -> AttestDer.parseTbsExtensions(seq(integer(1), withTag(0xa3, seq(basicConstraints(true, -1))), withTag(0xa3, seq(keyUsageCertSign()))))));
        assertEquals("extensions block is not the last TBS element",
            reason(() -> AttestDer.parseTbsExtensions(seq(integer(1), withTag(0xa3, seq(basicConstraints(true, -1))), integer(7)))));
        assertEquals("trailing bytes after tbsCertificate", reason(() -> AttestDer.parseTbsExtensions(cat(roleTbs(), bytes(0)))));
        assertEquals("tbsCertificate is not a SEQUENCE", reason(() -> AttestDer.parseTbsExtensions(integer(1))));
    }

    @Test void certificateEnvelopeRefusals() {
        byte[] cert = roleCert(basicConstraints(true, -1));
        assertEquals("trailing bytes after the certificate", reason(() -> AttestDer.tbsOfCertificate(cat(cert, bytes(0)))));
        assertEquals("certificate is not a DER SEQUENCE", reason(() -> AttestDer.tbsOfCertificate(integer(1))));
        assertEquals("certificate has no tbsCertificate", reason(() -> AttestDer.tbsOfCertificate(seq(integer(1)))));
        assertTrue(AttestDer.tbsOfCertificate(cert).length > 0);
        assertEquals(AttestDer.parseCertExtensions(cert).oids, Arrays.asList("2.5.29.19"));
    }

    @Test void criticalExtensionRecognition() {
        byte[] ok = roleCert(basicConstraints(true, -1), keyUsageCertSign());
        assertNull(AttestDer.unrecognisedCriticalExtension(ok, null));
        byte[] unknownCrit = roleCert(basicConstraints(true, -1), ext("1.2.3.4", true, bytes(5, 0)));
        assertEquals("1.2.3.4", AttestDer.unrecognisedCriticalExtension(unknownCrit, null));
        byte[] unknownNonCrit = roleCert(ext("1.2.3.4", false, bytes(5, 0)));
        assertNull(AttestDer.unrecognisedCriticalExtension(unknownNonCrit, null));
        // a caller-supplied recognised set replaces the default (basicConstraints is then unrecognised)
        assertEquals("2.5.29.19", AttestDer.unrecognisedCriticalExtension(ok, new HashSet<>(Arrays.asList("2.5.29.15"))));
        assertEquals("duplicate extension 2.5.29.19", reason(() -> AttestDer.unrecognisedCriticalExtension(roleCert(basicConstraints(true, -1), basicConstraints(true, -1)), null)));
    }

    // ---- CA roles

    @Test void roleInfo() {
        AttestDer.CertRoleInfo i = AttestDer.readCertRoleInfo(roleCert(basicConstraints(true, 2), keyUsageCertSign()));
        assertTrue(i.hasBasicConstraints);
        assertTrue(i.ca);
        assertEquals(2, i.pathLen);
        assertTrue(i.hasKeyUsage);
        assertTrue(i.keyCertSign);
        i = AttestDer.readCertRoleInfo(roleCert(basicConstraints(false, -1), keyUsageDigitalSignature()));
        assertTrue(i.hasBasicConstraints);
        assertFalse(i.ca);
        assertEquals(-1, i.pathLen);
        assertTrue(i.hasKeyUsage);
        assertFalse(i.keyCertSign);
        i = AttestDer.readCertRoleInfo(roleCert());
        assertFalse(i.hasBasicConstraints);
        assertFalse(i.hasKeyUsage);
        assertEquals("duplicate keyUsage extension", reason(() -> AttestDer.readCertRoleInfo(roleCert(keyUsageCertSign(), keyUsageCertSign()))));
        assertEquals("duplicate BasicConstraints extension", reason(() -> AttestDer.readCertRoleInfo(roleCert(basicConstraints(true, -1), basicConstraints(true, -1)))));
        assertEquals("BasicConstraints is not a SEQUENCE", reason(() -> AttestDer.readCertRoleInfo(roleCert(ext("2.5.29.19", true, integer(1))))));
        assertEquals("BasicConstraints cA is not one byte", reason(() -> AttestDer.readCertRoleInfo(roleCert(ext("2.5.29.19", true, seq(bytes(0x01, 0x02, 0xff, 0xff)))))));
        assertEquals("BasicConstraints pathLenConstraint malformed", reason(() -> AttestDer.readCertRoleInfo(roleCert(ext("2.5.29.19", true, seq(bool(true), integer(-1)))))));
        assertEquals("BasicConstraints has trailing data", reason(() -> AttestDer.readCertRoleInfo(roleCert(ext("2.5.29.19", true, seq(bool(true), integer(1), integer(2)))))));
        assertEquals("keyUsage is not a BIT STRING", reason(() -> AttestDer.readCertRoleInfo(roleCert(ext("2.5.29.15", true, integer(1))))));
        assertEquals("keyUsage BIT STRING has more than 7 unused bits", reason(() -> AttestDer.readCertRoleInfo(roleCert(ext("2.5.29.15", true, bits((byte) 8, new byte[] {0x04}))))));
        assertEquals("extension value is not an OCTET STRING", reason(() -> AttestDer.readCertRoleInfo(roleCert(seq(oid("2.5.29.19"), withTag(0x0c, bytes(1)))))));
    }

    @Test void chainRoles() {
        byte[] leaf = roleCert();
        byte[] ca = roleCert(basicConstraints(true, -1), keyUsageCertSign());
        assertEquals("", AttestDer.checkChainRoles(Arrays.asList(leaf, ca, ca)));
        assertEquals("", AttestDer.checkChainRoles(Arrays.asList(ca))); // a lone self-signed root is not role-checked
        assertEquals("", AttestDer.checkChainRoles(Arrays.asList(leaf)));
        assertEquals("leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)",
            AttestDer.checkChainRoles(Arrays.asList(ca, ca)));
        assertEquals("issuer certificate at depth 1 has no BasicConstraints (not a CA)",
            AttestDer.checkChainRoles(Arrays.asList(leaf, roleCert())));
        assertEquals("issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)",
            AttestDer.checkChainRoles(Arrays.asList(leaf, roleCert(basicConstraints(false, -1)))));
        assertEquals("issuer certificate at depth 1 keyUsage lacks keyCertSign",
            AttestDer.checkChainRoles(Arrays.asList(leaf, roleCert(basicConstraints(true, -1), keyUsageDigitalSignature()))));
        // pathLen 0 on the depth-1 issuer is fine (no intermediate below); on depth 2 it is exceeded by one intermediate
        byte[] pl0 = roleCert(basicConstraints(true, 0), keyUsageCertSign());
        assertEquals("", AttestDer.checkChainRoles(Arrays.asList(leaf, pl0)));
        assertEquals("issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)",
            AttestDer.checkChainRoles(Arrays.asList(leaf, ca, pl0)));
        byte[] pl1 = roleCert(basicConstraints(true, 1), keyUsageCertSign());
        assertEquals("", AttestDer.checkChainRoles(Arrays.asList(leaf, ca, pl1)));
        // a keyUsage-less CA is allowed; a malformed certificate in the chain is reported with the reader's message
        assertEquals("", AttestDer.checkChainRoles(Arrays.asList(leaf, roleCert(basicConstraints(true, -1)))));
        List<byte[]> malformed = Arrays.asList(leaf, new byte[] {0x30, 0x00});
        assertEquals("certificate extension parse failed: DER: truncated header", AttestDer.checkChainRoles(malformed));
    }

    // ---- validity of a full certificate

    @Test void validityWindow() {
        java.security.KeyPair k = ecKey("secp256r1");
        byte[] c = certWithValidity("v", "v", "250101000000Z", "250102000000Z", k, k);
        AttestDer.DerInstant[] v = AttestDer.derValidity(c);
        assertTrue(v[0].ok && v[1].ok);
        assertEquals(1735689600000L, v[0].ms);
        assertEquals(1735776000000L, v[1].ms);
        assertTrue(AttestDer.derValidAt(c, 1735689600000L, 0));
        assertTrue(AttestDer.derValidAt(c, 1735776000000L, 0)); // inclusive at notAfter
        assertFalse(AttestDer.derValidAt(c, 1735776000001L, 0));
        assertFalse(AttestDer.derValidAt(c, 1735689599999L, 0));
        assertTrue(AttestDer.derValidAt(c, 1735689599999L, 1)); // skew widens both ends
        assertTrue(AttestDer.derValidAt(c, 1735776000001L, 1));
        assertTrue(AttestDer.derValidAtF(c, 1735776000001L, 1.5));
        assertFalse(AttestDer.derValidAtF(c, 1735776000002L, 1.5));
        AttestDer.DerInstant[] bad = AttestDer.derValidity(new byte[] {0x30, 0x00});
        assertFalse(bad[0].ok || bad[1].ok);
        assertFalse(AttestDer.derValidAt(new byte[] {1, 2, 3}, 0, 1_000_000_000L)); // unparseable: fail closed whatever the skew
        byte[] unparsable = certWithValidity("v", "v", "251301000000Z", "250102000000Z", k, k);
        assertFalse(AttestDer.derValidAt(unparsable, 1735689600000L, 1_000_000_000L));
    }
}
