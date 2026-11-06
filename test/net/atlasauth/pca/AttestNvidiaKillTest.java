package net.atlasauth.pca;

import static net.atlasauth.pca.AttestNvidiaTest.BINDING;
import static net.atlasauth.pca.AttestNvidiaTest.M1;
import static net.atlasauth.pca.AttestNvidiaTest.NOW;
import static net.atlasauth.pca.AttestNvidiaTest.VENDOR;
import static net.atlasauth.pca.AttestNvidiaTest.block;
import static net.atlasauth.pca.AttestNvidiaTest.cfg;
import static net.atlasauth.pca.AttestNvidiaTest.config;
import static net.atlasauth.pca.AttestNvidiaTest.constructError;
import static net.atlasauth.pca.AttestNvidiaTest.evidence;
import static net.atlasauth.pca.AttestNvidiaTest.filled;
import static net.atlasauth.pca.AttestNvidiaTest.nonceOf;
import static net.atlasauth.pca.AttestNvidiaTest.opaqueAll;
import static net.atlasauth.pca.AttestNvidiaTest.parseError;
import static net.atlasauth.pca.AttestNvidiaTest.pem;
import static net.atlasauth.pca.AttestNvidiaTest.sign;
import static net.atlasauth.pca.AttestNvidiaTest.tlvOpaque;
import static net.atlasauth.pca.AttestNvidiaTest.transcript;
import static net.atlasauth.pca.AttestTestDer.basicConstraints;
import static net.atlasauth.pca.AttestTestDer.cat;
import static net.atlasauth.pca.AttestTestDer.cert;
import static net.atlasauth.pca.AttestTestDer.ecKey;
import static net.atlasauth.pca.AttestTestDer.keyUsageCertSign;
import static net.atlasauth.pca.AttestTestDer.keyUsageDigitalSignature;
import static net.atlasauth.pca.AttestTestDer.roleCert;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * NVIDIA GPU SPDM verifier, exact outcomes at the boundaries the mutation run left open: the parser's length / record /
 * block / opaque edges, the device-chain refusal table (unparseable, validity edge, non-P-384 keys, root role and
 * self-signature), the CA role reader, the JavaScript Number() / String() / slice helpers and the measurement-key order.
 */
public class AttestNvidiaKillTest {

    static KeyPair keyPair(String alg, int bits) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance(alg);
            if (bits > 0) g.initialize(bits);
            return g.generateKeyPair();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static String pinsOf(byte[]... m) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < m.length; i++) sb.append(i == 0 ? "" : ",").append('"').append(i + 1).append("\":\"").append(AttestCommon.toHexLower(m[i])).append('"');
        return sb.append('}').toString();
    }

    // ------------------------------------------------------------- the SPDM parser

    @Test
    void parserBoundaries() {
        // exactly the minimum length: no blocks, no opaque data
        byte[] min = cat(transcript(new byte[32], new ArrayList<>(), new byte[0]), new byte[96]);
        assertEquals(37 + 8 + 32 + 2 + 96, min.length);
        assertEquals("no error", parseError(min));
        AttestNvidia.SpdmReport r0 = AttestNvidia.parseSpdmEvidence(min);
        assertEquals(0, r0.measurements.size());
        assertEquals(0, r0.opaque.size());

        // the record length one past the transcript (no opaque data, so the overrun check is exact)
        byte[] ok = cat(transcript(new byte[32], Arrays.asList(block(1, M1)), new byte[0]), new byte[96]);
        assertEquals("no error", parseError(ok));
        byte[] over = ok.clone();
        over[37 + 5] = (byte) (over[37 + 5] + 1);
        assertEquals("parseNvidiaSpdmEvidence: measurement record length overruns transcript", parseError(over));

        // a block of exactly three bytes (an empty DMTF value) and a last opaque TLV with an empty value (header ends at the opaque end)
        byte[] edge = cat(transcript(new byte[32], Arrays.asList(block(5, new byte[0]), block(6, M1)), cat(tlvOpaque(3, new byte[] {'9'}), tlvOpaque(7, new byte[0]))), new byte[96]);
        assertEquals("no error", parseError(edge));
        AttestNvidia.SpdmReport re = AttestNvidia.parseSpdmEvidence(edge);
        assertEquals(2, re.measurements.size());
        assertEquals(5, re.measurements.get(0).index);
        assertEquals(0, re.measurements.get(0).digest.length);
        assertEquals(6, re.measurements.get(1).index);
        assertTrue(Arrays.equals(M1, re.measurements.get(1).digest));
        assertEquals(0, re.opaque.get(7).length);
        assertTrue(Arrays.equals(new byte[] {'9'}, re.opaque.get(3)));
        assertEquals(2, re.opaque.size());

        // a record longer than 65535 bytes (its third length byte is used, shifted by 16)
        byte[] big = cat(transcript(new byte[32], Arrays.asList(block(1, filled(40000, 1)), block(2, filled(30000, 2))), new byte[0]), new byte[96]);
        assertEquals("no error", parseError(big));
        AttestNvidia.SpdmReport rb = AttestNvidia.parseSpdmEvidence(big);
        assertEquals(2, rb.measurements.size());
        assertEquals(40000, rb.measurements.get(0).digest.length);
        assertEquals(30000, rb.measurements.get(1).digest.length);
    }

    // ------------------------------------------------------------- helpers

    @Test
    void jsSliceEdges() {
        assertEquals("ab", AttestNvidia.jsSlice("abc", 0, 2));
        assertEquals("", AttestNvidia.jsSlice("abc", 0, 0));
        assertEquals("", AttestNvidia.jsSlice("abc", 0, -9));
        assertEquals("", AttestNvidia.jsSlice("abc", 1, 1));
        assertEquals("bc", AttestNvidia.jsSlice("abc", -2, 3));
        assertEquals("abc", AttestNvidia.jsSlice("abc", 0, 9));
        assertEquals("", AttestNvidia.jsSlice("abc", 9, 3));
        // formatVbiosVersion of two bytes: half - 2 is 0
        assertEquals("01.00", AttestNvidia.formatVbiosVersion(new byte[] {0x01, 0x00}));
    }

    @Test
    void jsNumberTable() {
        assertEquals(Double.POSITIVE_INFINITY, AttestNvidia.jsNumber("+Infinity"));
        assertEquals(Double.POSITIVE_INFINITY, AttestNvidia.jsNumber(" Infinity "));
        assertEquals(Double.NEGATIVE_INFINITY, AttestNvidia.jsNumber("-Infinity"));
        assertEquals(0d, AttestNvidia.jsNumber("0"));
        assertEquals(0d, AttestNvidia.jsNumber("00"));
        assertEquals(7d, AttestNvidia.jsNumber("07"));
        assertEquals(0.5d, AttestNvidia.jsNumber("0.5"));
        assertEquals(0d, AttestNvidia.jsNumber("0e1"));
        assertEquals(1d, AttestNvidia.jsNumber("0x1"));
        assertEquals(16d, AttestNvidia.jsNumber("0X10"));
        assertEquals(15d, AttestNvidia.jsNumber("0o17"));
        assertEquals(15d, AttestNvidia.jsNumber("0O17"));
        assertEquals(5d, AttestNvidia.jsNumber("0b101"));
        assertEquals(5d, AttestNvidia.jsNumber("0B101"));
        assertEquals(255d, AttestNvidia.jsNumber("0xfF"));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("0x")));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("0b")));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("0xg")));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("0o8")));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("0b2")));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("1x10")));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("1b1")));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("-Infinityx")));
        // a sign or a non-ASCII digit after the radix prefix is not a number (BigInteger would take it)
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("0x-1")));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("0x+1")));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("0b+1")));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("0x\u0661")));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("0x\uff11")));
        assertTrue(AttestNvidia.isJsInteger(3));
        assertTrue(AttestNvidia.isJsInteger(-0.0));
        assertFalse(AttestNvidia.isJsInteger(1.5));
        assertFalse(AttestNvidia.isJsInteger(Double.NaN));
        assertFalse(AttestNvidia.isJsInteger(Double.NEGATIVE_INFINITY));
    }

    @Test
    void jsStringTable() {
        assertEquals("null", AttestNvidia.jsString(null));
        assertEquals("abc", AttestNvidia.jsString("abc"));
        assertEquals("", AttestNvidia.jsString(""));
        assertEquals("true", AttestNvidia.jsString(Boolean.TRUE));
        assertEquals("false", AttestNvidia.jsString(Boolean.FALSE));
        assertEquals("1", AttestNvidia.jsString(1.0d));
        assertEquals("1.5", AttestNvidia.jsString(1.5d));
        assertEquals("1e+21", AttestNvidia.jsString(1e21d));
        assertEquals("7", AttestNvidia.jsString(7L));
        assertEquals("c", AttestNvidia.jsString('c'));
        assertEquals("[object Object]", AttestNvidia.jsString(cfg("{\"a\":1}")));
        assertEquals("1,true,,[object Object],a,b", AttestNvidia.jsString(Json.parseLenient("[1.0,true,null,{},[\"a\",\"b\"]]")));
        assertEquals("", AttestNvidia.jsString(new ArrayList<Object>()));
    }

    static boolean ca(byte[] raw) {
        AttCert c = new AttCert();
        c.raw = raw;
        return AttestNvidia.certIsCA(c);
    }

    @Test
    void certIsCaTable() {
        assertFalse(ca(new byte[] {0x31, 0x00}), "unreadable role info");
        assertFalse(ca(roleCert()), "no BasicConstraints");
        assertFalse(ca(roleCert(keyUsageCertSign())), "keyUsage without BasicConstraints");
        assertFalse(ca(roleCert(basicConstraints(false, -1))), "cA false");
        assertTrue(ca(roleCert(basicConstraints(true, -1))), "cA, no keyUsage");
        assertTrue(ca(roleCert(basicConstraints(true, -1), keyUsageCertSign())), "cA with keyCertSign");
        assertFalse(ca(roleCert(basicConstraints(true, -1), keyUsageDigitalSignature())), "cA without keyCertSign");
    }

    // ------------------------------------------------------------- the device chain and the verifier

    static Map<String, Object> withChain(Map<String, Object> ev, String chainPem) {
        Map<String, Object> out = new HashMap<>(ev);
        out.put("certChainPem", chainPem);
        return out;
    }

    @Test
    void deviceChainRefusals() {
        AttestNvidiaTest.Gpu g = new AttestNvidiaTest.Gpu();
        byte[] report = sign(g.leaf, transcript(nonceOf(BINDING), Arrays.asList(block(1, M1)), opaqueAll("535.86")));
        Map<String, Object> ev = evidence(g, report);
        VendorVerifier v = AttestHarness.verifier(VENDOR, cfg(config(g, pinsOf(M1), "")));
        assertEquals("", v.verify(ev, BINDING, NOW).reason);

        // an undecodable certificate body
        assertEquals("device chain unparseable: error:1E08010C:DECODER routines::unsupported",
            v.verify(withChain(ev, "-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----"), BINDING, NOW).reason);
        // the validity window has no slack: 2025-01-01T00:00:00Z .. 2035-01-01T00:00:00Z
        long notBefore = 1_735_689_600_000L;
        long notAfter = 2_051_222_400_000L;
        assertEquals("device chain cert #0 is outside its validity window", v.verify(ev, BINDING, notAfter + 1).reason);
        assertEquals("device chain cert #0 is outside its validity window", v.verify(ev, BINDING, notBefore - 1).reason);
        // keys other than ECDSA P-384: RSA, Ed25519, and one the key reader refuses (X25519)
        for (KeyPair kp : new KeyPair[] {keyPair("RSA", 2048), keyPair("Ed25519", 0), keyPair("X25519", 0)}) {
            String chain = pem(cert("GH100 A01 FSP BROM", "NV Root", kp, g.root)) + "\n" + pem(g.rootDer);
            assertEquals("device chain cert #0 is not an ECDSA P-384 key", v.verify(withChain(ev, chain), BINDING, NOW).reason, kp.getPublic().getAlgorithm());
        }
        // a lone root: it must be a CA and self-signed
        assertEquals("device chain root is not a self-signed CA",
            v.verify(withChain(ev, pem(cert("NV Root", "NV Root", g.root, g.root))), BINDING, NOW).reason);
        KeyPair stranger = ecKey("secp384r1");
        assertEquals("device chain root is not a self-signed CA",
            v.verify(withChain(ev, pem(cert("NV Root", "NV Root", g.root, stranger, basicConstraints(true, -1), keyUsageCertSign()))), BINDING, NOW).reason);
        // a two-certificate chain whose root is a CA but not self-signed
        byte[] crossRoot = cert("NV Root", "Other", g.root, stranger, basicConstraints(true, -1), keyUsageCertSign());
        assertEquals("device chain root is not a self-signed CA",
            v.verify(withChain(ev, pem(g.leafDer) + "\n" + pem(crossRoot)), BINDING, NOW).reason);
    }

    @Test
    void evidenceShapeAndOptionalHostFields() {
        AttestNvidiaTest.Gpu g = new AttestNvidiaTest.Gpu();
        VendorVerifier v = AttestHarness.verifier(VENDOR, cfg(config(g, pinsOf(M1), "")));
        Map<String, Object> onlyChain = new HashMap<>();
        onlyChain.put("certChainPem", g.chainPem());
        assertEquals("no NVIDIA GPU evidence for this action", v.verify(onlyChain, BINDING, NOW).reason);
        onlyChain.put("evidence", 5L);
        assertEquals("no NVIDIA GPU evidence for this action", v.verify(onlyChain, BINDING, NOW).reason);

        // a report without the driver / VBIOS opaque fields: neither host field is asserted
        byte[] bare = sign(g.leaf, transcript(nonceOf(BINDING), Arrays.asList(block(1, M1)), tlvOpaque(15, new byte[] {'g'})));
        HardwareResult r = v.verify(evidence(g, bare), BINDING, NOW);
        assertEquals("", r.reason);
        assertTrue(r.ok && r.bound);
        assertEquals(3, r.hostAsserted.size());
        assertEquals("nvidia-gpu-cc", r.hostAsserted.get("attestation_type"));
        assertEquals(AttestCommon.toHexLower(AttestCommon.sha384Sum(M1)), r.hostAsserted.get("gpu_measurements_sha384"));
        assertEquals("CN=GH100 A01 FSP BROM", r.hostAsserted.get("leaf_subject"));
        assertFalse(r.hostAsserted.containsKey("driver_version"));
        assertFalse(r.hostAsserted.containsKey("vbios_version"));
        // only the VBIOS field
        byte[] vbOnly = sign(g.leaf, transcript(nonceOf(BINDING), Arrays.asList(block(1, M1)), tlvOpaque(6, new byte[] {0x04, 0x03, 0x02, 0x01})));
        HardwareResult rv = v.verify(evidence(g, vbOnly), BINDING, NOW);
        assertEquals(4, rv.hostAsserted.size());
        assertEquals("03.04.02", rv.hostAsserted.get("vbios_version"));
        assertFalse(rv.hostAsserted.containsKey("driver_version"));
        // an empty leafSubjectIncludes matches every subject
        assertTrue(AttestHarness.verifier(VENDOR, cfg(config(g, pinsOf(M1), ",\"leafSubjectIncludes\":\"\""))).verify(evidence(g, bare), BINDING, NOW).ok);
    }

    @Test
    void measurementKeyOrder() {
        AttestNvidiaTest.Gpu g = new AttestNvidiaTest.Gpu();
        byte[] report = sign(g.leaf, transcript(nonceOf(BINDING), Arrays.asList(block(1, M1), block(2, filled(48, 0x22))), opaqueAll("535.86")));
        Map<String, Object> ev = evidence(g, report);
        // "10" is an array-index key (listed first); "01" is not, so it follows in insertion order
        assertEquals("measurement block 10 missing from report",
            AttestHarness.verifier(VENDOR, cfg(config(g, "{\"01\":\"bb\",\"10\":\"aa\"}", ""))).verify(ev, BINDING, NOW).reason);
        // "255" and "2" are index keys (ascending), "1.0" is not and comes last
        assertEquals("measurement block 2 does not match the pinned digest",
            AttestHarness.verifier(VENDOR, cfg(config(g, "{\"1.0\":\"bb\",\"255\":\"aa\",\"2\":\"cc\"}", ""))).verify(ev, BINDING, NOW).reason);
        // keys of four or more digits are out of range wherever they sort; a 20-digit key is refused, not parsed as a long
        assertEquals("createNvidiaSpdmVerifier: measurement index out of range", constructError(config(g, "{\"1\":\"aa\",\"1000\":\"bb\"}", "")));
        assertEquals("createNvidiaSpdmVerifier: measurement index out of range", constructError(config(g, "{\"99999999999999999999\":\"bb\"}", "")));
        assertEquals("createNvidiaSpdmVerifier: measurement index out of range", constructError(config(g, "{\"4294967294\":\"bb\"}", "")));
        assertEquals("no error", constructError(config(g, "{\"255\":\"aa\",\"0x0\":\"bb\",\"007\":\"cc\"}", "")));
    }

    // spdm:224: after the links, before the root check; the RIM signer chain goes through the same verifyDeviceChain
    @Test
    void strictChainProfile() {
        AttestNvidiaTest.Gpu g = new AttestNvidiaTest.Gpu();
        byte[] report = sign(g.leaf, transcript(nonceOf(BINDING), Arrays.asList(block(1, M1)), opaqueAll("535.86")));
        Map<String, Object> ev = evidence(g, report);
        VendorVerifier v = AttestHarness.verifier(VENDOR, cfg(config(g, pinsOf(M1), "")));
        for (K05StrictChainTest.Case c : K05StrictChainTest.cases(g.leaf, g.root, "secp384r1")) {
            StringBuilder chain = new StringBuilder();
            for (byte[] der : c.ders) chain.append(pem(der)).append("\n");
            String want = c.reason.isEmpty() ? "" : c.notCa ? "device chain cert #1 issues a certificate but is not a CA" : "device chain profile: " + c.reason;
            assertEquals(want, v.verify(withChain(ev, chain.toString()), BINDING, NOW).reason, c.name);
        }
        // the profile comes before the root check
        KeyPair stranger = ecKey("secp384r1");
        byte[] caLeaf = cert("GH100 A01 FSP BROM", "NV Root", g.leaf, stranger, basicConstraints(true, -1));
        byte[] notSelfSigned = cert("NV Root", "Other", stranger, g.root, basicConstraints(true, -1), keyUsageCertSign());
        assertEquals("device chain profile: leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)",
            v.verify(withChain(ev, pem(caLeaf) + "\n" + pem(notSelfSigned)), BINDING, NOW).reason);
    }
}
