package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * NVIDIA GPU SPDM verifier: the nvidia-gpu-spdm rows of the shared attestation evidence vectors (a missing file FAILS), the
 * fail-closed construction and evidence tables, and exact-outcome unit tests of the parser, chain, binding, measurement pins,
 * collateral hook (RIM naming, golden comparison, firmware policy) and the CRL / OCSP readers.
 */
public class AttestNvidiaTest {
    static final String VENDOR = "nvidia-gpu-spdm";
    static final long NOW = 1_800_000_000_000L;
    static final AttestationBinding BINDING = new AttestationBinding("holder-key", "grant-1", 7, "nonce-1");

    @SuppressWarnings("unchecked")
    static Map<String, Object> cfg(String json) { return (Map<String, Object>) Json.parseLenient(json); }

    static String constructError(String json) {
        try {
            AttestFactory.verifierFromConfig(VENDOR, cfg(json));
        } catch (AttestException e) {
            return e.getMessage();
        }
        return "no error";
    }

    // ------------------------------------------------------------- shared vectors

    @Test
    void sharedVectorRows() {
        int n = 0;
        for (Map<String, Object> row : AttestVectors.rows("attestation_vectors")) {
            if (!VENDOR.equals(row.get("vendor"))) continue;
            n++;
            Map<String, Object> got;
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> c = (Map<String, Object>) row.get("config");
                VendorVerifier v = AttestFactory.verifierFromConfig(VENDOR, c);
                @SuppressWarnings("unchecked")
                Map<String, Object> ev = row.get("evidence") instanceof Map ? (Map<String, Object>) row.get("evidence") : null;
                Double now = AttestCommon.asFinite(row.get("now"));
                got = v.verify(ev, AttestVectors.bindingOf(row.get("expected_binding")), now.longValue()).wire();
            } catch (AttestException e) {
                got = new LinkedHashMap<>();
                got.put("construct_error", e.getMessage());
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> exp = new LinkedHashMap<>((Map<String, Object>) row.get("expect"));
            Map<String, Object> g = new LinkedHashMap<>(got);
            if ("prefix".equals(exp.get("reason_match"))) {
                String prefix = (String) exp.get("reason_prefix");
                String reason = g.get("reason") instanceof String ? (String) g.get("reason") : "";
                assertTrue(reason.startsWith(prefix), row.get("id") + ": reason '" + reason + "' does not start with '" + prefix + "'");
                g.remove("reason");
                exp.remove("reason");
            }
            exp.remove("reason_match");
            exp.remove("reason_prefix");
            assertEquals(AttestVectors.canon(exp), AttestVectors.canon(g), row.get("id") + " (" + row.get("intent") + ")");
        }
        assertTrue(n > 0, "no " + VENDOR + " rows in the attestation evidence vectors");
    }

    // ------------------------------------------------------------- fail-closed tables

    @Test
    void constructionRefusals() {
        assertEquals("createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)", constructError("{}"));
        assertEquals("createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)",
            constructError("{\"rootSpkiSha256\":[\"aa\"]}"));
        assertEquals("createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)",
            constructError("{\"rootSpkiSha256\":[\"aa\"],\"policy\":{\"measurements\":{}}}"));
        assertEquals("createNvidiaSpdmVerifier: measurement index out of range", constructError("{\"rootSpkiSha256\":[\"aa\"],\"policy\":{\"measurements\":{\"256\":\"aa\"}}}"));
        assertEquals("createNvidiaSpdmVerifier: measurement index out of range", constructError("{\"rootSpkiSha256\":[\"aa\"],\"policy\":{\"measurements\":{\"-1\":\"aa\"}}}"));
        assertEquals("createNvidiaSpdmVerifier: measurement index out of range", constructError("{\"rootSpkiSha256\":[\"aa\"],\"policy\":{\"measurements\":{\"1.5\":\"aa\"}}}"));
        assertEquals("createNvidiaSpdmVerifier: measurement index out of range", constructError("{\"rootSpkiSha256\":[\"aa\"],\"policy\":{\"measurements\":{\"x\":\"aa\"}}}"));
        assertEquals("createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)", constructError("{\"rootSpkiSha256\":[]}"));
        assertEquals("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root", constructError("{\"rootSpkiSha256\":[\"aa\"],\"collateral\":{}}"));
        assertEquals("nvidiaCollateralHook: malformed minDriverVersion 'x'",
            constructError("{\"rootSpkiSha256\":[\"aa\"],\"collateral\":{\"rimRootSpkiSha256\":[\"aa\"],\"firmware\":{\"minDriverVersion\":\"x\"}}}"));
        assertEquals("nvidiaCollateralHook: malformed minVbiosVersion '96.00000'",
            constructError("{\"rootSpkiSha256\":[\"aa\"],\"collateral\":{\"rimRootSpkiSha256\":[\"aa\"],\"firmware\":{\"minVbiosVersion\":\"96.00000\"}}}"));
        assertEquals("nvidiaCollateralHook: malformed denyDriverVersions entry '1..2'",
            constructError("{\"rootSpkiSha256\":[\"aa\"],\"collateral\":{\"rimRootSpkiSha256\":[\"aa\"],\"firmware\":{\"denyDriverVersions\":[\"1..2\"]}}}"));
        // the collateral hook is checked before the root pins (reference order)
        assertEquals("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root", constructError("{\"collateral\":{}}"));
        // complete configurations
        assertEquals("no error", constructError("{\"rootSpkiSha256\":[\"aa\"],\"collateral\":{\"rimRootSpkiSha256\":[\"aa\"]}}"));
        assertEquals("no error", constructError("{\"rootSpkiSha256\":[\"aa\"],\"policy\":{\"measurements\":{\"0\":\"aa\",\"255\":\"bb\",\"\":\"cc\"}}}"));
    }

    @Test
    void noEvidenceAndEmptyChain() {
        VendorVerifier v = AttestFactory.verifierFromConfig(VENDOR, cfg("{\"rootSpkiSha256\":[\"aa\"],\"policy\":{\"measurements\":{\"1\":\"aa\"}}}"));
        HardwareResult r = v.verify(null, BINDING, NOW);
        assertEquals("no NVIDIA GPU evidence for this action", r.reason);
        assertFalse(r.ok || r.bound);
        assertNull(r.measured);
        assertNull(r.hostAsserted);
        Map<String, Object> ev = new HashMap<>();
        ev.put("evidence", "AA==");
        assertEquals("no NVIDIA GPU evidence for this action", v.verify(ev, BINDING, NOW).reason);
        ev.put("certChainPem", 5);
        assertEquals("no NVIDIA GPU evidence for this action", v.verify(ev, BINDING, NOW).reason);
        ev.put("certChainPem", "");
        assertEquals("device chain unparseable: parsePemChain: no certificates found", v.verify(ev, BINDING, NOW).reason);
    }

    // ------------------------------------------------------------- helpers

    @Test
    void vbiosVersionFormat() {
        assertEquals("96.00.9f.00.04", AttestNvidia.formatVbiosVersion(new byte[] {0x00, (byte) 0x9f, 0x00, (byte) 0x96, 0x04, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa}));
        assertEquals("", AttestNvidia.formatVbiosVersion(new byte[0]));
        assertEquals("1", AttestNvidia.formatVbiosVersion(new byte[] {0x01}));
        assertEquals("cd", AttestNvidia.jsSlice("abcdef", 2, -2));
        assertEquals("", AttestNvidia.jsSlice("abc", 2, 1));
        assertEquals("ab", AttestNvidia.jsSlice("abc", -9, 2));
    }

    @Test
    void jsNumberAndString() {
        assertEquals(0d, AttestNvidia.jsNumber(" "));
        assertEquals(16d, AttestNvidia.jsNumber("0x10"));
        assertEquals(1d, AttestNvidia.jsNumber(" 1. "));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("1d")));
        assertTrue(Double.isNaN(AttestNvidia.jsNumber("-0x10")));
        assertTrue(Double.isInfinite(AttestNvidia.jsNumber("Infinity")));
        assertFalse(AttestNvidia.isJsInteger(Double.POSITIVE_INFINITY));
        assertEquals("null", AttestNvidia.jsString(null));
        assertEquals("[object Object]", AttestNvidia.jsString(new HashMap<>()));
        assertEquals("1,,x", AttestNvidia.jsString(Arrays.asList(Json.parseLenient("1"), null, "x")));
    }

    // ------------------------------------------------------------- an end-to-end GPU transcript (P-384 chain, signed report)

    static final class Gpu {
        final KeyPair root = ecKey("secp384r1");
        final KeyPair leaf = ecKey("secp384r1");
        final byte[] rootDer = cert("NV Root", "NV Root", root, root, basicConstraints(true, -1), keyUsageCertSign());
        final byte[] leafDer = cert("GH100 A01 FSP BROM", "NV Root", leaf, root);

        String pin() { return AttestCert.keyOfCert(AttestCert.parseCertDer(rootDer)).spkiSha256(); }

        String chainPem() { return pem(leafDer) + "\n" + pem(rootDer); }
    }

    static String pem(byte[] der) {
        return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der) + "\n-----END CERTIFICATE-----";
    }

    static byte[] le16(int v) { return new byte[] {(byte) v, (byte) (v >> 8)}; }

    static byte[] block(int index, byte[] value) {
        byte[] body = cat(new byte[] {0x01}, le16(value.length), value);
        return cat(new byte[] {(byte) index, 0x01}, le16(body.length), body);
    }

    static byte[] tlvOpaque(int type, byte[] value) { return cat(le16(type), le16(value.length), value); }

    /** request(37) || response(header, blocks, responder nonce, opaque) — unsigned. */
    static byte[] transcript(byte[] nonce, List<byte[]> blocks, byte[] opaque) {
        byte[] req = cat(new byte[] {0x11, (byte) 0xe0, 0, 0}, nonce, new byte[] {0});
        byte[] rec = cat(blocks.toArray(new byte[0][]));
        byte[] resp = cat(new byte[] {0x11, 0x60, 0, 0, (byte) blocks.size(), (byte) rec.length, (byte) (rec.length >> 8), (byte) (rec.length >> 16)},
            rec, new byte[32], le16(opaque.length), opaque);
        return cat(req, resp);
    }

    static byte[] sign(KeyPair k, byte[] signed) {
        try {
            Signature s = Signature.getInstance("SHA384withECDSAinP1363Format");
            s.initSign(k.getPrivate());
            s.update(signed);
            return cat(signed, s.sign());
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] nonceOf(AttestationBinding b) { return AttestCommon.sha256Sum(AttestCommon.attestationBindingBytes(b)); }

    static final byte[] M1 = filled(48, 0x11);
    static final byte[] M2 = filled(48, 0x22);

    static byte[] filled(int n, int v) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) v);
        return b;
    }

    static byte[] opaqueAll(String driver) {
        return cat(tlvOpaque(3, (driver + "\0").getBytes(StandardCharsets.ISO_8859_1)),
            tlvOpaque(6, new byte[] {0x00, (byte) 0x9f, 0x00, (byte) 0x96, 0x04, 0x00, 0x00, 0x00}),
            tlvOpaque(15, "g520".getBytes(StandardCharsets.ISO_8859_1)),
            tlvOpaque(17, "pg520".getBytes(StandardCharsets.ISO_8859_1)),
            tlvOpaque(18, "0200".getBytes(StandardCharsets.ISO_8859_1)));
    }

    static Map<String, Object> evidence(Gpu g, byte[] report) {
        Map<String, Object> ev = new HashMap<>();
        ev.put("evidence", Base64.getEncoder().encodeToString(report));
        ev.put("certChainPem", g.chainPem());
        return ev;
    }

    static String config(Gpu g, String measurements, String extra) {
        return "{\"rootSpkiSha256\":[\"" + g.pin().toUpperCase() + "\"],\"policy\":{\"measurements\":" + measurements + extra + "}}";
    }

    @Test
    void endToEnd() {
        Gpu g = new Gpu();
        byte[] report = sign(g.leaf, transcript(nonceOf(BINDING), Arrays.asList(block(2, M2), block(1, M1)), opaqueAll("535.86")));
        Map<String, Object> ev = evidence(g, report);
        String pins = "{\"1\":\"" + AttestCommon.toHexLower(M1).toUpperCase() + "\"}";
        VendorVerifier v = AttestFactory.verifierFromConfig(VENDOR, cfg(config(g, pins, "")));
        HardwareResult r = v.verify(ev, BINDING, NOW);
        assertEquals("", r.reason);
        assertTrue(r.ok && r.bound);
        assertEquals(HardwareResult.newMeasured("", ""), r.measured);
        assertEquals("nvidia-gpu-cc", r.hostAsserted.get("attestation_type"));
        assertEquals(AttestCommon.toHexLower(AttestCommon.sha384Sum(cat(M1, M2))), r.hostAsserted.get("gpu_measurements_sha384"));
        assertEquals("CN=GH100 A01 FSP BROM", r.hostAsserted.get("leaf_subject"));
        assertEquals("535.86", r.hostAsserted.get("driver_version"));
        assertEquals("96.00.9f.00.04", r.hostAsserted.get("vbios_version"));
        assertEquals(5, r.hostAsserted.size());

        // the leaf subject filter
        assertEquals("device leaf subject does not contain 'GB100'",
            AttestFactory.verifierFromConfig(VENDOR, cfg(config(g, pins, ",\"leafSubjectIncludes\":\"GB100\""))).verify(ev, BINDING, NOW).reason);
        assertTrue(AttestFactory.verifierFromConfig(VENDOR, cfg(config(g, pins, ",\"leafSubjectIncludes\":\"GH100\""))).verify(ev, BINDING, NOW).ok);
        // pins
        String other = "{\"rootSpkiSha256\":[\"" + "00".repeat(32) + "\"],\"policy\":{\"measurements\":" + pins + "}}";
        assertEquals("chain root is not a pinned NVIDIA root", AttestFactory.verifierFromConfig(VENDOR, cfg(other)).verify(ev, BINDING, NOW).reason);
        // measurement pins: missing block, wrong digest; the first failing entry in key order is reported
        assertEquals("measurement block 3 missing from report",
            AttestFactory.verifierFromConfig(VENDOR, cfg(config(g, "{\"3\":\"aa\"}", ""))).verify(ev, BINDING, NOW).reason);
        // array-index keys are checked in numeric order (Object.entries), not insertion order
        assertEquals("measurement block 1 does not match the pinned digest",
            AttestFactory.verifierFromConfig(VENDOR, cfg(config(g, "{\"3\":\"aa\",\"1\":\"bb\"}", ""))).verify(ev, BINDING, NOW).reason);
        assertEquals("measurement block 1 does not match the pinned digest",
            AttestFactory.verifierFromConfig(VENDOR, cfg(config(g, "{\"2\":\"" + AttestCommon.toHexLower(M2) + "\",\"1\":\"bb\"}", ""))).verify(ev, BINDING, NOW).reason);
        // binding
        assertEquals("SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)",
            v.verify(ev, new AttestationBinding("holder-key", "grant-1", 8, "nonce-1"), NOW).reason);
        assertEquals("no expected attestation binding supplied", v.verify(ev, null, NOW).reason);
        assertEquals("binding not constructible: binding: nonce required", v.verify(ev, new AttestationBinding("h", "g", 1, ""), NOW).reason);
        // signature: one flipped byte in the signed part, in the signature
        byte[] bad = report.clone();
        bad[40] ^= 1;
        assertEquals("GPU attestation report signature does not verify under the device identity key", v.verify(evidence(g, bad), BINDING, NOW).reason);
        bad = report.clone();
        bad[bad.length - 1] ^= 1;
        assertEquals("GPU attestation report signature does not verify under the device identity key", v.verify(evidence(g, bad), BINDING, NOW).reason);
        // the chain must be valid at now
        assertEquals("device chain cert #0 is outside its validity window", v.verify(ev, BINDING, 1_000_000_000_000L).reason);
        // a P-256 chain is refused
        KeyPair p256 = ecKey("secp256r1");
        Map<String, Object> ev256 = new HashMap<>(ev);
        ev256.put("certChainPem", pem(cert("x", "NV Root", p256, g.root)) + "\n" + pem(g.rootDer));
        assertEquals("device chain cert #0 is not an ECDSA P-384 key", v.verify(ev256, BINDING, NOW).reason);
        // the root must be a CA, and must have signed the leaf
        Map<String, Object> evNoCa = new HashMap<>(ev);
        byte[] plainRoot = cert("NV Root", "NV Root", g.root, g.root);
        evNoCa.put("certChainPem", pem(g.leafDer) + "\n" + pem(plainRoot));
        assertEquals("device chain cert #1 issues a certificate but is not a CA", v.verify(evNoCa, BINDING, NOW).reason);
        KeyPair stranger = ecKey("secp384r1");
        Map<String, Object> evForged = new HashMap<>(ev);
        evForged.put("certChainPem", pem(cert("GH100 A01 FSP BROM", "NV Root", g.leaf, stranger)) + "\n" + pem(g.rootDer));
        assertEquals("device chain link #0 signature does not verify under its issuer", v.verify(evForged, BINDING, NOW).reason);
        // more than five certificates
        StringBuilder six = new StringBuilder();
        for (int i = 0; i < 6; i++) six.append(pem(g.rootDer)).append('\n');
        Map<String, Object> ev6 = new HashMap<>(ev);
        ev6.put("certChainPem", six.toString());
        assertEquals("device chain unparseable: parsePemChain: chain longer than 5", v.verify(ev6, BINDING, NOW).reason);
    }

    // ------------------------------------------------------------- the SPDM parser

    static String parseError(byte[] b) {
        try {
            AttestNvidia.parseSpdmEvidence(b);
        } catch (AttestException e) {
            return e.getMessage();
        }
        return "no error";
    }

    static String versionReason(int req, int resp) {
        byte[] t = cat(transcript(new byte[32], Arrays.asList(block(1, M1)), tlvOpaque(3, new byte[] {'1'})), new byte[96]);
        t[0] = (byte) req;
        t[37] = (byte) resp;
        return AttestNvidia.spdmVersionReason(AttestNvidia.parseSpdmEvidence(t));
    }

    @Test
    void spdmVersionRule() {
        assertNull(versionReason(0x11, 0x11));
        assertNull(versionReason(0x12, 0x12));
        assertEquals("SPDM version 0x10/0x10 is not an accepted GET_MEASUREMENTS version", versionReason(0x10, 0x10));
        assertEquals("SPDM version 0x12/0x11 is not an accepted GET_MEASUREMENTS version", versionReason(0x12, 0x11));
        assertEquals("SPDM version 0x11/0x12 is not an accepted GET_MEASUREMENTS version", versionReason(0x11, 0x12));
    }

    @Test
    void spdmParser() {
        byte[] ok = cat(transcript(new byte[32], Arrays.asList(block(1, M1)), tlvOpaque(3, new byte[] {'1'})), new byte[96]);
        assertEquals("no error", parseError(ok));
        AttestNvidia.SpdmReport rep = AttestNvidia.parseSpdmEvidence(ok);
        assertEquals(1, rep.measurements.size());
        assertEquals(1, rep.measurements.get(0).index);
        assertTrue(Arrays.equals(M1, rep.measurements.get(0).digest));
        assertEquals(96, rep.signature.length);
        assertEquals(ok.length - 96, rep.signedBytes.length);
        assertEquals(1, rep.opaque.get(3).length);

        int min = 37 + 8 + 32 + 2 + 96;
        assertEquals("parseNvidiaSpdmEvidence: transcript too short (" + (min - 1) + ")", parseError(new byte[min - 1]));
        byte[] c = ok.clone();
        c[1] = 0x10;
        assertEquals("parseNvidiaSpdmEvidence: request code 0x10 is not GET_MEASUREMENTS", parseError(c));
        c = ok.clone();
        c[37 + 1] = 0x61;
        assertEquals("parseNvidiaSpdmEvidence: response code is not MEASUREMENTS", parseError(c));
        c = ok.clone();
        c[37 + 4] = 2;
        assertEquals("parseNvidiaSpdmEvidence: header says 2 blocks, parsed 1", parseError(c));
        c = ok.clone();
        c[37 + 7] = 1; // record length + 65536
        assertEquals("parseNvidiaSpdmEvidence: measurement record length overruns transcript", parseError(c));
        assertEquals("parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript", parseError(cat(ok, new byte[] {0})));
        byte[] tooBig = cat(transcript(new byte[32], Arrays.asList(block(1, M1)), cat(le16(3), le16(9), new byte[] {1})), new byte[96]);
        assertEquals("parseNvidiaSpdmEvidence: opaque TLV overruns opaque data", parseError(tooBig));
        byte[] shortTlv = cat(transcript(new byte[32], Arrays.asList(block(1, M1)), new byte[] {1, 0, 0}), new byte[96]);
        assertEquals("parseNvidiaSpdmEvidence: truncated opaque TLV header", parseError(shortTlv));
        byte[] tinyBlock = cat(new byte[] {1, 1}, le16(2), new byte[] {1, 0});
        assertEquals("parseNvidiaSpdmEvidence: measurement block overruns record",
            parseError(cat(transcript(new byte[32], Arrays.asList(tinyBlock), new byte[0]), new byte[96])));
        byte[] dmtfOver = cat(new byte[] {1, 1}, le16(4), new byte[] {1, 9, 0, 0});
        assertEquals("parseNvidiaSpdmEvidence: DMTF value overruns measurement block",
            parseError(cat(transcript(new byte[32], Arrays.asList(dmtfOver), new byte[0]), new byte[96])));
        byte[] hdrShort = new byte[] {1, 1, 0};
        assertEquals("parseNvidiaSpdmEvidence: truncated measurement block header",
            parseError(cat(transcript(new byte[32], Arrays.asList(hdrShort), new byte[0]), new byte[96])));
    }

    // ------------------------------------------------------------- the collateral hook

    static VendorVerifier hooked(Gpu g, String collateral) {
        return AttestFactory.verifierFromConfig(VENDOR, cfg("{\"rootSpkiSha256\":[\"" + g.pin() + "\"],\"collateral\":" + collateral + "}"));
    }

    @Test
    void collateralHook() {
        Gpu g = new Gpu();
        byte[] bare = sign(g.leaf, transcript(nonceOf(BINDING), Arrays.asList(block(1, M1)), tlvOpaque(3, new byte[] {'5'})));
        assertEquals("GPU report does not carry the opaque fields needed to name its RIMs",
            hooked(g, "{\"rimRootSpkiSha256\":[\"aa\"]}").verify(evidence(g, bare), BINDING, NOW).reason);
        byte[] full = sign(g.leaf, transcript(nonceOf(BINDING), Arrays.asList(block(1, M1)), opaqueAll("535.86")));
        Map<String, Object> ev = evidence(g, full);
        assertEquals("firmware policy: driver 535.86 is below the minimum 535.104",
            hooked(g, "{\"rimRootSpkiSha256\":[\"aa\"],\"firmware\":{\"minDriverVersion\":\"535.104\"}}").verify(ev, BINDING, NOW).reason);
        assertEquals("firmware policy: VBIOS 96.00.9f.00.04 is below the minimum 96.00.a0",
            hooked(g, "{\"rimRootSpkiSha256\":[\"aa\"],\"firmware\":{\"minVbiosVersion\":\"96.00.a0\"}}").verify(ev, BINDING, NOW).reason);
        assertEquals("firmware policy: driver 535.86 is on the deny list",
            hooked(g, "{\"rimRootSpkiSha256\":[\"aa\"],\"firmware\":{\"denyDriverVersions\":[\"535.86.0\"]}}").verify(ev, BINDING, NOW).reason);
        assertEquals("firmware policy: VBIOS 96.00.9f.00.04 is on the deny list",
            hooked(g, "{\"rimRootSpkiSha256\":[\"aa\"],\"firmware\":{\"denyVbiosVersions\":[\"96.0.9F.0.4\"]}}").verify(ev, BINDING, NOW).reason);
        assertEquals("no RIM collateral supplied for this report",
            hooked(g, "{\"rimRootSpkiSha256\":[\"aa\"],\"firmware\":{\"minDriverVersion\":\"535.86\"}}").verify(ev, BINDING, NOW).reason);
        Map<String, Object> withCol = new HashMap<>(ev);
        withCol.put("collateral", new HashMap<String, Object>());
        assertEquals("driver RIM: RIM: empty or oversized document", hooked(g, "{\"rimRootSpkiSha256\":[\"aa\"]}").verify(withCol, BINDING, NOW).reason);
        Map<String, Object> col = new HashMap<>();
        col.put("driverRimXml", "<a/>");
        col.put("vbiosRimXml", "");
        withCol.put("collateral", col);
        assertEquals("driver RIM: RIM: root element is not SoftwareIdentity", hooked(g, "{\"rimRootSpkiSha256\":[\"aa\"]}").verify(withCol, BINDING, NOW).reason);
        col.put("driverRimXml", "<SoftwareIdentity/>");
        assertEquals("driver RIM: RIM: expected exactly one Signature element", hooked(g, "{\"rimRootSpkiSha256\":[\"aa\"]}").verify(withCol, BINDING, NOW).reason);
        // chip family: a GB100 report against a GH100 leaf
        byte[] gb = sign(g.leaf, transcript(nonceOf(BINDING), Arrays.asList(block(1, M1)), cat(opaqueAll("570.1"), tlvOpaque(35, "GB100\0".getBytes(StandardCharsets.ISO_8859_1)))));
        assertEquals("device leaf subject 'CN=GH100 A01 FSP BROM' is not a GB100 device certificate (chip family mismatch)",
            hooked(g, "{\"rimRootSpkiSha256\":[\"aa\"]}").verify(evidence(g, gb), BINDING, NOW).reason);
    }

    @Test
    void rimIdsNaming() {
        AttestNvidia.SpdmReport rep = AttestNvidia.parseSpdmEvidence(cat(transcript(new byte[32], Arrays.asList(block(1, M1)), opaqueAll("535.86")), new byte[96]));
        AttestNvidiaRim.RimIds ids = AttestNvidiaRim.rimIdsForReport(rep);
        assertEquals("GH100", ids.chip);
        assertEquals("NV_GPU_DRIVER_GH100_535.86", ids.driver);
        assertEquals("NV_GPU_VBIOS_PG520_0200_G520_96009F0004", ids.vbios);
        rep.opaque.put(35, "GB100".getBytes(StandardCharsets.ISO_8859_1));
        assertEquals("NV_GPU_CC_DRIVER_GB100_535.86", AttestNvidiaRim.rimIdsForReport(rep).driver);
        rep.opaque.put(35, "gb100".getBytes(StandardCharsets.ISO_8859_1));
        assertNull(AttestNvidiaRim.rimIdsForReport(rep));
        rep.opaque.put(35, new byte[0]);
        assertNull(AttestNvidiaRim.rimIdsForReport(rep));
        rep.opaque.remove(35);
        rep.opaque.put(3, " \0\0".getBytes(StandardCharsets.ISO_8859_1));
        assertNull(AttestNvidiaRim.rimIdsForReport(rep));
    }

    static AttestNvidiaRim.Rim rim(Object[]... rows) {
        Map<Long, AttestNvidiaRim.Golden> m = new HashMap<>();
        for (Object[] r : rows) {
            long idx = (Long) r[0];
            @SuppressWarnings("unchecked")
            List<String> hashes = (List<String>) r[2];
            m.put(idx, new AttestNvidiaRim.Golden(idx, (Boolean) r[1], hashes.size(), 48, hashes));
        }
        return new AttestNvidiaRim.Rim("GH100", "1", m);
    }

    @Test
    void goldenComparison() {
        List<byte[]> blocks = new ArrayList<>();
        for (int i = 1; i <= 35; i++) blocks.add(block(i, filled(48, i)));
        AttestNvidia.SpdmReport rep = AttestNvidia.parseSpdmEvidence(cat(transcript(new byte[32], blocks, tlvOpaque(11, new byte[] {0x55})), new byte[96]));
        String h0 = AttestCommon.toHexLower(filled(48, 1));
        String h34 = AttestCommon.toHexLower(filled(48, 35));
        // index i of a RIM is block i + 1 of the report
        assertEquals("", AttestNvidiaRim.compareReportToRims(rep, rim(new Object[] {0L, true, Arrays.asList("ff", h0)}), rim(new Object[] {1L, false, Arrays.asList("00")})));
        assertEquals("runtime measurements differ from the golden RIM values at 1 index(es)",
            AttestNvidiaRim.compareReportToRims(rep, rim(new Object[] {0L, true, Arrays.asList("ff")}), rim()));
        assertEquals("driver and VBIOS RIMs both have an active measurement at index 0",
            AttestNvidiaRim.compareReportToRims(rep, rim(new Object[] {0L, true, Arrays.asList(h0)}), rim(new Object[] {0L, true, Arrays.asList(h0)})));
        assertEquals("RIMs carry no active golden measurements", AttestNvidiaRim.compareReportToRims(rep, rim(new Object[] {0L, false, Arrays.asList(h0)}), rim()));
        // NVDEC0 disabled (opaque 11 = 0x55): block 35 (RIM index 34) is not compared
        assertEquals("", AttestNvidiaRim.compareReportToRims(rep, rim(new Object[] {34L, true, Arrays.asList("ff")}), rim()));
        rep.opaque.put(11, new byte[] {0x54});
        assertEquals("runtime measurements differ from the golden RIM values at 1 index(es)",
            AttestNvidiaRim.compareReportToRims(rep, rim(new Object[] {34L, true, Arrays.asList("ff")}), rim()));
        assertEquals("", AttestNvidiaRim.compareReportToRims(rep, rim(new Object[] {34L, true, Arrays.asList(h34)}), rim()));
        // a golden index the report does not carry
        assertEquals("runtime measurements differ from the golden RIM values at 2 index(es)",
            AttestNvidiaRim.compareReportToRims(rep, rim(new Object[] {40L, true, Arrays.asList(h0)}, new Object[] {0L, true, Arrays.asList("ab")}), rim()));
        AttestNvidia.SpdmReport one = AttestNvidia.parseSpdmEvidence(cat(transcript(new byte[32], Arrays.asList(block(1, M1)), new byte[0]), new byte[96]));
        assertEquals("RIMs list more active measurements than the report carries",
            AttestNvidiaRim.compareReportToRims(one, rim(new Object[] {0L, true, Arrays.asList(h0)}), rim(new Object[] {1L, true, Arrays.asList(h0)})));
    }

    @Test
    void versions() {
        assertEquals(0, AttestNvidiaRim.cmpVersion(AttestNvidiaRim.parseVersion("535.86", 10), AttestNvidiaRim.parseVersion("535.86.0", 10)));
        assertEquals(-1, AttestNvidiaRim.cmpVersion(AttestNvidiaRim.parseVersion("535.86", 10), AttestNvidiaRim.parseVersion("535.104", 10)));
        assertEquals(1, AttestNvidiaRim.cmpVersion(AttestNvidiaRim.parseVersion("96.00.a0", 16), AttestNvidiaRim.parseVersion("96.00.9f.00.04", 16)));
        assertNull(AttestNvidiaRim.parseVersion("96.00000", 16));
        assertNull(AttestNvidiaRim.parseVersion("a.1", 10));
        assertNull(AttestNvidiaRim.parseVersion("", 10));
        assertEquals(1e20, AttestNvidiaRim.parseVersion("100000000000000000000", 10)[0]);
    }

    // ------------------------------------------------------------- CRL / OCSP readers

    @Test
    void revocationReaders() {
        Gpu g = new Gpu();
        CertKey k = AttestCert.keyOfCert(AttestCert.parseCertDer(g.rootDer));
        assertEquals("CRL parse failed: DER truncated", AttestNvidiaRim.verifyCrl(new byte[] {0x30}, k, NOW).reason);
        assertEquals("CRL parse failed: CRL: bad outer SEQUENCE", AttestNvidiaRim.verifyCrl(new byte[] {0x31, 0x00}, k, NOW).reason);
        List<AttCert> chain = Arrays.asList(AttestCert.parseCertDer(g.leafDer), AttestCert.parseCertDer(g.rootDer));
        assertEquals("no CRLs supplied", AttestNvidiaRim.checkChainRevocation(chain, new ArrayList<>(), NOW, new ArrayList<>()));
        assertEquals("CRL #0 rejected: CRL parse failed: DER truncated", AttestNvidiaRim.checkChainRevocation(chain, Arrays.asList(new byte[] {0x30}), NOW, new ArrayList<>()));
        assertEquals("chain too short for OCSP", AttestNvidiaOcsp.checkChainOcsp(chain.subList(0, 1), Arrays.asList(new byte[] {0}), NOW));
        assertEquals("no OCSP responses supplied", AttestNvidiaOcsp.checkChainOcsp(chain, new ArrayList<>(), NOW));
        assertEquals("OCSP response #0 for 'CN=GH100 A01 FSP BROM' rejected: response is not valid DER",
            AttestNvidiaOcsp.checkChainOcsp(chain, Arrays.asList(new byte[] {0x30}), NOW));
        assertEquals("OCSP response #0 for 'CN=GH100 A01 FSP BROM' rejected: trailing bytes after OCSPResponse",
            AttestNvidiaOcsp.checkChainOcsp(chain, Arrays.asList(new byte[] {0x30, 0x00, 0x00}), NOW));
        assertEquals("OCSP response #0 for 'CN=GH100 A01 FSP BROM' rejected: OCSP responseStatus is 6 (not successful)",
            AttestNvidiaOcsp.checkChainOcsp(chain, Arrays.asList(seq(withTag(0x0a, new byte[] {6}))), NOW));
        assertEquals("OCSP response #0 for 'CN=GH100 A01 FSP BROM' rejected: successful response carries no responseBytes",
            AttestNvidiaOcsp.checkChainOcsp(chain, Arrays.asList(seq(withTag(0x0a, new byte[] {0}))), NOW));
        assertEquals("OCSP response #0 for 'CN=GH100 A01 FSP BROM' rejected: OCSP response rejected: malformed OCSPResponse",
            AttestNvidiaOcsp.checkChainOcsp(chain, Arrays.asList(seq(withTag(0x02, new byte[] {0}))), NOW));
    }

    @Test
    void ocspTimes() {
        assertEquals(Long.valueOf(0L), AttestNvidiaOcsp.timeMs("19700101000000Z", false));
        assertEquals(Long.valueOf(123L), AttestNvidiaOcsp.timeMs("19700101000000.123Z", false));
        assertEquals(Long.valueOf(500L), AttestNvidiaOcsp.timeMs("19700101000000.5Z", false));
        assertNull(AttestNvidiaOcsp.timeMs("19700101000000.50Z", false)); // trailing zero in the fraction
        assertNull(AttestNvidiaOcsp.timeMs("20230229000000Z", false)); // no roll-over
        assertEquals(Long.valueOf(951782400000L), AttestNvidiaOcsp.timeMs("000229000000Z", true)); // 2000-02-29
        assertEquals(Long.valueOf(-631152000000L), AttestNvidiaOcsp.timeMs("500101000000Z", true)); // 1950
        assertNull(AttestNvidiaOcsp.timeMs("20231301000000Z", false));
        assertNull(AttestNvidiaOcsp.timeMs("20230101240000Z", false));
        assertNull(AttestNvidiaOcsp.timeMs("20230100000000Z", false));
        // the CRL reader rolls over like Date.UTC
        assertEquals(AttestNvidiaRim.dateUtc(2023, 3, 1, 0, 0, 0), AttestNvidiaRim.dateUtc(2023, 2, 29, 0, 0, 0));
        assertEquals(AttestNvidiaRim.dateUtc(1950, 1, 1, 0, 0, 0), AttestNvidiaRim.dateUtc(50, 1, 1, 0, 0, 0));
    }
}
