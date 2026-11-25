package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.SIG_ALG_ECDSA_SHA256;
import static net.atlasauth.pca.AttestTestDer.basicConstraints;
import static net.atlasauth.pca.AttestTestDer.bits;
import static net.atlasauth.pca.AttestTestDer.cat;
import static net.atlasauth.pca.AttestTestDer.ecKey;
import static net.atlasauth.pca.AttestTestDer.integer;
import static net.atlasauth.pca.AttestTestDer.keyUsageCertSign;
import static net.atlasauth.pca.AttestTestDer.name;
import static net.atlasauth.pca.AttestTestDer.octets;
import static net.atlasauth.pca.AttestTestDer.oid;
import static net.atlasauth.pca.AttestTestDer.seq;
import static net.atlasauth.pca.AttestTestDer.withTag;
import static net.atlasauth.pca.AttestVendorRows.BINDING;
import static net.atlasauth.pca.AttestVendorRows.NOW;
import static net.atlasauth.pca.AttestVendorRows.b64;
import static net.atlasauth.pca.AttestVendorRows.cfg;
import static net.atlasauth.pca.AttestVendorRows.constructError;
import static net.atlasauth.pca.AttestVendorRows.pem;
import static net.atlasauth.pca.AttestVendorRows.run;
import static net.atlasauth.pca.AttestVendorRows.signRaw;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Exact-outcome kill tests for the Intel TDX DCAP quote path (AttestIntel): the quote parser at every truncation point, the
 * lenient TLV reader and the SGX-extension byte scan, the PCK chain walk, the genuine-quote checks and the factory.
 * {@link Fx} also builds a complete, valid PCS collateral set (used by AttestIntelCollateralK05KillTest).
 */
public class AttestIntelK05KillTest {
    static final String V = "intel-tdx-dcap";
    static final String SGX = "1.2.840.113741.1.13.1";
    static final String M96 = "a".repeat(96);

    static byte[] b(int... v) {
        byte[] o = new byte[v.length];
        for (int i = 0; i < v.length; i++) o[i] = (byte) v[i];
        return o;
    }

    static byte[] le(long v, int n) {
        byte[] o = new byte[n];
        for (int i = 0; i < n; i++) o[i] = (byte) (v >>> (8 * i));
        return o;
    }

    static byte[] derSign(KeyPair k, byte[] msg) {
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(k.getPrivate());
            s.update(msg);
            return s.sign();
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A certificate with an explicit serial and validity (ECDSA / SHA-256 signature by signer). */
    static byte[] mkCert(long serial, String subjectCn, String issuerCn, String notBefore, String notAfter, KeyPair subject, KeyPair signer, byte[]... extensions) {
        byte[] exts = extensions.length == 0 ? new byte[0] : withTag(0xa3, seq(cat(extensions)));
        byte[] tbs = seq(withTag(0xa0, integer(2)), integer(serial), SIG_ALG_ECDSA_SHA256, name(issuerCn),
            seq(withTag(0x17, notBefore.getBytes(StandardCharsets.US_ASCII)), withTag(0x17, notAfter.getBytes(StandardCharsets.US_ASCII))),
            name(subjectCn), subject.getPublic().getEncoded(), exts);
        return seq(tbs, SIG_ALG_ECDSA_SHA256, bits((byte) 0, derSign(signer, tbs)));
    }

    static int[] seqSvns() {
        int[] a = new int[16];
        for (int i = 0; i < 16; i++) a[i] = i + 1;
        return a;
    }

    static byte[] rawPoint(KeyPair k) {
        ECPublicKey p = (ECPublicKey) k.getPublic();
        byte[] out = new byte[64];
        fit(p.getW().getAffineX().toByteArray(), out, 0);
        fit(p.getW().getAffineY().toByteArray(), out, 32);
        return out;
    }

    private static void fit(byte[] v, byte[] dst, int off) {
        int skip = v.length > 32 ? v.length - 32 : 0;
        System.arraycopy(v, skip, dst, off + 32 - (v.length - skip), v.length - skip);
    }

    // ------------------------------------------------------------- JSON text helpers (PCS documents)

    static String q(String s) { return "\"" + s + "\""; }

    static String arr(String... items) { return "[" + String.join(",", items) + "]"; }

    /** An object of key / raw-JSON-value pairs; a null value leaves the key out. */
    static String obj(String... kv) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kv.length; i += 2) {
            if (kv[i + 1] == null) continue;
            if (sb.length() > 1) sb.append(',');
            sb.append('"').append(kv[i]).append("\":").append(kv[i + 1]);
        }
        return sb.append('}').toString();
    }

    static String quoted(String... s) {
        String[] o = new String[s.length];
        for (int i = 0; i < s.length; i++) o[i] = q(s[i]);
        return arr(o);
    }

    static int[] all(int v) {
        int[] a = new int[16];
        Arrays.fill(a, v);
        return a;
    }

    static String comps(int[] v) {
        String[] s = new String[v.length];
        for (int i = 0; i < v.length; i++) s[i] = "{\"svn\":" + v[i] + "}";
        return arr(s);
    }

    static String level(int[] sgx, int[] tdx, int pce, String status, String... adv) {
        return obj("tcb", obj("sgxtcbcomponents", comps(sgx), "pcesvn", String.valueOf(pce), "tdxtcbcomponents", comps(tdx)),
            "tcbStatus", q(status), "advisoryIDs", quoted(adv));
    }

    static final String MODULE = obj("mrsigner", q("00".repeat(48)), "attributes", q("00".repeat(8)), "attributesMask", q("ff".repeat(8)));
    static final String ISSUE = "2025-06-01T00:00:00Z";
    static final String NEXT = "2030-01-01T00:00:00Z";

    static String tcbInfo(String id, String version, String issue, String next, String fmspc, String eval, String levels) {
        return obj("id", id, "version", version, "issueDate", issue, "nextUpdate", next, "fmspc", fmspc, "tcbEvaluationDataNumber", eval,
            "tdxModule", MODULE, "tcbLevels", levels);
    }

    static String qeLevel(int isvsvn, String status, String... adv) {
        return obj("tcb", obj("isvsvn", String.valueOf(isvsvn)), "tcbStatus", q(status), "advisoryIDs", quoted(adv));
    }

    static String qeIdentity(String version, String issue, String next, String eval, String levels) {
        return obj("id", q("TD_QE"), "version", version, "issueDate", issue, "nextUpdate", next, "tcbEvaluationDataNumber", eval,
            "miscselect", q("00000000"), "miscselectMask", q("ffffffff"), "attributes", q("00".repeat(16)), "attributesMask", q("ff".repeat(16)),
            "mrsigner", q("00".repeat(32)), "isvprodid", "0", "tcbLevels", levels);
    }

    /** A PCS document: {"name": body, "signature": hex(r||s over the exact body bytes)}. */
    static String signed(String name, String body, KeyPair k) {
        return "{\"" + name + "\":" + body + ",\"signature\":\"" + AttestCommon.toHexLower(signRaw(k, "SHA256", body.getBytes(StandardCharsets.UTF_8))) + "\"}";
    }

    /**
     * A complete, valid genuine TDX quote (root serial 1, PCK CA 2, PCK leaf 3) and its PCS collateral (TCB Signing serial 4
     * under the same root); every part can be overridden before quote() / collateral().
     */
    static final class Fx {
        final KeyPair root = ecKey("secp256r1");
        final KeyPair ca = ecKey("secp256r1");
        final KeyPair pck = ecKey("secp256r1");
        final KeyPair ak = ecKey("secp256r1");
        final KeyPair tcbSigner = ecKey("secp256r1");
        final KeyPair other = ecKey("secp256r1");
        final byte[] fmspc = {0x00, (byte) 0x90, 0x6e, (byte) 0xd5, 0x00, 0x00};
        final byte[] rootDer;
        final byte[] caDer;
        final byte[] pckDer;
        final byte[] tcbDer;
        final byte[] body = new byte[AttestIntel.TD_REPORT_LEN];
        byte[] auth = "auth".getBytes(StandardCharsets.US_ASCII);
        byte[] akRaw;
        /** null: the default QE report (binding the AK, everything else zero). */
        byte[] qe;
        KeyPair qeSigner;
        String chain;

        String tcbInfoBody = tcbInfo(q("TDX"), "3", q(ISSUE), q(NEXT), q("00906ed50000"), "17",
            arr(level(all(1), all(0), 13, "UpToDate", "INTEL-SA-B", "INTEL-SA-A")));
        String qeBody = qeIdentity("2", q(ISSUE), q(NEXT), "17", arr(qeLevel(0, "UpToDate", "INTEL-SA-C")));
        KeyPair tcbJsonSigner;
        KeyPair qeJsonSigner;
        String tcbChain;
        String qeChain;
        KeyPair rootCrlSigner;
        KeyPair pckCrlSigner;
        long[] rootRevoked = {};
        long[] pckRevoked = {};
        AttestIntelCollateral.Policy pol;
        boolean allowDebug;

        Fx() {
            rootDer = mkCert(1, "Intel SGX Root CA", "Intel SGX Root CA", "250101000000Z", "350101000000Z", root, root, basicConstraints(true, 1), keyUsageCertSign());
            caDer = mkCert(2, "Intel SGX PCK Platform CA", "Intel SGX Root CA", "250101000000Z", "350101000000Z", ca, root, basicConstraints(true, 0), keyUsageCertSign());
            pckDer = mkCert(3, "Intel SGX PCK Certificate", "Intel SGX PCK Platform CA", "250101000000Z", "350101000000Z", pck, ca,
                AttestIntelTest.sgxExtension(seqSvns(), 13, fmspc));
            tcbDer = mkCert(4, "Intel SGX TCB Signing", "Intel SGX Root CA", "250101000000Z", "350101000000Z", tcbSigner, root);
            body[0] = 3; // tee_tcb_svn: SEAM SVN 3, minor 0 (the tdxModule identity applies)
            Arrays.fill(body, 136, 184, (byte) 0x11);
            System.arraycopy(AttestCommon.attestationBindingBytes(BINDING), 0, body, 520, 64);
            akRaw = rawPoint(ak);
            qeSigner = pck;
            chain = pem(pckDer) + pem(caDer) + pem(rootDer);
            tcbJsonSigner = tcbSigner;
            qeJsonSigner = tcbSigner;
            tcbChain = pem(tcbDer) + pem(rootDer);
            qeChain = pem(tcbDer) + pem(rootDer);
            rootCrlSigner = root;
            pckCrlSigner = ca;
        }

        String pin() { return AttestCommon.toHexLower(AttestCommon.sha256Sum(root.getPublic().getEncoded())); }

        String mrTd() { return AttestCommon.toHexLower(Arrays.copyOfRange(body, 136, 184)); }

        byte[] defaultQe() {
            byte[] r = new byte[AttestIntel.SGX_REPORT];
            System.arraycopy(AttestCommon.sha256Sum(cat(akRaw, auth)), 0, r, AttestIntel.QE_RDATA_OFF, 32);
            return r;
        }

        byte[] quote() {
            byte[] header = new byte[AttestIntel.HEADER_LEN];
            header[0] = 4;
            header[2] = 2;
            header[4] = (byte) 0x81;
            byte[] qeR = qe != null ? qe : defaultQe();
            byte[] qeSig = signRaw(qeSigner, "SHA256", qeR);
            byte[] quoteSig = signRaw(ak, "SHA256", cat(header, body));
            byte[] ch = chain.getBytes(StandardCharsets.US_ASCII);
            byte[] inner = cat(qeR, qeSig, le(auth.length, 2), auth, le(5, 2), le(ch.length, 4), ch);
            byte[] sig = cat(quoteSig, akRaw, le(6, 2), le(inner.length, 4), inner);
            return cat(header, body, le(sig.length, 4), sig);
        }

        AttestIntelCollateral.Collateral collateral() {
            AttestIntelCollateral.Collateral c = new AttestIntelCollateral.Collateral();
            c.tcbInfoJson = signed("tcbInfo", tcbInfoBody, tcbJsonSigner);
            c.tcbInfoChain = tcbChain;
            c.qeIdentityJson = signed("enclaveIdentity", qeBody, qeJsonSigner);
            c.qeIdentityChain = qeChain;
            c.rootCrl = AttestIntelTest.crl(rootCrlSigner, "250101000000Z", "350101000000Z", rootRevoked);
            c.pckCrl = AttestIntelTest.crl(pckCrlSigner, "250101000000Z", "350101000000Z", pckRevoked);
            return c;
        }

        Map<String, Object> wireCollateral() {
            AttestIntelCollateral.Collateral c = collateral();
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("tcbInfoJson", c.tcbInfoJson);
            m.put("tcbInfoIssuerChainPem", c.tcbInfoChain);
            m.put("qeIdentityJson", c.qeIdentityJson);
            m.put("qeIdentityIssuerChainPem", c.qeIdentityChain);
            m.put("pckCrlDer", b64(c.pckCrl));
            m.put("rootCrlDer", b64(c.rootCrl));
            return m;
        }

        AttestIntelCollateral.Result run() {
            return AttestIntelCollateral.verifyIntelTdxCollateral(quote(), collateral(), NOW, pol, pin(), allowDebug);
        }

        /** The verifier config: report-data binding, this root pinned, the MRTD allowed, plus extra policy / top-level members. */
        Map<String, Object> config(String policyExtra, String topExtra) {
            return cfg("{\"binding\":\"report-data\",\"trustAnchorRootCaSpkiSha256\":\"" + pin() + "\"" + topExtra + ",\"policy\":{\"mrtds\":[\"" + mrTd() + "\"]"
                + policyExtra + "}}");
        }
    }

    // ------------------------------------------------------------- parseDcapQuote truncation points

    /** header (version) + an all-zero TD report + the signature data length + sigData. */
    static byte[] rq(int version, byte[] sigData) {
        byte[] header = new byte[AttestIntel.HEADER_LEN];
        header[0] = (byte) version;
        header[1] = (byte) (version >> 8);
        header[2] = 2;
        header[4] = (byte) 0x81;
        return cat(header, new byte[AttestIntel.TD_REPORT_LEN], le(sigData.length, 4), sigData);
    }

    static String perr(byte[] quote) {
        try {
            AttestIntel.parseDcapQuote(quote);
            return "ok";
        } catch (AttestException e) {
            return e.getMessage();
        }
    }

    static final String P = "parseDcapQuote: truncated reading ";

    static byte[] z(int n) { return new byte[n]; }

    static byte[] outer(long size) { return cat(le(6, 2), le(size, 4)); }

    @Test
    void parserTruncationPoints() {
        assertEquals("parseDcapQuote: unsupported quote version 260 (expected 4)", perr(rq(260, z(0))));
        byte[] min = rq(4, z(0));
        assertEquals(636, min.length);
        assertEquals(P + "quote signature", perr(min));
        assertEquals(P + "outer cert-data header", perr(rq(4, z(128))));
        assertEquals(P + "QE report", perr(rq(4, cat(z(128), outer(0)))));
        assertEquals(P + "QE report", perr(rq(4, cat(z(128), outer(0), z(10)))));
        assertEquals(P + "QE report signature", perr(rq(4, cat(z(128), outer(0), z(384)))));
        assertEquals(P + "QE report signature", perr(rq(4, cat(z(128), outer(0), z(394)))));
        assertEquals(P + "QE auth-data size", perr(rq(4, cat(z(128), outer(0), z(448)))));
        assertEquals(P + "QE auth-data size", perr(rq(4, cat(z(128), outer(0), z(449)))));
        assertEquals(P + "inner cert-data header", perr(rq(4, cat(z(128), outer(0), z(450)))));
        assertEquals(P + "inner cert-data header", perr(rq(4, cat(z(128), outer(0), z(453)))));
        // the shortest complete signature data: empty auth data and an empty PCK chain, ending exactly at the inner header
        byte[] ok = rq(4, cat(z(128), outer(456), z(450), le(5, 2), le(0, 4)));
        assertEquals("ok", perr(ok));
        AttestIntel.DcapQuote d = AttestIntel.parseDcapQuote(ok);
        assertEquals("", d.pckChainPem);
        assertEquals(0, d.qeAuthData.length);
        assertEquals(384, d.qeReportBody.length);
    }

    // ------------------------------------------------------------- readDerTlvLenient / indexOfBytes

    static void tlv(AttestDer.Tlv t, int tag, int start, int end) {
        assertNotNull(t);
        assertEquals(tag, t.tag);
        assertEquals(start, t.start);
        assertEquals(end, t.end);
    }

    @Test
    void lenientTlvReader() {
        tlv(AttestIntel.readDerTlvLenient(b(0x04, 0x00), 0), 4, 2, 2);
        tlv(AttestIntel.readDerTlvLenient(b(0x09, 0x04, 0x00), 1), 4, 3, 3);
        assertNull(AttestIntel.readDerTlvLenient(b(0x04), 0));
        assertNull(AttestIntel.readDerTlvLenient(b(0x04, 0x00, 0x04, 0x00), -1));
        tlv(AttestIntel.readDerTlvLenient(b(0x04, 0x84, 0, 0, 0, 1, 7), 0), 4, 6, 7);
        tlv(AttestIntel.readDerTlvLenient(b(0x04, 0x81, 0x00), 0), 4, 3, 3);
        assertNull(AttestIntel.readDerTlvLenient(b(0x04, 0x85, 0, 0, 0, 0, 0), 0));
        assertNull(AttestIntel.readDerTlvLenient(b(0x04, 0x80, 0, 0), 0));
        assertNull(AttestIntel.readDerTlvLenient(b(0x04, 0x82, 0x00), 0));
        byte[] big = new byte[4 + 256];
        big[0] = 0x04;
        big[1] = (byte) 0x82;
        big[2] = 0x01;
        tlv(AttestIntel.readDerTlvLenient(big, 0), 4, 4, 260);
        assertNull(AttestIntel.readDerTlvLenient(b(0x04, 0x05, 1), 0));
    }

    @Test
    void indexOfBytes() {
        assertEquals(0, AttestIntel.indexOfBytes(b(1, 2), b(1, 2)));
        assertEquals(1, AttestIntel.indexOfBytes(b(9, 1, 2), b(1, 2)));
        assertEquals(-1, AttestIntel.indexOfBytes(b(9, 2), b(1, 2)));
        assertEquals(-1, AttestIntel.indexOfBytes(b(1), b(1, 2)));
    }

    // ------------------------------------------------------------- the SGX extension byte scan

    static final byte[] FMSPC6 = {0x00, (byte) 0x90, 0x6e, (byte) 0xd5, 0x00, 0x00};
    static final byte[] FM = cat(AttestIntel.OID_SGX_FMSPC, octets(FMSPC6));

    static byte[] comp(int n, byte[] value) { return seq(oid(SGX + ".2." + n), value); }

    static List<byte[]> std(int pce) {
        List<byte[]> out = new ArrayList<>();
        for (int i = 1; i <= 16; i++) out.add(comp(i, integer(i)));
        out.add(comp(17, integer(pce)));
        return out;
    }

    static byte[] tcb(List<byte[]> comps) { return cat(AttestIntel.OID_SGX_TCB, seq(comps.toArray(new byte[0][]))); }

    static String xerr(byte[] leaf) {
        try {
            AttestIntel.extractPckFmspcAndTcb(leaf);
            return "ok";
        } catch (AttestException e) {
            return e.getMessage();
        }
    }

    static final String X = "extractPckFmspcAndTcb: ";

    @Test
    void sgxExtensionScanAccepts() {
        // the FMSPC OID at offset 0, the TCB SEQUENCE last
        AttestIntel.PckTcb t = AttestIntel.extractPckFmspcAndTcb(cat(FM, tcb(std(13))));
        assertArrayEquals(FMSPC6, t.fmspc);
        assertEquals(16, t.sgx.length);
        for (int i = 0; i < 16; i++) assertEquals(i + 1, t.sgx[i]);
        assertEquals(13, t.pcesvn);
        // the TCB OID at offset 0, the FMSPC right after the TCB SEQUENCE (the component walk stops at its end)
        t = AttestIntel.extractPckFmspcAndTcb(cat(tcb(std(13)), FM));
        assertEquals(13, t.pcesvn);
        assertEquals(16, t.sgx[15]);
        // a PCESVN of 0 is present
        assertEquals(0, AttestIntel.extractPckFmspcAndTcb(cat(FM, tcb(std(0)))).pcesvn);
    }

    @Test
    void sgxExtensionScanRefusals() {
        assertEquals(X + "FMSPC OID not found in certificate", xerr(tcb(std(13))));
        assertEquals(X + "TCB OID not found in certificate", xerr(FM));
        assertEquals(X + "malformed FMSPC OCTET STRING", xerr(cat(AttestIntel.OID_SGX_FMSPC, withTag(0x05, FMSPC6), tcb(std(13)))));
        assertEquals(X + "malformed FMSPC OCTET STRING", xerr(cat(AttestIntel.OID_SGX_FMSPC, octets(z(5)), tcb(std(13)))));
        assertEquals(X + "malformed FMSPC OCTET STRING", xerr(cat(tcb(std(13)), AttestIntel.OID_SGX_FMSPC)));
        assertEquals(X + "malformed TCB SEQUENCE", xerr(cat(FM, AttestIntel.OID_SGX_TCB, withTag(0x31, integer(1)))));
        assertEquals(X + "malformed TCB SEQUENCE", xerr(cat(FM, AttestIntel.OID_SGX_TCB)));
        assertEquals(X + "malformed TCB component", xerr(cat(FM, AttestIntel.OID_SGX_TCB, seq(withTag(0x31, integer(1))))));
        assertEquals(X + "malformed TCB component", xerr(cat(FM, AttestIntel.OID_SGX_TCB, withTag(0x30, b(0x30, 0x05)))));
        assertEquals(X + "TCB component missing OID", xerr(cat(FM, AttestIntel.OID_SGX_TCB, seq(seq(integer(1), integer(1))))));
        assertEquals(X + "TCB component missing OID", xerr(cat(FM, AttestIntel.OID_SGX_TCB, seq(seq()))));
        assertEquals(X + "TCB component missing value", xerr(cat(FM, AttestIntel.OID_SGX_TCB, seq(seq(oid(SGX + ".2.1"))))));
        List<byte[]> noPce = std(13);
        noPce.remove(16);
        assertEquals(X + "PCESVN not found in TCB extension", xerr(cat(FM, tcb(noPce))));
    }

    @Test
    void sgxExtensionComponentValues() {
        // a non-INTEGER value is skipped
        List<byte[]> c = std(13);
        c.set(0, comp(1, octets(b(7))));
        assertEquals(0, AttestIntel.extractPckFmspcAndTcb(cat(FM, tcb(c))).sgx[0]);
        // multi-byte INTEGERs: the SVN keeps the low byte, the PCESVN the low 16 bits
        c = std(258);
        c.set(0, comp(1, integer(0x0105)));
        AttestIntel.PckTcb t = AttestIntel.extractPckFmspcAndTcb(cat(FM, tcb(c)));
        assertEquals(5, t.sgx[0]);
        assertEquals(258, t.pcesvn);
        // component numbers 0 and 18 are ignored (no SVN slot, not the PCESVN)
        c = std(13);
        c.add(comp(0, integer(9)));
        c.add(comp(18, integer(99)));
        t = AttestIntel.extractPckFmspcAndTcb(cat(FM, tcb(c)));
        assertEquals(13, t.pcesvn);
        for (int i = 0; i < 16; i++) assertEquals(i + 1, t.sgx[i]);
    }

    @Test
    void sgxExtensionWalksAtMost65Components() {
        List<byte[]> c = new ArrayList<>();
        for (int i = 0; i < 64; i++) c.add(comp(18, octets(z(1))));
        c.add(comp(17, integer(13)));
        assertEquals(13, AttestIntel.extractPckFmspcAndTcb(cat(FM, tcb(c))).pcesvn);
        c.add(0, comp(18, octets(z(1))));
        assertEquals(X + "PCESVN not found in TCB extension", xerr(cat(FM, tcb(c))));
    }

    // ------------------------------------------------------------- PCK chain

    @Test
    void pckChainOutcomes() {
        Fx f = new Fx();
        AttestIntel.PckChainResult r = AttestIntel.verifyIntelPckChain(f.chain, f.pin(), NOW);
        assertTrue(r.ok, r.reason);
        assertEquals("", r.reason);
        assertFalse(r.validity);
        assertEquals(3, r.depth);
        assertArrayEquals(f.pckDer, r.leaf.raw);
        // the pin is compared case-insensitively
        assertTrue(AttestIntel.verifyIntelPckChain(f.chain, f.pin().toUpperCase(java.util.Locale.ROOT), NOW).ok);
        // a lone pinned self-signed root is its own leaf
        r = AttestIntel.verifyIntelPckChain(pem(f.rootDer), f.pin(), NOW);
        assertTrue(r.ok, r.reason);
        assertEquals(1, r.depth);
        assertArrayEquals(f.rootDer, r.leaf.raw);
        // validity is inclusive at notAfter, refused one millisecond later (and flagged as a validity failure)
        long notAfter = AttestIntelCollateral.dateUtc(2035, 1, 1, 0, 0, 0);
        assertTrue(AttestIntel.verifyIntelPckChain(f.chain, f.pin(), notAfter).ok);
        r = AttestIntel.verifyIntelPckChain(f.chain, f.pin(), notAfter + 1);
        assertFalse(r.ok);
        assertTrue(r.validity);
        assertEquals("PCK chain certificate outside its validity period", r.reason);
        // two certificates issuing each other: the walk stops at the repeat
        KeyPair ka = ecKey("secp256r1");
        KeyPair kb = ecKey("secp256r1");
        String cycle = pem(mkCert(10, "A", "B", "250101000000Z", "350101000000Z", ka, kb)) + pem(mkCert(11, "B", "A", "250101000000Z", "350101000000Z", kb, ka));
        r = AttestIntel.verifyIntelPckChain(cycle, f.pin(), NOW);
        assertEquals("PCK chain does not terminate in a self-signed root", r.reason);
        assertFalse(r.validity);
    }

    // ------------------------------------------------------------- genuine quote

    @Test
    void genuineQuoteWholeResult() {
        Fx f = new Fx();
        // an empty policy object allows everything (the empty allowlists are skipped)
        AttestIntel.TdxResult r = AttestIntel.verifyGenuineTdxQuote(f.quote(), f.pin(), NOW, new AttestIntel.QuotePolicy(), false);
        assertTrue(r.ok, r.reason);
        assertEquals("", r.reason);
        assertEquals("00906ed50000", r.fmspc);
        assertArrayEquals(Arrays.copyOfRange(f.body, 136, 184), r.mrTd);
        assertArrayEquals(Arrays.copyOfRange(f.body, 520, 584), r.reportData);
        assertEquals(13, r.pck.pcesvn);

        AttestIntel.QuotePolicy seams = new AttestIntel.QuotePolicy();
        seams.hasMrSeams = true; // flagged with the default (empty) list: nothing is allowed
        assertEquals("MRSEAM not in policy allowlist", AttestIntel.verifyGenuineTdxQuote(f.quote(), f.pin(), NOW, seams, false).reason);
        AttestIntel.QuotePolicy signers = new AttestIntel.QuotePolicy();
        signers.hasMrSigner = true;
        assertEquals("MRSIGNERSEAM not in policy allowlist", AttestIntel.verifyGenuineTdxQuote(f.quote(), f.pin(), NOW, signers, false).reason);

        AttestIntel.TdxResult bad = AttestIntel.verifyGenuineTdxQuote(new byte[1], f.pin(), NOW, null, false);
        assertFalse(bad.ok);
        assertEquals("quote parse failed: parseDcapQuote: too short for header + TD report + sig length", bad.reason);
        assertEquals("", bad.fmspc);
        assertNull(bad.pck);
    }

    @Test
    void qeReportDataTailMustBeZero() {
        for (int off : new int[] {AttestIntel.QE_RDATA_OFF + 32, AttestIntel.SGX_REPORT - 1}) {
            Fx f = new Fx();
            f.qe = f.defaultQe();
            f.qe[off] = 1;
            assertEquals("QE report_data does not bind the attestation key (AK not endorsed by this QE)",
                AttestIntel.verifyGenuineTdxQuote(f.quote(), f.pin(), NOW, null, false).reason, "byte " + off);
        }
    }

    @Test
    void attestationKeyMustBeACurvePoint() {
        Fx f = new Fx();
        f.akRaw = new byte[64]; // (0, 0) is not on P-256; the QE still endorses it
        assertEquals("attestation public key is not a valid P-256 point", AttestIntel.verifyGenuineTdxQuote(f.quote(), f.pin(), NOW, null, false).reason);
    }

    @Test
    void p256CompactNeedsExactly64Bytes() {
        KeyPair k = ecKey("secp256r1");
        ECPublicKey pub = (ECPublicKey) k.getPublic();
        byte[] msg = "m".getBytes(StandardCharsets.US_ASCII);
        byte[] sig = signRaw(k, "SHA256", msg);
        assertTrue(AttestIntel.verifyP256Compact(msg, sig, pub));
        // r and s each left-padded with a zero byte still verify as raw ECDSA, but are not the 64-byte compact form
        byte[] padded = cat(z(1), Arrays.copyOfRange(sig, 0, 32), z(1), Arrays.copyOfRange(sig, 32, 64));
        assertTrue(AttestCommon.verifyRawECDSA(pub, AttestCommon.sha256Sum(msg), padded));
        assertFalse(AttestIntel.verifyP256Compact(msg, padded, pub));
    }

    // ------------------------------------------------------------- the factory and verify()

    @Test
    void factoryEdges() {
        assertNull(constructError(V, "{\"binding\":\"azure-runtime-data\",\"policy\":{\"mrtds\":[\"" + M96 + "\"]}}"));
        assertEquals("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)",
            constructError(V, "{\"binding\":\"report-data\"}"));
        // only mrSeams / mrSignerSeams are read from the policy (a caller map may hold any other key, even null)
        Map<String, Object> pol = new HashMap<>();
        pol.put("mrtds", new ArrayList<Object>(Arrays.asList(M96)));
        pol.put(null, "x");
        Map<String, Object> c = new HashMap<>();
        c.put("binding", "report-data");
        c.put("policy", pol);
        assertNotNull(AttestHarness.verifier(V, c));
    }

    @Test
    void policyListsAreLowercased() {
        Fx f = new Fx();
        Arrays.fill(f.body, 64, 112, (byte) 0xaa); // MRSIGNERSEAM
        Arrays.fill(f.body, 328, 376, (byte) 0xab); // RTMR0
        String extra = ",\"mrSignerSeams\":[\"" + "AA".repeat(48) + "\"],\"fmspcs\":[\"00906ED50000\"],\"rtmrs\":[\"" + "AB".repeat(48) + "\"]";
        HardwareResult r = run(V, f.config(extra, ",\"allowMissingCollateral\":true"), AttestIntelTest.ev("quote", b64(f.quote())), BINDING, NOW);
        assertTrue(r.ok, r.reason);
        Map<String, String> host = new LinkedHashMap<>();
        host.put("attestation_type", "tdx-dcap");
        host.put("fmspc", "00906ed50000");
        host.put("tcb_status", "unevaluated");
        assertEquals(host, r.hostAsserted);
    }
}
