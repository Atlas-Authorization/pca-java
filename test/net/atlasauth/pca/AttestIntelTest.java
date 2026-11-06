package net.atlasauth.pca;

import static net.atlasauth.pca.AttestVendorRows.BINDING;
import static net.atlasauth.pca.AttestVendorRows.NOW;
import static net.atlasauth.pca.AttestVendorRows.assertDenied;
import static net.atlasauth.pca.AttestVendorRows.b64;
import static net.atlasauth.pca.AttestVendorRows.cfg;
import static net.atlasauth.pca.AttestVendorRows.constructError;
import static net.atlasauth.pca.AttestVendorRows.pem;
import static net.atlasauth.pca.AttestVendorRows.run;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Intel TDX DCAP: vector replay, constructor refusals, the fail-closed table, a generated quote, the PCS collateral pieces. */
public class AttestIntelTest {
    static final String V = "intel-tdx-dcap";
    static final String M96 = "a".repeat(96);
    static final String CFG = "{\"binding\":\"report-data\",\"policy\":{\"mrtds\":[\"" + M96 + "\"]}}";

    @Test
    void vectors() { AttestVendorRows.replayVendor(V); }

    @Test
    void constructRefusals() {
        String m = "\"" + M96 + "\"";
        assertEquals("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'",
            constructError(V, "{\"binding\":\"x\",\"policy\":{\"mrtds\":[" + m + "]}}"));
        assertEquals("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)",
            constructError(V, "{\"binding\":\"report-data\",\"policy\":{}}"));
        assertEquals("createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)",
            constructError(V, "{\"binding\":\"report-data\",\"policy\":{\"mrtds\":[\"abc\"]}}"));
        assertEquals("createIntelDcapVerifier: policy.mrSeams, if given, must be a NON-EMPTY list",
            constructError(V, "{\"binding\":\"report-data\",\"policy\":{\"mrtds\":[" + m + "],\"mrSeams\":[]}}"));
        assertEquals("createIntelDcapVerifier: every mrSignerSeams entry must be 96 hex chars (48 bytes)",
            constructError(V, "{\"binding\":\"report-data\",\"policy\":{\"mrtds\":[" + m + "],\"mrSignerSeams\":[\"zz\"]}}"));
        assertEquals("createIntelDcapVerifier: policy.mrSeams, if given, must be a NON-EMPTY list",
            constructError(V, "{\"binding\":\"report-data\",\"policy\":{\"mrtds\":[" + m + "],\"mrSeams\":null}}"));
        assertNull(constructError(V, "{\"binding\":\"report-data\",\"policy\":{\"mrtds\":[" + m + "],\"mrSeams\":[" + m + "]}}"));
    }

    @Test
    void failClosedTable() {
        byte[] bad = new byte[700];
        bad[0] = 4;
        bad[2] = 2;
        bad[4] = (byte) 0x81;
        bad[632] = (byte) 0xff;
        bad[633] = (byte) 0xff;
        Object[][] rows = {
            {"nil evidence", null, BINDING, "no Intel DCAP quote for this action"},
            {"no binding", ev("quote", "AA=="), null, "no expected attestation binding supplied"},
            {"short quote", ev("quote", "AA=="), BINDING, "DCAP quote invalid: quote parse failed: parseDcapQuote: too short for header + TD report + sig length"},
            {"version 0", ev("quote", b64(new byte[700])), BINDING, "DCAP quote invalid: quote parse failed: parseDcapQuote: unsupported quote version 0 (expected 4)"},
            {"signature data overruns", ev("quote", b64(bad)), BINDING, "DCAP quote invalid: quote parse failed: parseDcapQuote: signature data (65535) overruns the quote"},
        };
        for (Object[] r : rows) {
            @SuppressWarnings("unchecked")
            Map<String, Object> e = (Map<String, Object>) r[1];
            assertDenied((String) r[0], run(V, cfg(CFG), e, (AttestationBinding) r[2], NOW), (String) r[3], false);
        }
    }

    @Test
    void quoteParserRefusals() {
        byte[] q = new byte[700];
        q[0] = 4;
        assertEquals("parseDcapQuote: unsupported attestation key type 0 (expected ECDSA-P256 = 2)", parseErr(q));
        q[2] = 2;
        q[4] = 0x7f;
        assertEquals("parseDcapQuote: unexpected TEE type 0x7f (expected TDX = 0x81)", parseErr(q));
        q[4] = (byte) 0x81;
        q[632] = 10; // signature data of 10 bytes
        assertEquals("parseDcapQuote: truncated reading quote signature", parseErr(q));
    }

    private static String parseErr(byte[] q) {
        try {
            AttestIntel.parseDcapQuote(q);
            return null;
        } catch (AttestException e) {
            return e.getMessage();
        }
    }

    static Map<String, Object> ev(Object... kv) { return AttestAmdTest.ev(kv); }

    // ------------------------------------------------------------- a generated genuine quote

    static final String SGX = "1.2.840.113741.1.13.1";

    /** The Intel SGX extension: the TCB (16 SGX SVNs + PCESVN) and the FMSPC, in the order the byte scan reads them. */
    static byte[] sgxExtension(int[] sgxSvns, int pcesvn, byte[] fmspc) {
        List<byte[]> comps = new ArrayList<>();
        for (int i = 0; i < 16; i++) comps.add(AttestTestDer.seq(AttestTestDer.oid(SGX + ".2." + (i + 1)), AttestTestDer.integer(sgxSvns[i])));
        comps.add(AttestTestDer.seq(AttestTestDer.oid(SGX + ".2.17"), AttestTestDer.integer(pcesvn)));
        comps.add(AttestTestDer.seq(AttestTestDer.oid(SGX + ".2.18"), AttestTestDer.octets(new byte[16])));
        byte[] tcb = AttestTestDer.seq(AttestTestDer.oid(SGX + ".2"), AttestTestDer.seq(comps.toArray(new byte[0][])));
        byte[] fm = AttestTestDer.seq(AttestTestDer.oid(SGX + ".4"), AttestTestDer.octets(fmspc));
        return AttestTestDer.ext(SGX, false, AttestTestDer.seq(tcb, fm));
    }

    static void le(ByteArrayOutputStream o, long v, int n) {
        for (int i = 0; i < n; i++) o.write((int) (v >>> (8 * i)) & 0xff);
    }

    static final class Genuine {
        final KeyPair root = AttestTestDer.ecKey("secp256r1");
        final KeyPair ca = AttestTestDer.ecKey("secp256r1");
        final KeyPair pck = AttestTestDer.ecKey("secp256r1");
        final KeyPair ak = AttestTestDer.ecKey("secp256r1");
        final byte[] fmspc = {0x00, (byte) 0x90, 0x6e, (byte) 0xd5, 0x00, 0x00};
        final byte[] mrTd = new byte[48];
        final int[] sgxSvns = new int[16];
        byte[] reportData = AttestCommon.attestationBindingBytes(BINDING);
        boolean tdDebug;
        boolean qeDebug;
        byte[] rootDer;
        byte[] caDer;
        byte[] pckDer;

        Genuine() {
            Arrays.fill(mrTd, (byte) 0x11);
            for (int i = 0; i < 16; i++) sgxSvns[i] = i + 1;
            rootDer = AttestTestDer.cert("Intel SGX Root CA", "Intel SGX Root CA", root, root, AttestTestDer.basicConstraints(true, 1), AttestTestDer.keyUsageCertSign());
            caDer = AttestTestDer.cert("Intel SGX PCK Platform CA", "Intel SGX Root CA", ca, root, AttestTestDer.basicConstraints(true, 0), AttestTestDer.keyUsageCertSign());
            pckDer = AttestTestDer.cert("Intel SGX PCK Certificate", "Intel SGX PCK Platform CA", pck, ca, sgxExtension(sgxSvns, 13, fmspc));
        }

        String pin() { return AttestCommon.toHexLower(AttestCommon.sha256Sum(root.getPublic().getEncoded())); }

        String chainPem() { return pem(pckDer) + pem(caDer) + pem(rootDer); }

        byte[] body() {
            byte[] b = new byte[AttestIntel.TD_REPORT_LEN];
            b[0] = 3; // tee_tcb_svn: SEAM SVN 3, minor 0 (the tdxModule identity applies)
            if (tdDebug) b[120] = 1;
            System.arraycopy(mrTd, 0, b, 136, 48);
            System.arraycopy(reportData, 0, b, 520, 64);
            return b;
        }

        byte[] akRaw() {
            ECPublicKey k = (ECPublicKey) ak.getPublic();
            byte[] out = new byte[64];
            fill(k.getW().getAffineX().toByteArray(), out, 0);
            fill(k.getW().getAffineY().toByteArray(), out, 32);
            return out;
        }

        private static void fill(byte[] v, byte[] dst, int off) {
            int skip = v.length > 32 ? v.length - 32 : 0;
            System.arraycopy(v, skip, dst, off + 32 - (v.length - skip), v.length - skip);
        }

        byte[] quote() {
            byte[] header = new byte[AttestIntel.HEADER_LEN];
            header[0] = 4;
            header[2] = 2;
            header[4] = (byte) 0x81;
            byte[] body = body();
            byte[] akRaw = akRaw();
            byte[] auth = "auth".getBytes(StandardCharsets.US_ASCII);
            byte[] qe = new byte[AttestIntel.SGX_REPORT];
            if (qeDebug) qe[AttestIntel.QE_ATTR_OFF] = 0x02;
            byte[] akBinding = AttestCommon.sha256Sum(AttestTestDer.cat(akRaw, auth));
            System.arraycopy(akBinding, 0, qe, AttestIntel.QE_RDATA_OFF, 32);
            byte[] qeSig = AttestVendorRows.signRaw(pck, "SHA256", qe);
            byte[] quoteSig = AttestVendorRows.signRaw(ak, "SHA256", AttestTestDer.cat(header, body));
            byte[] chain = chainPem().getBytes(StandardCharsets.US_ASCII);

            ByteArrayOutputStream inner = new ByteArrayOutputStream();
            inner.write(qe, 0, qe.length);
            inner.write(qeSig, 0, 64);
            le(inner, auth.length, 2);
            inner.write(auth, 0, auth.length);
            le(inner, 5, 2);
            le(inner, chain.length, 4);
            inner.write(chain, 0, chain.length);
            byte[] outerBody = inner.toByteArray();

            ByteArrayOutputStream sig = new ByteArrayOutputStream();
            sig.write(quoteSig, 0, 64);
            sig.write(akRaw, 0, 64);
            le(sig, 6, 2);
            le(sig, outerBody.length, 4);
            sig.write(outerBody, 0, outerBody.length);
            byte[] sigData = sig.toByteArray();

            ByteArrayOutputStream q = new ByteArrayOutputStream();
            q.write(header, 0, header.length);
            q.write(body, 0, body.length);
            le(q, sigData.length, 4);
            q.write(sigData, 0, sigData.length);
            return q.toByteArray();
        }

        Map<String, Object> config(String extra) {
            return cfg("{\"binding\":\"report-data\",\"trustAnchorRootCaSpkiSha256\":\"" + pin() + "\",\"allowMissingCollateral\":true,\"policy\":{\"mrtds\":[\""
                + AttestCommon.toHexLower(mrTd) + "\"]" + extra + "}}");
        }
    }

    @Test
    void genuineQuoteVerifies() {
        Genuine g = new Genuine();
        HardwareResult r = run(V, g.config(""), ev("quote", b64(g.quote())), BINDING, NOW);
        assertTrue(r.ok, r.reason);
        assertTrue(r.bound);
        assertEquals(AttestCommon.toHexLower(g.mrTd), r.measured.get("runtime_measurement"));
        assertEquals("", r.measured.get("operator"));
        Map<String, String> host = new LinkedHashMap<>();
        host.put("attestation_type", "tdx-dcap");
        host.put("fmspc", "00906ed50000");
        host.put("tcb_status", "unevaluated");
        assertEquals(host, r.hostAsserted);

        AttestIntel.PckTcb t = AttestIntel.extractPckFmspcAndTcb(g.pckDer);
        assertArrayEquals(g.fmspc, t.fmspc);
        assertEquals(13, t.pcesvn);
        for (int i = 0; i < 16; i++) assertEquals(i + 1, t.sgx[i]);
    }

    @Test
    void genuineQuoteRefusals() {
        Genuine g = new Genuine();
        byte[] quote = g.quote();
        String pre = "DCAP quote invalid: ";
        assertDenied("collateral required", run(V, cfg("{\"binding\":\"report-data\",\"trustAnchorRootCaSpkiSha256\":\"" + g.pin()
            + "\",\"policy\":{\"mrtds\":[\"" + AttestCommon.toHexLower(g.mrTd) + "\"]}}"), ev("quote", b64(quote)), BINDING, NOW),
            "Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)", false);
        assertDenied("wrong pin", run(V, cfg(CFG), ev("quote", b64(quote)), BINDING, NOW),
            pre + "PCK chain invalid: Intel SGX Root CA does not match the pinned trust anchor", false);
        assertDenied("mrtd", run(V, cfg("{\"binding\":\"report-data\",\"trustAnchorRootCaSpkiSha256\":\"" + g.pin()
            + "\",\"allowMissingCollateral\":true,\"policy\":{\"mrtds\":[\"" + M96 + "\"]}}"), ev("quote", b64(quote)), BINDING, NOW),
            pre + "MRTD not in policy allowlist", false);
        assertDenied("fmspc", run(V, g.config(",\"fmspcs\":[\"000000000000\"]"), ev("quote", b64(quote)), BINDING, NOW), pre + "FMSPC not in policy allowlist", false);
        assertDenied("mrseam", run(V, g.config(",\"mrSeams\":[\"" + M96 + "\"]"), ev("quote", b64(quote)), BINDING, NOW), pre + "MRSEAM not in policy allowlist", false);
        assertDenied("binding", run(V, g.config(""), ev("quote", b64(quote)), new AttestationBinding("holder-key", "passport:abc", 1, "nonce-1"), NOW),
            "report_data does not bind holder/grant/epoch/nonce", false);
        assertDenied("expired", run(V, g.config(""), ev("quote", b64(quote)), BINDING, 2_200_000_000_000L),
            pre + "PCK chain invalid: PCK chain certificate outside its validity period", false);

        byte[] tampered = quote.clone();
        tampered[AttestIntel.HEADER_LEN + 136] ^= 1; // MRTD byte under the quote signature
        assertDenied("tampered", run(V, g.config(""), ev("quote", b64(tampered)), BINDING, NOW),
            pre + "TD quote signature does not verify under the attestation key", false);

        Genuine dbg = new Genuine();
        dbg.tdDebug = true;
        assertDenied("td debug", run(V, dbg.config(""), ev("quote", b64(dbg.quote())), BINDING, NOW), pre + "TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)", false);
        assertTrue(run(V, dbg.config(",\"allowDebug\":true"), ev("quote", b64(dbg.quote())), BINDING, NOW).ok);

        Genuine qd = new Genuine();
        qd.qeDebug = true;
        assertDenied("qe debug", run(V, qd.config(""), ev("quote", b64(qd.quote())), BINDING, NOW), pre + "QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)", false);

        byte[] trailing = Arrays.copyOf(quote, quote.length + 1);
        trailing[quote.length] = 1;
        assertDenied("trailing", run(V, g.config(""), ev("quote", b64(trailing)), BINDING, NOW),
            pre + "quote parse failed: parseDcapQuote: non-zero bytes after the signature data", false);
    }

    // ------------------------------------------------------------- PCS collateral pieces

    /** A CRL issued and signed (ECDSA / SHA-256) by signer, revoking the given serials. */
    static byte[] crl(KeyPair signer, String thisUpdate, String nextUpdate, long... serials) {
        List<byte[]> revoked = new ArrayList<>();
        for (long s : serials) revoked.add(AttestTestDer.seq(AttestTestDer.integer(s), AttestTestDer.withTag(0x17, "250101000000Z".getBytes(StandardCharsets.US_ASCII))));
        byte[] tbs = AttestTestDer.seq(AttestTestDer.integer(1), AttestTestDer.SIG_ALG_ECDSA_SHA256, AttestTestDer.name("Intel SGX Root CA"),
            AttestTestDer.withTag(0x17, thisUpdate.getBytes(StandardCharsets.US_ASCII)),
            AttestTestDer.withTag(0x17, nextUpdate.getBytes(StandardCharsets.US_ASCII)),
            revoked.isEmpty() ? new byte[0] : AttestTestDer.seq(revoked.toArray(new byte[0][])));
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(signer.getPrivate());
            s.update(tbs);
            return AttestTestDer.seq(tbs, AttestTestDer.SIG_ALG_ECDSA_SHA256, AttestTestDer.bits((byte) 0, s.sign()));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void crlVerification() {
        KeyPair k = AttestTestDer.ecKey("secp256r1");
        CertKey key = AttestCert.keyOfCert(AttestCert.parseCertDer(AttestTestDer.cert("Intel SGX Root CA", "Intel SGX Root CA", k, k)));
        AttestIntelCollateral.CrlResult ok = AttestIntelCollateral.verifyCrl(crl(k, "250101000000Z", "350101000000Z", 258, 2815), key, NOW);
        assertEquals("", ok.reason);
        assertTrue(ok.revoked.contains("102") && ok.revoked.contains("aff") && ok.revoked.size() == 2, String.valueOf(ok.revoked));
        assertEquals("CRL is stale (nextUpdate passed)", AttestIntelCollateral.verifyCrl(crl(k, "250101000000Z", "260101000000Z"), key, NOW).reason);
        assertEquals("CRL thisUpdate is in the future", AttestIntelCollateral.verifyCrl(crl(k, "300101000000Z", "350101000000Z"), key, NOW).reason);
        KeyPair other = AttestTestDer.ecKey("secp256r1");
        assertEquals("CRL signature does not verify under the issuer", AttestIntelCollateral.verifyCrl(crl(other, "250101000000Z", "350101000000Z"), key, NOW).reason);
        assertEquals("CRL parse failed: CRL: bad outer SEQUENCE", AttestIntelCollateral.verifyCrl(new byte[] {0x31, 0x00}, key, NOW).reason);
        assertEquals("CRL parse failed: DER truncated", AttestIntelCollateral.verifyCrl(new byte[] {0x30}, key, NOW).reason);
        // the nextUpdate boundary is inclusive (stale only after it)
        long next = AttestIntelCollateral.dateUtc(2035, 1, 1, 0, 0, 0);
        assertEquals("", AttestIntelCollateral.verifyCrl(crl(k, "250101000000Z", "350101000000Z"), key, next).reason);
        assertEquals("CRL is stale (nextUpdate passed)", AttestIntelCollateral.verifyCrl(crl(k, "250101000000Z", "350101000000Z"), key, next + 1).reason);
    }

    @Test
    void dateUtcRollsOver() {
        assertEquals(AttestIntelCollateral.dateUtc(2025, 3, 1, 0, 0, 0), AttestIntelCollateral.dateUtc(2025, 2, 29, 0, 0, 0));
        assertEquals(AttestIntelCollateral.dateUtc(2026, 1, 1, 0, 0, 0), AttestIntelCollateral.dateUtc(2025, 13, 1, 0, 0, 0));
        assertEquals(AttestIntelCollateral.dateUtc(1999, 1, 1, 0, 0, 0), AttestIntelCollateral.dateUtc(99, 1, 1, 0, 0, 0));
        assertEquals(946684800000L, AttestIntelCollateral.dateUtc(2000, 1, 1, 0, 0, 0));
    }

    @Test
    void signedJsonDocuments() {
        assertEquals("{\"a\":\"}\\\"{\"}", AttestIntelCollateral.rawJsonObject(" {\"tcbInfo\" : {\"a\":\"}\\\"{\"},\"signature\":\"x\"}", "tcbInfo"));
        assertNull(AttestIntelCollateral.rawJsonObject("{\"signature\":\"x\",\"tcbInfo\":{}}", "tcbInfo"));
        assertNull(AttestIntelCollateral.rawJsonObject("{\"tcbInfo\":[1]}", "tcbInfo"));

        KeyPair k = AttestTestDer.ecKey("secp256r1");
        CertKey key = AttestCert.keyOfCert(AttestCert.parseCertDer(AttestTestDer.cert("TCB Signing", "TCB Signing", k, k)));
        String body = "{\"id\":\"TDX\", \"version\":3}";
        String sig = AttestCommon.toHexLower(AttestVendorRows.signRaw(k, "SHA256", body.getBytes(StandardCharsets.UTF_8)));
        AttestIntelCollateral.SignedBody ok = AttestIntelCollateral.verifySignedJson("{\"tcbInfo\":" + body + ",\"signature\":\"" + sig + "\"}", "tcbInfo", key);
        assertEquals("", ok.reason);
        assertEquals("TDX", ok.body.get("id"));
        // the signature covers the exact bytes: re-spacing the body breaks it
        assertEquals("tcbInfo signature does not verify under the TCB Signing certificate",
            AttestIntelCollateral.verifySignedJson("{\"tcbInfo\":{\"id\":\"TDX\",\"version\":3},\"signature\":\"" + sig + "\"}", "tcbInfo", key).reason);
        assertEquals("tcbInfo signature missing or malformed",
            AttestIntelCollateral.verifySignedJson("{\"tcbInfo\":" + body + ",\"signature\":\"" + sig.substring(2) + "\"}", "tcbInfo", key).reason);
        assertEquals("tcbInfo not found / malformed", AttestIntelCollateral.verifySignedJson("[]", "tcbInfo", key).reason);
        assertEquals("tcbInfo document is not valid JSON", AttestIntelCollateral.verifySignedJson("{\"tcbInfo\":{}", "tcbInfo", key).reason);
    }

    @Test
    void freshness() {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("issueDate", "2027-01-01T00:00:00Z");
        b.put("nextUpdate", "2027-02-01T00:00:00Z");
        assertEquals("", AttestIntelCollateral.checkFresh(b, "TCB info", AttestIntelCollateral.dateUtc(2027, 1, 15, 0, 0, 0)));
        assertEquals("TCB info: issueDate is in the future", AttestIntelCollateral.checkFresh(b, "TCB info", AttestIntelCollateral.dateUtc(2026, 12, 31, 0, 0, 0)));
        assertEquals("TCB info: stale (nextUpdate passed)", AttestIntelCollateral.checkFresh(b, "TCB info", AttestIntelCollateral.dateUtc(2027, 2, 1, 0, 0, 1)));
        b.put("nextUpdate", "soon");
        assertEquals("TCB info: issueDate/nextUpdate missing", AttestIntelCollateral.checkFresh(b, "TCB info", NOW));
    }

    // ------------------------------------------------------------- TCB / QE identity evaluation

    static List<Object> svns(int v) {
        List<Object> out = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("svn", new Json.Num(Integer.toString(v)));
            out.add(m);
        }
        return out;
    }

    static Map<String, Object> level(int sgx, int tdx, int pce, String status, String... adv) {
        Map<String, Object> tcb = new LinkedHashMap<>();
        tcb.put("sgxtcbcomponents", svns(sgx));
        tcb.put("tdxtcbcomponents", svns(tdx));
        tcb.put("pcesvn", new Json.Num(Integer.toString(pce)));
        Map<String, Object> l = new LinkedHashMap<>();
        l.put("tcb", tcb);
        l.put("tcbStatus", status);
        l.put("advisoryIDs", new ArrayList<Object>(Arrays.asList((Object[]) adv)));
        return l;
    }

    static Map<String, Object> info(Object... levels) {
        Map<String, Object> mod = new LinkedHashMap<>();
        mod.put("mrsigner", "00".repeat(48));
        mod.put("attributes", "0000000000000000");
        mod.put("attributesMask", "ffffffffffffffff");
        Map<String, Object> i = new LinkedHashMap<>();
        i.put("tdxModule", mod);
        i.put("tcbLevels", new ArrayList<Object>(Arrays.asList(levels)));
        return i;
    }

    @Test
    void tcbEvaluation() {
        byte[] sgx = new byte[16];
        Arrays.fill(sgx, (byte) 5);
        byte[] tee = new byte[16];
        Arrays.fill(tee, (byte) 5);
        tee[1] = 0;
        byte[] mr = new byte[48];
        byte[] attr = new byte[8];
        Map<String, Object> inf = info(level(6, 6, 1, "UpToDate"), level(5, 0, 10, "SWHardeningNeeded", "INTEL-SA-2"), level(0, 0, 0, "OutOfDate", "INTEL-SA-1"));
        AttestIntelCollateral.TcbEval t = AttestIntelCollateral.evaluateTcb(inf, sgx, 10, tee, mr, attr);
        assertNull(t.err);
        assertEquals("SWHardeningNeeded", t.platform);
        assertEquals("UpToDate", t.module);
        assertEquals(Arrays.asList("INTEL-SA-2"), t.advisories);
        // a PCESVN one below the level skips it
        assertEquals("OutOfDate", AttestIntelCollateral.evaluateTcb(inf, sgx, 9, tee, mr, attr).platform);
        assertEquals("platform TCB is below every level in the TCB info",
            AttestIntelCollateral.evaluateTcb(info(level(6, 6, 1, "UpToDate")), sgx, 10, tee, mr, attr).err);
        byte[] mr2 = new byte[48];
        mr2[0] = 1;
        assertEquals("TD report MRSIGNERSEAM does not match the TDX module identity", AttestIntelCollateral.evaluateTcb(inf, sgx, 10, tee, mr2, attr).err);
        byte[] attr2 = new byte[8];
        attr2[7] = 1;
        assertEquals("TD report SEAM attributes do not match the TDX module identity", AttestIntelCollateral.evaluateTcb(inf, sgx, 10, tee, mr, attr2).err);
        assertEquals("TCB info has no tcbLevels", AttestIntelCollateral.evaluateTcb(info(), sgx, 10, tee, mr, attr).err);
        byte[] tee2 = tee.clone();
        tee2[1] = 3;
        assertEquals("TDX module identity TDX_03 not present in TCB info", AttestIntelCollateral.evaluateTcb(inf, sgx, 10, tee2, mr, attr).err);
        assertEquals("TCB level has an unknown tcbStatus",
            AttestIntelCollateral.evaluateTcb(info(level(0, 0, 0, "Fine")), sgx, 10, tee, mr, attr).err);
    }

    @Test
    void qeIdentityEvaluation() {
        Map<String, Object> id = new LinkedHashMap<>();
        id.put("id", "TD_QE");
        id.put("version", new Json.Num("2"));
        id.put("miscselect", "00000000");
        id.put("miscselectMask", "ffffffff");
        id.put("attributes", "00".repeat(16));
        id.put("attributesMask", "ff".repeat(16));
        id.put("mrsigner", "00".repeat(32));
        id.put("isvprodid", new Json.Num("2"));
        Map<String, Object> lvl = new LinkedHashMap<>();
        Map<String, Object> tcb = new LinkedHashMap<>();
        tcb.put("isvsvn", new Json.Num("4"));
        lvl.put("tcb", tcb);
        lvl.put("tcbStatus", "UpToDate");
        id.put("tcbLevels", new ArrayList<Object>(Arrays.asList((Object) lvl)));
        byte[] qe = new byte[384];
        qe[256] = 2;
        qe[258] = 4;
        assertEquals("UpToDate", AttestIntelCollateral.evaluateQe(id, qe).status);
        qe[258] = 3;
        assertEquals("QE ISVSVN is below every known level", AttestIntelCollateral.evaluateQe(id, qe).err);
        qe[258] = 4;
        qe[256] = 1;
        assertEquals("QE ISVPRODID does not match the QE identity", AttestIntelCollateral.evaluateQe(id, qe).err);
        qe[256] = 2;
        qe[128] = 1;
        assertEquals("QE MRSIGNER does not match the QE identity", AttestIntelCollateral.evaluateQe(id, qe).err);
        qe[128] = 0;
        qe[48] = 1;
        assertEquals("QE ATTRIBUTES do not match the QE identity", AttestIntelCollateral.evaluateQe(id, qe).err);
        qe[48] = 0;
        assertEquals("QE report has wrong length", AttestIntelCollateral.evaluateQe(id, new byte[383]).err);
        id.put("id", "QE");
        assertEquals("QE identity id is not TD_QE", AttestIntelCollateral.evaluateQe(id, qe).err);
    }

    @Test
    void statusOrder() {
        assertEquals("OutOfDate", AttestIntelCollateral.worstStatus("UpToDate", "OutOfDate"));
        assertEquals("Revoked", AttestIntelCollateral.worstStatus("Revoked", "OutOfDate"));
        assertEquals("SWHardeningNeeded", AttestIntelCollateral.worstStatus("SWHardeningNeeded", "SWHardeningNeeded"));
        assertFalse(AttestIntelCollateral.DEFAULT_ACCEPTED_STATUSES.contains("ConfigurationNeeded"));
        assertEquals("collateral incomplete (fail closed)",
            AttestIntelCollateral.verifyIntelTdxCollateral(new byte[0], new AttestIntelCollateral.Collateral(), NOW, null, AttestIntel.SGX_ROOT_CA_SPKI_SHA256, false).reason);
    }
}
