package net.atlasauth.pca;

import static net.atlasauth.pca.AttestIntelK05KillTest.Fx;
import static net.atlasauth.pca.AttestIntelK05KillTest.MODULE;
import static net.atlasauth.pca.AttestIntelK05KillTest.NEXT;
import static net.atlasauth.pca.AttestIntelK05KillTest.all;
import static net.atlasauth.pca.AttestIntelK05KillTest.arr;
import static net.atlasauth.pca.AttestIntelK05KillTest.b;
import static net.atlasauth.pca.AttestIntelK05KillTest.derSign;
import static net.atlasauth.pca.AttestIntelK05KillTest.level;
import static net.atlasauth.pca.AttestIntelK05KillTest.mkCert;
import static net.atlasauth.pca.AttestIntelK05KillTest.obj;
import static net.atlasauth.pca.AttestIntelK05KillTest.q;
import static net.atlasauth.pca.AttestIntelK05KillTest.qeLevel;
import static net.atlasauth.pca.AttestIntelK05KillTest.signed;
import static net.atlasauth.pca.AttestTestDer.SIG_ALG_ECDSA_SHA256;
import static net.atlasauth.pca.AttestTestDer.basicConstraints;
import static net.atlasauth.pca.AttestTestDer.bits;
import static net.atlasauth.pca.AttestTestDer.ecKey;
import static net.atlasauth.pca.AttestTestDer.integer;
import static net.atlasauth.pca.AttestTestDer.keyUsageCertSign;
import static net.atlasauth.pca.AttestTestDer.name;
import static net.atlasauth.pca.AttestTestDer.octets;
import static net.atlasauth.pca.AttestTestDer.seq;
import static net.atlasauth.pca.AttestTestDer.utf8;
import static net.atlasauth.pca.AttestTestDer.withTag;
import static net.atlasauth.pca.AttestVendorRows.BINDING;
import static net.atlasauth.pca.AttestVendorRows.NOW;
import static net.atlasauth.pca.AttestVendorRows.b64;
import static net.atlasauth.pca.AttestVendorRows.pem;
import static net.atlasauth.pca.AttestVendorRows.run;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

/**
 * Exact-outcome kill tests for the Intel PCS collateral path (AttestIntelCollateral): the whole verifyIntelTdxCollateral
 * result over a generated valid collateral set and a tamper matrix of it, plus the CRL reader, the signed-JSON reader and
 * the TCB / QE identity evaluation units.
 */
public class AttestIntelCollateralK05KillTest {
    static final String V = "intel-tdx-dcap";

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(String json) { return new LinkedHashMap<>((Map<String, Object>) Json.parseLenient(json)); }

    static Object parse(String json) { return Json.parseLenient(json); }

    static String reason(Consumer<Fx> tweak) {
        Fx f = new Fx();
        tweak.accept(f);
        return f.run().reason;
    }

    // ------------------------------------------------------------- the whole result

    @Test
    void validCollateralWholeResult() {
        AttestIntelCollateral.Result r = new Fx().run();
        assertTrue(r.ok, r.reason);
        assertEquals("", r.reason);
        assertEquals("UpToDate", r.status);
        assertEquals(Arrays.asList("INTEL-SA-A", "INTEL-SA-B", "INTEL-SA-C"), r.advisoryIds);
    }

    @Test
    void incompleteCollateral() {
        String inc = "collateral incomplete (fail closed)";
        Fx f = new Fx();
        assertEquals(inc, AttestIntelCollateral.verifyIntelTdxCollateral(f.quote(), null, NOW, null, f.pin(), false).reason);
        List<Consumer<AttestIntelCollateral.Collateral>> blanks = Arrays.<Consumer<AttestIntelCollateral.Collateral>>asList(
            c -> c.tcbInfoJson = "", c -> c.qeIdentityJson = "", c -> c.pckCrl = null, c -> c.pckCrl = new byte[0],
            c -> c.rootCrl = null, c -> c.rootCrl = new byte[0], c -> c.tcbInfoChain = "", c -> c.qeIdentityChain = "");
        byte[] quote = f.quote();
        for (int i = 0; i < blanks.size(); i++) {
            AttestIntelCollateral.Collateral c = f.collateral();
            blanks.get(i).accept(c);
            assertEquals(inc, AttestIntelCollateral.verifyIntelTdxCollateral(quote, c, NOW, null, f.pin(), false).reason, "blank #" + i);
        }
        // the defaults of a fresh Collateral are empty strings (never null)
        AttestIntelCollateral.Collateral c = new AttestIntelCollateral.Collateral();
        c.tcbInfoJson = "x";
        assertEquals(inc, AttestIntelCollateral.verifyIntelTdxCollateral(quote, c, NOW, null, f.pin(), false).reason);
        c.qeIdentityJson = "x";
        c.pckCrl = new byte[] {1};
        c.rootCrl = new byte[] {1};
        assertEquals(inc, AttestIntelCollateral.verifyIntelTdxCollateral(quote, c, NOW, null, f.pin(), false).reason);
        c.tcbInfoChain = "x";
        assertEquals(inc, AttestIntelCollateral.verifyIntelTdxCollateral(quote, c, NOW, null, f.pin(), false).reason);
    }

    @Test
    void tamperMatrix() {
        assertEquals("quote invalid: quote parse failed: parseDcapQuote: too short for header + TD report + sig length",
            AttestIntelCollateral.verifyIntelTdxCollateral(new byte[10], new Fx().collateral(), NOW, null, new Fx().pin(), false).reason);
        assertEquals("PCK CA certificate is revoked by the Intel Root CA CRL", reason(f -> f.rootRevoked = new long[] {2}));
        assertEquals("PCK leaf certificate is revoked by the PCK CRL", reason(f -> f.pckRevoked = new long[] {3}));
        assertEquals("TCB info: issuer chain certificate is revoked by the Intel Root CA CRL", reason(f -> f.rootRevoked = new long[] {4}));
        assertEquals("Intel Root CA CRL: CRL signature does not verify under the issuer", reason(f -> f.rootCrlSigner = f.ca));
        assertEquals("PCK CRL: CRL signature does not verify under the issuer", reason(f -> f.pckCrlSigner = f.root));
        assertEquals("TCB info: issuer chain invalid: Intel SGX Root CA does not match the pinned trust anchor", reason(f -> f.tcbChain = otherChain(f)));
        assertEquals("TCB info: issuer chain certificate outside its validity period", reason(f -> f.tcbChain = pem(mkCert(4, "Intel SGX TCB Signing",
            "Intel SGX Root CA", "250101000000Z", "260101000000Z", f.tcbSigner, f.root)) + pem(f.rootDer)));
        assertEquals("TCB info: tcbInfo signature does not verify under the TCB Signing certificate", reason(f -> f.tcbJsonSigner = f.other));
        assertEquals("TCB info: stale (nextUpdate passed)", reason(f -> f.tcbInfoBody = f.tcbInfoBody.replace(NEXT, "2026-01-01T00:00:00Z")));
        String v3 = "TCB info is not a TDX v3 document";
        assertEquals(v3, reason(f -> f.tcbInfoBody = f.tcbInfoBody.replace("\"id\":\"TDX\"", "\"id\":\"SGX\"")));
        assertEquals(v3, reason(f -> f.tcbInfoBody = f.tcbInfoBody.replace("\"version\":3", "\"version\":2")));
        assertEquals(v3, reason(f -> f.tcbInfoBody = f.tcbInfoBody.replace("\"version\":3,", "")));
        String fm = "TCB info FMSPC does not match the quote PCK";
        assertEquals("", reason(f -> f.tcbInfoBody = f.tcbInfoBody.replace("00906ed50000", "00906ED50000")));
        assertEquals(fm, reason(f -> f.tcbInfoBody = f.tcbInfoBody.replace("00906ed50000", "000000000000")));
        assertEquals(fm, reason(f -> f.tcbInfoBody = f.tcbInfoBody.replace("\"00906ed50000\"", "5")));
        assertEquals("QE identity: issuer chain invalid: Intel SGX Root CA does not match the pinned trust anchor", reason(f -> f.qeChain = otherChain(f)));
        assertEquals("QE identity: enclaveIdentity signature does not verify under the TCB Signing certificate", reason(f -> f.qeJsonSigner = f.other));
        assertEquals("QE identity: stale (nextUpdate passed)", reason(f -> f.qeBody = f.qeBody.replace(NEXT, "2026-01-01T00:00:00Z")));
        assertEquals("TCB evaluation: platform TCB is below every level in the TCB info",
            reason(f -> f.tcbInfoBody = f.tcbInfoBody.replace("\"pcesvn\":13", "\"pcesvn\":14")));
        assertEquals("QE identity: QE ISVSVN is below every known level", reason(f -> f.qeBody = f.qeBody.replace("\"isvsvn\":0", "\"isvsvn\":1")));
        assertEquals("TCB evaluation: TD report MRSIGNERSEAM does not match the TDX module identity", reason(f -> f.body[64] = 1));
    }

    /** A TCB Signing chain under a different (unpinned) self-signed root with the same name. */
    static String otherChain(Fx f) {
        byte[] otherRoot = mkCert(1, "Intel SGX Root CA", "Intel SGX Root CA", "250101000000Z", "350101000000Z", f.other, f.other,
            basicConstraints(true, 1), keyUsageCertSign());
        return pem(mkCert(4, "Intel SGX TCB Signing", "Intel SGX Root CA", "250101000000Z", "350101000000Z", f.tcbSigner, f.other)) + pem(otherRoot);
    }

    @Test
    void evaluationDataNumbers() {
        assertEquals("", reason(f -> f.tcbInfoBody = f.tcbInfoBody.replace("\"tcbEvaluationDataNumber\":17", "\"tcbEvaluationDataNumber\":0")));
        assertEquals("", reason(f -> f.qeBody = f.qeBody.replace("\"tcbEvaluationDataNumber\":17", "\"tcbEvaluationDataNumber\":0")));
        assertEquals("tcbEvaluationDataNumber missing", reason(f -> f.tcbInfoBody = f.tcbInfoBody.replace("\"tcbEvaluationDataNumber\":17,", "")));
        assertEquals("tcbEvaluationDataNumber missing", reason(f -> f.qeBody = f.qeBody.replace("\"tcbEvaluationDataNumber\":17,", "")));
        String below = "tcbEvaluationDataNumber below policy minimum";
        assertEquals("", reason(f -> f.pol = minEval(false, 100)));
        assertEquals("", reason(f -> f.pol = minEval(true, 17)));
        assertEquals(below, reason(f -> f.pol = minEval(true, 18)));
        assertEquals(below, reason(f -> {
            f.pol = minEval(true, 18);
            f.tcbInfoBody = f.tcbInfoBody.replace("\"tcbEvaluationDataNumber\":17", "\"tcbEvaluationDataNumber\":20");
        }));
        assertEquals(below, reason(f -> {
            f.pol = minEval(true, 18);
            f.qeBody = f.qeBody.replace("\"tcbEvaluationDataNumber\":17", "\"tcbEvaluationDataNumber\":20");
        }));
    }

    static AttestIntelCollateral.Policy minEval(boolean has, double v) {
        AttestIntelCollateral.Policy p = new AttestIntelCollateral.Policy();
        p.hasMinEval = has;
        p.minEval = v;
        return p;
    }

    @Test
    void statusPolicy() {
        Fx f = new Fx();
        f.tcbInfoBody = f.tcbInfoBody.replace("\"UpToDate\"", "\"OutOfDate\"");
        AttestIntelCollateral.Result r = f.run();
        assertFalse(r.ok);
        assertEquals("TCB status OutOfDate is not accepted by policy", r.reason);
        assertEquals("OutOfDate", r.status);
        assertEquals(Arrays.asList("INTEL-SA-A", "INTEL-SA-B", "INTEL-SA-C"), r.advisoryIds);
        AttestIntelCollateral.Policy p = new AttestIntelCollateral.Policy();
        p.acceptStatuses = Arrays.asList("OutOfDate");
        f.pol = p; // the list is only honoured with hasAccept
        assertEquals("TCB status OutOfDate is not accepted by policy", f.run().reason);
        p.hasAccept = true;
        r = f.run();
        assertTrue(r.ok, r.reason);
        assertEquals("OutOfDate", r.status);
        // the QE status takes part in the worst-of
        Fx g = new Fx();
        g.qeBody = g.qeBody.replace("\"UpToDate\"", "\"SWHardeningNeeded\"");
        r = g.run();
        assertTrue(r.ok, r.reason);
        assertEquals("SWHardeningNeeded", r.status);
    }

    @Test
    void debugTdNeedsAllowDebug() {
        assertEquals("quote invalid: TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)", reason(f -> f.body[120] = 1));
        Fx f = new Fx();
        f.body[120] = 1;
        f.allowDebug = true;
        assertTrue(f.run().ok);
    }

    @Test
    void verifyWithCollateralHost() {
        Fx f = new Fx();
        HardwareResult r = run(V, f.config("", ""), AttestIntelTest.ev("quote", b64(f.quote()), "collateral", f.wireCollateral()), BINDING, NOW);
        assertTrue(r.ok, r.reason);
        Map<String, String> host = new LinkedHashMap<>();
        host.put("attestation_type", "tdx-dcap");
        host.put("fmspc", "00906ed50000");
        host.put("tcb_status", "UpToDate");
        host.put("advisory_ids", "INTEL-SA-A,INTEL-SA-B,INTEL-SA-C");
        assertEquals(host, r.hostAsserted);

        // no advisories: no advisory_ids member
        Fx g = new Fx();
        g.tcbInfoBody = g.tcbInfoBody.replace("[\"INTEL-SA-B\",\"INTEL-SA-A\"]", "[]");
        g.qeBody = g.qeBody.replace("[\"INTEL-SA-C\"]", "[]");
        r = run(V, g.config("", ""), AttestIntelTest.ev("quote", b64(g.quote()), "collateral", g.wireCollateral()), BINDING, NOW);
        assertTrue(r.ok, r.reason);
        host.remove("advisory_ids");
        assertEquals(host, r.hostAsserted);

        // a refusal carries the collateral reason; the configured collateral policy can accept the status
        Fx h = new Fx();
        h.tcbInfoBody = h.tcbInfoBody.replace("\"UpToDate\"", "\"OutOfDate\"");
        AttestVendorRows.assertDenied("not accepted", run(V, h.config("", ""), AttestIntelTest.ev("quote", b64(h.quote()), "collateral", h.wireCollateral()),
            BINDING, NOW), "Intel collateral: TCB status OutOfDate is not accepted by policy", false);
        r = run(V, h.config(",\"collateral\":{\"acceptStatuses\":[\"OutOfDate\"]}", ""), AttestIntelTest.ev("quote", b64(h.quote()), "collateral",
            h.wireCollateral()), BINDING, NOW);
        assertTrue(r.ok, r.reason);
        assertEquals("OutOfDate", r.hostAsserted.get("tcb_status"));
    }

    @Test
    void fromWireNonStrings() {
        Map<String, Object> w = new LinkedHashMap<>();
        w.put("tcbInfoJson", new Json.Num("5"));
        w.put("qeIdentityJson", "q");
        AttestIntelCollateral.Collateral c = AttestIntelCollateral.fromWire(w);
        assertEquals("", c.tcbInfoJson);
        assertEquals("q", c.qeIdentityJson);
        assertEquals("", c.tcbInfoChain);
        assertEquals("", c.qeIdentityChain);
        assertNull(c.pckCrl);
        assertNull(c.rootCrl);
    }

    // ------------------------------------------------------------- the seams under verifyIntelTdxCollateral

    @Test
    void quoteChainParts() {
        Fx f = new Fx();
        AttestIntelCollateral.QuoteCrls r = new AttestIntelCollateral.QuoteCrls();
        assertEquals("", AttestIntelCollateral.quoteCrls(r, f.quote(), f.collateral(), NOW));
        assertArrayEquals(f.pckDer, r.leaf.raw);
        assertArrayEquals(f.caDer, r.ca.raw);
        assertEquals("", r.rootCrl.reason);
        assertEquals("", r.pckCrl.reason);

        assertEquals("collateral verification error (fail closed): parseDcapQuote: too short for header + TD report + sig length",
            AttestIntelCollateral.quoteCrls(new AttestIntelCollateral.QuoteCrls(), new byte[10], f.collateral(), NOW));
        String[][] cases = {
            {pem(f.rootDer), "PCK leaf not found"},
            {pem(f.pckDer), "PCK CA not found in the quote chain"},
            {pem(f.pckDer) + pem(f.caDer), "Intel root not found in the quote chain"},
        };
        for (String[] c : cases) {
            f.chain = c[0];
            assertEquals(c[1], AttestIntelCollateral.quoteCrls(new AttestIntelCollateral.QuoteCrls(), f.quote(), f.collateral(), NOW));
        }
    }

    @Test
    void signerKeyFromChain() {
        Fx f = new Fx();
        AttestIntelCollateral.SignerKey k = AttestIntelCollateral.signerKeyFromChain(f.tcbChain, f.pin(), NOW, Collections.emptySet());
        assertEquals("", k.reason);
        assertArrayEquals(f.tcbSigner.getPublic().getEncoded(), k.key.spki);
        assertEquals("issuer chain invalid: Intel SGX Root CA does not match the pinned trust anchor",
            AttestIntelCollateral.signerKeyFromChain(otherChain(f), f.pin(), NOW, Collections.emptySet()).reason);
        AttestIntelCollateral.SignerKey exp = AttestIntelCollateral.signerKeyFromChain(f.tcbChain, f.pin(), AttestIntelCollateral.dateUtc(2035, 1, 1, 0, 0, 1),
            Collections.emptySet());
        assertEquals("issuer chain certificate outside its validity period", exp.reason);
        assertNull(exp.key);
        assertEquals("issuer chain certificate is revoked by the Intel Root CA CRL",
            AttestIntelCollateral.signerKeyFromChain(f.tcbChain, f.pin(), NOW, new HashSet<>(Arrays.asList("1"))).reason);

        String bad = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        String why = null;
        try {
            AttestCert.certFromPem(bad);
        } catch (AttestException e) {
            why = e.getMessage();
        }
        assertNotNull(why);
        AttestIntelCollateral.SignerKey u = AttestIntelCollateral.unrevokedSigner(bad, null, Collections.emptySet());
        assertEquals("collateral verification error (fail closed): " + why, u.reason);
        assertNull(u.key);
    }

    // ------------------------------------------------------------- CRL reading

    @Test
    void tlvLenient() {
        AttestDer.Tlv t = AttestIntelCollateral.tlvLenient(b(0x04, 0x84, 0, 0, 0, 1, 7), 0, 7);
        assertEquals(4, t.tag);
        assertEquals(6, t.start);
        assertEquals(7, t.end);
        t = AttestIntelCollateral.tlvLenient(b(0x04, 0x81, 0x00), 0, 3);
        assertEquals(3, t.start);
        assertEquals(3, t.end);
        assertEquals("DER bad length", tlvErr(b(0x04, 0x85, 0, 0, 0, 0, 0)));
        assertEquals("DER bad length", tlvErr(b(0x04, 0x80, 0, 0)));
        assertEquals("DER bad length", tlvErr(b(0x04, 0x82, 0x00)));
        assertEquals("DER overrun", tlvErr(b(0x04, 0x05, 1)));
        assertEquals("DER truncated", tlvErr(b(0x04)));
    }

    static String tlvErr(byte[] x) {
        try {
            AttestIntelCollateral.tlvLenient(x, 0, x.length);
            return "ok";
        } catch (AttestException e) {
            return e.getMessage();
        }
    }

    static long epoch(int y, int mo, int d, int h, int mi, int s) { return LocalDateTime.of(y, mo, d, h, mi, s).toEpochSecond(ZoneOffset.UTC) * 1000L; }

    @Test
    void dateUtcEdges() {
        assertEquals(epoch(1900, 1, 1, 0, 0, 0), AttestIntelCollateral.dateUtc(0, 1, 1, 0, 0, 0));
        assertEquals(epoch(1999, 1, 1, 0, 0, 0), AttestIntelCollateral.dateUtc(99, 1, 1, 0, 0, 0));
        assertEquals(epoch(100, 1, 1, 0, 0, 0), AttestIntelCollateral.dateUtc(100, 1, 1, 0, 0, 0));
        assertEquals(epoch(-1, 1, 1, 0, 0, 0), AttestIntelCollateral.dateUtc(-1, 1, 1, 0, 0, 0));
        assertEquals(946684800000L + 300000L + 7000L, AttestIntelCollateral.dateUtc(2000, 1, 1, 0, 5, 7));
    }

    static long ct(int tag, String s) {
        byte[] x = s.getBytes(StandardCharsets.US_ASCII);
        return AttestIntelCollateral.crlTime(x, new AttestDer.Tlv(tag, 0, x.length));
    }

    static String ctErr(int tag, String s) {
        try {
            ct(tag, s);
            return "ok";
        } catch (AttestException e) {
            return e.getMessage();
        }
    }

    @Test
    void crlTimes() {
        long want = epoch(2030, 11, 15, 12, 34, 56);
        assertEquals(want, ct(0x18, "20301115123456Z"));
        assertEquals(want, ct(0x17, "301115123456Z"));
        assertEquals(epoch(1950, 1, 1, 0, 0, 0), ct(0x17, "500101000000Z"));
        assertEquals(epoch(2049, 1, 1, 0, 0, 0), ct(0x17, "490101000000Z"));
        assertEquals(epoch(1999, 1, 1, 0, 0, 0), ct(0x17, "990101000000Z"));
        assertEquals("bad UTCTime", ctErr(0x17, "3011151234Z"));
        assertEquals("bad GeneralizedTime", ctErr(0x18, "301115123456Z"));
        assertEquals("not a DER time", ctErr(0x02, "301115123456Z"));
    }

    static final byte[] ALG = SIG_ALG_ECDSA_SHA256;
    static final byte[] SIG = bits((byte) 0, b(1, 2));

    static byte[] utc(String s) { return withTag(0x17, s.getBytes(StandardCharsets.US_ASCII)); }

    static final byte[] THIS = utc("250101000000Z");
    static final byte[] NXT = utc("350101000000Z");

    static String crlErr(byte[] der) {
        try {
            AttestIntelCollateral.parseCrl(der);
            return "ok";
        } catch (AttestException e) {
            return e.getMessage();
        }
    }

    @Test
    void crlParserShapes() {
        // a v1 CRL (no version), its signature bits after the unused-bits octet
        byte[] tbs = seq(ALG, name("X"), THIS, NXT);
        AttestIntelCollateral.ParsedCrl p = AttestIntelCollateral.parseCrl(seq(tbs, ALG, SIG));
        assertArrayEquals(tbs, p.tbs);
        assertEquals(epoch(2025, 1, 1, 0, 0, 0), p.thisUpdate);
        assertEquals(epoch(2035, 1, 1, 0, 0, 0), p.nextUpdate);
        assertTrue(p.hasNext);
        assertTrue(p.revoked.isEmpty());
        assertArrayEquals(b(1, 2), p.sigDer);
        // an empty BIT STRING, and one holding only the unused-bits octet: no signature bytes
        assertEquals(0, AttestIntelCollateral.parseCrl(seq(tbs, ALG, withTag(0x03))).sigDer.length);
        assertEquals(0, AttestIntelCollateral.parseCrl(seq(tbs, ALG, bits((byte) 0, new byte[0]))).sigDer.length);
        // nextUpdate as GeneralizedTime; revoked serials normalised
        byte[] v2 = seq(integer(1), ALG, name("X"), THIS, withTag(0x18, "20350101000000Z".getBytes(StandardCharsets.US_ASCII)),
            seq(seq(integer(258), THIS), seq(integer(255), THIS)));
        p = AttestIntelCollateral.parseCrl(seq(v2, ALG, SIG));
        assertEquals(epoch(2035, 1, 1, 0, 0, 0), p.nextUpdate);
        assertEquals(new HashSet<>(Arrays.asList("102", "ff")), p.revoked);

        assertEquals("CRL: bad TBSCertList", crlErr(seq(integer(1), ALG, SIG)));
        assertEquals("CRL: bad signature", crlErr(seq(tbs, ALG, octets(b(1)))));
        assertEquals("CRL: bad signature", crlErr(seq(tbs, ALG, SIG, integer(1))));
        assertEquals("CRL: bad issuer", crlErr(seq(seq(integer(1), ALG, utf8("x"), THIS, NXT), ALG, SIG)));
        assertEquals("CRL: missing nextUpdate", crlErr(seq(seq(integer(1), ALG, name("X"), THIS), ALG, SIG)));
        assertEquals("CRL: missing nextUpdate", crlErr(seq(seq(integer(1), ALG, name("X"), THIS, seq(seq(integer(2), THIS))), ALG, SIG)));
        assertEquals("CRL: bad revoked entry", crlErr(seq(seq(integer(1), ALG, name("X"), THIS, NXT, seq(seq(utf8("x"), THIS))), ALG, SIG)));
    }

    @Test
    void crlValidFromThisUpdate() {
        KeyPair k = ecKey("secp256r1");
        CertKey key = CertKey.of(k.getPublic(), k.getPublic().getEncoded());
        assertEquals("", AttestIntelCollateral.verifyCrl(AttestIntelTest.crl(k, "250101000000Z", "350101000000Z"), key, epoch(2025, 1, 1, 0, 0, 0)).reason);
        assertEquals("CRL thisUpdate is in the future",
            AttestIntelCollateral.verifyCrl(AttestIntelTest.crl(k, "250101000000Z", "350101000000Z"), key, epoch(2025, 1, 1, 0, 0, 0) - 1).reason);
    }

    @Test
    void crlSignatureKeys() throws Exception {
        byte[] tbs = "tbs".getBytes(StandardCharsets.US_ASCII);
        KeyPair ec = ecKey("secp256r1");
        CertKey eck = CertKey.of(ec.getPublic(), ec.getPublic().getEncoded());
        assertTrue(AttestIntelCollateral.crlSigOk(tbs, derSign(ec, tbs), eck));
        assertFalse(AttestIntelCollateral.crlSigOk(tbs, new byte[0], eck)); // the verifier throws on a malformed signature

        KeyPairGenerator rg = KeyPairGenerator.getInstance("RSA");
        rg.initialize(2048);
        KeyPair rsa = rg.generateKeyPair();
        Signature rs = Signature.getInstance("SHA256withRSA");
        rs.initSign(rsa.getPrivate());
        rs.update(tbs);
        CertKey rsak = CertKey.of(rsa.getPublic(), rsa.getPublic().getEncoded());
        assertTrue(AttestIntelCollateral.crlSigOk(tbs, rs.sign(), rsak));
        assertFalse(AttestIntelCollateral.crlSigOk(tbs, new byte[] {1, 2, 3}, rsak));

        KeyPair ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Signature es = Signature.getInstance("Ed25519");
        es.initSign(ed.getPrivate());
        es.update(tbs);
        assertFalse(AttestIntelCollateral.crlSigOk(tbs, es.sign(), CertKey.of(ed.getPublic(), ed.getPublic().getEncoded())));
    }

    // ------------------------------------------------------------- signed JSON documents

    static String raw(String text) { return AttestIntelCollateral.rawJsonObject(text, "x"); }

    @Test
    void rawJsonObjectEdges() {
        assertNull(raw(""));
        assertNull(raw("   "));
        assertNull(raw("[\"x\":{}]"));
        assertEquals("{}", raw("{ \"x\":{}}"));
        assertEquals("{}", raw(" {\"x\" : {}}"));
        assertNull(raw("{\"y\":{}}"));
        assertNull(raw("{\"x\""));
        assertNull(raw("{\"x\" -{}}"));
        assertNull(raw("{\"x\":"));
        assertNull(raw("{\"x\":5{}}"));
        assertNull(raw("{\"x\":{"));
        assertEquals("{\"a\":{\"b\":1}}", raw("{\"x\":{\"a\":{\"b\":1}},\"y\":2}"));
    }

    // attest-intel-collateral.test.ts "reads the signed body, never a later duplicate member"
    @Test
    void aLaterDuplicateMemberNeverReplacesTheSignedBody() {
        Fx f = new Fx();
        byte[] quote = f.quote();
        AttestIntelCollateral.Collateral c = f.collateral();
        AttestIntelCollateral.Result honest = AttestIntelCollateral.verifyIntelTdxCollateral(quote, c, NOW, null, f.pin(), false);
        assertTrue(honest.ok, honest.reason);
        String tcb = c.tcbInfoJson, qe = c.qeIdentityJson;
        String forgedTcb = tcb.replace(",\"signature\":", ",\"tcbInfo\":{},\"signature\":");
        assertTrue(forgedTcb.length() > tcb.length());
        String forgedQe = qe.replace(",\"signature\":", ",\"enclaveIdentity\":{},\"signature\":");
        assertTrue(forgedQe.length() > qe.length());
        c.tcbInfoJson = forgedTcb;
        AttestIntelCollateral.Result r = AttestIntelCollateral.verifyIntelTdxCollateral(quote, c, NOW, null, f.pin(), false);
        assertEquals(honest.reason, r.reason);
        assertTrue(r.ok);
        assertEquals(honest.status, r.status);
        c.tcbInfoJson = tcb;
        c.qeIdentityJson = forgedQe;
        r = AttestIntelCollateral.verifyIntelTdxCollateral(quote, c, NOW, null, f.pin(), false);
        assertEquals(honest.reason, r.reason);
        assertTrue(r.ok);
        assertEquals(honest.status, r.status);
    }

    @Test
    void signedJsonEdges() throws Exception {
        KeyPair k = ecKey("secp256r1");
        CertKey key = CertKey.of(k.getPublic(), k.getPublic().getEncoded());
        // the body is the signed (first) member, whatever a later duplicate says
        String dup = signed("tcbInfo", "{\"a\":1}", k).replace(",\"signature\"", ",\"tcbInfo\":5,\"signature\"");
        AttestIntelCollateral.SignedBody first = AttestIntelCollateral.verifySignedJson(dup, "tcbInfo", key);
        assertEquals("", first.reason);
        assertEquals(1, first.body.size());
        assertTrue(first.body.containsKey("a"));
        KeyPairGenerator rg = KeyPairGenerator.getInstance("RSA");
        rg.initialize(2048);
        KeyPair rsa = rg.generateKeyPair();
        CertKey rsak = CertKey.of(rsa.getPublic(), rsa.getPublic().getEncoded());
        AttestIntelCollateral.SignedBody s = AttestIntelCollateral.verifySignedJson(signed("tcbInfo", "{}", k), "tcbInfo", rsak);
        assertEquals("tcbInfo signature does not verify under the TCB Signing certificate", s.reason);
        assertNull(s.body);
        AttestIntelCollateral.SignedBody ok = AttestIntelCollateral.verifySignedJson(signed("tcbInfo", "{\"a\":1}", k), "tcbInfo", key);
        assertEquals("", ok.reason);
        assertEquals(1, ok.body.size());
    }

    @Test
    void datesAndFreshness() {
        assertEquals(Long.valueOf(epoch(2027, 1, 15, 0, 0, 0)), AttestIntelCollateral.jsDateParse("2027-01-15"));
        assertEquals(Long.valueOf(epoch(2027, 1, 1, 0, 0, 0)), AttestIntelCollateral.jsDateParse("2027-01-01T00:00:00Z"));
        assertNull(AttestIntelCollateral.jsDateParse("soon"));
        // Date.parse refuses an offset hour over 23 and an offset minute over 59
        assertNull(AttestIntelCollateral.jsDateParse("2027-01-15T00:00:00+24:00"));
        assertNull(AttestIntelCollateral.jsDateParse("2027-01-15T00:00:00+00:60"));

        long issue = epoch(2027, 1, 1, 0, 0, 0);
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("issueDate", "2027-01-01T00:00:00Z");
        d.put("nextUpdate", "2027-02-01");
        assertEquals("", AttestIntelCollateral.checkFresh(d, "W", issue));
        assertEquals("W: issueDate is in the future", AttestIntelCollateral.checkFresh(d, "W", issue - 1));
        assertEquals("", AttestIntelCollateral.checkFresh(d, "W", epoch(2027, 2, 1, 0, 0, 0)));
        String missing = "W: issueDate/nextUpdate missing";
        d.put("issueDate", new Json.Num("1"));
        assertEquals(missing, AttestIntelCollateral.checkFresh(d, "W", issue));
        d.put("issueDate", "soon");
        assertEquals(missing, AttestIntelCollateral.checkFresh(d, "W", issue));
        d.put("issueDate", "2027-01-01");
        d.put("nextUpdate", new Json.Num("1"));
        assertEquals(missing, AttestIntelCollateral.checkFresh(d, "W", issue));
    }

    // ------------------------------------------------------------- status units

    @Test
    void statusUnits() {
        assertNull(AttestIntelCollateral.asTcbStatus(new Json.Num("1")));
        assertNull(AttestIntelCollateral.asTcbStatus("Fine"));
        assertEquals("Revoked", AttestIntelCollateral.asTcbStatus("Revoked"));
        // two unknown statuses tie: the first wins
        assertEquals("foo", AttestIntelCollateral.worstStatus("foo", "bar"));

        assertNull(AttestIntelCollateral.svnList("x"));
        assertNull(AttestIntelCollateral.svnList(parse(comps15())));
        double[] s = AttestIntelCollateral.svnList(parse(AttestIntelK05KillTest.comps(all(7))));
        assertEquals(16, s.length);
        assertEquals(7.0, s[15]);
        assertNull(AttestIntelCollateral.svnList(parse(arr(Collections.nCopies(16, "1").toArray(new String[0])))));
        assertNull(AttestIntelCollateral.svnList(parse(arr(Collections.nCopies(16, "{\"svn\":\"1\"}").toArray(new String[0])))));

        assertNull(AttestIntelCollateral.hexBytesN(new Json.Num("1"), 2));
        assertNull(AttestIntelCollateral.hexBytesN("abc", 2));
        assertNull(AttestIntelCollateral.hexBytesN("zzzz", 2));
        assertArrayEquals(b(0x0a, 0xff), AttestIntelCollateral.hexBytesN("0aFF", 2));

        assertEquals(Arrays.asList("A"), AttestIntelCollateral.advisoryList(m("{\"advisoryIDs\":[5,\"A\"]}")));
        assertEquals(new ArrayList<String>(), AttestIntelCollateral.advisoryList(m("{\"advisoryIDs\":\"A\"}")));

        assertNull(AttestIntelCollateral.findLevel("x", 1));
        Map<String, Object> hit = AttestIntelCollateral.findLevel(parse("[5,{\"tcbStatus\":\"OutOfDate\"},{\"tcb\":{\"isvsvn\":\"x\"}},"
            + "{\"tcb\":{\"isvsvn\":2},\"tcbStatus\":\"Revoked\"},{\"tcb\":{\"isvsvn\":1},\"tcbStatus\":\"UpToDate\"}]"), 1);
        assertEquals("UpToDate", hit.get("tcbStatus"));
    }

    static String comps15() {
        String[] s = new String[15];
        Arrays.fill(s, "{\"svn\":1}");
        return arr(s);
    }

    // ------------------------------------------------------------- TCB evaluation

    static Map<String, Object> info(String module, String levels) { return m(obj("tdxModule", module, "tdxModuleIdentities", null, "tcbLevels", levels)); }

    static int[] v(int... x) {
        int[] a = new int[16];
        System.arraycopy(x, 0, a, 0, x.length);
        return a;
    }

    static final byte[] MR = new byte[48];
    static final byte[] ATTR = new byte[8];

    static byte[] tee(int... x) {
        byte[] t = new byte[16];
        for (int i = 0; i < 16; i++) t[i] = (byte) (i < x.length ? x[i] : x[x.length - 1]);
        return t;
    }

    @Test
    void tcbLevelsMissing() {
        AttestIntelCollateral.TcbEval t = AttestIntelCollateral.evaluateTcb(m(obj("tdxModule", MODULE)), new byte[16], 0, tee(3, 0, 5), MR, ATTR);
        assertEquals("TCB info has no tcbLevels", t.err);
        assertEquals(new ArrayList<String>(), t.advisories);
    }

    @Test
    void tdxComponentsFromZeroForMinorZero() {
        // minor 0: every TDX component counts, so tee[0] = 3 < 4 skips the first level
        Map<String, Object> inf = info(MODULE, arr(level(all(0), v(4, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4), 0, "UpToDate"),
            level(all(0), all(0), 0, "OutOfDate", "SA-0")));
        AttestIntelCollateral.TcbEval t = AttestIntelCollateral.evaluateTcb(inf, new byte[16], 0, tee(3, 0, 5), MR, ATTR);
        assertNull(t.err);
        assertEquals("OutOfDate", t.platform);
        assertEquals("UpToDate", t.module);
        assertEquals(Arrays.asList("SA-0"), t.advisories);
    }

    @Test
    void moduleIdentityPathSkipsTheFirstTwoTdxComponents() {
        String ident = obj("id", q("TDX_03"), "mrsigner", q("00".repeat(48)), "attributes", q("00".repeat(8)), "attributesMask", q("ff".repeat(8)),
            "tcbLevels", arr(qeLevel(3, "Revoked"), qeLevel(2, "OutOfDate", "SA-M")));
        String ids = arr("5", obj("id", q("TDX_01")), ident);
        Map<String, Object> inf = m(obj("tdxModuleIdentities", ids, "tcbLevels", arr(
            level(all(0), v(0, 0, 6), 0, "Revoked"),
            level(all(0), v(9, 9), 0, "SWHardeningNeeded", "SA-P"))));
        byte[] tee = tee(2, 3, 5, 1, 5);
        AttestIntelCollateral.TcbEval t = AttestIntelCollateral.evaluateTcb(inf, new byte[16], 0, tee, MR, ATTR);
        assertNull(t.err);
        assertEquals("SWHardeningNeeded", t.platform);
        assertEquals("OutOfDate", t.module);
        assertEquals(Arrays.asList("SA-M", "SA-P"), t.advisories);
    }

    @Test
    void tcbLevelRefusals() {
        byte[] t0 = tee(3, 0, 5);
        String mal = "TDX module identity fields malformed";
        assertEquals(mal, AttestIntelCollateral.evaluateTcb(info(MODULE.replace("\"" + "00".repeat(48) + "\"", "\"00\""), arr(level(all(0), all(0), 0, "UpToDate"))),
            new byte[16], 0, t0, MR, ATTR).err);
        assertEquals(mal, AttestIntelCollateral.evaluateTcb(info(MODULE.replace("\"attributes\":\"" + "00".repeat(8) + "\"", "\"attributes\":\"00\""),
            arr(level(all(0), all(0), 0, "UpToDate"))), new byte[16], 0, t0, MR, ATTR).err);
        assertEquals(mal, AttestIntelCollateral.evaluateTcb(info(MODULE.replace("\"" + "ff".repeat(8) + "\"", "\"ff\""), arr(level(all(0), all(0), 0, "UpToDate"))),
            new byte[16], 0, t0, MR, ATTR).err);
        String comp = "malformed TCB level components";
        String good = level(all(0), all(0), 0, "UpToDate");
        assertEquals(comp, AttestIntelCollateral.evaluateTcb(info(MODULE, arr(good.replace("\"sgxtcbcomponents\":" + AttestIntelK05KillTest.comps(all(0)),
            "\"sgxtcbcomponents\":" + comps15()))), new byte[16], 0, t0, MR, ATTR).err);
        assertEquals(comp, AttestIntelCollateral.evaluateTcb(info(MODULE, arr(good.replace("\"tdxtcbcomponents\":" + AttestIntelK05KillTest.comps(all(0)),
            "\"tdxtcbcomponents\":" + comps15()))), new byte[16], 0, t0, MR, ATTR).err);
        assertEquals(comp, AttestIntelCollateral.evaluateTcb(info(MODULE, arr(good.replace("\"pcesvn\":0,", ""))), new byte[16], 0, t0, MR, ATTR).err);
        assertEquals("malformed TCB level", AttestIntelCollateral.evaluateTcb(info(MODULE, arr("5")), new byte[16], 0, t0, MR, ATTR).err);
    }

    @Test
    void everyComponentIsCompared() {
        byte[] sgx = new byte[16];
        Arrays.fill(sgx, (byte) 5);
        byte[] t0 = tee(5, 0, 5);
        // only the last SGX (then the last TDX) component of the first level is above the platform
        Map<String, Object> inf = info(MODULE, arr(level(v(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6), all(0), 0, "UpToDate"),
            level(all(0), v(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6), 0, "SWHardeningNeeded"), level(all(5), v(5, 0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5), 0, "OutOfDate")));
        assertEquals("OutOfDate", AttestIntelCollateral.evaluateTcb(inf, sgx, 0, t0, MR, ATTR).platform);
    }

    // ------------------------------------------------------------- QE identity evaluation

    static Map<String, Object> qeId() {
        return m(obj("id", q("TD_QE"), "version", "2", "miscselect", q("00000000"), "miscselectMask", q("ffffffff"), "attributes", q("00".repeat(16)),
            "attributesMask", q("ff".repeat(16)), "mrsigner", q("00".repeat(32)), "isvprodid", "385",
            "tcbLevels", arr(qeLevel(386, "Revoked"), qeLevel(385, "UpToDate", "Q-1"), qeLevel(0, "OutOfDate"))));
    }

    static byte[] qeReport() {
        byte[] r = new byte[384];
        r[256] = (byte) 0x81;
        r[257] = 1;
        r[258] = (byte) 0x81;
        r[259] = 1;
        return r;
    }

    @Test
    void qeIdentityWholeResult() {
        AttestIntelCollateral.QeEval e = AttestIntelCollateral.evaluateQe(qeId(), qeReport());
        assertNull(e.err);
        assertEquals("UpToDate", e.status);
        assertEquals(Arrays.asList("Q-1"), e.advisories);

        Map<String, Object> id = qeId();
        id.remove("version");
        AttestIntelCollateral.QeEval x = AttestIntelCollateral.evaluateQe(id, qeReport());
        assertEquals("unsupported QE identity version", x.err);
        assertEquals(new ArrayList<String>(), x.advisories);
        id.put("version", new Json.Num("3"));
        assertEquals("unsupported QE identity version", AttestIntelCollateral.evaluateQe(id, qeReport()).err);
        for (String f : new String[] {"miscselect", "miscselectMask", "attributes", "attributesMask", "mrsigner", "isvprodid"}) {
            Map<String, Object> d = qeId();
            d.remove(f);
            assertEquals("QE identity fields malformed", AttestIntelCollateral.evaluateQe(d, qeReport()).err, f);
        }
        byte[] r = qeReport();
        r[16] = 1;
        assertEquals("QE MISCSELECT does not match the QE identity", AttestIntelCollateral.evaluateQe(qeId(), r).err);
    }
}
