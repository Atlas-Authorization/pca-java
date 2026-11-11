package net.atlasauth.pca;

import static net.atlasauth.pca.AttestTestDer.basicConstraints;
import static net.atlasauth.pca.AttestTestDer.bool;
import static net.atlasauth.pca.AttestTestDer.cert;
import static net.atlasauth.pca.AttestTestDer.certWithValidity;
import static net.atlasauth.pca.AttestTestDer.ecKey;
import static net.atlasauth.pca.AttestTestDer.ext;
import static net.atlasauth.pca.AttestTestDer.integer;
import static net.atlasauth.pca.AttestTestDer.keyUsageCertSign;
import static net.atlasauth.pca.AttestTestDer.roleTbs;
import static net.atlasauth.pca.AttestTestDer.seq;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Exact whole-result tests for the AMD SEV-SNP verifier internals, the vendor factory and the result / binding types. */
public class AttestAmdK05KillTest {
    static final String V = "amd-sev-snp";
    static final String DOWNGRADE = " — TCB downgrade?";
    static final String NB = "250101000000Z";
    static final String NA = "350101000000Z";
    static final long NB_MS = 1_735_689_600_000L; // 2025-01-01T00:00:00Z
    static final long NA_MS = 2_051_222_400_000L; // 2035-01-01T00:00:00Z
    static final String[] SPL_OIDS = {AttestAmd.OID_BL_SPL, AttestAmd.OID_TEE_SPL, AttestAmd.OID_SNP_SPL, AttestAmd.OID_UCODE_SPL};
    static final String[] SPL_NAMES = {"bootloader", "tee", "snp", "microcode"};
    static final int[] SPL_VALUES = {1, 2, 10, 11}; // reported_tcb 0x0b0a000000000201

    private static String msg(Runnable r) {
        try {
            r.run();
            return null;
        } catch (AttestException e) {
            return e.getMessage();
        }
    }

    private static byte[] bytes(int... v) {
        byte[] b = new byte[v.length];
        for (int i = 0; i < v.length; i++) b[i] = (byte) v[i];
        return b;
    }

    // ------------------------------------------------------------- decodeSpl

    private static Object[] spl(int... v) { return AttestAmd.decodeSpl(bytes(v)); }

    @Test
    void splWholeResult() {
        assertArrayEquals(new Object[] {0, "is not a DER INTEGER"}, spl());
        assertArrayEquals(new Object[] {0, "is not a DER INTEGER"}, spl(0x02, 0x01));
        assertArrayEquals(new Object[] {0, "is not a DER INTEGER"}, spl(0x03, 0x01, 0x05));
        assertArrayEquals(new Object[] {5, null}, spl(0x02, 0x01, 0x05));
        assertArrayEquals(new Object[] {0, null}, spl(0x02, 0x01, 0x00));
        assertArrayEquals(new Object[] {127, null}, spl(0x02, 0x01, 0x7f));
        assertArrayEquals(new Object[] {0, "has a wrong-length INTEGER"}, spl(0x02, 0x00, 0x00));
        assertArrayEquals(new Object[] {0, "has a wrong-length INTEGER"}, spl(0x02, 0x03, 0x00, 0x00, 0x01));
        assertArrayEquals(new Object[] {0, "has a wrong-length INTEGER"}, spl(0x02, 0x01, 0x05, 0x00));
        assertArrayEquals(new Object[] {0, "has a wrong-length INTEGER"}, spl(0x02, 0x02, 0x05));
        assertArrayEquals(new Object[] {0, "is negative"}, spl(0x02, 0x01, 0x80));
        assertArrayEquals(new Object[] {0, "is negative"}, spl(0x02, 0x02, 0xff, 0xff));
        assertArrayEquals(new Object[] {0, "is out of range (> 255)"}, spl(0x02, 0x02, 0x01, 0x80));
        assertArrayEquals(new Object[] {0, "is a non-minimal INTEGER"}, spl(0x02, 0x02, 0x00, 0x7f));
        assertArrayEquals(new Object[] {128, null}, spl(0x02, 0x02, 0x00, 0x80));
        assertArrayEquals(new Object[] {255, null}, spl(0x02, 0x02, 0x00, 0xff));
    }

    // ------------------------------------------------------------- parseSnpReport

    private static long le(byte[] b, int off, int n) {
        long v = 0;
        for (int i = n - 1; i >= 0; i--) v = (v << 8) | (b[off + i] & 0xffL);
        return v;
    }

    @Test
    void reportParsesEveryField() {
        byte[] b = new byte[AttestAmd.REPORT_LEN];
        for (int i = 0; i < b.length; i++) b[i] = (byte) (i * 37 + 11);
        AttestAmd.SnpReport r = AttestAmd.parseSnpReport(b);
        assertEquals(le(b, 0x004, 4), r.guestSvn);
        assertEquals(le(b, 0x008, 8), r.policy);
        assertEquals(le(b, 0x030, 4), r.vmpl);
        assertEquals(le(b, 0x034, 4), r.sigAlgo);
        assertEquals(le(b, 0x180, 8), r.reportedTcb);
        assertEquals(le(b, 0x1e0, 8), r.committedTcb);
        assertEquals(le(b, 0x1f0, 8), r.launchTcb);
        assertArrayEquals(Arrays.copyOfRange(b, 0x050, 0x090), r.reportData);
        assertArrayEquals(Arrays.copyOfRange(b, 0x090, 0x0c0), r.measurement);
        assertArrayEquals(Arrays.copyOfRange(b, 0x0c0, 0x0e0), r.hostData);
        assertArrayEquals(Arrays.copyOfRange(b, 0x1a0, 0x1e0), r.chipId);
        assertArrayEquals(Arrays.copyOfRange(b, 0, 0x2a0), r.signed);
        assertArrayEquals(Arrays.copyOfRange(b, 0x2a0, 0x2e8), r.sigR);
        assertArrayEquals(Arrays.copyOfRange(b, 0x2e8, 0x330), r.sigS);
        assertEquals(72, r.sigS.length);
        // the shortest parseable input ends with sig_s
        assertEquals(72, AttestAmd.parseSnpReport(new byte[816]).sigS.length);
        assertEquals("parseSevSnpReport: report too short (815 < 816)",
            assertThrows(AttestException.class, () -> AttestAmd.parseSnpReport(new byte[815])).getMessage());
    }

    // ------------------------------------------------------------- the report signature

    @Test
    void signatureRefusesOutOfRangeFields() {
        AttestAmdTest.Genuine g = new AttestAmdTest.Genuine();
        ECPublicKey key = (ECPublicKey) g.vcek.getPublic();
        byte[] raw = g.report();
        assertTrue(AttestAmd.verifySnpReportSignature(AttestAmd.parseSnpReport(raw), key));
        int[] high = {AttestAmd.OFF_SIG_R + 48, AttestAmd.OFF_SIG_R + 71, AttestAmd.OFF_SIG_S + 48, AttestAmd.OFF_SIG_S + 71};
        for (int off : high) {
            byte[] t = raw.clone();
            t[off] = 1;
            assertFalse(AttestAmd.verifySnpReportSignature(AttestAmd.parseSnpReport(t), key), "non-zero high byte at " + off);
        }
        byte[] zeroR = raw.clone();
        Arrays.fill(zeroR, AttestAmd.OFF_SIG_R, AttestAmd.OFF_SIG_R + 48, (byte) 0);
        assertFalse(AttestAmd.verifySnpReportSignature(AttestAmd.parseSnpReport(zeroR), key));
        byte[] maxS = raw.clone();
        Arrays.fill(maxS, AttestAmd.OFF_SIG_S, AttestAmd.OFF_SIG_S + 48, (byte) 0xff); // 2^384 - 1 > n
        assertFalse(AttestAmd.verifySnpReportSignature(AttestAmd.parseSnpReport(maxS), key));
    }

    // ------------------------------------------------------------- VCEK <-> report binding

    private static AttestAmd.SnpReport bindRep() {
        AttestAmd.SnpReport r = new AttestAmd.SnpReport();
        r.chipId = new byte[64];
        Arrays.fill(r.chipId, (byte) 0x5a);
        r.reportedTcb = 0x0b0a000000000201L;
        return r;
    }

    private static byte[] hw(int len) {
        byte[] chip = new byte[len];
        Arrays.fill(chip, (byte) 0x5a);
        return ext(AttestAmd.OID_HWID, false, chip);
    }

    /** The four good SPL extensions with index k replaced by repl (null: dropped). */
    private static List<byte[]> spls(int k, byte[] repl) {
        List<byte[]> out = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            if (i != k) out.add(ext(SPL_OIDS[i], false, integer(SPL_VALUES[i])));
            else if (repl != null) out.add(repl);
        }
        return out;
    }

    private static String bind(byte[] hwExt, List<byte[]> splExts) {
        List<byte[]> all = new ArrayList<>();
        if (hwExt != null) all.add(hwExt);
        all.addAll(splExts);
        return AttestAmd.checkVcekReportBinding(roleTbs(all.toArray(new byte[0][])), bindRep());
    }

    @Test
    void vcekBindingWholeResult() {
        assertEquals("", bind(hw(64), spls(-1, null)));
        assertEquals("VCEK extensions malformed: tbsCertificate is not a SEQUENCE", AttestAmd.checkVcekReportBinding(integer(1), bindRep()));
        assertEquals("VCEK certificate has no CHIP_ID (hwID) extension", bind(null, spls(-1, null)));
        byte[] chip = new byte[64];
        Arrays.fill(chip, (byte) 0x5a);
        assertEquals("VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)",
            bind(ext(AttestAmd.OID_HWID, true, chip), spls(-1, null)));
        assertEquals("VCEK CHIP_ID (hwID) extension is 63 bytes, expected 64", bind(hw(63), spls(-1, null)));
        assertEquals("VCEK CHIP_ID (hwID) extension is 65 bytes, expected 64", bind(hw(65), spls(-1, null)));
        chip[63] = 0x5b;
        assertEquals("VCEK CHIP_ID does not match report chip_id", bind(ext(AttestAmd.OID_HWID, false, chip), spls(-1, null)));
        for (int k = 0; k < 4; k++) {
            String n = SPL_NAMES[k];
            assertEquals("VCEK certificate has no " + n + " SPL extension", bind(hw(64), spls(k, null)), n);
            assertEquals("VCEK " + n + " SPL extension is marked critical (the AMD profile is non-critical)",
                bind(hw(64), spls(k, ext(SPL_OIDS[k], true, integer(SPL_VALUES[k])))), n);
            assertEquals("VCEK " + n + " SPL extension is negative", bind(hw(64), spls(k, ext(SPL_OIDS[k], false, integer(-1)))), n);
            assertEquals("VCEK " + n + " SPL extension is not a DER INTEGER", bind(hw(64), spls(k, ext(SPL_OIDS[k], false, bytes(0x04, 0x01, 0x01)))), n);
            int got = SPL_VALUES[k] + 1;
            assertEquals("VCEK " + n + " SPL " + got + " does not match report reported_tcb (" + SPL_VALUES[k] + ")" + DOWNGRADE,
                bind(hw(64), spls(k, ext(SPL_OIDS[k], false, integer(got)))), n);
        }
    }

    // ------------------------------------------------------------- VCEK -> ASK -> ARK

    private static byte[] vcekWith(AttestAmdTest.Genuine g, KeyPair subject, String notBefore, String notAfter) {
        return certWithValidity("VCEK", "SEV-Milan", notBefore, notAfter, subject, g.ask,
            ext(AttestAmd.OID_HWID, false, g.chipId),
            ext(AttestAmd.OID_BL_SPL, false, integer(1)),
            ext(AttestAmd.OID_TEE_SPL, false, integer(2)),
            ext(AttestAmd.OID_SNP_SPL, false, integer(10)),
            ext(AttestAmd.OID_UCODE_SPL, false, integer(11)));
    }

    private static String askArk(AttestAmdTest.Genuine g, byte[] askBc, byte[] arkBc) {
        byte[] askDer = cert("SEV-Milan", "ARK-Milan", g.ask, g.ark, askBc, keyUsageCertSign());
        byte[] arkDer = cert("ARK-Milan", "ARK-Milan", g.ark, g.ark, arkBc, keyUsageCertSign());
        return pem(askDer) + pem(arkDer);
    }

    private static String chain(AttestAmdTest.Genuine g, byte[] vcek, String askArk, long now, Object skew) {
        return AttestAmd.verifyAmdCertChain(vcek, askArk, g.pin(), now, skew).reason;
    }

    @Test
    void chainWholeResult() throws Exception {
        AttestAmdTest.Genuine g = new AttestAmdTest.Genuine();
        byte[] vcek = g.vcekDer();
        String askArk = g.askArkPem();

        AttestAmd.ChainResult ok = AttestAmd.verifyAmdCertChain(vcek, askArk, g.pin(), NOW, null);
        assertEquals("", ok.reason);
        assertArrayEquals(g.vcek.getPublic().getEncoded(), ok.key.getEncoded());
        assertArrayEquals(AttestDer.tbsOfCertificate(vcek), ok.tbs);
        // the pin compares case-insensitively
        assertEquals("", AttestAmd.verifyAmdCertChain(vcek, askArk, g.pin().toUpperCase(Locale.ROOT), NOW, null).reason);

        // clock skew
        String badSkew = "clockSkewMs must be a non-negative number";
        assertEquals("", chain(g, vcek, askArk, NOW, new Json.Num("0")));
        assertEquals("", chain(g, vcek, askArk, NOW, new Json.Num("0.5")));
        assertEquals(badSkew, chain(g, vcek, askArk, NOW, new Json.Num("-1")));
        assertEquals(badSkew, chain(g, vcek, askArk, NOW, new Json.Num("-0.5")));
        assertEquals(badSkew, chain(g, vcek, askArk, NOW, "x"));
        assertEquals("", chain(g, vcek, askArk, NA_MS, null));
        assertEquals("VCEK certificate has expired", chain(g, vcek, askArk, NA_MS + 1000, null));
        assertEquals("", chain(g, vcek, askArk, NA_MS + 1000, new Json.Num("2000")));
        assertEquals("VCEK certificate has expired", chain(g, vcek, askArk, NA_MS + 1000, new Json.Num("500")));
        assertEquals("", chain(g, vcek, askArk, NA_MS - 1000, new Json.Num("5000")));
        assertEquals("", chain(g, vcek, askArk, NB_MS, null));
        assertEquals("VCEK certificate is not yet valid", chain(g, vcek, askArk, NB_MS - 1000, null));
        assertEquals("", chain(g, vcek, askArk, NB_MS - 1000, new Json.Num("5000")));
        assertEquals("", chain(g, vcek, askArk, NB_MS + 1000, new Json.Num("5000")));

        // issuers must mark BasicConstraints critical
        byte[] nonCritAsk = ext("2.5.29.19", false, seq(bool(true), integer(0)));
        byte[] nonCritArk = ext("2.5.29.19", false, seq(bool(true), integer(1)));
        assertEquals("ASK certificate BasicConstraints is not marked critical",
            chain(g, vcek, askArk(g, nonCritAsk, basicConstraints(true, 1)), NOW, null));
        assertEquals("ARK certificate BasicConstraints is not marked critical",
            chain(g, vcek, askArk(g, basicConstraints(true, 0), nonCritArk), NOW, null));
        assertEquals("", chain(g, vcek, askArk(g, basicConstraints(true, 0), basicConstraints(true, 1)), NOW, null));

        // validity the strict reader cannot parse (either end)
        assertEquals("VCEK certificate validity is unparseable", chain(g, vcekWith(g, g.vcek, "251301000000Z", NA), askArk, NOW, null));
        assertEquals("VCEK certificate validity is unparseable", chain(g, vcekWith(g, g.vcek, NB, "351301000000Z"), askArk, NOW, null));
        assertEquals("", chain(g, vcekWith(g, g.vcek, NB, NA), askArk, NOW, null));

        // the VCEK key must be EC P-384
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        assertEquals("AMD chain verification error: VCEK is not EC secp384r1 (got rsa/undefined)",
            chain(g, vcekWith(g, rsa.generateKeyPair(), NB, NA), askArk, NOW, null));
        assertEquals("AMD chain verification error: VCEK is not EC secp384r1 (got ec/prime256v1)",
            chain(g, vcekWith(g, ecKey("secp256r1"), NB, NA), askArk, NOW, null));
    }

    // ------------------------------------------------------------- verifyReport

    @Test
    void verifyReportWholeResult() {
        AttestAmdTest.Genuine g = new AttestAmdTest.Genuine();
        AttestAmd v = (AttestAmd) AttestHarness.amd(g.config(""));
        byte[] raw = g.report();
        byte[] vcek = g.vcekDer();
        String askArk = g.askArkPem();

        Object[] ok = v.verifyReport(raw, vcek, askArk, NOW, BINDING);
        assertEquals(2, ok.length);
        assertEquals("", ok[0]);
        assertArrayEquals(g.measurement, ((AttestAmd.SnpReport) ok[1]).measurement);
        Object[] unbound = v.verifyReport(raw, vcek, askArk, NOW, null);
        assertEquals(2, unbound.length);
        assertEquals("", unbound[0]);
        assertNotNull(unbound[1]);

        assertArrayEquals(new Object[] {"report parse failed: parseSevSnpReport: report too short (1 < 816)", null},
            v.verifyReport(new byte[1], vcek, askArk, NOW, BINDING));
        assertArrayEquals(new Object[] {"report length 1000 is not the canonical 1184", null},
            v.verifyReport(new byte[1000], vcek, askArk, NOW, BINDING));
        int[] reserved = {AttestAmd.OFF_SIG_R + 48, AttestAmd.OFF_SIG_R + 71, AttestAmd.OFF_SIG_S + 48, AttestAmd.OFF_SIG_S + 71, 816, 1183};
        for (int off : reserved) {
            byte[] t = raw.clone();
            t[off] = 1;
            assertArrayEquals(new Object[] {"report signature block has non-zero reserved bytes", null}, v.verifyReport(t, vcek, askArk, NOW, BINDING), "offset " + off);
        }
        AttestAmd wrongPin = (AttestAmd) AttestHarness.amd(cfg("{\"family\":\"milan\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[\"aa\"]}}"));
        assertArrayEquals(new Object[] {"cert chain invalid: ARK does not match the pinned AMD trust anchor", null},
            wrongPin.verifyReport(raw, vcek, askArk, NOW, BINDING));
        byte[] tampered = raw.clone();
        tampered[AttestAmd.OFF_MEASUREMENT] ^= 1;
        assertArrayEquals(new Object[] {"report signature does not verify under VCEK", null}, v.verifyReport(tampered, vcek, askArk, NOW, BINDING));
        assertArrayEquals(new Object[] {"genuine verification error (fail closed): binding: epoch must be a non-negative safe integer", null},
            v.verifyReport(raw, vcek, askArk, NOW, new AttestationBinding("holder-key", "passport:abc", -1, "nonce-1")));
        assertArrayEquals(new Object[] {"report_data does not bind holder/grant/epoch/nonce", null},
            v.verifyReport(raw, vcek, askArk, NOW, new AttestationBinding("holder-key", "passport:abc", 1, "nonce-1")));
        AttestAmd vmpl = (AttestAmd) AttestHarness.amd(g.config(",\"requireVmpl\":2"));
        assertArrayEquals(new Object[] {"vmpl 0 is not the required 2", null}, vmpl.verifyReport(raw, vcek, askArk, NOW, BINDING));

        AttestAmdTest.Genuine down = new AttestAmdTest.Genuine();
        down.splBootloader = 0;
        AttestAmd dv = (AttestAmd) AttestHarness.amd(down.config(""));
        assertArrayEquals(new Object[] {"VCEK bootloader SPL 0 does not match report reported_tcb (1)" + DOWNGRADE, null},
            dv.verifyReport(down.report(), down.vcekDer(), down.askArkPem(), NOW, BINDING));
    }

    @Test
    void verifyEvidenceShape() {
        AttestAmdTest.Genuine g = new AttestAmdTest.Genuine();
        Map<String, Object> config = g.config("");
        String report = b64(g.report());
        String vcek = b64(g.vcekDer());
        String askArk = g.askArkPem();
        String none = "no AMD SEV-SNP evidence for this action";
        assertDenied("no vcek", run(V, config, AttestAmdTest.ev("report", report, "askArkPem", askArk), BINDING, NOW), none, false);
        assertDenied("vcek not a string", run(V, config, AttestAmdTest.ev("report", report, "vcekDer", new Json.Num("1"), "askArkPem", askArk), BINDING, NOW), none, false);
        assertDenied("chain not a string", run(V, config, AttestAmdTest.ev("report", report, "vcekDer", vcek, "askArkPem", new Json.Num("1")), BINDING, NOW), none, false);
        assertDenied("no chain", run(V, config, AttestAmdTest.ev("report", report, "vcekDer", vcek), BINDING, NOW), none, false);
        assertDenied("report not a string", run(V, config, AttestAmdTest.ev("report", new Json.Num("1"), "vcekDer", vcek, "askArkPem", askArk), BINDING, NOW), none, false);
        assertDenied("bad binding", run(V, config, AttestAmdTest.ev("report", report, "vcekDer", vcek, "askArkPem", askArk),
            new AttestationBinding("holder-key", "passport:abc", -1, "nonce-1"), NOW),
            "SEV-SNP report invalid: genuine verification error (fail closed): binding: epoch must be a non-negative safe integer", false);
        assertTrue(run(V, config, AttestAmdTest.ev("report", report, "vcekDer", vcek, "askArkPem", askArk), BINDING, NOW).ok);
    }

    // ------------------------------------------------------------- policy

    private static AttestAmd.SnpReport polRep() {
        AttestAmd.SnpReport r = new AttestAmd.SnpReport();
        r.measurement = new byte[48];
        r.hostData = new byte[32];
        Arrays.fill(r.hostData, (byte) 0xab);
        r.chipId = new byte[64];
        Arrays.fill(r.chipId, (byte) 0xcd);
        r.sigAlgo = 1;
        return r;
    }

    private static AttestAmd.SnpPolicy pol() {
        AttestAmd.SnpPolicy p = new AttestAmd.SnpPolicy();
        p.measurements = new ArrayList<>(Arrays.asList(AttestCommon.toHexLower(new byte[48])));
        return p;
    }

    @Test
    void policyWholeResult() {
        AttestAmd.SnpReport r = polRep();
        assertEquals("", pol().check(r));
        AttestAmd.SnpPolicy empty = pol();
        empty.measurements = new ArrayList<>();
        assertEquals("measurement not in policy allowlist", empty.check(r));

        AttestAmd.SnpPolicy committed = pol();
        committed.minCommittedTcb = BigInteger.valueOf(5);
        r.committedTcb = 5;
        assertEquals("", committed.check(r));
        r.committedTcb = 4;
        assertEquals("committed_tcb below minimum (rollback?)", committed.check(r));
        r.committedTcb = -1L; // u64 max
        assertEquals("", committed.check(r));
        r.committedTcb = 0;

        AttestAmd.SnpPolicy vm = pol();
        vm.requireVmpl = "x";
        assertEquals("vmpl 0 is not the required x", vm.check(r));
        vm.requireVmpl = "any";
        r.vmpl = 3;
        assertEquals("", vm.check(r));
        r.vmpl = 0;
        vm.requireVmpl = Boolean.TRUE;
        assertEquals("vmpl 0 is not the required true", vm.check(r));
        vm.requireVmpl = new Json.Num("0");
        assertEquals("", vm.check(r));
        vm.requireVmpl = new Json.Num("2.50");
        assertEquals("vmpl 0 is not the required 2.5", vm.check(r));
        r.vmpl = 1;
        vm.requireVmpl = new Json.Num("1.0");
        assertEquals("", vm.check(r));
        vm.requireVmpl = null;
        assertEquals("vmpl 1 is not the required 0", vm.check(r));
    }

    @Test
    void jsAnyStringRendering() {
        assertEquals("s", AttestAmd.jsAnyString("s"));
        assertEquals("", AttestAmd.jsAnyString(""));
        assertEquals("true", AttestAmd.jsAnyString(Boolean.TRUE));
        assertEquals("false", AttestAmd.jsAnyString(Boolean.FALSE));
        assertEquals("2.5", AttestAmd.jsAnyString(new Json.Num("2.50")));
        assertEquals("1e+21", AttestAmd.jsAnyString(new Json.Num("1e21")));
        assertEquals("7", AttestAmd.jsAnyString(7));
        assertEquals("1e999", AttestAmd.jsAnyString(new Json.Num("1e999")));
        assertEquals("null", AttestAmd.jsAnyString(null));
        assertEquals("[a]", AttestAmd.jsAnyString(Arrays.asList("a")));
    }

    @Test
    void createLowersAllowlistsAndRefusesNonStrings() {
        String m = AttestCommon.toHexLower(new byte[48]);
        AttestAmd a = (AttestAmd) AttestHarness.amd(cfg("{\"family\":\"genoa\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[\"" + m
            + "\"],\"hostData\":[\"" + "AB".repeat(32) + "\"],\"chipIds\":[\"" + "CD".repeat(64) + "\"]}}"));
        assertEquals("", a.policy.check(polRep()));
        assertEquals("genoa", a.family);
        assertEquals("report-data", a.binding);
        assertEquals(Arrays.asList("ab".repeat(32)), a.policy.hostData);
        assertEquals(Arrays.asList("cd".repeat(64)), a.policy.chipIds);
        assertEquals("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'",
            constructError(V, "{\"family\":5,\"binding\":\"report-data\",\"policy\":{\"measurements\":[\"aa\"]}}"));
        assertEquals("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'",
            constructError(V, "{\"family\":\"milan\",\"binding\":5,\"policy\":{\"measurements\":[\"aa\"]}}"));
    }

    // ------------------------------------------------------------- BigInt

    @Test
    void jsBigIntWholeResult() {
        assertEquals(BigInteger.ZERO, AttestAmd.parseJsBigInt(false));
        assertEquals(BigInteger.ONE, AttestAmd.parseJsBigInt(true));
        String[][] good = {
            {"0", "0"}, {"9", "9"}, {"5", "5"}, {"+5", "5"}, {"-7", "-7"}, {"07", "7"}, {"1234567890", "1234567890"},
            {"0x1", "1"}, {"0x1f", "31"}, {"0X1F", "31"}, {"0x1F", "31"}, {"0xA", "10"}, {"0xa", "10"}, {"0xf", "15"}, {"0xF", "15"},
            {"0x09", "9"}, {"0o10", "8"}, {"0O10", "8"}, {"0o7", "7"}, {"0b10", "2"}, {"0B10", "2"}, {"0b1", "1"}, {" 0x10 ", "16"},
        };
        for (String[] c : good) assertEquals(new BigInteger(c[1]), AttestAmd.parseJsBigInt(c[0]), c[0]);
        String[] bad = {"+", "-", "1a", "1x5", "0x", "0X", "0o", "0b", "0xg", "0xG", "0b2", "0o8", "/", ":", "+-5", "0x+1", "-0x5", "1 2", "a"};
        for (String s : bad) assertEquals("Cannot convert " + s + " to a BigInt", msg(() -> AttestAmd.parseJsBigInt(s)), s);
        assertEquals("The number 1e999 cannot be converted to a BigInt because it is not an integer",
            msg(() -> AttestAmd.parseJsBigInt(new Json.Num("1e999"))));
        assertEquals(BigInteger.valueOf(100), AttestAmd.parseJsBigInt(new Json.Num("1e2")));
        assertEquals("Cannot convert value to a BigInt", msg(() -> AttestAmd.parseJsBigInt(new ArrayList<Object>())));
        assertEquals("Cannot convert value to a BigInt", msg(() -> AttestAmd.parseJsBigInt(5.0)));
    }

    // ------------------------------------------------------------- factory, verifier wrapper, value types

    @Test
    void factorySeams() {
        assertEquals("", AttestFactory.errorPrefix("nope"));
        assertEquals("amd-snp verification error (fail closed): ", AttestFactory.errorPrefix(V));
        assertEquals("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'", msg(() -> AttestHarness.verifier(V, null)));
        Map<String, Object> throwing = new LinkedHashMap<String, Object>() {
            private static final long serialVersionUID = 1L;

            @Override
            public Object get(Object k) { throw new IllegalStateException("boom"); }
        };
        assertEquals("java.lang.IllegalStateException: boom", msg(() -> AttestFactory.verifierFromConfig(V, throwing)));
        assertEquals("attestation vendor x-test is not available in this build",
            msg(() -> AttestFactory.create("x-test", "NoSuchVendorClass", new LinkedHashMap<>())));
        assertEquals("attestation vendor x-test is not available in this build",
            msg(() -> AttestFactory.create("x-test", "AttestCommon", new LinkedHashMap<>())));
        assertEquals(V, AttestHarness.verifier(V, new AttestAmdTest.Genuine().config("")).vendor());
    }

    @Test
    void verifierWrapsThrowsAndMergesOverrides() {
        VendorVerifier noMsg = new VendorVerifier(V, (e, b, n) -> { throw new IllegalStateException(); }, null);
        assertEquals("amd-snp verification error (fail closed): java.lang.IllegalStateException", noMsg.verify(null, BINDING, NOW).reason);
        VendorVerifier withMsg = new VendorVerifier(V, (e, b, n) -> { throw new IllegalStateException("boom"); }, null);
        HardwareResult thrown = withMsg.verify(null, BINDING, NOW);
        assertEquals("amd-snp verification error (fail closed): boom", thrown.reason);
        assertFalse(thrown.ok);

        HardwareResult okRes = HardwareResult.ok(true, HardwareResult.newMeasured("m", "op"), null);
        Map<String, Object> ov = new LinkedHashMap<>();
        ov.put("operator", "x");
        HardwareResult merged = new VendorVerifier(V, (e, b, n) -> okRes, ov).verify(null, BINDING, NOW);
        assertTrue(merged.ok);
        assertTrue(merged.bound);
        assertEquals("x", merged.measured.get("operator"));
        assertEquals("m", merged.measured.get("runtime_measurement"));
        assertEquals("op", okRes.measured.get("operator"));

        assertSame(okRes, new VendorVerifier(V, (e, b, n) -> okRes, null).verify(null, BINDING, NOW));
        assertSame(okRes, new VendorVerifier(V, (e, b, n) -> okRes, new LinkedHashMap<>()).verify(null, BINDING, NOW));
        HardwareResult noMeasured = HardwareResult.ok(true, null, null);
        assertSame(noMeasured, new VendorVerifier(V, (e, b, n) -> noMeasured, ov).verify(null, BINDING, NOW));
        HardwareResult failed = HardwareResult.fail("no");
        assertSame(failed, new VendorVerifier(V, (e, b, n) -> failed, ov).verify(null, BINDING, NOW));
    }

    @Test
    void valueTypesDefaultNullStrings() {
        AttestationBinding nulls = new AttestationBinding(null, null, 3, null);
        assertEquals("", nulls.holderPub);
        assertEquals("", nulls.grantRef);
        assertEquals("", nulls.nonce);
        assertEquals(3.0, nulls.epoch);
        AttestationBinding set = new AttestationBinding("h", "g", 1, "n");
        assertEquals("h", set.holderPub);
        assertEquals("g", set.grantRef);
        assertEquals("n", set.nonce);
        assertEquals("", new HardwareResult(false, false, null, null, null).reason);
        assertEquals("r", HardwareResult.fail("r").reason);
    }
}
