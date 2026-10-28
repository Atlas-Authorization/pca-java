package net.atlasauth.pca;

import static net.atlasauth.pca.AttestVendorRows.BINDING;
import static net.atlasauth.pca.AttestVendorRows.NOW;
import static net.atlasauth.pca.AttestVendorRows.assertDenied;
import static net.atlasauth.pca.AttestVendorRows.b64;
import static net.atlasauth.pca.AttestVendorRows.cfg;
import static net.atlasauth.pca.AttestVendorRows.constructError;
import static net.atlasauth.pca.AttestVendorRows.pem;
import static net.atlasauth.pca.AttestVendorRows.run;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** AMD SEV-SNP: vector replay, constructor refusals, the fail-closed table and a generated end-to-end report. */
public class AttestAmdTest {
    static final String V = "amd-sev-snp";
    static final String CFG = "{\"family\":\"milan\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[\"aa\"]}}";

    @Test
    void vectors() { AttestVendorRows.replayVendor(V); }

    @Test
    void constructRefusals() {
        assertEquals("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'",
            constructError(V, "{\"family\":\"rome\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[\"aa\"]}}"));
        assertEquals("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'",
            constructError(V, "{\"family\":\"milan\",\"binding\":\"x\",\"policy\":{\"measurements\":[\"aa\"]}}"));
        assertEquals("createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)",
            constructError(V, "{\"family\":\"milan\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[]}}"));
        assertEquals("createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)",
            constructError(V, "{\"family\":\"milan\",\"binding\":\"report-data\"}"));
        // the BigInt floors are converted first: their error wins over the family error
        assertEquals("Cannot convert abc to a BigInt",
            constructError(V, "{\"family\":\"rome\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[\"aa\"],\"minReportedTcb\":\"abc\"}}"));
        assertNull(constructError(V, "{\"family\":\"genoa\",\"binding\":\"azure-runtime-data\",\"policy\":{\"measurements\":[\"aa\"],\"minReportedTcb\":\"18446744073709551615\"}}"));
    }

    @Test
    void jsBigInt() {
        assertEquals(BigInteger.valueOf(31), AttestAmd.parseJsBigInt(" 0x1F "));
        assertEquals(BigInteger.valueOf(5), AttestAmd.parseJsBigInt("0b101"));
        assertEquals(BigInteger.valueOf(8), AttestAmd.parseJsBigInt("0o10"));
        assertEquals(BigInteger.valueOf(-7), AttestAmd.parseJsBigInt("-7"));
        assertEquals(BigInteger.ZERO, AttestAmd.parseJsBigInt("   "));
        assertEquals(BigInteger.ONE, AttestAmd.parseJsBigInt(true));
        assertEquals(new BigInteger("18446744073709551615"), AttestAmd.parseJsBigInt("18446744073709551615"));
        assertEquals(BigInteger.valueOf(12), AttestAmd.parseJsBigInt(new Json.Num("12")));
        assertEquals("Cannot convert 0x-1 to a BigInt", msg(() -> AttestAmd.parseJsBigInt("0x-1")));
        assertEquals("Cannot convert 1.5 to a BigInt", msg(() -> AttestAmd.parseJsBigInt("1.5")));
        assertEquals("Cannot convert ١ to a BigInt", msg(() -> AttestAmd.parseJsBigInt("١")));
        assertEquals("Cannot convert null to a BigInt", msg(() -> AttestAmd.parseJsBigInt(null)));
        assertEquals("The number 1.5 cannot be converted to a BigInt because it is not an integer", msg(() -> AttestAmd.parseJsBigInt(new Json.Num("1.5"))));
    }

    private static String msg(Runnable r) {
        try {
            r.run();
            return null;
        } catch (AttestException e) {
            return e.getMessage();
        }
    }

    @Test
    void splDecoding() {
        assertEquals("is not a DER INTEGER", AttestAmd.decodeSpl(new byte[] {0x04, 0x01, 0x00})[1]);
        assertEquals("has a wrong-length INTEGER", AttestAmd.decodeSpl(new byte[] {0x02, 0x03, 0x00, 0x00, 0x01})[1]);
        assertEquals("is negative", AttestAmd.decodeSpl(new byte[] {0x02, 0x01, (byte) 0x80})[1]);
        assertEquals("is out of range (> 255)", AttestAmd.decodeSpl(new byte[] {0x02, 0x02, 0x01, 0x00})[1]);
        assertEquals("is a non-minimal INTEGER", AttestAmd.decodeSpl(new byte[] {0x02, 0x02, 0x00, 0x7f})[1]);
        assertEquals(255, AttestAmd.decodeSpl(new byte[] {0x02, 0x02, 0x00, (byte) 0xff})[0]);
        assertEquals(127, AttestAmd.decodeSpl(new byte[] {0x02, 0x01, 0x7f})[0]);
    }

    @Test
    void failClosedTable() {
        byte[] snp1184 = new byte[1184];
        byte[] reserved = new byte[1184];
        reserved[900] = 1;
        Object[][] rows = {
            {"nil evidence", CFG, null, BINDING, "no AMD SEV-SNP evidence for this action", false},
            {"empty evidence", CFG, ev(), BINDING, "no AMD SEV-SNP evidence for this action", false},
            {"no binding", CFG, ev("report", "AA==", "vcekDer", "AA==", "askArkPem", "x"), null, "no expected attestation binding supplied", false},
            {"short report", CFG, ev("report", "AA==", "vcekDer", "AA==", "askArkPem", "x"), BINDING,
                "SEV-SNP report invalid: report parse failed: parseSevSnpReport: report too short (1 < 816)", false},
            {"non-canonical length", CFG, ev("report", b64(new byte[1000]), "vcekDer", "AA==", "askArkPem", "x"), BINDING,
                "SEV-SNP report invalid: report length 1000 is not the canonical 1184", false},
            {"reserved bytes", CFG, ev("report", b64(reserved), "vcekDer", "AA==", "askArkPem", "x"), BINDING,
                "SEV-SNP report invalid: report signature block has non-zero reserved bytes", false},
            {"garbage VCEK", CFG, ev("report", b64(snp1184), "vcekDer", "AA==", "askArkPem", "x"), BINDING,
                "SEV-SNP report invalid: cert chain invalid: AMD chain verification error: ", true},
            {"negative skew", "{\"family\":\"milan\",\"binding\":\"report-data\",\"policy\":{\"measurements\":[\"aa\"]},\"clockSkewMs\":-1}",
                ev("report", b64(snp1184), "vcekDer", "AA==", "askArkPem", "x"), BINDING,
                "SEV-SNP report invalid: cert chain invalid: clockSkewMs must be a non-negative number", false},
            {"azure mode needs evidence", "{\"family\":\"milan\",\"binding\":\"azure-runtime-data\",\"policy\":{\"measurements\":[\"aa\"]}}", null, BINDING,
                "no AMD SEV-SNP evidence for this action", false},
        };
        for (Object[] r : rows) {
            @SuppressWarnings("unchecked")
            Map<String, Object> e = (Map<String, Object>) r[2];
            assertDenied((String) r[0], run(V, cfg((String) r[1]), e, (AttestationBinding) r[3], NOW), (String) r[4], (Boolean) r[5]);
        }
    }

    static Map<String, Object> ev(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    // ------------------------------------------------------------- a generated genuine report

    /** A complete, valid SEV-SNP evidence set: ARK and ASK (P-384) and a VCEK carrying the report's chip id and TCB. */
    static final class Genuine {
        final KeyPair ark = AttestTestDer.ecKey("secp384r1");
        final KeyPair ask = AttestTestDer.ecKey("secp384r1");
        final KeyPair vcek = AttestTestDer.ecKey("secp384r1");
        final byte[] chipId = new byte[64];
        final byte[] measurement = new byte[48];
        long reportedTcb = 0x0b0a000000000201L; // bootloader 1, tee 2, snp 10, microcode 11
        int splBootloader = 1;
        int vmpl;
        long policy;
        byte[] reportData;

        Genuine() {
            Arrays.fill(chipId, (byte) 0x5a);
            Arrays.fill(measurement, (byte) 0x3c);
            reportData = AttestCommon.attestationBindingBytes(BINDING);
        }

        String pin() { return AttestCommon.toHexLower(AttestCommon.sha384Sum(ark.getPublic().getEncoded())); }

        byte[] vcekDer() {
            return AttestTestDer.cert("VCEK", "SEV-Milan", vcek, ask,
                AttestTestDer.ext(AttestAmd.OID_HWID, false, chipId),
                AttestTestDer.ext(AttestAmd.OID_BL_SPL, false, AttestTestDer.integer(splBootloader)),
                AttestTestDer.ext(AttestAmd.OID_TEE_SPL, false, AttestTestDer.integer(2)),
                AttestTestDer.ext(AttestAmd.OID_SNP_SPL, false, AttestTestDer.integer(10)),
                AttestTestDer.ext(AttestAmd.OID_UCODE_SPL, false, AttestTestDer.integer(11)));
        }

        String askArkPem() {
            byte[] askDer = AttestTestDer.cert("SEV-Milan", "ARK-Milan", ask, ark, AttestTestDer.basicConstraints(true, 0), AttestTestDer.keyUsageCertSign());
            byte[] arkDer = AttestTestDer.cert("ARK-Milan", "ARK-Milan", ark, ark, AttestTestDer.basicConstraints(true, 1), AttestTestDer.keyUsageCertSign());
            return pem(askDer) + pem(arkDer);
        }

        byte[] report() {
            byte[] r = new byte[AttestAmd.REPORT_LEN];
            r[0] = 2;
            putLe(r, AttestAmd.OFF_POLICY, policy, 8);
            putLe(r, AttestAmd.OFF_VMPL, vmpl, 4);
            putLe(r, AttestAmd.OFF_SIG_ALGO, 1, 4);
            System.arraycopy(reportData, 0, r, AttestAmd.OFF_REPORT_DATA, 64);
            System.arraycopy(measurement, 0, r, AttestAmd.OFF_MEASUREMENT, 48);
            putLe(r, AttestAmd.OFF_REPORTED_TCB, reportedTcb, 8);
            System.arraycopy(chipId, 0, r, AttestAmd.OFF_CHIP_ID, 64);
            byte[] sig = AttestVendorRows.signRaw(vcek, "SHA384", Arrays.copyOfRange(r, 0, AttestAmd.OFF_SIGNED_END));
            for (int i = 0; i < 48; i++) {
                r[AttestAmd.OFF_SIG_R + i] = sig[47 - i];
                r[AttestAmd.OFF_SIG_S + i] = sig[95 - i];
            }
            return r;
        }

        Map<String, Object> evidence() { return ev("report", b64(report()), "vcekDer", b64(vcekDer()), "askArkPem", askArkPem()); }

        Map<String, Object> config(String extraPolicy) {
            return cfg("{\"family\":\"milan\",\"binding\":\"report-data\",\"trustAnchorArkSpkiSha384\":\"" + pin()
                + "\",\"policy\":{\"measurements\":[\"" + AttestCommon.toHexLower(measurement) + "\"]" + extraPolicy + "}}");
        }
    }

    static void putLe(byte[] b, int off, long v, int n) {
        for (int i = 0; i < n; i++) b[off + i] = (byte) (v >>> (8 * i));
    }

    @Test
    void genuineReportVerifies() {
        Genuine g = new Genuine();
        HardwareResult r = run(V, g.config(""), g.evidence(), BINDING, NOW);
        assertTrue(r.ok, r.reason);
        assertTrue(r.bound);
        assertEquals(AttestCommon.toHexLower(g.measurement), r.measured.get("runtime_measurement"));
        assertEquals(AttestCommon.toHexLower(g.chipId), r.measured.get("operator"));
        assertEquals("amd-sev-snp", r.hostAsserted.get("attestation_type"));
        assertEquals("milan", r.hostAsserted.get("family"));
    }

    @Test
    void genuineReportRefusals() {
        Genuine g = new Genuine();
        Map<String, Object> ev = g.evidence();
        String pre = "SEV-SNP report invalid: ";

        AttestationBinding other = new AttestationBinding("holder-key", "passport:abc", 1, "nonce-1");
        assertDenied("other binding", run(V, g.config(""), ev, other, NOW), pre + "report_data does not bind holder/grant/epoch/nonce", false);
        assertDenied("measurement", run(V, cfg("{\"family\":\"milan\",\"binding\":\"report-data\",\"trustAnchorArkSpkiSha384\":\"" + g.pin()
            + "\",\"policy\":{\"measurements\":[\"aa\"]}}"), ev, BINDING, NOW), pre + "measurement not in policy allowlist", false);
        assertDenied("wrong pin", run(V, cfg(CFG), ev, BINDING, NOW), pre + "cert chain invalid: ARK does not match the pinned AMD trust anchor", false);
        assertDenied("expired", run(V, g.config(""), ev, BINDING, 2_200_000_000_000L), pre + "cert chain invalid: VCEK certificate has expired", false);
        assertDenied("tcb floor", run(V, g.config(",\"minReportedTcb\":\"0x0b0a000000000202\""), ev, BINDING, NOW), pre + "reported_tcb below minimum (rollback?)", false);
        assertTrue(run(V, g.config(",\"minReportedTcb\":\"0x0b0a000000000201\""), ev, BINDING, NOW).ok, "an equal floor passes");
        assertDenied("guest svn", run(V, g.config(",\"minGuestSvn\":1"), ev, BINDING, NOW), pre + "guest_svn 0 below minimum 1", false);
        assertDenied("chip id", run(V, g.config(",\"chipIds\":[\"00\"]"), ev, BINDING, NOW), pre + "chip_id not in policy allowlist", false);
        assertDenied("vmpl number", run(V, g.config(",\"requireVmpl\":2"), ev, BINDING, NOW), pre + "vmpl 0 is not the required 2", false);
        assertTrue(run(V, g.config(",\"requireVmpl\":\"any\""), ev, BINDING, NOW).ok);

        byte[] tampered = g.report();
        tampered[AttestAmd.OFF_MEASUREMENT] ^= 1;
        Map<String, Object> ev2 = new LinkedHashMap<>(ev);
        ev2.put("report", b64(tampered));
        assertDenied("tampered", run(V, g.config(""), ev2, BINDING, NOW), pre + "report signature does not verify under VCEK", false);

        Genuine dbg = new Genuine();
        dbg.policy = AttestAmd.POLICY_DEBUG_BIT;
        assertDenied("debug", run(V, dbg.config(""), dbg.evidence(), BINDING, NOW), pre + "guest policy has the DEBUG bit set (host can inspect the guest)", false);
        assertTrue(run(V, dbg.config(",\"allowDebug\":true"), dbg.evidence(), BINDING, NOW).ok);

        Genuine down = new Genuine();
        down.splBootloader = 0;
        assertDenied("spl downgrade", run(V, down.config(""), down.evidence(), BINDING, NOW),
            pre + "VCEK bootloader SPL 0 does not match report reported_tcb (1) — TCB downgrade?", false);

        Map<String, Object> swapped = new LinkedHashMap<>(ev);
        String[] parts = g.askArkPem().split("(?<=-----END CERTIFICATE-----\n)");
        swapped.put("askArkPem", parts[1] + parts[0]);
        assertDenied("chain out of order", run(V, g.config(""), swapped, BINDING, NOW),
            pre + "cert chain invalid: second certificate of the chain is not a self-signed ARK (chain out of order?)", false);
    }
}
