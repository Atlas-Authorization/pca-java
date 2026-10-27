package net.atlasauth.pca;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * AMD SEV-SNP: genuine ATTESTATION_REPORT verification (ECDSA-P384 report signature under the VCEK, VCEK -&gt; ASK -&gt; ARK
 * chain to the pinned ARK of the configured family, VCEK &lt;-&gt; report binding, policy) with the same checks, order and
 * reason text as the reference verifier. Classical (ECDSA-P384 / RSA-PSS); no network I/O. Port of the Go attest_amd.go.
 */
final class AttestAmd implements VendorImpl {
    /** The SPKI SHA-384 (lowercase hex) of each family's ARK, as published by AMD's key distribution service. */
    static final Map<String, String> ARK_SPKI_SHA384 = new HashMap<>();
    static {
        ARK_SPKI_SHA384.put("milan", "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e");
        ARK_SPKI_SHA384.put("genoa", "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880");
        ARK_SPKI_SHA384.put("turin", "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5");
    }

    // ATTESTATION_REPORT layout (AMD SEV-SNP ABI): offsets, all integers little-endian.
    static final int OFF_GUEST_SVN = 0x004;
    static final int OFF_POLICY = 0x008;
    static final int OFF_VMPL = 0x030;
    static final int OFF_SIG_ALGO = 0x034;
    static final int OFF_REPORT_DATA = 0x050;
    static final int OFF_MEASUREMENT = 0x090;
    static final int OFF_HOST_DATA = 0x0c0;
    static final int OFF_REPORTED_TCB = 0x180;
    static final int OFF_CHIP_ID = 0x1a0;
    static final int OFF_COMMITTED_TCB = 0x1e0;
    static final int OFF_LAUNCH_TCB = 0x1f0;
    static final int OFF_SIGNED_END = 0x2a0;
    static final int OFF_SIG_R = 0x2a0;
    static final int OFF_SIG_S = 0x2e8;
    static final int REPORT_LEN = 0x4a0;
    static final long POLICY_DEBUG_BIT = 1L << 19;
    static final long SIG_ALGO_ECDSA_P384 = 1;

    static final String OID_HWID = "1.3.6.1.4.1.3704.1.4";
    static final String OID_BL_SPL = "1.3.6.1.4.1.3704.1.3.1";
    static final String OID_TEE_SPL = "1.3.6.1.4.1.3704.1.3.2";
    static final String OID_SNP_SPL = "1.3.6.1.4.1.3704.1.3.3";
    static final String OID_UCODE_SPL = "1.3.6.1.4.1.3704.1.3.8";
    static final int HWID_LEN = 64;

    private static final BigInteger P384_N = new BigInteger(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16);

    // ------------------------------------------------------------- report

    static final class SnpReport {
        long guestSvn;
        long policy;
        long vmpl;
        long sigAlgo;
        long reportedTcb;
        long committedTcb;
        long launchTcb;
        byte[] reportData;
        byte[] measurement;
        byte[] hostData;
        byte[] chipId;
        byte[] signed;
        byte[] sigR;
        byte[] sigS;
    }

    static long le32(byte[] b, int off) {
        return (b[off] & 0xffL) | (b[off + 1] & 0xffL) << 8 | (b[off + 2] & 0xffL) << 16 | (b[off + 3] & 0xffL) << 24;
    }

    static long le64(byte[] b, int off) { return le32(b, off) | le32(b, off + 4) << 32; }

    static SnpReport parseSnpReport(byte[] b) {
        int minLen = OFF_SIG_S + 72;
        if (b.length < minLen) {
            throw new AttestException("parseSevSnpReport: report too short (" + b.length + " < " + minLen + ")");
        }
        SnpReport r = new SnpReport();
        r.guestSvn = le32(b, OFF_GUEST_SVN);
        r.policy = le64(b, OFF_POLICY);
        r.vmpl = le32(b, OFF_VMPL);
        r.sigAlgo = le32(b, OFF_SIG_ALGO);
        r.reportedTcb = le64(b, OFF_REPORTED_TCB);
        r.committedTcb = le64(b, OFF_COMMITTED_TCB);
        r.launchTcb = le64(b, OFF_LAUNCH_TCB);
        r.reportData = Arrays.copyOfRange(b, OFF_REPORT_DATA, OFF_REPORT_DATA + 64);
        r.measurement = Arrays.copyOfRange(b, OFF_MEASUREMENT, OFF_MEASUREMENT + 48);
        r.hostData = Arrays.copyOfRange(b, OFF_HOST_DATA, OFF_HOST_DATA + 32);
        r.chipId = Arrays.copyOfRange(b, OFF_CHIP_ID, OFF_CHIP_ID + 64);
        r.signed = Arrays.copyOfRange(b, 0, OFF_SIGNED_END);
        r.sigR = Arrays.copyOfRange(b, OFF_SIG_R, OFF_SIG_R + 72);
        r.sigS = Arrays.copyOfRange(b, OFF_SIG_S, OFF_SIG_S + 72);
        return r;
    }

    static BigInteger leToBig(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) be[le.length - 1 - i] = le[i];
        return new BigInteger(1, be);
    }

    private static byte[] fixed48(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[48];
        int skip = b.length > 48 ? b.length - 48 : 0;
        System.arraycopy(b, skip, out, 48 - (b.length - skip), b.length - skip);
        return out;
    }

    /** ECDSA-P384 / SHA-384 over the signed region under the VCEK; AMD stores r and s little-endian. */
    static boolean verifySnpReportSignature(SnpReport r, ECPublicKey pub) {
        BigInteger rr = leToBig(r.sigR);
        BigInteger ss = leToBig(r.sigS);
        if (rr.signum() <= 0 || rr.compareTo(P384_N) >= 0 || ss.signum() <= 0 || ss.compareTo(P384_N) >= 0) return false;
        byte[] rs = new byte[96];
        System.arraycopy(fixed48(rr), 0, rs, 0, 48);
        System.arraycopy(fixed48(ss), 0, rs, 48, 48);
        return AttestCommon.verifyRawECDSA(pub, AttestCommon.sha384Sum(r.signed), rs);
    }

    /** Decodes an SPL extension value: one minimal DER INTEGER 0..255. {value, null} or {0, failure text}. */
    static Object[] decodeSpl(byte[] v) {
        if (v.length < 3 || v[0] != 0x02) return new Object[] {0, "is not a DER INTEGER"};
        int l = v[1] & 0xff;
        if (l < 1 || l > 2 || v.length != 2 + l) return new Object[] {0, "has a wrong-length INTEGER"};
        int c0 = v[2] & 0xff;
        if ((c0 & 0x80) != 0) return new Object[] {0, "is negative"};
        if (l == 2) {
            if (c0 != 0x00) return new Object[] {0, "is out of range (> 255)"};
            if ((v[3] & 0x80) == 0) return new Object[] {0, "is a non-minimal INTEGER"};
            return new Object[] {v[3] & 0xff, null};
        }
        return new Object[] {c0, null};
    }

    /** Binds the VCEK body to the report: hwID == chip_id and the four SPLs == the REPORTED_TCB bytes. The failure, or "". */
    static String checkVcekReportBinding(byte[] vcekTbs, SnpReport r) {
        AttestDer.ExtTable exts;
        try {
            exts = AttestDer.parseTbsExtensions(vcekTbs);
        } catch (AttestException e) {
            return "VCEK extensions malformed: " + AttestCommon.errMsg(e);
        }
        AttestDer.CertExt hw = exts.get(OID_HWID);
        if (hw == null) return "VCEK certificate has no CHIP_ID (hwID) extension";
        if (hw.critical) return "VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)";
        if (hw.value.length != HWID_LEN) {
            return "VCEK CHIP_ID (hwID) extension is " + hw.value.length + " bytes, expected " + HWID_LEN;
        }
        if (!AttestCommon.timingSafeEq(hw.value, r.chipId)) return "VCEK CHIP_ID does not match report chip_id";
        String[][] pairs = {{OID_BL_SPL, "bootloader", "0"}, {OID_TEE_SPL, "tee", "1"}, {OID_SNP_SPL, "snp", "6"}, {OID_UCODE_SPL, "microcode", "7"}};
        for (String[] p : pairs) {
            int want = (int) ((r.reportedTcb >>> (8 * Integer.parseInt(p[2]))) & 0xff);
            AttestDer.CertExt ext = exts.get(p[0]);
            if (ext == null) return "VCEK certificate has no " + p[1] + " SPL extension";
            if (ext.critical) return "VCEK " + p[1] + " SPL extension is marked critical (the AMD profile is non-critical)";
            Object[] d = decodeSpl(ext.value);
            if (d[1] != null) return "VCEK " + p[1] + " SPL extension " + d[1];
            int got = (Integer) d[0];
            if (got != want) {
                return "VCEK " + p[1] + " SPL " + got + " does not match report reported_tcb (" + want + ") — TCB downgrade?";
            }
        }
        return "";
    }

    /** The outcome of the chain check: the failure reason (empty when ok), the VCEK key and its tbsCertificate. */
    static final class ChainResult {
        final String reason;
        final ECPublicKey key;
        final byte[] tbs;

        ChainResult(String reason, ECPublicKey key, byte[] tbs) {
            this.reason = reason;
            this.key = key;
            this.tbs = tbs;
        }
    }

    /** Verifies VCEK -&gt; ASK -&gt; ARK with the ARK pinned. */
    static ChainResult verifyAmdCertChain(byte[] vcekDer, String askArkPem, String pin, long nowMs, Object clockSkew) {
        double skew = 0;
        if (clockSkew != null) {
            Double f = AttestCommon.asFinite(clockSkew);
            if (f == null || f < 0) return new ChainResult("clockSkewMs must be a non-negative number", null, null);
            skew = f;
        }
        try {
            AttCert vcek = AttestCert.parseCertDer(vcekDer);
            List<String> pems = AttestCommon.pemCertBlocks(askArkPem);
            if (pems.size() != 2) return fail("ASK+ARK chain must contain exactly two certificates (ASK then ARK)");
            AttCert ask = AttestCert.certFromPem(pems.get(0));
            AttCert ark = AttestCert.certFromPem(pems.get(1));
            if (!ark.selfIssued() || !AttestCert.certSigOkBy(ark, ark)) {
                return fail("second certificate of the chain is not a self-signed ARK (chain out of order?)");
            }
            if (ask.selfIssued()) return fail("first certificate of the chain is self-signed, not an ASK (chain out of order?)");
            if (!Arrays.equals(ask.rawSubject, vcek.rawIssuer)) return fail("ASK subject does not match the VCEK issuer");
            CertKey arkKey = AttestCert.keyOfCert(ark);
            if (!arkKey.spkiSha384().equals(pin.toLowerCase(Locale.ROOT))) return fail("ARK does not match the pinned AMD trust anchor");
            if (!Arrays.equals(ask.rawIssuer, ark.rawSubject) || !AttestCert.certSigOkBy(ask, ark)) return fail("ASK is not signed by ARK");
            if (!AttestCert.certSigOkBy(vcek, ask)) return fail("VCEK is not signed by ASK");

            String[] labels = {"VCEK", "ASK", "ARK"};
            List<byte[]> ders = Arrays.asList(vcekDer, ask.raw, ark.raw);
            String roleErr = AttestDer.checkChainRoles(ders);
            if (!roleErr.isEmpty()) return fail("AMD chain role check failed: " + roleErr);
            for (int i = 0; i < ders.size(); i++) {
                String label = labels[i];
                byte[] der = ders.get(i);
                AttestDer.ExtTable exts = AttestDer.parseCertExtensions(der);
                for (String oid : exts.oids) {
                    if (exts.m.get(oid).critical && !AttestDer.RECOGNISED_CRITICAL_EXTENSIONS.contains(oid)) {
                        return fail(label + " certificate has an unrecognised critical extension " + oid);
                    }
                }
                if (!label.equals("VCEK")) {
                    AttestDer.CertExt bc = exts.get("2.5.29.19");
                    if (bc == null || !bc.critical) return fail(label + " certificate BasicConstraints is not marked critical");
                }
                AttestDer.DerInstant[] v = AttestDer.derValidity(der);
                if (!v[0].ok || !v[1].ok) return fail(label + " certificate validity is unparseable");
                if ((double) nowMs + skew < (double) v[0].ms) return fail(label + " certificate is not yet valid");
                if ((double) nowMs - skew > (double) v[1].ms) return fail(label + " certificate has expired");
            }

            CertKey vk = AttestCert.keyOfCert(vcek);
            if (!"ec".equals(vk.typ) || !"secp384r1".equals(vk.curve)) {
                String curve = vk.curve == null || vk.curve.isEmpty() ? "undefined" : vk.curve;
                throw new AttestException("VCEK is not EC secp384r1 (got " + vk.typ + "/" + curve + ")");
            }
            AttestCommon.ecPointOfKey(vk, "P-384");
            byte[] tbs = AttestDer.tbsOfCertificate(vcekDer);
            return new ChainResult("", (ECPublicKey) vk.pub, tbs);
        } catch (AttestException e) {
            return fail("AMD chain verification error: " + AttestCommon.errMsg(e));
        }
    }

    private static ChainResult fail(String r) { return new ChainResult(r, null, null); }

    // ------------------------------------------------------------- policy

    static final class SnpPolicy {
        List<String> measurements = new ArrayList<>();
        List<String> hostData = new ArrayList<>();
        List<String> chipIds = new ArrayList<>();
        boolean allowDebug;
        boolean requireEcdsaP384;
        Double minGuestSvn;
        BigInteger minReportedTcb;
        BigInteger minCommittedTcb;
        BigInteger minLaunchTcb;
        /** null (default 0), "any", or a number. */
        Object requireVmpl;

        String check(SnpReport r) {
            if (requireEcdsaP384 && r.sigAlgo != SIG_ALGO_ECDSA_P384) return "unexpected signature_algo " + r.sigAlgo;
            if (!allowDebug && (r.policy & POLICY_DEBUG_BIT) != 0) return "guest policy has the DEBUG bit set (host can inspect the guest)";
            if (minGuestSvn != null && (double) r.guestSvn < minGuestSvn) {
                return "guest_svn " + r.guestSvn + " below minimum " + AttestCommon.jsNumString(minGuestSvn);
            }
            if (minReportedTcb != null && u64(r.reportedTcb).compareTo(minReportedTcb) < 0) return "reported_tcb below minimum (rollback?)";
            if (minCommittedTcb != null && u64(r.committedTcb).compareTo(minCommittedTcb) < 0) return "committed_tcb below minimum (rollback?)";
            if (minLaunchTcb != null && u64(r.launchTcb).compareTo(minLaunchTcb) < 0) return "launch_tcb below minimum";
            if (requireVmpl == null) {
                if (r.vmpl != 0) return "vmpl " + r.vmpl + " is not the required 0";
            } else if (requireVmpl instanceof String) {
                if (!"any".equals(requireVmpl)) return "vmpl " + r.vmpl + " is not the required " + requireVmpl;
            } else {
                Double f = AttestCommon.asFinite(requireVmpl);
                if (f == null || (double) r.vmpl != f) return "vmpl " + r.vmpl + " is not the required " + jsAnyString(requireVmpl);
            }
            if (!measurements.isEmpty() && !measurements.contains(AttestCommon.toHexLower(r.measurement))) return "measurement not in policy allowlist";
            if (!hostData.isEmpty() && !hostData.contains(AttestCommon.toHexLower(r.hostData))) return "host_data not in policy allowlist";
            if (!chipIds.isEmpty() && !chipIds.contains(AttestCommon.toHexLower(r.chipId))) return "chip_id not in policy allowlist";
            return "";
        }
    }

    static BigInteger u64(long v) { return new BigInteger(Long.toUnsignedString(v)); }

    static String jsAnyString(Object v) {
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double f = AttestCommon.asFinite(v);
        if (f != null) return AttestCommon.jsNumString(f);
        return String.valueOf(v);
    }

    private static boolean digitsIn(String s, int base) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'z' ? c - 'a' + 10 : c >= 'A' && c <= 'Z' ? c - 'A' + 10 : 99;
            if (d >= base) return false;
        }
        return true;
    }

    /** BigInt(v) for a JSON value; the error text is the reference's. */
    static BigInteger parseJsBigInt(Object v) {
        if (v == null) throw new AttestException("Cannot convert null to a BigInt");
        if (v instanceof Boolean) return ((Boolean) v) ? BigInteger.ONE : BigInteger.ZERO;
        if (v instanceof String) {
            String t = (String) v;
            String s = AttestCommon.jsTrim(t);
            if (s.isEmpty()) return BigInteger.ZERO;
            int base = 10;
            String body = s;
            if (s.length() > 2 && s.charAt(0) == '0') {
                char p = s.charAt(1);
                if (p == 'x' || p == 'X') { base = 16; body = s.substring(2); }
                else if (p == 'o' || p == 'O') { base = 8; body = s.substring(2); }
                else if (p == 'b' || p == 'B') { base = 2; body = s.substring(2); }
            }
            if (base == 10) {
                String digits = body.startsWith("+") || body.startsWith("-") ? body.substring(1) : body;
                if (digitsIn(digits, 10)) return new BigInteger(body);
            } else if (digitsIn(body, base)) {
                return new BigInteger(body, base);
            }
            throw new AttestException("Cannot convert " + t + " to a BigInt");
        }
        if (v instanceof Json.Num) {
            Double f = AttestCommon.asFinite(v);
            if (f == null || f != Math.floor(f)) {
                throw new AttestException("The number " + ((Json.Num) v).raw + " cannot be converted to a BigInt because it is not an integer");
            }
            // BigInt(Number): the exact value of the double JSON.parse produced
            return new BigDecimal(f).toBigInteger();
        }
        throw new AttestException("Cannot convert value to a BigInt");
    }

    // ------------------------------------------------------------- the verifier

    final String family;
    final String pin;
    final String binding;
    final SnpPolicy policy;
    final Object skew;

    private AttestAmd(String family, String pin, String binding, SnpPolicy policy, Object skew) {
        this.family = family;
        this.pin = pin;
        this.binding = binding;
        this.policy = policy;
        this.skew = skew;
    }

    /** The factory entry (AttestFactory looks it up by name); AttestException refuses the configuration. */
    static VendorImpl create(Map<String, Object> cfg) {
        Map<String, Object> pol = AttestCommon.asRec(cfg.get("policy"));
        if (pol == null) pol = new LinkedHashMap<>();
        SnpPolicy p = new SnpPolicy();
        // the wire config carries the u64 floors as decimal strings: converted before the constructor runs
        p.requireEcdsaP384 = !Boolean.FALSE.equals(pol.get("requireEcdsaP384"));
        p.allowDebug = Boolean.TRUE.equals(pol.get("allowDebug"));
        p.requireVmpl = pol.get("requireVmpl");
        if (pol.containsKey("minReportedTcb")) p.minReportedTcb = parseJsBigInt(pol.get("minReportedTcb"));
        if (pol.containsKey("minCommittedTcb")) p.minCommittedTcb = parseJsBigInt(pol.get("minCommittedTcb"));
        if (pol.containsKey("minLaunchTcb")) p.minLaunchTcb = parseJsBigInt(pol.get("minLaunchTcb"));
        Object fam = cfg.get("family");
        String family = fam instanceof String ? (String) fam : "";
        String pin = ARK_SPKI_SHA384.get(family);
        if (pin == null) throw new AttestException("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'");
        Object o = cfg.get("trustAnchorArkSpkiSha384");
        if (o instanceof String) pin = (String) o; // conformance harness only: replaces the built-in pin
        Object b = cfg.get("binding");
        String binding = b instanceof String ? (String) b : "";
        if (!binding.equals("report-data") && !binding.equals("azure-runtime-data")) {
            throw new AttestException("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'");
        }
        List<String> ms = AttestCommon.asStrList(pol.get("measurements"));
        if (ms == null || ms.isEmpty()) {
            throw new AttestException("createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)");
        }
        p.measurements = AttestCommon.lowerAll(ms);
        List<String> l = AttestCommon.asStrList(pol.get("hostData"));
        if (l != null) p.hostData = AttestCommon.lowerAll(l);
        l = AttestCommon.asStrList(pol.get("chipIds"));
        if (l != null) p.chipIds = AttestCommon.lowerAll(l);
        p.minGuestSvn = AttestCommon.asFinite(pol.get("minGuestSvn"));
        return new AttestAmd(family, pin, binding, p, cfg.get("clockSkewMs"));
    }

    static byte[] evBytes(Map<String, Object> ev, String key) {
        Object s = ev == null ? null : ev.get(key);
        return s instanceof String ? AttestCommon.nodeB64((String) s) : null;
    }

    private static boolean nonZero(byte[] b, int from, int to) {
        for (int i = from; i < to; i++) if (b[i] != 0) return true;
        return false;
    }

    /** verifyGenuineSevSnpReport: {reason, report}; the report is null on failure. */
    Object[] verifyReport(byte[] raw, byte[] vcekDer, String askArkPem, long nowMs, AttestationBinding expected) {
        SnpReport rep;
        try {
            rep = parseSnpReport(raw);
        } catch (AttestException e) {
            return new Object[] {"report parse failed: " + AttestCommon.errMsg(e), null};
        }
        if (raw.length != REPORT_LEN) return new Object[] {"report length " + raw.length + " is not the canonical " + REPORT_LEN, null};
        if (nonZero(raw, OFF_SIG_S + 72, raw.length) || nonZero(raw, OFF_SIG_R + 48, OFF_SIG_R + 72) || nonZero(raw, OFF_SIG_S + 48, OFF_SIG_S + 72)) {
            return new Object[] {"report signature block has non-zero reserved bytes", null};
        }
        ChainResult chain = verifyAmdCertChain(vcekDer, askArkPem, pin, nowMs, skew);
        if (!chain.reason.isEmpty() || chain.key == null || chain.tbs == null) return new Object[] {"cert chain invalid: " + chain.reason, null};
        if (!verifySnpReportSignature(rep, chain.key)) return new Object[] {"report signature does not verify under VCEK", null};
        String bindErr = checkVcekReportBinding(chain.tbs, rep);
        if (!bindErr.isEmpty()) return new Object[] {bindErr, null};
        if (expected != null) {
            byte[] want;
            try {
                want = AttestCommon.attestationBindingBytes(expected);
            } catch (AttestException e) {
                return new Object[] {"genuine verification error (fail closed): " + e.getMessage(), null};
            }
            if (!AttestCommon.timingSafeEq(want, rep.reportData)) return new Object[] {"report_data does not bind holder/grant/epoch/nonce", null};
        }
        String pol = policy.check(rep);
        if (!pol.isEmpty()) return new Object[] {pol, null};
        return new Object[] {"", rep};
    }

    @Override
    public HardwareResult verify(Map<String, Object> ev, AttestationBinding expected, long nowMs) {
        byte[] report = evBytes(ev, "report");
        byte[] vcek = evBytes(ev, "vcekDer");
        Object askArk = ev == null ? null : ev.get("askArkPem");
        if (ev == null || report == null || vcek == null || !(askArk instanceof String)) {
            return HardwareResult.fail("no AMD SEV-SNP evidence for this action");
        }
        if (expected == null) return HardwareResult.fail("no expected attestation binding supplied");
        boolean direct = binding.equals("report-data");
        Object[] out = verifyReport(report, vcek, (String) askArk, nowMs, direct ? expected : null);
        SnpReport rep = (SnpReport) out[1];
        if (rep == null) return HardwareResult.fail("SEV-SNP report invalid: " + out[0]);
        if (!direct) {
            byte[] rd = evBytes(ev, "runtimeData");
            if (rd == null) return HardwareResult.fail("azure-runtime-data binding needs the runtime-data JSON bytes");
            String why = AttestCommon.checkAzureRuntimeDataBinding(rep.reportData, rd, expected);
            if (!why.isEmpty()) return HardwareResult.fail(why);
        }
        Map<String, String> host = new LinkedHashMap<>();
        host.put("attestation_type", "amd-sev-snp");
        host.put("family", family);
        host.put("measurement", AttestCommon.toHexLower(rep.measurement));
        return HardwareResult.ok(true, HardwareResult.newMeasured(AttestCommon.toHexLower(rep.measurement), AttestCommon.toHexLower(rep.chipId)), host);
    }
}
