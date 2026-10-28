package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Intel TDX (DCAP v4, ECDSA-P256): the genuine quote end to end (PCK chain to the pinned Intel SGX Root CA, QE report under
 * the PCK leaf, attestation key endorsed by the QE, TD quote signature), the PCA binding in its two modes, and the optional
 * Intel PCS collateral ({@link AttestIntelCollateral}). Same checks, order and reason text as the reference verifier. Port
 * of the Go attest_intel.go.
 */
final class AttestIntel implements VendorImpl {
    /** Pins Intel's SGX Provisioning Certification Root CA (SPKI SHA-256, lowercase hex). */
    static final String SGX_ROOT_CA_SPKI_SHA256 = "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e";

    static final int HEADER_LEN = 48;
    static final int TD_REPORT_LEN = 584;
    static final int SGX_REPORT = 384;
    static final int QE_ATTR_OFF = 48;
    static final int QE_RDATA_OFF = 0x140;

    static final class DcapQuote {
        byte[] header;
        byte[] tdReportBody;
        byte[] quoteSignature;
        byte[] akPubRaw;
        byte[] qeReportBody;
        byte[] qeReportSignature;
        byte[] qeAuthData;
        String pckChainPem;
    }

    private static int le16(byte[] b, int off) { return (b[off] & 0xff) | (b[off + 1] & 0xff) << 8; }

    private static long le32(byte[] b, int off) { return AttestAmd.le32(b, off); }

    private static void need(int o, int n, long sigEnd, String what) {
        if ((long) o + n > sigEnd) throw new AttestException("parseDcapQuote: truncated reading " + what);
    }

    static DcapQuote parseDcapQuote(byte[] q) {
        if (q.length < HEADER_LEN + TD_REPORT_LEN + 4) {
            throw new AttestException("parseDcapQuote: too short for header + TD report + sig length");
        }
        int version = le16(q, 0);
        int attKeyType = le16(q, 2);
        long teeType = le32(q, 4);
        if (version != 4) throw new AttestException("parseDcapQuote: unsupported quote version " + version + " (expected 4)");
        if (attKeyType != 2) {
            throw new AttestException("parseDcapQuote: unsupported attestation key type " + attKeyType + " (expected ECDSA-P256 = 2)");
        }
        if (teeType != 0x81) {
            throw new AttestException("parseDcapQuote: unexpected TEE type 0x" + Long.toHexString(teeType) + " (expected TDX = 0x81)");
        }
        DcapQuote out = new DcapQuote();
        out.header = Arrays.copyOfRange(q, 0, HEADER_LEN);
        out.tdReportBody = Arrays.copyOfRange(q, HEADER_LEN, HEADER_LEN + TD_REPORT_LEN);
        int o = HEADER_LEN + TD_REPORT_LEN;
        long sigDataLen = le32(q, o);
        o += 4;
        long sigEnd = o + sigDataLen;
        if (sigEnd > q.length) throw new AttestException("parseDcapQuote: signature data (" + sigDataLen + ") overruns the quote");
        need(o, 64, sigEnd, "quote signature");
        out.quoteSignature = Arrays.copyOfRange(q, o, o + 64);
        o += 64;
        need(o, 64, sigEnd, "attestation public key");
        out.akPubRaw = Arrays.copyOfRange(q, o, o + 64);
        o += 64;
        need(o, 6, sigEnd, "outer cert-data header");
        int outerType = le16(q, o);
        long outerSize = le32(q, o + 2);
        o += 6;
        if (outerType != 6) throw new AttestException("parseDcapQuote: outer cert-data type " + outerType + " (expected QE-report-cert-data = 6)");
        long outerEnd = o + outerSize;
        if (outerEnd > sigEnd) throw new AttestException("parseDcapQuote: outer cert-data overruns signature data");
        need(o, SGX_REPORT, sigEnd, "QE report");
        out.qeReportBody = Arrays.copyOfRange(q, o, o + SGX_REPORT);
        o += SGX_REPORT;
        need(o, 64, sigEnd, "QE report signature");
        out.qeReportSignature = Arrays.copyOfRange(q, o, o + 64);
        o += 64;
        need(o, 2, sigEnd, "QE auth-data size");
        int authSize = le16(q, o);
        o += 2;
        need(o, authSize, sigEnd, "QE auth-data");
        out.qeAuthData = Arrays.copyOfRange(q, o, o + authSize);
        o += authSize;
        need(o, 6, sigEnd, "inner cert-data header");
        int innerType = le16(q, o);
        long innerSize = le32(q, o + 2);
        o += 6;
        if (innerType != 5) throw new AttestException("parseDcapQuote: inner cert-data type " + innerType + " (expected PCK-cert-chain = 5)");
        if (o + innerSize > outerEnd) throw new AttestException("parseDcapQuote: inner cert-data overruns outer cert-data");
        out.pckChainPem = new String(q, o, (int) innerSize, StandardCharsets.UTF_8);
        for (int i = (int) sigEnd; i < q.length; i++) {
            if (q[i] != 0) throw new AttestException("parseDcapQuote: non-zero bytes after the signature data");
        }
        return out;
    }

    // ------------------------------------------------------------- the Intel SGX extension (byte scan, as the reference does)

    static final byte[] OID_SGX_FMSPC = {0x06, 0x0a, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04};
    static final byte[] OID_SGX_TCB = {0x06, 0x0a, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02};

    /** Reads one TLV at off; null on any malformed or overrunning length. */
    static AttestDer.Tlv readDerTlvLenient(byte[] buf, int off) {
        if (off < 0 || off + 2 > buf.length) return null;
        int tag = buf[off] & 0xff;
        long l = buf[off + 1] & 0xff;
        int p = off + 2;
        if ((l & 0x80) != 0) {
            int n = (int) (l & 0x7f);
            if (n == 0 || n > 4 || p + n > buf.length) return null;
            l = 0;
            for (int i = 0; i < n; i++) l = l * 256 + (buf[p++] & 0xff);
        }
        long end = p + l;
        if (end > buf.length) return null;
        return new AttestDer.Tlv(tag, p, (int) end);
    }

    static int indexOfBytes(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }

    static final class PckTcb {
        byte[] fmspc;
        /** The 16 SGX TCB component SVNs. */
        byte[] sgx;
        int pcesvn;
    }

    /** Reads the FMSPC and the issued TCB from the PCK leaf's Intel SGX extension. */
    static PckTcb extractPckFmspcAndTcb(byte[] leaf) {
        int fi = indexOfBytes(leaf, OID_SGX_FMSPC);
        if (fi < 0) throw new AttestException("extractPckFmspcAndTcb: FMSPC OID not found in certificate");
        AttestDer.Tlv fv = readDerTlvLenient(leaf, fi + OID_SGX_FMSPC.length);
        if (fv == null || fv.tag != 0x04 || fv.end - fv.start != 6) throw new AttestException("extractPckFmspcAndTcb: malformed FMSPC OCTET STRING");
        byte[] fmspc = Arrays.copyOfRange(leaf, fv.start, fv.end);
        int ti = indexOfBytes(leaf, OID_SGX_TCB);
        if (ti < 0) throw new AttestException("extractPckFmspcAndTcb: TCB OID not found in certificate");
        AttestDer.Tlv seq = readDerTlvLenient(leaf, ti + OID_SGX_TCB.length);
        if (seq == null || seq.tag != 0x30) throw new AttestException("extractPckFmspcAndTcb: malformed TCB SEQUENCE");
        byte[] sgx = new byte[16];
        int pcesvn = -1;
        int p = seq.start;
        int idx = 0;
        while (p < seq.end) {
            AttestDer.Tlv pair = readDerTlvLenient(leaf, p);
            if (pair == null || pair.tag != 0x30) throw new AttestException("extractPckFmspcAndTcb: malformed TCB component");
            AttestDer.Tlv oid = readDerTlvLenient(leaf, pair.start);
            if (oid == null || oid.tag != 0x06) throw new AttestException("extractPckFmspcAndTcb: TCB component missing OID");
            AttestDer.Tlv val = readDerTlvLenient(leaf, oid.end);
            if (val == null) throw new AttestException("extractPckFmspcAndTcb: TCB component missing value");
            int last = leaf[oid.end - 1] & 0xff;
            if (val.tag == 0x02) {
                int n = 0; // uint32 arithmetic: the high bits fall off as in the reference
                for (int b = val.start; b < val.end; b++) n = n << 8 | (leaf[b] & 0xff);
                if (last >= 1 && last <= 16) sgx[last - 1] = (byte) (n & 0xff);
                else if (last == 17) pcesvn = n & 0xffff;
            }
            p = pair.end;
            idx++;
            if (idx > 64) break;
        }
        if (pcesvn < 0) throw new AttestException("extractPckFmspcAndTcb: PCESVN not found in TCB extension");
        PckTcb t = new PckTcb();
        t.fmspc = fmspc;
        t.sgx = sgx;
        t.pcesvn = pcesvn;
        return t;
    }

    // ------------------------------------------------------------- PCK chain

    static final class PckChainResult {
        boolean ok;
        String reason = "";
        /** The failure was a validity-window failure. */
        boolean validity;
        AttCert leaf;
        ECPublicKey leafKey;
        int depth;
    }

    private static PckChainResult chainFail(String r) {
        PckChainResult x = new PckChainResult();
        x.reason = r;
        return x;
    }

    private static String k(byte[] b) { return new String(b, StandardCharsets.ISO_8859_1); }

    /**
     * Verifies a PEM chain to the pinned Intel SGX Root CA (every certificate valid at nowMs, every link signed, the root
     * self-signed and pinned, CA roles, no unrecognised critical extension, an EC P-256 leaf).
     */
    static PckChainResult verifyIntelPckChain(String pckChainPem, String pin, long nowMs) {
        try {
            List<String> blocks = AttestCommon.pemCertBlocks(pckChainPem);
            if (blocks.isEmpty()) return chainFail("no PEM certificates in the PCK chain");
            List<AttCert> certs = new ArrayList<>();
            for (String b : blocks) certs.add(AttestCert.certFromPem(b));
            Set<String> issuers = new HashSet<>();
            Map<String, AttCert> bySubject = new HashMap<>();
            for (AttCert c : certs) {
                issuers.add(k(c.rawIssuer));
                bySubject.put(k(c.rawSubject), c);
            }
            AttCert leaf = certs.get(0);
            for (AttCert c : certs) {
                if (!issuers.contains(k(c.rawSubject))) {
                    leaf = c;
                    break;
                }
            }
            List<AttCert> ordered = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            for (AttCert cur = leaf; cur != null && !seen.contains(k(cur.rawSubject)); ) {
                ordered.add(cur);
                seen.add(k(cur.rawSubject));
                if (cur.selfIssued()) break;
                cur = bySubject.get(k(cur.rawIssuer));
            }
            AttCert root = ordered.get(ordered.size() - 1);
            if (!root.selfIssued()) return chainFail("PCK chain does not terminate in a self-signed root");
            if (ordered.size() != certs.size()) return chainFail("PCK chain is not a single connected path (orphan/duplicate certificates)");
            for (AttCert c : ordered) {
                if (!AttestDer.derValidAt(c.raw, nowMs, 0)) {
                    PckChainResult r = chainFail("PCK chain certificate outside its validity period");
                    r.validity = true;
                    return r;
                }
            }
            for (int i = 0; i < ordered.size() - 1; i++) {
                AttCert child = ordered.get(i);
                AttCert parent = ordered.get(i + 1);
                if (!Arrays.equals(child.rawIssuer, parent.rawSubject)) return chainFail("certificate at depth " + i + " issuer does not match its parent subject");
                if (!AttestCert.certSigOkBy(child, parent)) return chainFail("certificate at depth " + i + " is not signed by its issuer");
            }
            if (!AttestCert.certSigOkBy(root, root)) return chainFail("root certificate is not self-signed");
            CertKey rootKey = AttestCert.keyOfCert(root);
            if (!rootKey.spkiSha256().equals(pin.toLowerCase(Locale.ROOT))) return chainFail("Intel SGX Root CA does not match the pinned trust anchor");
            List<byte[]> ders = new ArrayList<>();
            for (AttCert c : ordered) ders.add(c.raw);
            String roleFail = AttestDer.checkChainRoles(ders);
            if (!roleFail.isEmpty()) return chainFail(roleFail);
            for (int i = 0; i < ders.size(); i++) {
                String crit = AttestDer.unrecognisedCriticalExtension(ders.get(i), null);
                if (crit != null) return chainFail("PCK chain certificate at depth " + i + " has an unrecognised critical extension " + crit);
            }
            CertKey lk = AttestCert.keyOfCert(leaf);
            if (!"ec".equals(lk.typ)) return chainFail("PCK leaf key is not EC (got " + lk.typ + ")");
            AttestCommon.ecPointOfKey(lk, "P-256");
            PckChainResult ok = new PckChainResult();
            ok.ok = true;
            ok.leaf = leaf;
            ok.leafKey = (ECPublicKey) lk.pub;
            ok.depth = ordered.size();
            return ok;
        } catch (AttestException e) {
            return chainFail("PCK chain X.509 verification error (fail closed): " + AttestCommon.errMsg(e));
        }
    }

    // ------------------------------------------------------------- genuine quote

    static final class QuotePolicy {
        List<String> mrtds = new ArrayList<>();
        List<String> fmspcs = new ArrayList<>();
        List<String> rtmrs = new ArrayList<>();
        List<String> mrSeams = new ArrayList<>();
        List<String> mrSignerSeams = new ArrayList<>();
        boolean hasMrSeams;
        boolean hasMrSigner;
        boolean allowDebug;
    }

    static final class TdxResult {
        boolean ok;
        String reason = "";
        byte[] reportData;
        String fmspc = "";
        PckTcb pck;
        byte[] mrTd;
    }

    private static TdxResult bad(String r) {
        TdxResult x = new TdxResult();
        x.reason = r;
        return x;
    }

    static boolean verifyP256Compact(byte[] msg, byte[] sig, ECPublicKey pub) {
        if (sig.length != 64) return false;
        return AttestCommon.verifyRawECDSA(pub, AttestCommon.sha256Sum(msg), sig);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String hex(byte[] b, int from, int to) { return AttestCommon.toHexLower(Arrays.copyOfRange(b, from, to)); }

    static TdxResult verifyGenuineTdxQuote(byte[] quote, String pin, long nowMs, QuotePolicy pol, boolean allowDebugOnly) {
        DcapQuote q;
        try {
            q = parseDcapQuote(quote);
        } catch (AttestException e) {
            return bad("quote parse failed: " + AttestCommon.errMsg(e));
        }
        byte[] body = q.tdReportBody;
        PckChainResult chain = verifyIntelPckChain(q.pckChainPem, pin, nowMs);
        if (!chain.ok || chain.leafKey == null || chain.leaf == null) return bad("PCK chain invalid: " + chain.reason);
        PckTcb tcb;
        try {
            tcb = extractPckFmspcAndTcb(chain.leaf.raw);
        } catch (AttestException e) {
            return bad("PCK FMSPC/TCB extraction failed: " + AttestCommon.errMsg(e));
        }
        if (!verifyP256Compact(q.qeReportBody, q.qeReportSignature, chain.leafKey)) return bad("QE report signature does not verify under the PCK leaf");
        if ((q.qeReportBody[QE_ATTR_OFF] & 0x02) != 0) return bad("QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)");
        byte[] qeReportData = Arrays.copyOfRange(q.qeReportBody, QE_RDATA_OFF, QE_RDATA_OFF + 64);
        byte[] akBinding = AttestCommon.sha256Sum(concat(q.akPubRaw, q.qeAuthData));
        boolean zero = true;
        for (int i = 32; i < 64; i++) if (qeReportData[i] != 0) zero = false;
        if (!AttestCommon.timingSafeEq(Arrays.copyOfRange(qeReportData, 0, 32), akBinding) || !zero) {
            return bad("QE report_data does not bind the attestation key (AK not endorsed by this QE)");
        }
        ECPublicKey akPub = AttestCommon.pointToKey("P-256", concat(new byte[] {0x04}, q.akPubRaw));
        if (akPub == null) return bad("attestation public key is not a valid P-256 point");
        if (!verifyP256Compact(concat(q.header, body), q.quoteSignature, akPub)) return bad("TD quote signature does not verify under the attestation key");
        boolean allowDebug = allowDebugOnly || (pol != null && pol.allowDebug);
        if (!allowDebug && (body[120] & 1) != 0) return bad("TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)");
        String mrTd = hex(body, 136, 184);
        String fmspcHex = AttestCommon.toHexLower(tcb.fmspc);
        if (pol != null) {
            if (!pol.mrtds.isEmpty() && !pol.mrtds.contains(mrTd)) return bad("MRTD not in policy allowlist");
            if (!pol.fmspcs.isEmpty() && !pol.fmspcs.contains(fmspcHex)) return bad("FMSPC not in policy allowlist");
            if (pol.hasMrSeams && !pol.mrSeams.contains(hex(body, 16, 64))) return bad("MRSEAM not in policy allowlist");
            if (pol.hasMrSigner && !pol.mrSignerSeams.contains(hex(body, 64, 112))) return bad("MRSIGNERSEAM not in policy allowlist");
            if (!pol.rtmrs.isEmpty() && !pol.rtmrs.contains(hex(body, 328, 376))) return bad("RTMR0 not in policy allowlist");
        }
        TdxResult r = new TdxResult();
        r.ok = true;
        r.reportData = Arrays.copyOfRange(body, 520, 584);
        r.fmspc = fmspcHex;
        r.pck = tcb;
        r.mrTd = Arrays.copyOfRange(body, 136, 184);
        return r;
    }

    // ------------------------------------------------------------- the verifier

    final String binding;
    final QuotePolicy pol;
    final String pin;
    final boolean allowMissing;
    final AttestIntelCollateral.Policy collateralPol;

    private AttestIntel(String binding, QuotePolicy pol, String pin, boolean allowMissing, AttestIntelCollateral.Policy collateralPol) {
        this.binding = binding;
        this.pol = pol;
        this.pin = pin;
        this.allowMissing = allowMissing;
        this.collateralPol = collateralPol;
    }

    private static boolean hex96(String m) { return AttestCommon.isHexChars(m) && m.length() == 96; }

    /** The factory entry (AttestFactory looks it up by name); AttestException refuses the configuration. */
    static VendorImpl create(Map<String, Object> cfg) {
        Object b = cfg.get("binding");
        String binding = b instanceof String ? (String) b : "";
        if (!binding.equals("report-data") && !binding.equals("azure-runtime-data")) {
            throw new AttestException("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'");
        }
        Map<String, Object> pol = AttestCommon.asRec(cfg.get("policy"));
        if (pol == null) pol = new LinkedHashMap<>();
        List<String> mr = AttestCommon.asStrList(pol.get("mrtds"));
        if (mr == null || mr.isEmpty()) {
            throw new AttestException("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)");
        }
        List<String> mrtds = AttestCommon.lowerAll(mr);
        for (String m : mrtds) if (!hex96(m)) throw new AttestException("createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)");
        QuotePolicy qp = new QuotePolicy();
        qp.mrtds = mrtds;
        for (String name : new String[] {"mrSeams", "mrSignerSeams"}) {
            if (!pol.containsKey(name)) continue;
            List<String> list = AttestCommon.asStrList(pol.get(name));
            if (list == null || list.isEmpty()) throw new AttestException("createIntelDcapVerifier: policy." + name + ", if given, must be a NON-EMPTY list");
            for (String m : list) if (!hex96(m)) throw new AttestException("createIntelDcapVerifier: every " + name + " entry must be 96 hex chars (48 bytes)");
            if (name.equals("mrSeams")) {
                qp.mrSeams = AttestCommon.lowerAll(list);
                qp.hasMrSeams = true;
            } else {
                qp.mrSignerSeams = AttestCommon.lowerAll(list);
                qp.hasMrSigner = true;
            }
        }
        List<String> l = AttestCommon.asStrList(pol.get("fmspcs"));
        if (l != null) qp.fmspcs = AttestCommon.lowerAll(l);
        l = AttestCommon.asStrList(pol.get("rtmrs"));
        if (l != null) qp.rtmrs = AttestCommon.lowerAll(l);
        qp.allowDebug = Boolean.TRUE.equals(pol.get("allowDebug"));
        String pin = SGX_ROOT_CA_SPKI_SHA256;
        Object p = cfg.get("trustAnchorRootCaSpkiSha256");
        if (p instanceof String) pin = ((String) p).toLowerCase(Locale.ROOT);
        boolean allowMissing = Boolean.TRUE.equals(cfg.get("allowMissingCollateral"));
        AttestIntelCollateral.Policy cp = null;
        Map<String, Object> cpw = AttestCommon.asRec(pol.get("collateral"));
        if (cpw != null) {
            cp = new AttestIntelCollateral.Policy();
            List<String> acc = AttestCommon.asStrList(cpw.get("acceptStatuses"));
            if (acc != null) {
                cp.acceptStatuses = acc;
                cp.hasAccept = true;
            }
            Double f = AttestCommon.asFinite(cpw.get("minTcbEvaluationDataNumber"));
            if (f != null) {
                cp.minEval = f;
                cp.hasMinEval = true;
            }
        }
        return new AttestIntel(binding, qp, pin, allowMissing, cp);
    }

    @Override
    public HardwareResult verify(Map<String, Object> ev, AttestationBinding expected, long nowMs) {
        byte[] quote = AttestAmd.evBytes(ev, "quote");
        if (ev == null || quote == null) return HardwareResult.fail("no Intel DCAP quote for this action");
        if (expected == null) return HardwareResult.fail("no expected attestation binding supplied");
        TdxResult q = verifyGenuineTdxQuote(quote, pin, nowMs, pol, false);
        if (!q.ok) return HardwareResult.fail("DCAP quote invalid: " + q.reason);
        if (binding.equals("report-data")) {
            byte[] want;
            try {
                want = AttestCommon.attestationBindingBytes(expected);
            } catch (AttestException e) {
                return HardwareResult.fail("binding not constructible: " + e.getMessage());
            }
            if (!AttestCommon.timingSafeEq(q.reportData, want)) return HardwareResult.fail("report_data does not bind holder/grant/epoch/nonce");
        } else {
            byte[] rd = AttestAmd.evBytes(ev, "runtimeData");
            if (rd == null) return HardwareResult.fail("azure-runtime-data binding needs the runtime-data JSON bytes");
            String why = AttestCommon.checkAzureRuntimeDataBinding(q.reportData, rd, expected);
            if (!why.isEmpty()) return HardwareResult.fail(why);
        }
        Map<String, String> host = new LinkedHashMap<>();
        host.put("attestation_type", "tdx-dcap");
        host.put("fmspc", q.fmspc);
        Map<String, Object> col = AttestCommon.asRec(ev.get("collateral"));
        if (col != null) {
            AttestIntelCollateral.Result res = AttestIntelCollateral.verifyIntelTdxCollateral(quote, AttestIntelCollateral.fromWire(col), nowMs,
                collateralPol, pin, pol.allowDebug);
            if (!res.status.isEmpty()) host.put("tcb_status", res.status);
            if (!res.advisoryIds.isEmpty()) host.put("advisory_ids", String.join(",", res.advisoryIds));
            if (!res.ok) return HardwareResult.fail("Intel collateral: " + (res.reason.isEmpty() ? "rejected" : res.reason));
        } else if (allowMissing) {
            host.put("tcb_status", "unevaluated");
        } else {
            return HardwareResult.fail("Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)");
        }
        return HardwareResult.ok(true, HardwareResult.newMeasured(AttestCommon.toHexLower(q.mrTd), ""), host);
    }
}
