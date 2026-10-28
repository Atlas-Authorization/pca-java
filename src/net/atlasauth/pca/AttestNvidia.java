package net.atlasauth.pca;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * NVIDIA GPU confidential-computing attestation (Hopper / Blackwell): the SPDM 1.1 GET_MEASUREMENTS transcript signed by the
 * GPU's device-identity key, the device certificate chain pinned to the NVIDIA Device Identity CA, the PCA challenge bound
 * through the SPDM request nonce, pinned measurement blocks, and the optional collateral hook (signed RIMs, CRLs, OCSP and a
 * firmware policy: {@link AttestNvidiaRim}, {@link AttestNvidiaOcsp}). Same checks, order and reason text as the reference
 * verifier. Classical (ECDSA-P384 / SHA-384); no network I/O. Port of the Go attest_nvidia.go.
 */
public final class AttestNvidia implements VendorImpl {
    static final int SPDM_REQ_LEN = 37;
    static final int SPDM_NONCE_LEN = 32;
    static final int SPDM_SIG_LEN = 96;
    static final int NVIDIA_MAX_CHAIN = 5;

    static final int OPAQUE_DRIVER_VERSION = 3;
    static final int OPAQUE_VBIOS_VERSION = 6;
    static final int OPAQUE_CHIP_INFO = 35;

    /** One measurement block: its index and DMTF value. */
    static final class Measurement {
        final int index;
        final byte[] digest;

        Measurement(int index, byte[] digest) {
            this.index = index;
            this.digest = digest;
        }
    }

    /** A parsed request||response transcript. */
    static final class SpdmReport {
        int requestVersion;
        int responseVersion;
        byte[] requestNonce;
        final List<Measurement> measurements = new ArrayList<>();
        final Map<Integer, byte[]> opaque = new HashMap<>();
        byte[] signature;
        byte[] signedBytes;
    }

    private static int u8(byte[] b, int o) { return b[o] & 0xff; }

    private static int le16(byte[] b, int o) { return u8(b, o) | (u8(b, o + 1) << 8); }

    /** null when the request version is >= 0x11 and the response echoes it, else the refusal reason. */
    static String spdmVersionReason(SpdmReport r) {
        if (r.requestVersion >= 0x11 && r.responseVersion == r.requestVersion) return null;
        return "SPDM version 0x" + Integer.toHexString(r.requestVersion) + "/0x" + Integer.toHexString(r.responseVersion)
            + " is not an accepted GET_MEASUREMENTS version";
    }

    /** parseNvidiaSpdmEvidence: AttestException on any structural problem. */
    static SpdmReport parseSpdmEvidence(byte[] b) {
        if (b.length < SPDM_REQ_LEN + 8 + SPDM_NONCE_LEN + 2 + SPDM_SIG_LEN) {
            throw new AttestException("parseNvidiaSpdmEvidence: transcript too short (" + b.length + ")");
        }
        if (u8(b, 1) != 0xe0) {
            throw new AttestException("parseNvidiaSpdmEvidence: request code 0x" + Integer.toHexString(u8(b, 1)) + " is not GET_MEASUREMENTS");
        }
        SpdmReport rep = new SpdmReport();
        rep.requestVersion = u8(b, 0);
        rep.requestNonce = Arrays.copyOfRange(b, 4, 4 + SPDM_NONCE_LEN);
        byte[] r = Arrays.copyOfRange(b, SPDM_REQ_LEN, b.length);
        if (u8(r, 1) != 0x60) throw new AttestException("parseNvidiaSpdmEvidence: response code is not MEASUREMENTS");
        rep.responseVersion = u8(r, 0);
        int numBlocks = u8(r, 4);
        int recLen = u8(r, 5) | (u8(r, 6) << 8) | (u8(r, 7) << 16);
        int o = 8;
        if ((long) o + recLen + SPDM_NONCE_LEN + 2 + SPDM_SIG_LEN > r.length) {
            throw new AttestException("parseNvidiaSpdmEvidence: measurement record length overruns transcript");
        }
        int recEnd = o + recLen;
        while (o < recEnd) {
            if (o + 4 > recEnd) throw new AttestException("parseNvidiaSpdmEvidence: truncated measurement block header");
            int index = u8(r, o);
            int size = le16(r, o + 2);
            int bodyStart = o + 4;
            if (bodyStart + size > recEnd || size < 3) throw new AttestException("parseNvidiaSpdmEvidence: measurement block overruns record");
            int vsize = le16(r, bodyStart + 1);
            if (3 + vsize > size) throw new AttestException("parseNvidiaSpdmEvidence: DMTF value overruns measurement block");
            rep.measurements.add(new Measurement(index, Arrays.copyOfRange(r, bodyStart + 3, bodyStart + 3 + vsize)));
            o = bodyStart + size;
        }
        if (rep.measurements.size() != numBlocks) {
            throw new AttestException("parseNvidiaSpdmEvidence: header says " + numBlocks + " blocks, parsed " + rep.measurements.size());
        }
        o += SPDM_NONCE_LEN;
        int opaqueLen = le16(r, o);
        o += 2;
        if (o + opaqueLen + SPDM_SIG_LEN != r.length) {
            throw new AttestException("parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript");
        }
        int opaqueEnd = o + opaqueLen;
        while (o < opaqueEnd) {
            if (o + 4 > opaqueEnd) throw new AttestException("parseNvidiaSpdmEvidence: truncated opaque TLV header");
            int t = le16(r, o);
            int l = le16(r, o + 2);
            o += 4;
            if (o + l > opaqueEnd) throw new AttestException("parseNvidiaSpdmEvidence: opaque TLV overruns opaque data");
            rep.opaque.put(t, Arrays.copyOfRange(r, o, o + l));
            o += l;
        }
        rep.signature = Arrays.copyOfRange(r, r.length - SPDM_SIG_LEN, r.length);
        rep.signedBytes = Arrays.copyOfRange(b, 0, b.length - SPDM_SIG_LEN);
        return rep;
    }

    /** String.prototype.slice for an ASCII string (negative indices count from the end). */
    static String jsSlice(String s, int from, int to) {
        int n = s.length();
        int a = from < 0 ? Math.max(0, from + n) : Math.min(from, n);
        int z = to < 0 ? Math.max(0, to + n) : Math.min(to, n);
        return a >= z ? "" : s.substring(a, z);
    }

    /** NVIDIA's VBIOS version rendering: byte-reverse, re-pair as dotted hex ("96.00.9f.00.04"). */
    static String formatVbiosVersion(byte[] raw) {
        byte[] rev = new byte[raw.length];
        for (int i = 0; i < raw.length; i++) rev[raw.length - 1 - i] = raw[i];
        String hx = AttestCommon.toHexLower(rev);
        int half = hx.length() / 2;
        String temp = jsSlice(hx, half, hx.length()) + jsSlice(hx, half - 2, half);
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < temp.length(); i += 2) parts.add(temp.substring(i, Math.min(i + 2, temp.length())));
        return String.join(".", parts);
    }

    /** Node's X509Certificate.ca: BasicConstraints CA:TRUE, and keyCertSign when keyUsage is present. */
    static boolean certIsCA(AttCert c) {
        AttestDer.CertRoleInfo info;
        try {
            info = AttestDer.readCertRoleInfo(c.raw);
        } catch (AttestException e) {
            return false;
        }
        return info.hasBasicConstraints && info.ca && (!info.hasKeyUsage || info.keyCertSign);
    }

    static String subjectLine(AttCert c) { return AttestCommon.nameText(c.rawSubject).replace("\n", ", "); }

    /** A verified chain (leaf first), or the failure reason. */
    static final class Chain {
        final List<AttCert> certs;
        final String reason;

        Chain(List<AttCert> certs, String reason) {
            this.certs = certs;
            this.reason = reason;
        }
    }

    private static Chain chainFail(String reason) { return new Chain(null, reason); }

    /**
     * verifyNvidiaDeviceChain (leaf first): every link signed, every issuer a CA, every certificate valid at nowMs, an ECDSA
     * P-384 key throughout, the root self-signed and pinned by SPKI SHA-256.
     */
    static Chain verifyDeviceChain(String pemText, List<String> pins, long nowMs) {
        List<String> blocks = AttestCommon.pemCertBlocks(pemText);
        if (blocks.isEmpty()) return chainFail("device chain unparseable: parsePemChain: no certificates found");
        if (blocks.size() > NVIDIA_MAX_CHAIN) return chainFail("device chain unparseable: parsePemChain: chain longer than " + NVIDIA_MAX_CHAIN);
        List<AttCert> chain = new ArrayList<>();
        for (String b : blocks) {
            try {
                chain.add(AttestCert.certFromPem(b));
            } catch (AttestException e) {
                return chainFail("device chain unparseable: " + AttestCommon.errMsg(e));
            }
        }
        for (int i = 0; i < chain.size(); i++) {
            AttCert c = chain.get(i);
            if (!AttestDer.derValidAt(c.raw, nowMs, 0)) return chainFail("device chain cert #" + i + " is outside its validity window");
            CertKey k;
            try {
                k = AttestCert.keyOfCert(c);
            } catch (AttestException e) {
                k = null;
            }
            if (k == null || !k.typ.equals("ec") || !k.curve.equals("secp384r1")) {
                return chainFail("device chain cert #" + i + " is not an ECDSA P-384 key");
            }
        }
        for (int i = 0; i < chain.size() - 1; i++) {
            AttCert issuer = chain.get(i + 1);
            if (!certIsCA(issuer)) return chainFail("device chain cert #" + (i + 1) + " issues a certificate but is not a CA");
            if (!AttestCert.certSigOkBy(chain.get(i), issuer)) return chainFail("device chain link #" + i + " signature does not verify under its issuer");
        }
        AttCert root = chain.get(chain.size() - 1);
        if (!certIsCA(root) || !AttestCert.certSigOkBy(root, root)) return chainFail("device chain root is not a self-signed CA");
        String spki;
        try {
            spki = AttestCert.keyOfCert(root).spkiSha256();
        } catch (AttestException e) {
            return chainFail("device chain root is not a self-signed CA");
        }
        boolean pinned = false;
        for (String p : pins) if (p.toLowerCase(Locale.ROOT).equals(spki)) pinned = true;
        if (!pinned) return chainFail("chain root is not a pinned NVIDIA root");
        return new Chain(chain, "");
    }

    // ------------------------------------------------------------- JavaScript Number() / String() for configuration values

    private static final Pattern JS_DECIMAL = Pattern.compile("[+-]?(?:[0-9]+\\.?[0-9]*|\\.[0-9]+)(?:[eE][+-]?[0-9]+)?");

    /** Number(s) for a string (NaN when it is not a number). */
    static double jsNumber(String s) {
        String t = AttestCommon.jsTrim(s);
        if (t.isEmpty()) return 0;
        if (t.equals("Infinity") || t.equals("+Infinity")) return Double.POSITIVE_INFINITY;
        if (t.equals("-Infinity")) return Double.NEGATIVE_INFINITY;
        if (t.length() > 2 && t.charAt(0) == '0') {
            char p = Character.toLowerCase(t.charAt(1));
            int radix = p == 'x' ? 16 : p == 'o' ? 8 : p == 'b' ? 2 : 0;
            if (radix != 0) {
                try {
                    return new BigInteger(t.substring(2), radix).doubleValue();
                } catch (NumberFormatException e) {
                    return Double.NaN;
                }
            }
        }
        if (!JS_DECIMAL.matcher(t).matches()) return Double.NaN;
        return Double.parseDouble(t);
    }

    static boolean isJsInteger(double f) { return !Double.isNaN(f) && !Double.isInfinite(f) && f == Math.floor(f); }

    /** String(v) for a JSON value. */
    @SuppressWarnings("unchecked")
    static String jsString(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double f = AttestCommon.asFinite(v);
        if (f != null) return AttestCommon.jsNumString(f);
        if (v instanceof Map) return "[object Object]";
        if (v instanceof List) {
            List<String> parts = new ArrayList<>();
            for (Object x : (List<Object>) v) parts.add(x == null ? "" : jsString(x));
            return String.join(",", parts);
        }
        return String.valueOf(v);
    }

    /** A canonical array-index key ("0", "1", ... no leading zeros), which Object.entries lists first, in numeric order. */
    private static boolean isArrayIndexKey(String k) {
        if (k.isEmpty() || k.length() > 10) return false;
        for (int i = 0; i < k.length(); i++) if (k.charAt(i) < '0' || k.charAt(i) > '9') return false;
        if (k.length() > 1 && k.charAt(0) == '0') return false;
        return Long.parseLong(k) < 4294967295L;
    }

    // ------------------------------------------------------------- the verifier

    private final List<String> pins;
    private final List<Integer> wantIndex = new ArrayList<>();
    private final List<String> wantDigest = new ArrayList<>();
    private final String leafSub;
    private final AttestNvidiaRim.Hook hook;

    private AttestNvidia(List<String> pins, String leafSub, AttestNvidiaRim.Hook hook) {
        this.pins = pins;
        this.leafSub = leafSub;
        this.hook = hook;
    }

    /** createNvidiaSpdmVerifier from the language-neutral configuration; AttestException for a refused configuration. */
    static VendorImpl create(Map<String, Object> cfg) {
        AttestNvidiaRim.Hook hook = null;
        Map<String, Object> col = AttestCommon.asRec(cfg.get("collateral"));
        if (col != null) hook = AttestNvidiaRim.Hook.create(col);
        List<String> pins = AttestCommon.asStrList(cfg.get("rootSpkiSha256"));
        if (pins == null || pins.isEmpty()) {
            throw new AttestException("createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)");
        }
        Map<String, Object> pol = AttestCommon.asRec(cfg.get("policy"));
        Map<String, Object> meas = pol == null ? null : AttestCommon.asRec(pol.get("measurements"));
        if ((meas == null || meas.isEmpty()) && hook == null) {
            throw new AttestException("createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)");
        }
        String leafSub = pol != null && pol.get("leafSubjectIncludes") instanceof String ? (String) pol.get("leafSubjectIncludes") : "";
        AttestNvidia v = new AttestNvidia(pins, leafSub, hook);
        if (meas != null) {
            // Object.entries order: array-index keys ascending, then the other keys in insertion order
            List<String> keys = new ArrayList<>();
            List<String> rest = new ArrayList<>();
            for (String k : meas.keySet()) (isArrayIndexKey(k) ? keys : rest).add(k);
            keys.sort((a, b) -> Long.compare(Long.parseLong(a), Long.parseLong(b)));
            keys.addAll(rest);
            for (String k : keys) {
                double idx = jsNumber(k);
                if (!isJsInteger(idx) || idx < 0 || idx > 255) throw new AttestException("createNvidiaSpdmVerifier: measurement index out of range");
                v.wantIndex.add((int) idx);
                v.wantDigest.add(jsString(meas.get(k)).toLowerCase(Locale.ROOT));
            }
        }
        return v;
    }

    @Override
    public HardwareResult verify(Map<String, Object> ev, AttestationBinding expected, long nowMs) {
        if (ev == null || !(ev.get("evidence") instanceof String) || !(ev.get("certChainPem") instanceof String)) {
            return HardwareResult.fail("no NVIDIA GPU evidence for this action");
        }
        byte[] evidence = AttestCommon.nodeB64((String) ev.get("evidence"));
        Chain chain = verifyDeviceChain((String) ev.get("certChainPem"), pins, nowMs);
        if (chain.certs == null) return HardwareResult.fail(chain.reason);
        AttCert leaf = chain.certs.get(0);
        if (!leafSub.isEmpty() && !AttestCommon.nameText(leaf.rawSubject).contains(leafSub)) {
            return HardwareResult.fail("device leaf subject does not contain '" + leafSub + "'");
        }
        SpdmReport rep;
        try {
            rep = parseSpdmEvidence(evidence);
        } catch (AttestException e) {
            return HardwareResult.fail("GPU attestation report parse failed: " + AttestCommon.errMsg(e));
        }
        // SPDM 1.1+ is the first version with the signed GET_MEASUREMENTS layout parsed here; request and response must agree
        String versionWhy = spdmVersionReason(rep);
        if (versionWhy != null) return HardwareResult.fail(versionWhy);
        boolean sigOk;
        try {
            CertKey lk = AttestCert.keyOfCert(leaf);
            sigOk = lk.pub instanceof ECPublicKey
                && AttestCommon.verifyRawECDSA((ECPublicKey) lk.pub, AttestCommon.sha384Sum(rep.signedBytes), rep.signature);
        } catch (AttestException e) {
            sigOk = false;
        }
        if (!sigOk) return HardwareResult.fail("GPU attestation report signature does not verify under the device identity key");
        if (expected == null) return HardwareResult.fail("no expected attestation binding supplied");
        byte[] raw;
        try {
            raw = AttestCommon.attestationBindingBytes(expected);
        } catch (AttestException e) {
            return HardwareResult.fail("binding not constructible: " + AttestCommon.errMsg(e));
        }
        if (!Arrays.equals(rep.requestNonce, AttestCommon.sha256Sum(raw))) {
            return HardwareResult.fail("SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)");
        }
        Map<Integer, Measurement> byIndex = new HashMap<>();
        for (Measurement m : rep.measurements) byIndex.put(m.index, m);
        for (int i = 0; i < wantIndex.size(); i++) {
            int idx = wantIndex.get(i);
            Measurement m = byIndex.get(idx);
            if (m == null) return HardwareResult.fail("measurement block " + idx + " missing from report");
            if (!AttestCommon.toHexLower(m.digest).equals(wantDigest.get(i))) {
                return HardwareResult.fail("measurement block " + idx + " does not match the pinned digest");
            }
        }
        if (hook != null) {
            String why = hook.withBundle(AttestCommon.asRec(ev.get("collateral"))).run(rep, chain.certs, nowMs);
            if (!why.isEmpty()) return HardwareResult.fail(why);
        }
        List<Measurement> sorted = new ArrayList<>(rep.measurements);
        sorted.sort((a, b) -> Integer.compare(a.index, b.index)); // List.sort is stable
        java.io.ByteArrayOutputStream all = new java.io.ByteArrayOutputStream();
        for (Measurement m : sorted) all.write(m.digest, 0, m.digest.length);
        Map<String, String> host = new LinkedHashMap<>();
        host.put("attestation_type", "nvidia-gpu-cc");
        host.put("gpu_measurements_sha384", AttestCommon.toHexLower(AttestCommon.sha384Sum(all.toByteArray())));
        host.put("leaf_subject", subjectLine(leaf));
        byte[] drv = rep.opaque.get(OPAQUE_DRIVER_VERSION);
        if (drv != null) host.put("driver_version", stripTrailingNul(new String(drv, StandardCharsets.UTF_8)));
        byte[] vb = rep.opaque.get(OPAQUE_VBIOS_VERSION);
        if (vb != null) host.put("vbios_version", formatVbiosVersion(vb));
        return HardwareResult.ok(true, HardwareResult.newMeasured("", ""), host);
    }

    static String stripTrailingNul(String s) {
        int e = s.length();
        while (e > 0 && s.charAt(e - 1) == '\0') e--;
        return s.substring(0, e);
    }
}
