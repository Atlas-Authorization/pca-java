package net.atlasauth.pca;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;

/**
 * AMD SEV-SNP evidence helpers: the 1184-byte ATTESTATION_REPORT parser (all integers little-endian), the ECDSA P-384 / SHA-384 report
 * signature over bytes [0, 0x2a0), the VCEK certificate helpers and the CHIP_ID / reported-TCB binding, the acceptance policy gate, the
 * default identity derivation, the KDS VCEK fetch over an injected transport, and the end-to-end genuine-report check. Classical
 * cryptography only: nothing here makes a SEV-SNP attestation post-quantum, which is why {@link Attestation#createMultiRootVerifier}
 * exists. The parser verifies nothing; call {@link #verifySevSnpReportSignature} and the chain checks for that.
 */
public final class HardwareSevSnp {
    private HardwareSevSnp() {}

    /** The SIGNATURE_ALGO value for ECDSA over P-384 with SHA-384 (the only algorithm SEV-SNP uses). */
    public static final int SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384 = 1;
    /** Guest POLICY bit 19: DEBUG (the host may read and modify guest memory, so there is no confidentiality). */
    public static final BigInteger SEV_SNP_POLICY_DEBUG_BIT = BigInteger.ONE.shiftLeft(19);
    /** The SHA-384 (lowercase hex) of the DER SubjectPublicKeyInfo of AMD's Milan ARK: the root the chain is pinned to. */
    public static final String AMD_MILAN_ARK_SPKI_SHA384 = AttestAmd.ARK_SPKI_SHA384.get("milan");

    private static final int OFF_SIG_S = 0x2e8;
    private static final int REPORT_LEN = 0x4a0;
    private static final X9ECParameters P384 = ECNamedCurveTable.getByName("P-384");

    /** An SNP firmware version as AMD defines it. */
    public static final class FirmwareVersion {
        public final int major, minor, build;

        FirmwareVersion(int major, int minor, int build) { this.major = major; this.minor = minor; this.build = build; }
    }

    /** A fully parsed {@code ATTESTATION_REPORT}. Byte arrays are fresh copies; 32-bit fields are unsigned values in a long. */
    public static final class ParsedReport {
        public final long version, guestSvn, vmpl, signatureAlgo;
        public final BigInteger policy, currentTcb, platformInfo, reportedTcb, committedTcb, launchTcb, launchMitVector, currentMitVector;
        public final byte[] familyId, imageId, reportData, measurement, hostData, idKeyDigest, authorKeyDigest, reportId, reportIdMa, chipId;
        /** CPUID family, model and stepping (report version 3 and later; 0 before). */
        public final int cpuidFamId, cpuidModId, cpuidStep;
        public final FirmwareVersion currentVersion, committedVersion;
        /** AMD's little-endian r and s, each the 72-byte field exactly as it sits in the report. */
        public final byte[] signatureR, signatureS;
        /** The signed region, report bytes [0, 0x2a0). */
        public final byte[] signed;
        /** The full report bytes. */
        public final byte[] raw;

        private ParsedReport(byte[] b) {
            version = AttestAmd.le32(b, 0x000);
            guestSvn = AttestAmd.le32(b, 0x004);
            policy = AttestAmd.u64(AttestAmd.le64(b, 0x008));
            familyId = Arrays.copyOfRange(b, 0x010, 0x020);
            imageId = Arrays.copyOfRange(b, 0x020, 0x030);
            vmpl = AttestAmd.le32(b, 0x030);
            signatureAlgo = AttestAmd.le32(b, 0x034);
            currentTcb = AttestAmd.u64(AttestAmd.le64(b, 0x038));
            platformInfo = AttestAmd.u64(AttestAmd.le64(b, 0x040));
            reportData = Arrays.copyOfRange(b, 0x050, 0x090);
            measurement = Arrays.copyOfRange(b, 0x090, 0x0c0);
            hostData = Arrays.copyOfRange(b, 0x0c0, 0x0e0);
            idKeyDigest = Arrays.copyOfRange(b, 0x0e0, 0x110);
            authorKeyDigest = Arrays.copyOfRange(b, 0x110, 0x140);
            reportId = Arrays.copyOfRange(b, 0x140, 0x160);
            reportIdMa = Arrays.copyOfRange(b, 0x160, 0x180);
            reportedTcb = AttestAmd.u64(AttestAmd.le64(b, 0x180));
            cpuidFamId = b[0x188] & 0xff;
            cpuidModId = b[0x189] & 0xff;
            cpuidStep = b[0x18a] & 0xff;
            chipId = Arrays.copyOfRange(b, 0x1a0, 0x1e0);
            committedTcb = AttestAmd.u64(AttestAmd.le64(b, 0x1e0));
            currentVersion = new FirmwareVersion(b[0x1ea] & 0xff, b[0x1e9] & 0xff, b[0x1e8] & 0xff);
            committedVersion = new FirmwareVersion(b[0x1ee] & 0xff, b[0x1ed] & 0xff, b[0x1ec] & 0xff);
            launchTcb = AttestAmd.u64(AttestAmd.le64(b, 0x1f0));
            launchMitVector = AttestAmd.u64(AttestAmd.le64(b, 0x1f8));
            currentMitVector = AttestAmd.u64(AttestAmd.le64(b, 0x200));
            signatureR = Arrays.copyOfRange(b, 0x2a0, 0x2a0 + 72);
            signatureS = Arrays.copyOfRange(b, OFF_SIG_S, OFF_SIG_S + 72);
            signed = Arrays.copyOfRange(b, 0, 0x2a0);
            raw = b.clone();
        }
    }

    /** Lowercase hex of {@code bytes} (the identity text of a measurement, chip id or host data). */
    public static String toHex(byte[] bytes) { return AttestCommon.toHexLower(bytes); }

    /** Parse the report layout. Throws when the buffer cannot hold the signed region and the r and s fields (816 bytes). */
    public static ParsedReport parseSevSnpReport(byte[] bytes) {
        int min = OFF_SIG_S + 72;
        if (bytes.length < min) throw new IllegalArgumentException("parseSevSnpReport: report too short (" + bytes.length + " < " + min + ")");
        return new ParsedReport(bytes);
    }

    /** A validated P-384 public key as its uncompressed SEC1 point ({@code 04 || X(48) || Y(48)}). */
    public static final class EcdsaP384PublicKey {
        /** The 97-byte uncompressed SEC1 point. */
        public final byte[] point;
        final ECPublicKey key;

        private EcdsaP384PublicKey(byte[] point, ECPublicKey key) { this.point = point; this.key = key; }
    }

    /**
     * Validate a P-384 public key given as an uncompressed (97-byte) or compressed (49-byte) SEC1 point; normalized to uncompressed.
     * Throws when the bytes are not a point of the curve (a hybrid form, an off-curve point and an out-of-field coordinate included).
     */
    public static EcdsaP384PublicKey ecdsaP384PublicKey(byte[] sec1) {
        int n = sec1.length;
        boolean compressed = n == 49 && (sec1[0] == 0x02 || sec1[0] == 0x03), uncompressed = n == 97 && sec1[0] == 0x04;
        if (!compressed && !uncompressed) throw new IllegalArgumentException("invalid Point, expected length of 49, or uncompressed 97, got " + n);
        byte[] point = P384.getCurve().decodePoint(sec1).normalize().getEncoded(false); // throws on an off-curve or malformed point
        ECPublicKey key = AttestCommon.pointToKey("P-384", point);
        if (key == null) throw new IllegalArgumentException("bad point: not on the P-384 curve");
        return new EcdsaP384PublicKey(point, key);
    }

    private static BigInteger leToBigInt(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) be[le.length - 1 - i] = le[i];
        return new BigInteger(1, be);
    }

    private static void put48(BigInteger v, byte[] dst, int off) {
        byte[] b = v.toByteArray();
        int skip = Math.max(0, b.length - 48);
        System.arraycopy(b, skip, dst, off + 48 - (b.length - skip), b.length - skip);
    }

    /**
     * AMD's little-endian r and s (72-byte fields) as the big-endian compact form (r || s, 96 bytes). The scalars occupy the low 48 bytes
     * and any value outside [1, n) throws, a non-zero byte above the low 48 included.
     */
    public static byte[] sevSnpSignatureToCompact(byte[] r, byte[] s) {
        BigInteger n = P384.getN(), rv = leToBigInt(r), sv = leToBigInt(s);
        if (rv.signum() <= 0 || rv.compareTo(n) >= 0) throw new IllegalArgumentException("sev-snp signature: r out of range");
        if (sv.signum() <= 0 || sv.compareTo(n) >= 0) throw new IllegalArgumentException("sev-snp signature: s out of range");
        byte[] out = new byte[96];
        put48(rv, out, 0);
        put48(sv, out, 48);
        return out;
    }

    /**
     * Verify the report's ECDSA P-384 / SHA-384 signature over its signed region under the VCEK key. High-S signatures are accepted (AMD
     * does not normalize them). Never throws: a malformed signature is false.
     */
    public static boolean verifySevSnpReportSignature(ParsedReport report, EcdsaP384PublicKey vcek) {
        try {
            return AttestCommon.verifyRawECDSA(vcek.key, AttestCommon.sha384Sum(report.signed), sevSnpSignatureToCompact(report.signatureR, report.signatureS));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Bind the VCEK certificate body (its {@code tbsCertificate}) to the report: its hwID extension must equal the report's chip id and its
     * four SPL extensions must equal bytes 0 (bootloader), 1 (tee), 6 (snp) and 7 (microcode) of the reported TCB. Without it a genuine
     * but OLD VCEK could vouch for a report claiming a new TCB, or one chip's VCEK for another's report. The failure reason, or null.
     */
    public static String checkVcekReportBinding(byte[] vcekTbs, ParsedReport report) {
        AttestAmd.SnpReport r = new AttestAmd.SnpReport();
        r.chipId = report.chipId;
        r.reportedTcb = report.reportedTcb.longValue(); // the low 64 bits: the u64 as it sits in the report
        String why = AttestAmd.checkVcekReportBinding(vcekTbs, r);
        return why.isEmpty() ? null : why;
    }

    /** The {@code tbsCertificate} TLV of a DER certificate. Throws on a non-SEQUENCE, trailing bytes, or a first element that is not a SEQUENCE. */
    public static byte[] extractTbsCertificate(byte[] certDer) { return AttestDer.tbsOfCertificate(certDer); }

    /** A VCEK certificate's key and its {@code tbsCertificate}. */
    public static final class VcekKey {
        public final EcdsaP384PublicKey key;
        public final byte[] tbs;

        VcekKey(EcdsaP384PublicKey key, byte[] tbs) { this.key = key; this.tbs = tbs; }
    }

    private static EcdsaP384PublicKey keyOf(ECPublicKey k) {
        byte[] p = new byte[97];
        p[0] = 0x04;
        put48(k.getW().getAffineX(), p, 1);
        put48(k.getW().getAffineY(), p, 49);
        return ecdsaP384PublicKey(p);
    }

    /** Decode a VCEK certificate (DER): its EC P-384 key (any other key throws) and its {@code tbsCertificate}. */
    public static VcekKey extractVcekPublicKey(byte[] vcekDer) {
        CertKey vk = AttestCert.keyOfCert(AttestCert.parseCertDer(vcekDer));
        if (!"ec".equals(vk.typ) || !"secp384r1".equals(vk.curve)) {
            throw new IllegalArgumentException("VCEK is not EC secp384r1 (got " + vk.typ + "/" + (vk.curve.isEmpty() ? "undefined" : vk.curve) + ")");
        }
        return new VcekKey(ecdsaP384PublicKey(AttestCommon.ecPointOfKey(vk, "P-384")), extractTbsCertificate(vcekDer));
    }

    /** Split a PEM bundle into its {@code -----BEGIN CERTIFICATE-----} blocks, text unchanged. */
    public static List<String> splitPemCertificates(String pem) { return AttestCommon.pemCertBlocks(pem); }

    /** The outcome of {@link #verifyAmdCertChain}. */
    public static final class AmdChainResult {
        public final boolean ok;
        public final String reason;
        /** The VCEK key (present iff the chain verified). */
        public final EcdsaP384PublicKey vcek;
        /** The VCEK certificate's {@code tbsCertificate} (present iff the chain verified). */
        public final byte[] vcekTbs;

        AmdChainResult(boolean ok, String reason, EcdsaP384PublicKey vcek, byte[] vcekTbs) { this.ok = ok; this.reason = reason; this.vcek = vcek; this.vcekTbs = vcekTbs; }
    }

    /**
     * Verify the AMD chain VCEK to ASK to ARK: the VCEK signed by the ASK, the ASK by the ARK, and the ARK self-signed and equal to the
     * pinned anchor ({@code trustAnchorArkSpkiSha384}; null is Milan's), never taken from the supplied chain; CA roles, critical extensions
     * and every validity window at {@code nowMs} (with {@code clockSkewMs}, null is 0). {@code askArkPem} is the ASK then ARK bundle.
     * Never throws: every broken link is a reason.
     */
    public static AmdChainResult verifyAmdCertChain(byte[] vcekDer, String askArkPem, String trustAnchorArkSpkiSha384, double nowMs, Double clockSkewMs) {
        try {
            if (Double.isNaN(nowMs) || Double.isInfinite(nowMs)) return chainFail("nowMs (verifier clock) is required for the AMD chain validity check");
            AttestAmd.ChainResult c = AttestAmd.verifyAmdCertChain(vcekDer, askArkPem, trustAnchorArkSpkiSha384 == null ? AMD_MILAN_ARK_SPKI_SHA384 : trustAnchorArkSpkiSha384,
                (long) nowMs, clockSkewMs);
            if (!c.reason.isEmpty()) return chainFail(c.reason);
            return new AmdChainResult(true, null, keyOf(c.key), c.tbs);
        } catch (RuntimeException e) {
            return chainFail("AMD chain verification error: " + (e.getMessage() == null ? "unknown" : e.getMessage()));
        }
    }

    private static AmdChainResult chainFail(String why) { return new AmdChainResult(false, why, null, null); }

    // ---- KDS fetch ----

    /** The injected transport of {@link #fetchVcekFromKds}: a GET that answers the HTTP status and the body. */
    @FunctionalInterface
    public interface Fetch {
        Response get(String url) throws Exception;
    }

    /** An HTTP answer. */
    public static final class Response {
        public final int status;
        public final byte[] body;

        public Response(int status, byte[] body) { this.status = status; this.body = body; }
    }

    /** A transport over the JDK HTTP client (network I/O: pass it explicitly to {@link #fetchVcekFromKds}). */
    public static Fetch httpFetch() {
        HttpClient client = HttpClient.newHttpClient();
        return url -> {
            HttpResponse<byte[]> r = client.send(HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofByteArray());
            return new Response(r.statusCode(), r.body());
        };
    }

    /**
     * Fetch the VCEK certificate (DER) for a report from AMD's key distribution service, keyed by its CHIP_ID and the four SPL bytes of the
     * reported TCB: {@code <baseUrl>/<product>/<chip id hex>?blSPL=&teeSPL=&snpSPL=&ucodeSPL=}. {@code product} (null: Milan) and
     * {@code baseUrl} (null: {@code https://kdsintf.amd.com/vcek/v1}) are used as given. NETWORK I/O happens only through {@code fetch},
     * which is required; any non-2xx status throws.
     */
    public static byte[] fetchVcekFromKds(byte[] chipId, BigInteger reportedTcb, String product, String baseUrl, Fetch fetch) throws Exception {
        String p = product == null ? "Milan" : product, base = baseUrl == null ? "https://kdsintf.amd.com/vcek/v1" : baseUrl;
        if (fetch == null) throw new IllegalStateException("fetchVcekFromKds: no fetch implementation available");
        String q = "blSPL=" + spl(reportedTcb, 0) + "&teeSPL=" + spl(reportedTcb, 1) + "&snpSPL=" + spl(reportedTcb, 6) + "&ucodeSPL=" + spl(reportedTcb, 7);
        String url = base + "/" + p + "/" + toHex(chipId) + "?" + q;
        Response res = fetch.get(url);
        if (res.status < 200 || res.status > 299) throw new IllegalStateException("KDS VCEK fetch failed: HTTP " + res.status + " for " + url);
        return res.body;
    }

    private static int spl(BigInteger tcb, int index) { return tcb.shiftRight(8 * index).and(BigInteger.valueOf(0xff)).intValue(); }

    // ---- policy and identity ----

    /**
     * The default report to measured-identity mapping {@code {model_id: "", weights_digest, weights_measured: false, runtime_measurement,
     * operator}}: the runtime measurement is the hex launch measurement and the operator the hex chip id. SEV-SNP has no weights field; with
     * {@code weightsFromHostData} (INSECURE: HOST_DATA is asserted by the host) the weights digest is the hex host data, and it is still
     * never marked measured.
     */
    public static Function<ParsedReport, Map<String, Object>> makeDefaultDeriveIdentity(boolean weightsFromHostData) {
        return report -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("model_id", "");
            m.put("weights_digest", weightsFromHostData ? toHex(report.hostData) : "");
            m.put("weights_measured", false);
            m.put("runtime_measurement", toHex(report.measurement));
            m.put("operator", toHex(report.chipId));
            return m;
        };
    }

    private static List<String> lowered(Object list) {
        List<String> out = new ArrayList<>();
        for (Object x : (List<?>) list) {
            if (!(x instanceof String)) throw new IllegalArgumentException("x.toLowerCase is not a function");
            out.add(((String) x).toLowerCase(Locale.ROOT));
        }
        return out;
    }

    /**
     * Check a report against an acceptance policy; the reason of the first failure, else null. The policy is a map: {@code requireEcdsaP384}
     * (anything but false requires algorithm 1), {@code allowDebug} (only true admits a DEBUG guest), {@code minGuestSvn} (a number),
     * {@code minReportedTcb} / {@code minCommittedTcb} / {@code minLaunchTcb} (a BigInteger; any other type is ignored), {@code requireVmpl}
     * (a number, default 0, or "any"), and the lists {@code measurements}, {@code hostData}, {@code chipIds} (hex, compared lowercase; an
     * empty or absent list does not gate). Throws on a null policy or a non-string list element.
     */
    public static String checkSevSnpPolicy(ParsedReport report, Map<String, Object> policy) {
        if (policy == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'requireEcdsaP384')");
        if (!Boolean.FALSE.equals(policy.get("requireEcdsaP384")) && report.signatureAlgo != SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384) return "unexpected signature_algo " + report.signatureAlgo;
        if (!Boolean.TRUE.equals(policy.get("allowDebug")) && report.policy.and(SEV_SNP_POLICY_DEBUG_BIT).signum() != 0) return "guest policy has the DEBUG bit set (host can inspect the guest)";
        Double minSvn = IntentJs.num(policy.get("minGuestSvn"));
        if (minSvn != null && report.guestSvn < minSvn) return "guest_svn " + report.guestSvn + " below minimum " + AttestCommon.jsNumString(minSvn);
        if (policy.get("minReportedTcb") instanceof BigInteger && report.reportedTcb.compareTo((BigInteger) policy.get("minReportedTcb")) < 0) return "reported_tcb below minimum (rollback?)";
        if (policy.get("minCommittedTcb") instanceof BigInteger && report.committedTcb.compareTo((BigInteger) policy.get("minCommittedTcb")) < 0) return "committed_tcb below minimum (rollback?)";
        if (policy.get("minLaunchTcb") instanceof BigInteger && report.launchTcb.compareTo((BigInteger) policy.get("minLaunchTcb")) < 0) return "launch_tcb below minimum";
        Object want = policy.get("requireVmpl") == null ? Integer.valueOf(0) : policy.get("requireVmpl");
        if (!"any".equals(want)) {
            Double w = IntentJs.num(want);
            if (w == null || (double) report.vmpl != w) return "vmpl " + report.vmpl + " is not the required " + IntentRevocation.jsText(want, true);
        }
        if (policy.get("measurements") instanceof List && !((List<?>) policy.get("measurements")).isEmpty()
            && !lowered(policy.get("measurements")).contains(toHex(report.measurement))) return "measurement not in policy allowlist";
        if (policy.get("hostData") instanceof List && !((List<?>) policy.get("hostData")).isEmpty()
            && !lowered(policy.get("hostData")).contains(toHex(report.hostData))) return "host_data not in policy allowlist";
        if (policy.get("chipIds") instanceof List && !((List<?>) policy.get("chipIds")).isEmpty()
            && !lowered(policy.get("chipIds")).contains(toHex(report.chipId))) return "chip_id not in policy allowlist";
        return null;
    }

    // ---- genuine report ----

    /** The outcome of {@link #verifyGenuineSevSnpReport}. */
    public static final class GenuineReportResult {
        public final boolean ok;
        public final String reason;
        public final ParsedReport report;
        /** The identity {@link #makeDefaultDeriveIdentity} derives (present iff ok). */
        public final Map<String, Object> measured;

        GenuineReportResult(boolean ok, String reason, ParsedReport report, Map<String, Object> measured) { this.ok = ok; this.reason = reason; this.report = report; this.measured = measured; }
    }

    private static GenuineReportResult genuineFail(String why) { return new GenuineReportResult(false, why, null, null); }

    /**
     * Parse and verify a genuine report end to end, offline: the canonical 1184-byte layout with the reserved signature bytes zero; the chain
     * ({@link #verifyAmdCertChain}); the report signature under the chain-trusted VCEK; the VCEK to report binding; with {@code expected}, the
     * report data equal to {@link Attestation#attestationBinding}; with {@code policy}, the policy gate. Fails closed with a reason.
     */
    public static GenuineReportResult verifyGenuineSevSnpReport(byte[] reportBytes, byte[] vcekDer, String askArkPem, String trustAnchorArkSpkiSha384,
                                                                double nowMs, Double clockSkewMs, AttestationBinding expected, Map<String, Object> policy) {
        try {
            ParsedReport report;
            try {
                report = parseSevSnpReport(reportBytes);
            } catch (RuntimeException e) {
                return genuineFail("report parse failed: " + (e.getMessage() == null ? "unknown" : e.getMessage()));
            }
            // exactly 1184 bytes with the signature block beyond r and s reserved-zero: anything else is a second encoding of the same signed report
            if (reportBytes.length != REPORT_LEN) return genuineFail("report length " + reportBytes.length + " is not the canonical " + REPORT_LEN);
            boolean reserved = false;
            for (int i = OFF_SIG_S + 72; i < reportBytes.length; i++) reserved |= reportBytes[i] != 0;
            for (int i = 0x2a0 + 48; i < 0x2a0 + 72; i++) reserved |= reportBytes[i] != 0 || reportBytes[i + (OFF_SIG_S - 0x2a0)] != 0;
            if (reserved) return genuineFail("report signature block has non-zero reserved bytes");
            AmdChainResult chain = verifyAmdCertChain(vcekDer, askArkPem, trustAnchorArkSpkiSha384, nowMs, clockSkewMs);
            if (!chain.ok) return genuineFail("cert chain invalid: " + chain.reason);
            if (!verifySevSnpReportSignature(report, chain.vcek)) return genuineFail("report signature does not verify under VCEK");
            String bind = checkVcekReportBinding(chain.vcekTbs, report);
            if (bind != null) return genuineFail(bind);
            if (expected != null && !AttestCommon.timingSafeEq(AttestCommon.attestationBindingBytes(expected), report.reportData)) {
                return genuineFail("report_data does not bind holder/grant/epoch/nonce");
            }
            if (policy != null) {
                String why = checkSevSnpPolicy(report, policy);
                if (why != null) return genuineFail(why);
            }
            return new GenuineReportResult(true, null, report, makeDefaultDeriveIdentity(false).apply(report));
        } catch (RuntimeException e) {
            return genuineFail("genuine verification error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()));
        }
    }
}
