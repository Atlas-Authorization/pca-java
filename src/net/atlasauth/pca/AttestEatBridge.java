package net.atlasauth.pca;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Public doors onto the package-private AMD SEV-SNP report parser and genuine-report verifier, for the attest-eat port that lives in its
 * own subpackage. No logic beyond shaping the answer is added here.
 */
public final class AttestEatBridge {
    private AttestEatBridge() {}

    /** The AMD ARK SPKI SHA-384 pin (lowercase hex) of each family ({@code milan}, {@code genoa}, {@code turin}). */
    public static Map<String, String> arkPins() { return new LinkedHashMap<>(AttestAmd.ARK_SPKI_SHA384); }

    private static Map<String, Object> shape(byte[] raw, AttestAmd.SnpReport r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("version", AttestAmd.le32(raw, 0));
        m.put("guest_svn", r.guestSvn);
        m.put("debug", (r.policy & AttestAmd.POLICY_DEBUG_BIT) != 0);
        m.put("measurement", AttestCommon.toHexLower(r.measurement));
        m.put("chip_id", AttestCommon.toHexLower(r.chipId));
        m.put("reported_tcb", Long.toUnsignedString(r.reportedTcb));
        return m;
    }

    /** parseSevSnpReport: the fields the EAT layer projects (version, guest_svn, debug, measurement, chip_id, reported_tcb); throws on a short buffer. */
    public static Map<String, Object> parseReport(byte[] raw) {
        return shape(raw, AttestAmd.parseSnpReport(raw));
    }

    /**
     * verifyGenuineSevSnpReport with the reference's policy (ECDSA-P384, VMPL 0, debug refused unless {@code allowDebug}, the launch
     * measurement must equal {@code expectedMeasurement} when given). {@code clockSkewMs} is null for none. Returns {@code {reason}}
     * (empty on success) and, on success, the parsed report fields.
     */
    public static Map<String, Object> verifyGenuineSevSnp(byte[] raw, byte[] vcekDer, String askArkPem, String arkPin, long nowMs, Object clockSkewMs,
                                                         String expectedMeasurement, boolean allowDebug) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> pol = new LinkedHashMap<>();
        // an empty reference allowlist means "no measurement pin": pin the report's own launch measurement (a no-op) when none was asked for
        String m = expectedMeasurement;
        if (m == null) {
            try {
                m = AttestCommon.toHexLower(AttestAmd.parseSnpReport(raw).measurement);
            } catch (AttestException e) {
                out.put("reason", "report parse failed: " + AttestCommon.errMsg(e));
                return out;
            }
        }
        pol.put("measurements", java.util.List.of(m));
        pol.put("allowDebug", allowDebug);
        Map<String, Object> cfg = new LinkedHashMap<>();
        cfg.put("family", "milan");
        cfg.put("binding", "report-data");
        cfg.put("policy", pol);
        if (clockSkewMs != null) cfg.put("clockSkewMs", clockSkewMs);
        AttestAmd amd = (AttestAmd) AttestAmd.create(cfg, arkPin);
        Object[] r = amd.verifyReport(raw, vcekDer, askArkPem, nowMs, null);
        out.put("reason", r[0]);
        if (r[1] != null) out.put("report", shape(raw, (AttestAmd.SnpReport) r[1]));
        return out;
    }
}
