package net.atlasauth.pca;

import java.util.Map;

/**
 * Verifies the hardware evidence of one vendor under a fixed configuration. Safe for concurrent use. Built by
 * {@link AttestFactory#verifierFromConfig}.
 */
public final class VendorVerifier {
    private final String vendor;
    private final VendorImpl impl;
    private final Map<String, Object> overrides;

    VendorVerifier(String vendor, VendorImpl impl, Map<String, Object> overrides) {
        this.vendor = vendor;
        this.impl = impl;
        this.overrides = overrides;
    }

    /** The vendor this verifier was built for. */
    public String vendor() { return vendor; }

    /**
     * Verifies the vendor evidence (null: none supplied for this action) against the expected binding at the clock nowMs
     * (epoch milliseconds). It never throws: anything unexpected is a failed result.
     */
    public HardwareResult verify(Map<String, Object> evidence, AttestationBinding expected, long nowMs) {
        HardwareResult res;
        try {
            res = impl.verify(evidence, expected, nowMs);
        } catch (RuntimeException | StackOverflowError e) {
            String m = e.getMessage() != null ? e.getMessage() : e.toString();
            return HardwareResult.fail(AttestFactory.errorPrefix(vendor) + m);
        }
        if (res.ok && res.measured != null && overrides != null && !overrides.isEmpty()) {
            return new HardwareResult(true, res.bound, res.reason, AttestCommon.mergeOverrides(res.measured, overrides), res.hostAsserted);
        }
        return res;
    }
}
