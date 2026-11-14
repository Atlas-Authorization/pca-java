package net.atlasauth.pca;

import java.util.Map;

/**
 * The verifier factory as the tests use it. The shared conformance vectors sign AMD chains under a test root named by
 * trustAnchorArkSpkiSha384. Production configuration cannot do that: AttestFactory ignores the member.
 */
final class AttestHarness {
    private AttestHarness() {}

    static VendorVerifier verifier(String vendor, Map<String, Object> config) {
        Object pin = config == null ? null : config.get("trustAnchorArkSpkiSha384");
        if (!"amd-sev-snp".equals(vendor) || !(pin instanceof String)) return AttestFactory.verifierFromConfig(vendor, config);
        return new VendorVerifier(vendor, amd(config), AttestCommon.asRec(config.get("identity_overrides")));
    }

    static VendorImpl amd(Map<String, Object> config) {
        Object pin = config.get("trustAnchorArkSpkiSha384");
        return AttestAmd.create(config, pin instanceof String ? (String) pin : null);
    }
}
