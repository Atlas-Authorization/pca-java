package net.atlasauth.pca;

import java.util.Map;

/**
 * One vendor's verifier under a fixed configuration. The vendor classes (AttestAmd, AttestIntel, AttestMaa, AttestGcp,
 * AttestNvidia) each expose {@code static VendorImpl create(Map<String, Object> config)} which throws
 * {@link AttestException} for a refused configuration; {@link AttestFactory} finds them by that name.
 */
public interface VendorImpl {
    HardwareResult verify(Map<String, Object> evidence, AttestationBinding expected, long nowMs);
}
