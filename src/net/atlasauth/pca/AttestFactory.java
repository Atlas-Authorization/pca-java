package net.atlasauth.pca;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * verifier_from_config: build a vendor attestation verifier from the language-neutral configuration documented in the
 * conformance vector file (verifier_config_schema), and the default-verifier seam of passport verification. Port of the Go
 * attest_factory.go.
 *
 * <p>Each vendor lives in its own class exposing {@code static VendorImpl create(Map<String, Object> config)}:
 * AttestAmd, AttestIntel, AttestMaa, AttestGcp, AttestNvidia. They are looked up by name so the foundation compiles
 * before the vendor classes exist; a vendor class that is absent is refused like an unknown vendor.
 */
public final class AttestFactory {
    private AttestFactory() {}

    /** The vendors {@link #verifierFromConfig} builds a verifier for. */
    public static final List<String> ATTESTATION_VENDORS = Collections.unmodifiableList(
        Arrays.asList("amd-sev-snp", "intel-tdx-dcap", "azure-maa", "gcp-confidential-space", "nvidia-gpu-spdm"));

    private static final Map<String, String> VENDOR_CLASS = new HashMap<>();
    private static final Map<String, String> ERROR_PREFIX = new HashMap<>();
    static {
        VENDOR_CLASS.put("amd-sev-snp", "AttestAmd");
        VENDOR_CLASS.put("intel-tdx-dcap", "AttestIntel");
        VENDOR_CLASS.put("azure-maa", "AttestMaa");
        VENDOR_CLASS.put("gcp-confidential-space", "AttestGcp");
        VENDOR_CLASS.put("nvidia-gpu-spdm", "AttestNvidia");
        ERROR_PREFIX.put("amd-sev-snp", "amd-snp verification error (fail closed): ");
        ERROR_PREFIX.put("intel-tdx-dcap", "intel-dcap verification error (fail closed): ");
        ERROR_PREFIX.put("azure-maa", "azure-maa verification error (fail closed): ");
        ERROR_PREFIX.put("gcp-confidential-space", "gcp-confidential-space verification error (fail closed): ");
        ERROR_PREFIX.put("nvidia-gpu-spdm", "nvidia-spdm verification error (fail closed): ");
    }

    static String errorPrefix(String vendor) {
        String p = ERROR_PREFIX.get(vendor);
        return p == null ? "" : p;
    }

    /**
     * Builds the verifier for (vendor, config); the AttestException is the constructor's refusal of the configuration (a
     * missing allowlist, an absent trust anchor, a malformed pin: there is no accept-all). identity_overrides, if present,
     * are merged over the measured identity of every successful verification.
     */
    public static VendorVerifier verifierFromConfig(String vendor, Map<String, Object> config) {
        if (config == null) config = new LinkedHashMap<>();
        String cls = VENDOR_CLASS.get(vendor);
        if (cls == null) throw new AttestException("unknown attestation vendor \"" + vendor + "\"");
        VendorImpl impl;
        try {
            Method m = Class.forName(AttestFactory.class.getPackageName() + "." + cls).getDeclaredMethod("create", Map.class);
            m.setAccessible(true);
            impl = (VendorImpl) m.invoke(null, config);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof AttestException) throw (AttestException) e.getCause();
            throw new AttestException(String.valueOf(e.getCause()));
        } catch (ReflectiveOperationException e) {
            throw new AttestException("attestation vendor " + vendor + " is not available in this build");
        }
        Map<String, Object> ov = AttestCommon.asRec(config.get("identity_overrides"));
        return new VendorVerifier(vendor, impl, ov);
    }
}
