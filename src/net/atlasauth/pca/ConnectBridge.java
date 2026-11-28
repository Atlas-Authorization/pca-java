package net.atlasauth.pca;

import java.util.Map;

/** Public seam over the package-private signature helpers, for the outbound connection vault (net.atlasauth.pca.connect). */
public final class ConnectBridge {
    private ConnectBridge() {}

    /** True iff the artifact's signature verifies under the pinned Ed25519 signer (a non-ed25519 suite is not pinned here, so it fails). Never throws. */
    public static boolean verifyArtifactSig(String domain, Map<String, Object> artifact, String pinnedPk) {
        return IntentArtifacts.verifyArtifactSig(domain, artifact, pinnedPk, null);
    }
}
